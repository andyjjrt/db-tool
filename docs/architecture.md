# 系統設計

DB Gateway 讓使用者透過瀏覽器以 SQL 查詢 ParadeDB（PostgreSQL 17 + `pg_search`），並以「群組」管理誰能讀哪些 schema、表，以及表裡的哪些列。本文說明目前程式的設計。實作過程中的計畫與決策紀錄見 [`plans/permission-model.md`](plans/permission-model.md)。

## 1. 核心原則

- **權限只有一個來源：OpenFGA。** 群組、成員、表與 schema 授權、列級控制宣告、admin 名單都是 OpenFGA tuple。SQLite 不存任何權限狀態。
- **PG 是執行端。** 每個使用者以自己的 `u_<id>` role 登入目標 DB；能看到什麼完全由 PostgreSQL 的 `GRANT` 與 RLS 決定，gateway 不在查詢路徑上過濾資料。
- **映射沒有額外邏輯。** 每種 tuple 對應固定的一組 PG 操作（`PgOp`）；衝突在寫入時檢查並拒絕，不在映射時合併。
- **不自動 migrate、不提權。** 目標 DB 的一次性設定（`gateway_acl`、`gw_managed`、ParadeDB 授權）由操作者手動執行，gateway 只做唯讀檢查。執行期所有操作都以該連線的管理帳號（DB owner 或 superuser）直接執行，權限不足就失敗並回報。

## 2. 元件

```
           ┌──────────────── Admin API (/api/admin) ────────────────┐
           │  current_user → require_admin → RuleService             │
           └───────┬───────────────────────────────┬────────────────┘
                   │ 檢查 + 寫 tuple                │ 收回類：內聯套用
                   ▼                               ▼
             ┌──────────┐   ReadChanges     ┌──────────┐
             │ OpenFGA  │ ────────────────▶ │  Syncer  │──┐
             └──────────┘                   └──────────┘  │ PgOp
                   ▲  全部 tuple             ┌───────────┐ │
                   └──────────────────────── │Reconciler │─┤
                                             └───────────┘ ▼
   SQLite（users、sessions、connections、          ┌─────────────┐
   descriptions、sync_state、audit_log）           │ PgExecutor  │──▶ 目標 DB
                                                   └─────────────┘   (g_* / u_* / RLS)
```

| 元件 | 位置 | 職責 |
|---|---|---|
| Admin API | `api/admin_permissions.py`、`api/auth.py` | HTTP 端點、身分與 admin 檢查、錯誤碼映射 |
| RuleService | `permissions/rules.py` | 寫入前檢查（衝突、存在性、低基數、不安全 view），寫 OpenFGA，寫稽核，收回類變更內聯套用 |
| PermissionStore | `permissions/store*.py` | OpenFGA（正式）與 in-memory（測試）兩種實作，同一份契約 |
| mapping | `permissions/mapping.py` | tuple → `PgOp` 的純函式 |
| PgExecutor | `permissions/executor.py` | 每次 `apply` 一個交易；物件不存在的 op 略過並回報 |
| Syncer | `permissions/syncer.py` | 每個連線一個 consumer，依 OpenFGA 變更串流套用到 PG |
| Reconciler | `permissions/reconciler.py` | 全量比對 OpenFGA 與 PG catalog，修正 drift、回報無法修正的項目 |
| scan | `permissions/scan.py` | 找出會繞過列級控制的 view 與 SECURITY DEFINER 函式 |
| Provisioner | `provisioner/roles.py` | 建立 `u_<id>`、加入 `gw_managed`、建 session 時補齊群組 membership |
| targetdb.check | `targetdb/check.py` | 目標 DB 設定的唯讀檢查 |

## 3. 權限模型

### 3.1 OpenFGA 模型

```
type user
type column
type group
  relations
    define member: [user]
type gateway
  relations
    define admin: [user]
    define group: [group]
type db_schema
  relations
    define reader: [group#member]
type db_table
  relations
    define reader: [group#member]
    define row_column: [column]
type row_set
  relations
    define table: [db_table]
    define reader: [group#member]
```

物件 id：`user:<users.id>`、`group:<name>`、`gateway:main`、`column:<col>`、`db_schema:<conn>/<schema>`、`db_table:<conn>/<schema>/<table>`、`row_set:<conn>/<schema>/<table>/<col>=<value>`。每段以 percent-encoding 跳脫 `/ = : # @ % 空白`（`permissions/ids.py`）。

### 3.2 tuple 與 PG 操作

| tuple | 寫入時 | 刪除時 |
|---|---|---|
| `gateway:main#group@group:g` | 每個連線 `CREATE ROLE g_g NOLOGIN` | 先刪該群組的 `row_grants`，再 `DROP ROLE g_g` |
| `group:g#member@user:u` | `GRANT g_g TO u_u WITH INHERIT TRUE`（個人 role 尚未建立則略過，建 session 時補） | `REVOKE g_g FROM u_u` |
| `db_schema:c/s#reader@group:g#member` | `GRANT SELECT ON ALL TABLES IN SCHEMA s`、default privileges、`row_grants(g_g, s, '*', '*')` | 反向 |
| `db_table:c/s/t#reader@group:g#member` | `GRANT SELECT ON s.t`、`row_grants(g_g, s, t, '*')` | 反向 |
| `row_set:c/s/t/col=v#reader@group:g#member` | `row_grants(g_g, s, t, v)` | 刪除該筆 |
| `db_table:c/s/t#row_column@column:col` | 宣告列級受控（見 3.3） | 取消列級受控 |
| `gateway:main#admin@user:u` | 無 | 無 |

群組與成員是全域的：同一個 cluster 上的所有連線共用 `g_*`、`u_*` role。

### 3.3 列級控制（RLS）

目標 DB 的一次性設定（`targetdb/setup.sql`）建立：

- `gw_managed` role：所有 `u_*` 都是成員；
- `gateway_acl.row_grants(group_role, schema_name, table_name, column_name, value)`：`'*'` 代表整張表或整個 schema；
- 三個 `SECURITY DEFINER` 函式：`is_managed()`、`allow_all(schema, table)`、`allowed_values(schema, table)`，都以 `session_user` 判斷呼叫者。

宣告一張表為列級受控時，gateway 以管理帳號執行：

```sql
ALTER TABLE s.t ENABLE ROW LEVEL SECURITY;
ALTER TABLE s.t FORCE ROW LEVEL SECURITY;
CREATE POLICY gw_passthrough ON s.t USING (NOT (SELECT gateway_acl.is_managed()));
CREATE POLICY gw_read ON s.t FOR SELECT
  USING ((SELECT (SELECT gateway_acl.allow_all('s', 't'))
                 OR team::text = ANY ((SELECT gateway_acl.allowed_values('s', 't'))::text[])));
GRANT SELECT ON s.t TO gw_managed;
```

結果：

| 使用者的規則 | 在列級受控表上看到 |
|---|---|
| `db_table#reader` 或所屬 `db_schema#reader` | 全部列 |
| `row_set#reader`（可多筆、可跨群組） | 指定值的聯集 |
| 都沒有 | 0 列（表看得到，但沒有資料） |
| 非 gateway 的 role（應用帳號、owner） | 全部列（`gw_passthrough`），既有應用不受影響 |

設計要點：

- 用 `session_user` 而不是 `current_user`：使用者 `SET ROLE` 成群組 role 也改變不了判斷結果，函式也不收「查詢者」參數。
- policy 不加 `TO` 子句，函式 `EXECUTE` 保留給 PUBLIC：passthrough 需要每個 role 都能執行。
- `gw_read` 外層的 scalar `SELECT` 讓欄位參照成為 correlated SubPlan。少了這層，ParadeDB 不會在受控表上使用它的 custom scan，`paradedb.score()` 會失敗。
- 未受控的表上沒有 RLS，權限只看 `GRANT`：沒有規則就是 `permission denied`。
- 表級 reader 的 `'*'` 在授權時就寫入 `row_grants`，所以已授權的表之後才宣告為列級受控，既有讀者不會暫時看到 0 列。

### 3.4 寫入時檢查

所有檢查與寫入都在 RuleService 的全域鎖內完成，違反時回 409 並列出衝突的既有規則。

| 檢查 | 原因 |
|---|---|
| 同一群組在同一 schema 不能同時有 schema reader 與 table reader | 兩者都 `GRANT SELECT` 同一張表，收回一個會連帶拿掉另一個 |
| `row_set` 只能建在列級受控表上，欄位必須是宣告的分區欄位 | 未受控的表上 row_set 不會生效 |
| 取消列級受控前，不能還有 row_set reader | 否則留下不會生效的規則 |
| 分區欄位 distinct 數超過 200 時拒絕宣告；一張表只能有一個分區欄位 | 低基數限制；`gw_read` 只認一個欄位 |
| 群組底下還有規則時不能刪除 | 避免留下孤兒授權 |
| 授權會讓群組讀到不安全 view 時拒絕；已有群組讀得到不安全 view 時拒絕宣告 | 見 3.5 |
| 群組、連線名稱建立後不可改 | 它們是 OpenFGA id 與 PG role 名的一部分 |

### 3.5 不安全的 view 與函式

PostgreSQL 以 view 的 owner 檢查一般 view 底下的表，以查詢者檢查 `security_invoker` view 底下的表。因為 policy 看的是 `session_user`、而且表開了 FORCE RLS，一般 owner 建的 view 不會讓使用者多看到資料。`scan.unsafe_views` 找出會洩漏的情況：

- owner 是 superuser 或 BYPASSRLS、直接讀受控表的非 invoker view：RLS 對這種 owner 整個跳過；
- 讀到受控表、或查詢中呼叫使用者函式的 materialized view：內容是 REFRESH 時算出來的；
- 直接讀受控表的分割家族成員（父表或分割區）、而該成員本身沒有列級控制的非 invoker view：RLS 只套用在查詢指名的那張表；
- 查詢中呼叫 owner 為 superuser 或 BYPASSRLS 的 `SECURITY DEFINER` 函式的 view；
- 經由任何路徑讀到以上物件的 view，包括 invoker view。

不分析：函式內容、函式間接呼叫、foreign table。建立 foreign server 與 user mapping 屬於 DB owner 的設定，不在防護範圍內。`scan.definer_functions` 列出所有 `SECURITY DEFINER` 函式，只回報，不阻擋。

## 4. 同步

### 4.1 寫入流程

1. Admin API → RuleService 檢查 → `PermissionStore.write` → `audit_log`（kind=`admin`）。
2. 收回類變更（移除成員、收回授權、刪群組、取消宣告）：在全域鎖內立刻套用對應的 PG 操作，逾時 5 秒。成功回 200 `synced`，逾時或失敗回 202 `pending`，之後由 Syncer 補上。
3. 授予類變更不內聯套用，由 Syncer 在下一輪（預設 2 秒）套用。

宣告列級受控例外：先在 PG 套用 `EnableRowPolicy`，成功後才寫 tuple，寫 tuple 失敗時撤回。所以宣告完成時 RLS 已經生效。

### 4.2 Syncer

- 每個連線一個 consumer（`sync_state.consumer = pg:<name>`），各自是獨立 task，一個連線出錯不影響其他連線。
- 每輪：`ReadChanges(token)` → 每筆 change 在一個 PG 交易內套用 → 整頁成功才寫回 continuation token。失敗時記錄 `last_error`、`fail_count`，指數退避（最長 60 秒），token 不前進。ops 都是冪等的，重放是安全的。
- 映射拒絕的 tuple（例如連線已刪除）寫一筆 `sync` 稽核後跳過，不會卡住串流。
- token 失效（`ContinuationTokenInvalid`），或 OpenFGA store 換了：先找最新位置，跑一次嚴格的全量 reconcile，成功後才從最新位置繼續。

### 4.3 Reconciler

啟動時跑一次，之後每 10 分鐘一次；也可以由 `POST /api/admin/reconcile` 觸發，`dry_run` 只回傳計畫。它比對「所有 tuple 映射出的期望狀態」與 PG catalog：

- **自動修正**（寫 `sync` 稽核）：缺少或多出的 `g_*` 授權與 membership、`row_grants` 裡不該有的資料、被改壞或關掉的 RLS／policy、缺少的 `g_*` role、OpenFGA 沒有對應群組的孤兒 `g_*` role。
- **只回報**：`gw_*` policy 卻沒有宣告（`undeclared_policy`）、受控表上的其他 permissive policy（`extra_policy`）、由其他 grantor 授予的 membership（`membership_grantor`）、新 schema 缺 `gw_managed` USAGE（`managed_usage_missing`）、不安全 view（`unsafe_view`）、bypass owner 且 `gw_managed` 可執行的 definer 函式（`definer_function`）、刪不掉的孤兒 role（`undroppable_group_role`）等。

Reconciler 用來偵測 drift，不是防範 DB owner 的安全邊界：DB owner 本來就能關掉 RLS 或建立其他存取路徑。

### 4.4 鎖與一致性

- 鎖的順序固定為：RuleService 全域鎖 → `ConnectionLocks(conn)` → PgExecutor 內部鎖。
- 內聯收回、Syncer、Reconciler 對同一個連線一律序列化：Syncer 的「讀一頁、套用、寫 token」與 Reconciler 的「讀 tuple、讀 catalog、套用」都在連線鎖內完成。
- 內聯收回在套用前會再查一次 store；如果 tuple 已經重新出現，就跳過。所以延遲到的收回不會蓋掉較新的授予。
- `REPEATABLE READ` 交易會看到舊的 `row_grants`，要到交易結束後才生效。這是已接受的限制。

## 5. 身分與 admin

- `INITIAL_ADMINS`（`permissions/admin.py`）是寫在程式碼裡的 login key 清單，不讀環境變數。初始 admin 永遠是 admin，不能被移除或停用。
- 一般 admin 存成 `gateway:main#admin` tuple。他們可以新增 admin，但只有初始 admin 能移除 admin、停用 admin 帳號、註冊連線。
- 登入屬於 M1，還沒實作：`api/auth.py` 的 `current_user` 對所有請求都回 401。M1 會把它換成真正的 session 驗證；測試以 `app.dependency_overrides` 注入使用者。

## 6. 資料存放

| 位置 | 內容 |
|---|---|
| OpenFGA | 所有權限：群組、成員、授權、列級宣告、admin |
| SQLite（`DBGW_METADATA_DB_PATH`） | `users`、`activations`、`sessions`、`connections`（連線設定與 secret 參照）、`descriptions`（顯示用說明）、`sync_state`（每個連線的同步位置）、`audit_log`（只能新增） |
| 目標 DB | `gw_managed`、`g_*`、`u_*`、`gateway_acl.*`、各表的 RLS policy |
| 環境變數 | 連線管理帳號的帳密（`DBGW_SECRET_<REF>`） |

`audit_log` 由 trigger 擋下 UPDATE 與 DELETE。kind 包括 `admin`（管理操作）、`sync`（drift 修正與同步錯誤）、`query`、`export`、`login`、`logout`。

## 7. 失敗時的行為

| 狀況 | 行為 |
|---|---|
| OpenFGA 連不上 | 管理 API 回 503；Syncer 記錄錯誤並退避；PG 現況不動，使用者查詢不受影響 |
| 目標 DB 連不上（連線失敗、帳密錯、secret 缺） | 該連線的操作回 503，附原因；其他連線照常 |
| 目標 DB 執行失敗（lock 逾時等） | 回 503，附錯誤類別與 SQLSTATE，不附 PG 錯誤訊息原文 |
| 目標 DB 拒絕操作（例如管理帳號權限不足） | 回 502，附錯誤類別與 SQLSTATE；gateway 不會自行提權 |
| 一次 reconcile 全部連線、其中一個掛掉 | 回 200，每個連線各自回報 |
| 刪群組時 role 還有依賴 | 成員已先撤銷，回 `pending`，Syncer 會重試 `DROP ROLE` |

## 8. 已知限制

- 登入（M1）尚未實作，管理 API 目前無法實際使用。
- 掃描與分區欄位的 distinct 計數，在全域鎖和連線鎖內執行，而 SQL 查詢本身沒有設 `statement_timeout`。
- 大群組刪除時，內聯撤銷會逐筆查 OpenFGA，可能慢到回 `pending`，但結果仍然正確。
- 同一個 PG cluster 只能部署一套 gateway。
- ParadeDB 在 RLS 表上的效能數據尚未量測（併入 M1 驗證報告）。
