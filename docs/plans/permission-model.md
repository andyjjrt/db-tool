# 實作計畫：權限模型（規格書第 7 節）

> 這是實作過程的計畫與決策紀錄，後面章節（§8 起）的決定會覆蓋前面的內容。目前系統的設計請看 [`../architecture.md`](../architecture.md)，使用方法請看 [`../usage.md`](../usage.md)。

來源：[DB Gateway 規格書 v1 §7 權限模型](https://claude.ai/artifact/YYEmX8H7iMwQi1dawMwXEz#239dedd0-4a8a.mem2fzv4v2g.19942)（rev 129）。
相關章節：§3 架構、§5 帳號生命週期、§8 稽核、§9 資料模型、§10 API、§13 風險、§14 M3。

## 0. 範圍與前提

**本計畫交付**

- OpenFGA 模型與 `PermissionStore` 介面（OpenFGA 實作 + 記憶體實作供測試）
- `RuleService`：群組、成員、表級規則、列級規則、admin 關係寫成 OpenFGA tuple，並在寫入前檢查規則衝突
- tuple → PG 操作的映射（每筆 tuple 對應固定操作，Syncer 與 Reconciler 共用）
- Syncer（`ReadChanges` → 逐筆套用）、Reconciler（全量比對）
- 目標 DB 的設定 SQL（由操作者手動執行，見 `docs/target-db-setup.md`）與唯讀檢查 `targetdb.check`：`gw_managed`、`gateway_acl` schema、`row_grants`、RLS 函式、`paradedb` 授權
- 列級受控表的宣告與取消
- admin 規則（寫死的初始 admin、只有初始 admin 能移出）
- §10 的管理 API：groups、grants、row-policies、sync、reconcile、drift、admins

**不在本計畫**：UI（權限管理頁）、寫入等級（M4）、進階列級規則（M6）。

**依賴 M1，尚未實作**：repo 目前只有空 scaffold。下列 M1 元件本計畫只做到「足以讓權限功能跑起來與測試」的最小版本，完整版留給 M1：

- 專案骨架（FastAPI app、設定、SQLite 連線與 migration）
- `users`、`connections`、`audit_log` 表
- Provisioner 的 `CREATE ROLE u_<id>`（本計畫只加上「加入 `gw_managed`」與「建 session 時依 OpenFGA 補齊群組 membership」）
- dev 環境：docker compose（ParadeDB、OpenFGA、OpenFGA 用的 PostgreSQL）

## 1. 規劃時發現並已修正的規格問題

已同步改進規格書 §7、§13。

1. **`SECURITY DEFINER` 函式裡的 `current_user` 是函式 owner，不是查詢者。** 改用 `session_user`：gateway 以 `u_<id>` 登入，`session_user` 就是個人 role，使用者 `SET ROLE` 也改不了。函式不收「查詢者」參數，避免被拿來查別人的可見值。
2. **`STABLE` 函式不保證只計算一次。** policy 裡包成子查詢 `(SELECT gateway_acl.allowed_values(...))`，planner 會變成 InitPlan，每次查詢只算一次。
3. **啟用 RLS 會擋住非 gateway 的 role**（table owner、應用程式帳號、ETL）。另加 `gw_passthrough` policy：只有 `gw_managed` 成員受 `gw_read` 限制，其他 role 照舊。
4. **`gateway_acl` 不能「沒有任何權限」。** policy 要能執行函式，所以 `USAGE ON SCHEMA gateway_acl` 與函式 `EXECUTE` 授給 PUBLIC，`row_grants` 表不授任何權限。
5. **`REPEATABLE READ` 交易會看到舊的 `row_grants`。** `GRANT`/`REVOKE` 與 membership 變更在下一個 statement 就生效，但 `row_grants` 要等交易結束。v1 接受（已寫進 §13）；若要嚴格 5 秒，列級收回時對受影響成員中 `xact_start` 早於收回時間的連線執行 `pg_terminate_backend`（選配）。

## 2. 設計重點

### 2.1 原則：映射沒有額外邏輯

每筆 tuple 對應固定的 PG 操作，不依其他 tuple 或表的狀態推導；刪除 tuple 就執行反向操作。會讓映射互相衝突的規則，在寫入 OpenFGA 前由 `RuleService` 拒絕（2.4）。

```
管理 API ─> RuleService（寫入時檢查）─> OpenFGA
                                          │ ReadChanges
                                          v
                              Syncer：每筆 change ─> mapping(tuple) ─> [PgOp] ─> apply
Reconciler：全部 tuple ─> mapping ─> 期望狀態 ─┐
            PG 實際狀態 ───────────────────────┴─> diff ─> [PgOp] ─> apply
```

- `mapping(tuple) -> list[PgOp]` 是純函式，寫入用 `grant_ops`、刪除用 `revoke_ops`。
- Syncer 照事件順序逐筆套用。每個 op 都是冪等的（`GRANT` 重複無妨、`REVOKE` 不存在的權限無妨、`row_grants` 用 `INSERT ... ON CONFLICT DO NOTHING` 與 `DELETE`），所以從舊的 token 重放也會收斂到正確狀態。
- Reconciler 把所有 tuple 的 `grant_ops` 聯集起來當期望狀態，與 PG 實際狀態比對。因為寫入時已排除衝突，聯集不會互相矛盾。

### 2.2 OpenFGA 模型

```
model
  schema 1.1
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

`row_set#table` 只用來判斷 row_set 屬於哪張表（不靠解析物件 id），不參與權限計算。

`db_table#row_column@column:<col>` 表示這張表宣告為列級受控、分區欄位是 `<col>`；每張表最多一筆（RuleService 保證）。宣告者與時間記在稽核（2026-10-18 決定，取代 SQLite 的 `row_policies`）。

### 2.3 映射表

| tuple | `grant_ops`（寫入時） | `revoke_ops`（刪除時） |
|---|---|---|
| `group:g#member@user:u` | `GRANT g_g TO u_u`（每個連線；個人 role 尚未建立則略過，建 session 時補） | `REVOKE g_g FROM u_u` |
| `db_schema:c/s#reader@group:g#member` | `GRANT SELECT ON ALL TABLES IN SCHEMA s TO g_g`；`ALTER DEFAULT PRIVILEGES FOR ROLE <owner> IN SCHEMA s GRANT SELECT ON TABLES TO g_g`；`row_grants(g_g, s, '*', '*')` | 反向 |
| `db_table:c/s/t#reader@group:g#member` | `GRANT SELECT ON s.t TO g_g`；`row_grants(g_g, s, t, '*')` | 反向 |
| `row_set:c/s/t/col=v#reader@group:g#member` | `row_grants(g_g, s, t, v)`（`s`、`t` 由 `table` 關係取得） | 刪除該筆 |
| `row_set:...#table@db_table:...` | 無 | 無 |
| `db_table:c/s/t#row_column@column:col` | 宣告列級受控：`ENABLE` + `FORCE ROW LEVEL SECURITY`、建立 `gw_passthrough` 與 `gw_read`、`GRANT SELECT ON s.t TO gw_managed` | 取消列級受控：`DROP POLICY` ×2、`NO FORCE` + `DISABLE ROW LEVEL SECURITY`、`REVOKE SELECT ON s.t FROM gw_managed` |
| `gateway:main#group@group:g` | `CREATE ROLE g_g NOLOGIN`（每個連線） | `DROP ROLE g_g`（先刪該群組的 `row_grants`） |
| `gateway:main#admin@user:u` | 無（只更新 admin 快取） | 無 |

不屬於任何 tuple、一次性的設定：

- **目標 DB 設定（每個目標 DB，操作者手動執行）**：`GRANT USAGE ON SCHEMA <各 schema> TO gw_managed`；`paradedb` 的 `USAGE` 與函式 `EXECUTE` 授給 `gw_managed`。Reconciler 發現新 schema 缺 `USAGE` 時只回報，不自動補。

`<owner>` 清單來自連線設定 `default_privilege_owners`。

**結果**（每個群組在一張列級受控表上）：

| OpenFGA | 看到 |
|---|---|
| `db_table#reader` 或所屬 `db_schema#reader` | 全部列 |
| `row_set#reader`（可多筆） | 指定值的聯集 |
| 都沒有 | 0 列（`SELECT` 來自 `gw_managed`，看得到表但沒有資料） |

未受控的表上，`row_grants` 不會被讀到；權限只看 `GRANT`，沒有規則就是 `permission denied`。

表級 reader 的 `'*'` 在授權時就寫入，所以已授權的表之後才宣告為列級受控，既有讀者不會暫時看到 0 列。

### 2.4 寫入時檢查（`RuleService`）

| 檢查 | 原因 |
|---|---|
| 同一群組在同一 schema 不能同時有 `db_schema#reader` 與 `db_table#reader` | 兩者都 `GRANT SELECT` 同一張表，收回其中一個會連帶拿掉另一個。要從整個 schema 改成部分表，先刪 schema 規則再加表規則 |
| `row_set` 只能建在列級受控表上，欄位必須是 `db_table#row_column` 宣告的分區欄位 | 未受控的表上 row_set 不會生效 |
| 寫入 row_set 的第一筆 reader 時一併寫入 `table` parent tuple；刪除最後一筆 reader 時一併刪除 | parent tuple 由各群組共用 |
| 取消列級受控前，該表不能還有 row_set reader | 否則留下不會生效的規則 |
| 分區欄位 distinct 數超過門檻（預設 200）時拒絕宣告 | 低基數限制（§13） |
| 一張表只能有一筆 `row_column`；已宣告時再宣告（不論欄位）拒絕 | `gw_read` 只認一個欄位 |
| 群組名稱、連線名稱建立後不可改 | 它們是 OpenFGA id 與 PG role 名的一部分 |

檢查與寫入要在同一把 `asyncio.Lock`（全域，單一 process）內完成，避免兩個管理者同時寫入時都通過檢查。違反時回 409，訊息說明衝突的既有規則。

### 2.5 RLS 物件（每個目標 DB）

```sql
CREATE ROLE gw_managed NOLOGIN;              -- 所有 u_<id> 都是成員（Provisioner 建 role 時加入）
CREATE SCHEMA gateway_acl AUTHORIZATION <連線管理帳號>;
CREATE TABLE gateway_acl.row_grants (
  group_role  name NOT NULL,
  schema_name name NOT NULL,
  table_name  name NOT NULL,                 -- '*' = 整個 schema（db_schema reader）
  column_name name NOT NULL,                 -- schema 規則為 '*'
  value       text NOT NULL,                 -- '*' = 全部列
  PRIMARY KEY (schema_name, table_name, group_role, value)
);
REVOKE ALL ON gateway_acl.row_grants FROM PUBLIC;
GRANT USAGE ON SCHEMA gateway_acl TO PUBLIC;

CREATE FUNCTION gateway_acl.is_managed() RETURNS boolean
  LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog
  AS $$ SELECT pg_has_role(session_user, 'gw_managed', 'USAGE') $$;

CREATE FUNCTION gateway_acl.allow_all(p_schema name, p_table name) RETURNS boolean
  LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog
  AS $$ SELECT EXISTS (SELECT 1 FROM gateway_acl.row_grants g
          JOIN pg_catalog.pg_roles r ON r.rolname = g.group_role
          WHERE g.schema_name = p_schema AND g.table_name IN (p_table, '*') AND g.value = '*'
            AND pg_has_role(session_user, r.oid, 'USAGE')) $$;

CREATE FUNCTION gateway_acl.allowed_values(p_schema name, p_table name) RETURNS text[]
  LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog
  AS $$ SELECT coalesce(array_agg(DISTINCT g.value), '{}') FROM gateway_acl.row_grants g
          JOIN pg_catalog.pg_roles r ON r.rolname = g.group_role
          WHERE g.schema_name = p_schema AND g.table_name = p_table AND g.value <> '*'
            AND pg_has_role(session_user, r.oid, 'USAGE') $$;

-- 表宣告為列級受控時（以 owner 身分）
ALTER TABLE s.t ENABLE ROW LEVEL SECURITY;
ALTER TABLE s.t FORCE ROW LEVEL SECURITY;
CREATE POLICY gw_passthrough ON s.t USING (NOT (SELECT gateway_acl.is_managed()));
CREATE POLICY gw_read ON s.t FOR SELECT
  USING ((SELECT (SELECT gateway_acl.allow_all('s', 't'))
                 OR team::text = ANY ((SELECT gateway_acl.allowed_values('s', 't'))::text[])));
GRANT SELECT ON s.t TO gw_managed;
```

已在 PostgreSQL 17 容器實測（2026-10-16）：

- 表 reader、schema reader → 全部列；row_set（team=b）→ 只有 b；同時屬於 a、b 兩群組 → a ∪ b；沒有規則 → 0 列，且在 `information_schema.tables` 看得到表
- 未受控的表：只有 schema reader 讀得到，其他人 `permission denied`
- schema 規則收回（`REVOKE ... ON ALL TABLES` + 刪 `row_grants`）→ 受控表 0 列、未受控表 `permission denied`
- 非 gateway 應用帳號與 owner → 透過 `gw_passthrough` 讀全部
- 使用者 `SET ROLE g_a` 後列數不變；直接呼叫 `allowed_values` 只回傳自己的值
- 讀 `row_grants` 回 permission denied；建同名 temp table 並改 `search_path` 無法劫持
- `EXPLAIN` 顯示三個函式都是 InitPlan
- 規格原本的 `current_user` 寫法回傳 `{}`；`REPEATABLE READ` 交易內刪除 `row_grants` 後仍看到舊資料

注意：

- `ANY` 裡的子查詢必須加 `::text[]`，否則會被當成 `ANY (subquery)` 而報 `text = text[]` 錯誤
- `gw_read` 外層多包一個 scalar `SELECT`，讓欄位參照變成 correlated SubPlan：沒包的話 ParadeDB 0.26 在受控表上不走自己的 custom scan，`paradedb.score()` 會報 `FeatureNotSupported`（2026-10-18 驗收時發現）。看到的列不變；舊寫法的 policy 會被 Reconciler 視為 drift 重建
- `gw_read` 不加 `TO gw_managed`：加了的話，使用者 `SET ROLE` 成群組 role 後會變 0 列
- 函式 `EXECUTE` 保留給 PUBLIC：passthrough 需要每個 role 都能執行，`session_user` 讓它們只回傳呼叫者自己的結果
- 啟用 RLS 與表權限的 `GRANT`/`REVOKE` 都需要 table owner（或 grant option）。每個連線的管理帳號是該 DB 的 owner，也可能是 superuser，所有 op 都直接以它執行，不 `SET ROLE`。權限不足時 op 失敗並回報，不自動補權限（2026-10-17 決定）

### 2.6 OpenFGA 物件 id

- `user:<users.id>`、`group:<name>`、`gateway:main`、`column:<column>`
- `db_schema:<conn>/<schema>`、`db_table:<conn>/<schema>/<table>`、`row_set:<conn>/<schema>/<table>/<column>=<value>`
- `<conn>` 用 `connections.name`
- 每段以 percent-encoding 跳脫 `/ = : # @ % 空白`；超過 OpenFGA 長度上限時拒絕寫入（低基數欄位不會碰到）
- `ids.py` 提供 encode（RuleService 建 id 用）與 round-trip 測試；row_set 所屬的表以 `table` 關係為準

### 2.7 同步流程與時效

1. 管理 API → `RuleService`（檢查）→ `PermissionStore.write(writes, deletes)` → `audit_log`（kind=admin，含 tuple）
2. 若含收回類變更：在同一把鎖內直接套用這些 tuple 的 `revoke_ops`（逾時 5 秒）。成功回 200 `synced`，逾時回 202 `pending`，之後由 Syncer 補上
3. Syncer 背景迴圈（每 2 秒）：`ReadChanges(token)` → 依序套用每筆 change 的 ops → 全部成功才寫回 `sync_state.continuation_token`；失敗記 `last_error`、`fail_count`，指數退避，token 不前進（重放是安全的）
4. Reconciler：啟動時跑一次、之後每 10 分鐘一次、`POST /api/admin/reconcile` 可手動觸發（`dry_run` 只回傳 `[PgOp]`）。drift 修正寫入稽核（kind=sync）
5. 每個連線一把 `asyncio.Lock`：API 內收回、Syncer、Reconciler 對同一個 DB 序列化套用。管理寫入另有一把全域鎖（2.4），涵蓋「檢查 → 寫入 OpenFGA → 內聯收回」，避免舊的內聯收回蓋掉較新的授予
6. 每筆 change 的 ops 在一個 PG 交易內執行

OpenFGA 無法連線：管理 API 回 503，`/api/admin/sync` 顯示錯誤；PG 現況不動，查詢不受影響。

### 2.8 admin

- `INITIAL_ADMINS: frozenset[str]`（login_key）寫在 `db_gateway/permissions/admin.py`，不讀環境變數
- `is_admin(user)` = 在 `INITIAL_ADMINS` 內，或 OpenFGA `check(user:<id>, admin, gateway:main)`；同一 request 內快取
- 移出 admin、停用 admin 帳號：呼叫者必須在 `INITIAL_ADMINS`，否則 403；目標在 `INITIAL_ADMINS` 一律 403
- `GET /api/admin/admins` 合併兩個來源並標示 `initial: true`

## 3. 程式結構

```
src/db_gateway/
  permissions/
    model.fga          # OpenFGA 模型（2.2）
    ids.py             # 物件 id encode/decode
    store.py           # PermissionStore Protocol、Tuple、Change
    store_openfga.py   # openfga-sdk 實作
    store_memory.py    # 測試用；ReadChanges 以遞增序號模擬
    rules.py           # RuleService：寫入時檢查 + tuple 寫入/刪除 + 稽核
    admin.py           # INITIAL_ADMINS、is_admin、移出規則
    mapping.py         # tuple → grant_ops / revoke_ops（2.3）
    pg_ops.py          # PgOp 型別與 SQL 產生（psycopg.sql.Identifier）
    actual.py          # 讀 PG 實際狀態（Reconciler 用）
    syncer.py
    reconciler.py
  targetdb/
    check.py           # 唯讀檢查目標 DB 設定與管理帳號權限，回報缺項
  api/admin_permissions.py
tests/
  unit/                # ids、mapping、rules 檢查、admin（不需外部服務）
  integration/         # docker compose：ParadeDB + OpenFGA
```

## 4. 工作項目（依序）

每步都附測試，前一步通過再做下一步。

| # | 項目 | 產出 | 驗證 |
|---|---|---|---|
| 1 | 專案骨架與 dev 環境 | uv 依賴（fastapi、psycopg[binary,pool]、openfga-sdk、pytest）、`docker-compose.yml`、SQLite migration（`groups`、`sync_state` 與 M1 最小表） | `docker compose up` 後健康檢查通過 |
| 2 | OpenFGA 模型與 store | `model.fga`、`ids.py`、`PermissionStore` 兩種實作；啟動時比對 model，不同則寫入新版並記錄 model id | id round-trip；兩種實作跑同一組合約測試（write/delete/read/read_changes/check） |
| 3 | 目標 DB 設定與檢查 | `docs/target-db-setup.md`（操作者手動執行的 SQL）、`targetdb/check.py`（唯讀檢查，回報缺什麼）：`gw_managed`、`gateway_acl`、函式、schema `USAGE` 與 `paradedb` 授權給 `gw_managed` | 照文件設定後檢查無問題；缺項時檢查逐項回報；一般 role 讀不到 `row_grants` |
| 4 | 映射 | `mapping.py`、`pg_ops.py` | 2.3 每一列一個單元測試；`revoke_ops(t)` 套用在 `grant_ops(t)` 之後回到原狀；ops 重複套用結果不變 |
| 5 | 套用與實際狀態 | apply（以連線管理帳號直接執行，角色或物件不存在的 op 略過）、`actual.py` | 套用一組 tuple 後讀實際狀態 → 與期望狀態一致（收斂測試） |
| 6 | RuleService 與 admin | 群組 CRUD（含 `CREATE ROLE g_<name>`）、成員、表級/列級規則、宣告/取消列級受控、admin 加入/移出 | 2.4 每條檢查各有拒絕測試（409）；parent tuple 隨第一筆/最後一筆 reader 寫入/刪除；每個操作有稽核；非初始 admin 移出 admin → 403 |
| 7 | Syncer | `ReadChanges` 迴圈、`sync_state`、退避、API 內收回（5 秒 → 202） | 收回後 5 秒內 PG 生效；OpenFGA 停掉時查詢正常、管理 API 503；從舊 token 重放後狀態正確 |
| 8 | Reconciler | 全量比對、drift 偵測與修正、dry_run、新 schema 補 `USAGE` | 手動 `GRANT` 一張表 → drift 出現 → reconcile 後消失並有稽核 |
| 9 | Provisioner hook | 建 role 時加入 `gw_managed`；建 session 時依 OpenFGA 補齊 membership | 新使用者首次登入即有正確群組 |
| 10 | 管理 API | §10 的 groups、grants、row-policies、sync、reconcile、drift、admins | API 測試；回應帶 `synced`/`pending`；衝突回 409 |
| 11 | M3 驗收與繞過測試 | 見第 5 節 | 全部通過 |

## 5. 驗收測試（對應規格 §14 M3）

在 ParadeDB 容器上跑，以實際 `u_<id>` 連線驗證，不只看 catalog。

- 表級：授予 → 可 `SELECT`；收回 → 未受控表 `permission denied`、受控表 0 列，5 秒內生效
- 列級：`team='a'` 的群組只看到 a；表 reader、schema reader 看到全部；沒有規則看到 0 列
- 多群組：同時屬於 a、b 兩群組 → 看到 a ∪ b；再加一個表 reader 群組 → 全部列
- 先授權再宣告為列級受控 → 既有讀者全程看得到全部列
- 寫入時檢查：schema 規則與表規則重疊、未受控表建 row_set、仍有 row_set 時取消受控 → 都被拒絕
- 繞過：
  - 使用者 `SET ROLE` 成群組 role → 列數不變（`session_user` 不變）
  - 直接呼叫 `allowed_values` → 只回傳自己的值
  - 讀 `gateway_acl.row_grants` → permission denied
  - 建同名函式或改 `search_path` → 無法劫持
  - security_invoker = false 的 view → 依 §13 掃描並拒絕授權（測試掃描能抓到）
  - `SECURITY DEFINER` 函式 → 掃描能抓到
  - owner、BYPASSRLS、非 gateway role → 透過 `gw_passthrough` 照常讀全部（確認不影響既有應用）
- ParadeDB：在列級受控表上 `@@@`、`paradedb.score()` 結果正確（效能數據併入 M1 驗證報告）
- 同步：OpenFGA 停機 → 既有查詢正常；恢復後 Syncer 補齊；DBA 手動 `GRANT` → drift → 修正
- admin：一般 admin 移出 admin、停用 admin 帳號 → 403；初始 admin 可以；初始 admin 不可被移出

## 6. 我自己訂的預設值（可改）

| 項目 | 預設 |
|---|---|
| Syncer 輪詢間隔 | 2 秒 |
| Reconciler 週期 | 10 分鐘 + 啟動時 |
| 收回類同步逾時 | 5 秒（規格既有） |
| 失敗退避 | 1 秒起，倍增至 60 秒 |
| 分區欄位 distinct 上限 | 200 |
| 規則衝突的回應 | 409 + 衝突的既有規則 |

## 7. 風險

- 管理帳號的權限由操作者手動設定；檢查只能回報缺什麼，無法替他補
- OpenFGA `ReadChanges` 的變更保留期限：若 Syncer 長時間停擺而 token 過期，退回跑一次全量 Reconcile 再從最新位置開始
- 列級受控表對所有 gateway 使用者可見（0 列）：會出現在 SQL editor 的表清單裡，表名本來就能從系統目錄看到（§13 已接受）

## 8. 已確認的決定（2026-10-16）

- 整個 schema 的 reader 對列級受控表 → 全部列（`row_grants(g, s, '*', '*')`）
- 非 gateway 的 role → `gw_passthrough` policy 維持原狀，不要求 DBA 設 `BYPASSRLS`
- 映射沒有額外邏輯：移除 `scoped_reader` 與交集；衝突在寫入時檢查並拒絕
- 列級受控表的 `SELECT` 授予 `gw_managed`，沒有規則的人看到 0 列而不是 `permission denied`
- `row_set#table` 保留，用來判斷所屬的表，不解析物件 id

## 9. 已確認的決定（2026-10-17，W2 gate 後）

- 不收回 PUBLIC 的 `CONNECT`：使用者只能經 gateway 以 `u_<id>` 連線，資料可見性由表權限與 RLS 決定，收回 CONNECT 沒有安全效益，還會影響既有應用
- 每個連線的管理帳號是該 DB 的 owner，也可能是 superuser；拿掉 `owner_role` 與 `SET ROLE`，所有 op 直接以它執行。權限不足時 op 失敗並回報，不自動補
- gateway 不自動對目標 DB 做 migrate：`gateway_acl` 物件、`gw_managed`、`paradedb` 授權都由操作者照 `docs/target-db-setup.md` 手動執行；gateway 只做唯讀檢查（`targetdb.check`），在註冊連線與啟動時回報缺項
- 執行期的權限操作（建群組 role、GRANT/REVOKE、membership、宣告列級受控時 `ENABLE RLS` / `CREATE POLICY`）仍由 gateway 自動執行，這是權限模型本身
- RLS 函式用 `pg_has_role(..., 'USAGE')` 並 join `pg_roles`：管理帳號以 CREATEROLE 建立 role 時得到的隱含 membership 不繼承權限，不會被當成受控使用者；`row_grants` 裡的孤兒資料（role 已不存在）會被忽略，不會讓查詢報錯
- 群組與成員是全域的，同一個 cluster 上的多個連線共用 `g_*`、`u_*`，行為一致；群組底下還有規則時不可刪除
- 重放時角色或物件不存在的 op 略過並記錄（規則見 `permissions/types.py`）；`DropGroupRole` 先刪該群組的 `row_grants` 再刪 role

## 10. 已確認的決定（2026-10-18，W3 gate 後）

- 列級受控的宣告改存 OpenFGA（`db_table#row_column@column:<col>`），刪除 SQLite 的 `row_policies`：權限相關的狀態只有 OpenFGA 一個來源，Syncer / Reconciler / 重放都照 tuple 處理，RLS 被手動關掉時 Reconciler 會像其他 drift 一樣修回
- 宣告：RuleService 先以 executor 套用 `EnableRowPolicy`（有 op 被略過也算失敗），成功後才寫 tuple；寫 tuple 失敗時套用 `DisableRowPolicy` 撤回。取消宣告：先刪 tuple，再套用 `DisableRowPolicy`（失敗只記錄，Syncer 會再套用）
- PG 上有 `gw_*` policy 但 OpenFGA 沒有對應宣告時，Reconciler 只回報，不自動移除
- 由非管理帳號（例如 superuser 手動）授予的 membership，管理帳號撤不掉；Syncer 回報錯誤並註明需人工以 superuser 撤銷，不自動提權

## 11. 已確認的決定（2026-10-18，W4 gate 後）

- 群組是否存在改由 OpenFGA 的 `gateway:main#group@group:<name>` 決定，刪除 SQLite 的 `groups` 表。SQLite 不再存任何權限相關狀態，只剩使用者、session、連線設定、同步位置與稽核
- 說明文字放 SQLite 的 `descriptions` 表（key 為 OpenFGA 物件 id，例如 `group:analysts`），只是顯示用，不決定物件是否存在；刪除群組時一併刪除
- 建立群組：寫入 group tuple，`g_*` role 由 Syncer 依變更串流建立（與其他授權一樣）；刪除群組：群組底下沒有規則時，在同一次寫入刪除所有 member tuple 與 group tuple，內聯套用 `DROP ROLE`，回 `synced` / `pending`
- Reconciler：OpenFGA 沒有 group tuple 的 `g_*` role 直接 `DropGroupRole`（同一個 PG cluster 只有一套 gateway，`g_*` 都是 gateway 建的）
- Reconciler 是 drift 偵測，不是防 DB owner 的安全邊界：owner 本來就能關掉 RLS，owner 的竄改不在防護範圍內
- 新增 `w5-scan`：找出會繞過列級控制的 view，授權會讓群組讀到它們時（表規則，或 schema 規則涵蓋到它）拒絕。policy 用 `session_user` 判斷且表有 FORCE RLS，所以一般 owner 的非 invoker view 不會漏資料；會漏的是：
  - owner 是 superuser 或 BYPASSRLS、直接讀受控表的非 invoker view（RLS 對它整個跳過）
  - 讀到受控表、或查詢裡呼叫任何使用者函式的 materialized view（內容是 REFRESH 時以管理者身分算出來的）
  - 直接讀受控表的分割家族成員（父表或分割區）、但該成員本身沒有列級控制的非 invoker view（不論 owner）：RLS 只套用在查詢指名的那張表
  - 查詢裡呼叫 owner 為 superuser 或 BYPASSRLS 的 `SECURITY DEFINER` 函式的 view（保守處理，不分析函式內容）
  - 經由任何路徑讀到上述各項的 view（包含 invoker view）
  - 不分析 foreign table：建立 foreign server 與 user mapping 屬於 DB owner 的設定，不在防護範圍內
- `SECURITY DEFINER` 函式只回報，並標出 owner 是否會跳過 RLS
