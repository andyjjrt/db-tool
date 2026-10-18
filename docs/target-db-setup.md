# 目標資料庫設定

Gateway 不會自動修改目標資料庫。操作者須在每個目標 DB 以該連線的管理帳號手動執行
`src/db_gateway/targetdb/setup.sql`，使 `gateway_acl` 物件由管理帳號擁有；再由 superuser
執行 `src/db_gateway/targetdb/setup_superuser.sql`。Gateway 的
`targetdb.check` 只讀取設定並回報缺項，不會替操作者執行 SQL。

## 管理帳號前置條件

每個連線的管理帳號必須是該 DB 的 owner，或 superuser。非 superuser 管理帳號還需要
`CREATEROLE`、`gw_managed` 的 `ADMIN OPTION`，並且對受控 schema 中每張表的 owner
具有繼承權限，以及屬於 `default_privilege_owners` 設定中的每個角色。

由 DBA 或 superuser 設定資料庫 owner 與 CREATEROLE：

```sql
ALTER DATABASE <db> OWNER TO <admin>;
ALTER ROLE <admin> CREATEROLE;
```

`<admin>` 必須繼承每個受控表 owner 與每個 default privilege owner 的權限：

```sql
GRANT <table_owner> TO <admin>;
GRANT <default_privilege_owner> TO <admin>;
```

確保管理帳號有 `ADMIN OPTION`。只有在 `gw_managed` 於管理帳號執行 `setup.sql` 之前就已存在時才需要，由 superuser 執行（管理帳號自己建立 `gw_managed` 時已自動取得）：

```sql
GRANT gw_managed TO <admin> WITH ADMIN OPTION, INHERIT FALSE, SET FALSE;
```

PostgreSQL 16 以上，管理帳號以 `CREATEROLE` 建立 `gw_managed` 和 `g_*` 時會有
ADMIN-only membership；在預設 `createrole_self_grant=''` 下，此 membership 既不繼承也
不能 `SET ROLE`，因此不會被當成 managed user。不要額外授予管理帳號可繼承或可
`SET ROLE` 的 `gw_managed` membership。若另行授予 `ADMIN OPTION`，務必將 INHERIT 和 SET
都設為 FALSE。

## 安裝 ParadeDB 並套用設定

先以連線管理帳號執行核心設定。不可用 superuser 取代這一步，否則
`gateway_acl`、表與 SECURITY DEFINER 函式會由 superuser 擁有，管理帳號可能無法維護
`row_grants` 或更新函式：

```sh
psql -d <db> -v ON_ERROR_STOP=1 -f src/db_gateway/targetdb/setup.sql
```

接著由 superuser 執行：

```sh
psql -d <db> -v ON_ERROR_STOP=1 -f src/db_gateway/targetdb/setup_superuser.sql
```

`setup.sql` 會建立 `gw_managed`、`gateway_acl`、`row_grants`、三個 RLS 函式及
`gateway_acl.setup_version`。`setup_superuser.sql` 會在 `pg_search` 尚未安裝時建立
extension，並授予 `paradedb` schema 的 `USAGE` 和其中所有函式的 `EXECUTE` 給
`gw_managed`。若非 superuser DB owner 執行這兩項 ParadeDB GRANT，PostgreSQL 只會印出
`no privileges were granted` 警告，並不會替管理帳號授予權限；請務必改由 superuser
執行 `setup_superuser.sql`。
`row_grants` 不授權給 PUBLIC 或 `gw_managed`；`gateway_acl` 的 `USAGE` 與三個 RLS
函式的 `EXECUTE` 保留給 PUBLIC。

對每個 managed schema，由其 owner 或 DBA 執行：

```sql
GRANT USAGE ON SCHEMA <managed_schema> TO gw_managed;
```

本設定不會撤銷 PUBLIC 的資料庫 `CONNECT`。只有在操作者因其他政策自行撤銷
PUBLIC `CONNECT` 時，才需額外執行：

```sql
GRANT CONNECT ON DATABASE <db> TO gw_managed;
```

更新 ParadeDB extension 後，superuser 必須重跑 `setup_superuser.sql`，讓新函式也取得
授權：

```sql
ALTER EXTENSION pg_search UPDATE;
GRANT USAGE ON SCHEMA paradedb TO gw_managed;
GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA paradedb TO gw_managed;
```

## 驗證設定

`POST /api/admin/connections` 只允許程式碼中 `INITIAL_ADMINS` 的初始管理者登錄連線。
一般 admin 會在讀取 secret 或嘗試目標連線之前收到 403；新增一般 admin 並不會授予
登錄連線的權限。登錄時執行唯讀檢查，連線逾時為 5 秒；啟動檢查在背景執行，
不會阻塞 `/healthz`。

以連線管理帳號開啟 psycopg 連線，呼叫唯讀檢查：

```python
from db_gateway.targetdb import check_target_db

problems = await check_target_db(
    conn,
    schemas=("sales", "analytics"),
    default_privilege_owners=("warehouse_owner",),
)
```

回傳空清單表示目前設定符合程式版本。每筆 `Problem` 都有穩定的 `code`、說明
`message`，以及可選的 `remediation` 提示；提示只供操作者參考，不會執行。若有缺項，
依 `code` 和提示修正後再檢查。`conn` 必須是 idle，不能已有開啟的 transaction；否則
檢查會直接報錯，不會把呼叫者的 transaction 改成 READ ONLY。檢查在自己的 READ ONLY
transaction 中執行，不會變更 DB。

Gateway 建立的 `u_*` 個人 role 使用 `INHERIT`，且 `gw_managed` membership 可繼承；
不得將 `u_*` 改成 `NOINHERIT` 或把 membership 設為 `INHERIT FALSE`。
`createrole_self_grant` 必須保持空值；W3 的權限執行器會在建立 role 的 transaction
中暫時執行 `SET LOCAL createrole_self_grant = ''`。checker 會回報可讓管理帳號變成
managed user 的設定或 membership，包括 admin 已經取得 `USAGE` 或 `SET` 的情形。

## 升級設定

目前設定版本為 1。`setup.sql` 開頭的 `-- setup_version: 1` 是版本來源；
checker 會從該標記讀取版本，並確認 SQL guard 與版本 row 的值一致。

未來每次修改 canonical SQL 時，必須同步提高 `setup.sql` 中的三處版本值（開頭的 `-- setup_version:`、guard 的 `current_version >`、`VALUES (TRUE, n)`；`SETUP_VERSION` 由此自動讀取，三處不一致時 import 即失敗），並在此
列出升級差異及操作者需要執行的 SQL。資料庫版本較舊時，檢查會回報
`setup_version_outdated`，提示執行本文件中的升級步驟；資料庫版本較新時會回報
`setup_version_newer`，表示 gateway 程式需先升級。

## 維運範圍與 drift

同一個 PostgreSQL cluster 只能部署一套 gateway。`g_*`、`u_*` 是 cluster 共用
role；同一套 gateway 的多個連線可以共用它們，但不同部署不能共用該命名空間。
Reconciler 會撤銷未出現在 OpenFGA 的群組授權，並刪除孤兒 `g_*` role。
`gateway_acl.row_grants` 整張表由 gateway 管理；手動加入的資料會在 reconcile 時刪除。
群組刪除後若 role 因跨 DB 依賴或權限而無法刪除，drift 會回報
`undroppable_group_role`；操作者須先移除依賴，再手動 `DROP ROLE` 或重新 reconcile。

由其他 grantor（例如 superuser）授予的 membership，連線管理帳號可能無權撤銷。
Syncer 會記錄錯誤、退避且不前進同步位置；Reconciler 也會回報。
請由 superuser 人工執行對應的 `REVOKE ... GRANTED BY ...`，gateway 不會自行提權。
新 schema 缺少 `gw_managed` 的 USAGE 也只回報，須由操作者依前述設定補齊。

Reconciler 是 drift 偵測，不是對 DB owner 的安全邊界。DB owner 本來就能關閉 RLS、
改寫 policy 或建立其他資料存取路徑。Foreign table 不分析；foreign server 與
user mapping 屬於 DB owner 的設定與責任。

## View 與 SECURITY DEFINER 函式

授予 table reader 或 schema reader 前，gateway 會掃描該連線全部列級受控表。
如果授權包含會洩漏資料的 view 或 materialized view，就回 409，列出物件與原因。
宣告新的列級受控表時也會先掃描；若任何群組已有該不安全 relation 或其 schema
的 reader 規則，宣告同樣回 409，在任何 PG 或 OpenFGA 寫入之前拒絕。
沒有讀者的 view 不會阻止宣告；之後的授權仍會被檢查。

包括 superuser / BYPASSRLS owner 的非 invoker view、快照型 materialized view、
未受控分割家族成員的非 invoker view，以及呼叫 bypass owner 的 SECURITY DEFINER
函式或間接讀到上述物件的 view。一般 owner 的 view 在 FORCE RLS 與 `session_user`
policy 下不會因此被判為洩漏。

對直接讀表的普通 view，可由 owner 執行：

```sql
ALTER VIEW <schema>.<view> SET (security_invoker = true);
```

或改用不具有 superuser / BYPASSRLS 的 owner。`security_invoker` 無法修復底層的
不安全 view、SECURITY DEFINER 呼叫或 materialized view 快照；須先修復底層路徑，
讓需要直接查詢的分割家族成員都有列級控制，或撤銷相關 reader 規則。
不安全 materialized view 不應授予受 RLS 約束的群組。

Reconciler 的 `unsafe_view` 與 `definer_function` 都只回報，不會自動改 owner、
view 設定或 EXECUTE 權限。SECURITY DEFINER 函式 owner 能跳過 RLS 且
`gw_managed` 有效擁有 EXECUTE 時會回報；函式內容不分析。請改 owner，
或由 owner / DBA 撤銷 PUBLIC、`gw_managed` 或其他繼承來源的 EXECUTE；
只從 `gw_managed` REVOKE 並不能消除 PUBLIC 帶來的權限。
