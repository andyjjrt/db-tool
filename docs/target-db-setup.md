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
