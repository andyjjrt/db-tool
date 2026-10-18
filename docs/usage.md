# 使用方法

本文說明如何架設 DB Gateway、註冊目標資料庫，以及透過管理 API 管理群組與權限。系統設計見 [`architecture.md`](architecture.md)，目標 DB 的一次性設定見 [`target-db-setup.md`](target-db-setup.md)。

> **目前狀態**：已可用 OIDC 登入（見 [第 6 節](#6-登入與使用者)）。M1 剩下的開通（理由、週一失效）、個人 role 的 LOGIN／短效密碼與 reaper 尚未實作。

## 1. 需求

- Python 3.13、[uv](https://docs.astral.sh/uv/)
- OpenFGA（v1.22 以上，以 PostgreSQL 為 datastore）
- 目標資料庫：PostgreSQL 16 以上；要用全文搜尋時需要 ParadeDB（`pg_search`）
- 開發與測試：Docker（`docker compose`）

## 2. 開發環境

```sh
uv sync
docker compose up -d --wait     # ParadeDB (127.0.0.1:55432) + OpenFGA (127.0.0.1:58080)
```

測試：

```sh
uv run pytest tests/unit -q          # 不需要外部服務
uv run pytest tests/integration -q   # 需要 docker compose 的服務
uv run pytest tests/acceptance -q    # 以真實 u_* 登入驗證計畫第 5 節的每一條
uv run ruff check . && uv run pyright
```

整合與驗收測試會在 dev cluster 上建立、刪除 role 與資料庫，並以 advisory lock 依序執行。測試進行中不要另外在 dev cluster 上做實驗。

停止並清除資料：`docker compose down -v`。

## 3. 部署

### 3.1 建立 OpenFGA store

Gateway 不會自行建立 store，請先建一個並記下 id：

```sh
curl -s -X POST http://<openfga>:8080/stores \
  --json '{"name": "db-gateway"}'
# {"id":"01J...","name":"db-gateway",...}
```

授權模型（`src/db_gateway/permissions/model.json`）由 gateway 在啟動時寫入：store 裡最新的模型和程式內建的相同就直接沿用，不同就寫入一個新版本。

### 3.2 設定

設定一律從環境變數讀取，前綴為 `DBGW_`（`src/db_gateway/settings.py`）：

| 環境變數 | 預設 | 說明 |
|---|---|---|
| `DBGW_METADATA_DB_PATH` | `./var/metadata.sqlite3` | SQLite 檔案位置；啟動時自動 migrate |
| `DBGW_OPENFGA_API_URL` | `http://localhost:58080` | OpenFGA HTTP API |
| `DBGW_OPENFGA_STORE_ID` | 無 | 必填；沒設定時 app 仍可啟動，但管理 API 回 503 |
| `DBGW_OPENFGA_MODEL_ID` | 無 | 固定使用某個模型版本；通常不用設 |
| `DBGW_SYNC_POLL_INTERVAL_S` | `2` | Syncer 輪詢間隔（秒） |
| `DBGW_RECONCILE_INTERVAL_S` | `600` | Reconciler 週期（秒），啟動時另外跑一次 |
| `DBGW_REVOKE_SYNC_TIMEOUT_S` | `5` | 收回類操作內聯套用的逾時，超過回 `pending` |
| `DBGW_TARGET_CONNECT_TIMEOUT_S` | `5` | 連到目標 DB 的連線逾時 |
| `DBGW_SECRET_<REF>` | 無 | 各連線管理帳號的帳密，見下方 |
| `DBGW_OIDC_ISSUER` | 無 | OIDC issuer，例如 `https://kc.example.com/realms/corp`；沒設定時 `/auth/login` 回 503、其他 API 回 401 |
| `DBGW_OIDC_CLIENT_ID` | 無 | client id |
| `DBGW_OIDC_CLIENT_SECRET` | 無 | confidential client 的 secret；不設就當 public client（只用 PKCE） |
| `DBGW_OIDC_REDIRECT_URI` | 無 | 例如 `https://gw.example.com/auth/callback`；也用來推出 gateway 的 origin，供跨站檢查 |
| `DBGW_OIDC_SCOPES` | `openid email profile` | 要求的 scope |
| `DBGW_OIDC_LOGIN_CLAIM` | `preferred_username` | 對應 `users.login_key` 的 claim |
| `DBGW_OIDC_HTTP_TIMEOUT_S` | `10` | 呼叫 IdP 的逾時 |
| `DBGW_OIDC_JWKS_MIN_REFRESH_S` | `60` | 兩次 JWKS 重抓的最短間隔（含失敗） |
| `DBGW_COOKIE_SECURE` | `true` | 本機用 http 開發時設 `false` |
| `DBGW_SESSION_TTL_S` | `3600` | 登入 session 的絕對期限 |
| `DBGW_SESSION_IDLE_S` | `300` | 閒置多久後 session 失效 |

**連線帳密**：註冊連線時填的是 `admin_secret_ref`，不是密碼。gateway 會把 ref 轉成大寫、非英數字元換成 `_`，再讀取 `DBGW_SECRET_<REF>`。這個變數的值是 libpq 連線字串片段，只能包含 `user`、`password`、`passfile`、`sslcert`、`sslkey`、`sslrootcert`，而且必須有 `user`。host、port、dbname、sslmode 來自連線設定，secret 不能覆寫。

```sh
export DBGW_SECRET_PROD_ADMIN='user=gw_admin password=change-me'   # ref: prod-admin
```

**初始 admin**：寫在 `src/db_gateway/permissions/admin.py` 的 `INITIAL_ADMINS`（login key 清單）。要改這份清單，必須改程式碼並重新部署。清單是空的時候，啟動會記一筆 warning。

### 3.3 設定目標資料庫

每個目標 DB 都要由操作者手動執行一次設定 SQL，gateway 不會自動執行。完整步驟與管理帳號的前置條件見 [`target-db-setup.md`](target-db-setup.md)。摘要：

```sh
psql -d <db> -U <admin>    -v ON_ERROR_STOP=1 -f src/db_gateway/targetdb/setup.sql
psql -d <db> -U postgres   -v ON_ERROR_STOP=1 -f src/db_gateway/targetdb/setup_superuser.sql
```

### 3.4 啟動

```sh
uv run uvicorn db_gateway.app:create_app --factory --host 0.0.0.0 --port 8000 \
    --log-config src/db_gateway/logging_config.json
```

`--log-config` 會把 access log 裡 `/auth/` 路徑的 query string 拿掉，避免 authorization code 和 state 寫進 log；也可以改用 `--no-access-log`。前面若有 reverse proxy，它的 access log 也要做同樣的遮蔽。

啟動時會在背景執行以下工作，`/healthz` 不需要等它們完成：

- Syncer 開始同步。
- Reconciler 先跑一次，之後每 `DBGW_RECONCILE_INTERVAL_S` 秒跑一次。
- 對每個已註冊的連線執行唯讀設定檢查，有缺項就寫 log。

就算 OpenFGA 或某個目標 DB 連不上，app 仍會啟動。

- 健康檢查：`GET /healthz` → `{"status": "ok"}`
- API 文件：`GET /docs`（OpenAPI）

### 3.5 註冊連線

只有初始 admin 可以註冊連線。註冊前會以該連線的帳密執行唯讀設定檢查，有缺項就回 422 並列出缺少的項目，不會寫入任何東西。

```sh
curl -X POST $GW/api/admin/connections --json '{
  "name": "prod",
  "host": "db.internal",
  "port": 5432,
  "dbname": "analytics",
  "sslmode": "verify-full",
  "admin_secret_ref": "prod-admin",
  "default_privilege_owners": ["warehouse_owner"]
}'
```

- `name`：小寫英文開頭，只能用 `a-z0-9_-`，長度 1–41；建立後不能修改，因為它是 OpenFGA id 的一部分。
- `default_privilege_owners`：會在受控 schema 裡建表的 role。授予 schema reader 時，gateway 會為它們設定 `ALTER DEFAULT PRIVILEGES`，讓之後新建的表也自動授權。

註冊完成後，Syncer 會在下一輪把既有的群組 role 建到這個連線上。

## 4. 管理操作

以下範例的 `$GW` 是 gateway 的網址，並用 `curl --json`（curl 7.82 以上，會自動帶 JSON 的 content-type）送出請求，登入用的 `dbgw_session` cookie 略過不寫（瀏覽器登入後由 cookie 帶上）。所有請求都必須以 admin 身分登入。請求內容是 JSON，多出未定義的欄位會回 422。

### 4.1 群組與成員

```sh
# 建立群組（name：小寫英文開頭，a-z0-9_，最長 41）
curl -X POST $GW/api/admin/groups --json '{"name": "sales_a", "description": "A 區業務"}'

# 列出群組（含說明）
curl $GW/api/admin/groups

# 修改說明（null 會刪除說明）
curl -X PUT $GW/api/admin/groups/sales_a/description --json '{"description": "A 區業務團隊"}'

# 加入、移除成員（user_id 是 users.id）
curl -X POST   $GW/api/admin/groups/sales_a/members --json '{"user_id": 42}'
curl -X DELETE $GW/api/admin/groups/sales_a/members/42

# 刪除群組（群組底下不能還有授權規則）
curl -X DELETE $GW/api/admin/groups/sales_a
```

建立群組後，各連線上的 `g_sales_a` role 會由 Syncer 建立，通常幾秒內完成。其他物件的說明也可以用 `PUT /api/admin/descriptions` 設定，例如 `{"object_id": "db_table:prod/sales/orders", "description": "..."}`。

### 4.2 表與 schema 授權

```sh
# 整個 schema：現有與之後新建的表都能讀
curl -X POST $GW/api/admin/grants/schema-reader \
  --json '{"group": "analysts", "connection": "prod", "schema": "sales"}'

# 單一張表
curl -X POST $GW/api/admin/grants/table-reader \
  --json '{"group": "sales_a", "connection": "prod", "schema": "sales", "table": "customers"}'

# 收回：同一個端點改用 DELETE，body 相同
curl -X DELETE $GW/api/admin/grants/table-reader \
  --json '{"group": "sales_a", "connection": "prod", "schema": "sales", "table": "customers"}'

# 查詢規則（可用 group、connection 過濾）
curl "$GW/api/admin/rules?group=sales_a"
```

同一個群組在同一個 schema 上，不能同時有 schema reader 和 table reader。如果要從整個 schema 改成只開部分表，先收回 schema 規則，再加表規則。

授予後由 Syncer 套用，預設約 2 秒內生效。

### 4.3 列級控制

讓不同群組只看到同一張表裡的部分列，要兩個步驟：

**步驟一：宣告列級受控**，指定分區欄位：

```sh
curl -X POST $GW/api/admin/row-policies \
  --json '{"connection": "prod", "schema": "sales", "table": "orders", "column": "region"}'
```

這個操作會直接在 PG 上啟用 RLS，回應時就已經生效。限制：

- 分區欄位的 distinct 值不能超過 200 個；
- 一張表只能有一個分區欄位；
- 欄位型別必須能比較相等；
- 如果已經有群組讀得到會繞過這張表的 view，宣告會被拒絕（409），見 [4.5](#45-不安全的-view)。

宣告後的可見範圍：
- 有 table reader 或 schema reader 的群組：仍看得到全部列。
- 沒有任何規則的使用者：查得到這張表，但結果是 0 列。

**步驟二：授予 row set**：

```sh
curl -X POST $GW/api/admin/grants/row-set --json '{
  "group": "sales_a", "connection": "prod", "schema": "sales",
  "table": "orders", "column": "region", "value": "A"
}'
```

`sales_a` 的成員只會看到 `region = 'A'` 的列。一個使用者如果屬於多個群組，看到的是各群組允許值的聯集。

查詢與取消宣告：

```sh
curl "$GW/api/admin/row-policies?connection=prod"
curl -X DELETE $GW/api/admin/row-policies \
  --json '{"connection": "prod", "schema": "sales", "table": "orders"}'
```

表上還有 row set 規則時，不能取消宣告；要先收回所有 row set。

### 4.4 收回的時效

收回類操作包括移除成員、收回授權、刪群組、取消宣告。這些操作會在回應前直接套用到 PG：

| 回應 | 意義 |
|---|---|
| `200 {"status": "synced"}` | 所有連線都已生效 |
| `202 {"status": "pending"}` | 有連線在逾時內沒有完成（預設 5 秒）；OpenFGA 已經更新，Syncer 會在背景補上 |

收到 `pending` 時，可以查看 `GET /api/admin/sync`，確認是哪個連線還沒跟上。

### 4.5 不安全的 view

如果授權（table reader，或涵蓋到它的 schema reader）會讓群組讀到可能繞過列級控制的 view，gateway 會回 409，並在 `conflicts` 列出物件與原因：

| `reason` | 意思 | 修法 |
|---|---|---|
| `bypass_owner` | view 的 owner 是 superuser 或 BYPASSRLS | 改用一般 owner，或 `ALTER VIEW ... SET (security_invoker = true)` |
| `matview` | materialized view 的內容是 REFRESH 時算出來的 | 不要授予受 RLS 約束的群組 |
| `unprotected_partition` | view 讀的分割區或父表本身沒有列級控制 | 讓該家族成員也宣告列級受控，或改寫 view |
| `bypass_definer_function` | view 呼叫了 owner 會跳過 RLS 的 `SECURITY DEFINER` 函式 | 改函式 owner，或不要在 view 中呼叫它 |

更多說明見 [`target-db-setup.md`](target-db-setup.md#view-與-security-definer-函式)。

### 4.6 admin 管理

```sh
curl $GW/api/admin/admins                                  # 初始 admin 會標示 "initial": true
curl -X POST   $GW/api/admin/admins --json '{"user_id": 7}'    # 任何 admin 都可以新增
curl -X DELETE $GW/api/admin/admins/7                      # 只有初始 admin 可以移除
```

初始 admin 不能被移除。對不是 admin 的使用者執行移除，會回 404。

### 4.7 使用者

只有登錄過的使用者能登入（初始 admin 例外，見第 6 節）。`login_key` 是 IdP 那個 claim 的值，區分大小寫。

```sh
curl $GW/api/admin/users                                   # ?include_disabled=false 可排除停用者
curl $GW/api/admin/users --json '{"login_key": "alice", "email": "alice@example.com"}'   # 201；重複回 409
curl -X PATCH $GW/api/admin/users/7 --json '{"login_key": "alice.chen"}'  # 例如 IdP 改了 username
curl -X POST  $GW/api/admin/users/7/disable                # 下一個請求起就被登出
curl -X POST  $GW/api/admin/users/7/enable
curl -X POST  $GW/api/admin/users/7/unbind                 # 解除 OIDC sub 綁定，下次登入重新綁
```

- 停用：初始 admin 不能被停用；停用 admin 帳號只有初始 admin 能做；不能停用自己。
- `login_key` 不能改成初始 admin 的 key，初始 admin 的 key 也不能被改掉。
- `unbind`：用在使用者在 IdP 被重建、`sub` 變了的時候。初始 admin 不能 unbind（他們的 `sub` 寫在程式裡）；unbind admin 帳號只有初始 admin 能做。回應的 `oidc_bound` 表示目前是否已綁定。

## 5. 監控與維運

### 5.1 同步狀態

```sh
curl $GW/api/admin/sync              # 每個連線的 continuation_token、last_applied_at、last_error、fail_count
curl -X POST "$GW/api/admin/sync?connection=prod"   # 立刻同步一次
```

`fail_count` 持續增加，表示該連線的串流卡住了，原因寫在 `last_error`。這時 token 不會前進，問題排除後會自動補上。常見原因：

| `last_error` | 處理 |
|---|---|
| `target X unreachable: connect failed` | 確認網路與目標 DB 是否正常 |
| `credentials invalid` / `secret missing or invalid` | 檢查 `DBGW_SECRET_<REF>` |
| `InsufficientPrivilege`（42501） | 管理帳號權限不足，依 `target-db-setup.md` 補齊；gateway 不會自行提權 |
| `DependentObjectsStillExist`（2BP01），發生在刪群組時 | 該 role 在其他 DB 仍有權限；那些 DB 的連線同步後就會解除 |
| membership 由其他 grantor 授予 | 由 superuser 手動執行 `REVOKE ... GRANTED BY ...` |

### 5.2 drift 與 reconcile

```sh
curl "$GW/api/admin/drift?connection=prod"                     # 只看，不修改
curl -X POST "$GW/api/admin/reconcile?connection=prod&dry_run=true"
curl -X POST "$GW/api/admin/reconcile"                         # 修正所有連線
```

回應以連線名稱為 key，每個連線一份報告，內容包括：
- `fixes`：已修正的項目；`dry_run` 時是計畫修正的項目。
- `reported`：只回報、不會自動修正的項目。
- `skipped`、`failed`、`error`、`target_unavailable`。

不指定 `connection` 時一律回 200；指定單一連線、而它的目標 DB 連不上時，回 503 並附上報告。

`reported` 裡的常見種類：

| kind | 意思 |
|---|---|
| `unsafe_view` | 有群組讀得到不安全的 view |
| `definer_function` | owner 會跳過 RLS、且 `gw_managed` 可以執行的 `SECURITY DEFINER` 函式 |
| `undeclared_policy` | 表上有 `gw_*` policy，但沒有宣告列級受控 |
| `extra_policy` | 列級受控表上有其他 permissive policy |
| `membership_grantor` | 有 membership 是由管理帳號以外的 role 授予的 |
| `managed_usage_missing` | 新 schema 的 `gw_managed` 缺少 USAGE，要依設定文件補上 |
| `undroppable_group_role` | 孤兒 `g_*` role 刪不掉（權限不足或仍有依賴） |
| `user_not_managed` | 有 `u_*` role 不是 `gw_managed` 的成員 |

### 5.3 稽核

`audit_log` 只能新增，不能修改或刪除，由 trigger 保證：

- `kind = 'admin'`：每一次管理操作，包含寫入的 tuple。
- `kind = 'sync'`：drift 修正，以及同步時的錯誤。

```sh
sqlite3 var/metadata.sqlite3 \
  "SELECT ts, kind, user_id, error, detail FROM audit_log ORDER BY id DESC LIMIT 20"
```

### 5.4 錯誤碼

| 狀態碼 | 情況 |
|---|---|
| 401 | 沒有登入，或 session 已過期、閒置逾時、使用者被停用 |
| 403 | 不是 admin；一般 admin 執行只限初始 admin 的操作；跨站的寫入請求（`Origin` 不是 gateway 自己） |
| 404 | 群組、連線、使用者或宣告不存在 |
| 409 | 規則衝突、群組已存在、群組還有規則、不安全的 view |
| 422 | 輸入不合法、註冊連線時設定檢查不通過 |
| 502 | 目標 DB 拒絕操作（例如權限不足），附錯誤類別與 SQLSTATE |
| 503 | OpenFGA 連不上、目標 DB 連不上或查詢失敗 |

回應不會包含 secret 片段，也不會包含 PG 錯誤訊息原文。

## 6. 登入與使用者

### 6.1 設定 IdP

在 IdP（例如 Keycloak）建立一個 OIDC client：

- Standard flow（Authorization Code）開啟，PKCE method 設 `S256`。
- Valid redirect URI 設成 `DBGW_OIDC_REDIRECT_URI`。
- 登入 claim（預設 `preferred_username`）必須是使用者自己改不了的值。Keycloak 要確認 realm 的 `Edit username` 是關閉的。

### 6.2 登入流程

1. 瀏覽器開 `$GW/auth/login?next=/某頁`，gateway 導向 IdP。`next` 只接受站內路徑，其他值一律導回 `/`。
2. 登入後 IdP 導回 `/auth/callback`。gateway 驗證 ID token（簽章、iss、aud、azp、exp、nonce），並確認 callback 回到的是發起登入的同一個瀏覽器。
3. 以登入 claim 查 `users.login_key`：
   - 查不到或已停用 → 403。
   - 帳號第一次登入時綁定 token 的 `sub`；之後 `sub` 不同一律 403。
4. 成功後設定 `dbgw_session` cookie（HttpOnly、SameSite=Lax、Secure），導回 `next`。session 閒置 `DBGW_SESSION_IDLE_S` 秒或超過 `DBGW_SESSION_TTL_S` 秒就失效。
5. `POST /auth/logout` 結束 session（回 204）。只登出 gateway，不會登出 IdP。

`GET /api/me` 回傳目前使用者：`{id, login_key, email, display_name, is_admin, is_initial_admin}`。

登入與登出都記在 `audit_log`（kind `login`／`logout`）；失敗的登入不記。

### 6.3 初始 admin

初始 admin 寫在 `src/db_gateway/permissions/admin.py`，login key 對應一個固定的 OIDC `sub`：

```python
INITIAL_ADMINS: Mapping[str, str] = MappingProxyType({"andyjjrt": "<sub>"})
```

第一次部署時 `sub` 還是空字串，所以這位初始 admin 無法登入。請照下列步驟設定：

1. 用該帳號登入一次，會得到 403。
2. gateway 的 log 會出現一行 warning，裡面有這次登入的 `sub` 和可以直接貼上的程式碼：
   ```
   initial admin 'andyjjrt' has no pinned OIDC subject; login refused. To allow this login, pin it in src/db_gateway/permissions/admin.py: INITIAL_ADMINS = MappingProxyType({"andyjjrt": "8f14e45f-..."})
   ```
3. 把它寫進 `admin.py`，重新部署，再登入一次。這次會自動建立 `users` 資料。

`sub` 釘好之後，若有其他人以相同的 login key 登入，`sub` 不符就會被拒絕，log 也不會印出他的 `sub`。其他使用者則要先由 admin 用 `/api/admin/users` 登錄（第 4.7 節）。

### 6.4 目標 DB 上的個人 role（尚未接上）

以下屬於 M1 的後半段，目前只有底層函式：

- 使用者開始一個查詢 session 時，呼叫 `provisioner.on_session_start(...)`：
  - 在目標 DB 建立 `u_<id>`（LOGIN、INHERIT），並加入 `gw_managed`；
  - 依 OpenFGA 補齊群組 membership。如果使用者被加入群組時個人 role 還不存在，Syncer 會先略過那次授權，由這一步補上。
- 使用者以 `u_<id>` 連到目標 DB 查詢。能看到什麼完全由 PG 決定，gateway 不在查詢路徑上。
