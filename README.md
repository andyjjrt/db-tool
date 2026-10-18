# DB Gateway

讓使用者透過瀏覽器以 SQL 查詢 ParadeDB（PostgreSQL 17 + `pg_search`），並以群組管理「誰能讀哪些 schema、表，以及表裡的哪些列」。

- 權限存在 OpenFGA，是唯一的來源；gateway 把它同步成目標 DB 上的 `GRANT` 與 RLS policy。
- 每個使用者以自己的 `u_<id>` role 連線，能看到的資料完全由 PostgreSQL 決定。
- 列級控制：同一張表可以讓不同群組只看到某個欄位特定值的列，可搭配 ParadeDB 的 `@@@` 與 `paradedb.score()`。
- 收回權限時在 5 秒內生效；Syncer 持續同步，Reconciler 定期修正被手動改掉的權限。
- gateway 不會自動修改目標 DB 的結構，也不會提權；目標 DB 的一次性設定由操作者手動執行。

> 目前狀態：權限模型、管理 API 與 OIDC 登入已完成；M1 的開通、個人 role 啟用與 reaper 尚未實作。

## 快速開始（開發環境）

```sh
uv sync
docker compose up -d --wait            # ParadeDB + OpenFGA
uv run pytest -q                       # unit + integration + acceptance
uv run ruff check . && uv run pyright
```

啟動 app：

```sh
export DBGW_OPENFGA_STORE_ID=<store id>   # 先在 OpenFGA 建立 store，見 docs/usage.md
export DBGW_OIDC_ISSUER=... DBGW_OIDC_CLIENT_ID=... DBGW_OIDC_REDIRECT_URI=http://localhost:8000/auth/callback
export DBGW_COOKIE_SECURE=false           # 本機 http
uv run uvicorn db_gateway.app:create_app --factory --log-config src/db_gateway/logging_config.json
```

## 文件

| 文件 | 內容 |
|---|---|
| [docs/architecture.md](docs/architecture.md) | 系統設計：元件、權限模型、RLS、同步、鎖、失敗時的行為、已知限制 |
| [docs/usage.md](docs/usage.md) | 使用方法：部署、設定、註冊連線、管理 API 範例、監控與維運 |
| [docs/target-db-setup.md](docs/target-db-setup.md) | 目標資料庫的一次性設定、管理帳號前置條件、drift 與不安全 view 的處理 |
| [docs/plans/permission-model.md](docs/plans/permission-model.md) | 實作計畫與各階段的決策紀錄 |

## 專案結構

```
src/db_gateway/
  app.py              FastAPI app 與 lifespan（啟動 Syncer、Reconciler）
  api/                管理 API、登入路由與身分檢查
  auth/               OIDC client、登入 state、登入 session
  permissions/        OpenFGA store、映射、RuleService、Syncer、Reconciler、掃描器
  provisioner/        個人 role 與 session 開始時的 membership 補齊
  targetdb/           目標 DB 設定 SQL 與唯讀檢查
  metadata/           SQLite 連線、migration、稽核
tests/
  unit/ integration/ acceptance/
```
