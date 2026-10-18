# DB Gateway

PostgreSQL permission management backed by OpenFGA. Target database setup is manual:
see [target database setup](docs/target-db-setup.md).

## Admin API

Run `uv run uvicorn db_gateway.app:create_app --factory` after configuring
`DBGW_OPENFGA_STORE_ID`, `DBGW_OPENFGA_API_URL` and `DBGW_METADATA_DB_PATH`.
The lifespan starts permission sync and startup/periodic reconciliation; an OpenFGA
outage does not stop the application. Connection credentials use a secret reference,
resolved as `DBGW_SECRET_<NORMALIZED_REF>` containing libpq `user` / `password` fields.

`/docs` describes `/api/admin`: groups, descriptions, members, schema/table/row-set
grants, rule listings, row policies, connection registration, sync, reconcile, drift,
and admins. `POST /reconcile?dry_run=true` and `GET /drift` only report planned fixes.
Grant bodies use `group`, `connection`, `schema`, plus `table`, `column`, `value`
as appropriate. DELETE grant endpoints take the same JSON body.
Revokes return `200 {"status":"synced"}` or `202 {"status":"pending"}`.
Conflicts return 409 with conflicting rules; missing resources 404, invalid input or
target setup 422, forbidden admin operations 403, and an unavailable permission store
or target database 503. Runtime connection failures include a safe reason
(`connect failed`, `credentials invalid`, or `secret missing or invalid`).
Query failures return 503 with the error class and SQLSTATE, without server messages.
A permission operation the target rejects (for example a missing privilege of the admin
account) returns 502 with the error class and SQLSTATE; the gateway never escalates.
Bulk reconcile/drift calls always return 200 with every per-connection report;
single-connection calls return 503 only for an unavailable target, retaining the
report and any applied fixes. Other reconcile failures stay in the report.
Startup target checks run in the background; startup and registration checks use
a five-second connection timeout. Runtime connections use
`DBGW_TARGET_CONNECT_TIMEOUT_S` (default 5 seconds).
`POST /api/admin/connections` is restricted to `INITIAL_ADMINS`, the code-defined
initial administrators. Ordinary admins receive 403 before credentials are resolved
or a target connection is attempted.

Login awaits M1: `current_user` currently rejects every request with 401
(`login not implemented, M1`). There is no header or environment authentication bypass.
Tests supply identities only through FastAPI dependency overrides.
