"""Admin operations. Identity is supplied only by the M1 dependency boundary."""

import json
from dataclasses import asdict
from typing import Annotated, Any, Literal

import psycopg
from fastapi import APIRouter, Depends, HTTPException, Request, Response
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field, StrictStr, field_validator

from db_gateway import metadata
from db_gateway.api.auth import permission_store, require_admin, require_initial_admin
from db_gateway.metadata import audit
from db_gateway.permissions import ids
from db_gateway.permissions.admin import AdminUser, list_admins
from db_gateway.permissions.context import ConnectionInfo, admin_conninfo, load_connections
from db_gateway.permissions.ids import InvalidInput
from db_gateway.permissions.reconciler import ReconcileReport
from db_gateway.permissions.rules import NotFound, RuleConflict, RuleService
from db_gateway.permissions.store import PermissionStore, Tuple
from db_gateway.targetdb.check import check_target_db

router = APIRouter(prefix="/api/admin", tags=["admin"])
Actor = Annotated[AdminUser, Depends(require_admin)]
Store = Annotated[PermissionStore, Depends(permission_store)]


def rule_service(request: Request) -> RuleService:
    return request.app.state.rules


Rules = Annotated[RuleService, Depends(rule_service)]


class Input(BaseModel):
    model_config = ConfigDict(extra="forbid")


class GroupInput(Input):
    name: str
    description: str | None = None


class DescriptionInput(Input):
    description: str | None = None


class ObjectDescriptionInput(DescriptionInput):
    object_id: str


class UserInput(Input):
    user_id: int = Field(ge=1)


class SchemaGrant(Input):
    group: str
    connection: str
    schema_name: str = Field(alias="schema")


class TableGrant(SchemaGrant):
    table: str


class RowGrant(TableGrant):
    column: str
    value: str


class TableInput(Input):
    connection: str
    schema_name: str = Field(alias="schema")
    table: str


class PolicyInput(TableInput):
    column: str


class ConnectionInput(Input):
    name: str = Field(pattern=r"^[a-z][a-z0-9_-]{0,40}$")
    host: str = Field(min_length=1)
    port: int = Field(default=5432, ge=1, le=65535)
    dbname: str = Field(min_length=1)
    sslmode: Literal["disable", "allow", "prefer", "require", "verify-ca", "verify-full"] = (
        "require"
    )
    admin_secret_ref: str = Field(min_length=1)
    default_privilege_owners: list[StrictStr]

    @field_validator("default_privilege_owners")
    @classmethod
    def nonempty_owners(cls, owners: list[str]) -> list[str]:
        if any(not owner.strip() for owner in owners):
            raise InvalidInput("default_privilege_owners must contain only non-empty strings")
        return owners


def revoke_response(response: Response, status: str) -> dict[str, str]:
    response.status_code = 200 if status == "synced" else 202
    return {"status": status}


async def require_connection(request: Request, name: str) -> None:
    if name not in {info.name for info in await load_connections(request.app.state.metadata)}:
        raise NotFound(f"connection not found: {name}")


async def validate_connection(info: ConnectionInfo) -> list[dict[str, Any]]:
    """Read-only registration/startup check, with credentials for this exact target."""
    try:
        conninfo = admin_conninfo(info)
    except (psycopg.ProgrammingError, KeyError, ValueError):
        return [
            {
                "code": "connection_check_failed",
                "message": (
                    f"secret {info.admin_secret_ref} missing or not a valid credentials fragment"
                ),
                "remediation": None,
            }
        ]
    try:
        conn = await psycopg.AsyncConnection.connect(conninfo, connect_timeout=5)
    except psycopg.OperationalError as exc:
        return [{"code": "connection_check_failed", "message": str(exc), "remediation": None}]
    try:
        async with conn:
            # Registration has no managed-schema selection yet. Check global setup
            # and role premises, not ownership of unrelated/extension relations.
            return [
                asdict(problem)
                for problem in await check_target_db(
                    conn, schemas=(), default_privilege_owners=info.default_privilege_owners
                )
            ]
    except psycopg.Error:
        return [
            {
                "code": "connection_check_failed",
                "message": f"target {info.name} validation failed",
                "remediation": None,
            }
        ]


@router.get("/groups")
async def groups(actor: Actor, rules: Rules) -> Any:
    return await rules.list_groups()


@router.post("/groups", status_code=201)
async def create_group(body: GroupInput, actor: Actor, rules: Rules) -> dict[str, str]:
    await rules.create_group(actor, body.name, body.description)
    return {"name": body.name}


@router.delete("/groups/{name}")
async def delete_group(name: str, actor: Actor, rules: Rules, response: Response) -> dict[str, str]:
    return revoke_response(response, await rules.delete_group(actor, name))


@router.put("/groups/{name}/description")
async def group_description(
    name: str, body: DescriptionInput, actor: Actor, rules: Rules
) -> dict[str, str]:
    if name not in {group.name for group in await rules.list_groups()}:
        raise NotFound(f"group not found: {name}")
    await rules.set_description(actor, ids.group(name), body.description)
    return {"status": "updated"}


@router.put("/descriptions")
async def description(body: ObjectDescriptionInput, actor: Actor, rules: Rules) -> dict[str, str]:
    await rules.set_description(actor, body.object_id, body.description)
    return {"status": "updated"}


@router.post("/groups/{name}/members", status_code=201)
async def add_member(name: str, body: UserInput, actor: Actor, rules: Rules) -> dict[str, str]:
    await rules.add_member(actor, name, body.user_id)
    return {"status": "accepted"}


@router.delete("/groups/{name}/members/{user_id}")
async def remove_member(
    name: str, user_id: int, actor: Actor, rules: Rules, response: Response
) -> dict[str, str]:
    return revoke_response(response, await rules.remove_member(actor, name, user_id))


@router.post("/grants/schema-reader", status_code=201)
async def grant_schema(body: SchemaGrant, actor: Actor, rules: Rules) -> dict[str, str]:
    await rules.grant_schema_reader(actor, body.group, body.connection, body.schema_name)
    return {"status": "accepted"}


@router.delete("/grants/schema-reader")
async def revoke_schema(
    body: SchemaGrant, actor: Actor, rules: Rules, response: Response
) -> dict[str, str]:
    return revoke_response(
        response,
        await rules.revoke_schema_reader(actor, body.group, body.connection, body.schema_name),
    )


@router.post("/grants/table-reader", status_code=201)
async def grant_table(body: TableGrant, actor: Actor, rules: Rules) -> dict[str, str]:
    await rules.grant_table_reader(actor, body.group, body.connection, body.schema_name, body.table)
    return {"status": "accepted"}


@router.delete("/grants/table-reader")
async def revoke_table(
    body: TableGrant, actor: Actor, rules: Rules, response: Response
) -> dict[str, str]:
    return revoke_response(
        response,
        await rules.revoke_table_reader(
            actor, body.group, body.connection, body.schema_name, body.table
        ),
    )


@router.post("/grants/row-set", status_code=201)
async def grant_row(body: RowGrant, actor: Actor, rules: Rules) -> dict[str, str]:
    await rules.grant_row_set(
        actor, body.group, body.connection, body.schema_name, body.table, body.column, body.value
    )
    return {"status": "accepted"}


@router.delete("/grants/row-set")
async def revoke_row(
    body: RowGrant, actor: Actor, rules: Rules, response: Response
) -> dict[str, str]:
    return revoke_response(
        response,
        await rules.revoke_row_set(
            actor,
            body.group,
            body.connection,
            body.schema_name,
            body.table,
            body.column,
            body.value,
        ),
    )


@router.get("/rules")
async def list_rules(
    request: Request,
    actor: Actor,
    store: Store,
    group: str | None = None,
    connection: str | None = None,
) -> list[Tuple]:
    if connection is not None:
        await require_connection(request, connection)
    if group is not None and not await store.read(ids.GATEWAY_MAIN, "group", ids.group(group)):
        raise NotFound(f"group not found: {group}")
    found: list[Tuple] = []
    for rule in await store.read():
        if rule.relation != "reader" or (
            group is not None and rule.user != ids.group_member(group)
        ):
            continue
        if connection is not None:
            parser = {
                "db_schema": ids.parse_db_schema,
                "db_table": ids.parse_db_table,
                "row_set": ids.parse_row_set,
            }.get(rule.object.partition(":")[0])
            if parser is None or parser(rule.object).connection != connection:
                continue
        found.append(rule)
    return found


@router.get("/row-policies")
async def row_policies(
    request: Request, actor: Actor, store: Store, connection: str | None = None
) -> list[dict[str, str]]:
    if connection is not None:
        await require_connection(request, connection)
    policies = []
    for rule in await store.read():
        if rule.relation == "row_column" and rule.object.startswith("db_table:"):
            ref = ids.parse_db_table(rule.object)
            if connection is None or ref.connection == connection:
                policies.append({**asdict(ref), "column": ids.parse_column(rule.user)})
    return policies


@router.post("/row-policies", status_code=201)
async def declare_policy(body: PolicyInput, actor: Actor, rules: Rules) -> dict[str, str]:
    await rules.declare_row_policy(
        actor, body.connection, body.schema_name, body.table, body.column
    )
    return {"status": "synced"}


@router.delete("/row-policies")
async def undeclare_policy(
    body: TableInput, actor: Actor, rules: Rules, response: Response
) -> dict[str, str]:
    error = await rules.undeclare_row_policy(actor, body.connection, body.schema_name, body.table)
    return revoke_response(response, "pending" if error is not None else "synced")


@router.get("/connections")
async def connections(request: Request, actor: Actor) -> Any:
    return await load_connections(request.app.state.metadata)


@router.post("/connections", status_code=201)
async def register_connection(
    body: ConnectionInput,
    request: Request,
    actor: Annotated[AdminUser, Depends(require_initial_admin)],
) -> dict[str, str]:
    db = request.app.state.metadata
    info = ConnectionInfo(
        id=0,
        **body.model_dump(exclude={"default_privilege_owners"}),
        default_privilege_owners=tuple(body.default_privilege_owners),
    )
    problems = await validate_connection(info)
    if problems:
        raise HTTPException(status_code=422, detail={"missing": problems})
    async with metadata.transaction(db):
        async with db.execute("SELECT id FROM connections WHERE name = ?", (body.name,)) as cur:
            if await cur.fetchone() is not None:
                raise RuleConflict(f"connection already exists: {body.name}")
        cursor = await db.execute(
            "INSERT INTO connections "
            "(name, host, port, dbname, sslmode, admin_secret_ref, default_privilege_owners) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (
                body.name,
                body.host,
                body.port,
                body.dbname,
                body.sslmode,
                body.admin_secret_ref,
                json.dumps(body.default_privilege_owners),
            ),
        )
        await audit.record(
            db,
            "admin",
            user_id=actor.id,
            connection_id=cursor.lastrowid,
            detail={"action": "register_connection", "name": body.name},
        )
    return {"name": body.name}


@router.get("/sync")
async def sync_status(request: Request, actor: Actor) -> Any:
    return await request.app.state.syncer.status()


@router.post("/sync")
async def sync(request: Request, actor: Actor, connection: str | None = None) -> Any:
    names = [info.name for info in await load_connections(request.app.state.metadata)]
    if connection is not None:
        await require_connection(request, connection)
        names = [connection]
    for name in names:
        await request.app.state.syncer.sync_once(name)
    return await request.app.state.syncer.status()


async def reconcile_reports(request: Request, connection: str | None, dry_run: bool) -> Any:
    reconciler = request.app.state.reconciler
    if connection is not None:
        await require_connection(request, connection)
    reports = await reconciler.reconcile_all(dry_run=dry_run, connection=connection)
    body = {name: report_body(report) for name, report in reports.items()}
    if connection is not None and reports[connection].target_unavailable:
        return JSONResponse(status_code=503, content=body)
    return body


def report_body(report: ReconcileReport) -> dict[str, Any]:
    body = asdict(report)
    for field in ("fixes", "skipped", "failed"):
        body[field] = [{"op": type(op).__name__, **asdict(op)} for op in getattr(report, field)]
    return body


@router.post("/reconcile")
async def reconcile(
    request: Request, actor: Actor, connection: str | None = None, dry_run: bool = False
) -> Any:
    return await reconcile_reports(request, connection, dry_run)


@router.get("/drift")
async def drift(request: Request, actor: Actor, connection: str | None = None) -> Any:
    return await reconcile_reports(request, connection, True)


@router.get("/admins")
async def admins(request: Request, actor: Actor, store: Store) -> list[dict[str, Any]]:
    async with request.app.state.metadata.execute("SELECT id, login_key FROM users") as cur:
        users = {row[0]: row[1] for row in await cur.fetchall()}
    entries: dict[str, dict[str, Any]] = {}
    for entry in await list_admins(store):
        login = entry.login_key or users.get(entry.user_id)
        if login is not None:
            key = login
        else:
            assert entry.user_id is not None
            key = ids.user(entry.user_id)
        if key not in entries:
            user_id = entry.user_id
            if user_id is None:
                user_id = next((uid for uid, name in users.items() if name == login), None)
            entries[key] = {"user_id": user_id, "login_key": login, "initial": entry.initial}
        else:
            entries[key]["initial"] |= entry.initial
    return list(entries.values())


@router.post("/admins", status_code=201)
async def add_admin(body: UserInput, actor: Actor, rules: Rules) -> dict[str, str]:
    await rules.add_admin(actor, body.user_id)
    return {"status": "accepted"}


@router.delete("/admins/{user_id}")
async def remove_admin(user_id: int, actor: Actor, rules: Rules) -> dict[str, str]:
    await rules.remove_admin(actor, user_id)
    return {"status": "synced"}
