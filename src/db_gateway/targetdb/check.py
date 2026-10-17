"""Read-only verification of manually configured target databases.

The checker reads ``setup.sql`` only to obtain canonical function bodies. It
never executes that file or performs DDL/DCL on a target database.

The setup version is parsed from ``setup.sql`` at import time; if its copies
disagree, importing this module raises RuntimeError (a packaging guard).
"""

import re
from collections.abc import Sequence
from dataclasses import dataclass
from importlib.resources import files

import psycopg
from psycopg.pq import TransactionStatus

_SETUP_SQL = files(__package__).joinpath("setup.sql").read_text(encoding="utf-8")
_SETUP_VERSION_PATTERNS = (
    re.compile(r"(?m)^--\s*setup_version:\s*(\d+)\s*$"),
    re.compile(r"current_version\s*>\s*(\d+)", re.IGNORECASE),
    re.compile(r"VALUES\s*\(\s*TRUE\s*,\s*(\d+)\s*\)", re.IGNORECASE),
)


def _setup_version() -> int:
    versions: list[int] = []
    for pattern in _SETUP_VERSION_PATTERNS:
        match = pattern.search(_SETUP_SQL)
        if match is None:
            raise RuntimeError("setup.sql must define one setup version, guard, and marker")
        versions.append(int(match.group(1)))
    if len(set(versions)) != 1:
        raise RuntimeError("setup.sql version comment, guard, and marker must agree")
    return versions[0]


SETUP_VERSION = _setup_version()

_FUNCTIONS: dict[str, tuple[tuple[str, ...], str]] = {
    "is_managed": ((), "boolean"),
    "allow_all": (("name", "name"), "boolean"),
    "allowed_values": (("name", "name"), "text[]"),
}
_FUNCTION_DEFINITION = re.compile(
    r"CREATE\s+OR\s+REPLACE\s+FUNCTION\s+gateway_acl\."
    r"(?P<name>is_managed|allow_all|allowed_values)\s*"
    r"\(.*?\)\s*RETURNS\s+(?P<result>.*?)\s+LANGUAGE\s+sql\b"
    r".*?\bAS\s+\$function\$(?P<body>.*?)\$function\$",
    re.IGNORECASE | re.DOTALL,
)


@dataclass(frozen=True, slots=True)
class Problem:
    """A missing or mismatched target-database requirement."""

    code: str
    message: str
    remediation: str | None = None


def _normalize_source(source: str) -> str:
    return " ".join(source.split())


def _canonical_function_sources() -> dict[str, str]:
    sources = {
        match.group("name").lower(): _normalize_source(match.group("body"))
        for match in _FUNCTION_DEFINITION.finditer(_SETUP_SQL)
    }
    if sources.keys() != _FUNCTIONS.keys():
        raise RuntimeError("setup.sql must define the three canonical gateway_acl functions")
    return sources


_CANONICAL_FUNCTION_SOURCES = _canonical_function_sources()


async def check_target_db(
    conn: psycopg.AsyncConnection,
    *,
    schemas: Sequence[str],
    default_privilege_owners: Sequence[str],
) -> list[Problem]:
    """Read target DB setup and admin privileges inside a READ ONLY transaction."""
    if conn.info.transaction_status is not TransactionStatus.IDLE:
        raise ValueError(
            "check_target_db requires an idle connection; it starts its own transaction"
        )

    schema_names = tuple(schemas)
    owner_names = tuple(default_privilege_owners)
    problems: list[Problem] = []

    async with conn.transaction():
        await conn.execute("SET TRANSACTION READ ONLY")

        cursor = await conn.execute(
            "SELECT admin.oid, admin.rolsuper, admin.rolcreaterole, "
            "       admin.oid = target.datdba "
            "FROM pg_catalog.pg_roles AS admin "
            "CROSS JOIN pg_catalog.pg_database AS target "
            "WHERE admin.rolname = current_user "
            "  AND target.datname = pg_catalog.current_database()"
        )
        admin_row = await cursor.fetchone()
        if admin_row is None:
            problems.append(
                Problem("admin_role_missing", "The current admin role is missing from pg_roles.")
            )
            admin_oid = None
            is_superuser = False
        else:
            admin_oid, is_superuser, can_create_roles, owns_database = admin_row
            if not is_superuser and not (owns_database and can_create_roles):
                problems.append(
                    Problem(
                        "admin_privileges",
                        "The admin must be a superuser or both own the database "
                        "and have CREATEROLE.",
                        "Make the admin the database owner and grant CREATEROLE.",
                    )
                )
            if not is_superuser:
                cursor = await conn.execute("SELECT current_setting('createrole_self_grant')")
                row = await cursor.fetchone()
                if row is not None:
                    grants = {token.strip().lower() for token in row[0].split(",") if token.strip()}
                    if grants & {"inherit", "set", "all"}:
                        problems.append(
                            Problem(
                                "createrole_self_grant",
                                "createrole_self_grant can make roles created by the admin "
                                "inherited or SET-able, which can make the admin managed.",
                                "Keep this setting empty or override it per role-creation "
                                "transaction.",
                            )
                        )

        cursor = await conn.execute(
            "SELECT oid FROM pg_catalog.pg_roles WHERE rolname = 'gw_managed'"
        )
        managed_row = await cursor.fetchone()
        managed_oid = managed_row[0] if managed_row is not None else None
        if managed_oid is None:
            problems.append(
                Problem(
                    "managed_role_missing",
                    "The gw_managed role does not exist.",
                    "Run the role section of docs/target-db-setup.md.",
                )
            )
        elif admin_oid is not None and not is_superuser:
            cursor = await conn.execute(
                "SELECT pg_catalog.pg_has_role(current_user, %s, 'USAGE') "
                "    OR pg_catalog.pg_has_role(current_user, %s, 'SET')",
                (managed_oid, managed_oid),
            )
            row = await cursor.fetchone()
            if row is not None and row[0]:
                problems.append(
                    Problem(
                        "admin_is_managed",
                        "The admin currently counts as a gw_managed member.",
                        "Remove inherited or SET membership, and keep createrole_self_grant empty.",
                    )
                )

            cursor = await conn.execute(
                "SELECT EXISTS ("
                "  SELECT 1 FROM pg_catalog.pg_auth_members "
                "  WHERE roleid = %s AND member = %s AND admin_option"
                ")",
                (managed_oid, admin_oid),
            )
            row = await cursor.fetchone()
            if row is None or not row[0]:
                problems.append(
                    Problem(
                        "managed_admin_option",
                        "The admin lacks ADMIN OPTION on gw_managed.",
                        "Run GRANT gw_managed TO <admin> WITH ADMIN OPTION.",
                    )
                )

        if schema_names:
            cursor = await conn.execute(
                "SELECT n.nspname, c.relname, owner.rolname, "
                "       pg_catalog.pg_has_role(current_user, c.relowner, 'USAGE') "
                "FROM pg_catalog.pg_class AS c "
                "JOIN pg_catalog.pg_namespace AS n ON n.oid = c.relnamespace "
                "JOIN pg_catalog.pg_roles AS owner ON owner.oid = c.relowner "
                "WHERE n.nspname::text = ANY(%s::text[]) "
                "  AND c.relkind IN ('r', 'p', 'v', 'm', 'f') "
                "ORDER BY n.nspname, c.relname",
                (list(schema_names),),
            )
            for schema_name, table_name, owner_name, has_owner_usage in await cursor.fetchall():
                if not has_owner_usage:
                    problems.append(
                        Problem(
                            "table_owner_membership",
                            f"The admin cannot inherit table owner {owner_name} "
                            f"for {schema_name}.{table_name}.",
                            f"Grant {owner_name} to the admin role.",
                        )
                    )

        for owner_name in owner_names:
            cursor = await conn.execute(
                "SELECT oid FROM pg_catalog.pg_roles WHERE rolname = %s",
                (owner_name,),
            )
            owner_row = await cursor.fetchone()
            if owner_row is None:
                problems.append(
                    Problem(
                        "default_privilege_owner_missing",
                        f"Default privilege owner {owner_name} does not exist.",
                    )
                )
                continue
            cursor = await conn.execute(
                "SELECT pg_catalog.pg_has_role(current_user, %s, 'USAGE')",
                (owner_row[0],),
            )
            row = await cursor.fetchone()
            if row is None or not row[0]:
                problems.append(
                    Problem(
                        "default_privilege_owner_membership",
                        f"The admin is not a member of default privilege owner {owner_name}.",
                        f"Grant {owner_name} to the admin role.",
                    )
                )

        cursor = await conn.execute(
            "SELECT oid, nspowner FROM pg_catalog.pg_namespace WHERE nspname = 'gateway_acl'"
        )
        gateway_schema = await cursor.fetchone()
        if gateway_schema is None:
            problems.append(
                Problem(
                    "gateway_acl_schema_missing",
                    "The gateway_acl schema does not exist.",
                    "Run src/db_gateway/targetdb/setup.sql as the target DB operator.",
                )
            )
        else:
            gateway_schema_oid = gateway_schema[0]
            gateway_schema_owner = gateway_schema[1]
            if not is_superuser:
                cursor = await conn.execute(
                    "SELECT pg_catalog.pg_has_role(current_user, %s, 'USAGE')",
                    (gateway_schema_owner,),
                )
                row = await cursor.fetchone()
                if row is None or not row[0]:
                    problems.append(
                        Problem(
                            "gateway_acl_schema_owner",
                            "The admin does not own or inherit the owner of gateway_acl.",
                            "Run setup.sql as the database admin account.",
                        )
                    )

            cursor = await conn.execute(
                "SELECT EXISTS ("
                "  SELECT 1 FROM pg_catalog.pg_namespace AS n "
                "  CROSS JOIN LATERAL pg_catalog.aclexplode("
                "    coalesce(n.nspacl, pg_catalog.acldefault('n', n.nspowner))"
                "  ) AS acl "
                "  WHERE n.oid = %s AND acl.grantee <> n.nspowner "
                "    AND acl.privilege_type = 'CREATE'"
                ")",
                (gateway_schema_oid,),
            )
            row = await cursor.fetchone()
            if row is not None and row[0]:
                problems.append(
                    Problem(
                        "gateway_acl_extra_create",
                        "A non-owner has CREATE on the gateway_acl schema.",
                        "Revoke CREATE from every grantee except the gateway_acl owner.",
                    )
                )
            cursor = await conn.execute(
                "SELECT EXISTS ("
                "  SELECT 1 FROM pg_catalog.pg_namespace AS n "
                "  CROSS JOIN LATERAL pg_catalog.aclexplode("
                "    coalesce(n.nspacl, pg_catalog.acldefault('n', n.nspowner))"
                "  ) AS acl "
                "  WHERE n.oid = %s AND acl.grantee = 0 AND acl.privilege_type = 'USAGE'"
                ")",
                (gateway_schema_oid,),
            )
            row = await cursor.fetchone()
            if row is None or not row[0]:
                problems.append(
                    Problem(
                        "gateway_acl_public_usage",
                        "PUBLIC lacks USAGE on the gateway_acl schema.",
                        "Run GRANT USAGE ON SCHEMA gateway_acl TO PUBLIC.",
                    )
                )

            cursor = await conn.execute(
                "SELECT c.oid, c.relowner "
                "FROM pg_catalog.pg_class AS c "
                "WHERE c.relnamespace = %s AND c.relname = 'row_grants' "
                "  AND c.relkind IN ('r', 'p')",
                (gateway_schema_oid,),
            )
            row_grants = await cursor.fetchone()
            if row_grants is None:
                problems.append(
                    Problem(
                        "row_grants_missing",
                        "The gateway_acl.row_grants table does not exist.",
                        "Run src/db_gateway/targetdb/setup.sql.",
                    )
                )
            else:
                row_grants_oid, row_grants_owner = row_grants
                if not is_superuser:
                    cursor = await conn.execute(
                        "SELECT pg_catalog.has_table_privilege(current_user, %s, 'SELECT') "
                        "   AND pg_catalog.has_table_privilege(current_user, %s, 'INSERT') "
                        "   AND pg_catalog.has_table_privilege(current_user, %s, 'DELETE')",
                        (row_grants_oid, row_grants_oid, row_grants_oid),
                    )
                    row = await cursor.fetchone()
                    if row is None or not row[0]:
                        problems.append(
                            Problem(
                                "row_grants_admin_privilege",
                                "The admin lacks SELECT, INSERT, or DELETE on "
                                "gateway_acl.row_grants.",
                                "Run setup.sql as the database admin account or grant "
                                "these privileges to it.",
                            )
                        )

                    cursor = await conn.execute(
                        "SELECT pg_catalog.pg_has_role(current_user, %s, 'USAGE')",
                        (row_grants_owner,),
                    )
                    row = await cursor.fetchone()
                    if row is None or not row[0]:
                        problems.append(
                            Problem(
                                "gateway_acl_object_owner",
                                "The admin does not own or inherit the owner of "
                                "gateway_acl.row_grants.",
                                "Run setup.sql as the database admin account.",
                            )
                        )

                cursor = await conn.execute(
                    "SELECT a.attname, pg_catalog.format_type(a.atttypid, a.atttypmod), "
                    "       a.attnotnull "
                    "FROM pg_catalog.pg_attribute AS a "
                    "WHERE a.attrelid = %s AND a.attnum > 0 AND NOT a.attisdropped "
                    "ORDER BY a.attnum",
                    (row_grants_oid,),
                )
                actual_columns = await cursor.fetchall()
                expected_columns = [
                    ("group_role", "name", True),
                    ("schema_name", "name", True),
                    ("table_name", "name", True),
                    ("column_name", "name", True),
                    ("value", "text", True),
                ]
                if actual_columns != expected_columns:
                    problems.append(
                        Problem(
                            "row_grants_columns",
                            "gateway_acl.row_grants has unexpected columns or types.",
                            "Reapply the row_grants definition in setup.sql.",
                        )
                    )

                cursor = await conn.execute(
                    "SELECT coalesce(array_agg(a.attname ORDER BY key.ordinality), "
                    "       ARRAY[]::name[]) "
                    "FROM pg_catalog.pg_index AS i "
                    "CROSS JOIN LATERAL unnest(i.indkey::smallint[]) "
                    "  WITH ORDINALITY AS key(attnum, ordinality) "
                    "JOIN pg_catalog.pg_attribute AS a "
                    "  ON a.attrelid = i.indrelid AND a.attnum = key.attnum "
                    "WHERE i.indrelid = %s AND i.indisprimary",
                    (row_grants_oid,),
                )
                row = await cursor.fetchone()
                expected_primary_key = ["schema_name", "table_name", "group_role", "value"]
                if row is None or row[0] != expected_primary_key:
                    problems.append(
                        Problem(
                            "row_grants_primary_key",
                            "gateway_acl.row_grants has an unexpected primary key.",
                            "Reapply the row_grants definition in setup.sql.",
                        )
                    )

                cursor = await conn.execute(
                    "SELECT acl.grantee "
                    "FROM pg_catalog.pg_class AS c "
                    "CROSS JOIN LATERAL pg_catalog.aclexplode("
                    "  coalesce(c.relacl, pg_catalog.acldefault('r', c.relowner))"
                    ") AS acl "
                    "WHERE c.oid = %s",
                    (row_grants_oid,),
                )
                acl_rows = await cursor.fetchall()
                forbidden_grantees = {
                    grantee for (grantee,) in acl_rows if grantee == 0 or grantee == managed_oid
                }
                if 0 in forbidden_grantees:
                    problems.append(
                        Problem(
                            "row_grants_public_privilege",
                            "PUBLIC has a privilege on gateway_acl.row_grants.",
                            "Run REVOKE ALL ON gateway_acl.row_grants FROM PUBLIC.",
                        )
                    )
                if managed_oid is not None and managed_oid in forbidden_grantees:
                    problems.append(
                        Problem(
                            "row_grants_managed_privilege",
                            "gw_managed has a privilege on gateway_acl.row_grants.",
                            "Run REVOKE ALL ON gateway_acl.row_grants FROM gw_managed.",
                        )
                    )

            await _check_functions(
                conn,
                gateway_schema_oid,
                None if row_grants is None else row_grants[0],
                None if row_grants is None else row_grants[1],
                is_superuser,
                problems,
            )
            await _check_setup_version(conn, gateway_schema_oid, is_superuser, problems)

        if managed_oid is not None:
            for schema_name in schema_names:
                cursor = await conn.execute(
                    "SELECT oid FROM pg_catalog.pg_namespace WHERE nspname = %s",
                    (schema_name,),
                )
                schema_row = await cursor.fetchone()
                if schema_row is None:
                    problems.append(
                        Problem(
                            "managed_schema_missing",
                            f"Managed schema {schema_name} does not exist.",
                        )
                    )
                    continue
                cursor = await conn.execute(
                    "SELECT pg_catalog.has_schema_privilege(%s, %s, 'USAGE')",
                    (managed_oid, schema_row[0]),
                )
                row = await cursor.fetchone()
                if row is None or not row[0]:
                    problems.append(
                        Problem(
                            "managed_schema_usage",
                            f"gw_managed lacks USAGE on schema {schema_name}.",
                            f"Run GRANT USAGE ON SCHEMA {schema_name} TO gw_managed.",
                        )
                    )

            cursor = await conn.execute(
                "SELECT oid FROM pg_catalog.pg_namespace WHERE nspname = 'paradedb'"
            )
            paradedb_row = await cursor.fetchone()
            if paradedb_row is None:
                problems.append(
                    Problem(
                        "paradedb_schema_missing",
                        "The paradedb schema does not exist.",
                        "Install the pg_search extension before applying setup.sql.",
                    )
                )
            else:
                paradedb_oid = paradedb_row[0]
                cursor = await conn.execute(
                    "SELECT pg_catalog.has_schema_privilege(%s, %s, 'USAGE')",
                    (managed_oid, paradedb_oid),
                )
                row = await cursor.fetchone()
                if row is None or not row[0]:
                    problems.append(
                        Problem(
                            "paradedb_schema_usage",
                            "gw_managed lacks USAGE on schema paradedb.",
                            "Run GRANT USAGE ON SCHEMA paradedb TO gw_managed.",
                        )
                    )
                cursor = await conn.execute(
                    "SELECT p.oid, p.proname, "
                    "       pg_catalog.has_function_privilege(%s, p.oid, 'EXECUTE') "
                    "FROM pg_catalog.pg_proc AS p "
                    "WHERE p.pronamespace = %s",
                    (managed_oid, paradedb_oid),
                )
                paradedb_functions = await cursor.fetchall()
                if not paradedb_functions:
                    problems.append(
                        Problem(
                            "paradedb_functions_missing",
                            "No functions were found in the paradedb schema.",
                        )
                    )
                for _, function_name, has_execute in paradedb_functions:
                    if not has_execute:
                        problems.append(
                            Problem(
                                "paradedb_function_execute",
                                f"gw_managed lacks EXECUTE on paradedb.{function_name}.",
                                "Run GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA paradedb "
                                "TO gw_managed.",
                            )
                        )

            cursor = await conn.execute(
                "SELECT pg_catalog.has_database_privilege(%s, pg_catalog.current_database(), "
                "'CONNECT')",
                (managed_oid,),
            )
            row = await cursor.fetchone()
            if row is None or not row[0]:
                problems.append(
                    Problem(
                        "managed_database_connect",
                        "gw_managed cannot CONNECT to the current database.",
                        "Grant CONNECT to PUBLIC or explicitly to gw_managed.",
                    )
                )

    return problems


async def _check_functions(
    conn: psycopg.AsyncConnection,
    schema_oid: int,
    row_grants_oid: int | None,
    row_grants_owner: int | None,
    is_superuser: bool,
    problems: list[Problem],
) -> None:
    cursor = await conn.execute(
        "SELECT p.oid, p.proname, "
        "       ARRAY("
        "         SELECT t.typname "
        "         FROM unnest(p.proargtypes::oid[]) WITH ORDINALITY AS arg(type_oid, ord) "
        "         JOIN pg_catalog.pg_type AS t ON t.oid = arg.type_oid "
        "         ORDER BY arg.ord"
        "       ), "
        "       pg_catalog.format_type(p.prorettype, NULL), "
        "       lang.lanname, "
        "       pg_catalog.pg_has_role(current_user, p.proowner, 'USAGE'), "
        "       p.prosecdef, p.provolatile, p.proconfig, p.prosrc, "
        "       EXISTS ("
        "         SELECT 1 FROM pg_catalog.aclexplode("
        "           coalesce(p.proacl, pg_catalog.acldefault('f', p.proowner))"
        "         ) AS acl "
        "         WHERE acl.grantee = 0 AND acl.privilege_type = 'EXECUTE'"
        "       ) "
        "FROM pg_catalog.pg_proc AS p "
        "JOIN pg_catalog.pg_language AS lang ON lang.oid = p.prolang "
        "WHERE p.pronamespace = %s AND p.proname::text = ANY(%s::text[])",
        (schema_oid, list(_FUNCTIONS)),
    )
    actual_functions = await cursor.fetchall()
    actual_by_signature = {
        (name, tuple(argument_types)): (
            oid,
            return_type,
            language,
            admin_can_use_owner,
            security_definer,
            volatility,
            config,
            source,
            public_execute,
        )
        for (
            oid,
            name,
            argument_types,
            return_type,
            language,
            admin_can_use_owner,
            security_definer,
            volatility,
            config,
            source,
            public_execute,
        ) in actual_functions
    }

    expected_signatures = {(name, types) for name, (types, _) in _FUNCTIONS.items()}
    for name, argument_types in actual_by_signature:
        if (name, argument_types) not in expected_signatures:
            problems.append(
                Problem(
                    "function_overload",
                    f"gateway_acl.{name} has unexpected overload ({', '.join(argument_types)}).",
                    "Drop every overload not defined in setup.sql.",
                )
            )

    for name, (argument_types, return_type) in _FUNCTIONS.items():
        function = actual_by_signature.get((name, argument_types))
        if function is None:
            problems.append(
                Problem(
                    "function_missing",
                    f"gateway_acl.{name}({', '.join(argument_types)}) is missing.",
                    "Reapply the function definition in setup.sql.",
                )
            )
            continue

        (
            function_oid,
            actual_return,
            language,
            admin_can_use_owner,
            security_definer,
            volatility,
            config,
            source,
            public_execute,
        ) = function
        if not is_superuser and not admin_can_use_owner:
            problems.append(
                Problem(
                    "gateway_acl_object_owner",
                    f"The admin cannot use the owner of gateway_acl.{name}.",
                    "Run setup.sql as the database admin account.",
                )
            )
        if language != "sql":
            problems.append(
                Problem(
                    "function_language",
                    f"gateway_acl.{name} is not a SQL-language function.",
                    "Reapply its definition from setup.sql.",
                )
            )
        if row_grants_oid is not None and row_grants_owner is not None:
            cursor = await conn.execute(
                "SELECT %s::oid = p.proowner "
                "    OR pg_catalog.has_table_privilege(p.proowner, %s, 'SELECT') "
                "FROM pg_catalog.pg_proc AS p WHERE p.oid = %s",
                (row_grants_owner, row_grants_oid, function_oid),
            )
            row = await cursor.fetchone()
            if row is None or not row[0]:
                problems.append(
                    Problem(
                        "function_row_grants_access",
                        f"The owner of gateway_acl.{name} cannot read gateway_acl.row_grants.",
                        "Make the function owner the row_grants owner or grant it SELECT.",
                    )
                )

        configured_search_path = "search_path=pg_catalog, pg_temp"
        if (
            not security_definer
            or volatility != "s"
            or actual_return != return_type
            or config is None
            or configured_search_path not in config
        ):
            problems.append(
                Problem(
                    "function_security",
                    f"gateway_acl.{name} has unexpected return type or security settings.",
                    "Reapply its SECURITY DEFINER, STABLE, and search_path settings "
                    "from setup.sql.",
                )
            )
        if not public_execute:
            problems.append(
                Problem(
                    "function_public_execute",
                    f"PUBLIC cannot EXECUTE gateway_acl.{name}.",
                    "Run GRANT EXECUTE on the function to PUBLIC.",
                )
            )
        if _normalize_source(source) != _CANONICAL_FUNCTION_SOURCES[name]:
            problems.append(
                Problem(
                    "function_body_mismatch",
                    f"gateway_acl.{name} does not match the canonical body in setup.sql.",
                    "Reapply the function definition in setup.sql.",
                )
            )


async def _check_setup_version(
    conn: psycopg.AsyncConnection,
    schema_oid: int,
    is_superuser: bool,
    problems: list[Problem],
) -> None:
    cursor = await conn.execute(
        "SELECT c.oid, c.relowner "
        "FROM pg_catalog.pg_class AS c "
        "WHERE c.relnamespace = %s AND c.relname = 'setup_version' "
        "  AND c.relkind IN ('r', 'p')",
        (schema_oid,),
    )
    row = await cursor.fetchone()
    if row is None:
        problems.append(
            Problem(
                "setup_version_missing",
                "The gateway_acl.setup_version table does not exist.",
                "Run src/db_gateway/targetdb/setup.sql.",
            )
        )
        return

    setup_version_oid, setup_version_owner = row
    if not is_superuser:
        cursor = await conn.execute(
            "SELECT pg_catalog.pg_has_role(current_user, %s, 'USAGE')",
            (setup_version_owner,),
        )
        owner_row = await cursor.fetchone()
        if owner_row is None or not owner_row[0]:
            problems.append(
                Problem(
                    "gateway_acl_object_owner",
                    "The admin does not own or inherit the owner of gateway_acl.setup_version.",
                    "Run setup.sql as the database admin account.",
                )
            )

    cursor = await conn.execute(
        "SELECT a.attname, pg_catalog.format_type(a.atttypid, a.atttypmod) "
        "FROM pg_catalog.pg_attribute AS a "
        "WHERE a.attrelid = %s AND a.attnum > 0 AND NOT a.attisdropped",
        (setup_version_oid,),
    )
    columns = {column_name: type_name for column_name, type_name in await cursor.fetchall()}
    if columns.get("version") != "integer" or columns.get("singleton") != "boolean":
        problems.append(
            Problem(
                "setup_version_invalid",
                "gateway_acl.setup_version has an unexpected definition.",
                "Reapply the setup_version definition in setup.sql.",
            )
        )
        return

    cursor = await conn.execute("SELECT version FROM gateway_acl.setup_version WHERE singleton")
    version_row = await cursor.fetchone()
    if version_row is None:
        problems.append(
            Problem(
                "setup_version_missing",
                "gateway_acl.setup_version has no applied version row.",
                "Run src/db_gateway/targetdb/setup.sql.",
            )
        )
    elif version_row[0] < SETUP_VERSION:
        problems.append(
            Problem(
                "setup_version_outdated",
                f"Database setup version {version_row[0]} is older than required "
                f"version {SETUP_VERSION}.",
                "Run the upgrade steps in docs/target-db-setup.md.",
            )
        )
    elif version_row[0] > SETUP_VERSION:
        problems.append(
            Problem(
                "setup_version_newer",
                f"Database setup version {version_row[0]} is newer than this gateway supports "
                f"({SETUP_VERSION}).",
                "Upgrade the gateway before checking this database.",
            )
        )
