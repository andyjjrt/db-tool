-- setup_version: 1

DO $roles$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = 'gw_managed') THEN
        CREATE ROLE gw_managed NOLOGIN;
    END IF;
END
$roles$;

CREATE SCHEMA IF NOT EXISTS gateway_acl AUTHORIZATION CURRENT_USER;

DO $version_check$
DECLARE
    current_version integer;
BEGIN
    IF pg_catalog.to_regclass('gateway_acl.setup_version') IS NOT NULL THEN
        SELECT version
        INTO current_version
        FROM gateway_acl.setup_version
        WHERE singleton;
        IF current_version > 1 THEN
            RAISE EXCEPTION
                'target DB setup version % is newer than this setup script',
                current_version;
        END IF;
    END IF;
END
$version_check$;

CREATE TABLE IF NOT EXISTS gateway_acl.row_grants (
    group_role name NOT NULL,
    schema_name name NOT NULL,
    table_name name NOT NULL,
    column_name name NOT NULL,
    value text NOT NULL,
    PRIMARY KEY (schema_name, table_name, group_role, value)
);
REVOKE ALL PRIVILEGES ON TABLE gateway_acl.row_grants FROM PUBLIC, gw_managed;

GRANT USAGE ON SCHEMA gateway_acl TO PUBLIC;

CREATE OR REPLACE FUNCTION gateway_acl.is_managed() RETURNS boolean
    LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp
    AS $function$
        SELECT pg_catalog.pg_has_role(session_user, 'gw_managed', 'USAGE')
            OR pg_catalog.pg_has_role(session_user, 'gw_managed', 'SET')
    $function$;

CREATE OR REPLACE FUNCTION gateway_acl.allow_all(p_schema name, p_table name)
RETURNS boolean
    LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp
    AS $function$
        SELECT EXISTS (
            SELECT 1
            FROM gateway_acl.row_grants AS g
            JOIN pg_catalog.pg_roles AS r ON r.rolname = g.group_role
            WHERE g.schema_name = p_schema
              AND g.table_name IN (p_table, '*')
              AND g.value = '*'
              AND pg_catalog.pg_has_role(session_user, r.oid, 'USAGE')
        )
    $function$;

CREATE OR REPLACE FUNCTION gateway_acl.allowed_values(p_schema name, p_table name)
RETURNS text[]
    LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp
    AS $function$
        SELECT coalesce(array_agg(DISTINCT g.value), '{}'::text[])
        FROM gateway_acl.row_grants AS g
        JOIN pg_catalog.pg_roles AS r ON r.rolname = g.group_role
        WHERE g.schema_name = p_schema
          AND g.table_name = p_table
          AND g.value <> '*'
          AND pg_catalog.pg_has_role(session_user, r.oid, 'USAGE')
    $function$;

GRANT EXECUTE ON FUNCTION gateway_acl.is_managed() TO PUBLIC;
GRANT EXECUTE ON FUNCTION gateway_acl.allow_all(name, name) TO PUBLIC;
GRANT EXECUTE ON FUNCTION gateway_acl.allowed_values(name, name) TO PUBLIC;

CREATE TABLE IF NOT EXISTS gateway_acl.setup_version (
    singleton boolean PRIMARY KEY DEFAULT true CHECK (singleton),
    version integer NOT NULL CHECK (version > 0)
);
INSERT INTO gateway_acl.setup_version (singleton, version)
VALUES (TRUE, 1)
ON CONFLICT (singleton) DO UPDATE
SET version = GREATEST(gateway_acl.setup_version.version, EXCLUDED.version);
GRANT SELECT ON TABLE gateway_acl.setup_version TO PUBLIC;

