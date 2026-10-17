-- Run as a superuser, after setup.sql.
CREATE EXTENSION IF NOT EXISTS pg_search;

GRANT USAGE ON SCHEMA paradedb TO gw_managed;
GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA paradedb TO gw_managed;
