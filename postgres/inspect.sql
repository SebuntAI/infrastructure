-- Read-only PostgreSQL checks for the SebuntAI setup.
-- Run these statements as postgres. Table grants and installed extensions are
-- scoped to the current database, so connect to each app database as needed.

SELECT version();

SELECT name, setting
FROM pg_settings
WHERE name IN (
    'listen_addresses',
    'port',
    'unix_socket_directories',
    'password_encryption',
    'ssl'
)
ORDER BY name;

SELECT rolname,
       rolsuper,
       rolcreatedb,
       rolcreaterole,
       rolreplication,
       rolbypassrls,
       rolcanlogin,
       rolpassword IS NULL AS no_password_set
FROM pg_authid
WHERE rolname IN (
    'human',
    'assistant',
    'assistant_cmd_monitoring',
    'assistant_web_monitoring',
    'system_resources_monitoring',
    'tux',
    'postgres'
)
ORDER BY rolname;

SELECT datname,
       pg_get_userbyid(datdba) AS owner,
       datacl
FROM pg_database
WHERE datistemplate = false
ORDER BY datname;

SELECT line_number,
       type,
       database,
       user_name,
       address,
       auth_method,
       error
FROM pg_hba_file_rules
ORDER BY line_number;

SELECT line_number, error
FROM pg_hba_file_rules
WHERE error IS NOT NULL;

-- Run after connecting to each application database.
SELECT n.nspname AS schema,
       c.relname AS object,
       c.relkind AS object_kind,
       pg_get_userbyid(c.relowner) AS owner,
       c.relacl AS privileges
FROM pg_class AS c
JOIN pg_namespace AS n ON n.oid = c.relnamespace
WHERE n.nspname = 'public'
  AND c.relkind IN ('r', 'p', 'v', 'm', 'S')
ORDER BY c.relname;

SELECT extname, extversion, extnamespace::regnamespace AS schema
FROM pg_extension
ORDER BY extname;
