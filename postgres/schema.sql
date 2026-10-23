-- SebuntAI PostgreSQL bootstrap reference for a fresh PostgreSQL 16 cluster.
--
-- This is a reference, not an idempotent migration. It creates the login roles,
-- application databases, database/schema access, and vector extensions. It does
-- not create application tables. Apply the per-agent db/schema.sql files from
-- their application repositories after reviewing them.
--
-- Run with psql as the Unix postgres account after installing PostgreSQL 16 and
-- postgresql-16-pgvector. The application roles intentionally have no passwords;
-- local clients authenticate with peer. Role creation below grants no admin
-- attributes.

CREATE ROLE human LOGIN;
CREATE ROLE assistant LOGIN;
CREATE ROLE assistant_cmd_monitoring LOGIN;
CREATE ROLE assistant_web_monitoring LOGIN;
CREATE ROLE system_resources_monitoring LOGIN;
CREATE ROLE tux LOGIN;

CREATE DATABASE assistant OWNER postgres;
CREATE DATABASE assistant_cmd_monitoring OWNER postgres;
CREATE DATABASE assistant_web_monitoring OWNER postgres;
CREATE DATABASE system_resources_monitoring OWNER postgres;
CREATE DATABASE tux OWNER human;

-- Remove the default PUBLIC database privileges and grant only required access.
REVOKE ALL ON DATABASE assistant FROM PUBLIC;
GRANT CONNECT ON DATABASE assistant TO assistant, human;

REVOKE ALL ON DATABASE assistant_cmd_monitoring FROM PUBLIC;
GRANT CONNECT ON DATABASE assistant_cmd_monitoring
    TO assistant_cmd_monitoring, human, assistant;

REVOKE ALL ON DATABASE assistant_web_monitoring FROM PUBLIC;
GRANT CONNECT ON DATABASE assistant_web_monitoring
    TO assistant_web_monitoring, human, assistant;

REVOKE ALL ON DATABASE system_resources_monitoring FROM PUBLIC;
GRANT CONNECT ON DATABASE system_resources_monitoring
    TO system_resources_monitoring, human, assistant;

REVOKE ALL ON DATABASE tux FROM PUBLIC;
GRANT CONNECT ON DATABASE tux TO tux, human, assistant;

-- Allow each app to create its own objects in public. Human and Assistant need
-- schema usage in databases whose tables they are allowed to inspect.
\connect assistant
GRANT USAGE, CREATE ON SCHEMA public TO assistant;
GRANT USAGE ON SCHEMA public TO human;
CREATE EXTENSION vector;

\connect assistant_cmd_monitoring
GRANT USAGE, CREATE ON SCHEMA public TO assistant_cmd_monitoring;
GRANT USAGE ON SCHEMA public TO human, assistant;

\connect assistant_web_monitoring
GRANT USAGE, CREATE ON SCHEMA public TO assistant_web_monitoring;
GRANT USAGE ON SCHEMA public TO human, assistant;
CREATE EXTENSION vector;

\connect system_resources_monitoring
GRANT USAGE, CREATE ON SCHEMA public TO system_resources_monitoring;
GRANT USAGE ON SCHEMA public TO human, assistant;

-- Tux's database and tables are owned by human. The tux service role gets
-- schema usage and table/sequence CRUD through tux/db/schema.sql, not CREATE.
\connect tux
GRANT USAGE ON SCHEMA public TO human, tux, assistant;
CREATE EXTENSION vector;
