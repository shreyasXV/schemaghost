-- SchemaGhost demo seed: creates a multi-tenant schema-per-tenant setup

CREATE EXTENSION IF NOT EXISTS pg_stat_statements;

-- Create three tenant schemas
CREATE SCHEMA IF NOT EXISTS tenant_acme;
CREATE SCHEMA IF NOT EXISTS tenant_globex;
CREATE SCHEMA IF NOT EXISTS tenant_initech;

-- Create identical table structure in each schema (schema-per-tenant pattern)
DO $$
DECLARE
  schemas TEXT[] := ARRAY['tenant_acme', 'tenant_globex', 'tenant_initech'];
  s TEXT;
BEGIN
  FOREACH s IN ARRAY schemas LOOP
    EXECUTE format('
      CREATE TABLE IF NOT EXISTS %I.users (
        id SERIAL PRIMARY KEY,
        email TEXT UNIQUE NOT NULL,
        name TEXT,
        created_at TIMESTAMPTZ DEFAULT NOW()
      )', s);

    EXECUTE format('
      CREATE TABLE IF NOT EXISTS %I.orders (
        id SERIAL PRIMARY KEY,
        user_id INT REFERENCES %I.users(id),
        amount NUMERIC(10,2),
        status TEXT DEFAULT ''pending'',
        created_at TIMESTAMPTZ DEFAULT NOW()
      )', s, s);

    EXECUTE format('
      CREATE TABLE IF NOT EXISTS %I.events (
        id SERIAL PRIMARY KEY,
        user_id INT,
        event_type TEXT,
        payload JSONB,
        created_at TIMESTAMPTZ DEFAULT NOW()
      )', s);
  END LOOP;
END $$;

-- Seed some data
INSERT INTO tenant_acme.users (email, name) VALUES
  ('alice@acme.com', 'Alice'), ('bob@acme.com', 'Bob'), ('carol@acme.com', 'Carol');
INSERT INTO tenant_globex.users (email, name) VALUES
  ('dave@globex.com', 'Dave'), ('eve@globex.com', 'Eve');
INSERT INTO tenant_initech.users (email, name) VALUES
  ('frank@initech.com', 'Frank');

INSERT INTO tenant_acme.orders (user_id, amount, status)
  SELECT id, (random()*1000)::numeric(10,2), 'complete' FROM tenant_acme.users;
INSERT INTO tenant_globex.orders (user_id, amount, status)
  SELECT id, (random()*500)::numeric(10,2), 'pending' FROM tenant_globex.users;
