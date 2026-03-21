-- ============================================================
-- SchemaGhost Real-World Test Scenarios
-- ============================================================
-- Tests THREE isolation patterns with realistic data volumes
-- ============================================================

-- Clean slate
DROP DATABASE IF EXISTS sg_test_schema;
DROP DATABASE IF EXISTS sg_test_rowlevel;
DROP DATABASE IF EXISTS sg_test_mixed;

-- ============================================================
-- SCENARIO 1: Schema-per-Tenant (like Salesforce, Citus-style)
-- Simulates a B2B SaaS with 10 tenants, each in their own schema
-- ============================================================
CREATE DATABASE sg_test_schema;
\c sg_test_schema

CREATE EXTENSION IF NOT EXISTS pg_stat_statements;

-- Create 10 tenant schemas with realistic SaaS tables
DO $$
DECLARE
  tenant_names TEXT[] := ARRAY[
    'acme_corp', 'globex_inc', 'initech', 'hooli', 'pied_piper',
    'stark_industries', 'wayne_enterprises', 'umbrella_corp', 'cyberdyne', 'oscorp'
  ];
  t TEXT;
BEGIN
  FOREACH t IN ARRAY tenant_names LOOP
    EXECUTE format('CREATE SCHEMA IF NOT EXISTS %I', t);
    
    -- Users table
    EXECUTE format('
      CREATE TABLE %I.users (
        id SERIAL PRIMARY KEY,
        email TEXT UNIQUE NOT NULL,
        name TEXT NOT NULL,
        role TEXT DEFAULT ''member'',
        last_login TIMESTAMPTZ,
        created_at TIMESTAMPTZ DEFAULT NOW()
      )', t);
    
    -- Projects table
    EXECUTE format('
      CREATE TABLE %I.projects (
        id SERIAL PRIMARY KEY,
        name TEXT NOT NULL,
        description TEXT,
        owner_id INT REFERENCES %I.users(id),
        status TEXT DEFAULT ''active'',
        created_at TIMESTAMPTZ DEFAULT NOW()
      )', t, t);
    
    -- Tasks table (high volume)
    EXECUTE format('
      CREATE TABLE %I.tasks (
        id SERIAL PRIMARY KEY,
        project_id INT REFERENCES %I.projects(id),
        title TEXT NOT NULL,
        description TEXT,
        assignee_id INT,
        status TEXT DEFAULT ''todo'',
        priority INT DEFAULT 3,
        due_date DATE,
        created_at TIMESTAMPTZ DEFAULT NOW(),
        updated_at TIMESTAMPTZ DEFAULT NOW()
      )', t, t);
    
    -- Events/audit log (very high volume)
    EXECUTE format('
      CREATE TABLE %I.events (
        id SERIAL PRIMARY KEY,
        user_id INT,
        event_type TEXT NOT NULL,
        resource_type TEXT,
        resource_id INT,
        payload JSONB DEFAULT ''{}''::jsonb,
        ip_address INET,
        created_at TIMESTAMPTZ DEFAULT NOW()
      )', t);
    
    -- Invoices
    EXECUTE format('
      CREATE TABLE %I.invoices (
        id SERIAL PRIMARY KEY,
        user_id INT REFERENCES %I.users(id),
        amount NUMERIC(12,2) NOT NULL,
        currency TEXT DEFAULT ''USD'',
        status TEXT DEFAULT ''pending'',
        due_date DATE,
        paid_at TIMESTAMPTZ,
        created_at TIMESTAMPTZ DEFAULT NOW()
      )', t, t);
  END LOOP;
END $$;

-- Seed data with varying volumes per tenant (simulating real usage patterns)
-- Acme = power user (lots of data), Oscorp = tiny tenant
DO $$
DECLARE
  tenant_names TEXT[] := ARRAY[
    'acme_corp', 'globex_inc', 'initech', 'hooli', 'pied_piper',
    'stark_industries', 'wayne_enterprises', 'umbrella_corp', 'cyberdyne', 'oscorp'
  ];
  user_counts INT[] := ARRAY[50, 30, 20, 40, 15, 25, 35, 10, 20, 5];
  t TEXT;
  uc INT;
  i INT;
BEGIN
  FOR i IN 1..array_length(tenant_names, 1) LOOP
    t := tenant_names[i];
    uc := user_counts[i];
    
    -- Insert users
    EXECUTE format('
      INSERT INTO %I.users (email, name, role, last_login)
      SELECT 
        ''user'' || n || ''@'' || %L || ''.com'',
        ''User '' || n,
        CASE WHEN n <= 3 THEN ''admin'' ELSE ''member'' END,
        NOW() - (random() * interval ''30 days'')
      FROM generate_series(1, %s) n
    ', t, t, uc);
    
    -- Insert projects (5-20 per tenant)
    EXECUTE format('
      INSERT INTO %I.projects (name, description, owner_id, status)
      SELECT 
        ''Project '' || n,
        ''Description for project '' || n,
        (random() * %s + 1)::int,
        CASE WHEN random() > 0.2 THEN ''active'' ELSE ''archived'' END
      FROM generate_series(1, %s) n
    ', t, uc, greatest(5, uc / 3));
    
    -- Insert tasks (heavy — 10-100x users)
    EXECUTE format('
      INSERT INTO %I.tasks (project_id, title, assignee_id, status, priority, due_date)
      SELECT 
        (random() * %s + 1)::int,
        ''Task '' || n || '': '' || CASE 
          WHEN random() > 0.5 THEN ''Fix bug in module''
          ELSE ''Implement feature request''
        END,
        (random() * %s + 1)::int,
        (ARRAY[''todo'', ''in_progress'', ''review'', ''done''])[floor(random()*4+1)::int],
        floor(random()*5+1)::int,
        CURRENT_DATE + (random() * 60)::int
      FROM generate_series(1, %s) n
    ', t, greatest(5, uc/3), uc, uc * 20);
    
    -- Insert events (highest volume — 50-500x users)  
    EXECUTE format('
      INSERT INTO %I.events (user_id, event_type, resource_type, resource_id, payload, ip_address)
      SELECT 
        (random() * %s + 1)::int,
        (ARRAY[''page_view'', ''click'', ''api_call'', ''login'', ''logout'', ''export'', ''import'', ''search''])[floor(random()*8+1)::int],
        (ARRAY[''project'', ''task'', ''user'', ''invoice''])[floor(random()*4+1)::int],
        (random() * 100 + 1)::int,
        jsonb_build_object(''duration_ms'', (random()*5000)::int, ''browser'', ''Chrome''),
        (''10.'' || (random()*255)::int || ''.'' || (random()*255)::int || ''.'' || (random()*255)::int)::inet
      FROM generate_series(1, %s) n
    ', t, uc, uc * 100);
    
    -- Insert invoices
    EXECUTE format('
      INSERT INTO %I.invoices (user_id, amount, currency, status, due_date)
      SELECT 
        (random() * %s + 1)::int,
        (random() * 10000)::numeric(12,2),
        CASE WHEN random() > 0.8 THEN ''EUR'' ELSE ''USD'' END,
        (ARRAY[''pending'', ''paid'', ''overdue'', ''cancelled''])[floor(random()*4+1)::int],
        CURRENT_DATE + (random() * 90)::int
      FROM generate_series(1, %s) n
    ', t, uc, uc * 5);
  END LOOP;
END $$;

-- Generate query traffic (simulate real workload)
-- Acme does HEAVY queries (the noisy neighbor)
SET search_path = acme_corp;
SELECT count(*) FROM events WHERE created_at > NOW() - interval '1 day';
SELECT count(*) FROM events WHERE created_at > NOW() - interval '1 day';
SELECT count(*) FROM events WHERE created_at > NOW() - interval '1 day';
SELECT * FROM tasks WHERE status = 'todo' ORDER BY priority, created_at LIMIT 100;
SELECT * FROM tasks WHERE status = 'todo' ORDER BY priority, created_at LIMIT 100;
SELECT u.name, count(t.id) FROM users u LEFT JOIN tasks t ON t.assignee_id = u.id GROUP BY u.name;
SELECT u.name, count(t.id) FROM users u LEFT JOIN tasks t ON t.assignee_id = u.id GROUP BY u.name;
SELECT * FROM events ORDER BY created_at DESC LIMIT 1000;  -- expensive!
SELECT * FROM events ORDER BY created_at DESC LIMIT 1000;  -- expensive!
SELECT * FROM events ORDER BY created_at DESC LIMIT 1000;  -- expensive!

SET search_path = globex_inc;
SELECT count(*) FROM tasks WHERE status = 'in_progress';
SELECT * FROM users WHERE last_login > NOW() - interval '7 days';

SET search_path = initech;
SELECT count(*) FROM events;

SET search_path = hooli;
SELECT * FROM tasks WHERE status = 'todo' LIMIT 50;
SELECT * FROM tasks WHERE status = 'todo' LIMIT 50;
SELECT count(*) FROM invoices WHERE status = 'overdue';

SET search_path = pied_piper;
SELECT count(*) FROM users;

SET search_path = public;


-- ============================================================
-- SCENARIO 2: Row-Level Isolation (most common pattern)
-- Single schema, tenant_id column in every table
-- ============================================================
\c postgres
CREATE DATABASE sg_test_rowlevel;
\c sg_test_rowlevel

CREATE EXTENSION IF NOT EXISTS pg_stat_statements;

-- Organizations (tenants)
CREATE TABLE organizations (
  id SERIAL PRIMARY KEY,
  name TEXT NOT NULL,
  slug TEXT UNIQUE NOT NULL,
  plan TEXT DEFAULT 'free',
  created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Users with tenant_id
CREATE TABLE users (
  id SERIAL PRIMARY KEY,
  tenant_id INT NOT NULL REFERENCES organizations(id),
  email TEXT NOT NULL,
  name TEXT NOT NULL,
  role TEXT DEFAULT 'member',
  last_login TIMESTAMPTZ,
  created_at TIMESTAMPTZ DEFAULT NOW()
);
CREATE INDEX idx_users_tenant ON users(tenant_id);

-- Documents
CREATE TABLE documents (
  id SERIAL PRIMARY KEY,
  tenant_id INT NOT NULL REFERENCES organizations(id),
  title TEXT NOT NULL,
  content TEXT,
  author_id INT REFERENCES users(id),
  status TEXT DEFAULT 'draft',
  word_count INT DEFAULT 0,
  created_at TIMESTAMPTZ DEFAULT NOW(),
  updated_at TIMESTAMPTZ DEFAULT NOW()
);
CREATE INDEX idx_docs_tenant ON documents(tenant_id);

-- Comments
CREATE TABLE comments (
  id SERIAL PRIMARY KEY,
  tenant_id INT NOT NULL REFERENCES organizations(id),
  document_id INT REFERENCES documents(id),
  user_id INT REFERENCES users(id),
  body TEXT NOT NULL,
  created_at TIMESTAMPTZ DEFAULT NOW()
);
CREATE INDEX idx_comments_tenant ON comments(tenant_id);

-- API requests log (high volume)
CREATE TABLE api_requests (
  id SERIAL PRIMARY KEY,
  tenant_id INT NOT NULL REFERENCES organizations(id),
  method TEXT NOT NULL,
  path TEXT NOT NULL,
  status_code INT,
  duration_ms INT,
  user_id INT,
  ip_address INET,
  created_at TIMESTAMPTZ DEFAULT NOW()
);
CREATE INDEX idx_api_tenant ON api_requests(tenant_id);

-- Billing
CREATE TABLE billing_events (
  id SERIAL PRIMARY KEY,
  tenant_id INT NOT NULL REFERENCES organizations(id),
  event_type TEXT NOT NULL,
  amount NUMERIC(12,2),
  currency TEXT DEFAULT 'USD',
  created_at TIMESTAMPTZ DEFAULT NOW()
);
CREATE INDEX idx_billing_tenant ON billing_events(tenant_id);

-- Seed 15 organizations with varying sizes
INSERT INTO organizations (name, slug, plan) VALUES
  ('Acme Corp', 'acme', 'enterprise'),
  ('Globex Inc', 'globex', 'pro'),
  ('Initech', 'initech', 'pro'),
  ('Hooli', 'hooli', 'enterprise'),
  ('Pied Piper', 'piedpiper', 'startup'),
  ('Stark Industries', 'stark', 'enterprise'),
  ('Wayne Enterprises', 'wayne', 'enterprise'),
  ('Umbrella Corp', 'umbrella', 'pro'),
  ('Cyberdyne', 'cyberdyne', 'startup'),
  ('Oscorp', 'oscorp', 'free'),
  ('Weyland-Yutani', 'weyland', 'pro'),
  ('Soylent Corp', 'soylent', 'startup'),
  ('Tyrell Corp', 'tyrell', 'enterprise'),
  ('Wonka Industries', 'wonka', 'free'),
  ('Dunder Mifflin', 'dundermifflin', 'startup');

-- Seed users (enterprise tenants get more users)
INSERT INTO users (tenant_id, email, name, role, last_login)
SELECT 
  o.id,
  'user' || n || '@' || o.slug || '.com',
  'User ' || n || ' at ' || o.name,
  CASE WHEN n <= 2 THEN 'admin' ELSE 'member' END,
  NOW() - (random() * interval '30 days')
FROM organizations o
CROSS JOIN generate_series(1, 
  CASE 
    WHEN o.plan = 'enterprise' THEN 100
    WHEN o.plan = 'pro' THEN 40
    WHEN o.plan = 'startup' THEN 15
    ELSE 5
  END
) n;

-- Seed documents
INSERT INTO documents (tenant_id, title, content, author_id, status, word_count)
SELECT 
  u.tenant_id,
  'Document ' || n || ' by ' || u.name,
  repeat('Lorem ipsum dolor sit amet. ', (random()*50+1)::int),
  u.id,
  (ARRAY['draft', 'published', 'archived'])[floor(random()*3+1)::int],
  (random() * 5000)::int
FROM users u
CROSS JOIN generate_series(1, 5) n
WHERE u.role = 'admin' OR random() > 0.7;

-- Seed comments
INSERT INTO comments (tenant_id, document_id, user_id, body)
SELECT 
  d.tenant_id,
  d.id,
  (SELECT id FROM users WHERE tenant_id = d.tenant_id ORDER BY random() LIMIT 1),
  'Comment on ' || d.title || ': Great work!'
FROM documents d
CROSS JOIN generate_series(1, 3) n
WHERE random() > 0.4;

-- Seed API requests (heavy traffic — this is the noisy neighbor signal)
-- Acme (tenant 1) generates 10x more traffic than others
INSERT INTO api_requests (tenant_id, method, path, status_code, duration_ms, user_id, ip_address)
SELECT 
  CASE 
    WHEN random() < 0.4 THEN 1   -- Acme gets 40% of all traffic (noisy!)
    WHEN random() < 0.6 THEN 4   -- Hooli gets 20%
    WHEN random() < 0.7 THEN 6   -- Stark gets 10%
    ELSE (random() * 14 + 1)::int  -- rest spread across others
  END,
  (ARRAY['GET', 'POST', 'PUT', 'DELETE'])[floor(random()*4+1)::int],
  (ARRAY['/api/docs', '/api/users', '/api/search', '/api/export', '/api/upload', '/api/analytics'])[floor(random()*6+1)::int],
  CASE WHEN random() > 0.05 THEN 200 WHEN random() > 0.5 THEN 404 ELSE 500 END,
  (random() * 2000)::int,  -- 0-2000ms response time
  NULL,
  ('10.' || (random()*255)::int || '.' || (random()*255)::int || '.' || (random()*255)::int)::inet
FROM generate_series(1, 50000) n;

-- Seed billing
INSERT INTO billing_events (tenant_id, event_type, amount)
SELECT
  o.id,
  (ARRAY['charge', 'refund', 'upgrade', 'overage'])[floor(random()*4+1)::int],
  (random() * 1000)::numeric(12,2)
FROM organizations o
CROSS JOIN generate_series(1, 10) n;

-- Simulate queries (generate pg_stat_statements entries)
-- Noisy neighbor pattern: Acme runs expensive queries
SELECT count(*) FROM api_requests WHERE tenant_id = 1;
SELECT count(*) FROM api_requests WHERE tenant_id = 1;
SELECT count(*) FROM api_requests WHERE tenant_id = 1;
SELECT * FROM api_requests WHERE tenant_id = 1 AND duration_ms > 1000 ORDER BY created_at DESC;
SELECT * FROM api_requests WHERE tenant_id = 1 AND duration_ms > 1000 ORDER BY created_at DESC;
SELECT avg(duration_ms), max(duration_ms) FROM api_requests WHERE tenant_id = 1;
SELECT d.title, count(c.id) FROM documents d LEFT JOIN comments c ON c.document_id = d.id WHERE d.tenant_id = 1 GROUP BY d.title;
SELECT * FROM documents WHERE tenant_id = 1 AND content LIKE '%search term%';  -- full table scan!

-- Normal tenant queries
SELECT count(*) FROM api_requests WHERE tenant_id = 2;
SELECT * FROM users WHERE tenant_id = 3 AND role = 'admin';
SELECT count(*) FROM documents WHERE tenant_id = 4;
SELECT * FROM api_requests WHERE tenant_id = 5 ORDER BY created_at DESC LIMIT 10;


-- ============================================================
-- SCENARIO 3: Mixed/Hybrid (schema + row-level)
-- Some tables shared, some per-schema
-- ============================================================
\c postgres
CREATE DATABASE sg_test_mixed;
\c sg_test_mixed

CREATE EXTENSION IF NOT EXISTS pg_stat_statements;

-- Shared tables in public schema with org_id
CREATE TABLE organizations (
  id SERIAL PRIMARY KEY,
  name TEXT NOT NULL,
  slug TEXT UNIQUE,
  created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE shared_users (
  id SERIAL PRIMARY KEY,
  org_id INT REFERENCES organizations(id),
  email TEXT NOT NULL,
  name TEXT NOT NULL,
  created_at TIMESTAMPTZ DEFAULT NOW()
);
CREATE INDEX idx_shared_users_org ON shared_users(org_id);

CREATE TABLE shared_audit_log (
  id SERIAL PRIMARY KEY,
  org_id INT REFERENCES organizations(id),
  action TEXT NOT NULL,
  details JSONB,
  created_at TIMESTAMPTZ DEFAULT NOW()
);
CREATE INDEX idx_audit_org ON shared_audit_log(org_id);

INSERT INTO organizations (name, slug) VALUES 
  ('Alpha Co', 'alpha'), ('Beta LLC', 'beta'), ('Gamma Inc', 'gamma');

INSERT INTO shared_users (org_id, email, name)
SELECT o.id, 'user' || n || '@' || o.slug || '.com', 'User ' || n
FROM organizations o CROSS JOIN generate_series(1, 20) n;

INSERT INTO shared_audit_log (org_id, action, details)
SELECT 
  (random()*2+1)::int,
  (ARRAY['login', 'create', 'update', 'delete'])[floor(random()*4+1)::int],
  '{}'::jsonb
FROM generate_series(1, 5000) n;

-- Queries
SELECT count(*) FROM shared_audit_log WHERE org_id = 1;
SELECT count(*) FROM shared_audit_log WHERE org_id = 2;
SELECT * FROM shared_users WHERE org_id = 1;
