-- Direct seeding for schema-per-tenant test
\c sg_test_schema

-- Seed acme_corp (HEAVY - noisy neighbor)
INSERT INTO acme_corp.users (email, name, role, last_login)
SELECT 'user' || n || '@acme.com', 'Acme User ' || n,
  CASE WHEN n <= 5 THEN 'admin' ELSE 'member' END,
  NOW() - (random() * interval '30 days')
FROM generate_series(1, 50) n;

INSERT INTO acme_corp.projects (name, owner_id, status)
SELECT 'Project ' || n, (random()*49+1)::int, 
  CASE WHEN random() > 0.2 THEN 'active' ELSE 'archived' END
FROM generate_series(1, 20) n;

INSERT INTO acme_corp.tasks (project_id, title, assignee_id, status, priority)
SELECT (random()*19+1)::int, 'Task ' || n, (random()*49+1)::int,
  (ARRAY['todo','in_progress','review','done'])[floor(random()*4+1)::int],
  floor(random()*5+1)::int
FROM generate_series(1, 2000) n;

INSERT INTO acme_corp.events (user_id, event_type, resource_type, payload)
SELECT (random()*49+1)::int,
  (ARRAY['page_view','click','api_call','login','export','search'])[floor(random()*6+1)::int],
  (ARRAY['project','task','user','invoice'])[floor(random()*4+1)::int],
  jsonb_build_object('duration_ms', (random()*5000)::int)
FROM generate_series(1, 10000) n;

INSERT INTO acme_corp.invoices (user_id, amount, status)
SELECT (random()*49+1)::int, (random()*10000)::numeric(12,2),
  (ARRAY['pending','paid','overdue'])[floor(random()*3+1)::int]
FROM generate_series(1, 500) n;

-- Seed globex_inc (MODERATE)
INSERT INTO globex_inc.users (email, name, role)
SELECT 'user' || n || '@globex.com', 'Globex User ' || n,
  CASE WHEN n <= 3 THEN 'admin' ELSE 'member' END
FROM generate_series(1, 30) n;

INSERT INTO globex_inc.projects (name, owner_id) SELECT 'GProject ' || n, (random()*29+1)::int FROM generate_series(1, 10) n;
INSERT INTO globex_inc.tasks (project_id, title, assignee_id, status, priority)
SELECT (random()*9+1)::int, 'GTask ' || n, (random()*29+1)::int,
  (ARRAY['todo','in_progress','review','done'])[floor(random()*4+1)::int], floor(random()*5+1)::int
FROM generate_series(1, 500) n;
INSERT INTO globex_inc.events (user_id, event_type, resource_type) 
SELECT (random()*29+1)::int, 'page_view', 'task' FROM generate_series(1, 3000) n;
INSERT INTO globex_inc.invoices (user_id, amount, status)
SELECT (random()*29+1)::int, (random()*5000)::numeric(12,2), 'paid' FROM generate_series(1, 100) n;

-- Seed initech (LIGHT)
INSERT INTO initech.users (email, name) SELECT 'user' || n || '@initech.com', 'Initech User ' || n FROM generate_series(1, 10) n;
INSERT INTO initech.projects (name, owner_id) SELECT 'IProject ' || n, (random()*9+1)::int FROM generate_series(1, 5) n;
INSERT INTO initech.tasks (project_id, title, status) SELECT (random()*4+1)::int, 'ITask ' || n, 'todo' FROM generate_series(1, 100) n;
INSERT INTO initech.events (user_id, event_type) SELECT (random()*9+1)::int, 'login' FROM generate_series(1, 500) n;

-- Seed hooli (MODERATE-HEAVY)
INSERT INTO hooli.users (email, name, role) SELECT 'user' || n || '@hooli.com', 'Hooli User ' || n, CASE WHEN n <= 4 THEN 'admin' ELSE 'member' END FROM generate_series(1, 40) n;
INSERT INTO hooli.projects (name, owner_id) SELECT 'HProject ' || n, (random()*39+1)::int FROM generate_series(1, 15) n;
INSERT INTO hooli.tasks (project_id, title, assignee_id, status, priority)
SELECT (random()*14+1)::int, 'HTask ' || n, (random()*39+1)::int,
  (ARRAY['todo','in_progress','done'])[floor(random()*3+1)::int], floor(random()*5+1)::int
FROM generate_series(1, 1000) n;
INSERT INTO hooli.events (user_id, event_type) SELECT (random()*39+1)::int, 'api_call' FROM generate_series(1, 5000) n;
INSERT INTO hooli.invoices (user_id, amount, status) SELECT (random()*39+1)::int, (random()*8000)::numeric(12,2), 'pending' FROM generate_series(1, 200) n;

-- Seed remaining tenants (MINIMAL)
INSERT INTO pied_piper.users (email, name) SELECT 'user' || n || '@piedpiper.com', 'PP User ' || n FROM generate_series(1, 8) n;
INSERT INTO pied_piper.events (user_id, event_type) SELECT (random()*7+1)::int, 'login' FROM generate_series(1, 200) n;

INSERT INTO stark_industries.users (email, name) SELECT 'user' || n || '@stark.com', 'Stark User ' || n FROM generate_series(1, 25) n;
INSERT INTO stark_industries.events (user_id, event_type) SELECT (random()*24+1)::int, 'click' FROM generate_series(1, 2000) n;

INSERT INTO wayne_enterprises.users (email, name) SELECT 'user' || n || '@wayne.com', 'Wayne User ' || n FROM generate_series(1, 20) n;
INSERT INTO wayne_enterprises.events (user_id, event_type) SELECT (random()*19+1)::int, 'page_view' FROM generate_series(1, 1500) n;

INSERT INTO umbrella_corp.users (email, name) SELECT 'user' || n || '@umbrella.com', 'Umbrella User ' || n FROM generate_series(1, 10) n;
INSERT INTO umbrella_corp.events (user_id, event_type) SELECT (random()*9+1)::int, 'api_call' FROM generate_series(1, 800) n;

INSERT INTO cyberdyne.users (email, name) SELECT 'user' || n || '@cyberdyne.com', 'Cyberdyne User ' || n FROM generate_series(1, 15) n;
INSERT INTO cyberdyne.events (user_id, event_type) SELECT (random()*14+1)::int, 'search' FROM generate_series(1, 1000) n;

INSERT INTO oscorp.users (email, name) SELECT 'user' || n || '@oscorp.com', 'Oscorp User ' || n FROM generate_series(1, 5) n;
INSERT INTO oscorp.events (user_id, event_type) SELECT (random()*4+1)::int, 'login' FROM generate_series(1, 100) n;

ANALYZE;

-- Reset stats and run realistic workload
SELECT pg_stat_statements_reset();

-- Acme HAMMERS the DB (noisy neighbor!)
SELECT count(*) FROM acme_corp.events WHERE created_at > NOW() - interval '1 day';
SELECT count(*) FROM acme_corp.events WHERE created_at > NOW() - interval '1 day';
SELECT count(*) FROM acme_corp.events WHERE created_at > NOW() - interval '1 day';
SELECT count(*) FROM acme_corp.events WHERE created_at > NOW() - interval '1 day';
SELECT count(*) FROM acme_corp.events WHERE created_at > NOW() - interval '1 day';
SELECT * FROM acme_corp.tasks WHERE status = 'todo' ORDER BY priority, created_at LIMIT 100;
SELECT * FROM acme_corp.tasks WHERE status = 'todo' ORDER BY priority, created_at LIMIT 100;
SELECT * FROM acme_corp.tasks WHERE status = 'todo' ORDER BY priority, created_at LIMIT 100;
SELECT u.name, count(t.id) FROM acme_corp.users u LEFT JOIN acme_corp.tasks t ON t.assignee_id = u.id GROUP BY u.name;
SELECT u.name, count(t.id) FROM acme_corp.users u LEFT JOIN acme_corp.tasks t ON t.assignee_id = u.id GROUP BY u.name;
SELECT * FROM acme_corp.events ORDER BY created_at DESC LIMIT 1000;
SELECT * FROM acme_corp.events ORDER BY created_at DESC LIMIT 1000;
SELECT * FROM acme_corp.events ORDER BY created_at DESC LIMIT 1000;
SELECT * FROM acme_corp.invoices WHERE status = 'overdue' ORDER BY amount DESC;
SELECT count(*) FROM acme_corp.users WHERE last_login > NOW() - interval '7 days';

-- Hooli does moderate work
SELECT * FROM hooli.tasks WHERE status = 'todo' LIMIT 50;
SELECT * FROM hooli.tasks WHERE status = 'todo' LIMIT 50;
SELECT count(*) FROM hooli.invoices WHERE status = 'overdue';
SELECT count(*) FROM hooli.events;

-- Globex does some work
SELECT count(*) FROM globex_inc.tasks WHERE status = 'in_progress';
SELECT * FROM globex_inc.users WHERE last_login > NOW() - interval '7 days';
SELECT count(*) FROM globex_inc.events;

-- Initech barely queries
SELECT count(*) FROM initech.events;
SELECT count(*) FROM initech.users;

-- Pied Piper: minimal
SELECT count(*) FROM pied_piper.users;
