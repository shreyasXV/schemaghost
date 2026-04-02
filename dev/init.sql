-- FaultWall demo seed: tables matching policies.yaml agent missions

CREATE EXTENSION IF NOT EXISTS pg_stat_statements;

-- ── public.feedback — agents can read this ──
CREATE TABLE IF NOT EXISTS public.feedback (
    id SERIAL PRIMARY KEY,
    agent_id TEXT NOT NULL,
    mission TEXT NOT NULL,
    content TEXT NOT NULL,
    rating INT CHECK (rating BETWEEN 1 AND 5),
    created_at TIMESTAMPTZ DEFAULT NOW()
);

INSERT INTO public.feedback (agent_id, mission, content, rating) VALUES
    ('cursor-ai', 'summarize-feedback', 'Great autocomplete suggestions', 5),
    ('cursor-ai', 'summarize-feedback', 'Sometimes suggests deprecated APIs', 3),
    ('langchain-agent', 'research', 'Found relevant papers quickly', 4),
    ('demo-agent', 'read-feedback', 'Testing the feedback loop', 4),
    ('cursor-ai', 'update-shipping', 'Shipping updates were accurate', 5),
    ('langchain-agent', 'research', 'Missed some recent publications', 2),
    ('demo-agent', 'read-feedback', 'Policy engine works as expected', 5),
    ('cursor-ai', 'summarize-feedback', 'Tab completion could be faster', 3);

-- ── public.products — agents can read this ──
CREATE TABLE IF NOT EXISTS public.products (
    id SERIAL PRIMARY KEY,
    name TEXT NOT NULL,
    price NUMERIC(10,2) NOT NULL,
    category TEXT NOT NULL,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

INSERT INTO public.products (name, price, category) VALUES
    ('PostgreSQL Handbook', 49.99, 'books'),
    ('SQL Debugging Tool', 199.00, 'software'),
    ('Database Monitor Pro', 299.00, 'software'),
    ('Query Optimizer Guide', 39.99, 'books'),
    ('FaultWall Enterprise License', 999.00, 'licenses'),
    ('Cloud DB Hosting (monthly)', 59.99, 'services');

-- ── public.users — BLOCKED (PII) ──
CREATE TABLE IF NOT EXISTS public.users (
    id SERIAL PRIMARY KEY,
    email TEXT UNIQUE NOT NULL,
    name TEXT NOT NULL,
    password_hash TEXT NOT NULL,
    ssn TEXT NOT NULL,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

INSERT INTO public.users (email, name, password_hash, ssn) VALUES
    ('alice@example.com', 'Alice Johnson', '$2b$12$fakehashaaaaaaaaaaaaa', '123-45-6789'),
    ('bob@example.com', 'Bob Smith', '$2b$12$fakehashbbbbbbbbbbbbbb', '987-65-4321'),
    ('carol@example.com', 'Carol Davis', '$2b$12$fakehashcccccccccccccc', '456-78-9012'),
    ('dave@example.com', 'Dave Wilson', '$2b$12$fakehashdddddddddddddd', '321-54-9876'),
    ('eve@example.com', 'Eve Martinez', '$2b$12$fakehasheeeeeeeeeeeeee', '654-32-1098');

-- ── public.payments — BLOCKED (PII) ──
CREATE TABLE IF NOT EXISTS public.payments (
    id SERIAL PRIMARY KEY,
    user_id INT REFERENCES public.users(id),
    amount NUMERIC(10,2) NOT NULL,
    card_last4 TEXT NOT NULL,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

INSERT INTO public.payments (user_id, amount, card_last4) VALUES
    (1, 49.99, '4242'),
    (2, 199.00, '1234'),
    (3, 299.00, '5678'),
    (1, 39.99, '4242'),
    (4, 999.00, '9999'),
    (5, 59.99, '3333');
