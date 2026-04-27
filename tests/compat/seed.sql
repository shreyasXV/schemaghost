-- FaultWall compatibility test seed
CREATE DATABASE faultwall_test;
CREATE USER appuser WITH PASSWORD 'apppass123';
GRANT ALL PRIVILEGES ON DATABASE faultwall_test TO appuser;
\c faultwall_test
GRANT ALL ON SCHEMA public TO appuser;
CREATE TABLE feedback(id serial primary key, user_id int, body text, created_at timestamptz DEFAULT now());
CREATE TABLE users(id serial primary key, email text, password_hash text);
CREATE TABLE payments(id serial primary key, user_id int, amount numeric);
INSERT INTO feedback(user_id, body) VALUES (1, 'test feedback'), (2, 'another feedback');
INSERT INTO users(email, password_hash) VALUES ('a@b.com', 'hash1'), ('c@d.com', 'hash2');
INSERT INTO payments(user_id, amount) VALUES (1, 100), (2, 200);
GRANT ALL ON ALL TABLES IN SCHEMA public TO appuser;
GRANT ALL ON ALL SEQUENCES IN SCHEMA public TO appuser;
