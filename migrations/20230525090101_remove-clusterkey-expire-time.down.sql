-- Add down migration script here
ALTER TABLE cluster_key ADD expire_at DATETIME DEFAULT CURRENT_TIMESTAMP AFTER `create_at`;