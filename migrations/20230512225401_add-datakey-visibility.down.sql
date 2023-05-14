-- Add down migration script here
ALTER TABLE data_key DROP visibility;
ALTER TABLE data_key ADD soft_delete BOOLEAN NOT NULL default 0;
ALTER TABLE data_key ADD email VARCHAR(40) NOT NULL;
DROP TABLE IF EXISTS request_delete;