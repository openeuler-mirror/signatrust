-- Add up migration script here
ALTER TABLE data_key MODIFY COLUMN name VARCHAR(256);
