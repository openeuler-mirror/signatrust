-- Add up migration script here
ALTER TABLE request_delete ADD user_email varchar(60) NOT NULL DEFAULT 'not recorded' AFTER `user_id`;