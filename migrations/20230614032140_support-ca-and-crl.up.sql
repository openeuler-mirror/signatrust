-- Add up migration script here
# Support for parent_id and serial_number
ALTER TABLE data_key ADD parent_id INT AFTER `key_type`;
ALTER TABLE data_key ADD serial_number VARCHAR(90) AFTER `fingerprint`;
ALTER TABLE data_key MODIFY COLUMN key_state varchar(20);

# Break changes: request delete will be dropped&recreated to support different pending operation
DROP TABLE IF EXISTS request_delete;
CREATE TABLE pending_operation (
                id INT AUTO_INCREMENT,
                user_id INT NOT NULL,
                key_id INT NOT NULL,
                request_type VARCHAR(30) NOT NULL,
                user_email varchar(60) NOT NULL,
                reason VARCHAR(200),
                create_at DATETIME,
                PRIMARY KEY(id),
                FOREIGN KEY (user_id) REFERENCES user(id),
                FOREIGN KEY (key_id) REFERENCES data_key(id),
                UNIQUE KEY `unique_user_and_key_and_type` (`user_id`,`key_id`, `request_type`)
);

# Add new table for crl content and revoked certificates
CREATE TABLE x509_crl_content (
            id INT AUTO_INCREMENT,
            ca_id INT NOT NULL,
            create_at DATETIME,
            update_at DATETIME,
            data TEXT NOT NULL,
            PRIMARY KEY(id),
            FOREIGN KEY (ca_id) REFERENCES data_key(id)
);
CREATE TABLE x509_keys_revoked (
            id INT AUTO_INCREMENT,
            ca_id INT NOT NULL,
            key_id INT NOT NULL,
            create_at DATETIME,
            reason VARCHAR(30),
            FOREIGN KEY (ca_id) REFERENCES data_key(id),
            FOREIGN KEY (key_id) REFERENCES data_key(id),
            UNIQUE KEY `unique_ca_and_key` (`ca_id`,`key_id`),
            PRIMARY KEY(id)
);