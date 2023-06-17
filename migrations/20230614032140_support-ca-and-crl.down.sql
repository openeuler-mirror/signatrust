-- Add down migration script here
DROP TABLE IF EXISTS x509_keys_revoked;
DROP TABLE IF EXISTS x509_crl_content;
ALTER TABLE data_key DROP parent_id;
ALTER TABLE data_key DROP serial_number;
ALTER TABLE data_key MODIFY COLUMN key_state varchar(10);

DROP TABLE IF EXISTS pending_operation;
CREATE TABLE request_delete (
            id INT AUTO_INCREMENT,
            user_id INT NOT NULL,
            key_id INT NOT NULL,
            create_at DATETIME,
            PRIMARY KEY(id),
            FOREIGN KEY (user_id) REFERENCES user(id),
            FOREIGN KEY (key_id) REFERENCES data_key(id),
            UNIQUE KEY `unique_user_and_key` (`user_id`,`key_id`)
);
