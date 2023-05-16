-- Add up migration script here
ALTER TABLE data_key ADD visibility varchar(10) NOT NULL DEFAULT 'public' AFTER `description`;
ALTER TABLE data_key DROP soft_delete;
ALTER TABLE data_key DROP email;
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
