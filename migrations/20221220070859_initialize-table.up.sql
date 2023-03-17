CREATE TABLE cluster_key (
                         id INT AUTO_INCREMENT,
                         data TEXT NOT NULL,
                         algorithm VARCHAR(30),
                         identity VARCHAR(40) UNIQUE,
                         create_at DATETIME,
                         expire_at DATETIME,
                         PRIMARY KEY(id)
);

CREATE TABLE data_key (
                          id INT AUTO_INCREMENT,
                          name VARCHAR(100) UNIQUE NOT NULL,
                          description VARCHAR(200),
                          user VARCHAR(40) NOT NULL,
                          email VARCHAR(40) NOT NULL,
                          attributes VARCHAR(1000),
                          key_type VARCHAR(10) NOT NULL,
                          private_key TEXT,
                          public_key TEXT,
                          certificate TEXT,
                          create_at DATETIME,
                          expire_at DATETIME,
                          key_state VARCHAR(10) NOT NULL,
                          soft_delete BOOLEAN NOT NULL default 0,
                          PRIMARY KEY(id)
);

CREATE TABLE user (
                          id INT AUTO_INCREMENT,
                          email VARCHAR(60) UNIQUE,
                          PRIMARY KEY(id)
);


CREATE TABLE token (
                          id INT AUTO_INCREMENT,
                          user_id INT NOT NULL,
                          token VARCHAR(200),
                          expire_at DATETIME,
                          PRIMARY KEY(id),
                          FOREIGN KEY (user_id) REFERENCES user(id)

);
