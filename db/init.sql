CREATE DATABASE knights;
use knights;


CREATE TABLE accounts (
	  id int(11) NOT NULL ,
  	username VARCHAR(50) NOT NULL,
  	password VARCHAR(255) NOT NULL,
  	email VARCHAR(100) NOT NULL,
    PRIMARY KEY (id)
);

INSERT INTO accounts (id, username, password, email) VALUES (1, 'test', 'test', 'test@test.com');
