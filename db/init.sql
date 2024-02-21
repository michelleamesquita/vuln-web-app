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


CREATE TABLE comments (
	  id int(11) NOT NULL AUTO_INCREMENT,

  	comment VARCHAR(100) NOT NULL,
    PRIMARY KEY (id)
);

CREATE TABLE personalinfo (
	  id int(11) NOT NULL ,
  	username VARCHAR(50) NOT NULL,
  	password VARCHAR(255) NOT NULL,
  	email VARCHAR(100) NOT NULL,
	cpf VARCHAR(100) NOT NULL,
    PRIMARY KEY (id)
);

INSERT INTO personalinfo (id, username, password, email, cpf) VALUES (1,'Marty Mcfly', 'delorean', 'delorean@back2future.com', '12345678900');


