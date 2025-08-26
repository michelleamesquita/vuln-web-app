CREATE DATABASE knights;
use knights;


CREATE TABLE IF NOT EXISTS accounts (
    id int(11) NOT NULL AUTO_INCREMENT,
    username varchar(50) NOT NULL,
    password varchar(255) NOT NULL,
    email varchar(100) NOT NULL,
    cpf varchar(255),
    PRIMARY KEY (id)
) ENGINE=InnoDB AUTO_INCREMENT=2 DEFAULT CHARSET=utf8;

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


