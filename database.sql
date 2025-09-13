CREATE DATABASE IF NOT EXISTS database_utenti;
USE database_utenti;
CREATE TABLE users (
    userid INT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(16) NOT NULL UNIQUE,
    email VARCHAR(50) NOT NULL,
    password VARCHAR(50) NOT NULL
);
INSERT INTO users(username,email,password)
VALUES ('admin','admin','admin')