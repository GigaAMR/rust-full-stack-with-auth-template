-- Add migration script here
CREATE TABLE "users" (
    id SERIAL PRIMARY KEY UNIQUE,
    uuid VARCHAR(36) UNIQUE,
    username VARCHAR(24) UNIQUE,
    pass VARCHAR(60),
    email VARCHAR(254) UNIQUE,
    perms INTEGER
);