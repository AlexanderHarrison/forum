#!/bin/bash
rm -f db.sqlite
echo "
CREATE TABLE chatlog (
    user_id INT8 REFERENCES users(id),
    message TEXT NOT NULL
);
CREATE TABLE users (
    user_id INT8 PRIMARY KEY,
    username TEXT NOT NULL,
    email TEXT NOT NULL,
    login_salt INT8,
    login_hash INT8
);
CREATE TABLE sessions (
    session_id INT8 PRIMARY KEY,
    user_id INT8 REFERENCES users(id) ON DELETE CASCADE
);
" | sqlite3 db.sqlite

