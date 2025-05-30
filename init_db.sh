#!/bin/bash
rm -f db.sqlite
echo "CREATE TABLE chatlog ( username TEXT NOT NULL, message TEXT NOT NULL );" | sqlite3 db.sqlite

