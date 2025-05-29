#!/bin/bash
rm -f db.sqlite
echo "CREATE TABLE rows ( text TEXT NOT NULL );" | sqlite3 db.sqlite

