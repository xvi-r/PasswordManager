import sqlite3
from flask import g 

DATABASE = "users.db"

def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DATABASE)
    return g.db

        
def init_db():
    con = sqlite3.connect(DATABASE)
    cursor = con.cursor()
    con.execute("PRAGMA foreign_keys = ON")
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            vault BLOB
        )
    """)
    
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS refresh_tokens (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            token_hash TEXT NOT NULL,
            expires_at INTEGER NOT NULL,
            created_at INTEGER NOT NULL,
            revoked INTEGER DEFAULT 0,
            device_uid INTEGER NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
        """)
    
    cursor.execute("""
    CREATE INDEX IF NOT EXISTS idx_refresh_tokens_user_id
    ON refresh_tokens(user_id)
    """)


    con.commit()
    con.close()