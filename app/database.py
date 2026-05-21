import sqlite3
import os
from pathlib import Path

if os.environ.get("VERCEL"):
    DB_PATH = Path("/tmp/aegis_demo.db")
else:
    DB_PATH = Path(__file__).resolve().parent / "aegis_demo.db"


def get_connection():
    return sqlite3.connect(DB_PATH)


def initialize_database():
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            role TEXT NOT NULL,
            api_key TEXT NOT NULL
        )
    """)

    cursor.execute("DELETE FROM users")

    users = [
        ("admin", "administrator", "ADMIN-API-KEY-12345"),
        ("devuser", "developer", "DEV-API-KEY-67890"),
        ("guest", "guest", "GUEST-API-KEY-00000")
    ]

    cursor.executemany(
        "INSERT INTO users (username, role, api_key) VALUES (?, ?, ?)",
        users
    )

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS waf_rules (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            pattern TEXT NOT NULL,
            description TEXT NOT NULL,
            enabled INTEGER NOT NULL DEFAULT 1
        )
    """)

    cursor.execute("DELETE FROM waf_rules")

    waf_rules = [
        ("' OR '", "SQL Injection (OR operator bypass)", 1),
        ("1=1", "SQL Injection (tautology bypass)", 1),
        ("--", "SQL comment character block", 1),
        ("cat /etc/passwd", "LFI/Command execution pattern 1", 1),
        ("\\.\\./", "Directory Traversal pattern (../)", 1),
        ("pickle\\.loads", "Python deserialization hijack detector", 1),
        ("eval\\(", "Python dynamic expression injection detector", 1)
    ]

    cursor.executemany(
        "INSERT INTO waf_rules (pattern, description, enabled) VALUES (?, ?, ?)",
        waf_rules
    )

    conn.commit()
    conn.close()

