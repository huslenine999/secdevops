import sqlite3
from pathlib import Path

DB_PATH = Path(__file__).resolve().parent / "pyshield_demo.db"


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

    conn.commit()
    conn.close()
