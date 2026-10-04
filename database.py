import sqlite3
from datetime import datetime

DATABASE = "data/security_logs.db"


def create_database():

    connection = sqlite3.connect(DATABASE)
    cursor = connection.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS security_alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            alert_type TEXT,
            ip_address TEXT,
            username TEXT,
            attempts INTEGER,
            risk_level TEXT,
            description TEXT,
            timestamp TEXT
        )
    """)

    connection.commit()
    connection.close()
def save_alert(alert):

    connection = sqlite3.connect(DATABASE)
    cursor = connection.cursor()

    # Check whether the same alert already exists
    cursor.execute("""
        SELECT id
        FROM security_alerts
        WHERE alert_type = ?
          AND ip_address = ?
          AND username = ?
          AND attempts = ?
          AND risk_level = ?
    """, (
        alert["type"],
        alert["ip"],
        alert["user"],
        alert["count"],
        alert["risk"]
    ))

    existing = cursor.fetchone()

    if existing:
        connection.close()
        return False

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    cursor.execute("""
        INSERT INTO security_alerts (
            alert_type,
            ip_address,
            username,
            attempts,
            risk_level,
            description,
            timestamp
        )
        VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (
        alert["type"],
        alert["ip"],
        alert["user"],
        alert["count"],
        alert["risk"],
        alert["description"],
        timestamp
    ))

    connection.commit()
    connection.close()

    return True
def get_alerts():

    connection = sqlite3.connect(DATABASE)
    connection.row_factory = sqlite3.Row

    cursor = connection.cursor()

    cursor.execute("""
        SELECT *
        FROM security_alerts
        ORDER BY id DESC
    """)

    alerts = cursor.fetchall()

    connection.close()

    return alerts


if __name__ == "__main__":

    create_database()

    print("Database created successfully.")
    print(f"Database location: {DATABASE}")