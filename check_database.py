import sqlite3

DATABASE = "data/security_logs.db"

connection = sqlite3.connect(DATABASE)
cursor = connection.cursor()

cursor.execute("""
    SELECT
        id,
        alert_type,
        ip_address,
        username,
        attempts,
        risk_level,
        description,
        timestamp
    FROM security_alerts
    ORDER BY id DESC
""")

alerts = cursor.fetchall()

print("\nStored Security Alerts")
print("=" * 80)

for alert in alerts:

    print("\n" + "-" * 80)
    print(f"ID          : {alert[0]}")
    print(f"Alert Type  : {alert[1]}")
    print(f"IP Address  : {alert[2]}")
    print(f"Username    : {alert[3]}")
    print(f"Attempts    : {alert[4]}")
    print(f"Risk Level  : {alert[5]}")
    print(f"Description : {alert[6]}")
    print(f"Timestamp   : {alert[7]}")

print("\nTotal stored alerts:", len(alerts))

connection.close()python check_database.py