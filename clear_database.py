import sqlite3

DATABASE = "data/security_logs.db"

connection = sqlite3.connect(DATABASE)
cursor = connection.cursor()

cursor.execute("DELETE FROM security_alerts")

connection.commit()
connection.close()

print("All old security alerts have been cleared.")
