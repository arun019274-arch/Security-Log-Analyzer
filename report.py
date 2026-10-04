import sqlite3
from datetime import datetime
import os

DATABASE = "data/security_logs.db"
REPORT_FILE = "reports/security_report.txt"


def generate_report():

    print("Starting report generation...")

    os.makedirs("reports", exist_ok=True)

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

    print(f"Found {len(alerts)} alerts in database.")

    with open(REPORT_FILE, "w") as file:

        file.write("=" * 70 + "\n")
        file.write("SECURITY LOG ANALYZER - SECURITY REPORT\n")
        file.write("=" * 70 + "\n\n")

        file.write(
            "Report Generated: "
            + datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            + "\n\n"
        )

        file.write(f"Total Alerts: {len(alerts)}\n\n")

        if not alerts:

            file.write("No security alerts found.\n")

        else:

            for alert in alerts:

                file.write("-" * 70 + "\n")
                file.write(f"Alert ID    : {alert['id']}\n")
                file.write(f"Alert Type  : {alert['alert_type']}\n")
                file.write(f"IP Address  : {alert['ip_address']}\n")
                file.write(f"Username    : {alert['username']}\n")
                file.write(f"Attempts    : {alert['attempts']}\n")
                file.write(f"Risk Level  : {alert['risk_level']}\n")
                file.write(f"Description : {alert['description']}\n")
                file.write(f"Timestamp   : {alert['timestamp']}\n")

            file.write("-" * 70 + "\n")

    print("Security report generated successfully.")
    print(f"Report location: {REPORT_FILE}")


if __name__ == "__main__":

    print("Running report.py...")

    generate_report()