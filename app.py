from flask import Flask, render_template, send_file
import sqlite3

from report import generate_report

app = Flask(__name__)

DATABASE = "data/security_logs.db"


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


@app.route("/")
def dashboard():

    alerts = get_alerts()

    return render_template(
        "dashboard.html",
        alerts=alerts
    )


@app.route("/generate-report")
def generate_security_report():

    generate_report()

    return send_file(
        "reports/security_report.txt",
        as_attachment=True
    )


if __name__ == "__main__":

    app.run(debug=True)