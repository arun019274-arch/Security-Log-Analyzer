from parser import read_logs
from risk import add_risk_levels
from database import create_database, save_alert


def detect_suspicious_activity(events):

    alerts = []

    failed_attempts = {}

    # Count failed login attempts by IP
    for event in events:

        if event["event"] == "LOGIN_FAILED":

            ip = event["ip"]

            if ip not in failed_attempts:
                failed_attempts[ip] = []

            failed_attempts[ip].append(event)

    # Detect repeated failed logins
    for ip, attempts in failed_attempts.items():

        if len(attempts) >= 3:

            alerts.append({
                "type": "MULTIPLE_FAILED_LOGINS",
                "ip": ip,
                "user": attempts[-1]["user"],
                "count": len(attempts),
                "description": (
                    f"{len(attempts)} failed login attempts "
                    f"detected from {ip}"
                )
            })

    # Detect successful login after multiple failures
    for event in events:

        if event["event"] == "LOGIN_SUCCESS":

            ip = event["ip"]

            if ip in failed_attempts and len(failed_attempts[ip]) >= 3:

                alerts.append({
                    "type": "SUCCESS_AFTER_FAILURES",
                    "ip": ip,
                    "user": event["user"],
                    "count": len(failed_attempts[ip]),
                    "description": (
                        f"Successful login detected after "
                        f"{len(failed_attempts[ip])} failed attempts "
                        f"from {ip}"
                    )
                })

    return alerts


if __name__ == "__main__":

    events = read_logs()

    alerts = detect_suspicious_activity(events)

    alerts = add_risk_levels(alerts)

    create_database()

    for alert in alerts:
        save_alert(alert)

    print("\nSecurity Alerts")
    print("=" * 70)

    if not alerts:

        print("No suspicious activity detected.")

    else:

        for alert in alerts:

            print("\n" + "-" * 70)
            print(f"Alert Type  : {alert['type']}")
            print(f"IP Address  : {alert['ip']}")
            print(f"Username    : {alert['user']}")
            print(f"Attempts    : {alert['count']}")
            print(f"Risk Level  : {alert['risk']}")
            print(f"Description : {alert['description']}")

    print("\nTotal alerts:", len(alerts))