def classify_risk(alert):
    alert_type = alert["type"]
    attempts = alert["count"]

    if alert_type == "SUCCESS_AFTER_FAILURES" and attempts >= 5:
        return "Critical"

    elif alert_type == "SUCCESS_AFTER_FAILURES" and attempts >= 3:
        return "High"

    elif alert_type == "MULTIPLE_FAILED_LOGINS" and attempts >= 5:
        return "High"

    elif alert_type == "MULTIPLE_FAILED_LOGINS" and attempts >= 3:
        return "Medium"

    else:
        return "Low"


def add_risk_levels(alerts):

    for alert in alerts:
        alert["risk"] = classify_risk(alert)

    return alerts