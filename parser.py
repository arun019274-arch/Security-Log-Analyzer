import re

LOG_FILE = "logs/sample_auth.log"


def parse_log_line(line):
    pattern = (
        r"(?P<timestamp>\S+\s+\S+)\s+"
        r"(?P<level>\w+)\s+"
        r"(?P<event>\w+)\s+"
        r"user=(?P<user>\S+)\s+"
        r"ip=(?P<ip>\S+)"
    )

    match = re.match(pattern, line.strip())

    if not match:
        return None

    return {
        "timestamp": match.group("timestamp"),
        "level": match.group("level"),
        "event": match.group("event"),
        "user": match.group("user"),
        "ip": match.group("ip")
    }


def read_logs():
    events = []

    with open(LOG_FILE, "r") as file:
        for line in file:
            event = parse_log_line(line)

            if event:
                events.append(event)

    return events


if __name__ == "__main__":

    events = read_logs()

    print("\nParsed Security Events")
    print("=" * 70)

    for event in events:
        print(
            f"Time: {event['timestamp']} | "
            f"Level: {event['level']} | "
            f"Event: {event['event']} | "
            f"User: {event['user']} | "
            f"IP: {event['ip']}"
        )

    print("\nTotal events:", len(events))