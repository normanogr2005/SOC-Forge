from .detector import detect_brute_force, detect_failed_login
from .parser import parse_log_file
from .storage import init_db, save_alert


def main() -> None:
    init_db()

    events = parse_log_file("logs/auth.log")

    print(f"[INFO] Events processed: {len(events)}")
    print()

    alerts = 0

    # AUTH-001: intentos individuales fallidos
    for event in events:
        alert = detect_failed_login(event)

        if alert:
            alerts += 1
            save_alert(alert)

            print(f"[ALERT] {alert.rule_id}")
            print(f"Severity: {alert.severity}")
            print(f"Source IP: {event.source_ip}")
            print(f"Message: {alert.message}")
            print("-" * 50)

    # AUTH-002: múltiples intentos desde una misma IP
    brute_force_alerts = detect_brute_force(events)

    for alert in brute_force_alerts:
        alerts += 1
        save_alert(alert)

        print(f"[ALERT] {alert.rule_id}")
        print(f"Severity: {alert.severity}")
        print(f"Source IP: {alert.event.source_ip}")
        print(f"Message: {alert.message}")
        print("-" * 50)

    print(f"[INFO] Alerts generated: {alerts}")


if __name__ == "__main__":
    main()