import json
from detections import detect_failed_logins, detect_unusual_regions, detect_sensitive_api_calls, detect_privilege_escalation

def load_events(filename):
        try:
                with open(filename, "r") as f:
                        data = json.load(f)
                        events = data["Records"]
        except FileNotFoundError as e:
                print(f"{e} ensure you are using .json")
                return []
        except json.JSONDecodeError as e:
                print(f"{e} ensure you are using .json")
                return []
        return events

def generate_report(num_of_events, failed_logins, unusual_regions, sensitive_api, priv_escalation):
    print("=" * 50)
    print("     CLOUDTRAIL SECURITY ANALYSIS REPORT")
    print("=" * 50)
    print(f"\nTotal events analyzed: {num_of_events}")

    print("\n" + "-" * 50)
    print("  FAILED CONSOLE LOGINS")
    print("-" * 50)
    if failed_logins:
        for user, ips in failed_logins.items():
            print(f"  User: {user}")
            print(f"    Attempts: {len(ips)}")
            print(f"    Source IPs: {', '.join(set(ips))}")
    else:
        print("  No failed logins detected.")

    print("\n" + "-" * 50)
    print("  UNUSUAL REGIONS")
    print("-" * 50)
    if unusual_regions:
        for region, count in unusual_regions.items():
            print(f"  {region}: {count} event(s)")
    else:
        print("  No unusual regions detected.")

    print("\n" + "-" * 50)
    print("  SENSITIVE API CALLS")
    print("-" * 50)
    if sensitive_api:
        for user, calls in sensitive_api.items():
            print(f"  User: {user}")
            print(f"    Actions: {', '.join(calls)}")
    else:
        print("  No sensitive API calls detected.")

    print("\n" + "-" * 50)
    print("  POSSIBLE PRIVILEGE ESCALATION")
    print("-" * 50)
    if priv_escalation:
        for user, calls in priv_escalation.items():
            print(f"  User: {user}")
            print(f"    Actions: {', '.join(calls)}")
            print(f"    WARNING: {len(calls)} sensitive actions by single user")
    else:
        print("  No privilege escalation detected.")

    print("\n" + "=" * 50)
    print("  END OF REPORT")
    print("=" * 50)

if __name__ =="__main__":
	events = load_events("sample_cloudtrail.json")
	num_of_events = len(events)
	failed_logins = detect_failed_logins(events)
	unusual_regions = detect_unusual_regions(events)
	sensitive_api = detect_sensitive_api_calls(events)
	priv_escalation = detect_privilege_escalation(sensitive_api)
	generate_report(num_of_events, failed_logins, unusual_regions, sensitive_api, priv_escalation)

