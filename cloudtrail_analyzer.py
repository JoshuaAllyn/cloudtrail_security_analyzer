import json
from detections import detect_failed_logins, detect_unusual_regions, detect_sensitive_api_calls, detect_privilege_escalation
from report import generate_report

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

if __name__ =="__main__":
	events = load_events("sample_cloudtrail.json")
	num_of_events = len(events)
	failed_logins = detect_failed_logins(events)
	unusual_regions = detect_unusual_regions(events)
	sensitive_api = detect_sensitive_api_calls(events)
	priv_escalation = detect_privilege_escalation(sensitive_api)
	generate_report(num_of_events, failed_logins, unusual_regions, sensitive_api, priv_escalation)

