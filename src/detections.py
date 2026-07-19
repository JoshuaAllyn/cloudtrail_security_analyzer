from mitre_mapping import mitre_mapping
from cloudtrail_event import CloudTrailEvent
from mitre_enricher import MitreEnricher

_enricher = MitreEnricher()

def detect_failed_logins(events):
        failed = {}
        for event in events:
                try:
                        if event["responseElements"]["ConsoleLogin"] == "Failure":
                                user = event["userIdentity"]["userName"]
                                if user not in failed:
                                        failed[user] = []
                                failed[user].append(event["sourceIPAddress"])
                except KeyError:
                        pass
        return failed

def detect_unusual_regions(events):
        counts = {}
        unusual = {}
        total = len(events)
        for event in events:
                region = event["awsRegion"]
                counts[region] = counts.get(region, 0) + 1
        for region, num in counts.items():
                if num / total < 0.10:
                        unusual[region] = num
        return unusual

def detect_sensitive_api_calls(events):
        sensitive = {}
        for event in events:
                if event["eventName"] in mitre_mapping:
                        user = event["userIdentity"]["userName"]
                        ct_event = CloudTrailEvent(
                                event_name=event["eventName"],
                                source_ip=event.get("sourceIPAddress"),
                                user_identity=user,
                                event_time=event.get("eventTime"),
                                event_source=event.get("eventSource"),
                        )
                        enrichment = _enricher.enrich(ct_event)
                        if user not in sensitive:
                                sensitive[user] = []
                        sensitive[user].append(enrichment)
        return sensitive

def detect_privilege_escalation(sensitive_api):
        suspicious_users = {}
        for user, event in sensitive_api.items():
                if len(event) >= 2:
                        suspicious_users[user] = event
        return suspicious_users
