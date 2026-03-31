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
        sensitive_calls = ["CreateUser", "AttachUserPolicy", "DeleteTrail", "CreateAccessKey", "PutBucketPolicy", "AuthorizeSecurityGroupIngress"]
        sensitive = {}
        for event in events:
                if event["eventName"] in sensitive_calls:
                        user = event["userIdentity"]["userName"]
                        if user not in sensitive:
                                sensitive[user] = []
                        sensitive[user].append(event["eventName"])
        return sensitive

def detect_privilege_escalation(sensitive_api):
        suspicious_users = {}
        for user, event in sensitive_api.items():
                if len(event) >= 2:
                        suspicious_users[user] = event
        return suspicious_users
