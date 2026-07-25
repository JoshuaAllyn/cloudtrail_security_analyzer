class CloudTrailEvent:
    def __init__(self, event_name, source_ip, user_identity, event_time, event_source):
        self.event_name = event_name
        self.source_ip = source_ip
        self.user_identity = user_identity
        self.event_time = event_time
        self.event_source = event_source

    def to_dict(self):
        return {
            "eventName": self.event_name,
            "sourceIPAddress": self.source_ip,
            "userIdentity": self.user_identity,
            "eventTime": self.event_time,
            "eventSource": self.event_source
        }
