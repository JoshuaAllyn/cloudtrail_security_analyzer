from mitre_intel import load_techniques
from mitre_mapping import mitre_mapping
from cloudtrail_event import CloudTrailEvent


class MitreEnricher:
    def __init__(self):
        self.techniques = load_techniques()

    def enrich(self, event: CloudTrailEvent) -> dict | None:
        technique_id = mitre_mapping.get(event.event_name)
        if technique_id is None:
            return None
        technique_details = self.techniques.get(technique_id)
        if technique_details is None:
            return None
        return {
            "technique_id": technique_id,
            **technique_details
        }
