import json
import os

_DEFAULT_PATH = os.path.normpath(
    os.path.join(os.path.dirname(__file__), "..", "data", "enterprise-attack.json")
)


def load_techniques(path=_DEFAULT_PATH):
    with open(path, "r") as f:
        data = json.load(f)
    result = {}
    for obj in data["objects"]:
        if obj["type"] != "attack-pattern":
            continue
        if obj.get("revoked") or obj.get("x_mitre_deprecated"):
            continue
        tid = next(
            (ref["external_id"] for ref in obj.get("external_references", [])
             if ref.get("source_name") == "mitre-attack"),
            None,
        )
        if tid is None:
            continue
        result[tid] = {
            "name": obj["name"],
            "description": obj["description"],
            "tactics": [
                phase["phase_name"]
                for phase in obj.get("kill_chain_phases", [])
                if phase.get("kill_chain_name") == "mitre-attack"
            ],
        }
    return result
