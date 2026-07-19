import json
import os

def _resolve_data_path():
    here = os.path.dirname(__file__)
    candidates = [
        os.path.join(here, "data", "enterprise-attack.json"),         # flat (Lambda)
        os.path.join(here, "..", "data", "enterprise-attack.json"),   # src/ sibling (CLI)
    ]
    for c in candidates:
        if os.path.exists(c):
            return os.path.normpath(c)
    return os.path.normpath(candidates[0])

_DEFAULT_PATH = _resolve_data_path()

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
