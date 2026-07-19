from mitre_mapping import mitre_mapping


def enrich_finding(action):
    clean_action = action.split(":")[-1]
    mitre = mitre_mapping.get(clean_action)
    return {"action": action, "mitre": mitre}   # mitre is None if no match


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
            for action in calls:
                finding = enrich_finding(action)
                mitre = finding["mitre"]
                if mitre:
                    print(f"    {action}  →  {mitre['id']} - {mitre['name']}")
                else:
                    print(f"    {action}")
    else:
        print("  No sensitive API calls detected.")
    print("\n" + "-" * 50)
    print("  POSSIBLE PRIVILEGE ESCALATION")
    print("-" * 50)
    if priv_escalation:
        for user, calls in priv_escalation.items():
            print(f"  User: {user}")
            for action in calls:
                finding = enrich_finding(action)
                mitre = finding["mitre"]
                if mitre:
                    print(f"    {action}  →  {mitre['id']} - {mitre['name']}")
                else:
                    print(f"    {action}")
            print(f"    WARNING: {len(calls)} sensitive actions by single user")
    else:
        print("  No privilege escalation detected.")
    print("\n" + "=" * 50)
    print("  END OF REPORT")


def build_alert_message(num_of_events, failed_logins, unusual_regions, sensitive_api, priv_escalation):
    lines = []
    lines.append("CloudTrail Security Alert")
    lines.append(f"Total events analyzed: {num_of_events}")
    lines.append(f"Failed logins: {len(failed_logins)}")
    lines.append(f"Unusual regions: {len(unusual_regions)}")
    if sensitive_api:
        lines.append("")
        lines.append("Sensitive API calls:")
        for user, calls in sensitive_api.items():
            lines.append(f"  User: {user}")
            for action in calls:
                finding = enrich_finding(action)
                mitre = finding["mitre"]
                if mitre:
                    lines.append(f"    {action} -> {mitre['id']} - {mitre['name']}")
                else:
                    lines.append(f"    {action}")
    if priv_escalation:
        lines.append("")
        lines.append("Privilege escalation:")
        for user, calls in priv_escalation.items():
            lines.append(f"  User: {user}")
            for action in calls:
                finding = enrich_finding(action)
                mitre = finding["mitre"]
                if mitre:
                    lines.append(f"    {action} -> {mitre['id']} - {mitre['name']}")
                else:
                    lines.append(f"    {action}")
            lines.append(f"    WARNING: {len(calls)} sensitive actions by single user")
    return "\n".join(lines)
