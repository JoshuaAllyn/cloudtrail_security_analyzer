from mitre_mapping import mitre_mapping

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
                clean_action = action.split(":")[-1]
                mitre = mitre_mapping.get(clean_action)
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
                clean_action = action.split(":")[-1]
                mitre = mitre_mapping.get(clean_action)
                if mitre:
                    print(f"    {action}  →  {mitre['id']} - {mitre['name']}")
                else:
                    print(f"    {action}")
            print(f"    WARNING: {len(calls)} sensitive actions by single user")
    else:
        print("  No privilege escalation detected.")
    print("\n" + "=" * 50)
    print("  END OF REPORT")
