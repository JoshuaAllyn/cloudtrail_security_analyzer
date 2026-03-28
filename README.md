# CloudTrail Security Analyzer

A Python-based command-line tool that analyzes AWS CloudTrail JSON logs to detect security threats and suspicious activity. Designed for cloud security engineers who need quick, automated threat detection across CloudTrail event data.

**Author:** Josh Allyn — [LinkedIn](https://www.linkedin.com/in/joshuaallyn/)

## Features

- **Failed Login Detection** — Identifies failed ConsoleLogin attempts, grouped by user and source IP
- **Unusual Region Detection** — Flags AWS regions that appear in less than 10% of total events, catching activity outside your organization's normal operating regions
- **Sensitive API Call Detection** — Monitors for high-risk API calls including `CreateUser`, `AttachUserPolicy`, `DeleteTrail`, `CreateAccessKey`, `PutBucketPolicy`, and `AuthorizeSecurityGroupIngress`
- **Privilege Escalation Detection** — Identifies users making two or more sensitive API calls, a common indicator of privilege escalation or account compromise
- **Error Handling** — Gracefully handles missing files, malformed JSON, and incomplete event records

## Requirements

- Python 3.6+
- No external dependencies — uses only Python standard library (`json`)

## Usage

1. Place your CloudTrail JSON log file in the same directory as the script
2. Update the filename in the script or rename your file to `sample_cloudtrail.json`
3. Run the analyzer:

```bash
python3 cloudtrail_analyzer.py
```

CloudTrail JSON files must follow the standard AWS format with events nested under a `"Records"` key.

## Sample Output

```
==================================================
     CLOUDTRAIL SECURITY ANALYSIS REPORT
==================================================

Total events analyzed: 15

--------------------------------------------------
  FAILED CONSOLE LOGINS
--------------------------------------------------
  User: admin
    Attempts: 3
    Source IPs: 203.0.113.99
  User: rogue-user
    Attempts: 1
    Source IPs: 203.0.113.50

--------------------------------------------------
  UNUSUAL REGIONS
--------------------------------------------------
  eu-west-1: 1 event(s)
  ap-northeast-2: 1 event(s)

--------------------------------------------------
  SENSITIVE API CALLS
--------------------------------------------------
  User: jsmith
    Actions: CreateUser, AttachUserPolicy, AuthorizeSecurityGroupIngress
  User: rogue-user
    Actions: DeleteTrail, CreateAccessKey
  User: deploy-bot
    Actions: PutBucketPolicy

--------------------------------------------------
  POSSIBLE PRIVILEGE ESCALATION
--------------------------------------------------
  User: jsmith
    Actions: CreateUser, AttachUserPolicy, AuthorizeSecurityGroupIngress
    WARNING: 3 sensitive actions by single user
  User: rogue-user
    Actions: DeleteTrail, CreateAccessKey
    WARNING: 2 sensitive actions by single user

==================================================
  END OF REPORT
==================================================
```

## Project Structure

```
cloudtrail-security-analyzer/
├── cloudtrail_analyzer.py      # Main analysis script
├── sample_cloudtrail.json      # Sample CloudTrail data for testing
└── README.md                   # This file
```

## How It Works

The analyzer reads a CloudTrail JSON file and runs four detection functions against the event data:

1. **load_events()** — Parses the JSON file and extracts the Records array with error handling for missing files and invalid JSON
2. **detect_failed_logins()** — Filters for ConsoleLogin events with a Failure response, groups results by username and collects source IPs
3. **detect_unusual_regions()** — Counts events per AWS region and flags any region representing less than 10% of total activity
4. **detect_sensitive_api_calls()** — Checks each event against a predefined list of high-risk API actions and groups findings by user
5. **detect_privilege_escalation()** — Analyzes the sensitive API results to identify users with two or more flagged actions

## Customization

- **Sensitive API calls:** Edit the `sensitive_calls` list in `detect_sensitive_api_calls()` to add or remove monitored API actions
- **Region threshold:** Adjust the `0.10` threshold in `detect_unusual_regions()` to change sensitivity (lower = more alerts)

## License

MIT
