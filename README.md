# CloudTrail Security Analyzer

A modular Python tool for automated AWS CloudTrail threat detection, deployable as an AWS Lambda function triggered by S3 events or run locally via CLI. Detects credential attacks, unusual region activity, privilege escalation, and defense evasion — with every sensitive API call enriched against the full MITRE ATT&CK knowledge base (679 techniques, sourced directly from MITRE's STIX data).

Author: Josh Allyn — [LinkedIn](https://www.linkedin.com/in/joshuaallyn/)

## Features

- **Failed Login Detection** — Identifies failed ConsoleLogin attempts grouped by user and source IP
- **Unusual Region Detection** — Flags AWS regions representing less than 10% of total event volume, catching activity outside normal operating patterns
- **Sensitive API Call Detection** — Monitors high-risk API actions including CreateUser, AttachUserPolicy, DeleteTrail, CreateAccessKey, PutBucketPolicy, and AuthorizeSecurityGroupIngress
- **Privilege Escalation Detection** — Identifies users performing two or more sensitive API actions in a single log file
- **MITRE ATT&CK Enrichment** — Sensitive API calls are enriched with real technique data (ID, name, description, tactics) loaded from MITRE's official STIX bundle — not hardcoded strings
- **SNS Alerting** — Publishes a findings summary to an SNS topic for email or downstream integration
- **Dual Execution Modes** — Runs locally via CLI or deployed as a serverless AWS Lambda function triggered by S3 uploads

## Architecture

```
S3 Bucket (CloudTrail logs)
        │
        │  s3:ObjectCreated event
        ▼
AWS Lambda Function
┌──────────────────────────────────────────────┐
│ lambda_function.py                           │
│   ├── detections.py                          │
│   │     ├── cloudtrail_event.py  (data class)│
│   │     ├── mitre_mapping.py  (event → T-ID) │
│   │     └── mitre_enricher.py                │
│   │           └── mitre_intel.py             │
│   │                 └── data/                │
│   │                    enterprise-attack.json│
│   ├── report.py                              │
│   └── sns_alerts.py                          │
└──────────────────────────────────────────────┘
        │
        │  sns:Publish
        ▼
SNS Topic → Email / Slack / SIEM
```

## How MITRE Enrichment Works

1. `mitre_mapping.py` maps CloudTrail event names to ATT&CK technique IDs (a simple `{event_name: technique_id}` dict — the routing layer). This dict defines the detection scope: every event name in it is treated as a sensitive API call, so it contains only API actions — authentication events like ConsoleLogin are handled by their own dedicated detector.
2. `mitre_intel.py` parses MITRE's official STIX 2.1 bundle (`data/enterprise-attack.json`) into a lookup of all 679 enterprise techniques, keyed by technique ID.
3. `MitreEnricher` (in `mitre_enricher.py`) resolves each detected event's technique ID into full technique data: canonical name, description, and tactics.
4. `detections.py` wraps matched events in `CloudTrailEvent` objects and passes them through the enricher, so reports and alerts carry real ATT&CK intelligence.

Adding a new detection is one dict entry: map the CloudTrail event name to its technique ID, and enrichment resolves the rest from the STIX data automatically.

The STIX bundle path is resolved per execution mode: relative to the Lambda task root (`/var/task/data/`) when deployed, relative to the repo when run via CLI.

## Project Structure

```
cloudtrail_security_analyzer/
├── src/
│   ├── cloudtrail_analyzer.py  # CLI entry point (argparse)
│   ├── lambda_function.py      # Lambda handler (S3 event trigger)
│   ├── detections.py           # Four detection functions
│   ├── cloudtrail_event.py     # CloudTrailEvent data class
│   ├── mitre_mapping.py        # Event name → ATT&CK technique ID
│   ├── mitre_intel.py          # STIX bundle parser (679 techniques)
│   ├── mitre_enricher.py       # Enrichment wrapper
│   ├── report.py               # Report + alert message generation
│   └── sns_alerts.py           # SNS publish logic
├── data/
│   └── enterprise-attack.json  # MITRE ATT&CK STIX bundle (bundled, ~45 MB)
├── sample_cloudtrail.json      # Sample CloudTrail data for testing
├── requirements.txt            # boto3 (local SNS/Lambda testing only)
└── README.md                   # This file
```

## MITRE ATT&CK Data

The MITRE enterprise ATT&CK STIX bundle is included in this repo at `data/enterprise-attack.json` (~45 MB), so a clone is immediately runnable. To refresh it to MITRE's latest release:

```bash
curl -L -o data/enterprise-attack.json \
  https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json
```

Note that technique counts and names in your output may shift slightly across MITRE releases.

## Detections and MITRE ATT&CK Coverage

| Detection | API Call / Event | MITRE Technique |
|---|---|---|
| Failed Login | ConsoleLogin (failure) | T1110 - Brute Force |
| Create Account | CreateUser | T1136.003 - Create Cloud Account |
| Credential Access | CreateAccessKey | T1098.001 - Additional Cloud Credentials |
| Policy Attachment | AttachUserPolicy | T1098.003 - Additional Cloud Roles |
| Defense Evasion | DeleteTrail | T1562.008 - Disable or Modify Cloud Logs |
| Firewall Modification | AuthorizeSecurityGroupIngress | T1562.007 - Disable or Modify Cloud Firewall |
| Data Access | PutBucketPolicy | T1530 - Data from Cloud Storage |
| Privilege Escalation | 2+ sensitive actions by single user | T1078 - Valid Accounts |

Technique names and descriptions in reports are pulled from the STIX bundle at runtime, so they always match MITRE's canonical wording.

## Local Usage

Requirements: Python 3.6+ — the CLI analysis path has no external dependencies. `requirements.txt` contains only boto3, needed for local SNS/Lambda testing; it is deliberately not packaged into `deploy.zip` since the Lambda runtime provides boto3 natively.

```bash
cd src
python3 cloudtrail_analyzer.py ../sample_cloudtrail.json
```

Sample output:

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
    T1136.003 - Cloud Account
    T1098.003 - Additional Cloud Roles
    T1562.007 - Disable or Modify Cloud Firewall
  User: rogue-user
    T1562.008 - Disable or Modify Cloud Logs
    T1098.001 - Additional Cloud Credentials
  User: deploy-bot
    T1530 - Data from Cloud Storage
--------------------------------------------------
  POSSIBLE PRIVILEGE ESCALATION
--------------------------------------------------
  User: jsmith
    T1136.003 - Cloud Account
    T1098.003 - Additional Cloud Roles
    T1562.007 - Disable or Modify Cloud Firewall
    WARNING: 3 sensitive actions by single user
  User: rogue-user
    T1562.008 - Disable or Modify Cloud Logs
    T1098.001 - Additional Cloud Credentials
    WARNING: 2 sensitive actions by single user
==================================================
     END OF REPORT
```

## Lambda Deployment

### Prerequisites

- AWS CLI configured with appropriate permissions
- Python 3.12 Lambda runtime
- An S3 bucket to receive CloudTrail logs

### Step 1 — Build the deployment package

The Lambda handler expects modules at the archive root and the STIX bundle under `data/`, so package from inside `src/` and then append `data/`:

```bash
cd src && zip -r ../deploy.zip . -x "*__pycache__*" && cd ..
zip -r deploy.zip data/
```

Verify with `unzip -l deploy.zip` — the `.py` files should sit at the archive root (no `src/` prefix) with `data/enterprise-attack.json` alongside.

### Step 2 — Create the SNS topic

```bash
aws sns create-topic --name cloudtrail-analyzer-alerts --region YOUR_REGION
```

### Step 3 — Create the S3 bucket

```bash
aws s3api create-bucket --bucket your-bucket-name --region YOUR_REGION \
  --create-bucket-configuration LocationConstraint=YOUR_REGION
```

(The `LocationConstraint` is required in every region except us-east-1.)

### Step 4 — Create the IAM role and policy

Save the Lambda trust policy as `trust-policy.json`:

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": { "Service": "lambda.amazonaws.com" },
    "Action": "sts:AssumeRole"
  }]
}
```

Save the execution policy as `lambda-policy.json`, scoped to your bucket and topic:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": "s3:GetObject",
      "Resource": "arn:aws:s3:::your-bucket-name/*"
    },
    {
      "Effect": "Allow",
      "Action": "sns:Publish",
      "Resource": "arn:aws:sns:YOUR_REGION:YOUR_ACCOUNT_ID:cloudtrail-analyzer-alerts"
    }
  ]
}
```

Then create and wire the role:

```bash
aws iam create-role \
  --role-name cloudtrail-analyzer-role \
  --assume-role-policy-document file://trust-policy.json

aws iam put-role-policy \
  --role-name cloudtrail-analyzer-role \
  --policy-name cloudtrail-analyzer-policy \
  --policy-document file://lambda-policy.json

aws iam attach-role-policy \
  --role-name cloudtrail-analyzer-role \
  --policy-arn arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole
```

`AWSLambdaBasicExecutionRole` supplies the CloudWatch Logs permissions. Note that `s3:GetObject` is scoped per bucket — if you later add another source bucket, its ARN must be added to this policy or invocations will fail with AccessDenied.

### Step 5 — Create the function

```bash
aws lambda create-function \
  --function-name cloudtrail-analyzer \
  --runtime python3.12 \
  --role arn:aws:iam::YOUR_ACCOUNT_ID:role/cloudtrail-analyzer-role \
  --handler lambda_function.lambda_handler \
  --zip-file fileb://deploy.zip \
  --timeout 30 \
  --memory-size 512 \
  --region YOUR_REGION \
  --environment "Variables={SNS_TOPIC_ARN=arn:aws:sns:YOUR_REGION:YOUR_ACCOUNT_ID:cloudtrail-analyzer-alerts}"
```

Memory note: 512 MB is deliberate — parsing the 45 MB STIX bundle at initialization peaks around 227 MB.

### Step 6 — Wire the S3 trigger

```bash
aws lambda add-permission \
  --function-name cloudtrail-analyzer \
  --statement-id s3-invoke \
  --action lambda:InvokeFunction \
  --principal s3.amazonaws.com \
  --source-arn arn:aws:s3:::your-bucket-name \
  --source-account YOUR_ACCOUNT_ID

aws s3api put-bucket-notification-configuration \
  --bucket your-bucket-name \
  --notification-configuration '{
    "LambdaFunctionConfigurations": [{
      "LambdaFunctionArn": "arn:aws:lambda:YOUR_REGION:YOUR_ACCOUNT_ID:function:cloudtrail-analyzer",
      "Events": ["s3:ObjectCreated:*"]
    }]
  }'
```

Verify the configuration stuck (the put command returns nothing on success):

```bash
aws s3api get-bucket-notification-configuration --bucket your-bucket-name
```

### Step 7 — Subscribe to alerts

```bash
aws sns subscribe \
  --topic-arn arn:aws:sns:YOUR_REGION:YOUR_ACCOUNT_ID:cloudtrail-analyzer-alerts \
  --protocol email \
  --notification-endpoint your@email.com
```

**AWS will send a confirmation email to the subscribed address — you must click the "Confirm subscription" link before any alerts will be delivered.** Unconfirmed subscriptions silently drop messages: the Lambda logs will show `Alert sent` but nothing will arrive. Verify with:

```bash
aws sns list-subscriptions-by-topic \
  --topic-arn arn:aws:sns:YOUR_REGION:YOUR_ACCOUNT_ID:cloudtrail-analyzer-alerts
```

A confirmed subscription shows a real `SubscriptionArn`; `PendingConfirmation` means the email hasn't been actioned yet.

### Updating an existing function

```bash
aws lambda update-function-code \
  --function-name cloudtrail-analyzer \
  --zip-file fileb://deploy.zip
```

Wait for `LastUpdateStatus` to report `Successful` before testing — invocations during the update run the previous code.

## Testing the Deployment

Drop a CloudTrail JSON file into the S3 bucket:

```bash
aws s3 cp sample_cloudtrail.json s3://your-bucket-name/
```

Or invoke directly with a minimal S3 test event (create the file yourself — it is not shipped in the repo):

```bash
cat > testevent.json << 'EOF'
{
  "Records": [{
    "s3": {
      "bucket": { "name": "your-bucket-name" },
      "object": { "key": "sample_cloudtrail.json" }
    }
  }]
}
EOF

aws lambda invoke --function-name cloudtrail-analyzer \
  --payload file://testevent.json \
  --cli-binary-format raw-in-base64-out response.json
```

Monitor execution in CloudWatch (allow a few seconds for S3 event delivery and log ingestion):

```bash
aws logs tail /aws/lambda/cloudtrail-analyzer --no-cli-pager
```

## Performance

Measured on python3.12 / 512 MB / x86_64 (eu-central-1):

- Cold start (Init Duration): ~970 ms — dominated by parsing the 45 MB STIX bundle at initialization
- Warm invocation: ~745 ms for a sample log file, including SNS publish
- Peak memory: ~227 MB

For comparison, V1 (hardcoded 7-entry MITRE lookup, no STIX) cold-started in ~360 ms. The added ~610 ms is the cost of loading real, complete ATT&CK data. A planned optimization is pre-extracting only the fields the enricher uses (ID, name, description, tactics) into a slim JSON at build time, cutting the bundle from 45 MB to under 1 MB and largely eliminating the difference.

## Customization

- **Sensitive API calls** — Add `event_name: technique_id` entries to the dict in `mitre_mapping.py`; names, descriptions, and tactics resolve automatically from the STIX bundle. Only API actions belong here — the dict defines the detection scope for `detect_sensitive_api_calls()`.
- **Region threshold** — Adjust the 0.10 threshold in `detect_unusual_regions()` to tune alert sensitivity.
- **Alert format** — `build_alert_message()` in `report.py` controls the condensed SNS summary independently of the full console report.

## License

MIT
