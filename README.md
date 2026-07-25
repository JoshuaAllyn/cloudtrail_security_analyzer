# CloudTrail Security Analyzer

A modular Python tool for automated AWS CloudTrail threat detection, deployable as an AWS Lambda function triggered by S3 events or run locally via CLI. Detects credential attacks, unusual region activity, privilege escalation, and defense evasion — with every sensitive API call enriched against the full MITRE ATT&CK knowledge base (679 techniques, sourced directly from MITRE's STIX data).

Author: Josh Allyn — [LinkedIn](https://www.linkedin.com/in/joshuaallyn/)

## Features

- **Failed Login Detection** — Identifies failed ConsoleLogin attempts grouped by user and source IP
- **Unusual Region Detection** — Flags AWS regions representing less than 10% of total event volume, catching activity outside normal operating patterns
- **Sensitive API Call Detection** — Monitors high-risk API actions including CreateUser, AttachUserPolicy, DeleteTrail, CreateAccessKey, PutBucketPolicy, and AuthorizeSecurityGroupIngress
- **Privilege Escalation Detection** — Identifies users performing two or more sensitive API actions in a single log file
- **MITRE ATT&CK Enrichment** — Sensitive API calls are enriched with real technique data (ID, name, description, tactics) loaded from MITRE's official STIX bundle — not hardcoded strings
- **SNS Alerting** — Publishes findings summary to an SNS topic for email or downstream integration
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

1. `mitre_mapping.py` maps CloudTrail event names to ATT&CK technique IDs (a simple `{event_name: technique_id}` dict — the routing layer)
2. `mitre_intel.py` parses MITRE's official STIX 2.1 bundle (`data/enterprise-attack.json`) into a lookup of all 679 enterprise techniques, keyed by technique ID
3. `MitreEnricher` (in `mitre_enricher.py`) resolves each detected event's technique ID into full technique data: canonical name, description, and tactics
4. `detections.py` wraps matched events in `CloudTrailEvent` objects and passes them through the enricher, so reports and alerts carry real ATT&CK intelligence

The STIX bundle path is resolved differently per execution mode: relative to the Lambda task root (`/var/task/data/`) when deployed, relative to the repo when run via CLI.

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
│   ├── report.py               # Report generation
│   └── sns_alerts.py           # SNS publish logic
├── data/
│   └── enterprise-attack.json  # MITRE ATT&CK STIX bundle (see below)
├── sample_cloudtrail.json      # Sample CloudTrail data for testing
└── README.md                   # This file
```

## MITRE ATT&CK Data

The analyzer requires MITRE's enterprise ATT&CK STIX bundle at `data/enterprise-attack.json`. It is not committed to this repo due to size (~45 MB). Download it from MITRE's official repository:

```bash
mkdir -p data
curl -L -o data/enterprise-attack.json \
  https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json
```

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

Technique names and descriptions in reports are pulled live from the STIX bundle, so they always match MITRE's current canonical wording.

## Local Usage

Requirements: Python 3.6+ — no external dependencies (boto3 only needed for Lambda/SNS paths)

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
    T1110.001 - Password Guessing
    T1136.003 - Cloud Account
    T1098.003 - Additional Cloud Roles
    T1562.007 - Disable or Modify Cloud Firewall
    T1110.001 - Password Guessing
  User: admin
    T1110.001 - Password Guessing
    T1110.001 - Password Guessing
    T1110.001 - Password Guessing
  User: rogue-user
    T1562.008 - Disable or Modify Cloud Logs
    T1110.001 - Password Guessing
    T1098.001 - Additional Cloud Credentials
  User: deploy-bot
    T1530 - Data from Cloud Storage

--------------------------------------------------
  POSSIBLE PRIVILEGE ESCALATION
--------------------------------------------------
  User: jsmith
    T1110.001 - Password Guessing
    T1136.003 - Cloud Account
    T1098.003 - Additional Cloud Roles
    T1562.007 - Disable or Modify Cloud Firewall
    T1110.001 - Password Guessing
    WARNING: 5 sensitive actions by single user
  User: admin
    T1110.001 - Password Guessing
    T1110.001 - Password Guessing
    T1110.001 - Password Guessing
    WARNING: 3 sensitive actions by single user
  User: rogue-user
    T1562.008 - Disable or Modify Cloud Logs
    T1110.001 - Password Guessing
    T1098.001 - Additional Cloud Credentials
    WARNING: 3 sensitive actions by single user

==================================================
  END OF REPORT
```

## Lambda Deployment

### Prerequisites

- AWS CLI configured with appropriate permissions
- Python 3.12 Lambda runtime
- An S3 bucket to receive CloudTrail logs
- The MITRE STIX bundle downloaded to `data/` (see above)

### Infrastructure Setup

1. Create SNS topic:

```bash
aws sns create-topic --name cloudtrail-analyzer-alerts --region YOUR_REGION
```

2. Create S3 bucket:

```bash
aws s3api create-bucket --bucket your-bucket-name --region YOUR_REGION
```

3. Create IAM role and policy:

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

The IAM policy grants s3:GetObject on the target bucket, sns:Publish on the target topic, and CloudWatch Logs write access.

4. Package and deploy:

The Lambda handler expects modules at the archive root and the STIX bundle under `data/`, so package from inside `src/` and then append `data/`:

```bash
cd src && zip -r ../deploy.zip . -x "*__pycache__*" && cd ..
zip -r deploy.zip data/

aws lambda create-function \
  --function-name cloudtrail-analyzer \
  --runtime python3.12 \
  --role arn:aws:iam::YOUR_ACCOUNT_ID:role/cloudtrail-analyzer-role \
  --handler lambda_function.lambda_handler \
  --zip-file fileb://deploy.zip \
  --timeout 30 \
  --memory-size 512 \
  --region YOUR_REGION
```

Memory note: 512 MB is deliberate — parsing the 45 MB STIX bundle at initialization peaks around 227 MB.

5. Set environment variable:

```bash
aws lambda update-function-configuration \
  --function-name cloudtrail-analyzer \
  --environment "Variables={SNS_TOPIC_ARN=arn:aws:sns:YOUR_REGION:YOUR_ACCOUNT_ID:cloudtrail-analyzer-alerts}"
```

6. Wire the S3 trigger:

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
  --notification-configuration file://s3-notification.json
```

7. Subscribe to alerts:

```bash
aws sns subscribe \
  --topic-arn arn:aws:sns:YOUR_REGION:YOUR_ACCOUNT_ID:cloudtrail-analyzer-alerts \
  --protocol email \
  --notification-endpoint your@email.com
```

### Updating an Existing Function

```bash
aws lambda update-function-code \
  --function-name cloudtrail-analyzer \
  --zip-file fileb://deploy.zip
```

## Testing the Deployment

Drop a CloudTrail JSON file into the S3 bucket:

```bash
aws s3 cp sample_cloudtrail.json s3://your-bucket-name/
```

Or invoke directly with a canned S3 event:

```bash
aws lambda invoke --function-name cloudtrail-analyzer \
  --payload file://s3event.json \
  --cli-binary-format raw-in-base64-out response.json
```

Monitor execution in CloudWatch:

```bash
aws logs tail /aws/lambda/cloudtrail-analyzer --no-cli-pager
```

## Performance

Measured on python3.12 / 512 MB / x86_64 (eu-central-1):

- Cold start (Init Duration): ~970 ms — dominated by parsing the 45 MB STIX bundle at initialization
- Warm invocation: ~745 ms for a sample log file, including SNS publish
- Peak memory: ~227 MB

For comparison, V1 (hardcoded 7-entry MITRE lookup, no STIX) cold-started in ~360 ms. The added ~610 ms is the cost of real, complete ATT&CK data. A planned optimization is pre-extracting only the fields the enricher uses (ID, name, description, tactics) into a slim JSON at build time, which would cut the bundle from 45 MB to under 1 MB and largely eliminate the difference.

## Customization

- **Sensitive API calls** — Edit the `sensitive_calls` list in `detections.py` to add or remove monitored actions
- **MITRE mappings** — Add `event_name: technique_id` entries to the dict in `mitre_mapping.py`; names, descriptions, and tactics resolve automatically from the STIX bundle
- **Region threshold** — Adjust the 0.10 threshold in `detect_unusual_regions()` to tune alert sensitivity

## License

MIT
