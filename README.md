# CloudTrail Security Analyzer

A modular Python tool for automated AWS CloudTrail threat detection, deployable as an AWS Lambda function triggered by S3 events or run locally via CLI. Detects credential attacks, lateral movement, privilege escalation, and defense evasion — mapped to MITRE ATT&CK techniques.

**Author:** Josh Allyn — [LinkedIn](https://www.linkedin.com/in/joshuaallyn/)  
**GitHub:** [cloudtrail_security_analyzer](https://github.com/JoshuaAllyn/cloudtrail_security_analyzer)

---

## Features

- **Failed Login Detection** — Identifies failed `ConsoleLogin` attempts grouped by user and source IP
- **Unusual Region Detection** — Flags AWS regions representing less than 10% of total event volume, catching activity outside normal operating patterns
- **Sensitive API Call Detection** — Monitors high-risk API actions including `CreateUser`, `AttachUserPolicy`, `DeleteTrail`, `CreateAccessKey`, `PutBucketPolicy`, and `AuthorizeSecurityGroupIngress`
- **Privilege Escalation Detection** — Identifies users performing two or more sensitive API actions in a single log file
- **MITRE ATT&CK Mapping** — Every sensitive API call is tagged with its corresponding ATT&CK technique ID and name
- **SNS Alerting** — Publishes findings summary to an SNS topic for email or downstream integration
- **Dual Execution Modes** — Runs locally via CLI or deployed as a serverless AWS Lambda function triggered by S3 uploads

---

## Architecture

```
S3 Bucket (CloudTrail logs)
        │
        │  s3:ObjectCreated event
        ▼
AWS Lambda Function
┌──────────────────────────────────────┐
│ lambda_function.py                   │
│   ├── detections.py                  │
│   ├── mitre_mapping.py               │
│   ├── report.py                      │
│   └── sns_alerts.py                  │
└──────────────────────────────────────┘
        │
        │  sns:Publish
        ▼
SNS Topic → Email / Slack / SIEM
```

---

## Project Structure

```
cloudtrail_security_analyzer/
├── cloudtrail_analyzer.py      # CLI entry point (argparse)
├── lambda_function.py          # Lambda handler (S3 event trigger)
├── detections.py               # Four detection functions
├── mitre_mapping.py            # MITRE ATT&CK technique mappings
├── report.py                   # Report generation
├── sns_alerts.py               # SNS publish logic
├── test_detections.py          # Unit tests
├── sample_cloudtrail.json      # Sample CloudTrail data for testing
└── README.md                   # This file
```

---

## Detections and MITRE ATT&CK Coverage

| Detection | API Call / Event | MITRE Technique |
|---|---|---|
| Failed Login | `ConsoleLogin` (failure) | T1110 - Brute Force |
| Create Account | `CreateUser` | T1136.003 - Create Cloud Account |
| Credential Access | `CreateAccessKey` | T1098.001 - Additional Cloud Credentials |
| Policy Attachment | `AttachUserPolicy` | T1098.003 - Additional Cloud Roles |
| Defense Evasion | `DeleteTrail` | T1562.008 - Disable Cloud Logs |
| Firewall Modification | `AuthorizeSecurityGroupIngress` | T1562.007 - Disable Cloud Firewall |
| Data Access | `PutBucketPolicy` | T1530 - Data from Cloud Storage |
| Privilege Escalation | 2+ sensitive actions by single user | T1078 - Valid Accounts |

---

## Local Usage

**Requirements:** Python 3.6+ — no external dependencies

```bash
python3 cloudtrail_analyzer.py sample_cloudtrail.json
```

**Sample Output:**

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
SENSITIVE API CALLS
--------------------------------------------------
User: jsmith
  CreateUser  →  T1136.003 - Create Account: Cloud Account
  AttachUserPolicy  →  T1098.003 - Account Manipulation: Additional Cloud Roles
  AuthorizeSecurityGroupIngress  →  T1562.007 - Impair Defenses: Disable or Modify Cloud Firewall
User: rogue-user
  DeleteTrail  →  T1562.008 - Impair Defenses: Disable Cloud Logs
  CreateAccessKey  →  T1098.001 - Account Manipulation: Additional Cloud Credentials

--------------------------------------------------
POSSIBLE PRIVILEGE ESCALATION
--------------------------------------------------
User: jsmith
  WARNING: 3 sensitive actions by single user
User: rogue-user
  WARNING: 2 sensitive actions by single user

==================================================
END OF REPORT
==================================================
```

---

## Lambda Deployment

### Prerequisites

- AWS CLI configured with appropriate permissions
- Python 3.12 Lambda runtime
- An S3 bucket to receive CloudTrail logs

### Infrastructure Setup

**1. Create SNS topic:**
```bash
aws sns create-topic --name cloudtrail-analyzer-alerts --region us-east-1
```

**2. Create S3 bucket:**
```bash
aws s3api create-bucket --bucket your-bucket-name --region us-east-1
```

**3. Create IAM role and policy:**
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

The IAM policy grants `s3:GetObject` on the target bucket, `sns:Publish` on the target topic, and CloudWatch Logs write access.

**4. Package and deploy:**
```bash
zip cloudtrail-analyzer.zip \
  lambda_function.py detections.py mitre_mapping.py report.py sns_alerts.py

aws lambda create-function \
  --function-name cloudtrail-security-analyzer \
  --runtime python3.12 \
  --role arn:aws:iam::YOUR_ACCOUNT_ID:role/cloudtrail-analyzer-role \
  --handler lambda_function.lambda_handler \
  --zip-file fileb://cloudtrail-analyzer.zip \
  --timeout 60 \
  --memory-size 256 \
  --region us-east-1
```

**5. Set environment variable:**
```bash
aws lambda update-function-configuration \
  --function-name cloudtrail-security-analyzer \
  --environment "Variables={SNS_TOPIC_ARN=arn:aws:sns:us-east-1:YOUR_ACCOUNT_ID:cloudtrail-analyzer-alerts}"
```

**6. Wire the S3 trigger:**
```bash
aws lambda add-permission \
  --function-name cloudtrail-security-analyzer \
  --statement-id s3-invoke \
  --action lambda:InvokeFunction \
  --principal s3.amazonaws.com \
  --source-arn arn:aws:s3:::your-bucket-name \
  --source-account YOUR_ACCOUNT_ID

aws s3api put-bucket-notification-configuration \
  --bucket your-bucket-name \
  --notification-configuration file://s3-notification.json
```

**7. Subscribe to alerts:**
```bash
aws sns subscribe \
  --topic-arn arn:aws:sns:us-east-1:YOUR_ACCOUNT_ID:cloudtrail-analyzer-alerts \
  --protocol email \
  --notification-endpoint your@email.com
```

### Testing

Drop a CloudTrail JSON file into the S3 bucket:
```bash
aws s3 cp sample_cloudtrail.json s3://your-bucket-name/
```

Monitor execution in CloudWatch:
```bash
aws logs tail /aws/lambda/cloudtrail-security-analyzer --no-cli-pager
```

---

## Running Tests

```bash
python3 -m unittest test_detections.py -v
```

Tests validate all four detection functions against `sample_cloudtrail.json`, asserting expected users and regions are correctly identified.

---

## Customization

- **Sensitive API calls** — Edit the `sensitive_calls` list in `detections.py` to add or remove monitored actions
- **MITRE mappings** — Extend the nested dictionary in `mitre_mapping.py` to cover additional techniques
- **Region threshold** — Adjust the `0.10` threshold in `detect_unusual_regions()` to tune alert sensitivity

---

## License

MIT
