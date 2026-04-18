import json
import boto3
from detections import detect_failed_logins, detect_unusual_regions, detect_sensitive_api_calls, detect_privilege_escalation
from report import generate_report

def lambda_handler(event, context):
    bucket = event["Records"][0]["s3"]["bucket"]["name"]
    key = event["Records"][0]["s3"]["object"]["key"]
    s3_client = boto3.client("s3")
    response = s3_client.get_object(Bucket=bucket, Key=key)
    events = json.loads(response["Body"].read())["Records"]
    num_of_events = len(events)
    failed_logins = detect_failed_logins(events)
    unusual_regions = detect_unusual_regions(events)
    sensitive_api = detect_sensitive_api_calls(events)
    priv_escalation = detect_privilege_escalation(sensitive_api)
    generate_report(num_of_events, failed_logins, unusual_regions, sensitive_api, priv_escalation)
