import json
import boto3
import os

def send_sns_alert(failed_logins, unusual_regions, sensitive_api, priv_escalation):
    topic_arn = os.environ.get("SNS_TOPIC_ARN")
    sns_client = boto3.client("sns")
    message = f" failed login count: {len(failed_logins)} unusual region count: {len(unusual_regions)} sensitive api count: {len(sensitive_api)} suspected privilege escalation count: {len(priv_escalation)}"
    subject = "Cloud Trail Alert"
    sns_client.publish(TopicArn=topic_arn, Message=message, Subject=subject)
