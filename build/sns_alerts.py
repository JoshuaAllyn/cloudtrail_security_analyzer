import boto3
import os


def send_sns_alert(message):
    topic_arn = os.environ.get("SNS_TOPIC_ARN")
    if not topic_arn:
        print("SNS_TOPIC_ARN not set - skipping alert")
        return
    subject = "CloudTrail Security Alert"
    sns_client = boto3.client("sns")
    try:
        sns_client.publish(TopicArn=topic_arn, Message=message, Subject=subject)
        print("Alert sent")
    except Exception as e:
        print(f"Failed to send alert: {e}")
