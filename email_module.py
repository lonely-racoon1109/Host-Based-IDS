import smtplib
from email.mime.text import MIMEText

def send_alert_email(summary, features, result):
    sender = "shubhashree.bhore@nmiet.edu.in"
    password = "jrbs vanz izcn vfpc"   # NOT your normal password
    receiver = "iamshubhashree505@gmail.com"

    subject = "🚨 IDS ALERT: Anomaly Detected, Secure your device"

    body = f"""
Anomaly detected in Host-based IDS

Result: {result}

Summary:
{summary}

Features:
{features}
"""

    msg = MIMEText(body)
    msg["Subject"] = subject
    msg["From"] = sender
    msg["To"] = receiver

    try:
        server = smtplib.SMTP("smtp.gmail.com", 587)
        server.starttls()
        server.login(sender, password)
        server.sendmail(sender, receiver, msg.as_string())
        server.quit()
        print("Email alert sent.")
    except Exception as e:
        print("Email failed:", e)