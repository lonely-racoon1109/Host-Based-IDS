import smtplib
from email.mime.text import MIMEText

def format_shap(top_features):
    lines = []
    for name, value in top_features:
        direction = "↑ increases anomaly" if value > 0 else "↓ reduces anomaly"
        lines.append(f"{name}: {round(value,4)} ({direction})")
    return "\n".join(lines)


def send_alert_email(summary, features, prediction, score, shap_features):
    sender = ""
    password = ""   
    receiver = ""

    subject = f"🚨 IDS ALERT: {prediction} Detected"

    shap_text = format_shap(shap_features)

    body = f"""
    ⚠️ Intrusion Detection Alert

    Prediction: {prediction}
    Anomaly Score: {round(score, 4)}

    ----------------------------------
    Top Contributing Factors (SHAP)
    ----------------------------------
    {shap_text}

    ----------------------------------
    Window Summary
    ----------------------------------
    Failed Logins: {summary.get("failed_logins")}
    Successful Logins: {summary.get("successful_logins")}
    Unique IPs: {summary.get("unique_ips")}
    Users Targeted: {summary.get("users_targeted")}

    ----------------------------------
    Raw Features
    ----------------------------------
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