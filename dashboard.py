import streamlit as st
import pandas as pd
import plotly.express as px
from streamlit_autorefresh import st_autorefresh
import os
import numpy as np
import joblib

st.set_page_config(page_title="IDS SOC Dashboard", layout="wide")

st.title("🛡️ Host-Based IDS Security Monitoring")

st_autorefresh(interval=2000, limit=1000, key="refresh")

LOG_FILE = "ids_log.csv"

# --------------------------------------------------
# LOAD CSV ONLY (STRICT)
# --------------------------------------------------

def load_data():
    if not os.path.exists(LOG_FILE):
        return pd.DataFrame()

    try:
        df = pd.read_csv(LOG_FILE)
    except:
        return pd.DataFrame()

    df.columns = df.columns.str.strip().str.lower()

    required_cols = ["timestamp", "score", "label", "service"]

    for col in required_cols:
        if col not in df.columns:
            st.error(f"Missing column: {col}")
            st.stop()

    if "timestamp" in df.columns:
        df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")

    if "score" in df.columns:
        df["score"] = pd.to_numeric(df["score"], errors="coerce")

    return df


df = load_data()

if df.empty:
    st.warning("Waiting for IDS data...")
    st.stop()

# --------------------------------------------------
# SEVERITY
# --------------------------------------------------

def severity(score):
    if score > 0.2:
        return "HIGH"
    elif score > 0.05:
        return "MEDIUM"
    return "LOW"

if "score" not in df.columns:
    st.error("Missing 'score' column — IDS pipeline is broken")
    st.stop()

df["severity"] = df["score"].apply(severity)

# --------------------------------------------------
# METRICS
# --------------------------------------------------

col1, col2, col3, col4 = st.columns(4)

col1.metric("Total Events", len(df))
col2.metric("Anomalies", (df["label"] == "ANOMALY").sum())
col3.metric("High Severity", (df["severity"] == "HIGH").sum())
col4.metric("Unique Services", df["service"].nunique())

st.divider()

# --------------------------------------------------
# EVENT INTENSITY
# --------------------------------------------------

df_time = (
    df.set_index("timestamp")
      .resample("30s")
      .size()
      .reset_index(name="event_count")
)

df_time["event_count"] = df_time["event_count"].rolling(3).mean()

fig1 = px.area(df_time, x="timestamp", y="event_count",
               title="Attack Intensity Over Time")

st.plotly_chart(fig1, width="stretch", key="intensity")

# --------------------------------------------------
# SEVERITY TIMELINE
# --------------------------------------------------

fig2 = px.scatter(
    df,
    x="timestamp",
    y="score",
    color="severity",
    title="Anomaly Severity Timeline"
)

st.plotly_chart(fig2, width="stretch", key="scatter")

# --------------------------------------------------
# SERVICES
# --------------------------------------------------

top_services = df["service"].value_counts().head(10).reset_index()
top_services.columns = ["service", "count"]

fig3 = px.bar(top_services, x="service", y="count",
              title="Top Targeted Services")

st.plotly_chart(fig3, width="stretch", key="services")

# --------------------------------------------------
# USERS
# --------------------------------------------------

if "user" in df.columns:
    top_users = df["user"].value_counts().head(10).reset_index()
    top_users.columns = ["user", "count"]

    fig4 = px.bar(top_users, x="user", y="count",
                  title="Top Targeted Users")

    st.plotly_chart(fig4, width="stretch", key="users")

# --------------------------------------------------
# ALERT TABLE
# --------------------------------------------------

st.subheader("🚨 Active Alerts")

alerts = df[df["severity"] == "HIGH"].sort_values("timestamp", ascending=False)

st.dataframe(
    alerts[["timestamp", "service", "user", "ip", "score", "label", "severity"]].head(20),
    width="stretch"
)

# --------------------------------------------------
# 🧠 ATTACK STORY GENERATOR (THIS IS YOUR WOW FEATURE)
# --------------------------------------------------

st.subheader("🧠 Attack Narrative (Auto Explanation)")
st.caption(f"Last updated: {df['timestamp'].max()}")

def generate_story(row):
    service = row.get("service", "system")
    user = row.get("user", "unknown user")
    ip = row.get("ip", "unknown IP")
    score = row.get("score", 0)
    severity = row.get("severity", "LOW")

    if severity == "HIGH":
        return f"""
High-risk activity detected on {service}.
Multiple suspicious actions were performed targeting user(s): {user}.
Source IP involved: {ip}.
The behavior strongly deviates from normal patterns and may indicate a brute-force or intrusion attempt.
Immediate investigation is recommended.
"""

    elif severity == "MEDIUM":
        return f"""
Moderate anomaly detected on {service}.
User(s) affected: {user}.
Source IP: {ip}.
Activity shows unusual behavior but not conclusively malicious.
Monitoring should be increased.
"""

    else:
        return f"""
Low-risk anomaly observed on {service}.
User(s): {user}.
IP: {ip}.
This appears to be slightly unusual but likely benign.
"""

# show latest event story
latest = df.iloc[-1]
story = generate_story(latest)

st.info(story)

# --------------------------------------------------
# RAW LOGS
# --------------------------------------------------

with st.expander("Raw Event Stream"):
    st.dataframe(df.tail(50), width="stretch")