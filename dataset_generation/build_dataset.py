import csv
import numpy as np
import random

FEATURE_COLUMNS = [
    "failed_logins","successful_logins","priv_escalations",
    "file_access_events","kernel_alerts","auth_ratio",
    "unique_ips","failed_per_ip","users_count",
    "privileged_user_targeted","multiple_failed_users_flag",
    "priv_after_failure_flag","svc_sshd","svc_sudo","svc_kernel",
    "hour","day_of_week","is_night","is_weekend",
    "sensitive_file_access","suspicious_command_flag",
    "weird_behavior_flag",
    "failed_to_success_sequence",
    "ip_entropy"
]

rng = np.random.default_rng(42)

# -----------------------------
# Hour distribution
# -----------------------------
hour_weights = np.array([
    1,1,1,1,1,2,3,5,8,9,8,7,
    6,7,8,9,8,7,5,4,3,2,2,1
])
hour_probs = hour_weights / hour_weights.sum()


# -----------------------------
# SANITIZE + DERIVED FEATURES
# -----------------------------
def sanitize(row):
    row["failed_logins"] = max(row["failed_logins"], 0)
    row["successful_logins"] = max(row["successful_logins"], 0)

    total = row["failed_logins"] + row["successful_logins"]

    row["auth_ratio"] = round(
        row["failed_logins"] / total, 4
    ) if total > 0 else 0.0

    row["unique_ips"] = max(row["unique_ips"], 1)

    row["failed_per_ip"] = round(
        row["failed_logins"] / row["unique_ips"], 4
    )

    # Flags
    row["multiple_failed_users_flag"] = int(row["users_count"] > 1)
    row["priv_after_failure_flag"] = int(
        row["priv_escalations"] > 0 and row["failed_logins"] > 0
    )

    # NEW: sequence feature
    row["failed_to_success_sequence"] = int(
        row["failed_logins"] > 0 and row["successful_logins"] > 0
    )

    # NEW: entropy approximation
    row["ip_entropy"] = round(
        row["unique_ips"] / (row["failed_logins"] + 1), 4
    )

    return row


# -----------------------------
# NORMAL DATA
# -----------------------------
def normal_window():
    hour = int(rng.choice(24, p=hour_probs))

    failed = int(rng.integers(0, 3))
    success = int(rng.integers(1, 4))  # ensure normal success exists
    priv = int(rng.random() < 0.1)
    users = int(rng.integers(1, 3))

    row = {
        "failed_logins": failed,
        "successful_logins": success,
        "priv_escalations": priv,
        "file_access_events": int(rng.integers(0, 3)),
        "kernel_alerts": 0,
        "unique_ips": int(rng.integers(1, 4)),
        "users_count": users,
        "privileged_user_targeted": int(rng.random() < 0.05),
        "svc_sshd": 1,
        "svc_sudo": int(rng.random() < 0.2),
        "svc_kernel": 0,
        "hour": hour,
        "day_of_week": int(rng.integers(0, 5)),
        "is_night": int(hour < 6 or hour >= 22),
        "is_weekend": int(rng.random() < 0.1),
    }

    # --- behavioral noise (IMPORTANT) ---
    row["sensitive_file_access"] = int(rng.random() < 0.15)
    row["suspicious_command_flag"] = int(rng.random() < 0.15)

    # occasional burst (realistic anomaly but still normal)
    if rng.random() < 0.1:
        row["failed_logins"] += int(rng.integers(2, 5))
        row["unique_ips"] += int(rng.integers(1, 3))

    # weakened weird behavior (no longer perfect signal)
    row["weird_behavior_flag"] = int(
        (row["is_night"] == 1 and row["priv_escalations"] > 0)
        or (rng.random() < 0.15)
    )

    return sanitize(row)


# -----------------------------
# ATTACK DATA
# -----------------------------
def attack_window():
    hour = int(rng.integers(0, 24))
    attack_type = rng.choice(["brute", "distributed", "escalation"])

    if attack_type == "brute":
        failed = int(rng.integers(20, 80))
        ips = int(rng.integers(1, 3))
        users = int(rng.integers(1, 3))
        success = int(rng.integers(0, 2))
        priv = 0

    elif attack_type == "distributed":
        failed = int(rng.integers(10, 40))
        ips = int(rng.integers(10, 40))
        users = int(rng.integers(5, 20))
        success = int(rng.integers(0, 2))
        priv = 0

    else:  # escalation
        failed = int(rng.integers(0, 4))
        ips = int(rng.integers(1, 3))
        users = int(rng.integers(1, 2))
        success = int(rng.integers(1, 3))
        priv = int(rng.integers(1, 3))

    row = {
        "failed_logins": failed,
        "successful_logins": success,
        "priv_escalations": priv,
        "file_access_events": int(rng.integers(2, 6)),
        "kernel_alerts": int(rng.random() < 0.2),
        "unique_ips": ips,
        "users_count": users,
        "privileged_user_targeted": int(rng.random() < 0.7),
        "svc_sshd": 1,
        "svc_sudo": int(priv > 0),
        "svc_kernel": 0,
        "hour": hour,
        "day_of_week": int(rng.integers(0, 7)),
        "is_night": int(hour < 6 or hour >= 22),
        "is_weekend": int(rng.integers(0, 7) >= 5),
    }

    # strong but NOT perfect signals
    row["sensitive_file_access"] = int(rng.random() < 0.65)
    row["suspicious_command_flag"] = int(rng.random() < 0.65)

    row["weird_behavior_flag"] = int(
        (row["is_night"] == 1 and row["priv_escalations"] > 0)
        or (row["failed_logins"] > 10)
        or (rng.random() < 0.2)
    )

    return sanitize(row)


# -----------------------------
# WRITE DATASET
# -----------------------------
def write_dataset(filename, n_normal, n_attack):
    rows = []

    for _ in range(n_normal):
        rows.append({**normal_window(), "label": "NORMAL"})

    for _ in range(n_attack):
        rows.append({**attack_window(), "label": "ATTACK"})

    random.shuffle(rows)

    with open(filename, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=FEATURE_COLUMNS + ["label"])
        writer.writeheader()
        writer.writerows(rows)

    print(f"{filename} generated: {n_normal} NORMAL, {n_attack} ATTACK")


# -----------------------------
# MAIN
# -----------------------------
write_dataset("train.csv", 3000, 0)
write_dataset("validation.csv", 1000, 300)
write_dataset("simulation.csv", 1500, 500)