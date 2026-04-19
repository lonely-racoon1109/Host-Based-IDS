import pandas as pd

def fix(file):
    df = pd.read_csv(file)

    # ----------------------------
    # Fix 1: Priv escalation requires success
    # ----------------------------
    mask = (df["priv_escalations"] > 0) & (df["successful_logins"] == 0)
    df.loc[mask, "successful_logins"] = 1

    # ----------------------------
    # Fix 2: Reduce auth_ratio = 1.0 in NORMAL
    # ----------------------------
    mask = (
        (df["label"] == "NORMAL") &
        (df["failed_logins"] > 0) &
        (df["successful_logins"] == 0)
    )
    df.loc[mask, "successful_logins"] = 1

    # ----------------------------
    # Recompute derived features
    # ----------------------------
    total = df["failed_logins"] + df["successful_logins"]

    df["auth_ratio"] = total.where(total > 0, 1)  # avoid div by 0
    df["auth_ratio"] = df["failed_logins"] / total.replace(0, 1)

    df["failed_per_ip"] = df["failed_logins"] / df["unique_ips"].replace(0, 1)

    df.to_csv(file, index=False)
    print(f"{file} fixed")

def validate(file):
    print(f"\n--- Validating {file} ---")
    df = pd.read_csv(file)

    # ----------------------------
    # Rule 1: Priv escalation requires login
    # ----------------------------
    bad1 = df[(df["priv_escalations"] > 0) & (df["successful_logins"] == 0)]
    print(f"Priv escalation without login: {len(bad1)}")

    # ----------------------------
    # Rule 2: failed_per_ip consistency
    # ----------------------------
    bad2 = df[(df["failed_per_ip"] > 0) & (df["unique_ips"] == 0)]
    print(f"failed_per_ip > 0 but unique_ips = 0: {len(bad2)}")

    # ----------------------------
    # Rule 3: Suspicious auth_ratio
    # ----------------------------
    normal_df = df[df["label"] == "NORMAL"]

    bad3 = normal_df[normal_df["auth_ratio"] == 1.0]
    percent = (len(bad3) / len(normal_df)) * 100 if len(normal_df) > 0 else 0
    print(f"auth_ratio = 1.0 in NORMAL: {len(bad3)} ({percent:.2f}%)")

    # ----------------------------
    # Rule 4: Basic stats
    # ----------------------------
    print("\nFeature distribution:")
    print(df[[
        "failed_logins",
        "successful_logins",
        "unique_ips",
        "failed_per_ip",
        "auth_ratio",
        "sensitive_file_access",
        "suspicious_command_flag",
        "weird_behavior_flag"
    ]].describe())

    print("\nATTACK vs NORMAL mean")

    print(df.groupby("label")[[
        "failed_logins",
        "sensitive_file_access",
        "suspicious_command_flag",
        "weird_behavior_flag"
    ]].mean())

    # ----------------------------
    # Optional: show bad samples
    # ----------------------------
    if len(bad1) > 0:
        print("\nSample bad priv escalation rows:")
        print(bad1.head())

    if len(bad2) > 0:
        print("\nSample IP inconsistency rows:")
        print(bad2.head())

    print("\nValidation complete.\n")


if __name__ == "__main__":
    validate("train.csv")
    validate("validation.csv")
    validate("simulation.csv")

    # fix("train.csv")
    # fix("validation.csv")
    # fix("simulation.csv")