import random
from datetime import datetime, timedelta

users = ["root", "admin", "user1", "user2", "test", "guest"]
ips = ["192.168.1.5", "192.168.1.10", "10.0.0.2", "172.16.0.3"]
files = ["/etc/passwd", "/etc/shadow", "/etc/hosts"]

start_time = datetime(2026, 4, 3, 10, 0, 0)

def random_time(offset):
    return start_time + timedelta(seconds=offset)

def format_time(dt):
    return dt.strftime("%b %d %H:%M:%S")

logs = []

# -------------------------
# NORMAL LOGINS
# -------------------------
for i in range(100):
    dt = random_time(i * 30)
    user = random.choice(users)
    ip = random.choice(ips)

    logs.append(
        f"{format_time(dt)} archlinux sshd-session[1234]: Accepted password for {user} from {ip} port 22 ssh2"
    )

# -------------------------
# BRUTE FORCE ATTACK
# -------------------------
for i in range(50):
    dt = random_time(5000 + i * 5)
    user = random.choice(users)
    ip = "1.1.1.1"

    logs.append(
        f"{format_time(dt)} archlinux sshd-session[9999]: Failed password for {user} from {ip} port 22 ssh2"
    )

# -------------------------
# MULTI-USER ATTACK
# -------------------------
for i in range(30):
    dt = random_time(8000 + i * 60)
    user = users[i % len(users)]
    ip = "2.2.2.2"

    logs.append(
        f"{format_time(dt)} archlinux sshd-session[8888]: Failed password for invalid user {user} from {ip} port 22 ssh2"
    )

# -------------------------
# PRIVILEGE ESCALATION (sudo)
# -------------------------
for i in range(40):
    dt = random_time(10000 + i * 20)
    user = random.choice(users)

    logs.append(
        f"{format_time(dt)} archlinux sudo: {user} : TTY=pts/0 ; COMMAND=/bin/bash"
    )

# -------------------------
# FILE ACCESS (sensitive)
# -------------------------
for i in range(40):
    dt = random_time(12000 + i * 15)
    user = random.choice(users)
    file = random.choice(files)

    logs.append(
        f"{format_time(dt)} archlinux audit: USER_CMD pid=1234 uid=1000 cmd=\"cat {file}\""
    )

# -------------------------
# WRITE TO FILE
# -------------------------
with open("synthetic_logs.txt", "w") as f:
    for log in logs:
        f.write(log + "\n")

print(f"Generated {len(logs)} logs in synthetic_logs.txt")