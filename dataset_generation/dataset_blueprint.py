import random
from datetime import datetime, timedelta


class SyntheticLogGenerator:
    def __init__(self):
        self.user_profiles = {
            "alice":   {"active_hours": (9, 18), "sudo_rate": 0.2},
            "bob":     {"active_hours": (10, 17), "sudo_rate": 0.1},
            "charlie": {"active_hours": (8, 20), "sudo_rate": 0.15},
            "deploy":  {"active_hours": (0, 23), "sudo_rate": 0.8},
            "backup":  {"active_hours": (1, 5),  "sudo_rate": 0.4},
        }

        self.attack_users = ["root", "admin", "test", "guest", "oracle"]

        self.normal_ips = [f"192.168.1.{i}" for i in range(10, 50)]
        self.attack_ips = [
            f"45.33.{random.randint(1,254)}.{random.randint(1,254)}"
            for _ in range(50)
        ]

    def _fmt(self, dt, service, pid, msg):
        return dt.strftime("%b %d %H:%M:%S") + f" hostname {service}[{pid}]: {msg}"

    def _pick_active_user(self, dt):
        hour = dt.hour
        active = [
            u for u, p in self.user_profiles.items()
            if p["active_hours"][0] <= hour <= p["active_hours"][1]
        ]
        return random.choice(active or list(self.user_profiles.keys()))

    # ----------------------------
    # NORMAL (LOW VOLUME)
    # ----------------------------
    def normal_session(self, dt):
        user = self._pick_active_user(dt)
        ip = random.choice(self.normal_ips)
        pid = random.randint(1000, 9999)

        lines = []

        # small noise only (max 1 fail)
        if random.random() < 0.2:
            lines.append(self._fmt(
                dt, "sshd", pid,
                f"Failed password for {user} from {ip} port {random.randint(1024,65535)} ssh2"
            ))

        # success
        lines.append(self._fmt(
            dt + timedelta(seconds=2), "sshd", pid,
            f"Accepted password for {user} from {ip} port {random.randint(1024,65535)} ssh2"
        ))

        # session open (not always)
        if random.random() < 0.6:
            lines.append(self._fmt(
                dt + timedelta(seconds=3), "sshd", pid,
                f"pam_unix(sshd:session): session opened for user {user} by (uid=0)"
            ))

        # sudo (controlled)
        if random.random() < self.user_profiles[user]["sudo_rate"]:
            lines.append(self._fmt(
                dt + timedelta(seconds=random.randint(10, 30)),
                "sudo", pid,
                f"{user} : TTY=pts/0 ; PWD=/home/{user} ; USER=root ; COMMAND=/usr/bin/apt update"
            ))

        return lines, "NORMAL"

    # ----------------------------
    # ATTACKS (BURSTY BUT CAPPED)
    # ----------------------------
    def brute_force(self, dt):
        target = random.choice(self.attack_users)
        ip = random.choice(self.attack_ips)
        pid = random.randint(1000, 9999)

        lines = []
        count = random.randint(15, 40)  # HARD CAP

        for i in range(count):
            lines.append(self._fmt(
                dt + timedelta(seconds=i * random.uniform(1, 2)),
                "sshd", pid,
                f"Failed password for {target} from {ip} port {random.randint(1024,65535)} ssh2"
            ))

        return lines, "ATTACK"

    def distributed_attack(self, dt):
        lines = []

        count = random.randint(15, 35)

        for i in range(count):
            user = random.choice(self.attack_users + list(self.user_profiles.keys()))
            ip = random.choice(self.attack_ips)
            pid = random.randint(1000, 9999)

            lines.append(self._fmt(
                dt + timedelta(seconds=i * random.uniform(2, 5)),
                "sshd", pid,
                f"Failed password for {user} from {ip} port {random.randint(1024,65535)} ssh2"
            ))

        return lines, "ATTACK"

    def privilege_escalation(self, dt):
        user = random.choice(list(self.user_profiles.keys()))
        ip = random.choice(self.attack_ips)
        pid = random.randint(1000, 9999)

        return [
            self._fmt(dt, "sshd", pid,
                      f"Accepted password for {user} from {ip} port {random.randint(1024,65535)} ssh2"),
            self._fmt(dt + timedelta(seconds=5), "sudo", pid,
                      f"{user} : TTY=pts/0 ; PWD=/home/{user} ; USER=root ; COMMAND=/bin/bash"),
        ], "ATTACK"

    def sensitive_file_access(self, dt):
        user = random.choice(list(self.user_profiles.keys()))
        pid = random.randint(1000, 9999)

        targets = ["/etc/shadow", "/etc/sudoers", "/root/.ssh/authorized_keys"]

        lines = []
        for path in random.sample(targets, k=2):  # capped
            lines.append(self._fmt(
                dt + timedelta(seconds=random.randint(0, 20)),
                "audit", pid,
                f"type=SYSCALL ... cmd=cat ... type=PATH name=\"{path}\""
            ))

        return lines, "ATTACK"

    # ----------------------------
    # DATASET GENERATION (FIXED)
    # ----------------------------
    def generate_dataset(self, mode="train", size=2000, start_dt=None):
        if start_dt is None:
            start_dt = datetime(2024, 1, 1, 0, 0, 0)

        entries = []
        dt = start_dt

        normal_gens = [self.normal_session]
        attack_gens = [
            self.brute_force,
            self.distributed_attack,
            self.privilege_escalation,
            self.sensitive_file_access
        ]

        for _ in range(size):

            if mode == "train":
                is_attack = False
            elif mode == "validation":
                is_attack = random.random() < 0.3
            else:  # simulation
                is_attack = random.random() < 0.2

            gen = random.choice(attack_gens if is_attack else normal_gens)

            lines, label = gen(dt)

            # HARD LIMIT: max 50 lines per window
            if len(lines) > 50:
                lines = lines[:50]

            for line in lines:
                entries.append((line, label))

            # CRITICAL FIX: spacing prevents aggregation explosion
            if is_attack:
                dt += timedelta(seconds=random.randint(30, 90))
            else:
                dt += timedelta(minutes=random.randint(2, 6))

        random.shuffle(entries)
        return entries