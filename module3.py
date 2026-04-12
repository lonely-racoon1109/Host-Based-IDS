import re
from datetime import datetime

class LogParser:
    def __init__(self):
        self.event_rules = [
            ("AUTH_FAILED", [
                r"Failed password",
                r"Invalid user",
                r"authentication failure",
                r"Connection closed by invalid user",
                r"User unknown",
                r"pam_faillock",
            ]),

            ("AUTH_SUCCESS", [
                r"Accepted password",
                r"Accepted publickey"
            ]),

            ("PRIV_ESCALATION", [
                r"sudo:"
            ]),

            ("FILE_ACCESS", [
                r"cmd="
            ]),

            ("KERNEL_ALERT", [
                r"kernel:",
                r"denied",
                r"segfault",
                r"audit",
                r"overflow"
            ])
        ]

    def _match_event(self, line):
        for event, patterns in self.event_rules:
            if any(p.lower() in line.lower() for p in patterns):
                return event
        return None

    def _extract_user(self, line):
        m = re.search(r"invalid user (\w+)", line)
        if m: return m.group(1)

        m = re.search(r"for (\w+)", line)
        if m: return m.group(1)

        m = re.search(r"user (\w+)", line)
        if m: return m.group(1)

        return None

    def _extract_ip(self, line):
        m = re.search(r"from ([\d\.:]+)", line)
        if m: return m.group(1)

        m = re.search(r"rhost=([\d\.:]+)", line)
        if m: return m.group(1)

        return None

    def parse_line(self, line):
        date_match = re.search(r'^\w{3}\s+\d+\s\d+:\d+:\d+', line)
        if not date_match:
            return None

        try:
            dt = datetime.strptime(date_match.group() + f" {datetime.now().year}",
                                   "%b %d %H:%M:%S %Y")
        except:
            return None

        event = self._match_event(line)
        if not event:
            return

        return {
            "timestamp": dt.strftime("%Y-%m-%d %H:%M:%S"),
            "event_type": event,
            "service": re.search(r'\s([a-zA-Z\-]+)(?:\[\d+\])?:', line).group(1),
            "user": self._extract_user(line),
            "ip": self._extract_ip(line),
            "raw": line.strip()
        }