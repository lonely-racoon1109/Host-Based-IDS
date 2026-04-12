import re
from datetime import datetime


class LogParser:
    def __init__(self):
        self.patterns = [

            ("AUTH_FAILED", re.compile(
                r'Failed password for (?:invalid user\s+)?(?P<user>\w+) from (?P<ip>[\d\.:]+)'
            )),

            ("AUTH_SUCCESS", re.compile(
                r'Accepted \w+ for (?P<user>\w+) from (?P<ip>[\d\.:]+)'
            )),

            ("PRIV_ESCALATION", re.compile(
                r'sudo: (?P<user>\w+)'
            )),

            ("FILE_ACCESS", re.compile(
                r'cmd=".*?(?P<file>/etc/\w+)"'
            )),
        ]

    def extract_time(self, line):
        match = re.search(r'^\w{3}\s+\d+\s\d+:\d+:\d+', line)
        if match:
            try:
                return datetime.strptime(
                    match.group() + f" {datetime.now().year}",
                    "%b %d %H:%M:%S %Y"
                )
            except:
                return datetime.min
        return datetime.min

    def parse_line(self, line):
        date_match = re.search(r'^\w{3}\s+\d+\s\d+:\d+:\d+', line)

        if not date_match:
            return None

        try:
            raw_date = f"{date_match.group()} {datetime.now().year}"
            dt = datetime.strptime(raw_date, "%b %d %H:%M:%S %Y")
            timestamp = dt.strftime("%Y-%m-%d %H:%M:%S")

        except:
            return None


        for event_type, pattern in self.patterns:
            match = pattern.search(line)
            if match:
                data = match.groupdict()

                service_match = re.search(r'\s([a-zA-Z\-]+)(?:\[\d+\])?:', line)
                service = service_match.group(1) if service_match else "unknown"

                return {
                    "timestamp": timestamp,
                    "event_type": event_type,
                    "service": service,
                    "user": data.get("user"),
                    "ip": data.get("ip"),
                    "extra": data
                }

        return None
    
    
    