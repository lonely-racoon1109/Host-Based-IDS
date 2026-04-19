import re
from datetime import datetime


# -----------------------------
# Core patterns (minimal, not fragile)
# -----------------------------

_SYSLOG_TS_RE = re.compile(r'^(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})')

_IP_RE = re.compile(
    r'(?:from|rhost=|src=)\s*('
    r'[\d]{1,3}(?:\.[\d]{1,3}){3}'
    r'|[0-9a-fA-F:]{3,39})'
)


class LogParser:
    def __init__(self):
        self.stats = {"total": 0, "parsed": 0, "unknown": 0}
        self._year = datetime.now().year
        self._last_month = datetime.now().month

    # ==================================================
    # MAIN ENTRY
    # ==================================================
    def parse_line(self, line, source_name="unknown"):
        self.stats["total"] += 1
        line = line.strip()

        timestamp = self._extract_timestamp(line)
        service = self._extract_service(line)
        user = self._extract_user(line)
        ip = self._extract_ip(line)

        event_type = self._classify_event(line, service)

        if event_type == "UNKNOWN":
            self.stats["unknown"] += 1

        self.stats["parsed"] += 1

        if "penalty" in line or "drop connection" in line:
            return {
                "timestamp": timestamp,
                "event_type": "AUTH_FAILED",
                "source": source_name,
                "service": "sshd",
                "user": None,
                "ip": self._extract_ip(line),
                "raw": line
            }

        return {
            "timestamp": timestamp,
            "event_type": event_type,
            "source": source_name,
            "service": service,
            "user": user,
            "ip": ip,
            "raw": line
        }

    # ==================================================
    # STEP 1: NORMALIZATION
    # ==================================================
    def _extract_timestamp(self, line):
        m = _SYSLOG_TS_RE.match(line)
        if not m:
            return datetime.now()

        try:
            dt = datetime.strptime(m.group(1), "%b %d %H:%M:%S")

            if dt.month == 12 and self._last_month == 1:
                self._year -= 1
            elif dt.month == 1 and self._last_month == 12:
                self._year += 1

            self._last_month = dt.month
            return dt.replace(year=self._year)
        except:
            return datetime.now()

    def _extract_service(self, line):
        if "sshd" in line:
            return "sshd"
        if "sudo" in line or "COMMAND=" in line:
            return "sudo"
        if "su[" in line:
            return "su"
        if "kernel" in line:
            return "kernel"
        return "unknown"

    def _extract_user(self, line):
        # sudo format
        m = re.search(r':\s*(\w+)\s*:', line)
        if m:
            return m.group(1)

        # ssh format
        m = re.search(r'for(?: invalid user)? (\S+)', line)
        if m:
            return m.group(1)

        # generic
        m = re.search(r'\buser=(\S+)', line)
        if m:
            return m.group(1)

        return None

    def _extract_ip(self, line):
        m = _IP_RE.search(line)
        return m.group(1) if m else None

    # ==================================================
    # STEP 2: INTELLIGENT CLASSIFICATION
    # ==================================================
    def _classify_event(self, line, service):
        l = line.lower()

        # ---------------- SSH AUTH ----------------
        if service == "sshd":
            if "failed" in l or "authentication" in l:
                return "AUTH_FAILED"

            if "invalid user" in l:
                return "AUTH_FAILED"

            if "connection closed" in l:
                return "AUTH_FAILED"

            if "accepted" in l:
                return "AUTH_SUCCESS"

        # ---------------- SUDO / PRIV ----------------
        if service == "sudo":
            if "command=" in l:
                return "PRIV_ESCALATION"

        if service == "su":
            if "session opened" in l:
                return "PRIV_ESCALATION"

        # ---------------- FILE ACCESS ----------------
        if any(x in l for x in ["/etc/shadow", "/etc/passwd"]):
            return "FILE_ACCESS"

        # ---------------- KERNEL ----------------
        if "kernel" in l and any(x in l for x in ["segfault", "denied", "overflow"]):
            return "KERNEL_ALERT"

        return "UNKNOWN"