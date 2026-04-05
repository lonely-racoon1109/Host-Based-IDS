import re
from datetime import datetime

def extract_time(line):
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