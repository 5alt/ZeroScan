import os

INPUT_DIR = "input"
INPUT_DOMAIN_FILE = os.path.join(INPUT_DIR, "domain.txt")

OUTPUT_DIR = "output"

IPS = "ips.txt"
REPORT_FILENAME = "report.html"


## API Keys
os.environ['virustotal_key'] = ""
os.environ['passivetotal_key'] = ""
os.environ['passivetotal_secret'] = ""


PASSIVE_SEARCH_DIR = "passive"
TAKEOVER_DIR = 'takeover'