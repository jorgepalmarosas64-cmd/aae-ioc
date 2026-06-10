import re
from urllib.parse import urlparse

MD5_RE = re.compile(r"^[a-fA-F0-9]{32}$")
SHA1_RE = re.compile(r"^[a-fA-F0-9]{40}$")
SHA256_RE = re.compile(r"^[a-fA-F0-9]{64}$")
IPV4_RE = re.compile(r"^(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)$")
DOMAIN_RE = re.compile(r"^(?!-)(?:[a-zA-Z0-9-]{1,63}\.)+[a-zA-Z]{2,63}$")

PREFERRED_COLUMNS = [
    "value", "indicator", "ioc", "observable", "attribute_value", "attribute",
    "sha256", "sha1", "md5", "ip", "domain", "url",
    "Indicator", "Value", "IOC"
]

def clean_ioc(value) -> str:
    if value is None:
        return ""
    value = str(value).strip()
    return value.strip('"').strip("'").strip()

def refang(value: str) -> str:
    value = clean_ioc(value)
    value = value.replace("[.]", ".").replace("(.)", ".")
    value = value.replace("hxxp://", "http://").replace("hxxps://", "https://")
    return value

def classify_ioc(raw: str) -> str:
    value = refang(raw)
    if not value:
        return "empty"

    if MD5_RE.match(value):
        return "md5"
    if SHA1_RE.match(value):
        return "sha1"
    if SHA256_RE.match(value):
        return "sha256"

    parsed = urlparse(value)
    if parsed.scheme in ("http", "https") and parsed.netloc:
        return "url"

    if IPV4_RE.match(value):
        return "ip"

    if DOMAIN_RE.match(value):
        return "domain"

    if "@" in value and "." in value.split("@")[-1]:
        return "email"

    return "unknown"

def is_private_ip(ip: str) -> bool:
    ip = clean_ioc(ip)
    return (
        ip.startswith("10.")
        or ip.startswith("192.168.")
        or ip.startswith("127.")
        or ip.startswith("169.254.")
        or ip == "0.0.0.0"
        or ip == "255.255.255.255"
    )

def pick_indicator_column(df):
    lower = {str(c).lower().strip(): c for c in df.columns}
    for c in PREFERRED_COLUMNS:
        if c.lower() in lower:
            return lower[c.lower()]
    return df.columns[0]

def row_context(row) -> str:
    parts = []
    for col, val in row.items():
        if val is None:
            continue
        sval = str(val)
        if sval.lower() == "nan":
            continue
        if len(sval) > 250:
            sval = sval[:250]
        parts.append(f"{col}: {sval}")
    return " | ".join(parts)
