import base64
import os
from urllib.parse import quote
import requests

TIMEOUT = 25

def api_status():
    return {
        "VirusTotal": "Configurado" if os.getenv("VIRUSTOTAL_API_KEY", "").strip() else "Sin API key",
        "OTX": "Configurado" if os.getenv("OTX_API_KEY", "").strip() else "Sin API key",
        "AbuseIPDB": "Configurado" if os.getenv("ABUSEIPDB_API_KEY", "").strip() else "Sin API key",
        "MalwareBazaar": "Disponible sin API key",
        "URLhaus": "Disponible sin API key",
    }

def _get_json(url, headers=None, params=None):
    try:
        r = requests.get(url, headers=headers or {}, params=params or {}, timeout=TIMEOUT)
        try:
            data = r.json()
        except Exception:
            data = {}
        return {"ok": r.ok, "status": r.status_code, "data": data, "error": "" if r.ok else r.text[:300]}
    except Exception as e:
        return {"ok": False, "status": None, "data": {}, "error": str(e)}

def _post_json(url, headers=None, data=None):
    try:
        r = requests.post(url, headers=headers or {}, data=data or {}, timeout=TIMEOUT)
        try:
            js = r.json()
        except Exception:
            js = {}
        return {"ok": r.ok, "status": r.status_code, "data": js, "error": "" if r.ok else r.text[:300]}
    except Exception as e:
        return {"ok": False, "status": None, "data": {}, "error": str(e)}

def virustotal(indicator, ioc_type):
    api_key = os.getenv("VIRUSTOTAL_API_KEY", "").strip()
    if not api_key:
        return {"checked": False, "source": "VirusTotal", "reason": "API key not configured"}

    base = "https://www.virustotal.com/api/v3"
    headers = {"x-apikey": api_key}

    if ioc_type in {"md5", "sha1", "sha256"}:
        url = f"{base}/files/{indicator}"
    elif ioc_type == "ip":
        url = f"{base}/ip_addresses/{indicator}"
    elif ioc_type == "domain":
        url = f"{base}/domains/{indicator}"
    elif ioc_type == "url":
        url_id = base64.urlsafe_b64encode(indicator.encode()).decode().strip("=")
        url = f"{base}/urls/{url_id}"
    else:
        return {"checked": False, "source": "VirusTotal", "reason": "Unsupported IoC type"}

    resp = _get_json(url, headers=headers)
    if not resp["ok"]:
        return {
            "checked": True,
            "source": "VirusTotal",
            "error": f"HTTP {resp['status']}: {resp.get('error','')[:120]}"
        }

    attrs = resp["data"].get("data", {}).get("attributes", {})
    stats = attrs.get("last_analysis_stats", {}) or {}

    signature_info = attrs.get("signature_info") or {}
    signer = ""
    if isinstance(signature_info, dict):
        signer = signature_info.get("signers") or signature_info.get("publisher") or signature_info.get("verified") or ""

    return {
        "checked": True,
        "source": "VirusTotal",
        "malicious": int(stats.get("malicious", 0) or 0),
        "suspicious": int(stats.get("suspicious", 0) or 0),
        "harmless": int(stats.get("harmless", 0) or 0),
        "undetected": int(stats.get("undetected", 0) or 0),
        "reputation": attrs.get("reputation", ""),
        "meaningful_name": attrs.get("meaningful_name", ""),
        "type_description": attrs.get("type_description", ""),
        "signer": signer,
        "error": "",
    }

def malwarebazaar(indicator, ioc_type):
    if ioc_type not in {"md5", "sha1", "sha256"}:
        return {"checked": False, "source": "MalwareBazaar", "reason": "Only hashes supported"}

    resp = _post_json("https://mb-api.abuse.ch/api/v1/", data={"query": "get_info", "hash": indicator})
    if not resp["ok"]:
        return {"checked": True, "source": "MalwareBazaar", "error": f"HTTP {resp['status']}: {resp.get('error','')[:120]}"}

    data = resp["data"]
    hit = data.get("query_status") == "ok"
    families = []
    tags = []
    file_names = []

    if hit:
        for item in data.get("data", []):
            if item.get("signature"):
                families.append(str(item.get("signature")))
            if item.get("file_name"):
                file_names.append(str(item.get("file_name")))
            for t in item.get("tags", []) or []:
                tags.append(str(t))

    return {
        "checked": True,
        "source": "MalwareBazaar",
        "hit": hit,
        "family": ", ".join(sorted(set(families))),
        "tags": ", ".join(sorted(set(tags))[:12]),
        "file_names": ", ".join(sorted(set(file_names))[:5]),
        "error": "",
    }

def urlhaus(indicator, ioc_type):
    if ioc_type != "url":
        return {"checked": False, "source": "URLhaus", "reason": "Only URLs supported"}

    resp = _post_json("https://urlhaus-api.abuse.ch/v1/url/", data={"url": indicator})
    if not resp["ok"]:
        return {"checked": True, "source": "URLhaus", "error": f"HTTP {resp['status']}: {resp.get('error','')[:120]}"}

    data = resp["data"]
    hit = data.get("query_status") == "ok"

    return {
        "checked": True,
        "source": "URLhaus",
        "hit": hit,
        "threat": data.get("threat", ""),
        "status": data.get("url_status", ""),
        "host": data.get("host", ""),
        "error": "",
    }

def otx(indicator, ioc_type):
    api_key = os.getenv("OTX_API_KEY", "").strip()
    if not api_key:
        return {"checked": False, "source": "OTX", "reason": "API key not configured"}

    type_map = {
        "ip": "IPv4",
        "domain": "domain",
        "url": "url",
        "md5": "file",
        "sha1": "file",
        "sha256": "file",
    }

    otx_type = type_map.get(ioc_type)
    if not otx_type:
        return {"checked": False, "source": "OTX", "reason": "Unsupported IoC type"}

    headers = {"X-OTX-API-KEY": api_key}
    encoded = quote(indicator, safe="")
    resp = _get_json(f"https://otx.alienvault.com/api/v1/indicators/{otx_type}/{encoded}/general", headers=headers)
    if not resp["ok"]:
        return {"checked": True, "source": "OTX", "error": f"HTTP {resp['status']}: {resp.get('error','')[:120]}"}

    pulse_info = resp["data"].get("pulse_info", {}) or {}
    pulse_count = int(pulse_info.get("count", 0) or 0)
    names = []
    for p in pulse_info.get("pulses", [])[:5]:
        name = p.get("name")
        if name:
            names.append(str(name))

    return {
        "checked": True,
        "source": "OTX",
        "pulses": pulse_count,
        "pulse_names": " | ".join(names),
        "error": "",
    }

def abuseipdb(indicator, ioc_type):
    api_key = os.getenv("ABUSEIPDB_API_KEY", "").strip()
    if ioc_type != "ip":
        return {"checked": False, "source": "AbuseIPDB", "reason": "Only IPs supported"}
    if not api_key:
        return {"checked": False, "source": "AbuseIPDB", "reason": "API key not configured"}

    headers = {"Key": api_key, "Accept": "application/json"}
    params = {"ipAddress": indicator, "maxAgeInDays": 90}
    resp = _get_json("https://api.abuseipdb.com/api/v2/check", headers=headers, params=params)
    if not resp["ok"]:
        return {"checked": True, "source": "AbuseIPDB", "error": f"HTTP {resp['status']}: {resp.get('error','')[:120]}"}

    data = resp["data"].get("data", {}) or {}
    return {
        "checked": True,
        "source": "AbuseIPDB",
        "score": int(data.get("abuseConfidenceScore", 0) or 0),
        "reports": int(data.get("totalReports", 0) or 0),
        "country": data.get("countryCode", ""),
        "isp": data.get("isp", ""),
        "usage_type": data.get("usageType", ""),
        "error": "",
    }
