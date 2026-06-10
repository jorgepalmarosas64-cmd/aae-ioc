MITRE_RULES = [
    ("powershell", "T1059.001", "PowerShell"),
    ("cmd.exe", "T1059.003", "Windows Command Shell"),
    ("script", "T1059", "Command and Scripting Interpreter"),
    ("phishing", "T1566", "Phishing"),
    ("macro", "T1204", "User Execution"),
    ("user execution", "T1204", "User Execution"),
    ("process injection", "T1055", "Process Injection"),
    ("injection", "T1055", "Process Injection"),
    ("registry run", "T1547.001", "Registry Run Keys / Startup Folder"),
    ("run key", "T1547.001", "Registry Run Keys / Startup Folder"),
    ("persistence", "T1547", "Boot or Logon Autostart Execution"),
    ("keylog", "T1056.001", "Keylogging"),
    ("credential", "T1555", "Credentials from Password Stores"),
    ("browser", "T1555.003", "Credentials from Web Browsers"),
    ("screen capture", "T1113", "Screen Capture"),
    ("screenshot", "T1113", "Screen Capture"),
    ("clipboard", "T1115", "Clipboard Data"),
    ("network discovery", "T1016", "System Network Configuration Discovery"),
    ("system information", "T1082", "System Information Discovery"),
    ("download", "T1105", "Ingress Tool Transfer"),
    ("payload delivery", "T1105", "Ingress Tool Transfer"),
    ("payload installation", "T1547", "Persistence / Autostart"),
    ("rat", "T1219", "Remote Access Software"),
    ("banker", "T1555", "Credentials from Password Stores"),
    ("stealer", "T1555", "Credentials from Password Stores"),
]

def infer_mitre(context: str, mb_tags: str = "", otx_names: str = ""):
    blob = f"{context} {mb_tags} {otx_names}".lower()
    hits = []
    seen = set()

    for needle, technique_id, name in MITRE_RULES:
        if needle in blob and technique_id not in seen:
            hits.append(f"{technique_id} - {name}")
            seen.add(technique_id)

    return " | ".join(hits)
