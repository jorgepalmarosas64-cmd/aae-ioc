from ioc_utils import is_private_ip

def recommended_action(verdict):
    if verdict == "Malicious":
        return "Bloqueo inmediato y búsqueda retrospectiva."
    if verdict == "Suspicious":
        return "Revisión manual y monitoreo reforzado."
    if verdict == "Low Confidence":
        return "Monitorear y validar con contexto interno."
    if verdict == "No Evidence":
        return "Sin bloqueo automático; mantener observación."
    if verdict.startswith("Invalid"):
        return "Corregir o depurar el indicador."
    if verdict == "Likely Benign":
        return "No bloquear; validar si pertenece al entorno."
    return "Revisión manual."

def build_verdict(indicator, ioc_type, results, context="", correlation_bonus=0):
    score = 0
    public_hits = 0
    evidence = []
    technical = []
    errors = []

    for source, res in results.items():
        if res.get("error"):
            errors.append(f"{source}: {res.get('error')}")

    if ioc_type == "empty":
        verdict = "Invalid / Empty"
        return verdict, 0, "Valor vacío.", "Sin indicador válido.", recommended_action(verdict), " | ".join(errors)

    if ioc_type == "unknown":
        verdict = "Invalid / Not IoC"
        return verdict, 0, "No se reconoció como indicador válido.", "Formato no reconocido.", recommended_action(verdict), " | ".join(errors)

    if ioc_type == "ip" and is_private_ip(indicator):
        verdict = "Likely Benign"
        return verdict, 5, "IP privada, local o no enrutable.", "Rango interno/común.", recommended_action(verdict), " | ".join(errors)

    vt = results.get("VirusTotal", {})
    if vt.get("checked"):
        mal = int(vt.get("malicious", 0) or 0)
        susp = int(vt.get("suspicious", 0) or 0)
        signer = vt.get("signer", "")
        technical.append(f"VirusTotal malicious={mal}, suspicious={susp}")
        if signer:
            technical.append(f"Signer/Publisher={signer}")

        if mal >= 10:
            score += 55
            public_hits += 1
            evidence.append("Alta detección en VirusTotal.")
        elif mal >= 5:
            score += 40
            public_hits += 1
            evidence.append("Detección relevante en VirusTotal.")
        elif mal >= 1:
            score += 20
            public_hits += 1
            evidence.append("Detección baja en VirusTotal.")
        if susp > 0:
            score += min(10, susp * 2)

    mb = results.get("MalwareBazaar", {})
    if mb.get("checked"):
        technical.append(f"MalwareBazaar hit={mb.get('hit')}, family={mb.get('family','')}")
        if mb.get("hit"):
            score += 70
            public_hits += 1
            fam = mb.get("family")
            evidence.append(f"Hash presente en MalwareBazaar{f' como {fam}' if fam else ''}.")

    uh = results.get("URLhaus", {})
    if uh.get("checked"):
        technical.append(f"URLhaus hit={uh.get('hit')}, status={uh.get('status','')}")
        if uh.get("hit"):
            score += 60
            public_hits += 1
            evidence.append("URL reportada en URLhaus.")

    otx = results.get("OTX", {})
    if otx.get("checked"):
        pulses = int(otx.get("pulses", 0) or 0)
        technical.append(f"OTX pulses={pulses}")
        if pulses >= 5:
            score += 25
            public_hits += 1
            evidence.append("Presente en múltiples pulsos de OTX.")
        elif pulses >= 1:
            score += 10
            public_hits += 1
            evidence.append("Presente en OTX.")

    aip = results.get("AbuseIPDB", {})
    if aip.get("checked"):
        aip_score = int(aip.get("score", 0) or 0)
        reports = int(aip.get("reports", 0) or 0)
        technical.append(f"AbuseIPDB score={aip_score}, reports={reports}")
        if aip_score >= 80:
            score += 45
            public_hits += 1
            evidence.append("IP con alta reputación de abuso.")
        elif aip_score >= 40:
            score += 25
            public_hits += 1
            evidence.append("IP con reputación de abuso moderada.")
        elif aip_score >= 10:
            score += 10
            evidence.append("IP con reportes menores de abuso.")

    if public_hits >= 2 and score < 75:
        score += 15
        evidence.append("Confirmado por más de una fuente pública.")

    if correlation_bonus > 0:
        score += correlation_bonus
        evidence.append("Relacionado con otros indicadores del mismo conjunto/campaña.")

    suspicious_context = ["rat", "stealer", "banker", "trojan", "payload", "malware", "phishing", "installation"]
    c = context.lower()
    if any(x in c for x in suspicious_context):
        score += 8
        evidence.append("El contexto del archivo sugiere asociación con actividad maliciosa.")

    score = min(score, 100)

    if score >= 75:
        verdict = "Malicious"
    elif score >= 40:
        verdict = "Suspicious"
    elif score >= 10:
        verdict = "Low Confidence"
    else:
        verdict = "No Evidence"

    if not evidence:
        justification = "No se encontró evidencia pública suficiente en las fuentes habilitadas."
    else:
        justification = " ".join(evidence)

    technical_evidence = " | ".join(technical) if technical else "Sin fuentes consultadas o sin API configurada."
    return verdict, score, justification, technical_evidence, recommended_action(verdict), " | ".join(errors)

def executive_risk(summary_counts):
    malicious = summary_counts.get("Malicious", 0)
    suspicious = summary_counts.get("Suspicious", 0)
    low = summary_counts.get("Low Confidence", 0)
    total = sum(summary_counts.values())

    if total == 0:
        return "Sin datos"

    ratio = (malicious + suspicious * 0.5 + low * 0.15) / total

    if malicious > 0 and ratio >= 0.4:
        return "ALTO"
    if malicious > 0 or suspicious > 0:
        return "MEDIO"
    if low / total > 0.5:
        return "REVISAR FUENTES"
    return "BAJO"
