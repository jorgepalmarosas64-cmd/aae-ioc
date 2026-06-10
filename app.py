from io import BytesIO
import pandas as pd
import streamlit as st
from dotenv import load_dotenv

from ioc_utils import clean_ioc, refang, classify_ioc, pick_indicator_column, row_context
from clients import virustotal, malwarebazaar, urlhaus, otx, abuseipdb, api_status
from verdict import build_verdict, executive_risk
from mitre import infer_mitre

load_dotenv()

st.set_page_config(
    page_title="AAE IOC",
    page_icon="🛡️",
    layout="centered",
)

st.title("🛡️ AAE IOC")
st.caption("Validador automático de indicadores de compromiso")

with st.expander("Estado de fuentes", expanded=False):
    status_df = pd.DataFrame([
        {"fuente": k, "estado": v} for k, v in api_status().items()
    ])
    st.dataframe(status_df, use_container_width=True)
    st.caption("Si VirusTotal/OTX/AbuseIPDB aparecen sin API key, sus resultados no se considerarán.")

uploaded = st.file_uploader(
    "Arrastra o selecciona tu archivo Excel",
    type=["xlsx", "xls"],
    label_visibility="visible",
)

def check_sources(indicator, ioc_type):
    return {
        "VirusTotal": virustotal(indicator, ioc_type),
        "MalwareBazaar": malwarebazaar(indicator, ioc_type),
        "URLhaus": urlhaus(indicator, ioc_type),
        "OTX": otx(indicator, ioc_type),
        "AbuseIPDB": abuseipdb(indicator, ioc_type),
    }

def correlation_bonus(df, row, ioc_type):
    bonus = 0
    for col in ["event_id", "Event ID", "event", "campaign", "threat", "category"]:
        if col in df.columns and col in row.index:
            val = row.get(col)
            if pd.notna(val):
                count = int((df[col].astype(str) == str(val)).sum())
                if count >= 5:
                    bonus += 5
                    break
    if ioc_type in {"md5", "sha1", "sha256"}:
        bonus += 3
    return min(bonus, 8)

def analyze(df):
    indicator_col = pick_indicator_column(df)
    total = len(df)
    progress = st.progress(0)
    status = st.empty()
    out = []

    for n, (_, row) in enumerate(df.iterrows(), start=1):
        raw = row.get(indicator_col, "")
        indicator = refang(clean_ioc(raw))
        ioc_type = classify_ioc(indicator)
        context = row_context(row)

        status.info(f"Analizando indicador {n} de {total}...")
        results = check_sources(indicator, ioc_type)
        corr = correlation_bonus(df, row, ioc_type)

        mb = results.get("MalwareBazaar", {})
        otx_result = results.get("OTX", {})

        mitre = infer_mitre(
            context=context,
            mb_tags=mb.get("tags", ""),
            otx_names=otx_result.get("pulse_names", ""),
        )

        verdict, score, justification, technical_evidence, action, errors = build_verdict(
            indicator=indicator,
            ioc_type=ioc_type,
            results=results,
            context=context,
            correlation_bonus=corr,
        )

        vt = results.get("VirusTotal", {})
        uh = results.get("URLhaus", {})
        aip = results.get("AbuseIPDB", {})

        out.append({
            "indicator": indicator,
            "type": ioc_type,
            "dictamen": verdict,
            "confianza": score,
            "justificacion": justification,
            "accion_recomendada": action,
            "mitre_inferido": mitre,
            "evidencia_tecnica": technical_evidence,
            "vt_checked": vt.get("checked", False),
            "vt_malicious": vt.get("malicious", ""),
            "vt_suspicious": vt.get("suspicious", ""),
            "vt_error": vt.get("error", ""),
            "malwarebazaar_checked": mb.get("checked", False),
            "malwarebazaar_hit": mb.get("hit", ""),
            "malwarebazaar_family": mb.get("family", ""),
            "urlhaus_checked": uh.get("checked", False),
            "urlhaus_hit": uh.get("hit", ""),
            "otx_checked": otx_result.get("checked", False),
            "otx_pulses": otx_result.get("pulses", ""),
            "otx_error": otx_result.get("error", ""),
            "abuseipdb_checked": aip.get("checked", False),
            "abuseipdb_score": aip.get("score", ""),
            "abuseipdb_error": aip.get("error", ""),
            "api_errors": errors,
            "contexto_origen": context,
        })
        progress.progress(n / total)

    status.success("Dictamen generado.")
    return pd.DataFrame(out)

if uploaded:
    try:
        df = pd.read_excel(uploaded)
    except Exception as e:
        st.error(f"No se pudo leer el Excel: {e}")
        st.stop()

    st.success(f"Archivo cargado correctamente: {len(df)} filas detectadas.")

    with st.expander("Vista previa", expanded=False):
        st.dataframe(df.head(20), use_container_width=True)

    if st.button("Generar dictamen", type="primary", use_container_width=True):
        result_df = analyze(df)

        summary = result_df["dictamen"].value_counts().to_dict()
        risk = executive_risk(summary)

        st.subheader("Resumen ejecutivo")

        col1, col2, col3 = st.columns(3)
        col1.metric("Indicadores", len(result_df))
        col2.metric("Malicious", summary.get("Malicious", 0))
        col3.metric("Riesgo general", risk)

        c4, c5, c6 = st.columns(3)
        c4.metric("Suspicious", summary.get("Suspicious", 0))
        c5.metric("Low Confidence", summary.get("Low Confidence", 0))
        c6.metric("No Evidence", summary.get("No Evidence", 0))

        st.subheader("Dictamen")
        st.dataframe(
            result_df[[
                "indicator",
                "type",
                "dictamen",
                "confianza",
                "justificacion",
                "accion_recomendada",
                "mitre_inferido",
            ]],
            use_container_width=True,
        )

        with st.expander("Evidencia técnica y diagnóstico", expanded=False):
            st.dataframe(
                result_df[[
                    "indicator",
                    "vt_checked",
                    "vt_malicious",
                    "vt_suspicious",
                    "malwarebazaar_hit",
                    "urlhaus_hit",
                    "otx_checked",
                    "otx_pulses",
                    "abuseipdb_checked",
                    "abuseipdb_score",
                    "api_errors",
                    "evidencia_tecnica",
                ]],
                use_container_width=True,
            )

        summary_df = pd.DataFrame([
            {"metric": "total_indicators", "value": len(result_df)},
            {"metric": "malicious", "value": summary.get("Malicious", 0)},
            {"metric": "suspicious", "value": summary.get("Suspicious", 0)},
            {"metric": "low_confidence", "value": summary.get("Low Confidence", 0)},
            {"metric": "no_evidence", "value": summary.get("No Evidence", 0)},
            {"metric": "invalid", "value": summary.get("Invalid / Not IoC", 0) + summary.get("Invalid / Empty", 0)},
            {"metric": "overall_risk", "value": risk},
        ])

        output = BytesIO()
        with pd.ExcelWriter(output, engine="openpyxl") as writer:
            summary_df.to_excel(writer, index=False, sheet_name="Executive Summary")
            result_df.to_excel(writer, index=False, sheet_name="IoC Verdicts")
            df.to_excel(writer, index=False, sheet_name="Original Input")

        st.download_button(
            "Descargar reporte Excel",
            data=output.getvalue(),
            file_name="aae_ioc_verdict.xlsx",
            mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            use_container_width=True,
        )

        st.caption("El dictamen es apoyo analítico y debe validarse con contexto interno del entorno.")
else:
    st.info("Carga un archivo Excel para comenzar.")
