# AAE IOC - IoC Validator V3

Versión con diagnóstico de fuentes.

## Mejoras V3

- Diagnóstico visible de APIs:
  - VirusTotal configurado/no configurado
  - OTX configurado/no configurado
  - AbuseIPDB configurado/no configurado
  - MalwareBazaar disponible
  - URLhaus disponible
- Tabla de evidencia por fuente.
- Columnas técnicas para depuración:
  - vt_checked
  - vt_malicious
  - vt_suspicious
  - mb_hit
  - otx_pulses
  - abuseipdb_score
  - api_errors
- Dictamen:
  - Malicious
  - Suspicious
  - Low Confidence
  - No Evidence
  - Invalid

## Ejecutar

```cmd
cd /d C:\IOC_APP\aae_ioc_app_v3
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
streamlit run app.py
```

## API Keys

```cmd
copy .env.example .env
notepad .env
```

Pega:

```env
VIRUSTOTAL_API_KEY=TU_LLAVE
OTX_API_KEY=TU_LLAVE
ABUSEIPDB_API_KEY=TU_LLAVE
```


---

## Deploy en Render

### Build Command

```bash
pip install -r requirements.txt
```

### Start Command

```bash
streamlit run app.py --server.address 0.0.0.0 --server.port $PORT
```

### Environment Variables

Configura estas variables en Render:

```env
VIRUSTOTAL_API_KEY=
OTX_API_KEY=
ABUSEIPDB_API_KEY=
```

No subas el archivo `.env` a GitHub.
