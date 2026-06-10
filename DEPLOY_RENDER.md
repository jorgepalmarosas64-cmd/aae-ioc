# Deploy rápido: AAE IOC

## 1. GitHub

Crea un repo llamado:

```text
aae-ioc
```

Sube todos estos archivos.

No subas `.env`.

## 2. Render

En Render:

```text
New → Web Service → Connect GitHub → aae-ioc
```

Configura:

### Build Command

```bash
pip install -r requirements.txt
```

### Start Command

```bash
streamlit run app.py --server.address 0.0.0.0 --server.port $PORT
```

## 3. Variables secretas

En Render → Environment:

```env
VIRUSTOTAL_API_KEY=tu_key
OTX_API_KEY=tu_key
ABUSEIPDB_API_KEY=tu_key
```

## 4. Resultado

Render generará una URL tipo:

```text
https://aae-ioc.onrender.com
```

Esa liga se comparte con el equipo.
