# SANN

Plataforma de análisis de escenarios de ciberseguridad. Visualiza grabaciones de pantalla sincronizadas con eventos de red, terminal, autenticación, syslog y más en una interfaz HUD.

![SANN Interface](TH.png)

## Requisitos

- Python 3.11+
- `ffprobe` (parte de ffmpeg): `sudo apt install ffmpeg`
- El dataset bruto (carpeta con `user*/...`) — **no está incluido en el repo**

## Setup

### 1. Clonar el repo

```bash
git clone https://github.com/vidzza/SANN.git
cd SANN
```

### 2. Instalar dependencias

```bash
pip install -r requirements.txt
```

### 3. Configurar rutas del dataset

```bash
cp .env.example .env
```

Edita `.env` y apunta `GODEYE_DATA_ROOT` a la carpeta raíz de tu dataset:

```
GODEYE_DATA_ROOT=/ruta/a/tu/dataset
GODEYE_DB_PATH=/ruta/a/tu/data/godeye_v2.db
```

La carpeta debe tener esta estructura mínima:

```
dataset/
└── user<id>/
    └── <cualquier layout>/
        ├── *.cast          # terminal (asciinema)
        ├── UAT-*.tsv       # keylogger
        ├── auth.log        # autenticación
        ├── syslog          # syslog
        ├── eve.json        # Suricata/IDS
        ├── bt.jsonl        # honeytrap
        ├── conn.log        # Zeek (JSONL)
        └── recording.ogv   # video (o .webm)
```

Ningún archivo es obligatorio — los que falten simplemente no aparecen en el panel correspondiente.

### 4. Importar el dataset por defecto

```bash
python3 import_manager.py
```

Esto:
1. Corre la ingestión completa (`ingest_v2.py`) y crea `data/godeye_v2.db`
2. Reconstruye el registro de medios (video + casts)
3. Corrige años en syslog/auth (inferidos del cast header)
4. Valida que todos los paneles tienen datos en la ventana del video

Si ya tienes la DB y solo quieres re-validar:

```bash
python3 import_manager.py --skip-ingest
```

### 5. Levantar el servidor

```bash
python3 -m uvicorn api.main:app --host 0.0.0.0 --port 8000
```

### 6. Abrir la UI

Navega a: **http://localhost:8000/threat**

## Múltiples datasets (Projects)

SANN soporta múltiples datasets aislados. Para añadir un segundo dataset (por ejemplo P032):

1. En la UI, el selector **PROJECT** en la barra superior lista los proyectos disponibles.
2. Vía API, crea un proyecto:

```bash
curl -X POST http://localhost:8000/api/projects \
  -H "Content-Type: application/json" \
  -d '{
    "name": "P032",
    "project_type": "dataset",
    "data_path": "/ruta/a/P032",
    "attacker_ips": "128.16.11.9,114.0.194.2"
  }'
```

3. Lanza la ingestión:

```bash
curl -X POST http://localhost:8000/api/projects/<project_id>/ingest
```

Cada proyecto tiene su propia base de datos SQLite aislada en `data/project_<id>.db`.

## Estructura del repo

```
SANN/
├── api/
│   └── main.py            # FastAPI — todos los endpoints
├── frontend/
│   └── palantir.html      # UI principal (single page)
├── import_manager.py      # Pipeline de importación + validación (dataset por defecto)
├── ingest_v2.py           # Motor de ingestión (usado por import_manager y la API)
├── .env.example           # Plantilla de configuración
└── requirements.txt
```

## Variables de entorno

| Variable | Default | Descripción |
|---|---|---|
| `GODEYE_DATA_ROOT` | `/tmp/obsidian_full/P003` | Carpeta raíz del dataset por defecto |
| `GODEYE_DB_PATH` | `data/godeye_v2.db` | Ruta al archivo SQLite principal |
| `GODEYE_ATTACKER_IPS` | IPs de P003 | IPs del atacante para clasificación sensor_packet (separadas por coma) |

Se pueden poner en un archivo `.env` en la raíz del repo.
