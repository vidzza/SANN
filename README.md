# GOD EYE

Plataforma de análisis de escenarios de ciberseguridad. Visualiza grabaciones de pantalla sincronizadas con eventos de red, terminal, autenticación, syslog y más en una interfaz HUD estilo Palantir.

## Requisitos

- Python 3.11+
- `ffprobe` (parte de ffmpeg): `sudo apt install ffmpeg`
- El dataset bruto (carpeta con `user*/...`) — **no está incluido en el repo**

## Setup

### 1. Clonar el repo

```bash
git clone https://github.com/tu-usuario/godeye.git
cd godeye
```

### 2. Instalar dependencias

```bash
pip install fastapi uvicorn
```

> Las dependencias del `requirements.txt` completo incluyen ML/AI opcionales. Para correr el servidor solo necesitas `fastapi` y `uvicorn`.

### 3. Configurar rutas del dataset

```bash
cp .env.example .env
```

Edita `.env` y apunta `GODEYE_DATA_ROOT` a la carpeta raíz de tu dataset:

```
GODEYE_DATA_ROOT=/ruta/a/tu/dataset
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
        ├── sensor.log      # pcap/zeek
        └── recording.webm  # video (o .ogv)
```

Ningún archivo es obligatorio — los que falten simplemente no aparecen en el panel correspondiente.

### 4. Importar el dataset

```bash
python3 import_manager.py
```

Esto:
1. Corre la ingestión completa (`ingest_v2.py`) y crea `data/godeye_v2.db`
2. Corrige timestamps de Suricata (detección automática de zona horaria)
3. Reconstruye el registro de medios (video + casts)
4. Corrige años en syslog/auth (inferidos del cast header)
5. Valida que todos los paneles tienen datos en la ventana del video

Si ya tienes la DB y solo quieres re-validar:

```bash
python3 import_manager.py --skip-ingest
```

### 5. Levantar el servidor

```bash
fuser -k 8000/tcp 2>/dev/null; python3 -m uvicorn api.main:app --host 0.0.0.0 --port 8000
```

### 6. Abrir la UI

Navega a: **http://localhost:8000/threat**

## Estructura del repo

```
godeye/
├── api/
│   └── main.py            # FastAPI — todos los endpoints
├── frontend/
│   └── palantir.html      # UI principal (single page)
├── import_manager.py      # Pipeline de importación + validación
├── ingest_v2.py           # Motor de ingestión
├── .env.example           # Plantilla de configuración
├── .gitignore
└── requirements.txt
```

## Variables de entorno

| Variable | Default | Descripción |
|---|---|---|
| `GODEYE_DATA_ROOT` | `/tmp/obsidian_full/P003` | Carpeta raíz del dataset |
| `GODEYE_DB_PATH` | `data/godeye_v2.db` | Ruta al archivo SQLite |

Se pueden poner en un archivo `.env` en la raíz del repo o exportar en la shell antes de correr cualquier script.

## Participantes soportados

El sistema detecta automáticamente cualquier carpeta `user<id>` en `DATA_ROOT`. No requiere una estructura de subdirectorios específica.
