# SANN — Prompt de trabajo para el equipo
> Diagnóstico completo del sistema al 2026-06-09. Todo lo que está roto, por qué, y exactamente qué hacer.

---

## Contexto de la plataforma

SANN es una plataforma de análisis de escenarios de ciberseguridad.
Pipeline: `ingest_v2.py` → SQLite (`data/godeye_v2.db` + `data/project_<id>.db`) → `api/main.py` (FastAPI) → `frontend/palantir.html`.

El sistema ahora soporta múltiples proyectos con DBs aisladas y un corpus combinado en `godeye_v2.db`.
Hay dos proyectos con datos reales: **P003** (`project_id=da2c86c9`, 134,812 eventos, 4 participantes) y **P032** (`project_id=9c4cee20`, 321,427 eventos, 3 participantes).

---

## BUGS CRÍTICOS — rompen funcionalidad

### BUG-1: Suricata almacena hora local en lugar de UTC

**Síntoma:** El panel Network (suricata/bt_jsonl) no muestra alertas durante la ventana de video para user2003 y user2016.

**Causa raíz confirmada:** `parse_suricata_eve` en `ingest_v2.py` almacena el timestamp sin convertir a UTC. Los archivos `eve.json` del dataset tienen timezone `-0400` (EDT), pero el parser le quita el offset en lugar de convertirlo.

```
raw_data contiene:  "timestamp": "2025-08-15T11:25:23.826914-0400"
almacenado en DB:    2025-08-15T11:25:23.826914   ← INCORRECTO (hora EDT, no UTC)
correcto sería:      2025-08-15T15:25:23.826914   ← +4h = UTC real
```

**Impacto concreto:**
- user2003: suricata almacenado como 11:25→15:41, video empieza a las 19:07 → **cero solapamiento**
- Con la corrección: suricata sería 15:25→19:41 UTC → **sí solapa con el video (19:07→19:39)**
- user2016: mismo problema, +4h lo alinearía con el video

**Fix en `ingest_v2.py` (`parse_suricata_eve`):**
```python
# ACTUAL (mal):
dt = datetime.fromisoformat(ts_str.replace('Z', '+00:00'))
ts_utc = dt.replace(tzinfo=None).isoformat()   # ← pierde el offset

# CORRECTO:
dt = datetime.fromisoformat(ts_str)             # preserva el offset
ts_utc = dt.astimezone(timezone.utc).replace(tzinfo=None).isoformat()
```

**Fix en la DB existente** (para no re-ingestar todo):
```python
import sqlite3, json
from datetime import datetime, timezone

for db_path in ['data/godeye_v2.db', 'data/project_da2c86c9.db']:
    con = sqlite3.connect(db_path)
    rows = con.execute(
        "SELECT event_id, raw_data FROM events WHERE source_type='suricata'"
    ).fetchall()
    updates = []
    for event_id, raw in rows:
        try:
            d = json.loads(raw)
            raw_ts = d.get('timestamp', '')
            if raw_ts and ('+' in raw_ts[10:] or raw_ts.endswith('Z')):
                dt = datetime.fromisoformat(raw_ts)
                utc_str = dt.astimezone(timezone.utc).replace(tzinfo=None).isoformat()
                updates.append((utc_str, event_id))
        except Exception:
            pass
    if updates:
        con.executemany("UPDATE events SET timestamp_utc=? WHERE event_id=?", updates)
        con.commit()
        print(f"{db_path}: updated {len(updates)} suricata rows")
    con.close()
```

---

### BUG-2: Sensor_packet tiene IPs vacías en ~24% de eventos de user4002

**Síntoma:** Panel PCAP muestra filas sin src/dst IP para user4002 (los primeros ~10k eventos).

**Causa:** Algunos sensor_packets tienen formato diferente en raw_data (el parser falla silenciosamente y guarda IPs vacías). El raw_data con formato correcto sí tiene IPs.

**Diagnóstico:** 
```
user4002 sensor: 44,927 eventos  has_src_ip=34,067  (75%)  — 10,860 sin IP
```

**Fix en `parse_sensor_log` (`ingest_v2.py`):** El parser usa `ast.literal_eval` pero falla en algunas líneas. Agregar fallback:
```python
# Si ast.literal_eval falla, intentar json.loads con comillas simples reemplazadas
try:
    d = ast.literal_eval(line)
except Exception:
    try:
        d = json.loads(line.replace("'", '"'))
    except Exception:
        continue  # skip malformed line, log it
```

**Fix adicional en el frontend** — el panel PCAP debe filtrar filas sin ninguna info útil:
```javascript
// En renderPcap: saltar eventos con IPs vacías Y sin action_name informativo
const vis = events.filter(e => e.src_ip || e.dest_ip || e.action_name)
               .slice(-_PANEL_MAX);
```

---

### BUG-3: `media_registry` no tiene `project_id` — toda la media aparece en todos los proyectos

**Síntoma:** Si hay múltiples proyectos, al cambiar de proyecto el selector de participantes cambia pero la media (video/cast) puede ser del proyecto anterior.

**Causa:** La columna `project_id` en `media_registry` existe pero está vacía (`''`) en los 19 registros actuales. El código en `media_list` filtra por `project_id=? OR project_id=''`, lo cual devuelve TODA la media cuando `project_id=''`.

**Fix 1 — Poblar los registros existentes:**
```python
import sqlite3
con = sqlite3.connect('data/godeye_v2.db')
# user2003, user4002 → P003 (da2c86c9)
con.execute("UPDATE media_registry SET project_id='da2c86c9' WHERE participant_id IN ('user2003','user4002','user0003')")
# user0032, user2016, user3017 → P032 (9c4cee20)
con.execute("UPDATE media_registry SET project_id='9c4cee20' WHERE participant_id IN ('user0032','user2016','user3017')")
con.commit(); con.close()
```

**Fix 2 — En `_write_media_rows` (`api/main.py`):** cuando se llama desde `sync_media_for_project`, pasar `project_id` y guardar en el INSERT.

**Fix 3 — En `media_list` y `cast_list` endpoints:** cambiar la condición a:
```python
# Si hay project_id, filtrar SOLO por ese project_id (no el fallback OR '')
if project_id:
    conds.append("project_id = ?")
    params.append(project_id)
```

---

### BUG-4: ZIP upload no sincroniza media después de ingestar

**Síntoma:** Se sube un ZIP, se ingesta correctamente, pero no aparecen video ni casts en la UI.

**Causa:** El endpoint `POST /api/projects/upload` lanza `ingest_v2.py` como subprocess y termina. No hay llamada posterior a `sync_media_for_project` que descubra los archivos `.ogv`/`.cast`/`.tsv` y los registre en `media_registry`.

**Fix en `api/main.py` — agregar `sync_media_for_project` automático cuando el ingest termina.** Opción simple: en `project_status`, cuando detecta que el ingest terminó (event_count > 0 y process ya no existe), disparar sync_media:
```python
@app.get("/api/projects/{project_id}/status")
def project_status(project_id: str):
    ...
    if status == "ingesting" and cnt > 0:
        # Check if any media registered yet
        media_cnt = q("SELECT COUNT(*) n FROM media_registry WHERE participant_id IN "
                      "(SELECT DISTINCT participant_id FROM events WHERE project_id=?)",
                      (project_id,))[0]['n']
        if media_cnt == 0:
            # Trigger media sync
            _sync_media_background(project_id, row)
        ...
```

O más simple: en el subprocess de ingest agregar una llamada HTTP de callback al terminar, o usar `import_manager.py` completo en lugar de `ingest_v2.py` directamente.

---

### BUG-5: `ingest_project` y `upload_project` usan `"python3"` hardcodeado

**Síntoma:** En entornos virtuales (venv), el ingest falla porque `python3` no apunta al intérprete correcto.

**Fix** (dos lugares en `api/main.py`):
```python
import sys
# Cambiar en ingest_project y upload_project:
cmd = [sys.executable, ingest_script, ...]   # en lugar de ["python3", ...]
```

---

### BUG-6: `cast_list` expone rutas absolutas del filesystem

**Síntoma:** `GET /api/media/cast_list` devuelve `"source_file": "/mnt/c/SANN_data/P003/user2003/..."` — leak de path del servidor.

**Fix en `api/main.py` (`media_cast_list`):**
```python
result.append({
    "media_id": r["media_id"],
    "filename": Path(r["source_file"]).name,
    # "source_file": r["source_file"],  ← ELIMINAR esta línea
    "start_timestamp": r["start_timestamp"],
    "start_unix": r["start_unix"],
    "duration_seconds": r["duration_seconds"],
})
```

---

### BUG-7: Video loading overlay se queda pegada si ffmpeg falla

**Síntoma:** Si el archivo de video no existe o ffmpeg falla, el overlay "TRANSCODING FOR BROWSER COMPATIBILITY…" nunca desaparece.

**Fix en `_reloadVideoStream` (`palantir.html`):**
```javascript
function _reloadVideoStream(pid, tOffset) {
  ...
  vid.onerror = () => {
    loading.style.display = 'none';
    vid.style.display = 'none';
    vid.onerror = null; vid.oncanplay = null;
    showToast('Video stream error — check ffmpeg is installed', 'error');
  };
  // Timeout de seguridad: si en 30s no hay canplay, mostrar error
  if (window._vidLoadTimeout) clearTimeout(window._vidLoadTimeout);
  window._vidLoadTimeout = setTimeout(() => {
    if (loading.style.display !== 'none') {
      loading.style.display = 'none';
      vid.style.display = 'none';
      showToast('Video taking too long — is ffmpeg installed?', 'warning');
    }
  }, 30000);
}
```

---

## BUGS IMPORTANTES — degradan la UX

### BUG-8: Cast player `getCurrentTime()` puede no existir en asciinema-player v3

**Síntoma:** El ticker en modo cast hace `S.castPlayer.getCurrentTime()` pero asciinema-player v3 expone `currentTime` como propiedad, no método.

**Fix en `palantir.html` (master ticker):**
```javascript
} else if (S.mediaMode === 'cast' && S.castPlayer && S.casts[S.activeCastIdx]) {
  try {
    // v3 puede usar propiedad o método según versión
    const castT = typeof S.castPlayer.getCurrentTime === 'function'
      ? S.castPlayer.getCurrentTime()
      : (S.castPlayer.currentTime ?? 0);
    const castStart = isoToEpoch(S.casts[S.activeCastIdx].start_timestamp);
    S.cursorEpoch = castStart + castT;
  } catch(e) { S.cursorEpoch += 0.25; }
}
```

---

### BUG-9: Panel PCAP muestra 127k sensor_packets de user3017 (payload masivo)

**Síntoma:** Para user3017, el panel PCAP tiene 127,321 eventos `sensor_packet` — en la ventana de ±120s hay cientos. Se renderiza basura.

**Causa:** `sensor_packet` es muy ruidoso (cada paquete TCP/UDP individual). El panel debería mostrar flujos agregados, no paquetes.

**Fix en `fetchAllPanels`:** Para `pcap`, filtrar solo eventos que tengan información de red útil, y preferir zeek/suricata sobre sensor_packet crudo:
```javascript
{ key: 'pcap', types: 'zeek,sensor', limit: 200 },
// En renderPcap: filtrar sensor_packet que no sean IDS alerts ni HTTP
const vis = events.filter(e => 
  e.source_type !== 'sensor' ||  // zeek siempre pasa
  e.action_name === 'http_traffic' ||
  e.action_name === 'ids_alert' ||
  (e.src_ip && e.dest_ip)
).slice(-_PANEL_MAX);
```

---

### BUG-10: `project_status` — race condition al marcar como "ready"

**Síntoma:** El polling del modal ZIP marca el proyecto como "ready" en cuanto hay un solo evento, aunque el ingest sigue corriendo (segundos/minutos más tarde).

**Fix correcto:** Que `ingest_v2.py` actualice `status='ready'` al terminar:
```python
# Al final de __main__ en ingest_v2.py, si hay main_db y project_id:
if args.project_id and args.main_db:
    try:
        mcon = sqlite3.connect(str(args.main_db))
        mcon.execute("UPDATE projects SET status='ready', event_count=?, updated_at=? WHERE project_id=?",
                     (total_events, datetime.now(timezone.utc).isoformat(), args.project_id))
        mcon.commit(); mcon.close()
    except Exception: pass
```

Eliminar el auto-mark en `project_status` y confiar en que ingest lo marca al final.

---

### BUG-11: Cast duplicado — `loadCast` y `renderMediaMode` pueden crear dos players

**Síntoma:** Si se llama `renderMediaMode()` mientras ya hay un `castPlayer`, el check `if (!S.castPlayer)` lo previene, pero `loadCast` siempre crea uno nuevo. Si se llama dos veces seguido (ej. al cambiar el selector de cast), quedan nodos huérfanos en el DOM.

**Fix en `loadCast`:** Ya existe `S.castPlayer.dispose()` pero `wrap.innerHTML = ''` necesita ir DESPUÉS del dispose:
```javascript
function loadCast(idx) {
  const cast = S.casts[idx];
  if (!cast) return;
  if (S.castPlayer) {
    try { S.castPlayer.dispose(); } catch(e) {}
    S.castPlayer = null;
  }
  const wrap = document.getElementById('cast-wrap');
  wrap.innerHTML = '';  // limpiar DESPUÉS de dispose
  ...
}
```

---

### BUG-12: `onseeked` y `ontimeupdate` se acumulan en `loadVideo`

**Síntoma:** Cada vez que se llama `loadVideo` (al cambiar participante o proyecto), se añade un nuevo `onseeked` y `ontimeupdate` al elemento `<video>`, creando múltiples handlers activos.

**Fix:** Usar `vid.removeEventListener` o limpiar antes de asignar. Como se usa asignación directa (`vid.onseeked = ...`) ya reemplaza el anterior — esto es correcto con `=`. Sin embargo, si en algún lugar se usa `addEventListener` también, habría duplicados. Verificar que solo se usen asignaciones directas `=`, no `addEventListener`, para estos handlers.

---

### BUG-13: Fase ribbon — badges viejos quedan activos al navegar a zona sin eventos

**Síntoma:** Si el cursor va a una zona sin eventos en el heatmap, el badge activo de la fase anterior permanece encendido.

**Fix en `updatePhaseBadge`:**
```javascript
function updatePhaseBadge() {
  // Si no hay datos, apagar todo
  if (!S.heatBuckets.length) {
    document.querySelectorAll('.phase-badge').forEach(b => b.classList.remove('active'));
    return;
  }
  ...
  const bucket = S.heatBuckets[idx];
  // Si bucket sin eventos, apagar todo
  if (!bucket || bucket.total === 0) {
    document.querySelectorAll('.phase-badge').forEach(b => b.classList.remove('active'));
    document.getElementById('current-phase-text').textContent = '';
    return;
  }
  ...
}
```

---

### BUG-14: `import_manager.py` no cubre proyectos creados por ZIP

**Síntoma:** Al subir un ZIP, solo se ejecuta `ingest_v2.py`. No se aplican: corrección de años en syslog/auth, corrección de timezone en suricata, deduplicación de `.orig`, sincronización de media, ni validación de ventana.

**Fix:** Crear una función `run_full_pipeline(project_id, data_root, db_path, attacker_ips)` en `import_manager.py` que aplique todos los pasos. Llamarla desde el endpoint de upload en lugar de solo `ingest_v2.py`:

```python
# import_manager.py — nueva función exportable
def run_full_pipeline(project_id: str, data_root: str, db_path: str,
                      attacker_ips: str = '', main_db: str = ''):
    """Ingest + all post-processing steps for any project."""
    db = Path(db_path)
    root = Path(data_root)
    main = Path(main_db) if main_db else None

    # 1. Ingest
    run_ingest(root, db, project_id=project_id, main_db=main, attacker_ips=attacker_ips)

    # 2. Open connections
    con = sqlite3.connect(str(db))
    main_con = sqlite3.connect(str(main)) if main and main.exists() else None

    # 3. Fix suricata timestamps
    fix_suricata_timestamps(con)
    if main_con: fix_suricata_timestamps(main_con, project_id=project_id)

    # 4. Fix syslog year
    fix_syslog_year(con)

    # 5. Dedup .orig
    dedupe_orig_participants(con)
    if main_con: dedupe_orig_participants(main_con)

    # 6. Taxonomy fix
    fix_recon_taxonomy(con)
    if main_con: fix_recon_taxonomy(main_con)

    # 7. Mark ready
    if main_con:
        main_con.execute("UPDATE projects SET status='ready' WHERE project_id=?", (project_id,))
        main_con.commit()

    con.close()
    if main_con: main_con.close()
```

En `api/main.py`, el subprocess del upload debe llamar `import_manager.py run_pipeline ...` en lugar de `ingest_v2.py` directamente.

---

## PIPELINE DE DATOS — fix definitivo para suricata en producción

El fix de BUG-1 necesita aplicarse también al **parser de `bt_jsonl`** y verificar si otros parsers tienen el mismo problema:

| Parser | Formato timestamp | ¿Tiene TZ? | ¿Necesita fix? |
|---|---|---|---|
| `parse_suricata_eve` | ISO con offset (`-0400`) | Sí | **SÍ — BUG-1** |
| `parse_bt_jsonl` | ISO sin TZ (naive) | No | UTC asumido — OK si el host usa UTC |
| `parse_sensor_log` | Unix epoch float | No | `datetime.fromtimestamp(t, tz=UTC)` — ya correcto |
| `parse_zeek_conn` | Unix epoch float | No | OK |
| `parse_cast_file` | Unix epoch float (relativo) | No | OK |
| `parse_uat_log` | ISO con ms, sin TZ | No | UTC asumido — verificar |
| `parse_syslog` | `Month DD HH:MM:SS` sin año/TZ | No | Año inferido de cast — riesgo |

---

## VERIFICACIÓN COMPLETA — checklist para el equipo

### Datos
```bash
# 1. Aplicar fix de suricata (BUG-1) — ejecutar script de corrección en DB existente
python3 fix_suricata_timestamps.py   # script a crear con el código de BUG-1

# 2. Poblar project_id en media_registry (BUG-3)
python3 -c "
import sqlite3
con = sqlite3.connect('data/godeye_v2.db')
con.execute(\"UPDATE media_registry SET project_id='da2c86c9' WHERE participant_id IN ('user2003','user4002','user0003')\")
con.execute(\"UPDATE media_registry SET project_id='9c4cee20' WHERE participant_id IN ('user0032','user2016','user3017')\")
con.commit(); con.close(); print('done')
"

# 3. Verificar que suricata ahora solapa con la ventana de video
python3 -c "
import sqlite3
con = sqlite3.connect('data/godeye_v2.db')
for pid, t0, t1 in [('user2003','2025-08-15T19:07:17','2025-08-15T19:39:53'),
                     ('user2016','2025-07-26T17:56:52','2025-07-26T19:51:26')]:
    r = con.execute('SELECT COUNT(*) n FROM events WHERE participant_id=? AND source_type=\"suricata\" AND timestamp_utc>=? AND timestamp_utc<=?', (pid,t0,t1)).fetchone()
    print(f'{pid}: {r[0]} suricata events in video window')
con.close()
"
# Esperado: user2003 >0, user2016 >0
```

### API
```bash
# Iniciar servidor
python3 -m uvicorn api.main:app --host 0.0.0.0 --port 8000

# Health
curl -s http://localhost:8000/api/health
# Esperado: {"status":"healthy","total_events":456239}

# Suricata en ventana de user2003 (debe devolver eventos ahora)
curl -s "http://localhost:8000/api/events/stream?participant_id=user2003&source_type=suricata&from_ts=2025-08-15T19:07:17&to_ts=2025-08-15T19:39:53&project_id=da2c86c9" | python3 -c "import json,sys; d=json.load(sys.stdin); print('suricata in window:', d['count'])"

# Media list sin path leak
curl -s "http://localhost:8000/api/media/cast_list?participant_id=user2003" | python3 -c "import json,sys; d=json.load(sys.stdin); [print(c.keys()) for c in d['casts'][:1]]"
# NO debe aparecer 'source_file' en las keys

# Upload ZIP
curl -X POST http://localhost:8000/api/projects/upload \
  -F "name=TestProject" \
  -F "file=@/ruta/a/dataset.zip" \
  -F "attacker_ips=10.0.0.1"
# Esperado: {"project_id":"...","status":"ingesting"}

# Polling de estado
curl -s "http://localhost:8000/api/projects/<project_id>/status"
# Esperado: status pasa de "ingesting" a "ready" cuando ingest termina

# Media lista después de ZIP
curl -s "http://localhost:8000/api/media/list?participant_id=<pid>&project_id=<project_id>"
# Esperado: video y casts si el ZIP los contenía
```

### UI
Abrir `http://localhost:8000/threat` y verificar:
1. **Project switch**: cambiar P003 ↔ P032 — panels se limpian, video se detiene, lista de participantes cambia
2. **user2003 → Network panel**: debe mostrar suricata + bt_jsonl dentro de la ventana de video (verificar con ±120s)
3. **user4002 → PCAP panel**: debe mostrar flujos con IPs (zeek tiene datos correctos, sensor_packet filtrado)
4. **Keylogger panel**: mostrar texto escrito con timestamps clicables → cursor se mueve
5. **Cast sync**: reproducir video, hacer click en "TERMINAL CAST" → cast debe saltar al mismo segundo
6. **Video seek manual**: hacer seek con la barra nativa del `<video>` → cursor del scrubber debe moverse
7. **ZIP upload**: botón "⊕ ZIP" → subir zip → modal muestra progreso → proyecto aparece en selector
8. **ffmpeg ausente**: si ffmpeg no está instalado, el overlay de video debe mostrar error (no quedarse pegado)
9. **Phase ribbon**: 14 tactics se iluminan correctamente al navegar el scrubber
10. **Badges de paneles**: muestran "X of Y (last 200)" cuando hay más de 200 eventos en ventana

---

## Archivos a modificar

| Archivo | Bugs que arregla |
|---|---|
| `ingest_v2.py` | BUG-1 (parser suricata), BUG-2 (sensor IPs), BUG-5 (sys.executable), BUG-10 (mark ready) |
| `import_manager.py` | BUG-1 (fix existente en DB), BUG-14 (pipeline completo para ZIP) |
| `api/main.py` | BUG-3 (media project_id filter), BUG-4 (sync_media post-upload), BUG-5 (sys.executable), BUG-6 (cast_list path leak) |
| `frontend/palantir.html` | BUG-7 (overlay timeout/onerror), BUG-8 (getCurrentTime), BUG-9 (pcap filter), BUG-11 (cast dispose), BUG-13 (phase badge reset) |

---

## Notas de arquitectura

- `media_registry` solo existe en `godeye_v2.db` (main DB) — nunca en project DBs
- `qp(project_id, sql, params)` enruta a project DB cuando `project_id != ''`, a main DB si `project_id == ''`
- Video se sirve via `ffmpeg` on-the-fly VP8/WebM (Theora no soportado en Chrome/Edge)
- El `?t=` en `/api/media/video/{pid}?t=30` hace seek via `-ss` de ffmpeg (no seek nativo)
- Timestamps en DB son UTC naive ISO sin `Z` ni offset — comparaciones de string funcionan porque están ordenadas lexicográficamente
