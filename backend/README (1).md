# SPECTRA Backend

Flask backend for the SPECTRA one-way (air-gapped) network threat monitoring
dashboard. It replaces every hardcoded array and `Math.random()` simulation
in the React frontend (`Unidirectional-Network-Monitoring-main`) with real
API responses.

## Run it

```bash
cd backend
python3 -m venv venv && source venv/bin/activate   # optional but recommended
pip install -r requirements.txt
python run.py
```

Server runs on `http://localhost:5000`. CORS is wide open (`*`) for local
dev — restrict `resources={r"/api/*": {"origins": ...}}` in `app/__init__.py`
before deploying.

## Endpoints

| Component | Endpoint | Notes |
|---|---|---|
| `HeroSection.jsx` KPI cards | `GET /api/dashboard/stats` | one-shot poll |
| " (live ticker) | `GET /api/dashboard/stream` | SSE, ticks every 1.5s |
| `ThreatCategories.jsx` | `GET /api/threats/categories` | the 6 detection vectors |
| " | `GET /api/threats/categories/<id>` | single category |
| `AIAnalytics.jsx` SHAP panel | `GET /api/analytics/features` | |
| " trend chart | `GET /api/analytics/trends?range=1h\|24h\|7d` | |
| " KPI cards | `GET /api/analytics/performance` | accuracy / FPR / latency |
| `NetworkVisualization.jsx` | `GET /api/network/topology?filter=all\|suspicious\|safe` | nodes + edges |
| `AlertInvestigation.jsx` table | `GET /api/alerts?severity=&vector=&min_confidence=` | all params optional |
| " drawer | `GET /api/alerts/<id>` | full rawJson payload |
| `TrafficReplay.jsx` selector | `GET /api/replay/pcaps` | |
| " start | `POST /api/replay/sessions` `{"pcap_id": "..."}` | returns `session_id` |
| " controls | `POST /api/replay/sessions/<id>/control` `{"action": "play\|pause\|restart", "speed": 1\|2\|5\|10}` | |
| " live feed | `GET /api/replay/sessions/<id>/stream` | SSE, one packet event per tick while playing |

Full JSON shapes match the objects the components already expect — field
names were kept identical (`badgeClass`, `shapFeature`, `rawJson`, etc.) so
swapping the hardcoded arrays for `fetch()` calls is a drop-in change.

## Wiring the frontend

A ready-to-use client is included at `frontend-integration/api.js` — copy it
into `src/api.js` in the React project and point `API_BASE` at your backend.
It wraps every endpoint above, including small `EventSource` helpers for the
two SSE streams (`streamDashboardStats`, `streamReplaySession`).

Example swap in `AIAnalytics.jsx`:

```jsx
// before
const features = [ /* hardcoded array */ ];

// after
const [features, setFeatures] = useState([]);
useEffect(() => { getShapFeatures().then(setFeatures); }, []);
```

`TrafficReplay.jsx`'s play/pause/restart/speed buttons map directly onto
`startReplaySession`, `controlReplaySession`, and `streamReplaySession` —
the component's local `logs`/`progress`/`packetsProcessed` state just gets
set from the SSE payload instead of a local packet generator.

## Notes

- All data currently lives in-memory (`app/data.py`) — no database. Swap in
  SQLAlchemy/Postgres if alerts need to persist or grow beyond the 6 seed
  records.
- Replay sessions are stored in a process-local dict — fine for a single
  Flask worker (the dev server or `flask run`), but won't be shared across
  multiple gunicorn workers. Move to Redis if you need multi-worker replay.
- No authentication is implemented — add it before exposing this beyond a
  local demo.


## SIH remaining requirements now implemented

- **Passive streaming ingest:** `POST /api/ingest/flow` accepts one flow/metadata record at a time. It performs no outbound network access, active probing, mitigation, or payload decryption.
- **TLS/QUIC encrypted-malware metadata detector:** `app/ml/stream_detectors.py` evaluates JA3/JA4-style fingerprints, TLS/QUIC metadata, SNI/ALPN, packet-size statistics and timing. It is explicitly `rule_based`, not a fabricated trained model.
- **Streaming reconnaissance:** a bounded 60-second per-source state tracks unique destination hosts/ports and unanswered probe ratios.
- **Streaming exfiltration:** a bounded 5-minute per-source state tracks outbound/inbound volume ratio, destination concentration and outbound rate.
- **Standard alert schema:** every new alert includes `timestamp_iso`, `flow_id`, `threat_class`, `severity`, `confidence_score` (0..1), and `supporting_evidence`, while legacy UI keys remain for compatibility.
- **Benchmarking:** `POST /api/benchmark/run` with a JSON `flows` array reports flows/sec, mean detection latency and model inference latency; `GET /api/benchmark/stats` reports process-local ingest throughput.

### Benchmark example

```json
POST /api/benchmark/run
{
  "flows": [
    {"flow_id":"F-1","src_ip":"10.0.0.1","dst_ip":"10.0.0.2","protocol":"TCP","dst_port":443},
    {"flow_id":"F-2","src_ip":"10.0.0.1","dst_ip":"10.0.0.3","protocol":"QUIC","tls_version":"TLS1.3","alpn":"h3","ja4":"q13d4-example"}
  ]
}
```

For the SIH demonstration, record the benchmark output together with the number of input flows, hardware/CPU, Python/package versions, and the selected replay speed. The project does not claim a fixed throughput target because the problem statement supplied to this project does not specify a numeric target.
