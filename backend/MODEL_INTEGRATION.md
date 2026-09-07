# RakshaNetra — Real Model Integration

This adds your two trained models into the existing RakshaNetra backend
scaffold, alongside (not replacing) the mock data in `app/data.py`.

## What's wired in

| Threat category | Model file | Trained on | Status |
|---|---|---|---|
| DDoS & Volumetric | `app/models/cic_binary_xgb.joblib` | CIC-IDS (69 flow features) | ✅ Live |
| Botnet C2 Beaconing | `app/models/ctu13_botnet_xgboost.joblib` | CTU-13 (9 flow features) | ✅ Live |
| DGA & DNS Tunnelling | — | — | ⬜ Not yet trained |
| TLS/QUIC Encrypted Malware | — | metadata rules | ✅ Active (rule-based, no decryption) |
| Reconnaissance / Port Scan | `app/models/recon_xgb.joblib` | UNSW-NB15 | ✅ Live ML + streaming fan-out state |
| Data Exfiltration | — | metadata rules | ✅ Active (rule-based) |

## New files added

```
backend/
├── app/
│   ├── models/                          ← trained model artifacts (data, not code)
│   │   ├── cic_binary_xgb.joblib
│   │   ├── cic_binary_features.json
│   │   ├── ctu13_botnet_xgboost.joblib
│   │   └── ctu13_botnet_features.json
│   ├── ml/
│   │   ├── __init__.py
│   │   ├── model_loader.py              ← loads both models once at startup
│   │   └── inference.py                 ← scores a flow dict, returns alert objects
│   └── routes/
│       └── inference.py                 ← NEW blueprint: /api/inference/*
```

## New endpoints

- `GET /api/inference/models` — confirms which models are currently loaded
- `POST /api/inference/score` — send a flow dict, get back any alerts fired, in the
  same shape as `app/data.py`'s `ALERTS` (so the frontend needs no changes to consume it)

### Example request

```bash
curl -X POST http://localhost:5000/api/inference/score \
  -H "Content-Type: application/json" \
  -d '{
    "flow_id": "FL-TEST-001",
    "src_ip": "192.168.1.50",
    "dst_ip": "10.0.0.9",
    "Protocol": 6,
    "Flow Duration": 500000,
    "Total Fwd Packets": 1200,
    "SYN Flag Count": 980,
    "dur": 2.3,
    "proto": "tcp",
    "dir": "->",
    "state": "S0",
    "stos": 0,
    "dtos": 0,
    "tot_pkts": 12,
    "tot_bytes": 900,
    "src_bytes": 450
  }'
```

A single flow dict can carry both feature sets — the DDoS model only reads its
69 CIC-style keys, the botnet model only reads its 9 CTU-13-style keys.
Missing keys default to 0, so partial flows won't crash the endpoint (but
will likely under-score — feed real feature values for accurate results).

## How this fits the read-only pipeline

`inference.py` is a pure function: flow dict in, alert dict (or `None`) out.
It performs no network I/O of its own — plug it into your `replay.py`
SSE loop (or wherever your real ingest pipeline assembles flow records)
by calling `score_flow_all(flow)` per flow and pushing any resulting
alerts into storage/SSE instead of (or alongside) the mock generator.

## Optional future trained models

TLS/QUIC and exfiltration are currently implemented as transparent, passive rule-based detectors rather than falsely labelled trained models. They can later be replaced or augmented with trained classifiers without changing the ingest or alert schema.

1. Drop the trained `.joblib`/`.pt` file and its features JSON into `app/models/`
2. Add one `_load_one(...)` line in `model_loader.py`
3. Add one `score_<name>(flow)` function in `inference.py` following the same
   pattern as `score_ddos`/`score_botnet_c2`
4. Add it to the loop in `score_flow_all()`

No other files need to change — `inference.py` and `app/routes/inference.py`
are additive, so `app/data.py`'s mock endpoints keep working as a fallback
throughout your migration.

## Note on the botnet model

`ctu13_botnet_xgboost.joblib` is a full `sklearn.Pipeline` — it does its own
categorical encoding for `proto`/`dir`/`state` internally. Pass raw string
values for those fields (e.g. `"proto": "tcp"`), not pre-encoded numbers.

## Live alert wiring (`app/store.py`)

Previously the replay engine (`app/routes/replay.py` -> `generate_packet()`
in `app/generators.py`) already called the real scorers for
`syn_flood_ddos` / `mirai_c2` / `apt29_dns_tunneling`, but only used the
resulting alert to build one packet-log line, then discarded it — the
Alert Investigation console (`/api/alerts`) and dashboard KPIs
(`/api/dashboard/*`) still only ever read `app/data.py`'s frozen mock
seed. `app/store.py` is the fix: a shared, thread-safe `LIVE_ALERTS` list
seeded from the mock alerts, appended to via `store.record_alert()`
whenever `score_ddos` / `score_botnet_c2` / `score_dga_dns` /
`score_flow_all` fires — from replay sessions *and* from direct
`POST /api/inference/score` calls. `app/routes/alerts.py` now reads from
`store.get_alerts()` instead of the static `ALERTS` import, and
`dashboard.py`'s `threatsDetected` KPI adds `store.real_alert_count()` on
top of the mock baseline instead of drifting on a pure random walk.

## Known issue: `cic_binary_xgb` (DDoS) rarely fires on synthetic flows

`app/ml/flow_synthesizer.py`'s `synthesize_ddos_flow()` originally only
populated 6 of the 69 features `cic_binary_xgb` expects — the other 63
silently defaulted to 0, which the model reliably read as benign. That's
now fixed: all 69 CIC-IDS2018 fields are populated with internally
consistent SYN-flood-vs-benign values (packet count, size, IAT, flag
ratios).

Even with full feature coverage, this specific trained model still has a
**narrow decision boundary** — most conceptually "attack-like" synthetic
vectors (tiny packets, huge SYN counts, 1.4M pps scale) still score as
benign. A hill-climbing search over the 69-dim input space confirms the
model *can* reach >99.9% attack confidence, so it is not broken or
label-inverted — it's just an XGBoost model that learned narrow,
correlated feature interactions from real CIC-IDS2018 rows that
independently-sampled synthetic values rarely reproduce. `mirai_c2` and
`apt29_dns_tunneling` fire at a modest but real rate under the same
synthetic approach; `syn_flood_ddos` essentially never does.

**Fix**: follow `app/ml/sample_flows.py`'s own instructions — export ~30-50
real attack/benign rows per class from the actual CIC-IDS2018 training
CSV into `app/models/sample_flows/sample_ddos_attack.json` /
`sample_ddos_normal.json`. `sample_flows.py` already prefers real sampled
rows over the synthesizer the moment those files exist, no other code
changes needed.
