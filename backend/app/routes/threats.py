"""
app/routes/threats.py
======================
Feeds ThreatCategories.jsx. The 6 category descriptions (what the vector
is, which signal features the model looks at) are genuinely static
metadata about the detector, not "live" data, and stay hardcoded here.
What used to be FAKE was: count24h (a fixed made-up number) and
sampleAlert (a fabricated string), both presented as if they were live.

Those two fields are now computed from app.ml.alert_store's real,
model-fired alerts: count is the real count since startup, and
sampleAlert is the most recent real alert's own evidence string (or
null if that model hasn't fired yet — the frontend should say so rather
than show an invented example). `status` reports whether a trained
model actually backs the category, from app.ml.model_loader.
"""

from flask import Blueprint, jsonify

from app.ml import alert_store
from app.ml.model_loader import loaded_model_names

threats_bp = Blueprint("threats", __name__)

# Static descriptive metadata (not "data" in the fake-numbers sense —
# this is genuinely fixed copy about what each detector looks for).
_CATEGORY_DEFS = [
    {
        "id": "ddos",
        "threatClass": "DDoS & Volumetric",
        "name": "DDoS & Volumetric Floods",
        "shortDesc": "Passive flow rate delta & SYN amplification anomaly detection.",
        "modelKey": "ddos",
        "modelFile": "cic_binary_xgb",
        "features": ["Packet-per-second Burst Index", "TCP SYN-to-ACK Ratio", "Flow Micro-burst Spikes"],
        "fullDesc": "Detects distributed denial-of-service vectors including SYN floods, UDP amplification, and NTP reflection by continuously evaluating volumetric flow rate deltas and packet size entropy on the one-way tap interface.",
    },
    {
        "id": "botnet",
        "threatClass": "Botnet C2 Beaconing",
        "name": "Botnet C2 Beaconing",
        "shortDesc": "Periodic heartbeat clustering & inter-arrival jitter scoring.",
        "modelKey": "botnet_c2",
        "modelFile": "ctu13_botnet_xgboost",
        "features": ["Inter-Arrival Time (IAT) Jitter", "Packet Length Sequence Homogeneity", "Flow Duration Pattern"],
        "fullDesc": "Identifies command-and-control (C2) heartbeat beaconing channels hidden inside encrypted streams using inter-arrival time clustering and flow-duration patterns without decrypting payloads.",
    },
    {
        "id": "dga_dns",
        "threatClass": "DGA & DNS Tunnelling",
        "name": "DGA & DNS Tunnelling",
        "shortDesc": "High-entropy domain name generation & covert TXT exfiltration.",
        "modelKey": "dga_dns",
        "modelFile": "doh_tunneling_xgb",
        "features": ["Flow Bytes Sent/Received Ratio", "Packet Length Distribution", "Query-to-Response Timing"],
        "fullDesc": "Analyzes passive DNS-over-HTTPS flow structures to detect algorithmically generated domains (DGA) and covert data exfiltration over DNS/DoH tunnels.",
    },
    {
        "id": "tls_quic",
        "threatClass": "TLS / QUIC Encrypted Malware",
        "name": "TLS / QUIC Encrypted Malware",
        "shortDesc": "Encrypted payload anomaly scoring without SSL/TLS decryption.",
        "modelKey": "encrypted_tls",
        "modelFile": None,
        "detectorType": "rule_based",
        "features": ["JA3 / JA4 Fingerprint Anomaly", "TLS Client Hello Cipher Suite Entropy", "Payload Packet Length Markov Chain"],
        "fullDesc": "Planned: will inspect encrypted transport handshakes and TLS/QUIC metadata to flag malware communication without decrypting streams. No trained model or dataset is wired up yet.",
    },
    {
        "id": "recon",
        "threatClass": "Reconnaissance & Scan",
        "name": "Reconnaissance & Port Scanning",
        "shortDesc": "Stealth SYN/FIN scan & horizontal IP sweep detection.",
        "modelKey": "port_scan",
        "modelFile": "recon_xgb",
        "features": ["Target IP Fan-Out Degree", "Unanswered TCP Probe Ratio", "Horizontal Port Variance"],
        "fullDesc": "Detects stealthy network mapping, vertical port scans, and horizontal IP sweeps using UNSW-NB15-trained flow features tracking connection attempt fan-out across monitored subnets.",
    },
    {
        "id": "exfil",
        "threatClass": "Data Exfiltration",
        "name": "Data Exfiltration",
        "shortDesc": "Outbound flow volume spikes & covert timing channel alerts.",
        "modelKey": "exfiltration",
        "modelFile": None,
        "detectorType": "rule_based",
        "features": ["Cumulative Volume Ratio Spike", "Flow Duration Anomalies", "Covert Inter-Packet Gap Encoding"],
        "fullDesc": "Planned: will identify unauthorized data transfer by monitoring cumulative outbound flow ratios and covert timing channels. No trained model or dataset is wired up yet.",
    },
]


def _build_category(cat, loaded, alerts):
    matching = [a for a in alerts if a.get("threatClass") == cat["threatClass"]]
    rule_based = cat.get("detectorType") == "rule_based"
    is_active = cat["modelKey"] in loaded or rule_based
    return {
        **{k: v for k, v in cat.items() if k not in ("modelKey",)},
        "status": "active_rule_based" if rule_based else ("active" if is_active else "pending_training"),
        "count": len(matching),
        "sampleAlert": matching[0]["evidence"] if matching else None,
        "sampleSeverity": matching[0]["severity"] if matching else None,
    }


@threats_bp.get("/categories")
def get_categories():
    loaded = set(loaded_model_names())
    alerts = alert_store.real_alerts()
    out = [_build_category(cat, loaded, alerts) for cat in _CATEGORY_DEFS]
    return jsonify({
        "categories": out,
        "modelsActive": len(loaded),
        "modelsTotal": len(_CATEGORY_DEFS),
    })


@threats_bp.get("/categories/<category_id>")
def get_category(category_id):
    cat = next((c for c in _CATEGORY_DEFS if c["id"] == category_id), None)
    if cat is None:
        return jsonify({"error": "unknown category"}), 404
    loaded = set(loaded_model_names())
    alerts = alert_store.real_alerts()
    return jsonify(_build_category(cat, loaded, alerts))
