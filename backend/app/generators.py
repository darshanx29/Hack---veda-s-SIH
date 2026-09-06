"""
Server-side generators that replace the client-side `Math.random()` /
`setInterval` simulation logic that used to live in HeroSection.jsx and
TrafficReplay.jsx.

generate_packet() drives 3 of the 4 replay PCAPs through the REAL
trained models (ddos, botnet_c2, dga_dns): each tick builds an
internally-consistent synthetic flow (see app/ml/synthetic_flows.py)
and scores it with the actual model. isThreat, threatLabel/alertText,
and confidence are now ALL taken from the model's own ScoreResult —
including the "CLEAN PASS" case, which previously substituted a fake
`random.uniform(1, 8)` confidence instead of the model's real
sub-threshold probability. Real fires are also pushed into
app/ml/alert_store so they show up in /api/alerts and the dashboard's
threatsDetected count.

quic_exfil has no trained model yet (encrypted_tls / exfiltration are
still unwired — see app/ml/model_loader.py), so it stays on the
original random simulation until a model exists for it. That's the
ONLY place in this file that still fabricates a threat verdict.

next_dashboard_stats() is now backed by real signals wherever one
exists: threatsDetected (real, from alert_store), aiConfidence (real
rolling average of every actual confidence value scored by the 3 real
models, threat or not), and latency (real average model inference
wall-clock time, from app.ml.perf_stats). Only flowsPerSec has no real
per-second network throughput to measure (no live capture in this
project) and stays a labeled synthetic rate.
"""
import random
import string
import threading
import time
from collections import deque
from datetime import datetime, timezone

from app.data import BASE_DASHBOARD_STATS, PCAPS
from app.ml import alert_store, perf_stats
from app.ml.inference import score_ddos, score_botnet_c2, score_dga_dns, score_recon, score_flow_all
from app.ml.model_loader import loaded_model_names
from app.ml.synthetic_flows import ddos_flow, botnet_flow, dga_dns_flow, recon_flow

# --------------------------------------------------------------------------
# Real rolling confidence window, fed by every real model score (threat or
# clean) from generate_packet() below. Backs the dashboard's aiConfidence.
# --------------------------------------------------------------------------
_confidence_lock = threading.Lock()
_recent_confidences = deque(maxlen=200)


def _record_confidence(value: float):
    with _confidence_lock:
        _recent_confidences.append(value)


def _average_confidence():
    with _confidence_lock:
        if not _recent_confidences:
            return None
        return round(sum(_recent_confidences) / len(_recent_confidences), 2)


# --------------------------------------------------------------------------
# Real flow throughput counter, incremented once per actual generate_packet()
# call (i.e. once per real packet the replay engine has actually processed —
# whether or not a trained model exists for that pcap). Backs flowsPerSec
# with a genuinely measured rate instead of a random walk that used to keep
# drifting even with zero real replay traffic running.
# --------------------------------------------------------------------------
_throughput_lock = threading.Lock()
_total_flows_processed = 0
_last_flow_count = 0
_last_flow_time = time.monotonic()


def _record_flow_processed():
    global _total_flows_processed
    with _throughput_lock:
        _total_flows_processed += 1


def _measured_flows_per_sec():
    global _last_flow_count, _last_flow_time
    with _throughput_lock:
        now = time.monotonic()
        elapsed = max(now - _last_flow_time, 0.001)
        rate = (_total_flows_processed - _last_flow_count) / elapsed
        _last_flow_count = _total_flows_processed
        _last_flow_time = now
        return round(rate, 1)


# --------------------------------------------------------------------------
# Dashboard hero stats (HeroSection.jsx ticker)
# --------------------------------------------------------------------------
_stats_state = dict(BASE_DASHBOARD_STATS)
_base_threats_detected = BASE_DASHBOARD_STATS["threatsDetected"]


def next_dashboard_stats():
    """threatsDetected: real (alert_store). aiConfidence: real rolling average
    of actual model confidences. latency: real average inference wall-clock
    time (perf_stats) — falls back to 0 only if no inference has run yet.
    flowsPerSec: real measured rate of packets actually processed by the
    replay engine since the last tick — reads 0 when no replay is running,
    rather than drifting via a random walk."""
    _stats_state["flowsPerSec"] = _measured_flows_per_sec()
    _stats_state["threatsDetected"] = _base_threats_detected + alert_store.real_alert_count()

    real_confidence = _average_confidence()
    _stats_state["aiConfidence"] = real_confidence if real_confidence is not None else 0.0

    real_latency = perf_stats.average_latency_ms()
    _stats_state["latency"] = real_latency if real_latency is not None else 0.0

    return dict(_stats_state)


# --------------------------------------------------------------------------
# PCAP replay packet stream (TrafficReplay.jsx generatePacketLog)
# --------------------------------------------------------------------------
_PROTOCOLS = ["DNS-TXT", "TLSv1.3", "TCP-SYN", "QUIC", "HTTPS"]
_SRC_IPS = ["192.168.1.104", "10.100.4.45", "172.16.8.99", "10.250.0.12"]
_DST_IPS = ["104.21.44.12", "185.220.101.5", "198.51.100.42", "8.8.8.8"]

# pcap_id -> (synthetic flow builder, real scorer, threat class label shown in the packet log)
_REAL_MODEL_PCAPS = {
    "apt29_dns_tunneling": (dga_dns_flow, score_dga_dns, "DNS TUNNEL DETECTED"),
    "mirai_c2": (botnet_flow, score_botnet_c2, "BOTNET C2 BEACON"),
    "syn_flood_ddos": (ddos_flow, score_ddos, "SYN FLOOD ANOMALY"),
}

# quic_exfil (and any unknown pcap_id) has no trained model yet -> stays mock
_MOCK_THREAT_LABELS = {
    "quic_exfil": ("COVERT QUIC EXFIL", "Encrypted payload byte length distribution skew"),
}

_ATTACK_ATTEMPT_RATE = 0.28  # how often we synthesize an attack-flavored flow to test the model against

# --------------------------------------------------------------------------
# Concurrent multi-model monitoring.
#
# Previously, replaying a given PCAP only ever exercised the ONE model tied
# to that PCAP's threat class (apt29_dns_tunneling -> dga_dns only, etc).
# The other 3 wired detectors sat idle for the whole session even though
# they're loaded and ready. `score_all_models_tick()` below runs every
# currently-loaded real model on its own independent synthetic flow on
# EVERY tick, regardless of which PCAP is selected -- i.e. all models
# monitor the (synthetic) traffic at the same time, in parallel, not one
# at a time picked by a dropdown. The per-pcap replay flavor above still
# decides what the packet log's src/dst/protocol "looks like", but the
# verdict now reflects every detector's own real predict_proba(), not just
# one of them.
# --------------------------------------------------------------------------
_ALL_MODEL_SPECS = {
    "ddos":       (ddos_flow,   score_ddos,   "ddos",      "DDoS & Volumetric"),
    "botnet_c2":  (botnet_flow, score_botnet_c2, "botnet_c2", "Botnet C2 Beaconing"),
    "dga_dns":    (dga_dns_flow, score_dga_dns, "dga_dns",   "DGA & DNS Tunnelling"),
    "recon":      (recon_flow,  score_recon,  "port_scan", "Reconnaissance & Scan"),
}


def score_all_models_tick() -> list[dict]:
    """Runs one independent synthetic flow through every currently-loaded
    model this tick and returns a result per model, e.g.:
        [{"model": "ddos", "label": "DDoS & Volumetric",
          "isThreat": False, "confidence": 3.2}, ...]
    Models with no loaded artifact are reported as unavailable rather than
    silently skipped, so the frontend can show a real "not loaded" state
    instead of just omitting the row.
    """
    loaded = set(loaded_model_names())
    results = []
    for model_key, (flow_builder, scorer, loader_name, label) in _ALL_MODEL_SPECS.items():
        if loader_name not in loaded:
            results.append({
                "model": model_key, "label": label,
                "isThreat": False, "confidence": None, "available": False,
            })
            continue

        attack_attempt = random.random() < _ATTACK_ATTEMPT_RATE
        flow = flow_builder(attack_attempt)
        flow["src_ip"] = random.choice(_SRC_IPS)
        flow["dst_ip"] = random.choice(_DST_IPS)

        try:
            result = scorer(flow)
        except Exception as exc:
            results.append({
                "model": model_key, "label": label,
                "isThreat": False, "confidence": None, "available": False,
                "error": f"{type(exc).__name__}: {exc}",
            })
            continue

        if result.alert:
            alert_store.add_alert(result.alert)

        results.append({
            "model": model_key, "label": label,
            "isThreat": bool(result.alert),
            "confidence": result.confidence,
            "available": True,
        })
    return results


def _make_packet_shell(is_threat: bool, threat_label: str, alert_text: str, confidence: float,
                        src: str, dst: str, protocol: str, length: int) -> dict:
    now = datetime.now(timezone.utc)
    return {
        "id": "".join(random.choices(string.ascii_lowercase + string.digits, k=7)),
        "time": now.strftime("%H:%M:%S.") + f"{now.microsecond // 1000:03d}",
        "src": src,
        "dst": dst,
        "protocol": protocol,
        "len": length,
        "isThreat": is_threat,
        "threatLabel": threat_label,
        "alertText": alert_text,
        "confidence": confidence,
    }


def _real_packet_metrics(pcap_id: str, flow: dict) -> tuple[str, int]:
    """Derives the packet log's protocol/length display fields from the
    SAME real flow object that was actually scored, instead of picking
    them independently at random. There's no live packet capture backing
    this demo, so these values come from the synthetic flow's own
    real numeric fields (see app/ml/synthetic_flows.py) rather than an
    unrelated random.choice()/randint()."""
    if pcap_id == "apt29_dns_tunneling":
        protocol = "DoH" if flow.get("DestinationPort") == 443 else "DNS"
        length = round(flow.get("PacketLengthMean", 72))
        return protocol, length
    if pcap_id == "mirai_c2":
        protocol = str(flow.get("proto", "tcp")).upper()
        tot_bytes = flow.get("tot_bytes", 0)
        tot_pkts = max(flow.get("tot_pkts", 1), 1)
        length = round(tot_bytes / tot_pkts) or 64
        return protocol, length
    if pcap_id == "syn_flood_ddos":
        protocol = "TCP-SYN" if flow.get("SYN Flag Count") else "TCP"
        length = round(flow.get("Packet Length Mean", 64))
        return protocol, length
    return "TCP", 64


def _merge_all_models(packet: dict, all_models: list[dict]) -> dict:
    """Folds the concurrent all-model tick into the single packet shell the
    frontend renders: `allModels` carries every detector's own live status
    for the top-of-page monitor panel, and the packet's own isThreat/
    threatLabel/confidence are widened so a fire from ANY model (not just
    the one tied to the selected PCAP) shows up in the stream, instead of
    other models' real detections being computed but thrown away."""
    fired = [m for m in all_models if m["isThreat"]]
    packet["allModels"] = all_models

    if fired:
        packet["isThreat"] = True
        other_labels = [m["label"] for m in fired if m["label"] != packet.get("threatLabel")]
        if packet.get("isThreat") and packet.get("threatLabel") not in ("CLEAN PASS", None):
            combined_labels = [packet["threatLabel"]] + other_labels
        else:
            combined_labels = [m["label"] for m in fired]
            packet["threatLabel"] = combined_labels[0]
            packet["alertText"] = f"{combined_labels[0]} model fired independently of the selected PCAP's own flow."
        packet["threatLabel"] = " + ".join(dict.fromkeys(combined_labels))
        top_confidence = max([packet.get("confidence") or 0] + [m["confidence"] for m in fired])
        packet["confidence"] = round(top_confidence, 1)

    return packet


def generate_packet(pcap_id: str) -> dict:
    _record_flow_processed()
    all_models = score_all_models_tick()

    if pcap_id in _REAL_MODEL_PCAPS:
        flow_builder, scorer, label = _REAL_MODEL_PCAPS[pcap_id]
        attack_attempt = random.random() < _ATTACK_ATTEMPT_RATE
        flow = flow_builder(attack_attempt)
        # There's no live network here to source real addresses from, so the
        # IP pair is still drawn from a fixed pool — but (unlike before) the
        # SAME pair is used for every field below and for the model's own
        # alert, instead of each display field independently re-randomizing.
        src_ip = random.choice(_SRC_IPS)
        dst_ip = random.choice(_DST_IPS)
        flow["src_ip"] = src_ip
        flow["dst_ip"] = dst_ip
        protocol, length = _real_packet_metrics(pcap_id, flow)

        result = scorer(flow)  # ScoreResult(confidence=<real predict_proba()>, alert=<real alert or None>)
        _record_confidence(result.confidence)

        if result.alert:
            alert_store.add_alert(result.alert)
            packet = _make_packet_shell(
                True, label, result.alert["evidence"], result.alert["confidence"],
                result.alert["srcIp"], result.alert["dstIp"], protocol, length,
            )
            return _merge_all_models(packet, all_models)

        # Real "clean pass" — confidence is the model's actual sub-threshold
        # probability, and src/dst/protocol/len are the same real flow's
        # fields, not independently re-randomized.
        packet = _make_packet_shell(
            False, "CLEAN PASS", "Flow entropy normal", result.confidence,
            src_ip, dst_ip, protocol, length,
        )
        return _merge_all_models(packet, all_models)

    # QUIC replay is now metadata-only and stateful: no payload/decryption is used.
    if pcap_id == "quic_exfil":
        src_ip = random.choice(_SRC_IPS); dst_ip = random.choice(_DST_IPS)
        attack_attempt = random.random() < _ATTACK_ATTEMPT_RATE
        flow = {
            "flow_id": "QUIC-" + "".join(random.choices(string.hexdigits, k=8)).upper(),
            "src_ip": src_ip, "dst_ip": dst_ip, "protocol": "QUIC",
            "tls_version": "TLS1.3", "alpn": "h3",
            "ja4": "q13d4-unknown" if attack_attempt else "q13d4-normal",
            "known_fingerprint": not attack_attempt, "sni": None if attack_attempt else "cdn.example",
            "cipher_suite_entropy": 4.8 if attack_attempt else 2.1,
            "packet_length_mean": 1100 if attack_attempt else 850,
            "packet_length_std": 1050 if attack_attempt else 120,
            "iat_jitter": 0.001 if attack_attempt else 0.03,
            "src_bytes": 180000 if attack_attempt else 1200, "dst_bytes": 3000 if attack_attempt else 900,
            "tot_pkts": 900 if attack_attempt else 12, "dur": 15 if attack_attempt else 2,
        }
        alerts = score_flow_all(flow)
        for alert in alerts: alert_store.add_alert(alert)
        alert = next((a for a in alerts if a.get("threatClass") == "Data Exfiltration"), None)
        alert = alert or next((a for a in alerts if a.get("threatClass") == "TLS / QUIC Encrypted Malware"), None)
        confidence = alert["confidence"] if alert else 8.0
        packet = _make_packet_shell(bool(alert), alert["threatClass"] if alert else "CLEAN PASS", alert["evidence"] if alert else "Encrypted metadata within baseline", confidence, src_ip, dst_ip, "QUIC", 1100 if attack_attempt else 850)
        return _merge_all_models(packet, all_models)

    # Unknown replay ids are kept harmless rather than fabricating a threat verdict.
    packet = _make_packet_shell(False, "CLEAN PASS", "No detector configured for this replay", 0.0, random.choice(_SRC_IPS), random.choice(_DST_IPS), "TCP", 64)
    return _merge_all_models(packet, all_models)


def pcap_total_packets(pcap_id: str) -> int:
    for p in PCAPS:
        if p["id"] == pcap_id:
            return p["totalPkts"]
    return 50000