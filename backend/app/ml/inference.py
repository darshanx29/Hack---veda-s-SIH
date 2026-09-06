
"""
app/ml/inference.py

Runs flow dictionaries through the loaded ML models.

Public scoring functions:
    score_ddos(flow)
    score_botnet_c2(flow)
    score_dga_dns(flow)
    score_recon(flow)

Each returns:
    ScoreResult(confidence, alert)

score_flow_all(flow) runs all currently loaded detectors.
"""

import time
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone

import numpy as np
import pandas as pd

from app.ml import perf_stats
from app.ml.stream_detectors import score_stream_metadata
from app.ml.model_loader import (
    get_feature_list,
    get_model,
    loaded_model_names,
)


@dataclass
class ScoreResult:
    confidence: float
    alert: dict | None


def _now_iso():
    return (
        datetime.now(timezone.utc)
        .strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3]
        + "Z"
    )


def _now_display():
    return datetime.now(timezone.utc).strftime(
        "%Y-%m-%d %H:%M:%S UTC"
    )


def _severity_from_confidence(confidence_pct: float):
    if confidence_pct >= 95:
        return "Critical", "badge-critical"
    if confidence_pct >= 80:
        return "High", "badge-high"
    if confidence_pct >= 50:
        return "Medium", "badge-medium"
    return "Low", "badge-low"


def _vectorize(flow: dict, feature_list: list) -> np.ndarray:
    return np.array(
        [[flow.get(feature, 0) for feature in feature_list]],
        dtype=float,
    )


def score_ddos(flow: dict) -> ScoreResult:
    model = get_model("ddos")
    feature_list = get_feature_list("ddos")

    X = _vectorize(flow, feature_list)

    start = time.perf_counter()
    proba = model.predict_proba(X)[0]
    perf_stats.record_latency_ms(
        (time.perf_counter() - start) * 1000
    )

    confidence = float(proba[1]) * 100

    if confidence < 50:
        return ScoreResult(
            confidence=round(confidence, 1),
            alert=None,
        )

    severity, badge_class = _severity_from_confidence(confidence)

    importances = getattr(model, "feature_importances_", None)

    if importances is not None and len(importances) == len(feature_list):
        top_feature = feature_list[int(np.argmax(importances))]
    else:
        top_feature = "flow rate anomaly"

    alert = {
        "id": f"ALT-{uuid.uuid4().hex[:8].upper()}",
        "flowId": flow.get(
            "flow_id",
            f"FL-{uuid.uuid4().hex[:6].upper()}",
        ),
        "threatClass": "DDoS & Volumetric",
        "severity": severity,
        "badgeClass": badge_class,
        "timestamp": _now_display(),
        "confidence": round(confidence, 1),
        "srcIp": flow.get("src_ip", "unknown"),
        "dstIp": flow.get("dst_ip", "unknown"),
        "evidence": (
            "CIC-IDS binary classifier flagged flow as "
            f"volumetric attack (top feature: {top_feature})."
        ),
        "shapFeature": (
            f"{top_feature} (model feature importance)"
        ),
        "rawJson": {
            "flow_id": flow.get("flow_id"),
            "timestamp": _now_iso(),
            "sensor_tap_id": "DIODE-HW-01",
            "threat_class": "DDOS_GENERIC",
            "severity": severity.upper(),
            "ai_confidence": round(confidence / 100, 4),
            "model": "cic_binary_xgb",
            "metrics": {
                feature: flow.get(feature, 0)
                for feature in feature_list[:8]
            },
        },
    }

    return ScoreResult(
        confidence=round(confidence, 1),
        alert=alert,
    )


def score_botnet_c2(flow: dict) -> ScoreResult:
    model = get_model("botnet_c2")
    feature_list = get_feature_list("botnet_c2")

    row = {
        feature: flow.get(feature)
        for feature in feature_list
    }

    X = pd.DataFrame([row])

    start = time.perf_counter()
    proba = model.predict_proba(X)[0]
    perf_stats.record_latency_ms(
        (time.perf_counter() - start) * 1000
    )

    confidence = float(proba[1]) * 100

    if confidence < 50:
        return ScoreResult(
            confidence=round(confidence, 1),
            alert=None,
        )

    severity, badge_class = _severity_from_confidence(confidence)

    alert = {
        "id": f"ALT-{uuid.uuid4().hex[:8].upper()}",
        "flowId": flow.get(
            "flow_id",
            f"FL-{uuid.uuid4().hex[:6].upper()}",
        ),
        "threatClass": "Botnet C2 Beaconing",
        "severity": severity,
        "badgeClass": badge_class,
        "timestamp": _now_display(),
        "confidence": round(confidence, 1),
        "srcIp": flow.get("src_ip", "unknown"),
        "dstIp": flow.get("dst_ip", "unknown"),
        "evidence": (
            "CTU-13 botnet classifier flagged flow "
            f"(duration={flow.get('dur')}s, "
            f"state={flow.get('state')})."
        ),
        "shapFeature": (
            "Flow duration / packet-count pattern "
            "(model prediction)"
        ),
        "rawJson": {
            "flow_id": flow.get("flow_id"),
            "timestamp": _now_iso(),
            "sensor_tap_id": "DIODE-HW-01",
            "threat_class": "BOTNET_C2_BEACON",
            "severity": severity.upper(),
            "ai_confidence": round(confidence / 100, 4),
            "model": "ctu13_botnet_xgboost",
            "metrics": row,
        },
    }

    return ScoreResult(
        confidence=round(confidence, 1),
        alert=alert,
    )


def score_dga_dns(flow: dict) -> ScoreResult:
    model = get_model("dga_dns")
    feature_list = get_feature_list("dga_dns")

    row = {
        feature: flow.get(feature, 0)
        for feature in feature_list
    }

    X = pd.DataFrame([row])

    start = time.perf_counter()
    proba = model.predict_proba(X)[0]
    perf_stats.record_latency_ms(
        (time.perf_counter() - start) * 1000
    )

    confidence = float(proba[1]) * 100

    if confidence < 50:
        return ScoreResult(
            confidence=round(confidence, 1),
            alert=None,
        )

    severity, badge_class = _severity_from_confidence(confidence)

    alert = {
        "id": f"ALT-{uuid.uuid4().hex[:8].upper()}",
        "flowId": flow.get(
            "flow_id",
            f"FL-{uuid.uuid4().hex[:6].upper()}",
        ),
        "threatClass": "DGA & DNS Tunnelling",
        "severity": severity,
        "badgeClass": badge_class,
        "timestamp": _now_display(),
        "confidence": round(confidence, 1),
        "srcIp": flow.get("src_ip", "unknown"),
        "dstIp": flow.get("dst_ip", "unknown"),
        "evidence": (
            "CIRA-CIC-DoHBrw classifier flagged flow "
            f"as DNS/DoH tunneling "
            f"(bytes_sent={row.get('FlowBytesSent')})."
        ),
        "shapFeature": (
            "Packet length / timing distribution anomaly "
            "(model prediction)"
        ),
        "rawJson": {
            "flow_id": flow.get("flow_id"),
            "timestamp": _now_iso(),
            "sensor_tap_id": "DIODE-HW-02",
            "threat_class": "DNS_TUNNELING",
            "severity": severity.upper(),
            "ai_confidence": round(confidence / 100, 4),
            "model": "doh_tunneling_xgb",
            "metrics": row,
        },
    }

    return ScoreResult(
        confidence=round(confidence, 1),
        alert=alert,
    )


def score_recon(flow: dict) -> ScoreResult:
    model = get_model("port_scan")
    feature_list = get_feature_list("port_scan")

    X = _vectorize(flow, feature_list)

    start = time.perf_counter()
    proba = model.predict_proba(X)[0]
    perf_stats.record_latency_ms(
        (time.perf_counter() - start) * 1000
    )

    confidence = float(proba[1]) * 100

    if confidence < 50:
        return ScoreResult(
            confidence=round(confidence, 1),
            alert=None,
        )

    severity, badge_class = _severity_from_confidence(confidence)

    importances = getattr(model, "feature_importances_", None)

    if importances is not None and len(importances) == len(feature_list):
        top_feature = feature_list[int(np.argmax(importances))]
    else:
        top_feature = "port fan-out anomaly"

    alert = {
        "id": f"ALT-{uuid.uuid4().hex[:8].upper()}",
        "flowId": flow.get(
            "flow_id",
            f"FL-{uuid.uuid4().hex[:6].upper()}",
        ),
        "threatClass": "Reconnaissance & Scan",
        "severity": severity,
        "badgeClass": badge_class,
        "timestamp": _now_display(),
        "confidence": round(confidence, 1),
        "srcIp": flow.get("src_ip", "unknown"),
        "dstIp": flow.get("dst_ip", "unknown"),
        "evidence": (
            "UNSW-NB15-trained classifier flagged flow "
            f"as reconnaissance/port-scan "
            f"(top feature: {top_feature})."
        ),
        "shapFeature": (
            f"{top_feature} (model feature importance)"
        ),
        "rawJson": {
            "flow_id": flow.get("flow_id"),
            "timestamp": _now_iso(),
            "sensor_tap_id": "DIODE-HW-02",
            "threat_class": "SYN_PORT_SCAN",
            "severity": severity.upper(),
            "ai_confidence": round(confidence / 100, 4),
            "model": "recon_xgb",
            "metrics": {
                feature: flow.get(feature, 0)
                for feature in feature_list[:8]
            },
        },
    }

    return ScoreResult(
        confidence=round(confidence, 1),
        alert=alert,
    )


def score_flow_all(flow: dict) -> list[dict]:
    """
    Run the flow through every currently loaded detector.

    Returns only alerts that actually fired.
    """

    scorers = {
        "ddos": score_ddos,
        "botnet_c2": score_botnet_c2,
        "dga_dns": score_dga_dns,
        "port_scan": score_recon,
    }

    loaded = set(loaded_model_names())
    alerts = []

    # Stateful passive detectors cover TLS/QUIC metadata, recon fan-out, and exfiltration.
    alerts.extend(score_stream_metadata(flow))

    for name, scorer in scorers.items():
        if name not in loaded:
            continue

        try:
            result = scorer(flow)
        except Exception as exc:
            # Do not crash the entire request if one detector has
            # an incompatible input schema.
            print(
                f"[inference] WARNING: {name} scoring failed: "
                f"{type(exc).__name__}: {exc}"
            )
            continue

        if result.alert is not None:
            alerts.append(result.alert)

    # Add the canonical SIH schema while retaining legacy camelCase fields for the existing UI.
    for alert in alerts:
        # Enrich every alert with the exact network endpoint metadata from the
        # triggering flow. This is what lets the console answer: who, where,
        # which port/protocol, and what attack type — instead of only showing
        # an aggregate threat count.
        alert.setdefault("timestamp_iso", _now_iso())
        alert.setdefault("flow_id", alert.get("flowId", flow.get("flow_id", "FL-UNKNOWN")))
        alert.setdefault("threat_class", alert.get("threatClass", "Unknown"))
        alert.setdefault("confidence_score", round(float(alert.get("confidence", 0)) / 100, 4))
        alert.setdefault("supporting_evidence", {"text": alert.get("evidence", "")})
        alert.setdefault("detector_type", "ml")

        alert.setdefault("srcIp", flow.get("src_ip", flow.get("srcIp", "unknown")))
        alert.setdefault("dstIp", flow.get("dst_ip", flow.get("dstIp", "unknown")))
        alert.setdefault("srcPort", flow.get("src_port", flow.get("srcPort", flow.get("sport", "unknown"))))
        alert.setdefault("dstPort", flow.get("dst_port", flow.get("dstPort", flow.get("dport", "unknown"))))
        alert.setdefault("protocol", flow.get("protocol", flow.get("proto", "unknown")))

        metrics = alert.setdefault("rawJson", {}).setdefault("metrics", {})
        metrics.setdefault("src_ip", alert["srcIp"])
        metrics.setdefault("dst_ip", alert["dstIp"])
        metrics.setdefault("src_port", alert["srcPort"])
        metrics.setdefault("dst_port", alert["dstPort"])
        metrics.setdefault("protocol", alert["protocol"])
    return alerts

