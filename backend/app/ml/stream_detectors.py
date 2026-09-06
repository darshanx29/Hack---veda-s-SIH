"""Passive, stateful detectors for the threat classes without trained artifacts.

These detectors consume flow/handshake metadata only. They never open sockets,
probe hosts, or decrypt TLS/QUIC payloads. They are deliberately labelled
rule_based so the UI/docs do not present them as trained ML models.
"""
import hashlib
import math
import threading
import time
from collections import defaultdict, deque
from datetime import datetime, timezone

_LOCK = threading.Lock()
_WINDOWS = {"recon": 60.0, "exfil": 300.0}
_RECON = defaultdict(deque)  # src -> (monotonic, dst_ip, dst_port, syn, success)
_EXFIL = defaultdict(deque)  # src -> (monotonic, dst, out, in, duration)


def _now_iso():
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _num(flow, *keys, default=0.0):
    for k in keys:
        v = flow.get(k)
        if v is not None:
            try: return float(v)
            except (TypeError, ValueError): pass
    return float(default)


def _alert(flow, threat_class, confidence, severity, evidence, detector, metrics):
    pct = round(max(0.0, min(100.0, confidence)), 1)
    return {
        "id": "ALT-" + hashlib.sha1(f"{time.time_ns()}:{flow.get('flow_id','')}".encode()).hexdigest()[:8].upper(),
        "flowId": flow.get("flow_id", "FL-STREAM"),
        "threatClass": threat_class,
        "severity": severity,
        "badgeClass": {"Critical":"badge-critical","High":"badge-high","Medium":"badge-medium","Low":"badge-low"}[severity],
        "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
        "confidence": pct,
        "srcIp": flow.get("src_ip", flow.get("srcIp", "unknown")),
        "dstIp": flow.get("dst_ip", flow.get("dstIp", "unknown")),
        "srcPort": flow.get("src_port", flow.get("srcPort", flow.get("sport", "unknown"))),
        "dstPort": flow.get("dst_port", flow.get("dstPort", flow.get("dport", "unknown"))),
        "protocol": flow.get("protocol", flow.get("proto", "unknown")),
        "evidence": evidence,
        "shapFeature": detector,
        "rawJson": {"flow_id": flow.get("flow_id"), "timestamp": _now_iso(), "sensor_tap_id": flow.get("sensor_tap_id", "DIODE-HW-01"), "threat_class": threat_class.upper().replace(" ", "_"), "severity": severity.upper(), "ai_confidence": round(pct/100, 4), "model": detector, "metrics": {
            **metrics,
            "src_ip": flow.get("src_ip", flow.get("srcIp", "unknown")),
            "dst_ip": flow.get("dst_ip", flow.get("dstIp", "unknown")),
            "src_port": flow.get("src_port", flow.get("srcPort", flow.get("sport", "unknown"))),
            "dst_port": flow.get("dst_port", flow.get("dstPort", flow.get("dport", "unknown"))),
            "protocol": flow.get("protocol", flow.get("proto", "unknown")),
        }},
        # Canonical SIH alert schema:
        "timestamp_iso": _now_iso(),
        "flow_id": flow.get("flow_id", "FL-STREAM"),
        "threat_class": threat_class,
        "confidence_score": round(pct/100, 4),
        "supporting_evidence": metrics,
        "detector_type": "rule_based",
    }


def score_encrypted_metadata(flow):
    """TLS/QUIC metadata-only anomaly score; no payload/decryption access."""
    proto = str(flow.get("protocol", flow.get("proto", ""))).lower()
    tls = str(flow.get("tls_version", flow.get("tls.version", "")))
    quic = proto == "quic" or "quic" in str(flow.get("alpn", "")).lower()
    encrypted = quic or proto in {"tls", "https", "tcp/443", "tcp443"} or tls.startswith("tls")
    if not encrypted: return None
    score = 0.0; reasons = []
    ja = str(flow.get("ja4") or flow.get("ja3") or "").strip()
    if ja and flow.get("known_fingerprint") is False:
        score += 0.35; reasons.append("unknown JA3/JA4 fingerprint")
    entropy = _num(flow, "cipher_suite_entropy", "tls_cipher_entropy")
    if entropy >= 4.0:
        score += 0.2; reasons.append("high ClientHello cipher-suite entropy")
    mean = _num(flow, "packet_length_mean", "Packet Length Mean", "pkt_len_mean")
    std = _num(flow, "packet_length_std", "Packet Length Std", "pkt_len_std")
    cv = std / max(mean, 1.0)
    if cv >= 0.9:
        score += 0.2; reasons.append("high encrypted packet-size variance")
    jitter = _num(flow, "iat_jitter", "IAT_jitter", "sjit")
    if jitter > 0 and jitter < 0.003:
        score += 0.15; reasons.append("low inter-packet timing jitter")
    if not flow.get("sni") and not flow.get("server_name"):
        score += 0.1; reasons.append("missing SNI/server-name metadata")
    if score < 0.5: return None
    severity = "Critical" if score >= .9 else "High" if score >= .75 else "Medium"
    return _alert(flow, "TLS / QUIC Encrypted Malware", score*100, severity,
        "Encrypted-session metadata anomaly; payload was not decrypted. " + "; ".join(reasons),
        "tls_quic_metadata_rules", {"protocol": proto, "tls_version": tls, "ja3": flow.get("ja3"), "ja4": flow.get("ja4"), "sni": flow.get("sni"), "alpn": flow.get("alpn"), "packet_length_mean": mean, "packet_length_std": std, "timing_jitter": jitter})


def score_recon_stream(flow):
    src = str(flow.get("src_ip", "unknown")); now = time.monotonic()
    dst = str(flow.get("dst_ip", "unknown")); port = int(_num(flow, "dst_port", "DestinationPort", "dport"))
    syn = bool(_num(flow, "syn", "SYN Flag Count", default=0))
    success = bool(flow.get("connection_success", flow.get("state") in {"SF", "CON", "ESTABLISHED"}))
    with _LOCK:
        q = _RECON[src]; q.append((now,dst,port,syn,success))
        while q and now-q[0][0] > _WINDOWS["recon"]: q.popleft()
        hosts={x[1] for x in q}; ports={x[2] for x in q if x[2]}; probes=sum(1 for x in q if x[3] or not x[4]); unanswered=sum(1 for x in q if x[3] and not x[4])
    if len(q) < 8: return None
    fanout=max(len(hosts),len(ports)); unanswered_ratio=unanswered/max(probes,1); rate=len(q)/_WINDOWS["recon"]
    score=min(1.0, 0.45*min(fanout/25,1)+0.35*unanswered_ratio+0.2*min(rate/2,1))
    if score < .55: return None
    severity="Critical" if score>=.9 else "High" if score>=.75 else "Medium"
    return _alert(flow,"Reconnaissance & Scan",score*100,severity,
        f"Passive {int(_WINDOWS['recon'])}s window: {len(hosts)} unique hosts, {len(ports)} unique destination ports, {unanswered_ratio:.0%} unanswered probes.",
        "recon_stream_fanout_rules", {"window_seconds":60,"unique_dst_hosts":len(hosts),"unique_dst_ports":len(ports),"probe_rate":round(rate,3),"unanswered_probe_ratio":round(unanswered_ratio,3)})


def score_exfil_stream(flow):
    src=str(flow.get("src_ip","unknown")); now=time.monotonic(); dst=str(flow.get("dst_ip","unknown"))
    out=_num(flow,"src_bytes","bytes_out","FlowBytesSent","sbytes"); inc=_num(flow,"dst_bytes","bytes_in","FlowBytesReceived","dbytes"); dur=_num(flow,"dur","Duration","flow_duration",default=1); pkts=_num(flow,"tot_pkts","packets",default=1)
    with _LOCK:
        q=_EXFIL[src]; q.append((now,dst,out,inc,dur));
        while q and now-q[0][0]>_WINDOWS["exfil"]: q.popleft()
        total_out=sum(x[2] for x in q); total_in=sum(x[3] for x in q); dsts={x[1] for x in q}
    ratio=total_out/max(total_in,1); concentration=1/max(len(dsts),1); rate=total_out/max(sum(x[4] for x in q),1)
    score=min(1.0, .45*min(ratio/20,1)+.25*min(rate/50000,1)+.2*concentration+.1*min(pkts/1000,1))
    if total_out < 50000 or score < .6: return None
    severity="Critical" if score>=.9 else "High" if score>=.75 else "Medium"
    return _alert(flow,"Data Exfiltration",score*100,severity,
        f"Passive {int(_WINDOWS['exfil'])}s outbound-volume anomaly: {total_out:.0f} bytes out vs {total_in:.0f} bytes in across {len(dsts)} destination(s).",
        "exfil_volume_ratio_rules", {"window_seconds":300,"bytes_out":round(total_out,1),"bytes_in":round(total_in,1),"out_in_ratio":round(ratio,3),"destinations":len(dsts),"outbound_rate_Bps":round(rate,2)})


def score_stream_metadata(flow):
    out=[]
    for fn in (score_encrypted_metadata, score_recon_stream, score_exfil_stream):
        try:
            a=fn(flow)
            if a: out.append(a)
        except Exception as exc:
            print(f"[stream_detectors] WARNING {fn.__name__}: {type(exc).__name__}: {exc}")
    return out


def reset_state():
    with _LOCK:
        _RECON.clear(); _EXFIL.clear()
