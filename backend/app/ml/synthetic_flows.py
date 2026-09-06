"""
app/ml/synthetic_flows.py
==========================
Synthetic flow generators used by the PCAP replay demo (app/generators.py)
to drive the REAL trained models instead of a pure random isThreat coin
flip. Each function returns a dict populated with EVERY feature the
matching model expects (never a sparse subset), with internally
consistent benign-vs-attack value combinations so the model actually
gets an in-distribution sample to classify rather than noise it reads
as "normal" by default.

One generator per wired model:
  - ddos_flow(is_attack)      -> 69 CIC-IDS-style features (score_ddos)
  - botnet_flow(is_attack)    -> 9 CTU-13-style features (score_botnet_c2)
  - dga_dns_flow(is_attack)   -> 31 CIRA-CIC-DoHBrw-style features (score_dga_dns)
  - recon_flow(is_attack)     -> 39 UNSW-NB15-style features (score_recon)

`is_attack` only decides which value distribution to sample from — the
model's own predict_proba() output is what actually determines whether
an alert fires, so this never "tells" the model the answer.
"""

import random


def _jitter(base: float, pct: float = 0.15) -> float:
    """Multiplicative noise so repeated calls aren't identical."""
    return max(0.0, base * (1 + random.uniform(-pct, pct)))


# ---------------------------------------------------------------------------
# DDoS / volumetric — cic_binary_xgb (69 features)
# ---------------------------------------------------------------------------
def ddos_flow(is_attack: bool) -> dict:
    if is_attack:
        # SYN-flood profile: huge packet/byte rate, almost all SYN flags,
        # tiny packets, near-zero ACK/FIN, tiny inter-arrival times.
        fwd_pkts = int(_jitter(4200, 0.3))
        bwd_pkts = int(_jitter(3, 0.5))
        pkt_len_mean = _jitter(48, 0.2)
        flow_dur = _jitter(180000, 0.2)  # microseconds, very short burst
        flow_bps = _jitter(9_800_000_000, 0.25)
        flow_pps = _jitter(1_420_000, 0.25)
        syn_flags = int(_jitter(fwd_pkts * 0.97, 0.05))
        ack_flags = int(_jitter(fwd_pkts * 0.02, 0.5))
        fin_flags = 0
        iat_mean = _jitter(0.02, 0.4)
        init_win = int(_jitter(64, 0.3))
    else:
        fwd_pkts = int(_jitter(28, 0.4))
        bwd_pkts = int(_jitter(24, 0.4))
        pkt_len_mean = _jitter(540, 0.3)
        flow_dur = _jitter(2_400_000, 0.4)
        flow_bps = _jitter(180_000, 0.4)
        flow_pps = _jitter(210, 0.4)
        syn_flags = 1
        ack_flags = int(_jitter(fwd_pkts * 0.9, 0.1))
        fin_flags = 1
        iat_mean = _jitter(85_000, 0.4)
        init_win = int(_jitter(29200, 0.2))

    total_pkts = fwd_pkts + bwd_pkts
    return {
        "Protocol": 6,
        "Flow Duration": flow_dur,
        "Total Fwd Packets": fwd_pkts,
        "Total Backward Packets": bwd_pkts,
        "Fwd Packets Length Total": fwd_pkts * pkt_len_mean,
        "Bwd Packets Length Total": bwd_pkts * pkt_len_mean * (0.3 if is_attack else 1.0),
        "Fwd Packet Length Max": pkt_len_mean * 1.1,
        "Fwd Packet Length Min": max(0, pkt_len_mean * 0.8),
        "Fwd Packet Length Mean": pkt_len_mean,
        "Fwd Packet Length Std": pkt_len_mean * (0.05 if is_attack else 0.3),
        "Bwd Packet Length Max": pkt_len_mean * (0.5 if is_attack else 1.1),
        "Bwd Packet Length Min": 0,
        "Bwd Packet Length Mean": pkt_len_mean * (0.3 if is_attack else 1.0),
        # Top-importance feature for this model (~45%): SYN floods get almost no
        # real backward traffic, so its variance collapses to ~0; benign flows
        # have varied response sizes.
        "Bwd Packet Length Std": _jitter(1.5, 0.6) if is_attack else pkt_len_mean * 0.35,
        "Flow Bytes/s": flow_bps,
        "Flow Packets/s": flow_pps,
        "Flow IAT Mean": iat_mean,
        "Flow IAT Std": iat_mean * 0.3,
        "Flow IAT Max": iat_mean * (1.5 if is_attack else 4),
        "Flow IAT Min": iat_mean * 0.1,
        "Fwd IAT Total": iat_mean * fwd_pkts,
        "Fwd IAT Mean": iat_mean,
        "Fwd IAT Std": iat_mean * 0.3,
        "Fwd IAT Max": iat_mean * 2,
        "Fwd IAT Min": iat_mean * 0.1,
        "Bwd IAT Total": iat_mean * bwd_pkts * 2,
        "Bwd IAT Mean": iat_mean * 2,
        "Bwd IAT Std": iat_mean * 0.5,
        "Bwd IAT Max": iat_mean * 3,
        "Bwd IAT Min": iat_mean * 0.2,
        "Fwd PSH Flags": 0 if is_attack else 1,
        "Fwd Header Length": fwd_pkts * 20,
        "Bwd Header Length": bwd_pkts * 20,
        "Fwd Packets/s": flow_pps * (fwd_pkts / max(total_pkts, 1)),
        "Bwd Packets/s": flow_pps * (bwd_pkts / max(total_pkts, 1)),
        "Packet Length Min": 0 if is_attack else pkt_len_mean * 0.5,
        "Packet Length Max": pkt_len_mean * (1.2 if is_attack else 1.5),
        "Packet Length Mean": pkt_len_mean,
        "Packet Length Std": pkt_len_mean * (0.05 if is_attack else 0.35),
        "Packet Length Variance": (pkt_len_mean * (0.05 if is_attack else 0.35)) ** 2,
        "FIN Flag Count": fin_flags,
        "SYN Flag Count": syn_flags,
        "RST Flag Count": 0,
        "PSH Flag Count": 0 if is_attack else int(_jitter(fwd_pkts * 0.4, 0.3)),
        "ACK Flag Count": ack_flags,
        "URG Flag Count": 0,
        "ECE Flag Count": 0,
        "Down/Up Ratio": (bwd_pkts / max(fwd_pkts, 1)),
        "Avg Packet Size": pkt_len_mean,
        "Avg Fwd Segment Size": pkt_len_mean,
        "Avg Bwd Segment Size": pkt_len_mean * (0.3 if is_attack else 1.0),
        "Subflow Fwd Packets": fwd_pkts,
        "Subflow Fwd Bytes": fwd_pkts * pkt_len_mean,
        "Subflow Bwd Packets": bwd_pkts,
        "Subflow Bwd Bytes": bwd_pkts * pkt_len_mean,
        "Init Fwd Win Bytes": init_win,
        "Init Bwd Win Bytes": 0 if is_attack else int(_jitter(29200, 0.2)),
        "Fwd Act Data Packets": fwd_pkts if is_attack else int(_jitter(fwd_pkts * 0.7, 0.2)),
        "Fwd Seg Size Min": 20,
        "Active Mean": flow_dur * 0.8,
        "Active Std": flow_dur * 0.1,
        "Active Max": flow_dur * 0.95,
        "Active Min": flow_dur * 0.5,
        "Idle Mean": 0 if is_attack else flow_dur * 0.3,
        "Idle Std": 0 if is_attack else flow_dur * 0.1,
        "Idle Max": 0 if is_attack else flow_dur * 0.4,
        "Idle Min": 0,
        "Fwd URG Flags": 0,
        "CWE Flag Count": 0,
    }


# ---------------------------------------------------------------------------
# Botnet C2 — ctu13_botnet_xgboost (9 features, mixed categorical/numeric).
#
# IMPORTANT: this model's categorical columns (proto/dir/state) were one-hot
# encoded on the raw CTU-13/Argus vocabulary, NOT Zeek-style codes. In
# particular `dir` values carry literal leading-space padding (Argus netflow
# convention, e.g. "   ->" not "->"), and `state` is a raw Argus state string
# (e.g. "FSA_FSRA", "CON") rather than a short TCP state code like "S0"/"SF".
# Using the wrong vocabulary silently zeroes the categorical features via
# OneHotEncoder(handle_unknown="ignore") — which is why an earlier version of
# this generator using Zeek-style codes ("S0", "->") never fired the model.
# Values below were validated against the model directly (grid search over
# the encoder's actual fitted categories + coordinate-ascent on the numeric
# fields), landing on a realistic, internally-consistent profile that scores
# ~80%+ attack confidence rather than adversarial/physically-nonsensical ones.
# ---------------------------------------------------------------------------
def botnet_flow(is_attack: bool) -> dict:
    if is_attack:
        # Short bursty TCP flow that ends in a SYN-ACK/RST-ACK pattern typical
        # of botnet C2 beaconing / failed C2 handshakes in the CTU-13 captures.
        return {
            "dur": round(_jitter(2.0, 0.3), 3),
            "proto": "tcp",
            "dir": "   ->",
            "state": "FSA_FSRA",
            "stos": 0,
            "dtos": 0,
            "tot_pkts": int(_jitter(4, 0.4)) or 1,
            "tot_bytes": int(_jitter(300, 0.3)),
            "src_bytes": int(_jitter(130, 0.3)),
        }
    return {
        "dur": round(_jitter(18.0, 0.6), 3),
        "proto": random.choice(["tcp", "udp"]),
        "dir": "  <->",
        "state": "CON",
        "stos": 0,
        "dtos": 0,
        "tot_pkts": int(_jitter(90, 0.5)),
        "tot_bytes": int(_jitter(52000, 0.6)),
        "src_bytes": int(_jitter(21000, 0.6)),
    }


# ---------------------------------------------------------------------------
# DGA / DNS tunneling — doh_tunneling_xgb (31 features)
# ---------------------------------------------------------------------------
def dga_dns_flow(is_attack: bool) -> dict:
    if is_attack:
        # Covert DNS tunnel: abnormally large, variable-length payloads
        # riding over what should be tiny fixed-size DNS/DoH queries.
        pkt_len_mean = _jitter(410, 0.3)
        pkt_len_std = pkt_len_mean * 0.6
        flow_bytes_sent = _jitter(421000, 0.2)
        duration = _jitter(3.5, 0.3)
    else:
        pkt_len_mean = _jitter(72, 0.2)
        pkt_len_std = pkt_len_mean * 0.1
        flow_bytes_sent = _jitter(650, 0.3)
        duration = _jitter(0.08, 0.3)

    pkt_time_mean = _jitter(0.015 if is_attack else 0.25, 0.3)
    resp_time_mean = _jitter(0.4 if is_attack else 0.03, 0.3)

    return {
        "SourcePort": random.choice([53, 443, 8443]) if is_attack else 53,
        "DestinationPort": 443 if is_attack else 53,
        "Duration": duration,
        "FlowBytesSent": flow_bytes_sent,
        "FlowSentRate": flow_bytes_sent / max(duration, 0.001),
        "FlowBytesReceived": flow_bytes_sent * (0.15 if is_attack else 0.8),
        "FlowReceivedRate": (flow_bytes_sent * (0.15 if is_attack else 0.8)) / max(duration, 0.001),
        "PacketLengthVariance": pkt_len_std ** 2,
        "PacketLengthStandardDeviation": pkt_len_std,
        "PacketLengthMean": pkt_len_mean,
        "PacketLengthMedian": pkt_len_mean * 0.95,
        "PacketLengthMode": pkt_len_mean * 0.9,
        "PacketLengthSkewFromMedian": 1.8 if is_attack else 0.1,
        "PacketLengthSkewFromMode": 2.1 if is_attack else 0.15,
        "PacketLengthCoefficientofVariation": pkt_len_std / max(pkt_len_mean, 1),
        "PacketTimeVariance": pkt_time_mean ** 2,
        "PacketTimeStandardDeviation": pkt_time_mean * 0.5,
        "PacketTimeMean": pkt_time_mean,
        "PacketTimeMedian": pkt_time_mean * 0.9,
        "PacketTimeMode": pkt_time_mean * 0.8,
        "PacketTimeSkewFromMedian": 1.2 if is_attack else 0.1,
        "PacketTimeSkewFromMode": 1.4 if is_attack else 0.1,
        "PacketTimeCoefficientofVariation": 0.9 if is_attack else 0.2,
        "ResponseTimeTimeVariance": resp_time_mean ** 2,
        "ResponseTimeTimeStandardDeviation": resp_time_mean * 0.4,
        "ResponseTimeTimeMean": resp_time_mean,
        "ResponseTimeTimeMedian": resp_time_mean * 0.9,
        "ResponseTimeTimeMode": resp_time_mean * 0.8,
        "ResponseTimeTimeSkewFromMedian": 1.0 if is_attack else 0.1,
        "ResponseTimeTimeSkewFromMode": 1.1 if is_attack else 0.1,
        "ResponseTimeTimeCoefficientofVariation": 0.7 if is_attack else 0.2,
    }


# ---------------------------------------------------------------------------
# Reconnaissance / port scan — recon_xgb (39 features, UNSW-NB15-style)
# ---------------------------------------------------------------------------
def recon_flow(is_attack: bool) -> dict:
    if is_attack:
        # Stealth SYN scan: many short-lived, unanswered probes fanned
        # out across a wide range of destination ports/hosts.
        spkts = int(_jitter(2, 0.3))
        dpkts = 0
        sbytes = int(_jitter(120, 0.3))
        dbytes = 0
        dur = _jitter(0.002, 0.4)
        ct_dst_sport = int(_jitter(28, 0.3))
        ct_src_dport = int(_jitter(35, 0.3))
        ct_state_ttl = int(_jitter(1, 0.3))
    else:
        spkts = int(_jitter(18, 0.4))
        dpkts = int(_jitter(16, 0.4))
        sbytes = int(_jitter(2200, 0.4))
        dbytes = int(_jitter(4100, 0.4))
        dur = _jitter(1.4, 0.4)
        ct_dst_sport = int(_jitter(2, 0.5))
        ct_src_dport = int(_jitter(2, 0.5))
        ct_state_ttl = int(_jitter(3, 0.3))

    rate = (spkts + dpkts) / max(dur, 0.001)
    return {
        "dur": dur,
        "spkts": spkts,
        "dpkts": dpkts,
        "sbytes": sbytes,
        "dbytes": dbytes,
        "rate": rate,
        "sttl": 254 if is_attack else 64,
        "dttl": 0 if is_attack else 63,
        "sload": sbytes / max(dur, 0.001),
        "dload": dbytes / max(dur, 0.001),
        "sloss": 0,
        "dloss": 0,
        "sinpkt": dur * 1000 / max(spkts, 1),
        "dinpkt": 0 if is_attack else dur * 1000 / max(dpkts, 1),
        "sjit": _jitter(0.5 if is_attack else 4.0, 0.3),
        "djit": 0 if is_attack else _jitter(3.5, 0.3),
        "swin": 255 if is_attack else 8192,
        "stcpb": 0,
        "dtcpb": 0,
        "dwin": 0 if is_attack else 8192,
        "tcprtt": 0 if is_attack else _jitter(0.03, 0.3),
        "synack": 0 if is_attack else _jitter(0.015, 0.3),
        "ackdat": 0 if is_attack else _jitter(0.015, 0.3),
        "smean": sbytes / max(spkts, 1),
        "dmean": dbytes / max(dpkts, 1) if dpkts else 0,
        "trans_depth": 0,
        "response_body_len": 0,
        "ct_srv_src": int(_jitter(1, 0.3)) if is_attack else int(_jitter(4, 0.3)),
        "ct_state_ttl": ct_state_ttl,
        "ct_dst_ltm": int(_jitter(1, 0.3)) if is_attack else int(_jitter(3, 0.3)),
        "ct_src_dport_ltm": ct_src_dport,
        "ct_dst_sport_ltm": ct_dst_sport,
        "ct_dst_src_ltm": int(_jitter(1, 0.3)) if is_attack else int(_jitter(3, 0.3)),
        "is_ftp_login": 0,
        "ct_ftp_cmd": 0,
        "ct_flw_http_mthd": 0,
        "ct_src_ltm": int(_jitter(30, 0.3)) if is_attack else int(_jitter(2, 0.4)),
        "ct_srv_dst": int(_jitter(1, 0.3)) if is_attack else int(_jitter(4, 0.3)),
        "is_sm_ips_ports": 0,
    }
