"""
app/routes/replay.py
=====================
Feeds TrafficReplay.jsx. Every packet streamed here comes from
app.generators.generate_packet(), which for apt29_dns_tunneling /
mirai_c2 / syn_flood_ddos runs an internally-consistent synthetic flow
through the REAL trained model (score_dga_dns / score_botnet_c2 /
score_ddos) and only reports isThreat=True when the model itself fires
(see app/ml/synthetic_flows.py + app/ml/inference.py). quic_exfil has
no trained model yet, so it stays on a labeled random simulation until
one exists (see app/generators.py's _MOCK_THREAT_LABELS).

Session state lives in-memory, keyed by session id. No frontend changes
needed beyond pointing TrafficReplay.jsx at these endpoints instead of
its local Math.random() loop.
"""

import json
import threading
import time
import traceback
import uuid

from flask import Blueprint, Response, jsonify, request

from app.data import PCAPS
from app.generators import generate_packet
from app.ml import perf_stats

replay_bp = Blueprint("replay", __name__)

_lock = threading.Lock()
_sessions = {}


def _new_session(pcap_id: str) -> dict:
    return {
        "id": uuid.uuid4().hex[:10],
        "pcap_id": pcap_id,
        "playing": False,
        "speed": 1,
        "progress": 0.0,
        "packetsProcessed": 0,
        "threatsCaught": 0,
    }


@replay_bp.get("/pcaps")
def list_pcaps():
    return jsonify(PCAPS)


@replay_bp.post("/sessions")
def create_session():
    body = request.get_json(force=True, silent=True) or {}
    pcap_id = body.get("pcap_id", PCAPS[0]["id"])
    session = _new_session(pcap_id)
    with _lock:
        _sessions[session["id"]] = session
    return jsonify(session)


@replay_bp.post("/sessions/<session_id>/control")
def control_session(session_id):
    body = request.get_json(force=True, silent=True) or {}
    action = body.get("action")
    with _lock:
        session = _sessions.get(session_id)
        if not session:
            return jsonify({"error": "unknown session"}), 404

        if action == "play":
            session["playing"] = True
        elif action == "pause":
            session["playing"] = False
        elif action == "restart":
            fresh = _new_session(session["pcap_id"])
            fresh["id"] = session_id
            fresh["playing"] = True
            _sessions[session_id] = fresh
            session = fresh
        if "speed" in body:
            session["speed"] = body["speed"]

        return jsonify(session)


@replay_bp.get("/sessions/<session_id>/stream")
def stream_session(session_id):
    with _lock:
        if session_id not in _sessions:
            return jsonify({"error": "unknown session"}), 404

    def event_stream():
        while True:
            with _lock:
                session = _sessions.get(session_id)
                if session is None:
                    break
                playing = session["playing"]
                pcap_id = session["pcap_id"]
                speed = session["speed"]

            if not playing:
                time.sleep(0.4)
                continue

            try:
                packet = generate_packet(pcap_id)
            except Exception as exc:
                # Previously an exception here (e.g. a model/feature mismatch)
                # silently killed the SSE stream with no signal at all — the
                # frontend just showed a permanently-stuck "Streaming" badge
                # and zeros forever. Now we surface the real error so it's
                # actually debuggable instead of looking like empty data.
                err_event = {
                    "fatalError": {
                        "message": str(exc),
                        "traceback": traceback.format_exc(),
                        "pcap_id": pcap_id,
                    }
                }
                yield f"data: {json.dumps(err_event)}\n\n"
                with _lock:
                    s = _sessions.get(session_id)
                    if s:
                        s["playing"] = False
                break

            with _lock:
                session = _sessions.get(session_id)
                if session is None:
                    break
                session["packetsProcessed"] += int(12 * speed)
                if packet["isThreat"]:
                    session["threatsCaught"] += 1
                session["progress"] = min(100.0, session["progress"] + 0.15 * speed)
                if session["progress"] >= 100:
                    session["playing"] = False
                session_out = dict(session)
                session_out["latencyMs"] = perf_stats.average_latency_ms()
                event = {"packet": packet, "session": session_out}

            yield f"data: {json.dumps(event)}\n\n"
            time.sleep(0.4 / max(speed, 0.01))

    return Response(event_stream(), mimetype="text/event-stream")
