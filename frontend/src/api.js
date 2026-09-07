// RakshaNetra API client
// Copy this into src/api.js in the React project.
// Every function's return shape matches what the components already expect
// from their hardcoded arrays, so swapping is a straight fetch-then-setState.

const API_BASE = import.meta.env.VITE_API_BASE || 'http://localhost:5000/api';

async function request(path, options = {}) {
  const res = await fetch(`${API_BASE}${path}`, {
    headers: { 'Content-Type': 'application/json' },
    ...options,
  });
  if (!res.ok) {
    const body = await res.json().catch(() => ({}));
    throw new Error(body.description || `Request to ${path} failed (${res.status})`);
  }
  return res.json();
}

// ---------------------------------------------------------------------------
// Dashboard (HeroSection.jsx)
// ---------------------------------------------------------------------------
export const getDashboardStats = () => request('/dashboard/stats');

/** onMessage(stats) fires every ~1.5s. onError(evt) fires on a real connection
 * failure — previously this was silently swallowed, so a broken backend just
 * looked like "stuck at zero" with no way to tell why. Returns a cleanup fn. */
export function streamDashboardStats(onMessage, onError) {
  const es = new EventSource(`${API_BASE}/dashboard/stream`);
  es.onmessage = (e) => onMessage(JSON.parse(e.data));
  es.onerror = (e) => { if (onError) onError(e); };
  return () => es.close();
}

// ---------------------------------------------------------------------------
// Threat categories (ThreatCategories.jsx)
// ---------------------------------------------------------------------------
export const getThreatCategories = () => request('/threats/categories');
export const getThreatCategory = (id) => request(`/threats/categories/${id}`);

// ---------------------------------------------------------------------------
// Analytics (AIAnalytics.jsx)
// ---------------------------------------------------------------------------
export const getShapFeatures = () => request('/analytics/features');
export const getTrendData = (range = '24h') => request(`/analytics/trends?range=${range}`);
export const getModelPerformance = () => request('/analytics/performance');

// ---------------------------------------------------------------------------
// Network topology (NetworkVisualization.jsx)
// ---------------------------------------------------------------------------
export const getNetworkTopology = (filter = 'all') =>
  request(`/network/topology?filter=${filter}`);

// ---------------------------------------------------------------------------
// Alerts (AlertInvestigation.jsx)
// ---------------------------------------------------------------------------
export function normalizeAlert(alert = {}) {
  const confidence = Number(
    alert.confidence ?? ((alert.confidence_score ?? alert.ai_confidence ?? 0) * 100)
  );
  const threatClass = alert.threatClass ?? alert.threat_class ?? 'Unknown';
  const evidence = alert.evidence ?? alert.supporting_evidence ?? 'No supporting evidence supplied.';
  const flowId = alert.flowId ?? alert.flow_id ?? 'FL-UNKNOWN';
  const timestamp = alert.timestamp ?? alert.timestamp_iso ?? 'Unknown';
  const severity = alert.severity ?? 'Medium';
  return {
    ...alert,
    flowId,
    flow_id: alert.flow_id ?? flowId,
    threatClass,
    threat_class: alert.threat_class ?? threatClass,
    severity,
    confidence: Number.isFinite(confidence) ? Math.round(confidence * 10) / 10 : 0,
    confidence_score: Number(alert.confidence_score ?? confidence / 100),
    timestamp,
    timestamp_iso: alert.timestamp_iso ?? timestamp,
    srcIp: alert.srcIp ?? alert.src_ip ?? alert.rawJson?.metrics?.src_ip ?? 'unknown',
    dstIp: alert.dstIp ?? alert.dst_ip ?? alert.rawJson?.metrics?.dst_ip ?? 'unknown',
    srcPort: alert.srcPort ?? alert.src_port ?? alert.rawJson?.metrics?.src_port ?? '—',
    dstPort: alert.dstPort ?? alert.dst_port ?? alert.rawJson?.metrics?.dst_port ?? '—',
    protocol: alert.protocol ?? alert.proto ?? alert.rawJson?.metrics?.protocol ?? '—',
    detectorType: alert.detectorType ?? alert.detector_type ?? (alert.rawJson?.model ? 'ml' : 'unknown'),
    evidence,
    supporting_evidence: alert.supporting_evidence ?? evidence,
    detector_type: alert.detector_type ?? (alert.rawJson?.model ? 'ml' : 'unknown'),
    badgeClass: alert.badgeClass ?? ({ Critical: 'badge-critical', High: 'badge-high', Medium: 'badge-medium', Low: 'badge-low' }[severity] || 'badge-medium'),
    rawJson: alert.rawJson ?? alert.raw_json ?? alert,
  };
}

export function getAlerts({ severity = 'All', vector = 'All', minConfidence = 0 } = {}) {
  const params = new URLSearchParams({
    severity,
    vector,
    min_confidence: String(minConfidence),
  });
  return request(`/alerts?${params}`).then((data) => Array.isArray(data) ? data.map(normalizeAlert) : []);
}
export const getAlert = (id) => request(`/alerts/${id}`);

// ---------------------------------------------------------------------------
// PCAP Traffic Replay (TrafficReplay.jsx)
// ---------------------------------------------------------------------------
export const getPcapList = () => request('/replay/pcaps');

export const startReplaySession = (pcapId) =>
  request('/replay/sessions', { method: 'POST', body: JSON.stringify({ pcap_id: pcapId }) });

export const controlReplaySession = (sessionId, action, speed) =>
  request(`/replay/sessions/${sessionId}/control`, {
    method: 'POST',
    body: JSON.stringify({ action, ...(speed ? { speed } : {}) }),
  });

/**
 * onEvent({ packet, session }) fires for each replayed packet while the
 * session is playing. onFatalError({message, traceback, pcap_id}) fires if
 * the backend's model scoring itself threw (surfaced instead of the stream
 * just silently dying). onConnError(evt) fires on a raw connection failure
 * (backend unreachable, CORS, etc). Returns a cleanup function.
 */
export function streamReplaySession(sessionId, onEvent, onFatalError, onConnError) {
  const es = new EventSource(`${API_BASE}/replay/sessions/${sessionId}/stream`);
  es.onmessage = (e) => {
    const data = JSON.parse(e.data);
    if (data.fatalError) {
      if (onFatalError) onFatalError(data.fatalError);
      es.close();
      return;
    }
    onEvent(data);
  };
  es.onerror = (e) => { if (onConnError) onConnError(e); };
  return () => es.close();
}
