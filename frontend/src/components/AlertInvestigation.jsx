import React, { useState, useEffect } from 'react';
import { 
  Search, 
  Filter, 
  ShieldAlert, 
  AlertTriangle, 
  CheckCircle, 
  FileText, 
  Copy, 
  Check, 
  X, 
  ExternalLink,
  ChevronRight,
  Sliders,
  Terminal,
  Layers,
  Sparkles
} from 'lucide-react';
import { getAlerts } from '../api';

export default function AlertInvestigation({ activeFilterThreat }) {
  const [selectedAlert, setSelectedAlert] = useState(null);
  const [severityFilter, setSeverityFilter] = useState('All');
  const [threatVectorFilter, setThreatVectorFilter] = useState(activeFilterThreat || 'All');
  const [minConfidence, setMinConfidence] = useState(90);
  const [copied, setCopied] = useState(false);
  const [overallAlerts, setOverallAlerts] = useState([]);

  // Real alerts from the backend: real model detections (app.ml.alert_store,
  // fired by score_ddos / score_botnet_c2 / score_dga_dns / score_recon)
  // plus any static seed rows in app/data.py (currently empty). Filtering
  // happens server-side in app/routes/alerts.py.
  const [filteredAlerts, setFilteredAlerts] = useState([]);

  useEffect(() => {
    let cancelled = false;
    getAlerts({ severity: severityFilter, vector: threatVectorFilter, minConfidence })
      .then((data) => {
        if (!cancelled) setFilteredAlerts(data);
      })
      .catch(() => {
        if (!cancelled) setFilteredAlerts([]);
      });
    return () => { cancelled = true; };
  }, [severityFilter, threatVectorFilter, minConfidence]);

  // Overall alert feed is intentionally fetched without the active table filters.
  // This keeps the dashboard summary truthful even when the operator is viewing
  // only one severity/vector in the table.
  useEffect(() => {
    const loadOverall = () => getAlerts({ severity: 'All', vector: 'All', minConfidence: 0 })
      .then(setOverallAlerts)
      .catch(() => {});
    loadOverall();
    const interval = setInterval(loadOverall, 5000);
    return () => clearInterval(interval);
  }, []);

  // Poll periodically so newly-fired alerts (from a running replay session
  // or /api/inference/score) show up without a manual refresh.
  useEffect(() => {
    const interval = setInterval(() => {
      getAlerts({ severity: severityFilter, vector: threatVectorFilter, minConfidence })
        .then(setFilteredAlerts)
        .catch(() => {});
    }, 5000);
    return () => clearInterval(interval);
  }, [severityFilter, threatVectorFilter, minConfidence]);


  const handleCopyJson = (jsonObj) => {
    navigator.clipboard.writeText(JSON.stringify(jsonObj, null, 2));
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <section className="py-20 relative bg-[#F3EFE8] border-t border-b border-slate-200">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 relative z-10">
        
        {/* Section Header */}
        <div className="flex flex-col md:flex-row md:items-end justify-between mb-8">
          <div>
            <div className="inline-flex items-center space-x-2 text-xs font-mono text-red-600 mb-2 font-semibold">
              <ShieldAlert className="w-3.5 h-3.5 text-red-600" />
              <span>FORENSIC INCIDENT INVESTIGATION</span>
            </div>
            <h2 className="text-3xl sm:text-4xl font-extrabold text-stone-900 tracking-tight">
              Alert <span className="gradient-text-hero">Investigation Console</span>
            </h2>
            <p className="mt-2 text-stone-600 text-sm sm:text-base max-w-2xl">
              Inspect passive threat alerts with full telemetry evidence breakdown, AI SHAP feature attribution, and raw JSON payload records.
            </p>
          </div>
        </div>

        {/* Overall alert posture — always uses the complete alert feed, not the table filters. */}
        <div className="grid grid-cols-2 sm:grid-cols-4 lg:grid-cols-7 gap-3 mb-6">
          {[
            ['TOTAL', overallAlerts.length, 'text-stone-900'],
            ['CRITICAL', overallAlerts.filter(a => a.severity === 'Critical').length, 'text-red-700'],
            ['HIGH', overallAlerts.filter(a => a.severity === 'High').length, 'text-orange-700'],
            ['MEDIUM', overallAlerts.filter(a => a.severity === 'Medium').length, 'text-amber-700'],
            ['TLS/QUIC', overallAlerts.filter(a => /TLS|QUIC/i.test(a.threatClass)).length, 'text-blue-700'],
            ['RECON', overallAlerts.filter(a => /Reconnaissance|Scan/i.test(a.threatClass)).length, 'text-indigo-700'],
            ['EXFIL', overallAlerts.filter(a => /Exfiltration/i.test(a.threatClass)).length, 'text-teal-700'],
          ].map(([label, value, cls]) => (
            <div key={label} className="glass-card rounded-xl p-3 border border-stone-200/90">
              <div className="text-[9px] font-mono text-stone-500 font-semibold tracking-wider">{label}</div>
              <div className={`text-xl font-extrabold font-mono mt-1 ${cls}`}>{value}</div>
            </div>
          ))}
        </div>

        {/* Filter Controls Bar */}
        <div className="glass-card rounded-2xl p-4 border border-stone-200/90 mb-6 flex flex-wrap items-center justify-between gap-4 shadow-xs">
          
          <div className="flex flex-wrap items-center gap-4">
            
            {/* Severity Filter */}
            <div className="flex items-center space-x-2 text-xs font-mono">
              <span className="text-stone-600 font-medium">Severity:</span>
              <div className="flex items-center space-x-1 bg-stone-100 p-1 rounded-xl border border-stone-200">
                {['All', 'Critical', 'High', 'Medium'].map(sev => (
                  <button
                    key={sev}
                    onClick={() => setSeverityFilter(sev)}
                    className={`px-2.5 py-1 rounded-lg transition-all cursor-pointer ${
                      severityFilter === sev ? 'bg-indigo-600 text-white font-semibold shadow-xs' : 'text-stone-600 hover:text-stone-900'
                    }`}
                  >
                    <span className={severityFilter === sev ? 'text-white' : ''}>{sev}</span>
                  </button>
                ))}
              </div>
            </div>

            {/* Threat Vector Filter */}
            <div className="flex items-center space-x-2 text-xs font-mono">
              <span className="text-stone-600 font-medium">Vector:</span>
              <select
                value={threatVectorFilter}
                onChange={(e) => setThreatVectorFilter(e.target.value)}
                className="bg-white text-stone-800 border border-stone-300 rounded-xl px-3 py-1.5 focus:outline-none focus:border-indigo-500 shadow-2xs cursor-pointer"
              >
                <option value="All">All Threat Vectors</option>
                <option value="DDoS">DDoS & Volumetric</option>
                <option value="Botnet">Botnet C2</option>
                <option value="DNS">DGA / DNS Tunnel</option>
                <option value="TLS">TLS / QUIC Malware</option>
                <option value="Reconnaissance">Reconnaissance</option>
                <option value="Exfiltration">Exfiltration</option>
              </select>
            </div>

          </div>

          {/* Min Confidence Slider */}
          <div className="flex items-center space-x-3 text-xs font-mono">
            <span className="text-stone-600 font-medium">Min Confidence:</span>
            <input
              type="range"
              min="80"
              max="99"
              value={minConfidence}
              onChange={(e) => setMinConfidence(Number(e.target.value))}
              className="w-28 accent-indigo-600 cursor-pointer"
            />
            <span className="text-indigo-600 font-bold w-10">{minConfidence}%</span>
          </div>

        </div>

        {/* Alerts Table Card */}
        <div className="glass-card rounded-2xl border border-stone-200/90 overflow-hidden shadow-xs">
          <div className="overflow-x-auto">
            <table className="w-full text-left border-collapse">
              <thead>
                <tr className="bg-stone-100/90 border-b border-stone-200 text-[11px] font-mono text-stone-600 uppercase tracking-wider font-semibold">
                  <th className="py-3.5 px-4">Alert</th>
                  <th className="py-3.5 px-4">Attack Type</th>
                  <th className="py-3.5 px-4">Severity</th>
                  <th className="py-3.5 px-4">When</th>
                  <th className="py-3.5 px-4">Attacker / Source</th>
                  <th className="py-3.5 px-4">Target / Destination</th>
                  <th className="py-3.5 px-4">Protocol / Ports</th>
                  <th className="py-3.5 px-4">Confidence</th>
                  <th className="py-3.5 px-4">Evidence</th>
                  <th className="py-3.5 px-4 text-right">Action</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-stone-200 text-xs font-mono">
                {filteredAlerts.length === 0 ? (
                  <tr>
                    <td colSpan="10" className="py-8 text-center text-stone-500 font-mono">
                      No alerts match the selected criteria.
                    </td>
                  </tr>
                ) : (
                  filteredAlerts.map((alert) => (
                    <tr
                      key={alert.id}
                      onClick={() => setSelectedAlert(alert)}
                      className="hover:bg-stone-50 transition-colors cursor-pointer group"
                    >
                      <td className="py-4 px-4 font-bold text-stone-900 group-hover:text-indigo-600">
                        {alert.id}
                        <span className="block text-[10px] text-stone-500 font-normal">{alert.flowId}</span>
                      </td>
                      <td className="py-4 px-4 text-stone-800 font-semibold">
                        {alert.threatClass}
                        <span className="block text-[9px] text-stone-500 font-normal uppercase">{alert.detector_type === 'rule_based' ? 'Metadata / Rule-Based' : 'ML Detector'}</span>
                      </td>
                      <td className="py-4 px-4">
                        <span className={`px-2.5 py-1 rounded text-[10px] font-bold ${alert.badgeClass}`}>
                          {alert.severity}
                        </span>
                      </td>
                      <td className="py-4 px-4 text-stone-600">
                        {alert.timestamp}
                      </td>
                      <td className="py-4 px-4 text-stone-700">
                        <span className="font-semibold">{alert.srcIp}</span>
                        <span className="block text-[10px] text-stone-500">port {alert.srcPort}</span>
                      </td>
                      <td className="py-4 px-4 text-stone-700">
                        <span className="font-semibold">{alert.dstIp}</span>
                        <span className="block text-[10px] text-stone-500">port {alert.dstPort}</span>
                      </td>
                      <td className="py-4 px-4 text-stone-700">
                        <span className="font-semibold">{alert.protocol}</span>
                        <span className="block text-[10px] text-stone-500">{alert.srcPort} ➔ {alert.dstPort}</span>
                      </td>
                      <td className="py-4 px-4">
                        <div className="flex items-center space-x-2">
                          <span className="font-bold text-indigo-600">{alert.confidence}%</span>
                          <div className="w-16 bg-stone-200 h-1.5 rounded-full overflow-hidden">
                            <div
                              className="bg-indigo-600 h-full rounded-full"
                              style={{ width: `${alert.confidence}%` }}
                            ></div>
                          </div>
                        </div>
                      </td>
                      <td className="py-4 px-4 max-w-[280px]">
                        <div className="truncate text-stone-600" title={alert.evidence}>{alert.evidence}</div>
                      </td>
                      <td className="py-4 px-4 text-right">
                        <button className="px-3 py-1 rounded-lg bg-indigo-50 text-indigo-700 border border-indigo-200 group-hover:bg-indigo-600 group-hover:text-white transition-all text-xs font-medium cursor-pointer">
                          Inspect
                        </button>
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </div>

      </div>

      {/* Slide-over Forensics Inspector Modal / Drawer */}
      {selectedAlert && (
        <div className="fixed inset-0 z-50 flex justify-end bg-black/80 backdrop-blur-md animate-in fade-in">
          <div className="glass-panel w-full max-w-2xl h-full border-l border-slate-700 p-6 sm:p-8 overflow-y-auto relative flex flex-col justify-between shadow-2xl">
            
            <div>
              {/* Header */}
              <div className="flex items-center justify-between pb-4 border-b border-slate-800 mb-6">
                <div>
                  <div className="flex items-center space-x-3">
                    <h3 className="text-2xl font-bold text-white">{selectedAlert.id}</h3>
                    <span className={`px-2.5 py-0.5 rounded text-xs font-mono font-bold ${selectedAlert.badgeClass}`}>
                      {selectedAlert.severity}
                    </span>
                  </div>
                  <p className="text-xs font-mono text-slate-400 mt-1">Flow ID: {selectedAlert.flowId} | Sensor: {selectedAlert.rawJson?.sensor_tap_id || 'DIODE-HW-01'}</p>
                </div>
                <button
                  onClick={() => setSelectedAlert(null)}
                  className="p-2 rounded-lg bg-slate-800 text-slate-400 hover:text-white"
                >
                  <X className="w-5 h-5" />
                </button>
              </div>

              {/* Threat Details */}
              <div className="space-y-6">
                
                {/* Network endpoint identity */}
                <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                  <div className="p-4 rounded-xl bg-slate-900 border border-red-500/20">
                    <span className="text-[10px] font-mono text-slate-400 uppercase">Attacker / Source</span>
                    <div className="mt-1 text-lg font-bold text-white">{selectedAlert.srcIp}</div>
                    <div className="text-xs font-mono text-red-300">Source port: {selectedAlert.srcPort}</div>
                  </div>
                  <div className="p-4 rounded-xl bg-slate-900 border border-blue-500/20">
                    <span className="text-[10px] font-mono text-slate-400 uppercase">Target / Destination</span>
                    <div className="mt-1 text-lg font-bold text-white">{selectedAlert.dstIp}</div>
                    <div className="text-xs font-mono text-blue-300">Destination port: {selectedAlert.dstPort}</div>
                  </div>
                  <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 md:col-span-2">
                    <span className="text-[10px] font-mono text-slate-400 uppercase">Transport</span>
                    <div className="mt-1 text-sm font-bold text-white">{selectedAlert.protocol} · {selectedAlert.srcIp}:{selectedAlert.srcPort} ➔ {selectedAlert.dstIp}:{selectedAlert.dstPort}</div>
                  </div>
                </div>

                {/* AI Confidence & Threat Vector Box */}
                <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 flex items-center justify-between">
                  <div>
                    <span className="text-xs font-mono text-slate-400 block">THREAT CLASSIFICATION</span>
                    <span className="text-lg font-bold text-white">{selectedAlert.threatClass}</span>
                  </div>
                  <div className="text-right">
                    <span className="text-xs font-mono text-slate-400 block">AI CONFIDENCE SCORE</span>
                    <span className="text-xl font-bold font-mono text-blue-400">{selectedAlert.confidence}%</span>
                  </div>
                </div>

                {/* Supporting Telemetry Evidence */}
                <div>
                  <h4 className="text-xs font-mono text-slate-400 uppercase tracking-wider mb-2">Supporting Telemetry Evidence</h4>
                  <div className="p-4 rounded-xl bg-red-950/20 border border-red-500/30 text-xs font-mono text-red-200 leading-relaxed">
                    <AlertTriangle className="w-4 h-4 text-red-400 inline mr-2" />
                    {selectedAlert.evidence}
                  </div>
                </div>

                {/* Key Feature SHAP Attribution */}
                <div>
                  <h4 className="text-xs font-mono text-slate-400 uppercase tracking-wider mb-2">Top Detector Signal</h4>
                  <div className="p-3.5 rounded-xl bg-slate-900 border border-blue-500/30 text-xs font-mono text-blue-300 flex items-center space-x-2">
                    <Sparkles className="w-4 h-4 text-blue-400 shrink-0" />
                    <span>{selectedAlert.shapFeature || selectedAlert.detector_type || 'Detector evidence'}</span>
                  </div>
                </div>

                {/* Passive architecture guarantee */}
                <div>
                  <h4 className="text-xs font-mono text-slate-400 uppercase tracking-wider mb-2">Passive Response Boundary</h4>
                  <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 text-xs text-slate-300 space-y-2">
                    <div className="flex items-center space-x-2 text-emerald-400 font-mono">
                      <CheckCircle className="w-4 h-4" />
                      <span>Read-only / one-way monitoring</span>
                    </div>
                    <p className="text-slate-400 leading-relaxed">RakshaNetra records and surfaces the detection only. It does not decrypt payloads, probe hosts, send mitigation commands, or modify the monitored network.</p>
                  </div>
                </div>

                {/* Raw JSON Payload Record */}
                <div>
                  <div className="flex items-center justify-between mb-2">
                    <h4 className="text-xs font-mono text-slate-400 uppercase tracking-wider">Raw Telemetry JSON</h4>
                    <button
                      onClick={() => handleCopyJson(selectedAlert.rawJson)}
                      className="flex items-center space-x-1 px-2.5 py-1 rounded bg-slate-800 text-slate-300 hover:text-white text-[11px] font-mono border border-slate-700"
                    >
                      {copied ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                      <span>{copied ? 'Copied!' : 'Copy JSON'}</span>
                    </button>
                  </div>
                  <pre className="p-4 rounded-xl bg-[#1C1917] border border-slate-700/80 text-[11px] font-mono text-amber-200/90 overflow-x-auto">
                    {JSON.stringify(selectedAlert.rawJson, null, 2)}
                  </pre>
                </div>

              </div>
            </div>

            {/* Footer */}
            <div className="pt-6 border-t border-slate-800 flex items-center justify-end space-x-3 mt-6">
              <button
                onClick={() => setSelectedAlert(null)}
                className="px-5 py-2.5 rounded-xl text-xs font-semibold bg-slate-800 text-slate-200 hover:bg-slate-700"
              >
                Close Inspector
              </button>
            </div>

          </div>
        </div>
      )}

    </section>
  );
}
