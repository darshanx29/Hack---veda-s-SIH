import React, { useState, useEffect, useRef } from 'react';
import { 
  Play, 
  Pause, 
  RotateCcw, 
  FastForward, 
  FileCode, 
  Terminal, 
  CheckCircle, 
  ShieldAlert, 
  Activity, 
  Zap, 
  Layers,
  Sparkles,
  Cpu
} from 'lucide-react';
import {
  getPcapList,
  startReplaySession,
  controlReplaySession,
  streamReplaySession
} from '../api';

// Fallback labels only (display metadata for the selector); every packet's
// isThreat/threatLabel/confidence in the stream below comes from the
// backend, which for apt29_dns_tunneling / mirai_c2 / syn_flood_ddos is the
// real trained model's own prediction (see app/ml/inference.py) — not a
// client-side coin flip.
const PCAP_META = {
  apt29_dns_tunneling: { name: 'apt29_dns_tunneling_campaign.pcap', size: '142.8 MB', vector: 'DNS Tunneling' },
  mirai_c2: { name: 'mirai_botnet_c2_beacon.pcap', size: '89.4 MB', vector: 'Botnet C2' },
  syn_flood_ddos: { name: 'syn_flood_ddos_10gbps.pcap', size: '512.0 MB', vector: 'DDoS Volumetric' },
  quic_exfil: { name: 'covert_quic_exfil_channel.pcap', size: '64.2 MB', vector: 'TLS/QUIC Anomaly' }
};

export default function TrafficReplay() {
  const [isPlaying, setIsPlaying] = useState(false);
  const [speed, setSpeed] = useState(1);
  const [selectedPcap, setSelectedPcap] = useState('apt29_dns_tunneling');
  const [progress, setProgress] = useState(0);
  const [packetsProcessed, setPacketsProcessed] = useState(0);
  const [threatsCaught, setThreatsCaught] = useState(0);
  const [aiLatencyMs, setAiLatencyMs] = useState(null);
  const [logs, setLogs] = useState([]);
  // Latest concurrent verdict from EVERY loaded model (see
  // app/generators.py::score_all_models_tick), refreshed every packet tick
  // regardless of which single PCAP is selected below — all models monitor
  // at once instead of only the one detector tied to the chosen PCAP.
  const [allModels, setAllModels] = useState([]);
  const [pcaps, setPcaps] = useState([]);
  const [sessionId, setSessionId] = useState(null);
  // Real connection/error state — previously every failure here (backend
  // unreachable, session create failing, the model itself throwing) was
  // silently swallowed by a bare .catch(() => {}), so a broken backend just
  // looked identical to "0 packets, nothing happening" with zero explanation.
  const [connError, setConnError] = useState(null);
  const logContainerRef = useRef(null);
  const cleanupRef = useRef(() => {});

  // Real pcap catalog from the backend (app/data.py PCAPS)
  useEffect(() => {
    getPcapList()
      .then((list) => setPcaps(list.map(p => ({ ...p, ...PCAP_META[p.id] }))))
      .catch((err) => {
        console.error('getPcapList failed, falling back to static labels:', err);
        setPcaps(Object.entries(PCAP_META).map(([id, meta]) => ({ id, ...meta })));
        setConnError(`Could not reach the backend for the pcap list (${err.message || err}). Showing static labels only — the replay controls below likely won't work until the backend is reachable.`);
      });
  }, []);

  // Open a fresh replay session (server-side) whenever the pcap changes,
  // and subscribe to its real packet stream.
  useEffect(() => {
    let cancelled = false;
    cleanupRef.current();
    setLogs([]);
    setAllModels([]);
    setProgress(0);
    setPacketsProcessed(0);
    setThreatsCaught(0);
    setSessionId(null);
    setConnError(null);

    startReplaySession(selectedPcap)
      .then((session) => {
        if (cancelled) return;
        setSessionId(session.id);
        const stop = streamReplaySession(
          session.id,
          ({ packet, session: s }) => {
            setLogs(prev => [...prev.slice(-40), packet]);
            if (packet.allModels) setAllModels(packet.allModels);
            setPacketsProcessed(s.packetsProcessed);
            setThreatsCaught(s.threatsCaught);
            setProgress(s.progress);
            if (s.latencyMs != null) setAiLatencyMs(s.latencyMs);
            if (!s.playing) setIsPlaying(false);
          },
          (fatalError) => {
            // A real model-scoring exception on the backend — shown verbatim
            // instead of the stream just going quiet forever.
            console.error('Replay backend model error:', fatalError);
            setConnError(`Model error while scoring "${fatalError.pcap_id}": ${fatalError.message}`);
            setIsPlaying(false);
          },
          () => {
            setConnError(prev => prev || 'Lost connection to the replay stream (backend unreachable or crashed). Check the backend terminal for a traceback.');
          }
        );
        cleanupRef.current = stop;
      })
      .catch((err) => {
        if (cancelled) return;
        console.error('startReplaySession failed:', err);
        setConnError(`Could not start a replay session (${err.message || err}). Is the backend running and reachable at the configured API_BASE?`);
      });

    return () => {
      cancelled = true;
      cleanupRef.current();
    };
  }, [selectedPcap]);

  // Auto-scroll log container directly (prevents layout thrashing & scrollIntoView page lag)
  useEffect(() => {
    if (logContainerRef.current) {
      logContainerRef.current.scrollTop = logContainerRef.current.scrollHeight;
    }
  }, [logs]);

  const sendControl = (action, nextSpeed) => {
    if (!sessionId) {
      setConnError('No active replay session yet — the backend call to create one may have failed. See the error banner above.');
      return;
    }
    controlReplaySession(sessionId, action, nextSpeed).catch((err) => {
      console.error('controlReplaySession failed:', err);
      setConnError(`Control request (${action}) failed: ${err.message || err}`);
    });
  };

  const togglePlay = () => {
    const next = !isPlaying;
    setIsPlaying(next);
    sendControl(next ? 'play' : 'pause');
  };

  const handleRestart = () => {
    setProgress(0);
    setPacketsProcessed(0);
    setThreatsCaught(0);
    setLogs([]);
    setIsPlaying(true);
    sendControl('restart');
  };

  const changeSpeed = (s) => {
    setSpeed(s);
    sendControl(isPlaying ? 'play' : 'pause', s);
  };

  return (
    <section className="py-20 relative bg-[#FAF8F5] border-t border-b border-slate-200">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 relative z-10">
        
        {/* Section Header */}
        <div className="flex flex-col md:flex-row md:items-end justify-between mb-10">
          <div>
            <div className="inline-flex items-center space-x-2 text-xs font-mono text-teal-700 mb-2 font-semibold">
              <Terminal className="w-3.5 h-3.5 text-teal-600" />
              <span>PASSIVE TRAFFIC SIMULATION & TESTING</span>
            </div>
            <h2 className="text-3xl sm:text-4xl font-extrabold text-stone-900 tracking-tight">
              Traffic Replay & <span className="gradient-text-blue">PCAP Forensics</span>
            </h2>
            <p className="mt-2 text-stone-600 text-sm sm:text-base max-w-2xl">
              Replay historical attack PCAPs over the passive tap engine to benchmark AI detection model accuracy and real-time detection latencies.
            </p>
          </div>

          {/* PCAP File Selector */}
          <div className="mt-4 md:mt-0 flex items-center space-x-2">
            <span className="text-xs font-mono text-stone-600 font-medium">PCAP Trace:</span>
            <select
              value={selectedPcap}
              onChange={(e) => setSelectedPcap(e.target.value)}
              className="bg-white text-stone-800 border border-stone-300 rounded-xl px-3 py-2 text-xs font-mono focus:outline-none focus:border-indigo-500 shadow-2xs cursor-pointer"
            >
              {pcaps.map(p => (
                <option key={p.id} value={p.id}>
                  {p.name} ({p.size})
                </option>
              ))}
            </select>
          </div>
        </div>

        {/* All-Model Concurrent Monitor — every loaded detector's live verdict,
            refreshed on every packet tick regardless of which single PCAP is
            selected below. Sits at the top so the combined output from all
            models is the first thing visible, instead of only the one
            detector tied to whichever PCAP happens to be chosen. */}
        <div className="glass-card rounded-2xl p-5 border border-stone-200/90 mb-6 shadow-xs">
          <div className="flex items-center justify-between mb-4">
            <div className="flex items-center space-x-2">
              <Cpu className="w-4 h-4 text-indigo-600" />
              <span className="text-sm font-semibold text-stone-800">All-Model Concurrent Monitor</span>
            </div>
            <span className="text-[11px] font-mono text-stone-500">
              {allModels.filter(m => m.available).length}/{allModels.length || 4} models scoring every tick
            </span>
          </div>

          {allModels.length === 0 ? (
            <p className="text-xs font-mono text-stone-400">
              No ticks yet — start the replay to see every model's live verdict here at once.
            </p>
          ) : (
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
              {allModels.map((m) => (
                <div
                  key={m.model}
                  className={`rounded-xl border p-3 flex flex-col gap-1 ${
                    !m.available
                      ? 'bg-stone-50 border-stone-200 opacity-60'
                      : m.isThreat
                      ? 'bg-red-50 border-red-200'
                      : 'bg-emerald-50/60 border-emerald-100'
                  }`}
                >
                  <div className="flex items-center justify-between">
                    <span className="text-[11px] font-mono font-semibold text-stone-800">{m.label}</span>
                    <span className={`h-1.5 w-1.5 rounded-full ${
                      !m.available ? 'bg-stone-400' : m.isThreat ? 'bg-red-500 animate-pulse' : 'bg-emerald-500'
                    }`}></span>
                  </div>
                  <span className={`text-xs font-mono font-bold ${
                    !m.available ? 'text-stone-400' : m.isThreat ? 'text-red-700' : 'text-emerald-700'
                  }`}>
                    {!m.available ? 'NOT LOADED' : m.isThreat ? `ALERT (${m.confidence}%)` : `CLEAN (${m.confidence}%)`}
                  </span>
                </div>
              ))}
            </div>
          )}
        </div>

        {/* Top Control Bar Card */}
        <div className="glass-card rounded-2xl p-6 border border-stone-200/90 mb-8 shadow-xs">
          
          <div className="flex flex-wrap items-center justify-between gap-4">
            
            {/* Play/Pause & Restart */}
            <div className="flex items-center space-x-3">
              <button
                onClick={togglePlay}
                className={`p-3.5 rounded-xl font-semibold text-white shadow-md transition-all active:scale-95 flex items-center space-x-2 cursor-pointer ${
                  isPlaying 
                    ? 'bg-amber-600 hover:bg-amber-500 shadow-amber-600/30' 
                    : 'bg-indigo-600 hover:bg-indigo-500 shadow-indigo-600/25'
                }`}
              >
                {isPlaying ? <Pause className="w-5 h-5 text-white" /> : <Play className="w-5 h-5 fill-current text-white" />}
                <span className="text-xs font-mono text-white font-bold">{isPlaying ? 'PAUSE REPLAY' : 'START REPLAY'}</span>
              </button>

              <button
                onClick={handleRestart}
                className="p-3.5 rounded-xl bg-stone-100 text-stone-700 hover:text-stone-900 hover:bg-stone-200 transition-all border border-stone-200 shadow-2xs cursor-pointer"
                title="Restart Replay"
              >
                <RotateCcw className="w-5 h-5" />
              </button>

              {/* Speed multiplier selector */}
              <div className="flex items-center space-x-1 bg-stone-100 p-1 rounded-xl border border-stone-200 shadow-xs">
                {[1, 2, 5, 10].map(s => (
                  <button
                    key={s}
                    onClick={() => changeSpeed(s)}
                    className={`px-2.5 py-1 rounded-lg text-xs font-mono font-semibold transition-all cursor-pointer ${
                      speed === s ? 'bg-indigo-600 text-white shadow-xs' : 'text-stone-600 hover:text-stone-900'
                    }`}
                  >
                    <span className={speed === s ? 'text-white' : ''}>{s}x</span>
                  </button>
                ))}
              </div>
            </div>

            {/* Dynamic Counters */}
            <div className="flex items-center space-x-6 text-xs font-mono">
              <div>
                <span className="text-stone-500 block text-[10px] font-medium">PACKETS PROCESSED</span>
                <span className="text-lg font-bold text-stone-900">{packetsProcessed.toLocaleString()}</span>
              </div>
              <div className="border-l border-stone-200 pl-6">
                <span className="text-stone-500 block text-[10px] font-medium">MALICIOUS FLOWS</span>
                <span className="text-lg font-bold text-red-600">{threatsCaught.toLocaleString()}</span>
              </div>
              <div className="border-l border-stone-200 pl-6 hidden sm:block">
                <span className="text-stone-500 block text-[10px] font-medium">AI LATENCY</span>
                <span className="text-lg font-bold text-emerald-600">
                  {aiLatencyMs != null ? `${aiLatencyMs} ms` : '—'}
                </span>
              </div>
            </div>

          </div>

          {/* Real connection/error banner — replaces the old silent failure
              where a broken backend or model just looked like "0, forever". */}
          {connError && (
            <div className="mt-4 p-3 rounded-xl bg-red-50 border border-red-200 text-xs font-mono text-red-800 flex items-start justify-between gap-3">
              <span>⚠ {connError}</span>
              <button onClick={() => setConnError(null)} className="text-red-400 hover:text-red-700 shrink-0">✕</button>
            </div>
          )}

          {/* Progress Scrubber Bar */}
          <div className="mt-6">
            <div className="flex justify-between text-xs font-mono text-stone-600 mb-1.5 font-medium">
              <span>PCAP Timeline Progress</span>
              <span className="text-indigo-600 font-bold">{progress.toFixed(1)}%</span>
            </div>
            <div className="w-full bg-stone-200 h-2.5 rounded-full overflow-hidden border border-stone-300">
              <div
                className="bg-indigo-600 h-full rounded-full transition-all duration-300 relative"
                style={{ width: `${progress}%` }}
              >
                <div className="absolute right-0 top-0 bottom-0 w-2 bg-white rounded-full opacity-75"></div>
              </div>
            </div>
          </div>

        </div>

        {/* Streaming Live Packet Console Log Feed */}
        <div className="glass-card rounded-2xl p-5 border border-stone-200/90 shadow-xs">
          
          <div className="flex items-center justify-between mb-4">
            <div className="flex items-center space-x-2">
              <Terminal className="w-4 h-4 text-indigo-600" />
              <span className="text-sm font-semibold text-stone-800">Packet Inspection Stream</span>
            </div>
            <div className={`flex items-center space-x-1.5 text-xs font-mono font-medium ${
              connError ? 'text-red-700' : isPlaying ? 'text-emerald-700' : 'text-stone-500'
            }`}>
              <span className={`h-2 w-2 rounded-full ${
                connError ? 'bg-red-500' : isPlaying ? 'bg-emerald-500 animate-pulse' : 'bg-stone-400'
              }`}></span>
              <span>{connError ? 'Error' : isPlaying ? 'Streaming' : 'Paused'}</span>
            </div>
          </div>

          {logs.length === 0 && !connError && (
            <p className="text-xs font-mono text-stone-400 mb-3">
              No packets yet — click "START REPLAY" above to begin scoring real flows.
            </p>
          )}

          {/* Live Packet Stream */}
          <div ref={logContainerRef} className="h-[360px] overflow-y-auto space-y-1.5 pr-1">
            {logs.map((log) => (
              <div
                key={log.id}
                className={`px-4 py-3 rounded-xl flex flex-col sm:flex-row sm:items-center justify-between gap-2 border transition-all ${
                  log.isThreat
                    ? 'bg-red-50 border-red-200'
                    : 'bg-stone-50/80 border-stone-200/80 hover:bg-stone-100/80'
                }`}
              >
                <div className="flex flex-wrap items-center gap-3 text-xs">
                  <span className="text-stone-400 font-mono text-[11px]">{log.time}</span>
                  <span className="px-2 py-0.5 rounded-md bg-indigo-50 text-[10px] font-bold font-mono text-indigo-600 border border-indigo-100">
                    {log.protocol}
                  </span>
                  <span className="text-stone-700 font-mono">
                    {log.src} <span className="text-stone-400">→</span> {log.dst}
                  </span>
                  <span className="text-stone-400 font-mono text-[11px]">({log.len} bytes)</span>
                </div>

                <div className="flex items-center space-x-3 shrink-0">
                  {log.isThreat ? (
                    <span className="flex items-center space-x-1.5 px-2.5 py-1 rounded-lg bg-red-100 border border-red-200 text-red-700 font-bold text-[11px] font-mono">
                      <ShieldAlert className="w-3.5 h-3.5 text-red-500" />
                      <span>{log.threatLabel} ({log.confidence}%)</span>
                    </span>
                  ) : (
                    <span className="flex items-center space-x-1 px-2 py-1 rounded-lg bg-emerald-50 text-emerald-700 text-[11px] font-mono font-medium border border-emerald-100">
                      <CheckCircle className="w-3 h-3 text-emerald-500" />
                      <span>Benign</span>
                    </span>
                  )}
                </div>
              </div>
            ))}
          </div>

        </div>

      </div>
    </section>
  );
}