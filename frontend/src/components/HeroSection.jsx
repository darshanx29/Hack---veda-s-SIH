import React, { useEffect, useRef, useState } from 'react';
import { 
  ArrowRight, 
  ShieldCheck, 
  Activity, 
  Cpu, 
  Zap, 
  Radio, 
  Lock, 
  Flame, 
  Layers,
  Sparkles
} from 'lucide-react';
import { getDashboardStats, streamDashboardStats, getAlerts } from '../api';

export default function HeroSection({ onExplore, onLiveDemo }) {
  const canvasRef = useRef(null);

  // Live dynamic counter stats state — sourced from the backend, which
  // derives threatsDetected from real alerts fired by the loaded ML
  // models (app.ml.alert_store), not a client-side random walk.
  const [stats, setStats] = useState({
    flowsPerSec: 0,
    threatsDetected: 0,
    aiConfidence: 0,
    latency: 0
  });

  // Initial fetch, then subscribe to the server-sent stats stream.
  // Initial fetch, then subscribe to the server-sent stats stream.
  useEffect(() => {
    let cleanup = () => {};
    let cancelled = false;

    getDashboardStats()
      .then((data) => {
        if (!cancelled) setStats(data);
      })
      .catch(() => {});

    cleanup = streamDashboardStats((data) => setStats(data));

    return () => {
      cancelled = true;
      cleanup();
    };
  }, []);

  // Track the previous real poll so the flows/sec badge can show a genuine
  // delta instead of a hardcoded "+4.2%".
  const prevFlowsRef = useRef(null);
  const [flowsDeltaPct, setFlowsDeltaPct] = useState(null);
  const [overallAlertSummary, setOverallAlertSummary] = useState({ total: 0, critical: 0, high: 0, tlsQuic: 0, recon: 0, exfil: 0 });
  const [recentAlerts, setRecentAlerts] = useState([]);

  useEffect(() => {
    const loadAlertSummary = () => {
      getAlerts({ severity: 'All', vector: 'All', minConfidence: 0 }).then((alerts) => {
        setRecentAlerts(alerts.slice(0, 10));
        setOverallAlertSummary({
          total: alerts.length,
          critical: alerts.filter(a => a.severity === 'Critical').length,
          high: alerts.filter(a => a.severity === 'High').length,
          tlsQuic: alerts.filter(a => /TLS|QUIC/i.test(a.threatClass)).length,
          recon: alerts.filter(a => /Reconnaissance|Scan/i.test(a.threatClass)).length,
          exfil: alerts.filter(a => /Exfiltration/i.test(a.threatClass)).length,
        });
      }).catch(() => {});
    };
    loadAlertSummary();
    const interval = setInterval(loadAlertSummary, 5000);
    return () => clearInterval(interval);
  }, []);

  useEffect(() => {
    if (prevFlowsRef.current != null && prevFlowsRef.current > 0) {
      const pct = ((stats.flowsPerSec - prevFlowsRef.current) / prevFlowsRef.current) * 100;
      setFlowsDeltaPct(Math.round(pct * 10) / 10);
    }
    prevFlowsRef.current = stats.flowsPerSec;
  }, [stats.flowsPerSec]);

  // HTML5 Canvas Network Diode & Particle Stream Visualizer
  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext('2d');

    let animationFrameId;
    let width = (canvas.width = canvas.parentElement.clientWidth);
    let height = (canvas.height = canvas.parentElement.clientHeight || 450);

    const handleResize = () => {
      if (!canvas || !canvas.parentElement) return;
      width = canvas.width = canvas.parentElement.clientWidth;
      height = canvas.height = canvas.parentElement.clientHeight || 450;
    };
    window.addEventListener('resize', handleResize);

    const nodeCount = 26;
    const nodes = Array.from({ length: nodeCount }, () => ({
      x: Math.random() * (width * 0.4),
      y: Math.random() * height,
      vx: (Math.random() * 0.8 + 0.3),
      vy: (Math.random() - 0.5) * 0.6,
      radius: Math.random() * 2.5 + 1.5,
      isThreat: Math.random() < 0.15
    }));

    const diodeParticles = [];
    let tick = 0;

    const render = () => {
      tick++;
      ctx.clearRect(0, 0, width, height);

      const diodeX = width * 0.45;

      // 1. Technical Background Grid on Canvas
      ctx.strokeStyle = 'rgba(195, 185, 170, 0.40)';
      ctx.lineWidth = 1;
      const gridSize = 30;
      for (let x = 0; x < width; x += gridSize) {
        ctx.beginPath();
        ctx.moveTo(x, 0);
        ctx.lineTo(x, height);
        ctx.stroke();
      }
      for (let y = 0; y < height; y += gridSize) {
        ctx.beginPath();
        ctx.moveTo(0, y);
        ctx.lineTo(width, y);
        ctx.stroke();
      }

      // 2. Hardware Diode Isolation Line (One-Way Physical Gate)
      ctx.save();
      ctx.beginPath();
      ctx.moveTo(diodeX, 15);
      ctx.lineTo(diodeX, height - 15);
      ctx.strokeStyle = '#4F46E5';
      ctx.lineWidth = 2;
      ctx.setLineDash([6, 6]);
      ctx.stroke();
      ctx.restore();

      // Diode Shield Badge on Canvas
      ctx.fillStyle = '#FFFFFF';
      ctx.strokeStyle = '#4F46E5';
      ctx.lineWidth = 1.5;
      ctx.beginPath();
      ctx.roundRect(diodeX - 52, height / 2 - 16, 104, 32, 6);
      ctx.fill();
      ctx.stroke();

      ctx.fillStyle = '#4F46E5';
      ctx.font = 'bold 10px JetBrains Mono, monospace';
      ctx.textAlign = 'center';
      ctx.fillText('DIODE TAP ➔', diodeX, height / 2 + 4);

      // 3. Spawn flowing data packets continuously
      if (tick % 4 === 0) {
        diodeParticles.push({
          x: 20,
          y: Math.random() * (height - 80) + 40,
          speed: Math.random() * 2.2 + 1.8,
          threat: Math.random() < 0.22,
          size: Math.random() * 2.5 + 2,
          opacity: 1
        });
      }

      // 4. Render network mesh nodes (Left Zone: Passive Mirror Input)
      for (let i = 0; i < nodes.length; i++) {
        const n = nodes[i];
        n.x += n.vx;
        n.y += n.vy;

        if (n.x > diodeX - 10) n.x = 20;
        if (n.y < 10 || n.y > height - 10) n.vy *= -1;

        // Draw node links
        for (let j = i + 1; j < nodes.length; j++) {
          const n2 = nodes[j];
          const dist = Math.hypot(n.x - n2.x, n.y - n2.y);
          if (dist < 90) {
            ctx.beginPath();
            ctx.moveTo(n.x, n.y);
            ctx.lineTo(n2.x, n2.y);
            ctx.strokeStyle = n.isThreat || n2.isThreat
              ? `rgba(220, 38, 38, ${0.45 * (1 - dist / 90)})`
              : `rgba(79, 70, 229, ${0.35 * (1 - dist / 90)})`;
            ctx.lineWidth = 1;
            ctx.stroke();
          }
        }

        // Draw node
        ctx.beginPath();
        ctx.arc(n.x, n.y, n.radius, 0, Math.PI * 2);
        ctx.fillStyle = n.isThreat ? '#DC2626' : '#4F46E5';
        ctx.fill();
      }

      // 5. Data Flow Particles crossing Diode into Engine Hub (Right Zone)
      for (let p = diodeParticles.length - 1; p >= 0; p--) {
        const particle = diodeParticles[p];
        particle.x += particle.speed;

        const targetY = height / 2 + Math.sin(particle.x * 0.02) * 50;
        particle.y += (targetY - particle.y) * 0.025;

        const crossedDiode = particle.x > diodeX;
        const color = particle.threat ? '#DC2626' : (crossedDiode ? '#D96B43' : '#4F46E5');

        ctx.beginPath();
        ctx.arc(particle.x, particle.y, particle.size, 0, Math.PI * 2);
        ctx.fillStyle = color;
        ctx.fill();

        // Laser beam line
        ctx.beginPath();
        ctx.moveTo(particle.x, particle.y);
        ctx.lineTo(particle.x - particle.speed * 4, particle.y);
        ctx.strokeStyle = particle.threat ? 'rgba(220, 38, 38, 0.45)' : 'rgba(217, 107, 67, 0.35)';
        ctx.lineWidth = 1.5;
        ctx.stroke();

        if (particle.x > width - 35) {
          diodeParticles.splice(p, 1);
        }
      }

      // 6. AI Classifier Engine Node (Right side target)
      const aiHubX = width * 0.85;
      const aiHubY = height / 2;

      ctx.beginPath();
      ctx.arc(aiHubX, aiHubY, 30, 0, Math.PI * 2);
      ctx.fillStyle = '#FFFFFF';
      ctx.strokeStyle = '#0D9488';
      ctx.lineWidth = 2;
      ctx.fill();
      ctx.stroke();

      ctx.beginPath();
      ctx.arc(aiHubX, aiHubY, 38 + Math.sin(tick * 0.05) * 3, 0, Math.PI * 2);
      ctx.strokeStyle = 'rgba(13, 148, 136, 0.28)';
      ctx.lineWidth = 1;
      ctx.stroke();

      ctx.fillStyle = '#1C1917';
      ctx.font = 'bold 11px Outfit, sans-serif';
      ctx.textAlign = 'center';
      ctx.fillText('AI ENGINE', aiHubX, aiHubY - 3);
      ctx.fillStyle = '#0D9488';
      ctx.font = '9px JetBrains Mono, monospace';
      ctx.fillText('SPECTRA V4', aiHubX, aiHubY + 10);

      animationFrameId = requestAnimationFrame(render);
    };

    render();

    return () => {
      cancelAnimationFrame(animationFrameId);
      window.removeEventListener('resize', handleResize);
    };
  }, []);

  return (
    <section className="relative pt-12 pb-20 overflow-hidden bg-radial-hero">
      
      {/* Background Lighting */}
      <div className="absolute top-1/4 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[700px] h-[380px] bg-amber-500/10 blur-[140px] rounded-full pointer-events-none"></div>

      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 relative z-10">
        
        {/* Main Grid: Headline Left + Visualization Right */}
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-12 items-center">
          
          {/* Left Column: Hero Text & CTAs */}
          <div className="lg:col-span-7 space-y-6">
            
            {/* Tagline */}
            <div className="inline-flex items-center space-x-2 px-3.5 py-1.5 rounded-md bg-stone-100 border border-stone-200 text-xs font-mono text-indigo-700 font-medium shadow-xs">
              <span className="flex h-2 w-2 rounded-full bg-indigo-500 animate-ping"></span>
              <Sparkles className="w-3.5 h-3.5 text-indigo-600" />
              <span>AIR-GAPPED THREAT CLASSIFIER 4.0</span>
            </div>

            {/* Main Headline */}
            <h1 className="text-4xl sm:text-5xl lg:text-6xl font-extrabold tracking-tight text-stone-900 leading-[1.1]">
              AI-Powered Threat Detection for <span className="gradient-text-hero">One-Way Traffic</span>
            </h1>

            {/* Subtext */}
            <p className="text-base sm:text-lg text-stone-600 font-normal leading-relaxed max-w-2xl">
              Detect, classify and score cyber threats from passive network traffic in near real time — without contacting or modifying the monitored network.
            </p>

            {/* Action Buttons */}
            <div className="flex flex-wrap items-center gap-4 pt-2">
              
              {/* Explore Platform */}
              <button
                onClick={onExplore}
                className="px-7 py-3.5 rounded-xl font-semibold text-sm bg-indigo-600 hover:bg-indigo-500 text-white shadow-lg shadow-indigo-600/25 transition-all duration-200 flex items-center space-x-2 active:scale-95 cursor-pointer"
              >
                <span className="text-white">Explore Platform</span>
                <ArrowRight className="w-4 h-4 text-white" />
              </button>

              {/* View Live Demo */}
              <button
                onClick={onLiveDemo}
                className="px-7 py-3.5 rounded-xl font-semibold text-sm bg-white hover:bg-stone-50 text-stone-800 border border-stone-300 shadow-sm transition-all duration-200 flex items-center space-x-2 active:scale-95 cursor-pointer"
              >
                <Radio className="w-4 h-4 text-indigo-600 animate-pulse" />
                <span>View Live Console</span>
              </button>

            </div>

            {/* Security Assurance Badges */}
            <div className="pt-6 border-t border-stone-200 grid grid-cols-3 gap-4 text-xs font-mono text-stone-600">
              <div className="flex items-center space-x-2">
                <ShieldCheck className="w-4 h-4 text-indigo-600" />
                <span className="text-stone-700 font-medium">100% Passive Tap</span>
              </div>
              <div className="flex items-center space-x-2">
                <Lock className="w-4 h-4 text-emerald-600" />
                <span className="text-stone-700 font-medium">Zero Tx Footprint</span>
              </div>
              <div className="flex items-center space-x-2">
                <Cpu className="w-4 h-4 text-amber-600" />
                <span className="text-stone-700 font-medium">Sub-ms Inference</span>
              </div>
            </div>

          </div>

          {/* Right Column */}
          <div className="lg:col-span-5 relative">
          </div>

        </div>

        {/* Overall Alert Posture — complete backend alert feed, independent of table filters */}
        <div className="mt-12 glass-card rounded-2xl p-5 border border-stone-200/90 shadow-xs">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
            <div>
              <p className="text-[10px] font-mono text-red-700 uppercase tracking-wider font-bold">OVERALL ALERT POSTURE</p>
              <p className="text-sm text-stone-600 mt-1">All detected threat classes from the passive backend alert store.</p>
            </div>
            <div className="flex flex-wrap gap-2 text-[10px] font-mono font-semibold">
              <span className="px-2.5 py-1 rounded-lg bg-stone-100 border border-stone-200">TOTAL {overallAlertSummary.total}</span>
              <span className="px-2.5 py-1 rounded-lg bg-red-50 text-red-700 border border-red-200">CRITICAL {overallAlertSummary.critical}</span>
              <span className="px-2.5 py-1 rounded-lg bg-orange-50 text-orange-700 border border-orange-200">HIGH {overallAlertSummary.high}</span>
              <span className="px-2.5 py-1 rounded-lg bg-blue-50 text-blue-700 border border-blue-200">TLS/QUIC {overallAlertSummary.tlsQuic}</span>
              <span className="px-2.5 py-1 rounded-lg bg-indigo-50 text-indigo-700 border border-indigo-200">RECON {overallAlertSummary.recon}</span>
              <span className="px-2.5 py-1 rounded-lg bg-teal-50 text-teal-700 border border-teal-200">EXFIL {overallAlertSummary.exfil}</span>
            </div>
          </div>
        </div>

        {/* Live Threat Intelligence KPI Cards */}
        <div className="mt-6 grid grid-cols-2 md:grid-cols-4 gap-4 sm:gap-6">
          
          {/* Card 1: Flows/sec */}
          <div className="glass-card glass-card-hover p-5 rounded-2xl relative overflow-hidden">
            <div className="absolute top-0 right-0 p-4 opacity-15">
              <Activity className="w-10 h-10 text-indigo-600" />
            </div>
            <p className="text-xs font-mono text-stone-600 uppercase tracking-wider font-semibold">FLOWS / SEC</p>
            <div className="mt-2 flex items-baseline space-x-2">
              <span className="text-2xl sm:text-3xl font-extrabold font-mono text-stone-900 tracking-tight">
                {stats.flowsPerSec.toLocaleString()}
              </span>
              {flowsDeltaPct != null && (
                <span className={`text-xs font-mono font-semibold ${flowsDeltaPct >= 0 ? 'text-emerald-700' : 'text-red-700'}`}>
                  {flowsDeltaPct >= 0 ? '+' : ''}{flowsDeltaPct}%
                </span>
              )}
            </div>
            <div className="mt-3 w-full bg-stone-200 h-1.5 rounded-full overflow-hidden">
              <div
                className="bg-indigo-600 h-full animate-pulse"
                style={{ width: `${Math.min(100, Math.round((stats.flowsPerSec / 50) * 100))}%` }}
              ></div>
            </div>
          </div>

          {/* Card 2: Threats Detected */}
          <div className="glass-card glass-card-hover p-5 rounded-2xl relative overflow-hidden">
            <div className="absolute top-0 right-0 p-4 opacity-15">
              <Flame className="w-10 h-10 text-red-600" />
            </div>
            <p className="text-xs font-mono text-stone-600 uppercase tracking-wider font-semibold">THREATS DETECTED</p>
            <div className="mt-2 flex items-baseline space-x-2">
              <span className="text-2xl sm:text-3xl font-extrabold font-mono text-stone-900 tracking-tight">
                {stats.threatsDetected.toLocaleString()}
              </span>
              <span className="text-xs font-mono text-red-700 font-semibold">SINCE STARTUP</span>
            </div>
            <div className="mt-3 w-full bg-stone-200 h-1.5 rounded-full overflow-hidden">
              <div
                className="bg-red-600 h-full"
                style={{ width: `${Math.min(100, Math.round((stats.threatsDetected / 20) * 100))}%` }}
              ></div>
            </div>
          </div>

          {/* Card 3: AI Confidence */}
          <div className="glass-card glass-card-hover p-5 rounded-2xl relative overflow-hidden">
            <div className="absolute top-0 right-0 p-4 opacity-15">
              <Cpu className="w-10 h-10 text-teal-600" />
            </div>
            <p className="text-xs font-mono text-stone-600 uppercase tracking-wider font-semibold">AI CONFIDENCE (LIVE AVG)</p>
            <div className="mt-2 flex items-baseline space-x-2">
              <span className="text-2xl sm:text-3xl font-extrabold font-mono text-stone-900 tracking-tight">
                {stats.aiConfidence}%
              </span>
              <span className="text-xs font-mono text-teal-700 font-semibold">
                {stats.aiConfidence > 0 ? 'REAL MODEL OUTPUT' : 'NO DATA YET'}
              </span>
            </div>
            <div className="mt-3 w-full bg-stone-200 h-1.5 rounded-full overflow-hidden">
              <div
                className="bg-teal-600 h-full"
                style={{ width: `${Math.min(100, stats.aiConfidence)}%` }}
              ></div>
            </div>
          </div>

          {/* Card 4: Detection Latency */}
          <div className="glass-card glass-card-hover p-5 rounded-2xl relative overflow-hidden">
            <div className="absolute top-0 right-0 p-4 opacity-15">
              <Zap className="w-10 h-10 text-amber-600" />
            </div>
            <p className="text-xs font-mono text-stone-600 uppercase tracking-wider font-semibold">DETECTION LATENCY</p>
            <div className="mt-2 flex items-baseline space-x-2">
              <span className="text-2xl sm:text-3xl font-extrabold font-mono text-stone-900 tracking-tight">
                {stats.latency} <span className="text-sm text-stone-500">ms</span>
              </span>
              <span className="text-xs font-mono text-emerald-700 font-semibold">
                {stats.latency > 0 ? 'MEASURED INFERENCE' : 'AWAITING FIRST SCORE'}
              </span>
            </div>
            <div className="mt-3 w-full bg-stone-200 h-1.5 rounded-full overflow-hidden">
              <div
                className="bg-emerald-600 h-full"
                style={{ width: `${stats.latency > 0 ? Math.max(5, 100 - Math.min(100, (stats.latency / 20) * 100)) : 0}%` }}
              ></div>
            </div>
          </div>

        </div>

        {/* Recent attack intelligence — endpoint-level detail, not just a count */}
        <div className="mt-6 glass-card rounded-2xl border border-stone-200/90 overflow-hidden shadow-xs">
          <div className="px-5 py-4 border-b border-stone-200 flex flex-col sm:flex-row sm:items-center justify-between gap-2">
            <div>
              <p className="text-[10px] font-mono text-red-700 uppercase tracking-wider font-bold">LIVE ATTACK INTELLIGENCE</p>
              <p className="text-sm text-stone-600 mt-1">Who is communicating with whom, what attack was detected, and why.</p>
            </div>
            <span className="text-[10px] font-mono text-stone-500">{recentAlerts.length} recent alert(s)</span>
          </div>
          <div className="overflow-x-auto">
            <table className="w-full text-left">
              <thead className="bg-stone-100/90 text-[10px] font-mono uppercase tracking-wider text-stone-500">
                <tr>
                  <th className="px-4 py-3">Time</th>
                  <th className="px-4 py-3">Attacker / Source</th>
                  <th className="px-4 py-3">Target</th>
                  <th className="px-4 py-3">Attack Type</th>
                  <th className="px-4 py-3">Severity</th>
                  <th className="px-4 py-3">Confidence</th>
                  <th className="px-4 py-3">Evidence</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-stone-200 text-xs font-mono">
                {recentAlerts.length === 0 ? (
                  <tr><td colSpan="7" className="px-4 py-8 text-center text-stone-500">No detections yet. Start a replay or send passive flow metadata to /api/ingest/flow.</td></tr>
                ) : recentAlerts.map((alert) => (
                  <tr key={alert.id} className="hover:bg-stone-50">
                    <td className="px-4 py-3 text-stone-500 whitespace-nowrap">{alert.timestamp}</td>
                    <td className="px-4 py-3 text-stone-800 font-semibold">
                      {alert.srcIp}
                      <span className="block text-[10px] text-stone-500">:{alert.srcPort}</span>
                    </td>
                    <td className="px-4 py-3 text-stone-800 font-semibold">
                      {alert.dstIp}
                      <span className="block text-[10px] text-stone-500">:{alert.dstPort}</span>
                    </td>
                    <td className="px-4 py-3 text-stone-800">
                      <span className="font-semibold">{alert.threatClass}</span>
                      <span className="block text-[9px] uppercase text-stone-500">{alert.protocol} · {alert.detector_type === 'rule_based' ? 'metadata' : 'ML'}</span>
                    </td>
                    <td className="px-4 py-3"><span className={`px-2 py-1 rounded ${alert.badgeClass}`}>{alert.severity}</span></td>
                    <td className="px-4 py-3 text-indigo-700 font-bold">{alert.confidence}%</td>
                    <td className="px-4 py-3 text-stone-600 max-w-[320px]"><div className="truncate" title={alert.evidence}>{alert.evidence}</div></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>

      </div>
    </section>
  );
}
