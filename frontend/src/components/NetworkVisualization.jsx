import React, { useState, useEffect, useRef } from 'react';
import { 
  GitFork, 
  ShieldAlert, 
  CheckCircle2, 
  AlertTriangle, 
  Activity, 
  Filter, 
  Server, 
  ArrowRight,
  Info,
  X,
  Lock,
  Layers
} from 'lucide-react';
import { getNetworkTopology } from '../api';

export default function NetworkVisualization({ onInspectNodeAlerts }) {
  const [selectedNode, setSelectedNode] = useState(null);
  const [filterMode, setFilterMode] = useState('all'); // 'all', 'suspicious', 'safe'
  const [hasData, setHasData] = useState(false);

  const canvasRef = useRef(null);

  // Real topology: nodes/edges built strictly from srcIp/dstIp that have
  // actually appeared in a model-fired alert (app.ml.alert_store), via
  // app/routes/network.py. There's no CMDB in this project, so there are
  // no invented machine names or risk scores — if no model has fired yet,
  // this is empty and the UI says so instead of showing a fake topology.
  const [rawNodes, setRawNodes] = useState([]);
  const [edges, setEdges] = useState([]);

  useEffect(() => {
    const load = () => {
      getNetworkTopology(filterMode)
        .then((data) => {
          setHasData(data.hasData);
          setEdges(data.edges);

          // Lay out nodes: Source zone on the left, Destination zone on
          // the right, evenly spaced vertically within each zone.
          const sources = data.nodes.filter(n => n.zone === 'Source');
          const dests = data.nodes.filter(n => n.zone === 'Destination');
          const positioned = [
            ...sources.map((n, i) => ({
              ...n,
              x: 0.18,
              y: (i + 1) / (sources.length + 1),
            })),
            ...dests.map((n, i) => ({
              ...n,
              x: 0.82,
              y: (i + 1) / (dests.length + 1),
            })),
          ];
          setRawNodes(positioned);
        })
        .catch(() => {});
    };
    load();
    const interval = setInterval(load, 8000);
    return () => clearInterval(interval);
  }, [filterMode]);

  const nodes = rawNodes;

  // Interactive HTML5 Canvas Renderer for Network Topology Graph
  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext('2d');

    let animId;
    let w = (canvas.width = canvas.parentElement.clientWidth);
    let h = (canvas.height = canvas.parentElement.clientHeight || 500);

    const handleResize = () => {
      if (!canvas || !canvas.parentElement) return;
      w = canvas.width = canvas.parentElement.clientWidth;
      h = canvas.height = canvas.parentElement.clientHeight || 500;
    };
    window.addEventListener('resize', handleResize);

    let frame = 0;

    const render = () => {
      frame++;
      ctx.clearRect(0, 0, w, h);

      // Background Zone Column Lines & Labels
      const zoneLeft = w * 0.18;
      const zoneRight = w * 0.82;

      // Draw Zone Partition Divider
      ctx.strokeStyle = 'rgba(195, 185, 170, 0.5)';
      ctx.lineWidth = 1;
      ctx.setLineDash([4, 4]);
      ctx.beginPath();
      ctx.moveTo(w * 0.5, 20);
      ctx.lineTo(w * 0.5, h - 20);
      ctx.stroke();
      ctx.setLineDash([]); // reset

      // Draw Zone Headings — real IPs come from actual model-fired alerts
      ctx.font = 'bold 11px JetBrains Mono, monospace';
      ctx.textAlign = 'center';
      ctx.fillStyle = '#665E55';
      ctx.fillText('SOURCE IPs (REAL ALERTS)', zoneLeft, 30);
      ctx.fillStyle = '#0D9488';
      ctx.fillText('DESTINATION IPs (REAL ALERTS)', zoneRight, 30);

      if (nodes.length === 0) {
        ctx.font = '12px Outfit, sans-serif';
        ctx.fillStyle = '#928A7E';
        ctx.fillText('No detections yet — start a replay session to populate this graph.', w / 2, h / 2);
      }

      // Map Node positions to pixel values
      const mappedNodes = nodes.map(n => ({
        ...n,
        px: n.x * w,
        py: n.y * h
      }));

      // Filter Nodes
      const visibleNodes = mappedNodes.filter(n => {
        if (filterMode === 'suspicious') return n.status === 'suspicious' || n.status === 'malicious';
        if (filterMode === 'safe') return n.status === 'safe';
        return true;
      });

      // 1. Draw Edges / Flow Lines
      edges.forEach(e => {
        const fromNode = mappedNodes.find(n => n.id === e.from);
        const toNode = mappedNodes.find(n => n.id === e.to);
        if (!fromNode || !toNode) return;

        const isHighlighted = e.malicious;

        // Draw line curve
        ctx.beginPath();
        ctx.moveTo(fromNode.px, fromNode.py);
        
        const cp1x = (fromNode.px + toNode.px) / 2;
        const cp1y = fromNode.py;
        const cp2x = (fromNode.px + toNode.px) / 2;
        const cp2y = toNode.py;

        ctx.bezierCurveTo(cp1x, cp1y, cp2x, cp2y, toNode.px, toNode.py);

        ctx.strokeStyle = isHighlighted ? 'rgba(220, 38, 38, 0.5)' : 'rgba(79, 70, 229, 0.28)';
        ctx.lineWidth = isHighlighted ? 2.5 : 1.5;
        ctx.stroke();

        // Draw animated data flow pulse along line
        const progress = ((frame * 1.5 + (fromNode.px * 0.5)) % 100) / 100;
        const pulseX = fromNode.px + (toNode.px - fromNode.px) * progress;
        const pulseY = fromNode.py + (toNode.py - fromNode.py) * progress;

        ctx.beginPath();
        ctx.arc(pulseX, pulseY, isHighlighted ? 3.5 : 2.5, 0, Math.PI * 2);
        ctx.fillStyle = isHighlighted ? '#DC2626' : '#4F46E5';
        ctx.fill();
      });

      // 2. Draw Nodes
      visibleNodes.forEach(n => {
        const isMalicious = n.status === 'malicious';
        const isSuspicious = n.status === 'suspicious';
        const isDiode = n.zone === 'Diode';

        // Outer Ring for Malicious/Suspicious Nodes
        if (isMalicious || isSuspicious) {
          ctx.beginPath();
          ctx.arc(n.px, n.py, 20 + Math.sin(frame * 0.08) * 3, 0, Math.PI * 2);
          ctx.strokeStyle = isMalicious ? 'rgba(239, 68, 68, 0.5)' : 'rgba(249, 115, 22, 0.5)';
          ctx.lineWidth = 2;
          ctx.stroke();
        }

        // Main Node Body Circle
        ctx.beginPath();
        ctx.arc(n.px, n.py, isDiode ? 16 : 13, 0, Math.PI * 2);
        ctx.fillStyle = isMalicious 
          ? '#DC2626' 
          : isSuspicious 
            ? '#EA580C' 
            : isDiode 
              ? '#4F46E5' 
              : '#FFFFFF';
        ctx.strokeStyle = isDiode ? '#4F46E5' : (isMalicious ? '#DC2626' : '#E4DED4');
        ctx.lineWidth = 2;
        ctx.fill();
        ctx.stroke();

        // Node Inner Dot
        ctx.beginPath();
        ctx.arc(n.px, n.py, 3.5, 0, Math.PI * 2);
        ctx.fillStyle = isDiode ? '#FFFFFF' : '#4F46E5';
        ctx.fill();

        // Label below node
        ctx.font = '10px Outfit, sans-serif';
        ctx.fillStyle = n.id === selectedNode?.id ? '#4F46E5' : '#1C1917';
        ctx.textAlign = 'center';
        ctx.fillText(n.name, n.px, n.py + 24);

        ctx.font = '9px JetBrains Mono, monospace';
        ctx.fillStyle = '#665E55';
        ctx.fillText(n.ip, n.px, n.py + 36);

        if (n.risk > 0) {
          ctx.font = 'bold 9px JetBrains Mono, monospace';
          ctx.fillStyle = isMalicious ? '#DC2626' : '#EA580C';
          ctx.fillText(`RISK ${n.risk}%`, n.px, n.py - 18);
        }
      });

      animId = requestAnimationFrame(render);
    };

    render();

    return () => {
      cancelAnimationFrame(animId);
      window.removeEventListener('resize', handleResize);
    };
  }, [filterMode, selectedNode]);

  // Handle canvas click to select node
  const handleCanvasClick = (e) => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const rect = canvas.getBoundingClientRect();
    const clickX = e.clientX - rect.left;
    const clickY = e.clientY - rect.top;

    const w = canvas.width;
    const h = canvas.height;

    const hitNode = nodes.find(n => {
      const px = n.x * w;
      const py = n.y * h;
      const dist = Math.hypot(clickX - px, clickY - py);
      return dist <= 24;
    });

    if (hitNode) {
      setSelectedNode(hitNode);
    } else {
      setSelectedNode(null);
    }
  };

  return (
    <section className="py-20 relative bg-[#F3EFE8] border-t border-b border-slate-200">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 relative z-10">
        
        {/* Section Header */}
        <div className="flex flex-col md:flex-row md:items-end justify-between mb-8">
          <div>
            <div className="inline-flex items-center space-x-2 text-xs font-mono text-indigo-700 mb-2 font-semibold">
              <GitFork className="w-3.5 h-3.5 text-indigo-600" />
              <span>PASSIVE NETWORK TOPOLOGY MAPPING</span>
            </div>
            <h2 className="text-3xl sm:text-4xl font-extrabold text-stone-900 tracking-tight">
              One-Way Traffic <span className="gradient-text-blue">Flow Topology</span>
            </h2>
            <p className="mt-2 text-stone-600 text-sm sm:text-base max-w-2xl">
              Source → Hardware Diode Flow → Destination security enclave. Suspicious nodes highlighted with real-time risk scores.
            </p>
          </div>

          {/* Filter Controls */}
          <div className="mt-4 md:mt-0 flex items-center space-x-2 bg-stone-100 p-1.5 rounded-xl border border-stone-200 shadow-xs">
            <Filter className="w-4 h-4 text-stone-500 ml-2" />
            <button
              onClick={() => setFilterMode('all')}
              className={`px-3 py-1.5 rounded-lg text-xs font-mono font-semibold transition-all cursor-pointer ${
                filterMode === 'all' ? 'bg-indigo-600 text-white font-semibold shadow-xs' : 'text-stone-600 hover:text-stone-900'
              }`}
            >
              <span className={filterMode === 'all' ? 'text-white' : ''}>All Nodes</span>
            </button>
            <button
              onClick={() => setFilterMode('suspicious')}
              className={`px-3 py-1.5 rounded-lg text-xs font-mono font-semibold transition-all cursor-pointer ${
                filterMode === 'suspicious' ? 'bg-red-600 text-white font-semibold shadow-xs' : 'text-stone-600 hover:text-stone-900'
              }`}
            >
              <span className={filterMode === 'suspicious' ? 'text-white' : ''}>Suspicious Only</span>
            </button>
            <button
              onClick={() => setFilterMode('safe')}
              className={`px-3 py-1.5 rounded-lg text-xs font-mono font-semibold transition-all cursor-pointer ${
                filterMode === 'safe' ? 'bg-emerald-600 text-white font-semibold shadow-xs' : 'text-stone-600 hover:text-stone-900'
              }`}
            >
              <span className={filterMode === 'safe' ? 'text-white' : ''}>Safe Only</span>
            </button>
          </div>
        </div>

        {/* Canvas Graph Box */}
        <div className="glass-card rounded-2xl p-4 border border-slate-800 relative overflow-hidden shadow-2xl">
          
          {/* Status bar top */}
          <div className="flex items-center justify-between px-4 py-2 bg-slate-950 rounded-xl border border-slate-800 mb-3 text-xs font-mono">
            <div className="flex items-center space-x-4">
              <span className="flex items-center space-x-1.5 text-slate-300">
                <span className="w-2.5 h-2.5 rounded-full bg-red-500"></span>
                <span>Malicious Node</span>
              </span>
              <span className="flex items-center space-x-1.5 text-slate-300">
                <span className="w-2.5 h-2.5 rounded-full bg-orange-500"></span>
                <span>Suspicious Node</span>
              </span>
            </div>

            <span className="hidden sm:inline">
              {hasData
                ? 'Click any node to inspect flow metrics & forensic trace.'
                : 'No real detections yet — start a replay session to populate this graph.'}
            </span>
          </div>

          {/* Canvas Topology Frame */}
          <div className="w-full h-[480px] bg-[#F5F1E9] rounded-xl relative cursor-pointer overflow-hidden border border-slate-200">
            <canvas
              ref={canvasRef}
              onClick={handleCanvasClick}
              className="w-full h-full block"
            ></canvas>
          </div>

        </div>

      </div>

      {/* Selected Node Inspection Modal / Drawer */}
      {selectedNode && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/75 backdrop-blur-md animate-in fade-in">
          <div className="glass-panel w-full max-w-lg rounded-2xl p-6 border border-slate-700 shadow-2xl relative">
            <button
              onClick={() => setSelectedNode(null)}
              className="absolute top-4 right-4 p-2 rounded-lg bg-slate-800 text-slate-400 hover:text-white"
            >
              <X className="w-5 h-5" />
            </button>

            <div className="flex items-center space-x-3 mb-4">
              <div className={`w-12 h-12 rounded-xl flex items-center justify-center font-bold text-white ${
                selectedNode.status === 'malicious' ? 'bg-red-500' : selectedNode.status === 'suspicious' ? 'bg-orange-500' : 'bg-blue-600'
              }`}>
                {selectedNode.status === 'malicious' ? <ShieldAlert className="w-6 h-6" /> : <Server className="w-6 h-6" />}
              </div>
              <div>
                <h3 className="text-xl font-bold text-white">{selectedNode.name}</h3>
                <p className="text-xs font-mono text-slate-400">IP: {selectedNode.ip} | Zone: {selectedNode.zone}</p>
              </div>
            </div>

            <div className="space-y-3 text-xs font-mono bg-slate-950 p-4 rounded-xl border border-slate-800 mb-6">
              <div className="flex justify-between py-1 border-b border-slate-800">
                <span className="text-slate-400">Threat Status:</span>
                <span className={`font-bold ${
                  selectedNode.status === 'malicious' ? 'text-red-400' : selectedNode.status === 'suspicious' ? 'text-orange-400' : 'text-emerald-400'
                }`}>
                  {selectedNode.status.toUpperCase()}
                </span>
              </div>
              <div className="flex justify-between py-1 border-b border-slate-800">
                <span className="text-slate-400">AI Risk Score:</span>
                <span className="text-white font-bold">{selectedNode.risk}%</span>
              </div>
              {selectedNode.threatType && (
                <div className="flex justify-between py-1">
                  <span className="text-slate-400">Flagged Threat Vector:</span>
                  <span className="text-red-400 font-semibold">{selectedNode.threatType}</span>
                </div>
              )}
            </div>

            <div className="flex items-center justify-end space-x-3">
              <button
                onClick={() => setSelectedNode(null)}
                className="px-4 py-2 rounded-lg text-xs font-semibold bg-slate-800 text-slate-300 hover:bg-slate-700"
              >
                Close
              </button>
              {selectedNode.risk > 0 && (
                <button
                  onClick={() => {
                    setSelectedNode(null);
                    if (onInspectNodeAlerts) onInspectNodeAlerts();
                  }}
                  className="px-4 py-2 rounded-lg text-xs font-semibold bg-red-600 hover:bg-red-500 text-white shadow-lg shadow-red-600/30"
                >
                  View Related Alerts
                </button>
              )}
            </div>

          </div>
        </div>
      )}

    </section>
  );
}
