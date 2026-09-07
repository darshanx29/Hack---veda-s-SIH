import React, { useState, useEffect } from 'react';
import { 
  ShieldAlert, 
  Globe, 
  Lock, 
  Terminal, 
  Search, 
  UploadCloud, 
  ChevronRight, 
  CheckCircle2, 
  Sparkles, 
  AlertTriangle,
  Cpu,
  Layers,
  X,
  ExternalLink
} from 'lucide-react';
import { getThreatCategories } from '../api';

// Icons are cosmetic UI, not model data, so they stay mapped client-side by id.
const ICONS = {
  ddos: ShieldAlert,
  botnet: Terminal,
  dga_dns: Globe,
  tls_quic: Lock,
  recon: Search,
  exfil: UploadCloud,
};

const BADGE_BY_SEVERITY = {
  Critical: 'badge-critical',
  High: 'badge-high',
  Medium: 'badge-medium',
  Low: 'badge-low',
};

export default function ThreatCategories({ onSelectThreatFilter }) {
  const [selectedThreat, setSelectedThreat] = useState(null);

  // Real data from the backend: `count` and `sampleAlert` come from
  // app.ml.alert_store's real, model-fired alerts — not invented numbers.
  // `status` reflects whether a trained model actually backs the category
  // (see app.ml.model_loader) instead of always claiming "6 MODELS ACTIVE".
  const [categories, setCategories] = useState([]);
  const [modelsActive, setModelsActive] = useState(0);
  const [modelsTotal, setModelsTotal] = useState(0);
  const [detectorSummary, setDetectorSummary] = useState({ ml: 0, ruleBased: 0, pending: 0 });

  useEffect(() => {
    const load = () => {
      getThreatCategories()
        .then((data) => {
          const mapped = data.categories.map(c => ({
            ...c,
            icon: ICONS[c.id] || ShieldAlert,
            badgeClass: BADGE_BY_SEVERITY[c.sampleSeverity] || 'badge-medium',
            severity: c.sampleSeverity || (c.status === 'active_rule_based' ? 'Rule-Based' : c.status === 'active' ? 'Monitoring' : 'Not Trained'),
          }));
          setCategories(mapped);
          setModelsActive(data.modelsActive || 0);
          setModelsTotal(data.modelsTotal || mapped.length);
          setDetectorSummary({
            ml: mapped.filter(c => c.status === 'active').length,
            ruleBased: mapped.filter(c => c.status === 'active_rule_based').length,
            pending: mapped.filter(c => c.status === 'pending_training').length,
          });
        })
        .catch(() => {});
    };
    load();
    const interval = setInterval(load, 8000);
    return () => clearInterval(interval);
  }, []);

  return (
    <section className="py-20 relative bg-[#F3EFE8] border-t border-b border-slate-200">
      
      {/* Background Grid */}
      <div className="absolute inset-0 bg-grid-pattern opacity-10 pointer-events-none"></div>

      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 relative z-10">
        
        {/* Section Header */}
        <div className="flex flex-col md:flex-row md:items-end justify-between mb-12">
          <div>
            <div className="inline-flex items-center space-x-2 text-xs font-mono text-indigo-600 mb-2 font-semibold">
              <Cpu className="w-3.5 h-3.5 text-indigo-600" />
              <span>DETECTION ENGINE VECTORS</span>
            </div>
            <h2 className="text-3xl sm:text-4xl font-extrabold text-stone-900 tracking-tight">
              Real-Time <span className="gradient-text-blue">Threat Detection Vectors</span>
            </h2>
            <p className="mt-2 text-stone-600 text-sm sm:text-base max-w-2xl">
              RakshaNetra inspects passive mirror traffic across 6 threat dimensions. Trained ML models and metadata/rule-based detectors are shown separately so the console never overstates model coverage.
            </p>
          </div>

          <div className="mt-4 md:mt-0 flex items-center space-x-3 text-xs font-mono text-stone-600">
            <span className="flex items-center space-x-1.5 px-3 py-1.5 rounded-lg bg-white border border-stone-200 shadow-xs">
              <span className="h-2 w-2 rounded-full bg-indigo-600 animate-pulse"></span>
              <span className="text-stone-800 font-semibold">{detectorSummary.ml} ML · {detectorSummary.ruleBased} RULE-BASED · {detectorSummary.pending} PENDING</span>
            </span>
          </div>
        </div>

        {/* 6 Threat Categories Cards Grid */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
          {categories.map((cat) => {
            const Icon = cat.icon;
            return (
              <div
                key={cat.id}
                onClick={() => setSelectedThreat(cat)}
                className="glass-card glass-card-hover rounded-2xl p-6 relative cursor-pointer group border border-stone-200/90 flex flex-col justify-between shadow-xs hover:shadow-md transition-all"
              >
                
                <div>
                  {/* Top Bar: Icon + Severity */}
                  <div className="flex items-center justify-between mb-4">
                    <div className="w-12 h-12 rounded-xl bg-indigo-50 border border-indigo-100 flex items-center justify-center group-hover:bg-indigo-100 transition-all">
                      <Icon className="w-6 h-6 text-indigo-600" />
                    </div>
                    <span className={`px-2.5 py-1 rounded-md text-xs font-mono font-semibold ${cat.badgeClass}`}>
                      {cat.severity}
                    </span>
                  </div>

                  {/* Title & Short Description */}
                  <h3 className="text-lg font-bold text-stone-900 group-hover:text-indigo-600 transition-colors">
                    {cat.name}
                  </h3>
                  <p className="mt-2 text-xs text-stone-600 leading-relaxed">
                    {cat.shortDesc}
                  </p>

                  {/* Top Model Features Tags */}
                  <div className="mt-4 flex flex-wrap gap-1.5">
                    {cat.features.slice(0, 2).map((feat, idx) => (
                      <span key={idx} className="px-2 py-0.5 rounded bg-stone-100 text-[10px] font-mono text-stone-700 border border-stone-200">
                        {feat}
                      </span>
                    ))}
                  </div>
                </div>

                {/* Footer: Real Detection Count Since Startup + Action Link */}
                <div className="mt-6 pt-4 border-t border-stone-200 flex items-center justify-between text-xs font-mono">
                  <span className="text-stone-600">
                    {cat.status === 'active' || cat.status === 'active_rule_based' ? 'Detections: ' : 'Status: '}
                    <span className="text-stone-900 font-semibold">
                      {cat.status === 'active' || cat.status === 'active_rule_based' ? cat.count.toLocaleString() : 'Not yet trained'}
                    </span>
                  </span>
                  <button className="flex items-center space-x-1 text-indigo-600 group-hover:text-indigo-700 font-medium">
                    <span>Inspect</span>
                    <ChevronRight className="w-4 h-4 group-hover:translate-x-1 transition-transform" />
                  </button>
                </div>

              </div>
            );
          })}
        </div>

      </div>

      {/* Modal Inspector for Selected Threat Category */}
      {selectedThreat && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-md animate-in fade-in duration-200">
          <div className="glass-panel w-full max-w-2xl rounded-2xl p-6 sm:p-8 border border-slate-700 shadow-2xl relative">
            
            {/* Close Button */}
            <button
              onClick={() => setSelectedThreat(null)}
              className="absolute top-5 right-5 p-2 rounded-lg bg-slate-800 text-slate-400 hover:text-white"
            >
              <X className="w-5 h-5" />
            </button>

            {/* Modal Title & Header */}
            <div className="flex items-center space-x-4 mb-6">
              <div className="w-14 h-14 rounded-2xl bg-blue-600/10 border border-blue-500/30 flex items-center justify-center">
                {React.createElement(selectedThreat.icon, { className: 'w-7 h-7 text-blue-400' })}
              </div>
              <div>
                <div className="flex items-center space-x-2">
                  <h3 className="text-2xl font-bold text-white">{selectedThreat.name}</h3>
                  <span className={`px-2.5 py-0.5 rounded text-xs font-mono font-semibold ${selectedThreat.badgeClass}`}>
                    {selectedThreat.severity}
                  </span>
                </div>
                <p className="text-xs font-mono text-slate-400 mt-1">
                  Detector: <span className="text-blue-400">{selectedThreat.modelFile || (selectedThreat.detectorType === 'rule_based' ? 'Metadata / Rule-Based' : 'Not trained yet')}</span>
                </p>
              </div>
            </div>

            {/* Full Description */}
            <div className="space-y-4">
              <div>
                <h4 className="text-xs font-mono text-slate-400 uppercase tracking-wider mb-1">Vector Analysis Overview</h4>
                <p className="text-sm text-slate-200 leading-relaxed bg-slate-950/80 p-4 rounded-xl border border-slate-800">
                  {selectedThreat.fullDesc}
                </p>
              </div>

              {/* Key Features Evaluated */}
              <div>
                <h4 className="text-xs font-mono text-slate-400 uppercase tracking-wider mb-2">Key Model Signal Features</h4>
                <div className="grid grid-cols-1 sm:grid-cols-3 gap-2">
                  {selectedThreat.features.map((feat, idx) => (
                    <div key={idx} className="p-3 rounded-lg bg-slate-900 border border-slate-800 text-xs font-mono text-blue-300 flex items-center space-x-2">
                      <Sparkles className="w-3.5 h-3.5 text-blue-400 shrink-0" />
                      <span>{feat}</span>
                    </div>
                  ))}
                </div>
              </div>

              {/* Most Recent REAL Detection (or an honest "none yet") */}
              <div>
                <h4 className="text-xs font-mono text-slate-400 uppercase tracking-wider mb-2">Most Recent Real Detection</h4>
                <div className="p-3.5 rounded-xl bg-red-950/30 border border-red-500/30 text-xs font-mono text-red-200 flex items-start space-x-3">
                  <AlertTriangle className="w-4 h-4 text-red-400 shrink-0 mt-0.5" />
                  <span>{selectedThreat.sampleAlert || 'No detections fired by this model yet — run a replay session to generate one.'}</span>
                </div>
              </div>
            </div>

            {/* Modal Actions */}
            <div className="mt-8 pt-4 border-t border-slate-800 flex items-center justify-between">
              <span className="text-xs font-mono text-slate-400">
                Passive Tap Sensor: <span className="text-emerald-400">MONITORING</span>
              </span>
              <div className="flex items-center space-x-3">
                <button
                  onClick={() => setSelectedThreat(null)}
                  className="px-4 py-2 rounded-lg text-xs font-semibold bg-slate-800 hover:bg-slate-700 text-slate-200"
                >
                  Close
                </button>
                <button
                  onClick={() => {
                    const thId = selectedThreat.id;
                    setSelectedThreat(null);
                    if (onSelectThreatFilter) onSelectThreatFilter(thId);
                  }}
                  className="px-4 py-2 rounded-lg text-xs font-semibold bg-blue-600 hover:bg-blue-500 text-white shadow-lg shadow-blue-600/30 flex items-center space-x-2"
                >
                  <span>View Alerts in Console</span>
                  <ExternalLink className="w-3.5 h-3.5" />
                </button>
              </div>
            </div>

          </div>
        </div>
      )}

    </section>
  );
}
