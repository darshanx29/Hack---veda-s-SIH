import React, { useState, useEffect } from 'react';
import { 
  Cpu, 
  BarChart3, 
  TrendingUp, 
  ShieldCheck, 
  HelpCircle, 
  Zap, 
  Activity, 
  Sparkles,
  Sliders,
  CheckCircle2,
  Info
} from 'lucide-react';
import { getShapFeatures, getTrendData as fetchTrendData, getModelPerformance } from '../api';

export default function AIAnalytics() {
  const [timeRange, setTimeRange] = useState('24h');
  const [hoveredFeature, setHoveredFeature] = useState(null);

  // Real feature importances pulled straight from each loaded model's own
  // `feature_importances_` (see app/routes/analytics.py) — not invented
  // SHAP values. `shap` field name kept for the progress-bar math below,
  // but the UI labels this "Feature Importance", not SHAP.
  const [features, setFeatures] = useState([]);
  // Real per-category alert counts since process startup (no historical
  // time-series store exists yet, so this isn't bucketed by time range).
  const [categoryCounts, setCategoryCounts] = useState({ ddos: 0, botnet: 0, dga_dns: 0, recon: 0 });
  const [totalRealAlerts, setTotalRealAlerts] = useState(0);
  const [performance, setPerformance] = useState({ modelsActive: 0, modelsTotal: 6, meanConfidence: null });

  useEffect(() => {
    const load = () => {
      getShapFeatures()
        .then((rows) => setFeatures(rows.map(r => ({
          name: r.name,
          shap: r.importance,
          category: r.category,
          desc: r.desc,
        }))))
        .catch(() => {});

      fetchTrendData(timeRange)
        .then((data) => {
          setCategoryCounts(data.counts);
          setTotalRealAlerts(data.totalRealAlerts);
        })
        .catch(() => {});

      getModelPerformance().then(setPerformance).catch(() => {});
    };
    load();
    const interval = setInterval(load, 8000);
    return () => clearInterval(interval);
  }, [timeRange]);

  const maxFeatureImportance = features.length ? Math.max(...features.map(f => f.shap)) : 1;
  const trendData = [
    { label: 'DDoS & Volumetric', key: 'ddos', color: 'bg-red-500', value: categoryCounts.ddos || 0 },
    { label: 'Botnet C2', key: 'botnet', color: 'bg-orange-500', value: categoryCounts.botnet || 0 },
    { label: 'DGA / DNS Tunnel', key: 'dga_dns', color: 'bg-yellow-500', value: categoryCounts.dga_dns || 0 },
    { label: 'Reconnaissance', key: 'recon', color: 'bg-blue-500', value: categoryCounts.recon || 0 },
  ];
  const maxTrendVal = Math.max(1, ...trendData.map(d => d.value));

  return (
    <section className="py-20 relative bg-[#FAF8F5] border-t border-b border-slate-200">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 relative z-10">
        
        {/* Section Title */}
        <div className="flex flex-col md:flex-row md:items-end justify-between mb-12">
          <div>
            <div className="inline-flex items-center space-x-2 text-xs font-mono text-teal-700 mb-2 font-semibold">
              <Sparkles className="w-3.5 h-3.5 text-teal-600" />
              <span>EXPLAINABLE THREAT ANALYTICS (XAI)</span>
            </div>
            <h2 className="text-3xl sm:text-4xl font-extrabold text-stone-900 tracking-tight">
              Threat Analytics & <span className="gradient-text-blue">Feature Attribution Signals</span>
            </h2>
            <p className="mt-2 text-stone-600 text-sm sm:text-base max-w-2xl">
              Inspect model decision metrics, feature attribution scores, and confidence distributions across one-way network traffic streams.
            </p>
          </div>

          {/* Time range selector */}
          <div className="mt-4 md:mt-0 flex items-center space-x-2 bg-stone-100 p-1 rounded-xl border border-stone-200 shadow-xs">
            {['1h', '24h', '7d'].map((range) => (
              <button
                key={range}
                onClick={() => setTimeRange(range)}
                className={`px-3 py-1.5 rounded-lg text-xs font-mono font-semibold transition-all cursor-pointer ${
                  timeRange === range
                    ? 'bg-indigo-600 text-white shadow-xs'
                    : 'text-stone-600 hover:text-stone-900'
                }`}
              >
                <span className={timeRange === range ? 'text-white' : ''}>{range.toUpperCase()}</span>
              </button>
            ))}
          </div>
        </div>

        {/* AI Performance & Confidence Header Cards */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-6 mb-10">
          
          {/* Models Trained (real, from model_loader) */}
          <div className="glass-card p-6 rounded-2xl border border-stone-200/90 shadow-xs">
            <div className="flex items-center justify-between text-xs font-mono text-stone-600 mb-2 font-medium">
              <span>MODELS TRAINED & LOADED</span>
              <Cpu className="w-4 h-4 text-indigo-600" />
            </div>
            <div className="flex items-baseline space-x-3">
              <span className="text-3xl font-extrabold font-mono text-stone-900">{performance.modelsActive} / {performance.modelsTotal}</span>
            </div>
            <p className="mt-3 text-xs text-stone-600">
              Threat categories with an actual trained artifact loaded (see app.ml.model_loader).
            </p>
          </div>

          {/* Real alert count since startup */}
          <div className="glass-card p-6 rounded-2xl border border-stone-200/90 shadow-xs">
            <div className="flex items-center justify-between text-xs font-mono text-stone-600 mb-2 font-medium">
              <span>REAL ALERTS FIRED</span>
              <ShieldCheck className="w-4 h-4 text-emerald-600" />
            </div>
            <div className="flex items-baseline space-x-3">
              <span className="text-3xl font-extrabold font-mono text-emerald-700">{totalRealAlerts.toLocaleString()}</span>
              <span className="text-xs font-mono text-stone-600 font-medium">SINCE STARTUP</span>
            </div>
            <p className="mt-3 text-xs text-stone-600">
              Every one of these came from a model's own prediction, not a random draw.
            </p>
          </div>

          {/* Mean confidence of real fired alerts */}
          <div className="glass-card p-6 rounded-2xl border border-stone-200/90 shadow-xs">
            <div className="flex items-center justify-between text-xs font-mono text-stone-600 mb-2 font-medium">
              <span>MEAN ALERT CONFIDENCE</span>
              <Zap className="w-4 h-4 text-amber-600" />
            </div>
            <div className="flex items-baseline space-x-3">
              <span className="text-3xl font-extrabold font-mono text-stone-900">
                {performance.meanConfidence != null ? `${performance.meanConfidence}%` : '—'}
              </span>
            </div>
            <p className="mt-3 text-xs text-stone-600">
              {performance.meanConfidence != null
                ? 'Average predict_proba() confidence across all real fired alerts.'
                : 'No alerts fired yet — run a replay session to generate real detections.'}
            </p>
          </div>

        </div>

        {/* SHAP Feature Importance & Threat Trend Dual Column */}
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-8">
          
          {/* Left Column: SHAP Feature Importance Breakdown (7 Cols) */}
          <div className="lg:col-span-7 glass-card p-6 rounded-2xl border border-stone-200/90 shadow-xs">
            <div className="flex items-center justify-between mb-6">
              <div>
                <h3 className="text-lg font-bold text-stone-900 flex items-center space-x-2">
                  <Sliders className="w-5 h-5 text-indigo-600" />
                  <span>Model Feature Importance</span>
                </h3>
                <p className="text-xs text-stone-600 mt-1">
                  Real feature_importances_ from each loaded model — not SHAP (not wired up), and not invented.
                </p>
              </div>
              <span className="px-2.5 py-1 rounded bg-indigo-50 border border-indigo-200 text-indigo-700 font-mono text-xs font-semibold">
                LIVE FROM MODEL
              </span>
            </div>

            {/* Feature Bars */}
            <div className="space-y-4">
              {features.length === 0 && (
                <p className="text-xs text-stone-500 font-mono">No loaded model exposes feature_importances_ yet.</p>
              )}
              {features.map((feat, idx) => {
                const percentage = Math.round((feat.shap / maxFeatureImportance) * 100);
                return (
                  <div
                    key={idx}
                    onMouseEnter={() => setHoveredFeature(feat)}
                    onMouseLeave={() => setHoveredFeature(null)}
                    className="p-3.5 rounded-xl bg-stone-50 border border-stone-200/80 hover:border-indigo-400 hover:bg-white transition-all cursor-pointer group shadow-2xs"
                  >
                    <div className="flex items-center justify-between text-xs font-mono mb-2">
                      <div className="flex items-center space-x-2">
                        <span className="text-stone-500 font-bold">#{idx + 1}</span>
                        <span className="text-stone-900 font-semibold group-hover:text-indigo-600 transition-colors">{feat.name}</span>
                      </div>
                      <div className="flex items-center space-x-2">
                        <span className="px-2 py-0.5 rounded bg-stone-200/80 text-[10px] text-stone-700 font-medium">{feat.category}</span>
                        <span className="text-indigo-600 font-bold">+{feat.shap}</span>
                      </div>
                    </div>

                    {/* Progress bar */}
                    <div className="w-full bg-stone-200 h-2 rounded-full overflow-hidden">
                      <div
                        className="bg-gradient-to-r from-indigo-600 via-indigo-500 to-teal-500 h-full rounded-full transition-all duration-500"
                        style={{ width: `${percentage}%` }}
                      ></div>
                    </div>

                    {/* Hover detail tooltip */}
                    {hoveredFeature?.name === feat.name && (
                      <p className="mt-2.5 text-[11px] text-stone-700 bg-white p-2.5 rounded-lg border border-indigo-200 animate-in fade-in shadow-xs">
                        <Info className="w-3 h-3 text-indigo-600 inline mr-1" />
                        {feat.desc}
                      </p>
                    )}
                  </div>
                );
              })}
            </div>
          </div>

          {/* Right Column: Threat Trends Time Series Chart (5 Cols) */}
          <div className="lg:col-span-5 glass-card p-6 rounded-2xl border border-stone-200/90 shadow-xs flex flex-col justify-between">
            <div>
              <div className="flex items-center justify-between mb-6">
                <div>
                  <h3 className="text-lg font-bold text-stone-900 flex items-center space-x-2">
                    <Activity className="w-5 h-5 text-teal-600" />
                    <span>Real Detections by Category</span>
                  </h3>
                  <p className="text-xs text-stone-600 mt-1">
                    All-time count since process startup — {totalRealAlerts.toLocaleString()} real alerts total. No historical time-series store exists yet, so this isn't split by {timeRange.toUpperCase()}.
                  </p>
                </div>
              </div>

              {/* Real per-category bar visualizer */}
              <div className="space-y-4 pt-4">
                {trendData.map((d) => {
                  const barWidth = Math.round((d.value / maxTrendVal) * 100);
                  return (
                    <div key={d.key} className="space-y-1">
                      <div className="flex items-center justify-between text-xs font-mono">
                        <span className="text-slate-400">{d.label}</span>
                        <span className="text-white font-semibold">{d.value} events</span>
                      </div>
                      <div className="w-full bg-slate-900 h-3 rounded-md overflow-hidden flex">
                        <div
                          style={{ width: `${barWidth}%` }}
                          className={`${d.color} h-full`}
                          title={`${d.label}: ${d.value}`}
                        ></div>
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>

            {/* Legend */}
            <div className="mt-6 pt-4 border-t border-slate-800 grid grid-cols-2 gap-2 text-xs font-mono">
              <div className="flex items-center space-x-2">
                <span className="w-2.5 h-2.5 rounded bg-red-500"></span>
                <span className="text-slate-300">DDoS Floods</span>
              </div>
              <div className="flex items-center space-x-2">
                <span className="w-2.5 h-2.5 rounded bg-orange-500"></span>
                <span className="text-slate-300">Botnet C2</span>
              </div>
              <div className="flex items-center space-x-2">
                <span className="w-2.5 h-2.5 rounded bg-yellow-500"></span>
                <span className="text-slate-300">DGA / DNS Tunnel</span>
              </div>
              <div className="flex items-center space-x-2">
                <span className="w-2.5 h-2.5 rounded bg-blue-500"></span>
                <span className="text-slate-300">Reconnaissance</span>
              </div>
            </div>

          </div>

        </div>

      </div>
    </section>
  );
}
