import React from 'react';
import { 
  ShieldAlert, 
  ArrowRight, 
  ShieldCheck, 
  Lock, 
  Cpu, 
  CheckCircle2, 
  Radio, 
  Terminal,
  Globe
} from 'lucide-react';

export default function FooterCTA({ onDeployClick, onDemoClick }) {
  return (
    <footer className="relative bg-[#F1ECE3] text-slate-400 border-t border-slate-200 pt-20 pb-12 overflow-hidden">
      
      {/* Background Ambient Glow */}
      <div className="absolute bottom-0 left-1/2 -translate-x-1/2 w-[700px] h-[300px] bg-amber-500/10 blur-[150px] rounded-full pointer-events-none"></div>

      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 relative z-10">
        
        {/* CTA Card Banner */}
        <div className="glass-card rounded-3xl p-8 sm:p-12 border border-slate-800 relative overflow-hidden mb-16 shadow-2xl">
          
          <div className="absolute top-0 right-0 p-8 opacity-10 pointer-events-none">
            <ShieldAlert className="w-64 h-64 text-blue-500" />
          </div>

          <div className="max-w-3xl space-y-6 relative z-10">
            <div className="inline-flex items-center space-x-2 px-3.5 py-1 rounded-md bg-indigo-50 border border-indigo-200 text-xs font-mono text-indigo-700 font-semibold shadow-2xs">
              <Lock className="w-3.5 h-3.5 text-indigo-600" />
              <span>AIR-GAPPED & HIGH-SECURITY READINESS</span>
            </div>

            <h2 className="text-3xl sm:text-4xl font-extrabold text-stone-900 tracking-tight">
              Ready to secure your one-way network traffic with <span className="gradient-text-hero">zero transmission risk?</span>
            </h2>

            <p className="text-stone-600 text-sm sm:text-base leading-relaxed">
              Deploy RakshaNetra's passive optical diode sensor tap in under 15 minutes. No network modification, no outbound transmissions, sub-millisecond AI threat classification.
            </p>

            <div className="flex flex-wrap items-center gap-4 pt-2">
              <button
                onClick={onDeployClick}
                className="px-7 py-3.5 rounded-xl font-semibold text-sm bg-indigo-600 hover:bg-indigo-500 text-white shadow-lg shadow-indigo-600/25 flex items-center space-x-2 active:scale-95 cursor-pointer"
              >
                <span className="text-white">Deploy Passive Sensor</span>
                <ArrowRight className="w-4 h-4 text-white" />
              </button>

              <button
                onClick={onDemoClick}
                className="px-7 py-3.5 rounded-xl font-semibold text-sm bg-white hover:bg-stone-50 text-stone-800 border border-stone-300 shadow-sm transition-all flex items-center space-x-2 active:scale-95 cursor-pointer"
              >
                <Radio className="w-4 h-4 text-indigo-600 animate-pulse" />
                <span>Schedule Technical Briefing</span>
              </button>
            </div>
          </div>

          {/* Compliance badges bar inside CTA */}
          <div className="mt-10 pt-6 border-t border-stone-200 grid grid-cols-2 md:grid-cols-4 gap-4 text-xs font-mono text-stone-700">
            <div className="flex items-center space-x-2">
              <ShieldCheck className="w-4 h-4 text-indigo-600 shrink-0" />
              <span className="font-medium">FIPS 140-3 Isolation</span>
            </div>
            <div className="flex items-center space-x-2">
              <CheckCircle2 className="w-4 h-4 text-emerald-600 shrink-0" />
              <span className="font-medium">SOC 2 Type II Certified</span>
            </div>
            <div className="flex items-center space-x-2">
              <Lock className="w-4 h-4 text-indigo-600 shrink-0" />
              <span className="font-medium">ISO 27001 Compliant</span>
            </div>
            <div className="flex items-center space-x-2">
              <Cpu className="w-4 h-4 text-teal-600 shrink-0" />
              <span className="font-medium">NATO Air-Gap Standard</span>
            </div>
          </div>

        </div>

        {/* Footer Navigation Matrix */}
        <div className="grid grid-cols-2 md:grid-cols-5 gap-8 pb-12 border-b border-stone-200">
          
          {/* Brand Col */}
          <div className="col-span-2 space-y-4">
            <div className="flex items-center space-x-3">
              <div className="flex items-center justify-center w-8 h-8 rounded-lg bg-indigo-600 text-white font-bold shadow-xs">
                <ShieldAlert className="w-5 h-5 text-white" />
              </div>
              <span className="font-heading font-extrabold text-xl text-stone-900">
                RakshaNetra<span className="text-indigo-600">.SEC</span>
              </span>
            </div>
            <p className="text-xs text-stone-600 max-w-sm leading-relaxed">
              AI-Powered Threat Detection for One-Way Traffic. Real-time classification, SHAP signal explainability, and forensic investigation for critical infrastructure.
            </p>
            <div className="flex items-center space-x-2 text-xs font-mono text-emerald-700 font-semibold">
              <span className="h-2 w-2 rounded-full bg-emerald-600 animate-pulse"></span>
              <span>RakshaNetra SYSTEM STATUS: 100% OPERATIONAL</span>
            </div>
          </div>

          {/* Links 1 */}
          <div>
            <h4 className="text-xs font-mono font-bold text-stone-900 uppercase tracking-wider mb-4">Platform</h4>
            <ul className="space-y-2.5 text-xs text-stone-600">
              <li><a href="#overview" className="hover:text-indigo-600 transition-colors">One-Way Diode Tap</a></li>
              <li><a href="#analytics" className="hover:text-indigo-600 transition-colors">AI Neural Engine</a></li>
              <li><a href="#analytics" className="hover:text-indigo-600 transition-colors">SHAP Signal Explainability</a></li>
              <li><a href="#network" className="hover:text-indigo-600 transition-colors">Topology Mapper</a></li>
            </ul>
          </div>

          {/* Links 2 */}
          <div>
            <h4 className="text-xs font-mono font-bold text-stone-900 uppercase tracking-wider mb-4">Threat Vectors</h4>
            <ul className="space-y-2.5 text-xs text-stone-600">
              <li><a href="#threats" className="hover:text-indigo-600 transition-colors">DDoS & SYN Floods</a></li>
              <li><a href="#threats" className="hover:text-indigo-600 transition-colors">Botnet C2 Beacons</a></li>
              <li><a href="#threats" className="hover:text-indigo-600 transition-colors">DGA / DNS Tunnelling</a></li>
              <li><a href="#threats" className="hover:text-indigo-600 transition-colors">TLS Encrypted Malware</a></li>
            </ul>
          </div>

          {/* Links 3 */}
          <div>
            <h4 className="text-xs font-mono font-bold text-stone-900 uppercase tracking-wider mb-4">Forensics</h4>
            <ul className="space-y-2.5 text-xs text-stone-600">
              <li><a href="#replay" className="hover:text-indigo-600 transition-colors">PCAP Traffic Replay</a></li>
              <li><a href="#investigate" className="hover:text-indigo-600 transition-colors">Alert Investigation</a></li>
              <li><a href="#investigate" className="hover:text-indigo-600 transition-colors">Raw JSON Telemetry</a></li>
              <li><a href="#investigate" className="hover:text-indigo-600 transition-colors">Containment Playbooks</a></li>
            </ul>
          </div>

        </div>

        {/* Bottom Bar */}
        <div className="pt-8 flex flex-col sm:flex-row items-center justify-between text-xs font-mono text-stone-500 gap-4">
          <p>© {new Date().getFullYear()} RakshaNetra Cyber Security Systems Inc. All rights reserved.</p>
          <div className="flex items-center space-x-6">
            <a href="#" className="hover:text-stone-800">Privacy Policy</a>
            <a href="#" className="hover:text-stone-800">Air-Gap Certification</a>
            <a href="#" className="hover:text-stone-800">Security Disclosures</a>
          </div>
        </div>

      </div>
    </footer>
  );
}
