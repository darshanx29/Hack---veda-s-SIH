import React, { useState, useRef } from 'react';
import Header from './components/Header';
import HeroSection from './components/HeroSection';
import ThreatCategories from './components/ThreatCategories';
import AIAnalytics from './components/AIAnalytics';
import TrafficReplay from './components/TrafficReplay';
import AlertInvestigation from './components/AlertInvestigation';
import FooterCTA from './components/FooterCTA';
import DotField from './components/DotField';
import { ShieldCheck, Sparkles, CheckCircle2, Zap } from 'lucide-react';

export default function App() {
  const [activeTab, setActiveTab] = useState('overview');
  const [activeFilterThreat, setActiveFilterThreat] = useState('All');
  const [toastMessage, setToastMessage] = useState(null);

  // Section refs for smooth scrolling
  const overviewRef = useRef(null);
  const threatsRef = useRef(null);
  const analyticsRef = useRef(null);
  const networkRef = useRef(null);
  const replayRef = useRef(null);
  const investigateRef = useRef(null);

  const showToast = (msg) => {
    setToastMessage(msg);
    setTimeout(() => setToastMessage(null), 3500);
  };

  const handleTabChange = (tabId) => {
    setActiveTab(tabId);
    const refMap = {
      overview: overviewRef,
      threats: threatsRef,
      analytics: analyticsRef,
      network: networkRef,
      replay: replayRef,
      investigate: investigateRef
    };

    const targetRef = refMap[tabId];
    if (targetRef && targetRef.current) {
      targetRef.current.scrollIntoView({ behavior: 'smooth' });
    }
  };

  const handleLaunchConsole = () => {
    handleTabChange('investigate');
    showToast('Live Console Activated: Displaying Passive Air-Gap Threat Stream');
  };

  const handleSelectThreatFilter = (threatId) => {
    setActiveFilterThreat(threatId);
    handleTabChange('investigate');
    showToast(`Filter Applied: Viewing ${threatId.toUpperCase()} alerts`);
  };

  return (
    <div className="min-h-screen bg-[#FAF8F5] text-slate-900 selection:bg-indigo-500/20 selection:text-indigo-900 relative">

      {/* Interactive Reactive DotField Background Canvas */}
      <div className="fixed inset-0 pointer-events-none z-0 overflow-hidden">
        <DotField
          dotRadius={1.6}
          dotSpacing={14}
          cursorRadius={400}
          cursorForce={0.1}
          bulgeOnly={true}
          bulgeStrength={48}
          glowRadius={170}
          sparkle={true}
          waveAmplitude={0.4}
          gradientFrom="rgba(147, 51, 234, 0.45)"
          gradientTo="rgba(99, 102, 241, 0.35)"
          glowColor="rgba(168, 85, 247, 0.28)"
        />
      </div>

      {/* Toast Notification */}
      {toastMessage && (
        <div className="fixed bottom-6 right-6 z-50 glass-card px-5 py-3 rounded-2xl border border-blue-500/40 shadow-2xl flex items-center space-x-3 text-xs font-mono text-white animate-in slide-in-from-bottom-5 duration-300">
          <Sparkles className="w-4 h-4 text-blue-400 animate-spin" />
          <span>{toastMessage}</span>
        </div>
      )}

      {/* Header */}
      <Header
        activeTab={activeTab}
        setActiveTab={handleTabChange}
        onLaunchDemo={handleLaunchConsole}
      />

      {/* Hero Section */}
      <div ref={overviewRef} id="overview">
        <HeroSection
          onExplore={() => handleTabChange('threats')}
          onLiveDemo={handleLaunchConsole}
        />
      </div>

      {/* Threat Categories */}
      <div ref={threatsRef} id="threats">
        <ThreatCategories
          onSelectThreatFilter={handleSelectThreatFilter}
        />
      </div>

      {/* AI Analytics & SHAP */}
      <div ref={analyticsRef} id="analytics">
        <AIAnalytics />
      </div>



      {/* PCAP Traffic Replay Simulator */}
      <div ref={replayRef} id="replay">
        <TrafficReplay />
      </div>

      {/* Alert Investigation Console */}
      <div ref={investigateRef} id="investigate">
        <AlertInvestigation
          activeFilterThreat={activeFilterThreat}
        />
      </div>

      {/* Footer CTA */}
      <FooterCTA
        onDeployClick={() => showToast('Sensor Deployment Wizard Started (Optical Diode Tap Active)')}
        onDemoClick={handleLaunchConsole}
      />

    </div>
  );
}
