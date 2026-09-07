import React, { useState } from 'react';
import { 
  Shield,
  Menu, 
  X, 
  Radio,
} from 'lucide-react';

export default function Header({ activeTab, setActiveTab, onLaunchDemo }) {
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);

  const navItems = [
    { id: 'overview', label: 'Overview' },
    { id: 'threats', label: 'Threats' },
    { id: 'analytics', label: 'Analytics' },
    { id: 'replay', label: 'Traffic Replay' },
    { id: 'investigate', label: 'Investigation' },
  ];

  return (
    <header className="sticky top-0 z-50 bg-white/80 backdrop-blur-md border-b border-stone-200/70 transition-all duration-300">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="flex items-center justify-between h-16">
          
          {/* Brand */}
          <div className="flex items-center space-x-2.5 cursor-pointer shrink-0" onClick={() => setActiveTab('overview')}>
            <Shield className="w-5 h-5 text-indigo-600" />
            <span className="font-heading font-bold text-lg tracking-tight text-slate-900">
              RakshaNetra
            </span>
          </div>

          {/* Desktop Nav */}
          <nav className="hidden lg:flex items-center space-x-1">
            {navItems.map((item) => {
              const isActive = activeTab === item.id;
              return (
                <button
                  key={item.id}
                  onClick={() => setActiveTab(item.id)}
                  className={`px-3.5 py-1.5 rounded-lg text-sm font-medium transition-colors duration-150 ${
                    isActive
                      ? 'bg-indigo-50 text-indigo-700'
                      : 'text-stone-500 hover:text-stone-800 hover:bg-stone-50'
                  }`}
                >
                  {item.label}
                </button>
              );
            })}
          </nav>

          {/* Right Actions */}
          <div className="hidden md:flex items-center space-x-3">
            {/* Status dot */}
            <div className="flex items-center space-x-1.5 text-xs text-emerald-700 font-medium">
              <span className="relative flex h-2 w-2">
                <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75"></span>
                <span className="relative inline-flex rounded-full h-2 w-2 bg-emerald-500"></span>
              </span>
              <span>Live</span>
            </div>

            <div className="w-px h-5 bg-stone-200"></div>

            {/* CTA */}
            <button
              onClick={onLaunchDemo}
              className="px-4 py-2 rounded-lg bg-indigo-600 hover:bg-indigo-500 text-sm font-medium transition-colors duration-150 flex items-center space-x-1.5 active:scale-[0.97]"
              style={{ color: '#fff' }}
            >
              <Radio className="w-3.5 h-3.5" style={{ color: '#fff' }} />
              <span style={{ color: '#fff' }}>Console</span>
            </button>
          </div>

          {/* Mobile Menu Button */}
          <div className="flex lg:hidden items-center">
            <button
              onClick={() => setMobileMenuOpen(!mobileMenuOpen)}
              className="p-2 rounded-lg text-stone-600 hover:text-stone-900 hover:bg-stone-100 transition-colors"
            >
              {mobileMenuOpen ? <X className="w-5 h-5" /> : <Menu className="w-5 h-5" />}
            </button>
          </div>

        </div>
      </div>

      {/* Mobile Drawer */}
      {mobileMenuOpen && (
        <div className="lg:hidden bg-white border-t border-stone-100 px-4 pt-2 pb-4 space-y-1">
          {navItems.map((item) => {
            const isActive = activeTab === item.id;
            return (
              <button
                key={item.id}
                onClick={() => {
                  setActiveTab(item.id);
                  setMobileMenuOpen(false);
                }}
                className={`w-full text-left px-4 py-2.5 rounded-lg text-sm font-medium transition-colors ${
                  isActive
                    ? 'bg-indigo-50 text-indigo-700'
                    : 'text-stone-600 hover:text-stone-900 hover:bg-stone-50'
                }`}
              >
                {item.label}
              </button>
            );
          })}

          <button
            onClick={() => {
              onLaunchDemo();
              setMobileMenuOpen(false);
            }}
            className="w-full mt-2 py-2.5 rounded-lg bg-indigo-600 text-center text-sm font-medium"
            style={{ color: '#fff' }}
          >
            Open Console
          </button>
        </div>
      )}
    </header>
  );
}
