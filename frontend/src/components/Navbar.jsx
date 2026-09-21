import React, { useEffect, useState } from 'react';
import { ShieldAlert, Activity, History, BarChart3, Info, CheckCircle2, XCircle } from 'lucide-react';

export default function Navbar({ activeTab, setActiveTab }) {
  const [health, setHealth] = useState(null);

  useEffect(() => {
    fetch('/api/v1/health')
      .then((res) => res.json())
      .then((data) => setHealth(data))
      .catch(() => setHealth(null));
  }, []);

  const tabs = [
    { id: 'scanner', label: 'URL Scanner', icon: ShieldAlert },
    { id: 'history', label: 'Scan History', icon: History },
    { id: 'experiments', label: 'Experiments 1-7', icon: BarChart3 },
    { id: 'about', label: 'Paper Specs', icon: Info },
  ];

  return (
    <header className="sticky top-0 z-50 bg-gray-950/80 backdrop-blur-md border-b border-gray-800">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 h-16 flex items-center justify-between">
        {/* Logo & Title */}
        <div className="flex items-center space-x-3 cursor-pointer" onClick={() => setActiveTab('scanner')}>
          <div className="bg-gradient-to-tr from-cyan-500 to-blue-600 p-2 rounded-xl shadow-lg shadow-cyan-500/20">
            <ShieldAlert className="w-6 h-6 text-white" />
          </div>
          <div>
            <div className="flex items-center space-x-2">
              <span className="font-extrabold text-xl tracking-tight text-white font-mono">PhishGuard</span>
              <span className="bg-cyan-500/10 text-cyan-400 text-xs font-semibold px-2 py-0.5 rounded border border-cyan-500/30">
                Adaptive Multimodal
              </span>
            </div>
            <p className="text-xs text-gray-400 font-mono hidden sm:block">
              Visual & URL Hybrid Phishing Detection Framework
            </p>
          </div>
        </div>

        {/* Navigation Links */}
        <nav className="flex space-x-1 sm:space-x-2">
          {tabs.map((tab) => {
            const Icon = tab.icon;
            const isActive = activeTab === tab.id;
            return (
              <button
                key={tab.id}
                onClick={() => setActiveTab(tab.id)}
                className={`flex items-center space-x-2 px-3 py-2 rounded-lg text-sm font-medium transition-all ${
                  isActive
                    ? 'bg-cyan-600/20 text-cyan-400 border border-cyan-500/30 shadow-sm'
                    : 'text-gray-400 hover:text-white hover:bg-gray-800/50'
                }`}
              >
                <Icon className="w-4 h-4" />
                <span className="hidden md:inline">{tab.label}</span>
              </button>
            );
          })}
        </nav>

        {/* Health Badge */}
        <div className="hidden lg:flex items-center space-x-2 text-xs font-mono bg-gray-900 px-3 py-1.5 rounded-full border border-gray-800">
          <Activity className="w-3.5 h-3.5 text-cyan-400 animate-pulse" />
          <span className="text-gray-400">Backend:</span>
          {health ? (
            <span className="flex items-center text-emerald-400 font-semibold">
              <CheckCircle2 className="w-3 h-3 mr-1" />
              Online (v{health.version})
            </span>
          ) : (
            <span className="flex items-center text-amber-400 font-semibold">
              <XCircle className="w-3 h-3 mr-1" />
              Connecting...
            </span>
          )}
        </div>
      </div>
    </header>
  );
}
