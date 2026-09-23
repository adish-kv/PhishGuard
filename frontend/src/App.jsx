import React, { useState } from 'react';
import Navbar from './components/Navbar';
import ScanForm from './components/ScanForm';
import RiskMeter from './components/RiskMeter';
import StageProgress from './components/StageProgress';
import HistoryTable from './components/HistoryTable';
import { AlertCircle } from 'lucide-react';

export default function App() {
  const [activeTab, setActiveTab] = useState('scanner');
  const [scanResult, setScanResult] = useState(null);
  const [errorMsg, setErrorMsg] = useState(null);

  const handleScanStart = () => {
    setErrorMsg(null);
  };

  const handleScanComplete = (result) => {
    setScanResult(result);
    setErrorMsg(null);
  };

  const handleScanError = (msg) => {
    setErrorMsg(msg);
  };

  const handleSelectHistoryScan = (item) => {
    setScanResult(item);
    setActiveTab('scanner');
    window.scrollTo({ top: 0, behavior: 'smooth' });
  };

  return (
    <div className="min-h-screen bg-slate-50 text-slate-900 font-sans selection:bg-blue-600 selection:text-white">
      {/* Top Navbar */}
      <Navbar activeTab={activeTab} setActiveTab={setActiveTab} />

      {/* Main Container */}
      <main className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8 space-y-8">
        {/* Error Banner */}
        {errorMsg && (
          <div className="bg-red-50 border border-red-200 text-red-800 text-xs font-mono p-4 rounded-xl flex items-center justify-between shadow-sm">
            <div className="flex items-center space-x-2">
              <AlertCircle className="w-4 h-4 text-red-600 shrink-0" />
              <span>{errorMsg}</span>
            </div>
            <button
              onClick={() => setErrorMsg(null)}
              className="text-slate-400 hover:text-slate-800 font-bold ml-4"
            >
              ✕
            </button>
          </div>
        )}

        {/* Tab 1: Scanner */}
        {activeTab === 'scanner' && (
          <div className="space-y-8">
            <ScanForm
              onScanStart={handleScanStart}
              onScanComplete={handleScanComplete}
              onError={handleScanError}
            />

            {scanResult && (
              <div className="space-y-8 animate-fadeIn">
                {/* 1. Risk Gauge / Verdict */}
                <RiskMeter result={scanResult} />

                {/* 2. 4-Stage Execution Waterfall */}
                <StageProgress result={scanResult} />
              </div>
            )}
          </div>
        )}

        {/* Tab 2: History */}
        {activeTab === 'history' && (
          <HistoryTable onSelectScan={handleSelectHistoryScan} />
        )}
      </main>

      {/* Footer */}
      <footer className="border-t border-slate-200 py-6 mt-16 text-center text-xs text-slate-500 font-mono bg-white">
        <p>PhishGuard © 2026 — Intelligent Phishing Website Detection Framework</p>
      </footer>
    </div>
  );
}
