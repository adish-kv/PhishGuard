import React, { useState } from 'react';
import Navbar from './components/Navbar';
import ScanForm from './components/ScanForm';
import RiskMeter from './components/RiskMeter';
import StageProgress from './components/StageProgress';
import ModalityChart from './components/ModalityChart';
import FeatureExplainer from './components/FeatureExplainer';
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
    <div className="min-h-screen bg-gray-950 text-gray-100 font-sans selection:bg-cyan-500 selection:text-gray-950">
      {/* Top Navbar */}
      <Navbar activeTab={activeTab} setActiveTab={setActiveTab} />

      {/* Main Container */}
      <main className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8 space-y-8">
        {/* Error Banner */}
        {errorMsg && (
          <div className="bg-red-950/80 border border-red-800 text-red-200 text-xs font-mono p-4 rounded-xl flex items-center justify-between shadow-lg">
            <div className="flex items-center space-x-2">
              <AlertCircle className="w-4 h-4 text-red-400 shrink-0" />
              <span>{errorMsg}</span>
            </div>
            <button
              onClick={() => setErrorMsg(null)}
              className="text-gray-400 hover:text-white font-bold ml-4"
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

                {/* 3. Modality Weights & SHAP Feature Explainer */}
                <div className="grid grid-cols-1 lg:grid-cols-12 gap-8">
                  <div className="lg:col-span-5">
                    <ModalityChart explanation={scanResult.explanation} />
                  </div>
                  <div className="lg:col-span-7">
                    <FeatureExplainer result={scanResult} />
                  </div>
                </div>
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
      <footer className="border-t border-gray-900 py-6 mt-16 text-center text-xs text-gray-600 font-mono">
        <p>PhishGuard © 2026 — Intelligent Phishing Website Detection Framework</p>
      </footer>
    </div>
  );
}
