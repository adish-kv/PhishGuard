import React, { useState } from 'react';
import { Search, Zap, Shield, AlertTriangle, Globe } from 'lucide-react';

export default function ScanForm({ onScanStart, onScanComplete, onError }) {
  const [url, setUrl] = useState('');
  const [forceFull, setForceFull] = useState(false);
  const [loading, setLoading] = useState(false);

  const sampleUrls = [
    { label: 'Phishing (PayPal Copy)', url: 'https://paypal-verify-login-account-update.com/signin' },
    { label: 'Phishing (Bank Account)', url: 'http://secure-online-banking-login-auth.xyz/verify' },
    { label: 'Legitimate (Google)', url: 'https://google.com' },
    { label: 'Legitimate (GitHub)', url: 'https://github.com' },
  ];

  const handleSubmit = async (e) => {
    if (e) e.preventDefault();
    if (!url || !url.trim()) return;

    setLoading(true);
    onScanStart();

    try {
      const response = await fetch('/api/v1/analyze', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          url: url.trim(),
          force_full_analysis: forceFull,
        }),
      });

      if (!response.ok) {
        const errorData = await response.json();
        throw new Error(errorData.detail || 'Analysis failed on backend server.');
      }

      const data = await response.json();
      onScanComplete(data);
    } catch (err) {
      onError(err.message || 'Failed to connect to backend server.');
    } finally {
      setLoading(false);
    }
  };

  const setSample = (sampleUrl) => {
    setUrl(sampleUrl);
  };

  return (
    <div className="bg-white border border-slate-200 rounded-2xl p-6 shadow-sm">
      <div className="flex items-center space-x-3 mb-4">
        <Globe className="w-5 h-5 text-blue-600" />
        <h2 className="text-lg font-bold text-slate-900 tracking-wide">Stage-Wise Adaptive URL Inspection</h2>
      </div>

      <form onSubmit={handleSubmit} className="space-y-4">
        <div className="relative">
          <input
            type="url"
            value={url}
            onChange={(e) => setUrl(e.target.value)}
            placeholder="Enter website URL to analyze (e.g., https://paypal-security-update.com)"
            required
            className="w-full bg-slate-50 text-slate-900 placeholder-slate-400 text-sm font-mono rounded-xl px-4 py-3.5 border border-slate-300 focus:outline-none focus:ring-2 focus:ring-blue-600/30 focus:border-blue-600 transition-all pr-32 shadow-inner"
          />
          <button
            type="submit"
            disabled={loading || !url.trim()}
            className="absolute right-2 top-2 bottom-2 bg-blue-600 hover:bg-blue-700 text-white font-semibold text-sm px-5 rounded-lg flex items-center space-x-2 transition-all disabled:opacity-50 disabled:cursor-not-allowed shadow-md shadow-blue-600/20"
          >
            {loading ? (
              <>
                <div className="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin" />
                <span>Analyzing...</span>
              </>
            ) : (
              <>
                <Search className="w-4 h-4" />
                <span>Analyze</span>
              </>
            )}
          </button>
        </div>

        {/* Options & Quick Presets */}
        <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3 pt-2">
          {/* Force Full Analysis Toggle */}
          <label className="flex items-center space-x-2 cursor-pointer text-xs font-mono text-slate-600 hover:text-slate-900">
            <input
              type="checkbox"
              checked={forceFull}
              onChange={(e) => setForceFull(e.target.checked)}
              className="w-4 h-4 rounded bg-slate-100 border-slate-300 text-blue-600 focus:ring-blue-500"
            />
            <Zap className={`w-3.5 h-3.5 ${forceFull ? 'text-amber-500' : 'text-slate-400'}`} />
            <span>Force Full Multimodal Analysis (Bypass Early Stopping)</span>
          </label>

          {/* Preset Buttons */}
          <div className="flex items-center space-x-2 overflow-x-auto w-full sm:w-auto pb-1 sm:pb-0">
            <span className="text-xs text-slate-500 font-mono whitespace-nowrap">Presets:</span>
            {sampleUrls.map((s, idx) => (
              <button
                key={idx}
                type="button"
                onClick={() => setSample(s.url)}
                className="text-xs bg-slate-100 hover:bg-blue-50 text-slate-700 hover:text-blue-700 px-2.5 py-1 rounded-md border border-slate-200 whitespace-nowrap font-mono transition-colors font-medium"
              >
                {s.label}
              </button>
            ))}
          </div>
        </div>
      </form>
    </div>
  );
}
