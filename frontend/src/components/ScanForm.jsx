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
    <div className="bg-gray-900/90 border border-gray-800 rounded-2xl p-6 shadow-2xl backdrop-blur-xl">
      <div className="flex items-center space-x-3 mb-4">
        <Globe className="w-5 h-5 text-cyan-400" />
        <h2 className="text-lg font-bold text-white tracking-wide">Stage-Wise Adaptive URL Inspection</h2>
      </div>

      <form onSubmit={handleSubmit} className="space-y-4">
        <div className="relative">
          <input
            type="url"
            value={url}
            onChange={(e) => setUrl(e.target.value)}
            placeholder="Enter website URL to analyze (e.g., https://paypal-security-update.com)"
            required
            className="w-full bg-gray-950 text-white placeholder-gray-500 text-sm font-mono rounded-xl px-4 py-3.5 border border-gray-800 focus:outline-none focus:ring-2 focus:ring-cyan-500/50 focus:border-cyan-500 transition-all pr-32"
          />
          <button
            type="submit"
            disabled={loading || !url.trim()}
            className="absolute right-2 top-2 bottom-2 bg-gradient-to-r from-cyan-500 to-blue-600 hover:from-cyan-400 hover:to-blue-500 text-white font-semibold text-sm px-5 rounded-lg flex items-center space-x-2 transition-all disabled:opacity-50 disabled:cursor-not-allowed shadow-md shadow-cyan-500/20"
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
          <label className="flex items-center space-x-2 cursor-pointer text-xs font-mono text-gray-400 hover:text-gray-300">
            <input
              type="checkbox"
              checked={forceFull}
              onChange={(e) => setForceFull(e.target.checked)}
              className="w-4 h-4 rounded bg-gray-950 border-gray-700 text-cyan-500 focus:ring-cyan-500/50"
            />
            <Zap className={`w-3.5 h-3.5 ${forceFull ? 'text-amber-400' : 'text-gray-500'}`} />
            <span>Force Full Multimodal Analysis (Bypass Early Stopping)</span>
          </label>

          {/* Preset Buttons */}
          <div className="flex items-center space-x-2 overflow-x-auto w-full sm:w-auto pb-1 sm:pb-0">
            <span className="text-xs text-gray-500 font-mono whitespace-nowrap">Presets:</span>
            {sampleUrls.map((s, idx) => (
              <button
                key={idx}
                type="button"
                onClick={() => setSample(s.url)}
                className="text-xs bg-gray-800/60 hover:bg-gray-800 text-gray-300 hover:text-white px-2.5 py-1 rounded-md border border-gray-700/50 whitespace-nowrap font-mono transition-colors"
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
