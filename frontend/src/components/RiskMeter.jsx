import React from 'react';
import { ShieldCheck, AlertOctagon, Zap, Clock, Cpu, Layers } from 'lucide-react';

export default function RiskMeter({ result }) {
  if (!result) return null;

  const isPhishing = result.prediction?.toLowerCase() === 'phishing';
  const confidencePct = (result.confidence * 100).toFixed(1);

  const getRiskBadgeColor = (level) => {
    switch (level?.toUpperCase()) {
      case 'CRITICAL':
        return 'bg-red-500/20 text-red-400 border-red-500/40';
      case 'HIGH':
        return 'bg-orange-500/20 text-orange-400 border-orange-500/40';
      case 'MEDIUM':
        return 'bg-amber-500/20 text-amber-400 border-amber-500/40';
      case 'LOW':
      default:
        return 'bg-emerald-500/20 text-emerald-400 border-emerald-500/40';
    }
  };

  return (
    <div
      className={`rounded-2xl border p-6 transition-all shadow-xl backdrop-blur-xl ${
        isPhishing
          ? 'bg-gradient-to-br from-red-950/40 via-gray-900 to-gray-950 border-red-900/40 shadow-red-950/20'
          : 'bg-gradient-to-br from-emerald-950/40 via-gray-900 to-gray-950 border-emerald-900/40 shadow-emerald-950/20'
      }`}
    >
      <div className="grid grid-cols-1 md:grid-cols-12 gap-6 items-center">
        {/* Main Verdict Badge */}
        <div className="md:col-span-5 flex items-center space-x-4 border-b md:border-b-0 md:border-r border-gray-800 pb-4 md:pb-0 md:pr-6">
          <div
            className={`p-3.5 rounded-2xl border ${
              isPhishing
                ? 'bg-red-500/10 border-red-500/30 text-red-400 shadow-lg shadow-red-500/10'
                : 'bg-emerald-500/10 border-emerald-500/30 text-emerald-400 shadow-lg shadow-emerald-500/10'
            }`}
          >
            {isPhishing ? <AlertOctagon className="w-10 h-10 animate-bounce" /> : <ShieldCheck className="w-10 h-10" />}
          </div>
          <div>
            <div className="flex items-center space-x-2">
              <span
                className={`text-2xl font-black uppercase tracking-wider font-mono ${
                  isPhishing ? 'text-red-400' : 'text-emerald-400'
                }`}
              >
                {result.prediction}
              </span>
              <span
                className={`text-xs font-bold px-2.5 py-0.5 rounded-full border ${getRiskBadgeColor(
                  result.risk_level
                )}`}
              >
                {result.risk_level} RISK
              </span>
            </div>
            <p className="text-xs text-gray-400 font-mono mt-1 break-all line-clamp-1">{result.url}</p>
          </div>
        </div>

        {/* Confidence Progress Meter */}
        <div className="md:col-span-4 space-y-2">
          <div className="flex justify-between items-center text-xs font-mono">
            <span className="text-gray-400">Model Confidence</span>
            <span className={`font-bold ${isPhishing ? 'text-red-400' : 'text-emerald-400'}`}>
              {confidencePct}%
            </span>
          </div>
          <div className="w-full bg-gray-950 h-3 rounded-full overflow-hidden border border-gray-800 p-0.5">
            <div
              className={`h-full rounded-full transition-all duration-700 ${
                isPhishing
                  ? 'bg-gradient-to-r from-orange-500 to-red-500'
                  : 'bg-gradient-to-r from-teal-500 to-emerald-400'
              }`}
              style={{ width: `${confidencePct}%` }}
            />
          </div>
          <div className="flex justify-between text-[10px] text-gray-500 font-mono">
            <span>0% (Uncertain)</span>
            <span>100% (Certain)</span>
          </div>
        </div>

        {/* Adaptive Engine Latency & Stage Metrics */}
        <div className="md:col-span-3 grid grid-cols-2 gap-3 text-xs font-mono bg-gray-950/60 p-3 rounded-xl border border-gray-800">
          <div>
            <div className="text-gray-500 flex items-center space-x-1">
              <Clock className="w-3 h-3 text-cyan-400" />
              <span>Total Latency</span>
            </div>
            <div className="text-sm font-bold text-white mt-0.5">
              {result.total_latency_ms ? `${result.total_latency_ms.toFixed(2)} ms` : 'N/A'}
            </div>
          </div>

          <div>
            <div className="text-gray-500 flex items-center space-x-1">
              <Layers className="w-3 h-3 text-purple-400" />
              <span>Stage Reached</span>
            </div>
            <div className="text-sm font-bold text-cyan-400 mt-0.5 uppercase">
              {result.stage_reached || 'Stage 1'}
            </div>
          </div>

          <div>
            <div className="text-gray-500 flex items-center space-x-1">
              <Cpu className="w-3 h-3 text-emerald-400" />
              <span>Modalities</span>
            </div>
            <div className="text-sm font-bold text-gray-200 mt-0.5">
              {result.modalities_used} / 6 Active
            </div>
          </div>

          <div>
            <div className="text-gray-500 flex items-center space-x-1">
              <Zap className="w-3 h-3 text-amber-400" />
              <span>Early Exit</span>
            </div>
            <div className={`text-sm font-bold mt-0.5 ${result.early_stopped ? 'text-amber-400' : 'text-blue-400'}`}>
              {result.early_stopped ? 'Yes (Fast)' : 'No (Full)'}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
