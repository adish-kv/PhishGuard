import React from 'react';
import { ShieldCheck, AlertOctagon, Zap, Clock, Cpu, Layers } from 'lucide-react';

export default function RiskMeter({ result }) {
  if (!result) return null;

  const isPhishing = result.prediction?.toLowerCase() === 'phishing';
  const confidencePct = (result.confidence * 100).toFixed(1);

  const getRiskBadgeColor = (level) => {
    switch (level?.toUpperCase()) {
      case 'CRITICAL':
        return 'bg-red-100 text-red-800 border-red-300';
      case 'HIGH':
        return 'bg-orange-100 text-orange-800 border-orange-300';
      case 'MEDIUM':
        return 'bg-amber-100 text-amber-800 border-amber-300';
      case 'LOW':
      default:
        return 'bg-emerald-100 text-emerald-800 border-emerald-300';
    }
  };

  return (
    <div
      className={`rounded-2xl border p-6 transition-all shadow-sm ${
        isPhishing
          ? 'bg-red-50/60 border-red-200'
          : 'bg-emerald-50/60 border-emerald-200'
      }`}
    >
      <div className="grid grid-cols-1 md:grid-cols-12 gap-6 items-center">
        {/* Main Verdict Badge */}
        <div className="md:col-span-7 flex items-center space-x-4 border-b md:border-b-0 md:border-r border-slate-200/80 pb-4 md:pb-0 md:pr-6">
          <div
            className={`p-3.5 rounded-2xl border ${
              isPhishing
                ? 'bg-red-100 border-red-300 text-red-600 shadow-sm'
                : 'bg-emerald-100 border-emerald-300 text-emerald-600 shadow-sm'
            }`}
          >
            {isPhishing ? <AlertOctagon className="w-10 h-10 animate-bounce" /> : <ShieldCheck className="w-10 h-10" />}
          </div>
          <div>
            <div className="flex items-center space-x-2">
              <span
                className={`text-2xl font-black uppercase tracking-wider font-mono ${
                  isPhishing ? 'text-red-700' : 'text-emerald-700'
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
            <p className="text-xs text-slate-600 font-mono mt-1 break-all line-clamp-1">{result.url}</p>
          </div>
        </div>

        {/* Adaptive Engine Latency & Stage Metrics */}
        <div className="md:col-span-5 grid grid-cols-2 sm:grid-cols-4 md:grid-cols-2 gap-3 text-xs font-mono bg-white p-3.5 rounded-xl border border-slate-200 shadow-sm">
          <div>
            <div className="text-slate-500 flex items-center space-x-1">
              <Clock className="w-3 h-3 text-blue-600" />
              <span>Total Latency</span>
            </div>
            <div className="text-sm font-bold text-slate-900 mt-0.5">
              {result.total_latency_ms ? `${result.total_latency_ms.toFixed(2)} ms` : 'N/A'}
            </div>
          </div>

          <div>
            <div className="text-slate-500 flex items-center space-x-1">
              <Layers className="w-3 h-3 text-blue-600" />
              <span>Stage Reached</span>
            </div>
            <div className="text-sm font-bold text-blue-700 mt-0.5 uppercase">
              {result.stage_reached || 'Stage 1'}
            </div>
          </div>

          <div>
            <div className="text-slate-500 flex items-center space-x-1">
              <Cpu className="w-3 h-3 text-slate-700" />
              <span>Modalities</span>
            </div>
            <div className="text-sm font-bold text-slate-800 mt-0.5">
              {result.modalities_used} / 6 Active
            </div>
          </div>

          <div>
            <div className="text-slate-500 flex items-center space-x-1">
              <Zap className="w-3 h-3 text-amber-600" />
              <span>Early Exit</span>
            </div>
            <div className={`text-sm font-bold mt-0.5 ${result.early_stopped ? 'text-amber-700' : 'text-blue-700'}`}>
              {result.early_stopped ? 'Yes (Fast)' : 'No (Full)'}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
