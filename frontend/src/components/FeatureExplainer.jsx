import React from 'react';
import { FileText, TrendingUp, TrendingDown, AlertTriangle, ShieldCheck, Cpu } from 'lucide-react';

export default function FeatureExplainer({ result }) {
  if (!result || !result.explanation) return null;

  const exp = result.explanation;
  const topRisk = exp.top_risk_features || [];
  const topSafe = exp.top_safe_features || [];
  const narrative = exp.summary_narrative || 'Explanation generated based on SHAP feature attribution scores.';

  return (
    <div className="bg-gray-900/90 border border-gray-800 rounded-2xl p-6 shadow-xl backdrop-blur-xl space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between border-b border-gray-800 pb-4">
        <div className="flex items-center space-x-3">
          <FileText className="w-5 h-5 text-cyan-400" />
          <h3 className="text-lg font-bold text-white">SHAP Feature Attribution & Explainability</h3>
        </div>
        <span className="text-xs font-mono bg-cyan-500/10 text-cyan-400 border border-cyan-500/30 px-3 py-1 rounded-full flex items-center space-x-1">
          <Cpu className="w-3.5 h-3.5 mr-1" />
          <span>SHAP KernelExplainer v0.51</span>
        </span>
      </div>

      {/* Summary Narrative Box */}
      <div className="bg-gray-950/80 border border-cyan-900/40 rounded-xl p-4 text-xs font-mono leading-relaxed text-gray-300 flex items-start space-x-3">
        <div className="p-2 bg-cyan-500/10 rounded-lg text-cyan-400 mt-0.5">
          <FileText className="w-4 h-4" />
        </div>
        <div>
          <div className="text-cyan-400 font-bold mb-1 uppercase tracking-wider">Automated Security Narrative</div>
          <p>{narrative}</p>
        </div>
      </div>

      {/* Risk vs Safety Feature Columns */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        {/* Top Risk Factors */}
        <div className="space-y-3">
          <div className="flex items-center space-x-2 text-sm font-bold text-red-400">
            <TrendingUp className="w-4 h-4 text-red-400" />
            <span>Top Risk Indicators (+SHAP Score)</span>
          </div>
          {topRisk.length > 0 ? (
            <div className="space-y-2">
              {topRisk.map((feat, idx) => (
                <div
                  key={idx}
                  className="bg-red-950/20 border border-red-900/40 rounded-xl p-3 flex justify-between items-center text-xs font-mono"
                >
                  <div className="space-y-0.5">
                    <div className="font-semibold text-gray-200">{feat.feature || feat.name}</div>
                    <div className="text-[11px] text-gray-400">{feat.description || 'Elevates phishing probability'}</div>
                  </div>
                  <span className="font-bold text-red-400 bg-red-950/50 px-2 py-1 rounded border border-red-800/50">
                    +{typeof feat.shap_value === 'number' ? feat.shap_value.toFixed(3) : feat.weight || '0.12'}
                  </span>
                </div>
              ))}
            </div>
          ) : (
            <div className="bg-gray-950 text-gray-500 p-4 rounded-xl text-xs font-mono text-center border border-gray-800">
              No significant phishing risk indicators flagged.
            </div>
          )}
        </div>

        {/* Top Legitimate Indicators */}
        <div className="space-y-3">
          <div className="flex items-center space-x-2 text-sm font-bold text-emerald-400">
            <TrendingDown className="w-4 h-4 text-emerald-400" />
            <span>Top Legitimate Indicators (-SHAP Score)</span>
          </div>
          {topSafe.length > 0 ? (
            <div className="space-y-2">
              {topSafe.map((feat, idx) => (
                <div
                  key={idx}
                  className="bg-emerald-950/20 border border-emerald-900/40 rounded-xl p-3 flex justify-between items-center text-xs font-mono"
                >
                  <div className="space-y-0.5">
                    <div className="font-semibold text-gray-200">{feat.feature || feat.name}</div>
                    <div className="text-[11px] text-gray-400">{feat.description || 'Supports site authenticity'}</div>
                  </div>
                  <span className="font-bold text-emerald-400 bg-emerald-950/50 px-2 py-1 rounded border border-emerald-800/50">
                    {typeof feat.shap_value === 'number' ? feat.shap_value.toFixed(3) : feat.weight || '-0.15'}
                  </span>
                </div>
              ))}
            </div>
          ) : (
            <div className="bg-gray-950 text-gray-500 p-4 rounded-xl text-xs font-mono text-center border border-gray-800">
              No strong trust factors detected.
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
