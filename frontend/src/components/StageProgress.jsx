import React from 'react';
import { CheckCircle2, Clock, FastForward, AlertCircle, Layers } from 'lucide-react';

export default function StageProgress({ result }) {
  if (!result) return null;

  const stageLatencies = result.stage_latencies_ms || {};
  const stageReachedStr = (result.stage_reached || 'stage_1').toLowerCase();

  const stages = [
    {
      id: 'stage_1',
      num: 1,
      name: 'Lexical & URL Structural',
      modalities: ['URL (22 features)'],
      cost: 'Cost: ~0.5ms (Zero Egress)',
    },
    {
      id: 'stage_2',
      num: 2,
      name: 'Static HTML & TLS Certificate',
      modalities: ['HTML (28 features)', 'SSL/TLS (10 features)'],
      cost: 'Cost: ~15-40ms (DOM / Socket)',
    },
    {
      id: 'stage_3',
      num: 3,
      name: 'WHOIS Domain & EasyOCR',
      modalities: ['Domain RDAP (6 features)', 'OCR Text (13 features)'],
      cost: 'Cost: ~80-150ms (RDAP / OCR)',
    },
    {
      id: 'stage_4',
      num: 4,
      name: 'CLIP Visual & FAISS Brand Matching',
      modalities: ['Visual ViT-B/32 (64d vector)', 'FAISS Cosine Index'],
      cost: 'Cost: ~200-500ms (Vision Model)',
    },
  ];

  // Determine numeric stage reached index
  const reachedStageIndex = stages.findIndex((s) => s.id === stageReachedStr) !== -1
    ? stages.findIndex((s) => s.id === stageReachedStr)
    : 0;

  return (
    <div className="bg-gray-900/90 border border-gray-800 rounded-2xl p-6 shadow-xl backdrop-blur-xl">
      <div className="flex items-center justify-between mb-6">
        <div className="flex items-center space-x-3">
          <Layers className="w-5 h-5 text-purple-400" />
          <h3 className="text-lg font-bold text-white">4-Stage Adaptive Multimodal Pipeline Execution</h3>
        </div>
        {result.early_stopped && (
          <span className="flex items-center space-x-1 text-xs font-mono font-semibold bg-amber-500/10 text-amber-400 px-3 py-1 rounded-full border border-amber-500/30">
            <FastForward className="w-3.5 h-3.5" />
            <span>Early Exit Triggered at Stage {reachedStageIndex + 1}</span>
          </span>
        )}
      </div>

      {/* Stage Flow Waterfall */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4 relative">
        {stages.map((stage, idx) => {
          const isExecuted = idx <= reachedStageIndex;
          const isExitStage = idx === reachedStageIndex;
          const isSkipped = idx > reachedStageIndex;
          const latencyMs = stageLatencies[stage.id];

          return (
            <div
              key={stage.id}
              className={`relative rounded-xl border p-4 transition-all flex flex-col justify-between ${
                isExitStage
                  ? result.prediction?.toLowerCase() === 'phishing'
                    ? 'bg-red-950/20 border-red-500/50 shadow-md shadow-red-500/10'
                    : 'bg-emerald-950/20 border-emerald-500/50 shadow-md shadow-emerald-500/10'
                  : isExecuted
                  ? 'bg-gray-950/80 border-cyan-900/50'
                  : 'bg-gray-950/30 border-gray-800/50 opacity-50'
              }`}
            >
              <div>
                {/* Header Badge */}
                <div className="flex items-center justify-between mb-2">
                  <span
                    className={`text-xs font-mono font-bold px-2 py-0.5 rounded ${
                      isExitStage
                        ? 'bg-cyan-500 text-gray-950'
                        : isExecuted
                        ? 'bg-gray-800 text-cyan-400'
                        : 'bg-gray-900 text-gray-600'
                    }`}
                  >
                    Stage {stage.num}
                  </span>
                  {isExecuted && (
                    <span className="flex items-center text-[11px] font-mono text-gray-400">
                      <Clock className="w-3 h-3 mr-1 text-cyan-400" />
                      {latencyMs !== undefined ? `${latencyMs.toFixed(2)} ms` : 'Done'}
                    </span>
                  )}
                  {isSkipped && (
                    <span className="text-[10px] font-mono text-gray-600 bg-gray-900 px-1.5 py-0.5 rounded">
                      Bypassed
                    </span>
                  )}
                </div>

                {/* Stage Title */}
                <h4 className="text-sm font-semibold text-white mb-2">{stage.name}</h4>

                {/* Modalities List */}
                <ul className="space-y-1 mb-3">
                  {stage.modalities.map((mod, mIdx) => (
                    <li key={mIdx} className="text-xs font-mono text-gray-400 flex items-center space-x-1.5">
                      <div
                        className={`w-1.5 h-1.5 rounded-full ${
                          isExecuted ? 'bg-cyan-400' : 'bg-gray-700'
                        }`}
                      />
                      <span>{mod}</span>
                    </li>
                  ))}
                </ul>
              </div>

              {/* Status Footer */}
              <div className="pt-2 border-t border-gray-800/60 text-[11px] font-mono flex items-center justify-between text-gray-500">
                <span>{stage.cost}</span>
                {isExitStage && (
                  <span className="text-cyan-400 font-bold flex items-center">
                    <CheckCircle2 className="w-3.5 h-3.5 mr-0.5 text-cyan-400" />
                    Verdict
                  </span>
                )}
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}
