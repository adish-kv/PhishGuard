import React, { useState } from 'react';
import {
  CheckCircle2,
  Clock,
  FastForward,
  AlertTriangle,
  Layers,
  Info,
  ChevronDown,
  ShieldAlert,
  Cpu,
  Lock,
  Globe,
  FileCode,
  Image,
  Sparkles,
  ExternalLink,
  X
} from 'lucide-react';

export default function StageProgress({ result }) {
  if (!result) return null;

  const [selectedStageId, setSelectedStageId] = useState('stage_1');

  const stageLatencies = result.stage_latencies_ms || {};
  const stageReachedStr = (result.stage_reached || 'stage_1').toLowerCase();
  const exp = result.explanation || {};

  const stages = [
    {
      id: 'stage_1',
      num: 1,
      name: 'Lexical & URL Structural',
      modalities: ['URL Subnet (22 features)', 'SSL/TLS (10 features)', 'Domain WHOIS (6 features)'],
      cost: 'Cost: ~0.5ms (Zero Egress)',
      thresholdRule: 'Early Exit if P1 ≤ 0.15 (Benign) or P1 ≥ 0.85 (Phishing)',
      featuresList: [
        'Shannon Character Entropy (Randomness metric)',
        'Subdomain Depth & Dot Count',
        'Raw IP Host Detection',
        'Suspicious Keyword Count (login, verify, account)',
        'TLS Certificate Validity & Age (Days)',
        'Domain RDAP Registration Age (Days)'
      ],
      reasons: exp.stage1_reasons || [],
      probability: exp.stage1_probability,
      icon: Globe,
      color: 'cyan'
    },
    {
      id: 'stage_2',
      num: 2,
      name: 'Static HTML DOM Analysis',
      modalities: ['HTML Subnet (28 features)'],
      cost: 'Cost: ~15-40ms (Static DOM)',
      thresholdRule: 'Early Exit if P2 ≤ 0.10 (Benign) or P2 ≥ 0.90 (Phishing)',
      featuresList: [
        'Credential Login Form Presence (<input type="password">)',
        'Form Action Target External Domain Ratio',
        'Obfuscated JavaScript Function Patterns (eval, unescape)',
        'Hidden iFrames & Meta Refresh Redirects',
        'External Resource Domain Ratios (CSS, JS, Images)'
      ],
      reasons: exp.stage2_reasons || [],
      probability: exp.stage2_probability,
      icon: FileCode,
      color: 'blue'
    },
    {
      id: 'stage_3',
      num: 3,
      name: 'WHOIS RDAP & EasyOCR Text',
      modalities: ['Domain RDAP Subnet', 'EasyOCR Text (13 features)'],
      cost: 'Cost: ~80-150ms (RDAP / OCR)',
      thresholdRule: 'Advanced Text Extraction if HTML DOM is ambiguous',
      featuresList: [
        'EasyOCR Image Text Extraction & Density',
        'Target Brand Keyword Frequency (PayPal, Apple, Bank of America)',
        'Bounding Box Text Density Ratio',
        'Registrar Trust Rating & DNSSEC Status'
      ],
      reasons: exp.stage3_reasons || [],
      probability: exp.stage3_probability,
      icon: Cpu,
      color: 'purple'
    },
    {
      id: 'stage_4',
      num: 4,
      name: 'CLIP Visual & FAISS Brand Matching',
      modalities: ['Visual ViT-B/32 (512d vector)', 'FAISS Cosine Brand Index'],
      cost: 'Cost: ~200-500ms (Vision Neural Net)',
      thresholdRule: 'Full Multimodal Upper Bound Classifier (PyTorch 192d Subnet)',
      featuresList: [
        'Playwright Sandboxed Chromium Screenshot Capture (1280x720)',
        'OpenAI CLIP ViT-B/32 Vision Embedding (512-dim)',
        'FAISS Inner Product Cosine Similarity Search',
        'Visual Brand Impersonation Match Confidence (%)',
        'PyTorch Multimodal Concatenated Subnet Classification'
      ],
      reasons: exp.stage4_reasons || [],
      probability: exp.final_probability,
      brandMatch: exp.brand_impersonation,
      icon: Image,
      color: 'pink'
    }
  ];

  // Map stage_reached string (e.g., 'stage1', 'stage_1', 'stage4')
  const normalizeStageStr = (s) => s.replace('_', '').toLowerCase();
  const reachedNorm = normalizeStageStr(stageReachedStr);

  const reachedStageIndex = stages.findIndex((s) => normalizeStageStr(s.id) === reachedNorm) !== -1
    ? stages.findIndex((s) => normalizeStageStr(s.id) === reachedNorm)
    : 0;

  const currentSelectedStage = stages.find((s) => s.id === selectedStageId) || stages[0];
  const selectedIdx = stages.findIndex((s) => s.id === selectedStageId);
  const isSelectedExecuted = selectedIdx <= reachedStageIndex;
  const isSelectedExit = selectedIdx === reachedStageIndex;

  return (
    <div className="bg-gray-900/90 border border-gray-800 rounded-2xl p-6 shadow-xl backdrop-blur-xl space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3">
        <div className="flex items-center space-x-3">
          <Layers className="w-5 h-5 text-purple-400" />
          <div>
            <h3 className="text-lg font-bold text-white">4-Stage Adaptive Multimodal Pipeline Execution</h3>
            <p className="text-xs text-gray-400 font-mono">
              Click any stage card below to inspect detailed feature extraction & decision metrics
            </p>
          </div>
        </div>

        {result.early_stopped && (
          <span className="flex items-center space-x-1.5 text-xs font-mono font-semibold bg-amber-500/10 text-amber-400 px-3 py-1.5 rounded-full border border-amber-500/30">
            <FastForward className="w-4 h-4" />
            <span>Early Exit Triggered at Stage {reachedStageIndex + 1}</span>
          </span>
        )}
      </div>

      {/* Stage Cards Flow (Clickable) */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4 relative">
        {stages.map((stage, idx) => {
          const isExecuted = idx <= reachedStageIndex;
          const isExitStage = idx === reachedStageIndex;
          const isSkipped = idx > reachedStageIndex;
          const isSelected = stage.id === selectedStageId;
          const latencyMs = stageLatencies[stage.id] || stageLatencies[`${stage.id}_ms`];
          const IconComp = stage.icon;

          return (
            <button
              key={stage.id}
              type="button"
              onClick={() => setSelectedStageId(stage.id)}
              className={`relative text-left rounded-xl border p-4 transition-all duration-200 flex flex-col justify-between cursor-pointer focus:outline-none ${
                isSelected
                  ? 'ring-2 ring-cyan-400 border-cyan-400 shadow-lg shadow-cyan-500/10 scale-[1.02]'
                  : 'hover:border-gray-700 hover:bg-gray-800/40'
              } ${
                isExitStage
                  ? result.prediction?.toLowerCase() === 'phishing'
                    ? 'bg-red-950/20 border-red-500/40 shadow-md shadow-red-500/10'
                    : 'bg-emerald-950/20 border-emerald-500/40 shadow-md shadow-emerald-500/10'
                  : isExecuted
                  ? 'bg-gray-950/80 border-cyan-900/50'
                  : 'bg-gray-950/30 border-gray-800/50 opacity-60'
              }`}
            >
              <div>
                {/* Top Badge Row */}
                <div className="flex items-center justify-between mb-2">
                  <span
                    className={`text-xs font-mono font-bold px-2 py-0.5 rounded flex items-center space-x-1 ${
                      isExitStage
                        ? 'bg-cyan-500 text-gray-950'
                        : isExecuted
                        ? 'bg-gray-800 text-cyan-400'
                        : 'bg-gray-900 text-gray-600'
                    }`}
                  >
                    <IconComp className="w-3 h-3 mr-1 inline" />
                    <span>Stage {stage.num}</span>
                  </span>

                  {isExecuted && (
                    <span className="flex items-center text-[11px] font-mono text-gray-400">
                      <Clock className="w-3 h-3 mr-1 text-cyan-400" />
                      {latencyMs !== undefined ? `${latencyMs.toFixed(2)} ms` : 'Done'}
                    </span>
                  )}
                  {isSkipped && (
                    <span className="text-[10px] font-mono text-amber-400/80 bg-amber-500/10 px-1.5 py-0.5 rounded border border-amber-500/20">
                      Bypassed
                    </span>
                  )}
                </div>

                {/* Stage Name */}
                <h4 className="text-sm font-semibold text-white mb-2">{stage.name}</h4>

                {/* Modalities Pill List */}
                <ul className="space-y-1 mb-3">
                  {stage.modalities.map((mod, mIdx) => (
                    <li key={mIdx} className="text-xs font-mono text-gray-400 flex items-center space-x-1.5">
                      <div className={`w-1.5 h-1.5 rounded-full ${isExecuted ? 'bg-cyan-400' : 'bg-gray-700'}`} />
                      <span className="truncate">{mod}</span>
                    </li>
                  ))}
                </ul>
              </div>

              {/* Bottom Footer */}
              <div className="pt-2 border-t border-gray-800/60 text-[11px] font-mono flex items-center justify-between text-gray-500">
                <span>{isExecuted ? 'Active' : 'Bypassed'}</span>
                <span className="text-cyan-400 font-bold flex items-center space-x-1">
                  <span>Inspect</span>
                  <ChevronDown className={`w-3 h-3 transition-transform ${isSelected ? 'rotate-180' : ''}`} />
                </span>
              </div>
            </button>
          );
        })}
      </div>

      {/* Detailed Stage Inspector Panel (Appears when clicking any Stage Card) */}
      <div className="bg-gray-950 border border-cyan-900/40 rounded-xl p-5 space-y-4 font-mono animate-fadeIn">
        {/* Panel Header */}
        <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-2 border-b border-gray-800 pb-3">
          <div className="flex items-center space-x-3">
            <div className="p-2 bg-cyan-500/10 border border-cyan-500/30 rounded-lg text-cyan-400">
              {React.createElement(currentSelectedStage.icon, { className: 'w-5 h-5' })}
            </div>
            <div>
              <div className="flex items-center space-x-2">
                <span className="text-sm font-bold text-white uppercase">
                  Stage {currentSelectedStage.num}: {currentSelectedStage.name}
                </span>
                <span
                  className={`text-[10px] font-bold px-2 py-0.5 rounded border ${
                    isSelectedExit
                      ? 'bg-emerald-500/20 text-emerald-400 border-emerald-500/40'
                      : isSelectedExecuted
                      ? 'bg-cyan-500/20 text-cyan-400 border-cyan-500/40'
                      : 'bg-amber-500/20 text-amber-400 border-amber-500/40'
                  }`}
                >
                  {isSelectedExit
                    ? 'VERDICT EXIT STAGE'
                    : isSelectedExecuted
                    ? 'EXECUTED (PASSED)'
                    : 'BYPASSED (COST SAVED)'}
                </span>
              </div>
              <p className="text-xs text-gray-400 mt-0.5">{currentSelectedStage.thresholdRule}</p>
            </div>
          </div>

          <div className="text-right text-xs text-gray-400">
            <div>Benchmark: <span className="text-cyan-400 font-bold">{currentSelectedStage.cost}</span></div>
          </div>
        </div>

        {/* Detailed Content Grid */}
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6 pt-1 text-xs">
          {/* Left Column: Extracted Features in this Stage */}
          <div className="space-y-2">
            <div className="text-cyan-400 font-bold uppercase tracking-wider flex items-center space-x-1.5">
              <Info className="w-3.5 h-3.5" />
              <span>Features Extracted in Stage {currentSelectedStage.num}</span>
            </div>
            <ul className="space-y-1.5 bg-gray-900/60 p-3 rounded-lg border border-gray-800 text-gray-300">
              {currentSelectedStage.featuresList.map((feat, idx) => (
                <li key={idx} className="flex items-start space-x-2">
                  <CheckCircle2 className={`w-3.5 h-3.5 mt-0.5 shrink-0 ${isSelectedExecuted ? 'text-emerald-400' : 'text-gray-600'}`} />
                  <span>{feat}</span>
                </li>
              ))}
            </ul>
          </div>

          {/* Right Column: Stage Triggered Reasons & Risk Indicators */}
          <div className="space-y-2">
            <div className="text-purple-400 font-bold uppercase tracking-wider flex items-center space-x-1.5">
              <AlertTriangle className="w-3.5 h-3.5 text-amber-400" />
              <span>Stage Decision & Triggered Indicators</span>
            </div>

            {currentSelectedStage.reasons && currentSelectedStage.reasons.length > 0 ? (
              <div className="space-y-1.5">
                {currentSelectedStage.reasons.map((reason, idx) => (
                  <div
                    key={idx}
                    className="bg-red-950/20 border border-red-900/40 p-2.5 rounded-lg text-red-300 flex items-start space-x-2"
                  >
                    <AlertTriangle className="w-3.5 h-3.5 text-red-400 shrink-0 mt-0.5" />
                    <span>{reason}</span>
                  </div>
                ))}
              </div>
            ) : isSelectedExecuted ? (
              <div className="bg-emerald-950/20 border border-emerald-900/40 p-3 rounded-lg text-emerald-300 text-xs">
                Stage {currentSelectedStage.num} executed cleanly. No critical anomaly triggers flagged in this layer.
              </div>
            ) : (
              <div className="bg-amber-950/20 border border-amber-900/40 p-3 rounded-lg text-amber-300 text-xs">
                ⚡ <strong>Early Exit Triggered in earlier stage!</strong> Stage {currentSelectedStage.num} analysis was bypassed to save computational cost and network egress latency.
              </div>
            )}

            {/* Additional details for Stage 4 brand match */}
            {currentSelectedStage.id === 'stage_4' && currentSelectedStage.brandMatch && currentSelectedStage.brandMatch !== 'none' && (
              <div className="bg-purple-950/30 border border-purple-800/50 p-3 rounded-lg text-purple-200 mt-2 flex items-center space-x-2">
                <Sparkles className="w-4 h-4 text-amber-400 shrink-0" />
                <div>
                  <strong>FAISS Brand Cosine Match:</strong> Impersonating <span className="text-amber-400 font-bold uppercase">{currentSelectedStage.brandMatch}</span> template!
                </div>
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
