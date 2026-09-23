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

  const isPhishing = result.prediction?.toLowerCase() === 'phishing';

  const stages = [
    {
      id: 'stage_1',
      num: 1,
      name: 'Lexical & URL Structural',
      modalities: ['URL Subnet (22 features)', 'SSL/TLS (10 features)', 'Domain WHOIS (6 features)'],
      cost: 'Cost: ~0.5ms (Zero Egress)',
      thresholdRule: 'Early Exit if P1 ≤ 0.15 (Benign) or P1 ≥ 0.85 (Phishing)',
      detailedFeatures: [
        {
          name: 'Shannon Character Entropy',
          extracted: 'Calculates character randomness score across hostname & path',
          checkBenign: 'Low entropy string format (< 4.25). Standard domain pattern.',
          checkPhish: 'Elevated entropy score (> 4.85). Random DGA-like string pattern.',
          badgeBenign: 'Clean',
          badgePhish: 'High Randomness'
        },
        {
          name: 'Subdomain Depth & Dot Separation',
          extracted: 'Parses URL hierarchy, subdomains count, and dot density ratio',
          checkBenign: 'Standard domain depth (<= 2 levels). No nested subdomains.',
          checkPhish: 'Deep subdomain nesting (>= 3 subdomains) masking true host.',
          badgeBenign: 'Clean',
          badgePhish: 'Deep Subdomains'
        },
        {
          name: 'Raw IP Host Identification',
          extracted: 'Checks if target host uses IPv4/IPv6 address instead of registered domain',
          checkBenign: 'Standard registered domain name hostname detected.',
          checkPhish: 'Direct IP address host format bypasses domain reputation.',
          badgeBenign: 'Clean',
          badgePhish: 'Raw IP Host'
        },
        {
          name: 'Suspicious Security Keywords Count',
          extracted: 'Scans path & query for terms (login, verify, secure, update, account)',
          checkBenign: '0 suspicious security keywords in URL path.',
          checkPhish: 'Multiple credential harvesting keywords present in path.',
          badgeBenign: 'Clean',
          badgePhish: 'Keyword Flagged'
        },
        {
          name: 'TLS/SSL Certificate Verification & Age',
          extracted: 'Executes TLS handshake to inspect issuer, expiration, and SAN match',
          checkBenign: 'Valid certificate issued by trusted CA. Subject match verified.',
          checkPhish: 'Self-signed, untrusted CA, or hostname SAN mismatch detected.',
          badgeBenign: 'Verified SSL',
          badgePhish: 'SSL Anomaly'
        },
        {
          name: 'Domain WHOIS / RDAP Registration Age',
          extracted: 'Queries RDAP protocol for domain creation timestamp',
          checkBenign: 'Established domain (> 365 days active). Registered reputation.',
          checkPhish: 'Newly registered domain (< 30 days active). Disposable site.',
          badgeBenign: 'Established',
          badgePhish: 'Newly Registered'
        }
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
      detailedFeatures: [
        {
          name: 'Credential Input Form Presence',
          extracted: 'Parses DOM tree for <input type="password"> & <form> tags',
          checkBenign: 'No password credential input fields detected in DOM.',
          checkPhish: 'Credential input fields detected for authentication capture.',
          badgeBenign: 'Clean',
          badgePhish: 'Password Form'
        },
        {
          name: 'Form Action External Target Ratio',
          extracted: 'Compares form action POST destination against host origin',
          checkBenign: 'Form action posts to same-origin domain endpoint.',
          checkPhish: 'Form action posts credentials to cross-origin external host.',
          badgeBenign: 'Clean',
          badgePhish: 'External POST'
        },
        {
          name: 'Obfuscated Script Function Patterns',
          extracted: 'Scans inline JS for eval(), unescape(), String.fromCharCode()',
          checkBenign: 'Standard cleartext JavaScript execution without obfuscation.',
          checkPhish: 'Obfuscated JavaScript payload detected to bypass static engines.',
          badgeBenign: 'Clean',
          badgePhish: 'JS Obfuscated'
        },
        {
          name: 'Hidden Overlay iFrames & Meta Refresh',
          extracted: 'Inspects DOM for 0-pixel iframes and meta http-equiv="refresh"',
          checkBenign: 'Zero hidden overlay frames or auto-redirect tags found.',
          checkPhish: 'Hidden overlay iframe tag or client-side meta redirect detected.',
          badgeBenign: 'Clean',
          badgePhish: 'Hidden iFrame'
        },
        {
          name: 'External Resource Hotlinking Ratios',
          extracted: 'Calculates ratio of external CSS, JS, and image asset links',
          checkBenign: 'Self-hosted static assets or standard CDN host links.',
          checkPhish: 'High ratio of asset images hotlinked directly from target brand.',
          badgeBenign: 'Clean',
          badgePhish: 'Asset Hotlink'
        }
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
      detailedFeatures: [
        {
          name: 'EasyOCR Image Text Token Extraction',
          extracted: 'Runs EasyOCR deep learning neural network on page screenshot',
          checkBenign: 'Extracted text tokens match legitimate site content.',
          checkPhish: 'Extracted rendered text contains phishing urgency phrases.',
          badgeBenign: 'Parsed',
          badgePhish: 'Urgency Text'
        },
        {
          name: 'Target Brand Keyword Frequency',
          extracted: 'Cross-checks OCR text against top 50 impersonated brand signatures',
          checkBenign: 'Rendered text matches registered domain identity.',
          checkPhish: 'Discrepancy: Target brand name rendered inside image text.',
          badgeBenign: 'Clean',
          badgePhish: 'Brand Mismatch'
        },
        {
          name: 'Bounding Box Text Spatial Density',
          extracted: 'Calculates bounding box coordinates & text density distribution',
          checkBenign: 'Standard web document paragraph & navigation text layout.',
          checkPhish: 'Centralized login form visual density with high contrast input.',
          badgeBenign: 'Normal Layout',
          badgePhish: 'Form Layout'
        },
        {
          name: 'Registrar Security & DNSSEC Accreditation',
          extracted: 'Verifies ICANN registrar trust tier and DNSSEC signatures',
          checkBenign: 'ICANN accredited tier-1 registrar with DNSSEC active.',
          checkPhish: 'Low-reputation registrar with anonymous WHOIS privacy mask.',
          badgeBenign: 'Verified',
          badgePhish: 'Unaccredited'
        }
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
      detailedFeatures: [
        {
          name: 'Playwright Sandboxed Chromium Screenshot',
          extracted: 'Captures full 1280x720 headless viewport screenshot in sandbox',
          checkBenign: 'Page rendered cleanly. Visual frame passed to CLIP vision pipeline.',
          checkPhish: 'Page rendered cleanly. Visual frame passed to CLIP vision pipeline.',
          badgeBenign: 'Rendered 1280x720',
          badgePhish: 'Rendered 1280x720'
        },
        {
          name: 'OpenAI CLIP ViT-B/32 Visual Vector',
          extracted: 'Encodes visual screenshot into 512-dimensional embedding space',
          checkBenign: '512-dim visual feature tensor normalized for similarity search.',
          checkPhish: '512-dim visual feature tensor normalized for similarity search.',
          badgeBenign: 'Extracted 512d',
          badgePhish: 'Extracted 512d'
        },
        {
          name: 'FAISS Inner Product Cosine Brand Search',
          extracted: 'Queries FAISS vector index against top brand visual templates',
          checkBenign: 'Low cosine similarity (< 0.85) to protected brand templates.',
          checkPhish: 'High cosine similarity (>= 0.85) matching protected brand template.',
          badgeBenign: 'No Match (<0.85)',
          badgePhish: 'Visual Brand Match'
        },
        {
          name: 'PyTorch Multimodal Concatenated Classifier',
          extracted: 'Late-fusion PyTorch neural net combining all 192 feature dimensions',
          checkBenign: 'Upper bound multimodal probability below risk threshold.',
          checkPhish: 'Upper bound multimodal probability confirms phishing classification.',
          badgeBenign: 'Benign Verdict',
          badgePhish: 'Phishing Verdict'
        }
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
                  ? isPhishing
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
          {/* Left Column: Extracted Features & How They Checked Out */}
          <div className="space-y-3">
            <div className="text-cyan-400 font-bold uppercase tracking-wider flex items-center space-x-1.5">
              <Info className="w-3.5 h-3.5" />
              <span>Extracted Features & Verification Breakdown</span>
            </div>

            <div className="space-y-2.5">
              {currentSelectedStage.detailedFeatures.map((feat, idx) => {
                const isFlagged = isSelectedExecuted && isPhishing;
                const badgeText = !isSelectedExecuted
                  ? 'BYPASSED'
                  : isFlagged
                  ? feat.badgePhish
                  : feat.badgeBenign;
                const checkText = !isSelectedExecuted
                  ? 'Bypassed to save computational resources and network latency.'
                  : isFlagged
                  ? feat.checkPhish
                  : feat.checkBenign;

                return (
                  <div
                    key={idx}
                    className={`p-3 rounded-xl border text-xs font-mono space-y-1.5 transition-colors ${
                      !isSelectedExecuted
                        ? 'bg-gray-900/40 border-gray-800 text-gray-500'
                        : isFlagged
                        ? 'bg-red-950/20 border-red-900/40 text-red-200'
                        : 'bg-gray-900/80 border-gray-800 text-gray-200'
                    }`}
                  >
                    {/* Top Row: Feature Name + Status Badge */}
                    <div className="flex items-center justify-between">
                      <div className="flex items-center space-x-2 font-semibold">
                        <CheckCircle2
                          className={`w-3.5 h-3.5 shrink-0 ${
                            !isSelectedExecuted
                              ? 'text-gray-600'
                              : isFlagged
                              ? 'text-red-400'
                              : 'text-emerald-400'
                          }`}
                        />
                        <span className="text-white">{feat.name}</span>
                      </div>

                      <span
                        className={`text-[10px] font-bold px-2 py-0.5 rounded border ${
                          !isSelectedExecuted
                            ? 'bg-gray-800/60 text-gray-500 border-gray-700/50'
                            : isFlagged
                            ? 'bg-red-500/20 text-red-400 border-red-500/30'
                            : 'bg-emerald-500/20 text-emerald-400 border-emerald-500/30'
                        }`}
                      >
                        {badgeText}
                      </span>
                    </div>

                    {/* What is Extracted */}
                    <div className="text-[11px] text-gray-400 pl-5">
                      <span className="text-cyan-400/90 font-medium">Extracted:</span> {feat.extracted}
                    </div>

                    {/* How it checks out */}
                    <div className="text-[11px] pl-5 leading-relaxed">
                      <span className="text-purple-400/90 font-medium">Verification Check:</span>{' '}
                      <span className={!isSelectedExecuted ? 'text-gray-500' : isFlagged ? 'text-red-300 font-semibold' : 'text-emerald-300'}>
                        {checkText}
                      </span>
                    </div>
                  </div>
                );
              })}
            </div>
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
