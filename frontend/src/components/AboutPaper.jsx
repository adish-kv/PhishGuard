import React from 'react';
import { BookOpen, ShieldCheck, CheckCircle2, Award, FileCode2 } from 'lucide-react';

export default function AboutPaper() {
  return (
    <div className="bg-gray-900/90 border border-gray-800 rounded-2xl p-6 shadow-xl backdrop-blur-xl space-y-6">
      <div className="flex items-center space-x-3 border-b border-gray-800 pb-4">
        <BookOpen className="w-6 h-6 text-cyan-400" />
        <div>
          <h2 className="text-xl font-bold text-white">Research Paper Specifications</h2>
          <p className="text-xs text-gray-400 font-mono">
            Intelligent Phishing Website Detection Using Visual and URL Hybrid Analysis
          </p>
        </div>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-6 font-mono text-xs">
        {/* Core Architecture */}
        <div className="bg-gray-950 p-5 rounded-xl border border-gray-800 space-y-3">
          <div className="text-cyan-400 font-bold text-sm flex items-center space-x-2">
            <Award className="w-4 h-4" />
            <span>4-Stage Adaptive Multimodal Engine</span>
          </div>
          <p className="text-gray-300 leading-relaxed">
            Standard multimodal phishing detection models process all modalities sequentially regardless of sample difficulty, incurring heavy computation (200-500ms per site). PhishGuard introduces a stage-wise decision engine that dynamically evaluates risk and halts early when confidence surpasses adaptive threshold \(\tau\).
          </p>
          <ul className="space-y-1.5 text-gray-400 pt-2">
            <li className="flex items-center space-x-2">
              <CheckCircle2 className="w-3.5 h-3.5 text-cyan-400" />
              <span>Stage 1: URL Lexical Subnet (22 features, &lt;0.5ms)</span>
            </li>
            <li className="flex items-center space-x-2">
              <CheckCircle2 className="w-3.5 h-3.5 text-blue-400" />
              <span>Stage 2: Static DOM HTML + SSL Cert (~25ms)</span>
            </li>
            <li className="flex items-center space-x-2">
              <CheckCircle2 className="w-3.5 h-3.5 text-purple-400" />
              <span>Stage 3: Domain WHOIS RDAP + EasyOCR (~100ms)</span>
            </li>
            <li className="flex items-center space-x-2">
              <CheckCircle2 className="w-3.5 h-3.5 text-pink-400" />
              <span>Stage 4: CLIP ViT-B/32 + FAISS Brand Similarity (~350ms)</span>
            </li>
          </ul>
        </div>

        {/* Evaluation & Zero-Leakage Guarantee */}
        <div className="bg-gray-950 p-5 rounded-xl border border-gray-800 space-y-3">
          <div className="text-emerald-400 font-bold text-sm flex items-center space-x-2">
            <ShieldCheck className="w-4 h-4" />
            <span>Methodological Rigor & Integrity</span>
          </div>
          <p className="text-gray-300 leading-relaxed">
            All experiments follow strict zero-leakage validation protocol. Domain-disjoint splitting enforces that no second-level domain (e.g., paypal.com) appears in both training and testing sets, eliminating synthetic accuracy inflation.
          </p>
          <div className="bg-gray-900 p-3 rounded border border-gray-800 space-y-1 text-[11px]">
            <div className="text-gray-400 font-bold">Primary Datasets:</div>
            <div className="text-gray-300">• PhishTank & OpenPhish Verified Active Feeds</div>
            <div className="text-gray-300">• Tranco Top 1 Million Legitimate Domain Benchmark</div>
            <div className="text-gray-300">• 10,000 Sample Domain-Disjoint Evaluation Split</div>
          </div>
        </div>
      </div>
    </div>
  );
}
