import React from 'react';
import { PieChart, Sparkles } from 'lucide-react';

export default function ModalityChart({ explanation }) {
  if (!explanation) return null;

  const weights = explanation.modality_weights || {
    url: 0.35,
    html: 0.25,
    ssl: 0.15,
    domain: 0.10,
    ocr: 0.08,
    visual: 0.07,
  };

  const modalityMeta = [
    { key: 'url', label: 'URL Lexical Subnet', color: 'from-cyan-500 to-blue-500', icon: '🔗' },
    { key: 'html', label: 'HTML DOM Subnet', color: 'from-blue-500 to-indigo-500', icon: '🌐' },
    { key: 'ssl', label: 'SSL/TLS Cert Subnet', color: 'from-indigo-500 to-purple-500', icon: '🔒' },
    { key: 'domain', label: 'Domain WHOIS Subnet', color: 'from-purple-500 to-pink-500', icon: '📅' },
    { key: 'ocr', label: 'OCR Text Subnet', color: 'from-pink-500 to-rose-500', icon: '🔤' },
    { key: 'visual', label: 'CLIP Visual Subnet', color: 'from-amber-500 to-emerald-500', icon: '🖼️' },
  ];

  const totalWeight = Object.values(weights).reduce((a, b) => a + b, 0) || 1;

  return (
    <div className="bg-gray-900/90 border border-gray-800 rounded-2xl p-6 shadow-xl backdrop-blur-xl">
      <div className="flex items-center space-x-3 mb-4">
        <PieChart className="w-5 h-5 text-cyan-400" />
        <h3 className="text-lg font-bold text-white">Modality Contribution Weights</h3>
      </div>

      <div className="space-y-4">
        {modalityMeta.map((item) => {
          const rawWeight = weights[item.key] || 0;
          const pct = Math.round((rawWeight / totalWeight) * 100);

          return (
            <div key={item.key} className="space-y-1">
              <div className="flex justify-between items-center text-xs font-mono">
                <span className="text-gray-300 flex items-center space-x-2">
                  <span>{item.icon}</span>
                  <span>{item.label}</span>
                </span>
                <span className="font-bold text-cyan-400">{pct}%</span>
              </div>
              <div className="w-full bg-gray-950 h-2.5 rounded-full overflow-hidden border border-gray-800">
                <div
                  className={`h-full rounded-full bg-gradient-to-r ${item.color} transition-all duration-500`}
                  style={{ width: `${pct}%` }}
                />
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}
