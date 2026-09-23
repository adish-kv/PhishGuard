import React, { useEffect, useState } from 'react';
import { History, Search, RefreshCw, ChevronRight, ExternalLink } from 'lucide-react';

export default function HistoryTable({ onSelectScan }) {
  const [history, setHistory] = useState([]);
  const [loading, setLoading] = useState(true);
  const [filter, setFilter] = useState('');

  const fetchHistory = async () => {
    setLoading(true);
    try {
      const res = await fetch('/api/v1/history');
      const json = await res.json();
      setHistory(json.items || []);
    } catch (err) {
      console.error('Failed to fetch history:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchHistory();
  }, []);

  const filteredItems = history.filter((item) =>
    filter ? item.url.toLowerCase().includes(filter.toLowerCase()) : true
  );

  return (
    <div className="bg-white border border-slate-200 rounded-2xl p-6 shadow-sm space-y-4">
      {/* Header & Search */}
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 border-b border-slate-200 pb-4">
        <div className="flex items-center space-x-3">
          <History className="w-5 h-5 text-blue-600" />
          <h3 className="text-lg font-bold text-slate-900">Historical Analysis Logs</h3>
        </div>

        <div className="flex items-center space-x-3 w-full sm:w-auto">
          <div className="relative flex-1 sm:w-64">
            <input
              type="text"
              value={filter}
              onChange={(e) => setFilter(e.target.value)}
              placeholder="Filter by URL..."
              className="w-full bg-slate-50 text-slate-900 placeholder-slate-400 text-xs font-mono rounded-lg px-3 py-2 border border-slate-300 focus:outline-none focus:border-blue-600"
            />
          </div>

          <button
            onClick={fetchHistory}
            disabled={loading}
            className="p-2 bg-slate-100 hover:bg-slate-200 text-slate-700 rounded-lg transition-colors border border-slate-200"
          >
            <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} />
          </button>
        </div>
      </div>

      {/* Table */}
      {loading ? (
        <div className="text-center text-slate-500 font-mono py-12">Loading analysis history...</div>
      ) : filteredItems.length === 0 ? (
        <div className="text-center text-slate-500 font-mono py-12">
          No historical scan records found. Run a scan from the Scanner tab.
        </div>
      ) : (
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs font-mono">
            <thead className="bg-slate-100 text-slate-700 border-b border-slate-200">
              <tr>
                <th className="p-3">Timestamp</th>
                <th className="p-3">Target URL</th>
                <th className="p-3">Verdict</th>
                <th className="p-3">Confidence</th>
                <th className="p-3">Risk Level</th>
                <th className="p-3">Stage Exit</th>
                <th className="p-3">Latency</th>
                <th className="p-3 text-right">Action</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-200 text-slate-800">
              {filteredItems.map((item, idx) => {
                const isPhish = item.prediction?.toLowerCase() === 'phishing';
                return (
                  <tr key={item.request_id || idx} className="hover:bg-blue-50/40 transition-colors">
                    <td className="p-3 text-slate-500">
                      {item.created_at ? new Date(item.created_at).toLocaleTimeString() : 'Recent'}
                    </td>
                    <td className="p-3 max-w-xs truncate font-semibold text-slate-900" title={item.url}>
                      {item.url}
                    </td>
                    <td className="p-3">
                      <span
                        className={`font-extrabold uppercase px-2 py-0.5 rounded text-[10px] ${
                          isPhish ? 'bg-red-100 text-red-700 border border-red-300' : 'bg-emerald-100 text-emerald-700 border border-emerald-300'
                        }`}
                      >
                        {item.prediction}
                      </span>
                    </td>
                    <td className="p-3 font-bold text-blue-700">
                      {(item.confidence * 100).toFixed(1)}%
                    </td>
                    <td className="p-3 text-slate-600">{item.risk_level}</td>
                    <td className="p-3 text-blue-800 uppercase">{item.stage_reached}</td>
                    <td className="p-3 text-amber-700 font-semibold">
                      {item.total_latency_ms ? `${item.total_latency_ms.toFixed(2)} ms` : 'N/A'}
                    </td>
                    <td className="p-3 text-right">
                      <button
                        onClick={() => onSelectScan(item)}
                        className="bg-blue-50 hover:bg-blue-100 text-blue-700 px-2.5 py-1 rounded border border-blue-200 flex items-center space-x-1 ml-auto transition-colors font-medium"
                      >
                        <span>View</span>
                        <ChevronRight className="w-3.5 h-3.5" />
                      </button>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
