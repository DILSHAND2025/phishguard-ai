import React, { useState, useEffect } from 'react';
import { 
  Briefcase, 
  ChevronRight, 
  ShieldAlert, 
  Inbox,
  RefreshCw
} from 'lucide-react';
import { fetchCases, getPriorityStyle } from '../../services/caseStore.js';

export const IncidentQueueTable = ({ onViewChange, onSelectCase }) => {
  const [cases, setCases] = useState([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let mounted = true;
    async function loadData() {
      setLoading(true);
      const res = await fetchCases({ status: 'active', limit: 8 });
      if (mounted) {
        setCases(res.cases || []);
        setTotal(res.total || 0);
        setLoading(false);
      }
    }
    loadData();
    return () => { mounted = false; };
  }, []);

  return (
    <div className="rounded-xl bg-gradient-to-b from-[#0c1424] to-[#070b14] border border-slate-800/80 p-5 shadow-lg font-sans">
      
      {/* Table Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 mb-4">
        <div>
          <div className="flex items-center gap-2">
            <Briefcase className="w-4 h-4 text-cyan-400" />
            <h3 className="text-sm font-bold uppercase tracking-wider font-mono text-slate-100">
              Active SOC Investigation Queue
            </h3>
            <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-cyan-950/70 border border-cyan-500/40 text-cyan-300 font-bold">
              {total} Active
            </span>
          </div>
          <p className="text-xs text-slate-400 mt-0.5">
            Database-backed persistent incidents ordered by Evidence Fusion threat score (highest risk first)
          </p>
        </div>

        <button
          onClick={() => onViewChange('investigation-case')}
          className="self-start sm:self-auto flex items-center gap-1.5 text-xs font-mono text-cyan-400 hover:text-cyan-300 hover:underline cursor-pointer"
        >
          <span>View All Cases</span>
          <ChevronRight className="w-3.5 h-3.5" />
        </button>
      </div>

      {loading ? (
        <div className="py-12 text-center text-xs text-slate-400 font-mono">
          <RefreshCw className="w-5 h-5 animate-spin mx-auto mb-2 text-cyan-400" />
          Loading case queue from database...
        </div>
      ) : cases.length === 0 ? (
        <div className="py-10 text-center space-y-2">
          <Inbox className="w-8 h-8 text-slate-600 mx-auto" />
          <p className="text-xs text-slate-400">No active cases in PostgreSQL database.</p>
          <button
            onClick={() => onViewChange('email-analysis')}
            className="px-3 py-1.5 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-semibold cursor-pointer"
          >
            Scan New Email
          </button>
        </div>
      ) : (
        <div className="overflow-x-auto">
          <table className="w-full text-left font-mono text-xs border-collapse">
            <thead>
              <tr className="border-b border-slate-800 text-[11px] text-slate-400 uppercase tracking-wider bg-[#09101e]">
                <th className="py-2.5 px-3">Case ID</th>
                <th className="py-2.5 px-3">Subject / Campaign</th>
                <th className="py-2.5 px-3">Priority</th>
                <th className="py-2.5 px-3">Score</th>
                <th className="py-2.5 px-3">Sender</th>
                <th className="py-2.5 px-3">Classification</th>
                <th className="py-2.5 px-3 text-right">Action</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 font-sans">
              {cases.map((c) => {
                const priority = c.priority || 'Low';
                const style = getPriorityStyle(priority);
                const score = typeof c.threatScore === 'number' ? c.threatScore : 0;

                return (
                  <tr 
                    key={c.caseId || c.id}
                    className="hover:bg-[#0c1830]/70 transition-colors group cursor-pointer"
                    onClick={() => onSelectCase && onSelectCase(c)}
                  >
                    <td className="py-3 px-3 font-bold text-cyan-300 font-mono whitespace-nowrap">
                      {c.caseId}
                    </td>

                    <td className="py-3 px-3 max-w-xs">
                      <div className="font-sans font-medium text-slate-200 group-hover:text-cyan-200 transition-colors truncate">
                        {c.subject || '(No Subject)'}
                      </div>
                      <div className="text-[10px] text-slate-500 truncate font-sans">
                        {c.riskSummary || c.sender}
                      </div>
                    </td>

                    <td className="py-3 px-3 whitespace-nowrap font-mono">
                      <span className={`text-[10px] px-2 py-0.5 rounded border uppercase font-bold ${style.badge}`}>
                        {priority}
                      </span>
                    </td>

                    <td className="py-3 px-3 font-bold whitespace-nowrap font-mono">
                      <span className={score >= 80 ? 'text-red-400 font-extrabold' : score >= 60 ? 'text-orange-400' : 'text-amber-400'}>
                        {score}/100
                      </span>
                    </td>

                    <td className="py-3 px-3 text-slate-300 truncate max-w-[180px] text-xs">
                      {c.sender}
                    </td>

                    <td className="py-3 px-3 whitespace-nowrap font-mono">
                      <span className={`text-[10px] px-1.5 py-0.5 rounded ${
                        (c.classification || '').toLowerCase() === 'phishing'
                          ? 'bg-red-950/60 text-red-300 border border-red-900/60'
                          : 'bg-slate-900 text-slate-300 border border-slate-800'
                      }`}>
                        {c.classification || 'Phishing'}
                      </span>
                    </td>

                    <td className="py-3 px-3 text-right whitespace-nowrap" onClick={(e) => e.stopPropagation()}>
                      <button
                        onClick={() => onSelectCase && onSelectCase(c)}
                        className="inline-flex items-center gap-1 px-2.5 py-1 rounded bg-[#0d1c38] hover:bg-cyan-900/60 border border-cyan-500/30 text-cyan-300 text-xs font-mono transition-all cursor-pointer"
                      >
                        <span>Open</span>
                        <ChevronRight className="w-3 h-3" />
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
};
