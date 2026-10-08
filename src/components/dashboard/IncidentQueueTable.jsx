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
    <div className="rounded-xl bg-white border border-slate-200 p-5 shadow-2xs font-sans">
      
      {/* Table Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 mb-4">
        <div>
          <div className="flex items-center gap-2">
            <Briefcase className="w-4 h-4 text-cyan-600" />
            <h3 className="text-sm font-bold uppercase tracking-wider font-mono text-slate-900">
              Active SOC Investigation Queue
            </h3>
            <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-cyan-50 border border-cyan-200 text-cyan-700 font-bold">
              {total} Active
            </span>
          </div>
          <p className="text-xs text-slate-500 mt-0.5">
            Database-backed persistent incidents ordered by Evidence Fusion threat score (highest risk first)
          </p>
        </div>

        <button
          onClick={() => onViewChange('investigation-case')}
          className="self-start sm:self-auto flex items-center gap-1.5 text-xs font-mono text-cyan-700 hover:text-cyan-800 font-semibold hover:underline cursor-pointer"
        >
          <span>View All Cases</span>
          <ChevronRight className="w-3.5 h-3.5" />
        </button>
      </div>

      {loading ? (
        <div className="py-12 text-center text-xs text-slate-500 font-mono space-y-2">
          <RefreshCw className="w-5 h-5 text-cyan-600 animate-spin mx-auto" />
          <p>Querying persistent case database...</p>
        </div>
      ) : cases.length === 0 ? (
        <div className="py-10 text-center text-xs text-slate-500 space-y-2">
          <Inbox className="w-8 h-8 text-slate-400 mx-auto" />
          <p>No active incidents found in database.</p>
        </div>
      ) : (
        <div className="overflow-x-auto">
          <table className="w-full text-left font-mono text-xs border-collapse">
            <thead>
              <tr className="border-b border-slate-200 text-[11px] text-slate-500 uppercase tracking-wider bg-slate-50/70">
                <th className="py-2.5 px-3">Score</th>
                <th className="py-2.5 px-3">Priority</th>
                <th className="py-2.5 px-3">Case ID</th>
                <th className="py-2.5 px-3 font-sans">Subject</th>
                <th className="py-2.5 px-3">Sender</th>
                <th className="py-2.5 px-3">Classification</th>
                <th className="py-2.5 px-3 text-right">Action</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100 font-sans">
              {cases.map((c) => {
                const style = getPriorityStyle(c.priority);
                return (
                  <tr
                    key={c.caseId || c.id}
                    onClick={() => {
                      if (onSelectCase) onSelectCase(c);
                      onViewChange('investigation-case');
                    }}
                    className="hover:bg-slate-50 transition-colors cursor-pointer group"
                  >
                    <td className="py-3 px-3 font-mono font-bold">
                      <span className={`px-2 py-0.5 rounded text-xs font-bold border ${style.pill}`}>
                        {c.threatScore}
                      </span>
                    </td>
                    <td className="py-3 px-3 whitespace-nowrap font-mono">
                      <span className={`text-[10px] px-2 py-0.5 rounded uppercase border font-semibold ${style.badge}`}>
                        {c.priority}
                      </span>
                    </td>
                    <td className="py-3 px-3 font-mono font-bold text-cyan-700 group-hover:text-cyan-800 whitespace-nowrap">
                      {c.caseId}
                    </td>
                    <td className="py-3 px-3 max-w-xs truncate font-medium text-slate-800 group-hover:text-cyan-700 transition-colors">
                      {c.subject || '(No Subject)'}
                    </td>
                    <td className="py-3 px-3 text-slate-500 max-w-[180px] truncate text-xs">
                      {c.sender}
                    </td>
                    <td className="py-3 px-3 whitespace-nowrap font-mono text-xs text-slate-600">
                      {c.classification || 'Phishing'}
                    </td>
                    <td className="py-3 px-3 text-right whitespace-nowrap">
                      <button
                        onClick={(e) => {
                          e.stopPropagation();
                          if (onSelectCase) onSelectCase(c);
                          onViewChange('security-analyzer');
                        }}
                        className="text-xs text-cyan-700 hover:text-cyan-900 font-semibold hover:underline"
                      >
                        Inspect
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
