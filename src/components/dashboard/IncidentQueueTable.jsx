import React from 'react';
import { 
  Briefcase, 
  AlertOctagon, 
  ExternalLink, 
  UserCheck, 
  Clock, 
  ChevronRight,
  Shield,
  Layers
} from 'lucide-react';
import { INCIDENT_CASES } from '../../data/mockSocData';

export const IncidentQueueTable = ({ onViewChange, onSelectCase }) => {
  const getPriorityBadge = (priority) => {
    switch (priority) {
      case 'CRITICAL':
        return 'bg-red-950/70 text-red-300 border-red-500/40 font-bold';
      case 'HIGH':
        return 'bg-amber-950/70 text-amber-300 border-amber-500/40 font-semibold';
      case 'MEDIUM':
        return 'bg-blue-950/70 text-blue-300 border-blue-500/40';
      default:
        return 'bg-slate-800 text-slate-300 border-slate-700';
    }
  };

  const getStatusBadge = (status) => {
    switch (status) {
      case 'INVESTIGATING':
        return 'text-amber-400 border border-amber-500/40 bg-amber-950/30';
      case 'CONTAINED':
        return 'text-cyan-400 border border-cyan-500/40 bg-cyan-950/30';
      case 'REMEDIATED':
      case 'RESOLVED':
        return 'text-emerald-400 border border-emerald-500/40 bg-emerald-950/30';
      default:
        return 'text-slate-400 border border-slate-700 bg-slate-900';
    }
  };

  return (
    <div className="rounded-xl bg-gradient-to-b from-[#0c1424] to-[#070b14] border border-slate-800/80 p-5 shadow-lg">
      
      {/* Table Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 mb-4">
        <div>
          <div className="flex items-center gap-2">
            <Briefcase className="w-4 h-4 text-cyan-400" />
            <h3 className="text-sm font-bold uppercase tracking-wider font-mono text-slate-100">
              Active SOC Investigation Cases
            </h3>
            <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-red-950/60 border border-red-500/40 text-red-300">
              4 Active
            </span>
          </div>
          <p className="text-xs text-slate-400 mt-0.5">
            Correlated multi-user phishing campaigns escalated to incident response
          </p>
        </div>

        <button
          onClick={() => onViewChange('investigation-case')}
          className="self-start sm:self-auto flex items-center gap-1.5 text-xs font-mono text-cyan-400 hover:text-cyan-300 hover:underline"
        >
          <span>View All Cases</span>
          <ChevronRight className="w-3.5 h-3.5" />
        </button>
      </div>

      {/* Table Responsive Container */}
      <div className="overflow-x-auto">
        <table className="w-full text-left font-mono text-xs border-collapse">
          <thead>
            <tr className="border-b border-slate-800 text-[11px] text-slate-400 uppercase tracking-wider bg-[#09101e]">
              <th className="py-2.5 px-3">Case ID</th>
              <th className="py-2.5 px-3">Campaign / Title</th>
              <th className="py-2.5 px-3">Priority</th>
              <th className="py-2.5 px-3">Risk</th>
              <th className="py-2.5 px-3">Attribution</th>
              <th className="py-2.5 px-3">MITRE Codes</th>
              <th className="py-2.5 px-3">Status</th>
              <th className="py-2.5 px-3 text-right">Action</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-800/60">
            {INCIDENT_CASES.map((c) => (
              <tr 
                key={c.caseId}
                className="hover:bg-[#0c1830]/70 transition-colors group"
              >
                {/* Case ID */}
                <td className="py-3 px-3 font-bold text-cyan-300 whitespace-nowrap">
                  {c.caseId}
                </td>

                {/* Title and summary */}
                <td className="py-3 px-3 max-w-xs">
                  <div className="font-sans font-medium text-slate-200 group-hover:text-cyan-200 transition-colors line-clamp-1">
                    {c.title}
                  </div>
                  <div className="text-[10px] text-slate-500 font-sans line-clamp-1 mt-0.5">
                    {c.primaryVector} • {c.affectedTargets} VIP Targets
                  </div>
                </td>

                {/* Priority */}
                <td className="py-3 px-3 whitespace-nowrap">
                  <span className={`text-[10px] px-2 py-0.5 rounded border ${getPriorityBadge(c.priority)}`}>
                    {c.priority}
                  </span>
                </td>

                {/* Risk Score */}
                <td className="py-3 px-3 font-bold whitespace-nowrap">
                  <span className={c.riskScore >= 90 ? 'text-red-400' : 'text-amber-400'}>
                    {c.riskScore}/100
                  </span>
                </td>

                {/* Attribution */}
                <td className="py-3 px-3 text-slate-300 whitespace-nowrap">
                  <span className="px-1.5 py-0.5 rounded bg-purple-950/40 border border-purple-500/30 text-purple-300 text-[11px]">
                    {c.threatActorGroup}
                  </span>
                </td>

                {/* MITRE Tags */}
                <td className="py-3 px-3">
                  <div className="flex flex-wrap gap-1">
                    {c.mitreTactics.map((code) => (
                      <span
                        key={code}
                        className="text-[10px] px-1 py-0.2 rounded bg-slate-900 border border-slate-800 text-slate-400"
                      >
                        {code}
                      </span>
                    ))}
                  </div>
                </td>

                {/* Status */}
                <td className="py-3 px-3 whitespace-nowrap">
                  <span className={`text-[10px] px-2 py-0.5 rounded ${getStatusBadge(c.status)}`}>
                    {c.status}
                  </span>
                </td>

                {/* Actions */}
                <td className="py-3 px-3 text-right whitespace-nowrap">
                  <button
                    onClick={() => {
                      if (onSelectCase) onSelectCase(c);
                      onViewChange('investigation-case');
                    }}
                    className="inline-flex items-center gap-1 px-2.5 py-1 rounded bg-[#0d1c38] hover:bg-cyan-900/60 border border-cyan-500/30 text-cyan-300 text-xs font-mono transition-all"
                  >
                    <span>War Room</span>
                    <ChevronRight className="w-3 h-3" />
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

    </div>
  );
};
