import React, { useState } from 'react';
import { 
  Radio, 
  ExternalLink, 
  ShieldAlert, 
  ShieldCheck, 
  AlertTriangle, 
  Filter, 
  Globe, 
  Mail, 
  FileCode,
  ArrowRight,
  Eye
} from 'lucide-react';
import { LIVE_THREAT_FEED } from '../../data/mockSocData';

export const LiveThreatStream = ({ onInspectEmail, onViewChange }) => {
  const [filterSeverity, setFilterSeverity] = useState('all');

  const filteredFeed = LIVE_THREAT_FEED.filter(item => {
    if (filterSeverity === 'critical') return item.riskScore >= 90;
    if (filterSeverity === 'suspicious') return item.riskScore >= 60 && item.riskScore < 90;
    if (filterSeverity === 'benign') return item.riskScore < 60;
    return true;
  });

  const getScoreBadge = (score) => {
    if (score >= 90) {
      return 'bg-red-500/20 text-red-400 border-red-500/40 shadow-[0_0_10px_rgba(239,68,68,0.3)]';
    } else if (score >= 60) {
      return 'bg-amber-500/20 text-amber-400 border-amber-500/40';
    } else {
      return 'bg-emerald-500/20 text-emerald-400 border-emerald-500/40';
    }
  };

  const getStatusBadge = (status) => {
    switch (status) {
      case 'QUARANTINED':
      case 'BLOCKED':
      case 'PURGED & ISOLATED':
        return 'bg-red-950/80 text-red-300 border-red-500/40';
      case 'DELIVERED':
        return 'bg-emerald-950/80 text-emerald-300 border-emerald-500/40';
      default:
        return 'bg-amber-950/80 text-amber-300 border-amber-500/40';
    }
  };

  return (
    <div className="rounded-xl bg-gradient-to-b from-[#0c1424] to-[#070b14] border border-slate-800/80 p-5 shadow-lg">
      
      {/* Feed Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 mb-4">
        <div>
          <div className="flex items-center gap-2">
            <span className="relative flex h-2.5 w-2.5">
              <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-cyan-400 opacity-75"></span>
              <span className="relative inline-flex rounded-full h-2.5 w-2.5 bg-cyan-500"></span>
            </span>
            <h3 className="text-sm font-bold uppercase tracking-wider font-mono text-slate-100">
              Live Intercepted Threat Stream
            </h3>
            <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-cyan-950/60 border border-cyan-500/30 text-cyan-300">
              Auto-Correlating
            </span>
          </div>
          <p className="text-xs text-slate-400 mt-0.5">
            Real-time mail ingestion, header anomaly detection, and AI forensic score
          </p>
        </div>

        {/* Filter buttons */}
        <div className="flex items-center gap-1 bg-[#090f1d] p-1 rounded-lg border border-slate-800 text-xs font-mono">
          <Filter className="w-3.5 h-3.5 text-slate-500 ml-1 mr-1" />
          {[
            { id: 'all', label: 'All (6)' },
            { id: 'critical', label: 'Critical (4)' },
            { id: 'suspicious', label: 'Suspicious (1)' },
            { id: 'benign', label: 'Benign (1)' },
          ].map(btn => (
            <button
              key={btn.id}
              onClick={() => setFilterSeverity(btn.id)}
              className={`px-2 py-1 rounded text-[11px] transition-all ${
                filterSeverity === btn.id
                  ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40 font-semibold'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              {btn.label}
            </button>
          ))}
        </div>
      </div>

      {/* Stream List */}
      <div className="space-y-2.5">
        {filteredFeed.map((item) => (
          <div
            key={item.id}
            className="group relative rounded-lg bg-[#091122]/90 hover:bg-[#0c1830] border border-slate-800/90 hover:border-cyan-500/40 p-3.5 transition-all duration-200"
          >
            <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-3">
              
              {/* Left Column: Risk Score & Threat Overview */}
              <div className="flex items-start gap-3 min-w-0">
                
                {/* Score Pill */}
                <div className={`flex flex-col items-center justify-center w-13 h-13 rounded-lg border font-mono shrink-0 ${getScoreBadge(item.riskScore)}`}>
                  <span className="text-base font-extrabold leading-none">
                    {item.riskScore}
                  </span>
                  <span className="text-[9px] uppercase tracking-tighter opacity-80 mt-0.5">
                    / 100
                  </span>
                </div>

                {/* Sender & Subject details */}
                <div className="min-w-0 space-y-1">
                  <div className="flex flex-wrap items-center gap-2">
                    <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-slate-800 text-slate-300">
                      {item.timestamp}
                    </span>
                    <span className="text-xs font-mono font-semibold text-slate-200 truncate max-w-xs">
                      {item.displaySender}
                    </span>
                    <span className="text-xs text-slate-500">→</span>
                    <span className="text-xs font-mono text-slate-400 truncate max-w-[180px]">
                      {item.recipient}
                    </span>
                    <span className={`text-[10px] font-mono px-2 py-0.5 rounded border ${getStatusBadge(item.status)}`}>
                      {item.status}
                    </span>
                  </div>

                  <div className="text-xs font-medium text-slate-200 group-hover:text-cyan-200 transition-colors truncate">
                    {item.subject}
                  </div>

                  {/* Indicators and auth status tags */}
                  <div className="flex flex-wrap items-center gap-1.5 pt-0.5">
                    <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-slate-900 border border-slate-800 text-cyan-400">
                      {item.threatCategory}
                    </span>
                    
                    <span className={`text-[10px] font-mono px-1 py-0.2 rounded ${
                      item.spf === 'PASS' ? 'text-emerald-400 bg-emerald-950/40' : 'text-red-400 bg-red-950/40'
                    }`}>
                      SPF: {item.spf}
                    </span>
                    <span className={`text-[10px] font-mono px-1 py-0.2 rounded ${
                      item.dmarc === 'PASS' ? 'text-emerald-400 bg-emerald-950/40' : 'text-red-400 bg-red-950/40'
                    }`}>
                      DMARC: {item.dmarc}
                    </span>

                    <span className="text-[10px] font-mono text-slate-400 flex items-center gap-1">
                      <Globe className="w-3 h-3 text-slate-500" />
                      {item.ipOrigin} [{item.country}]
                    </span>
                  </div>
                </div>

              </div>

              {/* Right Column: Actions */}
              <div className="flex items-center gap-2 self-end lg:self-center shrink-0">
                <button
                  onClick={() => {
                    if (onInspectEmail) onInspectEmail(item);
                    if (onViewChange) onViewChange('analysis-results');
                  }}
                  className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-[#0e1b33] hover:bg-cyan-950/80 border border-cyan-500/30 hover:border-cyan-400 text-xs font-mono text-cyan-300 transition-all"
                >
                  <Eye className="w-3.5 h-3.5" />
                  <span>Forensic Verdict</span>
                </button>

                <button
                  onClick={() => {
                    if (onViewChange) onViewChange('threat-graph');
                  }}
                  title="View Threat Infrastructure Graph"
                  className="p-1.5 rounded-lg bg-[#0e1b33] hover:bg-[#122444] border border-slate-800 text-slate-400 hover:text-cyan-300 transition-all"
                >
                  <ExternalLink className="w-3.5 h-3.5" />
                </button>
              </div>

            </div>

            {/* Expandable Malicious Indicators */}
            {item.maliciousIndicators.length > 0 && (
              <div className="mt-2.5 pt-2 border-t border-slate-800/60 flex flex-wrap items-center gap-1.5">
                <span className="text-[10px] font-mono uppercase text-slate-500">
                  AI IOC Flags:
                </span>
                {item.maliciousIndicators.map((flag, idx) => (
                  <span
                    key={idx}
                    className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-red-950/40 border border-red-500/30 text-red-300 flex items-center gap-1"
                  >
                    <span className="w-1 h-1 rounded-full bg-red-400"></span>
                    {flag}
                  </span>
                ))}
              </div>
            )}
          </div>
        ))}
      </div>

    </div>
  );
};
