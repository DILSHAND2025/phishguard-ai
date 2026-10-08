import React, { useState } from 'react';
import { 
  ExternalLink, 
  Filter, 
  Globe, 
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
      return 'bg-red-50 text-red-700 border-red-200';
    } else if (score >= 60) {
      return 'bg-orange-50 text-orange-700 border-orange-200';
    } else {
      return 'bg-emerald-50 text-emerald-700 border-emerald-200';
    }
  };

  const getStatusBadge = (status) => {
    switch (status) {
      case 'QUARANTINED':
      case 'BLOCKED':
      case 'PURGED & ISOLATED':
        return 'bg-red-50 text-red-700 border-red-200';
      case 'DELIVERED':
        return 'bg-emerald-50 text-emerald-700 border-emerald-200';
      default:
        return 'bg-amber-50 text-amber-800 border-amber-200';
    }
  };

  return (
    <div className="rounded-xl bg-white border border-slate-200 p-5 shadow-xs font-sans">
      
      {/* Feed Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 mb-4">
        <div>
          <div className="flex items-center gap-2">
            <span className="relative flex h-2 w-2">
              <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-red-400 opacity-75"></span>
              <span className="relative inline-flex rounded-full h-2 w-2 bg-red-500"></span>
            </span>
            <h3 className="text-sm font-bold uppercase tracking-wider text-slate-900">
              Live Threat Stream
            </h3>
            <span className="text-[10px] font-semibold px-2 py-0.5 rounded bg-slate-100 border border-slate-200 text-slate-700">
              Correlating
            </span>
          </div>
          <p className="text-xs text-slate-500 mt-0.5">
            Real-time mail ingestion, header anomaly detection, and AI forensic score
          </p>
        </div>

        {/* Filter buttons */}
        <div className="flex items-center gap-1 bg-slate-100 p-1 rounded-lg border border-slate-200 text-xs">
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
              className={`px-2.5 py-1 rounded text-xs transition-colors cursor-pointer ${
                filterSeverity === btn.id
                  ? 'bg-white text-slate-900 font-bold shadow-2xs'
                  : 'text-slate-600 hover:text-slate-900'
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
            className="group relative rounded-lg bg-white hover:bg-slate-50/70 border border-slate-200 p-3.5 transition-colors shadow-2xs"
          >
            <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-3">
              
              {/* Left Column: Risk Score & Threat Overview */}
              <div className="flex items-start gap-3 min-w-0">
                
                {/* Score Pill */}
                <div className={`flex flex-col items-center justify-center w-12 h-12 rounded-lg border shrink-0 ${getScoreBadge(item.riskScore)}`}>
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
                    <span className="text-[10px] px-1.5 py-0.5 rounded bg-slate-100 text-slate-600 font-mono">
                      {item.timestamp}
                    </span>
                    <span className="text-xs font-semibold text-slate-900 truncate max-w-xs">
                      {item.displaySender}
                    </span>
                    <span className="text-xs text-slate-400">→</span>
                    <span className="text-xs text-slate-600 truncate max-w-[180px]">
                      {item.recipient}
                    </span>
                    <span className={`text-[10px] font-bold px-2 py-0.5 rounded border ${getStatusBadge(item.status)}`}>
                      {item.status}
                    </span>
                  </div>

                  <div className="text-xs font-medium text-slate-800 truncate">
                    {item.subject}
                  </div>

                  {/* Indicators and auth status tags */}
                  <div className="flex flex-wrap items-center gap-1.5 pt-0.5">
                    <span className="text-[10px] px-1.5 py-0.5 rounded bg-slate-100 border border-slate-200 text-slate-700 font-medium">
                      {item.threatCategory}
                    </span>
                    
                    <span className={`text-[10px] px-1.5 py-0.5 rounded font-medium border ${
                      item.spf === 'PASS' ? 'text-emerald-700 bg-emerald-50 border-emerald-200' : 'text-red-700 bg-red-50 border-red-200'
                    }`}>
                      SPF: {item.spf}
                    </span>
                    <span className={`text-[10px] px-1.5 py-0.5 rounded font-medium border ${
                      item.dmarc === 'PASS' ? 'text-emerald-700 bg-emerald-50 border-emerald-200' : 'text-red-700 bg-red-50 border-red-200'
                    }`}>
                      DMARC: {item.dmarc}
                    </span>

                    <span className="text-[10px] text-slate-500 flex items-center gap-1 font-mono">
                      <Globe className="w-3 h-3 text-slate-400" />
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
                  className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-white hover:bg-slate-50 border border-slate-200 text-xs font-semibold text-slate-700 transition-colors shadow-2xs cursor-pointer"
                >
                  <Eye className="w-3.5 h-3.5 text-slate-500" />
                  <span>View Details</span>
                </button>

                <button
                  onClick={() => {
                    if (onViewChange) onViewChange('threat-graph');
                  }}
                  title="View Threat Graph"
                  className="p-1.5 rounded-lg bg-white hover:bg-slate-50 border border-slate-200 text-slate-500 hover:text-slate-800 transition-colors cursor-pointer shadow-2xs"
                >
                  <ExternalLink className="w-3.5 h-3.5" />
                </button>
              </div>

            </div>

            {/* Expandable Malicious Indicators */}
            {item.maliciousIndicators && item.maliciousIndicators.length > 0 && (
              <div className="mt-2.5 pt-2 border-t border-slate-100 flex flex-wrap items-center gap-1.5">
                <span className="text-[10px] uppercase font-semibold text-slate-400">
                  Flags:
                </span>
                {item.maliciousIndicators.map((flag, idx) => (
                  <span
                    key={idx}
                    className="text-[10px] px-1.5 py-0.5 rounded bg-red-50 border border-red-200 text-red-700 flex items-center gap-1 font-medium"
                  >
                    <span className="w-1 h-1 rounded-full bg-red-500"></span>
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
