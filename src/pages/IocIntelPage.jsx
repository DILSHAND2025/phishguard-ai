import React, { useState } from 'react';
import { 
  Binary, 
  ArrowRight, 
  ArrowLeft,
  Copy, 
  Check, 
  Globe, 
  Server, 
  Paperclip, 
  Database, 
  Mail, 
  Filter
} from 'lucide-react';

export const IocIntelPage = ({ onViewChange, currentAnalysis }) => {
  const [activeFilter, setActiveFilter] = useState('ALL');
  const [copiedIndex, setCopiedIndex] = useState(null);

  const rawIocs = currentAnalysis?.iocs || [
    {
      id: 'ioc-1',
      type: 'IP',
      value: '185.220.101.45',
      status: 'MALICIOUS',
      reputation: 'Tor relay node with 94% abuse confidence score (AS9009)',
      source: 'Envelope Originating / Received Hop Header',
      relatedIndicators: ['internal-corp-portal.online']
    },
    {
      id: 'ioc-2',
      type: 'DOMAIN',
      value: 'internal-corp-portal.online',
      status: 'MALICIOUS',
      reputation: 'Typosquatting domain targeting state treasury authorization',
      source: 'From Header',
      relatedIndicators: ['cfo-finance-update@internal-corp-portal.online']
    },
    {
      id: 'ioc-3',
      type: 'URL',
      value: 'http://internal-corp-portal.online/auth-portal/wire-release',
      status: 'MALICIOUS',
      reputation: 'Identified wire diversion credential harvesting endpoint',
      source: 'Email Body Hyperlink',
      relatedIndicators: ['internal-corp-portal.online']
    },
    {
      id: 'ioc-4',
      type: 'EMAIL',
      value: 'external-offshore-treasury@proton.me',
      status: 'SUSPICIOUS',
      reputation: 'Reply-To redirected recipient differing from sender identity',
      source: 'Reply-To Header',
      relatedIndicators: ['internal-corp-portal.online']
    },
    {
      id: 'ioc-5',
      type: 'ATTACHMENT',
      value: 'Wire_Remittance_Directive.pdf.exe',
      status: 'MALICIOUS',
      reputation: 'Double Extension / Obfuscated PE32 Executable Binary (242.6 KB)',
      source: 'Email Attachment Section',
      relatedIndicators: ['8f4c102948a7b6c5d4e3f27d1a293b6e']
    },
    {
      id: 'ioc-6',
      type: 'HASH (SHA256)',
      value: '8f4c102948a7b6c5d4e3f27d1a293b6e8f4c102948a7b6c5d4e3f27d1a293b6e',
      status: 'MALICIOUS',
      reputation: 'Flagged malicious payload hash (double extension PE32 dropper)',
      source: 'Attachment Hash for Wire_Remittance_Directive.pdf.exe',
      relatedIndicators: ['Wire_Remittance_Directive.pdf.exe']
    }
  ];

  const filteredIocs = rawIocs.filter(ioc => {
    if (activeFilter === 'ALL') return true;
    if (activeFilter === 'HASH') return ioc.type.startsWith('HASH');
    return ioc.type === activeFilter;
  });

  const handleCopy = (text, index) => {
    navigator.clipboard?.writeText(text);
    setCopiedIndex(index);
    setTimeout(() => setCopiedIndex(null), 1500);
  };

  const renderStatusBadge = (status) => {
    switch (status.toUpperCase()) {
      case 'MALICIOUS':
        return (
          <span className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded bg-red-50 border border-red-200 text-red-700 text-[10px] font-bold">
            <span className="w-1.5 h-1.5 rounded-full bg-red-500"></span>
            MALICIOUS
          </span>
        );
      case 'SUSPICIOUS':
        return (
          <span className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded bg-amber-50 border border-amber-200 text-amber-800 text-[10px] font-bold">
            <span className="w-1.5 h-1.5 rounded-full bg-amber-500"></span>
            SUSPICIOUS
          </span>
        );
      case 'CLEAN':
        return (
          <span className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded bg-emerald-50 border border-emerald-200 text-emerald-700 text-[10px] font-bold">
            <span className="w-1.5 h-1.5 rounded-full bg-emerald-500"></span>
            CLEAN
          </span>
        );
      default:
        return (
          <span className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded bg-slate-100 border border-slate-200 text-slate-600 text-[10px] font-semibold">
            <span className="w-1.5 h-1.5 rounded-full bg-slate-400"></span>
            UNKNOWN
          </span>
        );
    }
  };

  const renderTypeBadge = (type) => {
    if (type.startsWith('HASH')) {
      return (
        <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded bg-slate-100 border border-slate-200 text-slate-700 text-[10px] font-bold">
          <Binary className="w-3 h-3 text-slate-500" />
          <span>HASH</span>
        </span>
      );
    }
    switch (type.toUpperCase()) {
      case 'URL':
        return (
          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded bg-sky-50 border border-sky-200 text-sky-700 text-[10px] font-bold">
            <Globe className="w-3 h-3 text-sky-600" />
            <span>URL</span>
          </span>
        );
      case 'IP':
        return (
          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded bg-purple-50 border border-purple-200 text-purple-700 text-[10px] font-bold">
            <Server className="w-3 h-3 text-purple-600" />
            <span>IP</span>
          </span>
        );
      case 'DOMAIN':
        return (
          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded bg-blue-50 border border-blue-200 text-blue-700 text-[10px] font-bold">
            <Globe className="w-3 h-3 text-blue-600" />
            <span>DOMAIN</span>
          </span>
        );
      case 'EMAIL':
        return (
          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded bg-amber-50 border border-amber-200 text-amber-800 text-[10px] font-bold">
            <Mail className="w-3 h-3 text-amber-600" />
            <span>EMAIL</span>
          </span>
        );
      case 'ATTACHMENT':
        return (
          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded bg-red-50 border border-red-200 text-red-700 text-[10px] font-bold">
            <Paperclip className="w-3 h-3 text-red-600" />
            <span>ATTACHMENT</span>
          </span>
        );
      default:
        return (
          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded bg-slate-100 border border-slate-200 text-slate-700 text-[10px] font-semibold">
            {type}
          </span>
        );
    }
  };

  const maliciousCount = rawIocs.filter(i => i.status === 'MALICIOUS').length;
  const suspiciousCount = rawIocs.filter(i => i.status === 'SUSPICIOUS').length;
  const cleanCount = rawIocs.filter(i => i.status === 'CLEAN').length;
  const unknownCount = rawIocs.filter(i => i.status === 'UNKNOWN').length;

  return (
    <div className="space-y-6 pb-12 font-sans text-slate-900">
      
      {/* Top Banner Header */}
      <div className="rounded-xl bg-white border border-slate-200 p-6 shadow-xs">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
          <div>
            <div className="flex items-center gap-2 text-slate-500 text-xs font-semibold uppercase tracking-wider mb-1.5">
              <span>Automated IOC Extraction & Reputation</span>
            </div>

            <div className="flex flex-wrap items-center gap-3">
              <h1 className="text-xl sm:text-2xl font-bold text-slate-900 flex items-center gap-2.5">
                <Binary className="w-6 h-6 text-slate-700" />
                <span>Indicators of Compromise (IOC) Intelligence</span>
              </h1>
              <span className="px-2.5 py-0.5 rounded bg-slate-100 border border-slate-200 text-slate-700 text-xs font-semibold">
                {rawIocs.length} Extracted Artifacts
              </span>
            </div>

            <p className="text-xs text-slate-500 mt-1.5">
              Automated extraction of IPs, URLs, Domains, Email vectors, and Hashes with verified reputation scoring.
            </p>
          </div>

          {/* Navigation Controls */}
          <div className="flex flex-wrap items-center gap-2.5 shrink-0">
            <button
              type="button"
              id="btn-back-analysis-results-top"
              onClick={() => onViewChange('security-analyzer')}
              className="flex items-center gap-1.5 px-3.5 py-2 rounded-lg bg-white hover:bg-slate-50 border border-slate-200 text-slate-700 text-xs font-semibold transition-colors shadow-2xs cursor-pointer"
            >
              <ArrowLeft className="w-3.5 h-3.5 text-slate-500" />
              <span>Back to Security Analyzer</span>
            </button>

            <button
              type="button"
              id="btn-proceed-geo-top"
              onClick={() => onViewChange('geo-asn')}
              className="flex items-center gap-2 px-4 py-2 rounded-lg bg-slate-900 hover:bg-slate-800 text-white text-xs font-semibold shadow-xs transition-colors cursor-pointer"
            >
              <Server className="w-4 h-4" />
              <span>Proceed to GeoLocation</span>
              <ArrowRight className="w-4 h-4" />
            </button>
          </div>
        </div>
      </div>

      {/* Summary Metric Counters */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-4 text-xs">
        <div className="p-4 rounded-xl bg-white border border-slate-200 shadow-xs space-y-1">
          <div className="flex items-center justify-between">
            <span className="text-[10px] uppercase text-slate-500 font-bold">Malicious IOCs</span>
            <span className="w-2 h-2 rounded-full bg-red-500"></span>
          </div>
          <div className="text-2xl font-black text-slate-900">{maliciousCount}</div>
          <span className="text-[11px] text-red-700 font-medium">Immediate block recommended</span>
        </div>

        <div className="p-4 rounded-xl bg-white border border-slate-200 shadow-xs space-y-1">
          <div className="flex items-center justify-between">
            <span className="text-[10px] uppercase text-slate-500 font-bold">Suspicious IOCs</span>
            <span className="w-2 h-2 rounded-full bg-amber-500"></span>
          </div>
          <div className="text-2xl font-black text-slate-900">{suspiciousCount}</div>
          <span className="text-[11px] text-amber-800 font-medium">Under analyst review</span>
        </div>

        <div className="p-4 rounded-xl bg-white border border-slate-200 shadow-xs space-y-1">
          <div className="flex items-center justify-between">
            <span className="text-[10px] uppercase text-slate-500 font-bold">Clean Artifacts</span>
            <span className="w-2 h-2 rounded-full bg-emerald-500"></span>
          </div>
          <div className="text-2xl font-black text-slate-900">{cleanCount}</div>
          <span className="text-[11px] text-emerald-700 font-medium">Legitimate communication format</span>
        </div>

        <div className="p-4 rounded-xl bg-white border border-slate-200 shadow-xs space-y-1">
          <div className="flex items-center justify-between">
            <span className="text-[10px] uppercase text-slate-500 font-bold">Unlisted / Neutral</span>
            <span className="w-2 h-2 rounded-full bg-slate-400"></span>
          </div>
          <div className="text-2xl font-black text-slate-900">{unknownCount}</div>
          <span className="text-[11px] text-slate-500 font-medium">Pending external enrichment</span>
        </div>
      </div>

      {/* Main IOC Table & Filters */}
      <div className="rounded-xl bg-white border border-slate-200 p-5 shadow-xs space-y-4">
        
        {/* Filter Bar */}
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-slate-100 pb-3">
          <div className="flex items-center gap-2">
            <Filter className="w-4 h-4 text-slate-600" />
            <h2 className="text-sm font-bold uppercase tracking-wider text-slate-900">
              Extracted Indicators ({filteredIocs.length})
            </h2>
          </div>

          {/* Filter Pills */}
          <div className="flex flex-wrap gap-1.5 text-xs">
            {['ALL', 'IP', 'DOMAIN', 'URL', 'ATTACHMENT', 'HASH', 'EMAIL'].map(f => (
              <button
                key={f}
                type="button"
                onClick={() => setActiveFilter(f)}
                className={`px-3 py-1 rounded-md border transition-colors cursor-pointer font-semibold ${
                  activeFilter === f
                    ? 'bg-slate-900 border-slate-900 text-white shadow-2xs'
                    : 'bg-white border-slate-200 text-slate-600 hover:text-slate-900'
                }`}
              >
                {f}
              </button>
            ))}
          </div>
        </div>

        {/* IOC Data Table */}
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead>
              <tr className="border-b border-slate-200 text-[10px] text-slate-500 uppercase tracking-wider bg-slate-50/50">
                <th className="py-2.5 px-3">Type</th>
                <th className="py-2.5 px-3">Indicator Value</th>
                <th className="py-2.5 px-3">Status</th>
                <th className="py-2.5 px-3">Reputation Context</th>
                <th className="py-2.5 px-3">Source</th>
                <th className="py-2.5 px-3 text-right">Action</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100">
              {filteredIocs.map((ioc, idx) => (
                <tr key={ioc.id || idx} className="hover:bg-slate-50/60 transition-colors">
                  <td className="py-3 px-3 shrink-0">
                    {renderTypeBadge(ioc.type)}
                  </td>
                  <td className="py-3 px-3 font-semibold text-slate-900 max-w-xs break-all font-mono">
                    {ioc.value}
                  </td>
                  <td className="py-3 px-3 shrink-0">
                    {renderStatusBadge(ioc.status)}
                  </td>
                  <td className="py-3 px-3 text-slate-600 text-xs max-w-sm">
                    {ioc.reputation}
                    {ioc.relatedIndicators?.length > 0 && (
                      <div className="text-[11px] text-slate-400 mt-0.5">
                        Related: {ioc.relatedIndicators.filter(Boolean).join(', ')}
                      </div>
                    )}
                  </td>
                  <td className="py-3 px-3 text-[11px] text-slate-500">
                    {ioc.source}
                  </td>
                  <td className="py-3 px-3 text-right shrink-0">
                    <button
                      type="button"
                      onClick={() => handleCopy(ioc.value, idx)}
                      className="inline-flex items-center gap-1 text-[11px] text-slate-600 hover:text-slate-900 px-2 py-1 rounded bg-white hover:bg-slate-50 border border-slate-200 transition-colors cursor-pointer shadow-2xs font-medium"
                    >
                      {copiedIndex === idx ? <Check className="w-3 h-3 text-emerald-600" /> : <Copy className="w-3 h-3 text-slate-400" />}
                      <span>{copiedIndex === idx ? 'Copied' : 'Copy'}</span>
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

      </div>

      {/* Multi-Source Threat Intelligence Layer Cards */}
      <div className="rounded-xl bg-white border border-slate-200 p-5 shadow-xs space-y-4">
        <div className="flex items-center gap-2 border-b border-slate-100 pb-3">
          <Database className="w-5 h-5 text-slate-700" />
          <h2 className="text-sm font-bold uppercase tracking-wider text-slate-900">
            Enrichment Feeds Consensus
          </h2>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-3 text-xs">
          
          <div className="p-3.5 rounded-lg bg-slate-50 border border-slate-200 space-y-1.5">
            <div className="flex justify-between items-center">
              <span className="font-bold text-slate-900">VirusTotal</span>
              <span className="text-[10px] px-1.5 py-0.5 rounded bg-red-50 text-red-700 border border-red-200 font-bold">FLAGGED</span>
            </div>
            <p className="text-[11px] text-slate-500">
              Multi-engine consensus flags domain & double-extension executable hash.
            </p>
            <span className="text-[10px] text-slate-700 font-medium block pt-1 border-t border-slate-200">
              Detection: 56/72 Vendors
            </span>
          </div>

          <div className="p-3.5 rounded-lg bg-slate-50 border border-slate-200 space-y-1.5">
            <div className="flex justify-between items-center">
              <span className="font-bold text-slate-900">AbuseIPDB</span>
              <span className="text-[10px] px-1.5 py-0.5 rounded bg-amber-50 text-amber-800 border border-amber-200 font-bold">94% ABUSE</span>
            </div>
            <p className="text-[11px] text-slate-500">
              Originating IP 185.220.101.45 reported for port scanning and Tor relay behavior.
            </p>
            <span className="text-[10px] text-slate-700 font-medium block pt-1 border-t border-slate-200">
              Reports: 348 Submissions
            </span>
          </div>

          <div className="p-3.5 rounded-lg bg-slate-50 border border-slate-200 space-y-1.5">
            <div className="flex justify-between items-center">
              <span className="font-bold text-slate-900">URLhaus</span>
              <span className="text-[10px] px-1.5 py-0.5 rounded bg-red-50 text-red-700 border border-red-200 font-bold">BLACKLISTED</span>
            </div>
            <p className="text-[11px] text-slate-500">
              Associated phishing URL matches active credential harvest campaigns.
            </p>
            <span className="text-[10px] text-slate-700 font-medium block pt-1 border-t border-slate-200">
              Status: Active Phish
            </span>
          </div>

          <div className="p-3.5 rounded-lg bg-slate-50 border border-slate-200 space-y-1.5">
            <div className="flex justify-between items-center">
              <span className="font-bold text-slate-900">PhishTank</span>
              <span className="text-[10px] px-1.5 py-0.5 rounded bg-emerald-50 text-emerald-700 border border-emerald-200 font-bold">VERIFIED</span>
            </div>
            <p className="text-[11px] text-slate-500">
              Community verification confirms unauthorized wire and token redirection.
            </p>
            <span className="text-[10px] text-slate-700 font-medium block pt-1 border-t border-slate-200">
              Verdict: Validated Threat
            </span>
          </div>

        </div>
      </div>

    </div>
  );
};
