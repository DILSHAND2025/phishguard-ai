import React, { useState } from 'react';
import { 
  Binary, 
  ShieldAlert, 
  AlertTriangle, 
  ArrowRight, 
  ArrowLeft,
  Copy, 
  Check, 
  Globe, 
  Server, 
  Paperclip, 
  Database, 
  Info, 
  ExternalLink,
  ShieldCheck,
  Radio,
  Cpu,
  Mail,
  Filter,
  Layers
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
          <span className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded bg-red-950/80 border border-red-500/50 text-red-300 font-mono text-[10px] font-bold">
            <span className="w-1.5 h-1.5 rounded-full bg-red-400"></span>
            MALICIOUS
          </span>
        );
      case 'SUSPICIOUS':
        return (
          <span className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded bg-amber-950/80 border border-amber-500/50 text-amber-300 font-mono text-[10px] font-bold">
            <span className="w-1.5 h-1.5 rounded-full bg-amber-400"></span>
            SUSPICIOUS
          </span>
        );
      case 'CLEAN':
        return (
          <span className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded bg-emerald-950/80 border border-emerald-500/50 text-emerald-300 font-mono text-[10px] font-bold">
            <span className="w-1.5 h-1.5 rounded-full bg-emerald-400"></span>
            CLEAN
          </span>
        );
      default:
        return (
          <span className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded bg-slate-900 border border-slate-700 text-slate-400 font-mono text-[10px]">
            <span className="w-1.5 h-1.5 rounded-full bg-slate-500"></span>
            UNKNOWN
          </span>
        );
    }
  };

  const renderTypeBadge = (type) => {
    if (type.startsWith('HASH')) {
      return (
        <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded bg-pink-950/70 border border-pink-500/40 text-pink-300 font-mono text-[10px] font-bold">
          <Binary className="w-3 h-3 text-pink-400" />
          <span>HASH</span>
        </span>
      );
    }
    switch (type.toUpperCase()) {
      case 'URL':
        return (
          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded bg-cyan-950/70 border border-cyan-500/40 text-cyan-300 font-mono text-[10px] font-bold">
            <Globe className="w-3 h-3 text-cyan-400" />
            <span>URL</span>
          </span>
        );
      case 'IP':
        return (
          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded bg-purple-950/70 border border-purple-500/40 text-purple-300 font-mono text-[10px] font-bold">
            <Server className="w-3 h-3 text-purple-400" />
            <span>IP</span>
          </span>
        );
      case 'DOMAIN':
        return (
          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded bg-blue-950/70 border border-blue-500/40 text-blue-300 font-mono text-[10px] font-bold">
            <Globe className="w-3 h-3 text-blue-400" />
            <span>DOMAIN</span>
          </span>
        );
      case 'EMAIL':
        return (
          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded bg-amber-950/70 border border-amber-500/40 text-amber-300 font-mono text-[10px] font-bold">
            <Mail className="w-3 h-3 text-amber-400" />
            <span>EMAIL</span>
          </span>
        );
      case 'ATTACHMENT':
        return (
          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded bg-red-950/70 border border-red-500/40 text-red-300 font-mono text-[10px] font-bold">
            <Paperclip className="w-3 h-3 text-red-400" />
            <span>ATTACHMENT</span>
          </span>
        );
      default:
        return (
          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded bg-slate-800 border border-slate-700 text-slate-300 font-mono text-[10px]">
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
    <div className="space-y-6 pb-12 font-sans">
      
      {/* Top Banner Header */}
      <div className="relative overflow-hidden rounded-2xl bg-gradient-to-r from-purple-950/40 via-[#0d162a] to-[#070b13] border border-purple-500/40 p-6 shadow-[0_0_30px_rgba(168,85,247,0.15)]">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
          <div>
            <div className="flex items-center gap-2 text-purple-400 text-xs font-mono mb-1.5">
              <span className="w-2 h-2 rounded-full bg-purple-400 animate-ping"></span>
              STAGE 04 OF 08 • AUTOMATED IOC EXTRACTION & REPUTATION
            </div>

            <div className="flex flex-wrap items-center gap-3">
              <h1 className="text-xl sm:text-2xl font-extrabold text-white font-mono flex items-center gap-2.5">
                <Binary className="w-6 h-6 text-purple-400" />
                <span>Indicators of Compromise (IOC) Intelligence</span>
              </h1>
              <span className="px-2.5 py-0.5 rounded bg-cyan-950/80 border border-cyan-500/40 text-cyan-300 font-mono text-xs font-bold">
                {rawIocs.length} Extracted Artifacts
              </span>
            </div>

            <p className="text-xs text-slate-300 mt-1.5 font-mono">
              Automated extraction of IPs, URLs, Domains, Email vectors, and Hashes with verified reputation scoring.
            </p>
          </div>

          {/* Navigation Controls */}
          <div className="flex flex-wrap items-center gap-2.5 shrink-0">
            <button
              type="button"
              id="btn-back-analysis-results-top"
              onClick={() => onViewChange('analysis-results')}
              className="flex items-center gap-1.5 px-3.5 py-2 rounded-xl bg-[#091122] hover:bg-[#0e1b33] border border-slate-700 text-slate-300 font-mono text-xs transition-all cursor-pointer"
            >
              <ArrowLeft className="w-3.5 h-3.5" />
              <span>Back to AI Score</span>
            </button>

            <button
              type="button"
              id="btn-proceed-geo-top"
              onClick={() => onViewChange('geo-asn')}
              className="flex items-center gap-2 px-4 py-2 rounded-xl bg-gradient-to-r from-cyan-600 to-blue-600 hover:from-cyan-500 hover:to-blue-500 text-white font-mono text-xs font-bold shadow-[0_0_15px_rgba(6,182,212,0.4)] transition-all cursor-pointer"
            >
              <Server className="w-4 h-4" />
              <span>Proceed to GeoLocation & ASN</span>
              <ArrowRight className="w-4 h-4" />
            </button>
          </div>
        </div>
      </div>

      {/* Summary Metric Counters */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-4 font-mono text-xs">
        <div className="p-4 rounded-xl bg-[#09101e] border border-red-500/30 space-y-1">
          <span className="text-[10px] uppercase text-slate-400 font-bold">Malicious IOCs</span>
          <div className="text-2xl font-black text-red-400">{maliciousCount}</div>
          <span className="text-[10px] text-red-300/80">Immediate block required</span>
        </div>

        <div className="p-4 rounded-xl bg-[#09101e] border border-amber-500/30 space-y-1">
          <span className="text-[10px] uppercase text-slate-400 font-bold">Suspicious IOCs</span>
          <div className="text-2xl font-black text-amber-400">{suspiciousCount}</div>
          <span className="text-[10px] text-amber-300/80">Under analyst review</span>
        </div>

        <div className="p-4 rounded-xl bg-[#09101e] border border-emerald-500/30 space-y-1">
          <span className="text-[10px] uppercase text-slate-400 font-bold">Clean Artifacts</span>
          <div className="text-2xl font-black text-emerald-400">{cleanCount}</div>
          <span className="text-[10px] text-slate-500">Known benign format</span>
        </div>

        <div className="p-4 rounded-xl bg-[#09101e] border border-slate-800 space-y-1">
          <span className="text-[10px] uppercase text-slate-400 font-bold">Unlisted / Unknown</span>
          <div className="text-2xl font-black text-slate-400">{unknownCount}</div>
          <span className="text-[10px] text-slate-500">External intel pending</span>
        </div>
      </div>

      {/* Main IOC Table & Filters */}
      <div className="rounded-xl bg-[#09101e] border border-slate-800 p-5 shadow-lg space-y-4">
        
        {/* Filter Bar */}
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-slate-800 pb-3">
          <div className="flex items-center gap-2">
            <Filter className="w-4 h-4 text-cyan-400" />
            <h2 className="text-sm font-bold uppercase tracking-wider font-mono text-white">
              Extracted Indicators ({filteredIocs.length})
            </h2>
          </div>

          {/* Filter Pills */}
          <div className="flex flex-wrap gap-1.5 font-mono text-[11px]">
            {['ALL', 'IP', 'DOMAIN', 'URL', 'ATTACHMENT', 'HASH', 'EMAIL'].map(f => (
              <button
                key={f}
                type="button"
                onClick={() => setActiveFilter(f)}
                className={`px-2.5 py-1 rounded-lg border transition-all cursor-pointer ${
                  activeFilter === f
                    ? 'bg-cyan-950 border-cyan-400 text-cyan-300 font-bold shadow-sm'
                    : 'bg-[#060a14] border-slate-800 text-slate-400 hover:text-slate-200'
                }`}
              >
                {f}
              </button>
            ))}
          </div>
        </div>

        {/* IOC Data Table */}
        <div className="overflow-x-auto">
          <table className="w-full text-left font-mono text-xs">
            <thead>
              <tr className="border-b border-slate-800 text-[10px] text-slate-500 uppercase tracking-wider">
                <th className="py-2.5 px-3">Type</th>
                <th className="py-2.5 px-3">Indicator Value</th>
                <th className="py-2.5 px-3">Status</th>
                <th className="py-2.5 px-3">Reputation & Threat Context</th>
                <th className="py-2.5 px-3">Source</th>
                <th className="py-2.5 px-3 text-right">Action</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60">
              {filteredIocs.map((ioc, idx) => (
                <tr key={ioc.id || idx} className="hover:bg-slate-900/40 transition-colors">
                  <td className="py-3 px-3 shrink-0">
                    {renderTypeBadge(ioc.type)}
                  </td>
                  <td className="py-3 px-3 font-semibold text-slate-200 max-w-xs break-all">
                    {ioc.value}
                  </td>
                  <td className="py-3 px-3 shrink-0">
                    {renderStatusBadge(ioc.status)}
                  </td>
                  <td className="py-3 px-3 text-slate-300 text-[11px] max-w-sm">
                    {ioc.reputation}
                    {ioc.relatedIndicators?.length > 0 && (
                      <div className="text-[10px] text-cyan-400/80 mt-0.5">
                        Related: {ioc.relatedIndicators.filter(Boolean).join(', ')}
                      </div>
                    )}
                  </td>
                  <td className="py-3 px-3 text-[10px] text-slate-500">
                    {ioc.source}
                  </td>
                  <td className="py-3 px-3 text-right shrink-0">
                    <button
                      type="button"
                      onClick={() => handleCopy(ioc.value, idx)}
                      className="inline-flex items-center gap-1 text-[10px] font-mono text-slate-400 hover:text-cyan-300 px-2 py-1 rounded bg-[#060a14] border border-slate-800 transition-colors cursor-pointer"
                    >
                      {copiedIndex === idx ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                      <span>{copiedIndex === idx ? 'Copied' : 'Copy'}</span>
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

      </div>

      {/* Multi-Source Threat Intelligence Layer Cards (Phase 5) */}
      <div className="rounded-xl bg-[#09101e] border border-slate-800 p-5 shadow-lg space-y-4 font-mono">
        <div className="flex items-center gap-2 border-b border-slate-800 pb-3">
          <Database className="w-5 h-5 text-cyan-400" />
          <h2 className="text-sm font-bold uppercase tracking-wider text-white">
            Enrichment Feeds Status (Multi-Vendor Consensus)
          </h2>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-3">
          
          <div className="p-3.5 rounded-lg bg-[#060a14] border border-slate-800 space-y-1.5">
            <div className="flex justify-between items-center text-xs">
              <span className="font-bold text-white">VirusTotal</span>
              <span className="text-[10px] px-1.5 py-0.2 rounded bg-red-950 text-red-300 border border-red-500/40">FLAGGED</span>
            </div>
            <p className="text-[10px] text-slate-400">
              Multi-engine consensus flags domain & double-extension executable hash.
            </p>
            <span className="text-[9px] text-cyan-300 block pt-1 border-t border-slate-900">
              Detection: 56/72 Vendors
            </span>
          </div>

          <div className="p-3.5 rounded-lg bg-[#060a14] border border-slate-800 space-y-1.5">
            <div className="flex justify-between items-center text-xs">
              <span className="font-bold text-white">AbuseIPDB</span>
              <span className="text-[10px] px-1.5 py-0.2 rounded bg-amber-950 text-amber-300 border border-amber-500/40">94% ABUSE</span>
            </div>
            <p className="text-[10px] text-slate-400">
              Originating IP 185.220.101.45 reported for port scanning and Tor relay behavior.
            </p>
            <span className="text-[9px] text-amber-300 block pt-1 border-t border-slate-900">
              Reports: 348 Submissions
            </span>
          </div>

          <div className="p-3.5 rounded-lg bg-[#060a14] border border-slate-800 space-y-1.5">
            <div className="flex justify-between items-center text-xs">
              <span className="font-bold text-white">URLhaus</span>
              <span className="text-[10px] px-1.5 py-0.2 rounded bg-red-950 text-red-300 border border-red-500/40">BLACKLISTED</span>
            </div>
            <p className="text-[10px] text-slate-400">
              Associated phishing URL matches active credential harvest campaigns.
            </p>
            <span className="text-[9px] text-red-300 block pt-1 border-t border-slate-900">
              Status: Active Phish
            </span>
          </div>

          <div className="p-3.5 rounded-lg bg-[#060a14] border border-slate-800 space-y-1.5">
            <div className="flex justify-between items-center text-xs">
              <span className="font-bold text-white">PhishTank</span>
              <span className="text-[10px] px-1.5 py-0.2 rounded bg-emerald-950 text-emerald-300 border border-emerald-500/40">VERIFIED</span>
            </div>
            <p className="text-[10px] text-slate-400">
              Community verification confirms unauthorized wire and token redirection.
            </p>
            <span className="text-[9px] text-emerald-300 block pt-1 border-t border-slate-900">
              Verdict: Validated Threat
            </span>
          </div>

        </div>
      </div>

    </div>
  );
};
