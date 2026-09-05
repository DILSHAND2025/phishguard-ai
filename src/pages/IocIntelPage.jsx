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
  Globe2, 
  Server, 
  Paperclip, 
  Database, 
  Info, 
  ExternalLink,
  ShieldCheck,
  Radio,
  Cpu
} from 'lucide-react';

const IOC_DATA = [
  {
    type: 'URL',
    indicator: 'malicious-site.com/login',
    risk: 'HIGH',
    purpose: 'Credential phishing',
    status: 'FLAGGED / BLOCKED'
  },
  {
    type: 'IP',
    indicator: '185.220.101.15',
    risk: 'HIGH',
    purpose: 'Suspicious infrastructure',
    status: 'FLAGGED / BLOCKED'
  },
  {
    type: 'DOMAIN',
    indicator: 'bad-update.net',
    risk: 'HIGH',
    purpose: 'Malicious domain indicator',
    status: 'FLAGGED / BLOCKED'
  },
  {
    type: 'IP',
    indicator: '104.21.36.45',
    risk: 'MEDIUM',
    purpose: 'Suspicious hosting infrastructure',
    status: 'SUSPICIOUS / UNDER REVIEW'
  },
  {
    type: 'DOMAIN',
    indicator: 'evil-content.org',
    risk: 'HIGH',
    purpose: 'Malicious indicator',
    status: 'FLAGGED / BLOCKED'
  },
  {
    type: 'ATTACHMENT',
    indicator: 'invoice.pdf',
    risk: 'HIGH',
    purpose: 'Suspicious attachment',
    status: 'QUARANTINED'
  }
];

const ENRICHMENT_SOURCES = [
  {
    name: 'VirusTotal',
    type: 'Multi-Engine Consensus',
    simulatedResult: '58/70 security engines flagged associated domain/URL patterns as malicious.',
    status: 'Flagged High Risk'
  },
  {
    name: 'AbuseIPDB',
    type: 'IP Reputation Database',
    simulatedResult: 'Confidence of Abuse: 94%. Reported for unauthorized scanning and relay behavior.',
    status: 'High Abuse Confidence'
  },
  {
    name: 'URLhaus',
    type: 'Malicious URL Repository',
    simulatedResult: 'Matches active phishing campaign distribution URL signature.',
    status: 'Blacklisted URL'
  },
  {
    name: 'PhishTank',
    type: 'Community Phishing Feed',
    simulatedResult: 'Verified phishing credential submission target matching online banking decoy patterns.',
    status: 'Verified Phish'
  },
  {
    name: 'GeoIP / ASN',
    type: 'Autonomous System Resolution',
    simulatedResult: 'Routed through anonymizing relay infrastructure (AS9009 / AS202425).',
    status: 'High-Risk Egress'
  }
];

export const IocIntelPage = ({ onViewChange }) => {
  const [copiedIndex, setCopiedIndex] = useState(null);

  const handleCopy = (text, index) => {
    navigator.clipboard?.writeText(text);
    setCopiedIndex(index);
    setTimeout(() => setCopiedIndex(null), 1500);
  };

  const renderTypeBadge = (type) => {
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
          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded bg-sky-950/70 border border-sky-500/40 text-sky-300 font-mono text-[10px] font-bold">
            <Globe2 className="w-3 h-3 text-sky-400" />
            <span>DOMAIN</span>
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
          <span className="px-2 py-0.5 rounded bg-slate-800 text-slate-300 font-mono text-[10px]">
            {type}
          </span>
        );
    }
  };

  const renderRiskBadge = (risk) => {
    if (risk === 'HIGH') {
      return (
        <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded bg-red-950/80 border border-red-500/50 text-red-300 font-mono text-[10px] font-extrabold">
          <span className="w-1.5 h-1.5 rounded-full bg-red-400 animate-pulse"></span>
          <span>HIGH</span>
        </span>
      );
    }
    return (
      <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded bg-amber-950/80 border border-amber-500/50 text-amber-300 font-mono text-[10px] font-bold">
        <span>MEDIUM</span>
      </span>
    );
  };

  return (
    <div className="space-y-6 pb-12 font-sans">
      
      {/* Top Banner Header */}
      <div className="relative overflow-hidden rounded-2xl bg-gradient-to-r from-purple-950/40 via-[#0d162a] to-[#070b13] border border-purple-500/40 p-6 shadow-[0_0_30px_rgba(168,85,247,0.15)]">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
          <div>
            <div className="flex items-center gap-2 text-purple-400 text-xs font-mono mb-1.5">
              <span className="w-2 h-2 rounded-full bg-purple-400 animate-ping"></span>
              STAGE 04 OF 08 • IOC EXTRACTION & ENRICHMENT
            </div>

            <div className="flex flex-wrap items-center gap-3">
              <h1 className="text-xl sm:text-2xl font-extrabold text-white font-mono flex items-center gap-2.5">
                <Binary className="w-6 h-6 text-purple-400" />
                <span>IOC Intelligence</span>
              </h1>

              {/* Requirement 2: Small badge SIMULATED DEMO DATA */}
              <span className="px-2.5 py-0.5 rounded bg-amber-950/80 border border-amber-500/50 text-amber-300 font-mono text-[11px] font-bold shadow-sm">
                SIMULATED DEMO DATA
              </span>
            </div>

            <p className="text-xs text-slate-300 mt-1.5 font-mono">
              Extracted forensic artifacts mapped with multi-source synthetic reputation scoring for SIH 2026.
            </p>
          </div>

          {/* Action Buttons */}
          <div className="flex flex-wrap items-center gap-2.5 shrink-0">
            <button
              type="button"
              id="btn-back-analysis-results"
              onClick={() => onViewChange('analysis-results')}
              className="flex items-center gap-1.5 px-3.5 py-2 rounded-xl bg-[#091122] hover:bg-[#0e1b33] border border-slate-700 text-slate-300 font-mono text-xs transition-all cursor-pointer"
            >
              <ArrowLeft className="w-3.5 h-3.5" />
              <span>Back to Analysis</span>
            </button>

            {/* Requirement 9: Proceed to GeoLocation & ASN button */}
            <button
              type="button"
              id="btn-proceed-geo-asn"
              onClick={() => onViewChange('geo-asn')}
              className="flex items-center gap-2 px-4 py-2 rounded-xl bg-gradient-to-r from-cyan-600 to-blue-600 hover:from-cyan-500 hover:to-blue-500 text-white font-mono text-xs font-bold shadow-[0_0_15px_rgba(6,182,212,0.4)] transition-all cursor-pointer"
            >
              <span>Proceed to GeoLocation & ASN</span>
              <ArrowRight className="w-4 h-4" />
            </button>
          </div>
        </div>
      </div>

      {/* Requirement 8: Short explanation */}
      <div className="rounded-xl bg-[#09101e] border border-cyan-500/30 p-4 font-mono text-xs text-slate-300 flex items-start gap-3 shadow-md">
        <Info className="w-5 h-5 text-cyan-400 shrink-0 mt-0.5" />
        <div>
          <span className="text-cyan-300 font-bold block mb-0.5">Automated Intelligence Workflow:</span>
          <p className="text-slate-300 text-xs leading-relaxed font-sans">
            MAVERICK extracts indicators from the email and correlates them with threat-intelligence context to improve the overall risk assessment.
          </p>
        </div>
      </div>

      {/* Requirement 6: Summary Section (Total: 6, High: 5, Medium: 1) */}
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-4 font-mono">
        <div className="p-4 rounded-xl bg-[#09101e] border border-slate-800 flex items-center justify-between">
          <div>
            <span className="text-[11px] uppercase tracking-wider text-slate-400 block font-semibold">
              Total IOCs
            </span>
            <div className="text-2xl sm:text-3xl font-black text-white mt-1">
              6
            </div>
            <span className="text-[10px] text-slate-500">Extracted from Email Payload</span>
          </div>
          <div className="w-10 h-10 rounded-lg bg-slate-900 border border-slate-800 flex items-center justify-center text-cyan-400">
            <Binary className="w-5 h-5" />
          </div>
        </div>

        <div className="p-4 rounded-xl bg-[#09101e] border border-red-500/40 flex items-center justify-between">
          <div>
            <span className="text-[11px] uppercase tracking-wider text-slate-400 block font-semibold">
              High Risk
            </span>
            <div className="text-2xl sm:text-3xl font-black text-red-400 mt-1 flex items-center gap-2">
              <span>5</span>
              <span className="text-xs font-normal text-red-400/80">/ 6</span>
            </div>
            <span className="text-[10px] text-red-400/80">Critical Adversarial Indicators</span>
          </div>
          <div className="w-10 h-10 rounded-lg bg-red-950/60 border border-red-500/40 flex items-center justify-center text-red-400">
            <ShieldAlert className="w-5 h-5" />
          </div>
        </div>

        <div className="p-4 rounded-xl bg-[#09101e] border border-amber-500/40 flex items-center justify-between">
          <div>
            <span className="text-[11px] uppercase tracking-wider text-slate-400 block font-semibold">
              Medium Risk
            </span>
            <div className="text-2xl sm:text-3xl font-black text-amber-400 mt-1 flex items-center gap-2">
              <span>1</span>
              <span className="text-xs font-normal text-amber-400/80">/ 6</span>
            </div>
            <span className="text-[10px] text-amber-400/80">Hosting Infrastructure Flags</span>
          </div>
          <div className="w-10 h-10 rounded-lg bg-amber-950/60 border border-amber-500/40 flex items-center justify-center text-amber-400">
            <AlertTriangle className="w-5 h-5" />
          </div>
        </div>
      </div>

      {/* Requirement 3, 4, 5: Professional IOC Table */}
      <div className="rounded-xl bg-[#09101e] border border-slate-800 p-5 shadow-lg space-y-4">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-slate-800 pb-3">
          <div>
            <h2 className="text-sm font-bold uppercase tracking-wider font-mono text-white">
              Extracted Indicators Table
            </h2>
            <p className="text-xs text-slate-400 font-sans">
              Autonomous IOC extraction with simulated threat correlation flags
            </p>
          </div>
          <span className="text-[11px] font-mono text-cyan-300 bg-cyan-950/60 px-2 py-0.5 rounded border border-cyan-500/40">
            6 Extracted Entities
          </span>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left font-mono text-xs border-collapse">
            <thead>
              <tr className="border-b border-slate-800 text-[11px] text-slate-400 uppercase tracking-wider bg-[#060a14]">
                <th className="py-3 px-3.5">Type</th>
                <th className="py-3 px-3.5">Indicator</th>
                <th className="py-3 px-3.5">Risk</th>
                <th className="py-3 px-3.5">Purpose</th>
                <th className="py-3 px-3.5">Status</th>
                <th className="py-3 px-3.5 text-right">Copy</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60">
              {IOC_DATA.map((item, idx) => (
                <tr key={idx} className="hover:bg-[#0c1830]/70 transition-colors group">
                  
                  {/* Type */}
                  <td className="py-3.5 px-3.5 whitespace-nowrap">
                    {renderTypeBadge(item.type)}
                  </td>

                  {/* Indicator */}
                  <td className="py-3.5 px-3.5 font-bold text-cyan-300 break-all font-mono">
                    {item.indicator}
                  </td>

                  {/* Risk */}
                  <td className="py-3.5 px-3.5 whitespace-nowrap">
                    {renderRiskBadge(item.risk)}
                  </td>

                  {/* Purpose */}
                  <td className="py-3.5 px-3.5 text-slate-300 font-sans font-medium whitespace-nowrap">
                    {item.purpose}
                  </td>

                  {/* Status */}
                  <td className="py-3.5 px-3.5 whitespace-nowrap">
                    <span className={`text-[10px] font-mono px-2 py-0.5 rounded border ${
                      item.risk === 'HIGH' 
                        ? 'bg-red-950/60 border-red-500/40 text-red-300' 
                        : 'bg-amber-950/60 border-amber-500/40 text-amber-300'
                    }`}>
                      {item.status}
                    </span>
                  </td>

                  {/* Copy Action */}
                  <td className="py-3.5 px-3.5 text-right whitespace-nowrap">
                    <button 
                      type="button"
                      onClick={() => handleCopy(item.indicator, idx)}
                      className="p-1.5 rounded hover:bg-slate-800 text-slate-400 hover:text-cyan-300 transition-colors cursor-pointer"
                      title="Copy Indicator"
                    >
                      {copiedIndex === idx ? (
                        <Check className="w-3.5 h-3.5 text-emerald-400" />
                      ) : (
                        <Copy className="w-3.5 h-3.5" />
                      )}
                    </button>
                  </td>

                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* Requirement 7: Threat Intelligence Enrichment Section (Simulated Sources) */}
      <div className="rounded-xl bg-[#09101e] border border-slate-800 p-5 shadow-lg space-y-4">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-slate-800 pb-3">
          <div className="flex items-center gap-2">
            <Database className="w-5 h-5 text-cyan-400" />
            <div>
              <h2 className="text-sm font-bold uppercase tracking-wider font-mono text-white">
                Threat Intelligence Enrichment
              </h2>
              <p className="text-xs text-slate-400 font-sans">
                Simulated enrichment sources (Demonstration mode for SIH 2026 prototype)
              </p>
            </div>
          </div>
          <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-slate-800 text-slate-400">
            SIMULATED ENRICHMENT SOURCES
          </span>
        </div>

        {/* 5 Enrichment Source Cards */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3.5 font-mono text-xs">
          {ENRICHMENT_SOURCES.map((source, idx) => (
            <div 
              key={idx}
              className="p-3.5 rounded-lg bg-[#060a14] border border-slate-800 hover:border-cyan-500/40 transition-all space-y-2"
            >
              <div className="flex items-center justify-between">
                <span className="font-bold text-cyan-300 text-xs">
                  {source.name}
                </span>
                <span className="text-[9px] px-1.5 py-0.2 rounded bg-cyan-950 border border-cyan-500/40 text-cyan-300">
                  {source.type}
                </span>
              </div>

              <p className="text-[11px] text-slate-300 font-sans leading-snug">
                {source.simulatedResult}
              </p>

              <div className="pt-1.5 border-t border-slate-800/60 flex items-center justify-between text-[10px]">
                <span className="text-slate-500">Evaluation:</span>
                <span className="text-red-400 font-bold">{source.status}</span>
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Bottom Navigation CTA */}
      <div className="pt-2 flex flex-col sm:flex-row items-center justify-between gap-3 font-mono text-xs">
        <button
          type="button"
          onClick={() => onViewChange('analysis-results')}
          className="flex items-center gap-1.5 px-4 py-2.5 rounded-xl bg-[#08101e] hover:bg-[#0c1830] border border-slate-700 text-slate-300 transition-colors cursor-pointer"
        >
          <ArrowLeft className="w-4 h-4" />
          <span>Back to Analysis Results</span>
        </button>

        <button
          type="button"
          id="btn-proceed-geo-asn-bottom"
          onClick={() => onViewChange('geo-asn')}
          className="flex items-center gap-2 px-6 py-2.5 rounded-xl bg-gradient-to-r from-cyan-600 via-sky-600 to-blue-600 hover:from-cyan-500 hover:to-blue-500 text-white font-bold shadow-[0_0_20px_rgba(6,182,212,0.4)] transition-all cursor-pointer"
        >
          <span>Proceed to GeoLocation & ASN</span>
          <ArrowRight className="w-4 h-4" />
        </button>
      </div>

    </div>
  );
};
