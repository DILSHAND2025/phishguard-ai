import React, { useState } from 'react';
import {
  ShieldCheck,
  ShieldAlert,
  Globe,
  Key,
  CheckCircle2,
  XCircle,
  AlertTriangle,
  Info,
  Lock,
  Server,
  Layers,
  Eye,
  Cpu
} from 'lucide-react';

export const EmailAuthenticationCard = ({ emailAuth }) => {
  const [activeTab, setActiveTab] = useState('overview'); // 'overview' | 'evidence' | 'dns'

  if (!emailAuth) {
    return (
      <div className="rounded-xl bg-[#09101e] border border-slate-800 p-5 font-mono text-xs text-slate-400 space-y-2">
        <div className="flex items-center gap-2 text-slate-300 font-bold">
          <ShieldAlert className="w-4 h-4 text-cyan-400" />
          <span>EMAIL AUTHENTICATION & DNS FORENSICS</span>
        </div>
        <p className="text-slate-500">
          No live email authentication payload provided or analysis in progress.
        </p>
      </div>
    );
  }

  const {
    fromDomain = '',
    returnPathDomain = '',
    spf = {},
    dkim = {},
    dmarc = {},
    alignment = {},
    observedEvidence = {},
    observedEvidenceList = [],
    inferredEvidenceList = [],
    riskSignals = []
  } = emailAuth;

  const mtaAuth = observedEvidence?.mtaAuthentication || {};
  const dnsForensics = observedEvidence?.dnsForensics || {};

  // Status badge styling helper
  const getStatusBadge = (status = '') => {
    const s = String(status).toUpperCase();
    if (s.includes('FOUND') || s === 'PASS' || s === 'ALIGNED') {
      return {
        bg: 'bg-emerald-950/70',
        border: 'border-emerald-500/40',
        text: 'text-emerald-300',
        icon: CheckCircle2
      };
    }
    if (s.includes('SOFTFAIL') || s.includes('NONE') || s.includes('NO_POLICY') || s.includes('REVOKED') || s.includes('UNVERIFIED')) {
      return {
        bg: 'bg-amber-950/70',
        border: 'border-amber-500/40',
        text: 'text-amber-300',
        icon: AlertTriangle
      };
    }
    return {
      bg: 'bg-red-950/70',
      border: 'border-red-500/40',
      text: 'text-red-300',
      icon: XCircle
    };
  };

  const spfBadge = getStatusBadge(spf.displayStatus || spf.status);
  const dkimBadge = getStatusBadge(dkim.displayStatus || dkim.status);
  const dmarcBadge = getStatusBadge(dmarc.displayStatus || dmarc.status);

  const SpfIcon = spfBadge.icon;
  const DkimIcon = dkimBadge.icon;
  const DmarcIcon = dmarcBadge.icon;

  const spfAligned = alignment?.spfAligned || alignment?.details?.spfAligned;
  const dkimAligned = alignment?.dkimAligned || alignment?.details?.dkimAligned;
  const dmarcAligned = alignment?.dmarcAligned || alignment?.details?.dmarcAligned;

  return (
    <div className="rounded-2xl bg-gradient-to-b from-[#0a1224] to-[#070b13] border border-cyan-500/30 p-5 sm:p-6 shadow-[0_0_30px_rgba(6,182,212,0.1)] space-y-6 font-mono text-xs">
      
      {/* Header Banner */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-slate-800 pb-4">
        <div>
          <div className="flex items-center gap-2 text-cyan-400 text-[11px] font-bold uppercase tracking-wider mb-1">
            <span className="w-2 h-2 rounded-full bg-cyan-400 animate-pulse"></span>
            RFC 7208 / RFC 6376 / RFC 7489 Protocols
          </div>
          <div className="flex items-center gap-2.5">
            <ShieldCheck className="w-5 h-5 text-cyan-400" />
            <h2 className="text-base sm:text-lg font-bold text-white tracking-wide">
              EMAIL AUTHENTICATION & DNS FORENSICS
            </h2>
          </div>
        </div>

        {/* Tab Controls */}
        <div className="flex items-center gap-1.5 p-1 bg-[#060a14] rounded-xl border border-slate-800 self-start sm:self-auto">
          <button
            type="button"
            onClick={() => setActiveTab('overview')}
            className={`px-3 py-1.5 rounded-lg text-[11px] font-bold transition-all cursor-pointer ${
              activeTab === 'overview'
                ? 'bg-cyan-950 text-cyan-200 border border-cyan-500/40 shadow-sm'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            Protocol Overview
          </button>
          <button
            type="button"
            onClick={() => setActiveTab('evidence')}
            className={`px-3 py-1.5 rounded-lg text-[11px] font-bold transition-all cursor-pointer ${
              activeTab === 'evidence'
                ? 'bg-cyan-950 text-cyan-200 border border-cyan-500/40 shadow-sm'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            Observed vs Inferred
          </button>
          <button
            type="button"
            onClick={() => setActiveTab('dns')}
            className={`px-3 py-1.5 rounded-lg text-[11px] font-bold transition-all cursor-pointer ${
              activeTab === 'dns'
                ? 'bg-cyan-950 text-cyan-200 border border-cyan-500/40 shadow-sm'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            DNS Forensics
          </button>
        </div>
      </div>

      {/* Forensic Disclaimer */}
      <div className="p-3 rounded-xl bg-[#08101e] border border-cyan-500/20 text-[11px] text-slate-300 flex items-start gap-2.5">
        <Info className="w-4 h-4 text-cyan-400 shrink-0 mt-0.5" />
        <div className="space-y-0.5">
          <span className="text-cyan-300 font-bold">Forensic Evidence Standard:</span>
          <p className="text-slate-400 leading-relaxed font-sans">
            MAVERICK strictly separates <strong>Observed Evidence</strong> (direct headers & live DNS queries) from <strong>Inferred Intelligence</strong> (domain alignment & impersonation analytics). DNS record discovery is labeled as record presence and is never falsely marked as cryptographically verified.
          </p>
        </div>
      </div>

      {/* TAB 1: PROTOCOL OVERVIEW */}
      {activeTab === 'overview' && (
        <div className="space-y-6">
          
          {/* 3 Core Protocol Status Cards: SPF, DKIM, DMARC */}
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            
            {/* SPF Card */}
            <div className={`p-4 rounded-xl border ${spfBadge.bg} ${spfBadge.border} flex flex-col justify-between space-y-3`}>
              <div>
                <div className="flex items-center justify-between gap-2 border-b border-slate-800/80 pb-2 mb-2">
                  <div className="flex items-center gap-1.5">
                    <Globe className="w-4 h-4 text-cyan-400" />
                    <span className="text-xs font-bold text-white uppercase tracking-wider">SPF (RFC 7208)</span>
                  </div>
                  <span className={`px-2 py-0.5 rounded text-[10px] font-bold border ${spfBadge.bg} ${spfBadge.border} ${spfBadge.text} flex items-center gap-1`}>
                    <SpfIcon className="w-3 h-3" />
                    {spf.displayStatus || spf.status || 'UNCHECKED'}
                  </span>
                </div>

                <div className="space-y-1.5 text-[11px]">
                  <div className="flex items-center justify-between text-slate-400">
                    <span>Queried Domain:</span>
                    <span className="text-cyan-300 font-bold truncate max-w-[150px]" title={spf.domain || returnPathDomain || fromDomain}>
                      {spf.domain || returnPathDomain || fromDomain || 'N/A'}
                    </span>
                  </div>

                  <div className="flex items-center justify-between text-slate-400">
                    <span>Source:</span>
                    <span className="text-slate-200 font-medium">Backend Live DNS</span>
                  </div>

                  {mtaAuth.observedSpfVerdict && (
                    <div className="flex items-center justify-between text-slate-400">
                      <span>MTA Observed:</span>
                      <span className={`font-bold uppercase ${
                        mtaAuth.observedSpfVerdict === 'pass' ? 'text-emerald-400' : 'text-amber-400'
                      }`}>
                        spf={mtaAuth.observedSpfVerdict}
                      </span>
                    </div>
                  )}

                  {spf.record && (
                    <div className="pt-2">
                      <span className="text-[10px] text-slate-500 block mb-0.5">Discovered SPF Record:</span>
                      <code className="text-[10px] bg-[#050812] text-slate-300 p-1.5 rounded border border-slate-800 block break-all font-mono">
                        {spf.record}
                      </code>
                    </div>
                  )}

                  {spf.hasPlusAll && (
                    <div className="p-1.5 rounded bg-red-950/80 border border-red-500/40 text-red-300 text-[10px]">
                      🚨 Critical: SPF publishes "+all", allowing any sender to spoof this domain.
                    </div>
                  )}
                </div>
              </div>

              <div className="pt-2 border-t border-slate-800/80 text-[10.5px] text-slate-400">
                <span className="text-slate-500 block text-[10px]">Forensic Assessment:</span>
                {spf.status === 'RECORD_FOUND'
                  ? 'Valid SPF DNS record located. Designated relay check performed against envelope.'
                  : spf.status === 'PERMERROR'
                    ? 'Multiple conflicting SPF records detected in DNS (RFC 7208 PermError).'
                    : 'No valid SPF record published for envelope sender domain.'}
              </div>
            </div>

            {/* DKIM Card */}
            <div className={`p-4 rounded-xl border ${dkimBadge.bg} ${dkimBadge.border} flex flex-col justify-between space-y-3`}>
              <div>
                <div className="flex items-center justify-between gap-2 border-b border-slate-800/80 pb-2 mb-2">
                  <div className="flex items-center gap-1.5">
                    <Key className="w-4 h-4 text-cyan-400" />
                    <span className="text-xs font-bold text-white uppercase tracking-wider">DKIM (RFC 6376)</span>
                  </div>
                  <span className={`px-2 py-0.5 rounded text-[10px] font-bold border ${dkimBadge.bg} ${dkimBadge.border} ${dkimBadge.text} flex items-center gap-1`}>
                    <DkimIcon className="w-3 h-3" />
                    {dkim.displayStatus || dkim.status || 'NO SIGNATURE'}
                  </span>
                </div>

                <div className="space-y-1.5 text-[11px]">
                  <div className="flex items-center justify-between text-slate-400">
                    <span>Selector (s=):</span>
                    <span className="text-cyan-300 font-bold truncate max-w-[150px]">
                      {dkim.selector || (observedEvidence?.dkimSignatures?.[0]?.selector) || 'None'}
                    </span>
                  </div>

                  <div className="flex items-center justify-between text-slate-400">
                    <span>Signing Domain (d=):</span>
                    <span className="text-cyan-300 font-bold truncate max-w-[150px]">
                      {dkim.domain || (observedEvidence?.dkimSignatures?.[0]?.domain) || 'None'}
                    </span>
                  </div>

                  <div className="flex items-center justify-between text-slate-400">
                    <span>Algorithm:</span>
                    <span className="text-slate-200 font-medium">
                      {dkim.algorithm || (observedEvidence?.dkimSignatures?.[0]?.algorithm) || 'rsa-sha256'}
                    </span>
                  </div>

                  {mtaAuth.observedDkimVerdict && (
                    <div className="flex items-center justify-between text-slate-400">
                      <span>MTA Observed:</span>
                      <span className={`font-bold uppercase ${
                        mtaAuth.observedDkimVerdict === 'pass' ? 'text-emerald-400' : 'text-amber-400'
                      }`}>
                        dkim={mtaAuth.observedDkimVerdict}
                      </span>
                    </div>
                  )}

                  {dnsForensics?.dkim?.[0]?.record && (
                    <div className="pt-2">
                      <span className="text-[10px] text-slate-500 block mb-0.5">Discovered Public Key:</span>
                      <code className="text-[10px] bg-[#050812] text-slate-300 p-1.5 rounded border border-slate-800 block break-all font-mono truncate">
                        {dnsForensics.dkim[0].record}
                      </code>
                    </div>
                  )}
                </div>
              </div>

              <div className="pt-2 border-t border-slate-800/80 text-[10.5px] text-slate-400">
                <span className="text-slate-500 block text-[10px]">Forensic Assessment:</span>
                {dkim.dnsRecordFound
                  ? `DKIM public key found for selector "${dkim.selector || 's'}". Cryptographic key located in DNS.`
                  : 'DKIM signature missing or public key record not published in DNS.'}
              </div>
            </div>

            {/* DMARC Card */}
            <div className={`p-4 rounded-xl border ${dmarcBadge.bg} ${dmarcBadge.border} flex flex-col justify-between space-y-3`}>
              <div>
                <div className="flex items-center justify-between gap-2 border-b border-slate-800/80 pb-2 mb-2">
                  <div className="flex items-center gap-1.5">
                    <Lock className="w-4 h-4 text-cyan-400" />
                    <span className="text-xs font-bold text-white uppercase tracking-wider">DMARC (RFC 7489)</span>
                  </div>
                  <span className={`px-2 py-0.5 rounded text-[10px] font-bold border ${dmarcBadge.bg} ${dmarcBadge.border} ${dmarcBadge.text} flex items-center gap-1`}>
                    <DmarcIcon className="w-3 h-3" />
                    {dmarc.displayStatus || dmarc.status || 'NO POLICY'}
                  </span>
                </div>

                <div className="space-y-1.5 text-[11px]">
                  <div className="flex items-center justify-between text-slate-400">
                    <span>Enforced Policy (p=):</span>
                    <span className={`font-bold uppercase ${
                      dmarc.policy === 'reject' ? 'text-red-400' : dmarc.policy === 'quarantine' ? 'text-amber-400' : 'text-blue-400'
                    }`}>
                      {dmarc.policy || 'none'}
                    </span>
                  </div>

                  <div className="flex items-center justify-between text-slate-400">
                    <span>Subdomain Policy (sp=):</span>
                    <span className="text-slate-200 font-medium">{dmarc.subdomainPolicy || 'inherit'}</span>
                  </div>

                  <div className="flex items-center justify-between text-slate-400">
                    <span>Alignment Modes:</span>
                    <span className="text-slate-200 font-medium">
                      aspf={dmarc.aspf || 'r'} | adkim={dmarc.adkim || 'r'}
                    </span>
                  </div>

                  <div className="flex items-center justify-between text-slate-400">
                    <span>Enforcement % (pct=):</span>
                    <span className="text-slate-200 font-medium">{dmarc.percentage ?? 100}%</span>
                  </div>

                  {mtaAuth.observedDmarcVerdict && (
                    <div className="flex items-center justify-between text-slate-400">
                      <span>MTA Observed:</span>
                      <span className={`font-bold uppercase ${
                        mtaAuth.observedDmarcVerdict === 'pass' ? 'text-emerald-400' : 'text-amber-400'
                      }`}>
                        dmarc={mtaAuth.observedDmarcVerdict}
                      </span>
                    </div>
                  )}

                  {dmarc.record && (
                    <div className="pt-2">
                      <span className="text-[10px] text-slate-500 block mb-0.5">Published DMARC Policy:</span>
                      <code className="text-[10px] bg-[#050812] text-slate-300 p-1.5 rounded border border-slate-800 block break-all font-mono truncate">
                        {dmarc.record}
                      </code>
                    </div>
                  )}
                </div>
              </div>

              <div className="pt-2 border-t border-slate-800/80 text-[10.5px] text-slate-400">
                <span className="text-slate-500 block text-[10px]">Forensic Assessment:</span>
                {dmarc.status === 'RECORD_FOUND'
                  ? `DMARC record published with policy p=${dmarc.policy || 'none'}. Requires SPF or DKIM alignment.`
                  : 'No DMARC policy published; domain has no sender verification enforcement.'}
              </div>
            </div>

          </div>

          {/* DOMAIN ALIGNMENT SECTION */}
          <div className="p-4 rounded-xl bg-[#060a14] border border-slate-800 space-y-3">
            <div className="flex items-center justify-between border-b border-slate-800/80 pb-2">
              <div className="flex items-center gap-2">
                <Layers className="w-4 h-4 text-cyan-400" />
                <h3 className="text-xs font-bold text-white uppercase tracking-wider">
                  RFC 7489 Domain Alignment Analysis
                </h3>
              </div>
              <span className={`px-2.5 py-0.5 rounded text-[10px] font-bold border ${
                dmarcAligned
                  ? 'bg-emerald-950/70 border-emerald-500/40 text-emerald-300'
                  : 'bg-red-950/70 border-red-500/40 text-red-300'
              }`}>
                DMARC ALIGNMENT: {dmarcAligned ? 'PASSED' : 'FAILED'}
              </span>
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 pt-1">
              
              {/* SPF Alignment */}
              <div className={`p-3 rounded-lg border ${
                spfAligned
                  ? 'bg-emerald-950/20 border-emerald-500/30 text-slate-300'
                  : 'bg-amber-950/20 border-amber-500/30 text-slate-300'
              } space-y-1.5`}>
                <div className="flex items-center justify-between text-[11px]">
                  <span className="text-slate-400 font-bold">SPF Alignment ({alignment?.spfMode || 'relaxed'})</span>
                  <span className={`font-bold ${spfAligned ? 'text-emerald-400' : 'text-amber-400'}`}>
                    {spfAligned ? '✅ ALIGNED' : '⚠️ MISMATCH DETECTED'}
                  </span>
                </div>
                <div className="text-[10.5px] text-slate-400 space-y-0.5">
                  <div>From Domain: <strong className="text-white">{fromDomain || 'None'}</strong></div>
                  <div>Return-Path Domain: <strong className="text-white">{returnPathDomain || 'None'}</strong></div>
                </div>
                <p className="text-[10px] text-slate-400 pt-1 border-t border-slate-800/60 font-sans">
                  {spfAligned
                    ? 'Return-Path envelope domain matches Header From domain.'
                    : 'Return-Path envelope routes bounces to an external domain differing from sender.'}
                </p>
              </div>

              {/* DKIM Alignment */}
              <div className={`p-3 rounded-lg border ${
                dkimAligned
                  ? 'bg-emerald-950/20 border-emerald-500/30 text-slate-300'
                  : 'bg-amber-950/20 border-amber-500/30 text-slate-300'
              } space-y-1.5`}>
                <div className="flex items-center justify-between text-[11px]">
                  <span className="text-slate-400 font-bold">DKIM Alignment ({alignment?.dkimMode || 'relaxed'})</span>
                  <span className={`font-bold ${dkimAligned ? 'text-emerald-400' : 'text-amber-400'}`}>
                    {dkimAligned ? '✅ ALIGNED' : '⚠️ MISMATCH DETECTED'}
                  </span>
                </div>
                <div className="text-[10.5px] text-slate-400 space-y-0.5">
                  <div>From Domain: <strong className="text-white">{fromDomain || 'None'}</strong></div>
                  <div>DKIM Signing Domain: <strong className="text-white">{dkim.domain || 'None'}</strong></div>
                </div>
                <p className="text-[10px] text-slate-400 pt-1 border-t border-slate-800/60 font-sans">
                  {dkimAligned
                    ? 'Cryptographic signing domain (d=) aligns with Header From domain.'
                    : 'DKIM signature domain does not match visible Header From identity.'}
                </p>
              </div>

            </div>
          </div>

          {/* AUTHENTICATION RISK SIGNALS */}
          {riskSignals && riskSignals.length > 0 && (
            <div className="p-4 rounded-xl bg-[#060a14] border border-amber-500/30 space-y-2">
              <div className="flex items-center gap-2 text-amber-400 text-xs font-bold">
                <AlertTriangle className="w-4 h-4" />
                <span>IDENTIFIED AUTHENTICATION RISK SIGNALS ({riskSignals.length})</span>
              </div>
              <div className="space-y-1.5 pt-1">
                {riskSignals.map((signal, idx) => (
                  <div key={idx} className="p-2 rounded bg-slate-900/80 border border-slate-800 text-[11px] text-slate-300 flex items-start gap-2">
                    <span className="text-amber-400 font-bold">⚠️</span>
                    <span className="leading-tight">{signal}</span>
                  </div>
                ))}
              </div>
            </div>
          )}

        </div>
      )}

      {/* TAB 2: OBSERVED EVIDENCE VS INFERRED INTELLIGENCE */}
      {activeTab === 'evidence' && (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-5">
          
          {/* Column 1: OBSERVED EVIDENCE */}
          <div className="p-4 rounded-xl bg-[#060a14] border border-slate-800 space-y-3">
            <div className="flex items-center justify-between border-b border-slate-800 pb-2">
              <div className="flex items-center gap-2 text-cyan-400">
                <Eye className="w-4 h-4" />
                <h3 className="text-xs font-bold text-white uppercase tracking-wider">
                  Observed Evidence
                </h3>
              </div>
              <span className="text-[10px] text-slate-500">MTA Headers & Raw DNS</span>
            </div>

            <p className="text-[10.5px] text-slate-400 font-sans leading-relaxed">
              Directly observed data points extracted from the email MIME envelope and verified DNS records.
            </p>

            <div className="space-y-2 pt-1">
              {observedEvidenceList && observedEvidenceList.length > 0 ? (
                observedEvidenceList.map((item, idx) => (
                  <div key={idx} className="p-2.5 rounded bg-[#080d1a] border border-slate-800/80 text-[11px] text-slate-200 break-all leading-snug">
                    <span className="text-cyan-400 font-bold mr-1.5">●</span>
                    {item}
                  </div>
                ))
              ) : (
                <div className="text-slate-500 italic p-2">No raw observed headers extracted</div>
              )}
            </div>
          </div>

          {/* Column 2: INFERRED INTELLIGENCE */}
          <div className="p-4 rounded-xl bg-[#060a14] border border-slate-800 space-y-3">
            <div className="flex items-center justify-between border-b border-slate-800 pb-2">
              <div className="flex items-center gap-2 text-amber-400">
                <Cpu className="w-4 h-4" />
                <h3 className="text-xs font-bold text-white uppercase tracking-wider">
                  Inferred Intelligence
                </h3>
              </div>
              <span className="text-[10px] text-slate-500">MAVERICK Risk Calibration</span>
            </div>

            <p className="text-[10.5px] text-slate-400 font-sans leading-relaxed">
              Analytical intelligence synthesized by cross-referencing sender identities, alignment modes, and spoofing indicators.
            </p>

            <div className="space-y-2 pt-1">
              {inferredEvidenceList && inferredEvidenceList.length > 0 ? (
                inferredEvidenceList.map((item, idx) => (
                  <div key={idx} className="p-2.5 rounded bg-[#080d1a] border border-slate-800/80 text-[11px] text-slate-200 break-all leading-snug">
                    <span className="text-amber-400 font-bold mr-1.5">◆</span>
                    {item}
                  </div>
                ))
              ) : (
                <div className="text-slate-500 italic p-2">No inferred intelligence anomalies flagged</div>
              )}
            </div>
          </div>

        </div>
      )}

      {/* TAB 3: DNS FORENSICS DETAILS */}
      {activeTab === 'dns' && (
        <div className="space-y-4">
          <div className="p-4 rounded-xl bg-[#060a14] border border-slate-800 space-y-3">
            <div className="flex items-center justify-between border-b border-slate-800 pb-2">
              <div className="flex items-center gap-2 text-cyan-400">
                <Server className="w-4 h-4" />
                <h3 className="text-xs font-bold text-white uppercase tracking-wider">
                  Raw DNS TXT Records & Resolution Telemetry
                </h3>
              </div>
              <span className="text-[10px] text-slate-500">Live Backend Resolution</span>
            </div>

            {/* SPF DNS Record */}
            <div className="space-y-1.5">
              <span className="text-slate-400 font-bold text-[11px]">1. SPF DNS TXT Record ({spf.domain || fromDomain}):</span>
              <pre className="p-3 rounded-lg bg-[#040711] border border-slate-800 text-[11px] text-cyan-300 overflow-x-auto whitespace-pre-wrap font-mono">
                {spf.record || 'No TXT record starting with "v=spf1" found.'}
              </pre>
            </div>

            {/* DKIM DNS Record */}
            <div className="space-y-1.5 pt-2 border-t border-slate-800/60">
              <span className="text-slate-400 font-bold text-[11px]">
                2. DKIM Public Key Record ({dnsForensics?.dkim?.[0]?.queryHost || `${dkim.selector || 'selector'}._domainkey.${dkim.domain || fromDomain}`}):
              </span>
              <pre className="p-3 rounded-lg bg-[#040711] border border-slate-800 text-[11px] text-cyan-300 overflow-x-auto whitespace-pre-wrap font-mono">
                {dnsForensics?.dkim?.[0]?.record || 'No DKIM public key record found at selector host.'}
              </pre>
            </div>

            {/* DMARC DNS Record */}
            <div className="space-y-1.5 pt-2 border-t border-slate-800/60">
              <span className="text-slate-400 font-bold text-[11px]">
                3. DMARC Policy Record ({dnsForensics?.dmarc?.queriedHost || `_dmarc.${fromDomain}`}):
              </span>
              <pre className="p-3 rounded-lg bg-[#040711] border border-slate-800 text-[11px] text-cyan-300 overflow-x-auto whitespace-pre-wrap font-mono">
                {dmarc.record || 'No TXT record starting with "v=DMARC1" found.'}
              </pre>
            </div>
          </div>
        </div>
      )}

    </div>
  );
};
