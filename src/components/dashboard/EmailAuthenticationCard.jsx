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
      <div className="rounded-xl bg-white border border-slate-200 p-5 font-sans text-xs text-slate-500 space-y-2 shadow-xs">
        <div className="flex items-center gap-2 text-slate-800 font-bold">
          <ShieldAlert className="w-4 h-4 text-slate-500" />
          <span>Email Authentication & DNS Forensics</span>
        </div>
        <p className="text-slate-500">
          No live email authentication payload provided or analysis in progress.
        </p>
      </div>
    );
  }

  const fromDomain = emailAuth?.fromDomain || '';
  const returnPathDomain = emailAuth?.returnPathDomain || '';
  const spf = (emailAuth?.spf && typeof emailAuth.spf === 'object') ? emailAuth.spf : {};
  const dkim = (emailAuth?.dkim && typeof emailAuth.dkim === 'object') ? emailAuth.dkim : {};
  const dmarc = (emailAuth?.dmarc && typeof emailAuth.dmarc === 'object') ? emailAuth.dmarc : {};
  const alignment = (emailAuth?.alignment && typeof emailAuth.alignment === 'object') ? emailAuth.alignment : {};
  const observedEvidence = (emailAuth?.observedEvidence && typeof emailAuth.observedEvidence === 'object') ? emailAuth.observedEvidence : {};
  const observedEvidenceList = Array.isArray(emailAuth?.observedEvidenceList) ? emailAuth.observedEvidenceList : [];
  const inferredEvidenceList = Array.isArray(emailAuth?.inferredEvidenceList) ? emailAuth.inferredEvidenceList : [];
  const riskSignals = Array.isArray(emailAuth?.riskSignals) ? emailAuth.riskSignals : [];

  const mtaAuth = observedEvidence?.mtaAuthentication || {};
  const dnsForensics = observedEvidence?.dnsForensics || {};

  // Status badge styling helper - clean light theme
  const getStatusBadge = (status = '') => {
    const s = String(status).toUpperCase();
    if (s.includes('FOUND') || s === 'PASS' || s === 'ALIGNED') {
      return {
        bg: 'bg-emerald-50',
        border: 'border-emerald-200',
        text: 'text-emerald-700',
        icon: CheckCircle2
      };
    }
    if (s.includes('SOFTFAIL') || s.includes('NONE') || s.includes('NO_POLICY') || s.includes('REVOKED') || s.includes('UNVERIFIED') || s.includes('MISALIGNED')) {
      return {
        bg: 'bg-amber-50',
        border: 'border-amber-200',
        text: 'text-amber-700',
        icon: AlertTriangle
      };
    }
    return {
      bg: 'bg-red-50',
      border: 'border-red-200',
      text: 'text-red-700',
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
    <div className="rounded-xl bg-white border border-slate-200 p-5 sm:p-6 shadow-xs space-y-6 font-sans text-xs">
      
      {/* Header Banner */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-slate-100 pb-4">
        <div>
          <div className="flex items-center gap-2 text-slate-500 text-[11px] font-semibold uppercase tracking-wider mb-1">
            RFC 7208 / RFC 6376 / RFC 7489 Protocols
          </div>
          <div className="flex items-center gap-2.5">
            <ShieldCheck className="w-5 h-5 text-slate-700" />
            <h2 className="text-base sm:text-lg font-bold text-slate-900 tracking-tight">
              Email Authentication
            </h2>
          </div>
        </div>

        {/* Tab Controls */}
        <div className="flex items-center gap-1.5 p-1 bg-slate-100 rounded-lg border border-slate-200/80 self-start sm:self-auto">
          <button
            type="button"
            onClick={() => setActiveTab('overview')}
            className={`px-3 py-1.5 rounded-md text-xs font-semibold transition-all cursor-pointer ${
              activeTab === 'overview'
                ? 'bg-white text-slate-900 shadow-2xs'
                : 'text-slate-600 hover:text-slate-900'
            }`}
          >
            Protocol Overview
          </button>
          <button
            type="button"
            onClick={() => setActiveTab('evidence')}
            className={`px-3 py-1.5 rounded-md text-xs font-semibold transition-all cursor-pointer ${
              activeTab === 'evidence'
                ? 'bg-white text-slate-900 shadow-2xs'
                : 'text-slate-600 hover:text-slate-900'
            }`}
          >
            Observed vs Inferred
          </button>
          <button
            type="button"
            onClick={() => setActiveTab('dns')}
            className={`px-3 py-1.5 rounded-md text-xs font-semibold transition-all cursor-pointer ${
              activeTab === 'dns'
                ? 'bg-white text-slate-900 shadow-2xs'
                : 'text-slate-600 hover:text-slate-900'
            }`}
          >
            DNS Forensics
          </button>
        </div>
      </div>

      {/* Forensic Standard Note */}
      <div className="p-3.5 rounded-lg bg-slate-50 border border-slate-200 text-xs text-slate-600 flex items-start gap-2.5">
        <Info className="w-4 h-4 text-slate-500 shrink-0 mt-0.5" />
        <div className="space-y-0.5">
          <span className="text-slate-900 font-semibold">Forensic Evidence Standard:</span>
          <p className="leading-relaxed">
            MAVERICK strictly separates <strong>Observed Evidence</strong> (direct headers & live DNS queries) from <strong>Inferred Intelligence</strong> (domain alignment & impersonation analytics).
          </p>
        </div>
      </div>

      {/* TAB 1: PROTOCOL OVERVIEW */}
      {activeTab === 'overview' && (
        <div className="space-y-6">
          
          {/* 3 Clean Protocol Status Cards: SPF, DKIM, DMARC */}
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            
            {/* SPF Card */}
            <div className="p-4 rounded-xl bg-white border border-slate-200 shadow-2xs flex flex-col justify-between space-y-3">
              <div>
                <div className="flex items-center justify-between gap-2 border-b border-slate-100 pb-2 mb-2">
                  <div className="flex items-center gap-1.5">
                    <Globe className="w-4 h-4 text-slate-600" />
                    <span className="text-xs font-bold text-slate-900 uppercase tracking-wider">SPF</span>
                  </div>
                  <span className={`px-2 py-0.5 rounded text-[10px] font-bold border ${spfBadge.bg} ${spfBadge.border} ${spfBadge.text} flex items-center gap-1`}>
                    <SpfIcon className="w-3 h-3" />
                    {spf.displayStatus || spf.status || 'UNCHECKED'}
                  </span>
                </div>

                <div className="space-y-1.5 text-xs">
                  <div className="flex items-center justify-between text-slate-500">
                    <span>Domain:</span>
                    <span className="text-slate-900 font-medium truncate max-w-[150px]" title={spf.domain || returnPathDomain || fromDomain}>
                      {spf.domain || returnPathDomain || fromDomain || 'N/A'}
                    </span>
                  </div>

                  <div className="flex items-center justify-between text-slate-500">
                    <span>Source:</span>
                    <span className="text-slate-700 font-medium">Backend Live DNS</span>
                  </div>

                  {mtaAuth.observedSpfVerdict && (
                    <div className="flex items-center justify-between text-slate-500">
                      <span>MTA Observed:</span>
                      <span className={`font-semibold uppercase ${
                        mtaAuth.observedSpfVerdict === 'pass' ? 'text-emerald-700' : 'text-amber-700'
                      }`}>
                        spf={mtaAuth.observedSpfVerdict}
                      </span>
                    </div>
                  )}

                  {spf.record && (
                    <div className="pt-2">
                      <span className="text-[10px] text-slate-500 block mb-0.5">SPF Record:</span>
                      <code className="text-[10px] bg-slate-50 text-slate-700 p-1.5 rounded border border-slate-200 block break-all font-mono">
                        {spf.record}
                      </code>
                    </div>
                  )}

                  {spf.hasPlusAll && (
                    <div className="p-1.5 rounded bg-red-50 border border-red-200 text-red-700 text-[10px] font-medium">
                      Critical: SPF publishes &quot;+all&quot;, allowing spoofing.
                    </div>
                  )}
                </div>
              </div>

              <div className="pt-2 border-t border-slate-100 text-[11px] text-slate-500">
                {spf.status === 'RECORD_FOUND'
                  ? 'Valid SPF DNS record located.'
                  : spf.status === 'PERMERROR'
                    ? 'Multiple conflicting SPF records detected in DNS.'
                    : 'No valid SPF record published for envelope sender domain.'}
              </div>
            </div>

            {/* DKIM Card */}
            <div className="p-4 rounded-xl bg-white border border-slate-200 shadow-2xs flex flex-col justify-between space-y-3">
              <div>
                <div className="flex items-center justify-between gap-2 border-b border-slate-100 pb-2 mb-2">
                  <div className="flex items-center gap-1.5">
                    <Key className="w-4 h-4 text-slate-600" />
                    <span className="text-xs font-bold text-slate-900 uppercase tracking-wider">DKIM</span>
                  </div>
                  <span className={`px-2 py-0.5 rounded text-[10px] font-bold border ${dkimBadge.bg} ${dkimBadge.border} ${dkimBadge.text} flex items-center gap-1`}>
                    <DkimIcon className="w-3 h-3" />
                    {dkim.displayStatus || dkim.status || 'NO SIGNATURE'}
                  </span>
                </div>

                <div className="space-y-1.5 text-xs">
                  <div className="flex items-center justify-between text-slate-500">
                    <span>Selector (s=):</span>
                    <span className="text-slate-900 font-medium truncate max-w-[150px]">
                      {dkim.selector || (observedEvidence?.dkimSignatures?.[0]?.selector) || 'None'}
                    </span>
                  </div>

                  <div className="flex items-center justify-between text-slate-500">
                    <span>Signing Domain:</span>
                    <span className="text-slate-900 font-medium truncate max-w-[150px]">
                      {dkim.domain || (observedEvidence?.dkimSignatures?.[0]?.domain) || 'None'}
                    </span>
                  </div>

                  <div className="flex items-center justify-between text-slate-500">
                    <span>Algorithm:</span>
                    <span className="text-slate-700 font-medium">
                      {dkim.algorithm || (observedEvidence?.dkimSignatures?.[0]?.algorithm) || 'rsa-sha256'}
                    </span>
                  </div>

                  {mtaAuth.observedDkimVerdict && (
                    <div className="flex items-center justify-between text-slate-500">
                      <span>MTA Observed:</span>
                      <span className={`font-semibold uppercase ${
                        mtaAuth.observedDkimVerdict === 'pass' ? 'text-emerald-700' : 'text-amber-700'
                      }`}>
                        dkim={mtaAuth.observedDkimVerdict}
                      </span>
                    </div>
                  )}

                  {dnsForensics?.dkim?.[0]?.record && (
                    <div className="pt-2">
                      <span className="text-[10px] text-slate-500 block mb-0.5">Discovered Public Key:</span>
                      <code className="text-[10px] bg-slate-50 text-slate-700 p-1.5 rounded border border-slate-200 block break-all font-mono truncate">
                        {dnsForensics.dkim[0].record}
                      </code>
                    </div>
                  )}
                </div>
              </div>

              <div className="pt-2 border-t border-slate-100 text-[11px] text-slate-500">
                {dkim.dnsRecordFound
                  ? `DKIM public key found for selector "${dkim.selector || 's'}".`
                  : 'DKIM signature missing or public key record not published.'}
              </div>
            </div>

            {/* DMARC Card */}
            <div className="p-4 rounded-xl bg-white border border-slate-200 shadow-2xs flex flex-col justify-between space-y-3">
              <div>
                <div className="flex items-center justify-between gap-2 border-b border-slate-100 pb-2 mb-2">
                  <div className="flex items-center gap-1.5">
                    <Lock className="w-4 h-4 text-slate-600" />
                    <span className="text-xs font-bold text-slate-900 uppercase tracking-wider">DMARC</span>
                  </div>
                  <span className={`px-2 py-0.5 rounded text-[10px] font-bold border ${dmarcBadge.bg} ${dmarcBadge.border} ${dmarcBadge.text} flex items-center gap-1`}>
                    <DmarcIcon className="w-3 h-3" />
                    {dmarc.displayStatus || dmarc.status || 'NO POLICY'}
                  </span>
                </div>

                <div className="space-y-1.5 text-xs">
                  <div className="flex items-center justify-between text-slate-500">
                    <span>Enforced Policy:</span>
                    <span className={`font-semibold uppercase ${
                      dmarc.policy === 'reject' ? 'text-red-700' : dmarc.policy === 'quarantine' ? 'text-amber-700' : 'text-blue-700'
                    }`}>
                      {dmarc.policy || 'none'}
                    </span>
                  </div>

                  <div className="flex items-center justify-between text-slate-500">
                    <span>Subdomain Policy:</span>
                    <span className="text-slate-700 font-medium">{dmarc.subdomainPolicy || 'inherit'}</span>
                  </div>

                  <div className="flex items-center justify-between text-slate-500">
                    <span>Alignment Modes:</span>
                    <span className="text-slate-700 font-medium">
                      aspf={dmarc.aspf || 'r'} | adkim={dmarc.adkim || 'r'}
                    </span>
                  </div>

                  <div className="flex items-center justify-between text-slate-500">
                    <span>Enforcement %:</span>
                    <span className="text-slate-700 font-medium">{dmarc.percentage ?? 100}%</span>
                  </div>

                  {mtaAuth.observedDmarcVerdict && (
                    <div className="flex items-center justify-between text-slate-500">
                      <span>MTA Observed:</span>
                      <span className={`font-semibold uppercase ${
                        mtaAuth.observedDmarcVerdict === 'pass' ? 'text-emerald-700' : 'text-amber-700'
                      }`}>
                        dmarc={mtaAuth.observedDmarcVerdict}
                      </span>
                    </div>
                  )}

                  {dmarc.record && (
                    <div className="pt-2">
                      <span className="text-[10px] text-slate-500 block mb-0.5">Published DMARC Policy:</span>
                      <code className="text-[10px] bg-slate-50 text-slate-700 p-1.5 rounded border border-slate-200 block break-all font-mono truncate">
                        {dmarc.record}
                      </code>
                    </div>
                  )}
                </div>
              </div>

              <div className="pt-2 border-t border-slate-100 text-[11px] text-slate-500">
                {dmarc.status === 'RECORD_FOUND'
                  ? `DMARC record published with policy p=${dmarc.policy || 'none'}.`
                  : 'No DMARC policy published; domain has no sender verification enforcement.'}
              </div>
            </div>

          </div>

          {/* DOMAIN ALIGNMENT SECTION */}
          <div className="p-4 rounded-xl bg-slate-50 border border-slate-200 space-y-3">
            <div className="flex items-center justify-between border-b border-slate-200 pb-2">
              <div className="flex items-center gap-2">
                <Layers className="w-4 h-4 text-slate-600" />
                <h3 className="text-xs font-bold text-slate-900 uppercase tracking-wider">
                  RFC 7489 Domain Alignment Analysis
                </h3>
              </div>
              <span className={`px-2.5 py-0.5 rounded text-[10px] font-bold border ${
                dmarcAligned
                  ? 'bg-emerald-50 border-emerald-200 text-emerald-700'
                  : 'bg-red-50 border-red-200 text-red-700'
              }`}>
                DMARC ALIGNMENT: {dmarcAligned ? 'PASSED' : 'FAILED'}
              </span>
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 pt-1">
              
              {/* SPF Alignment */}
              <div className="p-3 rounded-lg bg-white border border-slate-200 space-y-1.5">
                <div className="flex items-center justify-between text-xs">
                  <span className="text-slate-600 font-semibold">SPF Alignment ({alignment?.spfMode || 'relaxed'})</span>
                  <span className={`font-bold ${spfAligned ? 'text-emerald-700' : 'text-amber-700'}`}>
                    {spfAligned ? 'ALIGNED' : 'MISMATCH'}
                  </span>
                </div>
                <div className="text-[11px] text-slate-500 space-y-0.5">
                  <div>From Domain: <strong className="text-slate-800">{fromDomain || 'None'}</strong></div>
                  <div>Return-Path Domain: <strong className="text-slate-800">{returnPathDomain || 'None'}</strong></div>
                </div>
              </div>

              {/* DKIM Alignment */}
              <div className="p-3 rounded-lg bg-white border border-slate-200 space-y-1.5">
                <div className="flex items-center justify-between text-xs">
                  <span className="text-slate-600 font-semibold">DKIM Alignment ({alignment?.dkimMode || 'relaxed'})</span>
                  <span className={`font-bold ${dkimAligned ? 'text-emerald-700' : 'text-amber-700'}`}>
                    {dkimAligned ? 'ALIGNED' : 'MISMATCH'}
                  </span>
                </div>
                <div className="text-[11px] text-slate-500 space-y-0.5">
                  <div>From Domain: <strong className="text-slate-800">{fromDomain || 'None'}</strong></div>
                  <div>DKIM Signing Domain: <strong className="text-slate-800">{dkim.domain || 'None'}</strong></div>
                </div>
              </div>

            </div>
          </div>

          {/* AUTHENTICATION RISK SIGNALS */}
          {riskSignals && riskSignals.length > 0 && (
            <div className="p-4 rounded-xl bg-amber-50 border border-amber-200 space-y-2">
              <div className="flex items-center gap-2 text-amber-900 text-xs font-bold">
                <AlertTriangle className="w-4 h-4 text-amber-600" />
                <span>IDENTIFIED AUTHENTICATION RISK SIGNALS ({riskSignals.length})</span>
              </div>
              <div className="space-y-1.5 pt-1">
                {riskSignals.map((signal, idx) => (
                  <div key={idx} className="p-2 rounded bg-white border border-amber-200 text-xs text-amber-900 flex items-start gap-2">
                    <span className="text-amber-600 font-bold shrink-0">!</span>
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
          <div className="p-4 rounded-xl bg-white border border-slate-200 space-y-3">
            <div className="flex items-center justify-between border-b border-slate-100 pb-2">
              <div className="flex items-center gap-2 text-slate-900">
                <Eye className="w-4 h-4 text-slate-600" />
                <h3 className="text-xs font-bold uppercase tracking-wider">
                  Observed Evidence
                </h3>
              </div>
              <span className="text-[10px] font-medium text-slate-400">MTA Headers & Raw DNS</span>
            </div>

            <p className="text-xs text-slate-500 leading-relaxed">
              Directly observed data points extracted from the email MIME envelope and verified DNS records.
            </p>

            <div className="space-y-2 pt-1">
              {observedEvidenceList && observedEvidenceList.length > 0 ? (
                observedEvidenceList.map((item, idx) => (
                  <div key={idx} className="p-2.5 rounded-lg bg-slate-50 border border-slate-200 text-xs text-slate-800 break-all leading-snug">
                    <span className="text-cyan-600 font-bold mr-1.5">•</span>
                    {item}
                  </div>
                ))
              ) : (
                <div className="text-slate-400 italic p-2 text-xs">No raw observed headers extracted</div>
              )}
            </div>
          </div>

          {/* Column 2: INFERRED INTELLIGENCE */}
          <div className="p-4 rounded-xl bg-white border border-slate-200 space-y-3">
            <div className="flex items-center justify-between border-b border-slate-100 pb-2">
              <div className="flex items-center gap-2 text-slate-900">
                <Cpu className="w-4 h-4 text-slate-600" />
                <h3 className="text-xs font-bold uppercase tracking-wider">
                  Inferred Intelligence
                </h3>
              </div>
              <span className="text-[10px] font-medium text-slate-400">Risk Interpretation</span>
            </div>

            <p className="text-xs text-slate-500 leading-relaxed">
              Analytical intelligence synthesized by cross-referencing sender identities, alignment modes, and spoofing indicators.
            </p>

            <div className="space-y-2 pt-1">
              {inferredEvidenceList && inferredEvidenceList.length > 0 ? (
                inferredEvidenceList.map((item, idx) => (
                  <div key={idx} className="p-2.5 rounded-lg bg-slate-50 border border-slate-200 text-xs text-slate-800 break-all leading-snug">
                    <span className="text-amber-600 font-bold mr-1.5">◆</span>
                    {item}
                  </div>
                ))
              ) : (
                <div className="text-slate-400 italic p-2 text-xs">No inferred intelligence anomalies flagged</div>
              )}
            </div>
          </div>

        </div>
      )}

      {/* TAB 3: DNS FORENSICS DETAILS */}
      {activeTab === 'dns' && (
        <div className="space-y-4">
          <div className="p-4 rounded-xl bg-white border border-slate-200 space-y-3">
            <div className="flex items-center justify-between border-b border-slate-100 pb-2">
              <div className="flex items-center gap-2 text-slate-900">
                <Server className="w-4 h-4 text-slate-600" />
                <h3 className="text-xs font-bold uppercase tracking-wider">
                  Raw DNS TXT Records
                </h3>
              </div>
              <span className="text-[10px] font-medium text-slate-400">Live Resolution</span>
            </div>

            {/* SPF DNS Record */}
            <div className="space-y-1.5">
              <span className="text-slate-700 font-semibold text-xs">1. SPF DNS TXT Record ({spf.domain || fromDomain}):</span>
              <pre className="p-3 rounded-lg bg-slate-50 border border-slate-200 text-xs text-slate-800 overflow-x-auto whitespace-pre-wrap font-mono">
                {spf.record || 'No TXT record starting with "v=spf1" found.'}
              </pre>
            </div>

            {/* DKIM DNS Record */}
            <div className="space-y-1.5 pt-2 border-t border-slate-100">
              <span className="text-slate-700 font-semibold text-xs">
                2. DKIM Public Key Record ({dnsForensics?.dkim?.[0]?.queryHost || `${dkim.selector || 'selector'}._domainkey.${dkim.domain || fromDomain}`}):
              </span>
              <pre className="p-3 rounded-lg bg-slate-50 border border-slate-200 text-xs text-slate-800 overflow-x-auto whitespace-pre-wrap font-mono">
                {dnsForensics?.dkim?.[0]?.record || 'No DKIM public key record found at selector host.'}
              </pre>
            </div>

            {/* DMARC DNS Record */}
            <div className="space-y-1.5 pt-2 border-t border-slate-100">
              <span className="text-slate-700 font-semibold text-xs">
                3. DMARC Policy Record ({dnsForensics?.dmarc?.queriedHost || `_dmarc.${fromDomain}`}):
              </span>
              <pre className="p-3 rounded-lg bg-slate-50 border border-slate-200 text-xs text-slate-800 overflow-x-auto whitespace-pre-wrap font-mono">
                {dmarc.record || 'No TXT record starting with "v=DMARC1" found.'}
              </pre>
            </div>
          </div>
        </div>
      )}

    </div>
  );
};
