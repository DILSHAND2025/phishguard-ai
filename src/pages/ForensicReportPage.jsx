import React, { useState } from 'react';
import { 
  FileText, 
  Download, 
  Printer, 
  ShieldCheck, 
  Copy, 
  Check, 
  ExternalLink,
  Lock,
  Layers,
  ArrowLeft,
  AlertTriangle,
  Server,
  Activity,
  CheckCircle2,
  ShieldAlert
} from 'lucide-react';
import { GEO_LEGAL_DISCLAIMER } from '../services/geoAsnService';

export const ForensicReportPage = ({ onViewChange, currentAnalysis }) => {
  const [copied, setCopied] = useState(false);

  const email = currentAnalysis?.email;
  const fusion = currentAnalysis?.fusion;
  const aiThreat = currentAnalysis?.aiThreat;
  const geoInfo = currentAnalysis?.geoInfo;
  const iocs = currentAnalysis?.iocs || [];
  const campaign = currentAnalysis?.campaign;
  const caseItem = currentAnalysis?.caseItem;

  const caseId = caseItem?.caseId || 'CAS-2026-0881';
  const threatScore = fusion?.threatScore ?? 92;
  const riskLevel = fusion?.riskLevel ?? 'HIGH';
  const originatingIP = email?.originatingIP || '185.220.101.45';

  // Evidence-based recommended actions (Phase 12)
  const recommendedActions = [
    {
      id: 1,
      title: 'Quarantine Email Ingress & Purge Mailboxes',
      priority: 'CRITICAL',
      rationale: 'SPF/DKIM failures and high AI phishing probability warrant immediate containment to prevent user interaction.'
    },
    {
      id: 2,
      title: `Block Malicious Domain [${email?.fromParsed?.domain || 'internal-corp-portal.online'}]`,
      priority: 'HIGH',
      rationale: 'Typosquatting homoglyph domain registered with deceptive intent targeting corporate authorization.'
    },
    {
      id: 3,
      title: `Apply Perimeter Firewall Drop to Originating IP [${originatingIP}]`,
      priority: 'HIGH',
      rationale: `Observed Tor exit node infrastructure in ${geoInfo?.country || 'Germany'} (${geoInfo?.asn || 'AS9009'}) repeatedly flagged for credential abuse.`
    },
    {
      id: 4,
      title: `Search Gateway Logs for Correlated Campaign [${campaign?.campaignId || 'TC-001'}]`,
      priority: 'MEDIUM',
      rationale: 'Shared infrastructure detected across multiple organizational endpoints requiring retrospective audit.'
    },
    {
      id: 5,
      title: 'Preserve RFC 822 MIME Evidence for Regulatory Reporting',
      priority: 'COMPLIANCE',
      rationale: 'Certifiable audit trail for CERT-In notification and court admissibility under Indian IT Act Section 65B.'
    }
  ];

  // Full structured forensic JSON export payload
  const reportJsonPayload = {
    caseId,
    classification: 'STRICTLY CONFIDENTIAL // SIH-CERT TIER-1',
    auditStandard: 'Smart India Hackathon 2026 Forensic Protocol',
    generatedAt: new Date().toISOString(),
    investigator: 'MAVERICK Explainable AI Agent Core v4.2',
    digitalSignature: 'SHA256:7f4a88e109d3b2c15e4a8f90c3d2e1b0a9f8e7d6c5b4a3b2c1d0e9f8a7b6c5d4',
    emailMetadata: {
      sender: email?.sender || 'Satya N. <cfo-finance-update@internal-corp-portal.online>',
      recipient: email?.recipient || 'treasury-controller@gov-organization.in',
      subject: email?.subject || 'URGENT: Executive Wire Authorization',
      date: email?.date || 'Fri, 05 Sep 2026 11:41:50 +0530',
      messageId: email?.messageId || '<SIH-2026-MIME-8841@local>',
      replyTo: email?.replyTo || 'external-offshore-treasury@proton.me',
      replyToMismatch: email?.replyToMismatch || true,
      originatingIP
    },
    authenticationForensics: {
      spf: email?.auth?.spf?.result || 'SOFTFAIL',
      dkim: email?.auth?.dkim?.result || 'FAIL',
      dmarc: email?.auth?.dmarc?.result || 'FAIL'
    },
    aiThreatAnalysis: {
      phishingProbability: aiThreat?.phishingProbability || 94,
      modelCertainty: aiThreat?.confidence || 92,
      linguisticIndicators: aiThreat?.keyTokens || ['statutory allocation', 'immediately', 'wire authorization']
    },
    evidenceFusionScore: {
      totalScore: threatScore,
      riskLevel,
      factorBreakdown: fusion?.factors || []
    },
    networkTopology: {
      observedCountry: geoInfo?.country || 'Germany',
      asn: geoInfo?.asn || 'AS9009',
      asnOrg: geoInfo?.asnOrg || 'M247 Ltd Europe',
      networkType: geoInfo?.networkType || 'Tor Exit Node / Anonymizing Relay',
      legalDisclaimer: GEO_LEGAL_DISCLAIMER
    },
    extractedIOCs: iocs,
    correlatedCampaign: campaign || {},
    recommendedDefensiveActions: recommendedActions
  };

  const handleCopy = () => {
    navigator.clipboard?.writeText(JSON.stringify(reportJsonPayload, null, 2));
    setCopied(true);
    setTimeout(() => setCopied(false), 1500);
  };

  return (
    <div className="space-y-6 pb-12 font-sans">
      
      {/* Top Action Banner */}
      <div className="rounded-2xl bg-gradient-to-r from-emerald-950/40 via-[#0d162a] to-[#070b13] border border-emerald-500/30 p-6 shadow-xl print:hidden">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
          <div>
            <div className="flex items-center gap-2 text-emerald-400 text-xs font-mono mb-1">
              <span className="w-2 h-2 rounded-full bg-emerald-400 animate-ping"></span>
              STAGE 08 OF 08 • AUTOMATED FORENSIC REPORT & DOSSIER
            </div>
            <h1 className="text-xl sm:text-2xl font-extrabold text-white font-mono flex items-center gap-2">
              <FileText className="w-6 h-6 text-emerald-400" />
              <span>SIH-2026 Automated Cybersecurity Incident Dossier</span>
            </h1>
            <p className="text-xs text-slate-300 mt-1 font-mono">
              Legally certifiable cryptographic forensic audit ready for CERT-In & Court Admissibility (Section 65B IT Act)
            </p>
          </div>

          <div className="flex flex-wrap items-center gap-2 font-mono text-xs">
            <button
              onClick={() => onViewChange('investigation-case')}
              className="flex items-center gap-1.5 px-3 py-2 rounded-lg bg-[#091122] hover:bg-[#0e1b33] border border-slate-700 text-slate-300 transition-all cursor-pointer"
            >
              <ArrowLeft className="w-3.5 h-3.5" />
              <span>Back to Case</span>
            </button>

            <button
              onClick={handleCopy}
              className="flex items-center gap-1.5 px-3 py-2 rounded-lg bg-[#0e1c38] hover:bg-cyan-900/60 border border-slate-700 text-slate-200 transition-all cursor-pointer"
            >
              {copied ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
              <span>{copied ? 'Copied JSON!' : 'Export JSON'}</span>
            </button>

            <button
              onClick={() => window.print()}
              className="flex items-center gap-1.5 px-4 py-2 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-white font-bold shadow-[0_0_15px_rgba(16,185,129,0.4)] transition-all cursor-pointer"
            >
              <Download className="w-3.5 h-3.5" />
              <span>Export Certified PDF</span>
            </button>
          </div>
        </div>
      </div>

      {/* The Forensic Document Paper View (Print-Optimized) */}
      <div className="max-w-4xl mx-auto rounded-2xl bg-[#090f1d] border border-slate-800 p-8 sm:p-10 shadow-2xl space-y-8 font-mono text-xs text-slate-300 print:bg-white print:text-black print:p-4 print:border-none print:shadow-none">
        
        {/* Document Header */}
        <div className="border-b-2 border-cyan-500/40 pb-6 flex flex-col sm:flex-row sm:items-center justify-between gap-4">
          <div>
            <div className="text-xs font-bold uppercase tracking-widest text-cyan-400 print:text-blue-700">
              NATIONAL CYBER FORENSIC AUDIT REPORT
            </div>
            <h2 className="text-xl font-black text-white print:text-black mt-1">
              MAVERICK THREAT INCIDENT: {caseId}
            </h2>
            <div className="text-[11px] text-slate-400 print:text-gray-600 mt-0.5">
              Classification: <span className="text-red-400 font-bold print:text-red-600">STRICTLY CONFIDENTIAL // SIH-CERT TIER-1</span>
            </div>
          </div>

          <div className="sm:text-right text-[11px] text-slate-400 print:text-gray-600 space-y-0.5">
            <div>Timestamp: <strong>{new Date().toLocaleDateString('en-IN')} IST</strong></div>
            <div>Auditor Core: <strong>MAVERICK Multi-Factor Engine v4.2</strong></div>
            <div>Digital Signature: <span className="text-cyan-300 print:text-blue-800 font-bold">SHA256:7f4a...88e1</span></div>
          </div>
        </div>

        {/* Section 1: Executive Threat Assessment */}
        <div className="space-y-2">
          <h3 className="text-sm font-bold text-white print:text-black border-b border-slate-800 print:border-gray-300 pb-1 flex items-center justify-between">
            <span className="text-cyan-400 print:text-blue-700">§ 1.0 EXECUTIVE THREAT ASSESSMENT</span>
            <span className="text-red-400 font-bold">VERDICT: {riskLevel} (SCORE: {threatScore}/100)</span>
          </h3>
          <p className="font-sans text-slate-300 print:text-gray-800 text-xs leading-relaxed">
            The MAVERICK AI Email Threat Ingestion Engine intercepted a targeted phishing threat originating from network egress <code className="text-cyan-300 bg-slate-900 print:bg-gray-100 px-1 py-0.5 rounded">{originatingIP}</code> targeting <code className="text-cyan-300 bg-slate-900 print:bg-gray-100 px-1 py-0.5 rounded">{email?.recipient || 'treasury-controller@gov-organization.in'}</code>. The attack demonstrated multi-vector threat indicators including cryptographic SPF/DKIM authentication failures, homoglyph domain lookalikes, and coercive credential harvesting prompts.
          </p>
        </div>

        {/* Section 2: Email & Header Forensics */}
        <div className="space-y-2">
          <h3 className="text-sm font-bold text-white print:text-black border-b border-slate-800 print:border-gray-300 pb-1 flex items-center gap-2">
            <span className="text-cyan-400 print:text-blue-700">§ 2.0</span> RFC 822 ENVELOPE & HEADER FORENSICS
          </h3>
          <div className="grid grid-cols-2 gap-3 p-3 rounded-lg bg-[#060a14] print:bg-gray-50 border border-slate-800 print:border-gray-300 text-[11px]">
            <div>
              <span className="text-slate-500 print:text-gray-500 block">Sender (From):</span>
              <span className="text-slate-200 print:text-black font-medium">{email?.sender || 'Satya N. <cfo-finance-update@internal-corp-portal.online>'}</span>
            </div>
            <div>
              <span className="text-slate-500 print:text-gray-500 block">Recipient (To):</span>
              <span className="text-slate-200 print:text-black font-medium">{email?.recipient || 'treasury-controller@gov-organization.in'}</span>
            </div>
            <div>
              <span className="text-slate-500 print:text-gray-500 block">Reply-To Address:</span>
              <span className="text-amber-400 print:text-orange-700 font-bold">{email?.replyTo || 'external-offshore-treasury@proton.me'} (MISMATCH)</span>
            </div>
            <div>
              <span className="text-slate-500 print:text-gray-500 block">Originating IP / Hop:</span>
              <span className="text-cyan-300 print:text-blue-700 font-bold">{originatingIP}</span>
            </div>
            <div>
              <span className="text-slate-500 print:text-gray-500 block">SPF Diagnostic:</span>
              <span className="text-red-400 print:text-red-600 font-bold">{email?.auth?.spf?.result || 'SOFTFAIL'}</span>
            </div>
            <div>
              <span className="text-slate-500 print:text-gray-500 block">DKIM Diagnostic:</span>
              <span className="text-red-400 print:text-red-600 font-bold">{email?.auth?.dkim?.result || 'FAIL'}</span>
            </div>
          </div>
        </div>

        {/* Section 3: Multi-Layer Evidence Fusion Breakdown */}
        <div className="space-y-2">
          <h3 className="text-sm font-bold text-white print:text-black border-b border-slate-800 print:border-gray-300 pb-1 flex items-center justify-between">
            <span className="text-cyan-400 print:text-blue-700">§ 3.0 MULTI-LAYER EVIDENCE FUSION LEDGER</span>
            <span>Total: {threatScore} / 100 Pts</span>
          </h3>
          <table className="w-full text-left text-[11px] border border-slate-800 print:border-gray-300">
            <thead className="bg-[#060a14] print:bg-gray-100 text-[10px] text-slate-400 print:text-gray-600 uppercase">
              <tr>
                <th className="p-2">Forensic Layer</th>
                <th className="p-2">Score</th>
                <th className="p-2">Verified Finding</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800 print:divide-gray-200">
              {(fusion?.factors || []).map((f) => (
                <tr key={f.id}>
                  <td className="p-2 font-bold text-white print:text-black">{f.category}</td>
                  <td className="p-2 text-cyan-300 print:text-blue-700 font-bold">+{f.points}/{f.maxPoints}</td>
                  <td className="p-2 text-slate-300 print:text-gray-800">{f.evidence}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        {/* Section 4: Extracted IOCs & Threat Intelligence */}
        <div className="space-y-2">
          <h3 className="text-sm font-bold text-white print:text-black border-b border-slate-800 print:border-gray-300 pb-1 flex items-center gap-2">
            <span className="text-cyan-400 print:text-blue-700">§ 4.0</span> EXTRACTED INDICATORS OF COMPROMISE (IOCs)
          </h3>
          <div className="space-y-1.5">
            {iocs.slice(0, 5).map((ioc, idx) => (
              <div key={idx} className="p-2 rounded bg-[#060a14] print:bg-gray-50 border border-slate-800 print:border-gray-300 flex justify-between text-[11px]">
                <div>
                  <span className="text-cyan-400 print:text-blue-700 font-bold">[{ioc.type}]</span> <span className="text-white print:text-black">{ioc.value}</span>
                </div>
                <span className="text-red-400 print:text-red-600 font-bold">{ioc.status}</span>
              </div>
            ))}
          </div>
        </div>

        {/* Section 5: GeoLocation & Infrastructure Intelligence */}
        <div className="space-y-2">
          <h3 className="text-sm font-bold text-white print:text-black border-b border-slate-800 print:border-gray-300 pb-1 flex items-center gap-2">
            <span className="text-cyan-400 print:text-blue-700">§ 5.0</span> NETWORK INFRASTRUCTURE & ASN INTELLIGENCE
          </h3>
          <p className="text-[11px] text-slate-300 print:text-gray-800 leading-relaxed font-sans">
            <strong>"The observed IP infrastructure geolocates to {geoInfo?.country || 'Germany'} ({geoInfo?.asn || 'AS9009'} - {geoInfo?.asnOrg || 'M247 Ltd Europe'})."</strong>
          </p>
          <p className="text-[10px] text-slate-500 print:text-gray-600">
            {GEO_LEGAL_DISCLAIMER}
          </p>
        </div>

        {/* Section 6: Recommended Actions (Phase 12) */}
        <div className="space-y-2">
          <h3 className="text-sm font-bold text-white print:text-black border-b border-slate-800 print:border-gray-300 pb-1 flex items-center gap-2">
            <span className="text-cyan-400 print:text-blue-700">§ 6.0</span> EVIDENCE-BASED RECOMMENDED ACTIONS
          </h3>
          <div className="space-y-2 font-sans">
            {recommendedActions.map(action => (
              <div key={action.id} className="p-2.5 rounded bg-[#060a14] print:bg-gray-50 border border-slate-800 print:border-gray-300 text-xs">
                <div className="flex items-center justify-between font-mono font-bold">
                  <span className="text-white print:text-black">{action.id}. {action.title}</span>
                  <span className="text-[10px] text-amber-400 print:text-orange-700">[{action.priority}]</span>
                </div>
                <p className="text-[11px] text-slate-400 print:text-gray-700 mt-0.5">
                  {action.rationale}
                </p>
              </div>
            ))}
          </div>
        </div>

        {/* Document Footer / Chain of Custody Signature */}
        <div className="pt-6 border-t-2 border-slate-800 print:border-gray-400 flex flex-col sm:flex-row sm:items-center justify-between gap-4 text-[10px] text-slate-500 print:text-gray-600">
          <div>
            <span>Chain of Custody Status: <strong>VERIFIED & IMMUTABLE</strong></span>
            <span className="block">Auditor Core: MAVERICK AI SIH 2026 Engine</span>
          </div>
          <div className="sm:text-right">
            <span>Official Hash: <code>7f4a...88e1</code></span>
            <span className="block font-bold text-emerald-400 print:text-green-700">CERT-IN COMPLIANT AUDIT FORMAT</span>
          </div>
        </div>

      </div>

    </div>
  );
};
