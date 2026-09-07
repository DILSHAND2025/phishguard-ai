import React, { useState, useEffect } from 'react';
import { 
  FileText, 
  Download, 
  Printer, 
  ShieldCheck, 
  Copy, 
  Check, 
  Lock, 
  ArrowLeft, 
  AlertTriangle, 
  Hash, 
  Cpu, 
  CheckCircle, 
  FileCheck, 
  RefreshCw 
} from 'lucide-react';
import { buildForensicReport } from '../../services/forensicReportService.js';
import { generateForensicPdf, computePdfFileHash, downloadPdfInBrowser } from '../../services/pdfBuilder.js';
import { GEO_LEGAL_DISCLAIMER } from '../../services/geoAsnService.js';

export const ForensicReport = ({ analysisResult, onViewChange }) => {
  const [report, setReport] = useState(null);
  const [loading, setLoading] = useState(true);
  const [pdfExporting, setPdfExporting] = useState(false);
  const [pdfHash, setPdfHash] = useState('');
  const [copiedHash, setCopiedHash] = useState(false);
  const [copiedJson, setCopiedJson] = useState(false);
  const [activeTab, setActiveTab] = useState('full-dossier');

  // Build report model whenever analysisResult changes
  useEffect(() => {
    let isMounted = true;
    setLoading(true);

    buildForensicReport(analysisResult)
      .then(rep => {
        if (isMounted) {
          setReport(rep);
          setLoading(false);
        }
      })
      .catch(err => {
        console.error('Failed to compile forensic report:', err);
        if (isMounted) setLoading(false);
      });

    return () => { isMounted = false; };
  }, [analysisResult]);

  const handleExportPdf = async () => {
    if (!report) return;
    try {
      setPdfExporting(true);
      const pdfBytes = generateForensicPdf(report);
      const fileHash = await computePdfFileHash(pdfBytes);
      setPdfHash(fileHash);
      const filename = `${report.caseId || 'MAVERICK'}-Forensic-Report.pdf`;
      downloadPdfInBrowser(pdfBytes, filename);
    } catch (err) {
      console.error('PDF export failed:', err);
      alert(`PDF Export Error: ${err.message}`);
    } finally {
      setPdfExporting(false);
    }
  };

  const handleCopyHash = () => {
    if (!report?.evidenceIntegrity?.contentHashSha256) return;
    navigator.clipboard?.writeText(report.evidenceIntegrity.contentHashSha256);
    setCopiedHash(true);
    setTimeout(() => setCopiedHash(false), 2000);
  };

  const handleCopyJson = () => {
    if (!report) return;
    navigator.clipboard?.writeText(JSON.stringify(report, null, 2));
    setCopiedJson(true);
    setTimeout(() => setCopiedJson(false), 2000);
  };

  if (loading) {
    return (
      <div className="rounded-2xl bg-[#090f1d] border border-slate-800 p-12 text-center font-mono">
        <RefreshCw className="w-8 h-8 text-cyan-400 animate-spin mx-auto mb-3" />
        <p className="text-white text-sm font-bold">Compiling Forensic Evidence Ledger...</p>
        <p className="text-slate-400 text-xs mt-1">Calibrating multi-layer threat scores and computing SHA-256 hash...</p>
      </div>
    );
  }

  if (!report) {
    return (
      <div className="rounded-2xl bg-[#090f1d] border border-red-500/40 p-12 text-center font-mono">
        <AlertTriangle className="w-8 h-8 text-red-400 mx-auto mb-3" />
        <p className="text-white text-sm font-bold">Forensic Report Compilation Unavailable</p>
        <p className="text-slate-400 text-xs mt-1">No valid analysis results found in memory.</p>
      </div>
    );
  }

  const score = report.threatAssessment?.overallScore ?? 0;
  const risk = (report.threatAssessment?.classification || 'LOW').toUpperCase();
  const contentHash = report.evidenceIntegrity?.contentHashSha256 || '';

  const getRiskBadgeColor = (lvl) => {
    if (lvl === 'CRITICAL' || lvl === 'HIGH') return 'bg-red-950/80 border-red-500 text-red-400 shadow-[0_0_15px_rgba(239,68,68,0.3)]';
    if (lvl === 'SUSPICIOUS') return 'bg-amber-950/80 border-amber-500 text-amber-400 shadow-[0_0_15px_rgba(245,158,11,0.3)]';
    return 'bg-emerald-950/80 border-emerald-500 text-emerald-400 shadow-[0_0_15px_rgba(16,185,129,0.3)]';
  };

  return (
    <div className="space-y-6 pb-12 font-sans">
      
      {/* Top Action Control Banner (Hidden in Print) */}
      <div className="rounded-2xl bg-gradient-to-r from-[#0d162a] via-[#0b1325] to-[#070b13] border border-cyan-500/30 p-6 shadow-xl print:hidden">
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4">
          <div>
            <div className="flex items-center gap-2 text-cyan-400 text-xs font-mono mb-1">
              <span className="w-2 h-2 rounded-full bg-cyan-400 animate-ping"></span>
              STAGE 08 OF 08 • AUTOMATED FORENSIC REPORTING & EVIDENCE INTEGRITY
            </div>
            <h1 className="text-xl sm:text-2xl font-extrabold text-white font-mono flex items-center gap-2.5">
              <FileText className="w-6 h-6 text-cyan-400" />
              <span>Cybersecurity Incident Dossier: {report.caseId}</span>
            </h1>
            <p className="text-xs text-slate-300 mt-1 font-mono">
              Certified Multi-Layer Forensic Evidence with Cryptographic Chain of Custody (ISO/IEC 27037:2012)
            </p>
          </div>

          <div className="flex flex-wrap items-center gap-2.5 font-mono text-xs">
            {onViewChange && (
              <button
                type="button"
                id="btn-report-back-case"
                onClick={() => onViewChange('analysis-results')}
                className="flex items-center gap-1.5 px-3 py-2 rounded-xl bg-[#091122] hover:bg-[#0e1b33] border border-slate-700 text-slate-300 transition-all cursor-pointer"
              >
                <ArrowLeft className="w-3.5 h-3.5" />
                <span>Back to Verdict</span>
              </button>
            )}

            <button
              type="button"
              id="btn-copy-report-hash"
              onClick={handleCopyHash}
              className="flex items-center gap-1.5 px-3 py-2 rounded-xl bg-[#0e1c38] hover:bg-cyan-950/60 border border-slate-700 text-slate-200 transition-all cursor-pointer"
              title={contentHash}
            >
              {copiedHash ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Hash className="w-3.5 h-3.5 text-cyan-400" />}
              <span>{copiedHash ? 'Hash Copied!' : 'Copy SHA-256'}</span>
            </button>

            <button
              type="button"
              id="btn-export-report-json"
              onClick={handleCopyJson}
              className="flex items-center gap-1.5 px-3 py-2 rounded-xl bg-[#0e1c38] hover:bg-cyan-950/60 border border-slate-700 text-slate-200 transition-all cursor-pointer"
            >
              {copiedJson ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
              <span>{copiedJson ? 'JSON Copied!' : 'Export JSON'}</span>
            </button>

            <button
              type="button"
              id="btn-print-report"
              onClick={() => window.print()}
              className="flex items-center gap-1.5 px-3.5 py-2 rounded-xl bg-[#0e1c38] hover:bg-slate-800 border border-slate-700 text-slate-200 transition-all cursor-pointer"
            >
              <Printer className="w-3.5 h-3.5" />
              <span>Print</span>
            </button>

            <button
              type="button"
              id="btn-export-certified-pdf"
              onClick={handleExportPdf}
              disabled={pdfExporting}
              className="flex items-center gap-2 px-4 py-2 rounded-xl bg-gradient-to-r from-emerald-600 to-teal-600 hover:from-emerald-500 hover:to-teal-500 text-white font-bold shadow-[0_0_20px_rgba(16,185,129,0.4)] transition-all cursor-pointer disabled:opacity-50"
            >
              {pdfExporting ? (
                <>
                  <RefreshCw className="w-4 h-4 animate-spin" />
                  <span>Generating PDF...</span>
                </>
              ) : (
                <>
                  <Download className="w-4 h-4" />
                  <span>Export Certified PDF</span>
                </>
              )}
            </button>
          </div>
        </div>

        {/* Tab Navigation (Hidden in Print) */}
        <div className="flex flex-wrap items-center gap-2 mt-5 pt-4 border-t border-slate-800/80 font-mono text-xs">
          {[
            { id: 'full-dossier', label: 'Complete Dossier' },
            { id: 'observed-inferred', label: 'Observed vs Inferred' },
            { id: 'authentication', label: 'Email Authentication & DNS' },
            { id: 'timeline-actions', label: 'Timeline & Response Plan' }
          ].map(tab => (
            <button
              key={tab.id}
              type="button"
              onClick={() => setActiveTab(tab.id)}
              className={`px-3.5 py-1.5 rounded-lg border transition-all cursor-pointer ${
                activeTab === tab.id
                  ? 'bg-cyan-950/70 border-cyan-500 text-cyan-300 font-bold'
                  : 'bg-[#09101e] border-slate-800 text-slate-400 hover:text-white'
              }`}
            >
              {tab.label}
            </button>
          ))}
          {pdfHash && (
            <div className="ml-auto text-[11px] text-emerald-400 font-mono flex items-center gap-1.5">
              <CheckCircle className="w-3.5 h-3.5" />
              <span>PDF Hash: {pdfHash.slice(0, 16)}...</span>
            </div>
          )}
        </div>
      </div>

      {/* Main Dossier Paper / Canvas */}
      <div className="max-w-5xl mx-auto rounded-2xl bg-[#090f1d] border border-slate-800 p-6 sm:p-10 shadow-2xl space-y-8 font-mono text-xs text-slate-300 print:bg-white print:text-black print:p-4 print:border-none print:shadow-none">
        
        {/* Document Header */}
        <div className="border-b-2 border-cyan-500/50 pb-6 flex flex-col sm:flex-row sm:items-center justify-between gap-4">
          <div>
            <div className="text-xs font-bold uppercase tracking-widest text-cyan-400 print:text-blue-700 flex items-center gap-2">
              <ShieldCheck className="w-4 h-4" />
              <span>NATIONAL CYBERSECURITY INCIDENT DOSSIER</span>
            </div>
            <h2 className="text-2xl font-black text-white print:text-black mt-1 tracking-tight">
              INCIDENT: {report.caseId}
            </h2>
            <div className="text-[11px] text-slate-400 print:text-gray-600 mt-1">
              Classification: <span className="text-red-400 font-bold print:text-red-600">{report.classification}</span>
            </div>
          </div>

          <div className="sm:text-right text-[11px] text-slate-400 print:text-gray-600 space-y-1">
            <div>Audit Timestamp: <strong>{new Date(report.generatedAt).toUTCString()}</strong></div>
            <div>Investigator Core: <strong>MAVERICK Multi-Layer Engine v4.2</strong></div>
            <div className="flex sm:justify-end items-center gap-1">
              <span>SHA-256 Digest:</span>
              <code className="text-cyan-300 print:text-blue-800 font-bold bg-slate-950 print:bg-gray-100 px-1.5 py-0.5 rounded text-[10px]">
                {contentHash ? `${contentHash.slice(0, 12)}...${contentHash.slice(-8)}` : 'COMPUTING'}
              </code>
            </div>
          </div>
        </div>

        {/* Section 1: Executive Threat Assessment */}
        <div className="space-y-4">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-slate-800 print:border-gray-300 pb-2">
            <h3 className="text-sm font-bold text-white print:text-black flex items-center gap-2">
              <span className="text-cyan-400 print:text-blue-700">1.0</span> EXECUTIVE THREAT ASSESSMENT & CALIBRATION
            </h3>
            <span className={`px-3 py-1 rounded-lg border font-bold text-xs ${getRiskBadgeColor(risk)}`}>
              VERDICT: {risk} RISK ({score}/100)
            </span>
          </div>

          {/* Quick Score Metrics Cards */}
          <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
            <div className="p-4 rounded-xl bg-[#060a14] print:bg-gray-50 border border-slate-800 print:border-gray-300">
              <span className="text-slate-400 text-[10px] uppercase font-bold block">Composite Threat Score</span>
              <div className="flex items-baseline gap-1 mt-1">
                <span className="text-3xl font-black text-white print:text-black">{score}</span>
                <span className="text-xs text-slate-400">/ 100</span>
              </div>
              <span className="text-[10px] text-slate-500 block mt-1">Weighted 6-layer evidence fusion</span>
            </div>

            <div className="p-4 rounded-xl bg-[#060a14] print:bg-gray-50 border border-slate-800 print:border-gray-300">
              <span className="text-slate-400 text-[10px] uppercase font-bold block">AI Phishing Probability</span>
              <div className="flex items-baseline gap-1 mt-1">
                <span className="text-3xl font-black text-cyan-300 print:text-blue-700">
                  {report.mlAnalysis?.phishingProbability != null ? `${report.mlAnalysis.phishingProbability}%` : 'N/A'}
                </span>
              </div>
              <span className="text-[10px] text-slate-500 block mt-1">Natural language ML classifier</span>
            </div>

            <div className="p-4 rounded-xl bg-[#060a14] print:bg-gray-50 border border-slate-800 print:border-gray-300">
              <span className="text-slate-400 text-[10px] uppercase font-bold block">Email Authentication</span>
              <div className="text-sm font-black text-white print:text-black mt-2">
                SPF: <span className={report.emailAuthentication?.spf?.status.includes('PASS') ? 'text-emerald-400' : 'text-red-400'}>{report.emailAuthentication?.spf?.status || 'N/A'}</span>
                {' | '}
                DKIM: <span className={report.emailAuthentication?.dkim?.status.includes('PASS') ? 'text-emerald-400' : 'text-red-400'}>{report.emailAuthentication?.dkim?.status || 'N/A'}</span>
              </div>
              <span className="text-[10px] text-slate-500 block mt-1">
                Alignment: {report.emailAuthentication?.alignment?.dmarcAligned ? 'ALIGNED' : 'MISALIGNED (Spoof Risk)'}
              </span>
            </div>
          </div>

          {/* Executive Summary Narrative */}
          <div className="p-4 rounded-xl bg-[#060a14] print:bg-gray-50 border border-slate-800 print:border-gray-300">
            <span className="text-[11px] font-bold text-cyan-300 print:text-blue-800 uppercase block mb-1.5">
              Investigator-Grade Executive Summary:
            </span>
            <p className="font-sans text-slate-200 print:text-gray-900 text-xs leading-relaxed">
              {report.executiveSummary}
            </p>
          </div>
        </div>

        {/* Section 2: Ingress MIME Envelope & Header Forensics */}
        {(activeTab === 'full-dossier' || activeTab === 'authentication') && (
          <div className="space-y-3">
            <h3 className="text-sm font-bold text-white print:text-black border-b border-slate-800 print:border-gray-300 pb-1 flex items-center gap-2">
              <span className="text-cyan-400 print:text-blue-700">2.0</span> INGRESS EMAIL ENVELOPE & HEADER TELEMETRY
            </h3>
            
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 p-4 rounded-xl bg-[#060a14] print:bg-gray-50 border border-slate-800 print:border-gray-300 text-[11px]">
              <div>
                <span className="text-slate-500 print:text-gray-500 block">Sender Header (From):</span>
                <span className="text-white print:text-black font-semibold break-all">{report.emailMetadata?.sender}</span>
              </div>
              <div>
                <span className="text-slate-500 print:text-gray-500 block">Recipient (To):</span>
                <span className="text-white print:text-black font-semibold break-all">{report.emailMetadata?.recipient}</span>
              </div>
              <div>
                <span className="text-slate-500 print:text-gray-500 block">Subject Line:</span>
                <span className="text-slate-200 print:text-black font-medium">{report.emailMetadata?.subject}</span>
              </div>
              <div>
                <span className="text-slate-500 print:text-gray-500 block">RFC 822 Ingress Date:</span>
                <span className="text-slate-200 print:text-black">{report.emailMetadata?.date}</span>
              </div>
              <div>
                <span className="text-slate-500 print:text-gray-500 block">Return-Path:</span>
                <span className="text-slate-200 print:text-black font-mono">{report.emailMetadata?.returnPath || 'None'}</span>
              </div>
              <div>
                <span className="text-slate-500 print:text-gray-500 block">Reply-To Routing:</span>
                <span className={report.emailMetadata?.replyToMismatch ? 'text-amber-400 print:text-orange-700 font-bold' : 'text-slate-200 print:text-black'}>
                  {report.emailMetadata?.replyTo || 'Same as sender'} {report.emailMetadata?.replyToMismatch && '(CRITICAL MISMATCH)'}
                </span>
              </div>
              <div>
                <span className="text-slate-500 print:text-gray-500 block">Originating Hop IP:</span>
                <code className="text-cyan-300 print:text-blue-700 font-bold">{report.emailMetadata?.originatingIP}</code>
              </div>
              <div>
                <span className="text-slate-500 print:text-gray-500 block">MIME Message-ID:</span>
                <code className="text-slate-400 print:text-gray-600 text-[10px] break-all">{report.emailMetadata?.messageId}</code>
              </div>
            </div>
          </div>
        )}

        {/* Section 3: Live Email Authentication & Domain Alignment */}
        {(activeTab === 'full-dossier' || activeTab === 'authentication') && (
          <div className="space-y-3">
            <h3 className="text-sm font-bold text-white print:text-black border-b border-slate-800 print:border-gray-300 pb-1 flex items-center justify-between">
              <span className="flex items-center gap-2">
                <span className="text-cyan-400 print:text-blue-700">3.0</span> EMAIL AUTHENTICATION & DNS FORENSICS
              </span>
              <span className="text-xs text-slate-400 font-mono">RFC 7208 / RFC 6376 / RFC 7489</span>
            </h3>

            <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
              {/* SPF Card */}
              <div className="p-3.5 rounded-xl bg-[#060a14] print:bg-gray-50 border border-slate-800 print:border-gray-300">
                <div className="flex items-center justify-between">
                  <span className="font-bold text-white print:text-black text-xs">SPF (RFC 7208)</span>
                  <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                    report.emailAuthentication?.spf?.status.includes('PASS') ? 'bg-emerald-950/80 text-emerald-400 border border-emerald-500/40' : 'bg-red-950/80 text-red-400 border border-red-500/40'
                  }`}>
                    {report.emailAuthentication?.spf?.status}
                  </span>
                </div>
                <div className="mt-2 text-[10px] text-slate-400 space-y-1">
                  <div>Domain: <code className="text-slate-200 print:text-black">{report.emailAuthentication?.spf?.domain}</code></div>
                  {report.emailAuthentication?.spf?.hasPlusAll && (
                    <div className="text-red-400 font-bold">VULNERABILITY: +all wildcard detected!</div>
                  )}
                  <div className="text-slate-500 truncate" title={report.emailAuthentication?.spf?.record}>
                    DNS: {report.emailAuthentication?.spf?.record || 'None'}
                  </div>
                </div>
              </div>

              {/* DKIM Card */}
              <div className="p-3.5 rounded-xl bg-[#060a14] print:bg-gray-50 border border-slate-800 print:border-gray-300">
                <div className="flex items-center justify-between">
                  <span className="font-bold text-white print:text-black text-xs">DKIM (RFC 6376)</span>
                  <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                    report.emailAuthentication?.dkim?.status.includes('PASS') ? 'bg-emerald-950/80 text-emerald-400 border border-emerald-500/40' : 'bg-red-950/80 text-red-400 border border-red-500/40'
                  }`}>
                    {report.emailAuthentication?.dkim?.status}
                  </span>
                </div>
                <div className="mt-2 text-[10px] text-slate-400 space-y-1">
                  <div>Signing Domain: <code className="text-slate-200 print:text-black">{report.emailAuthentication?.dkim?.domain}</code></div>
                  <div>Selector: <code className="text-slate-200 print:text-black">{report.emailAuthentication?.dkim?.selector}</code></div>
                  <div>Public Key DNS: <span className={report.emailAuthentication?.dkim?.dnsRecordFound ? 'text-emerald-400' : 'text-slate-400'}>{report.emailAuthentication?.dkim?.dnsRecordFound ? 'VERIFIED' : 'NOT FOUND'}</span></div>
                </div>
              </div>

              {/* DMARC Card */}
              <div className="p-3.5 rounded-xl bg-[#060a14] print:bg-gray-50 border border-slate-800 print:border-gray-300">
                <div className="flex items-center justify-between">
                  <span className="font-bold text-white print:text-black text-xs">DMARC (RFC 7489)</span>
                  <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                    report.emailAuthentication?.dmarc?.policy === 'reject' ? 'bg-emerald-950/80 text-emerald-400 border border-emerald-500/40' : 'bg-amber-950/80 text-amber-400 border border-amber-500/40'
                  }`}>
                    p={report.emailAuthentication?.dmarc?.policy}
                  </span>
                </div>
                <div className="mt-2 text-[10px] text-slate-400 space-y-1">
                  <div>Policy Domain: <code className="text-slate-200 print:text-black">{report.emailAuthentication?.dmarc?.domain}</code></div>
                  <div>Subdomain Policy: <code className="text-slate-200 print:text-black">{report.emailAuthentication?.dmarc?.subdomainPolicy}</code></div>
                  <div>Compliance Verdict: <span className={report.emailAuthentication?.alignment?.dmarcAligned ? 'text-emerald-400 font-bold' : 'text-red-400 font-bold'}>{report.emailAuthentication?.alignment?.dmarcAligned ? 'ALIGNED' : 'FAIL'}</span></div>
                </div>
              </div>
            </div>
          </div>
        )}

        {/* Section 4: Strict Separation: Observed Evidence vs Inferred Intelligence */}
        {(activeTab === 'full-dossier' || activeTab === 'observed-inferred') && (
          <div className="space-y-3">
            <h3 className="text-sm font-bold text-white print:text-black border-b border-slate-800 print:border-gray-300 pb-1 flex items-center justify-between">
              <span className="flex items-center gap-2">
                <span className="text-cyan-400 print:text-blue-700">4.0</span> STRICT PARTITIONING: OBSERVED EVIDENCE vs INFERRED INTELLIGENCE
              </span>
              <span className="text-[10px] text-slate-500 uppercase">Statutory Requirement</span>
            </h3>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              {/* Left: Observed Evidence */}
              <div className="p-4 rounded-xl bg-[#060a14] print:bg-gray-50 border border-slate-800 print:border-gray-300 space-y-2">
                <div className="flex items-center gap-2 text-cyan-400 print:text-blue-700 font-bold text-xs">
                  <FileCheck className="w-4 h-4" />
                  <span>OBSERVED EMPIRICAL EVIDENCE (FACTS)</span>
                </div>
                <p className="text-[10px] text-slate-400 print:text-gray-600">
                  Cryptographically immutable, directly extracted from raw headers, DNS queries, and attachment headers.
                </p>
                <ul className="space-y-1.5 pt-1 text-[11px]">
                  {report.observedEvidence?.map((item, idx) => (
                    <li key={idx} className="flex items-start gap-1.5 text-slate-200 print:text-black">
                      <span className="text-cyan-400 font-bold">•</span>
                      <span className="break-all">{item}</span>
                    </li>
                  ))}
                </ul>
              </div>

              {/* Right: Inferred Intelligence */}
              <div className="p-4 rounded-xl bg-[#060a14] print:bg-gray-50 border border-slate-800 print:border-gray-300 space-y-2">
                <div className="flex items-center gap-2 text-purple-400 print:text-purple-700 font-bold text-xs">
                  <Cpu className="w-4 h-4" />
                  <span>INFERRED INTELLIGENCE (ANALYTICAL / AI)</span>
                </div>
                <p className="text-[10px] text-slate-400 print:text-gray-600">
                  Statistical predictions, ML classification probabilities, domain alignment deductions, and threat models.
                </p>
                <ul className="space-y-1.5 pt-1 text-[11px]">
                  {report.inferredIntelligence?.map((item, idx) => (
                    <li key={idx} className="flex items-start gap-1.5 text-slate-200 print:text-black">
                      <span className="text-purple-400 font-bold">›</span>
                      <span>{item}</span>
                    </li>
                  ))}
                </ul>
              </div>
            </div>
          </div>
        )}

        {/* Section 5: Extracted IOCs */}
        {(activeTab === 'full-dossier') && (
          <div className="space-y-3">
            <h3 className="text-sm font-bold text-white print:text-black border-b border-slate-800 print:border-gray-300 pb-1 flex items-center justify-between">
              <span className="flex items-center gap-2">
                <span className="text-cyan-400 print:text-blue-700">5.0</span> EXTRACTED INDICATORS OF COMPROMISE (IOCs)
              </span>
              <span className="text-xs text-slate-400">{report.iocAnalysis?.length || 0} Indicators</span>
            </h3>

            <div className="overflow-x-auto rounded-xl border border-slate-800 print:border-gray-300">
              <table className="w-full text-left text-[11px]">
                <thead className="bg-[#060a14] print:bg-gray-100 text-[10px] text-slate-400 print:text-gray-600 uppercase">
                  <tr>
                    <th className="p-2.5">Type</th>
                    <th className="p-2.5">Indicator Value</th>
                    <th className="p-2.5">Ingress Source</th>
                    <th className="p-2.5">Risk Status</th>
                    <th className="p-2.5">Confidence</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/80 print:divide-gray-200">
                  {(report.iocAnalysis || []).length === 0 ? (
                    <tr>
                      <td colSpan={5} className="p-3 text-center text-slate-500">No external IOCs extracted.</td>
                    </tr>
                  ) : (
                    report.iocAnalysis.map((ioc, idx) => (
                      <tr key={idx} className="hover:bg-slate-900/40 print:hover:bg-transparent">
                        <td className="p-2.5 font-bold text-cyan-300 print:text-blue-700">[{ioc.type}]</td>
                        <td className="p-2.5 text-white print:text-black font-mono break-all">{ioc.value}</td>
                        <td className="p-2.5 text-slate-400 print:text-gray-600">{ioc.source}</td>
                        <td className="p-2.5">
                          <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                            ioc.risk === 'MALICIOUS' ? 'bg-red-950/80 text-red-400' : 'bg-amber-950/80 text-amber-400'
                          }`}>
                            {ioc.risk}
                          </span>
                        </td>
                        <td className="p-2.5 text-slate-300 print:text-gray-800">{ioc.confidence}%</td>
                      </tr>
                    ))
                  )}
                </tbody>
              </table>
            </div>
          </div>
        )}

        {/* Section 6: Static Attachment Forensics */}
        {(activeTab === 'full-dossier') && (
          <div className="space-y-3">
            <h3 className="text-sm font-bold text-white print:text-black border-b border-slate-800 print:border-gray-300 pb-1 flex items-center justify-between">
              <span className="flex items-center gap-2">
                <span className="text-cyan-400 print:text-blue-700">6.0</span> STATIC ATTACHMENT FORENSICS
              </span>
              <span className="text-[10px] text-emerald-400 font-bold">Zero-Execution Static Inspection</span>
            </h3>

            <div className="overflow-x-auto rounded-xl border border-slate-800 print:border-gray-300">
              <table className="w-full text-left text-[11px]">
                <thead className="bg-[#060a14] print:bg-gray-100 text-[10px] text-slate-400 print:text-gray-600 uppercase">
                  <tr>
                    <th className="p-2.5">Filename</th>
                    <th className="p-2.5">Magic Bytes</th>
                    <th className="p-2.5">Extension Mismatch</th>
                    <th className="p-2.5">Risk Assessment</th>
                    <th className="p-2.5">SHA-256 Digest</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/80 print:divide-gray-200">
                  {(report.attachmentAnalysis?.attachments || []).length === 0 ? (
                    <tr>
                      <td colSpan={5} className="p-3 text-center text-slate-500">No payload attachments detected.</td>
                    </tr>
                  ) : (
                    report.attachmentAnalysis.attachments.map((att, idx) => (
                      <tr key={idx} className="hover:bg-slate-900/40 print:hover:bg-transparent">
                        <td className="p-2.5 font-bold text-white print:text-black">
                          {att.filename}
                          <span className="block text-[10px] text-slate-400 font-normal">{att.size} | {att.declaredMime}</span>
                        </td>
                        <td className="p-2.5 font-mono text-cyan-300 print:text-blue-700">{att.magicBytes}</td>
                        <td className="p-2.5">
                          {att.extensionMismatch ? (
                            <span className="text-red-400 font-bold">YES (SPOOFED)</span>
                          ) : (
                            <span className="text-emerald-400 font-medium">NO</span>
                          )}
                        </td>
                        <td className="p-2.5">
                          <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                            att.riskAssessment === 'CRITICAL' || att.riskAssessment === 'MALICIOUS' ? 'bg-red-950/80 text-red-400' : 'bg-emerald-950/80 text-emerald-400'
                          }`}>
                            {att.riskAssessment}
                          </span>
                        </td>
                        <td className="p-2.5 font-mono text-slate-300 print:text-gray-700 text-[10px] break-all">
                          {att.sha256}
                        </td>
                      </tr>
                    ))
                  )}
                </tbody>
              </table>
            </div>
          </div>
        )}

        {/* Section 7: GeoLocation & Network Topology */}
        {(activeTab === 'full-dossier') && (
          <div className="space-y-3">
            <h3 className="text-sm font-bold text-white print:text-black border-b border-slate-800 print:border-gray-300 pb-1 flex items-center gap-2">
              <span className="text-cyan-400 print:text-blue-700">7.0</span> NETWORK INFRASTRUCTURE & AUTONOMOUS SYSTEM INTELLIGENCE
            </h3>

            <div className="p-4 rounded-xl bg-[#060a14] print:bg-gray-50 border border-slate-800 print:border-gray-300 space-y-2 text-[11px]">
              {report.geoLocationAnalysis?.primaryNode ? (
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                  <div>
                    <span className="text-slate-500 block">Originating IP:</span>
                    <code className="text-cyan-300 print:text-blue-700 font-bold">{report.geoLocationAnalysis.primaryNode.ip}</code>
                  </div>
                  <div>
                    <span className="text-slate-500 block">Location:</span>
                    <span className="text-white print:text-black">{report.geoLocationAnalysis.primaryNode.city}, {report.geoLocationAnalysis.primaryNode.country}</span>
                  </div>
                  <div>
                    <span className="text-slate-500 block">Autonomous System (ASN):</span>
                    <span className="text-slate-200 print:text-black">{report.geoLocationAnalysis.primaryNode.asn} ({report.geoLocationAnalysis.primaryNode.asnOrg})</span>
                  </div>
                  <div>
                    <span className="text-slate-500 block">Network Type / Proxy Status:</span>
                    <span className={report.geoLocationAnalysis.primaryNode.isProxyOrVpn ? 'text-amber-400 font-bold' : 'text-slate-200'}>
                      {report.geoLocationAnalysis.primaryNode.networkType} {report.geoLocationAnalysis.primaryNode.isProxyOrVpn && '(ANONYMIZED)'}
                    </span>
                  </div>
                </div>
              ) : (
                <p className="text-slate-400">Direct or internal network origin. No public routing node identified.</p>
              )}

              <div className="pt-2 border-t border-slate-800/80 text-[10px] text-slate-500 print:text-gray-600">
                {report.geoLocationAnalysis?.disclaimer || GEO_LEGAL_DISCLAIMER}
              </div>
            </div>
          </div>
        )}

        {/* Section 8: Multi-Factor Evidence Fusion Breakdown */}
        {(activeTab === 'full-dossier') && (
          <div className="space-y-3">
            <h3 className="text-sm font-bold text-white print:text-black border-b border-slate-800 print:border-gray-300 pb-1 flex items-center justify-between">
              <span className="flex items-center gap-2">
                <span className="text-cyan-400 print:text-blue-700">8.0</span> MULTI-LAYER EVIDENCE FUSION BREAKDOWN
              </span>
              <span className="text-xs font-bold text-cyan-300">Composite: {score}/100 Pts</span>
            </h3>

            <div className="overflow-x-auto rounded-xl border border-slate-800 print:border-gray-300">
              <table className="w-full text-left text-[11px]">
                <thead className="bg-[#060a14] print:bg-gray-100 text-[10px] text-slate-400 print:text-gray-600 uppercase">
                  <tr>
                    <th className="p-2.5">Layer</th>
                    <th className="p-2.5">Mechanism</th>
                    <th className="p-2.5">Severity</th>
                    <th className="p-2.5">Points</th>
                    <th className="p-2.5">Verified Evidence</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/80 print:divide-gray-200">
                  {report.evidenceFusion?.factors?.map((f, idx) => (
                    <tr key={idx} className="hover:bg-slate-900/40 print:hover:bg-transparent">
                      <td className="p-2.5 font-bold text-white print:text-black">{f.category}</td>
                      <td className="p-2.5 text-slate-300 print:text-gray-800">{f.name}</td>
                      <td className="p-2.5">
                        <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                          f.severity === 'CRITICAL' ? 'bg-red-950/80 text-red-400' : f.severity === 'HIGH' ? 'bg-amber-950/80 text-amber-400' : 'bg-blue-950/80 text-blue-400'
                        }`}>
                          {f.severity}
                        </span>
                      </td>
                      <td className="p-2.5 font-mono text-cyan-300 font-bold">+{f.points}/{f.maxPoints}</td>
                      <td className="p-2.5 text-slate-400 print:text-gray-600 text-[10px]">{f.evidence}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        )}

        {/* Section 9: Advisory Action Plan & Timeline */}
        {(activeTab === 'full-dossier' || activeTab === 'timeline-actions') && (
          <div className="space-y-4">
            <h3 className="text-sm font-bold text-white print:text-black border-b border-slate-800 print:border-gray-300 pb-1 flex items-center gap-2">
              <span className="text-cyan-400 print:text-blue-700">9.0</span> PRIORITIZED INCIDENT RESPONSE & ADVISORY ACTION PLAN
            </h3>

            <div className="space-y-2 font-sans">
              {report.recommendations?.map(rec => (
                <div key={rec.id} className="p-3 rounded-xl bg-[#060a14] print:bg-gray-50 border border-slate-800 print:border-gray-300 text-xs">
                  <div className="flex items-center justify-between font-mono font-bold">
                    <span className="text-white print:text-black">{rec.id}. {rec.action}</span>
                    <span className={`text-[10px] px-2 py-0.5 rounded font-bold ${
                      rec.priority === 'CRITICAL' ? 'bg-red-950/80 text-red-400' : rec.priority === 'HIGH' ? 'bg-amber-950/80 text-amber-400' : rec.priority === 'COMPLIANCE' ? 'bg-blue-950/80 text-blue-400' : 'bg-slate-800 text-slate-300'
                    }`}>
                      {rec.priority}
                    </span>
                  </div>
                  <p className="text-[11px] text-slate-400 print:text-gray-700 mt-1">
                    {rec.rationale}
                  </p>
                </div>
              ))}
            </div>

            {/* Analysis Timeline */}
            <div className="pt-2">
              <span className="text-xs font-bold text-slate-400 uppercase block mb-2 font-mono">
                Investigation Pipeline Execution Stages:
              </span>
              <div className="grid grid-cols-2 sm:grid-cols-4 gap-2">
                {report.investigationTimeline?.map(step => (
                  <div key={step.step} className="p-2 rounded-lg bg-[#060a14] border border-slate-800 text-[10px] font-mono">
                    <span className="text-cyan-400 block font-bold">Step {step.step}</span>
                    <span className="text-slate-200 block truncate">{step.action}</span>
                    <span className="text-emerald-400 font-bold text-[9px]">{step.status}</span>
                  </div>
                ))}
              </div>
            </div>
          </div>
        )}

        {/* Section 10: Cryptographic Chain-of-Custody Integrity Certificate */}
        <div className="p-5 rounded-2xl bg-gradient-to-r from-[#0d162a] via-[#091122] to-[#060a14] border border-cyan-500/40 text-[11px] space-y-3 print:bg-white print:border-gray-400">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-slate-800 print:border-gray-300 pb-2">
            <div className="flex items-center gap-2 text-cyan-400 print:text-blue-800 font-bold">
              <Lock className="w-4 h-4" />
              <span>STATUTORY CHAIN-OF-CUSTODY & CRYPTOGRAPHIC INTEGRITY CERTIFICATE</span>
            </div>
            <span className="text-[10px] text-emerald-400 font-mono font-bold">
              CERT-IN & IT ACT SECTION 65B COMPLIANT
            </span>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 text-[11px]">
            <div>
              <span className="text-slate-500 block">Case Reference:</span>
              <span className="text-white font-mono font-bold">{report.caseId}</span>
            </div>
            <div>
              <span className="text-slate-500 block">Audited Standard:</span>
              <span className="text-slate-200">Smart India Hackathon 2026 Forensic Protocol</span>
            </div>
            <div className="sm:col-span-2">
              <span className="text-slate-500 block">Canonical Content SHA-256 Digest:</span>
              <code className="text-cyan-300 print:text-blue-800 font-mono text-[10.5px] break-all block bg-slate-950/80 print:bg-gray-100 p-1.5 rounded border border-slate-800">
                {contentHash}
              </code>
            </div>
            {pdfHash && (
              <div className="sm:col-span-2">
                <span className="text-slate-500 block">Certified PDF File SHA-256 Digest:</span>
                <code className="text-emerald-400 font-mono text-[10.5px] break-all block bg-slate-950/80 print:bg-gray-100 p-1.5 rounded border border-slate-800">
                  {pdfHash}
                </code>
              </div>
            )}
          </div>

          <p className="text-[10px] text-slate-400 print:text-gray-600 font-sans italic pt-1 border-t border-slate-800/80">
            * This digital record is generated deterministically from observed email headers, DNS records, static payload inspection, and trained natural language models. All hashes are verifiable against original raw MIME artifacts.
          </p>
        </div>

      </div>

    </div>
  );
};
