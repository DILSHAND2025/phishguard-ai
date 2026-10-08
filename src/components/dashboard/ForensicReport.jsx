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
      <div className="rounded-xl bg-white border border-slate-200 p-12 text-center font-sans shadow-xs">
        <RefreshCw className="w-8 h-8 text-slate-700 animate-spin mx-auto mb-3" />
        <p className="text-slate-900 text-sm font-bold">Compiling Forensic Evidence Ledger...</p>
        <p className="text-slate-500 text-xs mt-1">Calibrating multi-layer threat scores and computing SHA-256 hash...</p>
      </div>
    );
  }

  if (!report) {
    return (
      <div className="rounded-xl bg-white border border-red-200 p-12 text-center font-sans shadow-xs">
        <AlertTriangle className="w-8 h-8 text-red-500 mx-auto mb-3" />
        <p className="text-slate-900 text-sm font-bold">Forensic Report Compilation Unavailable</p>
        <p className="text-slate-500 text-xs mt-1">No valid analysis results found in memory.</p>
      </div>
    );
  }

  const score = report.threatAssessment?.overallScore ?? 0;
  const risk = (report.threatAssessment?.classification || 'LOW').toUpperCase();
  const contentHash = report.evidenceIntegrity?.contentHashSha256 || '';

  const getRiskBadgeColor = (lvl) => {
    if (lvl === 'CRITICAL') return 'bg-red-50 border-red-200 text-red-700';
    if (lvl === 'HIGH') return 'bg-orange-50 border-orange-200 text-orange-700';
    if (lvl === 'SUSPICIOUS' || lvl === 'MEDIUM') return 'bg-amber-50 border-amber-200 text-amber-800';
    return 'bg-emerald-50 border-emerald-200 text-emerald-700';
  };

  return (
    <div className="space-y-6 pb-12 font-sans text-slate-900">
      
      {/* Top Action Control Banner (Hidden in Print) */}
      <div className="rounded-xl bg-white border border-slate-200 p-6 shadow-xs print:hidden">
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4">
          <div>
            <div className="text-xs font-semibold uppercase tracking-wider text-slate-500 mb-1">
              Automated Forensic Reporting & Evidence Integrity
            </div>
            <h1 className="text-xl sm:text-2xl font-bold text-slate-900 flex items-center gap-2.5">
              <FileText className="w-6 h-6 text-slate-700" />
              <span>Forensic Incident Dossier: {report.caseId}</span>
            </h1>
            <p className="text-xs text-slate-500 mt-1">
              Tamper-evident forensic report with SHA-256 integrity verification to support evidence preservation and investigation.
            </p>
          </div>

          <div className="flex flex-wrap items-center gap-2 text-xs">
            {onViewChange && (
              <button
                type="button"
                id="btn-report-back-case"
                onClick={() => onViewChange('security-analyzer')}
                className="flex items-center gap-1.5 px-3 py-2 rounded-lg bg-white hover:bg-slate-50 border border-slate-200 text-slate-700 transition-colors shadow-2xs cursor-pointer font-medium"
              >
                <ArrowLeft className="w-3.5 h-3.5 text-slate-500" />
                <span>Back to Investigation</span>
              </button>
            )}

            <button
              type="button"
              id="btn-copy-report-hash"
              onClick={handleCopyHash}
              className="flex items-center gap-1.5 px-3 py-2 rounded-lg bg-white hover:bg-slate-50 border border-slate-200 text-slate-700 transition-colors shadow-2xs cursor-pointer font-medium"
              title={contentHash}
            >
              {copiedHash ? <Check className="w-3.5 h-3.5 text-emerald-600" /> : <Hash className="w-3.5 h-3.5 text-slate-500" />}
              <span>{copiedHash ? 'Hash Copied!' : 'Copy SHA-256'}</span>
            </button>

            <button
              type="button"
              id="btn-export-report-json"
              onClick={handleCopyJson}
              className="flex items-center gap-1.5 px-3 py-2 rounded-lg bg-white hover:bg-slate-50 border border-slate-200 text-slate-700 transition-colors shadow-2xs cursor-pointer font-medium"
            >
              {copiedJson ? <Check className="w-3.5 h-3.5 text-emerald-600" /> : <Copy className="w-3.5 h-3.5 text-slate-500" />}
              <span>{copiedJson ? 'JSON Copied!' : 'Export JSON'}</span>
            </button>

            <button
              type="button"
              id="btn-print-report"
              onClick={() => window.print()}
              className="flex items-center gap-1.5 px-3 py-2 rounded-lg bg-white hover:bg-slate-50 border border-slate-200 text-slate-700 transition-colors shadow-2xs cursor-pointer font-medium"
            >
              <Printer className="w-3.5 h-3.5 text-slate-500" />
              <span>Print</span>
            </button>

            <button
              type="button"
              id="btn-export-certified-pdf"
              onClick={handleExportPdf}
              disabled={pdfExporting}
              className="flex items-center gap-2 px-4 py-2 rounded-lg bg-slate-900 hover:bg-slate-800 text-white font-semibold shadow-xs transition-colors cursor-pointer disabled:opacity-50"
            >
              {pdfExporting ? (
                <>
                  <RefreshCw className="w-4 h-4 animate-spin" />
                  <span>Generating PDF...</span>
                </>
              ) : (
                <>
                  <Download className="w-4 h-4" />
                  <span>Export PDF</span>
                </>
              )}
            </button>
          </div>
        </div>

        {/* Tab Navigation (Hidden in Print) */}
        <div className="flex flex-wrap items-center gap-2 mt-5 pt-4 border-t border-slate-100 text-xs">
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
              className={`px-3.5 py-1.5 rounded-lg border transition-all cursor-pointer font-semibold ${
                activeTab === tab.id
                  ? 'bg-slate-900 border-slate-900 text-white shadow-2xs'
                  : 'bg-white border-slate-200 text-slate-600 hover:text-slate-900'
              }`}
            >
              {tab.label}
            </button>
          ))}
          {pdfHash && (
            <div className="ml-auto text-[11px] text-emerald-700 font-mono flex items-center gap-1.5">
              <CheckCircle className="w-3.5 h-3.5 text-emerald-600" />
              <span>PDF Hash: {pdfHash.slice(0, 16)}...</span>
            </div>
          )}
        </div>
      </div>

      {/* Main Dossier Paper / Canvas */}
      <div className="max-w-5xl mx-auto rounded-xl bg-white border border-slate-200 p-6 sm:p-10 shadow-xs space-y-8 font-sans text-xs text-slate-700 print:p-0 print:border-none print:shadow-none">
        
        {/* Document Header */}
        <div className="border-b-2 border-slate-200 pb-6 flex flex-col sm:flex-row sm:items-center justify-between gap-4">
          <div>
            <div className="text-xs font-bold uppercase tracking-wider text-slate-500 flex items-center gap-2">
              <ShieldCheck className="w-4 h-4 text-slate-700" />
              <span>CYBERSECURITY INCIDENT DOSSIER</span>
            </div>
            <h2 className="text-2xl font-black text-slate-900 mt-1 tracking-tight">
              CASE: {report.caseId}
            </h2>
            <div className="text-xs text-slate-600 mt-1 font-medium">
              Classification: <span className="text-slate-900 font-bold">{report.classification}</span>
            </div>
          </div>

          <div className="sm:text-right text-xs text-slate-500 space-y-1">
            <div>Audit Timestamp: <strong className="text-slate-700">{new Date(report.generatedAt).toUTCString()}</strong></div>
            <div>Investigator Engine: <strong className="text-slate-700">MAVERICK v4.2</strong></div>
            <div className="flex sm:justify-end items-center gap-1">
              <span>SHA-256 Digest:</span>
              <code className="text-slate-900 font-bold bg-slate-100 px-1.5 py-0.5 rounded text-[11px] font-mono border border-slate-200">
                {contentHash ? `${contentHash.slice(0, 12)}...${contentHash.slice(-8)}` : 'COMPUTING'}
              </code>
            </div>
          </div>
        </div>

        {/* Section 1: Executive Threat Assessment */}
        <div className="space-y-4">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-slate-100 pb-2">
            <h3 className="text-sm font-bold text-slate-900 flex items-center gap-2">
              <span>1.0</span> EXECUTIVE THREAT ASSESSMENT & CALIBRATION
            </h3>
            <span className={`px-3 py-1 rounded-lg border font-bold text-xs ${getRiskBadgeColor(risk)}`}>
              VERDICT: {risk} RISK ({score}/100)
            </span>
          </div>

          {/* Quick Score Metrics Cards */}
          <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
            <div className="p-4 rounded-xl bg-slate-50 border border-slate-200">
              <span className="text-slate-500 text-[10px] uppercase font-bold block">Threat Score</span>
              <div className="flex items-baseline gap-1 mt-1">
                <span className="text-3xl font-black text-slate-900">{score}</span>
                <span className="text-xs text-slate-400">/ 100</span>
              </div>
              <span className="text-[11px] text-slate-500 block mt-1">Weighted multi-layer fusion</span>
            </div>

            <div className="p-4 rounded-xl bg-slate-50 border border-slate-200">
              <span className="text-slate-500 text-[10px] uppercase font-bold block">AI Phishing Probability</span>
              <div className="flex items-baseline gap-1 mt-1">
                <span className="text-3xl font-black text-slate-900">
                  {report.mlAnalysis?.phishingProbability != null ? `${report.mlAnalysis.phishingProbability}%` : 'N/A'}
                </span>
              </div>
              <span className="text-[11px] text-slate-500 block mt-1">Natural language ML classifier</span>
            </div>

            <div className="p-4 rounded-xl bg-slate-50 border border-slate-200">
              <span className="text-slate-500 text-[10px] uppercase font-bold block">Email Authentication</span>
              <div className="text-xs font-bold text-slate-900 mt-2">
                SPF: <span className={report.emailAuthentication?.spf?.status.includes('PASS') ? 'text-emerald-700' : 'text-red-700'}>{report.emailAuthentication?.spf?.status || 'N/A'}</span>
                {' | '}
                DKIM: <span className={report.emailAuthentication?.dkim?.status.includes('PASS') ? 'text-emerald-700' : 'text-red-700'}>{report.emailAuthentication?.dkim?.status || 'N/A'}</span>
              </div>
              <span className="text-[11px] text-slate-500 block mt-1">
                Alignment: {report.emailAuthentication?.alignment?.dmarcAligned ? 'ALIGNED' : 'MISALIGNED (Spoof Risk)'}
              </span>
            </div>
          </div>

          {/* Executive Summary Narrative */}
          <div className="p-4 rounded-xl bg-slate-50 border border-slate-200">
            <span className="text-xs font-bold text-slate-900 uppercase block mb-1.5">
              Executive Summary:
            </span>
            <p className="text-slate-700 text-xs leading-relaxed">
              {report.executiveSummary}
            </p>
          </div>
        </div>

        {/* Section 2: Ingress MIME Envelope & Header Forensics */}
        {(activeTab === 'full-dossier' || activeTab === 'authentication') && (
          <div className="space-y-3">
            <h3 className="text-sm font-bold text-slate-900 border-b border-slate-100 pb-1 flex items-center gap-2">
              <span>2.0</span> INGRESS EMAIL ENVELOPE & HEADER TELEMETRY
            </h3>
            
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 p-4 rounded-xl bg-slate-50 border border-slate-200 text-xs">
              <div>
                <span className="text-slate-500 block">Sender Header (From):</span>
                <span className="text-slate-900 font-semibold break-all">{report.emailMetadata?.sender}</span>
              </div>
              <div>
                <span className="text-slate-500 block">Recipient (To):</span>
                <span className="text-slate-900 font-semibold break-all">{report.emailMetadata?.recipient}</span>
              </div>
              <div>
                <span className="text-slate-500 block">Subject Line:</span>
                <span className="text-slate-900 font-medium">{report.emailMetadata?.subject}</span>
              </div>
              <div>
                <span className="text-slate-500 block">RFC 822 Date:</span>
                <span className="text-slate-700">{report.emailMetadata?.date}</span>
              </div>
              <div>
                <span className="text-slate-500 block">Return-Path:</span>
                <span className="text-slate-700 font-mono text-[11px]">{report.emailMetadata?.returnPath || 'None'}</span>
              </div>
              <div>
                <span className="text-slate-500 block">Reply-To Routing:</span>
                <span className={report.emailMetadata?.replyToMismatch ? 'text-amber-700 font-bold' : 'text-slate-700'}>
                  {report.emailMetadata?.replyTo || 'Same as sender'} {report.emailMetadata?.replyToMismatch && '(MISMATCH)'}
                </span>
              </div>
              <div>
                <span className="text-slate-500 block">Originating Hop IP:</span>
                <code className="text-slate-900 font-mono font-bold">{report.emailMetadata?.originatingIP}</code>
              </div>
              <div>
                <span className="text-slate-500 block">Message-ID:</span>
                <code className="text-slate-600 font-mono text-[10px] break-all">{report.emailMetadata?.messageId}</code>
              </div>
            </div>
          </div>
        )}

        {/* Section 3: Live Email Authentication & Domain Alignment */}
        {(activeTab === 'full-dossier' || activeTab === 'authentication') && (
          <div className="space-y-3">
            <h3 className="text-sm font-bold text-slate-900 border-b border-slate-100 pb-1 flex items-center justify-between">
              <span>3.0 EMAIL AUTHENTICATION & DNS FORENSICS</span>
              <span className="text-xs text-slate-500">RFC 7208 / RFC 6376 / RFC 7489</span>
            </h3>

            <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
              {/* SPF Card */}
              <div className="p-4 rounded-xl bg-slate-50 border border-slate-200">
                <div className="flex items-center justify-between">
                  <span className="font-bold text-slate-900 text-xs">SPF (RFC 7208)</span>
                  <span className={`px-2 py-0.5 rounded text-[10px] font-bold border ${
                    report.emailAuthentication?.spf?.status.includes('PASS') ? 'bg-emerald-50 text-emerald-700 border-emerald-200' : 'bg-red-50 text-red-700 border-red-200'
                  }`}>
                    {report.emailAuthentication?.spf?.status}
                  </span>
                </div>
                <div className="mt-2 text-xs text-slate-600 space-y-1">
                  <div>Domain: <code className="text-slate-900 font-semibold">{report.emailAuthentication?.spf?.domain}</code></div>
                  {report.emailAuthentication?.spf?.hasPlusAll && (
                    <div className="text-red-700 font-bold">Wildcard +all detected!</div>
                  )}
                  <div className="text-slate-500 truncate" title={report.emailAuthentication?.spf?.record}>
                    DNS: {report.emailAuthentication?.spf?.record || 'None'}
                  </div>
                </div>
              </div>

              {/* DKIM Card */}
              <div className="p-4 rounded-xl bg-slate-50 border border-slate-200">
                <div className="flex items-center justify-between">
                  <span className="font-bold text-slate-900 text-xs">DKIM (RFC 6376)</span>
                  <span className={`px-2 py-0.5 rounded text-[10px] font-bold border ${
                    report.emailAuthentication?.dkim?.status.includes('PASS') ? 'bg-emerald-50 text-emerald-700 border-emerald-200' : 'bg-red-50 text-red-700 border-red-200'
                  }`}>
                    {report.emailAuthentication?.dkim?.status}
                  </span>
                </div>
                <div className="mt-2 text-xs text-slate-600 space-y-1">
                  <div>Signing Domain: <code className="text-slate-900 font-semibold">{report.emailAuthentication?.dkim?.domain}</code></div>
                  <div>Selector: <code className="text-slate-900">{report.emailAuthentication?.dkim?.selector}</code></div>
                  <div>Public Key: <span className={report.emailAuthentication?.dkim?.dnsRecordFound ? 'text-emerald-700 font-semibold' : 'text-slate-500'}>{report.emailAuthentication?.dkim?.dnsRecordFound ? 'VERIFIED' : 'NOT FOUND'}</span></div>
                </div>
              </div>

              {/* DMARC Card */}
              <div className="p-4 rounded-xl bg-slate-50 border border-slate-200">
                <div className="flex items-center justify-between">
                  <span className="font-bold text-slate-900 text-xs">DMARC (RFC 7489)</span>
                  <span className={`px-2 py-0.5 rounded text-[10px] font-bold border ${
                    report.emailAuthentication?.dmarc?.policy === 'reject' ? 'bg-emerald-50 text-emerald-700 border-emerald-200' : 'bg-amber-50 text-amber-800 border-amber-200'
                  }`}>
                    p={report.emailAuthentication?.dmarc?.policy}
                  </span>
                </div>
                <div className="mt-2 text-xs text-slate-600 space-y-1">
                  <div>Domain: <code className="text-slate-900 font-semibold">{report.emailAuthentication?.dmarc?.domain}</code></div>
                  <div>Subdomain Policy: <code className="text-slate-900">{report.emailAuthentication?.dmarc?.subdomainPolicy}</code></div>
                  <div>Alignment Verdict: <span className={report.emailAuthentication?.alignment?.dmarcAligned ? 'text-emerald-700 font-bold' : 'text-red-700 font-bold'}>{report.emailAuthentication?.alignment?.dmarcAligned ? 'ALIGNED' : 'FAIL'}</span></div>
                </div>
              </div>
            </div>
          </div>
        )}

        {/* Section 4: Strict Separation: Observed Evidence vs Inferred Intelligence */}
        {(activeTab === 'full-dossier' || activeTab === 'observed-inferred') && (
          <div className="space-y-3">
            <h3 className="text-sm font-bold text-slate-900 border-b border-slate-100 pb-1 flex items-center justify-between">
              <span>4.0 EVIDENCE PARTITIONING: OBSERVED EVIDENCE vs INFERRED INTELLIGENCE</span>
              <span className="text-[10px] text-slate-500 uppercase font-semibold">Evidence Standard</span>
            </h3>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              {/* Left: Observed Evidence */}
              <div className="p-4 rounded-xl bg-slate-50 border border-slate-200 space-y-2">
                <div className="flex items-center gap-2 text-slate-900 font-bold text-xs">
                  <FileCheck className="w-4 h-4 text-slate-600" />
                  <span>OBSERVED EMPIRICAL EVIDENCE (FACTS)</span>
                </div>
                <p className="text-[11px] text-slate-500">
                  Directly extracted from raw headers, DNS queries, and attachment headers.
                </p>
                <ul className="space-y-1.5 pt-1 text-xs">
                  {report.observedEvidence?.map((item, idx) => (
                    <li key={idx} className="flex items-start gap-1.5 text-slate-700">
                      <span className="text-cyan-600 font-bold">•</span>
                      <span className="break-all">{item}</span>
                    </li>
                  ))}
                </ul>
              </div>

              {/* Right: Inferred Intelligence */}
              <div className="p-4 rounded-xl bg-slate-50 border border-slate-200 space-y-2">
                <div className="flex items-center gap-2 text-slate-900 font-bold text-xs">
                  <Cpu className="w-4 h-4 text-slate-600" />
                  <span>INFERRED INTELLIGENCE (ANALYTICAL / AI)</span>
                </div>
                <p className="text-[11px] text-slate-500">
                  Statistical predictions, ML classification probabilities, domain alignment deductions, and threat models.
                </p>
                <ul className="space-y-1.5 pt-1 text-xs">
                  {report.inferredIntelligence?.map((item, idx) => (
                    <li key={idx} className="flex items-start gap-1.5 text-slate-700">
                      <span className="text-amber-600 font-bold">›</span>
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
            <h3 className="text-sm font-bold text-slate-900 border-b border-slate-100 pb-1 flex items-center justify-between">
              <span>5.0 EXTRACTED INDICATORS OF COMPROMISE (IOCs)</span>
              <span className="text-xs text-slate-500">{report.iocAnalysis?.length || 0} Indicators</span>
            </h3>

            <div className="overflow-x-auto rounded-xl border border-slate-200">
              <table className="w-full text-left text-xs">
                <thead className="bg-slate-50 text-[10px] text-slate-500 uppercase font-semibold">
                  <tr>
                    <th className="p-2.5">Type</th>
                    <th className="p-2.5">Indicator Value</th>
                    <th className="p-2.5">Ingress Source</th>
                    <th className="p-2.5">Risk Status</th>
                    <th className="p-2.5">Confidence</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-100">
                  {(report.iocAnalysis || []).length === 0 ? (
                    <tr>
                      <td colSpan={5} className="p-3 text-center text-slate-500">No external IOCs extracted.</td>
                    </tr>
                  ) : (
                    report.iocAnalysis.map((ioc, idx) => (
                      <tr key={idx} className="hover:bg-slate-50">
                        <td className="p-2.5 font-bold text-slate-900">[{ioc.type}]</td>
                        <td className="p-2.5 text-slate-900 font-mono break-all">{ioc.value}</td>
                        <td className="p-2.5 text-slate-600">{ioc.source}</td>
                        <td className="p-2.5">
                          <span className={`px-2 py-0.5 rounded text-[10px] font-bold border ${
                            ioc.risk === 'MALICIOUS' ? 'bg-red-50 text-red-700 border-red-200' : 'bg-amber-50 text-amber-800 border-amber-200'
                          }`}>
                            {ioc.risk}
                          </span>
                        </td>
                        <td className="p-2.5 text-slate-700">{ioc.confidence}%</td>
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
            <h3 className="text-sm font-bold text-slate-900 border-b border-slate-100 pb-1 flex items-center justify-between">
              <span>6.0 STATIC ATTACHMENT FORENSICS</span>
              <span className="text-[10px] text-emerald-700 font-semibold">Zero Execution Sandbox</span>
            </h3>

            <div className="overflow-x-auto rounded-xl border border-slate-200">
              <table className="w-full text-left text-xs">
                <thead className="bg-slate-50 text-[10px] text-slate-500 uppercase font-semibold">
                  <tr>
                    <th className="p-2.5">Filename</th>
                    <th className="p-2.5">Magic Bytes</th>
                    <th className="p-2.5">Extension Mismatch</th>
                    <th className="p-2.5">Risk Assessment</th>
                    <th className="p-2.5">SHA-256 Digest</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-100">
                  {(report.attachmentAnalysis?.attachments || []).length === 0 ? (
                    <tr>
                      <td colSpan={5} className="p-3 text-center text-slate-500">No payload attachments detected.</td>
                    </tr>
                  ) : (
                    report.attachmentAnalysis.attachments.map((att, idx) => (
                      <tr key={idx} className="hover:bg-slate-50">
                        <td className="p-2.5 font-bold text-slate-900">
                          {att.filename}
                          <span className="block text-[10px] text-slate-500 font-normal">{att.size} | {att.declaredMime}</span>
                        </td>
                        <td className="p-2.5 font-mono text-slate-700">{att.magicBytes}</td>
                        <td className="p-2.5">
                          {att.extensionMismatch ? (
                            <span className="text-red-700 font-bold">YES (SPOOFED)</span>
                          ) : (
                            <span className="text-emerald-700 font-medium">NO</span>
                          )}
                        </td>
                        <td className="p-2.5">
                          <span className={`px-2 py-0.5 rounded text-[10px] font-bold border ${
                            att.riskAssessment === 'CRITICAL' || att.riskAssessment === 'MALICIOUS' ? 'bg-red-50 text-red-700 border-red-200' : 'bg-emerald-50 text-emerald-700 border-emerald-200'
                          }`}>
                            {att.riskAssessment}
                          </span>
                        </td>
                        <td className="p-2.5 font-mono text-slate-700 text-[10px] break-all">
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
            <h3 className="text-sm font-bold text-slate-900 border-b border-slate-100 pb-1 flex items-center gap-2">
              <span>7.0 NETWORK INFRASTRUCTURE & AUTONOMOUS SYSTEM INTELLIGENCE</span>
            </h3>

            <div className="p-4 rounded-xl bg-slate-50 border border-slate-200 space-y-2 text-xs">
              {report.geoLocationAnalysis?.primaryNode ? (
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                  <div>
                    <span className="text-slate-500 block">Originating IP:</span>
                    <code className="text-slate-900 font-mono font-bold">{report.geoLocationAnalysis.primaryNode.ip}</code>
                  </div>
                  <div>
                    <span className="text-slate-500 block">Location:</span>
                    <span className="text-slate-900 font-medium">{report.geoLocationAnalysis.primaryNode.city}, {report.geoLocationAnalysis.primaryNode.country}</span>
                  </div>
                  <div>
                    <span className="text-slate-500 block">Autonomous System (ASN):</span>
                    <span className="text-slate-700">{report.geoLocationAnalysis.primaryNode.asn} ({report.geoLocationAnalysis.primaryNode.asnOrg})</span>
                  </div>
                  <div>
                    <span className="text-slate-500 block">Network Type / Proxy Status:</span>
                    <span className={report.geoLocationAnalysis.primaryNode.isProxyOrVpn ? 'text-amber-700 font-bold' : 'text-slate-700'}>
                      {report.geoLocationAnalysis.primaryNode.networkType} {report.geoLocationAnalysis.primaryNode.isProxyOrVpn && '(ANONYMIZED)'}
                    </span>
                  </div>
                </div>
              ) : (
                <p className="text-slate-500">Direct or internal network origin. No public routing node identified.</p>
              )}

              <div className="pt-2 border-t border-slate-200 text-[11px] text-slate-500">
                {report.geoLocationAnalysis?.disclaimer || GEO_LEGAL_DISCLAIMER}
              </div>
            </div>
          </div>
        )}

        {/* Section 8: Multi-Factor Evidence Fusion Breakdown */}
        {(activeTab === 'full-dossier') && (
          <div className="space-y-3">
            <h3 className="text-sm font-bold text-slate-900 border-b border-slate-100 pb-1 flex items-center justify-between">
              <span>8.0 MULTI-LAYER EVIDENCE FUSION BREAKDOWN</span>
              <span className="text-xs font-bold text-slate-900">Composite: {score}/100 Pts</span>
            </h3>

            <div className="overflow-x-auto rounded-xl border border-slate-200">
              <table className="w-full text-left text-xs">
                <thead className="bg-slate-50 text-[10px] text-slate-500 uppercase font-semibold">
                  <tr>
                    <th className="p-2.5">Layer</th>
                    <th className="p-2.5">Mechanism</th>
                    <th className="p-2.5">Severity</th>
                    <th className="p-2.5">Points</th>
                    <th className="p-2.5">Verified Evidence</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-100">
                  {report.evidenceFusion?.factors?.map((f, idx) => (
                    <tr key={idx} className="hover:bg-slate-50">
                      <td className="p-2.5 font-bold text-slate-900">{f.category}</td>
                      <td className="p-2.5 text-slate-700">{f.name}</td>
                      <td className="p-2.5">
                        <span className={`px-2 py-0.5 rounded text-[10px] font-bold border ${
                          f.severity === 'CRITICAL' ? 'bg-red-50 text-red-700 border-red-200' : f.severity === 'HIGH' ? 'bg-orange-50 text-orange-700 border-orange-200' : 'bg-slate-100 text-slate-700 border-slate-200'
                        }`}>
                          {f.severity}
                        </span>
                      </td>
                      <td className="p-2.5 font-mono font-bold text-slate-900">+{f.points}/{f.maxPoints}</td>
                      <td className="p-2.5 text-slate-600 text-[11px]">{f.evidence}</td>
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
            <h3 className="text-sm font-bold text-slate-900 border-b border-slate-100 pb-1 flex items-center gap-2">
              <span>9.0 PRIORITIZED INCIDENT RESPONSE & ADVISORY ACTION PLAN</span>
            </h3>

            <div className="space-y-2 font-sans">
              {report.recommendations?.map(rec => (
                <div key={rec.id} className="p-3.5 rounded-xl bg-slate-50 border border-slate-200 text-xs">
                  <div className="flex items-center justify-between font-bold">
                    <span className="text-slate-900">{rec.id}. {rec.action}</span>
                    <span className={`text-[10px] px-2 py-0.5 rounded font-bold border ${
                      rec.priority === 'CRITICAL' ? 'bg-red-50 text-red-700 border-red-200' : rec.priority === 'HIGH' ? 'bg-orange-50 text-orange-700 border-orange-200' : 'bg-slate-100 text-slate-700 border-slate-200'
                    }`}>
                      {rec.priority}
                    </span>
                  </div>
                  <p className="text-[11px] text-slate-600 mt-1">
                    {rec.rationale}
                  </p>
                </div>
              ))}
            </div>

            {/* Analysis Timeline */}
            <div className="pt-2">
              <span className="text-xs font-bold text-slate-500 uppercase block mb-2 font-sans">
                Investigation Pipeline Execution Stages:
              </span>
              <div className="grid grid-cols-2 sm:grid-cols-4 gap-2">
                {report.investigationTimeline?.map(step => (
                  <div key={step.step} className="p-2 rounded-lg bg-slate-50 border border-slate-200 text-[11px]">
                    <span className="text-slate-500 block font-semibold">Step {step.step}</span>
                    <span className="text-slate-900 block truncate font-medium">{step.action}</span>
                    <span className="text-emerald-700 font-semibold text-[10px]">{step.status}</span>
                  </div>
                ))}
              </div>
            </div>
          </div>
        )}

        {/* Section 10: Cryptographic Chain-of-Custody Integrity Certificate */}
        <div className="p-5 rounded-xl bg-slate-50 border border-slate-200 text-xs space-y-3">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-slate-200 pb-2">
            <div className="flex items-center gap-2 text-slate-900 font-bold">
              <Lock className="w-4 h-4 text-slate-600" />
              <span>STATUTORY CHAIN-OF-CUSTODY & CRYPTOGRAPHIC INTEGRITY CERTIFICATE</span>
            </div>
            <span className="text-[10px] text-emerald-700 font-semibold">
              EVIDENCE PRESERVATION READY
            </span>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 text-xs">
            <div>
              <span className="text-slate-500 block">Case Reference:</span>
              <span className="text-slate-900 font-mono font-bold">{report.caseId}</span>
            </div>
            <div>
              <span className="text-slate-500 block">Audit Standard:</span>
              <span className="text-slate-700">Forensic Integrity Specification</span>
            </div>
            <div className="sm:col-span-2">
              <span className="text-slate-500 block">Canonical Content SHA-256 Digest:</span>
              <code className="text-slate-900 font-mono text-[11px] break-all block bg-white p-2 rounded border border-slate-200 font-semibold">
                {contentHash}
              </code>
            </div>
            {pdfHash && (
              <div className="sm:col-span-2">
                <span className="text-slate-500 block">Certified PDF File SHA-256 Digest:</span>
                <code className="text-slate-900 font-mono text-[11px] break-all block bg-white p-2 rounded border border-slate-200 font-semibold">
                  {pdfHash}
                </code>
              </div>
            )}
          </div>

          <p className="text-[11px] text-slate-500 italic pt-1 border-t border-slate-200">
            * This digital record is generated deterministically from observed email headers, DNS records, static payload inspection, and trained natural language models. All hashes are verifiable against original raw MIME artifacts.
          </p>
        </div>

      </div>

    </div>
  );
};
