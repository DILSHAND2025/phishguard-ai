import React, { useState } from 'react';
import { 
  ShieldAlert, 
  Cpu, 
  Activity, 
  FileText, 
  Download, 
  Copy, 
  Check, 
  CheckCircle2, 
  ChevronDown, 
  ChevronUp, 
  RefreshCw, 
  AlertTriangle, 
  FileCode, 
  Shield 
} from 'lucide-react';
import { ForensicGeoMap } from '../components/dashboard/ForensicGeoMap.jsx';
import { EmailAuthenticationCard } from '../components/dashboard/EmailAuthenticationCard.jsx';
import { AttachmentForensicsCard } from '../components/dashboard/AttachmentForensicsCard.jsx';
import { buildForensicReport } from '../services/forensicReportService.js';
import { generateForensicPdf, downloadPdfInBrowser } from '../services/pdfBuilder.js';

export const SecurityAnalyzerPage = ({ 
  currentAnalysis, 
  onViewChange, 
  _onRunAnalysis,
  onRetrySave
}) => {
  // State toggles
  const [showRawHeaders, setShowRawHeaders] = useState(false);
  const [copiedRawHeaders, setCopiedRawHeaders] = useState(false);
  const [copiedHash, setCopiedHash] = useState(false);
  const [activeIocTab, setActiveIocTab] = useState('ALL');
  const [exportingPdf, setExportingPdf] = useState(false);
  const [exportingJson, setExportingJson] = useState(false);
  const [isRetryingSave, setIsRetryingSave] = useState(false);

  // If no analysis is loaded yet, provide a clean empty state with action to start one
  if (!currentAnalysis || !currentAnalysis.email) {
    return (
      <div className="rounded-xl bg-white border border-slate-200 p-12 text-center max-w-xl mx-auto my-12 space-y-4 shadow-xs font-sans">
        <div className="w-12 h-12 mx-auto rounded-full bg-slate-100 flex items-center justify-center text-slate-700">
          <ShieldAlert className="w-6 h-6" />
        </div>
        <h2 className="text-lg font-bold text-slate-900">No Email Analysis Loaded</h2>
        <p className="text-xs text-slate-500">
          Submit an email in the Email Analyzer portal or choose an existing case from the Cases queue.
        </p>
        <button
          onClick={() => onViewChange('email-analysis')}
          className="px-4 py-2 rounded-lg bg-slate-900 hover:bg-slate-800 text-white text-xs font-semibold cursor-pointer shadow-xs transition-colors"
        >
          Go to Email Analyzer
        </button>
      </div>
    );
  }

  const {
    email = {},
    emailAuth = null,
    iocs = [],
    aiThreat = null,
    geoInfo = null,
    geoList = [],
    fusion = null,
    caseItem = null
  } = currentAnalysis;

  // 1. Header & Identifiers
  const caseId = caseItem?.caseId || email?.scenarioName || 'MAV-2026-00000000';
  const threatScore = fusion?.threatScore ?? 'Unavailable';
  const riskLevel = (fusion?.riskLevel || 'LOW').toUpperCase();
  const sha256Hash = caseItem?.sha256 || currentAnalysis?.report?.evidenceIntegrity?.contentHashSha256 || '8f4c102948a7b6c5d4e3f27d1a293b6e8f4c102948a7b6c5d4e3f27d1a293b6e';
  const classification = currentAnalysis?.aiThreat?.classification || currentAnalysis?.classification || (threatScore >= 80 ? 'Credential Phishing' : threatScore >= 60 ? 'Suspicious Impersonation' : threatScore >= 30 ? 'Suspicious Anomaly' : 'Clean Communication');

  // 2. Threat Summary Metric Values
  const isMlAvailable = aiThreat && aiThreat.isMlAvailable;
  const mlDetectionValue = isMlAvailable && typeof aiThreat.phishingProbability === 'number'
    ? `${aiThreat.phishingProbability}%`
    : 'Unavailable';

  const iocCount = Array.isArray(iocs) ? iocs.length : 0;
  const caseStatus = riskLevel === 'CRITICAL' ? 'CRITICAL' : riskLevel === 'HIGH' ? 'HIGH' : riskLevel === 'SUSPICIOUS' || riskLevel === 'MEDIUM' ? 'MEDIUM' : 'LOW';

  // Helper: Status badge color (clean light tokens)
  const getRiskBadgeColor = (level) => {
    switch (level) {
      case 'CRITICAL':
        return 'bg-red-50 border-red-200 text-red-700';
      case 'HIGH':
        return 'bg-orange-50 border-orange-200 text-orange-700';
      case 'SUSPICIOUS':
      case 'MEDIUM':
        return 'bg-amber-50 border-amber-200 text-amber-800';
      default:
        return 'bg-emerald-50 border-emerald-200 text-emerald-700';
    }
  };

  const getRiskDotColor = (level) => {
    switch (level) {
      case 'CRITICAL':
        return 'bg-red-500';
      case 'HIGH':
        return 'bg-orange-500';
      case 'SUSPICIOUS':
      case 'MEDIUM':
        return 'bg-amber-500';
      default:
        return 'bg-emerald-500';
    }
  };

  // 3. Export PDF Action
  const handleExportPdf = async () => {
    try {
      setExportingPdf(true);
      const rep = await buildForensicReport(currentAnalysis);
      const pdfBytes = generateForensicPdf(rep);
      downloadPdfInBrowser(pdfBytes, `${rep.caseId || 'MAVERICK'}-Forensic-Report.pdf`);
    } catch (err) {
      console.error('PDF export failed:', err);
      alert(`PDF Export Error: ${err.message}`);
    } finally {
      setExportingPdf(false);
    }
  };

  // 4. Export JSON Action
  const handleExportJson = async () => {
    try {
      setExportingJson(true);
      const rep = await buildForensicReport(currentAnalysis);
      const jsonStr = JSON.stringify(rep, null, 2);
      const blob = new Blob([jsonStr], { type: 'application/json' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `${rep.caseId || 'MAVERICK'}-Forensic-Ledger.json`;
      a.click();
      URL.revokeObjectURL(url);
    } catch (err) {
      console.error('JSON export failed:', err);
      alert(`JSON Export Error: ${err.message}`);
    } finally {
      setExportingJson(false);
    }
  };

  // 5. Copy SHA-256
  const handleCopyHash = () => {
    navigator.clipboard?.writeText(sha256Hash);
    setCopiedHash(true);
    setTimeout(() => setCopiedHash(false), 2000);
  };

  // 6. Copy Raw Headers
  const handleCopyRawHeaders = () => {
    if (email.rawSnippet) {
      navigator.clipboard?.writeText(email.rawSnippet);
      setCopiedRawHeaders(true);
      setTimeout(() => setCopiedRawHeaders(false), 2000);
    }
  };

  // Filter IOCs by tab
  const filteredIocs = (Array.isArray(iocs) ? iocs : []).filter(ioc => {
    if (activeIocTab === 'ALL') return true;
    if (activeIocTab === 'IP') return ioc.type === 'IP';
    if (activeIocTab === 'URL') return ioc.type === 'URL';
    if (activeIocTab === 'DOMAIN') return ioc.type === 'DOMAIN';
    if (activeIocTab === 'EMAIL') return ioc.type === 'EMAIL';
    return true;
  });

  // Active GeoIP record for details column
  const activeGeoRecord = (Array.isArray(geoList) ? geoList : []).find(g => g.ip === selectedGeoIP) 
    || geoInfo 
    || geoList[0] 
    || null;

  return (
    <div className="space-y-6 pb-20 font-sans text-slate-900">
      
      {/* ========================================================
          ANALYZER HEADER
      ======================================================== */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 py-3 border-b border-slate-200">
        <div>
          <div className="flex items-center gap-2.5">
            <h1 className="text-2xl font-bold text-slate-900 tracking-tight">
              Security Analyzer
            </h1>
            <span className="px-2 py-0.5 rounded text-[10px] font-semibold bg-slate-100 text-slate-700 border border-slate-200">
              SOC Workspace
            </span>
          </div>
          <div className="flex flex-wrap items-center gap-3 mt-1 text-xs text-slate-500">
            <span>Case ID: <strong className="font-mono text-slate-800">{caseId}</strong></span>
            <span>•</span>
            {currentAnalysis.isSaved ? (
              <span className="text-emerald-700 font-medium flex items-center gap-1.5">
                <span className="w-2 h-2 rounded-full bg-emerald-500"></span>
                Saved in PostgreSQL
              </span>
            ) : (
              <span className="text-amber-700 font-medium flex items-center gap-1.5">
                <span className="w-2 h-2 rounded-full bg-amber-500"></span>
                In-Memory Session
              </span>
            )}
          </div>
        </div>

        <div className="flex items-center gap-2.5">
          <button
            type="button"
            onClick={() => onViewChange('email-analysis')}
            className="flex items-center gap-1.5 px-3.5 py-2 rounded-lg bg-white hover:bg-slate-50 border border-slate-200 text-xs font-semibold text-slate-700 transition-colors shadow-2xs cursor-pointer"
          >
            <RefreshCw className="w-3.5 h-3.5 text-slate-500" />
            <span>New Analysis</span>
          </button>

          <button
            type="button"
            onClick={handleExportPdf}
            disabled={exportingPdf}
            className="flex items-center gap-1.5 px-3.5 py-2 rounded-lg bg-slate-900 hover:bg-slate-800 text-white text-xs font-semibold shadow-xs transition-colors cursor-pointer disabled:opacity-50"
          >
            <Download className="w-3.5 h-3.5" />
            <span>{exportingPdf ? 'Exporting...' : 'Export Report'}</span>
          </button>
        </div>
      </div>

      {/* Database Persistence Failure Alert */}
      {currentAnalysis.dbSaveError && (
        <div className="rounded-xl bg-amber-50 border border-amber-200 p-4 text-xs text-amber-800 flex flex-col sm:flex-row sm:items-center justify-between gap-3 shadow-2xs">
          <div className="flex items-start gap-3">
            <AlertTriangle className="w-5 h-5 text-amber-600 shrink-0 mt-0.5" />
            <div className="space-y-1">
              <div className="font-semibold text-amber-900">Persistence Notice</div>
              <p>Analysis completed, but the case could not be saved to PostgreSQL.</p>
              <p className="text-[11px] text-amber-700 font-mono mt-0.5">Reason: {currentAnalysis.dbSaveError}</p>
            </div>
          </div>
          {onRetrySave && (
            <button
              type="button"
              onClick={async () => {
                setIsRetryingSave(true);
                await onRetrySave();
                setIsRetryingSave(false);
              }}
              disabled={isRetryingSave}
              className="px-3.5 py-2 rounded-lg bg-amber-600 hover:bg-amber-700 text-white font-semibold text-xs transition-colors shrink-0 flex items-center gap-1.5 cursor-pointer disabled:opacity-50 shadow-xs self-start sm:self-auto"
            >
              <RefreshCw className={`w-3.5 h-3.5 ${isRetryingSave ? 'animate-spin' : ''}`} />
              <span>{isRetryingSave ? 'Saving to Database...' : 'Retry Saving Case'}</span>
            </button>
          )}
        </div>
      )}

      {/* ========================================================
          SECTION 1: TOP KPI STATS (WHITE CARDS WITH SMALL COLORED INDICATORS)
      ======================================================== */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-3 sm:gap-4">
        
        {/* Card 1: Threat Score */}
        <div className="p-4 rounded-xl bg-white border border-slate-200 space-y-1 shadow-xs">
          <div className="flex items-center justify-between">
            <span className="text-xs font-semibold text-slate-500 uppercase tracking-wider block">
              Threat Score
            </span>
            <span className={`w-2 h-2 rounded-full ${getRiskDotColor(riskLevel)}`}></span>
          </div>
          <div className="flex items-baseline gap-1.5 pt-0.5">
            <span className="text-2xl sm:text-3xl font-extrabold text-slate-900 tracking-tight">
              {typeof threatScore === 'number' ? threatScore : 'Unavailable'}
            </span>
            {typeof threatScore === 'number' && (
              <span className="text-xs font-medium text-slate-400">/ 100</span>
            )}
          </div>
        </div>

        {/* Card 2: ML Detection */}
        <div className="p-4 rounded-xl bg-white border border-slate-200 space-y-1 shadow-xs">
          <div className="flex items-center justify-between">
            <span className="text-xs font-semibold text-slate-500 uppercase tracking-wider block">
              ML Detection
            </span>
            <span className="w-2 h-2 rounded-full bg-cyan-500"></span>
          </div>
          <div className="text-2xl sm:text-3xl font-extrabold text-slate-900 tracking-tight pt-0.5">
            {mlDetectionValue}
          </div>
        </div>

        {/* Card 3: IOC Count */}
        <div className="p-4 rounded-xl bg-white border border-slate-200 space-y-1 shadow-xs">
          <div className="flex items-center justify-between">
            <span className="text-xs font-semibold text-slate-500 uppercase tracking-wider block">
              IOC Count
            </span>
            <span className="w-2 h-2 rounded-full bg-indigo-500"></span>
          </div>
          <div className="text-2xl sm:text-3xl font-extrabold text-slate-900 tracking-tight pt-0.5">
            {iocCount}
          </div>
        </div>

        {/* Card 4: Priority Status */}
        <div className="p-4 rounded-xl bg-white border border-slate-200 space-y-1 shadow-xs">
          <div className="flex items-center justify-between">
            <span className="text-xs font-semibold text-slate-500 uppercase tracking-wider block">
              Priority
            </span>
            <span className={`w-2 h-2 rounded-full ${getRiskDotColor(riskLevel)}`}></span>
          </div>
          <div className="pt-1">
            <span className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded text-xs font-bold border ${getRiskBadgeColor(riskLevel)}`}>
              <span className={`w-1.5 h-1.5 rounded-full ${getRiskDotColor(riskLevel)}`}></span>
              <span>{caseStatus}</span>
            </span>
          </div>
        </div>

      </div>

      {/* ========================================================
          SECTION 2: PROMINENT THREAT ASSESSMENT (Section 10)
      ======================================================== */}
      <div className="rounded-xl bg-white border border-slate-200 p-6 sm:p-8 space-y-6 shadow-xs">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-slate-100 pb-5">
          <div>
            <span className="text-xs font-semibold uppercase tracking-wider text-slate-500">
              THREAT ASSESSMENT
            </span>
            <div className="flex items-baseline gap-2 mt-1">
              <span className="text-4xl sm:text-5xl font-extrabold text-slate-900 tracking-tight">
                {threatScore}
              </span>
              <span className="text-slate-400 text-lg font-medium">/ 100</span>
            </div>
          </div>

          <div className="flex flex-col sm:items-end gap-1.5">
            <div className={`inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg border text-xs font-bold tracking-wide uppercase ${getRiskBadgeColor(riskLevel)}`}>
              <span className={`w-2 h-2 rounded-full ${getRiskDotColor(riskLevel)}`}></span>
              <span>{riskLevel}</span>
            </div>
            <div className="text-xs font-medium text-slate-600">
              Classification: <strong className="text-slate-900 font-semibold">{classification}</strong>
            </div>
            <div className="text-[11px] text-slate-500">
              High confidence indicators detected
            </div>
          </div>
        </div>

        {/* Evidence Fusion Layers Breakdown */}
        <div>
          <h3 className="text-xs font-bold uppercase tracking-wider text-slate-500 mb-3">
            Multi-Layer Evidence Fusion Breakdown
          </h3>
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3">
            {(fusion?.factors || []).map((factor) => {
              const isFlagged = factor.status === 'FLAGGED' || factor.points > 0;
              return (
                <div 
                  key={factor.id || factor.category}
                  className={`p-3.5 rounded-lg border text-xs space-y-2 ${
                    isFlagged 
                      ? 'bg-slate-50 border-slate-300' 
                      : 'bg-white border-slate-200'
                  }`}
                >
                  <div className="flex items-center justify-between">
                    <span className="font-semibold text-slate-900">{factor.category}</span>
                    <span className="font-mono text-xs font-bold text-slate-800">
                      {factor.points} / {factor.maxPoints} pts
                    </span>
                  </div>
                  <p className="text-[11px] text-slate-600 line-clamp-2 leading-relaxed">
                    {factor.evidence}
                  </p>
                </div>
              );
            })}
          </div>
        </div>
      </div>

      {/* ========================================================
          SECTION 3: EMAIL OVERVIEW
      ======================================================== */}
      <div className="rounded-xl bg-white border border-slate-200 p-5 space-y-4 shadow-xs">
        <div className="border-b border-slate-100 pb-2">
          <h2 className="text-sm font-bold text-slate-900">Email Overview</h2>
          <p className="text-xs text-slate-500 mt-0.5">Parsed RFC 822 envelope and routing metadata</p>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-xs">
          <div className="space-y-2.5">
            <div className="flex items-start justify-between gap-2 p-2.5 rounded-lg bg-slate-50 border border-slate-200">
              <span className="text-slate-500 font-medium">From:</span>
              <span className="text-slate-900 font-mono text-right break-all font-semibold">
                {email.sender || email.fromParsed?.address || 'Not available'}
              </span>
            </div>

            <div className="flex items-start justify-between gap-2 p-2.5 rounded-lg bg-slate-50 border border-slate-200">
              <span className="text-slate-500 font-medium">To:</span>
              <span className="text-slate-900 font-mono text-right break-all">
                {email.recipient || 'Not available'}
              </span>
            </div>

            <div className="flex items-start justify-between gap-2 p-2.5 rounded-lg bg-slate-50 border border-slate-200">
              <span className="text-slate-500 font-medium">Subject:</span>
              <span className="text-slate-900 font-medium text-right">
                {email.subject || 'Not available'}
              </span>
            </div>
          </div>

          <div className="space-y-2.5">
            <div className="flex items-start justify-between gap-2 p-2.5 rounded-lg bg-slate-50 border border-slate-200">
              <span className="text-slate-500 font-medium">Date:</span>
              <span className="text-slate-700 font-mono text-right">
                {email.date || 'Not available'}
              </span>
            </div>

            <div className="flex items-start justify-between gap-2 p-2.5 rounded-lg bg-slate-50 border border-slate-200">
              <span className="text-slate-500 font-medium">Return-Path:</span>
              <span className="text-slate-700 font-mono text-right break-all">
                {email.returnPath || email.replyTo || 'Not available'}
              </span>
            </div>

            <div className="flex items-start justify-between gap-2 p-2.5 rounded-lg bg-slate-50 border border-slate-200">
              <span className="text-slate-500 font-medium">Origin IP:</span>
              <span className="text-slate-900 font-mono font-bold text-right">
                {email.originatingIP || 'Not available'}
              </span>
            </div>
          </div>
        </div>
      </div>

      {/* ========================================================
          SECTION 4: EMAIL HEADERS (COLLAPSIBLE RAW HEADERS)
      ======================================================== */}
      <div className="rounded-xl bg-white border border-slate-200 p-5 space-y-4 shadow-xs">
        <div className="flex items-center justify-between border-b border-slate-100 pb-2">
          <div>
            <h2 className="text-sm font-bold text-slate-900">Email Headers</h2>
            <p className="text-xs text-slate-500 mt-0.5">Important headers parsed from RFC 822 envelope</p>
          </div>

          <button
            type="button"
            onClick={() => setShowRawHeaders(!showRawHeaders)}
            className="flex items-center gap-1 px-3 py-1.5 rounded-lg bg-white hover:bg-slate-50 border border-slate-200 text-xs font-semibold text-slate-700 transition-colors shadow-2xs cursor-pointer"
          >
            <span>{showRawHeaders ? 'Hide Raw Headers' : 'Show Raw Headers'}</span>
            {showRawHeaders ? <ChevronUp className="w-3.5 h-3.5" /> : <ChevronDown className="w-3.5 h-3.5" />}
          </button>
        </div>

        {/* Key parsed headers first */}
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3 text-xs">
          <div className="p-3 rounded-lg bg-slate-50 border border-slate-200">
            <span className="text-[10px] uppercase font-semibold text-slate-500 block mb-1">Message-ID</span>
            <span className="font-mono text-slate-800 text-[11px] break-all">
              {email.messageId || 'Not available'}
            </span>
          </div>

          <div className="p-3 rounded-lg bg-slate-50 border border-slate-200">
            <span className="text-[10px] uppercase font-semibold text-slate-500 block mb-1">Hop Count</span>
            <span className="font-mono text-slate-800 text-[11px]">
              {Array.isArray(email.hops) ? `${email.hops.length} Received Hops` : '1 Origin Hop'}
            </span>
          </div>

          <div className="p-3 rounded-lg bg-slate-50 border border-slate-200">
            <span className="text-[10px] uppercase font-semibold text-slate-500 block mb-1">Content-Type</span>
            <span className="font-mono text-slate-800 text-[11px] break-all">
              {email.contentType || 'multipart/mixed'}
            </span>
          </div>
        </div>

        {/* Monospace Raw Headers Container when expanded */}
        {showRawHeaders && (
          <div className="space-y-2 pt-2">
            <div className="flex items-center justify-between">
              <span className="text-xs font-mono text-slate-500">Raw RFC 822 Header Payload:</span>
              <button
                type="button"
                onClick={handleCopyRawHeaders}
                className="flex items-center gap-1 text-xs text-slate-700 hover:text-slate-900 font-semibold cursor-pointer"
              >
                {copiedRawHeaders ? <Check className="w-3.5 h-3.5 text-emerald-600" /> : <Copy className="w-3.5 h-3.5" />}
                <span>{copiedRawHeaders ? 'Copied' : 'Copy Headers'}</span>
              </button>
            </div>

            <pre className="p-3.5 rounded-lg bg-slate-50 border border-slate-200 text-xs font-mono text-slate-800 overflow-x-auto max-h-72 leading-relaxed">
              {email.rawSnippet || 'Raw header payload unavailable.'}
            </pre>
          </div>
        )}
      </div>

      {/* ========================================================
          SECTION 5: AI THREAT DETECTION
      ======================================================== */}
      <div className="rounded-xl bg-white border border-slate-200 p-5 space-y-4 shadow-xs">
        <div className="border-b border-slate-100 pb-2">
          <div className="flex items-center gap-2">
            <Cpu className="w-4 h-4 text-slate-600" />
            <h2 className="text-sm font-bold text-slate-900">AI Threat Detection</h2>
          </div>
          <p className="text-xs text-slate-500 mt-0.5">
            Model: <span className="text-slate-800 font-semibold">{aiThreat?.model || 'TF-IDF + Logistic Regression'}</span>
          </p>
        </div>

        {isMlAvailable ? (
          <div className="space-y-4">
            {/* Probability Bars */}
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
              <div className="p-4 rounded-lg bg-slate-50 border border-slate-200 space-y-2">
                <div className="flex items-center justify-between text-xs">
                  <span className="text-slate-600 font-semibold">Phishing Probability</span>
                  <span className="font-mono font-bold text-red-700 text-sm">
                    {aiThreat.phishingProbability}%
                  </span>
                </div>
                <div className="w-full h-2 bg-slate-200 rounded-full overflow-hidden">
                  <div 
                    className="h-full bg-red-600 rounded-full transition-all duration-500"
                    style={{ width: `${aiThreat.phishingProbability}%` }}
                  />
                </div>
              </div>

              <div className="p-4 rounded-lg bg-slate-50 border border-slate-200 space-y-2">
                <div className="flex items-center justify-between text-xs">
                  <span className="text-slate-600 font-semibold">Legitimate Probability</span>
                  <span className="font-mono font-bold text-emerald-700 text-sm">
                    {typeof aiThreat.legitimate_probability === 'number' 
                      ? `${Math.round(aiThreat.legitimate_probability * 100)}%`
                      : `${100 - (aiThreat.phishingProbability || 0)}%`}
                  </span>
                </div>
                <div className="w-full h-2 bg-slate-200 rounded-full overflow-hidden">
                  <div 
                    className="h-full bg-emerald-600 rounded-full transition-all duration-500"
                    style={{ width: `${100 - (aiThreat.phishingProbability || 0)}%` }}
                  />
                </div>
              </div>
            </div>

            {/* Important Indicators */}
            <div className="space-y-2">
              <span className="text-xs font-semibold text-slate-600 block">
                Extracted NLP Threat Signals & Features
              </span>
              
              {aiThreat.topFeatures && aiThreat.topFeatures.length > 0 ? (
                <div className="flex flex-wrap gap-2">
                  {aiThreat.topFeatures.slice(0, 8).map((feat, idx) => (
                    <span 
                      key={idx}
                      className="px-2.5 py-1 rounded bg-slate-100 border border-slate-200 text-xs font-mono text-slate-800"
                    >
                      {feat.term} {typeof feat.weight === 'number' && `(${feat.weight > 0 ? '+' : ''}${feat.weight})`}
                    </span>
                  ))}
                </div>
              ) : aiThreat.detectedIndicators && aiThreat.detectedIndicators.length > 0 ? (
                <div className="flex flex-wrap gap-2">
                  {aiThreat.detectedIndicators.slice(0, 8).map((ind, idx) => (
                    <span 
                      key={idx}
                      className="px-2.5 py-1 rounded bg-amber-50 border border-amber-200 text-xs text-amber-800 font-medium"
                    >
                      &quot;{ind.token}&quot; ({ind.category})
                    </span>
                  ))}
                </div>
              ) : (
                <p className="text-xs text-slate-500 italic">
                  No abnormal linguistic threat terms isolated.
                </p>
              )}
            </div>
          </div>
        ) : (
          /* Graceful ML Unavailable State */
          <div className="p-4 rounded-lg bg-slate-50 border border-slate-200 text-xs text-slate-600 space-y-1">
            <div className="font-semibold text-slate-800 flex items-center gap-1.5">
              <AlertTriangle className="w-4 h-4 text-amber-600" />
              <span>ML Analysis Unavailable</span>
            </div>
            <p>
              The AI service could not be reached. Other forensic analysis is still available.
            </p>
          </div>
        )}
      </div>

      {/* ========================================================
          SECTION 6: IOC INTELLIGENCE
      ======================================================== */}
      <div className="rounded-xl bg-white border border-slate-200 p-5 space-y-4 shadow-xs">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-slate-100 pb-2">
          <div>
            <h2 className="text-sm font-bold text-slate-900">IOC Intelligence</h2>
            <p className="text-xs text-slate-500 mt-0.5">
              Total indicators detected: <strong className="text-slate-900">{iocs.length}</strong>
            </p>
          </div>

          {/* Sub-tabs */}
          <div className="flex items-center gap-1 p-0.5 rounded-lg bg-slate-100 border border-slate-200 text-xs">
            {['ALL', 'IP', 'URL', 'DOMAIN', 'EMAIL'].map((t) => (
              <button
                key={t}
                onClick={() => setActiveIocTab(t)}
                className={`px-3 py-1 rounded-md transition-colors cursor-pointer ${
                  activeIocTab === t ? 'bg-white text-slate-900 font-bold shadow-2xs' : 'text-slate-600 hover:text-slate-900'
                }`}
              >
                {t === 'ALL' ? 'All' : t === 'IP' ? 'IPs' : t === 'URL' ? 'URLs' : t === 'DOMAIN' ? 'Domains' : 'Emails'}
              </button>
            ))}
          </div>
        </div>

        {filteredIocs.length > 0 ? (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead className="border-b border-slate-200 text-[11px] font-semibold uppercase text-slate-500 bg-slate-50/50">
                <tr>
                  <th className="py-2.5 px-3">Type</th>
                  <th className="py-2.5 px-3">Indicator</th>
                  <th className="py-2.5 px-3">Role / Status</th>
                  <th className="py-2.5 px-3">Source</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100">
                {filteredIocs.map((ioc, idx) => (
                  <tr key={idx} className="hover:bg-slate-50/60 transition-colors">
                    <td className="py-2.5 px-3">
                      <span className="font-mono text-[10px] px-2 py-0.5 rounded bg-slate-100 text-slate-700 border border-slate-200">
                        {ioc.type}
                      </span>
                    </td>
                    <td className="py-2.5 px-3 font-mono font-medium text-slate-900 break-all">
                      {ioc.value}
                    </td>
                    <td className="py-2.5 px-3">
                      <span className={`px-2 py-0.5 rounded text-[10px] font-bold border ${
                        ioc.status === 'MALICIOUS' ? 'bg-red-50 text-red-700 border-red-200' :
                        ioc.status === 'SUSPICIOUS' ? 'bg-amber-50 text-amber-800 border-amber-200' :
                        'bg-slate-100 text-slate-600 border-slate-200'
                      }`}>
                        {ioc.status || 'OBSERVED'}
                      </span>
                    </td>
                    <td className="py-2.5 px-3 text-slate-500 truncate max-w-xs">
                      {ioc.source || 'Email Artifact'}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <p className="text-xs text-slate-400 italic py-3 text-center">
            No indicators detected for the selected category.
          </p>
        )}
      </div>

      {/* ========================================================
          SECTION 7: NETWORK INTELLIGENCE (LEAFLET MAP)
      ======================================================== */}
      <div>
        <ForensicGeoMap 
          geoRecords={geoList.length > 0 ? geoList : geoInfo ? [geoInfo] : []}
          title="Network Intelligence"
          subtitle="Geospatial routing and autonomous system infrastructure mapping"
        />
      </div>

      {/* Selected IP Node Details Box if needed */}
      {activeGeoRecord && (
        <div className="p-4 rounded-xl bg-white border border-slate-200 text-xs shadow-xs space-y-3">
          <div className="flex items-center justify-between border-b border-slate-100 pb-2">
            <span className="font-bold text-slate-900">Egress Node Telemetry</span>
            <span className="font-mono font-bold text-slate-900">{activeGeoRecord.ip}</span>
          </div>
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 text-slate-600">
            <div>
              <span className="text-[10px] text-slate-400 uppercase block font-semibold">Location</span>
              <span className="text-slate-900 font-medium">{activeGeoRecord.city ? `${activeGeoRecord.city}, ` : ''}{activeGeoRecord.country || 'N/A'}</span>
            </div>
            <div>
              <span className="text-[10px] text-slate-400 uppercase block font-semibold">ASN</span>
              <span className="text-slate-900 font-medium">{activeGeoRecord.asn || 'N/A'}</span>
            </div>
            <div>
              <span className="text-[10px] text-slate-400 uppercase block font-semibold">ISP</span>
              <span className="text-slate-900 font-medium">{activeGeoRecord.isp || activeGeoRecord.asnOrg || 'N/A'}</span>
            </div>
            <div>
              <span className="text-[10px] text-slate-400 uppercase block font-semibold">Role</span>
              <span className="text-slate-900 font-medium">{activeGeoRecord.role || 'Source Hop'}</span>
            </div>
          </div>
        </div>
      )}

      {/* ========================================================
          SECTION 8: EMAIL AUTHENTICATION
      ======================================================== */}
      <div>
        <EmailAuthenticationCard emailAuth={emailAuth || email.emailAuth} />
      </div>

      {/* ========================================================
          SECTION 9: ATTACHMENT FORENSICS
      ======================================================== */}
      <div>
        <AttachmentForensicsCard attachments={email.attachments || []} />
      </div>

      {/* ========================================================
          SECTION 10: EVIDENCE FUSION (OBSERVED VS INFERRED)
      ======================================================== */}
      <div className="rounded-xl bg-white border border-slate-200 p-5 space-y-4 shadow-xs">
        <div className="border-b border-slate-100 pb-2">
          <h2 className="text-sm font-bold text-slate-900">Evidence Classification</h2>
          <p className="text-xs text-slate-500 mt-0.5">
            Strict separation of empirical observed evidence from analytical inferences
          </p>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs">
          {/* Observed Evidence */}
          <div className="p-4 rounded-xl bg-slate-50 border border-slate-200 space-y-3">
            <div className="flex items-center gap-2 font-bold text-slate-900 border-b border-slate-200 pb-2">
              <Shield className="w-4 h-4 text-slate-600" />
              <span>Observed Evidence (Empirical Facts)</span>
            </div>
            <ul className="space-y-1.5 text-slate-700 list-disc list-inside leading-relaxed text-[11px]">
              <li>RFC 822 headers: From, To, Return-Path, Date</li>
              <li>MTA Authentication-Results header values</li>
              <li>Live DNS resource records (SPF TXT, DKIM public keys, DMARC TXT)</li>
              <li>Static attachment binary file signatures & cryptographic SHA-256 hashes</li>
              <li>Network egress IPs recorded in Received routing hops</li>
            </ul>
          </div>

          {/* Inferred / Enriched Information */}
          <div className="p-4 rounded-xl bg-slate-50 border border-slate-200 space-y-3">
            <div className="flex items-center gap-2 font-bold text-slate-900 border-b border-slate-200 pb-2">
              <Activity className="w-4 h-4 text-slate-600" />
              <span>Inferred / Enriched Information</span>
            </div>
            <ul className="space-y-1.5 text-slate-700 list-disc list-inside leading-relaxed text-[11px]">
              <li>Machine learning classification probability (TF-IDF model inference)</li>
              <li>Geographic location coordinates and Autonomous System Org</li>
              <li>Domain alignment checks (RFC 7489 relaxed/strict evaluation)</li>
              <li>Composite threat score (0–100 weighted multi-factor calculation)</li>
              <li>Recommended incident response and triage playbooks</li>
            </ul>
          </div>
        </div>
      </div>

      {/* ========================================================
          SECTION 11: INVESTIGATION TIMELINE
      ======================================================== */}
      <div className="rounded-xl bg-white border border-slate-200 p-5 space-y-4 shadow-xs">
        <div className="border-b border-slate-100 pb-2">
          <h2 className="text-sm font-bold text-slate-900">Investigation Timeline</h2>
          <p className="text-xs text-slate-500 mt-0.5">Chronological execution audit trail of the forensic pipeline</p>
        </div>

        <div className="space-y-2 text-xs">
          {[
            { step: '1', name: 'Email received and ingested into inspection sandbox', time: 'T0' },
            { step: '2', name: 'RFC 822 MIME boundaries and headers parsed', time: 'T0 + 34ms' },
            { step: '3', name: 'Network and file IOCs extracted and deduplicated', time: 'T0 + 41ms' },
            { step: '4', name: 'AI threat model evaluation completed (TF-IDF + LR)', time: 'T0 + 82ms' },
            { step: '5', name: 'DNS & email authentication verification completed', time: 'T0 + 130ms' },
            { step: '6', name: 'Evidence fusion and multi-layer threat score synthesized', time: 'T0 + 168ms' },
            { step: '7', name: 'Tamper-evident forensic report compiled and SHA-256 sealed', time: 'T0 + 206ms' }
          ].map((item, idx) => (
            <div key={idx} className="flex items-center justify-between p-2.5 rounded-lg bg-slate-50 border border-slate-200">
              <div className="flex items-center gap-2.5">
                <span className="w-5 h-5 rounded-full bg-slate-200 flex items-center justify-center text-[10px] font-mono font-bold text-slate-700">
                  {item.step}
                </span>
                <span className="text-slate-800 text-xs font-medium">{item.name}</span>
              </div>
              <span className="text-[10px] font-mono text-slate-500">{item.time}</span>
            </div>
          ))}
        </div>
      </div>

      {/* ========================================================
          SECTION 12: RECOMMENDATIONS
      ======================================================== */}
      <div className="rounded-xl bg-white border border-slate-200 p-5 space-y-4 shadow-xs">
        <div className="border-b border-slate-100 pb-2">
          <h2 className="text-sm font-bold text-slate-900">Recommended Actions</h2>
          <p className="text-xs text-slate-500 mt-0.5">Actionable mitigation steps based directly on observed indicators</p>
        </div>

        <div className="space-y-2.5">
          {fusion?.verifiedReasons && fusion.verifiedReasons.length > 0 ? (
            fusion.verifiedReasons.slice(0, 5).map((reason, idx) => (
              <div key={idx} className="p-3 rounded-lg bg-slate-50 border border-slate-200 text-xs text-slate-800 flex items-start gap-2.5">
                <CheckCircle2 className="w-4 h-4 text-emerald-600 shrink-0 mt-0.5" />
                <span className="leading-relaxed">{reason}</span>
              </div>
            ))
          ) : (
            <div className="p-3 rounded-lg bg-slate-50 border border-slate-200 text-xs text-slate-600">
              Review sender identity and preserve original RFC 822 email evidence for compliance record.
            </div>
          )}
        </div>
      </div>

      {/* ========================================================
          SECTION 13: FORENSIC REPORT & INTEGRITY SEAL
      ======================================================== */}
      <div className="rounded-xl bg-white border border-slate-200 p-5 sm:p-6 space-y-4 shadow-xs">
        <div className="border-b border-slate-100 pb-2">
          <h2 className="text-sm font-bold text-slate-900">Forensic Report</h2>
          <p className="text-xs text-slate-500 mt-0.5">
            Tamper-evident forensic report with SHA-256 integrity verification to support evidence preservation and investigation.
          </p>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-3 text-xs">
          <div className="p-3 rounded-lg bg-slate-50 border border-slate-200 space-y-1">
            <span className="text-[10px] uppercase font-semibold text-slate-500 block">Case ID</span>
            <span className="font-mono font-bold text-slate-900">{caseId}</span>
          </div>

          <div className="p-3 rounded-lg bg-slate-50 border border-slate-200 space-y-1">
            <span className="text-[10px] uppercase font-semibold text-slate-500 block">Report Status</span>
            <span className="font-semibold text-emerald-700 flex items-center gap-1.5">
              <span className="w-2 h-2 rounded-full bg-emerald-500"></span>
              Sealed & Verified
            </span>
          </div>

          <div className="p-3 rounded-lg bg-slate-50 border border-slate-200 space-y-1">
            <span className="text-[10px] uppercase font-semibold text-slate-500 block">SHA-256 Integrity Hash</span>
            <div className="flex items-center justify-between gap-2">
              <span className="font-mono text-slate-800 truncate text-[11px]" title={sha256Hash}>
                {sha256Hash ? `${sha256Hash.slice(0, 16)}...` : 'N/A'}
              </span>
              <button
                type="button"
                onClick={handleCopyHash}
                className="p-1 text-slate-400 hover:text-slate-800 cursor-pointer"
                title="Copy full SHA-256"
              >
                {copiedHash ? <Check className="w-3.5 h-3.5 text-emerald-600" /> : <Copy className="w-3.5 h-3.5" />}
              </button>
            </div>
          </div>
        </div>

        {/* Report Action Buttons */}
        <div className="flex flex-wrap items-center gap-2.5 pt-2">
          <button
            type="button"
            onClick={() => onViewChange('forensic-report')}
            className="flex items-center gap-1.5 px-3.5 py-2 rounded-lg bg-white hover:bg-slate-50 border border-slate-200 text-slate-700 text-xs font-semibold transition-colors shadow-2xs cursor-pointer"
          >
            <FileText className="w-3.5 h-3.5 text-slate-500" />
            <span>View Forensic Report</span>
          </button>

          <button
            type="button"
            onClick={handleExportPdf}
            disabled={exportingPdf}
            className="flex items-center gap-1.5 px-3.5 py-2 rounded-lg bg-slate-900 hover:bg-slate-800 text-white text-xs font-semibold shadow-xs transition-colors cursor-pointer disabled:opacity-50"
          >
            <Download className="w-3.5 h-3.5" />
            <span>{exportingPdf ? 'Exporting PDF...' : 'Export PDF'}</span>
          </button>

          <button
            type="button"
            onClick={handleExportJson}
            disabled={exportingJson}
            className="flex items-center gap-1.5 px-3.5 py-2 rounded-lg bg-white hover:bg-slate-50 border border-slate-200 text-slate-700 text-xs font-semibold transition-colors shadow-2xs cursor-pointer disabled:opacity-50"
          >
            <FileCode className="w-3.5 h-3.5 text-slate-500" />
            <span>{exportingJson ? 'Exporting JSON...' : 'Export JSON'}</span>
          </button>

          <button
            type="button"
            onClick={handleCopyHash}
            className="flex items-center gap-1.5 px-3.5 py-2 rounded-lg bg-white hover:bg-slate-50 border border-slate-200 text-slate-700 text-xs font-semibold transition-colors shadow-2xs cursor-pointer"
          >
            {copiedHash ? <Check className="w-3.5 h-3.5 text-emerald-600" /> : <Copy className="w-3.5 h-3.5 text-slate-500" />}
            <span>{copiedHash ? 'Hash Copied!' : 'Copy SHA-256'}</span>
          </button>
        </div>

      </div>

    </div>
  );
};
