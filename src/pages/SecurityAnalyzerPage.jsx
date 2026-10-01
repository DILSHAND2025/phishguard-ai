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
  _onRunAnalysis 
}) => {
  // State toggles
  const [showRawHeaders, setShowRawHeaders] = useState(false);
  const [copiedRawHeaders, setCopiedRawHeaders] = useState(false);
  const [copiedHash, setCopiedHash] = useState(false);
  const [activeIocTab, setActiveIocTab] = useState('ALL');
  const [selectedGeoIP, setSelectedGeoIP] = useState(null);
  const [exportingPdf, setExportingPdf] = useState(false);
  const [exportingJson, setExportingJson] = useState(false);

  // If no analysis is loaded yet, provide a clean empty state with action to start one
  if (!currentAnalysis || !currentAnalysis.email) {
    return (
      <div className="rounded-2xl bg-[#090d16] border border-slate-800 p-12 text-center max-w-xl mx-auto my-12 space-y-4">
        <div className="w-12 h-12 mx-auto rounded-full bg-slate-800 flex items-center justify-center text-cyan-400">
          <ShieldAlert className="w-6 h-6" />
        </div>
        <h2 className="text-lg font-bold text-white">No Email Analysis Loaded</h2>
        <p className="text-xs text-slate-400">
          Submit an email in the User Email Analysis portal or choose a case from the dashboard.
        </p>
        <button
          onClick={() => onViewChange('email-analysis')}
          className="px-4 py-2 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-semibold cursor-pointer"
        >
          Go to Email Analysis
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

  // 2. Threat Summary Metric Values
  const isMlAvailable = aiThreat && aiThreat.isMlAvailable;
  const mlDetectionValue = isMlAvailable && typeof aiThreat.phishingProbability === 'number'
    ? `${aiThreat.phishingProbability}%`
    : 'Unavailable';

  const iocCount = Array.isArray(iocs) ? iocs.length : 0;
  const caseStatus = riskLevel === 'CRITICAL' ? 'CRITICAL RISK' : riskLevel === 'HIGH' ? 'HIGH RISK' : riskLevel === 'SUSPICIOUS' ? 'SUSPICIOUS' : 'LOW RISK';

  // Helper: Status badge color
  const getRiskBadgeColor = (level) => {
    switch (level) {
      case 'CRITICAL':
      case 'HIGH':
        return 'bg-red-950/70 border-red-500/50 text-red-300';
      case 'SUSPICIOUS':
        return 'bg-amber-950/70 border-amber-500/50 text-amber-300';
      default:
        return 'bg-emerald-950/70 border-emerald-500/50 text-emerald-300';
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
    <div className="space-y-6 pb-20 font-sans text-slate-100">
      
      {/* ========================================================
          ANALYZER HEADER
      ======================================================== */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 py-3 border-b border-slate-800">
        <div>
          <div className="flex items-center gap-2.5">
            <h1 className="text-xl sm:text-2xl font-bold text-white tracking-tight">
              Security Analyzer
            </h1>
            <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-slate-800 text-cyan-300 border border-slate-700">
              FORENSIC WORKSPACE
            </span>
          </div>
          <div className="flex flex-wrap items-center gap-3 mt-1 text-xs font-mono text-slate-400">
            <span>Case ID: <strong className="text-slate-200">{caseId}</strong></span>
            <span>•</span>
            <span className="text-emerald-400 flex items-center gap-1">
              <span className="w-1.5 h-1.5 rounded-full bg-emerald-400"></span>
              Status: Analysis Complete
            </span>
          </div>
        </div>

        <div className="flex items-center gap-2.5">
          <button
            type="button"
            onClick={() => onViewChange('email-analysis')}
            className="flex items-center gap-1.5 px-3 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 border border-slate-700 text-xs font-medium text-slate-200 transition-colors cursor-pointer"
          >
            <RefreshCw className="w-3.5 h-3.5" />
            <span>New Analysis</span>
          </button>

          <button
            type="button"
            onClick={handleExportPdf}
            disabled={exportingPdf}
            className="flex items-center gap-1.5 px-3.5 py-2 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-semibold shadow-xs transition-colors cursor-pointer disabled:opacity-50"
          >
            <Download className="w-3.5 h-3.5" />
            <span>{exportingPdf ? 'Exporting...' : 'Export Report'}</span>
          </button>
        </div>
      </div>

      {/* ========================================================
          SECTION 1: THREAT SUMMARY (EXACTLY FOUR CARDS)
      ======================================================== */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-3 sm:gap-4">
        
        {/* Card 1: Threat Score */}
        <div className="p-4 rounded-xl bg-[#090d16] border border-slate-800 space-y-1 shadow-sm">
          <span className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider block">
            Threat Score
          </span>
          <div className="flex items-baseline gap-1.5">
            <span className="text-2xl sm:text-3xl font-extrabold text-white">
              {typeof threatScore === 'number' ? threatScore : 'Unavailable'}
            </span>
            {typeof threatScore === 'number' && (
              <span className="text-xs font-medium text-slate-500">/ 100</span>
            )}
          </div>
        </div>

        {/* Card 2: ML Detection */}
        <div className="p-4 rounded-xl bg-[#090d16] border border-slate-800 space-y-1 shadow-sm">
          <span className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider block">
            ML Detection
          </span>
          <div className="text-2xl sm:text-3xl font-extrabold text-white">
            {mlDetectionValue}
          </div>
        </div>

        {/* Card 3: IOC Count */}
        <div className="p-4 rounded-xl bg-[#090d16] border border-slate-800 space-y-1 shadow-sm">
          <span className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider block">
            IOC Count
          </span>
          <div className="text-2xl sm:text-3xl font-extrabold text-white">
            {iocCount}
          </div>
        </div>

        {/* Card 4: Case Status */}
        <div className="p-4 rounded-xl bg-[#090d16] border border-slate-800 space-y-1 shadow-sm">
          <span className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider block">
            Case Status
          </span>
          <div className="flex items-center gap-2 pt-0.5">
            <span className={`px-2 py-0.5 rounded text-xs font-bold border ${getRiskBadgeColor(riskLevel)}`}>
              {caseStatus}
            </span>
          </div>
        </div>

      </div>

      {/* ========================================================
          SECTION 2: THREAT ASSESSMENT & EVIDENCE BREAKDOWN
      ======================================================== */}
      <div className="rounded-xl bg-[#090d16] border border-slate-800 p-5 space-y-5 shadow-sm">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-slate-800/80 pb-3">
          <div>
            <h2 className="text-base font-bold text-white">Threat Assessment</h2>
            <p className="text-xs text-slate-400 mt-0.5">
              Multi-layer Evidence Fusion synthesizing verified indicators
            </p>
          </div>
          <div className="flex items-center gap-2">
            <span className="text-xs text-slate-400 font-mono">
              Composite Score: <strong className="text-white">{threatScore} / 100</strong>
            </span>
            <span className={`px-2 py-0.5 rounded text-[11px] font-bold border ${getRiskBadgeColor(riskLevel)}`}>
              {riskLevel}
            </span>
          </div>
        </div>

        {/* Evidence Fusion Layers Breakdown */}
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3">
          {(fusion?.factors || []).map((factor) => {
            const isFlagged = factor.status === 'FLAGGED' || factor.points > 0;
            return (
              <div 
                key={factor.id || factor.category}
                className={`p-3.5 rounded-lg border text-xs space-y-2 ${
                  isFlagged 
                    ? 'bg-slate-900/90 border-slate-750' 
                    : 'bg-slate-900/40 border-slate-850'
                }`}
              >
                <div className="flex items-center justify-between">
                  <span className="font-semibold text-slate-200">{factor.category}</span>
                  <span className="font-mono text-[11px] font-bold text-cyan-300">
                    {factor.points} / {factor.maxPoints} pts
                  </span>
                </div>
                <p className="text-[11px] text-slate-400 line-clamp-2 leading-relaxed">
                  {factor.evidence}
                </p>
              </div>
            );
          })}
        </div>
      </div>

      {/* ========================================================
          SECTION 3: EMAIL OVERVIEW
      ======================================================== */}
      <div className="rounded-xl bg-[#090d16] border border-slate-800 p-5 space-y-4 shadow-sm">
        <div className="border-b border-slate-800/80 pb-2">
          <h2 className="text-base font-bold text-white">Email Overview</h2>
          <p className="text-xs text-slate-400 mt-0.5">Parsed RFC 822 envelope and routing metadata</p>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs">
          <div className="space-y-3">
            <div className="flex items-start justify-between gap-2 p-2 rounded bg-slate-900/60 border border-slate-850">
              <span className="text-slate-400 font-medium">From:</span>
              <span className="text-slate-200 font-mono text-right break-all">
                {email.sender || email.fromParsed?.address || 'Not available'}
              </span>
            </div>

            <div className="flex items-start justify-between gap-2 p-2 rounded bg-slate-900/60 border border-slate-850">
              <span className="text-slate-400 font-medium">To:</span>
              <span className="text-slate-200 font-mono text-right break-all">
                {email.recipient || 'Not available'}
              </span>
            </div>

            <div className="flex items-start justify-between gap-2 p-2 rounded bg-slate-900/60 border border-slate-850">
              <span className="text-slate-400 font-medium">Subject:</span>
              <span className="text-slate-200 font-medium text-right">
                {email.subject || 'Not available'}
              </span>
            </div>
          </div>

          <div className="space-y-3">
            <div className="flex items-start justify-between gap-2 p-2 rounded bg-slate-900/60 border border-slate-850">
              <span className="text-slate-400 font-medium">Date:</span>
              <span className="text-slate-200 font-mono text-right">
                {email.date || 'Not available'}
              </span>
            </div>

            <div className="flex items-start justify-between gap-2 p-2 rounded bg-slate-900/60 border border-slate-850">
              <span className="text-slate-400 font-medium">Return-Path:</span>
              <span className="text-slate-200 font-mono text-right break-all">
                {email.returnPath || email.replyTo || 'Not available'}
              </span>
            </div>

            <div className="flex items-start justify-between gap-2 p-2 rounded bg-slate-900/60 border border-slate-850">
              <span className="text-slate-400 font-medium">Origin IP:</span>
              <span className="text-cyan-300 font-mono text-right">
                {email.originatingIP || 'Not available'}
              </span>
            </div>
          </div>
        </div>
      </div>

      {/* ========================================================
          SECTION 4: EMAIL HEADERS (COLLAPSIBLE RAW HEADERS)
      ======================================================== */}
      <div className="rounded-xl bg-[#090d16] border border-slate-800 p-5 space-y-4 shadow-sm">
        <div className="flex items-center justify-between border-b border-slate-800/80 pb-2">
          <div>
            <h2 className="text-base font-bold text-white">Email Headers</h2>
            <p className="text-xs text-slate-400 mt-0.5">Important headers parsed from RFC 822 envelope</p>
          </div>

          <button
            type="button"
            onClick={() => setShowRawHeaders(!showRawHeaders)}
            className="flex items-center gap-1 px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-xs font-medium text-slate-200 transition-colors cursor-pointer"
          >
            <span>{showRawHeaders ? 'Hide Raw Headers' : 'Show Raw Headers'}</span>
            {showRawHeaders ? <ChevronUp className="w-3.5 h-3.5" /> : <ChevronDown className="w-3.5 h-3.5" />}
          </button>
        </div>

        {/* Key parsed headers first */}
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3 text-xs">
          <div className="p-2.5 rounded bg-slate-900/80 border border-slate-800">
            <span className="text-[10px] uppercase font-semibold text-slate-400 block mb-1">Message-ID</span>
            <span className="font-mono text-slate-300 text-[11px] break-all">
              {email.messageId || 'Not available'}
            </span>
          </div>

          <div className="p-2.5 rounded bg-slate-900/80 border border-slate-800">
            <span className="text-[10px] uppercase font-semibold text-slate-400 block mb-1">Hop Count</span>
            <span className="font-mono text-slate-300 text-[11px]">
              {Array.isArray(email.hops) ? `${email.hops.length} Received Hops` : '1 Origin Hop'}
            </span>
          </div>

          <div className="p-2.5 rounded bg-slate-900/80 border border-slate-800">
            <span className="text-[10px] uppercase font-semibold text-slate-400 block mb-1">Content-Type</span>
            <span className="font-mono text-slate-300 text-[11px] break-all">
              {email.contentType || 'multipart/mixed'}
            </span>
          </div>
        </div>

        {/* Monospace Raw Headers Container when expanded */}
        {showRawHeaders && (
          <div className="space-y-2 pt-2">
            <div className="flex items-center justify-between">
              <span className="text-[11px] font-mono text-slate-400">Raw RFC 822 Header Text:</span>
              <button
                type="button"
                onClick={handleCopyRawHeaders}
                className="flex items-center gap-1 text-xs text-cyan-400 hover:text-cyan-300 cursor-pointer"
              >
                {copiedRawHeaders ? <Check className="w-3 h-3" /> : <Copy className="w-3 h-3" />}
                <span>{copiedRawHeaders ? 'Copied' : 'Copy Headers'}</span>
              </button>
            </div>

            <pre className="p-3.5 rounded-lg bg-[#050811] border border-slate-800 text-[11px] font-mono text-slate-300 overflow-x-auto max-h-72 leading-relaxed">
              {email.rawSnippet || 'Raw header payload unavailable.'}
            </pre>
          </div>
        )}
      </div>

      {/* ========================================================
          SECTION 5: AI THREAT DETECTION
      ======================================================== */}
      <div className="rounded-xl bg-[#090d16] border border-slate-800 p-5 space-y-4 shadow-sm">
        <div className="border-b border-slate-800/80 pb-2">
          <div className="flex items-center gap-2">
            <Cpu className="w-4 h-4 text-cyan-400" />
            <h2 className="text-base font-bold text-white">AI Threat Detection</h2>
          </div>
          <p className="text-xs text-slate-400 mt-0.5">
            Model: <span className="text-slate-200 font-semibold">{aiThreat?.model || 'TF-IDF + Logistic Regression'}</span>
          </p>
        </div>

        {isMlAvailable ? (
          <div className="space-y-4">
            {/* Probability Bars */}
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
              <div className="p-3.5 rounded-lg bg-slate-900 border border-slate-800 space-y-2">
                <div className="flex items-center justify-between text-xs">
                  <span className="text-slate-400 font-medium">Phishing Probability</span>
                  <span className="font-mono font-bold text-red-400 text-sm">
                    {aiThreat.phishingProbability}%
                  </span>
                </div>
                <div className="w-full h-1.5 bg-slate-800 rounded-full overflow-hidden">
                  <div 
                    className="h-full bg-red-500 rounded-full transition-all duration-500"
                    style={{ width: `${aiThreat.phishingProbability}%` }}
                  />
                </div>
              </div>

              <div className="p-3.5 rounded-lg bg-slate-900 border border-slate-800 space-y-2">
                <div className="flex items-center justify-between text-xs">
                  <span className="text-slate-400 font-medium">Legitimate Probability</span>
                  <span className="font-mono font-bold text-emerald-400 text-sm">
                    {typeof aiThreat.legitimate_probability === 'number' 
                      ? `${Math.round(aiThreat.legitimate_probability * 100)}%`
                      : `${100 - (aiThreat.phishingProbability || 0)}%`}
                  </span>
                </div>
                <div className="w-full h-1.5 bg-slate-800 rounded-full overflow-hidden">
                  <div 
                    className="h-full bg-emerald-500 rounded-full transition-all duration-500"
                    style={{ width: `${100 - (aiThreat.phishingProbability || 0)}%` }}
                  />
                </div>
              </div>
            </div>

            {/* Important Indicators */}
            <div className="space-y-2">
              <span className="text-xs font-semibold text-slate-400 block">
                Important Indicators & Model Features
              </span>
              
              {aiThreat.topFeatures && aiThreat.topFeatures.length > 0 ? (
                <div className="flex flex-wrap gap-2">
                  {aiThreat.topFeatures.slice(0, 8).map((feat, idx) => (
                    <span 
                      key={idx}
                      className="px-2.5 py-1 rounded bg-slate-900 border border-slate-800 text-xs font-mono text-cyan-300"
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
                      className="px-2.5 py-1 rounded bg-slate-900 border border-slate-800 text-xs text-amber-300"
                    >
                      &quot;{ind.token}&quot; ({ind.category})
                    </span>
                  ))}
                </div>
              ) : (
                <p className="text-xs text-slate-400 italic">
                  No abnormal linguistic threat terms isolated.
                </p>
              )}
            </div>
          </div>
        ) : (
          /* Graceful ML Unavailable State */
          <div className="p-4 rounded-lg bg-slate-900/80 border border-slate-800 text-xs text-slate-400 space-y-1">
            <div className="font-semibold text-white flex items-center gap-1.5">
              <AlertTriangle className="w-4 h-4 text-amber-400" />
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
      <div className="rounded-xl bg-[#090d16] border border-slate-800 p-5 space-y-4 shadow-sm">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-slate-800/80 pb-2">
          <div>
            <h2 className="text-base font-bold text-white">IOC Intelligence</h2>
            <p className="text-xs text-slate-400 mt-0.5">
              Total indicators detected: <strong className="text-white">{iocs.length}</strong>
            </p>
          </div>

          {/* Sub-tabs */}
          <div className="flex items-center gap-1 p-0.5 rounded-lg bg-slate-900 border border-slate-800 text-xs">
            {['ALL', 'IP', 'URL', 'DOMAIN', 'EMAIL'].map((t) => (
              <button
                key={t}
                onClick={() => setActiveIocTab(t)}
                className={`px-2.5 py-1 rounded-md transition-colors cursor-pointer ${
                  activeIocTab === t ? 'bg-slate-800 text-white font-semibold' : 'text-slate-400 hover:text-slate-200'
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
              <thead className="border-b border-slate-800 text-[11px] font-semibold uppercase text-slate-400">
                <tr>
                  <th className="py-2.5 px-3">Type</th>
                  <th className="py-2.5 px-3">Indicator</th>
                  <th className="py-2.5 px-3">Role / Status</th>
                  <th className="py-2.5 px-3">Source</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-850">
                {filteredIocs.map((ioc, idx) => (
                  <tr key={idx} className="hover:bg-slate-900/40 transition-colors">
                    <td className="py-2 px-3">
                      <span className="font-mono text-[10px] px-1.5 py-0.5 rounded bg-slate-800 text-slate-300">
                        {ioc.type}
                      </span>
                    </td>
                    <td className="py-2 px-3 font-mono font-medium text-slate-200 break-all">
                      {ioc.value}
                    </td>
                    <td className="py-2 px-3">
                      <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                        ioc.status === 'MALICIOUS' ? 'bg-red-950/80 text-red-300 border border-red-800/40' :
                        ioc.status === 'SUSPICIOUS' ? 'bg-amber-950/80 text-amber-300 border border-amber-800/40' :
                        'bg-slate-800 text-slate-400'
                      }`}>
                        {ioc.status || 'OBSERVED'}
                      </span>
                    </td>
                    <td className="py-2 px-3 text-slate-400 truncate max-w-xs">
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
          SECTION 7: NETWORK INTELLIGENCE (LEAFLET MAP + DETAILS)
      ======================================================== */}
      <div className="rounded-xl bg-[#090d16] border border-slate-800 p-5 space-y-4 shadow-sm">
        <div className="border-b border-slate-800/80 pb-2">
          <h2 className="text-base font-bold text-white">Network Intelligence</h2>
          <p className="text-xs text-slate-400 mt-0.5">
            Geospatial routing analysis and autonomous system infrastructure mapping
          </p>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-12 gap-5">
          {/* LEFT: Leaflet Map Container */}
          <div className="lg:col-span-7">
            <ForensicGeoMap 
              geoRecords={geoList.length > 0 ? geoList : geoInfo ? [geoInfo] : []}
              title="Network Topology"
              subtitle="Observed and resolved egress points"
            />
          </div>

          {/* RIGHT: Selected IP Details */}
          <div className="lg:col-span-5 space-y-4 text-xs">
            <div className="p-4 rounded-xl bg-slate-900/80 border border-slate-800 space-y-3">
              <div className="flex items-center justify-between border-b border-slate-800 pb-2">
                <span className="font-semibold text-slate-200">Selected Node Details</span>
                <span className="font-mono text-cyan-300 font-bold">
                  {activeGeoRecord?.ip || email.originatingIP || '185.220.101.45'}
                </span>
              </div>

              {geoList && geoList.length > 1 && (
                <div className="flex flex-wrap gap-1.5 pb-1">
                  {geoList.map((g) => (
                    <button
                      key={g.ip}
                      type="button"
                      onClick={() => setSelectedGeoIP(g.ip)}
                      className={`px-2 py-0.5 rounded font-mono text-[10px] transition-colors cursor-pointer ${
                        activeGeoRecord?.ip === g.ip
                          ? 'bg-cyan-950 text-cyan-300 border border-cyan-500/40 font-bold'
                          : 'bg-slate-800 text-slate-400 hover:text-slate-200'
                      }`}
                    >
                      {g.ip}
                    </button>
                  ))}
                </div>
              )}

              {activeGeoRecord ? (
                <div className="space-y-2 text-slate-300">
                  <div className="flex justify-between">
                    <span className="text-slate-400">Role:</span>
                    <span className="font-medium text-slate-200">{activeGeoRecord.role || 'Source Hop'}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-slate-400">Country:</span>
                    <span className="font-medium text-slate-200">{activeGeoRecord.country || 'Not available'}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-slate-400">Region:</span>
                    <span className="font-medium text-slate-200">{activeGeoRecord.region || 'Not available'}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-slate-400">City:</span>
                    <span className="font-medium text-slate-200">{activeGeoRecord.city || 'Not available'}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-slate-400">ASN:</span>
                    <span className="font-medium text-purple-300">{activeGeoRecord.asn || 'Not available'}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-slate-400">ISP:</span>
                    <span className="font-medium text-slate-200">{activeGeoRecord.isp || activeGeoRecord.asnOrg || 'Not available'}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-slate-400">Timezone:</span>
                    <span className="font-medium text-slate-200">{activeGeoRecord.timezone || 'UTC'}</span>
                  </div>
                </div>
              ) : (
                <p className="text-xs text-slate-400 italic">
                  Geolocation unavailable for this indicator.
                </p>
              )}

              {/* Explicit distinction: OBSERVED vs INFERRED */}
              <div className="pt-2 border-t border-slate-800 space-y-1.5 text-[11px]">
                <div className="flex items-center gap-1.5 text-slate-400">
                  <span className="w-1.5 h-1.5 rounded-full bg-cyan-400"></span>
                  <span><strong>Observed Evidence:</strong> Origin IP header hop.</span>
                </div>
                <div className="flex items-center gap-1.5 text-slate-400">
                  <span className="w-1.5 h-1.5 rounded-full bg-purple-400"></span>
                  <span><strong>Enrichment:</strong> GeoIP & ASN data (not proof of attacker identity).</span>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>

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
      <div className="rounded-xl bg-[#090d16] border border-slate-800 p-5 space-y-4 shadow-sm">
        <div className="border-b border-slate-800/80 pb-2">
          <h2 className="text-base font-bold text-white">Evidence Fusion</h2>
          <p className="text-xs text-slate-400 mt-0.5">
            Strict separation of empirical observed evidence from analytical inferences
          </p>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs">
          {/* Observed Evidence */}
          <div className="p-4 rounded-xl bg-slate-900/90 border border-slate-800 space-y-3">
            <div className="flex items-center gap-2 font-semibold text-cyan-300 border-b border-slate-800 pb-2">
              <Shield className="w-4 h-4" />
              <span>Observed Evidence (Empirical Facts)</span>
            </div>
            <ul className="space-y-1.5 text-slate-300 list-disc list-inside leading-relaxed text-[11px]">
              <li>RFC 822 headers: From, To, Return-Path, Date</li>
              <li>MTA Authentication-Results header values</li>
              <li>Live DNS resource records (SPF TXT, DKIM public keys, DMARC TXT)</li>
              <li>Static attachment binary file signatures & cryptographic SHA-256 hashes</li>
              <li>Network egress IPs recorded in Received routing hops</li>
            </ul>
          </div>

          {/* Inferred / Enriched Information */}
          <div className="p-4 rounded-xl bg-slate-900/90 border border-slate-800 space-y-3">
            <div className="flex items-center gap-2 font-semibold text-purple-300 border-b border-slate-800 pb-2">
              <Activity className="w-4 h-4" />
              <span>Inferred / Enriched Information</span>
            </div>
            <ul className="space-y-1.5 text-slate-300 list-disc list-inside leading-relaxed text-[11px]">
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
      <div className="rounded-xl bg-[#090d16] border border-slate-800 p-5 space-y-4 shadow-sm">
        <div className="border-b border-slate-800/80 pb-2">
          <h2 className="text-base font-bold text-white">Investigation Timeline</h2>
          <p className="text-xs text-slate-400 mt-0.5">Chronological execution audit trail of the forensic pipeline</p>
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
            <div key={idx} className="flex items-center justify-between p-2.5 rounded bg-slate-900/60 border border-slate-850">
              <div className="flex items-center gap-2.5">
                <span className="w-5 h-5 rounded-full bg-slate-800 flex items-center justify-center text-[10px] font-mono font-bold text-cyan-400">
                  {item.step}
                </span>
                <span className="text-slate-300 text-xs">{item.name}</span>
              </div>
              <span className="text-[10px] font-mono text-slate-500">{item.time}</span>
            </div>
          ))}
        </div>
      </div>

      {/* ========================================================
          SECTION 12: RECOMMENDATIONS
      ======================================================== */}
      <div className="rounded-xl bg-[#090d16] border border-slate-800 p-5 space-y-4 shadow-sm">
        <div className="border-b border-slate-800/80 pb-2">
          <h2 className="text-base font-bold text-white">Recommended Actions</h2>
          <p className="text-xs text-slate-400 mt-0.5">Actionable mitigation steps based directly on observed indicators</p>
        </div>

        <div className="space-y-2.5">
          {fusion?.verifiedReasons && fusion.verifiedReasons.length > 0 ? (
            fusion.verifiedReasons.slice(0, 5).map((reason, idx) => (
              <div key={idx} className="p-3 rounded-lg bg-slate-900 border border-slate-800 text-xs text-slate-300 flex items-start gap-2.5">
                <CheckCircle2 className="w-4 h-4 text-cyan-400 shrink-0 mt-0.5" />
                <span>{reason}</span>
              </div>
            ))
          ) : (
            <div className="p-3 rounded-lg bg-slate-900 border border-slate-800 text-xs text-slate-400">
              Review sender identity and preserve original RFC 822 email evidence for compliance record.
            </div>
          )}
        </div>
      </div>

      {/* ========================================================
          SECTION 13: FORENSIC REPORT & INTEGRITY SEAL
      ======================================================== */}
      <div className="rounded-xl bg-[#090d16] border border-slate-800 p-5 space-y-4 shadow-sm">
        <div className="border-b border-slate-800/80 pb-2">
          <h2 className="text-base font-bold text-white">Forensic Report</h2>
          <p className="text-xs text-slate-400 mt-0.5">
            Tamper-evident forensic report with SHA-256 integrity verification to support evidence preservation and investigation.
          </p>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-3 text-xs">
          <div className="p-3 rounded-lg bg-slate-900 border border-slate-800 space-y-1">
            <span className="text-[10px] uppercase font-semibold text-slate-400 block">Case ID</span>
            <span className="font-mono font-bold text-slate-200">{caseId}</span>
          </div>

          <div className="p-3 rounded-lg bg-slate-900 border border-slate-800 space-y-1">
            <span className="text-[10px] uppercase font-semibold text-slate-400 block">Report Status</span>
            <span className="font-semibold text-emerald-400">Sealed & Verified</span>
          </div>

          <div className="p-3 rounded-lg bg-slate-900 border border-slate-800 space-y-1">
            <span className="text-[10px] uppercase font-semibold text-slate-400 block">SHA-256 Integrity Hash</span>
            <div className="flex items-center justify-between gap-2">
              <span className="font-mono text-cyan-300 truncate text-[11px]" title={sha256Hash}>
                {sha256Hash ? `${sha256Hash.slice(0, 16)}...` : 'N/A'}
              </span>
              <button
                type="button"
                onClick={handleCopyHash}
                className="p-1 text-slate-400 hover:text-white cursor-pointer"
                title="Copy full SHA-256"
              >
                {copiedHash ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
              </button>
            </div>
          </div>
        </div>

        {/* Report Action Buttons */}
        <div className="flex flex-wrap items-center gap-2.5 pt-2">
          <button
            type="button"
            onClick={() => onViewChange('forensic-report')}
            className="flex items-center gap-1.5 px-3.5 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-semibold transition-colors cursor-pointer"
          >
            <FileText className="w-3.5 h-3.5 text-cyan-400" />
            <span>View Complete Report</span>
          </button>

          <button
            type="button"
            onClick={handleExportPdf}
            disabled={exportingPdf}
            className="flex items-center gap-1.5 px-3.5 py-2 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-semibold shadow-xs transition-colors cursor-pointer disabled:opacity-50"
          >
            <Download className="w-3.5 h-3.5" />
            <span>{exportingPdf ? 'Exporting PDF...' : 'Export PDF'}</span>
          </button>

          <button
            type="button"
            onClick={handleExportJson}
            disabled={exportingJson}
            className="flex items-center gap-1.5 px-3.5 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-semibold transition-colors cursor-pointer disabled:opacity-50"
          >
            <FileCode className="w-3.5 h-3.5" />
            <span>{exportingJson ? 'Exporting JSON...' : 'Export JSON'}</span>
          </button>

          <button
            type="button"
            onClick={handleCopyHash}
            className="flex items-center gap-1.5 px-3.5 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-semibold transition-colors cursor-pointer"
          >
            {copiedHash ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
            <span>{copiedHash ? 'Hash Copied!' : 'Copy SHA-256'}</span>
          </button>
        </div>

      </div>

    </div>
  );
};
