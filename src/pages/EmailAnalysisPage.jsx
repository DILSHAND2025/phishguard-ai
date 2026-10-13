import React, { useState, useRef } from 'react';
import { 
  UploadCloud, 
  CheckCircle2, 
  AlertTriangle, 
  ShieldCheck, 
  Download, 
  ArrowRight, 
  Trash2, 
  Loader2, 
  RefreshCw,
  FileText,
  Clock,
  XCircle
} from 'lucide-react';
import { buildForensicReport } from '../services/forensicReportService';
import { generateForensicPdf, downloadPdfInBrowser } from '../services/pdfBuilder';
import { getExplainableDiagnosticChecks } from '../services/diagnosticHelper';

const ANALYSIS_STEPS = [
  { id: 'reading', label: 'Reading email & computing SHA-256' },
  { id: 'headers', label: 'Extracting headers & sender identity' },
  { id: 'threat', label: 'Running ML intent detection' },
  { id: 'network', label: 'Checking network indicators & GeoIP' },
  { id: 'auth', label: 'Checking SPF, DKIM, and DMARC' },
  { id: 'assessment', label: 'Synthesizing evidence fusion & saving case' }
];

export const EmailAnalysisPage = ({ onViewChange, currentAnalysis, onRunAnalysis, onRetrySave }) => {
  // Input mode: 'eml' | 'headers' | 'url' | 'raw'
  const [activeTab, setActiveTab] = useState('eml');
  
  // File state
  const [selectedFile, setSelectedFile] = useState(null);
  const [fileContent, setFileContent] = useState('');
  const [isDragOver, setIsDragOver] = useState(false);
  const [fileError, setFileError] = useState(null);

  // Alternative input state
  const [headerInput, setHeaderInput] = useState('');
  const [urlInput, setUrlInput] = useState('');
  const [rawInput, setRawInput] = useState('');

  // Analysis / Loading state: 'idle' | 'queued' | 'analyzing' | 'completed' | 'failed'
  const [analysisStatus, setAnalysisStatus] = useState(currentAnalysis ? 'completed' : 'idle');
  const [currentStepIndex, setCurrentStepIndex] = useState(-1);
  const [isDownloadingPdf, setIsDownloadingPdf] = useState(false);
  const [isRetryingSave, setIsRetryingSave] = useState(false);
  const [activeLedgerTab, setActiveLedgerTab] = useState('ALL');

  const fileInputRef = useRef(null);

  // Core execution runner that coordinates states
  const executeAnalysis = async (payloadToAnalyze) => {
    if (!payloadToAnalyze) return;
    setFileError(null);
    setAnalysisStatus('analyzing');
    setCurrentStepIndex(0);

    const stepInterval = setInterval(() => {
      setCurrentStepIndex(prev => {
        if (prev < ANALYSIS_STEPS.length - 1) return prev + 1;
        return prev;
      });
    }, 280);

    try {
      if (onRunAnalysis) {
        await onRunAnalysis(payloadToAnalyze);
      }
      clearInterval(stepInterval);
      setCurrentStepIndex(ANALYSIS_STEPS.length);
      setAnalysisStatus('completed');
    } catch (err) {
      clearInterval(stepInterval);
      setAnalysisStatus('failed');
      setFileError('Analysis error: ' + (err.message || 'Failed to analyze email.'));
    }
  };

  // Handle file drop/selection with automatic triggering
  const processFile = (file) => {
    if (!file) return;
    setFileError(null);

    // Limit to 10 MB as requested
    const MAX_SIZE_BYTES = 10 * 1024 * 1024;
    if (file.size > MAX_SIZE_BYTES) {
      setFileError('File exceeds the maximum limit of 10 MB.');
      return;
    }

    const reader = new FileReader();
    reader.onerror = () => {
      setFileError('Could not read file. Please ensure it is accessible.');
      setAnalysisStatus('failed');
    };
    reader.onload = (e) => {
      const text = e.target?.result;
      if (!text || typeof text !== 'string' || !text.trim()) {
        setFileError('The selected file appears to be empty.');
        setAnalysisStatus('failed');
        return;
      }
      setSelectedFile({
        name: file.name,
        size: (file.size / 1024).toFixed(1) + ' KB'
      });
      setFileContent(text);

      // Auto-trigger analysis immediately on file selection/drop
      setAnalysisStatus('queued');
      setTimeout(() => {
        executeAnalysis(text);
      }, 400);
    };
    reader.readAsText(file);
  };

  const handleFileChange = (e) => {
    const file = e.target.files?.[0];
    if (file) processFile(file);
    e.target.value = '';
  };

  const handleDragOver = (e) => {
    e.preventDefault();
    setIsDragOver(true);
  };

  const handleDragLeave = (e) => {
    e.preventDefault();
    setIsDragOver(false);
  };

  const handleDrop = (e) => {
    e.preventDefault();
    setIsDragOver(false);
    const file = e.dataTransfer.files?.[0];
    if (file) processFile(file);
  };

  const handleRemoveFile = () => {
    setSelectedFile(null);
    setFileContent('');
    setFileError(null);
    setAnalysisStatus('idle');
  };

  // Run analysis pipeline manually for alternative tabs or retry
  const handleStartAnalysis = async () => {
    let payloadToAnalyze = null;

    if (activeTab === 'eml') {
      if (!fileContent) {
        if (fileInputRef.current) fileInputRef.current.click();
        return;
      }
      payloadToAnalyze = fileContent;
    } else if (activeTab === 'headers') {
      if (!headerInput.trim()) {
        setFileError('Please paste email headers first.');
        return;
      }
      payloadToAnalyze = headerInput.trim();
    } else if (activeTab === 'url') {
      if (!urlInput.trim()) {
        setFileError('Please enter a suspicious URL.');
        return;
      }
      // Wrap URL in RFC 822 format so full parser and extractors process it
      payloadToAnalyze = `From: submission@user-inbox.local\nTo: analyst@maverick.security\nSubject: Suspicious URL Analysis\n\nSuspicious Link: ${urlInput.trim()}`;
    } else if (activeTab === 'raw') {
      if (!rawInput.trim()) {
        setFileError('Please paste raw email content.');
        return;
      }
      payloadToAnalyze = rawInput.trim();
    }

    setAnalysisStatus('queued');
    setTimeout(() => {
      executeAnalysis(payloadToAnalyze);
    }, 350);
  };

  const handleDownloadReport = async () => {
    if (!currentAnalysis) return;
    try {
      setIsDownloadingPdf(true);
      const report = await buildForensicReport(currentAnalysis);
      const pdfBytes = generateForensicPdf(report);
      downloadPdfInBrowser(pdfBytes, `${report.caseId || 'MAVERICK'}-Security-Report.pdf`);
    } catch (err) {
      console.error('PDF export failed:', err);
      alert('Unable to generate PDF report: ' + err.message);
    } finally {
      setIsDownloadingPdf(false);
    }
  };

  const handleResetForNewAnalysis = () => {
    setSelectedFile(null);
    setFileContent('');
    setHeaderInput('');
    setUrlInput('');
    setRawInput('');
    setAnalysisStatus('idle');
    setCurrentStepIndex(-1);
    setFileError(null);
  };

  // Derive findings for the result view from actual analysis data
  const score = currentAnalysis?.fusion?.threatScore ?? 0;
  const rawRisk = (currentAnalysis?.fusion?.riskLevel || 'LOW').toUpperCase();
  const caseId = currentAnalysis?.caseItem?.caseId || currentAnalysis?.caseId || 'MAV-2026-00000000';
  const classification = currentAnalysis?.aiThreat?.classification || currentAnalysis?.classification || (score >= 80 ? 'Credential Phishing' : score >= 60 ? 'Suspicious Impersonation' : score >= 30 ? 'Suspicious Email' : 'Legitimate Communication');

  // Format risk level display with clean light-theme badges
  let riskBadgeColor = 'bg-emerald-50 border-emerald-200 text-emerald-700';
  let riskDotColor = 'bg-emerald-500';
  let riskLabel = 'LOW';
  let threatNarrative = 'No significant security threats were detected. The email appears consistent with safe communication.';

  if (rawRisk === 'CRITICAL' || score >= 80) {
    riskBadgeColor = 'bg-red-50 border-red-200 text-red-700';
    riskDotColor = 'bg-red-500';
    riskLabel = 'CRITICAL';
    threatNarrative = 'MAVERICK detected critical attack vectors. High confidence malicious indicators identified.';
  } else if (rawRisk === 'HIGH' || score >= 60) {
    riskBadgeColor = 'bg-orange-50 border-orange-200 text-orange-700';
    riskDotColor = 'bg-orange-500';
    riskLabel = 'HIGH';
    threatNarrative = 'MAVERICK detected multiple suspicious indicators. Caution is strongly advised.';
  } else if (rawRisk === 'SUSPICIOUS' || rawRisk === 'MEDIUM' || score >= 30) {
    riskBadgeColor = 'bg-amber-50 border-amber-200 text-amber-800';
    riskDotColor = 'bg-amber-500';
    riskLabel = 'MEDIUM';
    threatNarrative = 'MAVERICK detected anomalies in sender authentication or link structure.';
  }

  // Extract explainable diagnostic verification ledger from real evidence (zero fabrication)
  const diagnostic = getExplainableDiagnosticChecks(currentAnalysis);
  const { failedChecks, passedChecks, unavailableChecks, skippedChecks, flaggedReasons } = diagnostic;
  const allChecks = [
    ...failedChecks,
    ...passedChecks,
    ...unavailableChecks,
    ...skippedChecks
  ];
  const displayedChecks = activeLedgerTab === 'ALL'
    ? allChecks
    : activeLedgerTab === 'FAILED'
      ? failedChecks
      : activeLedgerTab === 'PASSED'
        ? passedChecks
        : activeLedgerTab === 'UNAVAILABLE'
          ? unavailableChecks
          : skippedChecks;

  return (
    <div className="max-w-3xl mx-auto py-6 sm:py-10 px-4 space-y-8 font-sans">
      
      {/* Hidden file input */}
      <input
        type="file"
        ref={fileInputRef}
        onChange={handleFileChange}
        accept=".eml,.EML,.msg,.MSG,.txt,message/rfc822,text/plain"
        className="hidden"
      />

      {/* QUEUED STATE */}
      {analysisStatus === 'queued' && (
        <div className="rounded-xl bg-white border border-slate-200 p-8 sm:p-12 text-center space-y-5 shadow-xs">
          <div className="relative w-14 h-14 mx-auto flex items-center justify-center">
            <div className="w-12 h-12 rounded-full bg-cyan-50 border border-cyan-200 flex items-center justify-center text-cyan-700 animate-pulse">
              <Clock className="w-6 h-6" />
            </div>
          </div>
          <div>
            <span className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-[11px] font-mono font-semibold bg-cyan-50 text-cyan-800 border border-cyan-200 mb-2">
              <span className="w-2 h-2 rounded-full bg-cyan-600 animate-ping"></span>
              PROCESSING STATE: QUEUED
            </span>
            <h2 className="text-xl font-bold text-slate-900 tracking-tight">Queued for Multi-Layer Analysis</h2>
            <p className="text-xs text-slate-500 mt-1 max-w-sm mx-auto">
              Email payload received, hash computed, and scheduled for execution across forensic, ML, and DNS verification layers.
            </p>
          </div>
        </div>
      )}

      {/* FAILED STATE */}
      {analysisStatus === 'failed' && (
        <div className="rounded-xl bg-white border border-red-200 p-8 sm:p-10 text-center space-y-5 shadow-xs">
          <div className="w-14 h-14 mx-auto rounded-full bg-red-50 border border-red-200 flex items-center justify-center text-red-600">
            <XCircle className="w-7 h-7" />
          </div>
          <div>
            <span className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-[11px] font-mono font-semibold bg-red-50 text-red-700 border border-red-200 mb-2">
              PROCESSING STATE: FAILED
            </span>
            <h2 className="text-xl font-bold text-slate-900 tracking-tight">Analysis Failed</h2>
            <p className="text-xs text-red-600 mt-1 max-w-md mx-auto">
              {fileError || 'The forensic pipeline encountered an unexpected error while processing the email.'}
            </p>
          </div>
          <div className="flex flex-wrap items-center justify-center gap-2.5 pt-2">
            <button
              onClick={() => {
                if (fileContent) {
                  executeAnalysis(fileContent);
                } else {
                  handleStartAnalysis();
                }
              }}
              className="px-4 py-2 rounded-lg bg-slate-900 hover:bg-slate-800 text-white text-xs font-semibold shadow-xs transition-colors cursor-pointer flex items-center gap-1.5"
            >
              <RefreshCw className="w-3.5 h-3.5" />
              <span>Retry Analysis</span>
            </button>
            <button
              onClick={handleResetForNewAnalysis}
              className="px-4 py-2 rounded-lg bg-white hover:bg-slate-50 border border-slate-200 text-slate-700 text-xs font-semibold shadow-2xs transition-colors cursor-pointer"
            >
              Choose Another Email
            </button>
          </div>
        </div>
      )}

      {/* 1. LOADING STATE */}
      {analysisStatus === 'analyzing' && (
        <div className="rounded-xl bg-white border border-slate-200 p-8 sm:p-12 text-center space-y-6 shadow-xs">
          <div className="relative w-16 h-16 mx-auto flex items-center justify-center">
            <div className="absolute inset-0 rounded-full border-3 border-slate-200 border-t-slate-800 animate-spin"></div>
            <ShieldCheck className="w-8 h-8 text-slate-800" />
          </div>

          <div>
            <h2 className="text-xl font-bold text-slate-900 tracking-tight">Analyzing your email...</h2>
            <p className="text-xs text-slate-500 mt-1">
              Executing multi-layer threat detection and forensic verification
            </p>
          </div>

          {/* Staged Checklist */}
          <div className="max-w-sm mx-auto space-y-2.5 text-left pt-2">
            {ANALYSIS_STEPS.map((step, idx) => {
              const isDone = currentStepIndex > idx;
              const isCurrent = currentStepIndex === idx;

              return (
                <div key={step.id} className="flex items-center gap-3 text-xs">
                  {isDone ? (
                    <CheckCircle2 className="w-4 h-4 text-emerald-600 shrink-0" />
                  ) : isCurrent ? (
                    <span className="w-4 h-4 flex items-center justify-center">
                      <span className="w-2 h-2 rounded-full bg-slate-900 animate-ping"></span>
                    </span>
                  ) : (
                    <span className="w-4 h-4 flex items-center justify-center">
                      <span className="w-2 h-2 rounded-full bg-slate-300"></span>
                    </span>
                  )}
                  <span className={`transition-colors ${
                    isDone ? 'text-slate-800 font-medium' : isCurrent ? 'text-slate-900 font-bold' : 'text-slate-400'
                  }`}>
                    {step.label}
                  </span>
                </div>
              );
            })}
          </div>
        </div>
      )}

      {/* 2. COMPLETED USER RESULT STATE */}
      {analysisStatus === 'completed' && currentAnalysis && (
        <div className="space-y-6">
          
          {/* Result Header */}
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-slate-200 pb-4">
            <div>
              <h1 className="text-2xl font-bold text-slate-900 tracking-tight">Email Security Result</h1>
              <div className="flex items-center gap-2 mt-1">
                <span className="text-xs font-mono text-slate-500">Case ID: <strong className="text-slate-800 font-semibold">{caseId}</strong></span>
                {currentAnalysis.isSaved ? (
                  <span className="text-[10px] font-mono px-2 py-0.5 rounded-full bg-emerald-50 border border-emerald-200 text-emerald-700 font-medium">
                    Saved to Database
                  </span>
                ) : null}
              </div>
            </div>

            <button
              onClick={handleResetForNewAnalysis}
              className="self-start sm:self-auto flex items-center gap-1.5 px-3.5 py-1.5 rounded-lg bg-white border border-slate-200 hover:bg-slate-50 text-xs font-medium text-slate-700 transition-colors shadow-2xs cursor-pointer"
            >
              <RefreshCw className="w-3.5 h-3.5 text-slate-500" />
              <span>Check Another Email</span>
            </button>
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

          {/* Main Threat Card */}
          <div className="rounded-xl bg-white border border-slate-200 p-6 sm:p-8 space-y-6 shadow-xs">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-slate-100 pb-6">
              <div>
                <div className="flex items-center gap-2">
                  <span className="text-xs font-semibold uppercase tracking-wider text-slate-500">
                    THREAT ASSESSMENT
                  </span>
                  {(currentAnalysis?.fusion?.isIncomplete || !currentAnalysis?.aiThreat?.isMlAvailable) && (
                    <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-amber-50 text-amber-800 border border-amber-200">
                      INCOMPLETE (ML OFFLINE)
                    </span>
                  )}
                </div>
                <div className="flex items-baseline gap-2 mt-1.5">
                  <span className="text-4xl sm:text-5xl font-extrabold text-slate-900 tracking-tight">
                    {score}
                  </span>
                  <span className="text-slate-400 text-lg font-medium">/ 100</span>
                </div>
              </div>

              <div className="flex flex-col sm:items-end gap-1.5">
                <div className={`inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg border text-xs font-bold tracking-wide uppercase ${riskBadgeColor}`}>
                  <span className={`w-2 h-2 rounded-full ${riskDotColor}`}></span>
                  <span>{riskLabel}</span>
                </div>
                <div className="text-xs font-medium text-slate-600">
                  Classification: <strong className="text-slate-900 font-semibold">{classification}</strong>
                </div>
                {(currentAnalysis?.fusion?.isIncomplete || !currentAnalysis?.aiThreat?.isMlAvailable) && (
                  <div className="text-[11px] text-amber-700 font-medium">
                    Score reflects forensics only; ML inference is offline.
                  </div>
                )}
              </div>
            </div>

            <div className="bg-slate-50 rounded-lg p-4 border border-slate-100">
              <p className="text-sm text-slate-700 leading-relaxed font-normal">
                {threatNarrative}
              </p>
            </div>

            {/* Why was it flagged? */}
            <div className="space-y-3 pt-1">
              <h3 className="text-xs font-bold uppercase tracking-wider text-slate-500">
                Why was this email flagged?
              </h3>

              {flaggedReasons.length > 0 ? (
                <div className="space-y-2.5">
                  {flaggedReasons.map((reason, idx) => (
                    <div 
                      key={idx} 
                      className="p-3.5 rounded-lg bg-white border border-slate-200 flex items-start gap-3 shadow-2xs"
                    >
                      <AlertTriangle className="w-4 h-4 text-amber-500 shrink-0 mt-0.5" />
                      <div>
                        <div className="text-xs font-semibold text-slate-900">{reason.title}</div>
                        <div className="text-xs text-slate-600 mt-0.5">{reason.detail}</div>
                      </div>
                    </div>
                  ))}
                </div>
              ) : (
                <div className="p-4 rounded-lg bg-emerald-50 border border-emerald-200 text-xs text-emerald-800 flex items-center gap-2.5">
                  <CheckCircle2 className="w-4 h-4 text-emerald-600 shrink-0" />
                  <span>No suspicious indicators detected. Email conforms to expected legitimate standards.</span>
                </div>
              )}
            </div>

            {/* Explainable Verification Checks Matrix (Failed, Passed, Unavailable, Not Performed) */}
            <div className="space-y-3 pt-3 border-t border-slate-100">
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                <div>
                  <h3 className="text-xs font-bold uppercase tracking-wider text-slate-500">
                    Forensic Verification Ledger
                  </h3>
                  <p className="text-[11px] text-slate-400">
                    Transparent classification of empirical findings, active tests, and service telemetry
                  </p>
                </div>

                {/* Filter Pills */}
                <div className="flex items-center gap-1 bg-slate-100 p-0.5 rounded-lg text-[11px] font-mono flex-wrap">
                  <button
                    onClick={() => setActiveLedgerTab('ALL')}
                    className={`px-2.5 py-1 rounded-md transition-colors cursor-pointer ${
                      activeLedgerTab === 'ALL' ? 'bg-white font-bold text-slate-900 shadow-2xs' : 'text-slate-600 hover:text-slate-900'
                    }`}
                  >
                    All ({allChecks.length})
                  </button>
                  <button
                    onClick={() => setActiveLedgerTab('FAILED')}
                    className={`px-2.5 py-1 rounded-md transition-colors cursor-pointer ${
                      activeLedgerTab === 'FAILED' ? 'bg-red-50 text-red-700 font-bold border border-red-200' : 'text-slate-600 hover:text-red-700'
                    }`}
                  >
                    Failed ({failedChecks.length})
                  </button>
                  <button
                    onClick={() => setActiveLedgerTab('PASSED')}
                    className={`px-2.5 py-1 rounded-md transition-colors cursor-pointer ${
                      activeLedgerTab === 'PASSED' ? 'bg-emerald-50 text-emerald-700 font-bold border border-emerald-200' : 'text-slate-600 hover:text-emerald-700'
                    }`}
                  >
                    Passed ({passedChecks.length})
                  </button>
                  <button
                    onClick={() => setActiveLedgerTab('UNAVAILABLE')}
                    className={`px-2.5 py-1 rounded-md transition-colors cursor-pointer ${
                      activeLedgerTab === 'UNAVAILABLE' ? 'bg-amber-50 text-amber-800 font-bold border border-amber-200' : 'text-slate-600 hover:text-amber-700'
                    }`}
                  >
                    Unavailable ({unavailableChecks.length})
                  </button>
                  <button
                    onClick={() => setActiveLedgerTab('SKIPPED')}
                    className={`px-2.5 py-1 rounded-md transition-colors cursor-pointer ${
                      activeLedgerTab === 'SKIPPED' ? 'bg-slate-200 font-bold text-slate-800' : 'text-slate-500 hover:text-slate-800'
                    }`}
                  >
                    Not Run ({skippedChecks.length})
                  </button>
                </div>
              </div>

              {/* Check items list */}
              <div className="space-y-2 mt-2">
                {displayedChecks.map((chk, cIdx) => {
                  const isFailed = chk.status === 'FAILED';
                  const isPassed = chk.status === 'PASSED';
                  const isUnavail = chk.status === 'UNAVAILABLE';

                  return (
                    <div
                      key={chk.id || cIdx}
                      className={`p-3 rounded-lg border text-xs transition-colors ${
                        isFailed 
                          ? 'bg-red-50/30 border-red-200' 
                          : isPassed 
                            ? 'bg-emerald-50/20 border-emerald-100' 
                            : isUnavail
                              ? 'bg-amber-50/20 border-amber-200'
                              : 'bg-slate-50 border-slate-200'
                      }`}
                    >
                      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-1.5 mb-1">
                        <div className="flex items-center gap-2">
                          <span className={`text-[10px] font-mono px-1.5 py-0.5 rounded font-bold uppercase ${
                            isFailed ? 'bg-red-100 text-red-700' :
                            isPassed ? 'bg-emerald-100 text-emerald-700' :
                            isUnavail ? 'bg-amber-100 text-amber-800' :
                            'bg-slate-200 text-slate-700'
                          }`}>
                            {chk.status === 'NOT_PERFORMED' ? 'NOT PERFORMED' : chk.status}
                          </span>
                          <span className="font-semibold text-slate-900">{chk.title}</span>
                          <span className="text-[10px] text-slate-400 font-mono hidden sm:inline">({chk.layer})</span>
                        </div>

                        <div className="flex items-center gap-2">
                          {chk.severity && (
                            <span className={`text-[10px] font-mono font-bold px-1.5 py-0.5 rounded ${
                              chk.severity === 'CRITICAL' ? 'bg-red-100 text-red-800' :
                              chk.severity === 'HIGH' ? 'bg-orange-100 text-orange-800' :
                              'bg-amber-100 text-amber-800'
                            }`}>
                              {chk.severity}
                            </span>
                          )}
                          {typeof chk.confidence === 'number' && (
                            <span className="text-[10px] text-slate-500 font-mono">
                              {chk.confidence}% Conf.
                            </span>
                          )}
                        </div>
                      </div>

                      <p className="text-[11px] text-slate-600 leading-relaxed mt-1">
                        {chk.details || chk.reason}
                      </p>
                    </div>
                  );
                })}
              </div>
            </div>

            {/* Action buttons as specified */}
            <div className="flex flex-col sm:flex-row items-center gap-3 pt-4 border-t border-slate-100">
              <button
                onClick={() => onViewChange('security-analyzer')}
                className="w-full sm:w-auto flex-1 flex items-center justify-center gap-2 px-5 py-2.5 rounded-lg bg-slate-900 hover:bg-slate-800 text-white text-xs font-semibold shadow-xs transition-colors cursor-pointer"
              >
                <span>View Full Investigation</span>
                <ArrowRight className="w-4 h-4" />
              </button>

              <button
                onClick={() => onViewChange('reports')}
                className="w-full sm:w-auto flex items-center justify-center gap-2 px-4 py-2.5 rounded-lg bg-white hover:bg-slate-50 border border-slate-200 text-xs font-semibold text-slate-700 transition-colors shadow-2xs cursor-pointer"
              >
                <FileText className="w-4 h-4 text-slate-500" />
                <span>View Forensic Report</span>
              </button>

              <button
                onClick={handleDownloadReport}
                disabled={isDownloadingPdf}
                className="w-full sm:w-auto flex items-center justify-center gap-2 px-4 py-2.5 rounded-lg bg-white hover:bg-slate-50 border border-slate-200 text-xs font-semibold text-slate-700 transition-colors shadow-2xs cursor-pointer disabled:opacity-50"
              >
                {isDownloadingPdf ? (
                  <Loader2 className="w-4 h-4 animate-spin text-slate-600" />
                ) : (
                  <Download className="w-4 h-4 text-slate-500" />
                )}
                <span>Export PDF</span>
              </button>
            </div>

          </div>

        </div>
      )}

      {/* 3. INPUT / UPLOAD FORM (IDLE STATE) */}
      {analysisStatus === 'idle' && (
        <div className="space-y-6">
          
          {/* Welcome Header */}
          <div className="text-center space-y-2">
            <h1 className="text-2xl sm:text-3xl font-bold text-slate-900 tracking-tight">
              Analyze a Suspicious Email
            </h1>
            <p className="text-sm text-slate-500 max-w-lg mx-auto">
              Upload an RFC 822 .EML message for automated forensics, AI classification, and multi-protocol verification.
            </p>
          </div>

          {/* Primary Upload Card */}
          <div className="rounded-xl bg-white border border-slate-200 p-6 sm:p-8 space-y-5 shadow-xs">
            <div className="flex items-center justify-between border-b border-slate-100 pb-3">
              <div>
                <h2 className="text-sm font-bold text-slate-900">Upload .EML</h2>
                <p className="text-xs text-slate-500 mt-0.5">
                  Select or drag-and-drop the raw message export
                </p>
              </div>
              <span className="text-xs font-medium text-slate-400">Max size 10 MB</span>
            </div>

            {/* Error banner if any */}
            {fileError && (
              <div className="p-3.5 rounded-lg bg-red-50 border border-red-200 text-xs text-red-700 flex items-center gap-2">
                <AlertTriangle className="w-4 h-4 shrink-0 text-red-500" />
                <span>{fileError}</span>
              </div>
            )}

            {/* Drag & Drop or Uploaded File state */}
            {!selectedFile ? (
              <div
                onDragOver={handleDragOver}
                onDragLeave={handleDragLeave}
                onDrop={handleDrop}
                onClick={() => fileInputRef.current?.click()}
                className={`border-2 border-dashed rounded-xl p-8 sm:p-12 text-center transition-all cursor-pointer ${
                  isDragOver 
                    ? 'border-slate-800 bg-slate-50' 
                    : 'border-slate-300 hover:border-slate-400 bg-slate-50/50 hover:bg-slate-50'
                }`}
              >
                <div className="w-12 h-12 mx-auto rounded-full bg-white border border-slate-200 flex items-center justify-center text-slate-700 mb-3 shadow-2xs">
                  <UploadCloud className="w-6 h-6" />
                </div>
                <div className="text-sm font-semibold text-slate-800">
                  Drag & Drop .EML file here
                </div>
                <div className="text-xs text-slate-400 mt-1">or</div>
                <div className="mt-3 inline-block px-4 py-2 rounded-lg bg-white hover:bg-slate-50 text-xs font-semibold text-slate-700 border border-slate-200 shadow-2xs transition-colors">
                  Browse File
                </div>
                <div className="text-[11px] text-slate-400 mt-3">
                  Supports RFC 822 format (.eml, .msg, .txt)
                </div>
              </div>
            ) : (
              /* Uploaded File State */
              <div className="p-4 rounded-xl bg-slate-50 border border-slate-200 flex items-center justify-between gap-3">
                <div className="flex items-center gap-3 min-w-0">
                  <div className="w-9 h-9 rounded-lg bg-emerald-50 border border-emerald-200 text-emerald-600 flex items-center justify-center shrink-0">
                    <CheckCircle2 className="w-5 h-5" />
                  </div>
                  <div className="min-w-0">
                    <div className="text-xs font-semibold text-slate-900 truncate">{selectedFile.name}</div>
                    <div className="text-[11px] text-slate-500 mt-0.5">
                      {selectedFile.size} • <span className="text-emerald-600 font-medium">Ready for investigation</span>
                    </div>
                  </div>
                </div>

                <div className="flex items-center gap-2 shrink-0">
                  <button
                    onClick={handleRemoveFile}
                    className="p-1.5 rounded-lg text-slate-400 hover:text-red-600 hover:bg-white border border-transparent hover:border-slate-200 transition-colors cursor-pointer"
                    title="Remove file"
                  >
                    <Trash2 className="w-4 h-4" />
                  </button>
                </div>
              </div>
            )}

            {/* Primary Action Button */}
            <button
              onClick={handleStartAnalysis}
              className="w-full py-3 rounded-lg bg-slate-900 hover:bg-slate-800 text-white text-xs font-semibold shadow-xs transition-colors cursor-pointer flex items-center justify-center gap-2"
            >
              <span>Analyze Email</span>
              <ArrowRight className="w-4 h-4" />
            </button>
          </div>

          {/* Alternative Inputs Section */}
          <div className="rounded-xl bg-white border border-slate-200 p-5 sm:p-6 space-y-4 shadow-xs">
            <div>
              <h3 className="text-xs font-bold uppercase tracking-wider text-slate-500">
                Alternative Ingestion Modes
              </h3>
            </div>

            {/* Sub-tabs */}
            <div className="flex items-center gap-2 border-b border-slate-100 pb-2">
              <button
                onClick={() => { setActiveTab('headers'); setFileError(null); }}
                className={`px-3 py-1.5 rounded-lg text-xs font-semibold transition-colors cursor-pointer ${
                  activeTab === 'headers' ? 'bg-slate-900 text-white' : 'text-slate-600 hover:text-slate-900 hover:bg-slate-100'
                }`}
              >
                Email Headers
              </button>
              <button
                onClick={() => { setActiveTab('url'); setFileError(null); }}
                className={`px-3 py-1.5 rounded-lg text-xs font-semibold transition-colors cursor-pointer ${
                  activeTab === 'url' ? 'bg-slate-900 text-white' : 'text-slate-600 hover:text-slate-900 hover:bg-slate-100'
                }`}
              >
                Suspicious URL
              </button>
              <button
                onClick={() => { setActiveTab('raw'); setFileError(null); }}
                className={`px-3 py-1.5 rounded-lg text-xs font-semibold transition-colors cursor-pointer ${
                  activeTab === 'raw' ? 'bg-slate-900 text-white' : 'text-slate-600 hover:text-slate-900 hover:bg-slate-100'
                }`}
              >
                Raw Message
              </button>
            </div>

            {/* Email Header Tab */}
            {activeTab === 'headers' && (
              <div className="space-y-3">
                <textarea
                  value={headerInput}
                  onChange={(e) => setHeaderInput(e.target.value)}
                  placeholder="Paste RFC 822 email headers here (Received, From, To, Authentication-Results, etc.)..."
                  rows={4}
                  className="w-full p-3 rounded-lg bg-slate-50 border border-slate-200 text-xs font-mono text-slate-900 placeholder-slate-400 focus:outline-none focus:bg-white focus:border-slate-400 transition-colors resize-y"
                />
                <button
                  onClick={handleStartAnalysis}
                  className="px-4 py-2 rounded-lg bg-slate-900 hover:bg-slate-800 text-xs font-semibold text-white transition-colors cursor-pointer"
                >
                  Analyze Headers
                </button>
              </div>
            )}

            {/* URL Tab */}
            {activeTab === 'url' && (
              <div className="space-y-3">
                <div className="flex items-center gap-2">
                  <input
                    type="url"
                    value={urlInput}
                    onChange={(e) => setUrlInput(e.target.value)}
                    placeholder="https://example-suspicious-login.com"
                    className="flex-1 p-2.5 rounded-lg bg-slate-50 border border-slate-200 text-xs font-mono text-slate-900 placeholder-slate-400 focus:outline-none focus:bg-white focus:border-slate-400 transition-colors"
                  />
                  <button
                    onClick={handleStartAnalysis}
                    className="px-4 py-2.5 rounded-lg bg-slate-900 hover:bg-slate-800 text-xs font-semibold text-white transition-colors cursor-pointer shrink-0"
                  >
                    Analyze URL
                  </button>
                </div>
              </div>
            )}

            {/* Raw Email Tab */}
            {activeTab === 'raw' && (
              <div className="space-y-3">
                <textarea
                  value={rawInput}
                  onChange={(e) => setRawInput(e.target.value)}
                  placeholder="Paste complete raw email RFC 822 payload here..."
                  rows={5}
                  className="w-full p-3 rounded-lg bg-slate-50 border border-slate-200 text-xs font-mono text-slate-900 placeholder-slate-400 focus:outline-none focus:bg-white focus:border-slate-400 transition-colors resize-y"
                />
                <button
                  onClick={handleStartAnalysis}
                  className="px-4 py-2 rounded-lg bg-slate-900 hover:bg-slate-800 text-xs font-semibold text-white transition-colors cursor-pointer"
                >
                  Analyze Raw Email
                </button>
              </div>
            )}

          </div>

        </div>
      )}

    </div>
  );
};
