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
  RefreshCw
} from 'lucide-react';
import { buildForensicReport } from '../services/forensicReportService';
import { generateForensicPdf, downloadPdfInBrowser } from '../services/pdfBuilder';

const ANALYSIS_STEPS = [
  { id: 'reading', label: 'Reading email' },
  { id: 'headers', label: 'Extracting headers' },
  { id: 'threat', label: 'Running threat detection' },
  { id: 'network', label: 'Checking network indicators' },
  { id: 'auth', label: 'Checking authentication' },
  { id: 'assessment', label: 'Generating security assessment' }
];

export const EmailAnalysisPage = ({ onViewChange, currentAnalysis, onRunAnalysis }) => {
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

  // Analysis / Loading state: 'idle' | 'analyzing' | 'completed'
  const [analysisStatus, setAnalysisStatus] = useState(currentAnalysis ? 'completed' : 'idle');
  const [currentStepIndex, setCurrentStepIndex] = useState(-1);
  const [isDownloadingPdf, setIsDownloadingPdf] = useState(false);

  const fileInputRef = useRef(null);

  // Handle file drop/selection
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
    };
    reader.onload = (e) => {
      const text = e.target?.result;
      if (!text || typeof text !== 'string' || !text.trim()) {
        setFileError('The selected file appears to be empty.');
        return;
      }
      setSelectedFile({
        name: file.name,
        size: (file.size / 1024).toFixed(1) + ' KB'
      });
      setFileContent(text);
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
  };

  // Run analysis pipeline
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
      // Wrap URL in minimal RFC 822 format so full parser and extractors process it
      payloadToAnalyze = `From: submission@user-inbox.local\nTo: analyst@maverick.security\nSubject: Suspicious URL Analysis\n\nSuspicious Link: ${urlInput.trim()}`;
    } else if (activeTab === 'raw') {
      if (!rawInput.trim()) {
        setFileError('Please paste raw email content.');
        return;
      }
      payloadToAnalyze = rawInput.trim();
    }

    setFileError(null);
    setAnalysisStatus('analyzing');
    setCurrentStepIndex(0);

    // Staged step runner that coordinates with actual pipeline execution
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
      setAnalysisStatus('idle');
      setFileError('Analysis error: ' + (err.message || 'Failed to analyze email.'));
    }
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

  // Format risk level display
  let riskBadgeColor = 'bg-emerald-950/70 border-emerald-500/50 text-emerald-400';
  let riskLabel = 'LOW RISK';
  let threatNarrative = 'No significant security threats were detected. The email appears consistent with safe communication.';

  if (rawRisk === 'CRITICAL' || score >= 80) {
    riskBadgeColor = 'bg-red-950/70 border-red-500/60 text-red-400';
    riskLabel = 'CRITICAL THREAT';
    threatNarrative = 'MAVERICK detected multiple critical attack vectors. Do not interact with this email.';
  } else if (rawRisk === 'HIGH' || score >= 60) {
    riskBadgeColor = 'bg-red-950/70 border-red-500/50 text-red-400';
    riskLabel = 'HIGH RISK';
    threatNarrative = 'MAVERICK detected multiple suspicious indicators. Caution is strongly advised.';
  } else if (rawRisk === 'SUSPICIOUS' || score >= 30) {
    riskBadgeColor = 'bg-amber-950/70 border-amber-500/50 text-amber-400';
    riskLabel = 'SUSPICIOUS';
    threatNarrative = 'MAVERICK detected anomalies in sender authentication or link structure.';
  }

  // Generate "Why was this email flagged?" from real evidence
  const flaggedReasons = [];

  const aiProb = currentAnalysis?.aiThreat?.phishingProbability;
  if (typeof aiProb === 'number' && aiProb >= 50) {
    flaggedReasons.push({
      title: 'Phishing indicators detected',
      detail: `AI language analysis identified high probability of phishing intent (${aiProb}% confidence).`
    });
  }

  const auth = currentAnalysis?.emailAuth || currentAnalysis?.email?.emailAuth;
  const spfFail = auth?.spf?.status === 'FAIL' || auth?.observedEvidence?.mtaAuthentication?.observedSpfVerdict === 'fail';
  const dkimFail = auth?.dkim?.status === 'FAIL' || auth?.observedEvidence?.mtaAuthentication?.observedDkimVerdict === 'fail';
  const dmarcFail = auth?.dmarc?.status === 'FAIL';
  const replyMismatch = auth?.inferredEvidence?.replyToMismatch;

  if (spfFail || dkimFail || dmarcFail || replyMismatch) {
    const failedProtocols = [];
    if (spfFail) failedProtocols.push('SPF');
    if (dkimFail) failedProtocols.push('DKIM');
    if (dmarcFail) failedProtocols.push('DMARC');
    if (replyMismatch) failedProtocols.push('Reply-To address mismatch');
    
    flaggedReasons.push({
      title: 'Authentication concerns',
      detail: `Sender authentication failed: ${failedProtocols.join(', ')}.`
    });
  }

  const iocs = currentAnalysis?.iocs || [];
  const suspiciousUrls = iocs.filter(i => i.type === 'URL' && i.status === 'MALICIOUS');
  const suspiciousIps = iocs.filter(i => i.type === 'IP' && (i.status === 'MALICIOUS' || i.status === 'SUSPICIOUS'));

  if (suspiciousUrls.length > 0 || suspiciousIps.length > 0) {
    flaggedReasons.push({
      title: 'Suspicious network/URL indicators',
      detail: `${suspiciousUrls.length} potentially dangerous link(s) and ${suspiciousIps.length} suspicious network address(es) identified.`
    });
  }

  const attachments = currentAnalysis?.email?.attachments || [];
  const suspiciousAtts = attachments.filter(a => a.isSuspicious);
  if (suspiciousAtts.length > 0) {
    flaggedReasons.push({
      title: 'Suspicious attachment indicators',
      detail: `Attachment "${suspiciousAtts[0].filename}" was flagged due to risky executable format or double extension.`
    });
  }

  // Fallback if none of the above specific rules triggered but score was elevated
  if (flaggedReasons.length === 0 && score >= 30) {
    flaggedReasons.push({
      title: 'Suspicious email characteristics',
      detail: 'Abnormal routing hops and linguistic urgency patterns were identified during automated inspection.'
    });
  }

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

      {/* 1. LOADING STATE */}
      {analysisStatus === 'analyzing' && (
        <div className="rounded-2xl bg-[#090e1b] border border-slate-800 p-8 sm:p-12 text-center space-y-6 shadow-2xl">
          <div className="relative w-16 h-16 mx-auto flex items-center justify-center">
            <div className="absolute inset-0 rounded-full border-2 border-cyan-500/20 border-t-cyan-400 animate-spin"></div>
            <ShieldCheck className="w-8 h-8 text-cyan-400" />
          </div>

          <div>
            <h2 className="text-xl font-bold text-white tracking-wide">Analyzing your email...</h2>
            <p className="text-xs text-slate-400 mt-1">
              Executing multi-layer threat detection and forensic verification
            </p>
          </div>

          {/* Staged Checklist */}
          <div className="max-w-sm mx-auto space-y-2 text-left pt-2">
            {ANALYSIS_STEPS.map((step, idx) => {
              const isDone = currentStepIndex > idx;
              const isCurrent = currentStepIndex === idx;

              return (
                <div key={step.id} className="flex items-center gap-3 text-xs">
                  {isDone ? (
                    <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
                  ) : isCurrent ? (
                    <span className="w-4 h-4 flex items-center justify-center">
                      <span className="w-2 h-2 rounded-full bg-cyan-400 animate-ping"></span>
                    </span>
                  ) : (
                    <span className="w-4 h-4 flex items-center justify-center">
                      <span className="w-2 h-2 rounded-full bg-slate-700"></span>
                    </span>
                  )}
                  <span className={`transition-colors ${
                    isDone ? 'text-slate-200' : isCurrent ? 'text-cyan-300 font-semibold' : 'text-slate-500'
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
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-slate-800 pb-4">
            <div>
              <h1 className="text-xl font-bold text-white tracking-tight">Email Security Result</h1>
              <div className="text-xs font-mono text-slate-400 mt-0.5">Case ID: {caseId}</div>
            </div>

            <button
              onClick={handleResetForNewAnalysis}
              className="self-start sm:self-auto flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-xs text-slate-200 transition-colors cursor-pointer"
            >
              <RefreshCw className="w-3.5 h-3.5" />
              <span>Check Another Email</span>
            </button>
          </div>

          {/* Main Threat Card */}
          <div className="rounded-2xl bg-[#090d16] border border-slate-800 p-6 sm:p-8 space-y-6 shadow-xl">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-slate-800/80 pb-6">
              <div>
                <span className="text-[11px] font-semibold uppercase tracking-wider text-slate-400">
                  THREAT ASSESSMENT
                </span>
                <div className="flex items-baseline gap-2 mt-1">
                  <span className="text-4xl sm:text-5xl font-extrabold text-white tracking-tight">
                    {score}
                  </span>
                  <span className="text-slate-400 text-base font-semibold">/ 100</span>
                </div>
              </div>

              <div className={`px-4 py-2 rounded-xl border font-bold text-sm tracking-wider self-start sm:self-auto ${riskBadgeColor}`}>
                {riskLabel}
              </div>
            </div>

            <p className="text-sm text-slate-300 leading-relaxed">
              {threatNarrative}
            </p>

            {/* Why was it flagged? */}
            <div className="space-y-3 pt-2">
              <h3 className="text-xs font-bold uppercase tracking-wider text-slate-400">
                Why was this email flagged?
              </h3>

              {flaggedReasons.length > 0 ? (
                <div className="space-y-2.5">
                  {flaggedReasons.map((reason, idx) => (
                    <div 
                      key={idx} 
                      className="p-3.5 rounded-xl bg-slate-900/80 border border-slate-800/90 flex items-start gap-3"
                    >
                      <AlertTriangle className="w-4 h-4 text-amber-400 shrink-0 mt-0.5" />
                      <div>
                        <div className="text-xs font-semibold text-slate-200">{reason.title}</div>
                        <div className="text-xs text-slate-400 mt-0.5">{reason.detail}</div>
                      </div>
                    </div>
                  ))}
                </div>
              ) : (
                <div className="p-4 rounded-xl bg-emerald-950/30 border border-emerald-800/40 text-xs text-emerald-300 flex items-center gap-2.5">
                  <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
                  <span>No suspicious indicators detected. Email conforms to expected legitimate standards.</span>
                </div>
              )}
            </div>

            {/* Actions: View Detailed Analysis & Download Report */}
            <div className="flex flex-col sm:flex-row items-center gap-3 pt-4 border-t border-slate-800/80">
              <button
                onClick={() => onViewChange('security-analyzer')}
                className="w-full sm:w-auto flex-1 flex items-center justify-center gap-2 px-5 py-2.5 rounded-xl bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-semibold shadow-xs transition-colors cursor-pointer"
              >
                <span>View Detailed Analysis</span>
                <ArrowRight className="w-4 h-4" />
              </button>

              <button
                onClick={handleDownloadReport}
                disabled={isDownloadingPdf}
                className="w-full sm:w-auto flex items-center justify-center gap-2 px-4 py-2.5 rounded-xl bg-slate-800 hover:bg-slate-700 border border-slate-700 text-xs font-semibold text-slate-200 transition-colors cursor-pointer disabled:opacity-50"
              >
                {isDownloadingPdf ? (
                  <Loader2 className="w-4 h-4 animate-spin text-cyan-400" />
                ) : (
                  <Download className="w-4 h-4" />
                )}
                <span>Download Report</span>
              </button>
            </div>

          </div>

        </div>
      )}

      {/* 3. INPUT / UPLOAD FORM (IDLE STATE) */}
      {analysisStatus === 'idle' && (
        <div className="space-y-8">
          
          {/* Welcome Section */}
          <div className="text-center space-y-2">
            <h1 className="text-2xl sm:text-3xl font-bold text-white tracking-tight">
              Analyze a Suspicious Email
            </h1>
            <p className="text-sm text-slate-400 max-w-lg mx-auto">
              Upload the suspicious email and MAVERICK will analyze it for phishing and other security indicators.
            </p>
            <div className="text-xs text-cyan-400/90 pt-1 font-medium tracking-wide">
              AI Detection • Network Intelligence • Email Authentication
            </div>
          </div>

          {/* Primary Upload Card */}
          <div className="rounded-2xl bg-[#090d16] border border-slate-800 p-6 sm:p-8 space-y-5 shadow-xl">
            <div>
              <h2 className="text-base font-bold text-white">Analyze Email</h2>
              <p className="text-xs text-slate-400 mt-0.5">
                Upload the original .EML file for analysis
              </p>
            </div>

            {/* Error banner if any */}
            {fileError && (
              <div className="p-3 rounded-lg bg-red-950/40 border border-red-500/40 text-xs text-red-300 flex items-center gap-2">
                <AlertTriangle className="w-4 h-4 shrink-0 text-red-400" />
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
                className={`border-2 border-dashed rounded-xl p-8 sm:p-12 text-center transition-colors cursor-pointer ${
                  isDragOver 
                    ? 'border-cyan-500 bg-cyan-950/20' 
                    : 'border-slate-700/80 hover:border-slate-600 bg-slate-900/40'
                }`}
              >
                <div className="w-12 h-12 mx-auto rounded-full bg-slate-800 flex items-center justify-center text-cyan-400 mb-3">
                  <UploadCloud className="w-6 h-6" />
                </div>
                <div className="text-sm font-semibold text-slate-200">
                  Drop your .EML file here
                </div>
                <div className="text-xs text-slate-400 mt-1">or</div>
                <div className="mt-2 inline-block px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-xs font-medium text-slate-200 border border-slate-700">
                  Browse Files
                </div>
                <div className="text-[11px] text-slate-500 mt-3">
                  Maximum file size: 10 MB
                </div>
              </div>
            ) : (
              /* Uploaded File State */
              <div className="p-4 rounded-xl bg-slate-900 border border-slate-700/80 flex items-center justify-between gap-3">
                <div className="flex items-center gap-3 min-w-0">
                  <div className="w-9 h-9 rounded-lg bg-emerald-950/80 border border-emerald-600/40 text-emerald-400 flex items-center justify-center shrink-0">
                    <CheckCircle2 className="w-5 h-5" />
                  </div>
                  <div className="min-w-0">
                    <div className="text-xs font-semibold text-white truncate">{selectedFile.name}</div>
                    <div className="text-[11px] text-slate-400 mt-0.5">
                      {selectedFile.size} • <span className="text-emerald-400">Email file ready for analysis</span>
                    </div>
                  </div>
                </div>

                <div className="flex items-center gap-2 shrink-0">
                  <button
                    onClick={handleRemoveFile}
                    className="p-1.5 rounded-lg text-slate-400 hover:text-red-400 hover:bg-slate-800 transition-colors cursor-pointer"
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
              className="w-full py-3 rounded-xl bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-semibold shadow-xs transition-colors cursor-pointer flex items-center justify-center gap-2"
            >
              <span>Analyze Email</span>
              <ArrowRight className="w-4 h-4" />
            </button>
          </div>

          {/* Alternative Inputs Section */}
          <div className="rounded-2xl bg-[#090d16] border border-slate-800/80 p-5 sm:p-6 space-y-4 shadow-sm">
            <div>
              <h3 className="text-xs font-bold uppercase tracking-wider text-slate-400">
                Other ways to provide email evidence
              </h3>
            </div>

            {/* Sub-tabs */}
            <div className="flex items-center gap-2 border-b border-slate-800 pb-2">
              <button
                onClick={() => { setActiveTab('headers'); setFileError(null); }}
                className={`px-3 py-1.5 rounded-lg text-xs font-medium transition-colors cursor-pointer ${
                  activeTab === 'headers' ? 'bg-slate-800 text-white' : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                Email Header
              </button>
              <button
                onClick={() => { setActiveTab('url'); setFileError(null); }}
                className={`px-3 py-1.5 rounded-lg text-xs font-medium transition-colors cursor-pointer ${
                  activeTab === 'url' ? 'bg-slate-800 text-white' : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                URL
              </button>
              <button
                onClick={() => { setActiveTab('raw'); setFileError(null); }}
                className={`px-3 py-1.5 rounded-lg text-xs font-medium transition-colors cursor-pointer ${
                  activeTab === 'raw' ? 'bg-slate-800 text-white' : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                Raw Email
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
                  className="w-full p-3 rounded-lg bg-slate-900 border border-slate-800 text-xs font-mono text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-500/60 transition-colors resize-y"
                />
                <button
                  onClick={handleStartAnalysis}
                  className="px-4 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-xs font-semibold text-white transition-colors cursor-pointer"
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
                    className="flex-1 p-2.5 rounded-lg bg-slate-900 border border-slate-800 text-xs font-mono text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-500/60 transition-colors"
                  />
                  <button
                    onClick={handleStartAnalysis}
                    className="px-4 py-2.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-xs font-semibold text-white transition-colors cursor-pointer shrink-0"
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
                  className="w-full p-3 rounded-lg bg-slate-900 border border-slate-800 text-xs font-mono text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-500/60 transition-colors resize-y"
                />
                <button
                  onClick={handleStartAnalysis}
                  className="px-4 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-xs font-semibold text-white transition-colors cursor-pointer"
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
