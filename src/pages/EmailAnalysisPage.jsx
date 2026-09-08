import React, { useState, useRef, useEffect } from 'react';
import { 
  UploadCloud, 
  FileCode, 
  CheckCircle2, 
  Clock, 
  AlertTriangle, 
  ArrowRight, 
  ShieldAlert, 
  Zap, 
  Copy, 
  Check, 
  Loader2, 
  Mail, 
  Globe, 
  Paperclip, 
  Cpu, 
  Activity, 
  RefreshCw,
  FolderOpen,
  FileText,
  Radio,
  SlidersHorizontal,
  ChevronRight,
  Brain,
  ShieldCheck,
  ShieldX
} from 'lucide-react';
import { parseEmailContent } from '../services/emailParser';
import { SYNTHETIC_SCENARIOS } from '../data/syntheticScenarios';
import { AttachmentForensicsCard } from '../components/dashboard/AttachmentForensicsCard.jsx';
import { EmailAuthenticationCard } from '../components/dashboard/EmailAuthenticationCard.jsx';

const PIPELINE_STAGES = [
  { id: 1, name: 'Email Parsing', detail: 'Decoding MIME envelope & boundary structures', duration: '34ms' },
  { id: 2, name: 'Header Forensics', detail: 'SPF, DKIM, DMARC alignment & hop traceroutes', duration: '48ms' },
  { id: 3, name: 'NLP Threat Analysis', detail: 'Evaluating urgency sentiment & extortion tokens', duration: '82ms' },
  { id: 4, name: 'IOC Extraction', detail: 'Extracting IPv4, domains, URLs & attachment hashes', duration: '41ms' },
  { id: 5, name: 'Threat Intel Enrichment', detail: 'Cross-referencing IOCs against synthetic feeds', duration: '64ms' },
  { id: 6, name: 'GeoLocation / ASN', detail: 'Resolving Autonomous Systems & origin topology', duration: '55ms' },
  { id: 7, name: 'Graph Correlation', detail: 'Linking threat actors & targeted infrastructure', duration: '71ms' },
  { id: 8, name: 'Risk Scoring', detail: 'Computing multi-factor explainable risk index', duration: '38ms' }
];

export const EmailAnalysisPage = ({ onViewChange, currentAnalysis, onRunAnalysis }) => {
  const [emailData, setEmailData] = useState(currentAnalysis?.email || null);
  const [selectedScenarioId, setSelectedScenarioId] = useState('ceo-bec');
  
  // Ingestion Mode Switcher: 'presets' | 'upload' | 'paste'
  const [ingestionMode, setIngestionMode] = useState('presets');
  const [isDragActive, setIsDragActive] = useState(false);
  const [pastedRawText, setPastedRawText] = useState('');
  const [copiedRaw, setCopiedRaw] = useState(false);
  
  // Active Workspace Tab: 'overview' | 'ai' | 'auth' | 'payloads' | 'raw'
  const [activeTab, setActiveTab] = useState('overview');

  // Real File Upload State
  const [isUploading, setIsUploading] = useState(false);
  const [uploadError, setUploadError] = useState(null);
  const [uploadedFileInfo, setUploadedFileInfo] = useState(null);

  // Pipeline Analysis State
  const [analysisState, setAnalysisState] = useState(currentAnalysis ? 'completed' : 'idle');
  const [activeStageIndex, setActiveStageIndex] = useState(-1);
  const [stageStatuses, setStageStatuses] = useState(
    PIPELINE_STAGES.map(() => currentAnalysis ? 'completed' : 'pending')
  );

  const fileInputRef = useRef(null);
  const timerRef = useRef(null);

  useEffect(() => {
    return () => {
      if (timerRef.current) clearInterval(timerRef.current);
    };
  }, []);

  // Sync when currentAnalysis updates from parent
  useEffect(() => {
    if (currentAnalysis?.email) {
      setEmailData(currentAnalysis.email);
    }
  }, [currentAnalysis]);

  // Load a synthetic scenario
  const handleLoadScenario = async (scenarioId) => {
    setSelectedScenarioId(scenarioId);
    setUploadError(null);
    setUploadedFileInfo(null);
    const scenario = SYNTHETIC_SCENARIOS.find(s => s.id === scenarioId) || SYNTHETIC_SCENARIOS[0];
    const parsed = await parseEmailContent(scenario.rawSnippet);
    
    parsed.scenarioName = scenario.name;
    parsed.category = scenario.category;
    parsed.tag = scenario.tag;
    if (scenario.urls) parsed.urls = scenario.urls;
    if (scenario.ips) parsed.ips = scenario.ips;
    if (scenario.attachments) parsed.attachments = scenario.attachments;

    setEmailData(parsed);
    setAnalysisState('idle');
    setActiveStageIndex(-1);
    setStageStatuses(PIPELINE_STAGES.map(() => 'pending'));
    setActiveTab('overview');
  };

  const handleBrowseClick = (e) => {
    if (e && typeof e.stopPropagation === 'function') e.stopPropagation();
    if (fileInputRef.current) fileInputRef.current.click();
  };

  // Handle file upload (.eml, .msg, or .txt)
  const handleFileUpload = async (file) => {
    if (!file) return;
    setUploadError(null);
    setIsUploading(true);

    try {
      if (file.size > 25 * 1024 * 1024) {
        throw new Error('File exceeds maximum safe inspection limit (25 MB).');
      }

      const reader = new FileReader();

      reader.onerror = () => {
        setIsUploading(false);
        setUploadError(`Failed to read file "${file.name}". Permission denied or unreadable.`);
      };

      reader.onload = async (event) => {
        try {
          const text = event.target?.result;
          if (!text || typeof text !== 'string' || !text.trim()) {
            throw new Error(`File "${file.name}" appears to be empty.`);
          }

          if (text.charCodeAt(0) === 0xD0 && text.charCodeAt(1) === 0xCF) {
            throw new Error('Binary Outlook .msg detected. Please export as RFC 822 standard .eml to inspect.');
          }

          const parsed = await parseEmailContent(text, { name: file.name, size: file.size });
          parsed.scenarioName = `Uploaded: ${file.name}`;
          parsed.tag = 'INGESTED FILE';

          setEmailData(parsed);
          setUploadedFileInfo({
            name: file.name,
            size: (file.size / 1024).toFixed(1) + ' KB',
            subject: parsed.subject || '(No Subject)',
            sender: parsed.fromParsed?.address || parsed.sender,
            attachmentsCount: parsed.attachments?.length || 0
          });
          setSelectedScenarioId('');
          setAnalysisState('idle');
          setActiveStageIndex(-1);
          setStageStatuses(PIPELINE_STAGES.map(() => 'pending'));
          setIsUploading(false);
          setActiveTab('overview');
        } catch (err) {
          console.error('Error parsing email file:', err);
          setUploadError(`Failed to parse "${file.name}": ${err.message || 'Malformed email.'}`);
          setIsUploading(false);
        }
      };

      reader.readAsText(file);
    } catch (err) {
      console.error('Error in handleFileUpload:', err);
      setUploadError(err.message || 'Unexpected error while processing the file.');
      setIsUploading(false);
    }
  };

  const handleFileChange = (e) => {
    const file = e.target.files?.[0];
    if (file) handleFileUpload(file);
    e.target.value = '';
  };

  const handleDragOver = (e) => {
    e.preventDefault();
    setIsDragActive(true);
  };

  const handleDragLeave = (e) => {
    e.preventDefault();
    setIsDragActive(false);
  };

  const handleDrop = (e) => {
    e.preventDefault();
    setIsDragActive(false);
    const file = e.dataTransfer.files?.[0];
    if (file) handleFileUpload(file);
  };

  const handleApplyPastedRaw = async () => {
    if (!pastedRawText.trim()) return;
    const parsed = await parseEmailContent(pastedRawText);
    parsed.scenarioName = 'Pasted RFC 822 Payload';
    parsed.tag = 'RAW PASTE';
    setEmailData(parsed);
    setAnalysisState('idle');
    setActiveStageIndex(-1);
    setStageStatuses(PIPELINE_STAGES.map(() => 'pending'));
    setActiveTab('overview');
  };

  const handleCopyRaw = () => {
    if (emailData?.rawSnippet) {
      navigator.clipboard?.writeText(emailData.rawSnippet);
      setCopiedRaw(true);
      setTimeout(() => setCopiedRaw(false), 1500);
    }
  };

  // Run the 8-stage pipeline
  const startAnalysis = () => {
    let targetEmail = emailData;
    if (!targetEmail) {
      const defaultScenario = SYNTHETIC_SCENARIOS[0];
      targetEmail = {
        sender: defaultScenario.sender,
        recipient: defaultScenario.recipient,
        subject: defaultScenario.subject,
        date: defaultScenario.date,
        rawSnippet: defaultScenario.rawSnippet,
        originatingIP: defaultScenario.originatingIP,
        urls: defaultScenario.urls,
        ips: defaultScenario.ips,
        attachments: defaultScenario.attachments,
        auth: {
          spf: { result: 'SOFTFAIL', details: 'Unauthorized IP' },
          dkim: { result: 'FAIL', details: 'Invalid signature' },
          dmarc: { result: 'FAIL', details: 'Quarantine policy' }
        }
      };
      setEmailData(targetEmail);
    }
    
    setAnalysisState('analyzing');
    setActiveStageIndex(0);
    
    const newStatuses = PIPELINE_STAGES.map(() => 'pending');
    newStatuses[0] = 'processing';
    setStageStatuses(newStatuses);

    let currentStep = 0;
    if (timerRef.current) clearInterval(timerRef.current);

    timerRef.current = setInterval(() => {
      currentStep++;
      if (currentStep < PIPELINE_STAGES.length) {
        setActiveStageIndex(currentStep);
        setStageStatuses(prev => {
          const updated = [...prev];
          updated[currentStep - 1] = 'completed';
          updated[currentStep] = 'processing';
          return updated;
        });
      } else {
        clearInterval(timerRef.current);
        setStageStatuses(PIPELINE_STAGES.map(() => 'completed'));
        setActiveStageIndex(PIPELINE_STAGES.length);
        setAnalysisState('completed');

        if (onRunAnalysis) {
          onRunAnalysis(targetEmail);
        }
      }
    }, 380);
  };

  const progressPercentage = analysisState === 'completed'
    ? 100
    : analysisState === 'analyzing'
      ? Math.round(((activeStageIndex + 0.5) / PIPELINE_STAGES.length) * 100)
      : 0;

  const riskScore = currentAnalysis?.fusion?.threatScore || 92;
  const riskLevel = currentAnalysis?.fusion?.riskLevel || 'HIGH';
  const aiConfidence = currentAnalysis?.aiThreat?.confidence || 92;

  return (
    <div className="space-y-6 pb-16 font-sans">
      
      {/* Hidden file input */}
      <input 
        type="file" 
        ref={fileInputRef} 
        onChange={handleFileChange} 
        onClick={(e) => { e.target.value = ''; }}
        accept=".eml,.msg,.txt,.EML,.MSG,.TXT,message/rfc822,text/plain,text/*,*/*" 
        className="hidden" 
      />

      {/* Modern, Breathable Hero Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 py-2 border-b border-slate-800/80">
        <div>
          <div className="flex items-center gap-2 text-cyan-400 text-xs font-mono mb-1">
            <span className="w-2 h-2 rounded-full bg-cyan-400"></span>
            <span>FORENSIC EMAIL INGESTION & PIPELINE</span>
          </div>
          <h1 className="text-2xl font-bold tracking-tight text-white">
            Email Threat Analysis
          </h1>
          <p className="text-xs text-slate-400 mt-0.5">
            Select a controlled test scenario or upload a raw RFC 822 (.eml) message to execute deep multi-vector triage.
          </p>
        </div>

        {/* Ingestion Mode Toggle Tabs */}
        <div className="flex items-center p-1 rounded-xl bg-[#09101e] border border-slate-800 self-start md:self-auto">
          <button
            type="button"
            onClick={() => setIngestionMode('presets')}
            className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium transition-all cursor-pointer ${
              ingestionMode === 'presets'
                ? 'bg-cyan-950/80 border border-cyan-500/40 text-cyan-300 font-semibold shadow-sm'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            <SlidersHorizontal className="w-3.5 h-3.5" />
            <span>Preset Scenarios</span>
          </button>

          <button
            type="button"
            onClick={() => setIngestionMode('upload')}
            className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium transition-all cursor-pointer ${
              ingestionMode === 'upload'
                ? 'bg-cyan-950/80 border border-cyan-500/40 text-cyan-300 font-semibold shadow-sm'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            <FolderOpen className="w-3.5 h-3.5" />
            <span>Upload File (.eml)</span>
          </button>

          <button
            type="button"
            onClick={() => setIngestionMode('paste')}
            className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium transition-all cursor-pointer ${
              ingestionMode === 'paste'
                ? 'bg-cyan-950/80 border border-cyan-500/40 text-cyan-300 font-semibold shadow-sm'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            <FileCode className="w-3.5 h-3.5" />
            <span>Paste Headers</span>
          </button>
        </div>
      </div>

      {/* Ingestion Panel (Dynamic by Selected Ingestion Mode) */}
      <div className="rounded-2xl bg-[#091122]/70 border border-slate-800/80 p-5 shadow-sm">
        
        {/* Mode 1: Preset Demo Scenarios */}
        {ingestionMode === 'presets' && (
          <div className="space-y-3">
            <div className="flex items-center justify-between">
              <span className="text-xs font-semibold text-slate-300">
                Choose a Synthetic Threat Scenario:
              </span>
              <span className="text-[11px] text-slate-500">Click to instantly load into parser memory</span>
            </div>
            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-2.5">
              {SYNTHETIC_SCENARIOS.map(scenario => {
                const isSelected = selectedScenarioId === scenario.id;
                return (
                  <button
                    key={scenario.id}
                    type="button"
                    onClick={() => handleLoadScenario(scenario.id)}
                    className={`p-3 rounded-xl border text-left transition-all cursor-pointer ${
                      isSelected 
                        ? 'bg-cyan-950/60 border-cyan-500/60 text-white shadow-[0_0_15px_rgba(6,182,212,0.15)]' 
                        : 'bg-[#060a14] border-slate-800/80 text-slate-400 hover:border-slate-700 hover:text-slate-200'
                    }`}
                  >
                    <div className="text-xs font-semibold truncate text-slate-100 mb-1">
                      {scenario.name}
                    </div>
                    <span className="text-[10px] font-mono uppercase px-1.5 py-0.5 rounded bg-slate-900 border border-slate-800 text-cyan-400/90 block truncate">
                      {scenario.category}
                    </span>
                  </button>
                );
              })}
            </div>
          </div>
        )}

        {/* Mode 2: Upload File */}
        {ingestionMode === 'upload' && (
          <div className="space-y-4">
            <div
              onDragOver={handleDragOver}
              onDragLeave={handleDragLeave}
              onDrop={handleDrop}
              onClick={handleBrowseClick}
              className={`rounded-xl border-2 border-dashed p-8 text-center transition-all cursor-pointer ${
                isDragActive
                  ? 'border-cyan-400 bg-cyan-950/40 shadow-md scale-[0.99]'
                  : uploadedFileInfo
                    ? 'border-emerald-500/40 bg-emerald-950/10'
                    : 'border-slate-800 hover:border-cyan-500/40 bg-[#060a14]'
              }`}
            >
              <div className="flex flex-col items-center justify-center space-y-2">
                <UploadCloud className="w-8 h-8 text-cyan-400/80" />
                <p className="text-xs font-medium text-slate-200">
                  Drag and drop your <span className="text-cyan-300 font-mono font-semibold">.eml</span> or <span className="text-cyan-300 font-mono font-semibold">.txt</span> file here, or click to browse
                </p>
                <p className="text-[11px] text-slate-500">
                  RFC 822 email parser safely extracts headers, routing hops, URLs, and attachments in quarantine.
                </p>
              </div>
            </div>

            {uploadedFileInfo && !uploadError && (
              <div className="p-3.5 rounded-xl bg-emerald-950/30 border border-emerald-500/40 flex items-center justify-between text-xs font-mono">
                <div className="flex items-center gap-3">
                  <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
                  <span className="text-white font-medium truncate max-w-sm">{uploadedFileInfo.name}</span>
                  <span className="text-slate-400">({uploadedFileInfo.size})</span>
                </div>
                <span className="text-emerald-400 text-[11px] font-semibold">File Ingested</span>
              </div>
            )}
          </div>
        )}

        {/* Mode 3: Paste RFC Headers */}
        {ingestionMode === 'paste' && (
          <div className="space-y-3">
            <div className="flex items-center justify-between text-xs text-slate-400">
              <span>Paste raw RFC 822 headers and MIME body below:</span>
            </div>
            <textarea
              rows={5}
              value={pastedRawText}
              onChange={(e) => setPastedRawText(e.target.value)}
              placeholder="Delivered-To: ...&#10;From: ...&#10;Subject: ...&#10;Received: from ...&#10;&#10;Email body content..."
              className="w-full p-3 bg-[#060a14] border border-slate-800 rounded-xl text-xs font-mono text-slate-200 focus:outline-none focus:border-cyan-500 placeholder-slate-600"
            />
            <div className="flex justify-end">
              <button
                type="button"
                onClick={handleApplyPastedRaw}
                className="px-4 py-2 rounded-xl bg-cyan-600 hover:bg-cyan-500 text-xs text-white font-semibold transition-all cursor-pointer"
              >
                Parse Ingested Headers
              </button>
            </div>
          </div>
        )}

        {/* Alerts & Upload Progress */}
        {isUploading && (
          <div className="mt-3 p-3 rounded-xl bg-cyan-950/40 border border-cyan-500/30 flex items-center justify-center gap-2 text-cyan-300 text-xs font-mono">
            <Loader2 className="w-4 h-4 animate-spin" />
            <span>Parsing RFC 822 email payload...</span>
          </div>
        )}

        {uploadError && (
          <div className="mt-3 p-3 rounded-xl bg-red-950/40 border border-red-500/40 flex items-center justify-between text-xs text-red-300 font-mono">
            <div className="flex items-center gap-2">
              <AlertTriangle className="w-4 h-4 text-red-400 shrink-0" />
              <span>{uploadError}</span>
            </div>
            <button type="button" onClick={() => setUploadError(null)} className="text-red-400 hover:text-white">✕</button>
          </div>
        )}

      </div>

      {/* Main Email Workspace (Shown when email is loaded) */}
      {emailData ? (
        <div className="rounded-2xl bg-[#091122]/70 border border-slate-800/80 shadow-md overflow-hidden">
          
          {/* Executive Header Banner */}
          <div className="p-5 border-b border-slate-800/80 bg-gradient-to-r from-[#0b162a] via-[#091222] to-[#070c17] flex flex-col lg:flex-row lg:items-center justify-between gap-4">
            <div className="space-y-1 max-w-3xl">
              <div className="flex items-center gap-2 flex-wrap">
                <span className="px-2 py-0.5 rounded bg-cyan-950/90 border border-cyan-500/40 text-cyan-300 text-[10px] font-mono font-bold">
                  {emailData.tag || 'INGESTED'}
                </span>
                <span className="text-xs text-slate-400 font-mono truncate">
                  Sender: <strong className="text-slate-200">{emailData.sender || 'Unknown'}</strong>
                </span>
                {analysisState === 'completed' && (
                  <span className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold border ${
                    riskLevel === 'CRITICAL' ? 'bg-red-950/80 text-red-300 border-red-500/50' : 'bg-amber-950/80 text-amber-300 border-amber-500/50'
                  }`}>
                    {riskScore}/100 • {riskLevel}
                  </span>
                )}
              </div>
              <h2 className="text-base sm:text-lg font-bold text-white tracking-tight line-clamp-1">
                {emailData.subject || '(No Subject Line)'}
              </h2>
            </div>

            {/* Quick Action Buttons */}
            <div className="flex items-center gap-2.5 shrink-0">
              <button
                type="button"
                onClick={startAnalysis}
                disabled={analysisState === 'analyzing'}
                className="flex items-center gap-1.5 px-4 py-2 rounded-xl bg-gradient-to-r from-cyan-600 to-blue-600 hover:from-cyan-500 hover:to-blue-500 text-white text-xs font-semibold shadow-md transition-all cursor-pointer disabled:opacity-50"
              >
                {analysisState === 'analyzing' ? (
                  <>
                    <Loader2 className="w-3.5 h-3.5 animate-spin" />
                    <span>Analyzing...</span>
                  </>
                ) : (
                  <>
                    <Zap className="w-3.5 h-3.5 fill-current" />
                    <span>{analysisState === 'completed' ? 'Re-run Analysis' : 'Run 8-Stage Triage'}</span>
                  </>
                )}
              </button>

              {analysisState === 'completed' && (
                <button
                  type="button"
                  onClick={() => onViewChange('analysis-results')}
                  className="flex items-center gap-1 px-3 py-2 rounded-xl bg-slate-800/80 hover:bg-slate-700 border border-slate-700 text-xs text-slate-200 font-medium transition-all cursor-pointer"
                >
                  <span>Detailed Verdict</span>
                  <ChevronRight className="w-3.5 h-3.5" />
                </button>
              )}
            </div>
          </div>

          {/* Pipeline Progress Indicator (Only visible during analysis) */}
          {analysisState === 'analyzing' && (
            <div className="p-4 bg-[#060b16] border-b border-slate-800 space-y-2 font-mono text-xs">
              <div className="flex items-center justify-between text-slate-300">
                <span className="flex items-center gap-2">
                  <Loader2 className="w-3.5 h-3.5 animate-spin text-cyan-400" />
                  <span>Pipeline Execution: Stage {activeStageIndex + 1} of 8</span>
                </span>
                <span className="text-cyan-400 font-bold">{progressPercentage}%</span>
              </div>
              <div className="w-full h-1.5 bg-slate-800 rounded-full overflow-hidden">
                <div 
                  className="h-full bg-cyan-400 rounded-full transition-all duration-300"
                  style={{ width: `${progressPercentage}%` }}
                />
              </div>
            </div>
          )}

          {/* Comfortable Workspace Tab Navigation */}
          <div className="flex items-center gap-1 px-4 border-b border-slate-800/80 bg-[#070e1c] overflow-x-auto text-xs">
            <button
              type="button"
              onClick={() => setActiveTab('overview')}
              className={`flex items-center gap-2 py-3 px-3.5 border-b-2 font-medium transition-all cursor-pointer whitespace-nowrap ${
                activeTab === 'overview'
                  ? 'border-cyan-400 text-cyan-300 font-semibold'
                  : 'border-transparent text-slate-400 hover:text-slate-200'
              }`}
            >
              <Mail className="w-3.5 h-3.5" />
              <span>Overview</span>
            </button>

            <button
              type="button"
              onClick={() => setActiveTab('ai')}
              className={`flex items-center gap-2 py-3 px-3.5 border-b-2 font-medium transition-all cursor-pointer whitespace-nowrap ${
                activeTab === 'ai'
                  ? 'border-cyan-400 text-cyan-300 font-semibold'
                  : 'border-transparent text-slate-400 hover:text-slate-200'
              }`}
            >
              <Brain className="w-3.5 h-3.5" />
              <span>AI Threat Model</span>
            </button>

            <button
              type="button"
              onClick={() => setActiveTab('auth')}
              className={`flex items-center gap-2 py-3 px-3.5 border-b-2 font-medium transition-all cursor-pointer whitespace-nowrap ${
                activeTab === 'auth'
                  ? 'border-cyan-400 text-cyan-300 font-semibold'
                  : 'border-transparent text-slate-400 hover:text-slate-200'
              }`}
            >
              <ShieldAlert className="w-3.5 h-3.5" />
              <span>Authentication & Routing</span>
            </button>

            <button
              type="button"
              onClick={() => setActiveTab('payloads')}
              className={`flex items-center gap-2 py-3 px-3.5 border-b-2 font-medium transition-all cursor-pointer whitespace-nowrap ${
                activeTab === 'payloads'
                  ? 'border-cyan-400 text-cyan-300 font-semibold'
                  : 'border-transparent text-slate-400 hover:text-slate-200'
              }`}
            >
              <Paperclip className="w-3.5 h-3.5" />
              <span>Payloads & IOCs</span>
              {emailData.attachments?.length > 0 && (
                <span className="px-1.5 py-0.2 rounded-full bg-red-950 text-red-300 text-[9px] font-bold">
                  {emailData.attachments.length}
                </span>
              )}
            </button>

            <button
              type="button"
              onClick={() => setActiveTab('raw')}
              className={`flex items-center gap-2 py-3 px-3.5 border-b-2 font-medium transition-all cursor-pointer whitespace-nowrap ${
                activeTab === 'raw'
                  ? 'border-cyan-400 text-cyan-300 font-semibold'
                  : 'border-transparent text-slate-400 hover:text-slate-200'
              }`}
            >
              <FileCode className="w-3.5 h-3.5" />
              <span>Raw RFC Source</span>
            </button>
          </div>

          {/* Tab Viewport */}
          <div className="p-6">
            
            {/* Tab 1: Executive Overview */}
            {activeTab === 'overview' && (
              <div className="space-y-6">
                
                {/* Core Email Metadata Cards */}
                <div className="grid grid-cols-1 md:grid-cols-2 gap-3.5 text-xs font-mono">
                  <div className="p-3.5 rounded-xl bg-[#060a14] border border-slate-800/80 space-y-1">
                    <span className="text-[10px] uppercase text-slate-500 font-semibold block">From (Sender)</span>
                    <div className="text-slate-200 font-medium break-all">{emailData.sender || 'Unknown'}</div>
                  </div>

                  <div className="p-3.5 rounded-xl bg-[#060a14] border border-slate-800/80 space-y-1">
                    <span className="text-[10px] uppercase text-slate-500 font-semibold block">To (Recipient)</span>
                    <div className="text-cyan-300 font-medium break-all">{emailData.recipient || 'Protected Entity'}</div>
                  </div>

                  <div className="p-3.5 rounded-xl bg-[#060a14] border border-slate-800/80 space-y-1">
                    <span className="text-[10px] uppercase text-slate-500 font-semibold block">Subject</span>
                    <div className="text-white font-medium">{emailData.subject || '(No Subject)'}</div>
                  </div>

                  <div className="p-3.5 rounded-xl bg-[#060a14] border border-slate-800/80 space-y-1">
                    <span className="text-[10px] uppercase text-slate-500 font-semibold block">Date / Hop Timestamp</span>
                    <div className="text-slate-300">{emailData.date || 'Standard Delivery Hop'}</div>
                  </div>
                </div>

                {/* Sender Alignment Mismatches (From vs Reply-To) */}
                <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-xs font-mono">
                  <div className={`p-3.5 rounded-xl border flex items-start justify-between gap-3 ${
                    emailData.replyToMismatch
                      ? 'bg-amber-950/20 border-amber-500/40 text-amber-300'
                      : 'bg-[#060a14] border-slate-800 text-slate-300'
                  }`}>
                    <div>
                      <span className="text-[10px] uppercase text-slate-400 font-bold block">From vs Reply-To Alignment</span>
                      <div className="font-bold mt-0.5">
                        {emailData.replyToMismatch ? '⚠️ MISMATCH DETECTED' : '✅ DOMAIN ALIGNED'}
                      </div>
                      <p className="text-[11px] text-slate-400 mt-1 font-sans">
                        {emailData.replyToMismatch 
                          ? 'Replies are redirected to an external domain differing from sender identity (BEC vector).'
                          : 'Reply-To points to the authenticated sender domain.'}
                      </p>
                    </div>
                  </div>

                  <div className={`p-3.5 rounded-xl border flex items-start justify-between gap-3 ${
                    emailData.returnPathMismatch
                      ? 'bg-amber-950/20 border-amber-500/40 text-amber-300'
                      : 'bg-[#060a14] border-slate-800 text-slate-300'
                  }`}>
                    <div>
                      <span className="text-[10px] uppercase text-slate-400 font-bold block">From vs Return-Path Alignment</span>
                      <div className="font-bold mt-0.5">
                        {emailData.returnPathMismatch ? '⚠️ MISMATCH DETECTED' : '✅ DOMAIN ALIGNED'}
                      </div>
                      <p className="text-[11px] text-slate-400 mt-1 font-sans">
                        {emailData.returnPathMismatch 
                          ? 'Bounce envelope directed to external untrusted routing domain.'
                          : 'Return-Path matches authenticated sender.'}
                      </p>
                    </div>
                  </div>
                </div>

                {/* Email Body Preview */}
                {emailData.body && (
                  <div className="p-4 rounded-xl bg-[#060a14] border border-slate-800 space-y-2">
                    <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider block font-mono">
                      Message Body Content
                    </span>
                    <div className="text-xs text-slate-300 leading-relaxed font-sans whitespace-pre-wrap max-h-48 overflow-y-auto pr-2">
                      {emailData.body}
                    </div>
                  </div>
                )}

              </div>
            )}

            {/* Tab 2: AI & Linguistic Threat Model */}
            {activeTab === 'ai' && (
              <div className="space-y-5 font-mono text-xs">
                <div className="p-4 rounded-xl bg-[#060a14] border border-slate-800 flex flex-col sm:flex-row sm:items-center justify-between gap-4">
                  <div className="space-y-1">
                    <div className="text-slate-400 text-[11px]">Model Inference Engine:</div>
                    <div className="text-sm font-bold text-white">TF-IDF + Logistic Regression Classifier</div>
                    <div className="text-[11px] text-slate-500 font-sans">
                      Trained on 5,000 corporate phishing & legitimate email corpora
                    </div>
                  </div>

                  <div className="flex items-center gap-4">
                    <div className="text-right">
                      <span className="text-[10px] text-slate-400 block">AI Confidence</span>
                      <span className="text-xl font-bold text-cyan-300">{aiConfidence}%</span>
                    </div>
                    <div className="text-right">
                      <span className="text-[10px] text-slate-400 block">Verdict</span>
                      <span className="text-xl font-bold text-red-400">{riskLevel}</span>
                    </div>
                  </div>
                </div>

                {/* Salient NLP indicators */}
                {currentAnalysis?.aiThreat?.topFeatures?.length > 0 && (
                  <div className="p-4 rounded-xl bg-[#060a14] border border-slate-800 space-y-3">
                    <div className="flex items-center justify-between text-xs text-slate-300">
                      <span className="font-bold flex items-center gap-2">
                        <Cpu className="w-3.5 h-3.5 text-cyan-400" />
                        Salient Learned Predictive Terms (TF-IDF Attribution)
                      </span>
                    </div>
                    <div className="flex flex-wrap gap-2">
                      {currentAnalysis.aiThreat.topFeatures.map((feat, idx) => (
                        <span 
                          key={idx}
                          className="px-2.5 py-1 rounded-lg bg-slate-900 border border-slate-800 text-[11px] text-slate-200"
                        >
                          <strong className="text-cyan-300">"{feat.term}"</strong> <span className="text-slate-500">({feat.weight > 0 ? `+${feat.weight}` : feat.weight})</span>
                        </span>
                      ))}
                    </div>
                  </div>
                )}

                <p className="text-[11px] text-slate-500 font-sans italic">
                  * Note: Machine learning threat analysis generates probabilistic predictions and is fused with header authentication and IOC telemetry for deterministic scoring.
                </p>
              </div>
            )}

            {/* Tab 3: Authentication & Routing */}
            {activeTab === 'auth' && (
              <div className="space-y-6">
                
                {/* 3 Authentication Diagnostics */}
                <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 text-xs font-mono">
                  <div className={`p-3.5 rounded-xl border ${
                    (emailData.auth?.spf?.result === 'PASS') 
                      ? 'bg-emerald-950/20 border-emerald-500/40 text-emerald-300' 
                      : (emailData.auth?.spf?.result === 'SOFTFAIL')
                        ? 'bg-amber-950/20 border-amber-500/40 text-amber-300'
                        : 'bg-red-950/20 border-red-500/40 text-red-300'
                  }`}>
                    <div className="text-[10px] uppercase font-bold text-slate-400 mb-1">SPF Verification</div>
                    <div className="font-extrabold text-sm mb-1">
                      {emailData.auth?.spf?.result || 'UNKNOWN'}
                    </div>
                    <p className="text-[10px] text-slate-400 font-sans line-clamp-2">
                      {emailData.auth?.spf?.details || 'Sender IP not authorized in domain SPF records'}
                    </p>
                  </div>

                  <div className={`p-3.5 rounded-xl border ${
                    (emailData.auth?.dkim?.result === 'PASS') 
                      ? 'bg-emerald-950/20 border-emerald-500/40 text-emerald-300' 
                      : 'bg-red-950/20 border-red-500/40 text-red-300'
                  }`}>
                    <div className="text-[10px] uppercase font-bold text-slate-400 mb-1">DKIM Cryptographic Signature</div>
                    <div className="font-extrabold text-sm mb-1">
                      {emailData.auth?.dkim?.result || 'FAIL'}
                    </div>
                    <p className="text-[10px] text-slate-400 font-sans line-clamp-2">
                      {emailData.auth?.dkim?.details || 'Cryptographic signature mismatch or absent'}
                    </p>
                  </div>

                  <div className={`p-3.5 rounded-xl border ${
                    (emailData.auth?.dmarc?.result === 'PASS') 
                      ? 'bg-emerald-950/20 border-emerald-500/40 text-emerald-300' 
                      : 'bg-red-950/20 border-red-500/40 text-red-300'
                  }`}>
                    <div className="text-[10px] uppercase font-bold text-slate-400 mb-1">DMARC Policy Alignment</div>
                    <div className="font-extrabold text-sm mb-1">
                      {emailData.auth?.dmarc?.result || 'FAIL'}
                    </div>
                    <p className="text-[10px] text-slate-400 font-sans line-clamp-2">
                      {emailData.auth?.dmarc?.details || 'Domain alignment mandates quarantine or rejection'}
                    </p>
                  </div>
                </div>

                {/* Email Authentication Card Deep Inspection */}
                {(emailData.emailAuth || currentAnalysis?.emailAuth) && (
                  <EmailAuthenticationCard emailAuth={emailData.emailAuth || currentAnalysis?.emailAuth} />
                )}

              </div>
            )}

            {/* Tab 4: Payloads & IOCs */}
            {activeTab === 'payloads' && (
              <div className="space-y-6">
                
                {/* Entities Grid: URLs, IPs, Attachments */}
                <div className="grid grid-cols-1 lg:grid-cols-3 gap-4 text-xs font-mono">
                  {/* URLs */}
                  <div className="p-4 rounded-xl bg-[#060a14] border border-slate-800 space-y-2">
                    <span className="flex items-center gap-2 text-cyan-400 font-semibold text-xs">
                      <Globe className="w-3.5 h-3.5" /> URLs ({emailData.urls?.length || 0})
                    </span>
                    <div className="space-y-1.5">
                      {(emailData.urls || []).map((u, i) => (
                        <div key={i} className="p-2 rounded bg-slate-900/90 border border-slate-800 text-[11px] text-slate-300 break-all">
                          {u}
                        </div>
                      ))}
                      {(!emailData.urls || emailData.urls.length === 0) && (
                        <div className="text-[11px] text-slate-500 italic p-2">No external URLs detected</div>
                      )}
                    </div>
                  </div>

                  {/* Origin IPs */}
                  <div className="p-4 rounded-xl bg-[#060a14] border border-slate-800 space-y-2">
                    <span className="flex items-center gap-2 text-amber-400 font-semibold text-xs">
                      <Activity className="w-3.5 h-3.5" /> Origin IPs & Hops ({(emailData.ips || [emailData.originatingIP]).length})
                    </span>
                    <div className="space-y-1.5">
                      {(emailData.ips || [emailData.originatingIP]).map((ip, i) => (
                        <div key={i} className="p-2 rounded bg-slate-900/90 border border-slate-800 text-[11px] text-slate-300 break-all">
                          {ip}
                        </div>
                      ))}
                    </div>
                  </div>

                  {/* Attachments */}
                  <div className="p-4 rounded-xl bg-[#060a14] border border-slate-800 space-y-2">
                    <span className="flex items-center gap-2 text-red-400 font-semibold text-xs">
                      <Paperclip className="w-3.5 h-3.5" /> Attachments ({emailData.attachments?.length || 0})
                    </span>
                    <div className="space-y-1.5">
                      {(emailData.attachments || []).map((att, i) => (
                        <div key={i} className="p-2 rounded bg-slate-900/90 border border-red-500/30 space-y-0.5">
                          <div className="text-[11px] font-bold text-red-300 truncate">{att.filename}</div>
                          <div className="text-[10px] text-slate-400 flex items-center justify-between">
                            <span>{att.size}</span>
                            <span className="text-red-400 font-semibold">{att.flag}</span>
                          </div>
                        </div>
                      ))}
                      {(!emailData.attachments || emailData.attachments.length === 0) && (
                        <div className="text-[11px] text-slate-500 italic p-2">No attachments enclosed</div>
                      )}
                    </div>
                  </div>
                </div>

                {/* Deep Attachment Forensics Card */}
                {emailData.attachments?.length > 0 && (
                  <AttachmentForensicsCard attachments={emailData.attachments} />
                )}

              </div>
            )}

            {/* Tab 5: Raw RFC Source */}
            {activeTab === 'raw' && (
              <div className="space-y-3 font-mono text-xs">
                <div className="flex items-center justify-between text-slate-400">
                  <span>Raw RFC 822 MIME Envelope Snippet:</span>
                  <button
                    type="button"
                    onClick={handleCopyRaw}
                    className="flex items-center gap-1.5 px-3 py-1 rounded-lg bg-slate-800 hover:bg-slate-700 text-cyan-300 cursor-pointer transition-colors"
                  >
                    {copiedRaw ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                    <span>{copiedRaw ? 'Copied' : 'Copy All'}</span>
                  </button>
                </div>
                <pre className="p-4 rounded-xl bg-[#050912] border border-slate-800 text-slate-300 overflow-x-auto whitespace-pre-wrap leading-relaxed text-[11px] max-h-96">
                  {emailData.rawSnippet || 'No raw snippet stored.'}
                </pre>
              </div>
            )}

          </div>

        </div>
      ) : (
        <div className="rounded-2xl bg-[#091122]/40 border border-slate-800/80 p-8 text-center font-mono text-xs text-slate-400 space-y-3">
          <Mail className="w-8 h-8 mx-auto text-slate-600" />
          <p className="text-sm font-semibold text-slate-300">No email loaded in memory</p>
          <p className="text-xs text-slate-500">Choose a synthetic scenario above or upload a .eml file to begin analysis.</p>
        </div>
      )}

    </div>
  );
};
