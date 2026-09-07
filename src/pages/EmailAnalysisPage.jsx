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
  Terminal, 
  Cpu, 
  Activity, 
  RefreshCw,
  FolderOpen,
  ShieldCheck,
  ShieldX,
  FileText,
  Radio,
  ExternalLink
} from 'lucide-react';
import { parseEmailContent } from '../services/emailParser';
import { SYNTHETIC_SCENARIOS } from '../data/syntheticScenarios';
import { AttachmentForensicsCard } from '../components/dashboard/AttachmentForensicsCard.jsx';

const PIPELINE_STAGES = [
  { id: 1, name: 'Email Parsing', detail: 'Decoding MIME envelope, headers & boundary structures', duration: '34ms' },
  { id: 2, name: 'Header Forensics', detail: 'SPF, DKIM, DMARC alignment & hop traceroute validation', duration: '48ms' },
  { id: 3, name: 'NLP Threat Analysis', detail: 'Evaluating urgency sentiment, extortion & impersonation tokens', duration: '82ms' },
  { id: 4, name: 'IOC Extraction', detail: 'Extracting IPv4, suspicious domains, URLs & attachment hashes', duration: '41ms' },
  { id: 5, name: 'Threat Intelligence Enrichment', detail: 'Cross-referencing IOCs against synthetic threat reputation feeds', duration: '64ms' },
  { id: 6, name: 'GeoLocation / ASN Analysis', detail: 'Resolving Autonomous Systems, BGP paths & origin nations', duration: '55ms' },
  { id: 7, name: 'Graph Correlation', detail: 'Linking threat actors, infrastructure nodes & targeted assets', duration: '71ms' },
  { id: 8, name: 'Risk Scoring', detail: 'Computing multi-factor explainable risk index & confidence level', duration: '38ms' }
];

export const EmailAnalysisPage = ({ onViewChange, currentAnalysis, onRunAnalysis }) => {
  const [emailData, setEmailData] = useState(currentAnalysis?.email || null);
  const [selectedScenarioId, setSelectedScenarioId] = useState('ceo-bec');
  const [isDragActive, setIsDragActive] = useState(false);
  const [showRawHeaders, setShowRawHeaders] = useState(false);
  const [showRawPasteModal, setShowRawPasteModal] = useState(false);
  const [pastedRawText, setPastedRawText] = useState('');
  const [copiedRaw, setCopiedRaw] = useState(false);
  
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

  // Update when currentAnalysis changes externally
  useEffect(() => {
    if (currentAnalysis?.email) {
      setEmailData(currentAnalysis.email);
    }
  }, [currentAnalysis]);

  // Load a synthetic scenario
  const handleLoadScenario = async (scenarioId) => {
    setSelectedScenarioId(scenarioId);
    const scenario = SYNTHETIC_SCENARIOS.find(s => s.id === scenarioId) || SYNTHETIC_SCENARIOS[0];
    const parsed = await parseEmailContent(scenario.rawSnippet);
    
    // Attach known scenario enrichment fields
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
  };

  const handleBrowseClick = (e) => {
    if (e && typeof e.stopPropagation === 'function') e.stopPropagation();
    if (fileInputRef.current) fileInputRef.current.click();
  };

  // Handle actual file upload (.eml or .txt)
  const handleFileUpload = async (file) => {
    if (!file) return;
    try {
      const reader = new FileReader();
      reader.onload = async (event) => {
        const text = event.target?.result;
        if (typeof text === 'string') {
          const parsed = await parseEmailContent(text, { name: file.name, size: file.size });
          parsed.scenarioName = `Uploaded: ${file.name}`;
          parsed.tag = 'REAL INGESTED FILE';
          setEmailData(parsed);
          setAnalysisState('idle');
          setActiveStageIndex(-1);
          setStageStatuses(PIPELINE_STAGES.map(() => 'pending'));
        }
      };
      reader.readAsText(file);
    } catch (err) {
      console.error('Error reading email file:', err);
    }
  };

  const handleFileChange = (e) => {
    const file = e.target.files?.[0];
    if (file) handleFileUpload(file);
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
    setShowRawPasteModal(false);
    setAnalysisState('idle');
    setActiveStageIndex(-1);
    setStageStatuses(PIPELINE_STAGES.map(() => 'pending'));
  };

  const handleCopyRaw = () => {
    if (emailData?.rawSnippet) {
      navigator.clipboard?.writeText(emailData.rawSnippet);
      setCopiedRaw(true);
      setTimeout(() => setCopiedRaw(false), 1500);
    }
  };

  // Run the 8-stage pipeline and call parent handler
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

        // Pass parsed email to parent state to execute evidence fusion & case generation
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

  // Active risk scores from parent fusion engine or defaults
  const riskScore = currentAnalysis?.fusion?.threatScore || 92;
  const riskLevel = currentAnalysis?.fusion?.riskLevel || 'HIGH';
  const aiConfidence = currentAnalysis?.aiThreat?.confidence || 92;

  return (
    <div className="space-y-6 pb-12 font-sans">
      
      {/* Hidden file input for real .eml upload */}
      <input 
        type="file" 
        ref={fileInputRef} 
        onChange={handleFileChange} 
        accept=".eml,.msg,.txt" 
        className="hidden" 
      />

      {/* Top Banner Header */}
      <div className="relative overflow-hidden rounded-2xl bg-gradient-to-r from-[#0c162b] via-[#091122] to-[#070b13] border border-cyan-500/30 p-6 shadow-[0_0_30px_rgba(6,182,212,0.1)]">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
          <div>
            <div className="flex items-center gap-2 text-cyan-400 text-xs font-mono mb-1">
              <span className="w-2 h-2 rounded-full bg-cyan-400 animate-ping"></span>
              STAGE 01 & 02 OF 08 • EMAIL INGESTION & HEADER FORENSICS
            </div>
            <h1 className="text-xl sm:text-2xl font-extrabold text-white font-mono flex items-center gap-2.5">
              <span>Suspicious Email Ingestion & Analysis Engine</span>
            </h1>
            <p className="text-xs text-slate-300 mt-1 max-w-3xl">
              Ingest raw <strong className="text-cyan-300">.eml files</strong>, RFC 822 headers, or select controlled SIH synthetic scenarios to execute the 8-stage automated threat verification pipeline.
            </p>
          </div>

          <div className="flex items-center gap-2 font-mono text-xs">
            <span className="px-2.5 py-1 rounded bg-slate-900/90 border border-slate-800 text-slate-400">
              Environment: <strong className="text-cyan-300">SIH 2026 Simulation</strong>
            </span>
          </div>
        </div>
      </div>

      {/* Section 1: Ingestion Zone & 5 Controlled Synthetic Presets */}
      <div className="rounded-xl bg-[#09101e] border border-slate-800/90 p-5 shadow-lg space-y-4">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-slate-800 pb-3">
          <div className="flex items-center gap-2">
            <UploadCloud className="w-5 h-5 text-cyan-400" />
            <h2 className="text-sm font-bold uppercase tracking-wider font-mono text-slate-100">
              Email Ingestion Controls
            </h2>
          </div>
          <span className="text-[11px] font-mono text-slate-400">
            Accepts RFC 822 / MIME (.eml, .txt) & Untrusted Payloads
          </span>
        </div>

        {/* 5 SIH Controlled Synthetic Scenarios Selector */}
        <div className="space-y-2">
          <span className="text-[11px] font-mono text-slate-400 uppercase tracking-wider block font-bold">
            Controlled SIH Demo Scenarios (One-Click Ingest):
          </span>
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-2">
            {SYNTHETIC_SCENARIOS.map(scenario => {
              const isSelected = selectedScenarioId === scenario.id;
              return (
                <button
                  key={scenario.id}
                  type="button"
                  onClick={() => handleLoadScenario(scenario.id)}
                  className={`p-2.5 rounded-lg border text-left font-mono transition-all cursor-pointer ${
                    isSelected 
                      ? 'bg-cyan-950/80 border-cyan-400 text-white shadow-[0_0_12px_rgba(6,182,212,0.3)]' 
                      : 'bg-[#060a14] border-slate-800 text-slate-400 hover:border-slate-700 hover:text-slate-200'
                  }`}
                >
                  <div className="flex items-center justify-between mb-1">
                    <span className="text-[11px] font-bold truncate text-cyan-300">{scenario.name}</span>
                  </div>
                  <span className="text-[9px] uppercase px-1.5 py-0.2 rounded bg-slate-900 border border-slate-800 text-slate-400 block truncate">
                    {scenario.category}
                  </span>
                </button>
              );
            })}
          </div>
        </div>

        {/* Upload & Paste Action Bar */}
        <div className="flex flex-wrap items-center gap-3 p-3 rounded-lg bg-[#060a14] border border-slate-800">
          <button
            type="button"
            id="btn-browse-file"
            onClick={handleBrowseClick}
            className="flex items-center gap-2 px-4 py-2.5 rounded-lg bg-[#0d1c38] hover:bg-[#122850] border border-cyan-500/40 text-cyan-300 text-xs font-mono font-semibold transition-all shadow-sm cursor-pointer"
          >
            <FolderOpen className="w-4 h-4 text-cyan-400" />
            <span>Upload .eml File</span>
          </button>

          <button
            type="button"
            onClick={() => setShowRawPasteModal(true)}
            className="flex items-center gap-2 px-4 py-2.5 rounded-lg bg-slate-900 hover:bg-slate-800 border border-slate-700 text-slate-300 text-xs font-mono transition-all cursor-pointer"
          >
            <FileCode className="w-4 h-4 text-slate-400" />
            <span>Paste Raw RFC Headers</span>
          </button>

          <span className="text-[11px] font-mono text-slate-400 ml-auto hidden md:inline">
            Attachments processed safely: <strong className="text-emerald-400 font-semibold">Strictly quarantined / No binary execution</strong>
          </span>
        </div>

        {/* Drag and drop area */}
        <div
          onDragOver={handleDragOver}
          onDragLeave={handleDragLeave}
          onDrop={handleDrop}
          onClick={handleBrowseClick}
          className={`rounded-xl border-2 border-dashed p-6 text-center transition-all duration-200 cursor-pointer ${
            isDragActive
              ? 'border-cyan-400 bg-cyan-950/30 shadow-[0_0_20px_rgba(6,182,212,0.25)]'
              : 'border-slate-800 hover:border-cyan-500/40 bg-[#060a14]/60'
          }`}
        >
          <div className="flex flex-col items-center justify-center space-y-2">
            <UploadCloud className="w-8 h-8 text-cyan-400 opacity-80" />
            <p className="text-xs font-medium text-slate-300">
              Drag and drop an <span className="text-cyan-300 font-mono font-bold">.eml</span> or <span className="text-cyan-300 font-mono font-bold">.txt</span> file here, or click to browse
            </p>
            <p className="text-[11px] text-slate-500 font-mono">
              Automatic RFC 822 parser extracts headers, routing hops, URLs, IPs, and cryptographic attachment hashes
            </p>
          </div>
        </div>
      </div>

      {/* Raw Paste Modal */}
      {showRawPasteModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm">
          <div className="w-full max-w-2xl rounded-2xl bg-[#09101e] border border-cyan-500/40 p-6 space-y-4 font-mono">
            <h3 className="text-sm font-bold text-white flex items-center gap-2">
              <FileCode className="w-4 h-4 text-cyan-400" />
              <span>Paste RFC 822 Email Headers & Body</span>
            </h3>
            <textarea
              rows={8}
              value={pastedRawText}
              onChange={(e) => setPastedRawText(e.target.value)}
              placeholder="Delivered-To: ...&#10;From: ...&#10;Subject: ...&#10;Received: from ...&#10;&#10;Email body..."
              className="w-full p-3 bg-[#050810] border border-slate-800 rounded-lg text-xs text-slate-200 focus:outline-none focus:border-cyan-500"
            />
            <div className="flex justify-end gap-2">
              <button
                type="button"
                onClick={() => setShowRawPasteModal(false)}
                className="px-4 py-2 rounded-lg bg-slate-800 text-xs text-slate-300 hover:bg-slate-700"
              >
                Cancel
              </button>
              <button
                type="button"
                onClick={handleApplyPastedRaw}
                className="px-4 py-2 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-xs text-white font-bold"
              >
                Parse Ingested Headers
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Section 2: Ingested Email Telemetry & Header Forensics */}
      {emailData ? (
        <div id="email-telemetry-container" className="rounded-xl bg-[#09101e] border border-cyan-500/50 p-5 sm:p-6 shadow-[0_0_25px_rgba(6,182,212,0.15)] space-y-5">
          
          {/* Header */}
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-slate-800 pb-3">
            <div className="flex items-center gap-2.5">
              <Mail className="w-5 h-5 text-cyan-400" />
              <h2 className="text-sm font-bold uppercase tracking-wider font-mono text-white">
                Ingested Email Telemetry & Forensics
              </h2>
              <span className="text-[10px] font-mono px-2.5 py-0.5 rounded bg-cyan-950/90 border border-cyan-400 text-cyan-300 font-extrabold shadow-[0_0_10px_rgba(6,182,212,0.3)] flex items-center gap-1.5">
                <span className="w-1.5 h-1.5 rounded-full bg-cyan-400 animate-pulse"></span>
                <span>{emailData.tag || 'INGESTED'}</span>
              </span>
            </div>

            <div className="flex items-center gap-2">
              <button
                type="button"
                onClick={() => setShowRawHeaders(!showRawHeaders)}
                className="text-xs font-mono text-slate-400 hover:text-cyan-300 transition-colors flex items-center gap-1.5 px-2.5 py-1 rounded bg-[#060a14] border border-slate-800"
              >
                <FileCode className="w-3.5 h-3.5 text-cyan-400" />
                <span>{showRawHeaders ? 'Hide RFC Headers' : 'View RFC Headers'}</span>
              </button>
            </div>
          </div>

          {/* Core Metadata: Sender, Recipient, Subject, Date */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4 font-mono text-xs">
            
            <div className="p-3.5 rounded-lg bg-[#060a14] border border-slate-800/80 space-y-1">
              <span className="text-[10px] uppercase text-slate-500 font-semibold block">Sender (From)</span>
              <div className="text-slate-200 font-medium break-all">{emailData.sender}</div>
            </div>

            <div className="p-3.5 rounded-lg bg-[#060a14] border border-slate-800/80 space-y-1">
              <span className="text-[10px] uppercase text-slate-500 font-semibold block">Recipient (To)</span>
              <div className="text-cyan-300 font-medium break-all">{emailData.recipient}</div>
            </div>

            <div className="p-3.5 rounded-lg bg-[#060a14] border border-slate-800/80 space-y-1">
              <span className="text-[10px] uppercase text-slate-500 font-semibold block">Subject</span>
              <div className="text-white font-medium">{emailData.subject}</div>
            </div>

            <div className="p-3.5 rounded-lg bg-[#060a14] border border-slate-800/80 space-y-1">
              <span className="text-[10px] uppercase text-slate-500 font-semibold block">Date / Timestamp</span>
              <div className="text-slate-300">{emailData.date}</div>
            </div>

          </div>

          {/* Phase 2: Email Header Forensics & Alignment Diagnostics */}
          <div className="space-y-3 font-mono text-xs border-t border-slate-800 pt-4">
            <div className="flex items-center justify-between">
              <span className="text-[11px] uppercase text-slate-400 font-bold tracking-wider flex items-center gap-2">
                <ShieldAlert className="w-4 h-4 text-cyan-400" />
                Email Header Forensics & Cryptographic Alignment
              </span>
              <span className="text-[10px] text-slate-500">
                RFC 7208 / RFC 6376 / RFC 7489
              </span>
            </div>

            {/* Authentication Protocol Diagnostic Cards */}
            <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
              
              {/* SPF Result */}
              <div className={`p-3 rounded-lg border ${
                (emailData.auth?.spf?.result === 'PASS') 
                  ? 'bg-emerald-950/30 border-emerald-500/40 text-emerald-300' 
                  : (emailData.auth?.spf?.result === 'SOFTFAIL')
                    ? 'bg-amber-950/30 border-amber-500/40 text-amber-300'
                    : 'bg-red-950/30 border-red-500/40 text-red-300'
              }`}>
                <div className="flex items-center justify-between mb-1">
                  <span className="text-[10px] uppercase font-bold text-slate-400">SPF Verification</span>
                  <span className="font-extrabold text-xs">
                    {emailData.auth?.spf?.result || (emailData.spfResult ? emailData.spfResult.split(' ')[0] : 'UNKNOWN')}
                  </span>
                </div>
                <p className="text-[10px] text-slate-400 line-clamp-2">
                  {emailData.auth?.spf?.details || emailData.spfResult || 'Sender IP not authorized in domain SPF records'}
                </p>
              </div>

              {/* DKIM Result */}
              <div className={`p-3 rounded-lg border ${
                (emailData.auth?.dkim?.result === 'PASS') 
                  ? 'bg-emerald-950/30 border-emerald-500/40 text-emerald-300' 
                  : 'bg-red-950/30 border-red-500/40 text-red-300'
              }`}>
                <div className="flex items-center justify-between mb-1">
                  <span className="text-[10px] uppercase font-bold text-slate-400">DKIM Cryptographic Signature</span>
                  <span className="font-extrabold text-xs">
                    {emailData.auth?.dkim?.result || (emailData.dkimResult ? emailData.dkimResult.split(' ')[0] : 'UNKNOWN')}
                  </span>
                </div>
                <p className="text-[10px] text-slate-400 line-clamp-2">
                  {emailData.auth?.dkim?.details || emailData.dkimResult || 'Cryptographic body signature mismatch or missing'}
                </p>
              </div>

              {/* DMARC Result */}
              <div className={`p-3 rounded-lg border ${
                (emailData.auth?.dmarc?.result === 'PASS') 
                  ? 'bg-emerald-950/30 border-emerald-500/40 text-emerald-300' 
                  : 'bg-red-950/30 border-red-500/40 text-red-300'
              }`}>
                <div className="flex items-center justify-between mb-1">
                  <span className="text-[10px] uppercase font-bold text-slate-400">DMARC Policy Alignment</span>
                  <span className="font-extrabold text-xs">
                    {emailData.auth?.dmarc?.result || (emailData.dmarcResult ? emailData.dmarcResult.split(' ')[0] : 'UNKNOWN')}
                  </span>
                </div>
                <p className="text-[10px] text-slate-400 line-clamp-2">
                  {emailData.auth?.dmarc?.details || emailData.dmarcResult || 'Domain alignment mandates quarantine or rejection'}
                </p>
              </div>

            </div>

            {/* Mismatch Indicators with Forensic Explanations */}
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 pt-1">
              
              <div className={`p-3 rounded-lg border flex items-start justify-between gap-2 ${
                emailData.replyToMismatch
                  ? 'bg-amber-950/20 border-amber-500/40 text-amber-300'
                  : 'bg-[#060a14] border-slate-800 text-slate-300'
              }`}>
                <div>
                  <span className="text-[10px] uppercase text-slate-400 font-bold block">From vs Reply-To Alignment</span>
                  <div className="font-bold text-xs mt-0.5">
                    {emailData.replyToMismatch ? '⚠️ MISMATCH DETECTED' : '✅ DOMAIN ALIGNED'}
                  </div>
                  <p className="text-[10px] text-slate-400 mt-1">
                    {emailData.replyToMismatch 
                      ? 'Replies redirected to an external address differing from sender identity.'
                      : 'Reply-To points to authorized sender domain.'}
                  </p>
                </div>
                {emailData.replyToMismatch && (
                  <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-amber-950 text-amber-300 border border-amber-500/40 shrink-0">
                    High BEC Risk
                  </span>
                )}
              </div>

              <div className={`p-3 rounded-lg border flex items-start justify-between gap-2 ${
                emailData.returnPathMismatch
                  ? 'bg-amber-950/20 border-amber-500/40 text-amber-300'
                  : 'bg-[#060a14] border-slate-800 text-slate-300'
              }`}>
                <div>
                  <span className="text-[10px] uppercase text-slate-400 font-bold block">From vs Return-Path Alignment</span>
                  <div className="font-bold text-xs mt-0.5">
                    {emailData.returnPathMismatch ? '⚠️ MISMATCH DETECTED' : '✅ DOMAIN ALIGNED'}
                  </div>
                  <p className="text-[10px] text-slate-400 mt-1">
                    {emailData.returnPathMismatch 
                      ? 'Bounce envelope directed to external untrusted routing domain.'
                      : 'Return-Path matches authenticated sender.'}
                  </p>
                </div>
                {emailData.returnPathMismatch && (
                  <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-amber-950 text-amber-300 border border-amber-500/40 shrink-0">
                    Spoofing Risk
                  </span>
                )}
              </div>

            </div>

          </div>

          {/* Detected Entities: URLs, IP Addresses, Attachments */}
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-4 font-mono text-xs">
            
            {/* Detected URLs */}
            <div className="p-3.5 rounded-lg bg-[#060a14] border border-slate-800 space-y-2">
              <div className="flex items-center justify-between text-slate-300 font-bold text-[11px]">
                <span className="flex items-center gap-1.5 text-cyan-400">
                  <Globe className="w-3.5 h-3.5" /> Detected URLs ({emailData.urls?.length || 0})
                </span>
              </div>
              <div className="space-y-1.5">
                {(emailData.urls || []).map((url, idx) => (
                  <div key={idx} className="p-2 rounded bg-slate-900/90 border border-slate-800 text-[11px] text-slate-300 break-all font-mono">
                    {url}
                  </div>
                ))}
                {(!emailData.urls || emailData.urls.length === 0) && (
                  <div className="text-[11px] text-slate-500 italic p-2">No external hyperlinks detected</div>
                )}
              </div>
            </div>

            {/* Detected IP addresses */}
            <div className="p-3.5 rounded-lg bg-[#060a14] border border-slate-800 space-y-2">
              <div className="flex items-center justify-between text-slate-300 font-bold text-[11px]">
                <span className="flex items-center gap-1.5 text-amber-400">
                  <Activity className="w-3.5 h-3.5" /> Detected IPs & Hops ({(emailData.ips || [emailData.originatingIP]).length})
                </span>
              </div>
              <div className="space-y-1.5">
                {(emailData.ips || [emailData.originatingIP]).map((ip, idx) => (
                  <div key={idx} className="p-2 rounded bg-slate-900/90 border border-slate-800 text-[11px] text-slate-300 break-all font-mono">
                    {ip}
                  </div>
                ))}
              </div>
            </div>

            {/* Attachments */}
            <div className="p-3.5 rounded-lg bg-[#060a14] border border-slate-800 space-y-2">
              <div className="flex items-center justify-between text-slate-300 font-bold text-[11px]">
                <span className="flex items-center gap-1.5 text-red-400">
                  <Paperclip className="w-3.5 h-3.5" /> Attachments ({emailData.attachments?.length || 0})
                </span>
              </div>
              <div className="space-y-1.5">
                {(emailData.attachments || []).map((att, idx) => (
                  <div key={idx} className="p-2 rounded bg-slate-900/90 border border-red-500/30 space-y-1">
                    <div className="text-[11px] font-bold text-red-300 break-all font-mono">
                      {att.filename}
                    </div>
                    <div className="text-[10px] text-slate-400 flex items-center justify-between">
                      <span>Size: {att.size}</span>
                      <span className="text-red-400 font-bold">{att.flag}</span>
                    </div>
                    {att.sha256 && (
                      <div className="text-[9px] text-slate-500 truncate">
                        SHA256: {att.sha256}
                      </div>
                    )}
                  </div>
                ))}
                {(!emailData.attachments || emailData.attachments.length === 0) && (
                  <div className="text-[11px] text-slate-500 italic p-2">No file attachments enclosed</div>
                )}
              </div>
            </div>

          </div>

          {/* 📎 ATTACHMENT FORENSICS Deep Inspection Section */}
          {emailData.attachments && emailData.attachments.length > 0 && (
            <AttachmentForensicsCard attachments={emailData.attachments} />
          )}

          {/* Optional Raw Headers Snippet */}
          {showRawHeaders && (
            <div className="p-3.5 rounded-lg bg-[#050810] border border-slate-800 font-mono text-xs space-y-2">
              <div className="flex items-center justify-between text-slate-400 pb-1 border-b border-slate-800">
                <span>Raw MIME Header Snippet (RFC 822)</span>
                <button
                  type="button"
                  onClick={handleCopyRaw}
                  className="flex items-center gap-1 text-cyan-400 hover:text-cyan-300 cursor-pointer"
                >
                  {copiedRaw ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                  <span>{copiedRaw ? 'Copied' : 'Copy'}</span>
                </button>
              </div>
              <pre className="text-[11px] text-slate-300 overflow-x-auto whitespace-pre-wrap leading-relaxed">
                {emailData.rawSnippet}
              </pre>
            </div>
          )}

          {/* Analyze Email CTA Button */}
          <div className="pt-3 border-t border-slate-800 flex flex-col sm:flex-row items-center justify-between gap-3">
            <span className="text-xs font-mono text-slate-400">
              Payload parsed. Ready to execute 8-stage automated forensic analysis pipeline.
            </span>

            <button
              type="button"
              id="btn-analyze-email"
              onClick={startAnalysis}
              disabled={analysisState === 'analyzing'}
              className="w-full sm:w-auto flex items-center justify-center gap-2.5 px-6 py-2.5 rounded-xl bg-gradient-to-r from-cyan-600 via-sky-600 to-blue-600 hover:from-cyan-500 hover:to-blue-500 text-white text-xs font-mono font-bold shadow-[0_0_20px_rgba(6,182,212,0.4)] transition-all cursor-pointer disabled:opacity-50 active:scale-95"
            >
              {analysisState === 'analyzing' ? (
                <>
                  <Loader2 className="w-4 h-4 animate-spin text-cyan-200" />
                  <span>Executing Pipeline...</span>
                </>
              ) : (
                <>
                  <Zap className="w-4 h-4 fill-current" />
                  <span>Analyze Email</span>
                </>
              )}
            </button>
          </div>

        </div>
      ) : (
        <div className="rounded-xl bg-[#09101e]/60 border border-slate-800/80 p-6 text-center font-mono text-xs text-slate-400 space-y-3">
          <div className="w-10 h-10 rounded-full bg-slate-900 border border-slate-800 mx-auto flex items-center justify-center text-slate-500">
            <Mail className="w-5 h-5" />
          </div>
          <div>
            <p className="text-slate-300 font-semibold text-sm">No email currently loaded in parser memory</p>
            <p className="text-slate-500 text-xs mt-1">
              Select a scenario above or upload a .eml file to initiate automated analysis.
            </p>
          </div>
          <button
            type="button"
            onClick={() => handleLoadScenario('ceo-bec')}
            className="inline-flex items-center gap-2 px-4 py-2 rounded-lg bg-cyan-950 border border-cyan-500/50 text-cyan-300 text-xs font-mono font-bold hover:bg-cyan-900 transition-colors cursor-pointer"
          >
            <Zap className="w-4 h-4 fill-current" />
            <span>Load Demo BEC Scenario</span>
          </button>
        </div>
      )}

      {/* Section 3: 8-Stage Simulated Analysis Pipeline */}
      {analysisState !== 'idle' && (
        <div id="pipeline-stages-container" className="rounded-xl bg-[#09101e] border border-slate-800 p-5 shadow-xl space-y-5 font-mono">
          
          <div className="space-y-2">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
              <div className="flex items-center gap-2">
                <Cpu className="w-5 h-5 text-cyan-400" />
                <h3 className="text-sm font-bold uppercase tracking-wider text-white">
                  8-Stage Forensic Analysis Pipeline
                </h3>
              </div>
              <div className="text-xs text-cyan-300 font-bold flex items-center gap-2">
                <span>{progressPercentage}% Complete</span>
                {analysisState === 'analyzing' && (
                  <span className="w-2 h-2 rounded-full bg-cyan-400 animate-ping"></span>
                )}
              </div>
            </div>

            <div className="w-full h-2 bg-slate-800 rounded-full overflow-hidden">
              <div 
                className="h-full bg-gradient-to-r from-cyan-500 via-sky-500 to-blue-500 transition-all duration-300 rounded-full shadow-[0_0_10px_rgba(6,182,212,0.5)]"
                style={{ width: `${progressPercentage}%` }}
              />
            </div>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-3">
            {PIPELINE_STAGES.map((stage, idx) => {
              const status = stageStatuses[idx];
              const isProcessing = status === 'processing';
              const isCompleted = status === 'completed';
              const isPending = status === 'pending';

              return (
                <div
                  key={stage.id}
                  className={`p-3.5 rounded-lg border transition-all duration-200 flex flex-col justify-between ${
                    isProcessing
                      ? 'bg-[#0e1f3a] border-cyan-400 shadow-[0_0_15px_rgba(6,182,212,0.3)]'
                      : isCompleted
                        ? 'bg-[#08151f] border-emerald-500/40 text-slate-300'
                        : 'bg-[#060a14] border-slate-800/80 text-slate-500'
                  }`}
                >
                  <div>
                    <div className="flex items-center justify-between text-xs mb-1.5">
                      <span className={`font-bold ${isProcessing ? 'text-cyan-300' : isCompleted ? 'text-emerald-400' : 'text-slate-600'}`}>
                        0{stage.id}
                      </span>

                      {isProcessing && (
                        <span className="flex items-center gap-1 text-[10px] font-bold text-cyan-300 px-1.5 py-0.2 rounded bg-cyan-950 border border-cyan-500/40">
                          <Loader2 className="w-3 h-3 animate-spin text-cyan-400" />
                          <span>PROCESSING</span>
                        </span>
                      )}

                      {isCompleted && (
                        <span className="flex items-center gap-1 text-[10px] font-bold text-emerald-300 px-1.5 py-0.2 rounded bg-emerald-950/60 border border-emerald-500/40">
                          <CheckCircle2 className="w-3 h-3 text-emerald-400" />
                          <span>COMPLETED</span>
                        </span>
                      )}

                      {isPending && (
                        <span className="flex items-center gap-1 text-[10px] text-slate-500 px-1.5 py-0.2 rounded bg-slate-900 border border-slate-800">
                          <Clock className="w-3 h-3" />
                          <span>PENDING</span>
                        </span>
                      )}
                    </div>

                    <div className={`text-xs font-bold ${isProcessing ? 'text-white' : isCompleted ? 'text-slate-200' : 'text-slate-400'}`}>
                      {stage.name}
                    </div>

                    <div className="text-[10px] text-slate-400 mt-1 line-clamp-2 leading-tight">
                      {stage.detail}
                    </div>
                  </div>

                  <div className="mt-2.5 pt-2 border-t border-slate-800/60 flex items-center justify-between text-[9px] text-slate-500">
                    <span>Latency:</span>
                    <span className={isCompleted ? 'text-cyan-300 font-bold' : ''}>
                      {isCompleted ? stage.duration : '--'}
                    </span>
                  </div>
                </div>
              );
            })}
          </div>

        </div>
      )}

      {/* Section 4: Analysis Complete Card */}
      {analysisState === 'completed' && (
        <div id="analysis-results-summary" className="rounded-xl bg-gradient-to-r from-red-950/40 via-[#0d172c] to-[#070b13] border-2 border-red-500/50 p-6 shadow-[0_0_30px_rgba(239,68,68,0.2)] font-mono space-y-5">
          
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-slate-800 pb-4">
            <div className="flex items-center gap-3">
              <div className="w-10 h-10 rounded-xl bg-emerald-950/80 border border-emerald-500/40 flex items-center justify-center text-emerald-400 shadow-[0_0_15px_rgba(16,185,129,0.3)]">
                <CheckCircle2 className="w-6 h-6" />
              </div>
              <div>
                <h3 className="text-base font-extrabold text-white">
                  Automated Forensic Analysis Complete
                </h3>
                <p className="text-xs text-slate-400">
                  Multi-layer evidence fusion, NLP threat classification, and IOC correlation synthesized
                </p>
              </div>
            </div>

            <div className="flex items-center gap-2">
              <button
                type="button"
                onClick={startAnalysis}
                className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs transition-colors cursor-pointer"
              >
                <RefreshCw className="w-3.5 h-3.5" />
                <span>Re-run Pipeline</span>
              </button>
            </div>
          </div>

          {/* Results Metric Row: Risk Level, Risk Score, Confidence */}
          <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
            
            <div className="p-4 rounded-xl bg-[#060a14] border border-red-500/40 text-center space-y-1">
              <span className="text-[11px] uppercase tracking-wider text-slate-400 block">
                Threat Verdict
              </span>
              <div className="text-2xl font-black text-red-400 flex items-center justify-center gap-1.5">
                <span className="w-2.5 h-2.5 rounded-full bg-red-400 animate-pulse"></span>
                <span>{riskLevel}</span>
              </div>
              <span className="text-[10px] text-red-300/80">Immediate Remediation Recommended</span>
            </div>

            <div className="p-4 rounded-xl bg-[#060a14] border border-red-500/40 text-center space-y-1">
              <span className="text-[11px] uppercase tracking-wider text-slate-400 block">
                Evidence Fusion Score
              </span>
              <div className="text-3xl font-black text-white">
                {riskScore}<span className="text-base text-slate-400 font-normal"> / 100</span>
              </div>
              <span className="text-[10px] text-slate-400">Synthesized from 6 Forensic Layers</span>
            </div>

            <div className="p-4 rounded-xl bg-[#060a14] border border-cyan-500/40 text-center space-y-1">
              <span className="text-[11px] uppercase tracking-wider text-slate-400 block">
                AI Confidence
              </span>
              <div className="text-3xl font-black text-cyan-300">
                {aiConfidence}%
              </div>
              <span className="text-[10px] text-slate-400">Calibrated NLP Certainty</span>
            </div>

          </div>

          {/* Action to Navigate to Results */}
          <div className="pt-2 flex flex-col sm:flex-row items-center justify-between gap-3">
            <span className="text-xs text-slate-400 text-center sm:text-left">
              Proceed to inspect detailed attribution weights, homoglyphs, and IOC breakdown.
            </span>

            <button
              type="button"
              id="btn-view-analysis-results"
              onClick={() => onViewChange('analysis-results')}
              className="w-full sm:w-auto flex items-center justify-center gap-2 px-6 py-2.5 rounded-xl bg-gradient-to-r from-cyan-600 via-sky-600 to-blue-600 hover:from-cyan-500 hover:to-blue-500 text-white text-xs font-mono font-bold shadow-[0_0_20px_rgba(6,182,212,0.4)] transition-all cursor-pointer active:scale-95"
            >
              <span>View Explainable Verdict</span>
              <ArrowRight className="w-4 h-4" />
            </button>
          </div>

        </div>
      )}

    </div>
  );
};
