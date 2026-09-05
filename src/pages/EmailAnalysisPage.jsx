import React, { useState, useRef, useEffect } from 'react';
import { 
  UploadCloud, 
  FileCode, 
  CheckCircle2, 
  Clock, 
  AlertTriangle, 
  ArrowRight, 
  ShieldAlert, 
  Play, 
  Zap, 
  Copy, 
  Check, 
  Loader2, 
  Mail, 
  Globe, 
  Paperclip, 
  FileText, 
  Terminal, 
  Cpu, 
  Layers, 
  Activity, 
  RefreshCw,
  FolderOpen
} from 'lucide-react';

const DEMO_EMAIL_DATA = {
  sender: 'Satya N. (Executive Desk) <cfo-finance-update@internal-corp-portal.online>',
  recipient: 'treasury-controller@gov-organization.in',
  subject: 'URGENT: Executive Wire Authorization - SIH-Q3 Allocation',
  date: 'Fri, 05 Sep 2026 11:41:50 +0530 (IST)',
  spfResult: 'SOFTFAIL (IP 185.220.101.45 not authorized)',
  dkimResult: 'FAIL (Invalid Cryptographic Signature)',
  dmarcResult: 'FAIL (Policy: Reject / Quarantine Enforced)',
  urls: [
    'http://internal-corp-portal.online/auth-portal/wire-release',
    'http://auth.secure-sso-verify.me/token'
  ],
  ips: [
    '185.220.101.45 (AS9009 - Tor Relay Node, Germany)',
    '45.154.255.82 (AS202425 - Reverse Proxy, Netherlands)',
    '194.26.29.110 (AS48693 - Relay Endpoint, Romania)'
  ],
  attachments: [
    {
      filename: 'Wire_Remittance_Directive.pdf.exe',
      size: '242.6 KB',
      flag: 'Double Extension / Obfuscated PE32 Executable'
    }
  ],
  rawSnippet: `Delivered-To: treasury-controller@gov-organization.in
Received: by 2002:a05:6512:2184 with SMTP id p4csp392873;
        Fri, 5 Sep 2026 11:41:50 +0530 (IST)
Return-Path: <cfo-finance-update@internal-corp-portal.online>
Received-SPF: softfail (mail.gov.in: domain of cfo-finance-update@internal-corp-portal.online does not designate 185.220.101.45)
Authentication-Results: mail.gov.in;
       dkim=fail (bad signature) header.i=@internal-corp-portal.online;
       dmarc=fail (p=REJECT sp=REJECT)
From: "Satya N. (Executive Desk)" <cfo-finance-update@internal-corp-portal.online>
Reply-To: <external-offshore-treasury@proton.me>
To: <treasury-controller@gov-organization.in>
Subject: URGENT: Executive Wire Authorization - SIH-Q3 Allocation
Date: Fri, 5 Sep 2026 11:41:50 +0530
Message-ID: <SIH-2026-MIME-8841@internal-corp-portal.online>

Treasury Controller,
Expedite statutory allocation transfer of INR 4,85,00,000 immediately for critical infrastructure.
Ministerial Directive bypass applied. Verification documents attached.`
};

const INITIAL_PIPELINE_STAGES = [
  { id: 1, name: 'Email Parsing', detail: 'Decoding MIME envelope, headers & boundary structures', duration: '34ms' },
  { id: 2, name: 'Header Forensics', detail: 'SPF, DKIM, DMARC alignment & hop traceroute validation', duration: '48ms' },
  { id: 3, name: 'NLP Threat Analysis', detail: 'Evaluating urgency sentiment, extortion & impersonation tokens', duration: '82ms' },
  { id: 4, name: 'IOC Extraction', detail: 'Extracting IPv4, suspicious domains, URLs & attachment hashes', duration: '41ms' },
  { id: 5, name: 'Threat Intelligence Enrichment', detail: 'Cross-referencing IOCs against synthetic threat reputation feeds', duration: '64ms' },
  { id: 6, name: 'GeoLocation / ASN Analysis', detail: 'Resolving Autonomous Systems, BGP paths & origin nations', duration: '55ms' },
  { id: 7, name: 'Graph Correlation', detail: 'Linking threat actors, infrastructure nodes & targeted assets', duration: '71ms' },
  { id: 8, name: 'Risk Scoring', detail: 'Computing multi-factor explainable risk index & confidence level', duration: '38ms' }
];

export const EmailAnalysisPage = ({ onViewChange, onInspectEmail }) => {
  const [emailData, setEmailData] = useState(null);
  const [isDragActive, setIsDragActive] = useState(false);
  const [showRawHeaders, setShowRawHeaders] = useState(false);
  const [copiedRaw, setCopiedRaw] = useState(false);
  
  // Pipeline Analysis State
  const [analysisState, setAnalysisState] = useState('idle'); // 'idle' | 'analyzing' | 'completed'
  const [activeStageIndex, setActiveStageIndex] = useState(-1);
  const [stageStatuses, setStageStatuses] = useState(
    INITIAL_PIPELINE_STAGES.map(() => 'pending')
  );

  const fileInputRef = useRef(null);
  const timerRef = useRef(null);

  useEffect(() => {
    return () => {
      if (timerRef.current) clearInterval(timerRef.current);
    };
  }, []);

  // Handler for loading demo email
  const handleUseDemoEmail = (e) => {
    if (e && typeof e.stopPropagation === 'function') {
      e.stopPropagation();
    }
    setEmailData({ ...DEMO_EMAIL_DATA });
    setAnalysisState('idle');
    setActiveStageIndex(-1);
    setStageStatuses(INITIAL_PIPELINE_STAGES.map(() => 'pending'));
  };

  const handleBrowseClick = (e) => {
    if (e && typeof e.stopPropagation === 'function') {
      e.stopPropagation();
    }
    if (fileInputRef.current) {
      fileInputRef.current.click();
    }
  };

  const handleFileChange = (e) => {
    const file = e.target.files?.[0];
    if (file) {
      handleUseDemoEmail();
    }
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
    handleUseDemoEmail();
  };

  const handleCopyRaw = () => {
    if (emailData) {
      navigator.clipboard?.writeText(emailData.rawSnippet);
      setCopiedRaw(true);
      setTimeout(() => setCopiedRaw(false), 1500);
    }
  };

  const startAnalysis = () => {
    if (!emailData) {
      setEmailData({ ...DEMO_EMAIL_DATA });
    }
    
    setAnalysisState('analyzing');
    setActiveStageIndex(0);
    
    const newStatuses = INITIAL_PIPELINE_STAGES.map(() => 'pending');
    newStatuses[0] = 'processing';
    setStageStatuses(newStatuses);

    let currentStep = 0;
    if (timerRef.current) clearInterval(timerRef.current);

    timerRef.current = setInterval(() => {
      currentStep++;
      if (currentStep < INITIAL_PIPELINE_STAGES.length) {
        setActiveStageIndex(currentStep);
        setStageStatuses(prev => {
          const updated = [...prev];
          updated[currentStep - 1] = 'completed';
          updated[currentStep] = 'processing';
          return updated;
        });
      } else {
        clearInterval(timerRef.current);
        setStageStatuses(INITIAL_PIPELINE_STAGES.map(() => 'completed'));
        setActiveStageIndex(INITIAL_PIPELINE_STAGES.length);
        setAnalysisState('completed');
      }
    }, 420);
  };

  const progressPercentage = analysisState === 'completed'
    ? 100
    : analysisState === 'analyzing'
      ? Math.round(((activeStageIndex + 0.5) / INITIAL_PIPELINE_STAGES.length) * 100)
      : 0;

  return (
    <div className="space-y-6 pb-12 font-sans">
      
      {/* Hidden file input for .eml browse */}
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
              STAGE 02 OF 08 • EMAIL INGESTION & PIPELINE
            </div>
            <h1 className="text-xl sm:text-2xl font-extrabold text-white font-mono flex items-center gap-2.5">
              <span>Suspicious Email Ingestion & Analysis Engine</span>
            </h1>
            <p className="text-xs text-slate-300 mt-1 max-w-3xl">
              Upload raw .eml files or load synthetic samples to trigger the 8-stage automated threat verification pipeline.
            </p>
          </div>

          <div className="flex items-center gap-2 font-mono text-xs">
            <span className="px-2.5 py-1 rounded bg-slate-900/90 border border-slate-800 text-slate-400">
              Environment: <strong className="text-cyan-300">SIH 2026 Simulation</strong>
            </span>
          </div>
        </div>
      </div>

      {/* Section 1: .eml Email Upload & Action Zone */}
      <div className="rounded-xl bg-[#09101e] border border-slate-800/90 p-5 shadow-lg space-y-4">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-slate-800 pb-3">
          <div className="flex items-center gap-2">
            <UploadCloud className="w-5 h-5 text-cyan-400" />
            <h2 className="text-sm font-bold uppercase tracking-wider font-mono text-slate-100">
              .eml Email Upload & Ingestion Controls
            </h2>
          </div>
          <span className="text-[11px] font-mono text-slate-400">
            Accepts RFC 822 / MIME (.eml, .txt)
          </span>
        </div>

        {/* Primary Action Buttons Bar */}
        <div className="flex flex-wrap items-center gap-3 p-3 rounded-lg bg-[#060a14] border border-slate-800">
          <button
            type="button"
            id="btn-use-demo-email"
            onClick={handleUseDemoEmail}
            className="flex items-center gap-2 px-5 py-2.5 rounded-lg bg-gradient-to-r from-cyan-600 via-sky-600 to-blue-600 hover:from-cyan-500 hover:to-blue-500 text-white text-xs font-mono font-bold shadow-[0_0_15px_rgba(6,182,212,0.4)] transition-all cursor-pointer active:scale-95"
          >
            <Zap className="w-4 h-4 fill-current text-cyan-200" />
            <span>Use Demo Email</span>
          </button>

          <button
            type="button"
            id="btn-browse-file"
            onClick={handleBrowseClick}
            className="flex items-center gap-2 px-4 py-2.5 rounded-lg bg-[#0d1c38] hover:bg-[#122850] border border-cyan-500/40 text-cyan-300 text-xs font-mono font-semibold transition-all shadow-sm cursor-pointer"
          >
            <FolderOpen className="w-4 h-4 text-cyan-400" />
            <span>Browse .eml File</span>
          </button>

          <span className="text-[11px] font-mono text-slate-400 ml-auto hidden md:inline">
            Click <strong className="text-cyan-300 font-semibold">"Use Demo Email"</strong> to populate simulated attack telemetry
          </span>
        </div>

        {/* Drag and drop area (dedicated target) */}
        <div
          onDragOver={handleDragOver}
          onDragLeave={handleDragLeave}
          onDrop={handleDrop}
          className={`rounded-xl border-2 border-dashed p-6 text-center transition-all duration-200 cursor-pointer ${
            isDragActive
              ? 'border-cyan-400 bg-cyan-950/30 shadow-[0_0_20px_rgba(6,182,212,0.25)]'
              : 'border-slate-800 hover:border-cyan-500/40 bg-[#060a14]/60'
          }`}
          onClick={handleBrowseClick}
        >
          <div className="flex flex-col items-center justify-center space-y-2">
            <UploadCloud className="w-8 h-8 text-cyan-400 opacity-80" />
            <p className="text-xs font-medium text-slate-300">
              Drag and drop an <span className="text-cyan-300 font-mono font-bold">.eml</span> file here, or click to browse
            </p>
            <p className="text-[11px] text-slate-500">
              Automatic parser extracts headers, routing hops, URLs, IPs, and payload attachments
            </p>
          </div>
        </div>
      </div>

      {/* Section 2: Display Demo Email Information */}
      {emailData ? (
        <div id="email-telemetry-container" className="rounded-xl bg-[#09101e] border border-cyan-500/50 p-5 sm:p-6 shadow-[0_0_25px_rgba(6,182,212,0.15)] space-y-5">
          
          {/* Header with DEMO EMAIL LOADED */}
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-slate-800 pb-3">
            <div className="flex items-center gap-2.5">
              <Mail className="w-5 h-5 text-cyan-400" />
              <h2 className="text-sm font-bold uppercase tracking-wider font-mono text-white">
                Ingested Email Telemetry
              </h2>
              <span className="text-[11px] font-mono px-2.5 py-0.5 rounded bg-cyan-950/90 border border-cyan-400 text-cyan-300 font-extrabold shadow-[0_0_10px_rgba(6,182,212,0.3)] flex items-center gap-1.5">
                <span className="w-2 h-2 rounded-full bg-cyan-400 animate-pulse"></span>
                <span>DEMO EMAIL LOADED</span>
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
              <span className="text-[10px] uppercase text-slate-500 font-semibold block">Sender</span>
              <div className="text-slate-200 font-medium break-all">{emailData.sender}</div>
            </div>

            <div className="p-3.5 rounded-lg bg-[#060a14] border border-slate-800/80 space-y-1">
              <span className="text-[10px] uppercase text-slate-500 font-semibold block">Recipient</span>
              <div className="text-cyan-300 font-medium break-all">{emailData.recipient}</div>
            </div>

            <div className="p-3.5 rounded-lg bg-[#060a14] border border-slate-800/80 space-y-1">
              <span className="text-[10px] uppercase text-slate-500 font-semibold block">Subject</span>
              <div className="text-white font-medium">{emailData.subject}</div>
            </div>

            <div className="p-3.5 rounded-lg bg-[#060a14] border border-slate-800/80 space-y-1">
              <span className="text-[10px] uppercase text-slate-500 font-semibold block">Date</span>
              <div className="text-slate-300">{emailData.date}</div>
            </div>

          </div>

          {/* Authentication Protocol Results: SPF, DKIM, DMARC */}
          <div className="space-y-2 font-mono text-xs">
            <span className="text-[11px] uppercase text-slate-400 font-bold tracking-wider block">
              Authentication Protocol Diagnostics
            </span>

            <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
              <div className="p-3 rounded-lg bg-red-950/30 border border-red-500/40 flex items-center justify-between">
                <div>
                  <span className="text-[10px] text-slate-400 block font-semibold">SPF Result</span>
                  <span className="font-bold text-red-400">{emailData.spfResult}</span>
                </div>
                <AlertTriangle className="w-4 h-4 text-red-400 shrink-0 ml-2" />
              </div>

              <div className="p-3 rounded-lg bg-red-950/30 border border-red-500/40 flex items-center justify-between">
                <div>
                  <span className="text-[10px] text-slate-400 block font-semibold">DKIM Result</span>
                  <span className="font-bold text-red-400">{emailData.dkimResult}</span>
                </div>
                <AlertTriangle className="w-4 h-4 text-red-400 shrink-0 ml-2" />
              </div>

              <div className="p-3 rounded-lg bg-red-950/30 border border-red-500/40 flex items-center justify-between">
                <div>
                  <span className="text-[10px] text-slate-400 block font-semibold">DMARC Result</span>
                  <span className="font-bold text-red-400">{emailData.dmarcResult}</span>
                </div>
                <AlertTriangle className="w-4 h-4 text-red-400 shrink-0 ml-2" />
              </div>
            </div>
          </div>

          {/* Detected Entities: URLs, IP Addresses, Attachments */}
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-4 font-mono text-xs">
            
            {/* Detected URLs */}
            <div className="p-3.5 rounded-lg bg-[#060a14] border border-slate-800 space-y-2">
              <div className="flex items-center justify-between text-slate-300 font-bold text-[11px]">
                <span className="flex items-center gap-1.5 text-cyan-400">
                  <Globe className="w-3.5 h-3.5" /> Detected URLs ({emailData.urls.length})
                </span>
              </div>
              <div className="space-y-1.5">
                {emailData.urls.map((url, idx) => (
                  <div key={idx} className="p-2 rounded bg-slate-900/90 border border-slate-800 text-[11px] text-slate-300 break-all font-mono">
                    {url}
                  </div>
                ))}
              </div>
            </div>

            {/* Detected IP addresses */}
            <div className="p-3.5 rounded-lg bg-[#060a14] border border-slate-800 space-y-2">
              <div className="flex items-center justify-between text-slate-300 font-bold text-[11px]">
                <span className="flex items-center gap-1.5 text-amber-400">
                  <Activity className="w-3.5 h-3.5" /> Detected IP Addresses ({emailData.ips.length})
                </span>
              </div>
              <div className="space-y-1.5">
                {emailData.ips.map((ip, idx) => (
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
                  <Paperclip className="w-3.5 h-3.5" /> Attachments ({emailData.attachments.length})
                </span>
              </div>
              <div className="space-y-1.5">
                {emailData.attachments.map((att, idx) => (
                  <div key={idx} className="p-2 rounded bg-slate-900/90 border border-red-500/30 space-y-1">
                    <div className="text-[11px] font-bold text-red-300 break-all font-mono">
                      {att.filename}
                    </div>
                    <div className="text-[10px] text-slate-400 flex items-center justify-between">
                      <span>Size: {att.size}</span>
                      <span className="text-red-400 font-bold">{att.flag}</span>
                    </div>
                  </div>
                ))}
              </div>
            </div>

          </div>

          {/* Optional Raw Headers Snippet */}
          {showRawHeaders && (
            <div className="p-3.5 rounded-lg bg-[#050810] border border-slate-800 font-mono text-xs space-y-2">
              <div className="flex items-center justify-between text-slate-400 pb-1 border-b border-slate-800">
                <span>Raw MIME Header Snippet (RFC 822)</span>
                <button
                  type="button"
                  onClick={handleCopyRaw}
                  className="flex items-center gap-1 text-cyan-400 hover:text-cyan-300"
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
              Payload parsed. Ready to execute 8-stage automated forensic analysis.
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
                  <span>Analyzing Email...</span>
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
        /* Empty State prompt with direct action button */
        <div className="rounded-xl bg-[#09101e]/60 border border-slate-800/80 p-6 text-center font-mono text-xs text-slate-400 space-y-3">
          <div className="w-10 h-10 rounded-full bg-slate-900 border border-slate-800 mx-auto flex items-center justify-center text-slate-500">
            <Mail className="w-5 h-5" />
          </div>
          <div>
            <p className="text-slate-300 font-semibold text-sm">No email currently loaded in parser memory</p>
            <p className="text-slate-500 text-xs mt-1">
              Click below or use the top button to populate the demo email.
            </p>
          </div>
          <button
            type="button"
            onClick={handleUseDemoEmail}
            className="inline-flex items-center gap-2 px-4 py-2 rounded-lg bg-cyan-950 border border-cyan-500/50 text-cyan-300 text-xs font-mono font-bold hover:bg-cyan-900 transition-colors cursor-pointer"
          >
            <Zap className="w-4 h-4 fill-current" />
            <span>Load Demo Email Now</span>
          </button>
        </div>
      )}

      {/* Section 3: 8-Stage Simulated Analysis Pipeline */}
      {analysisState !== 'idle' && (
        <div id="pipeline-stages-container" className="rounded-xl bg-[#09101e] border border-slate-800 p-5 shadow-xl space-y-5 font-mono">
          
          {/* Pipeline Header & Progress */}
          <div className="space-y-2">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
              <div className="flex items-center gap-2">
                <Cpu className="w-5 h-5 text-cyan-400" />
                <h3 className="text-sm font-bold uppercase tracking-wider text-white">
                  8-Stage Simulated Analysis Pipeline
                </h3>
              </div>
              <div className="text-xs text-cyan-300 font-bold flex items-center gap-2">
                <span>{progressPercentage}% Complete</span>
                {analysisState === 'analyzing' && (
                  <span className="w-2 h-2 rounded-full bg-cyan-400 animate-ping"></span>
                )}
              </div>
            </div>

            {/* Overall Progress Bar */}
            <div className="w-full h-2 bg-slate-800 rounded-full overflow-hidden">
              <div 
                className="h-full bg-gradient-to-r from-cyan-500 via-sky-500 to-blue-500 transition-all duration-300 rounded-full shadow-[0_0_10px_rgba(6,182,212,0.5)]"
                style={{ width: `${progressPercentage}%` }}
              />
            </div>
          </div>

          {/* Grid of 8 Stages with pending -> processing -> completed states */}
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-3">
            {INITIAL_PIPELINE_STAGES.map((stage, idx) => {
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
                  Analysis Complete
                </h3>
                <p className="text-xs text-slate-400">
                  All 8 forensic inspection layers finished successfully (Simulated Engine)
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
                <span>Re-run Analysis</span>
              </button>
            </div>
          </div>

          {/* Results Metric Row: Risk Level, Risk Score, Confidence */}
          <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
            
            <div className="p-4 rounded-xl bg-[#060a14] border border-red-500/40 text-center space-y-1">
              <span className="text-[11px] uppercase tracking-wider text-slate-400 block">
                Risk Level
              </span>
              <div className="text-2xl font-black text-red-400 flex items-center justify-center gap-1.5">
                <span className="w-2.5 h-2.5 rounded-full bg-red-400 animate-pulse"></span>
                <span>HIGH</span>
              </div>
              <span className="text-[10px] text-red-300/80">Immediate Remediation Recommended</span>
            </div>

            <div className="p-4 rounded-xl bg-[#060a14] border border-red-500/40 text-center space-y-1">
              <span className="text-[11px] uppercase tracking-wider text-slate-400 block">
                Risk Score
              </span>
              <div className="text-3xl font-black text-white">
                92<span className="text-base text-slate-400 font-normal"> / 100</span>
              </div>
              <span className="text-[10px] text-slate-400">Critical Threat Threshold Exceeded</span>
            </div>

            <div className="p-4 rounded-xl bg-[#060a14] border border-cyan-500/40 text-center space-y-1">
              <span className="text-[11px] uppercase tracking-wider text-slate-400 block">
                Confidence
              </span>
              <div className="text-3xl font-black text-cyan-300">
                92%
              </div>
              <span className="text-[10px] text-slate-400">High Model Certainty</span>
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
              <span>View Analysis Results</span>
              <ArrowRight className="w-4 h-4" />
            </button>
          </div>

        </div>
      )}

    </div>
  );
};
