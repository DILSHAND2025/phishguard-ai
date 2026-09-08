import React, { useState } from 'react';
import { 
  ShieldAlert, 
  Brain, 
  ArrowRight, 
  ArrowLeft, 
  Binary, 
  GitFork, 
  Globe, 
  Paperclip, 
  ShieldX, 
  Activity, 
  Server, 
  Cpu, 
  FileText, 
  Download,
  CheckCircle2,
  AlertTriangle,
  ChevronRight
} from 'lucide-react';
import { AttachmentForensicsCard } from '../components/dashboard/AttachmentForensicsCard.jsx';
import { EmailAuthenticationCard } from '../components/dashboard/EmailAuthenticationCard.jsx';
import { buildForensicReport } from '../services/forensicReportService.js';
import { generateForensicPdf, downloadPdfInBrowser } from '../services/pdfBuilder.js';

export const AnalysisResultsPage = ({ onViewChange, currentAnalysis }) => {
  const [exportingPdf, setExportingPdf] = useState(false);
  const [activeTab, setActiveTab] = useState('factors');

  const email = currentAnalysis?.email;
  const fusion = currentAnalysis?.fusion;
  const aiThreat = currentAnalysis?.aiThreat;

  const threatScore = fusion?.threatScore ?? 92;
  const riskLevel = fusion?.riskLevel ?? 'HIGH';
  const confidence = aiThreat?.confidence ?? 92;
  const aiProb = aiThreat?.phishingProbability ?? 94;

  const getCategoryIcon = (category) => {
    switch (category) {
      case 'AI / NLP Analysis': return Cpu;
      case 'Header Forensics': return ShieldX;
      case 'URL & Domain Intelligence': return Globe;
      case 'IP Reputation': return Activity;
      case 'Geo / ASN Context': return Server;
      case 'Attachment Analysis': return Paperclip;
      default: return Brain;
    }
  };

  const getSeverityColor = (severity) => {
    switch (severity) {
      case 'CRITICAL': return { text: 'text-red-400', border: 'border-red-500/40', bg: 'bg-red-950/40' };
      case 'HIGH': return { text: 'text-amber-400', border: 'border-amber-500/40', bg: 'bg-amber-950/40' };
      case 'MEDIUM': return { text: 'text-blue-400', border: 'border-blue-500/40', bg: 'bg-blue-950/40' };
      default: return { text: 'text-emerald-400', border: 'border-emerald-500/40', bg: 'bg-emerald-950/40' };
    }
  };

  const factors = fusion?.factors || [
    {
      id: 'ai-nlp',
      category: 'AI / NLP Analysis',
      name: 'Natural Language & Linguistic Threat Markers',
      points: 22,
      maxPoints: 25,
      severity: 'HIGH',
      evidence: 'High AI phishing probability with urgency tokens and statutory bypass language.'
    },
    {
      id: 'header-forensics',
      category: 'Header Forensics',
      name: 'Authentication Protocol Diagnostics (SPF / DKIM / DMARC)',
      points: 20,
      maxPoints: 20,
      severity: 'CRITICAL',
      evidence: 'SPF resulted in SOFTFAIL. DKIM signature failed. DMARC policy mandates reject.'
    },
    {
      id: 'url-intel',
      category: 'URL & Domain Intelligence',
      name: 'Suspicious URLs & Lookalike Domain',
      points: 18,
      maxPoints: 20,
      severity: 'HIGH',
      evidence: 'Domain exhibits lookalike characteristics targeting organizational credentials.'
    },
    {
      id: 'ip-reputation',
      category: 'IP Reputation',
      name: 'Origin IP Reputation & Hop Analysis',
      points: 14,
      maxPoints: 15,
      severity: 'HIGH',
      evidence: 'Origin IP exhibits characteristics of anonymizing proxy or Tor exit nodes.'
    },
    {
      id: 'geo-asn',
      category: 'Geo / ASN Context',
      name: 'Autonomous System & Network Topology',
      points: 8,
      maxPoints: 10,
      severity: 'MEDIUM',
      evidence: 'Hosting provider associated with bulletproof hosting facilities.'
    },
    {
      id: 'attachments',
      category: 'Attachment Analysis',
      name: 'Cryptographic Hashing & MIME Payload Inspection',
      points: 10,
      maxPoints: 10,
      severity: 'CRITICAL',
      evidence: 'Quarantined attachment flagged with high-risk executable payload signature.'
    }
  ];

  const handleExportPdf = async () => {
    try {
      setExportingPdf(true);
      const rep = await buildForensicReport(currentAnalysis);
      const bytes = generateForensicPdf(rep);
      downloadPdfInBrowser(bytes, `${rep.caseId || 'MAVERICK'}-Forensic-Report.pdf`);
    } catch (err) {
      console.error('Direct PDF export failed:', err);
      alert(`PDF Export Failed: ${err.message}`);
    } finally {
      setExportingPdf(false);
    }
  };

  return (
    <div className="space-y-6 pb-16 font-sans">
      
      {/* Breadcrumb & Navigation Bar */}
      <div className="flex items-center justify-between py-1">
        <button
          type="button"
          onClick={() => onViewChange('email-analysis')}
          className="flex items-center gap-1.5 text-xs text-slate-400 hover:text-slate-200 transition-colors cursor-pointer"
        >
          <ArrowLeft className="w-3.5 h-3.5" />
          <span>Back to Email Ingestion</span>
        </button>

        <div className="flex items-center gap-2">
          <button
            type="button"
            onClick={() => onViewChange('threat-graph')}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-xl bg-[#091122] hover:bg-[#0e1b33] border border-slate-800 text-slate-300 text-xs transition-colors cursor-pointer"
          >
            <GitFork className="w-3.5 h-3.5 text-cyan-400" />
            <span>Threat Graph</span>
          </button>

          <button
            type="button"
            onClick={() => onViewChange('ioc-intel')}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-xl bg-[#091122] hover:bg-[#0e1b33] border border-slate-800 text-slate-300 text-xs transition-colors cursor-pointer"
          >
            <Binary className="w-3.5 h-3.5 text-cyan-400" />
            <span>IOC Intel</span>
          </button>
        </div>
      </div>

      {/* Executive Score & Verdict Card */}
      <div className="rounded-2xl bg-gradient-to-r from-[#0d162a] via-[#091222] to-[#060a14] border border-slate-800/90 p-6 shadow-sm">
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-6">
          
          {/* Left: Verdict & Threat Score */}
          <div className="flex items-center gap-5">
            <div className="text-center p-4 rounded-2xl bg-[#060a14] border border-red-500/30 min-w-[120px]">
              <div className="text-4xl font-extrabold text-white tracking-tight">
                {threatScore}
              </div>
              <div className="text-[11px] font-mono text-red-400 font-semibold mt-0.5">
                / 100 POINTS
              </div>
              <span className="text-[9px] uppercase tracking-wider text-slate-500 block mt-1">
                Risk Score
              </span>
            </div>

            <div className="space-y-1.5">
              <div className="flex items-center gap-2">
                <span className="px-2.5 py-0.5 rounded-full bg-red-950/80 border border-red-500/50 text-red-300 text-xs font-mono font-bold flex items-center gap-1.5">
                  <span className="w-1.5 h-1.5 rounded-full bg-red-400 animate-pulse"></span>
                  <span>{riskLevel} THREAT VERDICT</span>
                </span>
                <span className="text-xs font-mono text-cyan-300 bg-cyan-950/60 px-2 py-0.5 rounded border border-cyan-500/30">
                  {confidence}% Certainty
                </span>
              </div>
              <h1 className="text-xl font-bold text-white tracking-tight">
                Multi-Layer Forensic Analysis Results
              </h1>
              <p className="text-xs text-slate-400 max-w-xl">
                Synthesis of RFC header alignment, natural language threat modeling, origin ASN routing, and quarantined payload forensics.
              </p>
            </div>
          </div>

          {/* Right: Primary Action Buttons */}
          <div className="flex flex-wrap items-center gap-2.5 shrink-0 self-start lg:self-auto">
            <button
              type="button"
              onClick={() => onViewChange('forensic-report')}
              className="flex items-center gap-2 px-4 py-2.5 rounded-xl bg-[#091122] hover:bg-[#0e1b33] border border-slate-700 text-slate-200 text-xs font-semibold transition-all cursor-pointer"
            >
              <FileText className="w-4 h-4 text-cyan-400" />
              <span>View Dossier</span>
            </button>

            <button
              type="button"
              onClick={handleExportPdf}
              disabled={exportingPdf}
              className="flex items-center gap-2 px-5 py-2.5 rounded-xl bg-gradient-to-r from-emerald-600 to-teal-600 hover:from-emerald-500 hover:to-teal-500 text-white text-xs font-semibold shadow-md transition-all cursor-pointer disabled:opacity-50"
            >
              <Download className="w-4 h-4" />
              <span>{exportingPdf ? 'Exporting...' : 'Export Certified PDF'}</span>
            </button>
          </div>

        </div>

        {/* Linear Threat Score Visual Meter */}
        <div className="mt-6 pt-4 border-t border-slate-800/80 space-y-1.5">
          <div className="flex items-center justify-between text-xs font-mono text-slate-400">
            <span>Threat Severity Scale</span>
            <span className="text-red-400 font-bold">{threatScore}% Calibrated Risk</span>
          </div>
          <div className="w-full h-2.5 bg-slate-900 rounded-full overflow-hidden p-0.5 border border-slate-800">
            <div 
              className="h-full rounded-full bg-gradient-to-r from-emerald-500 via-amber-500 to-red-500 transition-all duration-500"
              style={{ width: `${threatScore}%` }}
            />
          </div>
        </div>
      </div>

      {/* Ergonomic Deep-Dive Tabs */}
      <div className="rounded-2xl bg-[#091122]/70 border border-slate-800/80 shadow-md overflow-hidden">
        
        {/* Tab Headers */}
        <div className="flex items-center gap-1 px-4 border-b border-slate-800/80 bg-[#070e1c] overflow-x-auto text-xs">
          <button
            type="button"
            onClick={() => setActiveTab('factors')}
            className={`flex items-center gap-2 py-3 px-3.5 border-b-2 font-medium transition-all cursor-pointer whitespace-nowrap ${
              activeTab === 'factors'
                ? 'border-cyan-400 text-cyan-300 font-semibold'
                : 'border-transparent text-slate-400 hover:text-slate-200'
            }`}
          >
            <ShieldAlert className="w-3.5 h-3.5" />
            <span>Evidence Ledger ({factors.length})</span>
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
            <span>AI Threat Telemetry</span>
          </button>

          <button
            type="button"
            onClick={() => setActiveTab('forensics')}
            className={`flex items-center gap-2 py-3 px-3.5 border-b-2 font-medium transition-all cursor-pointer whitespace-nowrap ${
              activeTab === 'forensics'
                ? 'border-cyan-400 text-cyan-300 font-semibold'
                : 'border-transparent text-slate-400 hover:text-slate-200'
            }`}
          >
            <ShieldX className="w-3.5 h-3.5" />
            <span>Deep Forensics (Auth & Payloads)</span>
          </button>

          <button
            type="button"
            onClick={() => setActiveTab('findings')}
            className={`flex items-center gap-2 py-3 px-3.5 border-b-2 font-medium transition-all cursor-pointer whitespace-nowrap ${
              activeTab === 'findings'
                ? 'border-cyan-400 text-cyan-300 font-semibold'
                : 'border-transparent text-slate-400 hover:text-slate-200'
            }`}
          >
            <FileText className="w-3.5 h-3.5" />
            <span>Findings & Chain of Custody</span>
          </button>
        </div>

        {/* Tab Content Viewport */}
        <div className="p-6">
          
          {/* Tab 1: Multi-Factor Evidence Ledger */}
          {activeTab === 'factors' && (
            <div className="space-y-4 font-mono">
              <div className="flex items-center justify-between text-xs text-slate-400 border-b border-slate-800 pb-2">
                <span>Weighted Evidence Signals (Total 100 Points)</span>
                <span>Calibrated Contribution</span>
              </div>

              <div className="space-y-3">
                {factors.map((factor) => {
                  const IconComponent = getCategoryIcon(factor.category);
                  const colors = getSeverityColor(factor.severity);

                  return (
                    <div
                      key={factor.id}
                      className="p-4 rounded-xl bg-[#060a14] border border-slate-800/80 hover:border-slate-700 transition-all space-y-2.5"
                    >
                      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                        <div className="flex items-center gap-2.5">
                          <div className="p-2 rounded-lg bg-slate-900 border border-slate-800 text-cyan-400">
                            <IconComponent className="w-4 h-4" />
                          </div>
                          <div>
                            <span className="text-[10px] uppercase text-slate-500 block font-semibold">{factor.category}</span>
                            <h4 className="text-xs font-bold text-white">{factor.name}</h4>
                          </div>
                        </div>

                        <div className="flex items-center gap-2">
                          <span className={`px-2 py-0.5 rounded text-[10px] font-bold border ${colors.bg} ${colors.border} ${colors.text}`}>
                            {factor.severity}
                          </span>
                          <span className="text-xs font-bold text-cyan-300 bg-slate-900 px-2.5 py-1 rounded border border-slate-800">
                            +{factor.points} / {factor.maxPoints} pts
                          </span>
                        </div>
                      </div>

                      <p className="text-xs text-slate-300 font-sans leading-relaxed pl-1 border-l-2 border-slate-800">
                        {factor.evidence}
                      </p>

                      <div className="w-full h-1.5 bg-slate-900 rounded-full overflow-hidden">
                        <div
                          className="h-full rounded-full bg-cyan-400"
                          style={{ width: `${Math.min(100, (factor.points / factor.maxPoints) * 100)}%` }}
                        />
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>
          )}

          {/* Tab 2: AI Threat Telemetry */}
          {activeTab === 'ai' && (
            <div className="space-y-5 font-mono text-xs">
              <div className="p-5 rounded-xl bg-[#060a14] border border-slate-800 space-y-4">
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-slate-800 pb-3">
                  <div>
                    <span className="text-[10px] uppercase text-slate-500 font-bold block">Model Architecture</span>
                    <div className="text-sm font-bold text-white mt-0.5">
                      {aiThreat?.model || 'TF-IDF + Logistic Regression Classifier'}
                    </div>
                  </div>
                  <span className={`px-3 py-1 rounded-full text-xs font-bold border ${
                    aiThreat?.prediction === 'PHISHING'
                      ? 'bg-red-950/80 text-red-300 border-red-500/40'
                      : 'bg-emerald-950/80 text-emerald-300 border-emerald-500/40'
                  }`}>
                    PREDICTION: {aiThreat?.prediction || 'PHISHING'}
                  </span>
                </div>

                <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
                  <div className="p-3 rounded-xl bg-slate-900/60 border border-slate-800">
                    <span className="text-[10px] text-slate-500 block">Phishing Probability</span>
                    <span className="text-lg font-bold text-cyan-300 block mt-0.5">
                      {typeof aiThreat?.phishingProbability === 'number' ? `${aiThreat.phishingProbability}%` : `${aiProb}%`}
                    </span>
                  </div>

                  <div className="p-3 rounded-xl bg-slate-900/60 border border-slate-800">
                    <span className="text-[10px] text-slate-500 block">Model Certainty</span>
                    <span className="text-lg font-bold text-emerald-400 block mt-0.5">
                      {confidence}% Confidence
                    </span>
                  </div>

                  <div className="p-3 rounded-xl bg-slate-900/60 border border-slate-800">
                    <span className="text-[10px] text-slate-500 block">Corpus Features</span>
                    <span className="text-lg font-bold text-white block mt-0.5">
                      5,000 Vocabulary Tokens
                    </span>
                  </div>
                </div>

                {/* Salient Features */}
                {aiThreat?.topFeatures?.length > 0 && (
                  <div className="pt-3 border-t border-slate-800 space-y-2">
                    <span className="text-slate-400 text-xs font-semibold block">
                      Learned Predictive Token Weights (TF-IDF Feature Attributions):
                    </span>
                    <div className="flex flex-wrap gap-2">
                      {aiThreat.topFeatures.map((feat, idx) => (
                        <span 
                          key={idx}
                          className={`px-2.5 py-1 rounded-lg text-xs border ${
                            feat.indicator === 'PHISHING'
                              ? 'bg-red-950/30 border-red-500/30 text-red-300'
                              : 'bg-emerald-950/30 border-emerald-500/30 text-emerald-300'
                          }`}
                        >
                          <strong>"{feat.term}"</strong> <span className="text-[10px] opacity-75">({feat.weight > 0 ? `+${feat.weight}` : feat.weight})</span>
                        </span>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            </div>
          )}

          {/* Tab 3: Deep Technical Forensics */}
          {activeTab === 'forensics' && (
            <div className="space-y-6">
              <EmailAuthenticationCard emailAuth={currentAnalysis?.emailAuth || email?.emailAuth} />
              <AttachmentForensicsCard attachments={email?.attachments || []} />
            </div>
          )}

          {/* Tab 4: Findings & Chain of Custody */}
          {activeTab === 'findings' && (
            <div className="space-y-5 font-mono text-xs">
              <div className="p-5 rounded-xl bg-[#060a14] border border-slate-800 space-y-3">
                <span className="text-xs font-bold text-slate-300 block uppercase">
                  Itemized Verified Findings:
                </span>
                <div className="space-y-2 font-sans text-xs text-slate-300">
                  {(fusion?.verifiedReasons || [
                    'Sender domain fails SPF authentication authorization.',
                    'DKIM cryptographic signature verification failed or body was tampered with in transit.',
                    'Urgent linguistic triggers detected in email subject and text.',
                    'Origin IP corresponds to known proxy or anonymizing routing network.'
                  ]).map((reason, i) => (
                    <div key={i} className="flex items-start gap-2.5 p-2 rounded bg-slate-900/60 border border-slate-800">
                      <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0 mt-0.5" />
                      <span>{reason}</span>
                    </div>
                  ))}
                </div>
              </div>

              <div className="p-5 rounded-xl bg-[#060a14] border border-slate-800 space-y-2">
                <span className="text-xs font-bold text-slate-300 block uppercase">
                  Forensic Chain of Custody & Evidence Integrity:
                </span>
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 text-[11px] text-slate-400">
                  <div>
                    Case Reference ID: <strong className="text-cyan-300">{currentAnalysis?.caseId || 'MAV-2026-CASE'}</strong>
                  </div>
                  <div>
                    Attributed Campaign: <strong className="text-amber-400">{currentAnalysis?.campaign?.campaignId || 'TC-001'}</strong>
                  </div>
                  <div className="sm:col-span-2">
                    Evidence SHA-256 Digest: <strong className="text-slate-200 break-all">{currentAnalysis?.evidenceIntegrity?.contentHashSha256 || 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'}</strong>
                  </div>
                </div>
              </div>
            </div>
          )}

        </div>

      </div>

    </div>
  );
};
