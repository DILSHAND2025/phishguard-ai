import React, { useState } from 'react';
import { 
  ShieldAlert, 
  Brain, 
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
  CheckCircle2
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
      case 'CRITICAL': return { text: 'text-red-700', border: 'border-red-200', bg: 'bg-red-50' };
      case 'HIGH': return { text: 'text-orange-700', border: 'border-orange-200', bg: 'bg-orange-50' };
      case 'MEDIUM': return { text: 'text-amber-800', border: 'border-amber-200', bg: 'bg-amber-50' };
      default: return { text: 'text-emerald-700', border: 'border-emerald-200', bg: 'bg-emerald-50' };
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
    <div className="space-y-6 pb-16 font-sans text-slate-900">
      
      {/* Breadcrumb & Navigation Bar */}
      <div className="flex items-center justify-between py-1">
        <button
          type="button"
          onClick={() => onViewChange('email-analysis')}
          className="flex items-center gap-1.5 text-xs text-slate-500 hover:text-slate-800 transition-colors cursor-pointer font-medium"
        >
          <ArrowLeft className="w-3.5 h-3.5" />
          <span>Back to Email Ingestion</span>
        </button>

        <div className="flex items-center gap-2">
          <button
            type="button"
            onClick={() => onViewChange('threat-graph')}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-white hover:bg-slate-50 border border-slate-200 text-slate-700 text-xs font-semibold transition-colors shadow-2xs cursor-pointer"
          >
            <GitFork className="w-3.5 h-3.5 text-slate-500" />
            <span>Threat Graph</span>
          </button>

          <button
            type="button"
            onClick={() => onViewChange('ioc-intel')}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-white hover:bg-slate-50 border border-slate-200 text-slate-700 text-xs font-semibold transition-colors shadow-2xs cursor-pointer"
          >
            <Binary className="w-3.5 h-3.5 text-slate-500" />
            <span>IOC Intel</span>
          </button>
        </div>
      </div>

      {/* Executive Score & Verdict Card */}
      <div className="rounded-xl bg-white border border-slate-200 p-6 shadow-xs">
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-6">
          
          {/* Left: Verdict & Threat Score */}
          <div className="flex items-center gap-5">
            <div className="text-center p-4 rounded-xl bg-slate-50 border border-slate-200 min-w-[120px]">
              <div className="text-4xl font-extrabold text-slate-900 tracking-tight">
                {threatScore}
              </div>
              <div className="text-[11px] font-bold text-red-700 mt-0.5">
                / 100 POINTS
              </div>
              <span className="text-[10px] uppercase tracking-wider text-slate-400 block mt-1 font-semibold">
                Risk Score
              </span>
            </div>

            <div className="space-y-1.5">
              <div className="flex items-center gap-2">
                <span className="px-2.5 py-0.5 rounded-full bg-red-50 border border-red-200 text-red-700 text-xs font-bold flex items-center gap-1.5">
                  <span className="w-1.5 h-1.5 rounded-full bg-red-500"></span>
                  <span>{riskLevel} THREAT VERDICT</span>
                </span>
                <span className="text-xs font-medium text-slate-600 bg-slate-100 px-2 py-0.5 rounded border border-slate-200">
                  {confidence}% Certainty
                </span>
              </div>
              <h1 className="text-xl font-bold text-slate-900 tracking-tight">
                Forensic Analysis Results
              </h1>
              <p className="text-xs text-slate-500 max-w-xl">
                Synthesis of RFC header alignment, natural language threat modeling, origin ASN routing, and quarantined payload forensics.
              </p>
            </div>
          </div>

          {/* Right: Primary Action Buttons */}
          <div className="flex flex-wrap items-center gap-2.5 shrink-0 self-start lg:self-auto">
            <button
              type="button"
              onClick={() => onViewChange('forensic-report')}
              className="flex items-center gap-2 px-4 py-2.5 rounded-lg bg-white hover:bg-slate-50 border border-slate-200 text-slate-700 text-xs font-semibold shadow-2xs transition-colors cursor-pointer"
            >
              <FileText className="w-4 h-4 text-slate-500" />
              <span>View Dossier</span>
            </button>

            <button
              type="button"
              onClick={handleExportPdf}
              disabled={exportingPdf}
              className="flex items-center gap-2 px-5 py-2.5 rounded-lg bg-slate-900 hover:bg-slate-800 text-white text-xs font-semibold shadow-xs transition-colors cursor-pointer disabled:opacity-50"
            >
              <Download className="w-4 h-4" />
              <span>{exportingPdf ? 'Exporting...' : 'Export PDF'}</span>
            </button>
          </div>

        </div>

        {/* Linear Threat Score Visual Meter */}
        <div className="mt-6 pt-4 border-t border-slate-100 space-y-1.5">
          <div className="flex items-center justify-between text-xs text-slate-500">
            <span>Threat Severity Scale</span>
            <span className="text-slate-900 font-bold">{threatScore}% Calibrated Risk</span>
          </div>
          <div className="w-full h-2 bg-slate-100 rounded-full overflow-hidden border border-slate-200">
            <div 
              className="h-full rounded-full bg-red-600 transition-all duration-500"
              style={{ width: `${threatScore}%` }}
            />
          </div>
        </div>
      </div>

      {/* Ergonomic Deep-Dive Tabs */}
      <div className="rounded-xl bg-white border border-slate-200 shadow-xs overflow-hidden">
        
        {/* Tab Headers */}
        <div className="flex items-center gap-1 px-4 border-b border-slate-100 bg-slate-50/50 overflow-x-auto text-xs">
          <button
            type="button"
            onClick={() => setActiveTab('factors')}
            className={`flex items-center gap-2 py-3 px-3.5 border-b-2 font-semibold transition-all cursor-pointer whitespace-nowrap ${
              activeTab === 'factors'
                ? 'border-slate-900 text-slate-900'
                : 'border-transparent text-slate-500 hover:text-slate-800'
            }`}
          >
            <ShieldAlert className="w-3.5 h-3.5" />
            <span>Evidence Ledger ({factors.length})</span>
          </button>

          <button
            type="button"
            onClick={() => setActiveTab('ai')}
            className={`flex items-center gap-2 py-3 px-3.5 border-b-2 font-semibold transition-all cursor-pointer whitespace-nowrap ${
              activeTab === 'ai'
                ? 'border-slate-900 text-slate-900'
                : 'border-transparent text-slate-500 hover:text-slate-800'
            }`}
          >
            <Brain className="w-3.5 h-3.5" />
            <span>AI Threat Telemetry</span>
          </button>

          <button
            type="button"
            onClick={() => setActiveTab('forensics')}
            className={`flex items-center gap-2 py-3 px-3.5 border-b-2 font-semibold transition-all cursor-pointer whitespace-nowrap ${
              activeTab === 'forensics'
                ? 'border-slate-900 text-slate-900'
                : 'border-transparent text-slate-500 hover:text-slate-800'
            }`}
          >
            <ShieldX className="w-3.5 h-3.5" />
            <span>Deep Forensics</span>
          </button>

          <button
            type="button"
            onClick={() => setActiveTab('findings')}
            className={`flex items-center gap-2 py-3 px-3.5 border-b-2 font-semibold transition-all cursor-pointer whitespace-nowrap ${
              activeTab === 'findings'
                ? 'border-slate-900 text-slate-900'
                : 'border-transparent text-slate-500 hover:text-slate-800'
            }`}
          >
            <FileText className="w-3.5 h-3.5" />
            <span>Findings & Summary</span>
          </button>
        </div>

        {/* Tab Content Viewport */}
        <div className="p-6">
          
          {/* Tab 1: Multi-Factor Evidence Ledger */}
          {activeTab === 'factors' && (
            <div className="space-y-4">
              <div className="flex items-center justify-between text-xs text-slate-500 border-b border-slate-100 pb-2">
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
                      className="p-4 rounded-xl bg-slate-50 border border-slate-200 hover:border-slate-300 transition-colors space-y-2.5"
                    >
                      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                        <div className="flex items-center gap-2.5">
                          <div className="p-2 rounded-lg bg-white border border-slate-200 text-slate-700 shadow-2xs">
                            <IconComponent className="w-4 h-4" />
                          </div>
                          <div>
                            <span className="text-[10px] uppercase text-slate-500 block font-semibold">{factor.category}</span>
                            <h4 className="text-xs font-bold text-slate-900">{factor.name}</h4>
                          </div>
                        </div>

                        <div className="flex items-center gap-2">
                          <span className={`px-2 py-0.5 rounded text-[10px] font-bold border ${colors.bg} ${colors.border} ${colors.text}`}>
                            {factor.severity}
                          </span>
                          <span className="text-xs font-bold text-slate-900 bg-white px-2.5 py-1 rounded border border-slate-200 shadow-2xs">
                            +{factor.points} / {factor.maxPoints} pts
                          </span>
                        </div>
                      </div>

                      <p className="text-xs text-slate-600 leading-relaxed pl-2 border-l-2 border-slate-300">
                        {factor.evidence}
                      </p>

                      <div className="w-full h-1.5 bg-slate-200 rounded-full overflow-hidden">
                        <div
                          className="h-full rounded-full bg-slate-800"
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
            <div className="space-y-5 text-xs">
              <div className="p-5 rounded-xl bg-slate-50 border border-slate-200 space-y-4">
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-slate-200 pb-3">
                  <div>
                    <span className="text-[10px] uppercase text-slate-500 font-bold block">Model Architecture</span>
                    <div className="text-sm font-bold text-slate-900 mt-0.5">
                      {aiThreat?.model || 'TF-IDF + Logistic Regression Classifier'}
                    </div>
                  </div>
                  <span className={`px-3 py-1 rounded-full text-xs font-bold border ${
                    aiThreat?.prediction === 'PHISHING'
                      ? 'bg-red-50 text-red-700 border-red-200'
                      : 'bg-emerald-50 text-emerald-700 border-emerald-200'
                  }`}>
                    PREDICTION: {aiThreat?.prediction || 'PHISHING'}
                  </span>
                </div>

                <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
                  <div className="p-3 rounded-lg bg-white border border-slate-200">
                    <span className="text-[10px] text-slate-500 block font-semibold">Phishing Probability</span>
                    <span className="text-lg font-bold text-red-700 block mt-0.5 font-mono">
                      {typeof aiThreat?.phishingProbability === 'number' ? `${aiThreat.phishingProbability}%` : `${aiProb}%`}
                    </span>
                  </div>

                  <div className="p-3 rounded-lg bg-white border border-slate-200">
                    <span className="text-[10px] text-slate-500 block font-semibold">Model Certainty</span>
                    <span className="text-lg font-bold text-slate-900 block mt-0.5">
                      {confidence}% Confidence
                    </span>
                  </div>

                  <div className="p-3 rounded-lg bg-white border border-slate-200">
                    <span className="text-[10px] text-slate-500 block font-semibold">Corpus Features</span>
                    <span className="text-lg font-bold text-slate-900 block mt-0.5">
                      5,000 Vocabulary Tokens
                    </span>
                  </div>
                </div>

                {/* Salient Features */}
                {aiThreat?.topFeatures?.length > 0 && (
                  <div className="pt-3 border-t border-slate-200 space-y-2">
                    <span className="text-slate-600 text-xs font-semibold block">
                      Learned Predictive Token Weights (TF-IDF Feature Attributions):
                    </span>
                    <div className="flex flex-wrap gap-2">
                      {aiThreat.topFeatures.map((feat, idx) => (
                        <span 
                          key={idx}
                          className={`px-2.5 py-1 rounded-lg text-xs border font-mono ${
                            feat.indicator === 'PHISHING'
                              ? 'bg-red-50 border-red-200 text-red-700'
                              : 'bg-emerald-50 border-emerald-200 text-emerald-700'
                          }`}
                        >
                          <strong>&quot;{feat.term}&quot;</strong> <span className="text-[10px] opacity-75">({feat.weight > 0 ? `+${feat.weight}` : feat.weight})</span>
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
            <div className="space-y-5 text-xs">
              <div className="p-5 rounded-xl bg-slate-50 border border-slate-200 space-y-3">
                <span className="text-xs font-bold text-slate-900 block uppercase">
                  Itemized Verified Findings:
                </span>
                <div className="space-y-2 text-xs text-slate-700">
                  {(fusion?.verifiedReasons || [
                    'Sender domain fails SPF authentication authorization.',
                    'DKIM cryptographic signature verification failed or body was tampered with in transit.',
                    'Urgent linguistic triggers detected in email subject and text.',
                    'Origin IP corresponds to known proxy or anonymizing routing network.'
                  ]).map((reason, i) => (
                    <div key={i} className="flex items-start gap-2.5 p-2 rounded-lg bg-white border border-slate-200">
                      <CheckCircle2 className="w-4 h-4 text-emerald-600 shrink-0 mt-0.5" />
                      <span>{reason}</span>
                    </div>
                  ))}
                </div>
              </div>

              <div className="p-5 rounded-xl bg-slate-50 border border-slate-200 space-y-2">
                <span className="text-xs font-bold text-slate-900 block uppercase">
                  Forensic Chain of Custody & Evidence Integrity:
                </span>
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 text-xs text-slate-600">
                  <div>
                    Case Reference ID: <strong className="text-slate-900 font-mono">{currentAnalysis?.caseId || 'MAV-2026-CASE'}</strong>
                  </div>
                  <div>
                    Attributed Campaign: <strong className="text-slate-900 font-mono">{currentAnalysis?.campaign?.campaignId || 'TC-001'}</strong>
                  </div>
                  <div className="sm:col-span-2">
                    Evidence SHA-256 Digest: <strong className="text-slate-900 font-mono break-all">{currentAnalysis?.evidenceIntegrity?.contentHashSha256 || 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'}</strong>
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
