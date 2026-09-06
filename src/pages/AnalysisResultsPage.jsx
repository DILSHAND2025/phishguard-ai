import React from 'react';
import { 
  ShieldAlert, 
  AlertTriangle, 
  CheckCircle2, 
  Brain, 
  ArrowRight, 
  ArrowLeft,
  Binary,
  GitFork,
  Globe,
  Mail,
  Paperclip,
  ShieldX,
  FileWarning,
  Activity,
  Info,
  Server,
  Layers,
  Cpu
} from 'lucide-react';

export const AnalysisResultsPage = ({ onViewChange, currentAnalysis }) => {
  const email = currentAnalysis?.email;
  const fusion = currentAnalysis?.fusion;
  const aiThreat = currentAnalysis?.aiThreat;

  const threatScore = fusion?.threatScore ?? 92;
  const riskLevel = fusion?.riskLevel ?? 'HIGH';
  const confidence = aiThreat?.confidence ?? 92;
  const aiProb = aiThreat?.phishingProbability ?? 94;

  // Icon map for factors
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
      case 'CRITICAL': return { text: 'text-red-400', border: 'border-red-500/40', bg: 'bg-red-950/30' };
      case 'HIGH': return { text: 'text-amber-400', border: 'border-amber-500/40', bg: 'bg-amber-950/30' };
      case 'MEDIUM': return { text: 'text-blue-400', border: 'border-blue-500/40', bg: 'bg-blue-950/30' };
      default: return { text: 'text-emerald-400', border: 'border-emerald-500/40', bg: 'bg-emerald-950/30' };
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
      evidence: 'High AI phishing probability (94%) with coercive urgency and statutory allocation bypass tokens.'
    },
    {
      id: 'header-forensics',
      category: 'Header Forensics',
      name: 'Authentication Protocol Diagnostics (SPF / DKIM / DMARC)',
      points: 20,
      maxPoints: 20,
      severity: 'CRITICAL',
      evidence: 'SPF resulted in SOFTFAIL. DKIM cryptographic signature verification failed. DMARC policy alignment mandates quarantine/reject.'
    },
    {
      id: 'url-intel',
      category: 'URL & Domain Intelligence',
      name: 'Suspicious URLs & Lookalike Domain',
      points: 18,
      maxPoints: 20,
      severity: 'HIGH',
      evidence: 'Domain exhibits lookalike characteristics and deceptive naming patterns targeting organizational systems.'
    },
    {
      id: 'ip-reputation',
      category: 'IP Reputation',
      name: 'Origin IP Reputation & Hop Analysis',
      points: 14,
      maxPoints: 15,
      severity: 'HIGH',
      evidence: 'Origin IP exhibits characteristics of anonymizing proxy/Tor relay nodes.'
    },
    {
      id: 'geo-asn',
      category: 'Geo / ASN Context',
      name: 'Autonomous System & Network Topology',
      points: 8,
      maxPoints: 10,
      severity: 'MEDIUM',
      evidence: 'Observed network infrastructure routes through Germany (AS9009) with Tor egress classification.'
    },
    {
      id: 'attachment-analysis',
      category: 'Attachment Analysis',
      name: 'Attachment Payload Inspection',
      points: 10,
      maxPoints: 10,
      severity: 'CRITICAL',
      evidence: 'Double-extension obfuscated PE32 executable binary detected.'
    }
  ];

  return (
    <div className="space-y-6 pb-12 font-sans">
      
      {/* Top Banner Header */}
      <div className={`relative overflow-hidden rounded-2xl bg-gradient-to-r ${
        threatScore >= 60 ? 'from-red-950/40 via-[#0d162a] to-[#070b13] border-red-500/40 shadow-[0_0_30px_rgba(239,68,68,0.15)]' : 'from-emerald-950/40 via-[#0d162a] to-[#070b13] border-emerald-500/40'
      } border p-6`}>
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
          <div>
            <div className="flex items-center gap-2 text-red-400 text-xs font-mono mb-1.5">
              <span className="w-2 h-2 rounded-full bg-red-400 animate-ping"></span>
              STAGE 03 OF 08 • FORENSIC VERDICT & EXPLAINABLE RISK SCORE
            </div>

            <div className="flex flex-wrap items-center gap-2.5">
              <h1 className="text-xl sm:text-2xl font-extrabold text-white font-mono flex items-center gap-2.5">
                <ShieldAlert className="w-6 h-6 text-red-400" />
                <span>Threat Classification:</span>
              </h1>
              <span className="px-3 py-1 rounded-lg bg-red-950/90 border border-red-500 text-red-300 font-mono font-extrabold text-xs shadow-[0_0_12px_rgba(239,68,68,0.4)]">
                {riskLevel === 'CRITICAL' || riskLevel === 'HIGH' ? 'MALICIOUS / PHISHING' : riskLevel === 'SUSPICIOUS' ? 'SUSPICIOUS ACTIVITY' : 'BENIGN / VERIFIED'}
              </span>
            </div>

            <p className="text-xs text-slate-300 mt-1.5 font-mono">
              Target: <span className="text-cyan-300 font-semibold">{email?.recipient || 'treasury-controller@gov-organization.in'}</span> | 
              Case Reference: <span className="text-amber-400 font-bold">{currentAnalysis?.caseItem?.caseId || 'CAS-2026-0881'}</span>
            </p>
          </div>

          {/* Top Quick Actions */}
          <div className="flex flex-wrap items-center gap-2.5 shrink-0">
            <button
              type="button"
              id="btn-back-email-analysis-top"
              onClick={() => onViewChange('email-analysis')}
              className="flex items-center gap-1.5 px-3.5 py-2 rounded-xl bg-[#091122] hover:bg-[#0e1b33] border border-slate-700 text-slate-300 font-mono text-xs transition-all cursor-pointer"
            >
              <ArrowLeft className="w-3.5 h-3.5" />
              <span>Back to Ingestion</span>
            </button>

            <button
              type="button"
              id="btn-proceed-ioc-top"
              onClick={() => onViewChange('ioc-intel')}
              className="flex items-center gap-2 px-4 py-2 rounded-xl bg-gradient-to-r from-cyan-600 to-blue-600 hover:from-cyan-500 hover:to-blue-500 text-white font-mono text-xs font-bold shadow-[0_0_15px_rgba(6,182,212,0.4)] transition-all cursor-pointer"
            >
              <Binary className="w-4 h-4" />
              <span>Proceed to IOC Intelligence</span>
              <ArrowRight className="w-4 h-4" />
            </button>
          </div>
        </div>
      </div>

      {/* Required Concise Methodology Explanation Banner */}
      <div className="rounded-xl bg-[#09101e] border border-cyan-500/30 p-4 font-mono text-xs text-slate-300 flex items-start gap-3 shadow-md">
        <Info className="w-5 h-5 text-cyan-400 shrink-0 mt-0.5" />
        <div>
          <span className="text-cyan-300 font-bold block mb-0.5">MAVERICK Multi-Layer Evidence Fusion Engine:</span>
          <p className="text-slate-300 text-xs leading-relaxed font-sans">
            The overall threat score is calculated by combining AI linguistic analysis (25%), header forensics (20%), URL intelligence (20%), IP reputation (15%), Geo/ASN network topology (10%), and payload analysis (10%). Rather than relying on a single detection source, this engine provides fully explainable evidence.
          </p>
        </div>
      </div>

      {/* Main Score & Evidence Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        
        {/* Left Column: Risk Score & Threat Summary */}
        <div className="rounded-xl bg-[#0a1224] border border-red-500/40 p-6 flex flex-col justify-between shadow-[0_0_30px_rgba(239,68,68,0.15)] font-mono space-y-6">
          <div>
            <span className="text-xs uppercase tracking-wider text-slate-400 font-bold block text-center">
              Multi-Layer Threat Evaluation
            </span>

            {/* Circular Risk Score Display */}
            <div className="my-6 flex justify-center">
              <div className="relative inline-flex items-center justify-center w-40 h-40 rounded-full border-4 border-red-500/80 bg-gradient-to-b from-red-950/50 to-[#0a1120] text-red-400 shadow-[0_0_25px_rgba(239,68,68,0.3)]">
                <div className="text-center">
                  <div className="text-5xl font-black text-white tracking-tight">
                    {threatScore}
                  </div>
                  <div className="text-xs font-bold text-red-400 tracking-wider mt-0.5">
                    / 100
                  </div>
                  <div className="text-[10px] uppercase font-bold text-slate-400 mt-1">
                    Risk Score
                  </div>
                </div>
              </div>
            </div>

            {/* Core Metrics: Risk Level & AI Confidence */}
            <div className="grid grid-cols-2 gap-3 text-center pt-2 border-t border-slate-800">
              <div className="p-3 rounded-lg bg-[#060a14] border border-red-500/40">
                <span className="text-[10px] uppercase text-slate-400 block font-semibold">Verdict</span>
                <span className="text-lg font-black text-red-400 flex items-center justify-center gap-1.5 mt-0.5">
                  <span className="w-2 h-2 rounded-full bg-red-400 animate-pulse"></span>
                  {riskLevel}
                </span>
              </div>

              <div className="p-3 rounded-lg bg-[#060a14] border border-cyan-500/40">
                <span className="text-[10px] uppercase text-slate-400 block font-semibold">AI Probability</span>
                <span className="text-lg font-black text-cyan-300 block mt-0.5">
                  {aiProb}%
                </span>
              </div>
            </div>

            {/* Summary Highlights */}
            <div className="mt-5 space-y-2 text-xs text-slate-300">
              <div className="p-2.5 rounded bg-[#060a14] border border-slate-800/80 flex items-center justify-between text-[11px]">
                <span className="text-slate-400">Total Layers Evaluated:</span>
                <span className="text-white font-bold">6 Evidence Sources</span>
              </div>
              <div className="p-2.5 rounded bg-[#060a14] border border-slate-800/80 flex items-center justify-between text-[11px]">
                <span className="text-slate-400">Model Certainty:</span>
                <span className="text-cyan-300 font-bold">{confidence}% Confidence</span>
              </div>
              <div className="p-2.5 rounded bg-[#060a14] border border-slate-800/80 flex items-center justify-between text-[11px]">
                <span className="text-slate-400">Attributed Campaign:</span>
                <span className="text-amber-400 font-bold">{currentAnalysis?.campaign?.campaignId || 'TC-001'}</span>
              </div>
            </div>

            {/* Itemized Verified Findings */}
            {fusion?.verifiedReasons?.length > 0 && (
              <div className="mt-4 p-3 rounded-lg bg-[#060a14] border border-slate-800 space-y-1.5 text-[11px]">
                <span className="text-[10px] uppercase text-slate-400 font-bold block mb-1">
                  Itemized Evidence Signals:
                </span>
                {fusion.verifiedReasons.slice(0, 5).map((r, i) => (
                  <div key={i} className="text-slate-300 text-[10.5px] leading-tight">
                    {r}
                  </div>
                ))}
              </div>
            )}
          </div>

          {/* Primary Action Buttons */}
          <div className="pt-4 border-t border-slate-800 space-y-2.5">
            <button
              type="button"
              id="btn-proceed-to-ioc-intel"
              onClick={() => onViewChange('ioc-intel')}
              className="w-full py-2.5 rounded-xl bg-gradient-to-r from-cyan-600 via-sky-600 to-blue-600 hover:from-cyan-500 hover:to-blue-500 text-white text-xs font-bold flex items-center justify-center gap-2 shadow-[0_0_15px_rgba(6,182,212,0.35)] transition-all cursor-pointer active:scale-95"
            >
              <Binary className="w-4 h-4" />
              <span>Proceed to IOC Intelligence</span>
              <ArrowRight className="w-4 h-4" />
            </button>

            <button
              type="button"
              id="btn-back-to-email-analysis"
              onClick={() => onViewChange('threat-graph')}
              className="w-full py-2.5 rounded-xl bg-[#08101e] hover:bg-[#0c1830] border border-slate-700 text-slate-300 text-xs flex items-center justify-center gap-2 transition-all cursor-pointer"
            >
              <GitFork className="w-4 h-4 text-cyan-400" />
              <span>Explore Threat Graph</span>
            </button>
          </div>
        </div>

        {/* Right Column: Explainable AI & Evidence Breakdown Section */}
        <div className="lg:col-span-2 rounded-xl bg-[#09101e] border border-slate-800 p-6 space-y-5 shadow-lg">
          
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-slate-800 pb-3">
            <div className="flex items-center gap-2.5">
              <Brain className="w-5 h-5 text-cyan-400" />
              <h2 className="text-base font-bold font-mono text-white">
                Explainable Multi-Factor Evidence Ledger
              </h2>
            </div>
            <span className="text-[11px] font-mono text-cyan-300 bg-cyan-950/80 px-2.5 py-0.5 rounded border border-cyan-500/40">
              Total Score: {threatScore} / 100 Points
            </span>
          </div>

          {/* Factor Contribution Cards */}
          <div className="space-y-3.5 font-mono">
            {factors.map((factor) => {
              const IconComponent = getCategoryIcon(factor.category);
              const colors = getSeverityColor(factor.severity);

              return (
                <div
                  key={factor.id}
                  className="p-4 rounded-xl bg-[#060a14] border border-slate-800/90 hover:border-slate-700 transition-all space-y-2.5"
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
                      <span className={`px-2 py-0.5 rounded text-[10px] font-extrabold border ${colors.bg} ${colors.border} ${colors.text}`}>
                        {factor.severity}
                      </span>
                      <span className="text-xs font-black text-cyan-300 bg-slate-900 px-2.5 py-1 rounded border border-slate-800">
                        +{factor.points} / {factor.maxPoints} pts
                      </span>
                    </div>
                  </div>

                  <p className="text-xs text-slate-300 font-sans leading-relaxed pl-1 border-l-2 border-slate-800">
                    {factor.evidence}
                  </p>

                  {/* Progress bar representing fraction of maxPoints */}
                  <div className="w-full h-1.5 bg-slate-900 rounded-full overflow-hidden">
                    <div
                      className={`h-full rounded-full ${
                        factor.points / factor.maxPoints > 0.7 
                          ? 'bg-red-500' 
                          : factor.points / factor.maxPoints > 0.3 
                            ? 'bg-amber-500' 
                            : 'bg-cyan-500'
                      }`}
                      style={{ width: `${Math.min(100, (factor.points / factor.maxPoints) * 100)}%` }}
                    />
                  </div>
                </div>
              );
            })}
          </div>

          {/* AI NLP Linguistic Attribution Box */}
          {aiThreat?.detectedIndicators?.length > 0 && (
            <div className="mt-4 p-4 rounded-xl bg-gradient-to-r from-[#0d162a] to-[#080d19] border border-cyan-500/30 font-mono text-xs space-y-2">
              <div className="flex items-center justify-between">
                <span className="text-cyan-300 font-bold flex items-center gap-1.5">
                  <Cpu className="w-4 h-4" />
                  AI Model Linguistic Attribution Tokens:
                </span>
                <span className="text-[10px] text-slate-400">
                  {aiThreat.detectedIndicators.length} Tokens Identified
                </span>
              </div>
              <div className="flex flex-wrap gap-2 pt-1">
                {aiThreat.detectedIndicators.map((ind, idx) => (
                  <span 
                    key={idx} 
                    className="px-2 py-1 rounded bg-slate-900 border border-slate-800 text-[11px] text-slate-300"
                    title={ind.explanation}
                  >
                    <strong className="text-amber-300">"{ind.token}"</strong> <span className="text-slate-500">({ind.category})</span>
                  </span>
                ))}
              </div>
            </div>
          )}

        </div>

      </div>

    </div>
  );
};
