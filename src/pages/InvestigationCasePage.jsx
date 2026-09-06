import React, { useState } from 'react';
import { 
  Briefcase, 
  ShieldAlert, 
  CheckCircle2, 
  Clock, 
  ArrowRight, 
  ArrowLeft,
  UserCheck, 
  Layers, 
  FileText,
  Lock,
  Ban,
  Trash2,
  Send,
  Target,
  AlertTriangle,
  GitFork,
  Radio,
  Check
} from 'lucide-react';
import { getStoredCases, updateCaseStatus, toggleCaseContainment, addCaseNote } from '../services/caseStore';

export const InvestigationCasePage = ({ onViewChange, selectedCase, currentAnalysis }) => {
  const [cases, setCases] = useState(getStoredCases());
  const activeCaseId = selectedCase?.caseId || currentAnalysis?.caseItem?.caseId || cases[0]?.caseId;
  const currentCase = cases.find(c => c.caseId === activeCaseId) || cases[0] || {};

  const [newNoteText, setNewNoteText] = useState('');
  const [analystName, setAnalystName] = useState('Analyst (Lead)');

  const handleStatusChange = (newStatus) => {
    const updated = updateCaseStatus(currentCase.caseId, newStatus);
    setCases(updated);
  };

  const handleToggleContainment = (actionKey) => {
    const updated = toggleCaseContainment(currentCase.caseId, actionKey);
    setCases(updated);
  };

  const handleAddNote = (e) => {
    e.preventDefault();
    if (!newNoteText.trim()) return;
    const updated = addCaseNote(currentCase.caseId, newNoteText.trim(), analystName);
    setCases(updated);
    setNewNoteText('');
  };

  const campaign = currentAnalysis?.campaign || {
    campaignId: 'TC-001',
    title: 'Correlated Threat Campaign via Shared IP [185.220.101.45]',
    confidence: 'HIGH (Infrastructure Cluster)',
    clusterType: 'Shared Originating Subnet',
    emailCount: 3,
    domainCount: 2,
    targetsCount: 4,
    correlationReason: 'Potential threat campaign based on shared network infrastructure: Originating IP 185.220.101.45 and AS9009 observed across multiple ingress attempts targeting state treasury and procurement officials.'
  };

  const containment = currentCase.containmentStatus || {
    mailboxPurged: false,
    domainBlocked: true,
    ipBlocked: true,
    credentialsRevoked: false
  };

  return (
    <div className="space-y-6 pb-12 font-sans">
      
      {/* Top Banner Header */}
      <div className="rounded-2xl bg-gradient-to-r from-amber-950/40 via-[#0d162a] to-[#070b13] border border-amber-500/30 p-6 shadow-xl">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
          <div>
            <div className="flex items-center gap-2 text-amber-400 text-xs font-mono mb-1.5">
              <span className="w-2 h-2 rounded-full bg-amber-400 animate-ping"></span>
              STAGE 07 OF 08 • INCIDENT WAR ROOM & CAMPAIGN CORRELATION
            </div>
            <div className="flex flex-wrap items-center gap-3">
              <h1 className="text-xl sm:text-2xl font-extrabold text-white font-mono flex items-center gap-2.5">
                <Briefcase className="w-6 h-6 text-amber-400" />
                <span>Investigation Case: {currentCase.caseId}</span>
              </h1>
              <span className={`px-2.5 py-0.5 rounded text-xs font-mono font-extrabold border ${
                currentCase.status === 'CONFIRMED THREAT' 
                  ? 'bg-red-950 text-red-300 border-red-500/40'
                  : currentCase.status === 'UNDER INVESTIGATION'
                    ? 'bg-amber-950 text-amber-300 border-amber-500/40'
                    : 'bg-emerald-950 text-emerald-300 border-emerald-500/40'
              }`}>
                {currentCase.status}
              </span>
            </div>
            <p className="text-xs text-slate-300 mt-1.5 font-mono">
              {currentCase.title}
            </p>
          </div>

          <div className="flex flex-wrap items-center gap-2.5 shrink-0">
            <button
              type="button"
              onClick={() => onViewChange('threat-graph')}
              className="flex items-center gap-1.5 px-3.5 py-2 rounded-xl bg-[#091122] hover:bg-[#0e1b33] border border-slate-700 text-slate-300 font-mono text-xs transition-all cursor-pointer"
            >
              <ArrowLeft className="w-3.5 h-3.5" />
              <span>Back to Graph</span>
            </button>

            <button
              type="button"
              onClick={() => onViewChange('forensic-report')}
              className="flex items-center gap-2 px-4 py-2.5 rounded-xl bg-gradient-to-r from-cyan-600 to-blue-600 hover:from-cyan-500 hover:to-blue-500 text-white font-mono text-xs font-bold shadow-[0_0_15px_rgba(6,182,212,0.4)] transition-all cursor-pointer"
            >
              <FileText className="w-4 h-4" />
              <span>Generate Forensic Report</span>
              <ArrowRight className="w-4 h-4" />
            </button>
          </div>
        </div>
      </div>

      {/* Grid: Case Details & Containment */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 font-mono text-xs">
        
        {/* Left 2 Cols: Case Telemetry, Campaign Correlation, and Notes */}
        <div className="lg:col-span-2 space-y-6">
          
          {/* Metadata Card */}
          <div className="rounded-xl bg-[#09101e] border border-slate-800 p-5 space-y-4">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-slate-800 pb-3">
              <span className="font-bold uppercase tracking-wider text-slate-200">
                Incident Telemetry & Priority Parameters
              </span>
              <div className="flex items-center gap-2">
                <span className="text-slate-400 text-[10px]">Status:</span>
                <select
                  value={currentCase.status}
                  onChange={(e) => handleStatusChange(e.target.value)}
                  className="bg-[#060a14] border border-slate-700 text-cyan-300 rounded px-2 py-1 text-[11px] focus:outline-none focus:border-cyan-400"
                >
                  <option value="UNDER INVESTIGATION">🟡 UNDER INVESTIGATION</option>
                  <option value="CONFIRMED THREAT">🔴 CONFIRMED THREAT</option>
                  <option value="FALSE POSITIVE">🟢 FALSE POSITIVE</option>
                  <option value="CLOSED">⚫ CLOSED</option>
                </select>
              </div>
            </div>

            <div className="grid grid-cols-2 sm:grid-cols-3 gap-4">
              <div>
                <span className="text-slate-500 text-[10px] uppercase block">Risk Score</span>
                <span className="text-xl font-black text-red-400">{currentCase.riskScore} / 100</span>
              </div>
              <div>
                <span className="text-slate-500 text-[10px] uppercase block">Assigned Lead</span>
                <span className="text-cyan-300 font-bold">{currentCase.assignedAnalyst}</span>
              </div>
              <div>
                <span className="text-slate-500 text-[10px] uppercase block">Correlated IOCs</span>
                <span className="text-white font-bold">{currentCase.iocsCount} Artifacts</span>
              </div>
              <div>
                <span className="text-slate-500 text-[10px] uppercase block">Attributed Cluster</span>
                <span className="text-purple-300 font-bold">{currentCase.threatActorGroup}</span>
              </div>
              <div>
                <span className="text-slate-500 text-[10px] uppercase block">Targeted VIPs</span>
                <span className="text-amber-300 font-bold">{currentCase.affectedTargets} Mailboxes</span>
              </div>
              <div>
                <span className="text-slate-500 text-[10px] uppercase block">Created Timestamp</span>
                <span className="text-slate-300">{currentCase.creationTime}</span>
              </div>
            </div>

            <div className="pt-2 border-t border-slate-800 text-slate-300 font-sans text-xs leading-relaxed">
              {currentCase.summary}
            </div>
          </div>

          {/* Phase 9: Threat Campaign Correlation Section (MAJOR NOVELTY) */}
          <div className="rounded-xl bg-gradient-to-r from-[#0e172a] via-[#091122] to-[#070b13] border border-cyan-500/40 p-5 space-y-3">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-slate-800 pb-2.5">
              <div className="flex items-center gap-2">
                <Target className="w-5 h-5 text-cyan-400" />
                <h3 className="font-bold text-white uppercase tracking-wider text-xs">
                  Threat Campaign Infrastructure Correlation
                </h3>
              </div>
              <span className="px-2 py-0.5 rounded bg-cyan-950 text-cyan-300 border border-cyan-500/40 text-[10px] font-bold">
                CLUSTER: {campaign.campaignId}
              </span>
            </div>

            <p className="text-xs text-slate-300 font-sans leading-relaxed">
              <strong>{campaign.title}</strong>
            </p>

            <p className="text-[11px] text-slate-400 font-sans leading-relaxed">
              {campaign.correlationReason}
            </p>

            <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 pt-1 text-center font-mono">
              <div className="p-2 rounded bg-[#060a14] border border-slate-800">
                <span className="text-[10px] text-slate-500 block">Related Emails</span>
                <span className="text-sm font-bold text-white">{campaign.emailCount || 3} Emails</span>
              </div>
              <div className="p-2 rounded bg-[#060a14] border border-slate-800">
                <span className="text-[10px] text-slate-500 block">Lookalike Domains</span>
                <span className="text-sm font-bold text-cyan-300">{campaign.domainCount || 2} Domains</span>
              </div>
              <div className="p-2 rounded bg-[#060a14] border border-slate-800">
                <span className="text-[10px] text-slate-500 block">Shared IP Nodes</span>
                <span className="text-sm font-bold text-purple-300">1 Shared IP</span>
              </div>
              <div className="p-2 rounded bg-[#060a14] border border-slate-800">
                <span className="text-[10px] text-slate-500 block">Targeted Units</span>
                <span className="text-sm font-bold text-amber-300">{campaign.targetsCount || 4} Mailboxes</span>
              </div>
            </div>
          </div>

          {/* Investigator Notes & Activity Log */}
          <div className="rounded-xl bg-[#09101e] border border-slate-800 p-5 space-y-4">
            <div className="flex items-center justify-between border-b border-slate-800 pb-2.5">
              <span className="font-bold text-white uppercase tracking-wider text-xs flex items-center gap-2">
                <Clock className="w-4 h-4 text-cyan-400" />
                Investigator Chronological Notes ({currentCase.notes?.length || 0})
              </span>
            </div>

            {/* Existing Notes List */}
            <div className="space-y-2.5 max-h-56 overflow-y-auto pr-1">
              {(currentCase.notes || []).map((note) => (
                <div key={note.id} className="p-3 rounded-lg bg-[#060a14] border border-slate-800 space-y-1">
                  <div className="flex justify-between items-center text-[10px]">
                    <span className="text-cyan-300 font-bold">{note.author}</span>
                    <span className="text-slate-500">{note.timestamp}</span>
                  </div>
                  <p className="text-slate-300 font-sans text-xs leading-relaxed">
                    {note.text}
                  </p>
                </div>
              ))}
            </div>

            {/* Add Note Form */}
            <form onSubmit={handleAddNote} className="pt-2 border-t border-slate-800 space-y-2">
              <div className="flex gap-2">
                <input
                  type="text"
                  value={analystName}
                  onChange={(e) => setAnalystName(e.target.value)}
                  placeholder="Analyst designation..."
                  className="w-1/3 p-2 bg-[#060a14] border border-slate-800 rounded-lg text-slate-200 text-xs focus:outline-none focus:border-cyan-500"
                />
                <input
                  type="text"
                  value={newNoteText}
                  onChange={(e) => setNewNoteText(e.target.value)}
                  placeholder="Add case observation, MITRE tactic, or containment update..."
                  className="flex-1 p-2 bg-[#060a14] border border-slate-800 rounded-lg text-slate-200 text-xs focus:outline-none focus:border-cyan-500"
                />
                <button
                  type="submit"
                  className="px-4 py-2 bg-cyan-600 hover:bg-cyan-500 text-white font-bold rounded-lg transition-colors flex items-center gap-1"
                >
                  <Send className="w-3.5 h-3.5" />
                  <span>Log</span>
                </button>
              </div>
            </form>
          </div>

        </div>

        {/* Right 1 Col: Active Containment Actions Checklist */}
        <div className="space-y-6">
          
          <div className="rounded-xl bg-[#09101e] border border-slate-800 p-5 shadow-lg space-y-4">
            <div className="flex items-center justify-between border-b border-slate-800 pb-2.5">
              <span className="font-bold text-white uppercase tracking-wider text-xs flex items-center gap-2">
                <Lock className="w-4 h-4 text-amber-400" />
                Active Containment Playbook
              </span>
              <span className="text-[10px] text-slate-500 font-mono">SOC Actions</span>
            </div>

            <p className="text-[11px] text-slate-400 font-sans leading-relaxed">
              Verify and enforce defensive containment workflows across email gateways, firewalls, and active directory endpoints.
            </p>

            <div className="space-y-2.5">
              
              {/* Action 1: Mailbox Purged */}
              <div
                onClick={() => handleToggleContainment('mailboxPurged')}
                className={`p-3 rounded-lg border cursor-pointer transition-all flex items-center justify-between ${
                  containment.mailboxPurged 
                    ? 'bg-emerald-950/40 border-emerald-500/50 text-emerald-300' 
                    : 'bg-[#060a14] border-slate-800 text-slate-400 hover:border-slate-700'
                }`}
              >
                <div className="space-y-0.5">
                  <span className="font-bold text-xs block text-white">Quarantine Mailbox Ingress</span>
                  <span className="text-[10px] text-slate-400">Purge malicious message from inboxes</span>
                </div>
                <span className={`w-5 h-5 rounded flex items-center justify-center border ${
                  containment.mailboxPurged ? 'bg-emerald-600 border-emerald-400 text-white' : 'border-slate-700'
                }`}>
                  {containment.mailboxPurged && <Check className="w-3.5 h-3.5" />}
                </span>
              </div>

              {/* Action 2: Domain Sinkholed */}
              <div
                onClick={() => handleToggleContainment('domainBlocked')}
                className={`p-3 rounded-lg border cursor-pointer transition-all flex items-center justify-between ${
                  containment.domainBlocked 
                    ? 'bg-emerald-950/40 border-emerald-500/50 text-emerald-300' 
                    : 'bg-[#060a14] border-slate-800 text-slate-400 hover:border-slate-700'
                }`}
              >
                <div className="space-y-0.5">
                  <span className="font-bold text-xs block text-white">Sinkhole Phishing Domain</span>
                  <span className="text-[10px] text-slate-400">Apply DNS firewall RPZ block rule</span>
                </div>
                <span className={`w-5 h-5 rounded flex items-center justify-center border ${
                  containment.domainBlocked ? 'bg-emerald-600 border-emerald-400 text-white' : 'border-slate-700'
                }`}>
                  {containment.domainBlocked && <Check className="w-3.5 h-3.5" />}
                </span>
              </div>

              {/* Action 3: IP Blocked */}
              <div
                onClick={() => handleToggleContainment('ipBlocked')}
                className={`p-3 rounded-lg border cursor-pointer transition-all flex items-center justify-between ${
                  containment.ipBlocked 
                    ? 'bg-emerald-950/40 border-emerald-500/50 text-emerald-300' 
                    : 'bg-[#060a14] border-slate-800 text-slate-400 hover:border-slate-700'
                }`}
              >
                <div className="space-y-0.5">
                  <span className="font-bold text-xs block text-white">Block Originating IP</span>
                  <span className="text-[10px] text-slate-400">Drop traffic at edge router / firewall</span>
                </div>
                <span className={`w-5 h-5 rounded flex items-center justify-center border ${
                  containment.ipBlocked ? 'bg-emerald-600 border-emerald-400 text-white' : 'border-slate-700'
                }`}>
                  {containment.ipBlocked && <Check className="w-3.5 h-3.5" />}
                </span>
              </div>

              {/* Action 4: Credentials Revoked */}
              <div
                onClick={() => handleToggleContainment('credentialsRevoked')}
                className={`p-3 rounded-lg border cursor-pointer transition-all flex items-center justify-between ${
                  containment.credentialsRevoked 
                    ? 'bg-emerald-950/40 border-emerald-500/50 text-emerald-300' 
                    : 'bg-[#060a14] border-slate-800 text-slate-400 hover:border-slate-700'
                }`}
              >
                <div className="space-y-0.5">
                  <span className="font-bold text-xs block text-white">Revoke Targeted Credentials</span>
                  <span className="text-[10px] text-slate-400">Force password reset & token invalidation</span>
                </div>
                <span className={`w-5 h-5 rounded flex items-center justify-center border ${
                  containment.credentialsRevoked ? 'bg-emerald-600 border-emerald-400 text-white' : 'border-slate-700'
                }`}>
                  {containment.credentialsRevoked && <Check className="w-3.5 h-3.5" />}
                </span>
              </div>

            </div>
          </div>

          {/* Quick Case Switcher */}
          <div className="rounded-xl bg-[#09101e] border border-slate-800 p-4 space-y-2">
            <span className="text-[10px] uppercase font-bold text-slate-400 block tracking-wider">
              Other Active Cases in Queue:
            </span>
            <div className="space-y-1.5">
              {cases.map(c => (
                <div
                  key={c.caseId}
                  className={`p-2 rounded border cursor-pointer flex items-center justify-between transition-colors ${
                    c.caseId === currentCase.caseId ? 'bg-cyan-950/80 border-cyan-500/50 text-white' : 'bg-[#060a14] border-slate-800 text-slate-400 hover:text-slate-200'
                  }`}
                >
                  <span className="font-bold">{c.caseId}</span>
                  <span className="text-[10px] text-amber-300">{c.riskScore}/100</span>
                </div>
              ))}
            </div>
          </div>

        </div>

      </div>

    </div>
  );
};
