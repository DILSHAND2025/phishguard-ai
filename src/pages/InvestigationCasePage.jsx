import React, { useState } from 'react';
import { 
  Briefcase, 
  ShieldAlert, 
  CheckCircle2, 
  Clock, 
  ArrowRight, 
  UserCheck, 
  Layers, 
  FileText,
  Lock,
  Ban,
  Trash2,
  Send
} from 'lucide-react';
import { INCIDENT_CASES } from '../data/mockSocData';

export const InvestigationCasePage = ({ onViewChange, selectedCase }) => {
  const currentCase = selectedCase || INCIDENT_CASES[0];
  const [containmentStatus, setContainmentStatus] = useState({
    tokenRevoked: true,
    firewallBlocked: true,
    mailboxPurged: false,
    domainSinkholed: true
  });

  return (
    <div className="space-y-6 pb-12">
      
      {/* Header */}
      <div className="rounded-2xl bg-gradient-to-r from-amber-950/40 via-[#0d162a] to-[#070b13] border border-amber-500/30 p-6">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
          <div>
            <div className="flex items-center gap-2 text-amber-400 text-xs font-mono mb-1">
              <span className="w-2 h-2 rounded-full bg-amber-400 animate-ping"></span>
              STAGE 07 OF 08 • INCIDENT WAR ROOM & CONTAINMENT
            </div>
            <h1 className="text-xl font-extrabold text-white font-mono flex items-center gap-2">
              <Briefcase className="w-6 h-6 text-amber-400" />
              <span>Incident Case: {currentCase.caseId}</span>
            </h1>
            <p className="text-xs text-slate-300 mt-1 font-mono">
              {currentCase.title}
            </p>
          </div>

          <div className="flex items-center gap-3">
            <button
              onClick={() => onViewChange('forensic-report')}
              className="flex items-center gap-2 px-4 py-2.5 rounded-xl bg-cyan-950/80 hover:bg-cyan-900 border border-cyan-500/40 text-cyan-300 font-mono text-xs font-bold transition-all"
            >
              <FileText className="w-4 h-4" />
              <span>Generate Forensic Report</span>
              <ArrowRight className="w-4 h-4" />
            </button>
          </div>
        </div>
      </div>

      {/* Grid: Case Details & Timeline */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        
        {/* Left 2 Cols: Case Telemetry */}
        <div className="lg:col-span-2 space-y-6">
          
          {/* Metadata Card */}
          <div className="rounded-xl bg-[#09101e] border border-slate-800 p-5 space-y-4 font-mono text-xs">
            <h3 className="font-bold uppercase tracking-wider text-slate-200 border-b border-slate-800 pb-2 flex items-center justify-between">
              <span>Incident Parameters</span>
              <span className="text-red-400 font-extrabold">{currentCase.priority} PRIORITY</span>
            </h3>

            <div className="grid grid-cols-2 sm:grid-cols-3 gap-4">
              <div>
                <span className="text-slate-500 text-[11px] block">Attributed Actor:</span>
                <span className="text-purple-300 font-bold">{currentCase.threatActorGroup}</span>
              </div>
              <div>
                <span className="text-slate-500 text-[11px] block">Attack Stage:</span>
                <span className="text-white">{currentCase.attackStage}</span>
              </div>
              <div>
                <span className="text-slate-500 text-[11px] block">Assigned Lead:</span>
                <span className="text-cyan-300">{currentCase.assignedAnalyst}</span>
              </div>
              <div>
                <span className="text-slate-500 text-[11px] block">Correlated IOCs:</span>
                <span className="text-white">{currentCase.iocsCount} Artifacts</span>
              </div>
              <div>
                <span className="text-slate-500 text-[11px] block">Identified Targets:</span>
                <span className="text-red-300">{currentCase.affectedTargets} VIP Mailboxes</span>
              </div>
              <div>
                <span className="text-slate-500 text-[11px] block">Case Status:</span>
                <span className="text-amber-400 font-bold">{currentCase.status}</span>
              </div>
            </div>

            <div className="pt-2 border-t border-slate-800 text-slate-300 font-sans text-xs">
              <strong className="text-white font-mono">Executive Summary: </strong>
              {currentCase.summary}
            </div>
          </div>

          {/* Containment Playbook Actions */}
          <div className="rounded-xl bg-[#09101e] border border-slate-800 p-5 space-y-4">
            <h3 className="text-xs font-mono font-bold uppercase tracking-wider text-slate-200 border-b border-slate-800 pb-2">
              Automated SOC Containment Playbook (SOAR)
            </h3>

            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 font-mono text-xs">
              
              <div className="p-3 rounded-lg bg-[#060a14] border border-slate-800 flex items-center justify-between">
                <div>
                  <div className="text-white font-bold">1. Revoke VIP Session Tokens</div>
                  <div className="text-[10px] text-slate-400">Force Azure AD / Okta signout</div>
                </div>
                <button
                  onClick={() => setContainmentStatus(prev => ({ ...prev, tokenRevoked: !prev.tokenRevoked }))}
                  className={`px-2.5 py-1 rounded text-[11px] font-bold ${
                    containmentStatus.tokenRevoked ? 'bg-emerald-950 text-emerald-300 border border-emerald-500/40' : 'bg-slate-800 text-slate-400'
                  }`}
                >
                  {containmentStatus.tokenRevoked ? 'ENFORCED' : 'APPLY'}
                </button>
              </div>

              <div className="p-3 rounded-lg bg-[#060a14] border border-slate-800 flex items-center justify-between">
                <div>
                  <div className="text-white font-bold">2. Block C2 Subnet at Perimeter</div>
                  <div className="text-[10px] text-slate-400">Push BGP null route to Cisco ASA</div>
                </div>
                <button
                  onClick={() => setContainmentStatus(prev => ({ ...prev, firewallBlocked: !prev.firewallBlocked }))}
                  className={`px-2.5 py-1 rounded text-[11px] font-bold ${
                    containmentStatus.firewallBlocked ? 'bg-emerald-950 text-emerald-300 border border-emerald-500/40' : 'bg-slate-800 text-slate-400'
                  }`}
                >
                  {containmentStatus.firewallBlocked ? 'ENFORCED' : 'APPLY'}
                </button>
              </div>

              <div className="p-3 rounded-lg bg-[#060a14] border border-slate-800 flex items-center justify-between">
                <div>
                  <div className="text-white font-bold">3. Purge Correlated Inboxes</div>
                  <div className="text-[10px] text-slate-400">Hard-delete copies across O365</div>
                </div>
                <button
                  onClick={() => setContainmentStatus(prev => ({ ...prev, mailboxPurged: !prev.mailboxPurged }))}
                  className={`px-2.5 py-1 rounded text-[11px] font-bold ${
                    containmentStatus.mailboxPurged ? 'bg-emerald-950 text-emerald-300 border border-emerald-500/40' : 'bg-amber-950 text-amber-300 border border-amber-500/40'
                  }`}
                >
                  {containmentStatus.mailboxPurged ? 'PURGED' : 'EXECUTE PURGE'}
                </button>
              </div>

              <div className="p-3 rounded-lg bg-[#060a14] border border-slate-800 flex items-center justify-between">
                <div>
                  <div className="text-white font-bold">4. Domain Sinkhole Request</div>
                  <div className="text-[10px] text-slate-400">Dispatched to CERT-In / Registrar</div>
                </div>
                <button
                  onClick={() => setContainmentStatus(prev => ({ ...prev, domainSinkholed: !prev.domainSinkholed }))}
                  className={`px-2.5 py-1 rounded text-[11px] font-bold ${
                    containmentStatus.domainSinkholed ? 'bg-emerald-950 text-emerald-300 border border-emerald-500/40' : 'bg-slate-800 text-slate-400'
                  }`}
                >
                  {containmentStatus.domainSinkholed ? 'DISPATCHED' : 'SUBMIT'}
                </button>
              </div>

            </div>
          </div>

        </div>

        {/* Right Col: Live Timeline */}
        <div className="rounded-xl bg-[#09101e] border border-slate-800 p-5 space-y-4 font-mono text-xs">
          <h3 className="font-bold uppercase tracking-wider text-slate-200 border-b border-slate-800 pb-2">
            Chronological Audit Trail
          </h3>

          <div className="relative pl-4 space-y-4 before:absolute before:left-1 before:top-2 before:bottom-2 before:w-0.5 before:bg-slate-800">
            <div className="relative">
              <div className="absolute -left-[19px] top-1 w-2.5 h-2.5 rounded-full bg-red-400"></div>
              <div className="text-[10px] text-slate-500">11:42:08 IST</div>
              <div className="text-slate-200 font-bold">Email Intercepted</div>
              <p className="text-[11px] text-slate-400 font-sans">SPF softfail trigger on Tor IP 185.220.101.45</p>
            </div>

            <div className="relative">
              <div className="absolute -left-[19px] top-1 w-2.5 h-2.5 rounded-full bg-cyan-400"></div>
              <div className="text-[10px] text-slate-500">11:42:12 IST</div>
              <div className="text-cyan-300 font-bold">AI Threat Classification</div>
              <p className="text-[11px] text-slate-400 font-sans">MAVERICK assigns 98/100 BEC risk score</p>
            </div>

            <div className="relative">
              <div className="absolute -left-[19px] top-1 w-2.5 h-2.5 rounded-full bg-amber-400"></div>
              <div className="text-[10px] text-slate-500">11:42:15 IST</div>
              <div className="text-amber-300 font-bold">Quarantine & Alert Escalated</div>
              <p className="text-[11px] text-slate-400 font-sans">Case #CAS-2026-0881 auto-created for Tier-3 triage</p>
            </div>

            <div className="relative">
              <div className="absolute -left-[19px] top-1 w-2.5 h-2.5 rounded-full bg-emerald-400"></div>
              <div className="text-[10px] text-slate-500">11:45:00 IST</div>
              <div className="text-emerald-300 font-bold">Perimeter Ingress Blocked</div>
              <p className="text-[11px] text-slate-400 font-sans">Firewall rules enforced across all national endpoints</p>
            </div>
          </div>
        </div>

      </div>

    </div>
  );
};
