import React, { useState } from 'react';
import { 
  FileText, 
  Download, 
  Printer, 
  ShieldCheck, 
  Copy, 
  Check, 
  ExternalLink,
  Lock,
  Layers
} from 'lucide-react';

export const ForensicReportPage = ({ onViewChange }) => {
  const [copied, setCopied] = useState(false);

  const handleCopy = () => {
    setCopied(true);
    setTimeout(() => setCopied(false), 1500);
  };

  return (
    <div className="space-y-6 pb-12">
      
      {/* Action Banner */}
      <div className="rounded-2xl bg-gradient-to-r from-emerald-950/40 via-[#0d162a] to-[#070b13] border border-emerald-500/30 p-6">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
          <div>
            <div className="flex items-center gap-2 text-emerald-400 text-xs font-mono mb-1">
              <span className="w-2 h-2 rounded-full bg-emerald-400 animate-ping"></span>
              STAGE 08 OF 08 • AUTOMATED FORENSIC REPORT & DOSSIER
            </div>
            <h1 className="text-xl font-extrabold text-white font-mono flex items-center gap-2">
              <FileText className="w-6 h-6 text-emerald-400" />
              <span>SIH-2026 Automated Cybersecurity Incident Dossier</span>
            </h1>
            <p className="text-xs text-slate-300 mt-1 font-mono">
              Legally certifiable cryptographic forensic audit ready for CERT-In & Court Admissibility
            </p>
          </div>

          <div className="flex items-center gap-2">
            <button
              onClick={handleCopy}
              className="flex items-center gap-1.5 px-3 py-2 rounded-lg bg-[#0e1c38] hover:bg-cyan-900/60 border border-slate-700 text-slate-200 text-xs font-mono transition-all"
            >
              {copied ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
              <span>{copied ? 'Copied' : 'Copy JSON'}</span>
            </button>
            <button
              onClick={() => window.print()}
              className="flex items-center gap-1.5 px-4 py-2 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-white text-xs font-mono font-bold shadow-lg transition-all"
            >
              <Download className="w-3.5 h-3.5" />
              <span>Export Certified PDF</span>
            </button>
          </div>
        </div>
      </div>

      {/* The Forensic Document Paper View */}
      <div className="max-w-4xl mx-auto rounded-2xl bg-[#090f1d] border border-slate-800 p-8 sm:p-10 shadow-2xl space-y-8 font-mono text-xs text-slate-300">
        
        {/* Document Header */}
        <div className="border-b-2 border-cyan-500/40 pb-6 flex flex-col sm:flex-row sm:items-center justify-between gap-4">
          <div>
            <div className="text-xs font-bold uppercase tracking-widest text-cyan-400">
              NATIONAL CYBER FORENSIC AUDIT REPORT
            </div>
            <h2 className="text-xl font-black text-white mt-1">
              MAVERICK THREAT INCIDENT: CAS-2026-0881
            </h2>
            <div className="text-[11px] text-slate-400 mt-0.5">
              Classification: <span className="text-red-400 font-bold">STRICTLY CONFIDENTIAL // SIH-CERT TIER-1</span>
            </div>
          </div>

          <div className="sm:text-right text-[11px] text-slate-400 space-y-0.5">
            <div>Timestamp: <strong>05-SEP-2026 11:42:08 IST</strong></div>
            <div>Investigator: <strong>MAVERICK AI Agent Core v4.2</strong></div>
            <div>Digital Signature: <span className="text-cyan-300">SHA256:7f4a...88e1</span></div>
          </div>
        </div>

        {/* Section 1: Executive Incident Summary */}
        <div className="space-y-2">
          <h3 className="text-sm font-bold text-white border-b border-slate-800 pb-1 flex items-center gap-2">
            <span className="text-cyan-400">§ 1.0</span> EXECUTIVE THREAT ASSESSMENT
          </h3>
          <p className="font-sans text-slate-300 text-xs leading-relaxed">
            At 11:42:08 IST, the MAVERICK AI Email Threat Ingestion Engine intercepted an adversarial Business Email Compromise (BEC) attack originating from <code className="text-cyan-300 bg-slate-900 px-1 py-0.5 rounded">185.220.101.45</code> targeting the official finance controller mailbox of the organization. The attack leveraged a newly minted homoglyph domain (<code className="text-cyan-300 bg-slate-900 px-1 py-0.5 rounded">micros0ft-support-365.online</code>) with intent to induce immediate unauthorized treasury wire transfer of INR 4.85 Crores.
          </p>
        </div>

        {/* Section 2: Core Forensic Findings Table */}
        <div className="space-y-2">
          <h3 className="text-sm font-bold text-white border-b border-slate-800 pb-1 flex items-center gap-2">
            <span className="text-cyan-400">§ 2.0</span> CRYPTOGRAPHIC & HEADER EVIDENCE
          </h3>

          <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 pt-1">
            <div className="p-2.5 rounded bg-[#060a14] border border-slate-800">
              <span className="text-[10px] text-slate-500 block">SPF Check:</span>
              <span className="font-bold text-red-400">SOFTFAIL (Forged)</span>
            </div>
            <div className="p-2.5 rounded bg-[#060a14] border border-slate-800">
              <span className="text-[10px] text-slate-500 block">DKIM Signature:</span>
              <span className="font-bold text-red-400">INVALID / BROKEN</span>
            </div>
            <div className="p-2.5 rounded bg-[#060a14] border border-slate-800">
              <span className="text-[10px] text-slate-500 block">DMARC Policy:</span>
              <span className="font-bold text-red-400">REJECT ENFORCED</span>
            </div>
            <div className="p-2.5 rounded bg-[#060a14] border border-slate-800">
              <span className="text-[10px] text-slate-500 block">AI Risk Score:</span>
              <span className="font-bold text-red-400">98 / 100 CRITICAL</span>
            </div>
          </div>
        </div>

        {/* Section 3: Extracted Indicators of Compromise */}
        <div className="space-y-2">
          <h3 className="text-sm font-bold text-white border-b border-slate-800 pb-1 flex items-center gap-2">
            <span className="text-cyan-400">§ 3.0</span> EXTRACTED ADVERSARIAL IOCs (STIX 2.1)
          </h3>

          <div className="p-3 bg-[#050810] border border-slate-800 rounded-lg space-y-1 text-[11px] text-slate-400">
            <div>• <strong className="text-cyan-300">IPv4 Origin:</strong> 185.220.101.45 (AS9009 M247 Europe - Tor Exit)</div>
            <div>• <strong className="text-cyan-300">Phishing Domain:</strong> micros0ft-support-365.online (Reg Date: 2026-09-03)</div>
            <div>• <strong className="text-cyan-300">Reverse Proxy Node:</strong> 45.154.255.82 (Evilginx2 Phishlet)</div>
            <div>• <strong className="text-cyan-300">Secondary Exfil Mule:</strong> external-offshore-treasury@proton.me</div>
            <div>• <strong className="text-cyan-300">Correlated Actor:</strong> UNC4219 (APT29 CozyBear Subcontractor)</div>
          </div>
        </div>

        {/* Section 4: Mitre Alignment */}
        <div className="space-y-2">
          <h3 className="text-sm font-bold text-white border-b border-slate-800 pb-1 flex items-center gap-2">
            <span className="text-cyan-400">§ 4.0</span> MITRE ATT&CK ALIGNMENT
          </h3>

          <div className="grid grid-cols-3 gap-2 text-[10px]">
            <div className="p-2 bg-[#060a14] border border-slate-800 rounded">
              <strong className="text-red-300">T1566.002:</strong> Spearphishing Link
            </div>
            <div className="p-2 bg-[#060a14] border border-slate-800 rounded">
              <strong className="text-amber-300">T1583.001:</strong> Typosquat Domains
            </div>
            <div className="p-2 bg-[#060a14] border border-slate-800 rounded">
              <strong className="text-purple-300">T1056.004:</strong> Credential Hijack
            </div>
          </div>
        </div>

        {/* Footer Seal */}
        <div className="pt-6 border-t border-slate-800 flex flex-col sm:flex-row items-center justify-between gap-4 text-[10px] text-slate-500">
          <div className="flex items-center gap-2">
            <ShieldCheck className="w-5 h-5 text-emerald-400" />
            <span>Cryptographically Verified by MAVERICK Kernel • SIH-2026 Certification Authority</span>
          </div>
          <button
            onClick={() => onViewChange('dashboard')}
            className="text-cyan-400 hover:underline"
          >
            ← Return to Live SOC Dashboard
          </button>
        </div>

      </div>

    </div>
  );
};
