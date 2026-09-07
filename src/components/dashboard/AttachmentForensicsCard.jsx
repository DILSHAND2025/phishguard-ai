import React, { useState } from 'react';
import {
  Paperclip,
  ShieldAlert,
  ShieldCheck,
  FileWarning,
  Copy,
  Check,
  Binary,
  Layers,
  FileText,
  AlertTriangle,
  Info,
  Radio,
  FileCode,
  Archive
} from 'lucide-react';

export const AttachmentForensicsCard = ({ attachments = [] }) => {
  const [selectedIndex, setSelectedIndex] = useState(0);
  const [copiedField, setCopiedField] = useState(null);

  const safeAttachments = Array.isArray(attachments) ? attachments : [];
  const currentAttachment = safeAttachments[selectedIndex] || safeAttachments[0];

  const handleCopy = (text, fieldName) => {
    if (!text) return;
    if (typeof navigator !== 'undefined' && navigator.clipboard) {
      navigator.clipboard.writeText(text);
      setCopiedField(fieldName);
      setTimeout(() => setCopiedField(null), 1600);
    }
  };

  if (safeAttachments.length === 0) {
    return (
      <div className="rounded-xl bg-[#09101e] border border-slate-800/80 p-5 font-mono shadow-md">
        <div className="flex items-center justify-between border-b border-slate-800/80 pb-3">
          <div className="flex items-center gap-2">
            <div className="p-1.5 rounded-lg bg-slate-900 border border-slate-800 text-slate-400">
              <Paperclip className="w-4 h-4" />
            </div>
            <div>
              <span className="text-[10px] uppercase text-slate-500 font-bold tracking-wider block">Forensic Artifact</span>
              <h3 className="text-xs font-bold text-white tracking-wide">📎 ATTACHMENT FORENSICS</h3>
            </div>
          </div>
          <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-slate-900 text-slate-400 border border-slate-800">
            0 Attachments
          </span>
        </div>
        <div className="py-6 text-center text-slate-400 text-xs font-sans">
          <p className="italic">No file attachments enclosed in this email.</p>
          <span className="text-[11px] text-slate-500 block mt-1">
            Attachment payload risk: <strong className="text-emerald-400">0 / 10 pts (PASS)</strong>
          </span>
        </div>
      </div>
    );
  }

  const observed = currentAttachment?.observed || {};
  const inferred = currentAttachment?.inferred || {};
  const indicators = observed.indicators || [];

  const isSuspicious = currentAttachment?.isSuspicious || inferred.assessment === 'SUSPICIOUS' || inferred.assessment === 'MALICIOUS';
  const isMalicious = inferred.assessment === 'MALICIOUS';

  // Get indicator icon
  const getIndicatorIcon = (severity) => {
    switch (severity) {
      case 'CRITICAL':
        return <FileWarning className="w-3.5 h-3.5 text-red-400 shrink-0 mt-0.5" />;
      case 'HIGH':
        return <AlertTriangle className="w-3.5 h-3.5 text-amber-400 shrink-0 mt-0.5" />;
      case 'CLEAN':
        return <ShieldCheck className="w-3.5 h-3.5 text-emerald-400 shrink-0 mt-0.5" />;
      default:
        return <Info className="w-3.5 h-3.5 text-blue-400 shrink-0 mt-0.5" />;
    }
  };

  return (
    <div className={`rounded-xl bg-[#09101e] border ${
      isMalicious ? 'border-red-500/50 shadow-[0_0_20px_rgba(239,68,68,0.12)]' : isSuspicious ? 'border-amber-500/40 shadow-[0_0_15px_rgba(245,158,11,0.1)]' : 'border-slate-800'
    } p-5 font-mono shadow-md space-y-4`}>
      
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-slate-800/80 pb-3">
        <div className="flex items-center gap-2.5">
          <div className={`p-2 rounded-lg border ${
            isMalicious ? 'bg-red-950/70 border-red-500/40 text-red-400' : isSuspicious ? 'bg-amber-950/70 border-amber-500/40 text-amber-400' : 'bg-slate-900 border-slate-800 text-cyan-400'
          }`}>
            <Paperclip className="w-4 h-4" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <span className="text-[10px] uppercase text-slate-500 font-bold tracking-wider block">Static Forensic Analysis</span>
              <span className="px-1.5 py-0.2 rounded text-[9px] font-extrabold bg-emerald-950/80 border border-emerald-500/40 text-emerald-400">
                ZERO EXECUTION
              </span>
            </div>
            <h3 className="text-xs sm:text-sm font-black text-white tracking-wide flex items-center gap-2">
              <span>📎 ATTACHMENT FORENSICS</span>
              <span className="text-[11px] font-bold text-cyan-400 bg-cyan-950/80 px-2 py-0.5 rounded border border-cyan-500/30">
                {safeAttachments.length} {safeAttachments.length === 1 ? 'Attachment' : 'Attachments'}
              </span>
            </h3>
          </div>
        </div>

        {/* Assessment Badge */}
        <div className="flex items-center gap-2 self-start sm:self-auto">
          <span className={`px-2.5 py-1 rounded-lg text-xs font-black border uppercase tracking-wider ${
            isMalicious 
              ? 'bg-red-950/90 text-red-300 border-red-500/60 shadow-[0_0_10px_rgba(239,68,68,0.3)]' 
              : isSuspicious 
                ? 'bg-amber-950/90 text-amber-300 border-amber-500/60 shadow-[0_0_10px_rgba(245,158,11,0.25)]' 
                : 'bg-emerald-950/90 text-emerald-300 border-emerald-500/60'
          }`}>
            {inferred.assessment || (isSuspicious ? 'SUSPICIOUS' : 'CLEAN')}
          </span>
        </div>
      </div>

      {/* Multiple Attachments Tab Selector (if > 1) */}
      {safeAttachments.length > 1 && (
        <div className="flex flex-wrap gap-2 pb-1 border-b border-slate-800/80">
          {safeAttachments.map((att, idx) => (
            <button
              key={idx}
              type="button"
              id={`attachment-tab-${idx}`}
              onClick={() => setSelectedIndex(idx)}
              className={`px-3 py-1.5 rounded-lg text-xs font-bold transition-all cursor-pointer flex items-center gap-2 border ${
                selectedIndex === idx
                  ? 'bg-cyan-950/90 border-cyan-500/60 text-cyan-300 shadow-[0_0_10px_rgba(6,182,212,0.25)]'
                  : 'bg-[#060a14] border-slate-800 text-slate-400 hover:text-white hover:border-slate-700'
              }`}
            >
              <Paperclip className="w-3 h-3" />
              <span className="truncate max-w-[160px]">{att.filename || `Attachment #${idx + 1}`}</span>
              {att.isSuspicious && (
                <span className="w-1.5 h-1.5 rounded-full bg-red-400 animate-pulse"></span>
              )}
            </button>
          ))}
        </div>
      )}

      {/* Core File Identification Metadata */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-2.5 text-xs">
        <div className="p-3 rounded-lg bg-[#060a14] border border-slate-800/90">
          <span className="text-[10px] text-slate-500 uppercase block font-semibold">File</span>
          <span className="text-white font-bold truncate block mt-0.5" title={currentAttachment.filename}>
            {currentAttachment.filename}
          </span>
        </div>

        <div className="p-3 rounded-lg bg-[#060a14] border border-slate-800/90">
          <span className="text-[10px] text-slate-500 uppercase block font-semibold">Size</span>
          <span className="text-cyan-300 font-bold block mt-0.5">
            {currentAttachment.size || `${currentAttachment.sizeBytes || 0} B`}
          </span>
        </div>

        <div className="p-3 rounded-lg bg-[#060a14] border border-slate-800/90">
          <span className="text-[10px] text-slate-500 uppercase block font-semibold">Declared MIME</span>
          <span className="text-slate-200 font-semibold block truncate mt-0.5" title={currentAttachment.mimeType || 'application/octet-stream'}>
            {currentAttachment.mimeType || 'application/octet-stream'}
          </span>
        </div>

        <div className="p-3 rounded-lg bg-[#060a14] border border-slate-800/90">
          <span className="text-[10px] text-slate-500 uppercase block font-semibold">Actual Detected Type</span>
          <span className={`font-bold block truncate mt-0.5 ${
            currentAttachment.category === 'EXECUTABLE' ? 'text-red-400' : currentAttachment.category === 'ARCHIVE' ? 'text-amber-400' : 'text-emerald-400'
          }`} title={currentAttachment.detectedType}>
            {currentAttachment.detectedType || 'Binary Payload'}
          </span>
        </div>
      </div>

      {/* Cryptographic Hashes Section */}
      <div className="p-3 rounded-lg bg-[#060a14] border border-slate-800/90 space-y-2">
        <div className="flex items-center justify-between text-[11px] text-slate-400">
          <span className="flex items-center gap-1.5 font-bold uppercase tracking-wider text-slate-300">
            <Binary className="w-3.5 h-3.5 text-cyan-400" />
            Cryptographic Hashes (Byte Signatures)
          </span>
          <span className="text-[10px] text-slate-500">
            Calculated from raw attachment bytes
          </span>
        </div>

        {/* SHA-256 (Primary Forensic Identifier) */}
        <div className="p-2 rounded bg-[#09101d] border border-cyan-500/30 flex items-center justify-between gap-2">
          <div className="truncate">
            <span className="text-[10px] uppercase text-cyan-400 font-black block">SHA-256 (Primary Identifier):</span>
            <span className="font-mono text-white text-[11px] select-all break-all">
              {currentAttachment.sha256 || 'Unavailable'}
            </span>
          </div>
          <button
            type="button"
            id="copy-sha256-btn"
            onClick={() => handleCopy(currentAttachment.sha256, 'sha256')}
            className="p-1.5 rounded hover:bg-cyan-950/80 text-slate-400 hover:text-cyan-300 transition-colors shrink-0 cursor-pointer"
            title="Copy SHA-256"
          >
            {copiedField === 'sha256' ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
          </button>
        </div>

        {/* Secondary Hashes: SHA-1 & MD5 */}
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 text-[10.5px]">
          <div className="p-2 rounded bg-[#070c18] border border-slate-800 flex items-center justify-between gap-2">
            <div className="truncate">
              <span className="text-[9.5px] uppercase text-slate-500 font-bold block">SHA-1:</span>
              <span className="font-mono text-slate-300 truncate block select-all">
                {currentAttachment.sha1 || 'Unavailable'}
              </span>
            </div>
            <button
              type="button"
              id="copy-sha1-btn"
              onClick={() => handleCopy(currentAttachment.sha1, 'sha1')}
              className="p-1 rounded hover:bg-slate-800 text-slate-400 hover:text-slate-200 transition-colors shrink-0 cursor-pointer"
              title="Copy SHA-1"
            >
              {copiedField === 'sha1' ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
            </button>
          </div>

          <div className="p-2 rounded bg-[#070c18] border border-slate-800 flex items-center justify-between gap-2">
            <div className="truncate">
              <span className="text-[9.5px] uppercase text-slate-500 font-bold block">MD5:</span>
              <span className="font-mono text-slate-300 truncate block select-all">
                {currentAttachment.md5 || 'Unavailable'}
              </span>
            </div>
            <button
              type="button"
              id="copy-md5-btn"
              onClick={() => handleCopy(currentAttachment.md5, 'md5')}
              className="p-1 rounded hover:bg-slate-800 text-slate-400 hover:text-slate-200 transition-colors shrink-0 cursor-pointer"
              title="Copy MD5"
            >
              {copiedField === 'md5' ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
            </button>
          </div>
        </div>
      </div>

      {/* Strict Evidence Classification: OBSERVED vs INFERRED Panels */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-3.5">
        
        {/* Panel 1: OBSERVED EVIDENCE (Factual Static Indicators) */}
        <div className="p-3.5 rounded-lg bg-[#060a14] border border-cyan-500/30 space-y-2.5">
          <div className="flex items-center justify-between border-b border-slate-800/80 pb-1.5">
            <span className="text-[10px] uppercase font-black tracking-wider text-cyan-300 flex items-center gap-1.5">
              <Layers className="w-3.5 h-3.5 text-cyan-400" />
              OBSERVED EVIDENCE
            </span>
            <span className="text-[9.5px] text-slate-500 font-semibold">Factual Binary Markers</span>
          </div>

          <div className="space-y-1.5 max-h-56 overflow-y-auto pr-1">
            {indicators.length > 0 ? (
              indicators.map((ind, i) => (
                <div key={i} className="p-2 rounded bg-[#09101d] border border-slate-800/80 flex items-start gap-2 text-[11px]">
                  {getIndicatorIcon(ind.severity)}
                  <div>
                    <span className="text-white font-bold block leading-tight">{ind.label}</span>
                    <span className="text-slate-400 text-[10.5px] block font-sans mt-0.5 leading-snug">{ind.detail}</span>
                  </div>
                </div>
              ))
            ) : (
              <div className="p-2.5 rounded bg-[#09101d] border border-slate-800 text-[11px] text-slate-400 italic">
                ✓ No suspicious macro, script, or executable byte signatures observed.
              </div>
            )}
          </div>
        </div>

        {/* Panel 2: INFERRED INFORMATION (Risk & Threat Assessment) */}
        <div className="p-3.5 rounded-lg bg-[#060a14] border border-red-500/30 space-y-2.5">
          <div className="flex items-center justify-between border-b border-slate-800/80 pb-1.5">
            <span className="text-[10px] uppercase font-black tracking-wider text-red-400 flex items-center gap-1.5">
              <ShieldAlert className="w-3.5 h-3.5 text-red-400" />
              INFERRED INFORMATION
            </span>
            <span className="text-[9.5px] text-slate-500 font-semibold">Heuristic Threat Evaluation</span>
          </div>

          <div className="space-y-2 text-xs">
            <div className="p-2 rounded bg-[#09101d] border border-slate-800 flex items-center justify-between">
              <span className="text-slate-400 text-[11px]">Assessment:</span>
              <span className={`font-black text-xs uppercase ${
                isMalicious ? 'text-red-400' : isSuspicious ? 'text-amber-400' : 'text-emerald-400'
              }`}>
                {inferred.assessment || (isSuspicious ? 'SUSPICIOUS' : 'CLEAN')}
              </span>
            </div>

            <div className="p-2 rounded bg-[#09101d] border border-slate-800 flex items-center justify-between">
              <span className="text-slate-400 text-[11px]">Attachment Risk Impact:</span>
              <span className={`font-black text-xs ${
                isMalicious ? 'text-red-400' : isSuspicious ? 'text-amber-400' : 'text-emerald-400'
              }`}>
                +{currentAttachment.isSuspicious ? 10 : 0} / 10 pts (Fusion Layer 6)
              </span>
            </div>

            {/* Threat Intelligence Reputation */}
            <div className="p-2 rounded bg-[#09101d] border border-slate-800">
              <div className="flex items-center justify-between">
                <span className="text-slate-400 text-[11px]">Hash Reputation:</span>
                <span className={`font-bold text-[11px] uppercase ${
                  currentAttachment.reputation?.verdict === 'MALICIOUS' 
                    ? 'text-red-400' 
                    : currentAttachment.reputation?.status === 'SUCCESS' 
                      ? 'text-emerald-400' 
                      : 'text-slate-500'
                }`}>
                  {currentAttachment.reputation?.verdict || currentAttachment.reputation?.status || 'UNAVAILABLE'}
                </span>
              </div>
              <p className="text-[10px] text-slate-500 font-sans mt-1">
                {currentAttachment.reputation?.details || 'Threat intelligence query: UNAVAILABLE on server. Zero fabricated results.'}
              </p>
            </div>

            {/* Inferred reasons */}
            {inferred.reasons?.length > 0 && (
              <div className="p-2 rounded bg-[#09101d] border border-slate-800 space-y-1">
                <span className="text-[10px] uppercase text-slate-500 font-bold block">Evaluation Findings:</span>
                {inferred.reasons.map((r, idx) => (
                  <p key={idx} className="text-slate-300 text-[10.5px] font-sans leading-tight">
                    • {r}
                  </p>
                ))}
              </div>
            )}
          </div>
        </div>

      </div>

      {/* Safety Notice */}
      <div className="text-[10px] text-slate-500 font-sans italic border-t border-slate-800/80 pt-2 flex items-center gap-1.5">
        <ShieldCheck className="w-3.5 h-3.5 text-emerald-500 shrink-0" />
        <span>Strict forensic isolation: All inspection is purely static. Code, macros, and embedded binaries are never executed.</span>
      </div>

    </div>
  );
};
