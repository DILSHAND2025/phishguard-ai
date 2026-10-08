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
  AlertTriangle,
  Info
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
      <div className="rounded-xl bg-white border border-slate-200 p-5 font-sans shadow-xs">
        <div className="flex items-center justify-between border-b border-slate-100 pb-3">
          <div className="flex items-center gap-2">
            <div className="p-1.5 rounded-lg bg-slate-100 text-slate-600">
              <Paperclip className="w-4 h-4" />
            </div>
            <div>
              <span className="text-[10px] uppercase text-slate-500 font-bold tracking-wider block">Forensic Artifact</span>
              <h3 className="text-xs font-bold text-slate-900 tracking-wide">Attachment Forensics</h3>
            </div>
          </div>
          <span className="px-2 py-0.5 rounded text-[10px] font-semibold bg-slate-100 text-slate-600 border border-slate-200">
            0 Attachments
          </span>
        </div>
        <div className="py-6 text-center text-slate-500 text-xs font-sans">
          <p className="italic">No file attachments enclosed in this email.</p>
          <span className="text-[11px] text-slate-400 block mt-1">
            Attachment payload risk: <strong className="text-emerald-600 font-semibold">0 / 10 pts (PASS)</strong>
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

  // Check type mismatch
  const hasTypeMismatch = currentAttachment?.typeMismatch || 
    (currentAttachment?.category === 'EXECUTABLE' && currentAttachment?.filename && !currentAttachment.filename.toLowerCase().endsWith('.exe'));

  // Get indicator icon
  const getIndicatorIcon = (severity) => {
    switch (severity) {
      case 'CRITICAL':
        return <FileWarning className="w-3.5 h-3.5 text-red-600 shrink-0 mt-0.5" />;
      case 'HIGH':
        return <AlertTriangle className="w-3.5 h-3.5 text-amber-600 shrink-0 mt-0.5" />;
      case 'CLEAN':
        return <ShieldCheck className="w-3.5 h-3.5 text-emerald-600 shrink-0 mt-0.5" />;
      default:
        return <Info className="w-3.5 h-3.5 text-blue-600 shrink-0 mt-0.5" />;
    }
  };

  return (
    <div className="rounded-xl bg-white border border-slate-200 p-5 font-sans shadow-xs space-y-4">
      
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-slate-100 pb-3">
        <div className="flex items-center gap-2.5">
          <div className="p-2 rounded-lg bg-slate-100 text-slate-700">
            <Paperclip className="w-4 h-4" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <span className="text-[10px] uppercase text-slate-500 font-bold tracking-wider block">Static Forensic Analysis</span>
              <span className="px-1.5 py-0.2 rounded text-[9px] font-semibold bg-emerald-50 border border-emerald-200 text-emerald-700">
                Zero Execution Sandbox
              </span>
            </div>
            <h3 className="text-xs sm:text-sm font-bold text-slate-900 tracking-wide flex items-center gap-2">
              <span>Attachment Forensics</span>
              <span className="text-[11px] font-semibold text-slate-600 bg-slate-100 px-2 py-0.5 rounded border border-slate-200">
                {safeAttachments.length} {safeAttachments.length === 1 ? 'Attachment' : 'Attachments'}
              </span>
            </h3>
          </div>
        </div>

        {/* Assessment Badge */}
        <div className="flex items-center gap-2 self-start sm:self-auto">
          <span className={`px-2.5 py-1 rounded-lg text-xs font-bold border uppercase tracking-wider ${
            isMalicious 
              ? 'bg-red-50 text-red-700 border-red-200' 
              : isSuspicious 
                ? 'bg-amber-50 text-amber-700 border-amber-200' 
                : 'bg-emerald-50 text-emerald-700 border-emerald-200'
          }`}>
            {inferred.assessment || (isSuspicious ? 'SUSPICIOUS' : 'CLEAN')}
          </span>
        </div>
      </div>

      {/* Multiple Attachments Tab Selector (if > 1) */}
      {safeAttachments.length > 1 && (
        <div className="flex flex-wrap gap-2 pb-1 border-b border-slate-100">
          {safeAttachments.map((att, idx) => (
            <button
              key={idx}
              type="button"
              id={`attachment-tab-${idx}`}
              onClick={() => setSelectedIndex(idx)}
              className={`px-3 py-1.5 rounded-lg text-xs font-semibold transition-all cursor-pointer flex items-center gap-2 border ${
                selectedIndex === idx
                  ? 'bg-slate-900 border-slate-900 text-white'
                  : 'bg-slate-50 border-slate-200 text-slate-600 hover:text-slate-900'
              }`}
            >
              <Paperclip className="w-3 h-3" />
              <span className="truncate max-w-[160px]">{att.filename || `Attachment #${idx + 1}`}</span>
              {att.isSuspicious && (
                <span className="w-1.5 h-1.5 rounded-full bg-red-500"></span>
              )}
            </button>
          ))}
        </div>
      )}

      {/* Core File Identification Metadata - Clean Table/Card Grid */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-2.5 text-xs">
        <div className="p-3 rounded-lg bg-slate-50 border border-slate-200">
          <span className="text-[10px] text-slate-500 uppercase block font-semibold">Filename</span>
          <span className="text-slate-900 font-bold truncate block mt-0.5" title={currentAttachment.filename}>
            {currentAttachment.filename}
          </span>
        </div>

        <div className="p-3 rounded-lg bg-slate-50 border border-slate-200">
          <span className="text-[10px] text-slate-500 uppercase block font-semibold">Size</span>
          <span className="text-slate-800 font-bold block mt-0.5">
            {currentAttachment.size || `${currentAttachment.sizeBytes || 0} B`}
          </span>
        </div>

        <div className="p-3 rounded-lg bg-slate-50 border border-slate-200">
          <span className="text-[10px] text-slate-500 uppercase block font-semibold">MIME Type</span>
          <span className="text-slate-700 font-medium block truncate mt-0.5" title={currentAttachment.mimeType || 'application/octet-stream'}>
            {currentAttachment.mimeType || 'application/octet-stream'}
          </span>
        </div>

        <div className="p-3 rounded-lg bg-slate-50 border border-slate-200">
          <span className="text-[10px] text-slate-500 uppercase block font-semibold">File Type</span>
          <span className={`font-bold block truncate mt-0.5 ${
            currentAttachment.category === 'EXECUTABLE' ? 'text-red-700' : currentAttachment.category === 'ARCHIVE' ? 'text-amber-700' : 'text-emerald-700'
          }`} title={currentAttachment.detectedType}>
            {currentAttachment.detectedType || currentAttachment.category || 'Binary'}
          </span>
        </div>

        <div className="p-3 rounded-lg bg-slate-50 border border-slate-200">
          <span className="text-[10px] text-slate-500 uppercase block font-semibold">Mismatch</span>
          <span className={`font-bold block truncate mt-0.5 ${
            hasTypeMismatch ? 'text-red-700' : 'text-emerald-700'
          }`}>
            {hasTypeMismatch ? 'Extension Mismatch' : 'Matches Declared'}
          </span>
        </div>
      </div>

      {/* Cryptographic Hashes Section */}
      <div className="p-3.5 rounded-lg bg-slate-50 border border-slate-200 space-y-2">
        <div className="flex items-center justify-between text-xs text-slate-600">
          <span className="flex items-center gap-1.5 font-bold uppercase tracking-wider text-slate-700 text-[11px]">
            <Binary className="w-3.5 h-3.5 text-slate-600" />
            Cryptographic Hashes
          </span>
          <span className="text-[10px] text-slate-500">
            Calculated from raw bytes
          </span>
        </div>

        {/* SHA-256 (Primary Forensic Identifier) */}
        <div className="p-2.5 rounded-lg bg-white border border-slate-200 flex items-center justify-between gap-2 shadow-2xs">
          <div className="truncate">
            <span className="text-[10px] uppercase text-slate-500 font-bold block">SHA-256 (Primary Identifier):</span>
            <span className="font-mono text-slate-900 text-xs select-all break-all font-semibold">
              {currentAttachment.sha256 || 'Unavailable'}
            </span>
          </div>
          <button
            type="button"
            id="copy-sha256-btn"
            onClick={() => handleCopy(currentAttachment.sha256, 'sha256')}
            className="p-1.5 rounded hover:bg-slate-100 text-slate-500 hover:text-slate-900 transition-colors shrink-0 cursor-pointer"
            title="Copy SHA-256"
          >
            {copiedField === 'sha256' ? <Check className="w-3.5 h-3.5 text-emerald-600" /> : <Copy className="w-3.5 h-3.5" />}
          </button>
        </div>

        {/* Secondary Hashes: SHA-1 & MD5 */}
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 text-xs">
          <div className="p-2 rounded bg-white border border-slate-200 flex items-center justify-between gap-2">
            <div className="truncate">
              <span className="text-[10px] uppercase text-slate-400 font-bold block">SHA-1:</span>
              <span className="font-mono text-slate-700 truncate block select-all text-[11px]">
                {currentAttachment.sha1 || 'Unavailable'}
              </span>
            </div>
            <button
              type="button"
              id="copy-sha1-btn"
              onClick={() => handleCopy(currentAttachment.sha1, 'sha1')}
              className="p-1 rounded hover:bg-slate-100 text-slate-400 hover:text-slate-700 transition-colors shrink-0 cursor-pointer"
              title="Copy SHA-1"
            >
              {copiedField === 'sha1' ? <Check className="w-3 h-3 text-emerald-600" /> : <Copy className="w-3 h-3" />}
            </button>
          </div>

          <div className="p-2 rounded bg-white border border-slate-200 flex items-center justify-between gap-2">
            <div className="truncate">
              <span className="text-[10px] uppercase text-slate-400 font-bold block">MD5:</span>
              <span className="font-mono text-slate-700 truncate block select-all text-[11px]">
                {currentAttachment.md5 || 'Unavailable'}
              </span>
            </div>
            <button
              type="button"
              id="copy-md5-btn"
              onClick={() => handleCopy(currentAttachment.md5, 'md5')}
              className="p-1 rounded hover:bg-slate-100 text-slate-400 hover:text-slate-700 transition-colors shrink-0 cursor-pointer"
              title="Copy MD5"
            >
              {copiedField === 'md5' ? <Check className="w-3 h-3 text-emerald-600" /> : <Copy className="w-3 h-3" />}
            </button>
          </div>
        </div>
      </div>

      {/* Strict Evidence Classification: OBSERVED vs INFERRED Panels */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-3.5">
        
        {/* Panel 1: OBSERVED EVIDENCE (Factual Static Indicators) */}
        <div className="p-3.5 rounded-lg bg-white border border-slate-200 space-y-2.5">
          <div className="flex items-center justify-between border-b border-slate-100 pb-1.5">
            <span className="text-[10px] uppercase font-bold tracking-wider text-slate-900 flex items-center gap-1.5">
              <Layers className="w-3.5 h-3.5 text-slate-600" />
              Observed Evidence
            </span>
            <span className="text-[10px] text-slate-400 font-medium">Binary Markers</span>
          </div>

          <div className="space-y-1.5 max-h-56 overflow-y-auto pr-1">
            {indicators.length > 0 ? (
              indicators.map((ind, i) => (
                <div key={i} className="p-2 rounded-lg bg-slate-50 border border-slate-200 flex items-start gap-2 text-xs">
                  {getIndicatorIcon(ind.severity)}
                  <div>
                    <span className="text-slate-900 font-semibold block leading-tight">{ind.label}</span>
                    <span className="text-slate-500 text-[11px] block mt-0.5 leading-snug">{ind.detail}</span>
                  </div>
                </div>
              ))
            ) : (
              <div className="p-2.5 rounded bg-slate-50 border border-slate-200 text-xs text-slate-500 italic">
                No suspicious macro, script, or executable byte signatures observed.
              </div>
            )}
          </div>
        </div>

        {/* Panel 2: INFERRED INFORMATION (Risk & Threat Assessment) */}
        <div className="p-3.5 rounded-lg bg-white border border-slate-200 space-y-2.5">
          <div className="flex items-center justify-between border-b border-slate-100 pb-1.5">
            <span className="text-[10px] uppercase font-bold tracking-wider text-slate-900 flex items-center gap-1.5">
              <ShieldAlert className="w-3.5 h-3.5 text-slate-600" />
              Inferred Information
            </span>
            <span className="text-[10px] text-slate-400 font-medium">Risk Interpretation</span>
          </div>

          <div className="space-y-2 text-xs">
            <div className="p-2 rounded bg-slate-50 border border-slate-200 flex items-center justify-between">
              <span className="text-slate-500 text-xs">Assessment:</span>
              <span className={`font-bold text-xs uppercase ${
                isMalicious ? 'text-red-700' : isSuspicious ? 'text-amber-700' : 'text-emerald-700'
              }`}>
                {inferred.assessment || (isSuspicious ? 'SUSPICIOUS' : 'CLEAN')}
              </span>
            </div>

            <div className="p-2 rounded bg-slate-50 border border-slate-200 flex items-center justify-between">
              <span className="text-slate-500 text-xs">Risk Impact:</span>
              <span className={`font-bold text-xs ${
                isMalicious ? 'text-red-700' : isSuspicious ? 'text-amber-700' : 'text-emerald-700'
              }`}>
                +{currentAttachment.isSuspicious ? 10 : 0} / 10 pts (Fusion Layer)
              </span>
            </div>

            {/* Inferred reasons */}
            {inferred.reasons?.length > 0 && (
              <div className="p-2 rounded bg-slate-50 border border-slate-200 space-y-1">
                <span className="text-[10px] uppercase text-slate-500 font-bold block">Evaluation Findings:</span>
                {inferred.reasons.map((r, idx) => (
                  <p key={idx} className="text-slate-600 text-xs leading-tight">
                    • {r}
                  </p>
                ))}
              </div>
            )}
          </div>
        </div>

      </div>

      {/* Safety Notice */}
      <div className="text-[11px] text-slate-500 italic border-t border-slate-100 pt-2 flex items-center gap-1.5">
        <ShieldCheck className="w-3.5 h-3.5 text-emerald-600 shrink-0" />
        <span>Strict forensic isolation: All inspection is purely static. Code, macros, and embedded binaries are never executed.</span>
      </div>

    </div>
  );
};
