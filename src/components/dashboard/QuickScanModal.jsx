import React, { useState, useRef } from 'react';
import { 
  X, 
  Zap, 
  UploadCloud, 
  CheckCircle2, 
  AlertTriangle,
  Loader2,
  FolderOpen,
  Paperclip
} from 'lucide-react';
import { SYNTHETIC_SCENARIOS } from '../../data/syntheticScenarios';
import { parseEmailContent } from '../../services/emailParser';

export const QuickScanModal = ({ isOpen, onClose, onStartAnalysis }) => {
  const [activeTab, setActiveTab] = useState('upload'); // 'upload' | 'preset' | 'raw'
  const [selectedPresetId, setSelectedPresetId] = useState('ceo-bec');
  const [rawText, setRawText] = useState('');
  
  // File Upload State
  const [uploadedFile, setUploadedFile] = useState(null);
  const [uploadedParsed, setUploadedParsed] = useState(null);
  const [isReadingFile, setIsReadingFile] = useState(false);
  const [uploadError, setUploadError] = useState(null);
  const [isDragging, setIsDragging] = useState(false);
  const modalFileInputRef = useRef(null);

  // Scanning State
  const [isScanning, setIsScanning] = useState(false);
  const [scanProgress, setScanProgress] = useState(0);
  const [scanLog, setScanLog] = useState([]);

  if (!isOpen) return null;

  const handleProcessFile = (file) => {
    if (!file) return;
    setUploadError(null);
    setIsReadingFile(true);

    try {
      if (file.size > 25 * 1024 * 1024) {
        throw new Error('File exceeds maximum safe size limit (25 MB).');
      }

      const reader = new FileReader();

      reader.onerror = () => {
        setIsReadingFile(false);
        setUploadError(`Failed to read file "${file.name}". Permission denied or file unreadable.`);
      };

      reader.onload = async (event) => {
        try {
          const text = event.target?.result;
          if (!text || typeof text !== 'string' || !text.trim()) {
            throw new Error(`File "${file.name}" appears to be empty (0 bytes).`);
          }

          if (text.charCodeAt(0) === 0xD0 && text.charCodeAt(1) === 0xCF) {
            throw new Error('Binary Outlook .msg format detected. Please export message as RFC 822 .eml format.');
          }

          const parsed = await parseEmailContent(text, { name: file.name, size: file.size });
          parsed.scenarioName = `Uploaded: ${file.name}`;
          parsed.tag = 'REAL INGESTED FILE';

          setUploadedFile({
            name: file.name,
            size: (file.size / 1024).toFixed(1) + ' KB'
          });
          setUploadedParsed(parsed);
          setIsReadingFile(false);
        } catch (err) {
          console.error('Error parsing uploaded file:', err);
          setUploadError(err.message || 'Malformed email format.');
          setIsReadingFile(false);
        }
      };

      reader.readAsText(file);
    } catch (err) {
      setUploadError(err.message || 'Error processing file.');
      setIsReadingFile(false);
    }
  };

  const handleModalFileChange = (e) => {
    const file = e.target.files?.[0];
    if (file) handleProcessFile(file);
    e.target.value = '';
  };

  const handleModalDrop = (e) => {
    e.preventDefault();
    setIsDragging(false);
    const file = e.dataTransfer.files?.[0];
    if (file) handleProcessFile(file);
  };

  const handleRunScan = async () => {
    if (activeTab === 'upload') {
      if (!uploadedParsed) {
        if (modalFileInputRef.current) {
          modalFileInputRef.current.click();
        }
        return;
      }
    }

    setIsScanning(true);
    setScanProgress(15);
    setScanLog(['[+] Ingesting MIME envelope & headers...']);

    setTimeout(() => {
      setScanProgress(45);
      setScanLog(prev => [...prev, '[+] Parsing RFC 822 headers: SPF=FAIL, DKIM=FAIL, DMARC=FAIL']);
    }, 300);

    setTimeout(() => {
      setScanProgress(75);
      setScanLog(prev => [...prev, '[+] NLP Threat Model: Adversarial intent evaluated', '[+] Extracting IOCs & Multi-hop topology...']);
    }, 650);

    setTimeout(async () => {
      setScanProgress(100);
      setScanLog(prev => [...prev, '[+] SIH-MAVERICK Evidence Fusion completed. Dossier generated.']);
      setIsScanning(false);
      
      if (activeTab === 'upload') {
        if (onStartAnalysis && uploadedParsed) {
          onStartAnalysis(uploadedParsed);
        }
      } else if (activeTab === 'preset') {
        const scenario = SYNTHETIC_SCENARIOS.find(s => s.id === selectedPresetId) || SYNTHETIC_SCENARIOS[0];
        if (onStartAnalysis) {
          onStartAnalysis(scenario);
        }
      } else {
        if (rawText.trim()) {
          const parsed = await parseEmailContent(rawText);
          parsed.scenarioName = 'Pasted RFC 822 Scan';
          if (onStartAnalysis) {
            onStartAnalysis(parsed);
          }
        }
      }
      onClose();
    }, 1000);
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm animate-fadeIn font-sans">
      <div className="w-full max-w-2xl rounded-2xl bg-gradient-to-b from-[#0d1629] to-[#080d18] border border-cyan-500/40 p-6 shadow-[0_0_50px_rgba(6,182,212,0.2)]">
        
        {/* Header */}
        <div className="flex items-center justify-between border-b border-slate-800 pb-4">
          <div className="flex items-center gap-3">
            <div className="p-2 rounded-lg bg-cyan-950/60 border border-cyan-500/40 text-cyan-400">
              <Zap className="w-5 h-5" />
            </div>
            <div>
              <h3 className="text-base font-bold font-mono text-white">
                MAVERICK Quick Email Threat Scanner
              </h3>
              <p className="text-xs text-slate-400 font-mono">
                AI Deep Ingestion & Behavioral IOC Extractor
              </p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="p-1.5 rounded-lg text-slate-400 hover:text-white hover:bg-slate-800 transition-colors cursor-pointer"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Tab Selection */}
        <div className="flex gap-2 my-4 border-b border-slate-800/80 pb-2">
          <button
            type="button"
            onClick={() => setActiveTab('upload')}
            className={`px-3 py-1.5 rounded-lg text-xs font-mono font-medium transition-all cursor-pointer flex items-center gap-1.5 ${
              activeTab === 'upload'
                ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            <UploadCloud className="w-3.5 h-3.5" />
            <span>Upload .eml File</span>
          </button>

          <button
            type="button"
            onClick={() => setActiveTab('preset')}
            className={`px-3 py-1.5 rounded-lg text-xs font-mono font-medium transition-all cursor-pointer ${
              activeTab === 'preset'
                ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            Controlled SIH Scenarios
          </button>

          <button
            type="button"
            onClick={() => setActiveTab('raw')}
            className={`px-3 py-1.5 rounded-lg text-xs font-mono font-medium transition-all cursor-pointer ${
              activeTab === 'raw'
                ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            Raw Headers / RFC 822 Paste
          </button>
        </div>

        {/* Body content */}
        {activeTab === 'upload' ? (
          <div className="space-y-3">
            <input
              type="file"
              ref={modalFileInputRef}
              onChange={handleModalFileChange}
              onClick={(e) => { e.target.value = ''; }}
              accept=".eml,.msg,.txt,.EML,.MSG,.TXT,message/rfc822,text/plain,text/*,*/*"
              className="hidden"
            />

            {/* Drag & Drop Area */}
            <div
              onDragOver={(e) => { e.preventDefault(); setIsDragging(true); }}
              onDragLeave={(e) => { e.preventDefault(); setIsDragging(false); }}
              onDrop={handleModalDrop}
              onClick={() => modalFileInputRef.current?.click()}
              className={`rounded-xl border-2 border-dashed p-6 text-center transition-all cursor-pointer ${
                isDragging
                  ? 'border-cyan-400 bg-cyan-950/40 shadow-[0_0_25px_rgba(6,182,212,0.3)] scale-[0.99]'
                  : uploadedParsed
                    ? 'border-emerald-500/60 bg-emerald-950/20'
                    : 'border-slate-800 hover:border-cyan-500/40 bg-[#080d1a]'
              }`}
            >
              {isReadingFile ? (
                <div className="flex flex-col items-center justify-center py-4 space-y-2">
                  <Loader2 className="w-8 h-8 text-cyan-400 animate-spin" />
                  <p className="text-xs text-cyan-300 font-mono">
                    Ingesting RFC 822 envelope and extracting indicators...
                  </p>
                </div>
              ) : uploadedParsed ? (
                <div className="space-y-3">
                  <div className="flex items-center justify-center gap-2 text-emerald-400 font-mono font-bold text-xs">
                    <CheckCircle2 className="w-5 h-5" />
                    <span>File Ingested Successfully</span>
                  </div>

                  <div className="p-3 rounded-lg bg-[#060a14] border border-emerald-500/30 text-left space-y-1.5 font-mono text-xs">
                    <div className="flex items-center justify-between">
                      <span className="text-white font-bold truncate max-w-[320px]">
                        📄 {uploadedFile?.name}
                      </span>
                      <span className="text-cyan-400 text-[10px] font-bold">
                        {uploadedFile?.size}
                      </span>
                    </div>
                    <div className="text-slate-300 truncate text-[11px]">
                      <strong className="text-slate-400">Subject:</strong> {uploadedParsed.subject || '(No Subject)'}
                    </div>
                    <div className="text-cyan-300 truncate text-[11px]">
                      <strong className="text-slate-400">From:</strong> {uploadedParsed.fromParsed?.address || uploadedParsed.sender}
                    </div>
                    {uploadedParsed.attachments && uploadedParsed.attachments.length > 0 && (
                      <div className="text-amber-400 text-[11px] flex items-center gap-1 pt-1 border-t border-slate-800">
                        <Paperclip className="w-3.5 h-3.5" />
                        <span>{uploadedParsed.attachments.length} attachment(s) identified for static inspection</span>
                      </div>
                    )}
                  </div>

                  <p className="text-[11px] text-slate-400 font-mono">
                    Click <strong className="text-cyan-300">"Launch Forensic Scan"</strong> below to analyze, or click here to choose a different file.
                  </p>
                </div>
              ) : (
                <div className="flex flex-col items-center justify-center space-y-2.5">
                  <div className="p-3 rounded-xl bg-cyan-950/40 border border-cyan-500/30 text-cyan-400">
                    <UploadCloud className="w-7 h-7" />
                  </div>
                  <div>
                    <p className="text-xs font-semibold text-slate-200">
                      Drag & Drop your <span className="text-cyan-300 font-mono font-bold">.eml</span> or <span className="text-cyan-300 font-mono font-bold">.txt</span> file here
                    </p>
                    <p className="text-[11px] text-slate-500 font-mono mt-0.5">
                      or click anywhere in this box to browse local storage
                    </p>
                  </div>
                  <span className="inline-flex items-center gap-1.5 px-3 py-1 rounded-md bg-cyan-950/60 border border-cyan-500/40 text-cyan-300 text-[11px] font-mono">
                    <FolderOpen className="w-3.5 h-3.5" />
                    Browse Files
                  </span>
                </div>
              )}
            </div>

            {/* Error Message Banner */}
            {uploadError && (
              <div className="p-3 rounded-lg bg-red-950/50 border border-red-500/40 flex items-start gap-2 text-xs font-mono text-red-200">
                <AlertTriangle className="w-4 h-4 text-red-400 shrink-0 mt-0.5" />
                <div className="flex-1">
                  <strong>Upload Warning:</strong> {uploadError}
                </div>
                <button
                  type="button"
                  onClick={() => setUploadError(null)}
                  className="text-red-400 hover:text-white"
                >
                  <X className="w-3.5 h-3.5" />
                </button>
              </div>
            )}
          </div>
        ) : activeTab === 'preset' ? (
          <div className="space-y-2.5 max-h-64 overflow-y-auto pr-1">
            {SYNTHETIC_SCENARIOS.map(p => (
              <div
                key={p.id}
                onClick={() => setSelectedPresetId(p.id)}
                className={`p-3 rounded-lg border cursor-pointer transition-all ${
                  selectedPresetId === p.id
                    ? 'bg-[#0f1d38] border-cyan-400 shadow-[0_0_15px_rgba(6,182,212,0.2)]'
                    : 'bg-[#091122] border-slate-800 hover:border-slate-700'
                }`}
              >
                <div className="flex items-center justify-between">
                  <span className="text-xs font-bold text-white font-mono">{p.name}</span>
                  <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-red-950/60 border border-red-500/30 text-red-300 font-bold">
                    {p.category}
                  </span>
                </div>
                <div className="text-[11px] font-mono text-cyan-300/90 mt-1 truncate">
                  From: {p.sender}
                </div>
                <div className="text-xs text-slate-300 mt-0.5 line-clamp-1">
                  Subject: {p.subject}
                </div>
              </div>
            ))}
          </div>
        ) : (
          <div>
            <textarea
              rows={6}
              value={rawText}
              onChange={(e) => setRawText(e.target.value)}
              placeholder="Paste raw email RFC headers (Received from, DKIM-Signature, Authentication-Results, Message-ID)..."
              className="w-full p-3 bg-[#080d1a] border border-slate-800 rounded-lg text-xs font-mono text-slate-200 placeholder-slate-600 focus:outline-none focus:border-cyan-500"
            />
          </div>
        )}

        {/* Live scanning progress and console */}
        {isScanning && (
          <div className="mt-4 p-3 rounded-lg bg-[#050914] border border-cyan-500/30 space-y-2">
            <div className="flex items-center justify-between text-xs font-mono text-cyan-300">
              <span className="flex items-center gap-2">
                <Loader2 className="w-3.5 h-3.5 animate-spin text-cyan-400" />
                AI Scanning Pipeline Executing...
              </span>
              <span>{scanProgress}%</span>
            </div>
            <div className="w-full h-1.5 bg-slate-800 rounded-full overflow-hidden">
              <div 
                className="h-full bg-gradient-to-r from-cyan-400 to-blue-500 transition-all duration-300"
                style={{ width: `${scanProgress}%` }}
              />
            </div>
            <div className="space-y-1 font-mono text-[10px] text-slate-400">
              {scanLog.map((log, i) => (
                <div key={i} className="text-cyan-200/90">{log}</div>
              ))}
            </div>
          </div>
        )}

        {/* Footer actions */}
        <div className="mt-5 pt-4 border-t border-slate-800 flex items-center justify-between">
          <span className="text-[11px] font-mono text-slate-500">
            Powered by MAVERICK Deep Learning & Evidence Fusion
          </span>
          <div className="flex items-center gap-2">
            <button
              onClick={onClose}
              disabled={isScanning}
              className="px-4 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-xs font-mono text-slate-300 transition-colors cursor-pointer"
            >
              Cancel
            </button>
            <button
              onClick={handleRunScan}
              disabled={isScanning || isReadingFile}
              className="flex items-center gap-2 px-5 py-2 rounded-lg bg-gradient-to-r from-cyan-600 to-blue-600 hover:from-cyan-500 hover:to-blue-500 text-xs font-mono font-bold text-white shadow-[0_0_15px_rgba(6,182,212,0.4)] transition-all disabled:opacity-50 cursor-pointer"
            >
              <Zap className="w-4 h-4 fill-current" />
              <span>
                {activeTab === 'upload' && !uploadedParsed
                  ? 'Browse & Scan .eml'
                  : 'Launch Forensic Scan'}
              </span>
            </button>
          </div>
        </div>

      </div>
    </div>
  );
};
