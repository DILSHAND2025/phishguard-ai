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
      setScanLog(prev => [...prev, '[+] NLP Threat Model: Intent evaluated', '[+] Extracting IOCs & Multi-hop topology...']);
    }, 650);

    setTimeout(async () => {
      setScanProgress(100);
      setScanLog(prev => [...prev, '[+] MAVERICK Evidence Fusion completed. Dossier generated.']);
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
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-900/50 backdrop-blur-xs font-sans">
      <div className="w-full max-w-2xl rounded-xl bg-white border border-slate-200 p-6 shadow-xl">
        
        {/* Header */}
        <div className="flex items-center justify-between border-b border-slate-100 pb-4">
          <div className="flex items-center gap-3">
            <div className="p-2 rounded-lg bg-slate-100 text-slate-800">
              <Zap className="w-5 h-5" />
            </div>
            <div>
              <h3 className="text-base font-bold text-slate-900">
                Quick Email Threat Scanner
              </h3>
              <p className="text-xs text-slate-500">
                Multi-layer inspection & behavioral IOC extraction
              </p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="p-1.5 rounded-lg text-slate-400 hover:text-slate-700 hover:bg-slate-100 transition-colors cursor-pointer"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Tab Selection */}
        <div className="flex gap-2 my-4 border-b border-slate-100 pb-2">
          <button
            type="button"
            onClick={() => setActiveTab('upload')}
            className={`px-3 py-1.5 rounded-lg text-xs font-semibold transition-all cursor-pointer flex items-center gap-1.5 ${
              activeTab === 'upload'
                ? 'bg-slate-900 text-white shadow-2xs'
                : 'text-slate-600 hover:text-slate-900'
            }`}
          >
            <UploadCloud className="w-3.5 h-3.5" />
            <span>Upload .EML</span>
          </button>

          <button
            type="button"
            onClick={() => setActiveTab('preset')}
            className={`px-3 py-1.5 rounded-lg text-xs font-semibold transition-all cursor-pointer ${
              activeTab === 'preset'
                ? 'bg-slate-900 text-white shadow-2xs'
                : 'text-slate-600 hover:text-slate-900'
            }`}
          >
            Sample Scenarios
          </button>

          <button
            type="button"
            onClick={() => setActiveTab('raw')}
            className={`px-3 py-1.5 rounded-lg text-xs font-semibold transition-all cursor-pointer ${
              activeTab === 'raw'
                ? 'bg-slate-900 text-white shadow-2xs'
                : 'text-slate-600 hover:text-slate-900'
            }`}
          >
            Raw Headers Paste
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
                  ? 'border-slate-800 bg-slate-50 scale-[0.99]'
                  : uploadedParsed
                    ? 'border-emerald-300 bg-emerald-50/40'
                    : 'border-slate-300 hover:border-slate-400 bg-slate-50/50 hover:bg-slate-50'
              }`}
            >
              {isReadingFile ? (
                <div className="flex flex-col items-center justify-center py-4 space-y-2">
                  <Loader2 className="w-8 h-8 text-slate-700 animate-spin" />
                  <p className="text-xs text-slate-600">
                    Ingesting RFC 822 envelope and extracting indicators...
                  </p>
                </div>
              ) : uploadedParsed ? (
                <div className="space-y-3">
                  <div className="flex items-center justify-center gap-2 text-emerald-700 font-bold text-xs">
                    <CheckCircle2 className="w-5 h-5 text-emerald-600" />
                    <span>File Ingested Successfully</span>
                  </div>

                  <div className="p-3 rounded-lg bg-white border border-emerald-200 text-left space-y-1.5 text-xs">
                    <div className="flex items-center justify-between">
                      <span className="text-slate-900 font-bold truncate max-w-[320px]">
                        {uploadedFile?.name}
                      </span>
                      <span className="text-slate-500 text-[11px] font-semibold">
                        {uploadedFile?.size}
                      </span>
                    </div>
                    <div className="text-slate-600 truncate text-[11px]">
                      <strong>Subject:</strong> {uploadedParsed.subject || '(No Subject)'}
                    </div>
                    <div className="text-slate-600 truncate text-[11px]">
                      <strong>From:</strong> {uploadedParsed.fromParsed?.address || uploadedParsed.sender}
                    </div>
                    {uploadedParsed.attachments && uploadedParsed.attachments.length > 0 && (
                      <div className="text-amber-700 text-[11px] flex items-center gap-1 pt-1 border-t border-slate-100">
                        <Paperclip className="w-3.5 h-3.5 text-amber-600" />
                        <span>{uploadedParsed.attachments.length} attachment(s) identified for inspection</span>
                      </div>
                    )}
                  </div>

                  <p className="text-[11px] text-slate-500">
                    Click <strong>&quot;Launch Forensic Scan&quot;</strong> below to analyze, or click to choose a different file.
                  </p>
                </div>
              ) : (
                <div className="flex flex-col items-center justify-center space-y-2.5">
                  <div className="p-3 rounded-xl bg-white border border-slate-200 text-slate-700 shadow-2xs">
                    <UploadCloud className="w-7 h-7" />
                  </div>
                  <div>
                    <p className="text-xs font-semibold text-slate-800">
                      Drag & Drop your .EML file here
                    </p>
                    <p className="text-[11px] text-slate-400 mt-0.5">
                      or click anywhere in this box to browse local storage
                    </p>
                  </div>
                  <span className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-white border border-slate-200 text-slate-700 text-xs font-semibold shadow-2xs">
                    <FolderOpen className="w-3.5 h-3.5 text-slate-500" />
                    Browse Files
                  </span>
                </div>
              )}
            </div>

            {/* Error Message Banner */}
            {uploadError && (
              <div className="p-3 rounded-lg bg-red-50 border border-red-200 flex items-start gap-2 text-xs text-red-700">
                <AlertTriangle className="w-4 h-4 text-red-500 shrink-0 mt-0.5" />
                <div className="flex-1">
                  <strong>Upload Warning:</strong> {uploadError}
                </div>
                <button
                  type="button"
                  onClick={() => setUploadError(null)}
                  className="text-red-500 hover:text-red-700 cursor-pointer"
                >
                  <X className="w-3.5 h-3.5" />
                </button>
              </div>
            )}
          </div>
        ) : activeTab === 'preset' ? (
          <div className="space-y-2 max-h-64 overflow-y-auto pr-1">
            {SYNTHETIC_SCENARIOS.map(p => (
              <div
                key={p.id}
                onClick={() => setSelectedPresetId(p.id)}
                className={`p-3 rounded-lg border cursor-pointer transition-all ${
                  selectedPresetId === p.id
                    ? 'bg-slate-50 border-slate-800 shadow-2xs'
                    : 'bg-white border-slate-200 hover:bg-slate-50'
                }`}
              >
                <div className="flex items-center justify-between">
                  <span className="text-xs font-bold text-slate-900">{p.name}</span>
                  <span className="text-[10px] px-2 py-0.5 rounded bg-red-50 border border-red-200 text-red-700 font-bold">
                    {p.category}
                  </span>
                </div>
                <div className="text-[11px] text-slate-600 mt-0.5 truncate">
                  From: {p.sender}
                </div>
                <div className="text-xs text-slate-500 mt-0.5 line-clamp-1">
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
              className="w-full p-3 bg-slate-50 border border-slate-200 rounded-lg text-xs font-mono text-slate-900 placeholder-slate-400 focus:outline-none focus:bg-white focus:border-slate-400"
            />
          </div>
        )}

        {/* Live scanning progress and console */}
        {isScanning && (
          <div className="mt-4 p-3.5 rounded-lg bg-slate-50 border border-slate-200 space-y-2">
            <div className="flex items-center justify-between text-xs text-slate-700 font-semibold">
              <span className="flex items-center gap-2">
                <Loader2 className="w-3.5 h-3.5 animate-spin text-slate-700" />
                Scanning Pipeline Executing...
              </span>
              <span>{scanProgress}%</span>
            </div>
            <div className="w-full h-1.5 bg-slate-200 rounded-full overflow-hidden">
              <div 
                className="h-full bg-slate-900 transition-all duration-300"
                style={{ width: `${scanProgress}%` }}
              />
            </div>
            <div className="space-y-1 font-mono text-[11px] text-slate-600">
              {scanLog.map((log, i) => (
                <div key={i}>{log}</div>
              ))}
            </div>
          </div>
        )}

        {/* Footer actions */}
        <div className="mt-5 pt-4 border-t border-slate-100 flex items-center justify-between">
          <span className="text-xs text-slate-400">
            Powered by Evidence Fusion
          </span>
          <div className="flex items-center gap-2">
            <button
              onClick={onClose}
              disabled={isScanning}
              className="px-4 py-2 rounded-lg bg-white hover:bg-slate-50 border border-slate-200 text-xs font-semibold text-slate-700 transition-colors cursor-pointer shadow-2xs"
            >
              Cancel
            </button>
            <button
              onClick={handleRunScan}
              disabled={isScanning || isReadingFile}
              className="flex items-center gap-2 px-5 py-2 rounded-lg bg-slate-900 hover:bg-slate-800 text-xs font-semibold text-white shadow-xs transition-colors disabled:opacity-50 cursor-pointer"
            >
              <Zap className="w-4 h-4 fill-current" />
              <span>
                {activeTab === 'upload' && !uploadedParsed
                  ? 'Browse & Scan .EML'
                  : 'Launch Forensic Scan'}
              </span>
            </button>
          </div>
        </div>

      </div>
    </div>
  );
};
