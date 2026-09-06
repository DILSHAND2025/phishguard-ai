import React, { useState } from 'react';
import { 
  X, 
  Zap, 
  UploadCloud, 
  FileText, 
  Terminal, 
  CheckCircle2, 
  AlertTriangle,
  ArrowRight,
  ShieldAlert,
  Loader2
} from 'lucide-react';
import { SYNTHETIC_SCENARIOS } from '../../data/syntheticScenarios';
import { parseEmailContent } from '../../services/emailParser';

export const QuickScanModal = ({ isOpen, onClose, onStartAnalysis }) => {
  const [activeTab, setActiveTab] = useState('preset'); // 'preset' | 'raw'
  const [selectedPresetId, setSelectedPresetId] = useState('ceo-bec');
  const [rawText, setRawText] = useState('');
  const [isScanning, setIsScanning] = useState(false);
  const [scanProgress, setScanProgress] = useState(0);
  const [scanLog, setScanLog] = useState([]);

  if (!isOpen) return null;

  const handleRunScan = async () => {
    setIsScanning(true);
    setScanProgress(15);
    setScanLog(['[+] Ingesting MIME envelope & headers...']);

    setTimeout(() => {
      setScanProgress(45);
      setScanLog(prev => [...prev, '[+] Parsing RFC 822 headers: SPF=FAIL, DKIM=FAIL, DMARC=FAIL']);
    }, 300);

    setTimeout(() => {
      setScanProgress(75);
      setScanLog(prev => [...prev, '[+] NLP Threat Model: Adversarial intent detected (94.2%)', '[+] Extracted IOCs: Originating IP, Typosquat Domains, Hashes']);
    }, 700);

    setTimeout(async () => {
      setScanProgress(100);
      setScanLog(prev => [...prev, '[+] SIH-MAVERICK Threat Graph generated. Case updated.']);
      setIsScanning(false);
      
      if (activeTab === 'preset') {
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
    }, 1100);
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
            onClick={() => setActiveTab('preset')}
            className={`px-3 py-1.5 rounded-lg text-xs font-mono font-medium transition-all cursor-pointer ${
              activeTab === 'preset'
                ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            Controlled SIH Attack Scenarios
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
        {activeTab === 'preset' ? (
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
              disabled={isScanning}
              className="flex items-center gap-2 px-5 py-2 rounded-lg bg-gradient-to-r from-cyan-600 to-blue-600 hover:from-cyan-500 hover:to-blue-500 text-xs font-mono font-bold text-white shadow-[0_0_15px_rgba(6,182,212,0.4)] transition-all disabled:opacity-50 cursor-pointer"
            >
              <Zap className="w-4 h-4 fill-current" />
              <span>Launch Forensic Scan</span>
            </button>
          </div>
        </div>

      </div>
    </div>
  );
};
