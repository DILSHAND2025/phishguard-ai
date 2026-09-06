import React, { useState } from 'react';
import { 
  Settings, 
  Key, 
  Sliders, 
  ShieldAlert, 
  CheckCircle2, 
  Save, 
  RotateCcw, 
  Info, 
  ExternalLink,
  Lock,
  Cpu,
  Server,
  Database
} from 'lucide-react';
import { DEFAULT_FUSION_WEIGHTS } from '../services/evidenceFusion';

export const SettingsPage = ({ fusionWeights, onUpdateWeights }) => {
  const [weights, setWeights] = useState(fusionWeights || DEFAULT_FUSION_WEIGHTS);
  const [savedSuccess, setSavedSuccess] = useState(false);
  
  // API Keys (stored locally for demo/client mode)
  const [vtApiKey, setVtApiKey] = useState(() => localStorage.getItem('maverick_vt_key') || '');
  const [abuseApiKey, setAbuseApiKey] = useState(() => localStorage.getItem('maverick_abuse_key') || '');
  const [activeGateway, setActiveGateway] = useState(false);

  const totalPoints = Object.values(weights).reduce((acc, v) => acc + Number(v), 0);

  const handleWeightChange = (key, value) => {
    const num = Math.max(0, Math.min(50, parseInt(value, 10) || 0));
    setWeights(prev => ({
      ...prev,
      [key]: num
    }));
  };

  const handleSaveAll = () => {
    if (onUpdateWeights) {
      onUpdateWeights(weights);
    }
    localStorage.setItem('maverick_vt_key', vtApiKey);
    localStorage.setItem('maverick_abuse_key', abuseApiKey);
    localStorage.setItem('maverick_weights', JSON.stringify(weights));
    setSavedSuccess(true);
    setTimeout(() => setSavedSuccess(false), 2500);
  };

  const handleResetDefaults = () => {
    setWeights(DEFAULT_FUSION_WEIGHTS);
    if (onUpdateWeights) {
      onUpdateWeights(DEFAULT_FUSION_WEIGHTS);
    }
  };

  return (
    <div className="space-y-6 pb-12 font-sans">
      
      {/* Top Banner Header */}
      <div className="relative overflow-hidden rounded-2xl bg-gradient-to-r from-slate-900 via-[#0d1629] to-[#070b13] border border-slate-700/80 p-6 shadow-xl">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
          <div>
            <div className="flex items-center gap-2 text-cyan-400 text-xs font-mono mb-1.5">
              <Settings className="w-3.5 h-3.5" />
              <span>PLATFORM CONFIGURATION & SCORING ENGINE CALIBRATION</span>
            </div>
            <h1 className="text-xl sm:text-2xl font-extrabold text-white font-mono flex items-center gap-2.5">
              <span>MAVERICK Settings & Intelligence Parameters</span>
            </h1>
            <p className="text-xs text-slate-300 mt-1 max-w-3xl">
              Calibrate multi-factor evidence fusion weights, configure threat intelligence API endpoints, and view forensic environment posture.
            </p>
          </div>

          <div className="flex items-center gap-2 font-mono text-xs">
            <button
              onClick={handleSaveAll}
              className="flex items-center gap-2 px-4 py-2 rounded-xl bg-gradient-to-r from-cyan-600 to-blue-600 hover:from-cyan-500 hover:to-blue-500 text-white font-bold shadow-[0_0_15px_rgba(6,182,212,0.4)] transition-all cursor-pointer"
            >
              {savedSuccess ? <CheckCircle2 className="w-4 h-4 text-emerald-300" /> : <Save className="w-4 h-4" />}
              <span>{savedSuccess ? 'Configuration Saved!' : 'Save Parameters'}</span>
            </button>
          </div>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        
        {/* Left 2 Cols: Evidence Fusion Weights Calibration */}
        <div className="lg:col-span-2 space-y-6">
          <div className="rounded-xl bg-[#09101e] border border-slate-800 p-6 shadow-lg space-y-5">
            
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-slate-800 pb-3">
              <div className="flex items-center gap-2">
                <Sliders className="w-5 h-5 text-cyan-400" />
                <h2 className="text-sm font-bold uppercase tracking-wider font-mono text-white">
                  Multi-Factor Evidence Fusion Weight Distribution
                </h2>
              </div>
              <div className="flex items-center gap-2">
                <span className={`text-xs font-mono font-bold px-2 py-0.5 rounded ${totalPoints === 100 ? 'bg-emerald-950/80 text-emerald-300 border border-emerald-500/40' : 'bg-amber-950/80 text-amber-300 border border-amber-500/40'}`}>
                  Sum: {totalPoints} / 100 Pts
                </span>
                <button
                  type="button"
                  onClick={handleResetDefaults}
                  className="flex items-center gap-1 text-[11px] font-mono text-slate-400 hover:text-cyan-300 px-2 py-0.5 rounded bg-slate-900 border border-slate-800 transition-colors"
                >
                  <RotateCcw className="w-3 h-3" />
                  <span>Reset Defaults</span>
                </button>
              </div>
            </div>

            <p className="text-xs text-slate-400">
              Configure maximum score contributions for each forensic inspection layer. The multi-factor engine synthesizes these weights to calculate the explainable 0–100 threat score.
            </p>

            {/* Slider Controls */}
            <div className="space-y-4 font-mono text-xs">
              
              {/* 1. AI/NLP */}
              <div className="p-3.5 rounded-lg bg-[#060a14] border border-slate-800/80 space-y-2">
                <div className="flex justify-between items-center text-slate-200">
                  <span className="font-bold flex items-center gap-1.5 text-cyan-300">
                    <Cpu className="w-3.5 h-3.5" /> 1. AI / NLP Threat Analysis
                  </span>
                  <span className="font-black text-white bg-slate-900 px-2 py-0.5 rounded border border-slate-800">
                    {weights.aiNlp} Points
                  </span>
                </div>
                <input 
                  type="range" 
                  min="0" 
                  max="40" 
                  value={weights.aiNlp} 
                  onChange={(e) => handleWeightChange('aiNlp', e.target.value)}
                  className="w-full accent-cyan-400 cursor-pointer"
                />
                <span className="text-[10px] text-slate-500 block">
                  Urgency tokens, statutory coercion, credential theft terminology, and TF-IDF embedding.
                </span>
              </div>

              {/* 2. Header Forensics */}
              <div className="p-3.5 rounded-lg bg-[#060a14] border border-slate-800/80 space-y-2">
                <div className="flex justify-between items-center text-slate-200">
                  <span className="font-bold flex items-center gap-1.5 text-red-300">
                    <ShieldAlert className="w-3.5 h-3.5" /> 2. RFC 822 & Header Forensics (SPF / DKIM / DMARC)
                  </span>
                  <span className="font-black text-white bg-slate-900 px-2 py-0.5 rounded border border-slate-800">
                    {weights.headerForensics} Points
                  </span>
                </div>
                <input 
                  type="range" 
                  min="0" 
                  max="40" 
                  value={weights.headerForensics} 
                  onChange={(e) => handleWeightChange('headerForensics', e.target.value)}
                  className="w-full accent-red-400 cursor-pointer"
                />
                <span className="text-[10px] text-slate-500 block">
                  Cryptographic signature verification, alignment policies, and Reply-To / Return-Path mismatches.
                </span>
              </div>

              {/* 3. URL Intelligence */}
              <div className="p-3.5 rounded-lg bg-[#060a14] border border-slate-800/80 space-y-2">
                <div className="flex justify-between items-center text-slate-200">
                  <span className="font-bold flex items-center gap-1.5 text-amber-300">
                    3. URL & Domain Intelligence
                  </span>
                  <span className="font-black text-white bg-slate-900 px-2 py-0.5 rounded border border-slate-800">
                    {weights.urlIntel} Points
                  </span>
                </div>
                <input 
                  type="range" 
                  min="0" 
                  max="35" 
                  value={weights.urlIntel} 
                  onChange={(e) => handleWeightChange('urlIntel', e.target.value)}
                  className="w-full accent-amber-400 cursor-pointer"
                />
                <span className="text-[10px] text-slate-500 block">
                  Typosquatting/homoglyph domain indicators, external phishing feeds, and URLhaus signatures.
                </span>
              </div>

              {/* 4. IP Reputation */}
              <div className="p-3.5 rounded-lg bg-[#060a14] border border-slate-800/80 space-y-2">
                <div className="flex justify-between items-center text-slate-200">
                  <span className="font-bold flex items-center gap-1.5 text-purple-300">
                    4. IP Reputation & Hop Analysis
                  </span>
                  <span className="font-black text-white bg-slate-900 px-2 py-0.5 rounded border border-slate-800">
                    {weights.ipReputation} Points
                  </span>
                </div>
                <input 
                  type="range" 
                  min="0" 
                  max="30" 
                  value={weights.ipReputation} 
                  onChange={(e) => handleWeightChange('ipReputation', e.target.value)}
                  className="w-full accent-purple-400 cursor-pointer"
                />
                <span className="text-[10px] text-slate-500 block">
                  AbuseIPDB reports, anomalous transit hops, and unverified relay subnets.
                </span>
              </div>

              {/* 5. Geo / ASN Context */}
              <div className="p-3.5 rounded-lg bg-[#060a14] border border-slate-800/80 space-y-2">
                <div className="flex justify-between items-center text-slate-200">
                  <span className="font-bold flex items-center gap-1.5 text-blue-300">
                    5. GeoLocation & ASN Topology
                  </span>
                  <span className="font-black text-white bg-slate-900 px-2 py-0.5 rounded border border-slate-800">
                    {weights.geoAsnContext} Points
                  </span>
                </div>
                <input 
                  type="range" 
                  min="0" 
                  max="20" 
                  value={weights.geoAsnContext} 
                  onChange={(e) => handleWeightChange('geoAsnContext', e.target.value)}
                  className="w-full accent-blue-400 cursor-pointer"
                />
                <span className="text-[10px] text-slate-500 block">
                  Tor exit node detection, bulletproof hosting subnets, and Autonomous System categorization.
                </span>
              </div>

              {/* 6. Attachment Analysis */}
              <div className="p-3.5 rounded-lg bg-[#060a14] border border-slate-800/80 space-y-2">
                <div className="flex justify-between items-center text-slate-200">
                  <span className="font-bold flex items-center gap-1.5 text-emerald-300">
                    6. Attachment Payload & Hash Verification
                  </span>
                  <span className="font-black text-white bg-slate-900 px-2 py-0.5 rounded border border-slate-800">
                    {weights.attachmentPayload} Points
                  </span>
                </div>
                <input 
                  type="range" 
                  min="0" 
                  max="20" 
                  value={weights.attachmentPayload} 
                  onChange={(e) => handleWeightChange('attachmentPayload', e.target.value)}
                  className="w-full accent-emerald-400 cursor-pointer"
                />
                <span className="text-[10px] text-slate-500 block">
                  Double extension detection (.pdf.exe), PE32 executable signatures, and SHA256 checksums.
                </span>
              </div>

            </div>

          </div>
        </div>

        {/* Right 1 Col: API Integrations & Gateway Status */}
        <div className="space-y-6">
          
          {/* Threat Feeds Integration Card */}
          <div className="rounded-xl bg-[#09101e] border border-slate-800 p-5 shadow-lg space-y-4 font-mono text-xs">
            <div className="flex items-center gap-2 border-b border-slate-800 pb-2">
              <Key className="w-4 h-4 text-cyan-400" />
              <h3 className="font-bold text-white uppercase tracking-wider">
                External Threat Feeds
              </h3>
            </div>

            <p className="text-[11px] text-slate-400 leading-relaxed font-sans">
              Provide optional API keys for real-time external intelligence querying. Never committed to source control.
            </p>

            <div className="space-y-3">
              <div>
                <label className="text-[11px] text-slate-300 block mb-1">VirusTotal v3 API Key</label>
                <div className="relative">
                  <input
                    type="password"
                    value={vtApiKey}
                    onChange={(e) => setVtApiKey(e.target.value)}
                    placeholder="Enter VirusTotal API key..."
                    className="w-full p-2.5 bg-[#060a14] border border-slate-800 rounded-lg text-slate-200 focus:outline-none focus:border-cyan-500"
                  />
                  <Lock className="w-3.5 h-3.5 text-slate-500 absolute right-3 top-3" />
                </div>
              </div>

              <div>
                <label className="text-[11px] text-slate-300 block mb-1">AbuseIPDB v2 API Key</label>
                <div className="relative">
                  <input
                    type="password"
                    value={abuseApiKey}
                    onChange={(e) => setAbuseApiKey(e.target.value)}
                    placeholder="Enter AbuseIPDB API key..."
                    className="w-full p-2.5 bg-[#060a14] border border-slate-800 rounded-lg text-slate-200 focus:outline-none focus:border-cyan-500"
                  />
                  <Lock className="w-3.5 h-3.5 text-slate-500 absolute right-3 top-3" />
                </div>
              </div>
            </div>

            <div className="p-3 rounded-lg bg-[#050810] border border-slate-800 text-[10px] text-slate-400 space-y-1">
              <div className="flex items-center gap-1.5 text-cyan-300 font-bold">
                <Info className="w-3.5 h-3.5" />
                <span>Dual-Mode Architecture:</span>
              </div>
              <p>
                When running the optional Express backend gateway, keys are read securely from <code className="text-slate-300">.env</code> to avoid CORS and browser rate limits.
              </p>
            </div>
          </div>

          {/* Legal & Forensic Standard Card */}
          <div className="rounded-xl bg-[#09101e] border border-slate-800 p-5 shadow-lg space-y-3 font-mono text-xs">
            <div className="flex items-center gap-2 border-b border-slate-800 pb-2">
              <Server className="w-4 h-4 text-emerald-400" />
              <h3 className="font-bold text-white uppercase tracking-wider">
                SIH Forensic Standard
              </h3>
            </div>
            
            <div className="space-y-2 text-[11px] text-slate-300">
              <div className="flex items-center justify-between">
                <span className="text-slate-400">Target Standard:</span>
                <span className="text-cyan-300 font-bold">SIH 2026 Ready</span>
              </div>
              <div className="flex items-center justify-between">
                <span className="text-slate-400">Untrusted Attachment Execution:</span>
                <span className="text-emerald-400 font-bold">STRICTLY DISABLED</span>
              </div>
              <div className="flex items-center justify-between">
                <span className="text-slate-400">Fabricated Threat Intel:</span>
                <span className="text-red-400 font-bold">PROHIBITED</span>
              </div>
              <div className="flex items-center justify-between">
                <span className="text-slate-400">GeoLocation Attribution:</span>
                <span className="text-amber-300 font-bold">Infrastructure Only</span>
              </div>
            </div>
          </div>

        </div>

      </div>

    </div>
  );
};
