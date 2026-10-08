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
  Lock, 
  Cpu, 
  Server
} from 'lucide-react';
import { DEFAULT_FUSION_WEIGHTS } from '../services/evidenceFusion';

export const SettingsPage = ({ fusionWeights, onUpdateWeights }) => {
  const [weights, setWeights] = useState(fusionWeights || DEFAULT_FUSION_WEIGHTS);
  const [savedSuccess, setSavedSuccess] = useState(false);
  
  // API Keys & Backend Gateway (stored locally for demo/client mode)
  const [vtApiKey, setVtApiKey] = useState(() => localStorage.getItem('maverick_vt_key') || '');
  const [abuseApiKey, setAbuseApiKey] = useState(() => localStorage.getItem('maverick_abuse_key') || '');
  const [backendUrl, setBackendUrl] = useState(() => localStorage.getItem('maverick_backend_url') || '');
  const [connectionStatus, setConnectionStatus] = useState(null); // null | 'testing' | 'success' | 'error'
  const [connectionMsg, setConnectionMsg] = useState('');

  const totalPoints = Object.values(weights).reduce((acc, v) => acc + Number(v), 0);

  const handleWeightChange = (key, value) => {
    const num = Math.max(0, Math.min(50, parseInt(value, 10) || 0));
    setWeights(prev => ({
      ...prev,
      [key]: num
    }));
  };

  const handleTestConnection = async () => {
    const target = backendUrl.trim().replace(/\/$/, '');
    setConnectionStatus('testing');
    setConnectionMsg('Pinging gateway...');
    const candidates = [
      target ? `${target}/api/health` : '/api/health',
      target ? `${target}/health` : '/health',
      target ? `${target}/` : '/'
    ];

    for (const endpoint of candidates) {
      try {
        const res = await fetch(endpoint, { signal: AbortSignal.timeout ? AbortSignal.timeout(6000) : undefined });
        if (res.ok) {
          const data = await res.json();
          setConnectionStatus('success');
          setConnectionMsg(`Online: ${data.service || 'Backend Gateway'}`);
          return;
        }
      } catch {
        // Try next candidate
      }
    }

    setConnectionStatus('error');
    setConnectionMsg('Unable to reach backend gateway');
  };

  const handleSaveAll = () => {
    if (onUpdateWeights) {
      onUpdateWeights(weights);
    }
    localStorage.setItem('maverick_vt_key', vtApiKey);
    localStorage.setItem('maverick_abuse_key', abuseApiKey);
    localStorage.setItem('maverick_backend_url', backendUrl.trim());
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
    <div className="space-y-6 pb-12 font-sans text-slate-900">
      
      {/* Top Banner Header */}
      <div className="rounded-xl bg-white border border-slate-200 p-6 shadow-xs">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
          <div>
            <div className="flex items-center gap-2 text-slate-500 text-xs font-semibold uppercase tracking-wider mb-1.5">
              <Settings className="w-3.5 h-3.5" />
              <span>Platform Configuration & Scoring Calibration</span>
            </div>
            <h1 className="text-xl sm:text-2xl font-bold text-slate-900 tracking-tight">
              Settings & Intelligence Parameters
            </h1>
            <p className="text-xs text-slate-500 mt-1 max-w-3xl">
              Calibrate multi-factor evidence fusion weights, configure threat intelligence API endpoints, and view forensic environment posture.
            </p>
          </div>

          <div className="flex items-center gap-2 text-xs">
            <button
              onClick={handleSaveAll}
              className="flex items-center gap-2 px-4 py-2 rounded-lg bg-slate-900 hover:bg-slate-800 text-white font-semibold shadow-xs transition-colors cursor-pointer"
            >
              {savedSuccess ? <CheckCircle2 className="w-4 h-4 text-emerald-400" /> : <Save className="w-4 h-4" />}
              <span>{savedSuccess ? 'Configuration Saved!' : 'Save Parameters'}</span>
            </button>
          </div>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        
        {/* Left 2 Cols: Evidence Fusion Weights Calibration */}
        <div className="lg:col-span-2 space-y-6">
          <div className="rounded-xl bg-white border border-slate-200 p-6 shadow-xs space-y-5">
            
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-slate-100 pb-3">
              <div className="flex items-center gap-2">
                <Sliders className="w-5 h-5 text-slate-700" />
                <h2 className="text-sm font-bold uppercase tracking-wider text-slate-900">
                  Evidence Fusion Weight Distribution
                </h2>
              </div>
              <div className="flex items-center gap-2">
                <span className={`text-xs font-bold px-2 py-0.5 rounded border ${totalPoints === 100 ? 'bg-emerald-50 text-emerald-700 border-emerald-200' : 'bg-amber-50 text-amber-800 border-amber-200'}`}>
                  Sum: {totalPoints} / 100 Pts
                </span>
                <button
                  type="button"
                  onClick={handleResetDefaults}
                  className="flex items-center gap-1 text-[11px] text-slate-600 hover:text-slate-900 px-2 py-0.5 rounded bg-slate-100 border border-slate-200 transition-colors cursor-pointer font-medium"
                >
                  <RotateCcw className="w-3 h-3" />
                  <span>Reset Defaults</span>
                </button>
              </div>
            </div>

            <p className="text-xs text-slate-500">
              Configure maximum score contributions for each forensic inspection layer. The multi-factor engine synthesizes these weights to calculate the explainable 0–100 threat score.
            </p>

            {/* Slider Controls */}
            <div className="space-y-3.5 text-xs">
              
              {/* 1. AI/NLP */}
              <div className="p-3.5 rounded-lg bg-slate-50 border border-slate-200 space-y-2">
                <div className="flex justify-between items-center text-slate-800">
                  <span className="font-semibold flex items-center gap-1.5">
                    <Cpu className="w-3.5 h-3.5 text-slate-600" /> 1. AI / NLP Threat Analysis
                  </span>
                  <span className="font-bold text-slate-900 bg-white px-2 py-0.5 rounded border border-slate-200 shadow-2xs">
                    {weights.aiNlp} Points
                  </span>
                </div>
                <input 
                  type="range" 
                  min="0" 
                  max="40" 
                  value={weights.aiNlp} 
                  onChange={(e) => handleWeightChange('aiNlp', e.target.value)}
                  className="w-full accent-slate-900 cursor-pointer"
                />
                <span className="text-[11px] text-slate-500 block">
                  Urgency tokens, statutory coercion, credential theft terminology, and TF-IDF embedding.
                </span>
              </div>

              {/* 2. Header Forensics */}
              <div className="p-3.5 rounded-lg bg-slate-50 border border-slate-200 space-y-2">
                <div className="flex justify-between items-center text-slate-800">
                  <span className="font-semibold flex items-center gap-1.5">
                    <ShieldAlert className="w-3.5 h-3.5 text-slate-600" /> 2. RFC 822 & Header Forensics (SPF / DKIM / DMARC)
                  </span>
                  <span className="font-bold text-slate-900 bg-white px-2 py-0.5 rounded border border-slate-200 shadow-2xs">
                    {weights.headerForensics} Points
                  </span>
                </div>
                <input 
                  type="range" 
                  min="0" 
                  max="40" 
                  value={weights.headerForensics} 
                  onChange={(e) => handleWeightChange('headerForensics', e.target.value)}
                  className="w-full accent-slate-900 cursor-pointer"
                />
                <span className="text-[11px] text-slate-500 block">
                  Cryptographic signature verification, alignment policies, and Reply-To / Return-Path mismatches.
                </span>
              </div>

              {/* 3. URL Intelligence */}
              <div className="p-3.5 rounded-lg bg-slate-50 border border-slate-200 space-y-2">
                <div className="flex justify-between items-center text-slate-800">
                  <span className="font-semibold">
                    3. URL & Domain Intelligence
                  </span>
                  <span className="font-bold text-slate-900 bg-white px-2 py-0.5 rounded border border-slate-200 shadow-2xs">
                    {weights.urlIntel} Points
                  </span>
                </div>
                <input 
                  type="range" 
                  min="0" 
                  max="35" 
                  value={weights.urlIntel} 
                  onChange={(e) => handleWeightChange('urlIntel', e.target.value)}
                  className="w-full accent-slate-900 cursor-pointer"
                />
                <span className="text-[11px] text-slate-500 block">
                  Typosquatting/homoglyph domain indicators, external phishing feeds, and URLhaus signatures.
                </span>
              </div>

              {/* 4. IP Reputation */}
              <div className="p-3.5 rounded-lg bg-slate-50 border border-slate-200 space-y-2">
                <div className="flex justify-between items-center text-slate-800">
                  <span className="font-semibold">
                    4. IP Reputation & Hop Analysis
                  </span>
                  <span className="font-bold text-slate-900 bg-white px-2 py-0.5 rounded border border-slate-200 shadow-2xs">
                    {weights.ipReputation} Points
                  </span>
                </div>
                <input 
                  type="range" 
                  min="0" 
                  max="30" 
                  value={weights.ipReputation} 
                  onChange={(e) => handleWeightChange('ipReputation', e.target.value)}
                  className="w-full accent-slate-900 cursor-pointer"
                />
                <span className="text-[11px] text-slate-500 block">
                  AbuseIPDB reports, anomalous transit hops, and unverified relay subnets.
                </span>
              </div>

              {/* 5. Geo / ASN Context */}
              <div className="p-3.5 rounded-lg bg-slate-50 border border-slate-200 space-y-2">
                <div className="flex justify-between items-center text-slate-800">
                  <span className="font-semibold">
                    5. GeoLocation & ASN Topology
                  </span>
                  <span className="font-bold text-slate-900 bg-white px-2 py-0.5 rounded border border-slate-200 shadow-2xs">
                    {weights.geoAsnContext} Points
                  </span>
                </div>
                <input 
                  type="range" 
                  min="0" 
                  max="20" 
                  value={weights.geoAsnContext} 
                  onChange={(e) => handleWeightChange('geoAsnContext', e.target.value)}
                  className="w-full accent-slate-900 cursor-pointer"
                />
                <span className="text-[11px] text-slate-500 block">
                  Tor exit node detection, bulletproof hosting subnets, and Autonomous System categorization.
                </span>
              </div>

              {/* 6. Attachment Analysis */}
              <div className="p-3.5 rounded-lg bg-slate-50 border border-slate-200 space-y-2">
                <div className="flex justify-between items-center text-slate-800">
                  <span className="font-semibold">
                    6. Attachment Payload & Hash Verification
                  </span>
                  <span className="font-bold text-slate-900 bg-white px-2 py-0.5 rounded border border-slate-200 shadow-2xs">
                    {weights.attachmentPayload} Points
                  </span>
                </div>
                <input 
                  type="range" 
                  min="0" 
                  max="20" 
                  value={weights.attachmentPayload} 
                  onChange={(e) => handleWeightChange('attachmentPayload', e.target.value)}
                  className="w-full accent-slate-900 cursor-pointer"
                />
                <span className="text-[11px] text-slate-500 block">
                  Double extension detection (.pdf.exe), PE32 executable signatures, and SHA256 checksums.
                </span>
              </div>

            </div>

          </div>
        </div>

        {/* Right 1 Col: API Integrations & Gateway Status */}
        <div className="space-y-6">
          
          {/* Cloud Backend Gateway (Render / Custom) */}
          <div className="rounded-xl bg-white border border-slate-200 p-5 shadow-xs space-y-4 text-xs">
            <div className="flex items-center justify-between border-b border-slate-100 pb-2">
              <div className="flex items-center gap-2">
                <Server className="w-4 h-4 text-slate-700" />
                <h3 className="font-bold text-slate-900 uppercase tracking-wider">
                  Backend Gateway
                </h3>
              </div>
              <span className="px-2 py-0.5 rounded text-[10px] bg-slate-100 border border-slate-200 text-slate-700 font-semibold">
                GATEWAY
              </span>
            </div>

            <p className="text-xs text-slate-500 leading-relaxed">
              Connect your frontend to your live backend gateway for FastAPI ML inference, VirusTotal, AbuseIPDB, and PDF export.
            </p>

            <div className="space-y-2">
              <label className="text-xs text-slate-700 font-medium block">Backend Gateway URL</label>
              <input
                type="text"
                value={backendUrl}
                onChange={(e) => setBackendUrl(e.target.value)}
                placeholder="https://maverick-backend.onrender.com"
                className="w-full p-2.5 bg-slate-50 border border-slate-200 rounded-lg text-slate-900 focus:outline-none focus:bg-white focus:border-slate-400 placeholder-slate-400 text-xs"
              />
              <span className="text-[11px] text-slate-400 block">
                Leave empty to use default relative endpoint or local dev proxy.
              </span>
            </div>

            <div className="flex items-center justify-between pt-1">
              <button
                type="button"
                onClick={handleTestConnection}
                disabled={connectionStatus === 'testing'}
                className="px-3 py-1.5 rounded-lg bg-white hover:bg-slate-50 border border-slate-200 text-slate-700 text-xs font-semibold transition-colors cursor-pointer shadow-2xs"
              >
                <span>{connectionStatus === 'testing' ? 'Testing...' : 'Ping Gateway'}</span>
              </button>

              {connectionStatus === 'success' && (
                <span className="text-xs text-emerald-700 font-semibold flex items-center gap-1">
                  <CheckCircle2 className="w-3.5 h-3.5 text-emerald-600" />
                  <span>{connectionMsg}</span>
                </span>
              )}
              {connectionStatus === 'error' && (
                <span className="text-xs text-red-600 truncate max-w-[180px]">
                  {connectionMsg}
                </span>
              )}
            </div>
          </div>

          {/* Threat Feeds Integration Card */}
          <div className="rounded-xl bg-white border border-slate-200 p-5 shadow-xs space-y-4 text-xs">
            <div className="flex items-center gap-2 border-b border-slate-100 pb-2">
              <Key className="w-4 h-4 text-slate-700" />
              <h3 className="font-bold text-slate-900 uppercase tracking-wider">
                External Threat Feeds
              </h3>
            </div>

            <p className="text-xs text-slate-500 leading-relaxed">
              Provide optional API keys for real-time external intelligence querying. Never committed to source control.
            </p>

            <div className="space-y-3">
              <div>
                <label className="text-xs text-slate-700 font-medium block mb-1">VirusTotal v3 API Key</label>
                <div className="relative">
                  <input
                    type="password"
                    value={vtApiKey}
                    onChange={(e) => setVtApiKey(e.target.value)}
                    placeholder="Enter VirusTotal API key..."
                    className="w-full p-2.5 bg-slate-50 border border-slate-200 rounded-lg text-slate-900 focus:outline-none focus:bg-white focus:border-slate-400"
                  />
                  <Lock className="w-3.5 h-3.5 text-slate-400 absolute right-3 top-3" />
                </div>
              </div>

              <div>
                <label className="text-xs text-slate-700 font-medium block mb-1">AbuseIPDB v2 API Key</label>
                <div className="relative">
                  <input
                    type="password"
                    value={abuseApiKey}
                    onChange={(e) => setAbuseApiKey(e.target.value)}
                    placeholder="Enter AbuseIPDB API key..."
                    className="w-full p-2.5 bg-slate-50 border border-slate-200 rounded-lg text-slate-900 focus:outline-none focus:bg-white focus:border-slate-400"
                  />
                  <Lock className="w-3.5 h-3.5 text-slate-400 absolute right-3 top-3" />
                </div>
              </div>
            </div>

            <div className="p-3 rounded-lg bg-slate-50 border border-slate-200 text-xs text-slate-600 space-y-1">
              <div className="flex items-center gap-1.5 text-slate-800 font-semibold">
                <Info className="w-3.5 h-3.5 text-slate-500" />
                <span>Dual-Mode Architecture:</span>
              </div>
              <p>
                When running the Express gateway, keys are read securely from server <code className="text-slate-800">.env</code> to avoid CORS and browser rate limits.
              </p>
            </div>
          </div>

          {/* Legal & Forensic Standard Card */}
          <div className="rounded-xl bg-white border border-slate-200 p-5 shadow-xs space-y-3 text-xs">
            <div className="flex items-center gap-2 border-b border-slate-100 pb-2">
              <Server className="w-4 h-4 text-slate-700" />
              <h3 className="font-bold text-slate-900 uppercase tracking-wider">
                Forensic Standards
              </h3>
            </div>
            
            <div className="space-y-2 text-xs text-slate-700">
              <div className="flex items-center justify-between">
                <span className="text-slate-500">Untrusted Attachment Execution:</span>
                <span className="text-emerald-700 font-bold">STRICTLY DISABLED</span>
              </div>
              <div className="flex items-center justify-between">
                <span className="text-slate-500">Fabricated Threat Intel:</span>
                <span className="text-red-700 font-bold">PROHIBITED</span>
              </div>
              <div className="flex items-center justify-between">
                <span className="text-slate-500">GeoLocation Attribution:</span>
                <span className="text-slate-900 font-semibold">Infrastructure Only</span>
              </div>
            </div>
          </div>

        </div>

      </div>

    </div>
  );
};
