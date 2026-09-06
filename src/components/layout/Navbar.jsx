import React, { useState, useRef, useEffect } from 'react';
import { 
  Shield, 
  Search, 
  Activity, 
  Bell, 
  Terminal, 
  Clock, 
  Radio, 
  Zap, 
  Volume2, 
  VolumeX, 
  RefreshCw,
  Cpu,
  Layers,
  ChevronDown,
  LogOut,
  Check,
  User
} from 'lucide-react';
import { SOC_SUMMARY } from '../../data/mockSocData';

export const Navbar = ({ onOpenScan, currentView, onViewChange, currentUser, onLogout }) => {
  const [soundEnabled, setSoundEnabled] = useState(true);
  const [searchQuery, setSearchQuery] = useState('');
  const [timeRange, setTimeRange] = useState('24h');
  const [isRefreshing, setIsRefreshing] = useState(false);
  const [isUserMenuOpen, setIsUserMenuOpen] = useState(false);
  const userMenuRef = useRef(null);

  // Close user profile dropdown on click outside
  useEffect(() => {
    const handleClickOutside = (event) => {
      if (userMenuRef.current && !userMenuRef.current.contains(event.target)) {
        setIsUserMenuOpen(false);
      }
    };
    document.addEventListener('mousedown', handleClickOutside);
    return () => document.removeEventListener('mousedown', handleClickOutside);
  }, []);

  const handleRefresh = () => {
    setIsRefreshing(true);
    setTimeout(() => setIsRefreshing(false), 800);
  };

  return (
    <header className="sticky top-0 z-40 w-full border-b border-cyan-950/60 bg-[#070b13]/95 backdrop-blur-md">
      <div className="flex h-16 items-center justify-between px-4 sm:px-6">
        
        {/* Left: Brand & Threat Posture */}
        <div className="flex items-center gap-4">
          <div 
            onClick={() => onViewChange('dashboard')} 
            className="flex items-center gap-3 cursor-pointer group"
          >
            <div className="relative flex items-center justify-center w-10 h-10 rounded-lg bg-gradient-to-br from-cyan-950 via-[#0a1526] to-[#040810] border border-cyan-500/40 group-hover:border-cyan-400 group-hover:shadow-[0_0_15px_rgba(6,182,212,0.4)] transition-all">
              <Shield className="w-5 h-5 text-cyan-400 group-hover:scale-110 transition-transform" />
              <span className="absolute -top-1 -right-1 w-2.5 h-2.5 bg-cyan-400 rounded-full animate-ping opacity-75"></span>
              <span className="absolute -top-1 -right-1 w-2.5 h-2.5 bg-cyan-400 rounded-full"></span>
            </div>
            
            <div>
              <div className="flex items-center gap-2">
                <span className="text-lg font-extrabold tracking-wider bg-gradient-to-r from-cyan-400 via-sky-200 to-white bg-clip-text text-transparent">
                  MAVERICK
                </span>
                <span className="text-[10px] uppercase font-mono px-1.5 py-0.5 rounded bg-cyan-950/80 border border-cyan-700/50 text-cyan-300 font-semibold">
                  SIH 2026
                </span>
              </div>
              <p className="text-[11px] text-slate-400 font-mono tracking-tight hidden sm:block">
                AI Email Threat & Forensic Intelligence
              </p>
            </div>
          </div>

          <div className="hidden lg:block h-6 w-px bg-slate-800" />

          {/* DEFCON Threat Badge */}
          <div className="hidden md:flex items-center gap-2 px-3 py-1 rounded-md bg-red-950/40 border border-red-500/40 text-red-300 text-xs font-mono">
            <Radio className="w-3.5 h-3.5 text-red-400 animate-pulse" />
            <span className="font-bold tracking-wider">{SOC_SUMMARY.activeDefcon}:</span>
            <span className="text-[11px] text-red-200">{SOC_SUMMARY.defconStatus}</span>
          </div>
        </div>

        {/* Center: Global Threat Search */}
        <div className="flex-1 max-w-md mx-4 hidden md:block">
          <div className="relative">
            <Search className="absolute left-3 top-2.5 h-4 w-4 text-slate-500" />
            <input
              type="text"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              placeholder="Search IOCs, SHA256, Sender, ASN, or CVE..."
              className="w-full pl-9 pr-14 py-1.5 bg-[#0d1424] border border-slate-800 rounded-lg text-xs font-mono text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-500/60 focus:ring-1 focus:ring-cyan-500/30 transition-all"
            />
            <kbd className="absolute right-2.5 top-2 px-1.5 py-0.5 text-[10px] font-mono text-slate-500 bg-slate-900 border border-slate-800 rounded">
              Ctrl+K
            </kbd>
          </div>
        </div>

        {/* Right Controls: Engine Status, Time Filter, Scan CTA, Profile */}
        <div className="flex items-center gap-3">
          
          {/* AI Engine Pulse */}
          <div className="hidden xl:flex items-center gap-2 px-2.5 py-1 rounded bg-[#0b1322] border border-slate-800 text-[11px] font-mono text-slate-300">
            <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse"></span>
            <Cpu className="w-3.5 h-3.5 text-cyan-400" />
            <span>AI Neural-v4.2</span>
            <span className="text-emerald-400 font-bold">ACTIVE</span>
          </div>

          {/* Time range selector */}
          <div className="flex bg-[#0d1527] border border-slate-800 rounded-lg p-0.5 text-xs font-mono">
            {['24h', '7d', '30d'].map((range) => (
              <button
                key={range}
                onClick={() => setTimeRange(range)}
                className={`px-2 py-1 rounded text-[11px] uppercase transition-all ${
                  timeRange === range
                    ? 'bg-cyan-500/20 text-cyan-300 font-semibold border border-cyan-500/40 shadow-sm'
                    : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                {range}
              </button>
            ))}
          </div>

          {/* Sound alert toggle */}
          <button
            onClick={() => setSoundEnabled(!soundEnabled)}
            title={soundEnabled ? "Mute SOC Audio Alerts" : "Enable SOC Audio Alerts"}
            className="p-2 rounded-lg bg-[#0d1527] border border-slate-800 text-slate-400 hover:text-cyan-300 hover:border-cyan-500/40 transition-all"
          >
            {soundEnabled ? <Volume2 className="w-4 h-4 text-cyan-400" /> : <VolumeX className="w-4 h-4 text-slate-500" />}
          </button>

          {/* Refresh stream */}
          <button
            onClick={handleRefresh}
            title="Refresh Ingestion Feed"
            className="p-2 rounded-lg bg-[#0d1527] border border-slate-800 text-slate-400 hover:text-cyan-300 hover:border-cyan-500/40 transition-all"
          >
            <RefreshCw className={`w-4 h-4 ${isRefreshing ? 'animate-spin text-cyan-400' : ''}`} />
          </button>

          {/* Quick Scan Action Button */}
          <button
            onClick={onOpenScan}
            className="flex items-center gap-2 px-3.5 py-1.5 rounded-lg bg-gradient-to-r from-cyan-600 to-blue-600 hover:from-cyan-500 hover:to-blue-500 text-white text-xs font-semibold shadow-[0_0_15px_rgba(6,182,212,0.35)] hover:shadow-[0_0_20px_rgba(6,182,212,0.55)] transition-all active:scale-95"
          >
            <Zap className="w-3.5 h-3.5 fill-current" />
            <span className="hidden sm:inline">Scan Suspicious Email</span>
            <span className="sm:hidden">Scan</span>
          </button>

          {/* SOC Analyst / Google Authenticated User Profile Menu */}
          <div className="relative pl-2 border-l border-slate-800" ref={userMenuRef}>
            <button
              onClick={() => setIsUserMenuOpen(!isUserMenuOpen)}
              className="flex items-center gap-2.5 p-1 rounded-lg hover:bg-[#0c1424] border border-transparent hover:border-slate-800 transition-all cursor-pointer group"
              title="User Account & Session Controls"
            >
              <div className="relative">
                {currentUser?.picture ? (
                  <img
                    src={currentUser.picture}
                    alt={currentUser.name || 'Analyst'}
                    className="w-8 h-8 rounded-full border border-cyan-500/60 object-cover group-hover:border-cyan-400 group-hover:shadow-[0_0_10px_rgba(6,182,212,0.4)] transition-all"
                  />
                ) : (
                  <div className="w-8 h-8 rounded-full bg-slate-800 border border-cyan-500/40 flex items-center justify-center text-xs font-bold font-mono text-cyan-300 group-hover:border-cyan-400">
                    {currentUser?.name
                      ? currentUser.name.split(' ').map(n => n[0]).slice(0, 2).join('').toUpperCase()
                      : 'MK'}
                  </div>
                )}
                <span className="absolute bottom-0 right-0 w-2 h-2 rounded-full bg-emerald-400 border border-[#070b13] animate-pulse"></span>
              </div>
              
              <div className="hidden 2xl:block text-left">
                <div className="text-xs font-medium text-slate-200 group-hover:text-cyan-200 transition-colors truncate max-w-[140px]">
                  {currentUser?.name || 'Analyst SIH-01'}
                </div>
                <div className="text-[10px] text-cyan-400/80 font-mono truncate max-w-[140px]">
                  {currentUser?.email || 'SOC Lead Tier-3'}
                </div>
              </div>
              <ChevronDown className={`w-3.5 h-3.5 text-slate-500 group-hover:text-cyan-400 transition-transform ${isUserMenuOpen ? 'rotate-180 text-cyan-400' : ''}`} />
            </button>

            {/* Profile & Sign Out Dropdown Popover */}
            {isUserMenuOpen && (
              <div className="absolute right-0 mt-2 w-72 rounded-xl bg-gradient-to-b from-[#0e172a] to-[#070b13] border border-cyan-500/40 shadow-[0_10px_30px_rgba(0,0,0,0.8),0_0_20px_rgba(6,182,212,0.2)] p-4 z-50 animate-in fade-in slide-in-from-top-2 duration-150">
                
                {/* User Info Header */}
                <div className="flex items-start gap-3 pb-3 border-b border-slate-800">
                  {currentUser?.picture ? (
                    <img
                      src={currentUser.picture}
                      alt={currentUser.name}
                      className="w-10 h-10 rounded-full border border-cyan-400 object-cover shrink-0"
                    />
                  ) : (
                    <div className="w-10 h-10 rounded-full bg-cyan-950/80 border border-cyan-400 flex items-center justify-center text-sm font-mono font-bold text-cyan-300 shrink-0">
                      {currentUser?.name
                        ? currentUser.name.split(' ').map(n => n[0]).slice(0, 2).join('').toUpperCase()
                        : 'MK'}
                    </div>
                  )}
                  <div className="min-w-0 flex-1">
                    <div className="text-xs font-bold text-white truncate flex items-center gap-1.5">
                      <span className="truncate">{currentUser?.name || 'Authorized Investigator'}</span>
                    </div>
                    <div className="text-[11px] text-slate-400 font-mono truncate mt-0.5">
                      {currentUser?.email || 'analyst@gov-organization.in'}
                    </div>
                    <div className="flex items-center gap-1.5 mt-1.5">
                      <span className="inline-flex items-center gap-1 px-1.5 py-0.5 rounded bg-emerald-950/60 border border-emerald-500/40 text-[9px] font-mono text-emerald-300 font-semibold">
                        <Check className="w-2.5 h-2.5" /> Google OAuth
                      </span>
                      <span className="text-[9px] font-mono text-slate-500">Tier-3 SOC</span>
                    </div>
                  </div>
                </div>

                {/* Session Telemetry */}
                <div className="py-2.5 space-y-1.5 text-[10px] font-mono text-slate-400 border-b border-slate-800">
                  <div className="flex items-center justify-between">
                    <span className="flex items-center gap-1.5 text-slate-500">
                      <Shield className="w-3 h-3 text-cyan-400" /> Clearance Level:
                    </span>
                    <span className="text-cyan-300 font-semibold">CONFIDENTIAL / SIH</span>
                  </div>
                  <div className="flex items-center justify-between">
                    <span className="flex items-center gap-1.5 text-slate-500">
                      <User className="w-3 h-3 text-cyan-400" /> Google User ID:
                    </span>
                    <span className="text-slate-300 truncate max-w-[120px]" title={currentUser?.id}>
                      {currentUser?.id ? `${currentUser.id.slice(0, 10)}...` : 'G-77402'}
                    </span>
                  </div>
                </div>

                {/* Sign Out Action Button */}
                <div className="pt-3">
                  <button
                    onClick={() => {
                      setIsUserMenuOpen(false);
                      onLogout?.();
                    }}
                    className="w-full py-2 px-3 rounded-lg bg-red-950/30 hover:bg-red-950/70 border border-red-500/30 hover:border-red-500/60 text-red-300 hover:text-red-200 text-xs font-mono font-semibold flex items-center justify-center gap-2 transition-all cursor-pointer shadow-sm group"
                  >
                    <LogOut className="w-3.5 h-3.5 group-hover:-translate-x-0.5 transition-transform text-red-400" />
                    <span>Sign Out</span>
                  </button>
                </div>

              </div>
            )}

          </div>

        </div>
      </div>
    </header>
  );
};
