import React from 'react';
import { 
  LayoutDashboard, 
  MailSearch, 
  ShieldAlert, 
  Binary, 
  Globe2, 
  GitFork, 
  Briefcase, 
  FileText,
  ChevronRight,
  ShieldCheck,
  Server,
  Zap,
  Flame
} from 'lucide-react';

const navItems = [
  { id: 'dashboard', label: 'Dashboard', icon: LayoutDashboard, step: '01', badge: 'LIVE', badgeColor: 'bg-cyan-500/20 text-cyan-300 border-cyan-500/40' },
  { id: 'email-analysis', label: 'Email Analysis', icon: MailSearch, step: '02', badge: 'INPUT', badgeColor: 'bg-sky-500/20 text-sky-300 border-sky-500/40' },
  { id: 'analysis-results', label: 'Analysis Results', icon: ShieldAlert, step: '03', badge: 'AI SCORE', badgeColor: 'bg-red-500/20 text-red-300 border-red-500/40' },
  { id: 'ioc-intel', label: 'IOC Intelligence', icon: Binary, step: '04', badge: '48 IOCs', badgeColor: 'bg-purple-500/20 text-purple-300 border-purple-500/40' },
  { id: 'geo-asn', label: 'GeoLocation & ASN', icon: Globe2, step: '05', badge: 'GLOBAL', badgeColor: 'bg-indigo-500/20 text-indigo-300 border-indigo-500/40' },
  { id: 'threat-graph', label: 'Threat Graph', icon: GitFork, step: '06', badge: 'GRAPH', badgeColor: 'bg-cyan-500/20 text-cyan-300 border-cyan-500/40' },
  { id: 'investigation-case', label: 'Investigation Case', icon: Briefcase, step: '07', badge: 'WAR ROOM', badgeColor: 'bg-amber-500/20 text-amber-300 border-amber-500/40' },
  { id: 'forensic-report', label: 'Forensic Report', icon: FileText, step: '08', badge: 'SIH CERT', badgeColor: 'bg-emerald-500/20 text-emerald-300 border-emerald-500/40' },
];

export const Sidebar = ({ currentView, onViewChange }) => {
  return (
    <aside className="w-64 shrink-0 flex flex-col justify-between border-r border-cyan-950/50 bg-[#060a12] min-h-[calc(100vh-4rem)]">
      
      {/* Top Section: Navigation Links */}
      <div className="p-3 space-y-4">
        
        {/* Pipeline Heading */}
        <div className="px-3 pt-2">
          <div className="flex items-center justify-between">
            <span className="text-[10px] uppercase tracking-wider font-mono font-bold text-slate-400">
              FORENSIC PIPELINE
            </span>
            <span className="flex items-center gap-1 text-[10px] font-mono text-cyan-400">
              <span className="w-1.5 h-1.5 rounded-full bg-cyan-400 animate-ping"></span>
              8 STAGES
            </span>
          </div>
          <div className="h-0.5 w-full bg-gradient-to-r from-cyan-500/40 via-blue-500/20 to-transparent mt-1.5"></div>
        </div>

        {/* Nav List */}
        <nav className="space-y-1">
          {navItems.map((item) => {
            const Icon = item.icon;
            const isActive = currentView === item.id;
            return (
              <button
                key={item.id}
                onClick={() => onViewChange(item.id)}
                className={`w-full group flex items-center justify-between px-3 py-2.5 rounded-lg text-xs font-medium transition-all text-left ${
                  isActive
                    ? 'bg-gradient-to-r from-cyan-950/80 to-[#0e1b2f] text-cyan-200 border border-cyan-500/40 shadow-[0_0_12px_rgba(6,182,212,0.2)]'
                    : 'text-slate-400 hover:text-slate-200 hover:bg-[#0c1424] border border-transparent'
                }`}
              >
                <div className="flex items-center gap-2.5 min-w-0">
                  <span className={`font-mono text-[10px] px-1 rounded ${isActive ? 'bg-cyan-500/30 text-cyan-300 font-bold' : 'text-slate-600 group-hover:text-slate-400'}`}>
                    {item.step}
                  </span>
                  <Icon className={`w-4 h-4 shrink-0 transition-transform ${isActive ? 'text-cyan-400 scale-110' : 'text-slate-500 group-hover:text-cyan-300'}`} />
                  <span className="truncate tracking-wide">{item.label}</span>
                </div>

                {item.badge && (
                  <span className={`text-[9px] font-mono px-1.5 py-0.5 rounded border ${item.badgeColor}`}>
                    {item.badge}
                  </span>
                )}
              </button>
            );
          })}
        </nav>

        {/* Active Campaign Alert Box */}
        <div className="p-3 rounded-lg bg-gradient-to-b from-red-950/30 to-[#0d1525] border border-red-500/30">
          <div className="flex items-center gap-2 text-red-400 text-xs font-semibold mb-1">
            <Flame className="w-3.5 h-3.5 text-red-400 animate-bounce" />
            <span>Active Phish Campaign</span>
          </div>
          <p className="text-[11px] text-slate-300 leading-snug">
            UNC4219 impersonating Gov Treasury portal via QR polyglots.
          </p>
          <div className="mt-2 flex items-center justify-between text-[10px] font-mono text-red-300/80">
            <span>High Risk: 98/100</span>
            <button 
              onClick={() => onViewChange('investigation-case')}
              className="text-cyan-400 hover:underline flex items-center gap-0.5"
            >
              Case #0881 <ChevronRight className="w-3 h-3" />
            </button>
          </div>
        </div>

      </div>

      {/* Bottom Section: Telemetry & System Node Status */}
      <div className="p-3 border-t border-slate-800/80 bg-[#05080e] space-y-2.5">
        <div className="text-[10px] font-mono uppercase tracking-wider text-slate-500 font-semibold flex items-center justify-between">
          <span>SOC Node Health</span>
          <span className="text-emerald-400 flex items-center gap-1 font-bold">
            <span className="w-1.5 h-1.5 rounded-full bg-emerald-400"></span> 99.98%
          </span>
        </div>

        {/* Load bars */}
        <div className="space-y-1.5 text-[10px] font-mono text-slate-400">
          <div>
            <div className="flex justify-between mb-0.5">
              <span>AI Ingestion Queue</span>
              <span className="text-cyan-300">142 msg/sec</span>
            </div>
            <div className="w-full h-1 bg-slate-800 rounded-full overflow-hidden">
              <div className="h-full bg-gradient-to-r from-cyan-500 to-blue-500 w-[68%] rounded-full"></div>
            </div>
          </div>

          <div>
            <div className="flex justify-between mb-0.5">
              <span>Threat Intel Correlator</span>
              <span className="text-amber-300">Active</span>
            </div>
            <div className="w-full h-1 bg-slate-800 rounded-full overflow-hidden">
              <div className="h-full bg-gradient-to-r from-emerald-500 to-cyan-500 w-[42%] rounded-full"></div>
            </div>
          </div>
        </div>

        {/* Version info */}
        <div className="pt-2 border-t border-slate-900 flex items-center justify-between text-[9px] font-mono text-slate-600">
          <span>MAVERICK SOC v4.2.0</span>
          <span>SIH-2026 Core</span>
        </div>
      </div>

    </aside>
  );
};
