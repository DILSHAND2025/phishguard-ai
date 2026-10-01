import React, { useState } from 'react';
import { 
  LayoutDashboard, 
  ShieldCheck, 
  Briefcase, 
  FileText, 
  Settings, 
  User, 
  LogOut, 
  Shield, 
  Mail, 
  X 
} from 'lucide-react';

export const Sidebar = ({ currentView, onViewChange, currentUser, onLogout, isMobileOpen, onCloseMobile }) => {
  const [showProfileModal, setShowProfileModal] = useState(false);

  const mainNav = [
    { 
      id: 'dashboard', 
      label: 'Dashboard', 
      icon: LayoutDashboard,
      isActive: currentView === 'dashboard'
    },
    { 
      id: 'security-analyzer', 
      label: 'Security Analyzer', 
      icon: ShieldCheck,
      isActive: currentView === 'security-analyzer' || currentView === 'analysis-results'
    },
    { 
      id: 'investigation-case', 
      label: 'Cases', 
      icon: Briefcase,
      isActive: currentView === 'investigation-case' || currentView === 'cases'
    },
    { 
      id: 'forensic-report', 
      label: 'Reports', 
      icon: FileText,
      isActive: currentView === 'forensic-report' || currentView === 'reports'
    },
  ];

  const handleNavClick = (viewId) => {
    onViewChange(viewId);
    if (onCloseMobile) onCloseMobile();
  };

  return (
    <>
      <aside 
        className={`w-[230px] shrink-0 flex flex-col justify-between border-r border-slate-800/80 bg-[#090d16] text-slate-300 transition-all duration-200 z-30
          ${isMobileOpen ? 'fixed inset-y-0 left-0 shadow-2xl flex' : 'hidden md:flex'}`}
        style={{ minHeight: 'calc(100vh - 3.5rem)' }}
      >
        {/* Top Section */}
        <div className="p-3.5 space-y-4">
          
          {/* Mobile close button */}
          <div className="flex items-center justify-between md:hidden pb-2 border-b border-slate-800">
            <div className="flex items-center gap-2">
              <Shield className="w-4 h-4 text-cyan-400" />
              <span className="font-bold text-sm text-white tracking-wide">MAVERICK</span>
            </div>
            <button 
              onClick={onCloseMobile}
              className="p-1 rounded text-slate-400 hover:text-white"
              aria-label="Close sidebar"
            >
              <X className="w-4 h-4" />
            </button>
          </div>

          {/* Core Navigation Links */}
          <nav className="space-y-1">
            <div className="px-2.5 py-1 text-[10px] font-semibold text-slate-400 uppercase tracking-wider">
              Workspace
            </div>

            {mainNav.map((item) => {
              const Icon = item.icon;
              return (
                <button
                  key={item.id}
                  onClick={() => handleNavClick(item.id)}
                  className={`w-full flex items-center justify-between px-2.5 py-2 rounded-lg text-xs font-medium transition-colors text-left cursor-pointer ${
                    item.isActive
                      ? 'bg-slate-800 text-white font-semibold shadow-xs border border-slate-700/60'
                      : 'text-slate-400 hover:text-slate-200 hover:bg-slate-850/60'
                  }`}
                >
                  <div className="flex items-center gap-2.5 min-w-0">
                    <Icon className={`w-4 h-4 shrink-0 ${item.isActive ? 'text-cyan-400' : 'text-slate-400'}`} />
                    <span className="truncate">{item.label}</span>
                  </div>
                  {item.isActive && (
                    <span className="w-1.5 h-1.5 rounded-full bg-cyan-400"></span>
                  )}
                </button>
              );
            })}
          </nav>

          {/* Quick link to User Email Analysis */}
          <div className="pt-2">
            <div className="px-2.5 py-1 text-[10px] font-semibold text-slate-400 uppercase tracking-wider">
              Submission Mode
            </div>
            <button
              onClick={() => handleNavClick('email-analysis')}
              className={`w-full flex items-center justify-between px-2.5 py-2 rounded-lg text-xs font-medium transition-colors text-left cursor-pointer ${
                currentView === 'email-analysis'
                  ? 'bg-slate-800 text-white font-semibold border border-slate-700/60'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-850/60'
              }`}
            >
              <div className="flex items-center gap-2.5 min-w-0">
                <Mail className="w-4 h-4 shrink-0 text-sky-400" />
                <span className="truncate">Email Analysis</span>
              </div>
              <span className="text-[9px] px-1.5 py-0.5 rounded bg-sky-950/60 text-sky-300 border border-sky-800/40">
                User
              </span>
            </button>
          </div>

          {/* Divider */}
          <div className="h-px bg-slate-800 my-3"></div>

          {/* Secondary Links: Settings & Profile */}
          <nav className="space-y-1">
            <button
              onClick={() => handleNavClick('settings')}
              className={`w-full flex items-center gap-2.5 px-2.5 py-2 rounded-lg text-xs font-medium transition-colors text-left cursor-pointer ${
                currentView === 'settings'
                  ? 'bg-slate-800 text-white font-semibold border border-slate-700/60'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-850/60'
              }`}
            >
              <Settings className={`w-4 h-4 shrink-0 ${currentView === 'settings' ? 'text-cyan-400' : 'text-slate-400'}`} />
              <span>Settings</span>
            </button>

            <button
              onClick={() => setShowProfileModal(true)}
              className="w-full flex items-center gap-2.5 px-2.5 py-2 rounded-lg text-xs font-medium text-slate-400 hover:text-slate-200 hover:bg-slate-850/60 transition-colors text-left cursor-pointer"
            >
              <User className="w-4 h-4 shrink-0 text-slate-400" />
              <span>Profile</span>
            </button>
          </nav>

        </div>

        {/* Bottom User Area */}
        <div className="p-3 border-t border-slate-800/80 bg-[#070b13]">
          {currentUser ? (
            <div className="space-y-2">
              <div 
                onClick={() => setShowProfileModal(true)}
                className="flex items-center gap-2 p-1.5 rounded-lg hover:bg-slate-800/60 cursor-pointer transition-colors"
              >
                {currentUser.picture ? (
                  <img
                    src={currentUser.picture}
                    alt={currentUser.name}
                    className="w-7 h-7 rounded-full object-cover border border-slate-700 shrink-0"
                  />
                ) : (
                  <div className="w-7 h-7 rounded-full bg-slate-800 border border-slate-700 flex items-center justify-center text-[10px] font-bold text-cyan-300 shrink-0">
                    {currentUser.name ? currentUser.name.split(' ').map(n => n[0]).slice(0, 2).join('') : 'U'}
                  </div>
                )}
                <div className="min-w-0 flex-1">
                  <div className="text-xs font-medium text-slate-200 truncate">{currentUser.name || 'User'}</div>
                  <div className="text-[10px] text-slate-400 truncate">{currentUser.email || 'Online'}</div>
                </div>
              </div>

              <button
                onClick={onLogout}
                className="w-full py-1.5 px-2 rounded-lg bg-slate-900 hover:bg-red-950/40 border border-slate-800 hover:border-red-900/50 text-[11px] text-slate-400 hover:text-red-300 flex items-center justify-center gap-1.5 transition-colors cursor-pointer"
              >
                <LogOut className="w-3 h-3 text-red-400" />
                <span>Sign Out</span>
              </button>
            </div>
          ) : (
            <div className="text-[10px] text-slate-400 text-center py-1">
              MAVERICK Security Analyzer
            </div>
          )}
        </div>
      </aside>

      {/* Backdrop for mobile */}
      {isMobileOpen && (
        <div 
          onClick={onCloseMobile}
          className="fixed inset-0 bg-black/60 z-20 md:hidden backdrop-blur-xs"
        />
      )}

      {/* Profile Modal */}
      {showProfileModal && (
        <div className="fixed inset-0 bg-black/70 z-50 flex items-center justify-center p-4">
          <div className="bg-[#0b101d] border border-slate-700 rounded-xl max-w-sm w-full p-5 space-y-4 text-slate-200">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <h3 className="text-sm font-bold text-white flex items-center gap-2">
                <User className="w-4 h-4 text-cyan-400" />
                User Profile
              </h3>
              <button 
                onClick={() => setShowProfileModal(false)}
                className="p-1 text-slate-400 hover:text-white"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            <div className="flex items-center gap-3">
              {currentUser?.picture ? (
                <img src={currentUser.picture} alt="" className="w-12 h-12 rounded-full border border-cyan-500/40" />
              ) : (
                <div className="w-12 h-12 rounded-full bg-slate-800 border border-slate-700 flex items-center justify-center text-base font-bold text-cyan-300">
                  {currentUser?.name ? currentUser.name[0] : 'U'}
                </div>
              )}
              <div>
                <div className="font-semibold text-white">{currentUser?.name || 'Security Analyst'}</div>
                <div className="text-xs text-slate-400">{currentUser?.email || 'analyst@maverick.security'}</div>
                <div className="text-[10px] text-cyan-400 font-mono mt-0.5">Role: Forensic Investigator</div>
              </div>
            </div>

            <div className="p-3 bg-[#080d17] rounded-lg border border-slate-800 text-xs space-y-1.5 text-slate-300">
              <div className="flex justify-between">
                <span className="text-slate-400">Environment:</span>
                <span className="text-slate-200 font-mono">SOC Production</span>
              </div>
              <div className="flex justify-between">
                <span className="text-slate-400">SIH 2026 Build:</span>
                <span className="text-emerald-400 font-mono">v4.2.0 (Verified)</span>
              </div>
            </div>

            <div className="flex justify-end gap-2 pt-2">
              <button
                onClick={() => setShowProfileModal(false)}
                className="px-3 py-1.5 text-xs rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200"
              >
                Close
              </button>
            </div>
          </div>
        </div>
      )}
    </>
  );
};
