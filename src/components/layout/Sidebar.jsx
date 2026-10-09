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
      id: 'email-analysis', 
      label: 'Email Analyzer', 
      icon: Mail,
      isActive: currentView === 'email-analysis' || currentView === 'analyzer'
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
    { 
      id: 'settings', 
      label: 'Settings', 
      icon: Settings,
      isActive: currentView === 'settings'
    },
  ];

  const handleNavClick = (viewId) => {
    onViewChange(viewId);
    if (onCloseMobile) onCloseMobile();
  };

  return (
    <>
      <aside 
        className={`w-[230px] shrink-0 flex flex-col justify-between border-r border-slate-200 bg-white text-slate-700 transition-all duration-200 z-30
          ${isMobileOpen ? 'fixed inset-y-0 left-0 shadow-2xl flex' : 'hidden md:flex'}`}
        style={{ minHeight: 'calc(100vh - 3.5rem)' }}
      >
        {/* Top Section */}
        <div className="p-3.5 space-y-4">
          
          {/* Mobile close button */}
          <div className="flex items-center justify-between md:hidden pb-2 border-b border-slate-100">
            <div className="flex items-center gap-2">
              <Shield className="w-4 h-4 text-cyan-600" />
              <span className="font-bold text-sm text-slate-900 tracking-wide">MAVERICK</span>
            </div>
            <button 
              onClick={onCloseMobile}
              className="p-1 rounded text-slate-400 hover:text-slate-700"
              aria-label="Close sidebar"
            >
              <X className="w-4 h-4" />
            </button>
          </div>

          {/* Core Navigation Links */}
          <nav className="space-y-1">
            <div className="px-2.5 py-1 text-[11px] font-semibold text-slate-400 uppercase tracking-wider">
              Navigation
            </div>

            {mainNav.map((item) => {
              const Icon = item.icon;
              return (
                <button
                  key={item.id}
                  onClick={() => handleNavClick(item.id)}
                  className={`w-full flex items-center justify-between px-2.5 py-2 rounded-lg text-xs font-medium transition-colors text-left cursor-pointer ${
                    item.isActive
                      ? 'bg-cyan-50 text-cyan-800 font-semibold border-l-2 border-cyan-600 shadow-2xs'
                      : 'text-slate-600 hover:text-slate-900 hover:bg-slate-50'
                  }`}
                >
                  <div className="flex items-center gap-2.5 min-w-0">
                    <Icon className={`w-4 h-4 shrink-0 ${item.isActive ? 'text-cyan-600' : 'text-slate-400'}`} />
                    <span className="truncate">{item.label}</span>
                  </div>
                  {item.isActive && (
                    <span className="w-1.5 h-1.5 rounded-full bg-cyan-600"></span>
                  )}
                </button>
              );
            })}
          </nav>

        </div>

        {/* Bottom User Area */}
        <div className="p-3 border-t border-slate-200 bg-slate-50/70">
          {currentUser ? (
            <div className="space-y-2">
              <div 
                onClick={() => setShowProfileModal(true)}
                className="flex items-center gap-2 p-1.5 rounded-lg hover:bg-white cursor-pointer transition-colors border border-transparent hover:border-slate-200 shadow-2xs"
              >
                {currentUser.picture ? (
                  <img
                    src={currentUser.picture}
                    alt={currentUser.name}
                    className="w-7 h-7 rounded-full object-cover border border-slate-200 shrink-0"
                  />
                ) : (
                  <div className="w-7 h-7 rounded-full bg-cyan-100 border border-cyan-200 flex items-center justify-center text-[10px] font-bold text-cyan-700 shrink-0">
                    {currentUser.name ? currentUser.name.split(' ').map(n => n[0]).slice(0, 2).join('') : 'U'}
                  </div>
                )}
                <div className="min-w-0 flex-1">
                  <div className="text-xs font-medium text-slate-800 truncate">{currentUser.name || 'User'}</div>
                  <div className="text-[10px] text-slate-500 truncate">{currentUser.email || 'Online'}</div>
                </div>
              </div>

              <button
                onClick={onLogout}
                className="w-full py-1.5 px-2 rounded-lg bg-white hover:bg-red-50 border border-slate-200 hover:border-red-200 text-[11px] text-slate-600 hover:text-red-600 flex items-center justify-center gap-1.5 transition-colors cursor-pointer font-medium shadow-2xs"
              >
                <LogOut className="w-3 h-3 text-red-500" />
                <span>Sign Out</span>
              </button>
            </div>
          ) : (
            <div className="text-[11px] text-slate-500 text-center py-1">
              MAVERICK SOC Platform
            </div>
          )}
        </div>
      </aside>

      {/* Backdrop for mobile */}
      {isMobileOpen && (
        <div 
          onClick={onCloseMobile}
          className="fixed inset-0 bg-slate-900/40 z-20 md:hidden backdrop-blur-2xs"
        />
      )}

      {/* Profile Modal */}
      {showProfileModal && (
        <div className="fixed inset-0 bg-slate-900/40 z-50 flex items-center justify-center p-4">
          <div className="bg-white border border-slate-200 rounded-2xl max-w-sm w-full p-5 space-y-4 text-slate-700 shadow-xl">
            <div className="flex items-center justify-between border-b border-slate-100 pb-3">
              <h3 className="text-sm font-bold text-slate-900 flex items-center gap-2">
                <User className="w-4 h-4 text-cyan-600" />
                User Profile
              </h3>
              <button 
                onClick={() => setShowProfileModal(false)}
                className="p-1 text-slate-400 hover:text-slate-700 rounded-lg"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            <div className="flex items-center gap-3">
              {currentUser?.picture ? (
                <img src={currentUser.picture} alt="" className="w-12 h-12 rounded-full border border-slate-200" />
              ) : (
                <div className="w-12 h-12 rounded-full bg-cyan-100 border border-cyan-200 flex items-center justify-center text-base font-bold text-cyan-700">
                  {currentUser?.name ? currentUser.name[0] : 'U'}
                </div>
              )}
              <div>
                <div className="font-semibold text-slate-900">{currentUser?.name || 'Security Analyst'}</div>
                <div className="text-xs text-slate-500">{currentUser?.email || 'analyst@maverick.security'}</div>
                <div className="text-[10px] text-cyan-700 font-mono font-medium mt-0.5">Role: Forensic Investigator</div>
              </div>
            </div>

            <div className="p-3 bg-slate-50 rounded-xl border border-slate-200 text-xs space-y-1.5 text-slate-600">
              <div className="flex justify-between">
                <span className="text-slate-500">Environment:</span>
                <span className="text-slate-800 font-mono font-medium">SOC Production</span>
              </div>
              <div className="flex justify-between">
                <span className="text-slate-500">SIH 2026 Build:</span>
                <span className="text-emerald-700 font-mono font-semibold">v4.2.0 (Verified)</span>
              </div>
            </div>

            <div className="flex justify-end gap-2 pt-2">
              <button
                onClick={() => setShowProfileModal(false)}
                className="px-4 py-2 text-xs rounded-xl bg-slate-900 hover:bg-slate-800 text-white font-medium cursor-pointer shadow-xs"
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
