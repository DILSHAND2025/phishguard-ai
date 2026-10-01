import React, { useState, useRef, useEffect } from 'react';
import { 
  Shield, 
  Search, 
  HelpCircle, 
  LogOut, 
  Menu, 
  X, 
  Zap, 
  ShieldCheck, 
  ExternalLink 
} from 'lucide-react';

export const Navbar = ({ 
  onOpenScan, 
  currentView, 
  onViewChange, 
  currentUser, 
  onLogout,
  onToggleMobile 
}) => {
  const [searchQuery, setSearchQuery] = useState('');
  const [isUserMenuOpen, setIsUserMenuOpen] = useState(false);
  const [showHelpModal, setShowHelpModal] = useState(false);
  const userMenuRef = useRef(null);

  // Close profile dropdown on click outside
  useEffect(() => {
    const handleClickOutside = (event) => {
      if (userMenuRef.current && !userMenuRef.current.contains(event.target)) {
        setIsUserMenuOpen(false);
      }
    };
    document.addEventListener('mousedown', handleClickOutside);
    return () => document.removeEventListener('mousedown', handleClickOutside);
  }, []);

  const isUserEmailView = currentView === 'email-analysis';

  // Minimal Navbar for Normal User Email Analysis
  if (isUserEmailView) {
    return (
      <>
        <header className="sticky top-0 z-40 w-full border-b border-slate-800 bg-[#090d16]/95 backdrop-blur-md">
          <div className="max-w-7xl mx-auto flex h-14 items-center justify-between px-4 sm:px-6">
            
            {/* Left: Minimal MAVERICK Brand */}
            <div 
              onClick={() => onViewChange('email-analysis')} 
              className="flex items-center gap-2.5 cursor-pointer select-none"
            >
              <div className="w-8 h-8 rounded-lg bg-slate-800 border border-slate-700 flex items-center justify-center text-cyan-400">
                <Shield className="w-4 h-4" />
              </div>
              <span className="font-bold text-base tracking-wider text-white">
                MAVERICK
              </span>
            </div>

            {/* Right: Email Security, Help, Profile */}
            <div className="flex items-center gap-2 sm:gap-3">
              <span className="hidden sm:inline-flex items-center gap-1.5 px-2.5 py-1 rounded-md bg-slate-850 border border-slate-750 text-xs text-slate-300">
                <ShieldCheck className="w-3.5 h-3.5 text-cyan-400" />
                <span>Email Security</span>
              </span>

              <button
                onClick={() => setShowHelpModal(true)}
                className="flex items-center gap-1 px-2.5 py-1 rounded-md text-xs text-slate-400 hover:text-slate-200 hover:bg-slate-800/60 transition-colors cursor-pointer"
                title="Help & Submission Guidelines"
              >
                <HelpCircle className="w-4 h-4 text-slate-400" />
                <span className="hidden sm:inline">Help</span>
              </button>

              {/* User / Profile Avatar */}
              <div className="relative" ref={userMenuRef}>
                <button
                  onClick={() => setIsUserMenuOpen(!isUserMenuOpen)}
                  className="flex items-center gap-2 p-1 rounded-lg hover:bg-slate-800 transition-colors cursor-pointer"
                  aria-label="User Account"
                >
                  {currentUser?.picture ? (
                    <img
                      src={currentUser.picture}
                      alt={currentUser.name || 'User'}
                      className="w-7 h-7 rounded-full border border-slate-700 object-cover"
                    />
                  ) : (
                    <div className="w-7 h-7 rounded-full bg-slate-800 border border-slate-700 flex items-center justify-center text-xs font-bold text-cyan-300">
                      {currentUser?.name ? currentUser.name[0] : 'U'}
                    </div>
                  )}
                </button>

                {isUserMenuOpen && (
                  <div className="absolute right-0 mt-2 w-64 rounded-xl bg-[#0d1322] border border-slate-700/80 shadow-2xl p-3 z-50 text-xs">
                    <div className="pb-2 border-b border-slate-800">
                      <div className="font-semibold text-white truncate">{currentUser?.name || 'User'}</div>
                      <div className="text-[11px] text-slate-400 truncate">{currentUser?.email || 'Authenticated'}</div>
                    </div>
                    <div className="py-2 space-y-1">
                      <button
                        onClick={() => {
                          setIsUserMenuOpen(false);
                          onViewChange('security-analyzer');
                        }}
                        className="w-full flex items-center justify-between px-2 py-1.5 rounded-lg text-slate-300 hover:text-white hover:bg-slate-800 text-left cursor-pointer"
                      >
                        <span>Security Analyzer</span>
                        <ExternalLink className="w-3 h-3 text-cyan-400" />
                      </button>
                    </div>
                    <div className="pt-2 border-t border-slate-800">
                      <button
                        onClick={() => {
                          setIsUserMenuOpen(false);
                          onLogout?.();
                        }}
                        className="w-full py-1.5 px-2 rounded-lg bg-red-950/30 hover:bg-red-950/60 border border-red-900/40 text-red-300 text-center flex items-center justify-center gap-1.5 cursor-pointer"
                      >
                        <LogOut className="w-3.5 h-3.5" />
                        <span>Sign Out</span>
                      </button>
                    </div>
                  </div>
                )}
              </div>
            </div>

          </div>
        </header>

        {/* Help Modal for User */}
        {showHelpModal && (
          <div className="fixed inset-0 bg-black/70 z-50 flex items-center justify-center p-4">
            <div className="bg-[#0b101d] border border-slate-700 rounded-xl max-w-md w-full p-5 space-y-3 text-slate-200">
              <div className="flex items-center justify-between border-b border-slate-800 pb-2">
                <h3 className="font-bold text-white text-sm flex items-center gap-2">
                  <HelpCircle className="w-4 h-4 text-cyan-400" />
                  How to Analyze an Email
                </h3>
                <button onClick={() => setShowHelpModal(false)} className="p-1 text-slate-400 hover:text-white">
                  <X className="w-4 h-4" />
                </button>
              </div>
              <div className="text-xs text-slate-300 space-y-2">
                <p>
                  <strong>1. Export as .EML:</strong> In Outlook or Gmail, choose &quot;Download message&quot; or &quot;Save as .eml&quot; to preserve cryptographic headers.
                </p>
                <p>
                  <strong>2. Upload:</strong> Drag and drop the file into the upload zone or click &quot;Browse Files&quot;.
                </p>
                <p>
                  <strong>3. Analyze:</strong> MAVERICK runs AI threat detection, authenticates sender SPF/DKIM/DMARC, checks network indicators, and generates a plain-language assessment.
                </p>
              </div>
              <div className="flex justify-end pt-2">
                <button
                  onClick={() => setShowHelpModal(false)}
                  className="px-3 py-1.5 text-xs bg-slate-800 hover:bg-slate-700 text-white rounded-lg cursor-pointer"
                >
                  Got it
                </button>
              </div>
            </div>
          </div>
        )}
      </>
    );
  }

  // Security Analyst Workspace Header
  return (
    <>
      <header className="sticky top-0 z-40 w-full border-b border-slate-800/80 bg-[#090d16]/95 backdrop-blur-md">
        <div className="flex h-14 items-center justify-between px-3 sm:px-5">
          
          {/* Left: Mobile Toggle & Brand */}
          <div className="flex items-center gap-3">
            <button
              onClick={onToggleMobile}
              className="md:hidden p-1.5 rounded-lg text-slate-400 hover:text-white hover:bg-slate-800 cursor-pointer"
              aria-label="Toggle navigation menu"
            >
              <Menu className="w-5 h-5" />
            </button>

            <div 
              onClick={() => onViewChange('dashboard')} 
              className="flex items-center gap-2.5 cursor-pointer group"
            >
              <div className="w-8 h-8 rounded-lg bg-slate-800 border border-slate-700 flex items-center justify-center text-cyan-400 group-hover:border-cyan-500/50 transition-colors">
                <Shield className="w-4 h-4" />
              </div>
              
              <div className="flex items-center gap-2">
                <span className="font-bold text-base tracking-wider text-white">
                  MAVERICK
                </span>
                <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-slate-800 border border-slate-700 text-slate-300">
                  SOC
                </span>
              </div>
            </div>
          </div>

          {/* Center: Search */}
          <div className="flex-1 max-w-sm mx-4 hidden lg:block">
            <div className="relative">
              <Search className="absolute left-2.5 top-2 h-3.5 w-3.5 text-slate-500" />
              <input
                type="text"
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                placeholder="Search IOCs, SHA-256, Sender, ASN..."
                className="w-full pl-8 pr-3 py-1 bg-slate-900 border border-slate-800 rounded-lg text-xs font-mono text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-500/60 transition-colors"
              />
            </div>
          </div>

          {/* Right: Actions */}
          <div className="flex items-center gap-2.5">
            {/* Switch to User Email Analysis Mode */}
            <button
              onClick={() => onViewChange('email-analysis')}
              className="hidden sm:flex items-center gap-1.5 px-2.5 py-1 rounded-lg bg-slate-850 hover:bg-slate-800 border border-slate-750 text-xs text-slate-300 transition-colors cursor-pointer"
              title="Switch to User Email Analysis"
            >
              <span>User Ingestion</span>
            </button>

            {/* Quick Scan CTA */}
            <button
              onClick={onOpenScan}
              className="flex items-center gap-1.5 px-3 py-1 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-semibold shadow-xs transition-colors cursor-pointer"
            >
              <Zap className="w-3.5 h-3.5 fill-current" />
              <span className="hidden sm:inline">Quick Scan</span>
              <span className="sm:hidden">Scan</span>
            </button>

            {/* User Profile */}
            <div className="relative" ref={userMenuRef}>
              <button
                onClick={() => setIsUserMenuOpen(!isUserMenuOpen)}
                className="flex items-center gap-2 p-1 rounded-lg hover:bg-slate-800 transition-colors cursor-pointer"
                aria-label="User profile"
              >
                {currentUser?.picture ? (
                  <img
                    src={currentUser.picture}
                    alt={currentUser.name || 'Analyst'}
                    className="w-7 h-7 rounded-full border border-slate-700 object-cover"
                  />
                ) : (
                  <div className="w-7 h-7 rounded-full bg-slate-800 border border-slate-700 flex items-center justify-center text-xs font-bold text-cyan-300">
                    {currentUser?.name ? currentUser.name[0] : 'A'}
                  </div>
                )}
              </button>

              {isUserMenuOpen && (
                <div className="absolute right-0 mt-2 w-64 rounded-xl bg-[#0d1322] border border-slate-700/80 shadow-2xl p-3 z-50 text-xs">
                  <div className="pb-2 border-b border-slate-800">
                    <div className="font-semibold text-white truncate">{currentUser?.name || 'Security Analyst'}</div>
                    <div className="text-[11px] text-slate-400 truncate">{currentUser?.email || 'Online'}</div>
                  </div>
                  <div className="pt-2">
                    <button
                      onClick={() => {
                        setIsUserMenuOpen(false);
                        onLogout?.();
                      }}
                      className="w-full py-1.5 px-2 rounded-lg bg-red-950/30 hover:bg-red-950/60 border border-red-900/40 text-red-300 text-center flex items-center justify-center gap-1.5 cursor-pointer"
                    >
                      <LogOut className="w-3.5 h-3.5" />
                      <span>Sign Out</span>
                    </button>
                  </div>
                </div>
              )}
            </div>

          </div>

        </div>
      </header>
    </>
  );
};
