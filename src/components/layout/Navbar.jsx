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
        <header className="sticky top-0 z-40 w-full border-b border-slate-200 bg-white/95 backdrop-blur-md shadow-2xs">
          <div className="max-w-7xl mx-auto flex h-14 items-center justify-between px-4 sm:px-6">
            
            {/* Left: Minimal MAVERICK Brand */}
            <div 
              onClick={() => onViewChange('email-analysis')} 
              className="flex items-center gap-2.5 cursor-pointer select-none"
            >
              <div className="w-8 h-8 rounded-lg bg-cyan-50 border border-cyan-200 flex items-center justify-center text-cyan-600 shadow-2xs">
                <Shield className="w-4 h-4" />
              </div>
              <span className="font-bold text-base tracking-wider text-slate-900">
                MAVERICK
              </span>
            </div>

            {/* Right: Email Security, Help, Profile */}
            <div className="flex items-center gap-2 sm:gap-3">
              <span className="hidden sm:inline-flex items-center gap-1.5 px-2.5 py-1 rounded-md bg-slate-100 border border-slate-200 text-xs font-medium text-slate-700">
                <ShieldCheck className="w-3.5 h-3.5 text-cyan-600" />
                <span>Email Security</span>
              </span>

              <button
                onClick={() => setShowHelpModal(true)}
                className="flex items-center gap-1 px-2.5 py-1 rounded-md text-xs text-slate-600 hover:text-slate-900 hover:bg-slate-100 transition-colors cursor-pointer"
                title="Help & Submission Guidelines"
              >
                <HelpCircle className="w-4 h-4 text-slate-500" />
                <span className="hidden sm:inline">Help</span>
              </button>

              {/* User / Profile Avatar */}
              <div className="relative" ref={userMenuRef}>
                <button
                  onClick={() => setIsUserMenuOpen(!isUserMenuOpen)}
                  className="flex items-center gap-2 p-1 rounded-lg hover:bg-slate-100 transition-colors cursor-pointer"
                  aria-label="User Account"
                >
                  {currentUser?.picture ? (
                    <img
                      src={currentUser.picture}
                      alt={currentUser.name || 'User'}
                      className="w-7 h-7 rounded-full border border-slate-200 object-cover"
                    />
                  ) : (
                    <div className="w-7 h-7 rounded-full bg-cyan-100 border border-cyan-200 flex items-center justify-center text-xs font-bold text-cyan-700">
                      {currentUser?.name ? currentUser.name[0] : 'U'}
                    </div>
                  )}
                </button>

                {isUserMenuOpen && (
                  <div className="absolute right-0 mt-2 w-64 rounded-xl bg-white border border-slate-200 shadow-xl p-3 z-50 text-xs">
                    <div className="pb-2 border-b border-slate-100">
                      <div className="font-semibold text-slate-900 truncate">{currentUser?.name || 'User'}</div>
                      <div className="text-[11px] text-slate-500 truncate">{currentUser?.email || 'Authenticated'}</div>
                    </div>
                    <div className="py-2 space-y-1">
                      <button
                        onClick={() => {
                          setIsUserMenuOpen(false);
                          onViewChange('security-analyzer');
                        }}
                        className="w-full flex items-center justify-between px-2 py-1.5 rounded-lg text-slate-700 hover:text-slate-900 hover:bg-slate-50 text-left cursor-pointer"
                      >
                        <span>Security Analyzer</span>
                        <ExternalLink className="w-3 h-3 text-cyan-600" />
                      </button>
                    </div>
                    <div className="pt-2 border-t border-slate-100">
                      <button
                        onClick={() => {
                          setIsUserMenuOpen(false);
                          onLogout?.();
                        }}
                        className="w-full py-1.5 px-2 rounded-lg bg-red-50 hover:bg-red-100 border border-red-200 text-red-700 text-center flex items-center justify-center gap-1.5 cursor-pointer font-medium"
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
          <div className="fixed inset-0 bg-slate-900/40 backdrop-blur-2xs z-50 flex items-center justify-center p-4">
            <div className="bg-white border border-slate-200 rounded-2xl max-w-md w-full p-6 space-y-4 text-slate-700 shadow-xl">
              <div className="flex items-center justify-between border-b border-slate-100 pb-3">
                <h3 className="font-bold text-slate-900 text-sm flex items-center gap-2">
                  <HelpCircle className="w-4 h-4 text-cyan-600" />
                  How to Analyze an Email
                </h3>
                <button onClick={() => setShowHelpModal(false)} className="p-1 text-slate-400 hover:text-slate-700 rounded-lg">
                  <X className="w-4 h-4" />
                </button>
              </div>
              <div className="text-xs text-slate-600 space-y-2.5 leading-relaxed">
                <p>
                  <strong className="text-slate-900">1. Export as .EML:</strong> In Outlook or Gmail, choose &quot;Download message&quot; or &quot;Save as .eml&quot; to preserve cryptographic headers.
                </p>
                <p>
                  <strong className="text-slate-900">2. Upload:</strong> Drag and drop the file into the upload zone or click &quot;Browse Files&quot;.
                </p>
                <p>
                  <strong className="text-slate-900">3. Analyze:</strong> MAVERICK runs AI threat detection, authenticates sender SPF/DKIM/DMARC, checks network indicators, and generates a plain-language assessment.
                </p>
              </div>
              <div className="flex justify-end pt-2">
                <button
                  onClick={() => setShowHelpModal(false)}
                  className="px-4 py-2 text-xs bg-slate-900 hover:bg-slate-800 text-white font-medium rounded-xl cursor-pointer shadow-xs"
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
      <header className="sticky top-0 z-40 w-full border-b border-slate-200 bg-white/95 backdrop-blur-md shadow-2xs">
        <div className="flex h-14 items-center justify-between px-3 sm:px-5">
          
          {/* Left: Mobile Toggle & Brand */}
          <div className="flex items-center gap-3">
            <button
              onClick={onToggleMobile}
              className="md:hidden p-1.5 rounded-lg text-slate-500 hover:text-slate-900 hover:bg-slate-100 cursor-pointer"
              aria-label="Toggle navigation menu"
            >
              <Menu className="w-5 h-5" />
            </button>

            <div 
              onClick={() => onViewChange('dashboard')} 
              className="flex items-center gap-2.5 cursor-pointer group select-none"
            >
              <div className="w-8 h-8 rounded-lg bg-cyan-50 border border-cyan-200 flex items-center justify-center text-cyan-600 group-hover:border-cyan-400 transition-colors shadow-2xs">
                <Shield className="w-4 h-4" />
              </div>
              
              <div className="flex items-center gap-2">
                <span className="font-bold text-base tracking-wider text-slate-900">
                  MAVERICK
                </span>
                <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-slate-100 border border-slate-200 font-semibold text-slate-600">
                  SOC
                </span>
              </div>
            </div>
          </div>

          {/* Center: Search */}
          <div className="flex-1 max-w-sm mx-4 hidden lg:block">
            <div className="relative">
              <Search className="absolute left-2.5 top-2 h-3.5 w-3.5 text-slate-400" />
              <input
                type="text"
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                placeholder="Search IOCs, SHA-256, Sender, ASN..."
                className="w-full pl-8 pr-3 py-1.5 bg-slate-50 border border-slate-200 rounded-lg text-xs font-mono text-slate-800 placeholder-slate-400 focus:outline-none focus:bg-white focus:border-cyan-500 transition-colors"
              />
            </div>
          </div>

          {/* Right: Actions */}
          <div className="flex items-center gap-2.5">
            {/* Switch to User Email Analysis Mode */}
            <button
              onClick={() => onViewChange('email-analysis')}
              className="hidden sm:flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg bg-slate-100 hover:bg-slate-200/80 border border-slate-200 text-xs font-medium text-slate-700 transition-colors cursor-pointer"
              title="Switch to User Email Analysis"
            >
              <span>User Ingestion</span>
            </button>

            {/* Quick Scan CTA */}
            <button
              onClick={onOpenScan}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-semibold shadow-xs transition-colors cursor-pointer"
            >
              <Zap className="w-3.5 h-3.5 fill-current" />
              <span className="hidden sm:inline">Quick Scan</span>
              <span className="sm:hidden">Scan</span>
            </button>

            {/* User Profile */}
            <div className="relative" ref={userMenuRef}>
              <button
                onClick={() => setIsUserMenuOpen(!isUserMenuOpen)}
                className="flex items-center gap-2 p-1 rounded-lg hover:bg-slate-100 transition-colors cursor-pointer"
                aria-label="User profile"
              >
                {currentUser?.picture ? (
                  <img
                    src={currentUser.picture}
                    alt={currentUser.name || 'Analyst'}
                    className="w-7 h-7 rounded-full border border-slate-200 object-cover"
                  />
                ) : (
                  <div className="w-7 h-7 rounded-full bg-cyan-100 border border-cyan-200 flex items-center justify-center text-xs font-bold text-cyan-700">
                    {currentUser?.name ? currentUser.name[0] : 'A'}
                  </div>
                )}
              </button>

              {isUserMenuOpen && (
                <div className="absolute right-0 mt-2 w-64 rounded-xl bg-white border border-slate-200 shadow-xl p-3 z-50 text-xs">
                  <div className="pb-2 border-b border-slate-100">
                    <div className="font-semibold text-slate-900 truncate">{currentUser?.name || 'Security Analyst'}</div>
                    <div className="text-[11px] text-slate-500 truncate">{currentUser?.email || 'Online'}</div>
                  </div>
                  <div className="pt-2">
                    <button
                      onClick={() => {
                        setIsUserMenuOpen(false);
                        onLogout?.();
                      }}
                      className="w-full py-1.5 px-2 rounded-lg bg-red-50 hover:bg-red-100 border border-red-200 text-red-700 text-center flex items-center justify-center gap-1.5 cursor-pointer font-medium"
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
