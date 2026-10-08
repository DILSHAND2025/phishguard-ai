import React, { useState, useEffect, useRef } from 'react';
import { Shield, Lock, AlertCircle, Loader2 } from 'lucide-react';
import { 
  getGoogleClientId, 
  initGoogleIdentityServices, 
  storeUserSession 
} from '../services/authService';

export const LoginPage = ({ onLoginSuccess }) => {
  const [isLoading, setIsLoading] = useState(false);
  const [errorMsg, setErrorMsg] = useState('');
  const clientId = getGoogleClientId();
  const googleButtonRef = useRef(null);

  // Initialize Google Identity Services if client ID exists and script loaded
  useEffect(() => {
    let checkInterval = null;
    let attempts = 0;

    const tryInit = () => {
      attempts++;
      if (window.google?.accounts?.id && clientId) {
        const initialized = initGoogleIdentityServices({
          onCredentialResponse: (user) => {
            setIsLoading(false);
            onLoginSuccess?.(user);
          },
          onError: (err) => {
            setIsLoading(false);
            setErrorMsg(typeof err === 'string' ? err : 'Google OAuth authentication failed.');
          }
        });

        if (initialized) {
          if (googleButtonRef.current) {
            try {
              window.google.accounts.id.renderButton(googleButtonRef.current, {
                theme: 'outline',
                size: 'large',
                text: 'signin_with',
                shape: 'rectangular',
                width: 320
              });
            } catch {
              // fallback to styled button
            }
          }
          if (checkInterval) clearInterval(checkInterval);
        }
      }

      if (attempts > 20 && checkInterval) {
        clearInterval(checkInterval);
      }
    };

    tryInit();
    checkInterval = setInterval(tryInit, 250);

    return () => {
      if (checkInterval) clearInterval(checkInterval);
    };
  }, [clientId, onLoginSuccess]);

  // Primary "Sign in with Google" click handler
  const handleGoogleSignInClick = () => {
    setIsLoading(true);
    setErrorMsg('');

    // If real Google client ID is configured and GIS is ready
    if (clientId && window.google?.accounts?.id) {
      try {
        window.google.accounts.id.prompt((notification) => {
          if (notification.isNotDisplayed() || notification.isSkippedMoment()) {
            setIsLoading(false);
            setErrorMsg('Google login prompt blocked or skipped. Please use the Google Sign-in button above.');
          }
        });
      } catch {
        setIsLoading(false);
        setErrorMsg('Error initializing Google login prompt.');
      }
    } else {
      // Local development fallback
      setTimeout(() => {
        const demoGoogleUser = storeUserSession({
          id: 'google-uid-108492049281749',
          name: 'Deepak Raghavan (Analyst-Alpha)',
          email: 'deepak.raghavan@gov-organization.in',
          picture: 'https://images.unsplash.com/photo-1534528741775-53994a69daeb?w=150&auto=format&fit=crop&q=80',
          authMethod: 'google-oauth2-dev'
        });
        setIsLoading(false);
        onLoginSuccess?.(demoGoogleUser);
      }, 600);
    }
  };

  return (
    <div className="min-h-screen bg-[#F8FAFC] text-slate-800 flex flex-col items-center justify-center p-4 font-sans">
      
      {/* Brand Header */}
      <div className="flex flex-col items-center mb-6 text-center">
        <div className="flex items-center justify-center w-11 h-11 rounded-xl bg-white border border-slate-200 shadow-2xs mb-3">
          <Shield className="w-6 h-6 text-slate-800" />
        </div>
        
        <h1 className="text-2xl font-bold tracking-tight text-slate-900">
          MAVERICK
        </h1>
        
        <p className="text-xs text-slate-500 mt-1 leading-relaxed text-center max-w-[280px]">
          AI-Powered Email Threat Detection & Forensic Intelligence
        </p>
      </div>

      {/* Centered Login Card */}
      <div className="w-full max-w-[380px] rounded-xl bg-white border border-slate-200 shadow-xs p-6 sm:p-7 space-y-5">
        
        {/* Card Header */}
        <div className="text-center space-y-1">
          <h2 className="text-lg font-bold text-slate-900">
            Welcome
          </h2>
          <p className="text-xs text-slate-500 leading-normal">
            Secure access to your forensic security dashboard.
          </p>
        </div>

        {/* Error Alert Box */}
        {errorMsg && (
          <div className="p-3 rounded-lg bg-red-50 border border-red-200 flex items-start gap-2 text-xs text-red-700">
            <AlertCircle className="w-4 h-4 text-red-500 shrink-0 mt-0.5" />
            <span>{errorMsg}</span>
          </div>
        )}

        {/* Action Area */}
        <div className="space-y-4">
          
          {/* Official GIS Button (if rendered) */}
          <div ref={googleButtonRef} className="flex justify-center empty:hidden"></div>

          {/* Primary "Sign in with Google" Button */}
          <button
            type="button"
            id="btn-google-login"
            onClick={handleGoogleSignInClick}
            disabled={isLoading}
            className="w-full h-[46px] rounded-lg bg-white hover:bg-slate-50 active:bg-slate-100 text-slate-700 border border-slate-300 text-xs font-semibold flex items-center justify-center gap-3 transition-colors cursor-pointer disabled:opacity-70 shadow-2xs focus:outline-none focus:ring-2 focus:ring-slate-400"
          >
            {isLoading ? (
              <>
                <Loader2 className="w-4 h-4 animate-spin text-slate-600" />
                <span>Signing in with Google...</span>
              </>
            ) : (
              <>
                {/* Official Google 4-Color Vector Icon */}
                <svg className="w-4 h-4 shrink-0" viewBox="0 0 24 24">
                  <path
                    fill="#4285F4"
                    d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z"
                  />
                  <path
                    fill="#34A853"
                    d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z"
                  />
                  <path
                    fill="#FBBC05"
                    d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.06H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.94l2.85-2.22.81-.63z"
                  />
                  <path
                    fill="#EA4335"
                    d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.06l3.66 2.84c.87-2.6 3.3-4.52 6.16-4.52z"
                  />
                </svg>
                <span>Sign in with Google</span>
              </>
            )}
          </button>

          {/* Security Notice */}
          <div className="pt-1 text-center">
            <p className="text-[11px] text-slate-400 flex items-center justify-center gap-1.5">
              <Lock className="w-3.5 h-3.5 text-slate-400 shrink-0" />
              <span>Secure authentication powered by Google</span>
            </p>
          </div>

        </div>

      </div>

    </div>
  );
};
