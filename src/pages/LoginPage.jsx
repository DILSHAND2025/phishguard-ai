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
                theme: 'filled_black',
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
            if (window.google.accounts.oauth2) {
              const client = window.google.accounts.oauth2.initTokenClient({
                client_id: clientId,
                scope: 'openid profile email',
                callback: async (tokenResponse) => {
                  if (tokenResponse.access_token) {
                    try {
                      const res = await fetch('https://www.googleapis.com/oauth2/v3/userinfo', {
                        headers: { Authorization: `Bearer ${tokenResponse.access_token}` }
                      });
                      const info = await res.json();
                      const user = storeUserSession({
                        id: info.sub,
                        name: info.name || 'Authorized Investigator',
                        email: info.email || 'investigator@gov-organization.in',
                        picture: info.picture || '',
                        authMethod: 'google-oauth2-token'
                      });
                      setIsLoading(false);
                      onLoginSuccess?.(user);
                    } catch {
                      setIsLoading(false);
                      setErrorMsg('Failed to retrieve user profile from Google API.');
                    }
                  } else {
                    setIsLoading(false);
                    setErrorMsg('Google authentication was not completed.');
                  }
                },
                error_callback: (error) => {
                  setIsLoading(false);
                  setErrorMsg(error.message || 'Google OAuth error occurred.');
                }
              });
              client.requestAccessToken();
            } else {
              setIsLoading(false);
            }
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
    <div className="min-h-screen bg-[#0b0d0f] bg-gradient-to-b from-[#0b0d0f] to-[#101317] text-white flex flex-col items-center justify-center p-4 font-sans selection:bg-cyan-500/20 selection:text-cyan-200">
      
      {/* Brand Header */}
      <div className="flex flex-col items-center mb-5 text-center">
        <div className="flex items-center justify-center w-10 h-10 rounded-xl bg-[#14171f] border border-white/[0.08] shadow-sm mb-2.5">
          <Shield className="w-5 h-5 text-cyan-400" />
        </div>
        
        <h1 className="text-xl font-bold tracking-tight text-white">
          MAVERICK
        </h1>
        
        <p className="text-xs text-zinc-400 mt-1 leading-relaxed text-center max-w-[280px]">
          AI-Powered Email Threat Detection<br />& Forensic Intelligence
        </p>
      </div>

      {/* Centered Login Card */}
      <div className="w-full max-w-[380px] rounded-xl bg-[#13161c] border border-white/[0.08] shadow-lg shadow-black/25 p-6 sm:p-7 space-y-5">
        
        {/* Card Header */}
        <div className="text-center space-y-1">
          <h2 className="text-lg font-semibold text-white">
            Welcome
          </h2>
          <p className="text-xs text-zinc-400 leading-normal">
            Secure access to your forensic intelligence workspace.
          </p>
        </div>

        {/* Error Alert Box */}
        {errorMsg && (
          <div className="p-2.5 rounded-lg bg-red-950/40 border border-red-500/30 flex items-start gap-2 text-xs text-red-300">
            <AlertCircle className="w-4 h-4 text-red-400 shrink-0 mt-0.5" />
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
            className="w-full h-[48px] rounded-[10px] bg-white hover:bg-zinc-100 active:bg-zinc-200 text-zinc-900 text-sm font-medium flex items-center justify-center gap-3 transition-all cursor-pointer disabled:opacity-70 shadow-sm focus:outline-none focus:ring-2 focus:ring-cyan-500/40 focus:ring-offset-2 focus:ring-offset-[#13161c]"
          >
            {isLoading ? (
              <>
                <Loader2 className="w-4 h-4 animate-spin text-zinc-700" />
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
            <p className="text-xs text-zinc-400 flex items-center justify-center gap-1.5">
              <Lock className="w-3.5 h-3.5 text-zinc-400 shrink-0" />
              <span>Secure authentication powered by Google</span>
            </p>
          </div>

        </div>

      </div>

    </div>
  );
};
