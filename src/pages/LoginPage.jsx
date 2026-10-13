
import React, { useState, useEffect, useRef } from 'react';
import { Shield, Lock, AlertCircle, Loader2 } from 'lucide-react';
import {
  getGoogleClientId,
  initGoogleIdentityServices,
} from '../services/authService';

export const LoginPage = ({ onLoginSuccess }) => {
  const [isLoading, setIsLoading] = useState(false);
  const [errorMsg, setErrorMsg] = useState('');
  const googleButtonRef = useRef(null);
  const callbackRef = useRef({ onLoginSuccess });

  const clientId = getGoogleClientId();

  useEffect(() => {
    callbackRef.current.onLoginSuccess = onLoginSuccess;
  }, [onLoginSuccess]);

  useEffect(() => {
    if (!clientId) {
      setErrorMsg(
        'Google Client ID is missing. Check Vercel environment variables.'
      );
      return;
    }

    let intervalId;
    let attempts = 0;
    let active = true;
    let initialized = false;

    const initialize = () => {
      if (!active || initialized) return;

      if (!window.google?.accounts?.id || !googleButtonRef.current) {
        attempts += 1;

        if (attempts >= 40) {
          clearInterval(intervalId);
          setErrorMsg(
            'Google Sign-In failed to load. Refresh the page and try again.'
          );
        }
        return;
      }

      try {
        initialized = true;

        const success = initGoogleIdentityServices({
          onCredentialResponse: (user) => {
            setIsLoading(false);

            if (!user?.email) {
              setErrorMsg('Google did not return a verified user.');
              return;
            }

            callbackRef.current.onLoginSuccess?.(user);
          },
          onError: (error) => {
            setIsLoading(false);
            setErrorMsg(
              typeof error === 'string'
                ? error
                : error?.message || 'Google sign-in failed. Please try again.'
            );
          },
        });

        if (!success) {
          initialized = false;
          setErrorMsg('Could not initialize Google Sign-In.');
          return;
        }

        googleButtonRef.current.replaceChildren();

        window.google.accounts.id.renderButton(
          googleButtonRef.current,
          {
            theme: 'outline',
            size: 'large',
            text: 'signin_with',
            shape: 'rectangular',
            width: Math.min(
              320,
              googleButtonRef.current.parentElement?.clientWidth || 320
            ),
            locale: 'en',
          }
        );

        clearInterval(intervalId);
        setErrorMsg('');
      } catch (error) {
        initialized = false;
        console.error('Google initialization failed:', error);
        setErrorMsg('Unable to initialize Google Sign-In.');
      }
    };

    initialize();
    intervalId = setInterval(initialize, 250);

    return () => {
      active = false;
      clearInterval(intervalId);
    };
  }, [clientId]);

  return (
    <div className="min-h-screen bg-[#F8FAFC] text-slate-800 flex flex-col items-center justify-center p-4 font-sans">
      <div className="flex flex-col items-center mb-6 text-center">
        <div className="flex items-center justify-center w-11 h-11 rounded-xl bg-white border border-slate-200 shadow-sm mb-3">
          <Shield className="w-6 h-6 text-slate-800" />
        </div>

        <h1 className="text-2xl font-bold tracking-tight text-slate-900">
          MAVERICK
        </h1>

        <p className="text-xs text-slate-500 mt-1 leading-relaxed text-center max-w-[280px]">
          AI-Powered Email Threat Detection &amp; Forensic Intelligence
        </p>
      </div>

      <div className="w-full max-w-[380px] rounded-xl bg-white border border-slate-200 shadow-sm p-6 sm:p-7 space-y-5">
        <div className="text-center space-y-1">
          <h2 className="text-lg font-bold text-slate-900">Welcome</h2>
          <p className="text-xs text-slate-500 leading-normal">
            Secure access to your forensic security dashboard.
          </p>
        </div>

        {errorMsg && (
          <div
            role="alert"
            className="p-3 rounded-lg bg-red-50 border border-red-200 flex items-start gap-2 text-xs text-red-700"
          >
            <AlertCircle className="w-4 h-4 text-red-500 shrink-0 mt-0.5" />
            <span>{errorMsg}</span>
          </div>
        )}

        <div className="space-y-4">
          <div
            ref={googleButtonRef}
            className="flex w-full justify-center"
            style={{ minHeight: 46 }}
          />

          {isLoading && (
            <div className="flex items-center justify-center gap-2 text-sm text-slate-600">
              <Loader2 className="w-4 h-4 animate-spin" />
              <span>Signing in with Google...</span>
            </div>
          )}

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
