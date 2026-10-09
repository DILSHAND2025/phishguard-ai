import React, { Component } from 'react';
import { Shield, RefreshCw, Home, AlertCircle } from 'lucide-react';

export class ErrorBoundary extends Component {
  constructor(props) {
    super(props);
    this.state = { hasError: false, error: null };
  }

  static getDerivedStateFromError(error) {
    return { hasError: true, error };
  }

  componentDidCatch(error, errorInfo) {
    if (import.meta.env.DEV) {
      console.error('[MAVERICK ErrorBoundary] Uncaught runtime exception:', error, errorInfo);
    } else {
      // In production, log only high-level sanitized error type
      console.error('[MAVERICK ErrorBoundary] Runtime issue caught:', error?.name || 'Error');
    }
  }

  handleRetry = () => {
    this.setState({ hasError: false, error: null });
  };

  handleGoHome = () => {
    this.setState({ hasError: false, error: null });
    if (typeof window !== 'undefined') {
      window.location.href = '/';
    }
  };

  render() {
    if (this.state.hasError) {
      const isDev = Boolean(import.meta.env.DEV);
      const safeMessage = isDev && this.state.error?.message
        ? this.state.error.message
        : 'A temporary error occurred while rendering this view. You can retry loading or return to the main dashboard.';

      return (
        <div className="min-h-screen bg-[#F8FAFC] text-slate-800 flex flex-col items-center justify-center p-6 font-sans">
          <div className="w-full max-w-md rounded-2xl bg-white border border-slate-200 p-8 shadow-lg text-center space-y-5">
            <div className="inline-flex items-center justify-center w-14 h-14 rounded-2xl bg-red-50 border border-red-200 text-red-600 mx-auto">
              <Shield className="w-7 h-7" />
            </div>
            
            <div className="space-y-1.5">
              <h1 className="text-xl font-bold tracking-tight text-slate-900">MAVERICK</h1>
              <p className="text-sm text-slate-600">
                Something went wrong while loading the application.
              </p>
              <p className="text-xs text-slate-500 max-w-sm mx-auto leading-relaxed pt-1">
                {safeMessage}
              </p>
            </div>

            {isDev && this.state.error?.stack && (
              <details className="text-left text-[11px] bg-slate-50 p-3 rounded-lg border border-slate-200 text-slate-600 font-mono overflow-auto max-h-36">
                <summary className="cursor-pointer font-semibold text-slate-800 mb-1 flex items-center gap-1.5">
                  <AlertCircle className="w-3.5 h-3.5 text-amber-500" />
                  <span>Developer Diagnostics</span>
                </summary>
                <pre className="whitespace-pre-wrap">{this.state.error.stack}</pre>
              </details>
            )}

            <div className="pt-2 flex flex-col sm:flex-row items-center justify-center gap-2.5">
              <button
                type="button"
                onClick={this.handleRetry}
                className="w-full sm:w-auto inline-flex items-center justify-center gap-2 px-5 py-2.5 rounded-xl bg-cyan-600 hover:bg-cyan-500 text-white text-sm font-semibold transition-colors cursor-pointer shadow-xs"
              >
                <RefreshCw className="w-4 h-4" />
                <span>Retry</span>
              </button>
              <button
                type="button"
                onClick={this.handleGoHome}
                className="w-full sm:w-auto inline-flex items-center justify-center gap-2 px-4 py-2.5 rounded-xl bg-white hover:bg-slate-50 border border-slate-200 text-slate-700 text-sm font-semibold transition-colors cursor-pointer shadow-2xs"
              >
                <Home className="w-4 h-4 text-slate-500" />
                <span>Return to Dashboard</span>
              </button>
            </div>
          </div>
        </div>
      );
    }

    return this.props.children;
  }
}

