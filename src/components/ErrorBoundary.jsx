import React, { Component } from 'react';
import { Shield, RefreshCw } from 'lucide-react';

export class ErrorBoundary extends Component {
  constructor(props) {
    super(props);
    this.state = { hasError: false, error: null };
  }

  static getDerivedStateFromError(error) {
    return { hasError: true, error };
  }

  componentDidCatch(error, errorInfo) {
    console.error('[MAVERICK ErrorBoundary] Uncaught runtime exception:', error, errorInfo);
  }

  handleRetry = () => {
    this.setState({ hasError: false, error: null });
    window.location.reload();
  };

  render() {
    if (this.state.hasError) {
      return (
        <div className="min-h-screen bg-[#070b13] text-slate-100 flex flex-col items-center justify-center p-6 font-sans">
          <div className="w-full max-w-md rounded-2xl bg-[#0c121e] border border-red-500/30 p-8 shadow-2xl text-center space-y-5">
            <div className="inline-flex items-center justify-center w-14 h-14 rounded-2xl bg-red-950/40 border border-red-500/40 text-red-400 mx-auto">
              <Shield className="w-7 h-7" />
            </div>
            
            <div className="space-y-1">
              <h1 className="text-xl font-bold tracking-wider text-white">MAVERICK</h1>
              <p className="text-sm text-slate-300">
                Something went wrong while loading the application.
              </p>
            </div>

            <div className="pt-2">
              <button
                type="button"
                onClick={this.handleRetry}
                className="inline-flex items-center gap-2 px-5 py-2.5 rounded-xl bg-cyan-600 hover:bg-cyan-500 text-white text-sm font-semibold transition-colors cursor-pointer shadow-lg shadow-cyan-900/30"
              >
                <RefreshCw className="w-4 h-4" />
                <span>Retry</span>
              </button>
            </div>
          </div>
        </div>
      );
    }

    return this.props.children;
  }
}
