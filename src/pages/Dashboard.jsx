import React, { useState, useEffect } from 'react';
import { 
  ShieldCheck, 
  ShieldAlert, 
  MailWarning, 
  Zap, 
  ChevronRight, 
  ClipboardList, 
  AlertTriangle,
  Flame,
  CheckCircle2,
  Database
} from 'lucide-react';
import { StatCard } from '../components/dashboard/StatCard';
import { ThreatVelocityChart } from '../components/dashboard/ThreatVelocityChart';
import { IncidentQueueTable } from '../components/dashboard/IncidentQueueTable';
import { MitreMatrixSummary } from '../components/dashboard/MitreMatrixSummary';
import { LiveThreatStream } from '../components/dashboard/LiveThreatStream';
import { fetchCaseStats } from '../services/caseStore';

export const Dashboard = ({ onViewChange, onOpenScan, onInspectEmail, onSelectCase, currentAnalysis }) => {
  const [activeDeckTab, setActiveDeckTab] = useState('queue');
  const [dbStats, setDbStats] = useState({
    totalCases: 0,
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    topThreats: []
  });

  // Fetch real database case statistics
  useEffect(() => {
    let isMounted = true;
    async function loadStats() {
      const stats = await fetchCaseStats();
      if (isMounted && stats) {
        setDbStats(stats);
      }
    }
    loadStats();
    return () => { isMounted = false; };
  }, [currentAnalysis]);

  return (
    <div className="space-y-6 pb-16 font-sans">
      
      {/* Modern SOC Hero Banner — Clean White Card */}
      <div className="rounded-2xl bg-white border border-slate-200 p-6 sm:p-7 shadow-2xs">
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-5">
          <div className="space-y-2">
            <div className="flex flex-wrap items-center gap-2.5">
              <span className="flex items-center gap-1.5 px-2.5 py-0.5 rounded-full bg-cyan-50 border border-cyan-200 text-cyan-800 text-xs font-mono font-medium">
                <span className="w-2 h-2 rounded-full bg-cyan-600"></span>
                <span>SYSTEM ACTIVE</span>
              </span>
              <span className="text-xs text-slate-500 font-mono">
                Case DB: {dbStats.isDbUnavailable ? (
                  <strong className="text-amber-700 font-semibold">Gateway Unreachable</strong>
                ) : (
                  <strong className="text-emerald-700 font-semibold">PostgreSQL Active</strong>
                )}
              </span>
              <span className={`text-xs font-mono ${dbStats.isDbUnavailable ? 'text-amber-600' : 'text-slate-400'}`}>
                • {dbStats.isDbUnavailable ? 'Persistence Offline' : `${dbStats.totalCases} Persistent Cases`}
              </span>
            </div>

            <h1 className="text-xl sm:text-2xl font-bold tracking-tight text-slate-900">
              MAVERICK Threat Intelligence Hub
            </h1>

            <p className="text-xs sm:text-sm text-slate-600 max-w-2xl leading-relaxed">
              Autonomous deep-learning email perimeter defense backed by PostgreSQL case storage. Inspects RFC headers, extracts IOCs, models multi-hop infrastructure, and generates certifiable forensic dossiers.
            </p>
          </div>

          {/* Action CTAs */}
          <div className="flex flex-wrap items-center gap-2.5 shrink-0 self-start lg:self-auto">
            <button
              onClick={onOpenScan}
              className="flex items-center gap-2 px-4 py-2.5 rounded-xl bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-semibold shadow-xs transition-all cursor-pointer active:scale-95"
            >
              <Zap className="w-4 h-4 fill-current" />
              <span>Ingest & Scan Email</span>
            </button>

            <button
              onClick={() => onViewChange('investigation-case')}
              className="flex items-center gap-1.5 px-4 py-2.5 rounded-xl bg-slate-50 hover:bg-slate-100 border border-slate-200 text-slate-700 text-xs font-semibold transition-all cursor-pointer"
            >
              <ClipboardList className="w-4 h-4 text-cyan-600" />
              <span>Incident Queue</span>
              <ChevronRight className="w-3.5 h-3.5 text-slate-400" />
            </button>
          </div>
        </div>

        {/* Real-time Sub-metrics */}
        <div className="mt-5 pt-3 border-t border-slate-100 flex flex-wrap items-center justify-between gap-3 text-xs text-slate-600 font-mono">
          <div className="flex items-center gap-4 flex-wrap">
            <span>Critical: <strong className="text-red-600">{dbStats.critical}</strong></span>
            <span className="text-slate-300">|</span>
            <span>High: <strong className="text-orange-600">{dbStats.high}</strong></span>
            <span className="text-slate-300">|</span>
            <span>Medium: <strong className="text-amber-600">{dbStats.medium}</strong></span>
            <span className="text-slate-300">|</span>
            <span>Low: <strong className="text-emerald-600">{dbStats.low}</strong></span>
          </div>
          <div className="text-slate-400 text-[11px]">
            Database Sync: Live PostgreSQL
          </div>
        </div>
      </div>

      {/* REAL DATABASE STATS KPI CARDS (Requirement 5 & 14) */}
      <div className="grid grid-cols-2 sm:grid-cols-3 xl:grid-cols-5 gap-3.5">
        <StatCard
          title="TOTAL CASES"
          value={String(dbStats.totalCases)}
          subValue="Stored"
          change="Real DB Data"
          trend="up"
          icon={Database}
          accentColor="cyan"
          highlightTag="PostgreSQL"
        />
        <StatCard
          title="CRITICAL"
          value={String(dbStats.critical)}
          subValue="80-100"
          change="Immediate Action"
          trend="up"
          icon={ShieldAlert}
          accentColor="red"
          highlightTag="P1"
        />
        <StatCard
          title="HIGH"
          value={String(dbStats.high)}
          subValue="60-79"
          change="Elevated Risk"
          trend="up"
          icon={MailWarning}
          accentColor="orange"
          highlightTag="P2"
        />
        <StatCard
          title="MEDIUM"
          value={String(dbStats.medium)}
          subValue="30-59"
          change="Suspicious"
          trend="neutral"
          icon={AlertTriangle}
          accentColor="amber"
          highlightTag="P3"
        />
        <StatCard
          title="LOW"
          value={String(dbStats.low)}
          subValue="0-29"
          change="Benign"
          trend="down"
          icon={ShieldCheck}
          accentColor="emerald"
          highlightTag="P4"
        />
      </div>

      {/* Visual Analytics & TOP THREATS Widget (Requirement 6 & 15) */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-5">
        
        {/* Left 2 Cols: Threat Velocity Chart */}
        <div className="lg:col-span-2">
          <ThreatVelocityChart />
        </div>

        {/* Right Col: TOP THREATS (Requirement 6) */}
        <div className="lg:col-span-1 rounded-2xl bg-white border border-slate-200 p-5 space-y-3.5 shadow-2xs flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between border-b border-slate-100 pb-3">
              <div className="flex items-center gap-2">
                <Flame className="w-4 h-4 text-red-500" />
                <h3 className="text-xs font-mono font-bold uppercase tracking-wider text-slate-900">
                  TOP THREATS
                </h3>
              </div>
              <span className="text-[10px] font-mono text-slate-500">
                Sorted by threatScore DESC
              </span>
            </div>

            {dbStats.topThreats && dbStats.topThreats.length > 0 ? (
              <div className="space-y-2 mt-3">
                {dbStats.topThreats.map((threat, idx) => {
                  const score = threat.threatScore;
                  const isCrit = score >= 80;
                  const isHigh = score >= 60;
                  const isMed = score >= 30;

                  const badgeStyle = isCrit
                    ? 'bg-red-50 text-red-700 border-red-200'
                    : isHigh
                      ? 'bg-orange-50 text-orange-700 border-orange-200'
                      : isMed
                        ? 'bg-amber-50 text-amber-700 border-amber-200'
                        : 'bg-emerald-50 text-emerald-700 border-emerald-200';

                  const dotColor = isCrit ? 'bg-red-500' : isHigh ? 'bg-orange-500' : isMed ? 'bg-amber-500' : 'bg-emerald-500';
                  const priorityLabel = isCrit ? 'Critical' : isHigh ? 'High' : isMed ? 'Medium' : 'Low';

                  return (
                    <div
                      key={threat.caseId || idx}
                      onClick={() => {
                        if (onSelectCase) onSelectCase(threat);
                        onViewChange('investigation-case');
                      }}
                      className="p-2.5 rounded-xl bg-white hover:bg-slate-50 border border-slate-200/80 transition-all cursor-pointer flex items-center justify-between gap-3 group shadow-2xs"
                    >
                      <div className="flex items-center gap-2.5 min-w-0">
                        <span className="text-xs font-mono font-bold text-slate-400 w-4">
                          {idx + 1}.
                        </span>
                        <span className={`w-2 h-2 rounded-full ${dotColor} shrink-0`}></span>
                        <div className="min-w-0">
                          <div className="text-xs font-semibold text-slate-800 group-hover:text-cyan-700 transition-colors truncate">
                            {threat.subject || threat.classification || 'Threat Case'}
                          </div>
                          <div className="text-[10px] font-mono text-slate-500 truncate">
                            {threat.caseId} • {threat.classification || priorityLabel}
                          </div>
                        </div>
                      </div>

                      <div className="shrink-0 text-right font-mono">
                        <span className={`text-xs font-bold px-2 py-0.5 rounded border ${badgeStyle}`}>
                          Score {threat.threatScore}
                        </span>
                      </div>
                    </div>
                  );
                })}
              </div>
            ) : (
              <div className="py-8 text-center text-xs text-slate-500 space-y-2">
                <CheckCircle2 className="w-6 h-6 text-emerald-600 mx-auto" />
                <p>No high-risk threats currently stored in database.</p>
                <button
                  onClick={() => onViewChange('email-analysis')}
                  className="text-xs text-cyan-600 hover:underline font-mono"
                >
                  Scan an email to test
                </button>
              </div>
            )}
          </div>

          <div className="pt-2 border-t border-slate-100 mt-3">
            <button
              onClick={() => onViewChange('investigation-case')}
              className="w-full py-2 rounded-xl bg-slate-50 hover:bg-slate-100 text-center text-xs text-cyan-700 font-semibold transition-colors cursor-pointer flex items-center justify-center gap-1 border border-slate-200"
            >
              <span>View Full Case Priority Queue</span>
              <ChevronRight className="w-3.5 h-3.5" />
            </button>
          </div>
        </div>

      </div>

      {/* Operations Deck — Clean White Card */}
      <div className="rounded-2xl bg-white border border-slate-200 shadow-2xs overflow-hidden">
        
        {/* Operations Deck Tab Bar */}
        <div className="flex items-center justify-between px-4 border-b border-slate-200 bg-slate-50/70 overflow-x-auto text-xs">
          <div className="flex items-center gap-1">
            <button
              onClick={() => setActiveDeckTab('queue')}
              className={`py-3 px-3.5 font-medium border-b-2 transition-all cursor-pointer whitespace-nowrap ${
                activeDeckTab === 'queue'
                  ? 'border-cyan-600 text-cyan-800 font-semibold'
                  : 'border-transparent text-slate-500 hover:text-slate-800'
              }`}
            >
              Active Incident Queue
            </button>

            <button
              onClick={() => setActiveDeckTab('feed')}
              className={`py-3 px-3.5 font-medium border-b-2 transition-all cursor-pointer whitespace-nowrap ${
                activeDeckTab === 'feed'
                  ? 'border-cyan-600 text-cyan-800 font-semibold'
                  : 'border-transparent text-slate-500 hover:text-slate-800'
              }`}
            >
              Threat Stream
            </button>

            <button
              onClick={() => setActiveDeckTab('mitre')}
              className={`py-3 px-3.5 font-medium border-b-2 transition-all cursor-pointer whitespace-nowrap ${
                activeDeckTab === 'mitre'
                  ? 'border-cyan-600 text-cyan-800 font-semibold'
                  : 'border-transparent text-slate-500 hover:text-slate-800'
              }`}
            >
              MITRE ATT&CK Matrix
            </button>
          </div>
        </div>

        {/* Tab Content Panes */}
        <div className="p-4 sm:p-5">
          {activeDeckTab === 'queue' && (
            <IncidentQueueTable 
              onViewChange={onViewChange}
              onSelectCase={onSelectCase}
            />
          )}

          {activeDeckTab === 'feed' && (
            <LiveThreatStream 
              onInspectEmail={onInspectEmail}
              onViewChange={onViewChange}
            />
          )}

          {activeDeckTab === 'mitre' && (
            <MitreMatrixSummary />
          )}
        </div>

      </div>

    </div>
  );
};
