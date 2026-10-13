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
  const [loadingStats, setLoadingStats] = useState(true);
  const [statsError, setStatsError] = useState(null);
  const [dbStats, setDbStats] = useState({
    totalCases: 0,
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    openCases: 0,
    closedCases: 0,
    phishingDetections: 0,
    suspiciousDetections: 0,
    legitimateDetections: 0,
    severityDistribution: { critical: 0, high: 0, medium: 0, low: 0 },
    recentActivity: [],
    topThreats: []
  });

  // Fetch real database case statistics
  useEffect(() => {
    let isMounted = true;
    async function loadStats() {
      setLoadingStats(true);
      setStatsError(null);
      try {
        const stats = await fetchCaseStats();
        if (isMounted && stats) {
          setDbStats(stats);
          if (stats.isDbUnavailable) {
            setStatsError('PostgreSQL database is offline or unconfigured. Real-time local fallback active.');
          }
        }
      } catch (err) {
        if (isMounted) {
          setStatsError('Unable to load database metrics: ' + err.message);
        }
      } finally {
        if (isMounted) setLoadingStats(false);
      }
    }
    loadStats();
    return () => { isMounted = false; };
  }, [currentAnalysis]);

  // Compute severity distribution percentages for the real distribution bar
  const totalForBar = dbStats.totalCases || 0;
  const critPct = totalForBar > 0 ? Math.round((dbStats.critical / totalForBar) * 100) : 0;
  const highPct = totalForBar > 0 ? Math.round((dbStats.high / totalForBar) * 100) : 0;
  const medPct = totalForBar > 0 ? Math.round((dbStats.medium / totalForBar) * 100) : 0;
  const lowPct = totalForBar > 0 ? Math.max(0, 100 - critPct - highPct - medPct) : 0;

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
                • {dbStats.isDbUnavailable ? 'Local Persistence' : `${dbStats.totalCases} Stored Cases`}
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
            Database Sync: {dbStats.isDbUnavailable ? 'Offline' : 'Live PostgreSQL'}
          </div>
        </div>
      </div>

      {/* Database Error State Banner */}
      {statsError && (
        <div className="rounded-xl bg-amber-50 border border-amber-200 p-4 text-xs text-amber-800 flex items-start gap-3 shadow-2xs">
          <AlertTriangle className="w-5 h-5 text-amber-600 shrink-0 mt-0.5" />
          <div className="space-y-1">
            <div className="font-semibold text-amber-900">Database Synchronization Notice</div>
            <p className="text-amber-800 leading-relaxed">{statsError}</p>
          </div>
        </div>
      )}

      {/* REAL DATABASE STATS KPI CARDS (Requirement 4) */}
      <div className="grid grid-cols-2 sm:grid-cols-3 xl:grid-cols-5 gap-3.5">
        <StatCard
          title="SCAN TOTALS"
          value={loadingStats ? '...' : String(dbStats.totalCases)}
          subValue="Scanned & Stored"
          change="Real DB Data"
          trend="up"
          icon={Database}
          accentColor="cyan"
          highlightTag="PostgreSQL"
        />
        <StatCard
          title="PHISHING DETECTIONS"
          value={loadingStats ? '...' : String(dbStats.phishingDetections ?? (dbStats.critical + dbStats.high))}
          subValue="Malicious / BEC"
          change="Real Verdicts"
          trend="up"
          icon={ShieldAlert}
          accentColor="red"
          highlightTag="P1/P2"
        />
        <StatCard
          title="OPEN CASES"
          value={loadingStats ? '...' : String(dbStats.openCases ?? dbStats.totalCases)}
          subValue="Active Incidents"
          change="In Triage"
          trend="up"
          icon={MailWarning}
          accentColor="orange"
          highlightTag="Queue"
        />
        <StatCard
          title="MEDIUM ANOMALIES"
          value={loadingStats ? '...' : String(dbStats.medium)}
          subValue="Score 30-59"
          change="Suspicious"
          trend="neutral"
          icon={AlertTriangle}
          accentColor="amber"
          highlightTag="P3"
        />
        <StatCard
          title="BENIGN EMAILS"
          value={loadingStats ? '...' : String(dbStats.legitimateDetections ?? dbStats.low)}
          subValue="Clean Communication"
          change="Legitimate"
          trend="down"
          icon={ShieldCheck}
          accentColor="emerald"
          highlightTag="P4"
        />
      </div>

      {/* SEVERITY DISTRIBUTION BAR (Requirement 4) */}
      <div className="rounded-xl bg-white border border-slate-200 p-4 shadow-2xs space-y-2.5">
        <div className="flex items-center justify-between text-xs">
          <span className="font-bold uppercase tracking-wider font-mono text-slate-700">
            Database Threat Severity Distribution
          </span>
          <span className="font-mono text-slate-500">
            {totalForBar} Total Cases Evaluated
          </span>
        </div>

        {totalForBar > 0 ? (
          <div className="space-y-2">
            <div className="w-full h-3 rounded-full bg-slate-100 flex overflow-hidden">
              {critPct > 0 && (
                <div style={{ width: `${critPct}%` }} className="bg-red-500 transition-all" title={`Critical: ${dbStats.critical} (${critPct}%)`} />
              )}
              {highPct > 0 && (
                <div style={{ width: `${highPct}%` }} className="bg-orange-500 transition-all" title={`High: ${dbStats.high} (${highPct}%)`} />
              )}
              {medPct > 0 && (
                <div style={{ width: `${medPct}%` }} className="bg-amber-400 transition-all" title={`Medium: ${dbStats.medium} (${medPct}%)`} />
              )}
              {lowPct > 0 && (
                <div style={{ width: `${lowPct}%` }} className="bg-emerald-500 transition-all" title={`Low: ${dbStats.low} (${lowPct}%)`} />
              )}
            </div>

            <div className="flex items-center justify-between text-[11px] font-mono text-slate-600 flex-wrap gap-2 pt-0.5">
              <span className="flex items-center gap-1.5"><span className="w-2 h-2 rounded-full bg-red-500"></span>Critical: {dbStats.critical} ({critPct}%)</span>
              <span className="flex items-center gap-1.5"><span className="w-2 h-2 rounded-full bg-orange-500"></span>High: {dbStats.high} ({highPct}%)</span>
              <span className="flex items-center gap-1.5"><span className="w-2 h-2 rounded-full bg-amber-400"></span>Medium: {dbStats.medium} ({medPct}%)</span>
              <span className="flex items-center gap-1.5"><span className="w-2 h-2 rounded-full bg-emerald-500"></span>Low / Clean: {dbStats.low} ({lowPct}%)</span>
            </div>
          </div>
        ) : (
          /* Empty State when no cases stored */
          <div className="p-3 rounded-lg bg-slate-50 text-xs text-slate-500 text-center flex items-center justify-center gap-2">
            <CheckCircle2 className="w-4 h-4 text-slate-400" />
            <span>No cases stored in database yet. Ingest an email or run a threat scan to view real severity distribution.</span>
          </div>
        )}
      </div>

      {/* Visual Analytics & TOP THREATS Widget (Requirement 4 & 6) */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-5">
        
        {/* Left 2 Cols: Threat Velocity Chart */}
        <div className="lg:col-span-2">
          <ThreatVelocityChart 
            loading={loadingStats}
            error={statsError}
            dbStats={dbStats}
          />
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

            <button
              onClick={() => setActiveDeckTab('recent')}
              className={`py-3 px-3.5 font-medium border-b-2 transition-all cursor-pointer whitespace-nowrap ${
                activeDeckTab === 'recent'
                  ? 'border-cyan-600 text-cyan-800 font-semibold'
                  : 'border-transparent text-slate-500 hover:text-slate-800'
              }`}
            >
              Recent Activity ({Array.isArray(dbStats.recentActivity) ? dbStats.recentActivity.length : 0})
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

          {activeDeckTab === 'recent' && (
            <div className="space-y-3 font-sans">
              <div className="flex items-center justify-between border-b border-slate-100 pb-2">
                <div>
                  <h4 className="text-xs font-bold uppercase tracking-wider text-slate-900 font-mono">
                    Recent Database Ingestions & Analysis Activity
                  </h4>
                  <p className="text-[11px] text-slate-500">
                    Audit trail of newly analyzed messages stored in PostgreSQL
                  </p>
                </div>
              </div>

              {Array.isArray(dbStats.recentActivity) && dbStats.recentActivity.length > 0 ? (
                <div className="divide-y divide-slate-100">
                  {dbStats.recentActivity.map((item, idx) => {
                    const sc = item.threatScore ?? 0;
                    const isCrit = sc >= 80;
                    const isHigh = sc >= 60;
                    const isMed = sc >= 30;

                    return (
                      <div
                        key={item.caseId || idx}
                        onClick={() => {
                          if (onSelectCase) onSelectCase(item);
                          onViewChange('investigation-case');
                        }}
                        className="py-3 flex flex-col sm:flex-row sm:items-center justify-between gap-3 hover:bg-slate-50/80 p-2 rounded-xl transition-colors cursor-pointer group"
                      >
                        <div className="flex items-start gap-3 min-w-0">
                          <span className={`w-2.5 h-2.5 rounded-full mt-1.5 shrink-0 ${
                            isCrit ? 'bg-red-500' : isHigh ? 'bg-orange-500' : isMed ? 'bg-amber-500' : 'bg-emerald-500'
                          }`} />
                          <div className="min-w-0">
                            <div className="text-xs font-semibold text-slate-900 group-hover:text-cyan-700 transition-colors truncate">
                              {item.subject || '(No Subject)'}
                            </div>
                            <div className="text-[11px] text-slate-500 font-mono flex items-center gap-2 mt-0.5">
                              <span>{item.caseId}</span>
                              <span>•</span>
                              <span className="truncate max-w-xs">{item.sender}</span>
                            </div>
                          </div>
                        </div>

                        <div className="flex items-center gap-3 shrink-0 self-end sm:self-auto font-mono text-xs">
                          <span className={`px-2 py-0.5 rounded font-bold border ${
                            isCrit ? 'bg-red-50 text-red-700 border-red-200' :
                            isHigh ? 'bg-orange-50 text-orange-700 border-orange-200' :
                            isMed ? 'bg-amber-50 text-amber-800 border-amber-200' :
                            'bg-emerald-50 text-emerald-700 border-emerald-200'
                          }`}>
                            Score {sc}
                          </span>
                          <span className="text-slate-400 text-[11px]">
                            {item.analyzedAt ? new Date(item.analyzedAt).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }) : 'Recent'}
                          </span>
                          <ChevronRight className="w-4 h-4 text-slate-300 group-hover:text-cyan-600 transition-colors" />
                        </div>
                      </div>
                    );
                  })}
                </div>
              ) : (
                <div className="py-12 text-center text-xs text-slate-400 space-y-2">
                  <CheckCircle2 className="w-6 h-6 text-slate-300 mx-auto" />
                  <p>No recent activity recorded yet in the database.</p>
                </div>
              )}
            </div>
          )}
        </div>

      </div>

    </div>
  );
};
