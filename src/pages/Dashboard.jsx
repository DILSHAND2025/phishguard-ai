import React, { useState, useEffect } from 'react';
import { 
  ShieldCheck, 
  ShieldAlert, 
  MailWarning, 
  Timer, 
  Zap, 
  ChevronRight, 
  Globe, 
  Radio, 
  ClipboardList, 
  Crosshair, 
  Fingerprint,
  AlertTriangle,
  Flame,
  CheckCircle2,
  Database
} from 'lucide-react';
import { StatCard } from '../components/dashboard/StatCard';
import { ThreatVelocityChart } from '../components/dashboard/ThreatVelocityChart';
import { AttackVectorChart } from '../components/dashboard/AttackVectorChart';
import { LiveThreatStream } from '../components/dashboard/LiveThreatStream';
import { IncidentQueueTable } from '../components/dashboard/IncidentQueueTable';
import { MitreMatrixSummary } from '../components/dashboard/MitreMatrixSummary';
import { ForensicGeoMap } from '../components/dashboard/ForensicGeoMap';
import { SOC_SUMMARY } from '../data/mockSocData';
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

  const defaultNodes = [
    {
      ip: '185.220.101.45',
      role: 'SOURCE',
      roleLabel: 'Source / Originating IP',
      country: 'Germany',
      countryCode: 'DE',
      region: 'Hesse',
      city: 'Frankfurt am Main',
      latitude: 50.1109,
      longitude: 8.6821,
      timezone: 'Europe/Berlin',
      asn: 'AS9009',
      asnOrg: 'M247 Ltd Europe',
      isp: 'M247 Europe S.R.L.',
      networkType: 'Tor Exit Node / Anonymizing Relay',
      isProxyOrVpn: true,
      dataSource: 'FORENSIC TELEMETRY',
      isDemo: false,
      observedEvidence: 'Observed IP 185.220.101.45 geolocates to Frankfurt am Main, Germany (AS9009 - M247 Europe)',
      inferredContext: 'Tor Exit Node / Anonymizing Relay repeatedly observed in credential harvesting campaigns'
    }
  ];

  const activeGeoRecords = (currentAnalysis?.geoList && currentAnalysis.geoList.length > 0)
    ? currentAnalysis.geoList
    : (currentAnalysis?.geoInfo ? [currentAnalysis.geoInfo] : defaultNodes);

  return (
    <div className="space-y-6 pb-16 font-sans">
      
      {/* Modern SOC Hero Banner */}
      <div className="relative overflow-hidden rounded-2xl bg-gradient-to-r from-[#0a1224] via-[#091120] to-[#070b14] border border-slate-800/80 p-6 shadow-sm">
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-5">
          <div className="space-y-2">
            <div className="flex flex-wrap items-center gap-2.5">
              <span className="flex items-center gap-1.5 px-2.5 py-0.5 rounded-full bg-cyan-950/70 border border-cyan-500/40 text-cyan-300 text-xs font-mono font-medium">
                <span className="w-2 h-2 rounded-full bg-cyan-400"></span>
                <span>DEFCON 2 ACTIVE</span>
              </span>
              <span className="text-xs text-slate-400 font-mono">
                Case DB: <strong className="text-emerald-400 flex-inline items-center gap-1">PostgreSQL Active</strong>
              </span>
              <span className="text-xs text-slate-400 font-mono">
                • {dbStats.totalCases} Persistent Cases
              </span>
            </div>

            <h1 className="text-xl sm:text-2xl font-bold tracking-tight text-white">
              MAVERICK Threat Intelligence Hub
            </h1>

            <p className="text-xs sm:text-sm text-slate-400 max-w-2xl leading-relaxed">
              Autonomous deep-learning email perimeter defense backed by PostgreSQL case storage. Inspects RFC headers, extracts IOCs, models multi-hop ASN infrastructure, and generates certifiable forensic dossiers.
            </p>
          </div>

          {/* Action CTAs */}
          <div className="flex flex-wrap items-center gap-2.5 shrink-0 self-start lg:self-auto">
            <button
              onClick={onOpenScan}
              className="flex items-center gap-2 px-4 py-2.5 rounded-xl bg-gradient-to-r from-cyan-600 to-blue-600 hover:from-cyan-500 hover:to-blue-500 text-white text-xs font-semibold shadow-md transition-all cursor-pointer active:scale-95"
            >
              <Zap className="w-4 h-4 fill-current" />
              <span>Ingest & Scan Email</span>
            </button>

            <button
              onClick={() => onViewChange('investigation-case')}
              className="flex items-center gap-1.5 px-4 py-2.5 rounded-xl bg-[#0d172e] hover:bg-[#122244] border border-slate-700 text-slate-300 text-xs font-semibold transition-all cursor-pointer"
            >
              <ClipboardList className="w-4 h-4 text-cyan-400" />
              <span>Incident Queue</span>
              <ChevronRight className="w-3.5 h-3.5" />
            </button>
          </div>
        </div>

        {/* Real-time Sub-metrics */}
        <div className="mt-5 pt-3 border-t border-slate-800/80 flex flex-wrap items-center justify-between gap-3 text-xs text-slate-400 font-mono">
          <div className="flex items-center gap-4 flex-wrap">
            <span>Critical Incidents: <strong className="text-red-400">{dbStats.critical}</strong></span>
            <span className="text-slate-700">|</span>
            <span>High Risk: <strong className="text-orange-400">{dbStats.high}</strong></span>
            <span className="text-slate-700">|</span>
            <span>Medium Risk: <strong className="text-amber-400">{dbStats.medium}</strong></span>
            <span className="text-slate-700">|</span>
            <span>Low Risk: <strong className="text-emerald-400">{dbStats.low}</strong></span>
          </div>
          <div className="text-slate-500 text-[11px]">
            Database Sync: Live PostgreSQL
          </div>
        </div>
      </div>

      {/* REAL DATABASE STATS KPI CARDS (Requirement 14) */}
      <div className="grid grid-cols-2 sm:grid-cols-3 xl:grid-cols-5 gap-3.5">
        <StatCard
          title="TOTAL CASES"
          value={String(dbStats.totalCases)}
          subValue="Stored Investigations"
          change="Real DB Data"
          trend="up"
          icon={Database}
          accentColor="cyan"
          highlightTag="PostgreSQL"
        />
        <StatCard
          title="CRITICAL"
          value={String(dbStats.critical)}
          subValue="Score 80-100"
          change="Immediate Action"
          trend="up"
          icon={ShieldAlert}
          accentColor="red"
          highlightTag="SOC Priority P1"
        />
        <StatCard
          title="HIGH"
          value={String(dbStats.high)}
          subValue="Score 60-79"
          change="Elevated Threat"
          trend="up"
          icon={MailWarning}
          accentColor="red"
          highlightTag="SOC Priority P2"
        />
        <StatCard
          title="MEDIUM"
          value={String(dbStats.medium)}
          subValue="Score 30-59"
          change="Suspicious Anomaly"
          trend="neutral"
          icon={AlertTriangle}
          accentColor="amber"
          highlightTag="SOC Priority P3"
        />
        <StatCard
          title="LOW"
          value={String(dbStats.low)}
          subValue="Score 0-29"
          change="Benign / Informational"
          trend="down"
          icon={ShieldCheck}
          accentColor="emerald"
          highlightTag="SOC Priority P4"
        />
      </div>

      {/* Visual Analytics & TOP THREATS Widget (Requirement 15) */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-5">
        
        {/* Left 2 Cols: Threat Velocity Chart */}
        <div className="lg:col-span-2">
          <ThreatVelocityChart />
        </div>

        {/* Right Col: TOP THREATS (Requirement 15) */}
        <div className="lg:col-span-1 rounded-2xl bg-[#0a1122] border border-slate-800 p-5 space-y-3.5 shadow-sm">
          <div className="flex items-center justify-between border-b border-slate-800 pb-3">
            <div className="flex items-center gap-2">
              <Flame className="w-4 h-4 text-red-400" />
              <h3 className="text-xs font-mono font-bold uppercase tracking-wider text-white">
                TOP THREATS
              </h3>
            </div>
            <span className="text-[10px] font-mono text-slate-500">
              Sorted by threatScore DESC
            </span>
          </div>

          {dbStats.topThreats && dbStats.topThreats.length > 0 ? (
            <div className="space-y-2.5">
              {dbStats.topThreats.map((threat, idx) => {
                const isCrit = threat.threatScore >= 80;
                const isHigh = threat.threatScore >= 60;
                const dotColor = isCrit ? 'bg-red-500' : isHigh ? 'bg-orange-500' : 'bg-amber-500';

                return (
                  <div
                    key={threat.caseId || idx}
                    onClick={() => {
                      if (onSelectCase) onSelectCase(threat);
                      onViewChange('investigation-case');
                    }}
                    className="p-2.5 rounded-xl bg-[#070b16] hover:bg-[#0e1a33] border border-slate-800/80 hover:border-slate-700 transition-all cursor-pointer flex items-center justify-between gap-3 group"
                  >
                    <div className="flex items-center gap-2.5 min-w-0">
                      <span className="text-xs font-mono font-bold text-slate-400 w-4">
                        {idx + 1}.
                      </span>
                      <span className={`w-2 h-2 rounded-full ${dotColor} shrink-0`}></span>
                      <div className="min-w-0">
                        <div className="text-xs font-semibold text-slate-200 group-hover:text-cyan-300 transition-colors truncate">
                          {threat.subject || threat.classification || 'Threat Case'}
                        </div>
                        <div className="text-[10px] font-mono text-slate-400 truncate">
                          {threat.caseId} • {threat.classification || 'Phishing'}
                        </div>
                      </div>
                    </div>

                    <div className="shrink-0 text-right font-mono">
                      <span className={`text-xs font-extrabold px-2 py-0.5 rounded border ${
                        isCrit 
                          ? 'bg-red-950/80 text-red-300 border-red-500/60' 
                          : 'bg-orange-950/80 text-orange-300 border-orange-500/60'
                      }`}>
                        Score {threat.threatScore}
                      </span>
                    </div>
                  </div>
                );
              })}
            </div>
          ) : (
            <div className="py-8 text-center text-xs text-slate-400 space-y-2">
              <CheckCircle2 className="w-6 h-6 text-emerald-400 mx-auto" />
              <p>No high-risk threats currently stored in database.</p>
              <button
                onClick={() => onViewChange('email-analysis')}
                className="text-xs text-cyan-400 hover:underline font-mono"
              >
                Scan an email to test
              </button>
            </div>
          )}

          <div className="pt-2 border-t border-slate-800/60">
            <button
              onClick={() => onViewChange('investigation-case')}
              className="w-full py-1.5 rounded-lg bg-[#070d1a] hover:bg-[#0f1d38] text-center text-xs text-cyan-400 font-mono transition-colors cursor-pointer flex items-center justify-center gap-1"
            >
              <span>View Full Case Priority Queue</span>
              <ChevronRight className="w-3.5 h-3.5" />
            </button>
          </div>
        </div>

      </div>

      {/* Operations Deck */}
      <div className="rounded-2xl bg-[#091122]/70 border border-slate-800/80 shadow-md overflow-hidden">
        
        {/* Operations Deck Tab Bar */}
        <div className="flex items-center justify-between px-4 border-b border-slate-800/80 bg-[#070e1c] overflow-x-auto text-xs">
          <div className="flex items-center gap-1">
            <button
              type="button"
              onClick={() => setActiveDeckTab('queue')}
              className={`flex items-center gap-2 py-3 px-3.5 border-b-2 font-medium transition-all cursor-pointer whitespace-nowrap ${
                activeDeckTab === 'queue'
                  ? 'border-cyan-400 text-cyan-300 font-semibold'
                  : 'border-transparent text-slate-400 hover:text-slate-200'
              }`}
            >
              <ClipboardList className="w-3.5 h-3.5" />
              <span>Active Incident Queue ({dbStats.totalCases})</span>
            </button>

            <button
              type="button"
              onClick={() => setActiveDeckTab('geo')}
              className={`flex items-center gap-2 py-3 px-3.5 border-b-2 font-medium transition-all cursor-pointer whitespace-nowrap ${
                activeDeckTab === 'geo'
                  ? 'border-cyan-400 text-cyan-300 font-semibold'
                  : 'border-transparent text-slate-400 hover:text-slate-200'
              }`}
            >
              <Globe className="w-3.5 h-3.5" />
              <span>Global Egress Map</span>
            </button>

            <button
              type="button"
              onClick={() => setActiveDeckTab('stream')}
              className={`flex items-center gap-2 py-3 px-3.5 border-b-2 font-medium transition-all cursor-pointer whitespace-nowrap ${
                activeDeckTab === 'stream'
                  ? 'border-cyan-400 text-cyan-300 font-semibold'
                  : 'border-transparent text-slate-400 hover:text-slate-200'
              }`}
            >
              <Radio className="w-3.5 h-3.5 text-red-400" />
              <span>Live Threat Stream</span>
            </button>

            <button
              type="button"
              onClick={() => setActiveDeckTab('mitre')}
              className={`flex items-center gap-2 py-3 px-3.5 border-b-2 font-medium transition-all cursor-pointer whitespace-nowrap ${
                activeDeckTab === 'mitre'
                  ? 'border-cyan-400 text-cyan-300 font-semibold'
                  : 'border-transparent text-slate-400 hover:text-slate-200'
              }`}
            >
              <Crosshair className="w-3.5 h-3.5" />
              <span>MITRE ATT&CK Matrix</span>
            </button>
          </div>

          <span className="text-[11px] font-mono text-slate-500 hidden sm:inline">
            SOC Operations Deck • PostgreSQL Backed
          </span>
        </div>

        {/* Tab Viewport */}
        <div className="p-4 sm:p-5">
          {activeDeckTab === 'queue' && (
            <IncidentQueueTable 
              onViewChange={onViewChange}
              onSelectCase={onSelectCase}
            />
          )}

          {activeDeckTab === 'geo' && (
            <ForensicGeoMap 
              geoRecords={activeGeoRecords}
              title="FORENSIC GEOLOCATION"
              subtitle="Multi-Hop Network Egress & Phishing Infrastructure Topology"
            />
          )}

          {activeDeckTab === 'stream' && (
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
