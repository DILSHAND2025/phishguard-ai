import React from 'react';
import { 
  ShieldCheck, 
  ShieldAlert, 
  MailWarning, 
  Timer, 
  Terminal, 
  Sparkles, 
  Zap, 
  Radio, 
  Flame, 
  ChevronRight,
  TrendingUp,
  Fingerprint
} from 'lucide-react';
import { StatCard } from '../components/dashboard/StatCard';
import { ThreatVelocityChart } from '../components/dashboard/ThreatVelocityChart';
import { AttackVectorChart } from '../components/dashboard/AttackVectorChart';
import { LiveThreatStream } from '../components/dashboard/LiveThreatStream';
import { IncidentQueueTable } from '../components/dashboard/IncidentQueueTable';
import { MitreMatrixSummary } from '../components/dashboard/MitreMatrixSummary';
import { ForensicGeoMap } from '../components/dashboard/ForensicGeoMap';
import { SOC_SUMMARY } from '../data/mockSocData';

export const Dashboard = ({ onViewChange, onOpenScan, onInspectEmail, onSelectCase, currentAnalysis }) => {
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
      dataSource: 'DEMO / SYNTHETIC DATA',
      isDemo: true,
      observedEvidence: 'Observed IP 185.220.101.45 geolocates to Frankfurt am Main, Germany (AS9009 - M247 Europe)',
      inferredContext: 'Tor Exit Node / Anonymizing Relay repeatedly observed in credential harvesting campaigns'
    },
    {
      ip: '45.154.255.82',
      role: 'URL_HOST',
      roleLabel: 'URL / Phishing Infrastructure IP',
      country: 'Netherlands',
      countryCode: 'NL',
      region: 'North Holland',
      city: 'Amsterdam',
      latitude: 52.3676,
      longitude: 4.9041,
      timezone: 'Europe/Amsterdam',
      asn: 'AS202425',
      asnOrg: 'IP Volume Inc',
      isp: 'IP Volume Networks',
      networkType: 'Commercial Hosting / Fast-Flux Proxy',
      isProxyOrVpn: true,
      dataSource: 'DEMO / SYNTHETIC DATA',
      isDemo: true,
      observedEvidence: 'Observed IP 45.154.255.82 geolocates to Amsterdam, Netherlands (AS202425 - IP Volume Networks)',
      inferredContext: 'Commercial hosting infrastructure hosting lookalike financial credential portals'
    },
    {
      ip: '194.26.29.110',
      role: 'MAIL_SERVER',
      roleLabel: 'Email Server / Transit Hop',
      country: 'Romania',
      countryCode: 'RO',
      region: 'Bucharest',
      city: 'Bucharest',
      latitude: 44.4268,
      longitude: 26.1025,
      timezone: 'Europe/Bucharest',
      asn: 'AS48693',
      asnOrg: 'HostRoyale Egress Relay',
      isp: 'HostRoyale Ltd',
      networkType: 'Intermediate Transit Relay',
      isProxyOrVpn: false,
      dataSource: 'DEMO / SYNTHETIC DATA',
      isDemo: true,
      observedEvidence: 'Observed IP 194.26.29.110 geolocates to Bucharest, Romania (AS48693 - HostRoyale Ltd)',
      inferredContext: 'Intermediate MTA relay routing untrusted spoofed mail envelope'
    }
  ];

  const activeGeoRecords = (currentAnalysis?.geoList && currentAnalysis.geoList.length > 0)
    ? currentAnalysis.geoList
    : (currentAnalysis?.geoInfo ? [currentAnalysis.geoInfo] : defaultNodes);

  return (
    <div className="space-y-6 pb-12">
      
      {/* Top SOC Status & Mission Banner */}
      <div className="relative overflow-hidden rounded-2xl bg-gradient-to-r from-[#0b1426] via-[#091222] to-[#060a14] border border-cyan-500/30 p-5 sm:p-6 shadow-[0_0_30px_rgba(6,182,212,0.1)]">
        <div className="absolute -right-12 -top-12 w-64 h-64 bg-cyan-500/10 rounded-full blur-3xl pointer-events-none"></div>
        <div className="absolute -left-12 -bottom-12 w-64 h-64 bg-blue-600/10 rounded-full blur-3xl pointer-events-none"></div>

        <div className="relative flex flex-col lg:flex-row lg:items-center justify-between gap-4">
          <div className="space-y-1.5">
            <div className="flex flex-wrap items-center gap-2.5">
              <span className="flex items-center gap-1.5 px-2.5 py-0.5 rounded-full bg-cyan-950/80 border border-cyan-500/40 text-cyan-300 text-xs font-mono font-semibold">
                <span className="w-2 h-2 rounded-full bg-cyan-400 animate-pulse"></span>
                SOC COMMAND POSTURE: DEFCON 2
              </span>
              <span className="text-xs font-mono text-slate-400">
                AI Engine: <strong className="text-slate-200">Neural-v4.2-Hybrid</strong>
              </span>
              <span className="text-xs font-mono text-emerald-400">
                • 0.03% False Positive
              </span>
            </div>

            <h1 className="text-xl sm:text-2xl font-extrabold tracking-tight text-white flex items-center gap-2">
              <span>MAVERICK Threat Intelligence & Forensics Hub</span>
            </h1>

            <p className="text-xs sm:text-sm text-slate-300 max-w-3xl leading-relaxed">
              Autonomous, explainable deep-learning email perimeter defense. Inspects RFC headers, extracts IOCs, models multi-hop ASN infrastructure, and generates certifiable forensic dossiers for SIH 2026.
            </p>
          </div>

          {/* Quick CTA Actions */}
          <div className="flex flex-wrap items-center gap-3 shrink-0">
            <button
              onClick={onOpenScan}
              className="flex items-center gap-2 px-4 py-2 rounded-xl bg-gradient-to-r from-cyan-600 via-sky-600 to-blue-600 hover:from-cyan-500 hover:to-blue-500 text-white text-xs font-mono font-bold shadow-[0_0_20px_rgba(6,182,212,0.4)] transition-all active:scale-95"
            >
              <Zap className="w-4 h-4 fill-current" />
              <span>Ingest & Scan Email</span>
            </button>

            <button
              onClick={() => onViewChange('threat-graph')}
              className="flex items-center gap-2 px-4 py-2 rounded-xl bg-[#0e1a30] hover:bg-[#122342] border border-cyan-500/40 text-cyan-300 text-xs font-mono font-semibold transition-all"
            >
              <Fingerprint className="w-4 h-4 text-cyan-400" />
              <span>Explore Threat Graph</span>
              <ChevronRight className="w-3.5 h-3.5" />
            </button>
          </div>
        </div>

        {/* Real-time Sub-ticker */}
        <div className="mt-4 pt-3 border-t border-slate-800/80 flex flex-wrap items-center justify-between gap-2 text-[11px] font-mono text-slate-400">
          <div className="flex items-center gap-4">
            <span className="text-slate-300">
              Active Threats Quarantined: <strong className="text-red-400">1,438</strong>
            </span>
            <span className="hidden sm:inline text-slate-700">|</span>
            <span className="hidden sm:inline text-slate-300">
              Avg Pipeline MTTD: <strong className="text-emerald-400">{SOC_SUMMARY.meanTimeToDetect}</strong>
            </span>
            <span className="hidden sm:inline text-slate-700">|</span>
            <span className="hidden md:inline text-slate-300">
              Zero-Day Quishing Vectors: <strong className="text-amber-400">{SOC_SUMMARY.zeroDayPhishingCampaigns} Campaigns</strong>
            </span>
          </div>
          <div className="text-slate-500">
            Signature DB: {SOC_SUMMARY.lastRuleUpdate}
          </div>
        </div>
      </div>

      {/* 4 Stat Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-4 gap-4">
        <StatCard
          title="Total Scanned (24h)"
          value="28,492"
          subValue="Emails"
          change="+14.2%"
          trend="up"
          icon={ShieldCheck}
          accentColor="cyan"
          highlightTag="142 msg/sec"
        />
        <StatCard
          title="Malicious Blocked"
          value="1,438"
          subValue="High Threat"
          change="+7.8%"
          trend="up"
          icon={ShieldAlert}
          accentColor="red"
          highlightTag="98.2% Auto-Mitigated"
        />
        <StatCard
          title="Quarantined / Suspicious"
          value="389"
          subValue="Cases"
          change="-2.1%"
          trend="down"
          icon={MailWarning}
          accentColor="amber"
          highlightTag="Sandbox Isolations"
        />
        <StatCard
          title="Mean Time To Detect (MTTD)"
          value="4.2s"
          subValue="Per Mail"
          change="-18.4%"
          trend="down"
          icon={Timer}
          accentColor="emerald"
          highlightTag="Zero-Day Ready"
        />
      </div>

      {/* Threat Velocity Trend & Attack Vector Distribution */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div className="lg:col-span-2">
          <ThreatVelocityChart />
        </div>
        <div className="lg:col-span-1">
          <AttackVectorChart />
        </div>
      </div>

      {/* Forensic Geolocation Interactive Map Card */}
      <ForensicGeoMap 
        geoRecords={activeGeoRecords}
        title="FORENSIC GEOLOCATION"
        subtitle="Multi-Hop Network Egress & Phishing Infrastructure Topology"
      />

      {/* Live Threat Stream */}
      <LiveThreatStream 
        onInspectEmail={onInspectEmail}
        onViewChange={onViewChange}
      />

      {/* MITRE ATT&CK Matrix Correlation */}
      <MitreMatrixSummary />

      {/* Active Incident Cases Queue */}
      <IncidentQueueTable 
        onViewChange={onViewChange}
        onSelectCase={onSelectCase}
      />

    </div>
  );
};
