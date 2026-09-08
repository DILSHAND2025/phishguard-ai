import React, { useState } from 'react';
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
  const [activeDeckTab, setActiveDeckTab] = useState('geo');

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
    <div className="space-y-6 pb-16 font-sans">
      
      {/* Modern, Breathable SOC Hero Banner */}
      <div className="relative overflow-hidden rounded-2xl bg-gradient-to-r from-[#0a1224] via-[#091120] to-[#070b14] border border-slate-800/80 p-6 shadow-sm">
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-5">
          <div className="space-y-2">
            <div className="flex flex-wrap items-center gap-2.5">
              <span className="flex items-center gap-1.5 px-2.5 py-0.5 rounded-full bg-cyan-950/70 border border-cyan-500/40 text-cyan-300 text-xs font-mono font-medium">
                <span className="w-2 h-2 rounded-full bg-cyan-400"></span>
                <span>DEFCON 2 ACTIVE</span>
              </span>
              <span className="text-xs text-slate-400 font-mono">
                ML Pipeline: <strong className="text-slate-200">TF-IDF + Neural-v4.2</strong>
              </span>
              <span className="text-xs text-emerald-400 font-mono">
                • 0.03% False Positive Rate
              </span>
            </div>

            <h1 className="text-xl sm:text-2xl font-bold tracking-tight text-white">
              MAVERICK Threat Intelligence Hub
            </h1>

            <p className="text-xs sm:text-sm text-slate-400 max-w-2xl leading-relaxed">
              Autonomous deep-learning email perimeter defense. Inspects RFC headers, extracts IOCs, models multi-hop ASN infrastructure, and generates certifiable forensic dossiers.
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
              onClick={() => onViewChange('threat-graph')}
              className="flex items-center gap-1.5 px-4 py-2.5 rounded-xl bg-[#0d172e] hover:bg-[#122244] border border-slate-700 text-slate-300 text-xs font-semibold transition-all cursor-pointer"
            >
              <Fingerprint className="w-4 h-4 text-cyan-400" />
              <span>Threat Graph</span>
              <ChevronRight className="w-3.5 h-3.5" />
            </button>
          </div>
        </div>

        {/* Real-time Sub-metrics */}
        <div className="mt-5 pt-3 border-t border-slate-800/80 flex flex-wrap items-center justify-between gap-3 text-xs text-slate-400 font-mono">
          <div className="flex items-center gap-4 flex-wrap">
            <span>Quarantined Threats: <strong className="text-red-400">1,438</strong></span>
            <span className="text-slate-700">|</span>
            <span>Avg Pipeline MTTD: <strong className="text-emerald-400">{SOC_SUMMARY.meanTimeToDetect}</strong></span>
            <span className="text-slate-700">|</span>
            <span>Zero-Day Vectors: <strong className="text-amber-400">{SOC_SUMMARY.zeroDayPhishingCampaigns} Campaigns</strong></span>
          </div>
          <div className="text-slate-500 text-[11px]">
            Rule DB: {SOC_SUMMARY.lastRuleUpdate}
          </div>
        </div>
      </div>

      {/* 4 Clean Stat KPI Cards */}
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

      {/* Visual Analytics: Threat Velocity & Vector Distribution */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-5">
        <div className="lg:col-span-2">
          <ThreatVelocityChart />
        </div>
        <div className="lg:col-span-1">
          <AttackVectorChart />
        </div>
      </div>

      {/* Operations Deck (Segmented Workspace Tabs for Map, Feeds, and Queues) */}
      <div className="rounded-2xl bg-[#091122]/70 border border-slate-800/80 shadow-md overflow-hidden">
        
        {/* Operations Deck Tab Bar */}
        <div className="flex items-center justify-between px-4 border-b border-slate-800/80 bg-[#070e1c] overflow-x-auto text-xs">
          <div className="flex items-center gap-1">
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
              onClick={() => setActiveDeckTab('queue')}
              className={`flex items-center gap-2 py-3 px-3.5 border-b-2 font-medium transition-all cursor-pointer whitespace-nowrap ${
                activeDeckTab === 'queue'
                  ? 'border-cyan-400 text-cyan-300 font-semibold'
                  : 'border-transparent text-slate-400 hover:text-slate-200'
              }`}
            >
              <ClipboardList className="w-3.5 h-3.5" />
              <span>Active Incident Queue</span>
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
            SOC Operations Deck
          </span>
        </div>

        {/* Tab Viewport */}
        <div className="p-4 sm:p-5">
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

          {activeDeckTab === 'queue' && (
            <IncidentQueueTable 
              onViewChange={onViewChange}
              onSelectCase={onSelectCase}
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
