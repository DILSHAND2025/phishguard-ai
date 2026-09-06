import React from 'react';
import { 
  Globe2, 
  Server, 
  MapPin, 
  ShieldAlert, 
  AlertTriangle, 
  ArrowRight, 
  ArrowLeft, 
  Info, 
  Activity, 
  Layers, 
  Network, 
  ShieldCheck,
  Building,
  Radio,
  ExternalLink
} from 'lucide-react';
import { GEO_LEGAL_DISCLAIMER } from '../services/geoAsnService';

export const GeoAsnPage = ({ onViewChange, currentAnalysis }) => {
  const geoInfo = currentAnalysis?.geoInfo || {
    ip: '185.220.101.45',
    country: 'Germany',
    countryCode: 'DE',
    region: 'Hesse',
    city: 'Frankfurt am Main',
    asn: 'AS9009',
    asnOrg: 'M247 Ltd Europe',
    isp: 'M247 Europe S.R.L.',
    networkType: 'Tor Exit Node / Anonymizing Relay',
    riskLevel: 'HIGH',
    isProxyOrVpn: true,
    routingDetails: 'BGP Prefix: 185.220.100.0/22 | Tor Directory Authority Verified'
  };

  const originIP = currentAnalysis?.email?.originatingIP || geoInfo.ip || '185.220.101.45';

  const infrastructureList = [
    geoInfo,
    {
      ip: '45.154.255.82',
      country: 'Netherlands',
      countryCode: 'NL',
      region: 'North Holland',
      city: 'Amsterdam',
      asn: 'AS202425',
      asnOrg: 'IP Volume Inc',
      isp: 'IP Volume Networks',
      networkType: 'Commercial Hosting / Proxy Egress',
      riskLevel: 'HIGH',
      isProxyOrVpn: true,
      routingDetails: 'Fast-Flux Reverse Proxy Farm'
    },
    {
      ip: '194.26.29.110',
      country: 'Romania',
      countryCode: 'RO',
      region: 'Bucharest',
      city: 'Bucharest',
      asn: 'AS48693',
      asnOrg: 'HostRoyale Egress Relay',
      isp: 'HostRoyale Ltd',
      networkType: 'Transit Relay Endpoint',
      riskLevel: 'MEDIUM',
      isProxyOrVpn: true,
      routingDetails: 'Intermediate SMTP Routing Relay'
    }
  ];

  const correlationChain = [
    { step: '01', title: 'Email Envelope', detail: `Received from ${currentAnalysis?.email?.fromParsed?.address || 'cfo-finance-update@internal-corp-portal.online'}` },
    { step: '02', title: 'Sender Domain', detail: `${currentAnalysis?.email?.fromParsed?.domain || 'internal-corp-portal.online'} (Typosquat Indicator)` },
    { step: '03', title: 'Originating IP', detail: `${originIP} (Extracted from Received Hop)` },
    { step: '04', title: 'Autonomous System', detail: `${geoInfo.asn} (${geoInfo.asnOrg})` },
    { step: '05', title: 'Network Topology', detail: `${geoInfo.networkType || 'Tor Relay Node'}` },
    { step: '06', title: 'Observed GeoLocation', detail: `Observed infrastructure geolocates to ${geoInfo.country}` }
  ];

  return (
    <div className="space-y-6 pb-12 font-sans">
      
      {/* Top Banner Header */}
      <div className="relative overflow-hidden rounded-2xl bg-gradient-to-r from-blue-950/40 via-[#0d162a] to-[#070b13] border border-blue-500/40 p-6 shadow-[0_0_30px_rgba(59,130,246,0.15)]">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
          <div>
            <div className="flex items-center gap-2 text-blue-400 text-xs font-mono mb-1.5">
              <span className="w-2 h-2 rounded-full bg-blue-400 animate-ping"></span>
              STAGE 05 OF 08 • INFRASTRUCTURE & NETWORK ENRICHMENT
            </div>

            <div className="flex flex-wrap items-center gap-3">
              <h1 className="text-xl sm:text-2xl font-extrabold text-white font-mono flex items-center gap-2.5">
                <Globe2 className="w-6 h-6 text-blue-400" />
                <span>GeoLocation & ASN Intelligence</span>
              </h1>

              <span className="px-2.5 py-0.5 rounded bg-cyan-950/80 border border-cyan-500/50 text-cyan-300 font-mono text-[11px] font-bold shadow-sm">
                INFRASTRUCTURE RESOLUTION
              </span>
            </div>

            <p className="text-xs text-slate-300 mt-1.5 font-mono">
              Autonomous System mapping, BGP prefix analysis, and physical network routing context.
            </p>
          </div>

          {/* Navigation Buttons */}
          <div className="flex flex-wrap items-center gap-2.5 shrink-0">
            <button
              type="button"
              id="btn-back-ioc-top"
              onClick={() => onViewChange('ioc-intel')}
              className="flex items-center gap-1.5 px-3.5 py-2 rounded-xl bg-[#091122] hover:bg-[#0e1b33] border border-slate-700 text-slate-300 font-mono text-xs transition-all cursor-pointer"
            >
              <ArrowLeft className="w-3.5 h-3.5" />
              <span>Back to IOCs</span>
            </button>

            <button
              type="button"
              id="btn-proceed-threat-graph-top"
              onClick={() => onViewChange('threat-graph')}
              className="flex items-center gap-2 px-4 py-2 rounded-xl bg-gradient-to-r from-cyan-600 to-blue-600 hover:from-cyan-500 hover:to-blue-500 text-white font-mono text-xs font-bold shadow-[0_0_15px_rgba(6,182,212,0.4)] transition-all cursor-pointer"
            >
              <Network className="w-4 h-4" />
              <span>Proceed to Threat Graph</span>
              <ArrowRight className="w-4 h-4" />
            </button>
          </div>
        </div>
      </div>

      {/* Mandatory Forensic Standard Disclaimer Banner */}
      <div className="rounded-xl bg-gradient-to-r from-blue-950/40 via-[#0a1222] to-[#070b13] border border-cyan-500/40 p-4 font-mono text-xs text-slate-200 flex items-start gap-3 shadow-md">
        <Info className="w-5 h-5 text-cyan-400 shrink-0 mt-0.5" />
        <div className="space-y-1">
          <span className="text-cyan-300 font-bold block">
            CERT-In & Legal Chain-of-Custody Attribution Standard:
          </span>
          <p className="text-slate-300 text-xs leading-relaxed font-sans">
            <strong>"The observed IP infrastructure geolocates to {geoInfo.country}."</strong>
          </p>
          <p className="text-slate-400 text-[11px] leading-relaxed">
            {GEO_LEGAL_DISCLAIMER}
          </p>
        </div>
      </div>

      {/* Infrastructure Telemetry Cards Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 font-mono">
        
        {/* Originating IP Primary Intelligence Card */}
        <div className="rounded-xl bg-[#09101e] border border-cyan-500/40 p-5 shadow-lg space-y-4">
          <div className="flex items-center justify-between border-b border-slate-800 pb-3">
            <span className="text-xs font-bold text-white uppercase tracking-wider flex items-center gap-2">
              <Server className="w-4 h-4 text-cyan-400" />
              Originating Egress Node
            </span>
            <span className="px-2 py-0.5 rounded bg-red-950 text-red-300 text-[10px] font-bold border border-red-500/40">
              {geoInfo.riskLevel || 'HIGH RISK'}
            </span>
          </div>

          <div className="space-y-3 text-xs">
            <div>
              <span className="text-[10px] uppercase text-slate-500 block">IP Address</span>
              <span className="text-base font-black text-cyan-300">{originIP}</span>
            </div>

            <div className="grid grid-cols-2 gap-2">
              <div>
                <span className="text-[10px] uppercase text-slate-500 block">Observed Country</span>
                <span className="font-bold text-white flex items-center gap-1.5">
                  <MapPin className="w-3.5 h-3.5 text-blue-400" />
                  {geoInfo.country} ({geoInfo.countryCode})
                </span>
              </div>
              <div>
                <span className="text-[10px] uppercase text-slate-500 block">City / Region</span>
                <span className="text-slate-200">{geoInfo.city || 'Frankfurt'}, {geoInfo.region || 'Hesse'}</span>
              </div>
            </div>

            <div>
              <span className="text-[10px] uppercase text-slate-500 block">Autonomous System (ASN)</span>
              <span className="font-bold text-purple-300">{geoInfo.asn}</span>
              <span className="text-slate-400 block text-[11px]">{geoInfo.asnOrg}</span>
            </div>

            <div>
              <span className="text-[10px] uppercase text-slate-500 block">Internet Service Provider (ISP)</span>
              <span className="text-slate-200 font-semibold">{geoInfo.isp || geoInfo.asnOrg}</span>
            </div>

            <div>
              <span className="text-[10px] uppercase text-slate-500 block">Network Classification</span>
              <span className="inline-block px-2.5 py-1 rounded bg-slate-900 border border-slate-800 text-amber-300 font-bold text-[11px]">
                {geoInfo.networkType}
              </span>
            </div>

            <div className="pt-2 border-t border-slate-800 text-[10px] text-slate-500">
              {geoInfo.routingDetails}
            </div>
          </div>
        </div>

        {/* Multi-Hop Transit Infrastructure Table */}
        <div className="lg:col-span-2 rounded-xl bg-[#09101e] border border-slate-800 p-5 shadow-lg space-y-4">
          <div className="flex items-center justify-between border-b border-slate-800 pb-3">
            <span className="text-xs font-bold text-white uppercase tracking-wider flex items-center gap-2">
              <Activity className="w-4 h-4 text-cyan-400" />
              Observed Multi-Hop Transit Infrastructure
            </span>
            <span className="text-[10px] text-slate-400">
              3 Nodes Correlated in Routing Chain
            </span>
          </div>

          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead>
                <tr className="border-b border-slate-800 text-[10px] text-slate-500 uppercase tracking-wider">
                  <th className="py-2.5 px-3">IP Address</th>
                  <th className="py-2.5 px-3">Observed Nation</th>
                  <th className="py-2.5 px-3">ASN & Org</th>
                  <th className="py-2.5 px-3">Classification</th>
                  <th className="py-2.5 px-3 text-right">Risk</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60">
                {infrastructureList.map((node, idx) => (
                  <tr key={idx} className="hover:bg-slate-900/40 transition-colors">
                    <td className="py-3 px-3 font-bold text-cyan-300">
                      {node.ip}
                    </td>
                    <td className="py-3 px-3 text-slate-200">
                      {node.country} ({node.countryCode})
                    </td>
                    <td className="py-3 px-3 text-slate-300 text-[11px]">
                      <span className="font-bold text-purple-300">{node.asn}</span>
                      <span className="block text-[10px] text-slate-500">{node.asnOrg}</span>
                    </td>
                    <td className="py-3 px-3 text-[11px] text-amber-300">
                      {node.networkType}
                    </td>
                    <td className="py-3 px-3 text-right">
                      <span className={`px-2 py-0.5 rounded text-[10px] font-extrabold ${
                        node.riskLevel === 'CRITICAL' || node.riskLevel === 'HIGH'
                          ? 'bg-red-950 text-red-300 border border-red-500/40'
                          : 'bg-amber-950 text-amber-300 border border-amber-500/40'
                      }`}>
                        {node.riskLevel}
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          {/* Infrastructure Correlation Chain Timeline */}
          <div className="pt-3 border-t border-slate-800 space-y-2">
            <span className="text-[10px] uppercase font-bold text-slate-400 block tracking-wider">
              Forensic Infrastructure Chain of Attribution:
            </span>
            <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-2 text-center">
              {correlationChain.map(step => (
                <div key={step.step} className="p-2 rounded bg-[#060a14] border border-slate-800 space-y-0.5">
                  <span className="text-[9px] text-cyan-400 font-bold block">{step.step}</span>
                  <span className="text-[10px] text-white font-bold block truncate">{step.title}</span>
                  <span className="text-[9px] text-slate-500 block truncate">{step.detail}</span>
                </div>
              ))}
            </div>
          </div>
        </div>

      </div>

    </div>
  );
};
