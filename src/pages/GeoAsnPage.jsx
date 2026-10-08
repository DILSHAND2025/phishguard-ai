import React from 'react';
import { 
  Globe2, 
  Server, 
  MapPin, 
  ArrowRight, 
  ArrowLeft, 
  Info, 
  Activity, 
  Network
} from 'lucide-react';
import { GEO_LEGAL_DISCLAIMER } from '../services/geoAsnService';
import { ForensicGeoMap } from '../components/dashboard/ForensicGeoMap';

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

  const geoRecordsForMap = (currentAnalysis?.geoList && currentAnalysis.geoList.length > 0)
    ? currentAnalysis.geoList
    : infrastructureList;

  return (
    <div className="space-y-6 pb-12 font-sans text-slate-900">
      
      {/* Top Banner Header */}
      <div className="rounded-xl bg-white border border-slate-200 p-6 shadow-xs">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
          <div>
            <div className="flex items-center gap-2 text-slate-500 text-xs font-semibold uppercase tracking-wider mb-1.5">
              <span>Infrastructure & Network Enrichment</span>
            </div>

            <div className="flex flex-wrap items-center gap-3">
              <h1 className="text-xl sm:text-2xl font-bold text-slate-900 flex items-center gap-2.5">
                <Globe2 className="w-6 h-6 text-slate-700" />
                <span>GeoLocation & ASN Intelligence</span>
              </h1>

              <span className="px-2.5 py-0.5 rounded bg-slate-100 border border-slate-200 text-slate-700 text-xs font-semibold">
                Network Topology
              </span>
            </div>

            <p className="text-xs text-slate-500 mt-1.5">
              Autonomous System mapping, BGP prefix analysis, and physical network routing context.
            </p>
          </div>

          {/* Navigation Buttons */}
          <div className="flex flex-wrap items-center gap-2.5 shrink-0">
            <button
              type="button"
              id="btn-back-ioc-top"
              onClick={() => onViewChange('ioc-intel')}
              className="flex items-center gap-1.5 px-3.5 py-2 rounded-lg bg-white hover:bg-slate-50 border border-slate-200 text-slate-700 text-xs font-semibold transition-colors shadow-2xs cursor-pointer"
            >
              <ArrowLeft className="w-3.5 h-3.5 text-slate-500" />
              <span>Back to IOCs</span>
            </button>

            <button
              type="button"
              id="btn-proceed-threat-graph-top"
              onClick={() => onViewChange('threat-graph')}
              className="flex items-center gap-2 px-4 py-2 rounded-lg bg-slate-900 hover:bg-slate-800 text-white text-xs font-semibold shadow-xs transition-colors cursor-pointer"
            >
              <Network className="w-4 h-4" />
              <span>Proceed to Threat Graph</span>
              <ArrowRight className="w-4 h-4" />
            </button>
          </div>
        </div>
      </div>

      {/* Forensic Standard Disclaimer Banner */}
      <div className="rounded-xl bg-slate-50 border border-slate-200 p-4 text-xs text-slate-700 flex items-start gap-3">
        <Info className="w-5 h-5 text-slate-500 shrink-0 mt-0.5" />
        <div className="space-y-1">
          <span className="text-slate-900 font-bold block">
            Legal Chain-of-Custody Attribution Standard:
          </span>
          <p className="text-slate-700 text-xs leading-relaxed">
            <strong>&quot;The observed IP infrastructure geolocates to {geoInfo.country}.&quot;</strong>
          </p>
          <p className="text-slate-500 text-[11px] leading-relaxed">
            {GEO_LEGAL_DISCLAIMER}
          </p>
        </div>
      </div>

      {/* Interactive Forensic Geolocation Map */}
      <ForensicGeoMap 
        geoRecords={geoRecordsForMap}
        title="Network Intelligence"
        subtitle="Live Geo-Coordinates, ISP Organization, and Transit Routing Topography"
      />

      {/* Infrastructure Telemetry Cards Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        
        {/* Originating IP Primary Intelligence Card */}
        <div className="rounded-xl bg-white border border-slate-200 p-5 shadow-xs space-y-4">
          <div className="flex items-center justify-between border-b border-slate-100 pb-3">
            <span className="text-xs font-bold text-slate-900 uppercase tracking-wider flex items-center gap-2">
              <Server className="w-4 h-4 text-slate-600" />
              Originating Egress Node
            </span>
            <span className="px-2 py-0.5 rounded bg-red-50 text-red-700 text-[10px] font-bold border border-red-200">
              {geoInfo.riskLevel || 'HIGH RISK'}
            </span>
          </div>

          <div className="space-y-3 text-xs">
            <div>
              <span className="text-[10px] uppercase text-slate-500 block font-semibold">IP Address</span>
              <span className="text-base font-bold text-slate-900 font-mono">{originIP}</span>
            </div>

            <div className="grid grid-cols-2 gap-2">
              <div>
                <span className="text-[10px] uppercase text-slate-500 block font-semibold">Country</span>
                <span className="font-bold text-slate-900 flex items-center gap-1.5 mt-0.5">
                  <MapPin className="w-3.5 h-3.5 text-slate-500" />
                  {geoInfo.country} ({geoInfo.countryCode})
                </span>
              </div>
              <div>
                <span className="text-[10px] uppercase text-slate-500 block font-semibold">City / Region</span>
                <span className="text-slate-700 mt-0.5 block">{geoInfo.city || 'Frankfurt'}, {geoInfo.region || 'Hesse'}</span>
              </div>
            </div>

            <div>
              <span className="text-[10px] uppercase text-slate-500 block font-semibold">Autonomous System (ASN)</span>
              <span className="font-bold text-slate-900 font-mono">{geoInfo.asn}</span>
              <span className="text-slate-600 block text-[11px] mt-0.5">{geoInfo.asnOrg}</span>
            </div>

            <div>
              <span className="text-[10px] uppercase text-slate-500 block font-semibold">ISP</span>
              <span className="text-slate-800 font-medium">{geoInfo.isp || geoInfo.asnOrg}</span>
            </div>

            <div>
              <span className="text-[10px] uppercase text-slate-500 block font-semibold">Classification</span>
              <span className="inline-block px-2.5 py-1 rounded bg-slate-50 border border-slate-200 text-slate-800 font-medium text-xs mt-1">
                {geoInfo.networkType}
              </span>
            </div>

            <div className="pt-2 border-t border-slate-100 text-[11px] text-slate-500">
              {geoInfo.routingDetails}
            </div>
          </div>
        </div>

        {/* Multi-Hop Transit Infrastructure Table */}
        <div className="lg:col-span-2 rounded-xl bg-white border border-slate-200 p-5 shadow-xs space-y-4">
          <div className="flex items-center justify-between border-b border-slate-100 pb-3">
            <span className="text-xs font-bold text-slate-900 uppercase tracking-wider flex items-center gap-2">
              <Activity className="w-4 h-4 text-slate-600" />
              Observed Transit Infrastructure
            </span>
            <span className="text-xs text-slate-500">
              3 Nodes Correlated in Routing Chain
            </span>
          </div>

          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead>
                <tr className="border-b border-slate-200 text-[10px] text-slate-500 uppercase tracking-wider bg-slate-50/50">
                  <th className="py-2.5 px-3">IP Address</th>
                  <th className="py-2.5 px-3">Observed Nation</th>
                  <th className="py-2.5 px-3">ASN & Org</th>
                  <th className="py-2.5 px-3">Classification</th>
                  <th className="py-2.5 px-3 text-right">Risk</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100">
                {infrastructureList.map((node, idx) => (
                  <tr key={idx} className="hover:bg-slate-50">
                    <td className="py-3 px-3 font-mono font-bold text-slate-900">
                      {node.ip}
                    </td>
                    <td className="py-3 px-3 text-slate-800 font-medium">
                      {node.country} ({node.countryCode})
                    </td>
                    <td className="py-3 px-3 text-slate-600 text-xs">
                      <span className="font-bold text-slate-900 font-mono">{node.asn}</span>
                      <span className="block text-[11px] text-slate-500">{node.asnOrg}</span>
                    </td>
                    <td className="py-3 px-3 text-xs text-slate-700">
                      {node.networkType}
                    </td>
                    <td className="py-3 px-3 text-right">
                      <span className={`px-2 py-0.5 rounded text-[10px] font-bold border ${
                        node.riskLevel === 'CRITICAL' || node.riskLevel === 'HIGH'
                          ? 'bg-red-50 text-red-700 border-red-200'
                          : 'bg-amber-50 text-amber-800 border-amber-200'
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
          <div className="pt-3 border-t border-slate-100 space-y-2">
            <span className="text-xs uppercase font-bold text-slate-500 block tracking-wider">
              Forensic Infrastructure Chain of Attribution:
            </span>
            <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-2 text-center">
              {correlationChain.map(step => (
                <div key={step.step} className="p-2.5 rounded-lg bg-slate-50 border border-slate-200 space-y-0.5">
                  <span className="text-[10px] text-slate-500 font-bold block">{step.step}</span>
                  <span className="text-xs text-slate-900 font-semibold block truncate">{step.title}</span>
                  <span className="text-[10px] text-slate-500 block truncate">{step.detail}</span>
                </div>
              ))}
            </div>
          </div>
        </div>

      </div>

    </div>
  );
};
