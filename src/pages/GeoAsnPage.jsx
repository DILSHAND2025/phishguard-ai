import React from 'react';
import { 
  Globe2, 
  Server, 
  MapPin, 
  ShieldAlert, 
  AlertTriangle, 
  ArrowRight, 
  ArrowLeft, 
  ArrowDown, 
  Info, 
  Activity, 
  Layers, 
  Network, 
  ShieldCheck,
  Building,
  Radio
} from 'lucide-react';

const INFRASTRUCTURE_DATA = [
  {
    ip: '185.220.101.15',
    country: 'Germany',
    countryCode: 'DE',
    asn: 'AS9009',
    asnOrg: 'M247 Ltd Europe',
    context: 'Hosting / relay infrastructure',
    risk: 'HIGH'
  },
  {
    ip: '104.21.36.45',
    country: 'United States',
    countryCode: 'US',
    asn: 'AS13335',
    asnOrg: 'Cloudflare Edge Transit',
    context: 'Hosting infrastructure',
    risk: 'MEDIUM'
  }
];

const CORRELATION_CHAIN = [
  { step: '01', title: 'Email', detail: 'Received envelope & RFC 822 MIME headers' },
  { step: '02', title: 'Suspicious Domain', detail: 'Deceptive domain indicators & lookalike records' },
  { step: '03', title: 'IP Address', detail: 'Origin and transit hops extracted from headers' },
  { step: '04', title: 'ASN', detail: 'BGP routing prefix & Autonomous System entity' },
  { step: '05', title: 'GeoLocation', detail: 'Approximate hosting provider location' },
  { step: '06', title: 'Infrastructure Context', detail: 'Categorization as relay, hosting or cloud node' }
];

export const GeoAsnPage = ({ onViewChange }) => {
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
              {/* Requirement 1: Page heading "GeoLocation & ASN Intelligence" */}
              <h1 className="text-xl sm:text-2xl font-extrabold text-white font-mono flex items-center gap-2.5">
                <Globe2 className="w-6 h-6 text-blue-400" />
                <span>GeoLocation & ASN Intelligence</span>
              </h1>

              {/* Requirement 2: Badge "SIMULATED DEMO DATA" */}
              <span className="px-2.5 py-0.5 rounded bg-amber-950/80 border border-amber-500/50 text-amber-300 font-mono text-[11px] font-bold shadow-sm">
                SIMULATED DEMO DATA
              </span>
            </div>

            <p className="text-xs text-slate-300 mt-1.5 font-mono">
              Network infrastructure mapping and routing context for extracted threat indicators.
            </p>
          </div>

          {/* Top Navigation Buttons */}
          <div className="flex flex-wrap items-center gap-2.5 shrink-0">
            {/* Requirement 10: Back to IOC Intelligence */}
            <button
              type="button"
              id="btn-back-ioc-top"
              onClick={() => onViewChange('ioc-intel')}
              className="flex items-center gap-1.5 px-3.5 py-2 rounded-xl bg-[#091122] hover:bg-[#0e1b33] border border-slate-700 text-slate-300 font-mono text-xs transition-all cursor-pointer"
            >
              <ArrowLeft className="w-3.5 h-3.5" />
              <span>Back to IOC Intelligence</span>
            </button>

            {/* Requirement 10: Proceed to Threat Graph */}
            <button
              type="button"
              id="btn-proceed-threat-graph-top"
              onClick={() => onViewChange('threat-graph')}
              className="flex items-center gap-2 px-4 py-2 rounded-xl bg-gradient-to-r from-cyan-600 to-blue-600 hover:from-cyan-500 hover:to-blue-500 text-white font-mono text-xs font-bold shadow-[0_0_15px_rgba(6,182,212,0.4)] transition-all cursor-pointer"
            >
              <span>Proceed to Threat Graph</span>
              <ArrowRight className="w-4 h-4" />
            </button>
          </div>
        </div>
      </div>

      {/* Requirement 3: Important Disclaimer Near Top */}
      <div className="rounded-xl bg-amber-950/30 border border-amber-500/40 p-4 font-mono text-xs text-amber-200 flex items-start gap-3 shadow-md">
        <AlertTriangle className="w-5 h-5 text-amber-400 shrink-0 mt-0.5" />
        <div>
          <span className="font-bold text-amber-300 block mb-0.5 uppercase tracking-wide">
            Important Forensic Notice:
          </span>
          <p className="text-amber-100/90 text-xs leading-relaxed font-sans">
            GeoLocation represents infrastructure context associated with an indicator. It does not identify the physical location or identity of an attacker.
          </p>
        </div>
      </div>

      {/* Requirement 9: Short Methodology Explanation */}
      <div className="rounded-xl bg-[#09101e] border border-cyan-500/30 p-4 font-mono text-xs text-slate-300 flex items-start gap-3 shadow-md">
        <Info className="w-5 h-5 text-cyan-400 shrink-0 mt-0.5" />
        <div>
          <span className="text-cyan-300 font-bold block mb-0.5">Methodology:</span>
          <p className="text-slate-300 text-xs leading-relaxed font-sans">
            MAVERICK correlates IP, ASN and GeoLocation signals with extracted indicators to provide infrastructure context for investigation.
          </p>
        </div>
      </div>

      {/* Requirements 4 & 5: Clear Cards / Table Columns for DEMO Infrastructure Data */}
      <div className="rounded-xl bg-[#09101e] border border-slate-800 p-5 shadow-lg space-y-4">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-slate-800 pb-3">
          <div>
            <h2 className="text-sm font-bold uppercase tracking-wider font-mono text-white">
              Demonstration Infrastructure Endpoints
            </h2>
            <p className="text-xs text-slate-400 font-sans">
              Routing entities, autonomous systems, and hosting classification for inspected IPs
            </p>
          </div>
          <span className="text-[11px] font-mono text-cyan-300 bg-cyan-950/60 px-2.5 py-0.5 rounded border border-cyan-500/40">
            2 Simulated Nodes
          </span>
        </div>

        {/* Table View */}
        <div className="overflow-x-auto">
          <table className="w-full text-left font-mono text-xs border-collapse">
            <thead>
              <tr className="border-b border-slate-800 text-[11px] text-slate-400 uppercase tracking-wider bg-[#060a14]">
                <th className="py-3 px-3.5">IP Address</th>
                <th className="py-3 px-3.5">Country</th>
                <th className="py-3 px-3.5">ASN</th>
                <th className="py-3 px-3.5">Infrastructure Context</th>
                <th className="py-3 px-3.5">Risk</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60">
              {INFRASTRUCTURE_DATA.map((item, idx) => (
                <tr key={idx} className="hover:bg-[#0c1830]/70 transition-colors">
                  
                  {/* IP Address */}
                  <td className="py-3.5 px-3.5 font-bold text-cyan-300 font-mono">
                    <div className="flex items-center gap-2">
                      <Server className="w-3.5 h-3.5 text-slate-500" />
                      <span>{item.ip}</span>
                    </div>
                  </td>

                  {/* Country */}
                  <td className="py-3.5 px-3.5 whitespace-nowrap">
                    <span className="inline-flex items-center gap-1.5 text-slate-200">
                      <span className="px-1.5 py-0.2 rounded bg-slate-800 text-[10px] font-bold text-cyan-400">
                        {item.countryCode}
                      </span>
                      <span>{item.country}</span>
                    </span>
                  </td>

                  {/* ASN */}
                  <td className="py-3.5 px-3.5 whitespace-nowrap">
                    <span className="px-2 py-0.5 rounded bg-purple-950/60 border border-purple-500/40 text-purple-300 font-bold text-[11px]">
                      {item.asn}
                    </span>
                    <span className="text-[10px] text-slate-500 ml-2 hidden lg:inline">
                      ({item.asnOrg})
                    </span>
                  </td>

                  {/* Infrastructure Context */}
                  <td className="py-3.5 px-3.5 text-slate-300 font-sans font-medium">
                    {item.context}
                  </td>

                  {/* Risk */}
                  <td className="py-3.5 px-3.5 whitespace-nowrap">
                    {item.risk === 'HIGH' ? (
                      <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded bg-red-950/70 border border-red-500/50 text-red-300 font-bold text-[10px]">
                        <span className="w-1.5 h-1.5 rounded-full bg-red-400 animate-pulse"></span>
                        <span>HIGH</span>
                      </span>
                    ) : (
                      <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded bg-amber-950/70 border border-amber-500/50 text-amber-300 font-bold text-[10px]">
                        <span>MEDIUM</span>
                      </span>
                    )}
                  </td>

                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* Requirement 6: Visual Geographic Section (Country Distribution) */}
      <div className="rounded-xl bg-[#09101e] border border-slate-800 p-5 shadow-lg space-y-4 font-mono">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-slate-800 pb-3">
          <div className="flex items-center gap-2">
            <MapPin className="w-5 h-5 text-cyan-400" />
            <div>
              <h2 className="text-sm font-bold uppercase tracking-wider text-white">
                Geographic Infrastructure Distribution
              </h2>
              <p className="text-xs text-slate-400 font-sans">
                Distribution of hosting endpoints by country (Indicates infrastructure facility, not attacker location)
              </p>
            </div>
          </div>
          <span className="text-[10px] text-slate-400 bg-slate-900 px-2 py-0.5 rounded border border-slate-800">
            Simulated Sample Nodes
          </span>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          
          {/* Country Card 1: Germany */}
          <div className="p-4 rounded-xl bg-[#060a14] border border-slate-800 space-y-3">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                <span className="text-base font-bold text-white">Germany</span>
                <span className="text-[10px] px-1.5 py-0.2 rounded bg-slate-800 text-cyan-300 font-bold">
                  [DE]
                </span>
              </div>
              <span className="text-xs font-bold text-red-400 bg-red-950/60 border border-red-500/40 px-2 py-0.5 rounded">
                HIGH RISK ENDPOINT
              </span>
            </div>

            <div className="space-y-1">
              <div className="flex justify-between text-xs text-slate-400">
                <span>Associated IP: <strong>185.220.101.15</strong></span>
                <span>50% Share</span>
              </div>
              <div className="w-full h-1.5 bg-slate-800 rounded-full overflow-hidden">
                <div className="h-full bg-gradient-to-r from-red-500 to-rose-500 w-[50%] rounded-full"></div>
              </div>
            </div>

            <div className="text-[11px] text-slate-400 font-sans space-y-1 pt-1 border-t border-slate-800/60">
              <div>• <strong>ASN:</strong> AS9009 (M247 Ltd Europe)</div>
              <div>• <strong>Role:</strong> Hosting / relay infrastructure node</div>
              <div>• <strong>Location Note:</strong> Physical server datacenter in Europe</div>
            </div>
          </div>

          {/* Country Card 2: United States */}
          <div className="p-4 rounded-xl bg-[#060a14] border border-slate-800 space-y-3">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                <span className="text-base font-bold text-white">United States</span>
                <span className="text-[10px] px-1.5 py-0.2 rounded bg-slate-800 text-cyan-300 font-bold">
                  [US]
                </span>
              </div>
              <span className="text-xs font-bold text-amber-400 bg-amber-950/60 border border-amber-500/40 px-2 py-0.5 rounded">
                MEDIUM RISK ENDPOINT
              </span>
            </div>

            <div className="space-y-1">
              <div className="flex justify-between text-xs text-slate-400">
                <span>Associated IP: <strong>104.21.36.45</strong></span>
                <span>50% Share</span>
              </div>
              <div className="w-full h-1.5 bg-slate-800 rounded-full overflow-hidden">
                <div className="h-full bg-gradient-to-r from-amber-500 to-yellow-500 w-[50%] rounded-full"></div>
              </div>
            </div>

            <div className="text-[11px] text-slate-400 font-sans space-y-1 pt-1 border-t border-slate-800/60">
              <div>• <strong>ASN:</strong> AS13335 (Cloudflare Inc)</div>
              <div>• <strong>Role:</strong> Hosting infrastructure node</div>
              <div>• <strong>Location Note:</strong> Anycast edge transit node</div>
            </div>
          </div>

        </div>
      </div>

      {/* Requirement 7: ASN / Infrastructure Concepts Section */}
      <div className="rounded-xl bg-[#09101e] border border-slate-800 p-5 shadow-lg space-y-4 font-mono text-xs">
        <div className="flex items-center gap-2 border-b border-slate-800 pb-3">
          <Network className="w-5 h-5 text-purple-400" />
          <h2 className="text-sm font-bold uppercase tracking-wider text-white">
            ASN & Infrastructure Technical Reference
          </h2>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-3.5">
          
          <div className="p-3.5 rounded-lg bg-[#060a14] border border-slate-800 space-y-1.5">
            <span className="text-cyan-300 font-bold text-xs flex items-center gap-1.5">
              <Radio className="w-3.5 h-3.5" /> Autonomous System Numbers (ASN)
            </span>
            <p className="text-slate-300 font-sans leading-relaxed text-[11px]">
              ASN identifies the network/organization associated with an IP prefix.
            </p>
          </div>

          <div className="p-3.5 rounded-lg bg-[#060a14] border border-slate-800 space-y-1.5">
            <span className="text-purple-300 font-bold text-xs flex items-center gap-1.5">
              <MapPin className="w-3.5 h-3.5" /> GeoLocation Context
            </span>
            <p className="text-slate-300 font-sans leading-relaxed text-[11px]">
              GeoLocation provides approximate infrastructure location.
            </p>
          </div>

          <div className="p-3.5 rounded-lg bg-[#060a14] border border-slate-800 space-y-1.5">
            <span className="text-emerald-300 font-bold text-xs flex items-center gap-1.5">
              <ShieldCheck className="w-3.5 h-3.5" /> Investigation Signals
            </span>
            <p className="text-slate-300 font-sans leading-relaxed text-[11px]">
              These signals are used for correlation and investigation.
            </p>
          </div>

        </div>
      </div>

      {/* Requirement 8: Infrastructure Correlation Section */}
      <div className="rounded-xl bg-[#09101e] border border-slate-800 p-5 shadow-lg space-y-4 font-mono">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-slate-800 pb-3">
          <div className="flex items-center gap-2">
            <Layers className="w-5 h-5 text-cyan-400" />
            <div>
              <h2 className="text-sm font-bold uppercase tracking-wider text-white">
                Infrastructure Correlation Chain
              </h2>
              <p className="text-xs text-slate-400 font-sans">
                Progressive contextual enrichment from raw message to hosting classification
              </p>
            </div>
          </div>
          <span className="text-[10px] text-cyan-400 bg-cyan-950 px-2 py-0.5 rounded border border-cyan-500/40">
            6-Stage Correlation Flow
          </span>
        </div>

        {/* Visual Pipeline Stepper: Email ↓ Suspicious Domain ↓ IP Address ↓ ASN ↓ GeoLocation ↓ Infrastructure Context */}
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-6 gap-3 text-center">
          {CORRELATION_CHAIN.map((item, idx) => (
            <div 
              key={idx}
              className="relative p-3.5 rounded-xl bg-[#060a14] border border-slate-800 hover:border-cyan-500/40 transition-all flex flex-col justify-between"
            >
              <div>
                <div className="w-6 h-6 rounded-full bg-cyan-950 border border-cyan-500/40 text-cyan-300 text-[10px] font-bold mx-auto flex items-center justify-center mb-2">
                  {item.step}
                </div>
                <div className="text-xs font-bold text-white mb-1">
                  {item.title}
                </div>
                <div className="text-[10px] text-slate-400 font-sans leading-tight">
                  {item.detail}
                </div>
              </div>

              {idx < CORRELATION_CHAIN.length - 1 && (
                <div className="mt-2 text-cyan-500/60 hidden lg:flex justify-center">
                  <ArrowRight className="w-3.5 h-3.5" />
                </div>
              )}
            </div>
          ))}
        </div>
      </div>

      {/* Requirement 10: Bottom Navigation Buttons */}
      <div className="pt-3 border-t border-slate-800 flex flex-col sm:flex-row items-center justify-between gap-3 font-mono text-xs">
        <button
          type="button"
          id="btn-back-ioc-bottom"
          onClick={() => onViewChange('ioc-intel')}
          className="flex items-center gap-1.5 px-4 py-2.5 rounded-xl bg-[#08101e] hover:bg-[#0c1830] border border-slate-700 text-slate-300 transition-colors cursor-pointer"
        >
          <ArrowLeft className="w-4 h-4" />
          <span>Back to IOC Intelligence</span>
        </button>

        <button
          type="button"
          id="btn-proceed-threat-graph-bottom"
          onClick={() => onViewChange('threat-graph')}
          className="flex items-center gap-2 px-6 py-2.5 rounded-xl bg-gradient-to-r from-cyan-600 via-sky-600 to-blue-600 hover:from-cyan-500 hover:to-blue-500 text-white font-bold shadow-[0_0_20px_rgba(6,182,212,0.4)] transition-all cursor-pointer"
        >
          <span>Proceed to Threat Graph</span>
          <ArrowRight className="w-4 h-4" />
        </button>
      </div>

    </div>
  );
};
