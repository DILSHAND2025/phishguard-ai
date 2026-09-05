import React, { useState } from 'react';
import { 
  AreaChart, 
  Area, 
  XAxis, 
  YAxis, 
  CartesianGrid, 
  Tooltip, 
  ResponsiveContainer,
  Legend
} from 'recharts';
import { Activity, ShieldAlert, Zap } from 'lucide-react';
import { THREAT_VELOCITY_DATA } from '../../data/mockSocData';

const CustomTooltip = ({ active, payload, label }) => {
  if (active && payload && payload.length) {
    return (
      <div className="rounded-lg bg-[#0a1120] border border-cyan-500/40 p-3 shadow-xl backdrop-blur-md font-mono text-xs">
        <p className="text-cyan-300 font-bold border-b border-slate-800 pb-1 mb-2">
          Time: {label} UTC
        </p>
        <div className="space-y-1.5">
          {payload.map((entry, index) => (
            <div key={`item-${index}`} className="flex items-center justify-between gap-4">
              <span className="flex items-center gap-1.5 text-slate-300">
                <span 
                  className="w-2 h-2 rounded-full" 
                  style={{ backgroundColor: entry.color }}
                />
                {entry.name}:
              </span>
              <span className="font-bold text-white">
                {entry.value.toLocaleString()}
              </span>
            </div>
          ))}
        </div>
      </div>
    );
  }
  return null;
};

export const ThreatVelocityChart = () => {
  const [activeMetric, setActiveMetric] = useState('all');

  return (
    <div className="rounded-xl bg-gradient-to-b from-[#0c1424] to-[#070b14] border border-slate-800/80 p-5 shadow-lg">
      
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 mb-4">
        <div>
          <div className="flex items-center gap-2">
            <Activity className="w-4 h-4 text-cyan-400" />
            <h3 className="text-sm font-bold uppercase tracking-wider font-mono text-slate-100">
              Email Ingestion & Threat Velocity Trend
            </h3>
          </div>
          <p className="text-xs text-slate-400 mt-0.5">
            Real-time multi-vector volumetric analysis across 24 hours
          </p>
        </div>

        {/* Filter Pills */}
        <div className="flex items-center gap-1.5 bg-[#090f1d] p-1 rounded-lg border border-slate-800 text-xs font-mono">
          <button
            onClick={() => setActiveMetric('all')}
            className={`px-2.5 py-1 rounded transition-all ${
              activeMetric === 'all'
                ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40 font-semibold'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            Combined
          </button>
          <button
            onClick={() => setActiveMetric('threats')}
            className={`px-2.5 py-1 rounded transition-all ${
              activeMetric === 'threats'
                ? 'bg-red-500/20 text-red-300 border border-red-500/40 font-semibold'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            Threats Only
          </button>
        </div>
      </div>

      {/* Chart Area */}
      <div className="h-64 w-full">
        <ResponsiveContainer width="100%" height="100%">
          <AreaChart
            data={THREAT_VELOCITY_DATA}
            margin={{ top: 10, right: 10, left: -20, bottom: 0 }}
          >
            <defs>
              <linearGradient id="colorScanned" x1="0" y1="0" x2="0" y2="1">
                <stop offset="5%" stopColor="#06b6d4" stopOpacity={0.35} />
                <stop offset="95%" stopColor="#06b6d4" stopOpacity={0.0} />
              </linearGradient>
              <linearGradient id="colorBlocked" x1="0" y1="0" x2="0" y2="1">
                <stop offset="5%" stopColor="#ef4444" stopOpacity={0.45} />
                <stop offset="95%" stopColor="#ef4444" stopOpacity={0.0} />
              </linearGradient>
              <linearGradient id="colorSuspicious" x1="0" y1="0" x2="0" y2="1">
                <stop offset="5%" stopColor="#f59e0b" stopOpacity={0.35} />
                <stop offset="95%" stopColor="#f59e0b" stopOpacity={0.0} />
              </linearGradient>
            </defs>

            <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" opacity={0.5} />
            
            <XAxis 
              dataKey="time" 
              stroke="#64748b" 
              fontSize={11} 
              fontFamily="JetBrains Mono"
              tickLine={false} 
            />
            <YAxis 
              stroke="#64748b" 
              fontSize={11} 
              fontFamily="JetBrains Mono"
              tickLine={false}
            />

            <Tooltip content={<CustomTooltip />} />

            {activeMetric === 'all' && (
              <Area
                type="monotone"
                dataKey="scanned"
                name="Total Ingested"
                stroke="#06b6d4"
                strokeWidth={2}
                fillOpacity={1}
                fill="url(#colorScanned)"
              />
            )}

            <Area
              type="monotone"
              dataKey="blocked"
              name="Malicious Blocked"
              stroke="#ef4444"
              strokeWidth={2}
              fillOpacity={1}
              fill="url(#colorBlocked)"
            />

            <Area
              type="monotone"
              dataKey="suspicious"
              name="Quarantined"
              stroke="#f59e0b"
              strokeWidth={1.5}
              fillOpacity={1}
              fill="url(#colorSuspicious)"
            />
          </AreaChart>
        </ResponsiveContainer>
      </div>

      {/* Footer Metrics */}
      <div className="grid grid-cols-3 gap-2 mt-3 pt-3 border-t border-slate-800/80 text-center font-mono">
        <div className="p-2 rounded bg-[#09101d] border border-slate-800">
          <div className="text-[10px] text-slate-400 uppercase">Peak Hourly Flow</div>
          <div className="text-xs font-bold text-cyan-300 mt-0.5">3,820 msg/hr</div>
        </div>
        <div className="p-2 rounded bg-[#09101d] border border-slate-800">
          <div className="text-[10px] text-slate-400 uppercase">Block Ratio</div>
          <div className="text-xs font-bold text-red-400 mt-0.5">7.46% of traffic</div>
        </div>
        <div className="p-2 rounded bg-[#09101d] border border-slate-800">
          <div className="text-[10px] text-slate-400 uppercase">AI Isolation Rate</div>
          <div className="text-xs font-bold text-emerald-400 mt-0.5">99.9% Auto</div>
        </div>
      </div>

    </div>
  );
};
