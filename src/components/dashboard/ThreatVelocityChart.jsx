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
import { Activity, Zap } from 'lucide-react';
import { THREAT_VELOCITY_DATA } from '../../data/mockSocData';

const CustomTooltip = ({ active, payload, label }) => {
  if (active && payload && payload.length) {
    return (
      <div className="rounded-xl bg-white border border-slate-200 p-3 shadow-lg font-mono text-xs">
        <p className="text-slate-900 font-bold border-b border-slate-100 pb-1 mb-2">
          Time: {label} UTC
        </p>
        <div className="space-y-1.5">
          {payload.map((entry, index) => (
            <div key={`item-${index}`} className="flex items-center justify-between gap-4">
              <span className="flex items-center gap-1.5 text-slate-600">
                <span 
                  className="w-2 h-2 rounded-full" 
                  style={{ backgroundColor: entry.color }}
                />
                {entry.name}:
              </span>
              <span className="font-bold text-slate-900">
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
    <div className="rounded-xl bg-white border border-slate-200 p-5 shadow-2xs">
      
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 mb-4">
        <div>
          <div className="flex items-center gap-2">
            <Activity className="w-4 h-4 text-cyan-600" />
            <h3 className="text-sm font-bold uppercase tracking-wider font-mono text-slate-900">
              Threat Ingress Velocity & Blocking
            </h3>
          </div>
          <p className="text-xs text-slate-500 mt-0.5">
            24-Hour continuous email telemetry across gateway perimeter
          </p>
        </div>

        {/* Metric Filter Tabs */}
        <div className="flex items-center gap-1 bg-slate-50 p-1 rounded-lg border border-slate-200 text-xs font-mono self-start sm:self-auto">
          <button
            onClick={() => setActiveMetric('all')}
            className={`px-2.5 py-1 rounded transition-colors cursor-pointer ${
              activeMetric === 'all' 
                ? 'bg-white text-slate-900 font-bold shadow-2xs border border-slate-200/60' 
                : 'text-slate-500 hover:text-slate-800'
            }`}
          >
            All Ingress
          </button>
          <button
            onClick={() => setActiveMetric('blocked')}
            className={`px-2.5 py-1 rounded transition-colors cursor-pointer ${
              activeMetric === 'blocked' 
                ? 'bg-white text-slate-900 font-bold shadow-2xs border border-slate-200/60' 
                : 'text-slate-500 hover:text-slate-800'
            }`}
          >
            Blocked
          </button>
          <button
            onClick={() => setActiveMetric('phishing')}
            className={`px-2.5 py-1 rounded transition-colors cursor-pointer ${
              activeMetric === 'phishing' 
                ? 'bg-white text-slate-900 font-bold shadow-2xs border border-slate-200/60' 
                : 'text-slate-500 hover:text-slate-800'
            }`}
          >
            Phishing
          </button>
        </div>
      </div>

      {/* Chart Canvas */}
      <div className="h-64 sm:h-72 w-full">
        <ResponsiveContainer width="100%" height="100%">
          <AreaChart
            data={THREAT_VELOCITY_DATA}
            margin={{ top: 10, right: 10, left: -20, bottom: 0 }}
          >
            <defs>
              <linearGradient id="colorIngress" x1="0" y1="0" x2="0" y2="1">
                <stop offset="5%" stopColor="#0284c7" stopOpacity={0.25} />
                <stop offset="95%" stopColor="#0284c7" stopOpacity={0} />
              </linearGradient>
              <linearGradient id="colorBlocked" x1="0" y1="0" x2="0" y2="1">
                <stop offset="5%" stopColor="#10b981" stopOpacity={0.25} />
                <stop offset="95%" stopColor="#10b981" stopOpacity={0} />
              </linearGradient>
              <linearGradient id="colorPhishing" x1="0" y1="0" x2="0" y2="1">
                <stop offset="5%" stopColor="#ef4444" stopOpacity={0.25} />
                <stop offset="95%" stopColor="#ef4444" stopOpacity={0} />
              </linearGradient>
            </defs>

            <CartesianGrid strokeDasharray="3 3" stroke="#f1f5f9" vertical={false} />
            
            <XAxis 
              dataKey="time" 
              stroke="#94a3b8" 
              fontSize={11} 
              tickLine={false}
              fontFamily="monospace"
            />
            <YAxis 
              stroke="#94a3b8" 
              fontSize={11} 
              tickLine={false}
              axisLine={false}
              fontFamily="monospace"
            />
            
            <Tooltip content={<CustomTooltip />} />
            
            <Legend 
              wrapperStyle={{ fontSize: '11px', fontFamily: 'monospace', paddingTop: '10px' }}
              iconType="circle"
            />

            {(activeMetric === 'all' || activeMetric === 'ingress') && (
              <Area
                type="monotone"
                dataKey="scanned"
                name="Total Scanned"
                stroke="#0284c7"
                strokeWidth={2}
                fillOpacity={1}
                fill="url(#colorIngress)"
              />
            )}

            {(activeMetric === 'all' || activeMetric === 'blocked') && (
              <Area
                type="monotone"
                dataKey="blocked"
                name="Auto-Blocked"
                stroke="#10b981"
                strokeWidth={2}
                fillOpacity={1}
                fill="url(#colorBlocked)"
              />
            )}

            {(activeMetric === 'all' || activeMetric === 'phishing') && (
              <Area
                type="monotone"
                dataKey="phishing"
                name="Phishing/BEC"
                stroke="#ef4444"
                strokeWidth={2}
                fillOpacity={1}
                fill="url(#colorPhishing)"
              />
            )}
          </AreaChart>
        </ResponsiveContainer>
      </div>

      {/* Footer Snapshot Banner */}
      <div className="mt-3 pt-3 border-t border-slate-100 flex flex-wrap items-center justify-between gap-3 text-[11px] font-mono text-slate-500">
        <div className="flex items-center gap-2">
          <Zap className="w-3.5 h-3.5 text-cyan-600" />
          <span>Real-time Throughput: <strong className="text-slate-800">142 msgs/sec</strong></span>
        </div>
        <div>
          <span>Peak Velocity Window: <strong className="text-red-600">14:00 - 16:00 UTC</strong></span>
        </div>
      </div>

    </div>
  );
};
