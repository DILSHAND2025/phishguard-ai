import React from 'react';
import { 
  PieChart, 
  Pie, 
  Cell, 
  Tooltip, 
  ResponsiveContainer 
} from 'recharts';
import { Target, AlertTriangle } from 'lucide-react';
import { ATTACK_VECTORS } from '../../data/mockSocData';

const CustomPieTooltip = ({ active, payload }) => {
  if (active && payload && payload.length) {
    const data = payload[0].payload;
    return (
      <div className="rounded-lg bg-[#0a1120] border border-cyan-500/40 p-2.5 shadow-xl backdrop-blur-md font-mono text-xs">
        <div className="flex items-center gap-2 font-bold text-white mb-1">
          <span className="w-2.5 h-2.5 rounded-full" style={{ backgroundColor: data.color }} />
          {data.name}
        </div>
        <div className="text-slate-300">
          Distribution: <span className="text-cyan-300 font-semibold">{data.value}%</span>
        </div>
        <div className="text-slate-400 text-[11px]">
          Incidents Detected: <span className="text-white font-semibold">{data.count}</span>
        </div>
      </div>
    );
  }
  return null;
};

export const AttackVectorChart = () => {
  return (
    <div className="rounded-xl bg-gradient-to-b from-[#0c1424] to-[#070b14] border border-slate-800/80 p-5 shadow-lg flex flex-col justify-between">
      
      {/* Header */}
      <div>
        <div className="flex items-center justify-between mb-1">
          <div className="flex items-center gap-2">
            <Target className="w-4 h-4 text-red-400" />
            <h3 className="text-sm font-bold uppercase tracking-wider font-mono text-slate-100">
              Phishing & BEC Vectors
            </h3>
          </div>
          <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-red-950/60 border border-red-500/30 text-red-300">
            Top Threat
          </span>
        </div>
        <p className="text-xs text-slate-400">
          AI-classified vector distribution across intercepted mail
        </p>
      </div>

      {/* Chart in Center */}
      <div className="relative h-48 w-full my-2 flex items-center justify-center">
        <ResponsiveContainer width="100%" height="100%">
          <PieChart>
            <Pie
              data={ATTACK_VECTORS}
              cx="50%"
              cy="50%"
              innerRadius={52}
              outerRadius={78}
              paddingAngle={4}
              dataKey="value"
            >
              {ATTACK_VECTORS.map((entry, index) => (
                <Cell 
                  key={`cell-${index}`} 
                  fill={entry.color} 
                  stroke="#070b13" 
                  strokeWidth={2}
                />
              ))}
            </Pie>
            <Tooltip content={<CustomPieTooltip />} />
          </PieChart>
        </ResponsiveContainer>

        {/* Center Donut Label */}
        <div className="absolute inset-0 flex flex-col items-center justify-center pointer-events-none">
          <span className="text-xl font-extrabold font-mono text-white tracking-tight">
            1,438
          </span>
          <span className="text-[10px] uppercase font-mono text-slate-400">
            Threats
          </span>
        </div>
      </div>

      {/* Legend list */}
      <div className="space-y-2 pt-2 border-t border-slate-800/80">
        {ATTACK_VECTORS.map((item) => (
          <div key={item.name} className="flex items-center justify-between text-xs font-mono">
            <div className="flex items-center gap-2">
              <span 
                className="w-2 h-2 rounded-full shrink-0" 
                style={{ backgroundColor: item.color }} 
              />
              <span className="text-slate-300 truncate">{item.name}</span>
            </div>
            <div className="flex items-center gap-2">
              <span className="text-slate-400">{item.count}</span>
              <span className="font-bold text-white w-8 text-right">{item.value}%</span>
            </div>
          </div>
        ))}
      </div>

    </div>
  );
};
