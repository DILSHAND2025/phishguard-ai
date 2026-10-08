import React from 'react';
import { 
  PieChart, 
  Pie, 
  Cell, 
  Tooltip, 
  ResponsiveContainer 
} from 'recharts';
import { Target } from 'lucide-react';
import { ATTACK_VECTORS } from '../../data/mockSocData';

const CustomPieTooltip = ({ active, payload }) => {
  if (active && payload && payload.length) {
    const data = payload[0].payload;
    return (
      <div className="rounded-xl bg-white border border-slate-200 p-2.5 shadow-lg font-mono text-xs text-slate-800">
        <div className="flex items-center gap-2 font-bold text-slate-900 mb-1">
          <span className="w-2.5 h-2.5 rounded-full" style={{ backgroundColor: data.color }} />
          {data.name}
        </div>
        <div className="text-slate-600">
          Distribution: <span className="text-cyan-700 font-semibold">{data.value}%</span>
        </div>
        <div className="text-slate-500 text-[11px]">
          Incidents Detected: <span className="text-slate-900 font-semibold">{data.count}</span>
        </div>
      </div>
    );
  }
  return null;
};

export const AttackVectorChart = () => {
  return (
    <div className="rounded-xl bg-white border border-slate-200 p-5 shadow-2xs flex flex-col justify-between">
      
      {/* Header */}
      <div>
        <div className="flex items-center justify-between mb-1">
          <div className="flex items-center gap-2">
            <Target className="w-4 h-4 text-red-500" />
            <h3 className="text-sm font-bold uppercase tracking-wider font-mono text-slate-900">
              Phishing & BEC Vectors
            </h3>
          </div>
          <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-red-50 border border-red-200 text-red-700 font-medium">
            Top Threat
          </span>
        </div>
        <p className="text-xs text-slate-500">
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
                  stroke="#ffffff" 
                  strokeWidth={2}
                />
              ))}
            </Pie>
            <Tooltip content={<CustomPieTooltip />} />
          </PieChart>
        </ResponsiveContainer>

        {/* Center Donut Label */}
        <div className="absolute inset-0 flex flex-col items-center justify-center pointer-events-none">
          <span className="text-xl font-extrabold font-mono text-slate-900 tracking-tight">
            1,438
          </span>
          <span className="text-[10px] uppercase font-mono text-slate-500 font-medium">
            Threats
          </span>
        </div>
      </div>

      {/* Legend list */}
      <div className="space-y-2 pt-2 border-t border-slate-100">
        {ATTACK_VECTORS.map((item) => (
          <div key={item.name} className="flex items-center justify-between text-xs font-mono">
            <div className="flex items-center gap-2">
              <span 
                className="w-2 h-2 rounded-full shrink-0" 
                style={{ backgroundColor: item.color }} 
              />
              <span className="text-slate-600 truncate">{item.name}</span>
            </div>
            <div className="flex items-center gap-2">
              <span className="text-slate-400">{item.count}</span>
              <span className="font-bold text-slate-900 w-8 text-right">{item.value}%</span>
            </div>
          </div>
        ))}
      </div>

    </div>
  );
};
