import React from 'react';
import { ArrowUpRight, ArrowDownRight, ShieldAlert } from 'lucide-react';

export const StatCard = ({
  title,
  value,
  subValue,
  change,
  trend = 'up',
  icon: Icon,
  accentColor = 'cyan', // 'cyan' | 'red' | 'amber' | 'emerald'
  highlightTag,
}) => {
  const colorMap = {
    cyan: {
      border: 'border-cyan-500/30 hover:border-cyan-400',
      glow: 'hover:shadow-[0_0_20px_rgba(6,182,212,0.15)]',
      iconBg: 'bg-cyan-950/60 text-cyan-400 border border-cyan-500/30',
      text: 'text-cyan-400',
      bar: 'bg-cyan-500',
    },
    red: {
      border: 'border-red-500/30 hover:border-red-400',
      glow: 'hover:shadow-[0_0_20px_rgba(239,68,68,0.15)]',
      iconBg: 'bg-red-950/60 text-red-400 border border-red-500/30',
      text: 'text-red-400',
      bar: 'bg-red-500',
    },
    amber: {
      border: 'border-amber-500/30 hover:border-amber-400',
      glow: 'hover:shadow-[0_0_20px_rgba(245,158,11,0.15)]',
      iconBg: 'bg-amber-950/60 text-amber-400 border border-amber-500/30',
      text: 'text-amber-400',
      bar: 'bg-amber-500',
    },
    emerald: {
      border: 'border-emerald-500/30 hover:border-emerald-400',
      glow: 'hover:shadow-[0_0_20px_rgba(16,185,129,0.15)]',
      iconBg: 'bg-emerald-950/60 text-emerald-400 border border-emerald-500/30',
      text: 'text-emerald-400',
      bar: 'bg-emerald-500',
    },
  };

  const style = colorMap[accentColor] || colorMap.cyan;

  return (
    <div
      className={`relative overflow-hidden rounded-xl bg-gradient-to-b from-[#0c1424] to-[#070b14] p-4 sm:p-5 border transition-all duration-300 ${style.border} ${style.glow} group`}
    >
      {/* Subtle background cyber grid / corner notch */}
      <div className="absolute top-0 right-0 w-8 h-8 pointer-events-none">
        <div className={`absolute top-0 right-0 w-2 h-2 ${style.bar} opacity-60`}></div>
        <div className="absolute top-0 right-0 w-full h-[1px] bg-slate-700"></div>
        <div className="absolute top-0 right-0 h-full w-[1px] bg-slate-700"></div>
      </div>

      <div className="flex items-start justify-between">
        <div>
          <span className="text-[11px] font-mono uppercase tracking-wider text-slate-400">
            {title}
          </span>
          <div className="mt-1 flex items-baseline gap-2">
            <h3 className="text-2xl sm:text-3xl font-extrabold tracking-tight font-mono text-white">
              {value}
            </h3>
            {subValue && (
              <span className="text-xs text-slate-400 font-mono">
                {subValue}
              </span>
            )}
          </div>
        </div>

        {Icon && (
          <div className={`p-2.5 rounded-lg ${style.iconBg} transition-transform group-hover:scale-110`}>
            <Icon className="w-5 h-5" />
          </div>
        )}
      </div>

      <div className="mt-3.5 flex items-center justify-between pt-3 border-t border-slate-800/80 text-xs">
        <div className="flex items-center gap-1.5 font-mono">
          {change && (
            <span
              className={`flex items-center text-[11px] font-semibold ${
                trend === 'down' ? 'text-emerald-400' : 'text-red-400'
              }`}
            >
              {trend === 'up' ? (
                <ArrowUpRight className="w-3.5 h-3.5" />
              ) : (
                <ArrowDownRight className="w-3.5 h-3.5" />
              )}
              {change}
            </span>
          )}
          <span className="text-slate-500 text-[10px]">vs. last window</span>
        </div>

        {highlightTag && (
          <span className={`text-[10px] font-mono px-2 py-0.5 rounded ${style.iconBg}`}>
            {highlightTag}
          </span>
        )}
      </div>
    </div>
  );
};
