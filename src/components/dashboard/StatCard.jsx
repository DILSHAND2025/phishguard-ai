import React from 'react';
import { ArrowUpRight, ArrowDownRight } from 'lucide-react';

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
      dot: 'bg-cyan-500',
      badge: 'bg-cyan-50 text-cyan-700 border-cyan-200',
      iconText: 'text-cyan-600',
      iconBg: 'bg-cyan-50 border-cyan-100',
    },
    red: {
      dot: 'bg-red-500',
      badge: 'bg-red-50 text-red-700 border-red-200',
      iconText: 'text-red-600',
      iconBg: 'bg-red-50 border-red-100',
    },
    orange: {
      dot: 'bg-orange-500',
      badge: 'bg-orange-50 text-orange-700 border-orange-200',
      iconText: 'text-orange-600',
      iconBg: 'bg-orange-50 border-orange-100',
    },
    amber: {
      dot: 'bg-amber-500',
      badge: 'bg-amber-50 text-amber-700 border-amber-200',
      iconText: 'text-amber-600',
      iconBg: 'bg-amber-50 border-amber-100',
    },
    emerald: {
      dot: 'bg-emerald-500',
      badge: 'bg-emerald-50 text-emerald-700 border-emerald-200',
      iconText: 'text-emerald-600',
      iconBg: 'bg-emerald-50 border-emerald-100',
    },
  };

  const style = colorMap[accentColor] || colorMap.cyan;

  return (
    <div className="relative rounded-xl bg-white p-4 sm:p-5 border border-slate-200 shadow-2xs hover:border-slate-300 transition-all flex flex-col justify-between">
      <div>
        <div className="flex items-center justify-between mb-2">
          <div className="flex items-center gap-2">
            <span className={`w-2 h-2 rounded-full ${style.dot}`}></span>
            <span className="text-[11px] font-semibold uppercase tracking-wider text-slate-500 font-mono">
              {title}
            </span>
          </div>

          {Icon && (
            <div className={`p-1.5 rounded-lg border ${style.iconBg} ${style.iconText}`}>
              <Icon className="w-4 h-4" />
            </div>
          )}
        </div>

        <div className="mt-1 flex items-baseline gap-2">
          <h3 className="text-2xl sm:text-3xl font-bold tracking-tight text-slate-900 font-mono">
            {value}
          </h3>
          {subValue && (
            <span className="text-xs text-slate-500 font-mono">
              {subValue}
            </span>
          )}
        </div>
      </div>

      <div className="mt-3.5 flex items-center justify-between pt-3 border-t border-slate-100 text-xs">
        <div className="flex items-center gap-1.5 font-mono">
          {change && (
            <span
              className={`flex items-center text-[11px] font-semibold ${
                trend === 'down' ? 'text-emerald-600' : 'text-slate-600'
              }`}
            >
              {trend === 'up' ? (
                <ArrowUpRight className="w-3.5 h-3.5 text-slate-400" />
              ) : (
                <ArrowDownRight className="w-3.5 h-3.5 text-emerald-500" />
              )}
              {change}
            </span>
          )}
          <span className="text-slate-400 text-[10px]">vs. last window</span>
        </div>

        {highlightTag && (
          <span className={`text-[10px] font-mono px-2 py-0.5 rounded border font-medium ${style.badge}`}>
            {highlightTag}
          </span>
        )}
      </div>
    </div>
  );
};
