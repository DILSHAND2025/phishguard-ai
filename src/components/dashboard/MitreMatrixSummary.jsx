import React from 'react';
import { Layers } from 'lucide-react';
import { MITRE_TACTICS } from '../../data/mockSocData';

export const MitreMatrixSummary = () => {
  return (
    <div className="rounded-xl bg-white border border-slate-200 p-5 shadow-xs font-sans">
      
      {/* Header */}
      <div className="flex items-center justify-between mb-4">
        <div className="flex items-center gap-2">
          <Layers className="w-4 h-4 text-slate-600" />
          <h3 className="text-sm font-bold uppercase tracking-wider text-slate-900">
            MITRE ATT&CK Matrix Correlation
          </h3>
        </div>
        <span className="text-[10px] font-semibold px-2 py-0.5 rounded bg-slate-100 border border-slate-200 text-slate-700">
          v14.1 Enterprise
        </span>
      </div>

      {/* Grid of Mitre Tactics */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
        {MITRE_TACTICS.map((item) => (
          <div
            key={item.techniqueId}
            className="p-3 rounded-lg bg-slate-50 border border-slate-200 hover:border-slate-300 transition-colors"
          >
            <div className="flex items-center justify-between text-xs mb-1.5">
              <span className="font-bold text-slate-900 font-mono">{item.techniqueId}</span>
              <span
                className={`text-[10px] font-bold px-1.5 py-0.5 rounded border ${
                  item.severity === 'CRITICAL'
                    ? 'bg-red-50 text-red-700 border-red-200'
                    : 'bg-amber-50 text-amber-800 border-amber-200'
                }`}
              >
                {item.severity}
              </span>
            </div>

            <div className="text-xs text-slate-800 font-medium line-clamp-1">
              {item.name}
            </div>

            <div className="mt-2 pt-2 border-t border-slate-200/80 flex items-center justify-between text-[11px] text-slate-500">
              <span>{item.tactic}</span>
              <span className="text-slate-900 font-bold">{item.threatCount} Hits</span>
            </div>
          </div>
        ))}
      </div>

    </div>
  );
};
