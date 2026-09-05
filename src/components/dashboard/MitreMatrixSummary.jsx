import React from 'react';
import { ShieldCheck, Crosshair, AlertCircle, Layers } from 'lucide-react';
import { MITRE_TACTICS } from '../../data/mockSocData';

export const MitreMatrixSummary = () => {
  return (
    <div className="rounded-xl bg-gradient-to-b from-[#0c1424] to-[#070b14] border border-slate-800/80 p-5 shadow-lg">
      
      {/* Header */}
      <div className="flex items-center justify-between mb-4">
        <div className="flex items-center gap-2">
          <Layers className="w-4 h-4 text-cyan-400" />
          <h3 className="text-sm font-bold uppercase tracking-wider font-mono text-slate-100">
            MITRE ATT&CK Matrix Correlation
          </h3>
        </div>
        <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-cyan-950/60 border border-cyan-500/30 text-cyan-300">
          v14.1 Enterprise Matrix
        </span>
      </div>

      {/* Grid of Mitre Tactics */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
        {MITRE_TACTICS.map((item) => (
          <div
            key={item.techniqueId}
            className="p-3 rounded-lg bg-[#091122] border border-slate-800 hover:border-cyan-500/40 transition-all font-mono"
          >
            <div className="flex items-center justify-between text-xs mb-1.5">
              <span className="font-bold text-cyan-300">{item.techniqueId}</span>
              <span
                className={`text-[9px] px-1.5 py-0.2 rounded border ${
                  item.severity === 'CRITICAL'
                    ? 'bg-red-950/60 text-red-300 border-red-500/40'
                    : 'bg-amber-950/60 text-amber-300 border-amber-500/40'
                }`}
              >
                {item.severity}
              </span>
            </div>

            <div className="text-xs text-slate-200 font-sans font-medium line-clamp-1">
              {item.name}
            </div>

            <div className="mt-2 pt-2 border-t border-slate-800/60 flex items-center justify-between text-[10px] text-slate-400">
              <span>{item.tactic}</span>
              <span className="text-white font-bold">{item.threatCount} Hits</span>
            </div>
          </div>
        ))}
      </div>

    </div>
  );
};
