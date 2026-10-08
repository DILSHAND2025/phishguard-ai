/**
 * MAVERICK — Centralized Threat Priority Helper
 * Smart India Hackathon 2026
 * 
 * Maps the final Evidence Fusion threat score (0-100) to SOC Priority:
 * 80-100 = Critical
 * 60-79  = High
 * 30-59  = Medium
 * 0-29   = Low
 * 
 * @param {number|string} score
 * @returns {'Critical' | 'High' | 'Medium' | 'Low'}
 */
export function getThreatPriority(score) {
  const num = typeof score === 'number' ? score : Number(score);
  if (isNaN(num)) return 'Low';
  if (num >= 80) return 'Critical';
  if (num >= 60) return 'High';
  if (num >= 30) return 'Medium';
  return 'Low';
}

/**
 * Returns consistent SOC priority color tokens
 * - Red for Critical
 * - Orange for High
 * - Yellow/Amber for Medium
 * - Green for Low
 * 
 * @param {string} priority
 */
export function getPriorityStyle(priority) {
  const p = (priority || '').toLowerCase();
  switch (p) {
    case 'critical':
      return {
        label: 'CRITICAL',
        badge: 'bg-red-950/80 text-red-300 border-red-500/60 font-bold',
        text: 'text-red-400',
        border: 'border-red-500/60',
        dot: 'bg-red-500',
        pill: 'bg-red-500/10 text-red-400 border border-red-500/40',
        rowHighlight: 'hover:bg-red-950/20'
      };
    case 'high':
      return {
        label: 'HIGH',
        badge: 'bg-orange-950/80 text-orange-300 border-orange-500/60 font-semibold',
        text: 'text-orange-400',
        border: 'border-orange-500/60',
        dot: 'bg-orange-500',
        pill: 'bg-orange-500/10 text-orange-400 border border-orange-500/40',
        rowHighlight: 'hover:bg-orange-950/20'
      };
    case 'medium':
      return {
        label: 'MEDIUM',
        badge: 'bg-amber-950/80 text-amber-300 border-amber-500/60 font-medium',
        text: 'text-amber-400',
        border: 'border-amber-500/60',
        dot: 'bg-amber-400',
        pill: 'bg-amber-500/10 text-amber-400 border border-amber-500/40',
        rowHighlight: 'hover:bg-amber-950/20'
      };
    case 'low':
    default:
      return {
        label: 'LOW',
        badge: 'bg-emerald-950/80 text-emerald-300 border-emerald-500/60 font-medium',
        text: 'text-emerald-400',
        border: 'border-emerald-500/60',
        dot: 'bg-emerald-400',
        pill: 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/40',
        rowHighlight: 'hover:bg-emerald-950/20'
      };
  }
}
