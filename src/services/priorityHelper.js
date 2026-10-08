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
        badge: 'bg-red-50 text-red-700 border-red-200 font-bold',
        text: 'text-red-600',
        border: 'border-red-200',
        dot: 'bg-red-500',
        pill: 'bg-red-50 text-red-700 border border-red-200',
        rowHighlight: 'hover:bg-red-50/40'
      };
    case 'high':
      return {
        label: 'HIGH',
        badge: 'bg-orange-50 text-orange-700 border-orange-200 font-semibold',
        text: 'text-orange-600',
        border: 'border-orange-200',
        dot: 'bg-orange-500',
        pill: 'bg-orange-50 text-orange-700 border border-orange-200',
        rowHighlight: 'hover:bg-orange-50/40'
      };
    case 'medium':
      return {
        label: 'MEDIUM',
        badge: 'bg-amber-50 text-amber-700 border-amber-200 font-medium',
        text: 'text-amber-600',
        border: 'border-amber-200',
        dot: 'bg-amber-500',
        pill: 'bg-amber-50 text-amber-700 border border-amber-200',
        rowHighlight: 'hover:bg-amber-50/40'
      };
    case 'low':
    default:
      return {
        label: 'LOW',
        badge: 'bg-emerald-50 text-emerald-700 border-emerald-200 font-medium',
        text: 'text-emerald-600',
        border: 'border-emerald-200',
        dot: 'bg-emerald-500',
        pill: 'bg-emerald-50 text-emerald-700 border border-emerald-200',
        rowHighlight: 'hover:bg-emerald-50/40'
      };
  }
}
