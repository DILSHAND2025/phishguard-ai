/**
 * MAVERICK — API Configuration Service
 * Smart India Hackathon 2026
 * 
 * Provides the active backend API Gateway URL across:
 * - Render Production Backend (e.g. https://maverick-backend.onrender.com)
 * - Vercel Frontend Environment (VITE_API_URL)
 * - User-configurable custom URL from Settings page (localStorage)
 * - Localhost development (Vite proxy / port 5000)
 */

function cleanUrl(url) {
  if (!url || typeof url !== 'string') return '';
  let cleaned = url.trim().replace(/\/+$/, '');
  if (cleaned.endsWith('/api')) {
    cleaned = cleaned.slice(0, -4).replace(/\/+$/, '');
  }
  return cleaned;
}

export function getApiBaseUrl() {
  // 1. User-configured custom gateway from Settings in localStorage
  try {
    if (typeof window !== 'undefined' && window.localStorage) {
      const saved = localStorage.getItem('maverick_backend_url');
      if (saved && typeof saved === 'string' && saved.trim()) {
        const cleaned = cleanUrl(saved);
        if (typeof window !== 'undefined' && window.location && cleaned === window.location.origin) {
          return '';
        }
        return cleaned;
      }
    }
  } catch {
    // ignore localStorage errors
  }

  // 2. Vite / Process Environment Variable (configured in Vercel / .env)
  const envUrl = (typeof import.meta !== 'undefined' && import.meta.env?.VITE_API_URL) ||
                 (typeof process !== 'undefined' && process.env?.VITE_API_URL);
  if (envUrl && typeof envUrl === 'string' && envUrl.trim()) {
    const cleaned = cleanUrl(envUrl);
    if (typeof window !== 'undefined' && window.location && cleaned === window.location.origin) {
      return '';
    }
    return cleaned;
  }

  // 3. Fallback
  if (typeof window !== 'undefined') {
    return ''; // relative root, works with Vite proxy or same-domain
  }
  return 'http://localhost:5000';
}
