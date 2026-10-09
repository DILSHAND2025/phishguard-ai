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
  if (typeof window !== 'undefined') {
    const currentOrigin = (window.location && window.location.origin) || '';

    // 1. User-configured custom gateway from Settings in localStorage
    try {
      const storage = window.localStorage;
      if (storage && typeof storage.getItem === 'function') {
        const saved = storage.getItem('maverick_backend_url');
        if (saved && typeof saved === 'string' && saved.trim()) {
          const cleaned = cleanUrl(saved);

          // If the stored URL is a temporary or stale vercel.app URL, purge it immediately
          // to prevent routing to deprecated preview deployments.
          if (cleaned.includes('.vercel.app')) {
            try {
              if (typeof storage.removeItem === 'function') {
                storage.removeItem('maverick_backend_url');
              }
            } catch {
              // ignore
            }
            return '';
          }

          // External backend (e.g. Render https://*.onrender.com)
          if (cleaned && cleaned !== currentOrigin) {
            return cleaned;
          }
          return '';
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
      // If VITE_API_URL points to any .vercel.app domain or current origin, use relative paths
      if (cleaned.includes('.vercel.app') || cleaned === currentOrigin) {
        return '';
      }
      return cleaned;
    }

    // 3. Browser default: relative root (same domain as frontend)
    // Co-deployed Vercel serverless functions are accessed via /api/*
    return '';
  }

  // 4. Server-side fallback
  return 'http://localhost:5000';
}
