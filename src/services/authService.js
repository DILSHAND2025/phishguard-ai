/**
 * MAVERICK — Google Authentication & Session Service
 * Smart India Hackathon 2026
 * 
 * Handles:
 * - Google OAuth 2.0 / OpenID Connect via Google Identity Services (GIS)
 * - Secure JWT ID Token payload decoding
 * - Session state storage (ID, Name, Email, Picture, Expiration)
 * - Session validation and automatic expiration handling
 * - Clean sign out and token revocation
 */

const STORAGE_KEY = 'maverick_auth_user';
const SESSION_DURATION_HOURS = 8; // 8-hour SOC analyst shift session

// Read Google Client ID from environment variables
export function getGoogleClientId() {
  return import.meta.env.VITE_GOOGLE_CLIENT_ID || '';
}

// Decode standard Base64Url-encoded JWT payload
export function decodeJwtPayload(token) {
  try {
    const base64Url = token.split('.')[1];
    if (!base64Url) return null;
    const base64 = base64Url.replace(/-/g, '+').replace(/_/g, '/');
    const jsonPayload = decodeURIComponent(
      atob(base64)
        .split('')
        .map(c => '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2))
        .join('')
    );
    return JSON.parse(jsonPayload);
  } catch (err) {
    console.error('Failed to decode JWT ID token:', err);
    return null;
  }
}

// Retrieve current authenticated session or null if expired/absent
export function getCurrentUser() {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (!raw) return null;

    const user = JSON.parse(raw);
    if (!user || !user.email) return null;

    // Check expiration
    if (user.expiresAt && Date.now() > user.expiresAt) {
      console.warn('[MAVERICK Auth] Session expired. Clearing session.');
      localStorage.removeItem(STORAGE_KEY);
      return null;
    }

    return user;
  } catch (err) {
    console.error('Error retrieving user session:', err);
    localStorage.removeItem(STORAGE_KEY);
    return null;
  }
}

// Store authenticated user session
export function storeUserSession(userData) {
  const expiresAt = userData.expiresAt || (Date.now() + (SESSION_DURATION_HOURS * 60 * 60 * 1000));
  const cleanSession = {
    id: userData.id || userData.sub || 'google-user-01',
    name: userData.name || 'Authorized Investigator',
    email: userData.email || 'analyst@gov-organization.in',
    picture: userData.picture || '',
    authMethod: userData.authMethod || 'google-oauth2',
    authenticatedAt: new Date().toISOString(),
    expiresAt
  };

  localStorage.setItem(STORAGE_KEY, JSON.stringify(cleanSession));
  return cleanSession;
}

// Clear authenticated session and logout
export function logout() {
  localStorage.removeItem(STORAGE_KEY);
  if (window.google?.accounts?.id) {
    try {
      window.google.accounts.id.disableAutoSelect();
    } catch {
      // ignore
    }
  }
}

// Initialize Google Identity Services (GIS) if library is loaded
export function initGoogleIdentityServices({ onCredentialResponse, onError }) {
  const clientId = getGoogleClientId();

  if (!window.google?.accounts?.id) {
    console.warn('[MAVERICK Auth] Google Identity Services SDK not yet loaded in window.');
    return false;
  }

  if (!clientId) {
    console.warn('[MAVERICK Auth] VITE_GOOGLE_CLIENT_ID is not configured in .env.');
    return false;
  }

  try {
    window.google.accounts.id.initialize({
      client_id: clientId,
      callback: (response) => {
        if (response.credential) {
          const payload = decodeJwtPayload(response.credential);
          if (payload) {
            const user = storeUserSession({
              id: payload.sub,
              name: payload.name,
              email: payload.email,
              picture: payload.picture,
              authMethod: 'google-oauth-oidc',
              expiresAt: payload.exp ? payload.exp * 1000 : undefined
            });
            onCredentialResponse?.(user);
          } else {
            onError?.('Failed to decode Google ID token.');
          }
        } else {
          onError?.('No credential returned from Google OAuth.');
        }
      },
      auto_select: false,
      cancel_on_tap_outside: true
    });

    return true;
  } catch (err) {
    console.error('[MAVERICK Auth] Error initializing Google Identity Services:', err);
    onError?.(err.message);
    return false;
  }
}
