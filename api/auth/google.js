// api/auth/google.js – Vercel serverless function for Google OAuth verification
// ------------------------------------------------------------
// This function mirrors the /api/auth/google endpoint that previously
// lived in server/server.js. It validates the Google ID token using
// google-auth-library and returns a minimal user payload to the client.
// ------------------------------------------------------------
import { OAuth2Client } from 'google-auth-library';
import { parseJsonBody, sendResponse } from '../_utils.js';

const oauth2Client = new OAuth2Client(process.env.GOOGLE_CLIENT_ID);

export default async (req, res) => {
  // Allow only POST requests (Vercel may send OPTIONS for CORS preflight)
  if (req.method === 'OPTIONS') {
    // Simple preflight response – CORS headers are set inside sendResponse
    return sendResponse(res, 200, { success: true });
  }

  if (req.method !== 'POST') {
    return sendResponse(res, 405, { success: false, error: 'Method Not Allowed' });
  }

  try {
    const { credential } = await parseJsonBody(req);
    if (!credential) {
      return sendResponse(res, 400, { success: false, error: 'Missing credential' });
    }

    const ticket = await oauth2Client.verifyIdToken({
      idToken: credential,
      audience: process.env.GOOGLE_CLIENT_ID,
    });
    const payload = ticket.getPayload();

    // Return only the fields the client expects
    const user = {
      success: true,
      id: payload.sub,
      name: payload.name,
      email: payload.email,
      picture: payload.picture,
      authMethod: 'google-oauth2-backend',
      expiresAt: payload.exp ? payload.exp * 1000 : undefined,
    };
    return sendResponse(res, 200, user);
  } catch (err) {
    console.error('[Vercel Auth] Verification error:', err);
    return sendResponse(res, 401, { success: false, error: 'Invalid ID token', details: err.message });
  }
};
