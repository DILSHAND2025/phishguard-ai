/**
 * MAVERICK — Serverless Email Authentication & DNS Forensics Endpoint: POST /api/email-authentication
 * Smart India Hackathon 2026
 */

import { setCorsHeaders, parseJsonBody, sendResponse } from './_utils.js';
import { analyzeEmailAuthentication } from '../src/services/emailAuthService.js';

export default async function handler(req, res) {
  setCorsHeaders(res);

  if (req.method === 'OPTIONS') {
    return res.status ? res.status(204).end() : (res.writeHead(204), res.end());
  }

  if (req.method !== 'POST') {
    return sendResponse(res, 405, { success: false, error: 'Method Not Allowed' }, { 'Allow': 'POST, OPTIONS' });
  }

  try {
    const body = await parseJsonBody(req);
    const rawEmail = body.email || body.rawEmail || body.text || (typeof body === 'string' ? body : '');

    if (!rawEmail || !rawEmail.trim()) {
      return sendResponse(res, 400, {
        success: false,
        status: 'INVALID_INPUT',
        error: 'Missing or empty email content in request payload'
      });
    }

    const authResult = await analyzeEmailAuthentication(rawEmail);
    return sendResponse(res, 200, {
      success: true,
      status: 'SUCCESS',
      ...authResult
    });
  } catch (err) {
    return sendResponse(res, 500, {
      success: false,
      status: 'ERROR',
      error: 'Failed to process email authentication forensics',
      details: err.message
    });
  }
}
