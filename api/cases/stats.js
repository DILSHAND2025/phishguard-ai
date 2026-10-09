/**
 * MAVERICK — Serverless Case Statistics Endpoint: GET /api/cases/stats
 * Smart India Hackathon 2026
 */

import { setCorsHeaders, sendResponse } from '../_utils.js';
import { getCaseStats, DatabaseUnavailableError } from '../../server/caseDatabase.js';

export default async function handler(req, res) {
  setCorsHeaders(res);

  if (req.method === 'OPTIONS') {
    return res.status ? res.status(204).end() : (res.writeHead(204), res.end());
  }

  if (req.method !== 'GET') {
    return sendResponse(res, 405, { success: false, error: 'Method Not Allowed' }, { 'Allow': 'GET, OPTIONS' });
  }

  try {
    const stats = await getCaseStats();
    return sendResponse(res, 200, stats);
  } catch (err) {
    if (err instanceof DatabaseUnavailableError || err.code === 'DB_UNAVAILABLE') {
      return sendResponse(res, 503, {
        success: false,
        error: err.message || 'Database is unavailable or DATABASE_URL is not configured.',
        status: 'DB_UNAVAILABLE'
      });
    }
    return sendResponse(res, 500, { success: false, error: err.message });
  }
}
