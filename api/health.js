/**
 * MAVERICK — Serverless Health Check Endpoint: GET /api/health
 * Smart India Hackathon 2026
 */

import { setCorsHeaders, sendResponse } from './_utils.js';
import { isDatabaseAvailable } from '../server/caseDatabase.js';

export default async function handler(req, res) {
  setCorsHeaders(res);

  if (req.method === 'OPTIONS') {
    return res.status ? res.status(204).end() : (res.writeHead(204), res.end());
  }

  if (req.method !== 'GET') {
    return sendResponse(res, 405, { success: false, error: 'Method Not Allowed' }, { 'Allow': 'GET, OPTIONS' });
  }

  try {
    const dbActive = await isDatabaseAvailable();
    return sendResponse(res, 200, {
      status: 'online',
      service: 'MAVERICK Intelligence & Machine Learning Gateway',
      environment: 'SIH-2026',
      gatewayType: 'Serverless Function',
      databaseConfigured: Boolean(process.env.DATABASE_URL),
      databaseConnected: dbActive,
      mlConfigured: Boolean(process.env.ML_SERVICE_URL)
    });
  } catch (err) {
    return sendResponse(res, 500, {
      status: 'error',
      error: err.message
    });
  }
}
