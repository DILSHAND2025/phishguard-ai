/**
 * MAVERICK — Serverless Single Case Endpoint: GET /api/cases/:caseId & PATCH /api/cases/:caseId
 * Smart India Hackathon 2026
 */

import { setCorsHeaders, parseJsonBody, sendResponse } from '../_utils.js';
import { getCaseByCaseId, updateCaseStatus, DatabaseUnavailableError } from '../../server/caseDatabase.js';

export default async function handler(req, res) {
  setCorsHeaders(res);

  if (req.method === 'OPTIONS') {
    return res.status ? res.status(204).end() : (res.writeHead(204), res.end());
  }

  // Extract caseId from query or url
  let caseId = req.query?.caseId;
  if (!caseId && req.url) {
    const match = req.url.match(/\/api\/cases\/([A-Za-z0-9_-]+)/);
    if (match) {
      caseId = match[1];
    }
  }

  if (!caseId || caseId === 'stats') {
    return sendResponse(res, 400, { success: false, error: 'Missing or invalid caseId' });
  }

  if (req.method === 'GET') {
    try {
      const item = await getCaseByCaseId(caseId);
      if (!item) {
        return sendResponse(res, 404, { success: false, error: `Case ${caseId} not found` });
      }
      return sendResponse(res, 200, item);
    } catch (err) {
      if (err instanceof DatabaseUnavailableError || err.code === 'DB_UNAVAILABLE') {
        return sendResponse(res, 503, {
          success: false,
          error: 'Database is unavailable or DATABASE_URL is not configured.',
          status: 'DB_UNAVAILABLE'
        });
      }
      return sendResponse(res, 500, { success: false, error: err.message });
    }
  }

  if (req.method === 'PATCH') {
    try {
      const body = await parseJsonBody(req);
      if (!body.status) {
        return sendResponse(res, 400, { success: false, error: 'Missing status parameter in update request' });
      }
      const updated = await updateCaseStatus(caseId, body.status);
      if (!updated) {
        return sendResponse(res, 404, { success: false, error: `Case ${caseId} not found` });
      }
      return sendResponse(res, 200, { success: true, case: updated });
    } catch (err) {
      if (err instanceof DatabaseUnavailableError || err.code === 'DB_UNAVAILABLE') {
        return sendResponse(res, 503, {
          success: false,
          error: 'Database is unavailable or DATABASE_URL is not configured.',
          status: 'DB_UNAVAILABLE'
        });
      }
      return sendResponse(res, 400, { success: false, error: err.message });
    }
  }

  return sendResponse(res, 405, { success: false, error: 'Method Not Allowed' }, { 'Allow': 'GET, PATCH, OPTIONS' });
}
