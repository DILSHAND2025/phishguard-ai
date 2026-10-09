/**
 * MAVERICK — Serverless Cases Collection Endpoint: GET /api/cases & POST /api/cases
 * Smart India Hackathon 2026
 */

import { setCorsHeaders, parseJsonBody, sendResponse } from '../_utils.js';
import { saveCase, getCases, DatabaseUnavailableError } from '../../server/caseDatabase.js';

export default async function handler(req, res) {
  setCorsHeaders(res);

  if (req.method === 'OPTIONS') {
    return res.status ? res.status(204).end() : (res.writeHead(204), res.end());
  }

  // GET /api/cases
  if (req.method === 'GET') {
    try {
      const query = req.query || {};
      // If query is not parsed by runtime, parse from req.url
      let priority = query.priority;
      let classification = query.classification;
      let status = query.status || 'active';
      let page = query.page || 1;
      let limit = query.limit || 20;
      let search = query.search || '';
      let format = query.format;

      if (!priority && req.url && req.url.includes('?')) {
        const u = new URL(req.url, 'http://localhost');
        priority = u.searchParams.get('priority') || priority;
        classification = u.searchParams.get('classification') || classification;
        status = u.searchParams.get('status') || status;
        page = u.searchParams.get('page') || page;
        limit = u.searchParams.get('limit') || limit;
        search = u.searchParams.get('search') || search;
        format = u.searchParams.get('format') || format;
      }

      const result = await getCases({ priority, classification, status, page, limit, search });

      const extraHeaders = {
        'X-Total-Count': String(result.total),
        'X-Page': String(result.page),
        'X-Limit': String(result.limit),
        'X-Total-Pages': String(result.totalPages)
      };

      if (format === 'envelope' || query.envelope === 'true') {
        return sendResponse(res, 200, result, extraHeaders);
      }
      return sendResponse(res, 200, result.cases, extraHeaders);
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

  // POST /api/cases
  if (req.method === 'POST') {
    try {
      const payload = await parseJsonBody(req);
      const saved = await saveCase(payload);
      return sendResponse(res, saved.isDuplicate ? 200 : 201, {
        success: true,
        caseId: saved.caseId,
        isDuplicate: saved.isDuplicate,
        case: saved.case
      });
    } catch (err) {
      if (err instanceof DatabaseUnavailableError || err.code === 'DB_UNAVAILABLE') {
        return sendResponse(res, 503, {
          success: false,
          error: err.message || 'Analysis completed, but the case could not be saved. Database is unavailable.',
          status: 'DB_UNAVAILABLE'
        });
      }
      return sendResponse(res, 400, { success: false, error: err.message });
    }
  }

  // Method not allowed
  return sendResponse(res, 405, { success: false, error: 'Method Not Allowed' }, { 'Allow': 'GET, POST, OPTIONS' });
}
