/**
 * MAVERICK — Serverless ML Threat Inference Proxy: POST /api/predict
 * Smart India Hackathon 2026
 * 
 * Proxies prediction requests to the deployed FastAPI ML inference microservice
 * specified by the ML_SERVICE_URL environment variable.
 */

import { setCorsHeaders, parseJsonBody, sendResponse } from './_utils.js';

export default async function handler(req, res) {
  setCorsHeaders(res);

  if (req.method === 'OPTIONS') {
    return res.status ? res.status(204).end() : (res.writeHead(204), res.end());
  }

  if (req.method === 'GET') {
    const mlUrl = process.env.ML_SERVICE_URL || '';
    return sendResponse(res, 200, {
      status: 'online',
      service: 'MAVERICK ML Inference Proxy',
      mlConfigured: Boolean(mlUrl),
      targetService: mlUrl ? '[CONFIGURED]' : '[UNCONFIGURED]'
    });
  }

  if (req.method !== 'POST') {
    return sendResponse(res, 405, { success: false, error: 'Method Not Allowed' }, { 'Allow': 'GET, POST, OPTIONS' });
  }

  try {
    const body = await parseJsonBody(req);
    const text = body.text || '';

    if (!text || typeof text !== 'string' || text.trim().length === 0) {
      return sendResponse(res, 400, {
        prediction: 'UNAVAILABLE',
        phishing_probability: null,
        legitimate_probability: null,
        model: 'TF-IDF + Logistic Regression',
        status: 'EMPTY_INPUT',
        error: 'Empty or missing email text'
      });
    }

    const mlServiceUrl = (process.env.ML_SERVICE_URL || '').trim().replace(/\/+$/, '');

    if (!mlServiceUrl) {
      return sendResponse(res, 503, {
        prediction: 'UNAVAILABLE',
        phishing_probability: null,
        legitimate_probability: null,
        model: 'TF-IDF + Logistic Regression',
        status: 'UNAVAILABLE',
        error: 'ML inference service unavailable. ML_SERVICE_URL is not configured.'
      });
    }

    const targetUrl = mlServiceUrl.endsWith('/predict') ? mlServiceUrl : `${mlServiceUrl}/predict`;

    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 8000);

    try {
      const mlRes = await fetch(targetUrl, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ text }),
        signal: controller.signal
      });
      clearTimeout(timeoutId);

      if (mlRes.ok) {
        const data = await mlRes.json();
        return sendResponse(res, 200, data);
      }

      return sendResponse(res, 503, {
        prediction: 'UNAVAILABLE',
        phishing_probability: null,
        legitimate_probability: null,
        model: 'TF-IDF + Logistic Regression',
        status: 'UNAVAILABLE',
        error: `ML inference service returned HTTP ${mlRes.status}`
      });
    } catch (fetchErr) {
      clearTimeout(timeoutId);
      const isTimeout = fetchErr.name === 'AbortError';
      return sendResponse(res, 503, {
        prediction: 'UNAVAILABLE',
        phishing_probability: null,
        legitimate_probability: null,
        model: 'TF-IDF + Logistic Regression',
        status: 'UNAVAILABLE',
        error: isTimeout
          ? 'ML inference service timed out (>8000ms)'
          : 'Unable to reach ML inference service at configured ML_SERVICE_URL'
      });
    }
  } catch (err) {
    return sendResponse(res, 500, {
      prediction: 'UNAVAILABLE',
      phishing_probability: null,
      legitimate_probability: null,
      model: 'TF-IDF + Logistic Regression',
      status: 'ERROR',
      error: err.message
    });
  }
}
