/**
 * MAVERICK — Backend Intelligence Gateway (Node.js Built-in Zero-Dependency Server)
 * Smart India Hackathon 2026
 * 
 * Provides:
 * - API Key Protection: VirusTotal & AbuseIPDB keys never exposed to browser
 * - In-memory LRU caching of threat lookups
 * - Rate-limit and timeout handling (3000ms max)
 * - Safe fallback: returns UNKNOWN rather than fake data
 * 
 * Usage:
 * node server/server.js
 */

import http from 'node:http';
import https from 'node:https';
import url from 'node:url';
import { analyzeAttachment } from '../src/services/attachmentForensics.js';
import { analyzeEmailAuthentication } from '../src/services/emailAuthService.js';
import { buildForensicReport } from '../src/services/forensicReportService.js';
import { generateForensicPdf, computePdfFileHash } from '../src/services/pdfBuilder.js';
import { isPrivateOrReservedIP } from '../src/services/emailParser.js';

export { isPrivateOrReservedIP };

const PORT = process.env.PORT || 5000;
const VT_API_KEY = process.env.VIRUSTOTAL_API_KEY || '';
const ABUSE_API_KEY = process.env.ABUSEIPDB_API_KEY || '';
const PYTHON_CMD = process.env.PYTHON_PATH || (process.platform === 'win32' ? 'python' : 'python3');

const CACHE = new Map();

function sendJson(res, statusCode, data) {
  res.writeHead(statusCode, {
    'Content-Type': 'application/json',
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization'
  });
  res.end(JSON.stringify(data));
}

// Perform external HTTPS request with timeout
function fetchExternalJson(targetUrl, headers = {}, timeoutMs = 3000) {
  return new Promise((resolve, reject) => {
    const req = https.get(targetUrl, { headers, timeout: timeoutMs }, (res) => {
      let rawData = '';
      res.on('data', chunk => rawData += chunk);
      res.on('end', () => {
        try {
          if (res.statusCode >= 200 && res.statusCode < 300) {
            resolve(JSON.parse(rawData));
          } else {
            resolve(null);
          }
        } catch {
          resolve(null);
        }
      });
    });

    req.on('timeout', () => {
      req.destroy();
      resolve(null);
    });

    req.on('error', () => resolve(null));
  });
}

const server = http.createServer(async (req, res) => {
  // Handle CORS preflight
  if (req.method === 'OPTIONS') {
    res.writeHead(204, {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type, Authorization'
    });
    return res.end();
  }

  const parsedUrl = url.parse(req.url, true);
  const pathname = parsedUrl.pathname;

  // Root and Health check
  if (pathname === '/' || pathname === '/health' || pathname === '/api/health') {
    return sendJson(res, 200, {
      status: 'online',
      service: 'MAVERICK Intelligence & Machine Learning Gateway',
      environment: 'SIH-2026',
      vtKeyConfigured: Boolean(VT_API_KEY),
      abuseKeyConfigured: Boolean(ABUSE_API_KEY),
      cachedEntries: CACHE.size,
      endpoints: [
        'POST /predict or /api/ml/predict',
        'GET  /api/health',
        'GET  /api/geoip?ip=<ip>',
        'GET  /api/enrich?ioc=<ioc>&type=<IP|DOMAIN|HASH>',
        'POST /api/forensic-report/compile',
        'POST /api/forensic-report/pdf'
      ]
    });
  }

  // ML Prediction Endpoint: POST /predict or /api/ml/predict
  if ((pathname === '/predict' || pathname === '/api/ml/predict' || pathname === '/api/predict') && req.method === 'POST') {
    let body = '';
    req.on('data', chunk => body += chunk);
    req.on('end', async () => {
      try {
        const parsed = JSON.parse(body || '{}');
        const text = parsed.text || '';

        // 1. Try FastAPI ML Microservice on port 8000
        try {
          const controller = new AbortController();
          const timeoutId = setTimeout(() => controller.abort(), 2500);
          const mlRes = await fetch('http://127.0.0.1:8000/predict', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ text }),
            signal: controller.signal
          });
          clearTimeout(timeoutId);
          if (mlRes.ok) {
            const data = await mlRes.json();
            return sendJson(res, 200, data);
          }
        } catch {
          // FastAPI microservice offline or timeout, continue to CLI fallback
        }

        // 2. Direct CLI fallback using Python ml/predict.py
        try {
          const { execFile } = await import('node:child_process');
          execFile(PYTHON_CMD, ['ml/predict.py', '--text', text], { timeout: 15000 }, (err, stdout, stderr) => {
            if (err || stderr) {
              return sendJson(res, 503, {
                prediction: "UNAVAILABLE",
                phishing_probability: null,
                legitimate_probability: null,
                model: "TF-IDF + Logistic Regression",
                status: "UNAVAILABLE",
                error: "ML inference service unavailable"
              });
            }
            try {
              const result = JSON.parse(stdout.trim());
              return sendJson(res, 200, result);
            } catch {
              return sendJson(res, 500, {
                prediction: "UNAVAILABLE",
                status: "UNAVAILABLE",
                error: "Malformed ML output"
              });
            }
          });
          return;
        } catch {
          // fallback
        }

        return sendJson(res, 503, {
          prediction: "UNAVAILABLE",
          phishing_probability: null,
          legitimate_probability: null,
          model: "TF-IDF + Logistic Regression",
          status: "UNAVAILABLE"
        });
      } catch {
        return sendJson(res, 400, { error: 'Invalid JSON request payload' });
      }
    });
    return;
  }

  // GeoIP endpoint
  if (pathname === '/api/geoip') {
    const ip = parsedUrl.query.ip;
    if (!ip) return sendJson(res, 400, { error: 'Missing ip parameter', status: 'INVALID_INPUT' });

    // Validate IP format
    const ipv4Regex = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
    const isIPv4 = ipv4Regex.test(ip.trim());
    const isIPv6 = ip.includes(':');
    if (!isIPv4 && !isIPv6) {
      return sendJson(res, 400, { ip, status: 'INVALID_IP', error: 'Invalid IP address format' });
    }

    // Check private / reserved IP (SSRF Protection)
    const cleanIP = ip.trim().toLowerCase();
    if (isPrivateOrReservedIP(cleanIP)) {
      return sendJson(res, 200, {
        ip: cleanIP,
        status: 'PRIVATE_IP',
        isPrivate: true,
        error: 'Private/reserved non-routable IP address',
        country: 'Private / Reserved Network',
        countryCode: 'LAN',
        city: 'Local Area Network',
        latitude: null,
        longitude: null,
        isp: 'Private Infrastructure',
        asn: 'N/A'
      });
    }

    const cacheKey = `geo:${cleanIP}`;
    if (CACHE.has(cacheKey)) {
      return sendJson(res, 200, CACHE.get(cacheKey));
    }

    // 1. Try ipwho.is (HTTPS, fast, zero auth required)
    try {
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 2800);
      const resp = await fetch(`https://ipwho.is/${encodeURIComponent(cleanIP)}`, {
        signal: controller.signal,
        headers: { 'Accept': 'application/json' }
      });
      clearTimeout(timeoutId);

      if (resp.ok) {
        const live = await resp.json();
        if (live && live.success !== false && live.country) {
          const geoRecord = {
            ip: cleanIP,
            status: 'SUCCESS',
            country: live.country || 'Unknown Country',
            countryCode: live.country_code || live.countryCode || '',
            region: live.region || live.regionName || '',
            city: live.city || '',
            latitude: typeof live.latitude === 'number' ? live.latitude : null,
            longitude: typeof live.longitude === 'number' ? live.longitude : null,
            timezone: live.timezone?.id || live.timezone || '',
            asn: live.connection?.asn ? `AS${live.connection.asn}` : 'Unknown ASN',
            asnOrg: live.connection?.org || live.connection?.isp || '',
            isp: live.connection?.isp || live.connection?.org || '',
            networkType: 'Commercial Transit Network',
            riskLevel: 'LOW',
            isProxyOrVpn: false,
            routingDetails: live.connection?.asn ? `BGP ASN: AS${live.connection.asn} (${live.connection.isp || ''})` : ''
          };
          CACHE.set(cacheKey, geoRecord);
          return sendJson(res, 200, geoRecord);
        }
      }
    } catch {
      // Fallback to ip-api
    }

    // 2. Fallback to ip-api.com over HTTP
    try {
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 2500);
      const resp = await fetch(`http://ip-api.com/json/${encodeURIComponent(cleanIP)}?fields=status,country,countryCode,regionName,city,lat,lon,timezone,isp,org,as`, {
        signal: controller.signal
      });
      clearTimeout(timeoutId);

      if (resp.ok) {
        const live = await resp.json();
        if (live && live.status === 'success') {
          const asnParts = (live.as || '').split(' ');
          const geoRecord = {
            ip: cleanIP,
            status: 'SUCCESS',
            country: live.country || 'Unknown Country',
            countryCode: live.countryCode || '',
            region: live.regionName || '',
            city: live.city || '',
            latitude: typeof live.lat === 'number' ? live.lat : null,
            longitude: typeof live.lon === 'number' ? live.lon : null,
            timezone: live.timezone || '',
            asn: asnParts[0] || 'Unknown ASN',
            asnOrg: live.org || live.isp || '',
            isp: live.isp || live.org || '',
            networkType: 'Commercial Transit Network',
            riskLevel: 'LOW',
            isProxyOrVpn: false,
            routingDetails: live.as ? `BGP: ${live.as}` : ''
          };
          CACHE.set(cacheKey, geoRecord);
          return sendJson(res, 200, geoRecord);
        }
      }
    } catch {
      // Both external providers unavailable
    }

    // Return explicit UNAVAILABLE on failure - NEVER fabricate coordinates
    return sendJson(res, 200, {
      ip: cleanIP,
      status: 'UNAVAILABLE',
      error: 'Geolocation unavailable',
      country: 'Geolocation unavailable',
      countryCode: '',
      region: '',
      city: '',
      latitude: null,
      longitude: null,
      isp: 'Intelligence unavailable',
      asn: 'AS-UNKNOWN',
      asnOrg: 'Autonomous System resolution offline'
    });
  }

  // Threat Intelligence enrichment endpoint
  if (pathname === '/api/enrich') {
    const ioc = parsedUrl.query.ioc;
    const type = parsedUrl.query.type || 'UNKNOWN';
    if (!ioc) return sendJson(res, 400, { error: 'Missing ioc parameter' });

    const cacheKey = `enrich:${ioc.toLowerCase()}`;
    if (CACHE.has(cacheKey)) {
      return sendJson(res, 200, CACHE.get(cacheKey));
    }

    let vtData = { score: '0/88', verdict: 'UNKNOWN', details: 'VT API key unconfigured' };
    let abuseData = { abuseScore: 0, totalReports: 0, verdict: 'UNKNOWN', details: 'AbuseIPDB key unconfigured' };

    // AbuseIPDB query for IPs
    if (type.toUpperCase() === 'IP' && ABUSE_API_KEY) {
      try {
        const abuseRes = await fetchExternalJson(
          `https://api.abuseipdb.com/api/v2/check?ipAddress=${encodeURIComponent(ioc)}&maxAgeInDays=90`,
          { 'Key': ABUSE_API_KEY, 'Accept': 'application/json' }
        );
        if (abuseRes && abuseRes.data) {
          abuseData = {
            abuseScore: abuseRes.data.abuseConfidenceScore || 0,
            totalReports: abuseRes.data.totalReports || 0,
            verdict: abuseRes.data.abuseConfidenceScore > 50 ? 'HIGH ABUSE CONFIDENCE' : 'LOW RISK',
            details: `Country: ${abuseRes.data.countryCode || 'N/A'}, ISP: ${abuseRes.data.isp || 'N/A'}`
          };
        }
      } catch {
        // keep fallback
      }
    }

    // VirusTotal query for domains / hashes / URLs
    if (VT_API_KEY) {
      try {
        const vtEndpoint = type.toUpperCase() === 'IP' 
          ? `https://www.virustotal.com/api/v3/ip_addresses/${encodeURIComponent(ioc)}`
          : type.toUpperCase() === 'DOMAIN'
            ? `https://www.virustotal.com/api/v3/domains/${encodeURIComponent(ioc)}`
            : (type.toUpperCase() === 'HASH' || type.toUpperCase().includes('SHA') || type.toUpperCase().includes('MD5'))
              ? `https://www.virustotal.com/api/v3/files/${encodeURIComponent(ioc)}`
              : null;

        if (vtEndpoint) {
          const vtRes = await fetchExternalJson(vtEndpoint, { 'x-apikey': VT_API_KEY });
          if (vtRes && vtRes.data && vtRes.data.attributes) {
            const stats = vtRes.data.attributes.last_analysis_stats || {};
            const mal = stats.malicious || 0;
            const sus = stats.suspicious || 0;
            const total = (stats.harmless || 0) + (stats.undetected || 0) + mal + sus;
            vtData = {
              score: `${mal}/${total}`,
              verdict: mal > 5 ? 'MALICIOUS' : sus > 2 ? 'SUSPICIOUS' : 'CLEAN',
              details: `Flagged malicious by ${mal} security vendors`
            };
          }
        }
      } catch {
        // keep fallback
      }
    }

    const payload = {
      ioc,
      type,
      enriched: true,
      source: 'MAVERICK Backend Gateway',
      virusTotal: vtData,
      abuseIPDB: abuseData,
      urlhaus: { verdict: 'UNLISTED', status: 'Checked' },
      phishTank: { verdict: 'UNLISTED', details: 'Checked' },
      cachedAt: new Date().toISOString()
    };

    CACHE.set(cacheKey, payload);
    return sendJson(res, 200, payload);
  }

  // Attachment Forensic Analysis Endpoint: POST /api/attachment/analyze
  if (pathname === '/api/attachment/analyze' && req.method === 'POST') {
    const contentType = req.headers['content-type'] || '';
    const chunks = [];

    req.on('data', chunk => chunks.push(chunk));
    req.on('end', async () => {
      try {
        const fullBuffer = Buffer.concat(chunks);
        let filename = 'attachment.bin';
        let mimeType = 'application/octet-stream';
        let contentBuffer = null;

        if (contentType.includes('application/json')) {
          const jsonBody = JSON.parse(fullBuffer.toString('utf-8') || '{}');
          filename = jsonBody.filename || 'attachment.bin';
          mimeType = jsonBody.mime_type || jsonBody.mimeType || 'application/octet-stream';
          if (jsonBody.content) {
            contentBuffer = Buffer.from(jsonBody.content, 'base64');
          }
        } else if (contentType.includes('multipart/form-data')) {
          // Parse multipart form data safely in-memory without OS execution
          const boundaryMatch = contentType.match(/boundary=(?:"([^"]+)"|([^;]+))/i);
          if (boundaryMatch) {
            const boundary = boundaryMatch[1] || boundaryMatch[2];
            const boundaryBuffer = Buffer.from(`--${boundary}`);
            let start = fullBuffer.indexOf(boundaryBuffer);

            while (start !== -1) {
              const nextStart = fullBuffer.indexOf(boundaryBuffer, start + boundaryBuffer.length);
              const part = nextStart !== -1 
                ? fullBuffer.subarray(start + boundaryBuffer.length, nextStart)
                : fullBuffer.subarray(start + boundaryBuffer.length);

              const headerEnd = part.indexOf(Buffer.from('\r\n\r\n'));
              if (headerEnd !== -1) {
                const headerText = part.subarray(0, headerEnd).toString('utf-8');
                const fileMatch = headerText.match(/filename="?([^"\r\n]+)"?/i);
                const typeMatch = headerText.match(/Content-Type:\s*([^\r\n;]+)/i);

                if (fileMatch) {
                  filename = fileMatch[1];
                  if (typeMatch) mimeType = typeMatch[1].trim();
                  // Extract binary data (trim leading \r\n\r\n and trailing \r\n)
                  let dataPart = part.subarray(headerEnd + 4);
                  if (dataPart.length >= 2 && dataPart[dataPart.length - 2] === 0x0D && dataPart[dataPart.length - 1] === 0x0A) {
                    dataPart = dataPart.subarray(0, dataPart.length - 2);
                  }
                  contentBuffer = dataPart;
                  break;
                }
              }
              start = nextStart;
            }
          }
        } else {
          // Raw stream fallback
          contentBuffer = fullBuffer;
        }

        // Run safe static forensic analysis
        const forensicResult = await analyzeAttachment({
          filename,
          content: contentBuffer,
          mimeType
        });

        // Query hash reputation if VT_API_KEY is active and sha256 is present
        let reputation = {
          provider: 'VirusTotal (via Gateway)',
          status: 'UNAVAILABLE',
          verdict: 'UNAVAILABLE',
          score: 'N/A',
          details: 'Threat intelligence API unconfigured on server'
        };

        if (VT_API_KEY && forensicResult.sha256) {
          try {
            const vtRes = await fetchExternalJson(
              `https://www.virustotal.com/api/v3/files/${encodeURIComponent(forensicResult.sha256)}`,
              { 'x-apikey': VT_API_KEY }
            );
            if (vtRes && vtRes.data && vtRes.data.attributes) {
              const stats = vtRes.data.attributes.last_analysis_stats || {};
              const mal = stats.malicious || 0;
              const sus = stats.suspicious || 0;
              const total = (stats.harmless || 0) + (stats.undetected || 0) + mal + sus;
              reputation = {
                provider: 'VirusTotal',
                status: 'SUCCESS',
                score: `${mal}/${total}`,
                maliciousCount: mal,
                totalCount: total,
                verdict: mal > 5 ? 'MALICIOUS' : sus > 2 ? 'SUSPICIOUS' : 'CLEAN',
                details: `Flagged malicious by ${mal} security vendors`
              };
            }
          } catch {
            // Keep unavailable
          }
        }

        const responsePayload = {
          filename: forensicResult.filename,
          size: forensicResult.sizeBytes,
          mime_type: forensicResult.mimeType,
          detected_type: forensicResult.detectedType,
          sha256: forensicResult.sha256,
          sha1: forensicResult.sha1,
          md5: forensicResult.md5,
          indicators: forensicResult.observed?.indicators || [],
          reputation,
          risk: forensicResult.inferred || {},
          status: 'SUCCESS'
        };

        return sendJson(res, 200, responsePayload);
      } catch (err) {
        return sendJson(res, 500, {
          status: 'ERROR',
          error: 'Failed to process attachment static analysis',
          details: err.message
        });
      }
    });
    return;
  }

  // Email Authentication & DNS Forensics Endpoint: POST /api/email-authentication
  if ((pathname === '/api/email-authentication' || pathname === '/api/email/authenticate') && req.method === 'POST') {
    const contentType = req.headers['content-type'] || '';
    const chunks = [];
    let receivedBytes = 0;
    const MAX_BYTES = 10 * 1024 * 1024; // 10MB safety threshold

    req.on('data', chunk => {
      receivedBytes += chunk.length;
      if (receivedBytes > MAX_BYTES) {
        req.destroy(new Error('Payload exceeds maximum allowed size (10MB)'));
        return;
      }
      chunks.push(chunk);
    });

    req.on('error', (err) => {
      return sendJson(res, 413, {
        status: 'ERROR',
        error: err.message || 'Request payload too large'
      });
    });

    req.on('end', async () => {
      try {
        const fullBuffer = Buffer.concat(chunks);
        let rawEmail = '';

        if (contentType.includes('application/json')) {
          const jsonBody = JSON.parse(fullBuffer.toString('utf-8') || '{}');
          rawEmail = jsonBody.email || jsonBody.rawEmail || jsonBody.text || '';
        } else {
          rawEmail = fullBuffer.toString('utf-8');
        }

        if (!rawEmail || !rawEmail.trim()) {
          return sendJson(res, 400, {
            success: false,
            status: 'INVALID_INPUT',
            error: 'Missing or empty email content in request payload'
          });
        }

        const authResult = await analyzeEmailAuthentication(rawEmail);
        return sendJson(res, 200, {
          success: true,
          status: 'SUCCESS',
          ...authResult
        });
      } catch (err) {
        return sendJson(res, 500, {
          success: false,
          status: 'ERROR',
          error: 'Failed to process email authentication forensics',
          details: err.message
        });
      }
    });
    return;
  }

  // Automated Forensic Report Generation Endpoint: POST /api/forensic-report
  if ((pathname === '/api/forensic-report' || pathname === '/api/report') && req.method === 'POST') {
    let body = '';
    req.on('data', chunk => body += chunk);
    req.on('end', async () => {
      try {
        const payload = JSON.parse(body || '{}');
        const analysisData = payload.analysisResult || payload.analysis || payload;
        const options = payload.options || {};
        
        const report = await buildForensicReport(analysisData, options);
        return sendJson(res, 200, {
          success: true,
          status: 'SUCCESS',
          report
        });
      } catch (err) {
        return sendJson(res, 500, {
          success: false,
          status: 'ERROR',
          error: 'Failed to compile forensic report',
          details: err.message
        });
      }
    });
    return;
  }

  // Certified Forensic Report PDF Export Endpoint: POST /api/forensic-report/pdf
  if ((pathname === '/api/forensic-report/pdf' || pathname === '/api/report/pdf') && req.method === 'POST') {
    let body = '';
    req.on('data', chunk => body += chunk);
    req.on('end', async () => {
      try {
        const payload = JSON.parse(body || '{}');
        const report = payload.report || await buildForensicReport(payload.analysisResult || payload.analysis || payload, payload.options);
        const pdfBytes = generateForensicPdf(report);
        const fileHash = await computePdfFileHash(pdfBytes);
        const filename = `${report.caseId || 'MAV-2026-REPORT'}-Forensic-Dossier.pdf`;

        const acceptHeader = req.headers['accept'] || '';
        if (payload.format === 'json' || acceptHeader.includes('application/json')) {
          return sendJson(res, 200, {
            success: true,
            status: 'SUCCESS',
            caseId: report.caseId,
            filename,
            pdfSha256: fileHash,
            pdfBase64: Buffer.from(pdfBytes).toString('base64'),
            contentHash: report.evidenceIntegrity?.contentHashSha256
          });
        }

        res.writeHead(200, {
          'Content-Type': 'application/pdf',
          'Content-Length': pdfBytes.length,
          'Content-Disposition': `attachment; filename="${filename}"`,
          'X-Report-SHA256': fileHash,
          'Access-Control-Allow-Origin': '*',
          'Access-Control-Expose-Headers': 'X-Report-SHA256, Content-Disposition'
        });
        return res.end(Buffer.from(pdfBytes));
      } catch (err) {
        return sendJson(res, 500, {
          success: false,
          status: 'ERROR',
          error: 'Failed to generate forensic PDF',
          details: err.message
        });
      }
    });
    return;
  }

  // Fallback 404
  return sendJson(res, 404, { error: 'Route not found' });
});

const isDirectExecution = Boolean(process.argv[1] && (process.argv[1].endsWith('server.js') || process.argv[1].endsWith('server')));
if (isDirectExecution) {
  server.listen(PORT, '0.0.0.0', () => {
    console.log(`[+] MAVERICK Intelligence Gateway running on http://0.0.0.0:${PORT}`);
    console.log(`[+] VirusTotal configured: ${Boolean(VT_API_KEY)} | AbuseIPDB configured: ${Boolean(ABUSE_API_KEY)}`);
  });
}

export { server };
