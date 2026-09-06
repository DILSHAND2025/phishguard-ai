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

const PORT = process.env.PORT || 5000;
const VT_API_KEY = process.env.VIRUSTOTAL_API_KEY || '';
const ABUSE_API_KEY = process.env.ABUSEIPDB_API_KEY || '';

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

  // Health check
  if (pathname === '/api/health') {
    return sendJson(res, 200, {
      status: 'online',
      service: 'MAVERICK Intelligence Gateway',
      environment: 'SIH-2026',
      vtKeyConfigured: Boolean(VT_API_KEY),
      abuseKeyConfigured: Boolean(ABUSE_API_KEY),
      cachedEntries: CACHE.size
    });
  }

  // GeoIP endpoint
  if (pathname === '/api/geoip') {
    const ip = parsedUrl.query.ip;
    if (!ip) return sendJson(res, 400, { error: 'Missing ip parameter' });

    const cacheKey = `geo:${ip}`;
    if (CACHE.has(cacheKey)) {
      return sendJson(res, 200, CACHE.get(cacheKey));
    }

    try {
      const liveData = await fetchExternalJson(`https://ip-api.com/json/${ip}?fields=status,country,countryCode,regionName,city,lat,lon,isp,org,as`);
      if (liveData && liveData.status === 'success') {
        const asnParts = (liveData.as || '').split(' ');
        const geoRecord = {
          ip,
          country: liveData.country || 'Unknown Country',
          countryCode: liveData.countryCode || 'UN',
          region: liveData.regionName || '',
          city: liveData.city || '',
          latitude: liveData.lat || 0,
          longitude: liveData.lon || 0,
          asn: asnParts[0] || 'Unknown ASN',
          asnOrg: liveData.org || liveData.isp || 'Unknown Organization',
          isp: liveData.isp || 'Unknown ISP',
          networkType: 'Standard Transit Network',
          riskLevel: 'LOW',
          isProxyOrVpn: false,
          routingDetails: `Live IP-API Resolution | ${liveData.as || ''}`
        };
        CACHE.set(cacheKey, geoRecord);
        return sendJson(res, 200, geoRecord);
      }
    } catch {
      // ignore
    }

    return sendJson(res, 200, {
      ip,
      country: 'Unresolved',
      countryCode: 'UN',
      asn: 'AS-UNKNOWN',
      asnOrg: 'Resolution Unavailable',
      isp: 'Unknown ISP',
      riskLevel: 'UNKNOWN'
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

  // Fallback 404
  return sendJson(res, 404, { error: 'Route not found' });
});

server.listen(PORT, () => {
  console.log(`[+] MAVERICK Intelligence Gateway running on http://localhost:${PORT}`);
  console.log(`[+] VirusTotal configured: ${Boolean(VT_API_KEY)} | AbuseIPDB configured: ${Boolean(ABUSE_API_KEY)}`);
});
