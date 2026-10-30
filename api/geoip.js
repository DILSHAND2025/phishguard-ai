/**
 * MAVERICK — Serverless GeoIP Intelligence Endpoint: GET /api/geoip?ip=<ip>
 * Smart India Hackathon 2026
 * 
 * Provides live IP geolocation, ASN, and network topology enrichment without exposing credentials.
 * Implements strict private/reserved IP filtering to prevent SSRF and eliminates coordinate fabrication.
 */

import { setCorsHeaders, sendResponse } from './_utils.js';
import { 
  isValidIP, 
  isPublicIP, 
  classifyIP, 
  cleanIPString, 
  IP_CLASSIFICATION 
} from '../src/services/emailParser.js';

// Serverless in-memory cache for IP lookups
const GEO_CACHE = new Map();

export default async function handler(req, res) {
  setCorsHeaders(res);

  if (req.method === 'OPTIONS') {
    return res.status ? res.status(204).end() : (res.writeHead(204), res.end());
  }

  if (req.method !== 'GET') {
    return sendResponse(res, 405, { 
      success: false, 
      status: 'METHOD_NOT_ALLOWED', 
      error: 'Method Not Allowed' 
    }, { 'Allow': 'GET, OPTIONS' });
  }

  try {
    const reqUrl = new URL(req.url, `http://${req.headers.host || 'localhost'}`);
    const ip = (req.query && req.query.ip) || reqUrl.searchParams.get('ip') || '';
    const cleanIP = cleanIPString(ip);

    if (!cleanIP) {
      return sendResponse(res, 400, {
        status: 'INVALID_INPUT',
        error: 'Missing ip parameter in request query'
      });
    }

    if (!isValidIP(cleanIP)) {
      return sendResponse(res, 400, {
        ip: cleanIP,
        status: 'INVALID_IP',
        lookupStatus: 'INVALID_IP',
        classification: IP_CLASSIFICATION.INVALID_IP,
        error: 'Invalid IPv4 or IPv6 address format'
      });
    }

    const classification = classifyIP(cleanIP);
    const ipVersion = cleanIP.includes(':') ? 'IPv6' : 'IPv4';

    // SSRF & Non-Routable IP Protection: Never send private/reserved/loopback addresses upstream
    if (!isPublicIP(cleanIP)) {
      return sendResponse(res, 200, {
        ip: cleanIP,
        ipVersion,
        classification,
        status: 'PRIVATE_IP',
        lookupStatus: 'PRIVATE_IP',
        isPrivate: true,
        geoAvailable: false,
        country: 'Private / Reserved Network',
        countryCode: 'LAN',
        region: 'Internal Corporate Subnet',
        city: 'Local Area Network',
        latitude: null,
        longitude: null,
        isp: 'Private Infrastructure',
        asn: 'N/A',
        asnOrg: 'Internal Network Entity',
        provider: 'Internal Filter',
        dataSource: 'INTERNAL_FILTER',
        observedEvidence: `Observed IP ${cleanIP} belongs to ${classification.toLowerCase()} address space.`,
        inferredContext: 'Internal non-routable hop excluded from public geolocation lookups.'
      });
    }

    // Cache check
    const cacheKey = `geo:${cleanIP}`;
    if (GEO_CACHE.has(cacheKey)) {
      return sendResponse(res, 200, GEO_CACHE.get(cacheKey));
    }

    // Upstream query to ipwho.is (HTTPS, fast, zero auth required)
    try {
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 2800);
      const upstreamRes = await fetch(`https://ipwho.is/${encodeURIComponent(cleanIP)}`, {
        signal: controller.signal,
        headers: { 'Accept': 'application/json' }
      });
      clearTimeout(timeoutId);

      if (upstreamRes.ok) {
        const live = await upstreamRes.json();
        if (live && live.success !== false && (live.country || live.latitude !== undefined)) {
          const lat = typeof live.latitude === 'number' && live.latitude >= -90 && live.latitude <= 90 ? live.latitude : null;
          const lon = typeof live.longitude === 'number' && live.longitude >= -180 && live.longitude <= 180 ? live.longitude : null;
          const asnNum = live.connection?.asn ? `AS${live.connection.asn}` : 'Unknown ASN';
          const org = live.connection?.org || live.connection?.isp || '';
          const isp = live.connection?.isp || live.connection?.org || '';

          const geoRecord = {
            ip: cleanIP,
            ipVersion,
            classification,
            status: 'SUCCESS',
            lookupStatus: 'SUCCESS',
            isPrivate: false,
            geoAvailable: true,
            country: live.country || 'Unknown Country',
            countryCode: live.country_code || live.countryCode || '',
            region: live.region || live.regionName || '',
            city: live.city || '',
            latitude: lat,
            longitude: lon,
            timezone: live.timezone?.id || live.timezone || '',
            asn: asnNum,
            asnOrg: org,
            isp: isp,
            networkType: 'Commercial Transit Network',
            provider: 'ipwho.is',
            dataSource: 'LIVE FORENSIC TELEMETRY (Backend Gateway)',
            isDemo: false,
            routingDetails: live.connection?.asn ? `BGP ASN: AS${live.connection.asn} (${isp})` : ''
          };

          GEO_CACHE.set(cacheKey, geoRecord);
          return sendResponse(res, 200, geoRecord, {
            'Cache-Control': 'public, s-maxage=3600, stale-while-revalidate=86400'
          });
        } else if (live && live.success === false) {
          // Upstream reported rate limit or invalid IP
          return sendResponse(res, 200, {
            ip: cleanIP,
            ipVersion,
            classification,
            status: 'UNAVAILABLE',
            lookupStatus: live.message?.toLowerCase().includes('rate') ? 'RATE_LIMITED' : 'UNAVAILABLE',
            error: live.message || 'Geolocation unavailable',
            country: 'Geolocation unavailable',
            countryCode: '',
            region: '',
            city: '',
            latitude: null,
            longitude: null,
            isp: 'Intelligence unavailable',
            asn: 'AS-UNKNOWN',
            asnOrg: 'Autonomous System resolution offline',
            provider: 'ipwho.is',
            isDemo: false
          });
        }
      }
    } catch {
      // Upstream timeout or connection error
    }

    // Strict non-fabrication standard: coordinates are null on provider failure
    const fallbackRecord = {
      ip: cleanIP,
      ipVersion,
      classification,
      status: 'UNAVAILABLE',
      lookupStatus: 'UNAVAILABLE',
      error: 'Geolocation unavailable',
      country: 'Geolocation unavailable',
      countryCode: '',
      region: '',
      city: '',
      latitude: null,
      longitude: null,
      isp: 'Intelligence unavailable',
      asn: 'AS-UNKNOWN',
      asnOrg: 'Autonomous System resolution offline',
      provider: 'None',
      isDemo: false
    };

    return sendResponse(res, 200, fallbackRecord);
  } catch (err) {
    return sendResponse(res, 500, {
      status: 'ERROR',
      error: 'Internal server error processing geolocation request',
      details: err.message
    });
  }
}
