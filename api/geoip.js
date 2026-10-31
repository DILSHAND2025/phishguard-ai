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
      let country = 'Private / Internal Network';
      let countryCode = 'LAN';
      let region = 'Internal Corporate Subnet';
      let city = 'Local Area Network';
      let isp = 'Private Infrastructure';
      let asn = 'N/A (Private)';
      let networkType = 'Private Intranet (RFC 1918)';
      let role = 'PRIVATE';
      let roleLabel = 'Private Intranet (RFC 1918)';
      let observedEvidence = `Observed IP ${cleanIP} belongs to private ip intranet address space (RFC 1918).`;
      let inferredContext = 'Internal non-routable corporate hop excluded from public geolocation lookups.';

      if (classification === IP_CLASSIFICATION.TEST_NET_IP) {
        country = 'Documentation / Test Network';
        countryCode = 'TEST';
        region = 'RFC 5737 / RFC 3849 Benchmark & Documentation Range';
        city = 'Reserved Test-Net Subnet';
        isp = 'IANA Special-Purpose (Documentation)';
        asn = 'N/A (Documentation Subnet)';
        networkType = 'Documentation / TEST-NET Subnet (RFC 5737)';
        role = 'RESERVED / TEST-NET';
        roleLabel = 'Documentation / TEST-NET (RFC 5737)';
        observedEvidence = `Observed IP ${cleanIP} belongs to documentation/example address space (${classification} - RFC 5737 / RFC 3849).`;
        inferredContext = 'Non-routable documentation address; excluded from public geolocation lookups.';
      } else if (classification === IP_CLASSIFICATION.LOOPBACK_IP) {
        country = 'Loopback / Host-Local Network';
        countryCode = 'LOK';
        region = 'Local Host System Interface';
        city = 'Localhost (Loopback)';
        isp = 'Host Software Loopback';
        asn = 'N/A (Loopback)';
        networkType = 'Host-Local Loopback (RFC 1122)';
        role = 'LOOPBACK';
        roleLabel = 'Loopback Address';
        observedEvidence = `Observed IP ${cleanIP} is a loopback interface address (RFC 1122 / RFC 4291).`;
        inferredContext = 'Host-internal loopback address; excluded from public geolocation lookups.';
      } else if (classification === IP_CLASSIFICATION.LINK_LOCAL_IP) {
        country = 'Link-Local Network';
        countryCode = 'LL';
        region = 'Auto-Configured Segment';
        city = 'Link-Local Subnet';
        isp = 'Link-Local Infrastructure';
        asn = 'N/A (Link-Local)';
        networkType = 'Link-Local Subnet (RFC 3927)';
        role = 'LINK_LOCAL';
        roleLabel = 'Link-Local Address (RFC 3927)';
        observedEvidence = `Observed IP ${cleanIP} is an autoconfigured link-local address (RFC 3927 / RFC 4291).`;
        inferredContext = 'Non-routable link-local segment hop excluded from public geolocation lookups.';
      } else if (classification === IP_CLASSIFICATION.CGNAT) {
        country = 'Carrier-Grade NAT Network';
        countryCode = 'CGN';
        region = 'Shared Address Space';
        city = 'CGNAT Pool (RFC 6598)';
        isp = 'Carrier-Grade NAT';
        asn = 'N/A (CGNAT)';
        networkType = 'Carrier-Grade NAT Subnet (RFC 6598)';
        role = 'CGNAT';
        roleLabel = 'Carrier-Grade NAT (RFC 6598)';
        observedEvidence = `Observed IP ${cleanIP} belongs to Carrier-Grade NAT address space (RFC 6598).`;
        inferredContext = 'Shared address space; excluded from public geolocation lookups.';
      } else if (classification === IP_CLASSIFICATION.MULTICAST) {
        country = 'Multicast Network';
        countryCode = 'MC';
        region = 'Multicast Range';
        city = 'Multicast Group';
        isp = 'Multicast Group (RFC 5771)';
        asn = 'N/A (Multicast)';
        networkType = 'Multicast Subnet (RFC 5771)';
        role = 'MULTICAST';
        roleLabel = 'Multicast Address (RFC 5771)';
        observedEvidence = `Observed IP ${cleanIP} is a multicast address (RFC 5771 / RFC 4291).`;
        inferredContext = 'Multicast group traffic; excluded from public geolocation lookups.';
      } else if (classification === IP_CLASSIFICATION.RESERVED_IP) {
        country = 'Reserved / Special Network';
        countryCode = 'RES';
        region = 'Special-Purpose Routing Range';
        city = 'Reserved Range';
        isp = 'IANA Special-Purpose';
        asn = 'N/A (Special-Purpose)';
        networkType = 'Reserved / Special-Purpose Subnet';
        role = 'RESERVED';
        roleLabel = 'Reserved / Special-Purpose';
        observedEvidence = `Observed IP ${cleanIP} belongs to special-purpose/reserved address space (${classification}).`;
        inferredContext = 'Non-routable special-purpose network entity excluded from public geolocation lookups.';
      }

      return sendResponse(res, 200, {
        ip: cleanIP,
        ipVersion,
        classification,
        status: 'PRIVATE_IP',
        lookupStatus: 'PRIVATE_IP',
        isPrivate: true,
        geoAvailable: false,
        role,
        roleLabel,
        country,
        countryCode,
        region,
        city,
        latitude: null,
        longitude: null,
        isp,
        asn,
        asnOrg: isp,
        networkType,
        provider: 'Internal Filter',
        dataSource: 'INTERNAL_FILTER',
        observedEvidence,
        inferredContext
      }, {
        'Cache-Control': 'public, max-age=86400'
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
