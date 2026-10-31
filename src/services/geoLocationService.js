/**
 * MAVERICK — Forensic IP GeoLocation & Network Topology Service
 * Smart India Hackathon 2026 Core Component
 * 
 * Provider Abstraction Architecture:
 * GeoLocationService
 *  ├── MockGeoProvider (Controlled demo / test mode strictly labeled 'DEMO / SYNTHETIC DATA')
 *  ├── BackendGeoProvider (Queries /api/geoip on MAVERICK backend gateway)
 *  └── DirectIpWhoIsProvider (Queries ipwho.is directly over HTTPS with CORS support)
 * 
 * Strict Forensic Compliance:
 * 1. NEVER fabricates fake coordinates.
 * 2. If provider lookup fails, returns status: 'UNAVAILABLE' with message 'Geolocation unavailable'.
 * 3. Private / reserved IPs (RFC 1918, loopback, link-local) are flagged as 'PRIVATE_IP' and excluded from public geolocation.
 * 4. Caches repeated lookups in memory to avoid redundant network traffic.
 * 5. Clearly distinguishes OBSERVED EVIDENCE from ENRICHED INTELLIGENCE and INFERENCE.
 */

import { isValidIP, isPrivateIP, classifyIP, cleanIPString, isPublicIP, isValidIPv4, isValidIPv6, IP_CLASSIFICATION } from './emailParser.js';
import { getApiBaseUrl } from './apiConfig.js';

// Mandatory CERT-In & Court Admissibility Legal Disclaimer
export const GEO_LEGAL_DISCLAIMER =
  "IP geolocation provides approximate network location of observed network infrastructure and does not establish the sender's exact physical identity or location.";

// In-memory cache for IP lookups (IP -> Geolocation Record)
const IN_MEMORY_GEO_CACHE = new Map();

/**
 * Validate numeric coordinate bounds
 */
export function sanitizeCoordinate(val, min, max) {
  if (val === null || val === undefined || val === '') return null;
  const num = typeof val === 'number' ? val : parseFloat(val);
  if (typeof num !== 'number' || isNaN(num) || !isFinite(num)) return null;
  if (num < min || num > max) return null;
  return num;
}

/**
 * Base Provider Interface definition
 */
export class BaseGeoProvider {
  constructor(name) {
    this.name = name;
  }

  // Abstract lookup method
  async lookup(ip) {
    throw new Error(`Provider ${this.name} must implement lookup(ip)`);
  }
}

/**
 * 1. Backend Gateway Provider: Queries /api/geoip on MAVERICK Node.js backend
 */
export class BackendGeoProvider extends BaseGeoProvider {
  constructor(baseUrl = '') {
    super('MAVERICK Backend Gateway');
    this.baseUrl = baseUrl || getApiBaseUrl();
  }

  async lookup(ip) {
    if (!ip || !isPublicIP(ip)) return null;

    const isBrowser = typeof window !== 'undefined';
    const isLocalHost = isBrowser && 
      (window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1');

    // Priority 1: In browser, call same-origin /api/geoip?ip=... directly (Vercel serverless / Vite proxy)
    // Priority 2: Configured baseUrl (e.g. Render backend)
    // Priority 3: Local development servers if on localhost
    const candidateEndpoints = [
      isBrowser ? `/api/geoip?ip=${encodeURIComponent(ip)}` : '',
      this.baseUrl ? `${this.baseUrl}/api/geoip?ip=${encodeURIComponent(ip)}` : '',
      ...(isLocalHost ? [
        `http://localhost:5000/api/geoip?ip=${encodeURIComponent(ip)}`,
        `http://127.0.0.1:5000/api/geoip?ip=${encodeURIComponent(ip)}`
      ] : [])
    ].filter(Boolean);

    const endpoints = Array.from(new Set(candidateEndpoints));

    for (const endpoint of endpoints) {
      try {
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), 2500);

        const res = await fetch(endpoint, {
          method: 'GET',
          headers: { 'Accept': 'application/json' },
          signal: controller.signal
        });
        clearTimeout(timeoutId);

        if (res.ok) {
          const data = await res.json();
          if (data && (data.status === 'SUCCESS' || data.status === 'success' || data.countryCode || data.country || data.latitude !== undefined)) {
            const lat = sanitizeCoordinate(data.latitude, -90, 90);
            const lon = sanitizeCoordinate(data.longitude, -180, 180);
            return {
              ...data,
              latitude: lat,
              longitude: lon,
              geoAvailable: typeof data.geoAvailable === 'boolean' ? data.geoAvailable : (lat !== null && lon !== null),
              status: data.status || 'SUCCESS',
              lookupStatus: data.lookupStatus || data.status || 'SUCCESS',
              classification: data.classification || (isValidIPv6(ip) ? 'Public IPv6' : 'Public IPv4'),
              asn: data.asn || data.ASN || (data.connection?.asn ? (String(data.connection.asn).startsWith('AS') ? String(data.connection.asn) : `AS${data.connection.asn}`) : 'AS-UNKNOWN'),
              isp: data.isp || data.asnOrg || data.connection?.isp || data.connection?.org || 'Unknown ISP',
              dataSource: 'LIVE FORENSIC TELEMETRY (Backend Gateway)',
              provider: data.provider || 'MAVERICK Backend Gateway',
              isDemo: false
            };
          }
        }
      } catch {
        // Try next endpoint fallback
      }
    }

    return null;
  }
}

/**
 * 2. Direct ipwho.is Provider: Free public tier HTTPS IP geolocation with CORS support
 */
export class DirectIpWhoIsProvider extends BaseGeoProvider {
  constructor() {
    super('Direct ipwho.is Provider');
  }

  async lookup(ip) {
    if (!ip || !isPublicIP(ip)) return null;
    if (typeof fetch === 'undefined') return null;

    try {
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 3000);

      const url = `https://ipwho.is/${encodeURIComponent(ip)}`;
      const res = await fetch(url, { 
        headers: { 'Accept': 'application/json' },
        signal: controller.signal 
      });
      clearTimeout(timeoutId);

      if (res.ok) {
        const live = await res.json();
        if (live && live.success !== false && (live.country || live.latitude !== undefined)) {
          const lat = sanitizeCoordinate(live.latitude, -90, 90);
          const lon = sanitizeCoordinate(live.longitude, -180, 180);
          const asnNum = live.connection?.asn ? `AS${live.connection.asn}` : 'Unknown ASN';
          const org = live.connection?.org || live.connection?.isp || '';
          const isp = live.connection?.isp || live.connection?.org || '';

          return {
            ip,
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
            dataSource: 'LIVE FORENSIC TELEMETRY (ipwho.is)',
            provider: 'ipwho.is',
            isDemo: false,
            routingDetails: live.connection?.asn ? `BGP ASN: AS${live.connection.asn} (${isp})` : ''
          };
        }
      }
    } catch {
      // Direct connection blocked or offline
    }

    return null;
  }
}

// Backward-compatible alias
export const DirectIpApiProvider = DirectIpWhoIsProvider;

/**
 * 3. Mock Geo Provider: Controlled development/demonstration mode
 * Strictly tagged as 'DEMO / SYNTHETIC DATA'
 */
export class MockGeoProvider extends BaseGeoProvider {
  constructor(dataset = {}) {
    super('Controlled Synthetic Demo Provider');
    this.dataset = {
      '185.220.101.45': {
        ip: '185.220.101.45',
        country: 'Germany',
        countryCode: 'DE',
        region: 'Hesse',
        city: 'Frankfurt am Main',
        latitude: 50.1109,
        longitude: 8.6821,
        timezone: 'Europe/Berlin',
        asn: 'AS9009',
        asnOrg: 'M247 Ltd Europe',
        isp: 'M247 Europe S.R.L.',
        networkType: 'Tor Exit Node / Anonymizing Relay',
        isProxyOrVpn: true,
        riskLevel: 'HIGH',
        routingDetails: 'BGP Prefix: 185.220.100.0/22 | Tor Directory Authority Verified',
        ...dataset['185.220.101.45']
      },
      '45.154.255.82': {
        ip: '45.154.255.82',
        country: 'Netherlands',
        countryCode: 'NL',
        region: 'North Holland',
        city: 'Amsterdam',
        latitude: 52.3676,
        longitude: 4.9041,
        timezone: 'Europe/Amsterdam',
        asn: 'AS202425',
        asnOrg: 'IP Volume Inc',
        isp: 'IP Volume Networks',
        networkType: 'Commercial Hosting / Proxy Egress',
        isProxyOrVpn: true,
        riskLevel: 'HIGH',
        routingDetails: 'BGP Prefix: 45.154.252.0/22 | Fast-Flux Reverse Proxy Detected',
        ...dataset['45.154.255.82']
      },
      '193.106.191.12': {
        ip: '193.106.191.12',
        country: 'Russia',
        countryCode: 'RU',
        region: 'Moscow',
        city: 'Moscow',
        latitude: 55.7558,
        longitude: 37.6173,
        timezone: 'Europe/Moscow',
        asn: 'AS44034',
        asnOrg: 'HiChina Web Hosting',
        isp: 'HiChina Telecommunications',
        networkType: 'Bulletproof Hosting / C2 Infrastructure',
        isProxyOrVpn: false,
        riskLevel: 'CRITICAL',
        routingDetails: 'BGP Prefix: 193.106.190.0/23 | Repeatedly flagged in malware distributions',
        ...dataset['193.106.191.12']
      },
      '104.21.36.45': {
        ip: '104.21.36.45',
        country: 'United States',
        countryCode: 'US',
        region: 'California',
        city: 'San Francisco',
        latitude: 37.7749,
        longitude: -122.4194,
        timezone: 'America/Los_Angeles',
        asn: 'AS13335',
        asnOrg: 'Cloudflare Edge Transit',
        isp: 'Cloudflare Inc',
        networkType: 'Commercial CDN / Reverse Proxy',
        isProxyOrVpn: true,
        riskLevel: 'MEDIUM',
        routingDetails: 'Anycast Routing Gateway | Masking Origin Web Server',
        ...dataset['104.21.36.45']
      },
      '194.26.29.110': {
        ip: '194.26.29.110',
        country: 'Romania',
        countryCode: 'RO',
        region: 'Bucharest',
        city: 'Bucharest',
        latitude: 44.4268,
        longitude: 26.1025,
        timezone: 'Europe/Bucharest',
        asn: 'AS48693',
        asnOrg: 'HostRoyale Egress Relay',
        isp: 'HostRoyale Ltd',
        networkType: 'Transit Relay Endpoint',
        isProxyOrVpn: true,
        riskLevel: 'HIGH',
        routingDetails: 'BGP Prefix: 194.26.28.0/23 | Intermediate SMTP Routing Relay',
        ...dataset['194.26.29.110']
      },
      '14.139.56.2': {
        ip: '14.139.56.2',
        country: 'India',
        countryCode: 'IN',
        region: 'Delhi',
        city: 'New Delhi',
        latitude: 28.6139,
        longitude: 77.2090,
        timezone: 'Asia/Kolkata',
        asn: 'AS45820',
        asnOrg: 'National Informatics Centre (NIC)',
        isp: 'National Informatics Centre',
        networkType: 'National Educational & Research Network',
        isProxyOrVpn: false,
        riskLevel: 'LOW',
        routingDetails: 'BGP Prefix: 14.139.0.0/16 | Official Indian Government Gateway',
        ...dataset['14.139.56.2']
      }
    };
  }

  async lookup(ip) {
    const isProd = Boolean(
      (typeof import.meta !== 'undefined' && import.meta.env?.PROD) ||
      (typeof process !== 'undefined' && process.env?.NODE_ENV === 'production')
    );
    if (isProd) return null;

    if (this.dataset[ip]) {
      return {
        ...this.dataset[ip],
        dataSource: 'DEMO / SYNTHETIC DATA',
        provider: 'Controlled Synthetic Demo Provider',
        isDemo: true
      };
    }
    return null;
  }
}

/**
 * Master GeoLocation Service Abstraction
 */
export class GeoLocationService {
  constructor(options = {}) {
    const isProd = Boolean(
      (typeof import.meta !== 'undefined' && import.meta.env?.PROD) ||
      (typeof process !== 'undefined' && process.env?.NODE_ENV === 'production')
    );

    this.cache = options.cache || (options.providers ? new Map() : IN_MEMORY_GEO_CACHE);
    this.providers = options.providers || (isProd ? [
      new BackendGeoProvider(),
      new DirectIpWhoIsProvider()
    ] : [
      new MockGeoProvider(),
      new BackendGeoProvider(),
      new DirectIpWhoIsProvider()
    ]);
  }

  // Swap or register a custom provider
  setProviders(providers) {
    this.providers = Array.isArray(providers) ? providers : [providers];
  }

  // Clear cache for testing / new session
  clearCache() {
    this.cache.clear();
  }

  /**
   * Resolve a single IP to forensic geographic record
   */
  async resolveIP(ip, context = {}) {
    const rawInput = ip || '';
    const cleanIP = cleanIPString(typeof rawInput === 'string' ? rawInput : '');

    // 1. Validate IP format
    if (!cleanIP || !isValidIP(cleanIP)) {
      return {
        ip: cleanIP || (typeof ip === 'string' ? ip : ''),
        ipVersion: 'Unknown',
        classification: IP_CLASSIFICATION.INVALID_IP,
        sourceHeader: context.sourceHeader || 'None',
        status: 'INVALID_IP',
        lookupStatus: 'INVALID_IP',
        error: 'Invalid IP address',
        role: context.role || 'UNKNOWN',
        roleLabel: context.roleLabel || 'Invalid Address',
        isPrivate: false,
        geoAvailable: false,
        country: 'Invalid IP',
        countryCode: '',
        region: '',
        city: '',
        latitude: null,
        longitude: null,
        isp: '',
        asn: '',
        asnOrg: '',
        timezone: '',
        provider: 'None',
        isDemo: false,
        dataSource: 'NONE',
        observedEvidence: `Observed token "${ip}" does not conform to valid IPv4 or IPv6 standards.`,
        inferredContext: 'Non-routable malformed token excluded from infrastructure intelligence.',
        disclaimer: GEO_LEGAL_DISCLAIMER
      };
    }

    const classification = classifyIP(cleanIP);
    const ipVersion = isValidIPv6(cleanIP) ? 'IPv6' : 'IPv4';

    // 2. Check for Private / Reserved / Local IP (SSRF Protection & Non-Routable Filtering)
    if (!isPublicIP(cleanIP)) {
      let country = 'Private / Internal Network';
      let countryCode = 'LAN';
      let region = 'Internal Corporate Subnet';
      let city = 'Local Area Network';
      let isp = 'Private Infrastructure';
      let asn = 'N/A (Private/Local Subnet)';
      let networkType = 'Private Intranet (RFC 1918)';
      let computedRole = 'PRIVATE';
      let computedRoleLabel = 'Private Intranet (RFC 1918)';
      let nonRoutableStatus = 'PRIVATE_IP';
      let observedEvidence = `IP ${cleanIP} belongs to private ip intranet address space (RFC 1918 / RFC 4193).`;
      let inferredContext = 'Internal non-routable corporate hop; excluded from public geolocation lookups.';

      if (classification === IP_CLASSIFICATION.TEST_NET_IP) {
        country = 'Documentation / Test Network';
        countryCode = 'TEST';
        region = 'RFC 5737 / RFC 3849 Benchmark & Documentation Range';
        city = 'Reserved Test-Net Subnet';
        isp = 'IANA Special-Purpose (Documentation)';
        asn = 'N/A (Documentation Subnet)';
        networkType = 'Documentation / TEST-NET Subnet (RFC 5737)';
        computedRole = 'RESERVED / TEST-NET';
        computedRoleLabel = 'Documentation / TEST-NET (RFC 5737)';
        nonRoutableStatus = 'RESERVED_TEST_NET';
        observedEvidence = `IP ${cleanIP} belongs to documentation/example address space (${classification} - RFC 5737 / RFC 3849).`;
        inferredContext = 'Non-routable documentation address used in test scenarios or documentation; excluded from public geolocation.';
      } else if (classification === IP_CLASSIFICATION.LOOPBACK_IP) {
        country = 'Loopback / Host-Local Network';
        countryCode = 'LOK';
        region = 'Local Host System Interface';
        city = 'Localhost (Loopback)';
        isp = 'Host Software Loopback';
        asn = 'N/A (Loopback Interface)';
        networkType = 'Host-Local Loopback (RFC 1122)';
        computedRole = 'LOOPBACK';
        computedRoleLabel = 'Loopback Address';
        nonRoutableStatus = 'PRIVATE_IP';
        observedEvidence = `IP ${cleanIP} is a loopback interface address (RFC 1122 / RFC 4291).`;
        inferredContext = 'Host-internal loopback address; excluded from public network geolocation.';
      } else if (classification === IP_CLASSIFICATION.LINK_LOCAL_IP) {
        country = 'Link-Local Network';
        countryCode = 'LL';
        region = 'Auto-Configured Segment';
        city = 'Link-Local Subnet';
        isp = 'Link-Local Infrastructure';
        asn = 'N/A (Link-Local)';
        networkType = 'Link-Local Subnet (RFC 3927)';
        computedRole = 'LINK_LOCAL';
        computedRoleLabel = 'Link-Local Address (RFC 3927)';
        nonRoutableStatus = 'PRIVATE_IP';
        observedEvidence = `IP ${cleanIP} is an autoconfigured link-local address (RFC 3927 / RFC 4291).`;
        inferredContext = 'Non-routable link-local segment hop; excluded from public geolocation.';
      } else if (classification === IP_CLASSIFICATION.CGNAT) {
        country = 'Carrier-Grade NAT Network';
        countryCode = 'CGN';
        region = 'Shared Address Space';
        city = 'CGNAT Pool (RFC 6598)';
        isp = 'Carrier-Grade NAT';
        asn = 'N/A (CGNAT)';
        networkType = 'Carrier-Grade NAT Subnet (RFC 6598)';
        computedRole = 'CGNAT';
        computedRoleLabel = 'Carrier-Grade NAT (RFC 6598)';
        nonRoutableStatus = 'PRIVATE_IP';
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
        computedRole = 'MULTICAST';
        computedRoleLabel = 'Multicast Address (RFC 5771)';
        nonRoutableStatus = 'PRIVATE_IP';
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
        computedRole = 'RESERVED';
        computedRoleLabel = 'Reserved / Special-Purpose';
        nonRoutableStatus = 'RESERVED';
        observedEvidence = `IP ${cleanIP} belongs to special-purpose/reserved address space (${classification}).`;
        inferredContext = 'Non-routable reserved network entity; excluded from public geolocation.';
      }

      return {
        ip: cleanIP,
        ipVersion,
        classification,
        sourceHeader: context.sourceHeader || 'Headers',
        status: nonRoutableStatus,
        lookupStatus: nonRoutableStatus,
        isPrivate: true,
        geoAvailable: false,
        role: computedRole,
        roleLabel: computedRoleLabel,
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
        timezone: '',
        provider: 'Internal Filter',
        isDemo: false,
        dataSource: 'INTERNAL_FILTER',
        observedEvidence,
        inferredContext,
        disclaimer: GEO_LEGAL_DISCLAIMER
      };
    }

    // 3. Check in-memory cache to prevent duplicate calls
    if (this.cache.has(cleanIP)) {
      const cached = this.cache.get(cleanIP);
      return {
        ...cached,
        role: context.role || cached.role || 'OBSERVED_IP',
        roleLabel: context.roleLabel || cached.roleLabel || 'Observed Public IP',
        sourceHeader: context.sourceHeader || cached.sourceHeader || 'Headers'
      };
    }

    // 4. Query configured providers sequentially
    const isProd = Boolean(
      (typeof import.meta !== 'undefined' && import.meta.env?.PROD) ||
      (typeof process !== 'undefined' && process.env?.NODE_ENV === 'production')
    );
    const providersToQuery = (context.preferLive || isProd)
      ? [...this.providers.filter(p => !(p instanceof MockGeoProvider)), ...this.providers.filter(p => p instanceof MockGeoProvider)]
      : this.providers;

    let lastFailureInfo = null;

    for (const provider of providersToQuery) {
      try {
        const result = await provider.lookup(cleanIP);
        if (result) {
          // If the provider explicitly signaled failure/rate limit
          if (result.status === 'UNAVAILABLE' || result.lookupStatus === 'RATE_LIMITED' || (result.country === 'Geolocation unavailable' && result.latitude === null)) {
            lastFailureInfo = result;
            continue;
          }

          const sanitizedLat = sanitizeCoordinate(result.latitude, -90, 90);
          const sanitizedLon = sanitizeCoordinate(result.longitude, -180, 180);

          if ((result.country && result.country !== 'Geolocation unavailable') || result.city || sanitizedLat !== null) {
            const lat = sanitizedLat;
            const lon = sanitizedLon;

            const record = {
              ip: cleanIP,
              ipVersion,
              classification: result.classification || classification,
              sourceHeader: context.sourceHeader || 'Headers',
              status: result.status || 'SUCCESS',
              lookupStatus: result.lookupStatus || result.status || 'SUCCESS',
              isPrivate: false,
              geoAvailable: typeof result.geoAvailable === 'boolean' ? result.geoAvailable : (lat !== null && lon !== null),
              role: context.role || result.role || 'OBSERVED_IP',
              roleLabel: context.roleLabel || result.roleLabel || 'Observed Public IP',
              country: result.country || 'Unknown Country',
              countryCode: result.countryCode || result.country_code || '',
              region: result.region || result.regionName || '',
              city: result.city || '',
              latitude: lat,
              longitude: lon,
              timezone: result.timezone || '',
              isp: result.isp || result.asnOrg || result.connection?.isp || 'Unknown ISP',
              asn: result.asn || result.ASN || (result.connection?.asn ? (String(result.connection.asn).startsWith('AS') ? String(result.connection.asn) : `AS${result.connection.asn}`) : 'AS-UNKNOWN'),
              asnOrg: result.asnOrg || result.isp || result.connection?.org || 'Autonomous System',
              networkType: result.networkType || 'Standard Transit Infrastructure',
              isProxyOrVpn: Boolean(result.isProxyOrVpn),
              riskLevel: result.riskLevel || (result.isProxyOrVpn ? 'HIGH' : 'LOW'),
              routingDetails: result.routingDetails || `Observed routing via ${result.asn || result.ASN || 'upstream transit'}`,
              provider: result.provider || provider.name,
              isDemo: Boolean(result.isDemo),
              dataSource: result.dataSource || 'LIVE FORENSIC TELEMETRY',
              observedEvidence: result.observedEvidence || `Observed IP ${cleanIP} geolocates to ${result.city ? `${result.city}, ` : ''}${result.country || 'Unknown'} (${result.asn || result.ASN || 'Unknown ASN'} - ${result.asnOrg || result.isp || 'Transit'}).`,
              inferredContext: result.inferredContext || (result.isProxyOrVpn 
                ? 'Anonymizing relay / VPN egress infrastructure often leveraged in evasion directives.' 
                : 'Standard internet transit infrastructure routing.'),
              disclaimer: GEO_LEGAL_DISCLAIMER
            };

            this.cache.set(cleanIP, record);
            return record;
          }
        }
      } catch (err) {
        lastFailureInfo = { error: err.message };
      }
    }

    // 5. All providers failed or offline -> Return UNAVAILABLE without fake coordinates
    const unavailableRecord = {
      ip: cleanIP,
      ipVersion,
      classification,
      sourceHeader: context.sourceHeader || 'Headers',
      status: 'UNAVAILABLE',
      lookupStatus: lastFailureInfo?.lookupStatus || 'UNAVAILABLE',
      error: lastFailureInfo?.error || 'Geolocation unavailable',
      role: context.role || 'UNKNOWN',
      roleLabel: context.roleLabel || 'Observed Public IP',
      isPrivate: false,
      geoAvailable: false,
      country: 'Geolocation unavailable',
      countryCode: '',
      region: '',
      city: '',
      latitude: null,
      longitude: null,
      isp: 'Intelligence unavailable',
      asn: 'AS-UNKNOWN',
      asnOrg: 'Autonomous System resolution offline',
      timezone: '',
      provider: 'None',
      isDemo: false,
      dataSource: 'UNAVAILABLE',
      observedEvidence: `Observed public IP ${cleanIP} (Geolocation intelligence lookup unavailable).`,
      inferredContext: 'Geographic attribution unavailable; proceeding with remaining multi-layer forensic evidence.',
      disclaimer: GEO_LEGAL_DISCLAIMER
    };

    this.cache.set(cleanIP, unavailableRecord);
    return unavailableRecord;
  }

  /**
   * Resolve multiple network indicators in parallel
   */
  async resolveAllIPs(indicators = []) {
    if (!Array.isArray(indicators) || indicators.length === 0) {
      return [];
    }

    const uniqueMap = new Map();
    indicators.forEach(ind => {
      const ip = typeof ind === 'string' ? cleanIPString(ind) : cleanIPString(ind.ip || '');
      if (ip && !uniqueMap.has(ip)) {
        uniqueMap.set(ip, typeof ind === 'object' ? ind : { ip });
      }
    });

    const tasks = Array.from(uniqueMap.values()).map(ind => this.resolveIP(ind.ip, ind));
    return Promise.all(tasks);
  }
}

// Export singleton instance for app-wide use
export const defaultGeoService = new GeoLocationService();
