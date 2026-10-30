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
  if (typeof val !== 'number' || isNaN(val)) return null;
  if (val < min || val > max) return null;
  return val;
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
    const isLocalHost = typeof window !== 'undefined' && 
      (window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1');

    const endpoints = [
      this.baseUrl ? `${this.baseUrl}/api/geoip?ip=${encodeURIComponent(ip)}` : '',
      `/api/geoip?ip=${encodeURIComponent(ip)}`,
      ...(isLocalHost ? [
        `http://localhost:5000/api/geoip?ip=${encodeURIComponent(ip)}`,
        `http://127.0.0.1:5000/api/geoip?ip=${encodeURIComponent(ip)}`
      ] : [])
    ].filter(Boolean);

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
          if (data && (data.status === 'SUCCESS' || data.status === 'success' || data.countryCode || data.country)) {
            const lat = sanitizeCoordinate(data.latitude, -90, 90);
            const lon = sanitizeCoordinate(data.longitude, -180, 180);
            return {
              ...data,
              latitude: lat,
              longitude: lon,
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
      let computedRole = context.role || 'PRIVATE';
      let computedRoleLabel = context.roleLabel || 'Private Intranet (RFC 1918)';
      let observedEvidence = `IP ${cleanIP} belongs to private ip intranet address space (RFC 1918 / RFC 4193).`;
      let inferredContext = 'Internal non-routable corporate hop; excluded from public geolocation lookups.';

      if (classification === IP_CLASSIFICATION.TEST_NET_IP) {
        country = 'Documentation / Test Network';
        countryCode = 'TEST';
        region = 'RFC 5737 / RFC 3849 Benchmark & Documentation Range';
        city = 'Reserved Test-Net Subnet';
        isp = 'IANA Special-Purpose (Documentation)';
        asn = 'N/A (Documentation Subnet)';
        computedRole = context.role || 'RESERVED / TEST-NET';
        computedRoleLabel = context.roleLabel || 'Documentation / TEST-NET (RFC 5737)';
        observedEvidence = `IP ${cleanIP} belongs to documentation/example address space (${classification} - RFC 5737 / RFC 3849).`;
        inferredContext = 'Non-routable documentation address used in test scenarios or documentation; excluded from public geolocation.';
      } else if (classification === IP_CLASSIFICATION.LOOPBACK_IP) {
        country = 'Loopback / Host-Local Network';
        countryCode = 'LOK';
        region = 'Local Host System Interface';
        city = 'Localhost (Loopback)';
        isp = 'Host Software Loopback';
        asn = 'N/A (Loopback Interface)';
        computedRole = context.role || 'LOOPBACK';
        computedRoleLabel = context.roleLabel || 'Loopback Address';
        observedEvidence = `IP ${cleanIP} is a loopback interface address (RFC 1122 / RFC 4291).`;
        inferredContext = 'Host-internal loopback address; excluded from public network geolocation.';
      } else if (classification === IP_CLASSIFICATION.LINK_LOCAL_IP) {
        country = 'Link-Local Network';
        countryCode = 'LL';
        region = 'Auto-Configured Segment';
        city = 'Link-Local Subnet';
        isp = 'Link-Local Infrastructure';
        asn = 'N/A (Link-Local)';
        computedRole = context.role || 'LINK_LOCAL';
        computedRoleLabel = context.roleLabel || 'Link-Local Address (RFC 3927)';
        observedEvidence = `IP ${cleanIP} is an autoconfigured link-local address (RFC 3927 / RFC 4291).`;
        inferredContext = 'Non-routable link-local segment hop; excluded from public geolocation.';
      } else if (classification === IP_CLASSIFICATION.RESERVED_IP) {
        country = 'Reserved / Special Network';
        countryCode = 'RES';
        region = 'Special-Purpose Routing Range';
        city = 'Reserved Range';
        isp = 'IANA Special-Purpose';
        asn = 'N/A (Special-Purpose)';
        computedRole = context.role || 'RESERVED';
        computedRoleLabel = context.roleLabel || 'Reserved / Special-Purpose';
        observedEvidence = `IP ${cleanIP} belongs to special-purpose/reserved address space (${classification}).`;
        inferredContext = 'Non-routable reserved network entity; excluded from public geolocation.';
      }

      return {
        ip: cleanIP,
        ipVersion,
        classification,
        sourceHeader: context.sourceHeader || 'Headers',
        status: 'PRIVATE_IP',
        lookupStatus: 'PRIVATE_IP',
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

          if ((result.country && result.country !== 'Geolocation unavailable') || result.city || typeof result.latitude === 'number') {
            const lat = sanitizeCoordinate(result.latitude, -90, 90);
            const lon = sanitizeCoordinate(result.longitude, -180, 180);

            const record = {
              ip: cleanIP,
              ipVersion,
              classification,
              sourceHeader: context.sourceHeader || 'Headers',
              status: 'SUCCESS',
              lookupStatus: 'SUCCESS',
              isPrivate: false,
              geoAvailable: true,
              role: context.role || 'OBSERVED_IP',
              roleLabel: context.roleLabel || 'Observed Public IP',
              country: result.country || 'Unknown Country',
              countryCode: result.countryCode || '',
              region: result.region || '',
              city: result.city || '',
              latitude: lat,
              longitude: lon,
              timezone: result.timezone || '',
              isp: result.isp || result.asnOrg || 'Unknown ISP',
              asn: result.asn || 'AS-UNKNOWN',
              asnOrg: result.asnOrg || result.isp || 'Autonomous System',
              networkType: result.networkType || 'Standard Transit Infrastructure',
              isProxyOrVpn: Boolean(result.isProxyOrVpn),
              riskLevel: result.riskLevel || (result.isProxyOrVpn ? 'HIGH' : 'LOW'),
              routingDetails: result.routingDetails || `Observed routing via ${result.asn || 'upstream transit'}`,
              provider: result.provider || provider.name,
              isDemo: Boolean(result.isDemo),
              dataSource: result.dataSource || 'LIVE FORENSIC TELEMETRY',
              observedEvidence: `Observed IP ${cleanIP} geolocates to ${result.city ? `${result.city}, ` : ''}${result.country || 'Unknown'} (${result.asn || 'Unknown ASN'} - ${result.asnOrg || result.isp || 'Transit'}).`,
              inferredContext: result.isProxyOrVpn 
                ? 'Anonymizing relay / VPN egress infrastructure often leveraged in evasion directives.' 
                : 'Standard internet transit infrastructure routing.',
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
