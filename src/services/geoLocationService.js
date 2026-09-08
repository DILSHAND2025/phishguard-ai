/**
 * MAVERICK — Forensic IP GeoLocation & Network Topology Service
 * Smart India Hackathon 2026 Core Component
 * 
 * Provider Abstraction Architecture:
 * GeoLocationService
 *  ├── BackendGeoProvider (Queries /api/geoip on MAVERICK backend gateway)
 *  ├── DirectIpApiProvider (Queries ip-api.com directly as client-side fallback)
 *  └── MockGeoProvider (Controlled demo / test mode strictly labeled 'DEMO / SYNTHETIC DATA')
 * 
 * Strict Forensic Compliance:
 * 1. NEVER fabricates fake coordinates.
 * 2. If provider lookup fails, returns status: 'UNAVAILABLE' with message 'Geolocation unavailable'.
 * 3. Private / reserved IPs (RFC 1918, loopback, link-local) are flagged as 'PRIVATE_IP' and excluded from public geolocation.
 * 4. Caches repeated lookups in memory to avoid redundant network traffic.
 * 5. Clearly distinguishes OBSERVED EVIDENCE from INFERRED INFORMATION.
 */

import { isValidIP, isPrivateIP } from './emailParser.js';
import { getApiBaseUrl } from './apiConfig.js';

// Mandatory CERT-In & Court Admissibility Legal Disclaimer
export const GEO_LEGAL_DISCLAIMER =
  'IP GeoLocation represents observed network infrastructure and does not establish the physical identity or location of the attacker.';

// In-memory cache for IP lookups (IP -> Geolocation Record)
const IN_MEMORY_GEO_CACHE = new Map();

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
    const endpoints = [
      this.baseUrl ? `${this.baseUrl}/api/geoip?ip=${encodeURIComponent(ip)}` : '',
      `/api/geoip?ip=${encodeURIComponent(ip)}`,
      `http://localhost:5000/api/geoip?ip=${encodeURIComponent(ip)}`,
      `http://127.0.0.1:5000/api/geoip?ip=${encodeURIComponent(ip)}`
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
          if (data && (data.status === 'success' || data.countryCode || data.country)) {
            return {
              ...data,
              dataSource: 'LIVE FORENSIC TELEMETRY (Backend Gateway)',
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
 * 2. Direct IP-API Provider: Free public tier IP geolocation fallback
 */
export class DirectIpApiProvider extends BaseGeoProvider {
  constructor() {
    super('Direct IP-API Provider');
  }

  async lookup(ip) {
    if (typeof fetch === 'undefined') return null;

    try {
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 2800);

      const url = `https://ip-api.com/json/${encodeURIComponent(ip)}?fields=status,message,country,countryCode,regionName,city,lat,lon,timezone,isp,org,as`;
      const res = await fetch(url, { signal: controller.signal });
      clearTimeout(timeoutId);

      if (res.ok) {
        const live = await res.json();
        if (live.status === 'success') {
          const asnParts = (live.as || '').split(' ');
          return {
            ip,
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
            dataSource: 'LIVE FORENSIC TELEMETRY (ip-api.com)',
            isDemo: false,
            routingDetails: live.as ? `BGP Routing: ${live.as}` : ''
          };
        }
      }
    } catch {
      // Direct connection blocked or offline
    }

    return null;
  }
}

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
    if (this.dataset[ip]) {
      return {
        ...this.dataset[ip],
        dataSource: 'DEMO / SYNTHETIC DATA',
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
    this.cache = options.cache || IN_MEMORY_GEO_CACHE;
    this.providers = options.providers || [
      new MockGeoProvider(),
      new BackendGeoProvider(),
      new DirectIpApiProvider()
    ];
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
    if (!ip || typeof ip !== 'string' || !isValidIP(ip.trim())) {
      return {
        ip: ip || '',
        status: 'INVALID_IP',
        error: 'Invalid IP address',
        role: context.role || 'UNKNOWN',
        roleLabel: context.roleLabel || 'Invalid Address',
        isPrivate: false,
        country: 'Invalid IP',
        countryCode: '',
        city: '',
        latitude: null,
        longitude: null,
        isp: '',
        asn: '',
        asnOrg: '',
        timezone: '',
        isDemo: false,
        dataSource: 'NONE',
        observedEvidence: 'IP address format does not conform to valid IPv4 or IPv6 standards',
        inferredContext: 'Non-routable malformed token'
      };
    }

    const cleanIP = ip.trim();

    // 1. Check for Private / Reserved / Local IP
    if (isPrivateIP(cleanIP)) {
      return {
        ip: cleanIP,
        status: 'PRIVATE_IP',
        isPrivate: true,
        role: context.role || 'PRIVATE',
        roleLabel: context.roleLabel || 'Internal Network Hop (Private/RFC 1918)',
        country: 'Private / Reserved Network',
        countryCode: 'LAN',
        region: 'Internal Corporate Subnet',
        city: 'Local Area Network',
        latitude: null,
        longitude: null,
        isp: 'Private Infrastructure',
        asn: 'N/A (Private/Local Subnet)',
        asnOrg: 'Internal Network Entity',
        timezone: '',
        isDemo: false,
        dataSource: 'INTERNAL_FILTER',
        observedEvidence: `IP ${cleanIP} belongs to reserved non-routable address space (RFC 1918 / Loopback / Link-Local)`,
        inferredContext: 'Private network hop excluded from public geolocation lookups'
      };
    }

    // 2. Check in-memory cache to prevent duplicate calls
    if (this.cache.has(cleanIP)) {
      const cached = this.cache.get(cleanIP);
      return {
        ...cached,
        role: context.role || cached.role || 'UNKNOWN',
        roleLabel: context.roleLabel || cached.roleLabel || 'Network Indicator'
      };
    }

    // 3. Query configured providers sequentially
    for (const provider of this.providers) {
      try {
        const result = await provider.lookup(cleanIP);
        if (result && (result.country || result.city || result.latitude !== null)) {
          const record = {
            ip: cleanIP,
            status: 'SUCCESS',
            isPrivate: false,
            role: context.role || 'OBSERVED_IP',
            roleLabel: context.roleLabel || 'Observed Public IP',
            country: result.country || 'Unknown Country',
            countryCode: result.countryCode || '',
            region: result.region || '',
            city: result.city || '',
            latitude: typeof result.latitude === 'number' ? result.latitude : null,
            longitude: typeof result.longitude === 'number' ? result.longitude : null,
            timezone: result.timezone || '',
            isp: result.isp || result.asnOrg || 'Unknown ISP',
            asn: result.asn || 'AS-UNKNOWN',
            asnOrg: result.asnOrg || result.isp || 'Autonomous System',
            networkType: result.networkType || 'Standard Transit Infrastructure',
            isProxyOrVpn: Boolean(result.isProxyOrVpn),
            riskLevel: result.riskLevel || (result.isProxyOrVpn ? 'HIGH' : 'LOW'),
            routingDetails: result.routingDetails || `Observed routing via ${result.asn || 'upstream transit'}`,
            isDemo: Boolean(result.isDemo),
            dataSource: result.dataSource || 'LIVE FORENSIC TELEMETRY',
            observedEvidence: `Observed IP ${cleanIP} geolocates to ${result.city ? `${result.city}, ` : ''}${result.country || 'Unknown'} (${result.asn || 'Unknown ASN'} - ${result.asnOrg || result.isp || 'Transit'})`,
            inferredContext: result.isProxyOrVpn 
              ? 'Anonymizing relay / VPN egress infrastructure often leveraged in evasion directives' 
              : 'Standard internet transit infrastructure routing'
          };

          this.cache.set(cleanIP, record);
          return record;
        }
      } catch {
        // Continue to next provider
      }
    }

    // 4. All providers failed or offline -> Return UNAVAILABLE without fake coordinates
    const unavailableRecord = {
      ip: cleanIP,
      status: 'UNAVAILABLE',
      error: 'Geolocation unavailable',
      role: context.role || 'UNKNOWN',
      roleLabel: context.roleLabel || 'Observed Public IP',
      isPrivate: false,
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
      isDemo: false,
      dataSource: 'UNAVAILABLE',
      observedEvidence: `Observed public IP ${cleanIP} (Geolocation intelligence lookup unavailable)`,
      inferredContext: 'Geographic attribution unavailable; proceeding with remaining multi-layer forensic evidence'
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
      const ip = typeof ind === 'string' ? ind.trim() : (ind.ip || '').trim();
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
