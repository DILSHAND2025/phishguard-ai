/**
 * MAVERICK — GeoLocation & Autonomous System (ASN) Intelligence Service
 * Smart India Hackathon 2026
 * 
 * Resolves network topology for extracted IP addresses:
 * - Country, Region, City, Coordinates
 * - Autonomous System Number (ASN) & BGP Prefix
 * - ISP and Hosting Organization
 * - Network Type (Hosting, Anonymizing Tor Relay, CDN Proxy, Residential)
 * 
 * Strict Compliance:
 * NEVER states: "The attacker is located in [Country]"
 * ALWAYS states: "The observed IP infrastructure geolocates to [Country]"
 * INCLUDES: "IP GeoLocation represents observed network infrastructure and does not establish the physical identity or location of the attacker."
 */

import { queryBackendGateway } from './threatIntel.js';

const GEO_CACHE = new Map();

// Mandatory forensic disclaimer mandated for court and CERT-In readiness
export const GEO_LEGAL_DISCLAIMER = 
  'IP GeoLocation represents observed network infrastructure and does not establish the physical identity or location of the attacker.';

// Known ASN & Geo records for reproducible demo telemetry
const KNOWN_GEO_DATA = {
  '185.220.101.45': {
    ip: '185.220.101.45',
    country: 'Germany',
    countryCode: 'DE',
    region: 'Hesse',
    city: 'Frankfurt am Main',
    latitude: 50.1109,
    longitude: 8.6821,
    asn: 'AS9009',
    asnOrg: 'M247 Ltd Europe',
    isp: 'M247 Europe S.R.L.',
    networkType: 'Tor Exit Node / Anonymizing Relay',
    riskLevel: 'HIGH',
    isProxyOrVpn: true,
    routingDetails: 'BGP Prefix: 185.220.100.0/22 | Tor Directory Authority Verified'
  },
  '45.154.255.82': {
    ip: '45.154.255.82',
    country: 'Netherlands',
    countryCode: 'NL',
    region: 'North Holland',
    city: 'Amsterdam',
    latitude: 52.3676,
    longitude: 4.9041,
    asn: 'AS202425',
    asnOrg: 'IP Volume Inc',
    isp: 'IP Volume Networks',
    networkType: 'Commercial Hosting / Proxy Egress',
    riskLevel: 'HIGH',
    isProxyOrVpn: true,
    routingDetails: 'BGP Prefix: 45.154.252.0/22 | Fast-Flux Reverse Proxy Detected'
  },
  '193.106.191.12': {
    ip: '193.106.191.12',
    country: 'Russia',
    countryCode: 'RU',
    region: 'Moscow',
    city: 'Moscow',
    latitude: 55.7558,
    longitude: 37.6173,
    asn: 'AS44034',
    asnOrg: 'HiChina Web Hosting',
    isp: 'HiChina Telecommunications',
    networkType: 'Bulletproof Hosting / C2 Infrastructure',
    riskLevel: 'CRITICAL',
    isProxyOrVpn: false,
    routingDetails: 'BGP Prefix: 193.106.190.0/23 | Repeatedly flagged in malware distributions'
  },
  '104.21.36.45': {
    ip: '104.21.36.45',
    country: 'United States',
    countryCode: 'US',
    region: 'California',
    city: 'San Francisco',
    latitude: 37.7749,
    longitude: -122.4194,
    asn: 'AS13335',
    asnOrg: 'Cloudflare Edge Transit',
    isp: 'Cloudflare Inc',
    networkType: 'Commercial CDN / Reverse Proxy',
    riskLevel: 'MEDIUM',
    isProxyOrVpn: true,
    routingDetails: 'Anycast Routing Gateway | Masking Origin Web Server'
  },
  '194.26.29.110': {
    ip: '194.26.29.110',
    country: 'Romania',
    countryCode: 'RO',
    region: 'Bucharest',
    city: 'Bucharest',
    latitude: 44.4268,
    longitude: 26.1025,
    asn: 'AS48693',
    asnOrg: 'HostRoyale Egress Relay',
    isp: 'HostRoyale Ltd',
    networkType: 'Transit Relay Endpoint',
    riskLevel: 'HIGH',
    isProxyOrVpn: true,
    routingDetails: 'BGP Prefix: 194.26.28.0/23 | Intermediate SMTP Routing Relay'
  }
};

import { defaultGeoService } from './geoLocationService.js';

// Master GeoLocation & ASN resolver (delegates to GeoLocationService abstraction)
export async function resolveIPGeo(ip) {
  if (!ip || typeof ip !== 'string') return null;
  const result = await defaultGeoService.resolveIP(ip, { role: 'SOURCE', roleLabel: 'Originating IP' });
  return result;
}


