/**
 * MAVERICK — DNS Forensics Service
 * Provides robust DNS TXT record resolution, in-memory TTL caching,
 * domain validation, and mock resolver factory for test determinism.
 * 
 * Strict separation: This service queries actual DNS infrastructure or mock records;
 * it NEVER fabricates or simulates DNS data in production resolution.
 */

// In-memory DNS cache: domain -> { records: string[], timestamp: number, ttlMs: number }
const dnsCache = new Map();
let cacheHits = 0;
let cacheMisses = 0;

const DEFAULT_CACHE_TTL_MS = 5 * 60 * 1000; // 5 minutes

/**
 * Validates whether a given domain string is syntactically valid.
 * Complies with RFC 1035 / RFC 1123 domain name standards.
 * 
 * @param {string} domain 
 * @returns {boolean}
 */
export function isValidDomain(domain) {
  if (!domain || typeof domain !== 'string') return false;
  const trimmed = domain.trim().toLowerCase();
  if (trimmed.length === 0 || trimmed.length > 253) return false;
  
  // Strip trailing dot if present (FQDN)
  const normalized = trimmed.endsWith('.') ? trimmed.slice(0, -1) : trimmed;
  if (!normalized) return false;

  const labels = normalized.split('.');
  if (labels.length < 2) {
    // Top-level domain only or single label is not a valid fully qualified domain
    return false;
  }

  const labelRegex = /^_?[a-z0-9](?:[a-z0-9_-]{0,61}[a-z0-9])?$/i;
  for (const label of labels) {
    if (!label || label.length > 63) return false;
    if (!labelRegex.test(label)) return false;
  }

  // TLD must contain at least one letter and not be purely numeric
  const tld = labels[labels.length - 1];
  if (/^\d+$/.test(tld) || tld.length < 2) return false;

  return true;
}

/**
 * Normalizes a domain name by trimming and converting to lowercase.
 * 
 * @param {string} domain 
 * @returns {string}
 */
export function normalizeDomain(domain) {
  if (!domain || typeof domain !== 'string') return '';
  const trimmed = domain.trim().toLowerCase();
  return trimmed.endsWith('.') ? trimmed.slice(0, -1) : trimmed;
}

/**
 * Resolves TXT records for a given domain.
 * Supports:
 * - In-memory TTL caching
 * - Custom/Mock resolver injection via options.resolver
 * - Node.js `node:dns/promises` runtime resolution
 * - Browser graceful fallback (noting DNS resolution requires backend gateway)
 * 
 * @param {string} domain 
 * @param {Object} [options]
 * @param {Function} [options.resolver] - Optional custom resolver function (e.g. for testing)
 * @param {number} [options.ttlMs] - Custom cache TTL in milliseconds
 * @param {boolean} [options.bypassCache] - Skip cache lookup if true
 * @returns {Promise<{
 *   domain: string,
 *   records: string[],
 *   status: 'RESOLVED' | 'NO_RECORDS' | 'NXDOMAIN' | 'TIMEOUT' | 'ERROR' | 'INVALID_DOMAIN' | 'UNSUPPORTED_RUNTIME',
 *   fromCache: boolean,
 *   raw: any,
 *   error?: string
 * }>}
 */
export async function resolveTxt(domain, options = {}) {
  const normalized = normalizeDomain(domain);

  if (!isValidDomain(normalized)) {
    return {
      domain: normalized || domain,
      records: [],
      status: 'INVALID_DOMAIN',
      fromCache: false,
      raw: null,
      error: `Invalid domain syntax: ${domain}`
    };
  }

  const ttl = options.ttlMs || DEFAULT_CACHE_TTL_MS;

  // Check cache unless bypassed
  if (!options.bypassCache && !options.resolver) {
    const cached = dnsCache.get(normalized);
    if (cached && Date.now() - cached.timestamp < cached.ttlMs) {
      cacheHits++;
      return {
        domain: normalized,
        records: [...cached.records],
        status: cached.records.length > 0 ? 'RESOLVED' : 'NO_RECORDS',
        fromCache: true,
        raw: cached.raw
      };
    }
  }

  // 1. Custom or Mock Resolver
  if (typeof options.resolver === 'function') {
    try {
      const result = await options.resolver(normalized);
      if (Array.isArray(result)) {
        // Flatten chunks: DNS TXT records can be returned as string[] or string[][]
        const flatRecords = result.map(entry => Array.isArray(entry) ? entry.join('') : String(entry));
        return {
          domain: normalized,
          records: flatRecords,
          status: flatRecords.length > 0 ? 'RESOLVED' : 'NO_RECORDS',
          fromCache: false,
          raw: result
        };
      }
      if (result && typeof result === 'object') {
        const records = Array.isArray(result.records)
          ? result.records.map(entry => Array.isArray(entry) ? entry.join('') : String(entry))
          : [];
        return {
          domain: normalized,
          records,
          status: result.status || (records.length > 0 ? 'RESOLVED' : 'NO_RECORDS'),
          fromCache: false,
          raw: result.raw || result,
          error: result.error
        };
      }
      return {
        domain: normalized,
        records: [],
        status: 'NO_RECORDS',
        fromCache: false,
        raw: result
      };
    } catch (err) {
      const errCode = err.code || err.message || 'ERROR';
      let status = 'ERROR';
      if (errCode === 'ENOTFOUND' || errCode === 'NXDOMAIN') status = 'NXDOMAIN';
      else if (errCode === 'NODATA' || errCode === 'ENODATA') status = 'NO_RECORDS';
      else if (errCode === 'ETIMEOUT' || errCode === 'TIMEOUT') status = 'TIMEOUT';
      else if (errCode === 'ESERVFAIL' || errCode === 'SERVFAIL') status = 'SERVFAIL';

      return {
        domain: normalized,
        records: [],
        status,
        fromCache: false,
        raw: null,
        error: err.message
      };
    }
  }

  // 2. Node.js native DNS resolution (node:dns/promises)
  if (typeof process !== 'undefined' && process.versions && process.versions.node) {
    cacheMisses++;
    try {
      const dnsModule = 'node:dns/promises';
      const { resolveTxt: nodeResolveTxt } = await import(/* @vite-ignore */ dnsModule);
      const rawChunks = await nodeResolveTxt(normalized);

      // Node dns.resolveTxt returns Array of Array of strings (e.g. [['v=spf1 ...']])
      const records = rawChunks.map(chunk => Array.isArray(chunk) ? chunk.join('') : String(chunk));

      const payload = {
        domain: normalized,
        records,
        status: records.length > 0 ? 'RESOLVED' : 'NO_RECORDS',
        fromCache: false,
        raw: rawChunks
      };

      // Store in cache
      dnsCache.set(normalized, {
        records,
        timestamp: Date.now(),
        ttlMs: ttl,
        raw: rawChunks
      });

      return payload;
    } catch (err) {
      const errCode = err.code || '';
      let status = 'ERROR';
      if (errCode === 'ENOTFOUND' || errCode === 'NXDOMAIN') {
        status = 'NXDOMAIN';
      } else if (errCode === 'NODATA' || errCode === 'ENODATA') {
        status = 'NO_RECORDS';
      } else if (errCode === 'ETIMEOUT' || errCode === 'TIMEOUT') {
        status = 'TIMEOUT';
      } else if (errCode === 'ESERVFAIL' || errCode === 'SERVFAIL') {
        status = 'SERVFAIL';
      }

      // Negative cache for NXDOMAIN/NODATA with shorter TTL (60s)
      if (status === 'NXDOMAIN' || status === 'NO_RECORDS') {
        dnsCache.set(normalized, {
          records: [],
          timestamp: Date.now(),
          ttlMs: Math.min(ttl, 60000),
          raw: null
        });
      }

      return {
        domain: normalized,
        records: [],
        status,
        fromCache: false,
        raw: null,
        error: err.message || String(err)
      };
    }
  }

  // 3. Browser environment without backend endpoint directly called
  return {
    domain: normalized,
    records: [],
    status: 'UNSUPPORTED_RUNTIME',
    fromCache: false,
    raw: null,
    error: 'Direct DNS resolution is unavailable in browser runtime. Query via backend gateway API.'
  };
}

/**
 * Resolves IPv4 (A) records for a given domain using native Node.js DNS.
 * 
 * @param {string} domain 
 * @param {Object} [options]
 * @returns {Promise<{ domain: string, addresses: string[], status: string, error?: string }>}
 */
export async function resolve4(domain, options = {}) {
  const normalized = normalizeDomain(domain);
  if (!isValidDomain(normalized)) {
    return { domain: normalized || domain, addresses: [], status: 'INVALID_DOMAIN', error: `Invalid domain syntax: ${domain}` };
  }

  if (typeof options.resolver === 'function') {
    try {
      const res = await options.resolver(normalized, 'A');
      const addrs = Array.isArray(res) ? res : (res?.addresses || res?.records || []);
      return { domain: normalized, addresses: addrs, status: addrs.length > 0 ? 'RESOLVED' : 'NO_RECORDS' };
    } catch (err) {
      const errCode = err.code || '';
      return {
        domain: normalized,
        addresses: [],
        status: errCode === 'ENOTFOUND' ? 'NXDOMAIN' : errCode === 'NODATA' ? 'NO_RECORDS' : 'ERROR',
        error: err.message
      };
    }
  }

  if (typeof process !== 'undefined' && process.versions && process.versions.node) {
    try {
      const { resolve4: nodeResolve4 } = await import(/* @vite-ignore */ 'node:dns/promises');
      const addresses = await nodeResolve4(normalized);
      return { domain: normalized, addresses, status: addresses.length > 0 ? 'RESOLVED' : 'NO_RECORDS' };
    } catch (err) {
      const errCode = err.code || '';
      return {
        domain: normalized,
        addresses: [],
        status: errCode === 'ENOTFOUND' ? 'NXDOMAIN' : errCode === 'NODATA' ? 'NO_RECORDS' : 'ERROR',
        error: err.message
      };
    }
  }

  return { domain: normalized, addresses: [], status: 'UNSUPPORTED_RUNTIME', error: 'Direct DNS resolution is unavailable in browser runtime.' };
}

/**
 * Resolves IPv6 (AAAA) records for a given domain using native Node.js DNS.
 * 
 * @param {string} domain 
 * @param {Object} [options]
 * @returns {Promise<{ domain: string, addresses: string[], status: string, error?: string }>}
 */
export async function resolve6(domain, options = {}) {
  const normalized = normalizeDomain(domain);
  if (!isValidDomain(normalized)) {
    return { domain: normalized || domain, addresses: [], status: 'INVALID_DOMAIN', error: `Invalid domain syntax: ${domain}` };
  }

  if (typeof options.resolver === 'function') {
    try {
      const res = await options.resolver(normalized, 'AAAA');
      const addrs = Array.isArray(res) ? res : (res?.addresses || res?.records || []);
      return { domain: normalized, addresses: addrs, status: addrs.length > 0 ? 'RESOLVED' : 'NO_RECORDS' };
    } catch (err) {
      const errCode = err.code || '';
      return {
        domain: normalized,
        addresses: [],
        status: errCode === 'ENOTFOUND' ? 'NXDOMAIN' : errCode === 'NODATA' ? 'NO_RECORDS' : 'ERROR',
        error: err.message
      };
    }
  }

  if (typeof process !== 'undefined' && process.versions && process.versions.node) {
    try {
      const { resolve6: nodeResolve6 } = await import(/* @vite-ignore */ 'node:dns/promises');
      const addresses = await nodeResolve6(normalized);
      return { domain: normalized, addresses, status: addresses.length > 0 ? 'RESOLVED' : 'NO_RECORDS' };
    } catch (err) {
      const errCode = err.code || '';
      return {
        domain: normalized,
        addresses: [],
        status: errCode === 'ENOTFOUND' ? 'NXDOMAIN' : errCode === 'NODATA' ? 'NO_RECORDS' : 'ERROR',
        error: err.message
      };
    }
  }

  return { domain: normalized, addresses: [], status: 'UNSUPPORTED_RUNTIME', error: 'Direct DNS resolution is unavailable in browser runtime.' };
}

/**
 * Creates a mock DNS resolver function for deterministic testing.
 * 
 * @param {Record<string, string[] | { records?: string[], status?: string, error?: string }>} mockDatabase 
 * @returns {Function} (domain: string) => Promise<{ records: string[], status: string, raw: any, error?: string }>
 */
export function createMockDnsResolver(mockDatabase = {}) {
  // Case-insensitive lookup map
  const normalizedMap = new Map();
  for (const [key, val] of Object.entries(mockDatabase)) {
    normalizedMap.set(key.toLowerCase().trim(), val);
  }

  return async function mockResolver(domain, recordType = 'TXT') {
    const key = normalizeDomain(domain);
    if (!normalizedMap.has(key)) {
      const err = new Error(`Query failed with ENOTFOUND for domain ${domain}`);
      err.code = 'ENOTFOUND';
      throw err;
    }

    const value = normalizedMap.get(key);
    if (value instanceof Error) {
      throw value;
    }

    if (Array.isArray(value)) {
      return {
        records: value,
        addresses: value,
        status: value.length > 0 ? 'RESOLVED' : 'NO_RECORDS',
        raw: value
      };
    }

    if (typeof value === 'object' && value !== null) {
      if (value.error) {
        const err = new Error(value.error);
        if (value.status) err.code = value.status;
        throw err;
      }
      const typeKey = (recordType || 'TXT').toUpperCase();
      const typeSpecific = value[typeKey] || value[typeKey.toLowerCase()];
      if (Array.isArray(typeSpecific)) {
        return {
          records: typeSpecific,
          addresses: typeSpecific,
          status: typeSpecific.length > 0 ? 'RESOLVED' : 'NO_RECORDS',
          raw: typeSpecific
        };
      }
      return {
        records: value.records || value.addresses || [],
        addresses: value.addresses || value.records || [],
        status: value.status || ((value.records || value.addresses)?.length > 0 ? 'RESOLVED' : 'NO_RECORDS'),
        raw: value
      };
    }

    return {
      records: [],
      addresses: [],
      status: 'NO_RECORDS',
      raw: null
    };
  };
}

/**
 * Clears the DNS in-memory cache.
 */
export function clearDnsCache() {
  dnsCache.clear();
  cacheHits = 0;
  cacheMisses = 0;
}

/**
 * Returns cache metrics and hit rates.
 */
export function getDnsCacheStats() {
  return {
    size: dnsCache.size,
    hits: cacheHits,
    misses: cacheMisses,
    hitRate: (cacheHits + cacheMisses) > 0 ? (cacheHits / (cacheHits + cacheMisses)) : 0
  };
}
