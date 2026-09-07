/**
 * MAVERICK — Hash Threat Intelligence Reputation Service
 * Smart India Hackathon 2026
 * 
 * Abstraction layer for querying external hash reputation intelligence (VirusTotal, MalwareBazaar, etc.)
 * Server-side API key protection: Frontend NEVER handles or exposes threat intel API keys.
 * Strict Integrity Principle: NEVER fabricates reputation results. If no key/provider is available,
 * returns status: "UNAVAILABLE".
 */

export class BaseReputationProvider {
  constructor(name) {
    this.name = name;
  }

  async lookup(hash) {
    throw new Error('lookup() must be implemented by provider');
  }
}

/**
 * Backend Gateway Provider:
 * Delegates lookups to MAVERICK Node.js intelligence gateway server.
 */
export class GatewayHashProvider extends BaseReputationProvider {
  constructor(baseUrl = '') {
    super('MAVERICK Intelligence Gateway (VirusTotal Integration)');
    this.baseUrl = baseUrl || (typeof window !== 'undefined' ? '' : 'http://localhost:5000');
  }

  async lookup(hash) {
    if (!hash || typeof hash !== 'string' || hash.length < 32) {
      return {
        status: 'INVALID_INPUT',
        verdict: 'UNKNOWN',
        score: 'N/A',
        details: 'Invalid or missing hash string'
      };
    }

    try {
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 3000);
      
      const endpoint = `${this.baseUrl}/api/enrich?ioc=${encodeURIComponent(hash.trim().toLowerCase())}&type=HASH`;
      const response = await fetch(endpoint, {
        signal: controller.signal,
        headers: { 'Accept': 'application/json' }
      });
      clearTimeout(timeoutId);

      if (!response.ok) {
        return {
          status: 'UNAVAILABLE',
          verdict: 'UNAVAILABLE',
          score: 'N/A',
          details: `Intelligence gateway returned HTTP ${response.status}`
        };
      }

      const data = await response.json();
      
      if (data && data.virusTotal) {
        const vt = data.virusTotal;
        if (vt.verdict === 'UNKNOWN' && (vt.details || '').includes('unconfigured')) {
          return {
            status: 'UNAVAILABLE',
            verdict: 'UNAVAILABLE',
            score: 'N/A',
            details: 'VirusTotal API key unconfigured on server. Hash reputation unavailable.'
          };
        }

        return {
          status: 'SUCCESS',
          verdict: vt.verdict || 'UNKNOWN',
          score: vt.score || '0/0',
          maliciousCount: vt.maliciousCount || 0,
          totalCount: vt.totalCount || 0,
          details: vt.details || 'VirusTotal community consensus'
        };
      }

      return {
        status: 'UNAVAILABLE',
        verdict: 'UNAVAILABLE',
        score: 'N/A',
        details: 'Threat intelligence response format unrecognized'
      };
    } catch {
      return {
        status: 'UNAVAILABLE',
        verdict: 'UNAVAILABLE',
        score: 'N/A',
        details: 'Threat intelligence server gateway offline or unreachable'
      };
    }
  }
}

/**
 * Primary HashReputationService with in-memory caching and extensible provider support
 */
export class HashReputationService {
  constructor(provider = null) {
    this.provider = provider || new GatewayHashProvider();
    this.cache = new Map();
  }

  setProvider(provider) {
    this.provider = provider;
  }

  async checkHash(hash) {
    if (!hash || typeof hash !== 'string') {
      return {
        hash: '',
        status: 'INVALID_INPUT',
        verdict: 'UNKNOWN',
        score: 'N/A',
        details: 'No hash supplied for intelligence lookup'
      };
    }

    const cleanHash = hash.trim().toLowerCase();
    if (this.cache.has(cleanHash)) {
      return this.cache.get(cleanHash);
    }

    const result = await this.provider.lookup(cleanHash);
    const enriched = {
      hash: cleanHash,
      provider: this.provider.name,
      status: result.status || 'UNAVAILABLE',
      verdict: result.verdict || 'UNAVAILABLE',
      score: result.score || 'N/A',
      maliciousCount: result.maliciousCount || 0,
      totalCount: result.totalCount || 0,
      details: result.details || 'Reputation intelligence evaluated',
      queriedAt: new Date().toISOString()
    };

    this.cache.set(cleanHash, enriched);
    return enriched;
  }
}

export const defaultHashReputationService = new HashReputationService();
