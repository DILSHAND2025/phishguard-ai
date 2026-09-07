/**
 * MAVERICK — Live Email Authentication & DNS Forensics Service
 * Smart India Hackathon 2026
 * 
 * Implements end-to-end email authentication forensic investigation:
 * 1. RFC 5322 / RFC 822 Header Parsing (From, Return-Path, Reply-To, Received, Authentication-Results, DKIM-Signature)
 * 2. RFC 7601 / RFC 8601 Authentication-Results Parser (MTA Observed Findings)
 * 3. RFC 7208 SPF DNS Forensics & Mechanism Analysis
 * 4. RFC 6376 DKIM DNS Public Key Verification & Cryptographic Key Auditing
 * 5. RFC 7489 DMARC Policy Retrieval & Subdomain Fallback
 * 6. RFC 7489 Strict vs Relaxed Domain Alignment Engine
 * 7. Strict Separation: Observed Evidence (MTA & DNS) vs Inferred Evidence (Alignment & Spoofing Analysis)
 * 
 * NEVER fabricates or simulates DNS data.
 * NEVER conflates "DNS RECORD FOUND" with "CRYPTOGRAPHICALLY VERIFIED BY MAVERICK".
 */

import { isValidDomain, normalizeDomain, resolveTxt } from './dnsService.js';

// Common two-part public suffixes for organizational domain extraction
const TWO_PART_TLDS = new Set([
  'co.uk', 'gov.uk', 'ac.uk', 'org.uk', 'net.uk', 'me.uk', 'ltd.uk',
  'com.au', 'net.au', 'org.au', 'edu.au', 'gov.au',
  'co.in', 'net.in', 'org.in', 'gen.in', 'ind.in', 'firm.in', 'gov.in', 'ac.in', 'edu.in',
  'com.br', 'gov.br', 'org.br', 'co.jp', 'ne.jp', 'or.jp', 'go.jp', 'ac.jp',
  'co.nz', 'net.nz', 'org.nz', 'co.za', 'org.za', 'com.sg', 'edu.sg',
  'com.hk', 'edu.hk', 'co.kr', 'or.kr', 'com.tw', 'org.tw', 'com.cn', 'net.cn', 'org.cn',
  'com.mx', 'org.mx', 'com.my', 'edu.my', 'co.id', 'web.id', 'ac.id'
]);

/**
 * Extracts the organizational (registrable) domain from a fully-qualified domain.
 * e.g., 'mail.marketing.example.com' -> 'example.com'
 * e.g., 'auth.corp.example.co.uk' -> 'example.co.uk'
 * 
 * @param {string} domain 
 * @returns {string}
 */
export function getOrganizationalDomain(domain) {
  if (!domain || typeof domain !== 'string') return '';
  const normalized = normalizeDomain(domain);
  const parts = normalized.split('.');
  if (parts.length <= 2) return normalized;

  const lastTwo = `${parts[parts.length - 2]}.${parts[parts.length - 1]}`;
  if (TWO_PART_TLDS.has(lastTwo)) {
    if (parts.length >= 3) {
      return parts.slice(-3).join('.');
    }
    return normalized;
  }

  return parts.slice(-2).join('.');
}

/**
 * Parses an email address string formatted as:
 * - "John Doe <johndoe@example.com>"
 * - "<johndoe@example.com>"
 * - "johndoe@example.com"
 * 
 * @param {string} rawString 
 * @returns {{ raw: string, displayName: string, email: string, domain: string }}
 */
export function parseAddress(rawString) {
  if (!rawString || typeof rawString !== 'string') {
    return { raw: '', displayName: '', email: '', domain: '' };
  }

  const raw = rawString.trim();
  let displayName = '';
  let email = '';

  const angleMatch = raw.match(/^(.*?)\s*<([^\s<>@]+@[^\s<>@]+)>/);
  if (angleMatch) {
    displayName = angleMatch[1].replace(/^["']|["']$/g, '').trim();
    email = angleMatch[2].trim().toLowerCase();
  } else {
    const directMatch = raw.match(/([^\s<>@]+@[^\s<>@]+)/);
    if (directMatch) {
      email = directMatch[1].trim().toLowerCase();
      displayName = raw.replace(directMatch[0], '').replace(/[<>]/g, '').trim();
    } else {
      email = raw.replace(/[<>]/g, '').trim().toLowerCase();
    }
  }

  let domain = '';
  if (email.includes('@')) {
    domain = normalizeDomain(email.split('@')[1]);
  }

  return { raw, displayName, email, domain };
}

/**
 * Extracts raw headers from an RFC 5322 email string, unfolding multiline headers.
 * 
 * @param {string} rawEmail 
 * @returns {Record<string, string[]>} Case-insensitive map of header names to arrays of values
 */
export function extractRawHeaders(rawEmail) {
  const headers = {};
  if (!rawEmail || typeof rawEmail !== 'string') return headers;

  // Header section ends at first double newline (\r?\n\r?\n)
  const headerEndIndex = rawEmail.search(/\r?\n\r?\n/);
  const headerText = headerEndIndex !== -1 ? rawEmail.slice(0, headerEndIndex) : rawEmail;

  // Unfold folded header lines (RFC 5322 Section 2.2.3)
  const lines = headerText.split(/\r?\n/);
  const unfoldedLines = [];

  for (const line of lines) {
    if (/^[ \t]/.test(line) && unfoldedLines.length > 0) {
      // Continuation line: replace leading whitespace with a single space
      unfoldedLines[unfoldedLines.length - 1] += ' ' + line.trim();
    } else if (line.trim().length > 0) {
      unfoldedLines.push(line.trim());
    }
  }

  for (const line of unfoldedLines) {
    const colonIndex = line.indexOf(':');
    if (colonIndex > 0) {
      const key = line.slice(0, colonIndex).trim().toLowerCase();
      const val = line.slice(colonIndex + 1).trim();
      if (!headers[key]) headers[key] = [];
      headers[key].push(val);
    }
  }

  return headers;
}

/**
 * Parses RFC 7601 / RFC 8601 Authentication-Results header(s).
 * 
 * Example:
 * `mx.google.com; dkim=pass header.i=@github.com header.s=s2023; spf=pass (google.com: domain of support@github.com designates 192.30.252.204 as permitted sender) smtp.mailfrom=support@github.com; dmarc=pass (p=REJECT sp=REJECT) header.from=github.com`
 * 
 * @param {string[]} authResultHeaders 
 * @returns {{
 *   authservId: string,
 *   spf: { verdict: string, mailfrom: string, reason: string, clientIp: string } | null,
 *   dkim: Array<{ verdict: string, domain: string, selector: string, identity: string, reason: string }>,
 *   dmarc: { verdict: string, headerFrom: string, policy: string, disposition: string, reason: string } | null,
 *   raw: string[]
 * }}
 */
export function parseAuthenticationResults(authResultHeaders = []) {
  const result = {
    authservId: '',
    spf: null,
    dkim: [],
    dmarc: null,
    raw: authResultHeaders
  };

  if (!Array.isArray(authResultHeaders) || authResultHeaders.length === 0) {
    return result;
  }

  // Iterate in reverse (first header is closest to recipient MTA / boundary)
  for (const header of authResultHeaders) {
    const parts = header.split(';');
    if (parts.length === 0) continue;

    const authservId = parts[0].trim();
    if (!result.authservId) result.authservId = authservId;

    for (let i = 1; i < parts.length; i++) {
      const section = parts[i].trim();
      if (!section) continue;

      // Match method=result
      const methodMatch = section.match(/^(spf|dkim|dmarc|arc)=([a-zA-Z0-9_-]+)/i);
      if (!methodMatch) continue;

      const method = methodMatch[1].toLowerCase();
      const verdict = methodMatch[2].toLowerCase();

      // Extract details inside parentheses (e.g. comment / reason)
      const commentMatch = section.match(/\((.*?)\)/);
      const reason = commentMatch ? commentMatch[1].trim() : '';

      if (method === 'spf') {
        const mailfromMatch = section.match(/smtp\.mailfrom=([^\s;]+)/i);
        const ipMatch = section.match(/designates\s+([0-9a-fA-F:.]+)/i) || section.match(/client-ip=([^\s;]+)/i);

        result.spf = {
          verdict,
          mailfrom: mailfromMatch ? mailfromMatch[1].trim() : '',
          clientIp: ipMatch ? ipMatch[1].trim() : '',
          reason
        };
      } else if (method === 'dkim') {
        const domainMatch = section.match(/header\.d=([^\s;]+)/i);
        const selectorMatch = section.match(/header\.s=([^\s;]+)/i);
        const iMatch = section.match(/header\.i=([^\s;]+)/i);

        let dkimDomain = domainMatch ? domainMatch[1].trim() : '';
        if (!dkimDomain && iMatch) {
          const atIdx = iMatch[1].indexOf('@');
          if (atIdx !== -1) dkimDomain = iMatch[1].slice(atIdx + 1).trim();
        }

        result.dkim.push({
          verdict,
          domain: normalizeDomain(dkimDomain),
          selector: selectorMatch ? selectorMatch[1].trim() : '',
          identity: iMatch ? iMatch[1].trim() : '',
          reason
        });
      } else if (method === 'dmarc') {
        const fromMatch = section.match(/header\.from=([^\s;]+)/i);
        const policyMatch = section.match(/p=([a-zA-Z]+)/i);
        const dispMatch = section.match(/dis=([a-zA-Z]+)/i) || section.match(/action=([a-zA-Z]+)/i);

        result.dmarc = {
          verdict,
          headerFrom: fromMatch ? normalizeDomain(fromMatch[1].trim()) : '',
          policy: policyMatch ? policyMatch[1].toLowerCase() : '',
          disposition: dispMatch ? dispMatch[1].toLowerCase() : '',
          reason
        };
      }
    }
  }

  return result;
}

/**
 * Parses an RFC 6376 DKIM-Signature header tag-list.
 * 
 * Example:
 * `v=1; a=rsa-sha256; c=relaxed/relaxed; d=example.com; s=s2023; h=from:to:subject; bh=47DEQpj...; b=dzdV...`
 * 
 * @param {string} dkimHeader 
 * @returns {{
 *   version: string,
 *   algorithm: string,
 *   canonicalization: string,
 *   domain: string,
 *   selector: string,
 *   headers: string[],
 *   bodyHash: string,
 *   signature: string,
 *   timestamp: number | null,
 *   expiration: number | null,
 *   raw: string
 * }}
 */
export function parseDkimSignature(dkimHeader) {
  if (!dkimHeader || typeof dkimHeader !== 'string') {
    return null;
  }

  const tags = {};
  const pairs = dkimHeader.split(';');

  for (const pair of pairs) {
    const eqIdx = pair.indexOf('=');
    if (eqIdx > 0) {
      const tag = pair.slice(0, eqIdx).trim().toLowerCase();
      const val = pair.slice(eqIdx + 1).trim();
      tags[tag] = val;
    }
  }

  if (!tags.d || !tags.s) {
    return null;
  }

  return {
    version: tags.v || '1',
    algorithm: tags.a || 'rsa-sha256',
    canonicalization: tags.c || 'simple/simple',
    domain: normalizeDomain(tags.d),
    selector: tags.s.trim(),
    headers: tags.h ? tags.h.split(':').map(h => h.trim().toLowerCase()) : [],
    bodyHash: tags.bh || '',
    signature: tags.b || '',
    timestamp: tags.t ? parseInt(tags.t, 10) : null,
    expiration: tags.x ? parseInt(tags.x, 10) : null,
    raw: dkimHeader
  };
}

/**
 * Parses Received-SPF header (RFC 7208).
 * 
 * Example:
 * `Pass (mailfrom) identity=mailfrom; client-ip=192.0.2.1; helo=mail.example.com; envelope-from=user@example.com`
 * 
 * @param {string} headerVal 
 * @returns {{ verdict: string, clientIp: string, envelopeFrom: string, helo: string }}
 */
export function parseReceivedSpf(headerVal) {
  if (!headerVal || typeof headerVal !== 'string') return null;

  const verdictMatch = headerVal.match(/^([a-zA-Z]+)/);
  const verdict = verdictMatch ? verdictMatch[1].toLowerCase() : 'none';

  const ipMatch = headerVal.match(/client-ip=([^\s;]+)/i);
  const fromMatch = headerVal.match(/envelope-from=([^\s;]+)/i);
  const heloMatch = headerVal.match(/helo=([^\s;]+)/i);

  return {
    verdict,
    clientIp: ipMatch ? ipMatch[1].trim() : '',
    envelopeFrom: fromMatch ? fromMatch[1].trim() : '',
    helo: heloMatch ? heloMatch[1].trim() : ''
  };
}

/**
 * Queries and analyzes the SPF TXT record for a domain (RFC 7208).
 * 
 * @param {string} domain 
 * @param {Object} [options]
 * @returns {Promise<{
 *   domain: string,
 *   record: string | null,
 *   status: 'RECORD_FOUND' | 'NO_RECORD' | 'PERMERROR' | 'INVALID_DOMAIN' | 'ERROR',
 *   mechanisms: string[],
 *   defaultQualifier: string,
 *   hasPlusAll: boolean,
 *   allMechanism: string | null,
 *   lookupCountEstimate: number,
 *   warnings: string[],
 *   rawRecords: string[]
 * }>}
 */
export async function querySpfRecord(domain, options = {}) {
  const normDomain = normalizeDomain(domain);
  if (!isValidDomain(normDomain)) {
    return {
      domain: normDomain || domain,
      record: null,
      status: 'INVALID_DOMAIN',
      mechanisms: [],
      defaultQualifier: 'neutral',
      hasPlusAll: false,
      allMechanism: null,
      lookupCountEstimate: 0,
      warnings: [`Invalid domain format: ${domain}`],
      rawRecords: []
    };
  }

  const dnsResult = await resolveTxt(normDomain, options);
  if (dnsResult.status === 'INVALID_DOMAIN' || dnsResult.status === 'ERROR' || dnsResult.status === 'TIMEOUT') {
    return {
      domain: normDomain,
      record: null,
      status: dnsResult.status === 'INVALID_DOMAIN' ? 'INVALID_DOMAIN' : 'ERROR',
      mechanisms: [],
      defaultQualifier: 'none',
      hasPlusAll: false,
      allMechanism: null,
      lookupCountEstimate: 0,
      warnings: [dnsResult.error || `DNS query failed with ${dnsResult.status}`],
      rawRecords: []
    };
  }

  // Filter TXT records for SPF (must start with v=spf1)
  const spfRecords = (dnsResult.records || []).filter(rec => {
    const trimmed = rec.trim();
    return /^v=spf1(\s|$)/i.test(trimmed);
  });

  // RFC 7208 Section 4.5: Multiple SPF records results in a PermError
  if (spfRecords.length > 1) {
    return {
      domain: normDomain,
      record: spfRecords[0],
      status: 'PERMERROR',
      mechanisms: [],
      defaultQualifier: 'permerror',
      hasPlusAll: false,
      allMechanism: null,
      lookupCountEstimate: 0,
      warnings: [`RFC 7208 PermError: Multiple SPF records (${spfRecords.length}) detected for ${normDomain}`],
      rawRecords: spfRecords
    };
  }

  if (spfRecords.length === 0) {
    return {
      domain: normDomain,
      record: null,
      status: 'NO_RECORD',
      mechanisms: [],
      defaultQualifier: 'none',
      hasPlusAll: false,
      allMechanism: null,
      lookupCountEstimate: 0,
      warnings: [`No SPF record found for ${normDomain}`],
      rawRecords: dnsResult.records || []
    };
  }

  const rawSpf = spfRecords[0].trim();
  const tokens = rawSpf.split(/\s+/).filter(Boolean);
  const mechanisms = [];
  const warnings = [];
  let allMechanism = null;
  let defaultQualifier = 'neutral';
  let hasPlusAll = false;
  let lookupCount = 0;

  for (let i = 1; i < tokens.length; i++) {
    const token = tokens[i];
    mechanisms.push(token);

    // Count DNS lookup mechanisms (include, a, mx, ptr, exists, redirect)
    const lowerToken = token.toLowerCase();
    if (lowerToken.startsWith('include:') ||
        lowerToken === 'a' || lowerToken.startsWith('a:') || lowerToken.startsWith('a/') ||
        lowerToken === 'mx' || lowerToken.startsWith('mx:') || lowerToken.startsWith('mx/') ||
        lowerToken.startsWith('exists:') || lowerToken.startsWith('ptr') || lowerToken.startsWith('redirect=')) {
      lookupCount++;
    }

    if (lowerToken === '+all' || lowerToken === 'all') {
      hasPlusAll = true;
      allMechanism = token;
      defaultQualifier = 'pass';
      warnings.push(`CRITICAL: SPF uses '${token}', allowing ANY sender on the Internet to spoof this domain.`);
    } else if (lowerToken === '-all') {
      allMechanism = token;
      defaultQualifier = 'fail';
    } else if (lowerToken === '~all') {
      allMechanism = token;
      defaultQualifier = 'softfail';
    } else if (lowerToken === '?all') {
      allMechanism = token;
      defaultQualifier = 'neutral';
    }
  }

  // RFC 7208 Section 4.6.4: SPF lookup limit is 10
  if (lookupCount > 10) {
    warnings.push(`SPF mechanism contains ${lookupCount} DNS lookups, exceeding RFC 7208 limit of 10.`);
  }

  if (!allMechanism) {
    warnings.push('SPF record lacks terminal `all` mechanism; unlisted IPs may fall back to default neutral.');
  }

  return {
    domain: normDomain,
    record: rawSpf,
    status: 'RECORD_FOUND',
    mechanisms,
    defaultQualifier,
    hasPlusAll,
    allMechanism,
    lookupCountEstimate: lookupCount,
    warnings,
    rawRecords: spfRecords
  };
}

/**
 * Queries and inspects DKIM Public Key TXT record at <selector>._domainkey.<domain> (RFC 6376).
 * 
 * @param {string} selector 
 * @param {string} domain 
 * @param {Object} [options]
 * @returns {Promise<{
 *   selector: string,
 *   domain: string,
 *   queryHost: string,
 *   record: string | null,
 *   status: 'RECORD_FOUND' | 'REVOKED' | 'NO_RECORD' | 'INVALID_SELECTOR_OR_DOMAIN' | 'ERROR',
 *   keyType: string,
 *   publicKey: string,
 *   keyLengthBits: number | null,
 *   isRevoked: boolean,
 *   warnings: string[],
 *   rawRecords: string[]
 * }>}
 */
export async function queryDkimRecord(selector, domain, options = {}) {
  const normDomain = normalizeDomain(domain);
  const cleanSelector = (selector || '').trim();

  if (!cleanSelector || !isValidDomain(normDomain)) {
    return {
      selector: cleanSelector,
      domain: normDomain || domain,
      queryHost: `${cleanSelector}._domainkey.${normDomain}`,
      record: null,
      status: 'INVALID_SELECTOR_OR_DOMAIN',
      keyType: '',
      publicKey: '',
      keyLengthBits: null,
      isRevoked: false,
      warnings: ['Invalid selector or domain syntax for DKIM query'],
      rawRecords: []
    };
  }

  const queryHost = `${cleanSelector}._domainkey.${normDomain}`;
  const dnsResult = await resolveTxt(queryHost, options);

  if (dnsResult.status === 'NO_RECORDS' || dnsResult.status === 'NXDOMAIN') {
    return {
      selector: cleanSelector,
      domain: normDomain,
      queryHost,
      record: null,
      status: 'NO_RECORD',
      keyType: '',
      publicKey: '',
      keyLengthBits: null,
      isRevoked: false,
      warnings: [`No DKIM public key record found at ${queryHost}`],
      rawRecords: dnsResult.records || []
    };
  }

  if (dnsResult.status !== 'RESOLVED' || !dnsResult.records || dnsResult.records.length === 0) {
    return {
      selector: cleanSelector,
      domain: normDomain,
      queryHost,
      record: null,
      status: 'ERROR',
      keyType: '',
      publicKey: '',
      keyLengthBits: null,
      isRevoked: false,
      warnings: [dnsResult.error || `Failed to resolve ${queryHost}`],
      rawRecords: []
    };
  }

  // Find record containing p= or v=DKIM1
  const dkimRecord = dnsResult.records.find(r => /p=|v=DKIM1/i.test(r)) || dnsResult.records[0];
  const tags = {};
  const tagPairs = dkimRecord.split(';');

  for (const pair of tagPairs) {
    const eqIdx = pair.indexOf('=');
    if (eqIdx > 0) {
      const k = pair.slice(0, eqIdx).trim().toLowerCase();
      const v = pair.slice(eqIdx + 1).trim();
      tags[k] = v;
    }
  }

  const keyType = tags.k || 'rsa';
  const rawKey = tags.p !== undefined ? tags.p : '';
  const warnings = [];

  // RFC 6376: An empty "p=" tag explicitly revokes the key
  if (tags.p === '' || (tags.p && tags.p.trim() === '')) {
    return {
      selector: cleanSelector,
      domain: normDomain,
      queryHost,
      record: dkimRecord,
      status: 'REVOKED',
      keyType,
      publicKey: '',
      keyLengthBits: null,
      isRevoked: true,
      warnings: [`DKIM public key at ${queryHost} is explicitly revoked (empty p= tag)`],
      rawRecords: dnsResult.records
    };
  }

  // Estimate RSA key bit length from base64 string
  let keyLengthBits = null;
  if (rawKey) {
    try {
      // Base64 chars to bytes roughly: (length * 3) / 4. RSA keys have ASN.1 headers (~24-30 bytes).
      const rawBytes = Math.floor((rawKey.replace(/\s+/g, '').length * 3) / 4);
      if (rawBytes >= 480) keyLengthBits = 4096;
      else if (rawBytes >= 250) keyLengthBits = 2048;
      else if (rawBytes >= 120) keyLengthBits = 1024;
      else keyLengthBits = 512;

      if (keyLengthBits < 1024) {
        warnings.push(`Weak DKIM key size detected (~${keyLengthBits} bits). Insecure against factoring.`);
      } else if (keyLengthBits === 1024) {
        warnings.push(`Legacy DKIM key size detected (~1024 bits). 2048 bits or higher is recommended.`);
      }
    } catch {
      // Key length estimation failed
    }
  } else {
    warnings.push('DKIM record found but contains no public key (p=) tag');
  }

  return {
    selector: cleanSelector,
    domain: normDomain,
    queryHost,
    record: dkimRecord,
    status: 'RECORD_FOUND',
    keyType,
    publicKey: rawKey,
    keyLengthBits,
    isRevoked: false,
    warnings,
    rawRecords: dnsResult.records
  };
}

/**
 * Queries and inspects DMARC policy TXT record at _dmarc.<domain> (RFC 7489).
 * Implements organizational domain fallback if record is missing on a subdomain.
 * 
 * @param {string} domain 
 * @param {Object} [options]
 * @returns {Promise<{
 *   domain: string,
 *   queriedHost: string,
 *   record: string | null,
 *   status: 'RECORD_FOUND' | 'NO_RECORD' | 'PERMERROR' | 'INVALID_DOMAIN' | 'ERROR',
 *   policy: 'none' | 'quarantine' | 'reject' | 'unknown',
 *   subdomainPolicy: 'none' | 'quarantine' | 'reject' | 'inherit',
 *   adkim: 'r' | 's',
 *   aspf: 'r' | 's',
 *   percentage: number,
 *   rua: string[],
 *   ruf: string[],
 *   isOrgDomainFallback: boolean,
 *   warnings: string[],
 *   rawRecords: string[]
 * }>}
 */
export async function queryDmarcRecord(domain, options = {}) {
  const normDomain = normalizeDomain(domain);
  if (!isValidDomain(normDomain)) {
    return {
      domain: normDomain || domain,
      queriedHost: `_dmarc.${normDomain}`,
      record: null,
      status: 'INVALID_DOMAIN',
      policy: 'unknown',
      subdomainPolicy: 'inherit',
      adkim: 'r',
      aspf: 'r',
      percentage: 100,
      rua: [],
      ruf: [],
      isOrgDomainFallback: false,
      warnings: [`Invalid domain: ${domain}`],
      rawRecords: []
    };
  }

  let hostToQuery = `_dmarc.${normDomain}`;
  let isFallback = false;
  let dnsResult = await resolveTxt(hostToQuery, options);

  let dmarcRecords = (dnsResult.records || []).filter(r => /^v=DMARC1(\s*;|\s*$)/i.test(r.trim()));

  // Subdomain fallback to organizational domain if no DMARC record on subdomain
  if (dmarcRecords.length === 0) {
    const orgDomain = getOrganizationalDomain(normDomain);
    if (orgDomain && orgDomain !== normDomain) {
      hostToQuery = `_dmarc.${orgDomain}`;
      const orgResult = await resolveTxt(hostToQuery, options);
      const orgDmarcRecords = (orgResult.records || []).filter(r => /^v=DMARC1(\s*;|\s*$)/i.test(r.trim()));
      if (orgDmarcRecords.length > 0) {
        dmarcRecords = orgDmarcRecords;
        dnsResult = orgResult;
        isFallback = true;
      }
    }
  }

  // RFC 7489 Section 6.6.3: Multiple DMARC records is a fatal syntax error / permerror
  if (dmarcRecords.length > 1) {
    return {
      domain: normDomain,
      queriedHost: hostToQuery,
      record: dmarcRecords[0],
      status: 'PERMERROR',
      policy: 'unknown',
      subdomainPolicy: 'inherit',
      adkim: 'r',
      aspf: 'r',
      percentage: 100,
      rua: [],
      ruf: [],
      isOrgDomainFallback: isFallback,
      warnings: [`RFC 7489 PermError: Multiple DMARC records found at ${hostToQuery}`],
      rawRecords: dmarcRecords
    };
  }

  if (dmarcRecords.length === 0) {
    return {
      domain: normDomain,
      queriedHost: hostToQuery,
      record: null,
      status: 'NO_RECORD',
      policy: 'unknown',
      subdomainPolicy: 'inherit',
      adkim: 'r',
      aspf: 'r',
      percentage: 100,
      rua: [],
      ruf: [],
      isOrgDomainFallback: isFallback,
      warnings: [`No DMARC record published at ${hostToQuery}`],
      rawRecords: dnsResult.records || []
    };
  }

  const rawDmarc = dmarcRecords[0].trim();
  const tags = {};
  const tagPairs = rawDmarc.split(';');

  for (const pair of tagPairs) {
    const eqIdx = pair.indexOf('=');
    if (eqIdx > 0) {
      const k = pair.slice(0, eqIdx).trim().toLowerCase();
      const v = pair.slice(eqIdx + 1).trim();
      tags[k] = v;
    }
  }

  const warnings = [];

  // Parse policy (p=none|quarantine|reject)
  let policy = 'none';
  if (tags.p) {
    const pVal = tags.p.toLowerCase();
    if (['reject', 'quarantine', 'none'].includes(pVal)) {
      policy = pVal;
    } else {
      warnings.push(`Unknown DMARC policy tag 'p=${tags.p}', defaulting to none`);
    }
  } else {
    warnings.push('DMARC record missing mandatory policy tag p=');
  }

  // Parse subdomain policy (sp=)
  let subdomainPolicy = 'inherit';
  if (tags.sp) {
    const spVal = tags.sp.toLowerCase();
    if (['reject', 'quarantine', 'none'].includes(spVal)) {
      subdomainPolicy = spVal;
    }
  }

  // Parse alignment modes: adkim and aspf (r: relaxed, s: strict; default relaxed)
  const adkim = (tags.adkim && tags.adkim.toLowerCase() === 's') ? 's' : 'r';
  const aspf = (tags.aspf && tags.aspf.toLowerCase() === 's') ? 's' : 'r';

  // Percentage (pct=)
  let percentage = 100;
  if (tags.pct !== undefined) {
    const pctVal = parseInt(tags.pct, 10);
    if (!isNaN(pctVal) && pctVal >= 0 && pctVal <= 100) {
      percentage = pctVal;
      if (percentage < 100) {
        warnings.push(`DMARC policy percentage is restricted to ${percentage}%, partial enforcement active.`);
      }
    }
  }

  // Reporting URIs
  const rua = tags.rua ? tags.rua.split(',').map(u => u.trim()).filter(Boolean) : [];
  const ruf = tags.ruf ? tags.ruf.split(',').map(u => u.trim()).filter(Boolean) : [];

  if (policy === 'none') {
    warnings.push('DMARC policy is set to `p=none` (Monitoring Only); unauthorized senders are not blocked.');
  }

  return {
    domain: normDomain,
    queriedHost: hostToQuery,
    record: rawDmarc,
    status: 'RECORD_FOUND',
    policy,
    subdomainPolicy,
    adkim,
    aspf,
    percentage,
    rua,
    ruf,
    isOrgDomainFallback: isFallback,
    warnings,
    rawRecords: dmarcRecords
  };
}

/**
 * Evaluates RFC 7489 Domain Alignment for SPF and DKIM against the Header From domain.
 * 
 * @param {Object} params
 * @param {string} params.fromDomain 
 * @param {string} params.returnPathDomain 
 * @param {string[]} params.dkimDomains 
 * @param {'r' | 's'} [params.aspf='r']
 * @param {'r' | 's'} [params.adkim='r']
 * @returns {{
 *   spfAligned: boolean,
 *   dkimAligned: boolean,
 *   spfAlignmentMode: 'strict' | 'relaxed',
 *   dkimAlignmentMode: 'strict' | 'relaxed',
 *   fromOrgDomain: string,
 *   returnPathOrgDomain: string,
 *   matchedDkimDomain: string | null,
 *   dmarcAligned: boolean
 * }}
 */
export function analyzeDomainAlignment({
  fromDomain,
  returnPathDomain,
  dkimDomains = [],
  aspf = 'r',
  adkim = 'r'
}) {
  const normFrom = normalizeDomain(fromDomain);
  const normReturnPath = normalizeDomain(returnPathDomain);
  const fromOrg = getOrganizationalDomain(normFrom);
  const returnPathOrg = getOrganizationalDomain(normReturnPath);

  // 1. SPF Alignment Evaluation
  let spfAligned = false;
  if (normFrom && normReturnPath) {
    if (aspf === 's') {
      // Strict: exact domain match
      spfAligned = (normFrom === normReturnPath);
    } else {
      // Relaxed: organizational domain match
      spfAligned = (fromOrg === returnPathOrg);
    }
  }

  // 2. DKIM Alignment Evaluation
  let dkimAligned = false;
  let matchedDkimDomain = null;

  for (const dkimDom of dkimDomains) {
    const normDkim = normalizeDomain(dkimDom);
    if (!normDkim) continue;

    if (adkim === 's') {
      if (normFrom === normDkim) {
        dkimAligned = true;
        matchedDkimDomain = normDkim;
        break;
      }
    } else {
      const dkimOrg = getOrganizationalDomain(normDkim);
      if (fromOrg === dkimOrg) {
        dkimAligned = true;
        matchedDkimDomain = normDkim;
        break;
      }
    }
  }

  return {
    spfAligned,
    dkimAligned,
    spfAlignmentMode: aspf === 's' ? 'strict' : 'relaxed',
    dkimAlignmentMode: adkim === 's' ? 'strict' : 'relaxed',
    fromOrgDomain: fromOrg,
    returnPathOrgDomain: returnPathOrg,
    matchedDkimDomain,
    dmarcAligned: spfAligned || dkimAligned
  };
}

/**
 * End-to-end Live Email Authentication Forensic Analysis.
 * 
 * Pipeline:
 * Ingest Email -> Header Extraction -> Authentication-Results Parser ->
 * DNS Forensics (SPF, DKIM, DMARC) -> Domain Alignment ->
 * Evidence Synthesis (Observed vs Inferred) -> Risk Assessment.
 * 
 * @param {string} rawEmail 
 * @param {Object} [options]
 * @param {Function} [options.dnsResolver]
 * @returns {Promise<Object>}
 */
export async function analyzeEmailAuthentication(rawEmail, options = {}) {
  if (!rawEmail || typeof rawEmail !== 'string') {
    return {
      success: false,
      status: 'EMPTY_INPUT',
      error: 'No email content provided',
      observedEvidence: { headers: {}, mtaAuthentication: {}, dnsForensics: {}, items: [] },
      inferredEvidence: { alignment: {}, findings: [], items: [] },
      observedEvidenceList: [],
      inferredEvidenceList: [],
      riskSignals: [],
      summary: {
        spfStatus: 'UNCHECKED',
        dkimStatus: 'NO SIGNATURE',
        dmarcStatus: 'NO_POLICY',
        alignmentResult: 'MISALIGNED',
        authRiskScore: 0
      }
    };
  }

  // 1. Ingest and extract headers
  const headers = extractRawHeaders(rawEmail);

  const rawFrom = headers.from ? headers.from[0] : '';
  const parsedFrom = parseAddress(rawFrom);

  const rawReturnPath = headers['return-path'] ? headers['return-path'][0] : '';
  const parsedReturnPath = parseAddress(rawReturnPath);

  const rawReplyTo = headers['reply-to'] ? headers['reply-to'][0] : '';
  const parsedReplyTo = parseAddress(rawReplyTo);

  const rawSender = headers.sender ? headers.sender[0] : '';
  const parsedSender = parseAddress(rawSender);

  // 2. Parse MTA Observed Headers
  const authResults = parseAuthenticationResults(headers['authentication-results'] || []);
  const receivedSpfHeader = headers['received-spf'] ? parseReceivedSpf(headers['received-spf'][0]) : null;

  // Extract DKIM signatures from headers
  const dkimSignatures = (headers['dkim-signature'] || [])
    .map(parseDkimSignature)
    .filter(Boolean);

  // Determine domains for DNS lookup
  const fromDomain = parsedFrom.domain;
  const returnPathDomain = parsedReturnPath.domain || (authResults.spf ? normalizeDomain(authResults.spf.mailfrom.split('@')[1] || '') : '');

  // Selectors from DKIM signatures or Authentication-Results
  const dkimLookups = [];
  for (const sig of dkimSignatures) {
    if (sig.selector && sig.domain) {
      dkimLookups.push({ selector: sig.selector, domain: sig.domain, fromSignature: true });
    }
  }
  for (const arDkim of authResults.dkim) {
    if (arDkim.selector && arDkim.domain) {
      const alreadyIncluded = dkimLookups.some(l => l.selector === arDkim.selector && l.domain === arDkim.domain);
      if (!alreadyIncluded) {
        dkimLookups.push({ selector: arDkim.selector, domain: arDkim.domain, fromSignature: false });
      }
    }
  }

  // 3. DNS Forensics Resolution
  // Query SPF for Return-Path domain (RFC 7208) or From domain as fallback
  const spfDomainToQuery = returnPathDomain || fromDomain;
  let spfDns = null;
  if (spfDomainToQuery) {
    spfDns = await querySpfRecord(spfDomainToQuery, { resolver: options.dnsResolver });
  }

  // Query DKIM keys
  const dkimDnsResults = [];
  for (const target of dkimLookups) {
    const res = await queryDkimRecord(target.selector, target.domain, { resolver: options.dnsResolver });
    dkimDnsResults.push(res);
  }

  // Query DMARC record for From domain (RFC 7489)
  let dmarcDns = null;
  if (fromDomain) {
    dmarcDns = await queryDmarcRecord(fromDomain, { resolver: options.dnsResolver });
  }

  // 4. Domain Alignment Analysis
  const dkimDomains = [
    ...dkimSignatures.map(s => s.domain),
    ...authResults.dkim.map(d => d.domain)
  ];

  const alignment = analyzeDomainAlignment({
    fromDomain,
    returnPathDomain,
    dkimDomains,
    aspf: dmarcDns ? dmarcDns.aspf : 'r',
    adkim: dmarcDns ? dmarcDns.adkim : 'r'
  });

  // 5. Build OBSERVED EVIDENCE (Headers & Raw DNS Records)
  // Strictly what was parsed from the email and DNS; NEVER inferred
  const observedSpfVerdict = authResults.spf ? authResults.spf.verdict : (receivedSpfHeader ? receivedSpfHeader.verdict : 'none');
  const observedDkimVerdict = authResults.dkim.length > 0 ? (authResults.dkim.some(d => d.verdict === 'pass') ? 'pass' : authResults.dkim[0].verdict) : 'none';
  const observedDmarcVerdict = authResults.dmarc ? authResults.dmarc.verdict : 'none';

  const observedEvidence = {
    headers: {
      from: parsedFrom,
      returnPath: parsedReturnPath,
      replyTo: parsedReplyTo,
      sender: parsedSender,
      messageId: headers['message-id'] ? headers['message-id'][0] : null,
      subject: headers.subject ? headers.subject[0] : null,
      date: headers.date ? headers.date[0] : null
    },
    mtaAuthentication: {
      authservId: authResults.authservId,
      spf: authResults.spf,
      receivedSpf: receivedSpfHeader,
      dkim: authResults.dkim,
      dmarc: authResults.dmarc,
      observedSpfVerdict,
      observedDkimVerdict,
      observedDmarcVerdict
    },
    dkimSignatures,
    dnsForensics: {
      spf: spfDns ? {
        domain: spfDns.domain,
        record: spfDns.record,
        status: spfDns.status,
        mechanisms: spfDns.mechanisms,
        hasPlusAll: spfDns.hasPlusAll,
        warnings: spfDns.warnings
      } : null,
      dkim: dkimDnsResults.map(d => ({
        selector: d.selector,
        domain: d.domain,
        queryHost: d.queryHost,
        record: d.record,
        status: d.status,
        keyLengthBits: d.keyLengthBits,
        isRevoked: d.isRevoked,
        warnings: d.warnings
      })),
      dmarc: dmarcDns ? {
        domain: dmarcDns.domain,
        queriedHost: dmarcDns.queriedHost,
        record: dmarcDns.record,
        status: dmarcDns.status,
        policy: dmarcDns.policy,
        subdomainPolicy: dmarcDns.subdomainPolicy,
        adkim: dmarcDns.adkim,
        aspf: dmarcDns.aspf,
        percentage: dmarcDns.percentage,
        isOrgDomainFallback: dmarcDns.isOrgDomainFallback,
        warnings: dmarcDns.warnings
      } : null
    }
  };

  // 6. Build INFERRED EVIDENCE (Alignment, Spoofing Risk, Synthesized DMARC)
  // Strict separation: computed by MAVERICK logic based on observed evidence
  const inferredFindings = [];
  let authRiskScore = 0; // 0 (Clean) to 100 (Extremely Malicious/Spoofed)

  // A. Check Display Name Spoofing
  let displayNameSpoofingDetected = false;
  if (parsedFrom.displayName && parsedFrom.domain) {
    // Look for brand name or domain patterns in display name
    const brandPatterns = ['paypal', 'microsoft', 'google', 'apple', 'amazon', 'bank', 'support', 'security', 'billing', 'admin'];
    const lowerDisplay = parsedFrom.displayName.toLowerCase();
    const hasBrandInDisplay = brandPatterns.some(b => lowerDisplay.includes(b));
    const domainMatchesBrand = brandPatterns.some(b => lowerDisplay.includes(b) && parsedFrom.domain.includes(b));

    // Check if display name looks like an email address from a different domain
    const emailInDisplayMatch = parsedFrom.displayName.match(/([a-zA-Z0-9._%+-]+@([a-zA-Z0-9.-]+\.[a-zA-Z]{2,}))/);
    if (emailInDisplayMatch) {
      const displayDomain = normalizeDomain(emailInDisplayMatch[2]);
      if (displayDomain !== parsedFrom.domain) {
        displayNameSpoofingDetected = true;
        authRiskScore += 35;
        inferredFindings.push(`CRITICAL: Display name contains email address from '${displayDomain}' but sender domain is '${parsedFrom.domain}'`);
      }
    } else if (hasBrandInDisplay && !domainMatchesBrand) {
      authRiskScore += 20;
      inferredFindings.push(`SUSPICIOUS: Display Name '${parsedFrom.displayName}' contains trusted brand indicators not matching domain '${parsedFrom.domain}'`);
    }
  }

  // B. Reply-To Mismatch
  let replyToMismatch = false;
  if (parsedReplyTo.domain && parsedFrom.domain && parsedReplyTo.domain !== parsedFrom.domain) {
    replyToMismatch = true;
    authRiskScore += 25;
    inferredFindings.push(`Reply-To address domain (${parsedReplyTo.domain}) does not match From domain (${parsedFrom.domain})`);
  }

  // C. SPF Alignment & Record Analysis
  if (spfDns) {
    if (spfDns.hasPlusAll) {
      authRiskScore += 30;
      inferredFindings.push(`SPF record for ${spfDns.domain} contains '+all', allowing unrestricted spoofing.`);
    } else if (spfDns.status === 'NO_RECORD') {
      authRiskScore += 15;
      inferredFindings.push(`No SPF record published for ${spfDns.domain}.`);
    } else if (spfDns.status === 'PERMERROR') {
      authRiskScore += 20;
      inferredFindings.push(`SPF PermError: Multiple conflicting SPF records found.`);
    }

    if (!alignment.spfAligned && returnPathDomain) {
      authRiskScore += 15;
      inferredFindings.push(`SPF domain alignment failed: Return-Path (${returnPathDomain}) does not align with From (${fromDomain}).`);
    }
  }

  // D. DKIM Public Key & Signature Analysis
  if (dkimSignatures.length > 0) {
    if (!alignment.dkimAligned) {
      authRiskScore += 15;
      inferredFindings.push(`DKIM domain alignment failed: Signing domains [${dkimDomains.join(', ')}] do not align with From (${fromDomain}).`);
    }
  } else if (authResults.dkim.length === 0) {
    inferredFindings.push('Email contains no DKIM cryptographic signature header.');
  }

  for (const dkimDns of dkimDnsResults) {
    if (dkimDns.isRevoked) {
      authRiskScore += 30;
      inferredFindings.push(`DKIM public key for selector '${dkimDns.selector}' is revoked.`);
    } else if (dkimDns.status === 'NO_RECORD') {
      authRiskScore += 15;
      inferredFindings.push(`DKIM public key record not found for selector '${dkimDns.selector}' at ${dkimDns.queryHost}.`);
    }
  }

  // E. DMARC Evaluation & Enforcement
  let dmarcEffectiveStatus = 'PASS';
  if (!dmarcDns || dmarcDns.status === 'NO_RECORD') {
    dmarcEffectiveStatus = 'NO_POLICY';
    authRiskScore += 10;
    inferredFindings.push(`No DMARC policy published for ${fromDomain}; domain is vulnerable to spoofing.`);
  } else if (dmarcDns.status === 'PERMERROR') {
    dmarcEffectiveStatus = 'PERMERROR';
    authRiskScore += 20;
    inferredFindings.push(`DMARC PermError: Multiple DMARC policies detected.`);
  } else {
    // Under RFC 7489, DMARC passes if:
    // (SPF passes MTA auth AND SPF aligns) OR (DKIM passes MTA auth AND DKIM aligns)
    const spfDmarcPass = (observedSpfVerdict === 'pass' && alignment.spfAligned);
    const dkimDmarcPass = (observedDkimVerdict === 'pass' && alignment.dkimAligned);

    if (spfDmarcPass || dkimDmarcPass) {
      dmarcEffectiveStatus = 'PASS';
    } else {
      dmarcEffectiveStatus = 'FAIL';
      // DMARC Fail risk depends on policy
      if (dmarcDns.policy === 'reject') {
        authRiskScore += 45;
        inferredFindings.push(`DMARC FAIL with 'p=reject': Email failed both SPF and DKIM alignment for ${fromDomain}. Should be rejected.`);
      } else if (dmarcDns.policy === 'quarantine') {
        authRiskScore += 35;
        inferredFindings.push(`DMARC FAIL with 'p=quarantine': Email failed alignment for ${fromDomain}.`);
      } else {
        authRiskScore += 25;
        inferredFindings.push(`DMARC FAIL with 'p=none': Domain has no enforcement, but alignment failed.`);
      }
    }
  }

  // Cap auth risk score at 100
  authRiskScore = Math.min(100, Math.max(0, authRiskScore));

  // Compile structured list for Observed Evidence
  const observedEvidenceList = [
    `From: ${parsedFrom.raw || 'None'}`,
    `Return-Path: ${parsedReturnPath.raw || 'None'}`,
    ...(parsedReplyTo.raw ? [`Reply-To: ${parsedReplyTo.raw}`] : []),
    ...(authResults.spf ? [`Authentication-Results: spf=${authResults.spf.verdict}`] : []),
    ...(authResults.dkim.length > 0 ? authResults.dkim.map(d => `Authentication-Results: dkim=${d.verdict}${d.domain ? ` (header.d=${d.domain})` : ''}`) : []),
    ...(authResults.dmarc ? [`Authentication-Results: dmarc=${authResults.dmarc.verdict}${authResults.dmarc.policy ? ` (p=${authResults.dmarc.policy})` : ''}`] : []),
    ...(dkimSignatures.length > 0 ? dkimSignatures.map(s => `DKIM-Signature Header: d=${s.domain}, s=${s.selector}, a=${s.algorithm}`) : []),
    ...(spfDns ? [`SPF DNS Record: ${spfDns.status === 'RECORD_FOUND' ? spfDns.record : spfDns.status} (query: ${spfDns.domain})`] : []),
    ...(dkimDnsResults.length > 0 ? dkimDnsResults.map(d => `DKIM DNS Public Key: ${d.status === 'RECORD_FOUND' ? `RECORD FOUND (~${d.keyLengthBits || 'unknown'} bits)` : d.status} (host: ${d.queryHost})`) : []),
    ...(dmarcDns ? [`DMARC DNS Record: ${dmarcDns.status === 'RECORD_FOUND' ? `${dmarcDns.record} (policy: ${dmarcDns.policy})` : dmarcDns.status} (host: ${dmarcDns.queriedHost})`] : [])
  ];

  // Compile structured list for Inferred Intelligence
  const inferredEvidenceList = [
    `SPF Alignment: ${alignment.spfAligned ? 'ALIGNED' : 'MISALIGNED'} (${alignment.spfAlignmentMode} mode)`,
    `DKIM Alignment: ${alignment.dkimAligned ? 'ALIGNED' : 'MISALIGNED'} (${alignment.dkimAlignmentMode} mode)`,
    `DMARC Alignment: ${alignment.dmarcAligned ? 'ALIGNED (SPF or DKIM)' : 'MISALIGNED'} (Effective status: ${dmarcEffectiveStatus})`,
    ...inferredFindings
  ];

  const observedEvidenceWithItems = {
    ...observedEvidence,
    items: observedEvidenceList
  };

  const inferredEvidenceWithItems = {
    alignment,
    displayNameSpoofingDetected,
    replyToMismatch,
    dmarcEffectiveStatus,
    authRiskScore,
    findings: inferredFindings,
    items: inferredEvidenceList
  };

  const primaryDkimResult = dkimDnsResults[0] || null;
  const primaryDkimSig = dkimSignatures[0] || null;

  return {
    success: true,
    status: 'COMPLETE',
    fromDomain,
    returnPathDomain,

    authenticationResults: {
      spf: observedSpfVerdict,
      dkim: observedDkimVerdict,
      dmarc: observedDmarcVerdict,
      details: authResults
    },

    spf: {
      status: spfDns?.status === 'RECORD_FOUND' ? 'RECORD_FOUND' : (spfDns?.status || 'NO_RECORD'),
      displayStatus: spfDns?.status === 'RECORD_FOUND' ? 'SPF RECORD FOUND' : (spfDns?.status || 'NO RECORD'),
      domain: spfDomainToQuery,
      record: spfDns?.record || null,
      source: 'DNS',
      mechanisms: spfDns?.mechanisms || [],
      hasPlusAll: spfDns?.hasPlusAll || false,
      warnings: spfDns?.warnings || [],
      observedVerdict: observedSpfVerdict
    },

    dkim: {
      status: dkimDnsResults.length > 0 ? (dkimDnsResults.some(d => d.status === 'RECORD_FOUND') ? 'RECORD_FOUND' : dkimDnsResults[0].status) : 'NO_SIGNATURE',
      displayStatus: dkimDnsResults.length > 0 ? (dkimDnsResults.some(d => d.status === 'RECORD_FOUND') ? 'DKIM PUBLIC KEY FOUND' : dkimDnsResults[0].status) : 'NO SIGNATURE',
      domain: primaryDkimSig?.domain || primaryDkimResult?.domain || fromDomain,
      selector: primaryDkimSig?.selector || primaryDkimResult?.selector || '',
      dnsRecordFound: dkimDnsResults.some(d => d.status === 'RECORD_FOUND'),
      records: dkimDnsResults,
      algorithm: primaryDkimSig?.algorithm || 'rsa-sha256',
      canonicalization: primaryDkimSig?.canonicalization || 'simple/simple',
      observedVerdict: observedDkimVerdict
    },

    dmarc: {
      status: dmarcDns?.status === 'RECORD_FOUND' ? 'RECORD_FOUND' : (dmarcDns?.status || 'NO_RECORD'),
      displayStatus: dmarcDns?.status === 'RECORD_FOUND' ? 'DMARC RECORD FOUND' : (dmarcDns?.status || 'NO RECORD'),
      domain: fromDomain,
      policy: dmarcDns?.policy || 'unknown',
      subdomainPolicy: dmarcDns?.subdomainPolicy || 'inherit',
      adkim: dmarcDns?.adkim || 'r',
      aspf: dmarcDns?.aspf || 'r',
      percentage: dmarcDns?.percentage ?? 100,
      alignment: {
        spf: alignment.spfAligned,
        dkim: alignment.dkimAligned,
        dmarc: alignment.dmarcAligned
      },
      record: dmarcDns?.record || null,
      warnings: dmarcDns?.warnings || [],
      observedVerdict: observedDmarcVerdict
    },

    alignment: {
      spf: alignment.spfAligned ? 'ALIGNED' : 'MISALIGNED',
      dkim: alignment.dkimAligned ? 'ALIGNED' : 'MISALIGNED',
      dmarc: alignment.dmarcAligned ? 'PASS' : 'FAIL',
      spfAligned: alignment.spfAligned,
      dkimAligned: alignment.dkimAligned,
      dmarcAligned: alignment.dmarcAligned,
      details: alignment
    },

    observedEvidence: observedEvidenceWithItems,
    inferredEvidence: inferredEvidenceWithItems,
    observedEvidenceList,
    inferredEvidenceList,
    riskSignals: inferredFindings,

    summary: {
      spfStatus: spfDns ? (spfDns.status === 'RECORD_FOUND' ? 'SPF RECORD FOUND' : spfDns.status) : 'UNCHECKED',
      dkimStatus: dkimDnsResults.length > 0 ? (dkimDnsResults.some(d => d.status === 'RECORD_FOUND') ? 'DKIM PUBLIC KEY FOUND' : dkimDnsResults[0].status) : 'NO SIGNATURE',
      dmarcStatus: dmarcDns ? (dmarcDns.status === 'RECORD_FOUND' ? `DMARC RECORD FOUND (${dmarcDns.policy.toUpperCase()})` : dmarcDns.status) : 'NO_POLICY',
      alignmentResult: alignment.dmarcAligned ? 'ALIGNED' : 'MISALIGNED',
      authRiskScore
    }
  };
}
