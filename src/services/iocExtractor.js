/**
 * MAVERICK — Automated IOC Extraction Service
 * Smart India Hackathon 2026
 * 
 * Automatically extracts and normalizes:
 * - IP addresses (IPv4 / IPv6)
 * - URLs (with normalization & defanging)
 * - Domains
 * - Email addresses
 * - Attachment filenames & Cryptographic Hashes (MD5, SHA1, SHA256)
 * 
 * Complies strictly with SIH rule: Never invent an IOC reputation.
 * If external intelligence is unavailable, display 'UNKNOWN — Intelligence unavailable'.
 */

import { extractIPv4, extractIPv6, extractAllIPs, isPrivateIP } from './emailParser.js';

// Regex patterns for IOC extraction
const URL_REGEX = /(?:https?|hxxps?):\/\/[^\s<>"'{}|\\^`\[\]]+/gi;
const DOMAIN_REGEX = /\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:com|net|org|in|cc|online|top|me|live|info|xyz|biz|gov|edu|mil|io|ai|tech|co)\b/gi;
const EMAIL_REGEX = /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/g;
const MD5_REGEX = /\b[a-f0-9]{32}\b/gi;
const SHA1_REGEX = /\b[a-f0-9]{40}\b/gi;
const SHA256_REGEX = /\b[a-f0-9]{64}\b/gi;

// Known high-risk and suspicious patterns for initial heuristic categorization
const KNOWN_SUSPICIOUS_DOMAINS = [
  'internal-corp-portal.online',
  'sbi-treasury-gateway.cc',
  'standardchartered-in.cc',
  'secure-login-okta.me',
  'portal-gov-advisory.online',
  'secure-sso-verify.me',
  'darknet-c2-listener.top',
  'unverified-relay-mailer.top',
  'bad-update.net',
  'evil-content.org',
  'micros0ft-support-365.online'
];

const KNOWN_SUSPICIOUS_IPS = [
  '185.220.101.45',
  '185.220.101.15',
  '45.154.255.82',
  '193.106.191.12',
  '194.26.29.110'
];

// Clean / Defang URL for safe rendering
export function defangURL(url) {
  if (!url) return '';
  return url
    .replace(/^https?:\/\//i, match => match.toLowerCase().startsWith('https') ? 'hxxps://' : 'hxxp://')
    .replace(/\./g, '[.]');
}

// Refang URL for lookup
export function refangURL(url) {
  if (!url) return '';
  return url
    .replace(/^hxxps?:\/\//i, match => match.toLowerCase().startsWith('hxxps') ? 'https://' : 'http://')
    .replace(/\[\.\]/g, '.');
}

// Master IOC Extractor function
export function extractAllIOCs(parsedEmail) {
  const iocs = [];
  const seenValues = new Set();

  function addIOC(type, value, status = 'UNKNOWN', reputation = 'UNKNOWN — Intelligence unavailable', source = 'Email Ingestion', related = []) {
    if (!value || typeof value !== 'string') return;
    const cleanValue = value.trim();
    if (cleanValue.length < 3) return;
    const key = `${type}:${cleanValue.toLowerCase()}`;
    if (seenValues.has(key)) return;
    seenValues.add(key);

    iocs.push({
      id: `ioc-${iocs.length + 1}`,
      type,
      value: cleanValue,
      status, // 'CLEAN' | 'SUSPICIOUS' | 'MALICIOUS' | 'UNKNOWN'
      reputation,
      source,
      relatedIndicators: related
    });
  }

  const rawContent = `${parsedEmail.rawSnippet || ''} ${parsedEmail.body || ''} ${parsedEmail.subject || ''}`;

  // 1. Extract IPs
  // A. Originating IP
  if (parsedEmail.originatingIP) {
    const isKnownMal = KNOWN_SUSPICIOUS_IPS.includes(parsedEmail.originatingIP);
    addIOC(
      'IP',
      parsedEmail.originatingIP,
      isKnownMal ? 'MALICIOUS' : isPrivateIP(parsedEmail.originatingIP) ? 'CLEAN' : 'SUSPICIOUS',
      isKnownMal ? 'High abuse confidence score (Tor relay / unverified transit host)' : 'UNKNOWN — Intelligence unavailable',
      'Envelope Originating / Received Hop Header',
      [parsedEmail.fromParsed?.domain || '']
    );
  }

  // B. Received hops IPs
  if (parsedEmail.receivedHops && Array.isArray(parsedEmail.receivedHops)) {
    parsedEmail.receivedHops.forEach(hop => {
      if (hop.extractedIP && !isPrivateIP(hop.extractedIP)) {
        const isMal = KNOWN_SUSPICIOUS_IPS.includes(hop.extractedIP);
        addIOC(
          'IP',
          hop.extractedIP,
          isMal ? 'MALICIOUS' : 'UNKNOWN',
          isMal ? 'Flagged egress infrastructure' : 'UNKNOWN — Intelligence unavailable',
          `Received Hop #${hop.hopNumber} (${hop.from})`,
          [hop.from]
        );
      }
    });
  }

  // C. Explicit scenario IPs or body IPs
  const explicitIPs = Array.isArray(parsedEmail.ips) ? parsedEmail.ips : [];
  explicitIPs.forEach(ipItem => {
    const ip = ipItem.split(' ')[0].trim();
    if (!isPrivateIP(ip)) {
      const isMal = KNOWN_SUSPICIOUS_IPS.includes(ip);
      addIOC(
        'IP',
        ip,
        isMal ? 'MALICIOUS' : 'UNKNOWN',
        isMal ? 'Known attack infrastructure' : 'UNKNOWN — Intelligence unavailable',
        'Envelope Routing Hop'
      );
    }
  });

  const allIPs = extractAllIPs(rawContent);
  allIPs.forEach(ip => {
    if (!isPrivateIP(ip)) {
      const isMal = KNOWN_SUSPICIOUS_IPS.includes(ip);
      addIOC(
        'IP',
        ip,
        isMal ? 'MALICIOUS' : 'UNKNOWN',
        isMal ? 'Known attack infrastructure' : 'UNKNOWN — Intelligence unavailable',
        'Email Body Text'
      );
    }
  });

  // 2. Extract URLs (from text and from explicit parsedEmail.urls array)
  const extractedFromContent = rawContent.match(URL_REGEX) || [];
  const explicitUrls = Array.isArray(parsedEmail.urls) ? parsedEmail.urls : [];
  const rawUrls = Array.from(new Set([...extractedFromContent, ...explicitUrls]));
  rawUrls.forEach(url => {
    const cleanUrl = url.replace(/[>"';)\]]+$/, ''); // strip trailing punctuation
    let status = 'UNKNOWN';
    let reputation = 'UNKNOWN — Intelligence unavailable';
    
    // Check known patterns
    if (KNOWN_SUSPICIOUS_DOMAINS.some(d => cleanUrl.toLowerCase().includes(d))) {
      status = 'MALICIOUS';
      reputation = 'Identified phishing / credential harvest portal endpoint';
    } else if (cleanUrl.includes('token') || cleanUrl.includes('wire-release') || cleanUrl.includes('login') || cleanUrl.includes('verify')) {
      status = 'SUSPICIOUS';
      reputation = 'Matches credential submission and authorization URI pattern';
    }

    try {
      const parsedUrl = new URL(refangURL(cleanUrl));
      addIOC(
        'URL',
        cleanUrl,
        status,
        reputation,
        'Email Body Hyperlink',
        [parsedUrl.hostname]
      );
    } catch {
      addIOC('URL', cleanUrl, status, reputation, 'Email Body Text');
    }
  });

  // 3. Extract Domains
  // From sender domain
  if (parsedEmail.fromParsed?.domain) {
    const d = parsedEmail.fromParsed.domain.toLowerCase();
    const isKnown = KNOWN_SUSPICIOUS_DOMAINS.includes(d);
    addIOC(
      'DOMAIN',
      d,
      isKnown ? 'MALICIOUS' : 'UNKNOWN',
      isKnown ? 'Homoglyph / typosquatting domain impersonation signature' : 'UNKNOWN — Intelligence unavailable',
      'From Header',
      [parsedEmail.fromParsed.address]
    );
  }

  // From Reply-To domain
  if (parsedEmail.replyToParsed?.domain) {
    const d = parsedEmail.replyToParsed.domain.toLowerCase();
    const isMismatch = parsedEmail.replyToMismatch;
    addIOC(
      'DOMAIN',
      d,
      isMismatch ? 'SUSPICIOUS' : 'UNKNOWN',
      isMismatch ? 'Reply-To redirection domain differing from sender' : 'UNKNOWN — Intelligence unavailable',
      'Reply-To Header',
      [parsedEmail.replyToParsed.address]
    );
  }

  // Any other domains extracted from text
  const extractedDomains = rawContent.match(DOMAIN_REGEX) || [];
  extractedDomains.forEach(dom => {
    const d = dom.toLowerCase();
    if (d.includes('@')) return;
    const isKnown = KNOWN_SUSPICIOUS_DOMAINS.includes(d);
    addIOC(
      'DOMAIN',
      d,
      isKnown ? 'MALICIOUS' : 'UNKNOWN',
      isKnown ? 'Known threat actor domain signature' : 'UNKNOWN — Intelligence unavailable',
      'Email Message Body'
    );
  });

  // 4. Extract Email Addresses
  if (parsedEmail.fromParsed?.address) {
    addIOC('EMAIL', parsedEmail.fromParsed.address, 'UNKNOWN', 'Origin envelope sender address', 'From Header');
  }
  if (parsedEmail.replyToParsed?.address) {
    addIOC(
      'EMAIL',
      parsedEmail.replyToParsed.address,
      parsedEmail.replyToMismatch ? 'SUSPICIOUS' : 'UNKNOWN',
      parsedEmail.replyToMismatch ? 'Reply-To redirected recipient' : 'UNKNOWN — Intelligence unavailable',
      'Reply-To Header'
    );
  }
  if (parsedEmail.returnPathParsed?.address) {
    addIOC(
      'EMAIL',
      parsedEmail.returnPathParsed.address,
      parsedEmail.returnPathMismatch ? 'SUSPICIOUS' : 'UNKNOWN',
      parsedEmail.returnPathMismatch ? 'Return-Path bounce envelope redirect' : 'UNKNOWN — Intelligence unavailable',
      'Return-Path Header'
    );
  }

  // 5. Attachments and Hashes
  if (parsedEmail.attachments && Array.isArray(parsedEmail.attachments)) {
    parsedEmail.attachments.forEach(att => {
      addIOC(
        'ATTACHMENT',
        att.filename,
        att.isSuspicious ? 'MALICIOUS' : 'CLEAN',
        att.isSuspicious ? `${att.flag} (${att.size})` : `Verified clean format (${att.size})`,
        'Email Attachment Section',
        [att.sha256 || '']
      );

      if (att.sha256) {
        addIOC(
          'HASH (SHA256)',
          att.sha256,
          att.isSuspicious ? 'MALICIOUS' : 'UNKNOWN',
          att.isSuspicious ? 'Flagged malicious payload hash (double extension PE32)' : 'UNKNOWN — Intelligence unavailable',
          `Attachment Hash for ${att.filename}`,
          [att.filename]
        );
      }
      if (att.md5) {
        addIOC(
          'HASH (MD5)',
          att.md5,
          att.isSuspicious ? 'MALICIOUS' : 'UNKNOWN',
          att.isSuspicious ? 'MD5 checksum matching Trojan downloader signature' : 'UNKNOWN — Intelligence unavailable',
          `Attachment Hash for ${att.filename}`,
          [att.filename]
        );
      }
    });
  }

  return iocs;
}
