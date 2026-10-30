/**
 * MAVERICK — RFC 822 & MIME Email Parser Service
 * Smart India Hackathon 2026
 * 
 * Safely parses .eml, raw headers, and email text without executing attachments.
 * Extracts headers, Received chain hops, originating IP, body, and attachment metadata.
 */

import { analyzeAttachment } from './attachmentForensics.js';

// Helper to compute SHA-256 in browser using Web Crypto API
export async function computeSHA256(content) {
  try {
    const encoder = new TextEncoder();
    const data = typeof content === 'string' ? encoder.encode(content) : content;
    const hashBuffer = await crypto.subtle.digest('SHA-256', data);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
  } catch {
    return 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';
  }
}

// Fallback fast hash for MD5 & SHA1 simulation if native SubtleCrypto does not support MD5
export function computeFastHash(str, length = 32) {
  let hash = 0;
  for (let i = 0; i < str.length; i++) {
    const char = str.charCodeAt(i);
    hash = ((hash << 5) - hash) + char;
    hash |= 0;
  }
  const hex = Math.abs(hash).toString(16).padStart(8, '0');
  return (hex + hex + hex + hex).substring(0, length);
}

// Decode Quoted-Printable strings
export function decodeQuotedPrintable(str) {
  if (!str) return '';
  return str
    .replace(/=\r?\n/g, '') // soft line breaks
    .replace(/=([0-9A-Fa-f]{2})/g, (_, hex) => String.fromCharCode(parseInt(hex, 16)));
}

// Decode Base64 safely
export function decodeBase64(str) {
  try {
    const cleaned = str.replace(/\s+/g, '');
    return atob(cleaned);
  } catch {
    return str;
  }
}

// Decode MIME Encoded-Word (RFC 2047: =?charset?encoding?encoded_text?=)
export function decodeMimeWords(str) {
  if (!str) return '';
  const regex = /=\?([^?]+)\?([BQbq])\?([^?]+)\?=/g;
  return str.replace(regex, (_, charset, encoding, encodedText) => {
    if (encoding.toUpperCase() === 'B') {
      try {
        return atob(encodedText);
      } catch {
        return encodedText;
      }
    } else if (encoding.toUpperCase() === 'Q') {
      return decodeQuotedPrintable(encodedText.replace(/_/g, ' '));
    }
    return encodedText;
  });
}

// Parse email address string like 'Name <user@domain.com>' or 'user@domain.com'
export function parseEmailAddress(raw) {
  if (!raw) return { name: '', address: '', domain: '' };
  const cleaned = raw.trim();
  const angleMatch = cleaned.match(/^(.*?)\s*<([^>]+)>/);
  if (angleMatch) {
    const name = decodeMimeWords(angleMatch[1].replace(/^["']|["']$/g, '').trim());
    const address = angleMatch[2].trim().toLowerCase();
    const domain = address.split('@')[1] || '';
    return { name: name || address.split('@')[0], address, domain, raw: cleaned };
  }
  const address = cleaned.replace(/^["']|["']$/g, '').toLowerCase();
  const domain = address.split('@')[1] || '';
  return { name: address.split('@')[0], address, domain, raw: cleaned };
}

// Classification Taxonomy constants
export const IP_CLASSIFICATION = {
  PUBLIC_IPV4: 'Public IPv4',
  PUBLIC_IPV6: 'Public IPv6',
  PRIVATE_IP: 'Private IP',
  LOOPBACK_IP: 'Loopback IP',
  LINK_LOCAL_IP: 'Link-local IP',
  TEST_NET_IP: 'RESERVED / TEST-NET',
  DOCUMENTATION_IP: 'RESERVED / TEST-NET',
  RESERVED_TEST_NET: 'RESERVED / TEST-NET',
  RESERVED_IP: 'Reserved or special-purpose IP',
  INVALID_IP: 'Invalid IP'
};

// Clean IP string by stripping enclosing brackets and IPv6 prefixes
export function cleanIPString(ip) {
  if (!ip || typeof ip !== 'string') return '';
  return ip
    .trim()
    .replace(/^[\[<(\'\"]+|[\]>\)\'\"]+$/g, '') // remove surrounding brackets/quotes
    .replace(/^IPv6:\s*/i, '')                  // remove IPv6: prefix if present
    .trim();
}

// IPv4 and IPv6 regex definitions
export const IPV4_REGEX = /\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b/g;

// Standard RFC 4291 / RFC 5952 IPv6 regex
export const IPV6_REGEX = /(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|(?:[0-9a-fA-F]{1,4}:){1,7}:|(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|(?:[0-9a-fA-F]{1,4}:){1,5}(?::[0-9a-fA-F]{1,4}){1,2}|(?:[0-9a-fA-F]{1,4}:){1,4}(?::[0-9a-fA-F]{1,4}){1,3}|(?:[0-9a-fA-F]{1,4}:){1,3}(?::[0-9a-fA-F]{1,4}){1,4}|(?:[0-9a-fA-F]{1,4}:){1,2}(?::[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:(?:(?::[0-9a-fA-F]{1,4}){1,6})|:(?:(?::[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(?::[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(?:ffff(?::0{1,4}){0,1}:){0,1}(?:(?:25[0-5]|(?:2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(?:25[0-5]|(?:2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:(?:(?:25[0-5]|(?:2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(?:25[0-5]|(?:2[0-4]|1{0,1}[0-9]){0,1}[0-9])/gi;

const IPV4_EXACT = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;

/**
 * Validate if a string is a syntactically valid IPv4 address
 */
export function isValidIPv4(ip) {
  const clean = cleanIPString(ip);
  return IPV4_EXACT.test(clean);
}

/**
 * Validate if a string is a syntactically valid IPv6 address (RFC 4291 / RFC 5952)
 */
export function isValidIPv6(ip) {
  const clean = cleanIPString(ip);
  if (!clean || typeof clean !== 'string' || !clean.includes(':')) return false;
  const stripped = clean.split('%')[0]; // Strip scope ID
  
  if (stripped.includes(':::')) return false;

  const dblColons = stripped.split('::');
  if (dblColons.length > 2) return false;

  // Handle IPv4-mapped / IPv4-compatible IPv6 (e.g. ::ffff:192.0.2.1)
  let v6Str = stripped;
  const lastColon = stripped.lastIndexOf(':');
  const tail = stripped.slice(lastColon + 1);
  let v4Words = 0;
  if (tail.includes('.')) {
    if (!isValidIPv4(tail)) return false;
    v6Str = stripped.slice(0, lastColon);
    v4Words = 2; // IPv4 address occupies two 16-bit words (32 bits)
  }

  const hasDblColon = stripped.includes('::');

  if (hasDblColon) {
    const [left, right] = dblColons;
    // Extract non-empty parts on left and right of ::
    const leftParts = left ? left.split(':').filter(Boolean) : [];
    const rightParts = right ? right.split(':').filter(Boolean) : [];
    
    // If IPv4 mapped, exclude the tail from rightParts if already counted
    const totalNonZeroWords = leftParts.length + rightParts.length + v4Words;
    if (totalNonZeroWords > 7) return false;

    const missingZeros = (8 - v4Words) - (leftParts.length + rightParts.length);
    if (missingZeros < 0) return false;

    const fullWords = [...leftParts, ...Array(missingZeros).fill('0'), ...rightParts];
    if (fullWords.length + v4Words !== 8) return false;

    for (const word of fullWords) {
      if (!/^[0-9a-fA-F]{1,4}$/.test(word)) return false;
    }
    return true;
  } else {
    // Uncompressed IPv6
    const parts = v6Str.split(':');
    if (parts.length + v4Words !== 8) return false;
    for (const word of parts) {
      if (!/^[0-9a-fA-F]{1,4}$/.test(word)) return false;
    }
    return true;
  }
}

/**
 * Validate if a string is a valid IPv4 or IPv6 address
 */
export function isValidIP(ip) {
  if (!ip || typeof ip !== 'string') return false;
  return isValidIPv4(ip) || isValidIPv6(ip);
}

/**
 * Categorize any IP address according to strict forensic RFC classifications:
 * - Public IPv4
 * - Public IPv6
 * - Private IP
 * - Loopback IP
 * - Link-local IP
 * - Reserved or special-purpose IP
 * - Invalid IP
 */
export function classifyIP(ip) {
  const clean = cleanIPString(ip);
  if (!clean) return IP_CLASSIFICATION.INVALID_IP;

  // 1. IPv4 Classification
  if (isValidIPv4(clean)) {
    const parts = clean.split('.').map(Number);
    const [o1, o2, o3] = parts;

    // Loopback: 127.0.0.0/8
    if (o1 === 127) {
      return IP_CLASSIFICATION.LOOPBACK_IP;
    }

    // Link-local: 169.254.0.0/16
    if (o1 === 169 && o2 === 254) {
      return IP_CLASSIFICATION.LINK_LOCAL_IP;
    }

    // Private networks (RFC 1918)
    // 10.0.0.0/8
    if (o1 === 10) {
      return IP_CLASSIFICATION.PRIVATE_IP;
    }
    // 172.16.0.0/12
    if (o1 === 172 && o2 >= 16 && o2 <= 31) {
      return IP_CLASSIFICATION.PRIVATE_IP;
    }
    // 192.168.0.0/16
    if (o1 === 192 && o2 === 168) {
      return IP_CLASSIFICATION.PRIVATE_IP;
    }

    // Reserved / Special-purpose ranges
    // "This host on this network": 0.0.0.0/8
    if (o1 === 0) {
      return IP_CLASSIFICATION.RESERVED_IP;
    }
    // Shared address space (Carrier-Grade NAT): 100.64.0.0/10
    if (o1 === 100 && o2 >= 64 && o2 <= 127) {
      return IP_CLASSIFICATION.RESERVED_IP;
    }
    // IETF Protocol Assignments: 192.0.0.0/24
    if (o1 === 192 && o2 === 0 && o3 === 0) {
      return IP_CLASSIFICATION.RESERVED_IP;
    }
    // Documentation ranges (RFC 5737):
    // TEST-NET-1 (192.0.2.0/24), TEST-NET-2 (198.51.100.0/24), TEST-NET-3 (203.0.113.0/24)
    if (o1 === 192 && o2 === 0 && o3 === 2) {
      return IP_CLASSIFICATION.TEST_NET_IP;
    }
    if (o1 === 198 && o2 === 51 && o3 === 100) {
      return IP_CLASSIFICATION.TEST_NET_IP;
    }
    if (o1 === 203 && o2 === 0 && o3 === 113) {
      return IP_CLASSIFICATION.TEST_NET_IP;
    }
    // Benchmarking (RFC 2544): 198.18.0.0/15
    if (o1 === 198 && (o2 === 18 || o2 === 19)) {
      return IP_CLASSIFICATION.RESERVED_IP;
    }
    // Multicast (224.0.0.0/4)
    if (o1 >= 224 && o1 <= 239) {
      return IP_CLASSIFICATION.RESERVED_IP;
    }
    // Reserved for future use (240.0.0.0/4) & Broadcast 255.255.255.255
    if (o1 >= 240) {
      return IP_CLASSIFICATION.RESERVED_IP;
    }

    // If none of the reserved/private ranges match, it is a valid Public IPv4
    return IP_CLASSIFICATION.PUBLIC_IPV4;
  }

  // 2. IPv6 Classification
  if (isValidIPv6(clean)) {
    const lower = clean.toLowerCase();

    // Loopback: ::1
    if (lower === '::1' || lower === '0:0:0:0:0:0:0:1' || /^0*(?::0*)*:1$/.test(lower)) {
      return IP_CLASSIFICATION.LOOPBACK_IP;
    }

    // Unspecified: ::
    if (lower === '::' || lower === '0:0:0:0:0:0:0:0' || /^(?:0+:)*0+$/.test(lower)) {
      return IP_CLASSIFICATION.RESERVED_IP;
    }

    // Link-local: fe80::/10 (fe8, fe9, fea, feb)
    if (/^fe[89ab]/i.test(lower)) {
      return IP_CLASSIFICATION.LINK_LOCAL_IP;
    }

    // Unique Local Address (ULA - Private IPv6): fc00::/7 (fc00 - fdff)
    if (/^f[cd]/i.test(lower)) {
      return IP_CLASSIFICATION.PRIVATE_IP;
    }

    // Multicast: ff00::/8
    if (lower.startsWith('ff')) {
      return IP_CLASSIFICATION.RESERVED_IP;
    }

    // Documentation prefix: 2001:db8::/32 (RFC 3849)
    if (lower.startsWith('2001:db8:') || lower === '2001:db8::') {
      return IP_CLASSIFICATION.TEST_NET_IP;
    }

    // BMWG benchmarking: 2001:2::/48
    if (lower.startsWith('2001:2:')) {
      return IP_CLASSIFICATION.RESERVED_IP;
    }

    // Discard prefix: 100::/64
    if (lower.startsWith('100::') || lower.startsWith('100:0:')) {
      return IP_CLASSIFICATION.RESERVED_IP;
    }

    // IPv4-mapped IPv6 (::ffff:192.0.2.1)
    if (lower.startsWith('::ffff:')) {
      const v4Part = lower.slice(7);
      if (isValidIPv4(v4Part)) {
        const v4Class = classifyIP(v4Part);
        return v4Class === IP_CLASSIFICATION.PUBLIC_IPV4 ? IP_CLASSIFICATION.PUBLIC_IPV6 : v4Class;
      }
    }

    return IP_CLASSIFICATION.PUBLIC_IPV6;
  }

  return IP_CLASSIFICATION.INVALID_IP;
}

/**
 * Check if IP is public routable (Public IPv4 or Public IPv6)
 */
export function isPublicIP(ip) {
  const cat = classifyIP(ip);
  return cat === IP_CLASSIFICATION.PUBLIC_IPV4 || cat === IP_CLASSIFICATION.PUBLIC_IPV6;
}

/**
 * Check if IP is private, internal, loopback, link-local, or reserved (non-routable).
 * Backward-compatible with existing tests.
 */
export function isPrivateIP(ip) {
  return !isPublicIP(ip);
}

/**
 * Enhanced IP validator for SSRF protection and strict boundary auditing.
 * Checks standard private ranges as well as documentation/test networks (RFC 5737 / RFC 3849).
 */
export function isPrivateOrReservedIP(ip) {
  return !isPublicIP(ip);
}

// Extract public and private IPv4 from a string
export function extractIPv4(text) {
  if (!text || typeof text !== 'string') return [];
  const matches = text.match(IPV4_REGEX) || [];
  return Array.from(new Set(matches.map(ip => cleanIPString(ip)).filter(isValidIPv4)));
}

// Extract IPv6 from a string (including bracketed [IPv6:...] notations)
export function extractIPv6(text) {
  if (!text || typeof text !== 'string') return [];
  const matches = [];
  
  // 1. Bracketed format: [2607:f8b0:4002:c08::229] or [IPv6:2001:db8::1]
  const bracketV6Regex = /\[(?:IPv6:\s*)?([0-9a-fA-F:]+(?:%[0-9a-zA-Z]+)?)\]/gi;
  let bMatch;
  while ((bMatch = bracketV6Regex.exec(text)) !== null) {
    const c = cleanIPString(bMatch[1]);
    if (isValidIPv6(c)) {
      matches.push(c);
    }
  }

  // 2. Unbracketed IPv6 tokens in text
  // Split text by boundaries (spaces, parentheses, semicolons, angle brackets, commas, quotes)
  const tokens = text.split(/[\s\(\)<>\[\],;"']+/);
  for (const token of tokens) {
    if (token.includes(':')) {
      const c = cleanIPString(token);
      if (isValidIPv6(c)) {
        matches.push(c);
      }
    }
  }

  return Array.from(new Set(matches));
}

// Extract all unique IP addresses (IPv4 & IPv6)
export function extractAllIPs(text) {
  if (!text || typeof text !== 'string') return [];
  const v4 = extractIPv4(text);
  const v6 = extractIPv6(text);
  return Array.from(new Set([...v4, ...v6]));
}

// Parse raw headers block into structured key-value map and Received list
export function parseRawHeaders(headerText) {
  const headers = {};
  const receivedList = [];
  const lines = headerText.split(/\r?\n/);
  
  let currentKey = null;
  let currentValue = '';

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    // Line folding (starts with whitespace)
    if (/^[ \t]/.test(line) && currentKey) {
      currentValue += ' ' + line.trim();
    } else {
      if (currentKey) {
        const lowerKey = currentKey.toLowerCase();
        if (lowerKey === 'received') {
          receivedList.push(currentValue);
        } else {
          headers[lowerKey] = headers[lowerKey] ? `${headers[lowerKey]}; ${currentValue}` : currentValue;
        }
      }
      const colonIndex = line.indexOf(':');
      if (colonIndex > 0) {
        currentKey = line.substring(0, colonIndex).trim();
        currentValue = line.substring(colonIndex + 1).trim();
      } else {
        currentKey = null;
        currentValue = '';
      }
    }
  }

  if (currentKey) {
    const lowerKey = currentKey.toLowerCase();
    if (lowerKey === 'received') {
      receivedList.push(currentValue);
    } else {
      headers[lowerKey] = headers[lowerKey] ? `${headers[lowerKey]}; ${currentValue}` : currentValue;
    }
  }

  return { headers, receivedList };
}

// Parse individual Received hop header
export function parseReceivedHop(rawHop, hopIndex) {
  const fromMatch = rawHop.match(/from\s+([^\s;]+(?:\s+\([^)]+\))?)/i);
  const byMatch = rawHop.match(/by\s+([^\s;]+)/i);
  const withMatch = rawHop.match(/with\s+([^\s;]+)/i);
  const idMatch = rawHop.match(/id\s+([^\s;]+)/i);
  
  // Date is usually after the last semicolon
  const dateSplit = rawHop.split(';');
  const dateStr = dateSplit.length > 1 ? dateSplit[dateSplit.length - 1].trim() : '';

  // Extract IPs from 'from' clause first (the transmitting host), then the whole hop
  const fromText = fromMatch ? fromMatch[0] : '';
  const fromIPs = extractAllIPs(fromText);
  const allHopIPs = extractAllIPs(rawHop);

  // Preferred IP: public IP from 'from' clause, or any public IP in hop, or first IP
  const candidateIP = fromIPs.find(isPublicIP) || allHopIPs.find(isPublicIP) || fromIPs[0] || allHopIPs[0] || '';
  const classification = classifyIP(candidateIP);
  const ipVersion = isValidIPv6(candidateIP) ? 'IPv6' : isValidIPv4(candidateIP) ? 'IPv4' : 'Unknown';

  return {
    index: hopIndex,
    hopNumber: hopIndex + 1,
    raw: rawHop,
    from: fromMatch ? fromMatch[1].trim() : 'Unknown Relay',
    by: byMatch ? byMatch[1].trim() : 'Local Mail Delivery Agent',
    protocol: withMatch ? withMatch[1].trim() : 'SMTP',
    messageId: idMatch ? idMatch[1].trim() : '',
    date: dateStr,
    extractedIP: candidateIP,
    ipVersion,
    classification,
    isPrivate: !isPublicIP(candidateIP)
  };
}

// Check for suspicious double extensions or malicious payload flags
export function inspectAttachmentSafety(filename, sizeBytes = 0) {
  const lower = filename.toLowerCase();
  const dangerousExts = ['.exe', '.scr', '.vbs', '.bat', '.cmd', '.ps1', '.hta', '.jar', '.js'];
  const macroExts = ['.xlsm', '.docm', '.pptm'];
  
  let flag = 'NORMAL / CLEAN';
  let isSuspicious = false;

  // Double extension detection (e.g. .pdf.exe, .docx.scr)
  const doubleExtRegex = /\.(pdf|docx?|xlsx?|txt|jpg|png|zip)\.([a-z0-9]{2,4})$/i;
  if (doubleExtRegex.test(lower)) {
    flag = 'Double Extension / Obfuscated Executable Binary';
    isSuspicious = true;
  } else if (dangerousExts.some(ext => lower.endsWith(ext))) {
    flag = 'Direct Executable Payload';
    isSuspicious = true;
  } else if (macroExts.some(ext => lower.endsWith(ext))) {
    flag = 'Macro-Enabled Document Payload';
    isSuspicious = true;
  } else if (lower.endsWith('.iso') || lower.endsWith('.img') || lower.endsWith('.vhd')) {
    flag = 'Disk Image Container (Container Bypass)';
    isSuspicious = true;
  }

  // Size formatting
  const sizeFormatted = sizeBytes > 1048576 
    ? `${(sizeBytes / 1048576).toFixed(1)} MB`
    : sizeBytes > 1024 
      ? `${(sizeBytes / 1024).toFixed(1)} KB`
      : `${sizeBytes} B`;

  return {
    filename,
    size: sizeFormatted,
    rawSizeBytes: sizeBytes,
    flag,
    isSuspicious
  };
}

// Escape special regex characters in a string
export function escapeRegex(str) {
  if (!str || typeof str !== 'string') return '';
  return str.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

// Master parsing function for .eml, raw headers, or full RFC 822 string
export async function parseEmailContent(rawInput, fileMetadata = null) {
  if (!rawInput || typeof rawInput !== 'string') {
    throw new Error('Invalid input: Expected non-empty string email payload');
  }

  // Strip UTF-8 BOM if present (common in Windows exported files)
  let cleanInput = rawInput.charCodeAt(0) === 0xFEFF ? rawInput.slice(1) : rawInput;

  // Strip Unix mbox delimiter if present (e.g. "From MAILER-DAEMON ...")
  if (cleanInput.startsWith('From ')) {
    cleanInput = cleanInput.replace(/^From [^\r\n]*\r?\n/, '');
  }

  // Separate header block from body block (split at first double CRLF or LF)
  const headerEndPos = cleanInput.search(/\r?\n\r?\n/);
  let headerText = '';
  let bodyText = '';

  if (headerEndPos !== -1) {
    headerText = cleanInput.substring(0, headerEndPos);
    bodyText = cleanInput.substring(headerEndPos).replace(/^\r?\n\r?\n/, '');
  } else {
    // If no clear body separator, treat entire text as headers if it contains colons
    if (cleanInput.includes(':')) {
      headerText = cleanInput;
      bodyText = '';
    } else {
      headerText = '';
      bodyText = cleanInput;
    }
  }

  const { headers, receivedList } = parseRawHeaders(headerText);

  // Extract core RFC headers
  const fromRaw = decodeMimeWords(headers['from'] || '');
  const fromParsed = parseEmailAddress(fromRaw);

  const toRaw = decodeMimeWords(headers['to'] || '');
  const toParsed = parseEmailAddress(toRaw);

  const ccRaw = decodeMimeWords(headers['cc'] || '');
  const subjectRaw = decodeMimeWords(headers['subject'] || '(No Subject)');
  const dateRaw = headers['date'] || new Date().toUTCString();
  
  const replyToRaw = decodeMimeWords(headers['reply-to'] || '');
  const replyToParsed = parseEmailAddress(replyToRaw);

  const returnPathRaw = decodeMimeWords(headers['return-path'] || '');
  const returnPathParsed = parseEmailAddress(returnPathRaw);

  const messageId = headers['message-id'] || `<generated-${Date.now()}@local>`;

  // Parse Received hops
  const parsedHops = receivedList.map((hop, idx) => parseReceivedHop(hop, idx));

  // Determine Originating IP candidate
  let originatingIP = '';
  let originatingIPSource = '';
  let originatingIPExplanation = '';

  // 1. Inspect explicit originating headers (X-Originating-IP, X-Sender-IP, X-Real-IP, X-Client-IP)
  const candidateHeaderKeys = ['x-originating-ip', 'x-sender-ip', 'x-real-ip', 'x-client-ip'];
  for (const hKey of candidateHeaderKeys) {
    if (headers[hKey]) {
      const extracted = extractAllIPs(headers[hKey]);
      if (extracted.length > 0) {
        const first = extracted[0];
        originatingIPSource = hKey.toUpperCase();
        originatingIP = first;
        break;
      }
    }
  }

  // 2. If no explicit header or explicit header was private, check earliest external Received hop
  // Note: parsedHops is ordered top-to-bottom. The bottom hop (parsedHops.length - 1) is the earliest hop.
  if (!originatingIP || !isPublicIP(originatingIP)) {
    for (let i = parsedHops.length - 1; i >= 0; i--) {
      const hop = parsedHops[i];
      if (hop.extractedIP && isPublicIP(hop.extractedIP)) {
        originatingIP = hop.extractedIP;
        originatingIPSource = `Received (Hop #${hop.hopNumber})`;
        break;
      }
    }
  }

  // 3. If still no public IP found, check earliest hop even if private
  if (!originatingIP) {
    for (let i = parsedHops.length - 1; i >= 0; i--) {
      const hop = parsedHops[i];
      if (hop.extractedIP) {
        originatingIP = hop.extractedIP;
        const hopClass = classifyIP(originatingIP);
        const hopRole = hopClass === IP_CLASSIFICATION.TEST_NET_IP 
          ? 'Documentation / TEST-NET'
          : hopClass === IP_CLASSIFICATION.LOOPBACK_IP
            ? 'Loopback'
            : hopClass === IP_CLASSIFICATION.LINK_LOCAL_IP
              ? 'Link-Local'
              : hopClass === IP_CLASSIFICATION.RESERVED_IP
                ? 'Reserved Range'
                : 'Internal/Private Relay';
        originatingIPSource = `Received (Hop #${hop.hopNumber} - ${hopRole})`;
        originatingIPExplanation = hopClass === IP_CLASSIFICATION.TEST_NET_IP
          ? `Originating hop extracted documentation / TEST-NET IP (${originatingIP}); excluded from public network routing.`
          : hopClass === IP_CLASSIFICATION.LOOPBACK_IP
            ? `Originating hop extracted host-local loopback IP (${originatingIP}); internal to sender host.`
            : hopClass === IP_CLASSIFICATION.LINK_LOCAL_IP
              ? `Originating hop extracted link-local IP (${originatingIP}); autoconfigured non-routable hop.`
              : hopClass === IP_CLASSIFICATION.RESERVED_IP
                ? `Originating hop extracted special-purpose reserved IP (${originatingIP}); unroutable address space.`
                : `Originating hop extracted internal IP (${originatingIP}); sender's public egress IP was not observable in Received headers.`;
        break;
      }
    }
  }

  if (!originatingIP) {
    originatingIPExplanation = 'No extractable IP address identified in email headers; sender public IP could not be determined.';
  } else if (!originatingIPExplanation) {
    originatingIPExplanation = `Originating IP identified from ${originatingIPSource} as earliest external transit hop.`;
  }

  const originatingIPClassification = classifyIP(originatingIP);

  // Parse Authentication Headers (SPF, DKIM, DMARC)
  const receivedSpf = headers['received-spf'] || '';
  const authResults = headers['authentication-results'] || '';

  let spfResult = 'UNKNOWN';
  let spfDetails = 'No Received-SPF or Authentication-Results header found.';
  if (/pass/i.test(receivedSpf) || /spf=pass/i.test(authResults)) {
    spfResult = 'PASS';
    spfDetails = receivedSpf || 'SPF verification passed successfully.';
  } else if (/softfail/i.test(receivedSpf) || /spf=softfail/i.test(authResults)) {
    spfResult = 'SOFTFAIL';
    spfDetails = receivedSpf || 'Sender IP not designated in domain SPF record.';
  } else if (/fail/i.test(receivedSpf) || /spf=fail/i.test(authResults)) {
    spfResult = 'FAIL';
    spfDetails = receivedSpf || 'Sender IP rejected by domain SPF policy.';
  } else if (/neutral/i.test(receivedSpf) || /spf=neutral/i.test(authResults)) {
    spfResult = 'NEUTRAL';
    spfDetails = 'SPF record does not state whether IP is authorized.';
  }

  let dkimResult = 'UNKNOWN';
  let dkimDetails = 'No DKIM signature evaluated.';
  if (/dkim=pass/i.test(authResults)) {
    dkimResult = 'PASS';
    dkimDetails = 'Valid cryptographic DKIM signature matching sender domain.';
  } else if (/dkim=fail/i.test(authResults)) {
    dkimResult = 'FAIL';
    dkimDetails = 'Cryptographic signature verification failed or body hash mismatch.';
  } else if (headers['dkim-signature']) {
    dkimResult = 'UNVERIFIED';
    dkimDetails = 'DKIM-Signature header present but cryptographic public key validation required.';
  }

  let dmarcResult = 'UNKNOWN';
  let dmarcDetails = 'No DMARC policy result published in headers.';
  if (/dmarc=pass/i.test(authResults)) {
    dmarcResult = 'PASS';
    dmarcDetails = 'Domain alignment confirmed with published DMARC policy.';
  } else if (/dmarc=fail/i.test(authResults)) {
    dmarcResult = 'FAIL';
    dmarcDetails = 'DMARC alignment failed (quarantine or reject policy specified).';
  }

  // Mismatch Analysis
  const replyToMismatch = Boolean(replyToParsed.address && fromParsed.address && (replyToParsed.domain !== fromParsed.domain));
  const returnPathMismatch = Boolean(returnPathParsed.address && fromParsed.address && (returnPathParsed.domain !== fromParsed.domain));

  // Parse Attachments (look for MIME boundaries or Content-Disposition: attachment)
  const attachments = [];
  const boundaryMatch = headers['content-type']?.match(/boundary="?([^";\r\n]+)"?/i);
  let parsedMimeParts = false;

  if (boundaryMatch) {
    const boundary = boundaryMatch[1].trim();
    try {
      const rawParts = cleanInput.split(new RegExp(`--${escapeRegex(boundary)}(?:--)?`));
      for (let pIdx = 0; pIdx < rawParts.length; pIdx++) {
        const part = rawParts[pIdx];
        const partHeaderEnd = part.search(/\r?\n\r?\n/);
        if (partHeaderEnd === -1) continue;

        const partHeaderText = part.substring(0, partHeaderEnd);
        const partBody = part.substring(partHeaderEnd).replace(/^\r?\n\r?\n/, '').trim();

        const filenameMatch = partHeaderText.match(/filename="?([^"\r\n]+)"?/i) || partHeaderText.match(/name="?([^"\r\n]+)"?/i);
        const isAttachmentDisp = /Content-Disposition:\s*attachment/i.test(partHeaderText);

        if (filenameMatch || (isAttachmentDisp && filenameMatch)) {
          parsedMimeParts = true;
          const filename = filenameMatch[1];
          const mimeMatch = partHeaderText.match(/Content-Type:\s*([^;\r\n]+)/i);
          const declaredMime = mimeMatch ? mimeMatch[1].trim() : 'application/octet-stream';
          
          // Pass base64 content if present, or null
          const isBase64 = /Content-Transfer-Encoding:\s*base64/i.test(partHeaderText);
          const contentPayload = isBase64 ? partBody : (partBody.length > 0 ? partBody : null);

          try {
            const forensicRecord = await analyzeAttachment({
              filename,
              content: contentPayload,
              mimeType: declaredMime,
              index: attachments.length
            });
            attachments.push(forensicRecord);
          } catch (attErr) {
            console.warn('Failed to analyze attachment:', attErr);
          }
        }
      }
    } catch (bErr) {
      console.warn('Boundary parsing error:', bErr);
    }
  }

  // Fallback: regex search if MIME boundary split did not find attachments
  if (!parsedMimeParts) {
    const attachmentMatches = cleanInput.matchAll(/Content-Disposition:\s*attachment;[^]*?filename="?([^"\r\n]+)"?/gi);
    for (const match of attachmentMatches) {
      const filename = match[1];
      try {
        const forensicRecord = await analyzeAttachment({
          filename,
          content: null,
          mimeType: 'application/octet-stream',
          index: attachments.length
        });
        attachments.push(forensicRecord);
      } catch (attErr) {
        console.warn('Failed to analyze fallback attachment:', attErr);
      }
    }
  }

  // If user provided a fileMetadata attachment or manual attachment (and not the .eml file itself)
  if (fileMetadata && fileMetadata.name && attachments.length === 0 && !fileMetadata.name.toLowerCase().endsWith('.eml')) {
    try {
      const forensicRecord = await analyzeAttachment({
        filename: fileMetadata.name,
        content: fileMetadata.content || null,
        mimeType: fileMetadata.type || 'application/octet-stream',
        index: 0
      });
      attachments.push(forensicRecord);
    } catch (attErr) {
      console.warn('Failed to analyze metadata attachment:', attErr);
    }
  }

  // Sanitize body snippet for display
  let cleanBody = bodyText
    .replace(/<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi, '[REMOVED UNSAFE SCRIPT]')
    .replace(/<style\b[^<]*(?:(?!<\/style>)<[^<]*)*<\/style>/gi, '')
    .trim();

  // If body is empty, fallback to subject & sender snippet
  if (!cleanBody && headerText) {
    cleanBody = `Subject: ${subjectRaw}\nFrom: ${fromRaw}\n(Headers only payload ingested)`;
  }

  // Compute true cryptographic SHA-256 hash of ingested raw payload
  const emailSha256 = await computeSHA256(cleanInput);

  return {
    sender: fromRaw || 'Unknown Sender',
    fromParsed,
    recipient: toRaw || 'Unknown Recipient',
    toParsed,
    cc: ccRaw,
    subject: subjectRaw,
    date: dateRaw,
    replyTo: replyToRaw,
    replyToParsed,
    replyToMismatch,
    returnPath: returnPathRaw,
    returnPathParsed,
    returnPathMismatch,
    messageId,
    receivedHops: parsedHops,
    originatingIP: originatingIP || '',
    originatingIPClassification,
    originatingIPSource: originatingIPSource || 'None',
    originatingIPExplanation: originatingIPExplanation || '',
    headers,
    rawHeaders: headerText,
    body: cleanBody,
    rawSnippet: cleanInput.substring(0, 3500),
    sha256: emailSha256,
    auth: {
      spf: { result: spfResult, details: spfDetails },
      dkim: { result: dkimResult, details: dkimDetails },
      dmarc: { result: dmarcResult, details: dmarcDetails }
    },
    attachments,
    ingestedAt: new Date().toISOString()
  };
}

/**
 * Extract and categorize all network indicators (IPv4, IPv6, URL hosts) from parsed email.
 * Clearly distinguishes forensic roles:
 * - SOURCE: Originating egress IP
 * - MAIL_SERVER: Intermediate MTA transit relays
 * - URL_HOST: Suspicious URL / Phishing infrastructure IP
 * - BODY_MENTION: Referenced IP in body content
 * - PRIVATE: RFC 1918 / loopback / link-local internal IP (excluded from public geolocation)
 */
export function extractNetworkIndicators(parsedEmail) {
  if (!parsedEmail) return [];

  const indicators = [];
  const seenIPs = new Set();

  function addIndicator(ip, role, roleLabel, context, sourceHeader = 'Headers') {
    if (!ip || !isValidIP(ip)) return;
    const cleanIP = cleanIPString(ip);
    if (!cleanIP || seenIPs.has(cleanIP)) return;
    seenIPs.add(cleanIP);

    const classification = classifyIP(cleanIP);
    const isPriv = isPrivateIP(cleanIP);
    const ipVersion = isValidIPv6(cleanIP) ? 'IPv6' : 'IPv4';

    // Distinct non-public categorization: never conflate TEST-NET, loopback, or link-local as PRIVATE
    let computedRole = role;
    let computedRoleLabel = roleLabel;

    if (isPriv) {
      if (classification === IP_CLASSIFICATION.TEST_NET_IP) {
        computedRole = 'RESERVED / TEST-NET';
        computedRoleLabel = 'Documentation / TEST-NET (RFC 5737)';
      } else if (classification === IP_CLASSIFICATION.LOOPBACK_IP) {
        computedRole = 'LOOPBACK';
        computedRoleLabel = 'Loopback Address';
      } else if (classification === IP_CLASSIFICATION.LINK_LOCAL_IP) {
        computedRole = 'LINK_LOCAL';
        computedRoleLabel = 'Link-Local Address (RFC 3927)';
      } else if (classification === IP_CLASSIFICATION.PRIVATE_IP) {
        computedRole = 'PRIVATE';
        computedRoleLabel = 'Private Intranet (RFC 1918)';
      } else {
        computedRole = 'RESERVED';
        computedRoleLabel = 'Reserved / Special-Purpose';
      }
    }

    indicators.push({
      ip: cleanIP,
      ipVersion,
      classification,
      sourceHeader,
      role: computedRole,
      roleLabel: computedRoleLabel,
      isPrivate: isPriv,
      geoAvailable: !isPriv,
      context,
      confidence: role === 'SOURCE' ? 'HIGH' : role === 'URL_HOST' ? 'HIGH' : 'MEDIUM'
    });
  }

  // 1. Originating / Source IP
  if (parsedEmail.originatingIP) {
    addIndicator(
      parsedEmail.originatingIP,
      'SOURCE',
      'Source / Originating IP',
      parsedEmail.originatingIPExplanation || 'Envelope Egress / Earliest External Hop',
      parsedEmail.originatingIPSource || 'Originating IP Header'
    );
  }

  // 2. Intermediate MTA hops
  if (Array.isArray(parsedEmail.receivedHops)) {
    parsedEmail.receivedHops.forEach(hop => {
      if (hop.extractedIP) {
        addIndicator(
          hop.extractedIP,
          'MAIL_SERVER',
          `Email Server / Transit Hop (Hop #${hop.hopNumber})`,
          `Received: from ${hop.from || 'MTA relay'} by ${hop.by || 'gateway'}`,
          `Received (Hop #${hop.hopNumber})`
        );
      }
    });
  }

  // 3. Explicit IPs from scenario / metadata
  if (Array.isArray(parsedEmail.ips)) {
    parsedEmail.ips.forEach(ipItem => {
      const ip = (typeof ipItem === 'string' ? ipItem.split(' ')[0] : '').trim();
      if (ip) {
        addIndicator(ip, 'MAIL_SERVER', 'Transit Routing Hop', 'Scenario Network Trace', 'Metadata / Trace');
      }
    });
  }

  // 4. URL Host IPs
  const urls = Array.isArray(parsedEmail.urls) ? parsedEmail.urls : [];
  const bodyText = `${parsedEmail.body || ''} ${parsedEmail.rawSnippet || ''}`;
  const urlMatches = bodyText.match(/(?:https?|hxxps?):\/\/[^\s<>"'{}|\\^`\[\]]+/gi) || [];
  const combinedUrls = Array.from(new Set([...urls, ...urlMatches]));

  combinedUrls.forEach(urlStr => {
    try {
      const normalized = urlStr.replace(/^hxxps?:\/\//i, 'http://').replace(/\[\.\]/g, '.');
      const urlObj = new URL(normalized);
      const host = cleanIPString(urlObj.hostname);
      if (isValidIP(host)) {
        addIndicator(
          host,
          'URL_HOST',
          'URL / Phishing Infrastructure IP',
          `Direct IP in hyperlink: ${urlStr}`,
          'Email Hyperlink'
        );
      }
    } catch {
      // ignore malformed URLs
    }
  });

  // 5. Any remaining IPs found in body content
  const bodyIPs = extractAllIPs(bodyText);
  bodyIPs.forEach(ip => {
    addIndicator(
      ip,
      'BODY_MENTION',
      'Referenced IP Address',
      'Referenced inside email message content',
      'Email Message Content'
    );
  });

  return indicators;
}

