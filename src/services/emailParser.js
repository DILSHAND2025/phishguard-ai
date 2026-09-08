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

// IPv4 and IPv6 regex definitions
export const IPV4_REGEX = /\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b/g;
export const IPV6_REGEX = /(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|(?:[0-9a-fA-F]{1,4}:){1,7}:|(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|(?:[0-9a-fA-F]{1,4}:){1,5}(?::[0-9a-fA-F]{1,4}){1,2}|(?:[0-9a-fA-F]{1,4}:){1,4}(?::[0-9a-fA-F]{1,4}){1,3}|(?:[0-9a-fA-F]{1,4}:){1,3}(?::[0-9a-fA-F]{1,4}){1,4}|(?:[0-9a-fA-F]{1,4}:){1,2}(?::[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:(?:(?::[0-9a-fA-F]{1,4}){1,6})|:(?:(?::[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(?::[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(?:ffff(?::0{1,4}){0,1}:){0,1}(?:(?:25[0-5]|(?:2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(?:25[0-5]|(?:2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:(?:(?:25[0-5]|(?:2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(?:25[0-5]|(?:2[0-4]|1{0,1}[0-9]){0,1}[0-9])/gi;

// Validate if a string is a valid IPv4 or IPv6 address
export function isValidIP(ip) {
  if (!ip || typeof ip !== 'string') return false;
  const clean = ip.trim();
  const ipv4Exact = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
  if (ipv4Exact.test(clean)) return true;
  return clean.includes(':') && (clean.match(IPV6_REGEX) || [])[0] === clean;
}

// Extract public and private IPv4 from a string
export function extractIPv4(text) {
  if (!text || typeof text !== 'string') return [];
  const matches = text.match(IPV4_REGEX) || [];
  return Array.from(new Set(matches));
}

// Extract IPv6 from a string
export function extractIPv6(text) {
  if (!text || typeof text !== 'string') return [];
  const matches = text.match(IPV6_REGEX) || [];
  return Array.from(new Set(matches.map(ip => ip.trim())));
}

// Extract all unique IP addresses (IPv4 & IPv6)
export function extractAllIPs(text) {
  if (!text || typeof text !== 'string') return [];
  const v4 = extractIPv4(text);
  const v6 = extractIPv6(text);
  return Array.from(new Set([...v4, ...v6]));
}

// Check if IP is private/reserved/internal (IPv4 & IPv6)
export function isPrivateIP(ip) {
  if (!ip || typeof ip !== 'string') return true;
  const clean = ip.trim().toLowerCase();

  // IPv4 Private & Reserved ranges
  if (clean.startsWith('10.') || clean.startsWith('127.') || clean.startsWith('0.')) return true;
  if (clean.startsWith('192.168.')) return true;
  if (clean.startsWith('169.254.')) return true; // Link-local
  if (clean.startsWith('172.')) {
    const parts = clean.split('.');
    const secondOctet = parseInt(parts[1], 10);
    if (secondOctet >= 16 && secondOctet <= 31) return true;
  }
  if (clean.startsWith('100.')) {
    const parts = clean.split('.');
    const secondOctet = parseInt(parts[1], 10);
    if (secondOctet >= 64 && secondOctet <= 127) return true; // Carrier-grade NAT 100.64.0.0/10
  }
  if (clean === '255.255.255.255' || clean.startsWith('224.') || clean.startsWith('240.')) return true;

  // IPv6 Private & Reserved ranges
  if (clean === '::1' || clean === '::') return true; // Loopback & unspecified
  if (clean.startsWith('fe80:')) return true; // Link-local
  if (clean.startsWith('fc00:') || clean.startsWith('fd00:')) return true; // Unique local (ULA)
  if (clean.startsWith('ff00:')) return true; // Multicast

  return false;
}

/**
 * Enhanced IP validator for SSRF protection and strict boundary auditing.
 * Checks standard private ranges as well as documentation/test networks (RFC 5737 / RFC 3849).
 */
export function isPrivateOrReservedIP(ip) {
  if (!ip || typeof ip !== 'string') return true;
  if (isPrivateIP(ip)) return true;
  const clean = ip.trim().toLowerCase();
  // Documentation test-nets (RFC 5737: 192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24)
  if (clean.startsWith('192.0.2.') || clean.startsWith('198.51.100.') || clean.startsWith('203.0.113.')) return true;
  // IPv6 Documentation prefix (RFC 3849: 2001:db8::/32)
  if (clean.startsWith('2001:db8:')) return true;
  return false;
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

  const ips = extractIPv4(rawHop);
  const publicIP = ips.find(ip => !isPrivateIP(ip)) || ips[0] || '';

  return {
    hopNumber: hopIndex + 1,
    raw: rawHop,
    from: fromMatch ? fromMatch[1].trim() : 'Unknown Relay',
    by: byMatch ? byMatch[1].trim() : 'Local Mail Delivery Agent',
    protocol: withMatch ? withMatch[1].trim() : 'SMTP',
    messageId: idMatch ? idMatch[1].trim() : '',
    date: dateStr,
    extractedIP: publicIP,
    isPrivate: isPrivateIP(publicIP)
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

  // Determine Originating IP (from X-Originating-IP or earliest public Received hop)
  let originatingIP = '';
  if (headers['x-originating-ip']) {
    const extracted = extractIPv4(headers['x-originating-ip']);
    if (extracted.length > 0) originatingIP = extracted[0];
  }
  if (!originatingIP) {
    for (let i = parsedHops.length - 1; i >= 0; i--) {
      if (parsedHops[i].extractedIP && !parsedHops[i].isPrivate) {
        originatingIP = parsedHops[i].extractedIP;
        break;
      }
    }
  }
  // Fallback to any public IP found in Received or headers
  if (!originatingIP) {
    const allPublicIPs = extractIPv4(cleanInput).filter(ip => !isPrivateIP(ip));
    if (allPublicIPs.length > 0) originatingIP = allPublicIPs[0];
  }

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
    headers,
    rawHeaders: headerText,
    body: cleanBody,
    rawSnippet: cleanInput.substring(0, 3500),
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
 * - PRIVATE: RFC 1918 / loopback internal IP (ignored for public geolocation)
 */
export function extractNetworkIndicators(parsedEmail) {
  if (!parsedEmail) return [];

  const indicators = [];
  const seenIPs = new Set();

  function addIndicator(ip, role, roleLabel, context) {
    if (!ip || !isValidIP(ip)) return;
    const cleanIP = ip.trim();
    if (seenIPs.has(cleanIP)) return;
    seenIPs.add(cleanIP);

    const isPriv = isPrivateIP(cleanIP);
    indicators.push({
      ip: cleanIP,
      role: isPriv ? 'PRIVATE' : role,
      roleLabel: isPriv ? `${roleLabel} (Private/Non-Routable)` : roleLabel,
      isPrivate: isPriv,
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
      'Envelope Egress / Earliest External Hop'
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
          `Received: from ${hop.from || 'MTA relay'} by ${hop.by || 'gateway'}`
        );
      }
    });
  }

  // 3. Explicit IPs from scenario / metadata
  if (Array.isArray(parsedEmail.ips)) {
    parsedEmail.ips.forEach(ipItem => {
      const ip = (typeof ipItem === 'string' ? ipItem.split(' ')[0] : '').trim();
      if (ip) {
        addIndicator(ip, 'MAIL_SERVER', 'Transit Routing Hop', 'Scenario Network Trace');
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
      const host = urlObj.hostname.replace(/^\[|\]$/g, ''); // strip IPv6 brackets if any
      if (isValidIP(host)) {
        addIndicator(
          host,
          'URL_HOST',
          'URL / Phishing Infrastructure IP',
          `Direct IP in hyperlink: ${urlStr}`
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
      'Referenced inside email message content'
    );
  });

  return indicators;
}

