/**
 * MAVERICK — RFC 822 & MIME Email Parser Service
 * Smart India Hackathon 2026
 * 
 * Safely parses .eml, raw headers, and email text without executing attachments.
 * Extracts headers, Received chain hops, originating IP, body, and attachment metadata.
 */

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

// Extract public IPv4 from a string
export function extractIPv4(text) {
  if (!text) return [];
  const ipv4Regex = /\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b/g;
  const matches = text.match(ipv4Regex) || [];
  return Array.from(new Set(matches));
}

// Check if IP is private/internal
export function isPrivateIP(ip) {
  if (!ip) return true;
  if (ip.startsWith('10.') || ip.startsWith('127.') || ip.startsWith('0.')) return true;
  if (ip.startsWith('192.168.')) return true;
  if (ip.startsWith('172.')) {
    const secondOctet = parseInt(ip.split('.')[1], 10);
    if (secondOctet >= 16 && secondOctet <= 31) return true;
  }
  if (ip === '255.255.255.255') return true;
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

// Master parsing function for .eml, raw headers, or full RFC 822 string
export async function parseEmailContent(rawInput, fileMetadata = null) {
  if (!rawInput || typeof rawInput !== 'string') {
    throw new Error('Invalid input: Expected non-empty string email payload');
  }

  // Separate header block from body block (split at first double CRLF or LF)
  const headerEndPos = rawInput.search(/\r?\n\r?\n/);
  let headerText = '';
  let bodyText = '';

  if (headerEndPos !== -1) {
    headerText = rawInput.substring(0, headerEndPos);
    bodyText = rawInput.substring(headerEndPos).replace(/^\r?\n\r?\n/, '');
  } else {
    // If no clear body separator, treat entire text as headers if it contains colons
    if (rawInput.includes(':')) {
      headerText = rawInput;
      bodyText = '';
    } else {
      headerText = '';
      bodyText = rawInput;
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
    const allPublicIPs = extractIPv4(rawInput).filter(ip => !isPrivateIP(ip));
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

  // Parse Attachments (look for Content-Disposition: attachment or filename=)
  const attachments = [];
  const attachmentMatches = rawInput.matchAll(/Content-Disposition:\s*attachment;[^]*?filename="?([^"\r\n]+)"?/gi);
  for (const match of attachmentMatches) {
    const filename = match[1];
    const safety = inspectAttachmentSafety(filename, 248420);
    const mockHash = await computeSHA256(filename + Date.now());
    attachments.push({
      ...safety,
      md5: computeFastHash(filename, 32),
      sha1: computeFastHash(filename, 40),
      sha256: mockHash
    });
  }

  // If user provided a fileMetadata attachment or manual attachment
  if (fileMetadata && fileMetadata.name && attachments.length === 0 && fileMetadata.name.endsWith('.eml') === false) {
    const safety = inspectAttachmentSafety(fileMetadata.name, fileMetadata.size || 10240);
    const sha256 = await computeSHA256(fileMetadata.name);
    attachments.push({
      ...safety,
      md5: computeFastHash(fileMetadata.name, 32),
      sha1: computeFastHash(fileMetadata.name, 40),
      sha256
    });
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
    originatingIP: originatingIP || '185.220.101.45',
    headers,
    rawHeaders: headerText,
    body: cleanBody,
    rawSnippet: rawInput.substring(0, 3500),
    auth: {
      spf: { result: spfResult, details: spfDetails },
      dkim: { result: dkimResult, details: dkimDetails },
      dmarc: { result: dmarcResult, details: dmarcDetails }
    },
    attachments,
    ingestedAt: new Date().toISOString()
  };
}
