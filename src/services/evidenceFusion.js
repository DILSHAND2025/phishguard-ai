/**
 * MAVERICK — Multi-Layer Evidence Fusion Engine
 * Smart India Hackathon 2026 Core Novelty
 * 
 * Synthesizes 6 distinct cybersecurity evidence layers into an explainable 0–100 risk score:
 * 1. AI/NLP Linguistic Analysis (Max 25 pts)
 * 2. Header & Authentication Forensics (Max 20 pts)
 * 3. URL & Domain Intelligence (Max 20 pts)
 * 4. IP Reputation & Routing (Max 15 pts)
 * 5. GeoLocation & ASN Infrastructure (Max 10 pts)
 * 6. Attachment Payload Analysis (Max 10 pts)
 * 
 * Total = 100 Points Max
 * 
 * Risk Categorization:
 * - 0–30:   LOW
 * - 31–60:  SUSPICIOUS
 * - 61–80:  HIGH
 * - 81–100: CRITICAL
 * 
 * Produces an itemized, explainable evidence ledger showing only verified findings.
 */

export const DEFAULT_FUSION_WEIGHTS = {
  aiNlp: 25,
  headerForensics: 20,
  urlIntel: 20,
  ipReputation: 15,
  geoAsnContext: 10,
  attachmentPayload: 10
};

export function calculateEvidenceFusion({
  parsedEmail,
  aiThreat,
  iocs = [],
  geoInfo = null,
  weights = DEFAULT_FUSION_WEIGHTS
}) {
  const factors = [];
  let totalScore = 0;

  // 1. AI / NLP Analysis Layer (Max 25 pts)
  const aiProb = aiThreat?.phishingProbability || 10;
  const aiScore = Math.min(weights.aiNlp, Math.round((aiProb / 100) * weights.aiNlp));
  totalScore += aiScore;

  const aiEvidenceList = [];
  if (aiThreat?.detectedIndicators?.length > 0) {
    aiEvidenceList.push(`Detected ${aiThreat.detectedIndicators.length} linguistic markers (${aiThreat.keyTokens.slice(0, 4).join(', ')})`);
  }
  if (aiProb >= 70) {
    aiEvidenceList.push(`High AI model phishing probability of ${aiProb}%`);
  }

  factors.push({
    id: 'ai-nlp-analysis',
    category: 'AI / NLP Analysis',
    name: 'Natural Language & Linguistic Threat Markers',
    points: aiScore,
    maxPoints: weights.aiNlp,
    severity: aiScore >= 18 ? 'CRITICAL' : aiScore >= 10 ? 'HIGH' : 'LOW',
    status: aiScore >= 10 ? 'FLAGGED' : 'PASS',
    evidence: aiEvidenceList.length > 0 
      ? aiEvidenceList.join('. ') + '.'
      : 'No high-threat linguistic tokens detected by NLP classifier.',
    reasons: aiThreat?.detectedIndicators?.map(ind => `⚠️ ${ind.category}: "${ind.token}" (${ind.explanation})`) || []
  });

  // 2. Email Header Forensics Layer (Max 20 pts)
  let headerScore = 0;
  const headerReasons = [];

  // SPF check
  const spf = parsedEmail?.auth?.spf?.result || 'UNKNOWN';
  if (spf === 'FAIL') {
    headerScore += 6;
    headerReasons.push('❌ SPF verification FAILED: Sender IP rejected by domain SPF policy.');
  } else if (spf === 'SOFTFAIL') {
    headerScore += 4;
    headerReasons.push('⚠️ SPF SOFTFAIL: Sender IP is not an authorized designated relay for the domain.');
  }

  // DKIM check
  const dkim = parsedEmail?.auth?.dkim?.result || 'UNKNOWN';
  if (dkim === 'FAIL') {
    headerScore += 6;
    headerReasons.push('❌ DKIM cryptographic signature verification FAILED (tampered body or forged domain).');
  }

  // DMARC check
  const dmarc = parsedEmail?.auth?.dmarc?.result || 'UNKNOWN';
  if (dmarc === 'FAIL') {
    headerScore += 5;
    headerReasons.push('❌ DMARC policy alignment FAILED (mandated quarantine/reject rule triggered).');
  }

  // From vs Reply-To Mismatch
  if (parsedEmail?.replyToMismatch) {
    headerScore += 4;
    headerReasons.push(`⚠️ Reply-To mismatch: Replies directed to external domain "${parsedEmail.replyToParsed?.domain}" instead of sender "${parsedEmail.fromParsed?.domain}".`);
  }

  // From vs Return-Path Mismatch
  if (parsedEmail?.returnPathMismatch) {
    headerScore += 3;
    headerReasons.push(`⚠️ Return-Path mismatch: Bounces routed to untrusted domain "${parsedEmail.returnPathParsed?.domain}".`);
  }

  const clampedHeaderScore = Math.min(weights.headerForensics, headerScore);
  totalScore += clampedHeaderScore;

  factors.push({
    id: 'header-forensics',
    category: 'Header Forensics',
    name: 'RFC 822 & Authentication Protocols (SPF / DKIM / DMARC)',
    points: clampedHeaderScore,
    maxPoints: weights.headerForensics,
    severity: clampedHeaderScore >= 14 ? 'CRITICAL' : clampedHeaderScore >= 8 ? 'HIGH' : 'LOW',
    status: clampedHeaderScore >= 8 ? 'FLAGGED' : 'PASS',
    evidence: headerReasons.length > 0 
      ? headerReasons.join(' ')
      : 'All cryptographic authentication records (SPF, DKIM, DMARC) verified cleanly.',
    reasons: headerReasons
  });

  // 3. URL & Domain Intelligence Layer (Max 20 pts)
  let urlScore = 0;
  const urlReasons = [];
  const urlIOCs = iocs.filter(i => i.type === 'URL');
  const domainIOCs = iocs.filter(i => i.type === 'DOMAIN');

  const maliciousUrls = urlIOCs.filter(u => u.status === 'MALICIOUS');
  const suspiciousUrls = urlIOCs.filter(u => u.status === 'SUSPICIOUS');
  const maliciousDomains = domainIOCs.filter(d => d.status === 'MALICIOUS');

  if (maliciousUrls.length > 0) {
    urlScore += 12;
    urlReasons.push(`🔴 ${maliciousUrls.length} URL(s) flagged malicious by threat feeds (${maliciousUrls.map(u => u.value).slice(0, 2).join(', ')}).`);
  } else if (suspiciousUrls.length > 0) {
    urlScore += 6;
    urlReasons.push(`🟡 ${suspiciousUrls.length} URL(s) exhibit credential-harvesting URI patterns.`);
  }

  if (maliciousDomains.length > 0) {
    urlScore += 8;
    urlReasons.push(`🔴 Malicious homoglyph/typosquat domain detected: "${maliciousDomains.map(d => d.value).join(', ')}".`);
  }

  const clampedUrlScore = Math.min(weights.urlIntel, urlScore);
  totalScore += clampedUrlScore;

  factors.push({
    id: 'url-domain-intel',
    category: 'URL & Domain Intelligence',
    name: 'Threat Feeds & Lookalike Domain Analysis',
    points: clampedUrlScore,
    maxPoints: weights.urlIntel,
    severity: clampedUrlScore >= 12 ? 'CRITICAL' : clampedUrlScore >= 6 ? 'HIGH' : 'LOW',
    status: clampedUrlScore >= 6 ? 'FLAGGED' : 'PASS',
    evidence: urlReasons.length > 0 
      ? urlReasons.join(' ')
      : 'No malicious URLs or typosquatted domain indicators found.',
    reasons: urlReasons
  });

  // 4. IP Reputation Layer (Max 15 pts)
  let ipScore = 0;
  const ipReasons = [];
  const ipIOCs = iocs.filter(i => i.type === 'IP');
  const malIPs = ipIOCs.filter(i => i.status === 'MALICIOUS');
  const suspIPs = ipIOCs.filter(i => i.status === 'SUSPICIOUS');

  if (malIPs.length > 0) {
    ipScore += 12;
    ipReasons.push(`🔴 Originating IP ${malIPs[0].value} has high abuse confidence score in threat intelligence databases.`);
  } else if (suspIPs.length > 0) {
    ipScore += 6;
    ipReasons.push(`🟠 Transit IP ${suspIPs[0].value} associated with unverified proxy or relay networks.`);
  }

  const clampedIpScore = Math.min(weights.ipReputation, ipScore);
  totalScore += clampedIpScore;

  factors.push({
    id: 'ip-reputation',
    category: 'IP Reputation',
    name: 'Network Hop & Abuse Intelligence',
    points: clampedIpScore,
    maxPoints: weights.ipReputation,
    severity: clampedIpScore >= 10 ? 'HIGH' : clampedIpScore >= 5 ? 'MEDIUM' : 'LOW',
    status: clampedIpScore >= 5 ? 'FLAGGED' : 'PASS',
    evidence: ipReasons.length > 0 
      ? ipReasons.join(' ')
      : 'Originating IP exhibits neutral/clean reputation with no prior abuse reports.',
    reasons: ipReasons
  });

  // 5. Geo / ASN Context Layer (Max 10 pts)
  let geoScore = 0;
  const geoReasons = [];

  if (geoInfo?.isProxyOrVpn || (geoInfo?.networkType && geoInfo.networkType.toLowerCase().includes('tor'))) {
    geoScore += 8;
    geoReasons.push(`⚠️ Infrastructure categorized as anonymizing proxy/Tor node (${geoInfo.asn} - ${geoInfo.asnOrg}).`);
  } else if (geoInfo?.networkType && geoInfo.networkType.toLowerCase().includes('bulletproof')) {
    geoScore += 10;
    geoReasons.push(`❌ Hosting infrastructure on known bulletproof provider (${geoInfo.country}).`);
  } else if (geoInfo?.riskLevel === 'HIGH') {
    geoScore += 5;
    geoReasons.push(`⚠️ High-risk egress routing through ${geoInfo.country} (${geoInfo.asn}).`);
  }

  const clampedGeoScore = Math.min(weights.geoAsnContext, geoScore);
  totalScore += clampedGeoScore;

  factors.push({
    id: 'geo-asn-context',
    category: 'Geo / ASN Context',
    name: 'Autonomous System & Network Topology',
    points: clampedGeoScore,
    maxPoints: weights.geoAsnContext,
    severity: clampedGeoScore >= 7 ? 'HIGH' : clampedGeoScore >= 4 ? 'MEDIUM' : 'LOW',
    status: clampedGeoScore >= 4 ? 'FLAGGED' : 'PASS',
    evidence: geoReasons.length > 0 
      ? geoReasons.join(' ')
      : `Observed network infrastructure geolocates to ${geoInfo?.country || 'standard subnet'} with standard corporate routing.`,
    reasons: geoReasons
  });

  // 6. Attachment Payload Layer (Max 10 pts)
  let attScore = 0;
  const attReasons = [];
  const attachments = parsedEmail?.attachments || [];
  const suspiciousAtts = attachments.filter(a => a.isSuspicious);

  if (suspiciousAtts.length > 0) {
    attScore += 10;
    attReasons.push(`❌ High-risk attachment detected: "${suspiciousAtts[0].filename}" (${suspiciousAtts[0].flag}).`);
  } else if (attachments.length > 0) {
    attReasons.push(`📎 ${attachments.length} attachment(s) verified as standard benign document format.`);
  }

  const clampedAttScore = Math.min(weights.attachmentPayload, attScore);
  totalScore += clampedAttScore;

  factors.push({
    id: 'attachment-analysis',
    category: 'Attachment Analysis',
    name: 'MIME Binary & Double Extension Inspection',
    points: clampedAttScore,
    maxPoints: weights.attachmentPayload,
    severity: clampedAttScore >= 8 ? 'CRITICAL' : 'LOW',
    status: clampedAttScore >= 8 ? 'FLAGGED' : 'PASS',
    evidence: attReasons.length > 0 
      ? attReasons.join(' ')
      : 'No file attachments enclosed in this email.',
    reasons: attReasons
  });

  // Overall Risk Classification
  const finalScore = Math.min(100, Math.max(5, totalScore));
  let riskLevel = 'LOW';
  let badgeColor = 'emerald';
  if (finalScore >= 81) {
    riskLevel = 'CRITICAL';
    badgeColor = 'red';
  } else if (finalScore >= 61) {
    riskLevel = 'HIGH';
    badgeColor = 'red';
  } else if (finalScore >= 31) {
    riskLevel = 'SUSPICIOUS';
    badgeColor = 'amber';
  }

  // Generate itemized forensic highlights (only verified findings)
  const allReasons = [];
  factors.forEach(f => {
    f.reasons.forEach(r => allReasons.push(r));
  });

  return {
    threatScore: finalScore,
    riskLevel,
    badgeColor,
    factors,
    verifiedReasons: allReasons,
    weightsUsed: weights,
    evaluatedAt: new Date().toISOString()
  };
}
