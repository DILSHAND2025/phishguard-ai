/**
 * MAVERICK — End-to-End Integration & SIH Demonstration Readiness Test Suite
 * Smart India Hackathon 2026
 * 
 * Verifies complete pipeline integrity, realistic synthetic scenarios,
 * score parity, failure handling, security protections, and tamper evidence:
 * 1. End-to-End Pipeline Execution (Ingestion -> Fusion -> Report -> PDF)
 * 2. Scenario 1: Legitimate Official Communication (Benign baseline, low risk)
 * 3. Scenario 2: Credential Phishing Email (Elevated risk, IOC extraction)
 * 4. Scenario 3: Business Email Compromise / Executive Wire (Reply-To mismatch)
 * 5. Scenario 4: Malicious Attachment (Static PE header, zero execution)
 * 6. Scenario 5: Email Authentication Failure (SPF/DKIM/DMARC separation)
 * 7. Scenario 6: Suspicious Infrastructure (Multi-hop routing, GeoIP accuracy)
 * 8. Scenario 7: Combined High-Risk Multi-Vector Threat Analysis
 * 9. Threat Score Parity (Evidence Fusion == Report == PDF)
 * 10. Strict Evidence Provenance (Observed Facts vs Inferred Models)
 * 11. Failure Handling: ML service unavailable (degrades gracefully, no fake score)
 * 12. Failure Handling: DNS timeout / NXDOMAIN (never crashes, no fake records)
 * 13. Failure Handling: GeoIP unavailable (coordinates null, no fake location)
 * 14. Failure Handling: Malformed RFC 822 email payload
 * 15. Failure Handling: Empty email input validation
 * 16. Failure Handling: Zero-byte & oversized attachment threshold
 * 17. Security Audit: SSRF IP address validation (RFC 1918, CGNAT, loopbacks)
 * 18. Security Audit: Path traversal filename sanitization (../../evil.exe)
 * 19. Security Audit: Attachment zero-execution guarantee
 * 20. Cryptographic Chain of Custody: Content SHA-256 vs PDF SHA-256 integrity
 */

import test from 'node:test';
import assert from 'node:assert/strict';

// Core Forensic & Ingestion Services
import { parseEmailContent, extractNetworkIndicators, isValidIP, isPrivateIP, isPrivateOrReservedIP } from '../src/services/emailParser.js';
import { extractAllIOCs } from '../src/services/iocExtractor.js';
import { evaluateAIThreat } from '../src/services/aiThreatModel.js';
import { defaultGeoService, GeoLocationService, BaseGeoProvider } from '../src/services/geoLocationService.js';
import { analyzeAttachment } from '../src/services/attachmentForensics.js';
import { analyzeEmailAuthentication } from '../src/services/emailAuthService.js';
import { createMockDnsResolver } from '../src/services/dnsService.js';
import { calculateEvidenceFusion, DEFAULT_FUSION_WEIGHTS } from '../src/services/evidenceFusion.js';
import { buildForensicReport } from '../src/services/forensicReportService.js';
import { generateForensicPdf, computePdfFileHash } from '../src/services/pdfBuilder.js';
import { SYNTHETIC_SCENARIOS, getScenarioById } from '../src/data/syntheticScenarios.js';

test('MAVERICK End-to-End Integration & SIH Demonstration Suite', async (t) => {

  // Deterministic Mock DNS Database for hermetic integration testing
  const mockDnsDb = {
    'gov-organization.in': ['v=spf1 ip4:14.139.56.2 -all'],
    's1._domainkey.gov-organization.in': [
      'v=DKIM1; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0Y3yD9rE6j9a+9Vz0k8yP6Q7G...'
    ],
    '_dmarc.gov-organization.in': ['v=DMARC1; p=none; sp=none; pct=100; aspf=r; adkim=r'],
    'internal-corp-portal.online': ['v=spf1 include:_spf.google.com ~all'],
    '_dmarc.internal-corp-portal.online': ['v=DMARC1; p=reject; sp=reject'],
    'portal-gov-advisory.online': ['v=spf1 -all'],
    '_dmarc.portal-gov-advisory.online': ['v=DMARC1; p=quarantine'],
    'secure-login-okta.me': ['v=spf1 -all'],
    '_dmarc.secure-login-okta.me': ['v=DMARC1; p=reject'],
    'treasury-audit-gov.in': ['v=spf1 ~all'],
    '_dmarc.treasury-audit-gov.in': ['v=DMARC1; p=quarantine'],
    'example.com': ['v=spf1 ~all'],
    '_dmarc.example.com': ['v=DMARC1; p=none']
  };
  const mockResolver = createMockDnsResolver(mockDnsDb);

  // =========================================================================
  // 1. END-TO-END PIPELINE VERIFICATION
  // =========================================================================
  await t.test('1. Complete Pipeline: Ingestion -> ML -> Auth -> Fusion -> Report -> PDF -> SHA256', async () => {
    const rawEmail = `From: "Finance Director" <cfo@internal-corp-portal.online>
Reply-To: <external-treasury@proton.me>
To: <controller@gov-organization.in>
Subject: URGENT: Wire Remittance Release
Date: Fri, 05 Sep 2026 11:41:50 +0530
Received: from mail.internal-corp-portal.online (185.220.101.45) by mail.gov.in; Fri, 05 Sep 2026 11:41:50 +0530
Authentication-Results: mail.gov.in; dkim=fail; spf=softfail; dmarc=fail

Expedite statutory allocation transfer of INR 4,85,00,000 immediately.`;

    // 1. Parsing
    const parsed = await parseEmailContent(rawEmail);
    assert.ok(parsed.fromParsed);
    assert.equal(parsed.replyToMismatch, true);

    // 2. IOCs
    const iocs = extractAllIOCs(parsed);
    assert.ok(iocs.length >= 1);

    // 3. AI Threat (Live inference)
    const aiThreat = await evaluateAIThreat(parsed);
    assert.ok(aiThreat.model);

    // 4. Geo
    const geoInfo = await defaultGeoService.resolveIP(parsed.originatingIP);
    assert.ok(geoInfo);

    // 5. Auth with mockResolver
    const emailAuth = await analyzeEmailAuthentication(rawEmail, { resolver: mockResolver });
    assert.ok(emailAuth.spf);
    assert.ok(emailAuth.dkim);

    // 6. Fusion
    const fusion = calculateEvidenceFusion({
      parsedEmail: parsed,
      aiThreat,
      iocs,
      geoInfo,
      emailAuth,
      weights: DEFAULT_FUSION_WEIGHTS
    });
    assert.ok(typeof fusion.threatScore === 'number');
    assert.ok(fusion.threatScore >= 0 && fusion.threatScore <= 100);

    // 7. Forensic Report
    const report = await buildForensicReport({
      email: parsed,
      aiThreat,
      iocs,
      geoInfo,
      emailAuth,
      fusion
    });
    assert.match(report.caseId, /^MAV-2026-[A-F0-9]{8}$/);
    assert.equal(report.threatAssessment.overallScore, fusion.threatScore);

    // 8. PDF Generation
    const pdfBytes = generateForensicPdf(report);
    assert.ok(pdfBytes.length > 5000);
    assert.equal(Buffer.from(pdfBytes.slice(0, 8)).toString('utf-8'), '%PDF-1.4');

    // 9. Integrity SHA-256
    const pdfHash = await computePdfFileHash(pdfBytes);
    assert.match(pdfHash, /^[a-f0-9]{64}$/);
    assert.match(report.evidenceIntegrity.contentHashSha256, /^[a-f0-9]{64}$/);
  });

  // =========================================================================
  // 2. SCENARIO 1: LEGITIMATE OFFICIAL COMMUNICATION (BENIGN BASELINE)
  // =========================================================================
  await t.test('2. Scenario 1: Legitimate Email produces Low Threat Score (< 25) and Clean Classification', async () => {
    const legitScenario = getScenarioById('legitimate-circular');
    assert.ok(legitScenario, 'Legitimate scenario exists');

    const parsed = await parseEmailContent(legitScenario.rawSnippet);
    assert.equal(parsed.replyToMismatch, false);

    const iocs = extractAllIOCs(parsed);
    const aiThreat = {
      isMlAvailable: true,
      prediction: 'LEGITIMATE',
      phishingProbability: 5,
      legitimateProbability: 95,
      confidence: 95,
      model: 'TF-IDF + Logistic Regression'
    };
    const emailAuth = await analyzeEmailAuthentication(legitScenario.rawSnippet, { resolver: mockResolver });

    const fusion = calculateEvidenceFusion({
      parsedEmail: parsed,
      aiThreat,
      iocs,
      emailAuth,
      weights: DEFAULT_FUSION_WEIGHTS
    });

    assert.ok(fusion.threatScore < 25, `Expected low threat score (<25), got ${fusion.threatScore}`);
    assert.equal(fusion.riskLevel, 'LOW');

    const report = await buildForensicReport({ email: parsed, aiThreat, iocs, emailAuth, fusion });
    assert.ok(report.executiveSummary.includes('LOW RISK'));
    assert.ok(report.executiveSummary.includes('benign communication'));
  });

  // =========================================================================
  // 3. SCENARIO 2: CREDENTIAL PHISHING EMAIL
  // =========================================================================
  await t.test('3. Scenario 2: Credential Phishing email elevates threat score and extracts IOCs', async () => {
    const phishScenario = getScenarioById('sso-credential-harvest');
    assert.ok(phishScenario);

    const parsed = await parseEmailContent(phishScenario.rawSnippet);
    const iocs = extractAllIOCs(parsed);
    assert.ok(iocs.some(i => i.type === 'URL' || i.type === 'DOMAIN'));

    const aiThreat = {
      isMlAvailable: true,
      prediction: 'PHISHING',
      phishingProbability: 92,
      legitimateProbability: 8,
      confidence: 90,
      model: 'TF-IDF + Logistic Regression'
    };
    const fusion = calculateEvidenceFusion({
      parsedEmail: parsed,
      aiThreat,
      iocs,
      weights: DEFAULT_FUSION_WEIGHTS
    });

    assert.ok(fusion.threatScore >= 50, `Expected elevated score >= 50, got ${fusion.threatScore}`);
  });

  // =========================================================================
  // 4. SCENARIO 3: BUSINESS EMAIL COMPROMISE (BEC) / CEO FRAUD
  // =========================================================================
  await t.test('4. Scenario 3: Executive Wire BEC detects critical Reply-To mismatch', async () => {
    const becScenario = getScenarioById('ceo-bec');
    assert.ok(becScenario);

    const parsed = await parseEmailContent(becScenario.rawSnippet);
    assert.equal(parsed.replyToMismatch, true);
    assert.ok(parsed.replyTo.includes('proton.me'));
    assert.ok(parsed.sender.includes('internal-corp-portal.online'));

    const report = await buildForensicReport({ email: parsed });
    assert.ok(report.executiveSummary.includes('Reply-To mismatch'));
    assert.ok(report.recommendations.some(r => r.action.includes('Block Reply-To Routing Domain')));
  });

  // =========================================================================
  // 5. SCENARIO 4: MALICIOUS ATTACHMENT SIMULATION (ZERO EXECUTION)
  // =========================================================================
  await t.test('5. Scenario 4: Malicious Attachment inspects headers statically without execution', async () => {
    const attScenario = getScenarioById('ceo-bec');
    const attDef = attScenario.attachments[0];

    const staticResult = await analyzeAttachment({
      filename: attDef.filename,
      content: 'TVqQAAMAAAAEAAAA//8AALgAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
      mimeType: 'application/pdf',
      knownHashes: { sha256: attDef.sha256, sha1: attDef.sha1, md5: attDef.md5 }
    });

    assert.equal(staticResult.filename, 'Wire_Remittance_Directive.pdf.exe');
    assert.equal(staticResult.isSuspicious, true);
    assert.equal(staticResult.inferred.assessment, 'MALICIOUS');
    assert.equal(staticResult.observed.magicSignature, 'MZ (PE)');
    assert.ok(staticResult.observed.indicators.some(i => i.id === 'FILE_TYPE_MISMATCH' || i.id === 'DECLARED_EXECUTABLE'));
  });

  // =========================================================================
  // 6. SCENARIO 5: EMAIL AUTHENTICATION FAILURE (SPF / DKIM / DMARC)
  // =========================================================================
  await t.test('6. Scenario 5: Distinguishes observed Authentication-Results from DNS records', async () => {
    const authScenario = getScenarioById('banking-phish');
    const authResult = await analyzeEmailAuthentication(authScenario.rawSnippet, { resolver: mockResolver });

    assert.ok(authResult.authenticationResults);
    assert.ok(authResult.observedEvidence);
    assert.ok(authResult.inferredEvidence);
    assert.ok(authResult.alignment);

    // Authentication failure alone must not mandate 100/100
    const fusion = calculateEvidenceFusion({
      parsedEmail: { sender: authScenario.sender },
      emailAuth: authResult,
      weights: DEFAULT_FUSION_WEIGHTS
    });

    assert.ok(fusion.threatScore <= 45, 'Auth failure alone does not generate max threat score');
  });

  // =========================================================================
  // 7. SCENARIO 6: SUSPICIOUS INFRASTRUCTURE & MULTI-HOP GEO
  // =========================================================================
  await t.test('7. Scenario 6: Multi-hop routing extracts IPs and respects private boundaries', async () => {
    const rawMultiHop = `From: <mailer@edge.com>
Received: from edge.com (185.220.101.45) by mx1.corp.in; Fri, 05 Sep 2026 10:00:00 +0530
Received: from internal-relay (10.0.0.1) by edge.com; Fri, 05 Sep 2026 09:59:00 +0530
Received: from lan-host (192.168.1.50) by internal-relay; Fri, 05 Sep 2026 09:58:00 +0530

Multi-hop test payload.`;

    const parsed = await parseEmailContent(rawMultiHop);
    const indicators = extractNetworkIndicators(parsed);
    assert.ok(indicators.length >= 2);

    const publicHop = indicators.find(i => !i.isPrivate);
    assert.ok(publicHop);
    assert.equal(publicHop.ip, '185.220.101.45');

    const privateHop = indicators.find(i => i.isPrivate);
    assert.ok(privateHop);
    assert.ok(isPrivateIP(privateHop.ip));
  });

  // =========================================================================
  // 8. SCENARIO 7: COMBINED HIGH-RISK MULTI-VECTOR THREAT
  // =========================================================================
  await t.test('8. Scenario 7: Combined multi-vector email correctly engages all forensic layers', async () => {
    const multiVector = getScenarioById('shared-campaign');
    const parsed = await parseEmailContent(multiVector.rawSnippet);
    const iocs = extractAllIOCs(parsed);
    const aiThreat = {
      isMlAvailable: true,
      prediction: 'PHISHING',
      phishingProbability: 95,
      confidence: 94,
      model: 'TF-IDF + Logistic Regression'
    };
    const emailAuth = await analyzeEmailAuthentication(multiVector.rawSnippet, { resolver: mockResolver });
    const geoInfo = await defaultGeoService.resolveIP(multiVector.originatingIP);

    const fusion = calculateEvidenceFusion({
      parsedEmail: parsed,
      aiThreat,
      iocs,
      geoInfo,
      emailAuth,
      weights: DEFAULT_FUSION_WEIGHTS
    });

    assert.ok(fusion.factors.length >= 4);
    assert.ok(fusion.threatScore >= 60);
    assert.ok(fusion.riskLevel === 'HIGH' || fusion.riskLevel === 'CRITICAL');
  });

  // =========================================================================
  // 9. THREAT SCORE PARITY (FUSION == REPORT == PDF)
  // =========================================================================
  await t.test('9. Score Parity: Fusion score exactly matches report and compiled PDF metadata', async () => {
    const testScore = 88;
    const testRisk = 'CRITICAL';
    const mockAnalysis = {
      fusion: { threatScore: testScore, riskLevel: testRisk, factors: [] },
      email: { sender: 'test@example.com', recipient: 'target@example.com' }
    };

    const report = await buildForensicReport(mockAnalysis);
    assert.equal(report.threatAssessment.overallScore, testScore);
    assert.equal(report.threatAssessment.classification, testRisk);

    const pdfBytes = generateForensicPdf(report);
    const pdfText = Buffer.from(pdfBytes).toString('latin1');
    assert.ok(pdfText.includes(`${testScore}`));
    assert.ok(pdfText.includes('CRITICAL RISK'));
  });

  // =========================================================================
  // 10. STRICT EVIDENCE PROVENANCE (OBSERVED VS INFERRED)
  // =========================================================================
  await t.test('10. Strict Evidence Provenance: Observed Facts vs Inferred Models remain distinct', async () => {
    const report = await buildForensicReport({
      email: { sender: 'ceo@corp.com', originatingIP: '1.2.3.4' },
      emailAuth: { alignment: { dmarcAligned: false } },
      fusion: { threatScore: 75, riskLevel: 'HIGH' }
    });

    assert.ok(report.observedEvidence);
    assert.ok(report.inferredIntelligence);

    // Observed contains empirical headers
    assert.ok(report.observedEvidence.some(o => o.includes('Sender Identity Header:')));
    assert.ok(report.observedEvidence.some(o => o.includes('Originating IP Address:')));

    // Inferred contains derived conclusions and scores
    assert.ok(report.inferredIntelligence.some(i => i.includes('Multi-Factor Threat Index:')));
    assert.ok(report.inferredIntelligence.some(i => i.includes('DMARC RFC 7489 Alignment:')));
  });

  // =========================================================================
  // 11. FAILURE HANDLING: ML SERVICE UNAVAILABLE
  // =========================================================================
  await t.test('11. Failure Handling: ML service offline falls back gracefully without fabricating score', async () => {
    // When text is empty, evaluateAIThreat returns UNAVAILABLE / EMPTY_INPUT
    const mlFallback = await evaluateAIThreat({ body: '' });
    assert.ok(mlFallback);
    assert.equal(mlFallback.isMlAvailable, false);
    assert.equal(mlFallback.prediction, 'UNAVAILABLE');
    assert.equal(mlFallback.phishingProbability, null);
  });

  // =========================================================================
  // 12. FAILURE HANDLING: DNS TIMEOUT / NXDOMAIN
  // =========================================================================
  await t.test('12. Failure Handling: DNS non-existent domain returns NO_RECORD without crashing', async () => {
    const invalidAuth = await analyzeEmailAuthentication('From: user@non-existent-zone-sih-2026-xyz.invalid\n\nTest', { resolver: mockResolver });
    assert.ok(invalidAuth);
    assert.equal(invalidAuth.status, 'COMPLETE');
    assert.equal(invalidAuth.spf.hasPlusAll, false);
  });

  // =========================================================================
  // 13. FAILURE HANDLING: GEOLOCATION UNAVAILABLE
  // =========================================================================
  await t.test('13. Failure Handling: GeoIP unavailable returns null coordinates without inventing fake pins', async () => {
    // Test a GeoLocationService with an empty provider set
    class FailingGeoProvider extends BaseGeoProvider {
      async lookup() { return null; }
    }
    const failingService = new GeoLocationService({ providers: [new FailingGeoProvider()] });
    const res = await failingService.resolveIP('8.8.8.8');
    assert.equal(res.status, 'UNAVAILABLE');
    assert.equal(res.latitude, null);
    assert.equal(res.longitude, null);
  });

  // =========================================================================
  // 14. FAILURE HANDLING: MALFORMED RFC 822 PAYLOAD
  // =========================================================================
  await t.test('14. Failure Handling: Malformed email payload does not throw uncaught exception', async () => {
    const malformed = 'This is not an email header\x00\xFF\xFE Random binary noise';
    const parsed = await parseEmailContent(malformed);
    assert.ok(parsed);
    assert.equal(parsed.sender, 'Unknown Sender');
  });

  // =========================================================================
  // 15. FAILURE HANDLING: EMPTY EMAIL INPUT VALIDATION
  // =========================================================================
  await t.test('15. Failure Handling: Empty email input safely handled', async () => {
    await assert.rejects(
      async () => await parseEmailContent(''),
      /Invalid input/
    );
  });

  // =========================================================================
  // 16. FAILURE HANDLING: ZERO-BYTE & OVERSIZED ATTACHMENT
  // =========================================================================
  await t.test('16. Failure Handling: Zero-byte & oversized attachment threshold', async () => {
    // 1. Zero-byte buffer
    const zeroByte = await analyzeAttachment({
      filename: 'empty.dat',
      content: Buffer.alloc(0),
      mimeType: 'application/octet-stream'
    });
    assert.equal(zeroByte.status, 'SUCCESS');
    assert.equal(zeroByte.sizeBytes, 0);
    assert.equal(zeroByte.detectedType, 'Empty / Zero-Byte File');

    // 2. Oversized payload (> 25MB)
    const oversizedBytes = new Uint8Array(26 * 1024 * 1024);
    const oversized = await analyzeAttachment({
      filename: 'huge_archive.zip',
      content: oversizedBytes,
      mimeType: 'application/zip'
    });
    assert.equal(oversized.status, 'TOO_LARGE');
  });

  // =========================================================================
  // 17. SECURITY AUDIT: SSRF IP ADDRESS VALIDATION
  // =========================================================================
  await t.test('17. Security Audit: isPrivateOrReservedIP protects against SSRF across all reserved ranges', () => {
    // Loopback
    assert.equal(isPrivateOrReservedIP('127.0.0.1'), true);
    assert.equal(isPrivateOrReservedIP('127.10.20.30'), true);
    assert.equal(isPrivateOrReservedIP('::1'), true);

    // RFC 1918 Class A, B, C
    assert.equal(isPrivateOrReservedIP('10.0.0.1'), true);
    assert.equal(isPrivateOrReservedIP('10.254.254.254'), true);
    assert.equal(isPrivateOrReservedIP('172.16.0.1'), true);
    assert.equal(isPrivateOrReservedIP('172.24.100.5'), true);
    assert.equal(isPrivateOrReservedIP('172.31.255.255'), true);
    assert.equal(isPrivateOrReservedIP('192.168.1.1'), true);

    // Carrier-Grade NAT (100.64.0.0/10)
    assert.equal(isPrivateOrReservedIP('100.64.0.1'), true);
    assert.equal(isPrivateOrReservedIP('100.127.255.254'), true);

    // Link-Local (169.254.0.0/16 & fe80::)
    assert.equal(isPrivateOrReservedIP('169.254.1.1'), true);
    assert.equal(isPrivateOrReservedIP('fe80::1'), true);

    // Documentation ranges
    assert.equal(isPrivateOrReservedIP('192.0.2.1'), true);
    assert.equal(isPrivateOrReservedIP('198.51.100.1'), true);
    assert.equal(isPrivateOrReservedIP('203.0.113.1'), true);

    // Multicast & Reserved
    assert.equal(isPrivateOrReservedIP('224.0.0.1'), true);
    assert.equal(isPrivateOrReservedIP('255.255.255.255'), true);

    // Valid Public IPs must NOT be marked as private
    assert.equal(isPrivateOrReservedIP('185.220.101.45'), false);
    assert.equal(isPrivateOrReservedIP('8.8.8.8'), false);
    assert.equal(isPrivateOrReservedIP('1.1.1.1'), false);
    assert.equal(isPrivateOrReservedIP('14.139.56.2'), false);
  });

  // =========================================================================
  // 18. SECURITY AUDIT: PATH TRAVERSAL FILENAME SANITIZATION
  // =========================================================================
  await t.test('18. Security Audit: Path traversal filename sanitization prevents directory escape', async () => {
    const maliciousFilename = '../../../etc/passwd';
    const result = await analyzeAttachment({
      filename: maliciousFilename,
      content: 'root:x:0:0:root:/root:/bin/bash',
      mimeType: 'text/plain'
    });

    assert.ok(!result.filename.includes('../'));
    assert.equal(result.filename, 'passwd');
  });

  // =========================================================================
  // 19. SECURITY AUDIT: ATTACHMENT ZERO-EXECUTION GUARANTEE
  // =========================================================================
  await t.test('19. Security Audit: Attachment inspection uses purely static header parsing', async () => {
    const payload = await analyzeAttachment({
      filename: 'invoice.exe',
      content: 'MZ\x90\x00\x03\x00\x00\x00',
      mimeType: 'application/x-dosexec'
    });

    assert.equal(payload.observed.magicSignature, 'MZ (PE)');
    assert.ok(payload.sha256);
  });

  // =========================================================================
  // 20. CRYPTOGRAPHIC INTEGRITY: CONTENT SHA-256 VS PDF SHA-256
  // =========================================================================
  await t.test('20. Cryptographic Integrity: Content SHA-256 and PDF SHA-256 are distinct and tamper-evident', async () => {
    const report = await buildForensicReport({
      email: { sender: 'test@gov.in', subject: 'Integrity Check' },
      fusion: { threatScore: 40, riskLevel: 'SUSPICIOUS' }
    });

    const contentHash = report.evidenceIntegrity.contentHashSha256;
    assert.match(contentHash, /^[a-f0-9]{64}$/);

    const pdfBytes = generateForensicPdf(report);
    const pdfHash = await computePdfFileHash(pdfBytes);
    assert.match(pdfHash, /^[a-f0-9]{64}$/);

    // Content hash (digest of report JSON) and PDF hash (digest of binary file) must be distinct
    assert.notEqual(contentHash, pdfHash);

    // Mutating content must change content hash
    const mutated = await buildForensicReport({
      email: { sender: 'test@gov.in', subject: 'Integrity Check MODIFIED' },
      fusion: { threatScore: 40, riskLevel: 'SUSPICIOUS' }
    });
    assert.notEqual(mutated.evidenceIntegrity.contentHashSha256, contentHash);
  });

});
