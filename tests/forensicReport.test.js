/**
 * MAVERICK — Automated Forensic Reporting & Evidence Integrity Test Suite
 * Smart India Hackathon 2026
 * 
 * Verifies all forensic reporting, evidence integrity, and PDF generation capabilities:
 * 1. Case ID format validation (MAV-2026-XXXXXXXX)
 * 2. Case ID conversion from legacy CAS-2026-XXXX
 * 3. Case ID preservation if already valid
 * 4. Executive summary generation for high-risk / malicious incidents
 * 5. Executive summary generation for benign / low-risk communications
 * 6. Executive summary incorporates AI/ML prediction metrics
 * 7. Executive summary reflects SPF / DKIM / DMARC authentication verdicts
 * 8. Executive summary captures critical Reply-To mismatches
 * 9. Executive summary highlights obfuscated / high-risk attachment payloads
 * 10. Advisory recommendations generation and priority stratification
 * 11. Advisory recommendations include statutory evidence preservation
 * 12. Email metadata extraction and XSS string sanitization
 * 13. AI/ML threat telemetry mapping and confidence levels
 * 14. Live email authentication and DNS record mapping
 * 15. Domain alignment matrix (SPF, DKIM, DMARC) mapping
 * 16. Extracted IOC taxonomy, status, and confidence mapping
 * 17. GeoLocation & ASN network infrastructure with mandatory legal disclaimer
 * 18. Static attachment forensics with magic bytes and zero-execution inspection
 * 19. Strict partitioning: Observed Empirical Evidence facts
 * 20. Strict partitioning: Inferred Analytical Intelligence
 * 21. Multi-factor Evidence Fusion breakdown and total score calibration parity
 * 22. Investigation pipeline timeline audit sequence (8 stages)
 * 23. Real SHA-256 cryptographic content digest calculation
 * 24. Deterministic tamper detection (hash divergence upon content alteration)
 * 25. Null / empty / malformed analysisResult resilience (zero unhandled exceptions)
 * 26. Pure-JS PDF 1.4 binary stream generation (%PDF-1.4 header and %%EOF trailer)
 * 27. Multi-page document compilation (6 structured forensic sections)
 * 28. PDF binary file SHA-256 calculation
 * 29. End-to-end integration: full analysis -> forensic report -> PDF export
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import {
  buildForensicReport,
  generateCaseId,
  sanitizeReportString,
  synthesizeExecutiveSummary,
  generateAdvisoryRecommendations,
  computeSha256
} from '../src/services/forensicReportService.js';
import {
  generateForensicPdf,
  computePdfFileHash,
  escapePdfString,
  PdfDocument
} from '../src/services/pdfBuilder.js';
import { GEO_LEGAL_DISCLAIMER } from '../src/services/geoAsnService.js';

test('MAVERICK Automated Forensic Reporting & PDF Generation Suite', async (t) => {

  // Deterministic Mock Analysis Result
  const mockPhishingAnalysis = {
    caseItem: { caseId: 'CAS-2026-8841' },
    email: {
      sender: 'Satya N. <cfo-finance-update@internal-corp-portal.online>',
      recipient: 'treasury-controller@gov-organization.in',
      subject: 'URGENT: Executive Wire Authorization',
      date: 'Fri, 05 Sep 2026 11:41:50 +0530',
      messageId: '<SIH-2026-MIME-8841@local>',
      replyTo: 'external-offshore-treasury@proton.me',
      replyToMismatch: true,
      originatingIP: '185.220.101.45',
      receivedHops: [
        { hopNumber: 1, from: '185.220.101.45', by: 'mx1.mail.org', extractedIP: '185.220.101.45' }
      ],
      fromParsed: { domain: 'internal-corp-portal.online' },
      replyToParsed: { domain: 'proton.me' },
      returnPathParsed: { domain: 'internal-corp-portal.online' },
      attachments: [
        {
          filename: 'Executive_Invoice.pdf.exe',
          size: '245 KB',
          mimeType: 'application/pdf',
          detectedType: 'application/x-dosexec',
          sha256: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
          sha1: 'da39a3ee5e6b4b0d3255bfef95601890afd80709',
          md5: 'd41d8cd98f00b204e9800998ecf8427e',
          observed: { magicBytesHex: '4D 5A 90 00' },
          inferred: { extensionMismatch: true, assessment: 'MALICIOUS' },
          isSuspicious: true
        }
      ]
    },
    aiThreat: {
      isMlAvailable: true,
      prediction: 'PHISHING',
      phishingProbability: 94,
      legitimateProbability: 6,
      confidence: 92,
      model: 'TF-IDF + Logistic Regression',
      topFeatures: [
        { term: 'wire', weight: 3.2 },
        { term: 'urgent', weight: 2.8 }
      ],
      detectedIndicators: [{ token: 'wire transfer', category: 'Financial Coercion' }]
    },
    emailAuth: {
      fromDomain: 'internal-corp-portal.online',
      returnPathDomain: 'internal-corp-portal.online',
      spf: {
        status: 'SPF SOFTFAIL',
        domain: 'internal-corp-portal.online',
        record: 'v=spf1 include:_spf.google.com ~all',
        observedVerdict: 'softfail',
        hasPlusAll: false
      },
      dkim: {
        status: 'DKIM FAIL',
        domain: 'internal-corp-portal.online',
        selector: 's1',
        algorithm: 'rsa-sha256',
        dnsRecordFound: false,
        observedVerdict: 'fail'
      },
      dmarc: {
        status: 'DMARC FAIL (REJECT)',
        domain: 'internal-corp-portal.online',
        policy: 'reject',
        subdomainPolicy: 'reject',
        adkim: 'r',
        aspf: 'r',
        observedVerdict: 'fail'
      },
      alignment: {
        spfAligned: false,
        dkimAligned: false,
        dmarcAligned: false,
        spfMode: 'relaxed',
        dkimMode: 'relaxed'
      }
    },
    fusion: {
      threatScore: 92,
      riskLevel: 'CRITICAL',
      factors: [
        { id: 'ai', category: 'AI / NLP Analysis', name: 'Linguistic Urgency', points: 25, maxPoints: 25, severity: 'CRITICAL', evidence: 'High AI phishing probability (94%)' },
        { id: 'auth', category: 'Header Forensics', name: 'SPF/DKIM/DMARC Failure', points: 20, maxPoints: 20, severity: 'CRITICAL', evidence: 'Authentication failed' },
        { id: 'att', category: 'Attachment Analysis', name: 'Obfuscated PE Binary', points: 10, maxPoints: 10, severity: 'CRITICAL', evidence: 'Double-extension executable' }
      ],
      verifiedReasons: ['AI flagged phishing language', 'SPF softfail and DKIM failure', 'Executable payload detected']
    },
    geoInfo: {
      ip: '185.220.101.45',
      country: 'Germany',
      city: 'Frankfurt',
      asn: 'AS9009',
      asnOrg: 'M247 Ltd Europe',
      networkType: 'Tor Exit Node / Anonymizing Relay',
      isProxyOrVpn: true,
      lat: 50.1109,
      lon: 8.6821
    },
    iocs: [
      { type: 'IP', value: '185.220.101.45', source: 'Received Header', status: 'MALICIOUS', confidence: 95 },
      { type: 'DOMAIN', value: 'internal-corp-portal.online', source: 'From Header', status: 'SUSPICIOUS', confidence: 85 },
      { type: 'HASH', value: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855', source: 'Attachment', status: 'MALICIOUS', confidence: 99 }
    ]
  };

  // Test 1: Case ID Format
  await t.test('1. Generates standardized Case ID matching MAV-2026-XXXXXXXX', () => {
    const id = generateCaseId();
    assert.match(id, /^MAV-2026-[A-F0-9]{8}$/);
  });

  // Test 2: Case ID Conversion from legacy CAS-2026-XXXX
  await t.test('2. Converts legacy CAS-2026-XXXX to MAV-2026-XXXXXXXX hex format', () => {
    const id = generateCaseId('CAS-2026-8841');
    assert.match(id, /^MAV-2026-[A-F0-9]{8}$/);
    assert.equal(id, 'MAV-2026-00002289'); // 8841 in hex is 0x2289
  });

  // Test 3: Case ID Preservation
  await t.test('3. Preserves existing valid MAV-2026-XXXXXXXX format', () => {
    const validId = 'MAV-2026-A1B2C3D4';
    assert.equal(generateCaseId(validId), validId);
  });

  // Test 4: Executive Summary Generation for High-Risk Email
  await t.test('4. Synthesizes cautious investigator-grade executive summary for critical threat', () => {
    const summary = synthesizeExecutiveSummary({
      threatScore: 92,
      riskLevel: 'CRITICAL',
      email: mockPhishingAnalysis.email,
      aiThreat: mockPhishingAnalysis.aiThreat,
      emailAuth: mockPhishingAnalysis.emailAuth,
      attachments: mockPhishingAnalysis.email.attachments,
      iocs: mockPhishingAnalysis.iocs,
      geoInfo: mockPhishingAnalysis.geoInfo
    });

    assert.ok(summary.includes('92/100 (CRITICAL RISK)'));
    assert.ok(summary.includes('internal-corp-portal.online'));
    assert.ok(summary.includes('treasury-controller@gov-organization.in'));
    assert.ok(summary.includes('traceable to verified cryptographic signatures'));
  });

  // Test 5: Executive Summary Generation for Benign Email
  await t.test('5. Synthesizes objective summary for low-risk benign email', () => {
    const summary = synthesizeExecutiveSummary({
      threatScore: 10,
      riskLevel: 'LOW',
      email: { recipient: 'user@example.com', fromParsed: { domain: 'example.com' } },
      aiThreat: { isMlAvailable: true, phishingProbability: 12 },
      emailAuth: { spf: { observedVerdict: 'pass' }, dkim: { observedVerdict: 'pass' }, dmarc: { observedVerdict: 'pass' } }
    });

    assert.ok(summary.includes('10/100 (LOW RISK)'));
    assert.ok(summary.includes('benign communication'));
  });

  // Test 6: Executive Summary AI Telemetry
  await t.test('6. Incorporates machine learning probability into executive summary', () => {
    const summary = synthesizeExecutiveSummary({
      threatScore: 85,
      riskLevel: 'HIGH',
      email: { fromParsed: { domain: 'bank-alert.com' } },
      aiThreat: { isMlAvailable: true, phishingProbability: 88 }
    });
    assert.ok(summary.includes('88%'));
    assert.ok(summary.includes('machine learning'));
  });

  // Test 7: Executive Summary Authentication Protocol Failures
  await t.test('7. Highlights SPF/DKIM/DMARC failures in executive summary', () => {
    const summary = synthesizeExecutiveSummary({
      threatScore: 75,
      riskLevel: 'HIGH',
      email: {},
      emailAuth: {
        spf: { observedVerdict: 'fail' },
        dkim: { observedVerdict: 'fail' },
        dmarc: { observedVerdict: 'fail' }
      }
    });
    assert.ok(summary.includes('SPF (FAIL)'));
    assert.ok(summary.includes('DKIM signature verification failure'));
    assert.ok(summary.includes('DMARC policy alignment failure'));
  });

  // Test 8: Executive Summary Reply-To Mismatch
  await t.test('8. Flags Reply-To mismatch destination in executive summary', () => {
    const summary = synthesizeExecutiveSummary({
      threatScore: 80,
      riskLevel: 'HIGH',
      email: { replyToMismatch: true, replyTo: 'attacker@evil.com', replyToParsed: { domain: 'evil.com' } }
    });
    assert.ok(summary.includes('Reply-To mismatch'));
    assert.ok(summary.includes('evil.com'));
  });

  // Test 9: Executive Summary Malicious Attachment
  await t.test('9. Cites malicious attachment filename and detection flag in summary', () => {
    const summary = synthesizeExecutiveSummary({
      threatScore: 90,
      riskLevel: 'CRITICAL',
      email: {},
      attachments: [{ filename: 'malware.exe', isSuspicious: true, riskAssessment: 'CRITICAL', flag: 'executable PE payload' }]
    });
    assert.ok(summary.includes('malware.exe'));
    assert.ok(summary.includes('executable PE payload'));
  });

  // Test 10: Advisory Recommendations Prioritization
  await t.test('10. Generates prioritized advisory recommendations with actionable rationale', () => {
    const recs = generateAdvisoryRecommendations({
      threatScore: 92,
      riskLevel: 'CRITICAL',
      email: mockPhishingAnalysis.email,
      emailAuth: mockPhishingAnalysis.emailAuth,
      attachments: mockPhishingAnalysis.email.attachments,
      iocs: mockPhishingAnalysis.iocs,
      geoInfo: mockPhishingAnalysis.geoInfo
    });

    assert.ok(recs.length >= 4);
    assert.equal(recs[0].priority, 'CRITICAL');
    assert.ok(recs.some(r => r.action.includes('Quarantine Ingress Message')));
    assert.ok(recs.some(r => r.action.includes('Block Reply-To Routing Domain')));
    assert.ok(recs.some(r => r.action.includes('Isolate Payload & Query EDR')));
  });

  // Test 11: Statutory Compliance Recommendation Always Included
  await t.test('11. Always includes statutory RFC 822 chain of custody recommendation', () => {
    const recs = generateAdvisoryRecommendations({ threatScore: 0, riskLevel: 'LOW' });
    const comp = recs.find(r => r.priority === 'COMPLIANCE');
    assert.ok(comp);
    assert.ok(comp.action.includes('Preserve Cryptographic RFC 822 MIME Artifact'));
  });

  // Test 12: String Sanitization against XSS
  await t.test('12. Sanitizes malicious script tags and event handlers from strings', () => {
    const malicious = 'Invoice <script>alert("xss")</script> <style>body{}</style> javascript:void(0)';
    const clean = sanitizeReportString(malicious);
    assert.ok(!clean.includes('<script>'));
    assert.ok(!clean.includes('javascript:'));
    assert.ok(!clean.includes('<style>'));
    assert.ok(clean.includes('Invoice'));
  });

  // Test 13: Full Report Data Model Compilation
  const report = await buildForensicReport(mockPhishingAnalysis);

  await t.test('13. Builds complete forensic report model with valid MAV-2026 Case ID', () => {
    assert.ok(report);
    assert.match(report.caseId, /^MAV-2026-[A-F0-9]{8}$/);
    assert.equal(report.status, 'INVESTIGATION COMPLETE');
    assert.ok(report.generatedAt);
  });

  // Test 14: Score Parity with Evidence Fusion
  await t.test('14. Threat assessment score precisely matches Evidence Fusion score', () => {
    assert.equal(report.threatAssessment.overallScore, mockPhishingAnalysis.fusion.threatScore);
    assert.equal(report.threatAssessment.classification, mockPhishingAnalysis.fusion.riskLevel);
    assert.equal(report.evidenceFusion.threatScore, 92);
  });

  // Test 15: AI/ML Threat Telemetry
  await t.test('15. Accurately maps real AI/ML threat probabilities and linguistic tokens', () => {
    assert.equal(report.mlAnalysis.status, 'ACTIVE');
    assert.equal(report.mlAnalysis.phishingProbability, 94);
    assert.equal(report.mlAnalysis.legitimateProbability, 6);
    assert.equal(report.mlAnalysis.confidence, 92);
    assert.equal(report.mlAnalysis.model, 'TF-IDF + Logistic Regression');
    assert.ok(report.mlAnalysis.topFeatures.length > 0);
  });

  // Test 16: Live Email Authentication Mapping
  await t.test('16. Maps SPF, DKIM, and DMARC authentication verdicts correctly', () => {
    assert.equal(report.emailAuthentication.spf.status, 'SPF SOFTFAIL');
    assert.equal(report.emailAuthentication.dkim.status, 'DKIM FAIL');
    assert.equal(report.emailAuthentication.dmarc.policy, 'reject');
    assert.equal(report.emailAuthentication.alignment.spfAligned, false);
    assert.equal(report.emailAuthentication.alignment.dkimAligned, false);
    assert.equal(report.emailAuthentication.alignment.dmarcAligned, false);
  });

  // Test 17: Extracted IOC Analysis
  await t.test('17. Captures extracted IOCs with type, value, and confidence', () => {
    assert.equal(report.iocAnalysis.length, 3);
    const ipIoc = report.iocAnalysis.find(i => i.type === 'IP');
    assert.ok(ipIoc);
    assert.equal(ipIoc.value, '185.220.101.45');
    assert.equal(ipIoc.risk, 'MALICIOUS');
  });

  // Test 18: GeoLocation & Infrastructure Telemetry
  await t.test('18. Includes network topology, ASN, and mandatory non-bias disclaimer', () => {
    assert.equal(report.geoLocationAnalysis.status, 'RESOLVED');
    assert.equal(report.geoLocationAnalysis.primaryNode.country, 'Germany');
    assert.equal(report.geoLocationAnalysis.primaryNode.asn, 'AS9009');
    assert.equal(report.geoLocationAnalysis.primaryNode.isProxyOrVpn, true);
    assert.equal(report.geoLocationAnalysis.disclaimer, GEO_LEGAL_DISCLAIMER);
  });

  // Test 19: Static Attachment Forensics
  await t.test('19. Accurately details static attachment headers without payload execution', () => {
    assert.equal(report.attachmentAnalysis.count, 1);
    const att = report.attachmentAnalysis.attachments[0];
    assert.equal(att.filename, 'Executive_Invoice.pdf.exe');
    assert.equal(att.magicBytes, '4D 5A 90 00');
    assert.equal(att.extensionMismatch, true);
    assert.equal(att.riskAssessment, 'MALICIOUS');
    assert.ok(att.sha256);
  });

  // Test 20: Strict Partitioning of Observed Evidence
  await t.test('20. Observed Evidence section strictly contains empirical raw header/DNS facts', () => {
    const obs = report.observedEvidence;
    assert.ok(obs.length >= 5);
    assert.ok(obs.some(o => o.includes('Sender Identity Header:')));
    assert.ok(obs.some(o => o.includes('Originating IP Address:')));
    assert.ok(obs.some(o => o.includes('Attachment SHA-256')));
    // Must NOT contain probabilistic language
    assert.ok(!obs.some(o => o.toLowerCase().includes('probabilistic risk')));
  });

  // Test 21: Strict Partitioning of Inferred Intelligence
  await t.test('21. Inferred Intelligence section contains analytical models and scores', () => {
    const inf = report.inferredIntelligence;
    assert.ok(inf.length >= 3);
    assert.ok(inf.some(i => i.includes('Multi-Factor Threat Index:')));
    assert.ok(inf.some(i => i.includes('ML NLP Phishing Probability:')));
    assert.ok(inf.some(i => i.includes('Alignment:')));
  });

  // Test 22: Investigation Execution Timeline
  await t.test('22. Builds 8-step sequential investigation audit timeline', () => {
    assert.equal(report.investigationTimeline.length, 8);
    assert.equal(report.investigationTimeline[0].step, 1);
    assert.equal(report.investigationTimeline[7].step, 8);
    assert.ok(report.investigationTimeline.every(s => s.status));
  });

  // Test 23: SHA-256 Integrity Hash Computation
  await t.test('23. Computes real 64-hex-character SHA-256 content integrity hash', () => {
    const hash = report.evidenceIntegrity.contentHashSha256;
    assert.match(hash, /^[a-f0-9]{64}$/);
    assert.ok(report.evidenceIntegrity.digitalSignature.startsWith('SHA256:'));
  });

  // Test 24: Tamper Detection (Hash Divergence)
  await t.test('24. Tamper detection: hash divergence when analysis content is altered', async () => {
    const originalHash = report.evidenceIntegrity.contentHashSha256;
    
    // Create mutated clone
    const mutated = JSON.parse(JSON.stringify(mockPhishingAnalysis));
    mutated.fusion.threatScore = 30; // Tampered threat score
    const mutatedReport = await buildForensicReport(mutated);
    
    assert.notEqual(mutatedReport.evidenceIntegrity.contentHashSha256, originalHash);
  });

  // Test 25: Resilient Handling of Null / Empty Input
  await t.test('25. Handles null, empty, or undefined input gracefully without throwing', async () => {
    const emptyReport = await buildForensicReport(null);
    assert.ok(emptyReport);
    assert.match(emptyReport.caseId, /^MAV-2026-[A-F0-9]{8}$/);
    assert.equal(emptyReport.threatAssessment.overallScore, 0);
    assert.equal(emptyReport.threatAssessment.classification, 'LOW');
    assert.ok(emptyReport.evidenceIntegrity.contentHashSha256);
  });

  // Test 26: Pure-JS PDF 1.4 Binary Stream Generation
  const pdfBytes = generateForensicPdf(report);

  await t.test('26. Generates valid PDF 1.4 binary stream with correct magic header & EOF trailer', () => {
    assert.ok(pdfBytes instanceof Uint8Array);
    assert.ok(pdfBytes.length > 5000, `PDF size ${pdfBytes.length} too small`);
    
    const headerStr = Buffer.from(pdfBytes.slice(0, 8)).toString('utf-8');
    assert.equal(headerStr, '%PDF-1.4');

    const tailStr = Buffer.from(pdfBytes.slice(-100)).toString('utf-8');
    assert.ok(tailStr.includes('%%EOF'));
    assert.ok(tailStr.includes('startxref'));
  });

  // Test 27: Multi-Page PDF Document Structure
  await t.test('27. Verifies 6-page PDF document structure and catalog cross-references', () => {
    const fullPdfStr = Buffer.from(pdfBytes).toString('latin1');
    assert.ok(fullPdfStr.includes('/Count 6'), 'Should contain 6 pages in root catalog');
    assert.ok(fullPdfStr.includes('MAVERICK THREAT INTELLIGENCE & FORENSIC DOSSIER'));
    assert.ok(fullPdfStr.includes('Page 1 of 6'));
    assert.ok(fullPdfStr.includes('Page 6 of 6'));
  });

  // Test 28: PDF File SHA-256 Hash Computation
  await t.test('28. Computes valid SHA-256 hash of compiled PDF binary bytes', async () => {
    const fileHash = await computePdfFileHash(pdfBytes);
    assert.match(fileHash, /^[a-f0-9]{64}$/);
  });

  // Test 29: End-to-End Ingestion -> Report -> PDF Pipeline
  await t.test('29. End-to-End Pipeline: produces certified forensic report and PDF export', async () => {
    const endToEndReport = await buildForensicReport(mockPhishingAnalysis, { caseId: 'MAV-2026-99999999' });
    assert.equal(endToEndReport.caseId, 'MAV-2026-99999999');
    
    const docBytes = generateForensicPdf(endToEndReport);
    assert.ok(docBytes.length > 10000);

    const docHash = await computePdfFileHash(docBytes);
    assert.ok(docHash);
    assert.match(docHash, /^[a-f0-9]{64}$/);
  });

});
