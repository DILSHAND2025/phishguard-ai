/**
 * MAVERICK — Static Attachment Forensic Analysis Test Suite
 * Smart India Hackathon 2026
 * 
 * Verifies all 12 required test conditions using safe synthetic in-memory fixtures:
 * 1. Normal PDF
 * 2. Normal image
 * 3. Office document
 * 4. Extension mismatch
 * 5. Archive
 * 6. Multiple attachments
 * 7. Empty attachment
 * 8. Large attachment (>25MB)
 * 9. Invalid MIME type
 * 10. Path traversal filename
 * 11. Unknown hash reputation
 * 12. Threat-intelligence API unavailable
 * 
 * Plus: Complete Integration Test (Email -> Attachment -> SHA256 -> Static Analysis -> Fusion)
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import {
  analyzeAttachment,
  sanitizeFilename,
  detectMagicBytes,
  validateFileTypeConsistency,
  MAX_SAFE_FILE_SIZE
} from '../src/services/attachmentForensics.js';
import {
  HashReputationService,
  GatewayHashProvider,
  BaseReputationProvider
} from '../src/services/hashReputationService.js';
import { parseEmailContent } from '../src/services/emailParser.js';
import { extractAllIOCs } from '../src/services/iocExtractor.js';
import { evaluateAIThreat } from '../src/services/aiThreatModel.js';
import { resolveIPGeo } from '../src/services/geoAsnService.js';
import { calculateEvidenceFusion, DEFAULT_FUSION_WEIGHTS } from '../src/services/evidenceFusion.js';

test('MAVERICK Static Attachment Forensic Analysis Suite', async (t) => {

  // 1. Normal PDF
  await t.test('1. Normal benign PDF static analysis', async () => {
    const cleanPdf = Buffer.from('%PDF-1.4\n1 0 obj\n<< /Title (Invoice 2026) >>\nendobj\ntrailer\n<< >>\n%%EOF');
    const result = await analyzeAttachment({
      filename: 'invoice_2026.pdf',
      content: cleanPdf,
      mimeType: 'application/pdf',
      index: 0
    });

    assert.equal(result.status, 'SUCCESS');
    assert.equal(result.filename, 'invoice_2026.pdf');
    assert.ok(result.detectedType.includes('PDF'), `Should detect PDF type, got: ${result.detectedType}`);
    assert.equal(result.isSuspicious, false);
    assert.equal(result.inferred.assessment, 'CLEAN');
    assert.ok(result.sha256 && result.sha256.length === 64, 'SHA-256 computed');
    assert.ok(result.observed.indicators.some(i => i.id === 'PDF_NO_JS'), 'Observed clean no-JS indicator');
  });

  // 2. Normal Image
  await t.test('2. Normal image static analysis', async () => {
    const cleanPng = Buffer.from([
      0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, // PNG Header
      0x00, 0x00, 0x00, 0x0D, 0x49, 0x48, 0x44, 0x52  // IHDR chunk
    ]);
    const result = await analyzeAttachment({
      filename: 'organization_seal.png',
      content: cleanPng,
      mimeType: 'image/png',
      index: 0
    });

    assert.equal(result.status, 'SUCCESS');
    assert.ok(result.detectedType.includes('PNG'), `Should detect PNG, got: ${result.detectedType}`);
    assert.equal(result.isSuspicious, false);
    assert.equal(result.inferred.assessment, 'CLEAN');
  });

  // 3. Office Document (Macro presence)
  await t.test('3. Office document with embedded VBA macro', async () => {
    const macroDoc = Buffer.from('PK\x03\x04\x14\x00\x00\x00\x08\x00word/vbaProject.binAutoOpenDocument_Open');
    const result = await analyzeAttachment({
      filename: 'statutory_remittance.docm',
      content: macroDoc,
      mimeType: 'application/vnd.ms-word.document.macroEnabled.12',
      index: 0
    });

    assert.equal(result.status, 'SUCCESS');
    assert.equal(result.isSuspicious, true);
    assert.equal(result.inferred.assessment, 'MALICIOUS');
    assert.ok(result.observed.indicators.some(i => i.id === 'OFFICE_MACRO_DETECTED'), 'Flagged VBA macro code');
  });

  // 4. Extension Mismatch (Executable disguised as PDF)
  await t.test('4. Critical extension mismatch detection (invoice.pdf with PE header)', async () => {
    // DOS / PE executable header
    const fakePdfBytes = Buffer.from('MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00\xb8\x00\x00\x00\x00\x00\x00\x00@\x00\x00\x00');
    const result = await analyzeAttachment({
      filename: 'invoice.pdf',
      content: fakePdfBytes,
      mimeType: 'application/pdf',
      index: 0
    });

    assert.equal(result.status, 'SUCCESS');
    assert.equal(result.isSuspicious, true);
    assert.equal(result.inferred.assessment, 'MALICIOUS');
    assert.ok(result.detectedType.includes('Executable'), 'Detected real type is Executable');
    assert.ok(result.observed.indicators.some(i => i.id === 'FILE_TYPE_MISMATCH'), 'Flagged file type mismatch');
  });

  // 5. Archive (ZIP containing executable binary)
  await t.test('5. Compressed archive containing enclosed executable payload', async () => {
    // Synthetic ZIP containing payload.exe entry
    const zipWithExe = Buffer.from([
      0x50, 0x4B, 0x03, 0x04, // PK\x03\x04
      0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x0B, 0x00, // Name length: 11
      0x00, 0x00, // Extra field length: 0
      0x70, 0x61, 0x79, 0x6C, 0x6F, 0x61, 0x64, 0x2E, 0x65, 0x78, 0x65 // "payload.exe"
    ]);

    const result = await analyzeAttachment({
      filename: 'tax_audit_bundle.zip',
      content: zipWithExe,
      mimeType: 'application/zip',
      index: 0
    });

    assert.equal(result.status, 'SUCCESS');
    assert.equal(result.isSuspicious, true);
    assert.ok(result.observed.indicators.some(i => i.id === 'ARCHIVE_CONTAINS_EXECUTABLE'), 'Detected executable in archive');
  });

  // 6. Multiple Attachments
  await t.test('6. Multiple attachments email extraction and independent forensic records', async () => {
    const multiBoundaryEmail = `Content-Type: multipart/mixed; boundary="BOUNDARY123"

--BOUNDARY123
Content-Type: text/plain

Please find attachments.

--BOUNDARY123
Content-Type: application/pdf
Content-Disposition: attachment; filename="document_a.pdf"
Content-Transfer-Encoding: base64

JVBERi0xLjQKMSAwIG9iago8PCAvVGl0bGUgKEEpID4+CmVuZG9iagp0cmFpbGVyCjw8ID4+CiUlRU9G

--BOUNDARY123
Content-Type: application/octet-stream
Content-Disposition: attachment; filename="patch_installer.exe"
Content-Transfer-Encoding: base64

TVqQAAMAAAAEAAAA//8AALgAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=

--BOUNDARY123
Content-Type: image/png
Content-Disposition: attachment; filename="logo.png"
Content-Transfer-Encoding: base64

iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg==

--BOUNDARY123--`;

    const parsed = await parseEmailContent(multiBoundaryEmail);
    assert.equal(parsed.attachments.length, 3, 'All 3 attachments extracted');
    assert.equal(parsed.attachments[0].filename, 'document_a.pdf');
    assert.equal(parsed.attachments[1].filename, 'patch_installer.exe');
    assert.equal(parsed.attachments[2].filename, 'logo.png');

    assert.equal(parsed.attachments[0].isSuspicious, false, 'document_a.pdf is clean');
    assert.equal(parsed.attachments[1].isSuspicious, true, 'patch_installer.exe is flagged');
    assert.equal(parsed.attachments[2].isSuspicious, false, 'logo.png is clean');
  });

  // 7. Empty Attachment
  await t.test('7. Empty zero-byte attachment handling', async () => {
    const emptyBytes = Buffer.alloc(0);
    const result = await analyzeAttachment({
      filename: 'empty_notice.txt',
      content: emptyBytes,
      mimeType: 'text/plain',
      index: 0
    });

    assert.equal(result.status, 'SUCCESS');
    assert.equal(result.sizeBytes, 0);
    assert.equal(result.detectedType, 'Empty / Zero-Byte File');
    assert.equal(result.isSuspicious, false);
  });

  // 8. Large Attachment (>25MB Safe Rejection)
  await t.test('8. Excessively large attachment safe threshold rejection', async () => {
    // 26 MB simulated attachment
    const largeBuffer = Buffer.alloc(26 * 1024 * 1024);
    const result = await analyzeAttachment({
      filename: 'gigantic_disk_dump.iso',
      content: largeBuffer,
      mimeType: 'application/x-iso9660-image',
      index: 0
    });

    assert.equal(result.status, 'TOO_LARGE');
    assert.equal(result.error, 'File too large for static analysis');
    assert.ok(result.size.includes('26.0 MB'));
  });

  // 9. Invalid / Spoofed MIME Type
  await t.test('9. Invalid MIME type handling', async () => {
    const cleanPdf = Buffer.from('%PDF-1.4\n1 0 obj\n<< /Title (Invoice) >>\nendobj\ntrailer\n<< >>\n%%EOF');
    const result = await analyzeAttachment({
      filename: 'invoice.pdf',
      content: cleanPdf,
      mimeType: 'corrupted/non-existent-mime-format-xyz',
      index: 0
    });

    assert.equal(result.status, 'SUCCESS');
    assert.ok(result.detectedType.includes('PDF'), 'Resolved true file type from magic bytes despite invalid MIME');
  });

  // 10. Path Traversal Filename
  await t.test('10. Path traversal filename sanitization (../../malicious.exe)', async () => {
    const result = await analyzeAttachment({
      filename: '../../../../etc/cron.d/malicious.exe',
      content: null,
      mimeType: 'application/octet-stream',
      index: 0
    });

    assert.equal(result.filename, 'malicious.exe', 'Sanitized filename to basename only');
    assert.equal(result.isSuspicious, true);
    assert.ok(result.observed.indicators.some(i => i.id === 'PATH_TRAVERSAL_FILENAME'), 'Observed path traversal indicator');
  });

  // 11. Unknown Hash Reputation
  await t.test('11. Unknown hash reputation handling', async () => {
    class MockUnknownProvider extends BaseReputationProvider {
      constructor() { super('Mock Unknown Provider'); }
      async lookup(hash) {
        return {
          status: 'SUCCESS',
          verdict: 'UNKNOWN',
          score: '0/72',
          details: 'Zero reputation history in threat intelligence feeds'
        };
      }
    }

    const service = new HashReputationService(new MockUnknownProvider());
    const rep = await service.checkHash('e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855');

    assert.equal(rep.status, 'SUCCESS');
    assert.equal(rep.verdict, 'UNKNOWN');
    assert.equal(rep.score, '0/72');
    assert.ok(rep.details.includes('Zero reputation'));
  });

  // 12. Threat-Intelligence API Unavailable
  await t.test('12. Threat-intelligence API unavailable handling (Never fabricates)', async () => {
    // Provider pointing to inactive local port
    const offlineProvider = new GatewayHashProvider('http://127.0.0.1:59999');
    const service = new HashReputationService(offlineProvider);

    const rep = await service.checkHash('8f4c102948a7b6c5d4e3f27d1a293b6e8f4c102948a7b6c5d4e3f27d1a293b6e');

    assert.equal(rep.status, 'UNAVAILABLE');
    assert.equal(rep.verdict, 'UNAVAILABLE');
    assert.ok(rep.details.includes('offline') || rep.details.includes('unreachable') || rep.details.includes('UNAVAILABLE'));
  });

  // 13. Complete End-to-End Forensic Flow Integration
  await t.test('13. Complete Forensic Flow (Email -> Attachments -> SHA256 -> ML -> Geo -> Evidence Fusion)', async () => {
    const fullForensicEml = `From: "Satya N." <cfo@internal-corp-portal.online>
Reply-To: <external-offshore-treasury@proton.me>
To: <treasury-controller@gov-organization.in>
Subject: URGENT: Wire Authorization - INR 4,85,00,000
Date: Fri, 05 Sep 2026 11:41:50 +0530
Received: from mail.internal-corp-portal.online (185.220.101.45) by mail.gov.in; Fri, 05 Sep 2026 11:41:50 +0530
Received-SPF: softfail
Authentication-Results: mail.gov.in; dkim=fail; dmarc=fail
Content-Type: multipart/mixed; boundary="E2E_MIME_BOUND"

--E2E_MIME_BOUND
Content-Type: text/plain

Expedite statutory allocation transfer of INR 4,85,00,000 immediately. Ministerial Directive bypass applied.

--E2E_MIME_BOUND
Content-Type: application/octet-stream
Content-Disposition: attachment; filename="Directive_Authorization.pdf.exe"
Content-Transfer-Encoding: base64

TVqQAAMAAAAEAAAA//8AALgAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=

--E2E_MIME_BOUND--`;

    // Step A: Parse email and extract attachments with static forensics
    const parsed = await parseEmailContent(fullForensicEml);
    assert.equal(parsed.attachments.length, 1, 'Extracted attachment');
    const att = parsed.attachments[0];
    assert.equal(att.filename, 'Directive_Authorization.pdf.exe');
    assert.ok(att.sha256 && att.sha256.length === 64, 'Computed SHA-256');
    assert.equal(att.isSuspicious, true, 'Flagged double extension executable');

    // Step B: IOC Extraction
    const iocs = extractAllIOCs(parsed);
    assert.ok(iocs.some(i => i.type === 'ATTACHMENT'), 'Attachment IOC extracted');
    assert.ok(iocs.some(i => i.type === 'HASH (SHA256)'), 'SHA256 IOC extracted');

    // Step C: ML Threat Detection
    const aiThreat = await evaluateAIThreat(parsed);
    assert.ok(typeof aiThreat.phishingProbability === 'number' || aiThreat.status === 'UNAVAILABLE');

    // Step D: GeoLocation
    const geo = await resolveIPGeo(parsed.originatingIP);
    assert.equal(geo.country, 'Germany');

    // Step E: Evidence Fusion
    const fusion = calculateEvidenceFusion({
      parsedEmail: parsed,
      aiThreat,
      iocs,
      geoInfo: geo,
      weights: DEFAULT_FUSION_WEIGHTS
    });

    assert.equal(fusion.factors.length, 6, 'All 6 evidence layers present');
    
    // Verify Attachment layer specifically
    const attFactor = fusion.factors.find(f => f.id === 'attachment-analysis');
    assert.ok(attFactor, 'Attachment analysis layer present in factor ledger');
    assert.equal(attFactor.points, 10, 'Full 10 points assigned to suspicious attachment payload');
    assert.equal(attFactor.status, 'FLAGGED');
    assert.ok(attFactor.evidence.includes('Directive_Authorization.pdf.exe'));

    // Verify overall threat classification
    assert.ok(fusion.threatScore >= 65, `Threat score should be >= 65, got ${fusion.threatScore}`);
    assert.ok(fusion.riskLevel === 'HIGH' || fusion.riskLevel === 'CRITICAL');
  });

});
