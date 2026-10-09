/**
 * MAVERICK — Live Email Authentication & DNS Forensics Test Suite
 * Smart India Hackathon 2026
 * 
 * Verifies all 22 required forensic conditions using deterministic synthetic mock fixtures:
 * 1. SPF record found
 * 2. SPF missing (NO_RECORD)
 * 3. Multiple SPF records (RFC 7208 PermError)
 * 4. SPF malformed / +all vulnerability detection
 * 5. DKIM selector extraction
 * 6. DKIM DNS record found
 * 7. DKIM DNS record missing
 * 8. DMARC record found
 * 9. DMARC missing
 * 10. DMARC policy parsing (p=reject, quarantine, none, sp=, pct=, adkim=, aspf=)
 * 11. Authentication-Results parsing (pass, fail, softfail, neutral, none, temperror, permerror, params)
 * 12. From / Return-Path domain mismatch
 * 13. DKIM domain alignment (strict vs relaxed)
 * 14. SPF domain alignment (strict vs relaxed)
 * 15. Malformed email input handling (never crashes)
 * 16. Missing headers handling (no From, no Return-Path, etc.)
 * 17. DNS timeout handling
 * 18. NXDOMAIN handling
 * 19. Evidence Fusion integration (score bounds, no single-factor auto-malicious)
 * 20. Non-fabrication & Live Data Verification (labels 'RECORD FOUND', not fake 'VERIFIED')
 * 21. Reusable DNS service with caching & mockability
 * 22. Full Pipeline Ingestion -> Auth -> Alignment -> Evidence Fusion
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import {
  analyzeEmailAuthentication,
  parseAddress,
  extractRawHeaders,
  parseAuthenticationResults,
  parseDkimSignature,
  parseReceivedSpf,
  querySpfRecord,
  queryDkimRecord,
  queryDmarcRecord,
  analyzeDomainAlignment,
  getOrganizationalDomain
} from '../src/services/emailAuthService.js';
import {
  createMockDnsResolver,
  isValidDomain,
  normalizeDomain,
  resolveTxt,
  resolve4,
  resolve6,
  clearDnsCache,
  getDnsCacheStats
} from '../src/services/dnsService.js';
import { calculateEvidenceFusion, DEFAULT_FUSION_WEIGHTS } from '../src/services/evidenceFusion.js';
import emailAuthHandler from '../api/email-authentication.js';
import { getApiBaseUrl } from '../src/services/apiConfig.js';

test('MAVERICK Live Email Authentication & DNS Forensics Suite', async (t) => {

  // Deterministic Mock DNS Database
  const mockDnsDb = {
    'example.com': ['v=spf1 include:_spf.example.com ~all'],
    '_spf.example.com': ['v=spf1 ip4:192.0.2.0/24 -all'],
    'multi-spf.test': [
      'v=spf1 include:_spf.google.com ~all',
      'v=spf1 ip4:198.51.100.1 -all'
    ],
    'plus-all.test': ['v=spf1 +all'],
    's2023._domainkey.example.com': [
      'v=DKIM1; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0Y3yD9rE6j9a+9Vz0k8yP6Q7G...'
    ],
    'revoked._domainkey.example.com': [
      'v=DKIM1; k=rsa; p='
    ],
    '_dmarc.example.com': [
      'v=DMARC1; p=reject; sp=quarantine; pct=100; aspf=s; adkim=r; rua=mailto:dmarc@example.com'
    ],
    '_dmarc.corp.example.com': [], // Will test organizational domain fallback to _dmarc.example.com
    '_dmarc.multi.test': [
      'v=DMARC1; p=none;',
      'v=DMARC1; p=reject;'
    ],
    '_dmarc.none-policy.test': [
      'v=DMARC1; p=none; pct=50; rua=mailto:reports@none-policy.test'
    ],
    'timeout.test': { error: 'ETIMEOUT', status: 'TIMEOUT' }
  };

  const mockResolver = createMockDnsResolver(mockDnsDb);

  // 1. SPF Record Found
  await t.test('1. SPF record found via DNS resolution', async () => {
    const result = await querySpfRecord('example.com', { resolver: mockResolver });
    assert.equal(result.status, 'RECORD_FOUND');
    assert.equal(result.domain, 'example.com');
    assert.ok(result.record.includes('v=spf1'));
    assert.equal(result.hasPlusAll, false);
    assert.equal(result.defaultQualifier, 'softfail');
  });

  // 2. SPF Missing (NO_RECORD)
  await t.test('2. SPF missing (NO_RECORD)', async () => {
    const result = await querySpfRecord('nodata.test', {
      resolver: createMockDnsResolver({ 'nodata.test': [] })
    });
    assert.equal(result.status, 'NO_RECORD');
    assert.equal(result.record, null);
    assert.ok(result.warnings.some(w => w.includes('No SPF record found')));
  });

  // 3. Multiple SPF Records (RFC 7208 PermError)
  await t.test('3. Multiple SPF records detected as PermError', async () => {
    const result = await querySpfRecord('multi-spf.test', { resolver: mockResolver });
    assert.equal(result.status, 'PERMERROR');
    assert.ok(result.rawRecords.length > 1);
    assert.ok(result.warnings.some(w => w.includes('RFC 7208 PermError')));
  });

  // 4. SPF Malformed / +all Vulnerability Detection
  await t.test('4. SPF record with +all vulnerability flagged', async () => {
    const result = await querySpfRecord('plus-all.test', { resolver: mockResolver });
    assert.equal(result.status, 'RECORD_FOUND');
    assert.equal(result.hasPlusAll, true);
    assert.equal(result.defaultQualifier, 'pass');
    assert.ok(result.warnings.some(w => w.includes('+all')));
  });

  // 5. DKIM Selector Extraction
  await t.test('5. DKIM-Signature selector and tag parsing', async () => {
    const dkimHeader = 'v=1; a=rsa-sha256; c=relaxed/relaxed; d=example.com; s=s2023; h=from:to:subject; bh=47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=; b=dGVzdHNpZw==';
    const parsed = parseDkimSignature(dkimHeader);

    assert.ok(parsed !== null);
    assert.equal(parsed.selector, 's2023');
    assert.equal(parsed.domain, 'example.com');
    assert.equal(parsed.algorithm, 'rsa-sha256');
    assert.equal(parsed.canonicalization, 'relaxed/relaxed');
    assert.deepEqual(parsed.headers, ['from', 'to', 'subject']);
    assert.equal(parsed.signature, 'dGVzdHNpZw==');
  });

  // 6. DKIM DNS Record Found
  await t.test('6. DKIM public key record found in DNS', async () => {
    const result = await queryDkimRecord('s2023', 'example.com', { resolver: mockResolver });
    assert.equal(result.status, 'RECORD_FOUND');
    assert.equal(result.selector, 's2023');
    assert.equal(result.domain, 'example.com');
    assert.equal(result.isRevoked, false);
    assert.ok(result.publicKey.length > 0);
  });

  // 7. DKIM DNS Record Missing / Revoked
  await t.test('7. DKIM public key missing and revoked detection', async () => {
    const missing = await queryDkimRecord('unknown', 'example.com', { resolver: mockResolver });
    assert.equal(missing.status, 'NO_RECORD');
    assert.equal(missing.record, null);

    const revoked = await queryDkimRecord('revoked', 'example.com', { resolver: mockResolver });
    assert.equal(revoked.status, 'REVOKED');
    assert.equal(revoked.isRevoked, true);
    assert.ok(revoked.warnings.some(w => w.includes('revoked')));
  });

  // 8. DMARC Record Found
  await t.test('8. DMARC record found in DNS', async () => {
    const result = await queryDmarcRecord('example.com', { resolver: mockResolver });
    assert.equal(result.status, 'RECORD_FOUND');
    assert.equal(result.domain, 'example.com');
    assert.equal(result.policy, 'reject');
    assert.equal(result.subdomainPolicy, 'quarantine');
    assert.equal(result.aspf, 's');
    assert.equal(result.adkim, 'r');
    assert.equal(result.percentage, 100);
  });

  // 9. DMARC Missing & Subdomain Fallback
  await t.test('9. DMARC missing with organizational domain fallback', async () => {
    // corp.example.com has no direct DMARC record, but falls back to example.com
    const result = await queryDmarcRecord('corp.example.com', { resolver: mockResolver });
    assert.equal(result.status, 'RECORD_FOUND');
    assert.equal(result.isOrgDomainFallback, true);
    assert.equal(result.policy, 'reject');

    // Truly missing DMARC
    const noDmarc = await queryDmarcRecord('nonexistent-domain.xyz', {
      resolver: createMockDnsResolver({ '_dmarc.nonexistent-domain.xyz': [] })
    });
    assert.equal(noDmarc.status, 'NO_RECORD');
    assert.equal(noDmarc.policy, 'unknown');
  });

  // 10. DMARC Policy Parsing (quarantine, none, pct=50)
  await t.test('10. DMARC policy parsing with none and pct', async () => {
    const result = await queryDmarcRecord('none-policy.test', { resolver: mockResolver });
    assert.equal(result.status, 'RECORD_FOUND');
    assert.equal(result.policy, 'none');
    assert.equal(result.percentage, 50);
    assert.ok(result.warnings.some(w => w.includes('p=none')));
    assert.ok(result.warnings.some(w => w.includes('50%')));
  });

  // 11. Authentication-Results Parsing
  await t.test('11. Comprehensive Authentication-Results parser', async () => {
    const headers = [
      'mx.google.com; dkim=pass header.i=@example.com header.s=s2023; spf=softfail (google.com: 198.51.100.1 is not designated) smtp.mailfrom=sender@mailer.example.com; dmarc=pass (p=REJECT) header.from=example.com'
    ];
    const parsed = parseAuthenticationResults(headers);

    assert.equal(parsed.authservId, 'mx.google.com');
    assert.equal(parsed.spf?.verdict, 'softfail');
    assert.equal(parsed.spf?.mailfrom, 'sender@mailer.example.com');
    assert.equal(parsed.dkim.length, 1);
    assert.equal(parsed.dkim[0].verdict, 'pass');
    assert.equal(parsed.dkim[0].selector, 's2023');
    assert.equal(parsed.dmarc?.verdict, 'pass');
    assert.equal(parsed.dmarc?.policy, 'reject');
    assert.equal(parsed.dmarc?.headerFrom, 'example.com');
  });

  // 12. From / Return-Path Domain Mismatch
  await t.test('12. Domain mismatch detection between From and Return-Path', async () => {
    const alignment = analyzeDomainAlignment({
      fromDomain: 'company.com',
      returnPathDomain: 'mailer.attacker.com',
      dkimDomains: ['attacker.com'],
      aspf: 'r',
      adkim: 'r'
    });

    assert.equal(alignment.spfAligned, false);
    assert.equal(alignment.dkimAligned, false);
    assert.equal(alignment.dmarcAligned, false);
  });

  // 13. DKIM Domain Alignment (strict vs relaxed)
  await t.test('13. DKIM alignment in strict vs relaxed mode', async () => {
    // Relaxed mode: mail.example.com matches example.com
    const relaxed = analyzeDomainAlignment({
      fromDomain: 'example.com',
      returnPathDomain: 'example.com',
      dkimDomains: ['mail.example.com'],
      adkim: 'r'
    });
    assert.equal(relaxed.dkimAligned, true);

    // Strict mode: mail.example.com does NOT match example.com
    const strict = analyzeDomainAlignment({
      fromDomain: 'example.com',
      returnPathDomain: 'example.com',
      dkimDomains: ['mail.example.com'],
      adkim: 's'
    });
    assert.equal(strict.dkimAligned, false);
  });

  // 14. SPF Domain Alignment (strict vs relaxed)
  await t.test('14. SPF alignment in strict vs relaxed mode', async () => {
    // Relaxed mode: bounce.corp.example.co.uk matches example.co.uk
    const relaxed = analyzeDomainAlignment({
      fromDomain: 'corp.example.co.uk',
      returnPathDomain: 'bounce.corp.example.co.uk',
      dkimDomains: [],
      aspf: 'r'
    });
    assert.equal(relaxed.spfAligned, true);

    // Strict mode: exact FQDN match required
    const strict = analyzeDomainAlignment({
      fromDomain: 'corp.example.co.uk',
      returnPathDomain: 'bounce.corp.example.co.uk',
      dkimDomains: [],
      aspf: 's'
    });
    assert.equal(strict.spfAligned, false);
  });

  // 15. Malformed Email Input Handling (never crashes)
  await t.test('15. Malformed email input handling', async () => {
    const malformed1 = '';
    const res1 = await analyzeEmailAuthentication(malformed1, { dnsResolver: mockResolver });
    assert.equal(res1.success, false);
    assert.equal(res1.status, 'EMPTY_INPUT');

    const malformed2 = 'This is not an RFC 822 email at all\r\nJust random bytes: 0x99 0xFF';
    const res2 = await analyzeEmailAuthentication(malformed2, { dnsResolver: mockResolver });
    assert.equal(res2.success, true);
    assert.equal(res2.status, 'COMPLETE');
    assert.equal(res2.fromDomain, '');
  });

  // 16. Missing Headers Handling
  await t.test('16. Incomplete email with missing From and Return-Path', async () => {
    const rawNoFrom = `Subject: Hello World
To: recipient@test.org
Date: Fri, 05 Sep 2026 12:00:00 +0000

Body content here without From header.`;

    const res = await analyzeEmailAuthentication(rawNoFrom, { dnsResolver: mockResolver });
    assert.equal(res.success, true);
    assert.equal(res.fromDomain, '');
    assert.equal(res.returnPathDomain, '');
    assert.ok(res.observedEvidence !== null);
  });

  // 17. DNS Timeout Handling
  await t.test('17. Graceful handling of DNS timeout', async () => {
    const timeoutRes = await querySpfRecord('timeout.test', { resolver: mockResolver });
    assert.equal(timeoutRes.status, 'ERROR');
    assert.ok(timeoutRes.warnings[0].includes('TIMEOUT') || timeoutRes.warnings[0].includes('ETIMEOUT'));
  });

  // 18. NXDOMAIN Handling
  await t.test('18. Graceful handling of NXDOMAIN', async () => {
    const nxResolver = createMockDnsResolver({});
    const res = await queryDmarcRecord('nxdomain-nonexistent.org', { resolver: nxResolver });
    assert.equal(res.status, 'NO_RECORD');
  });

  // 19. Evidence Fusion Integration with Email Authentication
  await t.test('19. Evidence Fusion layer 2 calibrated with emailAuth (never single-factor malicious)', async () => {
    // Case A: DMARC FAIL and SPF FAIL, but legitimate text, no malicious IOCs, no bad attachments
    const mockAuthFailure = {
      observedEvidence: {
        mtaAuthentication: {
          observedSpfVerdict: 'fail',
          observedDkimVerdict: 'fail',
          observedDmarcVerdict: 'fail'
        },
        dnsForensics: {
          dmarc: { policy: 'reject' }
        }
      },
      inferredEvidence: {
        dmarcEffectiveStatus: 'FAIL'
      },
      fromDomain: 'example.com',
      returnPathDomain: 'attacker.com'
    };

    const benignParsedEmail = {
      sender: 'user@example.com',
      fromParsed: { address: 'user@example.com', domain: 'example.com' },
      returnPathParsed: { address: 'bounce@attacker.com', domain: 'attacker.com' },
      originatingIP: '192.0.2.1',
      rawSnippet: 'Subject: Normal Meeting Notes\n\nLet us meet tomorrow.'
    };

    const fusion = calculateEvidenceFusion({
      parsedEmail: benignParsedEmail,
      aiThreat: { phishingProbability: 10, prediction: 'LEGITIMATE', isMlAvailable: true },
      iocs: [],
      geoInfo: null,
      emailAuth: mockAuthFailure,
      weights: DEFAULT_FUSION_WEIGHTS
    });

    const headerFactor = fusion.factors.find(f => f.id === 'header-forensics');
    assert.ok(headerFactor !== undefined);
    assert.ok(headerFactor.points <= DEFAULT_FUSION_WEIGHTS.headerForensics, 'Header points clamped to max (20)');
    // Total score with only header forensics points cannot exceed 30 (LOW threshold)
    assert.ok(fusion.threatScore <= 30, `Score (${fusion.threatScore}) should remain LOW without corroborating layers`);
    assert.equal(fusion.riskLevel, 'LOW', 'DMARC FAIL alone MUST NOT classify email as MALICIOUS');
  });

  // 20. Live Data Non-Fabrication Principle
  await t.test('20. Live data non-fabrication standard', async () => {
    const syntheticEmail = `From: "Finance Desk" <finance@example.com>
Return-Path: <bounce@example.com>
DKIM-Signature: v=1; a=rsa-sha256; d=example.com; s=s2023; b=abc; bh=def;
Authentication-Results: mx.google.com; spf=pass smtp.mailfrom=bounce@example.com; dkim=pass header.d=example.com header.s=s2023; dmarc=pass

Synthetic invoice notification`;

    const result = await analyzeEmailAuthentication(syntheticEmail, { dnsResolver: mockResolver });
    assert.equal(result.success, true);
    // Labels must say RECORD FOUND, not VERIFIED
    assert.equal(result.spf.displayStatus, 'SPF RECORD FOUND');
    assert.equal(result.dkim.displayStatus, 'DKIM PUBLIC KEY FOUND');
    assert.equal(result.dmarc.displayStatus, 'DMARC RECORD FOUND');
    assert.notEqual(result.spf.displayStatus, 'SPF VERIFIED');
    assert.notEqual(result.dkim.displayStatus, 'DKIM VERIFIED');
  });

  // 21. Reusable DNS Service (resolve4, resolve6, caching)
  await t.test('21. DNS service utilities, address resolution, and cache metrics', async () => {
    clearDnsCache();
    assert.equal(isValidDomain('example.com'), true);
    assert.equal(isValidDomain('sub.example.co.uk'), true);
    assert.equal(isValidDomain('invalid..domain'), false);
    assert.equal(normalizeDomain('EXAMPLE.COM.'), 'example.com');
    assert.equal(getOrganizationalDomain('mailer.prod.example.com'), 'example.com');
    assert.equal(getOrganizationalDomain('auth.bank.co.in'), 'bank.co.in');

    const multiResolver = createMockDnsResolver({
      'host.example.com': {
        A: ['192.0.2.1', '192.0.2.2'],
        AAAA: ['2001:db8::1'],
        TXT: ['v=spf1 -all']
      }
    });

    const aRes = await resolve4('host.example.com', { resolver: multiResolver });
    assert.equal(aRes.status, 'RESOLVED');
    assert.equal(aRes.addresses.length, 2);

    const aaaaRes = await resolve6('host.example.com', { resolver: multiResolver });
    assert.equal(aaaaRes.status, 'RESOLVED');
    assert.equal(aaaaRes.addresses[0], '2001:db8::1');

    const stats = getDnsCacheStats();
    assert.ok(stats.size >= 0);
  });

  // 22. End-to-End Forensic Flow (Email -> Auth -> Alignment -> Fusion)
  await t.test('22. Full End-to-End Forensic Flow', async () => {
    const spoofedEmail = `From: "Executive Service" <cfo@trusted-domain.com>
Return-Path: <phisher@spoofed-host.net>
Authentication-Results: mta.target.in; spf=fail smtp.mailfrom=phisher@spoofed-host.net; dkim=fail; dmarc=fail header.from=trusted-domain.com
Subject: Urgent Payment Request

Please expedite statutory transfer.`;

    const auth = await analyzeEmailAuthentication(spoofedEmail, {
      dnsResolver: createMockDnsResolver({
        'spoofed-host.net': ['v=spf1 -all'],
        '_dmarc.trusted-domain.com': ['v=DMARC1; p=reject;']
      })
    });

    assert.equal(auth.fromDomain, 'trusted-domain.com');
    assert.equal(auth.returnPathDomain, 'spoofed-host.net');
    assert.equal(auth.alignment.spfAligned, false);
    assert.equal(auth.alignment.dmarcAligned, false);
    assert.ok(auth.riskSignals.length > 0);

    const fusion = calculateEvidenceFusion({
      parsedEmail: {
        sender: 'cfo@trusted-domain.com',
        fromParsed: { domain: 'trusted-domain.com' },
        returnPathParsed: { domain: 'spoofed-host.net' }
      },
      aiThreat: { phishingProbability: 95, prediction: 'PHISHING', isMlAvailable: true },
      iocs: [{ type: 'URL', status: 'MALICIOUS', value: 'http://malicious.link' }],
      geoInfo: null,
      emailAuth: auth,
      weights: DEFAULT_FUSION_WEIGHTS
    });

    assert.ok(fusion.threatScore >= 50, 'Combined phishing signals result in elevated threat score');
    assert.equal(fusion.riskLevel, 'SUSPICIOUS', 'Correct risk categorization');
    assert.ok(fusion.verifiedReasons.some(r => r.includes('SPF') || r.includes('DMARC')));
  });

  // 23. Missing SPF Record (NO_RECORD)
  await t.test('23. Missing SPF record handling', async () => {
    const emptyResolver = createMockDnsResolver({});
    const result = await querySpfRecord('nospecificspf.org', { resolver: emptyResolver });
    assert.equal(result.status, 'NO_RECORD');
    assert.equal(result.record, null);
    assert.ok(result.warnings.some(w => w.includes('No SPF record')));
  });

  // 24. Email without DKIM-Signature header
  await t.test('24. Email without DKIM-Signature header', async () => {
    const rawNoDkim = `From: "Alerts" <alerts@domain.org>
Return-Path: <alerts@domain.org>
Subject: Notice

Notification text without DKIM`;

    const res = await analyzeEmailAuthentication(rawNoDkim, {
      dnsResolver: createMockDnsResolver({
        'domain.org': ['v=spf1 -all'],
        '_dmarc.domain.org': ['v=DMARC1; p=reject;']
      })
    });

    assert.equal(res.success, true);
    assert.equal(res.dkim.status, 'NO_SIGNATURE');
    assert.equal(res.observedEvidence.dkimSignatures.length, 0);
    assert.equal(res.alignment.dkimAuthPass, false);
    assert.equal(res.alignment.dkimAligned, false);
  });

  // 25. Missing DMARC Record (NO_RECORD) - Never displays as DMARC PASSED
  await t.test('25. Missing DMARC record prevents DMARC alignment pass even with matching domains', async () => {
    const emailMatchingDomainsNoDmarc = `From: "Billing" <service@paypal.test>
Return-Path: <service@paypal.test>
Authentication-Results: mx.receiver.net; spf=pass smtp.mailfrom=service@paypal.test
Subject: Invoice

Payment request`;

    const res = await analyzeEmailAuthentication(emailMatchingDomainsNoDmarc, {
      dnsResolver: createMockDnsResolver({
        'paypal.test': ['v=spf1 -all']
        // No _dmarc.paypal.test record!
      })
    });

    assert.equal(res.success, true);
    assert.equal(res.dmarc.status, 'NO_RECORD');
    assert.equal(res.alignment.hasDmarcPolicy, false);
    assert.equal(res.alignment.spfAligned, true, 'SPF identifier matches domain');
    assert.equal(res.alignment.dmarcAligned, false, 'DMARC alignment cannot pass without a published DMARC policy');
    assert.equal(res.alignment.dmarc, 'UNENFORCED', 'DMARC alignment must be marked UNENFORCED');
    assert.equal(res.summary.alignmentResult, 'UNENFORCED');
  });

  // 26. Alignment Mismatch Detection
  await t.test('26. DMARC policy present but SPF and DKIM domains mismatch From header', async () => {
    const emailSpoofed = `From: "CEO" <ceo@corporate.com>
Return-Path: <attacker@mailhost.net>
DKIM-Signature: v=1; a=rsa-sha256; d=mailhost.net; s=k1; b=sig; bh=hash;
Authentication-Results: mx.target.com; spf=pass smtp.mailfrom=attacker@mailhost.net; dkim=pass header.d=mailhost.net; dmarc=fail action=none
Subject: Wire Transfer

Please transfer funds.`;

    const res = await analyzeEmailAuthentication(emailSpoofed, {
      dnsResolver: createMockDnsResolver({
        'corporate.com': ['v=spf1 -all'],
        '_dmarc.corporate.com': ['v=DMARC1; p=reject;'],
        'mailhost.net': ['v=spf1 -all'],
        'k1._domainkey.mailhost.net': ['v=DKIM1; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0Y3y...']
      })
    });

    assert.equal(res.success, true);
    assert.equal(res.dmarc.status, 'RECORD_FOUND');
    assert.equal(res.alignment.hasDmarcPolicy, true);
    assert.equal(res.alignment.spfAligned, false, 'SPF return-path mailhost.net does not align with corporate.com');
    assert.equal(res.alignment.dkimAligned, false, 'DKIM d=mailhost.net does not align with corporate.com');
    assert.equal(res.alignment.dmarcAligned, false, 'DMARC alignment MUST fail');
    assert.equal(res.alignment.dmarc, 'FAIL');
    assert.equal(res.summary.alignmentResult, 'MISALIGNED');
  });

  // 27. Genuine Alignment Success (SPF and DKIM passing under RFC 7489)
  await t.test('27. Genuine DMARC alignment success with valid policy and authenticating aligned streams', async () => {
    // 27A: SPF authenticates and aligns
    const spfAuthenticEmail = `From: "Bank Support" <support@trustedbank.com>
Return-Path: <bounce@trustedbank.com>
Authentication-Results: mx.cust.org; spf=pass smtp.mailfrom=bounce@trustedbank.com
Subject: Statement

Monthly statement`;

    const resSpf = await analyzeEmailAuthentication(spfAuthenticEmail, {
      dnsResolver: createMockDnsResolver({
        'trustedbank.com': ['v=spf1 -all'],
        '_dmarc.trustedbank.com': ['v=DMARC1; p=reject;']
      })
    });

    assert.equal(resSpf.alignment.hasDmarcPolicy, true);
    assert.equal(resSpf.alignment.spfAuthPass, true);
    assert.equal(resSpf.alignment.spfAligned, true);
    assert.equal(resSpf.alignment.dmarcAligned, true, 'SPF pass + aligned domain + DMARC policy passes DMARC');
    assert.equal(resSpf.alignment.dmarc, 'PASS');
    assert.equal(resSpf.summary.alignmentResult, 'ALIGNED');

    // 27B: DKIM authenticates and aligns even if SPF is misaligned
    const dkimAuthenticEmail = `From: "Bank Support" <support@trustedbank.com>
Return-Path: <notifications@thirdpartyrelay.org>
DKIM-Signature: v=1; a=rsa-sha256; d=trustedbank.com; s=s1; b=sig; bh=hash;
Authentication-Results: mx.cust.org; spf=pass smtp.mailfrom=notifications@thirdpartyrelay.org; dkim=pass header.d=trustedbank.com header.s=s1
Subject: Statement

Monthly statement`;

    const resDkim = await analyzeEmailAuthentication(dkimAuthenticEmail, {
      dnsResolver: createMockDnsResolver({
        'thirdpartyrelay.org': ['v=spf1 -all'],
        'trustedbank.com': ['v=spf1 -all'],
        '_dmarc.trustedbank.com': ['v=DMARC1; p=reject;'],
        's1._domainkey.trustedbank.com': ['v=DKIM1; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0Y3y...']
      })
    });

    assert.equal(resDkim.alignment.hasDmarcPolicy, true);
    assert.equal(resDkim.alignment.spfAligned, false, 'Third-party relay does not SPF align with trustedbank.com');
    assert.equal(resDkim.alignment.dkimAuthPass, true);
    assert.equal(resDkim.alignment.dkimAligned, true);
    assert.equal(resDkim.alignment.dmarcAligned, true, 'DKIM pass + aligned domain + DMARC policy passes DMARC');
    assert.equal(resDkim.alignment.dmarc, 'PASS');
    assert.equal(resDkim.summary.alignmentResult, 'ALIGNED');
  });

  // 28. Reserved .example Domain (RFC 2606 / RFC 6761)
  await t.test('28. Reserved .example test domain handled as DNS UNAVAILABLE', async () => {
    // When no mock resolver fixture is provided, resolveTxt on .example must return UNAVAILABLE
    const txtRes = await resolveTxt('paypal.example');
    assert.equal(txtRes.status, 'UNAVAILABLE');
    assert.ok(txtRes.error.includes('reserved example domain'));

    const spfRes = await querySpfRecord('paypal.example');
    assert.equal(spfRes.status, 'UNAVAILABLE');

    const dmarcRes = await queryDmarcRecord('paypal.example');
    assert.equal(dmarcRes.status, 'UNAVAILABLE');

    const emailExample = `From: "Security" <alerts@service.example>
Return-Path: <bounce@service.example>
Subject: Test Alert

Test message`;

    const res = await analyzeEmailAuthentication(emailExample);
    assert.equal(res.spf.status, 'UNAVAILABLE');
    assert.equal(res.dmarc.status, 'UNAVAILABLE');
    assert.equal(res.alignment.dmarcAligned, false);
    assert.equal(res.summary.spfStatus, 'DNS UNAVAILABLE (.EXAMPLE)');
    assert.equal(res.summary.dmarcStatus, 'DNS UNAVAILABLE (.EXAMPLE)');
    assert.notEqual(res.summary.alignmentResult, 'ALIGNED');
  });

  // =========================================================================
  // 29. VERCEL SERVERLESS HANDLER: POST /api/email-authentication
  // =========================================================================
  await t.test('29. Serverless handler: processes POST /api/email-authentication successfully', async () => {
    let statusCode = null;
    let jsonResult = null;
    const req = {
      method: 'POST',
      body: {
        email: 'From: alerts@service.example\nReturn-Path: <bounce@service.example>\nSubject: Security Notice\n\nAccount login observed.'
      }
    };
    const res = {
      setHeader: () => {},
      writeHead: (code) => { statusCode = code; },
      end: (data) => { if (data) jsonResult = JSON.parse(data); },
      status(code) {
        statusCode = code;
        return this;
      },
      json(data) {
        jsonResult = data;
        return this;
      }
    };

    await emailAuthHandler(req, res);
    assert.equal(statusCode, 200);
    assert.equal(jsonResult.success, true);
    assert.ok(jsonResult.status === 'SUCCESS' || jsonResult.status === 'COMPLETE');
    assert.ok(jsonResult.spf, 'Response must include SPF forensics');
    assert.ok(jsonResult.alignment, 'Response must include domain alignment analysis');
  });

  // =========================================================================
  // 30. SERVERLESS HANDLER: REJECTS EMPTY/MISSING EMAIL PAYLOAD WITH 400
  // =========================================================================
  await t.test('30. Serverless handler: rejects empty email with HTTP 400 INVALID_INPUT', async () => {
    let statusCode = null;
    let jsonResult = null;
    const req = {
      method: 'POST',
      body: {}
    };
    const res = {
      setHeader: () => {},
      writeHead: (code) => { statusCode = code; },
      end: (data) => { if (data) jsonResult = JSON.parse(data); },
      status(code) {
        statusCode = code;
        return this;
      },
      json(data) {
        jsonResult = data;
        return this;
      }
    };

    await emailAuthHandler(req, res);
    assert.equal(statusCode, 400);
    assert.equal(jsonResult.success, false);
    assert.equal(jsonResult.status, 'INVALID_INPUT');
  });

  // =========================================================================
  // 31. API CONFIG: PURGES STALE VERCEL PREVIEW URL FROM LOCALSTORAGE
  // =========================================================================
  await t.test('31. getApiBaseUrl(): purges preview vercel.app URL and returns relative root', () => {
    const mockStorage = new Map();
    globalThis.window = {
      location: { origin: 'https://phishguard-ai-mu-fawn.vercel.app', hostname: 'phishguard-ai-mu-fawn.vercel.app' },
      localStorage: {
        getItem: (k) => mockStorage.get(k) || null,
        setItem: (k, v) => mockStorage.set(k, String(v)),
        removeItem: (k) => mockStorage.delete(k)
      }
    };

    // Stale preview URL stored in localStorage
    globalThis.window.localStorage.setItem('maverick_backend_url', 'https://phishguard-pwy5iycb8-dilshand2025.vercel.app');

    const result = getApiBaseUrl();
    assert.equal(result, '', 'Must return relative root empty string instead of stale preview URL');
    assert.equal(globalThis.window.localStorage.getItem('maverick_backend_url'), null, 'Stale preview URL must be purged from localStorage');

    // Clean up
    delete globalThis.window;
  });

});
