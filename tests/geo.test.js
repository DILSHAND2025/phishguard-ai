/**
 * MAVERICK — Forensic IP GeoLocation & Interactive Map Test Suite
 * Smart India Hackathon 2026
 * 
 * Verifies all 10 required forensic geolocation specifications:
 * 1. Email containing a public IPv4
 * 2. Email containing multiple public IPs
 * 3. Email containing private IP
 * 4. Email without IP
 * 5. Invalid IP
 * 6. Geolocation API failure
 * 7. Missing API key
 * 8. Multiple markers
 * 9. Map rendering & cache verification
 * 10. Complete email -> IOC -> geolocation -> evidence-fusion flow
 */

import test from 'node:test';
import assert from 'node:assert/strict';

import { 
  parseEmailContent, 
  extractIPv4, 
  extractIPv6, 
  extractAllIPs, 
  isValidIP, 
  isPrivateIP, 
  extractNetworkIndicators 
} from '../src/services/emailParser.js';

import { extractAllIOCs } from '../src/services/iocExtractor.js';
import { 
  GeoLocationService, 
  BaseGeoProvider, 
  MockGeoProvider, 
  defaultGeoService, 
  GEO_LEGAL_DISCLAIMER 
} from '../src/services/geoLocationService.js';
import { calculateEvidenceFusion, DEFAULT_FUSION_WEIGHTS } from '../src/services/evidenceFusion.js';

test('MAVERICK Forensic IP GeoLocation Test Suite', async (t) => {

  // Test 1: Email containing a public IPv4
  await t.test('1. Email containing a public IPv4', async () => {
    const rawEml = `From: "Finance Relay" <mailer@transit-service.com>
To: <target@enterprise.in>
Subject: Quarterly Budget Notice
Date: Mon, 07 Sep 2026 09:00:00 +0530
Received: from mail.transit-service.com (185.220.101.45) by mx.enterprise.in; Mon, 07 Sep 2026 09:00:01 +0530

Please find the quarterly report.`;

    const parsed = await parseEmailContent(rawEml);
    assert.equal(parsed.originatingIP, '185.220.101.45');

    const networkIndicators = extractNetworkIndicators(parsed);
    assert.ok(networkIndicators.length >= 1, 'Network indicators extracted');
    const sourceInd = networkIndicators.find(n => n.role === 'SOURCE');
    assert.ok(sourceInd, 'Source IP indicator identified');
    assert.equal(sourceInd.ip, '185.220.101.45');
    assert.equal(sourceInd.isPrivate, false, 'Identified as public IP');

    const geoResult = await defaultGeoService.resolveIP(sourceInd.ip, sourceInd);
    assert.equal(geoResult.ip, '185.220.101.45');
    assert.equal(geoResult.country, 'Germany');
    assert.ok(typeof geoResult.latitude === 'number', 'Numeric latitude returned');
    assert.ok(typeof geoResult.longitude === 'number', 'Numeric longitude returned');
    assert.ok(geoResult.asn, 'ASN returned');
    assert.ok(geoResult.observedEvidence.includes('Germany'), 'Observed evidence populated');
  });

  // Test 2: Email containing multiple public IPs
  await t.test('2. Email containing multiple public IPs', async () => {
    const rawEml = `From: "Operations" <ops@multihop-service.online>
To: <target@enterprise.in>
Subject: Critical Systems Upgrade
Received: from relay2.transit.net (194.26.29.110) by mx.enterprise.in; Mon, 07 Sep 2026 10:00:02 +0530
Received: from mail.origin-source.org (185.220.101.45) by relay1.transit.net; Mon, 07 Sep 2026 10:00:01 +0530

Urgent notice: Verify directory status at http://45.154.255.82/login immediately.`;

    const parsed = await parseEmailContent(rawEml);
    const networkIndicators = extractNetworkIndicators(parsed);

    // Should find: 185.220.101.45 (SOURCE), 194.26.29.110 (MAIL_SERVER), 45.154.255.82 (URL_HOST)
    const ipsFound = networkIndicators.map(n => n.ip);
    assert.ok(ipsFound.includes('185.220.101.45'), 'Originating IP detected');
    assert.ok(ipsFound.includes('194.26.29.110'), 'Hop relay IP detected');
    assert.ok(ipsFound.includes('45.154.255.82'), 'URL host IP detected');

    const urlInd = networkIndicators.find(n => n.ip === '45.154.255.82');
    assert.equal(urlInd.role, 'URL_HOST', 'Correctly flagged as URL infrastructure');

    const geoList = await defaultGeoService.resolveAllIPs(networkIndicators);
    assert.ok(geoList.length >= 3, 'All public IPs resolved');

    const countries = geoList.map(g => g.country);
    assert.ok(countries.includes('Germany'), 'Germany resolved');
    assert.ok(countries.includes('Netherlands'), 'Netherlands resolved');
    assert.ok(countries.includes('Romania'), 'Romania resolved');
  });

  // Test 3: Email containing private IP
  await t.test('3. Email containing private IP', async () => {
    const rawEml = `From: "Internal IT" <helpdesk@corp.local>
To: <user@corp.local>
Subject: Intranet Portal
Received: from internal-node (192.168.1.150) by mail.corp.local (10.0.0.5); Mon, 07 Sep 2026 10:30:00 +0530

Local proxy is running on 172.16.0.25 and loopback 127.0.0.1.`;

    const parsed = await parseEmailContent(rawEml);
    const networkIndicators = extractNetworkIndicators(parsed);

    assert.ok(networkIndicators.length >= 1, 'Private indicators extracted');
    for (const ind of networkIndicators) {
      assert.equal(ind.isPrivate, true, `${ind.ip} recognized as private/reserved`);
      
      const geo = await defaultGeoService.resolveIP(ind.ip, ind);
      assert.equal(geo.status, 'PRIVATE_IP');
      assert.equal(geo.latitude, null, 'Private IP has no public latitude');
      assert.equal(geo.longitude, null, 'Private IP has no public longitude');
      assert.ok(geo.observedEvidence.includes('reserved non-routable'), 'Notes private address space');
    }
  });

  // Test 4: Email without IP
  await t.test('4. Email without IP', async () => {
    const rawEml = `From: "Colleague" <colleague@example.com>
To: <target@enterprise.in>
Subject: Quick coffee tomorrow?

Hey, are you free for a quick coffee catchup tomorrow morning?`;

    const parsed = await parseEmailContent(rawEml);
    const networkIndicators = extractNetworkIndicators(parsed);
    assert.equal(networkIndicators.length, 0, 'Zero network indicators for clean email without IPs');

    const resolved = await defaultGeoService.resolveAllIPs(networkIndicators);
    assert.equal(resolved.length, 0, 'Zero geolocation queries executed');
  });

  // Test 5: Invalid IP handling
  await t.test('5. Invalid IP handling', async () => {
    const invalidInputs = [
      '999.999.999.999',
      '185.220.101',
      'abc.def.ghi.jkl',
      '256.100.0.1',
      '',
      null,
      undefined
    ];

    for (const invalid of invalidInputs) {
      assert.equal(isValidIP(invalid), false, `${invalid} fails isValidIP`);
      const result = await defaultGeoService.resolveIP(invalid);
      assert.equal(result.status, 'INVALID_IP');
      assert.equal(result.latitude, null);
      assert.equal(result.longitude, null);
      assert.equal(result.country, 'Invalid IP');
    }
  });

  // Test 6: Geolocation API failure handling (Never creates fake coordinates)
  await t.test('6. Geolocation API failure handling (Never creates fake coordinates)', async () => {
    // Custom mock provider that always throws/fails
    class FailingProvider extends BaseGeoProvider {
      constructor() {
        super('Failing Mock Provider');
      }
      async lookup() {
        throw new Error('503 Service Unavailable: Remote upstream timeout');
      }
    }

    const failingService = new GeoLocationService({
      providers: [new FailingProvider()]
    });

    const result = await failingService.resolveIP('8.8.8.8');
    assert.equal(result.status, 'UNAVAILABLE');
    assert.equal(result.error, 'Geolocation unavailable');
    assert.equal(result.country, 'Geolocation unavailable');
    assert.equal(result.latitude, null, 'Coordinates strictly null on provider failure');
    assert.equal(result.longitude, null, 'Coordinates strictly null on provider failure');
    assert.equal(result.isDemo, false);
  });

  // Test 7: Missing API key handling
  await t.test('7. Missing API key handling', async () => {
    class KeylessProvider extends BaseGeoProvider {
      constructor() {
        super('Keyless Provider');
      }
      async lookup() {
        // Simulates provider returning null or 401 missing key
        return null;
      }
    }

    const keylessService = new GeoLocationService({
      providers: [new KeylessProvider()]
    });

    const result = await keylessService.resolveIP('1.1.1.1');
    assert.equal(result.status, 'UNAVAILABLE');
    assert.equal(result.error, 'Geolocation unavailable');
    assert.equal(result.latitude, null);
    assert.equal(result.longitude, null);
  });

  // Test 8: Multiple markers bounds check
  await t.test('8. Multiple markers bounds check', async () => {
    const multiIPs = [
      { ip: '185.220.101.45', role: 'SOURCE' },
      { ip: '45.154.255.82', role: 'URL_HOST' },
      { ip: '194.26.29.110', role: 'MAIL_SERVER' }
    ];

    const results = await defaultGeoService.resolveAllIPs(multiIPs);
    assert.equal(results.length, 3);

    // Verify all 3 have distinct valid coordinates
    const coords = results.map(r => ({ lat: r.latitude, lon: r.longitude }));
    for (const c of coords) {
      assert.equal(typeof c.lat, 'number');
      assert.equal(typeof c.lon, 'number');
      assert.ok(c.lat >= -90 && c.lat <= 90);
      assert.ok(c.lon >= -180 && c.lon <= 180);
    }

    // Verify distinct geographic coordinates
    const uniqueLats = new Set(coords.map(c => c.lat));
    assert.equal(uniqueLats.size, 3, 'Three distinct geographic pin locations');
  });

  // Test 9: Performance & In-memory Caching verification
  await t.test('9. Performance & In-memory Caching verification', async () => {
    let callCounter = 0;
    class CountingProvider extends BaseGeoProvider {
      constructor() {
        super('Counting Provider');
      }
      async lookup(ip) {
        callCounter++;
        return {
          country: 'Test Country',
          city: 'Test City',
          latitude: 10.0,
          longitude: 20.0,
          asn: 'AS12345'
        };
      }
    }

    const testCacheService = new GeoLocationService({
      providers: [new CountingProvider()]
    });

    // Query IP first time
    const res1 = await testCacheService.resolveIP('203.0.113.195');
    assert.equal(callCounter, 1, 'Provider called on initial query');
    assert.equal(res1.city, 'Test City');

    // Query identical IP 10 times
    for (let i = 0; i < 10; i++) {
      const cachedRes = await testCacheService.resolveIP('203.0.113.195');
      assert.equal(cachedRes.city, 'Test City');
    }

    // Provider should NOT have been called again (zero repeated API calls)
    assert.equal(callCounter, 1, 'Provider call count remained 1 due to in-memory cache');
  });

  // Test 10: Complete email -> IOC -> geolocation -> evidence-fusion flow
  await t.test('10. Complete email -> IOC -> geolocation -> evidence-fusion flow', async () => {
    const rawEml = `From: "Accounts Department" <billing@secure-internal-update.online>
To: <target-employee@enterprise.in>
Subject: URGENT: Wire Remittance Verification
Received: from relay.transit-service.com (194.26.29.110) by mail.enterprise.in; Fri, 06 Sep 2026 12:00:00 +0530
Received: from mail.secure-internal-update.online (185.220.101.45) by relay.transit-service.com; Fri, 06 Sep 2026 11:59:59 +0530

Mandatory directive: Expedite statutory allocation transfer immediately.
Access portal: http://45.154.255.82/auth/login`;

    // 1. Email Parser
    const parsedEmail = await parseEmailContent(rawEml);
    assert.equal(parsedEmail.originatingIP, '185.220.101.45');

    // 2. IOC Extractor
    const iocs = extractAllIOCs(parsedEmail);
    assert.ok(iocs.some(i => i.type === 'IP' && i.value === '185.220.101.45'));

    // 3. Network Indicators & Multi-IP GeoLocation
    const networkIndicators = extractNetworkIndicators(parsedEmail);
    assert.ok(networkIndicators.length >= 3, 'Extracted Source, Hop, and URL Host IPs');

    const geoList = await defaultGeoService.resolveAllIPs(networkIndicators);
    const sourceGeo = geoList.find(g => g.role === 'SOURCE');
    assert.equal(sourceGeo.country, 'Germany');

    // 4. Evidence Fusion Integration
    const fusion = calculateEvidenceFusion({
      parsedEmail,
      aiThreat: { phishingProbability: 75, prediction: 'PHISHING', model: 'TF-IDF + Logistic Regression' },
      iocs,
      geoInfo: sourceGeo,
      geoList,
      weights: DEFAULT_FUSION_WEIGHTS
    });

    // Check Layer 5 factor
    const geoFactor = fusion.factors.find(f => f.id === 'geo-asn-context');
    assert.ok(geoFactor, 'Layer 5 Geo/ASN context factor present in Evidence Fusion');
    assert.ok(geoFactor.points > 0, 'Geo factor allocated contextual evidence points');
    assert.ok(geoFactor.evidence.includes('Germany'), 'Evidence string cites observed geography');
    assert.ok(typeof fusion.threatScore === 'number', 'Final threat score computed');

    // Verify Forensic Legal Disclaimer is compliant
    assert.ok(GEO_LEGAL_DISCLAIMER.includes('observed network infrastructure'));
  });

});
