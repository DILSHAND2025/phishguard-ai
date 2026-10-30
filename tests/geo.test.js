/**
 * MAVERICK — Forensic IP GeoLocation & Interactive Map Test Suite
 * Smart India Hackathon 2026
 * 
 * Verifies all 12 forensic geolocation specifications from Section 8:
 * 1. Email containing a valid public IPv4 address
 * 2. Email containing a valid public IPv6 address
 * 3. Email containing a private IPv4 address
 * 4. Email containing a loopback address
 * 5. Email containing multiple Received headers (MTA sequence & roles)
 * 6. Email containing no extractable IP address
 * 7. Invalid IP address handling
 * 8. Geolocation API timeout handling
 * 9. Geolocation API rate-limit response handling
 * 10. Geolocation API invalid response handling
 * 11. Valid IP with missing location fields handling
 * 12. Multiple public IP addresses in one email
 * Plus:
 * 13. Missing API key handling
 * 14. Multiple markers bounds check
 * 15. Performance & in-memory caching verification
 * 16. Complete email -> IOC -> geolocation -> evidence-fusion flow
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
  isPublicIP,
  classifyIP,
  cleanIPString,
  IP_CLASSIFICATION,
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

  // Case 1: Email containing a valid public IPv4 address
  await t.test('1. Email containing a valid public IPv4 address', async () => {
    const rawEml = `From: "Finance Relay" <mailer@transit-service.com>
To: <target@enterprise.in>
Subject: Quarterly Budget Notice
Date: Mon, 07 Sep 2026 09:00:00 +0530
Received: from mail.transit-service.com (185.220.101.45) by mx.enterprise.in; Mon, 07 Sep 2026 09:00:01 +0530

Please find the quarterly report.`;

    const parsed = await parseEmailContent(rawEml);
    assert.equal(parsed.originatingIP, '185.220.101.45');
    assert.equal(parsed.originatingIPClassification, IP_CLASSIFICATION.PUBLIC_IPV4);

    const networkIndicators = extractNetworkIndicators(parsed);
    assert.ok(networkIndicators.length >= 1, 'Network indicators extracted');
    const sourceInd = networkIndicators.find(n => n.role === 'SOURCE');
    assert.ok(sourceInd, 'Source IP indicator identified');
    assert.equal(sourceInd.ip, '185.220.101.45');
    assert.equal(sourceInd.ipVersion, 'IPv4');
    assert.equal(sourceInd.classification, IP_CLASSIFICATION.PUBLIC_IPV4);
    assert.equal(sourceInd.isPrivate, false, 'Identified as public IP');

    const geoResult = await defaultGeoService.resolveIP(sourceInd.ip, sourceInd);
    assert.equal(geoResult.ip, '185.220.101.45');
    assert.equal(geoResult.country, 'Germany');
    assert.equal(geoResult.ipVersion, 'IPv4');
    assert.equal(geoResult.classification, IP_CLASSIFICATION.PUBLIC_IPV4);
    assert.ok(typeof geoResult.latitude === 'number', 'Numeric latitude returned');
    assert.ok(typeof geoResult.longitude === 'number', 'Numeric longitude returned');
    assert.ok(geoResult.latitude >= -90 && geoResult.latitude <= 90);
    assert.ok(geoResult.longitude >= -180 && geoResult.longitude <= 180);
    assert.ok(geoResult.asn, 'ASN returned');
    assert.ok(geoResult.observedEvidence.includes('Germany'), 'Observed evidence populated');
    assert.ok(geoResult.disclaimer.includes('approximate network location'), 'Mandatory disclaimer present');
  });

  // Case 2: Email containing a valid public IPv6 address
  await t.test('2. Email containing a valid public IPv6 address', async () => {
    const rawEml = `From: "IPv6 Transit" <sender@ipv6-corp.net>
To: <target@enterprise.in>
Subject: IPv6 Cloud Infrastructure Notice
Date: Mon, 07 Sep 2026 09:15:00 +0530
Received: from mail.ipv6-corp.net ([2607:f8b0:4002:c08::229]) by mx.google.com; Mon, 07 Sep 2026 09:15:01 +0530

Testing IPv6 forensic resolution.`;

    const parsed = await parseEmailContent(rawEml);
    assert.equal(parsed.originatingIP, '2607:f8b0:4002:c08::229', 'IPv6 extracted without brackets');
    assert.equal(parsed.originatingIPClassification, IP_CLASSIFICATION.PUBLIC_IPV6);

    const networkIndicators = extractNetworkIndicators(parsed);
    const sourceInd = networkIndicators.find(n => n.role === 'SOURCE');
    assert.ok(sourceInd, 'Source IPv6 indicator identified');
    assert.equal(sourceInd.ip, '2607:f8b0:4002:c08::229');
    assert.equal(sourceInd.ipVersion, 'IPv6');
    assert.equal(sourceInd.classification, IP_CLASSIFICATION.PUBLIC_IPV6);
    assert.equal(sourceInd.isPrivate, false, 'Identified as public IPv6');

    class IPv6MockProvider extends BaseGeoProvider {
      constructor() { super('IPv6 Mock Provider'); }
      async lookup(ip) {
        return {
          country: 'United States',
          region: 'California',
          city: 'Mountain View',
          latitude: 37.422,
          longitude: -122.084,
          asn: 'AS15169',
          isp: 'Google LLC'
        };
      }
    }
    const ipv6GeoService = new GeoLocationService({ providers: [new IPv6MockProvider()] });
    const geoResult = await ipv6GeoService.resolveIP(sourceInd.ip, sourceInd);
    assert.equal(geoResult.ip, '2607:f8b0:4002:c08::229');
    assert.equal(geoResult.ipVersion, 'IPv6');
    assert.equal(geoResult.classification, IP_CLASSIFICATION.PUBLIC_IPV6);
    assert.equal(geoResult.status, 'SUCCESS');
    assert.equal(geoResult.latitude, 37.422);
    assert.equal(geoResult.longitude, -122.084);
  });

  // Case 3: Email containing a private IPv4 address
  await t.test('3. Email containing a private IPv4 address', async () => {
    const rawEml = `From: "Internal IT" <helpdesk@corp.local>
To: <user@corp.local>
Subject: Intranet Portal Update
Received: from internal-node (192.168.1.150) by mail.corp.local (10.0.0.5); Mon, 07 Sep 2026 10:30:00 +0530

Local proxy on 172.16.0.25.`;

    const parsed = await parseEmailContent(rawEml);
    assert.equal(parsed.originatingIP, '192.168.1.150');
    assert.equal(parsed.originatingIPClassification, IP_CLASSIFICATION.PRIVATE_IP);

    const networkIndicators = extractNetworkIndicators(parsed);
    assert.ok(networkIndicators.length >= 1, 'Private indicators extracted');
    for (const ind of networkIndicators) {
      assert.equal(ind.isPrivate, true, `${ind.ip} recognized as private`);
      assert.equal(ind.classification, IP_CLASSIFICATION.PRIVATE_IP);
      const geo = await defaultGeoService.resolveIP(ind.ip, ind);
      assert.equal(geo.status, 'PRIVATE_IP');
      assert.equal(geo.geoAvailable, false);
      assert.equal(geo.latitude, null, 'Private IP has no public latitude');
      assert.equal(geo.longitude, null, 'Private IP has no public longitude');
      assert.ok(geo.observedEvidence.includes('private ip') || geo.observedEvidence.includes('reserved non-routable'));
    }
  });

  // Case 4: Email containing a loopback address
  await t.test('4. Email containing a loopback address', async () => {
    const rawEml = `From: "Daemon" <root@localhost>
To: <admin@localhost>
Subject: Local Cron Output
Received: from localhost ([127.0.0.1]) by mail.localdomain (Postfix) with ESMTP; Mon, 07 Sep 2026 11:00:00 +0530
X-Originating-IP: [::1]

Cron job completed.`;

    const parsed = await parseEmailContent(rawEml);
    assert.ok(parsed.originatingIP === '::1' || parsed.originatingIP === '127.0.0.1');
    assert.equal(parsed.originatingIPClassification, IP_CLASSIFICATION.LOOPBACK_IP);

    const networkIndicators = extractNetworkIndicators(parsed);
    for (const ind of networkIndicators) {
      assert.equal(ind.isPrivate, true);
      assert.equal(ind.classification, IP_CLASSIFICATION.LOOPBACK_IP);
      const geo = await defaultGeoService.resolveIP(ind.ip, ind);
      assert.equal(geo.status, 'PRIVATE_IP');
      assert.equal(geo.latitude, null);
      assert.equal(geo.longitude, null);
    }
  });

  // Case 5: Email containing multiple Received headers (MTA sequence & role identification)
  await t.test('5. Email containing multiple Received headers', async () => {
    const rawEml = `From: "Accounts" <billing@partner.com>
To: <target@enterprise.in>
Subject: Payment Remittance
Received: from mx-inbound.enterprise.in (194.26.29.110) by filter.enterprise.in; Mon, 07 Sep 2026 12:00:03 +0530
Received: from relay2.transit.net (194.26.29.110) by mx-inbound.enterprise.in; Mon, 07 Sep 2026 12:00:02 +0530
Received: from client.partner.com (185.220.101.45) by relay2.transit.net; Mon, 07 Sep 2026 12:00:01 +0530

Remittance advice attached.`;

    const parsed = await parseEmailContent(rawEml);
    // Originating IP should be 185.220.101.45 (earliest public sender hop)
    assert.equal(parsed.originatingIP, '185.220.101.45');
    assert.equal(parsed.receivedHops.length, 3);
    assert.equal(parsed.receivedHops[0].index, 0);
    assert.equal(parsed.receivedHops[2].index, 2);

    const networkIndicators = extractNetworkIndicators(parsed);
    const sourceInd = networkIndicators.find(n => n.role === 'SOURCE');
    const mailServerInd = networkIndicators.find(n => n.ip === '194.26.29.110');

    assert.ok(sourceInd, 'Source candidate identified');
    assert.equal(sourceInd.ip, '185.220.101.45');
    assert.ok(mailServerInd, 'Intermediate mail server identified');
    assert.equal(mailServerInd.role, 'MAIL_SERVER');
  });

  // Case 6: Email containing no extractable IP address
  await t.test('6. Email containing no extractable IP address', async () => {
    const rawEml = `From: "Colleague" <colleague@example.com>
To: <target@enterprise.in>
Subject: Quick coffee tomorrow?
Date: Mon, 07 Sep 2026 12:30:00 +0530

Hey, are you free for a quick coffee catchup tomorrow morning?`;

    const parsed = await parseEmailContent(rawEml);
    assert.equal(parsed.originatingIP, '', 'Empty string when no IP found');
    assert.equal(parsed.originatingIPClassification, IP_CLASSIFICATION.INVALID_IP);
    assert.ok(parsed.originatingIPExplanation.includes('could not be determined'));

    const networkIndicators = extractNetworkIndicators(parsed);
    assert.equal(networkIndicators.length, 0, 'Zero network indicators for clean email without IPs');

    const resolved = await defaultGeoService.resolveAllIPs(networkIndicators);
    assert.equal(resolved.length, 0, 'Zero geolocation queries executed');
  });

  // Case 7: Invalid IP address
  await t.test('7. Invalid IP address handling', async () => {
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
      assert.equal(classifyIP(invalid), IP_CLASSIFICATION.INVALID_IP, `${invalid} classified as Invalid IP`);
      const result = await defaultGeoService.resolveIP(invalid);
      assert.equal(result.status, 'INVALID_IP');
      assert.equal(result.latitude, null);
      assert.equal(result.longitude, null);
      assert.equal(result.country, 'Invalid IP');
    }
  });

  // Case 8: Geolocation API timeout
  await t.test('8. Geolocation API timeout handling (coordinates strictly null)', async () => {
    class TimeoutProvider extends BaseGeoProvider {
      constructor() { super('Timeout Provider'); }
      async lookup() {
        const err = new Error('The operation was aborted due to timeout (3000ms exceeded)');
        err.name = 'AbortError';
        throw err;
      }
    }

    const timeoutService = new GeoLocationService({ providers: [new TimeoutProvider()] });
    const result = await timeoutService.resolveIP('8.8.8.8');
    assert.equal(result.status, 'UNAVAILABLE');
    assert.ok(result.error.includes('timeout') || result.error === 'Geolocation unavailable');
    assert.equal(result.country, 'Geolocation unavailable');
    assert.equal(result.latitude, null, 'Coordinates strictly null on provider timeout');
    assert.equal(result.longitude, null, 'Coordinates strictly null on provider timeout');
    assert.equal(result.isDemo, false);
  });

  // Case 9: Geolocation API rate-limit response
  await t.test('9. Geolocation API rate-limit response handling', async () => {
    class RateLimitedProvider extends BaseGeoProvider {
      constructor() { super('Rate Limited Provider'); }
      async lookup() {
        return {
          status: 'UNAVAILABLE',
          lookupStatus: 'RATE_LIMITED',
          error: 'Rate limit exceeded: 429 Too Many Requests',
          country: 'Geolocation unavailable',
          latitude: null,
          longitude: null
        };
      }
    }

    const rateLimitService = new GeoLocationService({ providers: [new RateLimitedProvider()] });
    const result = await rateLimitService.resolveIP('8.8.8.8');
    assert.equal(result.status, 'UNAVAILABLE');
    assert.equal(result.latitude, null);
    assert.equal(result.longitude, null);
    assert.ok(result.error.toLowerCase().includes('rate limit') || result.lookupStatus === 'RATE_LIMITED');
  });

  // Case 10: Geolocation API invalid response
  await t.test('10. Geolocation API invalid response handling (malformed / non-numeric)', async () => {
    class MalformedProvider extends BaseGeoProvider {
      constructor() { super('Malformed Provider'); }
      async lookup() {
        return {
          country: 'Unknown',
          latitude: 'invalid_lat_string',
          longitude: 999.999 // Out of bounds
        };
      }
    }

    const malformedService = new GeoLocationService({ providers: [new MalformedProvider()] });
    const result = await malformedService.resolveIP('8.8.8.8');
    assert.equal(result.latitude, null, 'Non-numeric latitude sanitized to null');
    assert.equal(result.longitude, null, 'Out of bounds longitude sanitized to null');
  });

  // Case 11: Valid IP with missing location fields
  await t.test('11. Valid IP with missing location fields', async () => {
    class SparseProvider extends BaseGeoProvider {
      constructor() { super('Sparse Provider'); }
      async lookup() {
        return {
          country: 'France',
          latitude: 48.8566,
          longitude: 2.3522
        };
      }
    }

    const sparseService = new GeoLocationService({ providers: [new SparseProvider()] });
    const result = await sparseService.resolveIP('8.8.8.8');
    assert.equal(result.status, 'SUCCESS');
    assert.equal(result.country, 'France');
    assert.equal(result.latitude, 48.8566);
    assert.equal(result.longitude, 2.3522);
    assert.equal(typeof result.city, 'string');
    assert.equal(typeof result.region, 'string');
    assert.equal(typeof result.asn, 'string');
  });

  // Case 12: Multiple public IP addresses in one email
  await t.test('12. Multiple public IP addresses in one email', async () => {
    const rawEml = `From: "Operations" <ops@multihop-service.online>
To: <target@enterprise.in>
Subject: Critical Systems Upgrade
Received: from relay2.transit.net (194.26.29.110) by mx.enterprise.in; Mon, 07 Sep 2026 10:00:02 +0530
Received: from mail.origin-source.org (185.220.101.45) by relay1.transit.net; Mon, 07 Sep 2026 10:00:01 +0530

Urgent notice: Verify directory status at http://45.154.255.82/login immediately.`;

    const parsed = await parseEmailContent(rawEml);
    const networkIndicators = extractNetworkIndicators(parsed);

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

    for (const g of geoList) {
      assert.equal(typeof g.latitude, 'number');
      assert.equal(typeof g.longitude, 'number');
      assert.ok(g.latitude >= -90 && g.latitude <= 90);
      assert.ok(g.longitude >= -180 && g.longitude <= 180);
    }
  });

  // Case 13: Missing API key handling
  await t.test('13. Missing API key handling', async () => {
    class KeylessProvider extends BaseGeoProvider {
      constructor() { super('Keyless Provider'); }
      async lookup() { return null; }
    }

    const keylessService = new GeoLocationService({ providers: [new KeylessProvider()] });
    const result = await keylessService.resolveIP('1.1.1.1');
    assert.equal(result.status, 'UNAVAILABLE');
    assert.equal(result.error, 'Geolocation unavailable');
    assert.equal(result.latitude, null);
    assert.equal(result.longitude, null);
  });

  // Case 14: Multiple markers bounds check
  await t.test('14. Multiple markers bounds check', async () => {
    const multiIPs = [
      { ip: '185.220.101.45', role: 'SOURCE' },
      { ip: '45.154.255.82', role: 'URL_HOST' },
      { ip: '194.26.29.110', role: 'MAIL_SERVER' }
    ];

    const results = await defaultGeoService.resolveAllIPs(multiIPs);
    assert.equal(results.length, 3);

    const coords = results.map(r => ({ lat: r.latitude, lon: r.longitude }));
    for (const c of coords) {
      assert.equal(typeof c.lat, 'number');
      assert.equal(typeof c.lon, 'number');
      assert.ok(c.lat >= -90 && c.lat <= 90);
      assert.ok(c.lon >= -180 && c.lon <= 180);
    }

    const uniqueLats = new Set(coords.map(c => c.lat));
    assert.equal(uniqueLats.size, 3, 'Three distinct geographic pin locations');
  });

  // Case 15: Performance & In-memory Caching verification
  await t.test('15. Performance & In-memory Caching verification', async () => {
    let callCounter = 0;
    class CountingProvider extends BaseGeoProvider {
      constructor() { super('Counting Provider'); }
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

    const testCacheService = new GeoLocationService({ providers: [new CountingProvider()] });

    // Use a routable public IP
    const res1 = await testCacheService.resolveIP('8.8.8.8');
    assert.equal(callCounter, 1, 'Provider called on initial query');
    assert.equal(res1.city, 'Test City');

    // Query identical IP 10 times
    for (let i = 0; i < 10; i++) {
      const cachedRes = await testCacheService.resolveIP('8.8.8.8');
      assert.equal(cachedRes.city, 'Test City');
    }

    // Provider should NOT have been called again (zero repeated API calls)
    assert.equal(callCounter, 1, 'Provider call count remained 1 due to in-memory cache');
  });

  // Case 16: Complete email -> IOC -> geolocation -> evidence-fusion flow
  await t.test('16. Complete email -> IOC -> geolocation -> evidence-fusion flow', async () => {
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
    assert.ok(GEO_LEGAL_DISCLAIMER.includes('approximate network location'));
  });

});
