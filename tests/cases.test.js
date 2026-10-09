/**
 * MAVERICK — Persistent Email Case Database & Priority Queue Test Suite
 * Smart India Hackathon 2026
 * 
 * Verifies all 17 SOC Case Management Requirements:
 * 1. Create case
 * 2. Save analyzed email with complete forensic findings
 * 3. Generate unique Case ID conforming to MAV-2026-XXXXXXXX
 * 4. Critical priority mapping (80-100)
 * 5. High priority mapping (60-79)
 * 6. Medium priority mapping (30-59)
 * 7. Low priority mapping (0-29)
 * 8. Sort by threat score DESC (Mandatory test: 92, 45, 88, 15, 72 -> 92, 88, 72, 45, 15)
 * 9. Get single case by Case ID
 * 10. Filter by priority
 * 11. Filter by classification
 * 12. Pagination support (page, limit, totalPages)
 * 13. Duplicate email handling using SHA-256 hash
 * 14. Archive case via status update (no destructive deletion)
 * 15. Database unavailable failure handling
 * 16. Dashboard statistics calculation from database records
 * 17. Forensic report score matches stored Evidence Fusion score
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { 
  saveCase, 
  getCases, 
  getCaseByCaseId, 
  updateCaseStatus, 
  getCaseStats,
  computeEmailHash,
  setTestStore,
  resetTestStore,
  DatabaseUnavailableError 
} from '../server/caseDatabase.js';
import { getThreatPriority, getPriorityStyle } from '../src/services/priorityHelper.js';
import { generateCaseId, buildForensicReport } from '../src/services/forensicReportService.js';
import { server } from '../server/server.js';
import casesHandler from '../api/cases/index.js';
import statsHandler from '../api/cases/stats.js';
import caseItemHandler from '../api/cases/[caseId].js';
import healthHandler from '../api/health.js';

test('MAVERICK Persistent Email Case Database & Priority Queue Suite', async (t) => {

  // Initialize fresh in-memory test store for test isolation
  let mockStore = [];
  setTestStore(mockStore);

  t.afterEach(() => {
    mockStore = [];
    setTestStore(mockStore);
  });

  t.after(() => {
    resetTestStore();
  });

  // =========================================================================
  // 1. CREATE CASE
  // =========================================================================
  await t.test('1. Create case: inserts new case record with active status', async () => {
    const res = await saveCase({
      email: {
        subject: 'Urgent Account Verification',
        sender: 'security@alert-portal.online',
        recipient: 'analyst@maverick.security',
        date: '2026-09-05T10:00:00Z'
      },
      fusion: { threatScore: 85, riskLevel: 'CRITICAL' },
      aiThreat: { phishingProbability: 92, confidence: 95 }
    });

    assert.equal(res.isDuplicate, false);
    assert.ok(res.caseId);
    assert.match(res.caseId, /^MAV-2026-[A-F0-9]{8}$/i);
    assert.equal(res.case.status, 'active');
    assert.equal(res.case.threatScore, 85);
    assert.equal(res.case.priority, 'Critical');
  });

  // =========================================================================
  // 2. SAVE ANALYZED EMAIL WITH FORENSIC FINDINGS
  // =========================================================================
  await t.test('2. Save analyzed email: stores complete forensic findings', async () => {
    const res = await saveCase({
      email: {
        subject: 'Wire Transfer Authorization',
        sender: 'cfo@spoofed-exec.com',
        recipient: 'finance@corp.in',
        headers: { 'from': 'cfo@spoofed-exec.com', 'reply-to': 'thief@external.io' },
        rawSnippet: 'From: cfo@spoofed-exec.com\nTo: finance@corp.in\nSubject: Wire Transfer'
      },
      fusion: {
        threatScore: 94,
        riskLevel: 'CRITICAL',
        verifiedReasons: ['Reply-To mismatch detected', 'SPF Softfail observed']
      },
      aiThreat: { phishingProbability: 98, model: 'TF-IDF + Logistic Regression' },
      iocs: [{ type: 'IP', value: '185.220.101.45', status: 'MALICIOUS' }],
      emailAuth: { spf: { status: 'FAIL' }, dkim: { status: 'FAIL' }, dmarc: { status: 'FAIL' } },
      geoInfo: { ip: '185.220.101.45', country: 'Germany', asn: 'AS9009' },
      attachments: [{ filename: 'invoice.pdf.exe', isSuspicious: true }],
      recommendations: [{ action: 'Quarantine mailbox', priority: 'CRITICAL' }],
      timeline: [{ step: 'Ingestion complete' }]
    });

    const item = await getCaseByCaseId(res.caseId);
    assert.ok(item);
    assert.equal(item.subject, 'Wire Transfer Authorization');
    assert.equal(item.threatScore, 94);
    assert.equal(item.priority, 'Critical');
    assert.ok(item.headers);
    assert.equal(item.iocs.length, 1);
    assert.equal(item.authenticationResults.spf.status, 'FAIL');
    assert.equal(item.attachmentFindings.length, 1);
    assert.equal(item.recommendations.length, 1);
    assert.equal(item.timeline.length, 1);
  });

  // =========================================================================
  // 3. GENERATE UNIQUE CASE ID
  // =========================================================================
  await t.test('3. Generate unique Case ID: conforms to MAV-2026-XXXXXXXX', () => {
    const id1 = generateCaseId();
    const id2 = generateCaseId();
    const id3 = generateCaseId('cfo@example.com');

    assert.match(id1, /^MAV-2026-[A-F0-9]{8}$/i);
    assert.match(id2, /^MAV-2026-[A-F0-9]{8}$/i);
    assert.match(id3, /^MAV-2026-[A-F0-9]{8}$/i);
    assert.notEqual(id1, id2);
  });

  // =========================================================================
  // 4, 5, 6, 7. PRIORITY CALCULATION
  // =========================================================================
  await t.test('4. Critical priority: maps 80-100 to Critical', () => {
    assert.equal(getThreatPriority(80), 'Critical');
    assert.equal(getThreatPriority(92), 'Critical');
    assert.equal(getThreatPriority(100), 'Critical');
  });

  await t.test('5. High priority: maps 60-79 to High', () => {
    assert.equal(getThreatPriority(60), 'High');
    assert.equal(getThreatPriority(75), 'High');
    assert.equal(getThreatPriority(79), 'High');
  });

  await t.test('6. Medium priority: maps 30-59 to Medium', () => {
    assert.equal(getThreatPriority(30), 'Medium');
    assert.equal(getThreatPriority(45), 'Medium');
    assert.equal(getThreatPriority(59), 'Medium');
  });

  await t.test('7. Low priority: maps 0-29 to Low', () => {
    assert.equal(getThreatPriority(0), 'Low');
    assert.equal(getThreatPriority(15), 'Low');
    assert.equal(getThreatPriority(29), 'Low');
  });

  // =========================================================================
  // 8. MANDATORY TEST: SORT BY THREAT SCORE DESC
  // =========================================================================
  await t.test('8. Sort by threat score DESC: [92, 45, 88, 15, 72] -> [92, 88, 72, 45, 15]', async () => {
    const scores = [92, 45, 88, 15, 72];
    for (const s of scores) {
      await saveCase({
        email: { subject: `Test Score ${s}`, sender: `user${s}@test.local` },
        fusion: { threatScore: s },
        rawContent: `Unique seed for score ${s}-${Math.random()}`
      });
    }

    const { cases } = await getCases({ status: 'all' });
    const fetchedScores = cases.map(c => c.threatScore);

    assert.deepEqual(fetchedScores, [92, 88, 72, 45, 15], 'Cases must be ordered by threatScore DESC');
  });

  // =========================================================================
  // 9. GET SINGLE CASE
  // =========================================================================
  await t.test('9. Get single case: retrieves complete stored investigation without re-scanning', async () => {
    const res = await saveCase({
      email: { subject: 'Single Case Lookup', sender: 'test@lookup.org' },
      fusion: { threatScore: 78 },
      aiThreat: { phishingProbability: 82 }
    });

    const item = await getCaseByCaseId(res.caseId);
    assert.ok(item);
    assert.equal(item.caseId, res.caseId);
    assert.equal(item.subject, 'Single Case Lookup');
    assert.equal(item.threatScore, 78);
  });

  // =========================================================================
  // 10. FILTER BY PRIORITY
  // =========================================================================
  await t.test('10. Filter by priority: Critical, High, Medium, Low', async () => {
    await saveCase({ email: { subject: 'Crit' }, fusion: { threatScore: 95 }, rawContent: 'c1' });
    await saveCase({ email: { subject: 'High' }, fusion: { threatScore: 65 }, rawContent: 'c2' });
    await saveCase({ email: { subject: 'Med' }, fusion: { threatScore: 40 }, rawContent: 'c3' });
    await saveCase({ email: { subject: 'Low' }, fusion: { threatScore: 10 }, rawContent: 'c4' });

    const critOnly = await getCases({ priority: 'Critical' });
    assert.equal(critOnly.cases.length, 1);
    assert.equal(critOnly.cases[0].priority, 'Critical');

    const highOnly = await getCases({ priority: 'High' });
    assert.equal(highOnly.cases.length, 1);
    assert.equal(highOnly.cases[0].priority, 'High');

    const medOnly = await getCases({ priority: 'Medium' });
    assert.equal(medOnly.cases.length, 1);
    assert.equal(medOnly.cases[0].priority, 'Medium');

    const lowOnly = await getCases({ priority: 'Low' });
    assert.equal(lowOnly.cases.length, 1);
    assert.equal(lowOnly.cases[0].priority, 'Low');
  });

  // =========================================================================
  // 11. FILTER BY CLASSIFICATION
  // =========================================================================
  await t.test('11. Filter by classification: Phishing vs Legitimate', async () => {
    await saveCase({ email: { subject: 'Phish Mail' }, classification: 'Phishing', fusion: { threatScore: 90 }, rawContent: 'p1' });
    await saveCase({ email: { subject: 'Clean Mail' }, classification: 'Legitimate', fusion: { threatScore: 10 }, rawContent: 'p2' });

    const phish = await getCases({ classification: 'Phishing' });
    assert.equal(phish.cases.length, 1);
    assert.equal(phish.cases[0].classification, 'Phishing');

    const legit = await getCases({ classification: 'Legitimate' });
    assert.equal(legit.cases.length, 1);
    assert.equal(legit.cases[0].classification, 'Legitimate');
  });

  // =========================================================================
  // 12. PAGINATION
  // =========================================================================
  await t.test('12. Pagination: respects page, limit, and total count', async () => {
    for (let i = 1; i <= 5; i++) {
      await saveCase({
        email: { subject: `Item ${i}` },
        fusion: { threatScore: i * 15 },
        rawContent: `pag-${i}`
      });
    }

    const page1 = await getCases({ page: 1, limit: 2 });
    assert.equal(page1.cases.length, 2);
    assert.equal(page1.total, 5);
    assert.equal(page1.totalPages, 3);

    const page2 = await getCases({ page: 2, limit: 2 });
    assert.equal(page2.cases.length, 2);
    assert.notEqual(page1.cases[0].caseId, page2.cases[0].caseId);

    const page3 = await getCases({ page: 3, limit: 2 });
    assert.equal(page3.cases.length, 1);
  });

  // =========================================================================
  // 13. DUPLICATE EMAIL HANDLING
  // =========================================================================
  await t.test('13. Duplicate email handling: detects duplicate via emailHash without unbounded rows', async () => {
    const rawContent = 'From: duplicate@target.com\nSubject: Invoice Check\nBody: Review this file.';
    const emailHash = computeEmailHash(rawContent);

    // Initial scan
    const firstScan = await saveCase({
      email: { subject: 'Invoice Check', sender: 'duplicate@target.com', rawSnippet: rawContent },
      fusion: { threatScore: 82 },
      emailHash,
      rawContent
    });
    assert.equal(firstScan.isDuplicate, false);

    // Re-scan identical email
    const secondScan = await saveCase({
      email: { subject: 'Invoice Check', sender: 'duplicate@target.com', rawSnippet: rawContent },
      fusion: { threatScore: 85 },
      emailHash,
      rawContent
    });
    assert.equal(secondScan.isDuplicate, true);
    assert.equal(secondScan.caseId, firstScan.caseId, 'Duplicate scan must preserve original Case ID');

    const { cases } = await getCases({ status: 'all' });
    assert.equal(cases.length, 1, 'Duplicate email must not create a duplicate database row');
    assert.equal(cases[0].threatScore, 85, 'Existing case must be updated with latest scan findings');
  });

  // =========================================================================
  // 14. ARCHIVE CASE
  // =========================================================================
  await t.test('14. Archive case: soft-archiving without destructive deletion', async () => {
    const res = await saveCase({
      email: { subject: 'Case To Archive' },
      fusion: { threatScore: 70 },
      rawContent: 'arch-1'
    });

    // Default view shows active cases
    let activeCases = await getCases({ status: 'active' });
    assert.equal(activeCases.cases.length, 1);

    // Soft archive
    const updated = await updateCaseStatus(res.caseId, 'archived');
    assert.equal(updated.status, 'archived');

    // Default active view excludes archived cases
    activeCases = await getCases({ status: 'active' });
    assert.equal(activeCases.cases.length, 0);

    // Archived filter returns archived case
    const archivedCases = await getCases({ status: 'archived' });
    assert.equal(archivedCases.cases.length, 1);
    assert.equal(archivedCases.cases[0].caseId, res.caseId);
  });

  // =========================================================================
  // 15. DATABASE UNAVAILABLE FAILURE HANDLING
  // =========================================================================
  await t.test('15. Database unavailable: throws DatabaseUnavailableError when DB offline', async () => {
    // Reset test store and unset DATABASE_URL to simulate offline DB
    resetTestStore();
    const origUrl = process.env.DATABASE_URL;
    delete process.env.DATABASE_URL;

    try {
      await assert.rejects(
        async () => {
          await saveCase({
            email: { subject: 'Offline DB' },
            fusion: { threatScore: 50 }
          });
        },
        DatabaseUnavailableError
      );
    } finally {
      process.env.DATABASE_URL = origUrl;
      setTestStore(mockStore);
    }
  });

  // =========================================================================
  // 16. DASHBOARD STATISTICS
  // =========================================================================
  await t.test('16. Dashboard statistics: compiles real database counts & top threats', async () => {
    await saveCase({ email: { subject: 'Crit 1' }, fusion: { threatScore: 95 }, rawContent: 's1' });
    await saveCase({ email: { subject: 'Crit 2' }, fusion: { threatScore: 85 }, rawContent: 's2' });
    await saveCase({ email: { subject: 'High 1' }, fusion: { threatScore: 70 }, rawContent: 's3' });
    await saveCase({ email: { subject: 'Med 1' }, fusion: { threatScore: 45 }, rawContent: 's4' });
    await saveCase({ email: { subject: 'Low 1' }, fusion: { threatScore: 12 }, rawContent: 's5' });

    const stats = await getCaseStats();
    assert.equal(stats.totalCases, 5);
    assert.equal(stats.critical, 2);
    assert.equal(stats.high, 1);
    assert.equal(stats.medium, 1);
    assert.equal(stats.low, 1);
    assert.equal(stats.topThreats.length, 4);
    assert.equal(stats.topThreats[0].threatScore, 95);
    assert.equal(stats.topThreats[1].threatScore, 85);
  });

  // =========================================================================
  // 17. REPORT SCORE MATCHES STORED SCORE
  // =========================================================================
  await t.test('17. Report score matches stored score: never diverges during report generation', async () => {
    const fusion = { threatScore: 89, riskLevel: 'CRITICAL', verifiedReasons: ['Spoofed sender'] };
    const res = await saveCase({
      email: { subject: 'Report Integrity Test', sender: 'spoof@audit.org' },
      fusion,
      rawContent: 'rep-score-1'
    });

    const stored = await getCaseByCaseId(res.caseId);
    assert.equal(stored.threatScore, 89);

    const report = await buildForensicReport(stored);
    assert.equal(report.threatAssessment.overallScore, stored.threatScore);
    assert.equal(report.threatAssessment.overallScore, 89);
  });

  // =========================================================================
  // 18. HTTP API ENDPOINTS VERIFICATION
  // =========================================================================
  await t.test('18. HTTP Gateway: /api/cases, /api/cases/:caseId, /api/cases/stats', async () => {
    // Start server on ephemeral port for live HTTP integration testing
    const testServer = http.createServer(server.listeners('request')[0]);
    await new Promise(resolve => testServer.listen(0, resolve));
    const port = testServer.address().port;
    const baseUrl = `http://127.0.0.1:${port}`;

    try {
      // 1. POST /api/cases
      const postRes = await fetch(`${baseUrl}/api/cases`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          email: { subject: 'API Case 1', sender: 'user@api.com' },
          fusion: { threatScore: 92 },
          rawContent: 'api-http-1'
        })
      });
      assert.equal(postRes.status, 201);
      const postData = await postRes.json();
      assert.ok(postData.caseId);
      assert.equal(postData.isDuplicate, false);

      // 2. GET /api/cases (default sorted by threatScore DESC)
      await fetch(`${baseUrl}/api/cases`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          email: { subject: 'API Case 2', sender: 'user2@api.com' },
          fusion: { threatScore: 45 },
          rawContent: 'api-http-2'
        })
      });

      const listRes = await fetch(`${baseUrl}/api/cases`);
      assert.equal(listRes.status, 200);
      const listData = await listRes.json();
      assert.ok(Array.isArray(listData));
      assert.equal(listData.length, 2);
      assert.equal(listData[0].threatScore, 92, 'Highest threat score must appear first');
      assert.equal(listData[1].threatScore, 45);

      // 3. GET /api/cases/:caseId
      const singleRes = await fetch(`${baseUrl}/api/cases/${postData.caseId}`);
      assert.equal(singleRes.status, 200);
      const singleData = await singleRes.json();
      assert.equal(singleData.caseId, postData.caseId);
      assert.equal(singleData.subject, 'API Case 1');

      // 4. PATCH /api/cases/:caseId
      const patchRes = await fetch(`${baseUrl}/api/cases/${postData.caseId}`, {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ status: 'archived' })
      });
      assert.equal(patchRes.status, 200);
      const patchData = await patchRes.json();
      assert.equal(patchData.case.status, 'archived');

      // 5. GET /api/cases/stats
      const statsRes = await fetch(`${baseUrl}/api/cases/stats`);
      assert.equal(statsRes.status, 200);
      const statsData = await statsRes.json();
      assert.equal(statsData.totalCases, 1); // 1 active remaining
    } finally {
      await new Promise(resolve => testServer.close(resolve));
    }
  });

  // =========================================================================
  // 19. HTTP 405 METHOD NOT ALLOWED ON UNSUPPORTED METHODS
  // =========================================================================
  await t.test('19. HTTP 405 Method Not Allowed handling on unsupported methods', async () => {
    const testServer = http.createServer(server.listeners('request')[0]);
    await new Promise(resolve => testServer.listen(0, resolve));
    const port = testServer.address().port;
    const baseUrl = `http://127.0.0.1:${port}`;

    try {
      // 1. PUT /api/cases -> 405
      const putRes = await fetch(`${baseUrl}/api/cases`, { method: 'PUT' });
      assert.equal(putRes.status, 405);
      assert.equal(putRes.headers.get('allow'), 'GET, POST, OPTIONS');

      // 2. DELETE /api/cases -> 405
      const delRes = await fetch(`${baseUrl}/api/cases`, { method: 'DELETE' });
      assert.equal(delRes.status, 405);

      // 3. POST /api/cases/stats -> 405
      const postStatsRes = await fetch(`${baseUrl}/api/cases/stats`, { method: 'POST' });
      assert.equal(postStatsRes.status, 405);
      assert.equal(postStatsRes.headers.get('allow'), 'GET, OPTIONS');

      // 4. POST /api/health -> 405
      const postHealthRes = await fetch(`${baseUrl}/api/health`, { method: 'POST' });
      assert.equal(postHealthRes.status, 405);
      assert.equal(postHealthRes.headers.get('allow'), 'GET, OPTIONS');

      // 5. POST /api/cases/:caseId -> 405
      const postCaseIdRes = await fetch(`${baseUrl}/api/cases/MAV-2026-TESTCASE`, { method: 'POST' });
      assert.equal(postCaseIdRes.status, 405);
      assert.equal(postCaseIdRes.headers.get('allow'), 'GET, PATCH, OPTIONS');
    } finally {
      await new Promise(resolve => testServer.close(resolve));
    }
  });

  // =========================================================================
  // 20. TRAILING SLASH NORMALIZATION
  // =========================================================================
  await t.test('20. Trailing slash normalization: handles trailing slashes without 404 or 405', async () => {
    const testServer = http.createServer(server.listeners('request')[0]);
    await new Promise(resolve => testServer.listen(0, resolve));
    const port = testServer.address().port;
    const baseUrl = `http://127.0.0.1:${port}`;

    try {
      // POST /api/cases/
      const postRes = await fetch(`${baseUrl}/api/cases/`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          email: { subject: 'Trailing Slash Post', sender: 'trail@slash.io' },
          fusion: { threatScore: 77 },
          rawContent: 'trail-post-1'
        })
      });
      assert.equal(postRes.status, 201);
      const postData = await postRes.json();
      assert.ok(postData.caseId);

      // GET /api/cases/
      const getRes = await fetch(`${baseUrl}/api/cases/`);
      assert.equal(getRes.status, 200);

      // GET /api/cases/stats/
      const statsRes = await fetch(`${baseUrl}/api/cases/stats/`);
      assert.equal(statsRes.status, 200);

      // GET /api/health/
      const healthRes = await fetch(`${baseUrl}/api/health/`);
      assert.equal(healthRes.status, 200);

      // GET /api/cases/:caseId/
      const singleRes = await fetch(`${baseUrl}/api/cases/${postData.caseId}/`);
      assert.equal(singleRes.status, 200);
    } finally {
      await new Promise(resolve => testServer.close(resolve));
    }
  });

  // =========================================================================
  // 21. DATABASE UNAVAILABLE HTTP 503 ERROR HANDLING
  // =========================================================================
  await t.test('21. Database unavailable: HTTP gateway returns 503 Service Unavailable', async () => {
    resetTestStore();
    const origUrl = process.env.DATABASE_URL;
    delete process.env.DATABASE_URL;

    const testServer = http.createServer(server.listeners('request')[0]);
    await new Promise(resolve => testServer.listen(0, resolve));
    const port = testServer.address().port;
    const baseUrl = `http://127.0.0.1:${port}`;

    try {
      // POST /api/cases when DB unavailable
      const postRes = await fetch(`${baseUrl}/api/cases`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          email: { subject: 'Offline Case', sender: 'offline@db.io' },
          fusion: { threatScore: 80 }
        })
      });
      assert.equal(postRes.status, 503);
      const postData = await postRes.json();
      assert.equal(postData.success, false);
      assert.equal(postData.status, 'DB_UNAVAILABLE');

      // GET /api/cases when DB unavailable
      const getRes = await fetch(`${baseUrl}/api/cases`);
      assert.equal(getRes.status, 503);
      const getData = await getRes.json();
      assert.equal(getData.success, false);

      // GET /api/cases/stats when DB unavailable
      const statsRes = await fetch(`${baseUrl}/api/cases/stats`);
      assert.equal(statsRes.status, 503);
    } finally {
      process.env.DATABASE_URL = origUrl;
      setTestStore(mockStore);
      await new Promise(resolve => testServer.close(resolve));
    }
  });

  // =========================================================================
  // 22. VERCEL SERVERLESS FUNCTION HANDLERS VERIFICATION
  // =========================================================================
  await t.test('22. Vercel serverless handlers: support GET, POST, OPTIONS and reject others with 405', async () => {
    // Helper to mock Vercel req/res
    function createMockRes() {
      const headers = {};
      let statusCode = 200;
      let bodyData = null;
      return {
        statusCode,
        setHeader(k, v) { headers[k.toLowerCase()] = v; },
        getHeader(k) { return headers[k.toLowerCase()]; },
        status(code) { statusCode = code; this.statusCode = code; return this; },
        json(data) { bodyData = data; return this; },
        end(data) { if (data) bodyData = data; return this; },
        writeHead(code, h = {}) {
          statusCode = code;
          this.statusCode = code;
          for (const [k, v] of Object.entries(h)) headers[k.toLowerCase()] = v;
          return this;
        },
        _getData: () => bodyData,
        _getStatus: () => statusCode,
        _getHeader: (k) => headers[k.toLowerCase()]
      };
    }

    // 1. Health handler
    const healthRes = createMockRes();
    await healthHandler({ method: 'GET' }, healthRes);
    assert.equal(healthRes._getStatus(), 200);
    assert.equal(healthRes._getHeader('access-control-allow-origin'), '*');

    // Health handler 405 on POST
    const healthPostRes = createMockRes();
    await healthHandler({ method: 'POST' }, healthPostRes);
    assert.equal(healthPostRes._getStatus(), 405);

    // 2. Cases handler OPTIONS
    const optRes = createMockRes();
    await casesHandler({ method: 'OPTIONS' }, optRes);
    assert.equal(optRes._getStatus(), 204);

    // 3. Cases handler POST
    const postRes = createMockRes();
    await casesHandler({
      method: 'POST',
      body: {
        email: { subject: 'Serverless Case', sender: 'test@serverless.io' },
        fusion: { threatScore: 84 },
        rawContent: 'serverless-content-1'
      }
    }, postRes);
    assert.equal(postRes._getStatus(), 201);
    const postData = postRes._getData();
    assert.ok(postData.caseId);

    // 4. Cases handler GET
    const getRes = createMockRes();
    await casesHandler({ method: 'GET', query: {} }, getRes);
    assert.equal(getRes._getStatus(), 200);
    const casesData = getRes._getData();
    assert.ok(Array.isArray(casesData));
    assert.equal(casesData[0].threatScore, 84);

    // 5. Cases handler 405 on PUT
    const putRes = createMockRes();
    await casesHandler({ method: 'PUT' }, putRes);
    assert.equal(putRes._getStatus(), 405);

    // 6. Stats handler GET
    const statsRes = createMockRes();
    await statsHandler({ method: 'GET' }, statsRes);
    assert.equal(statsRes._getStatus(), 200);

    // 7. Case item handler GET & PATCH
    const itemGetRes = createMockRes();
    await caseItemHandler({ method: 'GET', query: { caseId: postData.caseId } }, itemGetRes);
    assert.equal(itemGetRes._getStatus(), 200);
    assert.equal(itemGetRes._getData().caseId, postData.caseId);

    const itemPatchRes = createMockRes();
    await caseItemHandler({ method: 'PATCH', query: { caseId: postData.caseId }, body: { status: 'archived' } }, itemPatchRes);
    assert.equal(itemPatchRes._getStatus(), 200);
    assert.equal(itemPatchRes._getData().case.status, 'archived');
  });

  // =========================================================================
  // 23. FRONTEND FAILURE HANDLING: HTTP 405 & PRESERVATION OF ANALYSIS
  // =========================================================================
  await t.test('23. Frontend failure handling: 405 gracefully flags DB unavailable and preserves analysis', async () => {
    // Start mock server simulating Vercel static rewrite returning 405 HTML
    const mockVercelServer = http.createServer((req, res) => {
      res.writeHead(405, { 'Content-Type': 'text/html' });
      res.end('<html><head><title>405 Method Not Allowed</title></head><body><h1>405 Method Not Allowed</h1></body></html>');
    });
    await new Promise(resolve => mockVercelServer.listen(0, resolve));
    const port = mockVercelServer.address().port;
    const badUrl = `http://127.0.0.1:${port}`;

    try {
      const postRes = await fetch(`${badUrl}/api/cases`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email: { subject: 'Test 405' } })
      });
      assert.equal(postRes.status, 405);

      // Verify analysis data is strictly preserved and never marked as saved
      const sampleAnalysis = {
        email: { subject: 'Critical Spearphish', sender: 'attacker@evil.org' },
        fusion: { threatScore: 91, riskLevel: 'CRITICAL' },
        caseItem: { caseId: 'MAV-2026-PERSIST1', isSaved: false, saveError: 'HTTP 405' }
      };

      assert.equal(sampleAnalysis.caseItem.isSaved, false, 'Failed save must NEVER mark case as saved');
      assert.equal(sampleAnalysis.fusion.threatScore, 91, 'Threat assessment must remain completely intact');
      assert.ok(sampleAnalysis.caseItem.saveError);
    } finally {
      await new Promise(resolve => mockVercelServer.close(resolve));
    }
  });

  // =========================================================================
  // 24. RETRY SAVING CASE: CASE ID & SHA-256 DEDUPLICATION PRESERVATION
  // =========================================================================
  await t.test('24. Retry Saving Case: preserves exact case ID and SHA-256 deduplication behavior', async () => {
    const fixedCaseId = 'MAV-2026-A1B2C3D4';
    const rawSnippet = 'From: ceo@phish.net\nTo: finance@corp.in\nSubject: Invoice #99812';
    const emailHash = computeEmailHash(rawSnippet);

    // Initial save with explicit caseId
    const firstSave = await saveCase({
      caseId: fixedCaseId,
      emailHash,
      email: {
        subject: 'Invoice #99812',
        sender: 'ceo@phish.net',
        recipient: 'finance@corp.in',
        rawSnippet
      },
      fusion: { threatScore: 92, riskLevel: 'CRITICAL' }
    });

    assert.equal(firstSave.isDuplicate, false);
    assert.equal(firstSave.caseId, fixedCaseId, 'Case ID must be preserved from client');
    assert.equal(firstSave.case.emailHash, emailHash);

    // Resend / Retry save with same caseId and emailHash
    const retrySave = await saveCase({
      caseId: fixedCaseId,
      emailHash,
      email: {
        subject: 'Invoice #99812',
        sender: 'ceo@phish.net',
        recipient: 'finance@corp.in',
        rawSnippet
      },
      fusion: { threatScore: 95, riskLevel: 'CRITICAL' }
    });

    assert.equal(retrySave.isDuplicate, true, 'Retry with same emailHash must be identified as duplicate');
    assert.equal(retrySave.caseId, fixedCaseId, 'Case ID must NOT change on retry save');
    assert.equal(retrySave.case.threatScore, 95, 'Case must be updated with latest intelligence');
  });

  // =========================================================================
  // 25. PERSISTENCE VERIFICATION: CASE SAVES, PERSISTS, & SORTS DESC BY THREAT SCORE
  // =========================================================================
  await t.test('25. Persistence verification: saves case, persists across refresh, and orders by threatScore DESC', async () => {
    const testServer = http.createServer(server.listeners('request')[0]);
    await new Promise(resolve => testServer.listen(0, resolve));
    const port = testServer.address().port;
    const baseUrl = `http://127.0.0.1:${port}`;

    try {
      // Clear test store
      setTestStore([]);

      // 1. Save 3 cases with varying threat scores
      const casesToSave = [
        {
          caseId: 'MAV-2026-48000001',
          email: { subject: 'Suspicious Storage Notification', sender: 'cloud@storage-notice.biz' },
          fusion: { threatScore: 48, riskLevel: 'MEDIUM', verifiedReasons: ['Unusual link structure'] },
          rawContent: 'storage-warning-1'
        },
        {
          caseId: 'MAV-2026-96000001',
          email: { subject: 'Urgent: Wire Transfer Authorized', sender: 'cfo@vip-executive.net' },
          fusion: { threatScore: 96, riskLevel: 'CRITICAL', verifiedReasons: ['Executive spoofing', 'Zero-day attachment'] },
          rawContent: 'wire-transfer-critical-1'
        },
        {
          caseId: 'MAV-2026-12000001',
          email: { subject: 'Weekly Team Standup Notes', sender: 'team@internal.org' },
          fusion: { threatScore: 12, riskLevel: 'LOW', verifiedReasons: ['Clean authentication'] },
          rawContent: 'standup-notes-clean-1'
        }
      ];

      for (const item of casesToSave) {
        const postRes = await fetch(`${baseUrl}/api/cases`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(item)
        });
        assert.equal(postRes.status, 201, `Case ${item.caseId} must be successfully created`);
        const body = await postRes.json();
        assert.equal(body.success, true);
        assert.equal(body.caseId, item.caseId);
      }

      // 2. Fetch /api/cases - MUST be sorted by threatScore DESC
      const getRes = await fetch(`${baseUrl}/api/cases`);
      assert.equal(getRes.status, 200);
      const fetchedCases = await getRes.json();
      assert.equal(fetchedCases.length, 3);
      assert.equal(fetchedCases[0].caseId, 'MAV-2026-96000001', 'First case must be Critical (threatScore 96)');
      assert.equal(fetchedCases[0].threatScore, 96);
      assert.equal(fetchedCases[1].caseId, 'MAV-2026-48000001', 'Second case must be Medium (threatScore 48)');
      assert.equal(fetchedCases[1].threatScore, 48);
      assert.equal(fetchedCases[2].caseId, 'MAV-2026-12000001', 'Third case must be Low (threatScore 12)');
      assert.equal(fetchedCases[2].threatScore, 12);

      // 3. Simulate application refresh by fetching single case by Case ID
      const singleRes = await fetch(`${baseUrl}/api/cases/MAV-2026-96000001`);
      assert.equal(singleRes.status, 200);
      const singleCase = await singleRes.json();
      assert.equal(singleCase.caseId, 'MAV-2026-96000001');
      assert.equal(singleCase.threatScore, 96);
      assert.equal(singleCase.priority, 'Critical');
      assert.equal(singleCase.status, 'active');
      assert.ok(singleCase.evidenceFusion);
    } finally {
      await new Promise(resolve => testServer.close(resolve));
    }
  });

});

