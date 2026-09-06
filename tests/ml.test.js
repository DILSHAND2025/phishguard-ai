/**
 * MAVERICK — AI/ML Threat Detection Test Suite
 * Smart India Hackathon 2026
 * 
 * Verifies:
 * 1. Normal legitimate email classification
 * 2. Obvious phishing email classification
 * 3. Short email handling
 * 4. Empty email handling
 * 5. Malformed request / input handling
 * 6. ML service unavailable fallback (never fabricates predictions)
 * 7. Complete forensic flow (.eml -> parse -> ML -> evidence fusion -> final risk score)
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import { parseEmailContent } from '../src/services/emailParser.js';
import { extractAllIOCs } from '../src/services/iocExtractor.js';
import { queryMLPrediction, evaluateAIThreat } from '../src/services/aiThreatModel.js';
import { calculateEvidenceFusion, DEFAULT_FUSION_WEIGHTS } from '../src/services/evidenceFusion.js';
import { resolveIPGeo } from '../src/services/geoAsnService.js';

test('MAVERICK AI/ML Threat Detection Suite', async (t) => {

  await t.test('1. Normal legitimate email classification', async () => {
    const legitText = `Hi team,
The weekly cloud infrastructure review has been scheduled for tomorrow afternoon.
Please find the completed quarterly notes attached for our internal discussion.
Thanks, Support Team.`;

    const result = await queryMLPrediction(legitText);
    assert.equal(result.status, 'SUCCESS', 'ML prediction succeeded');
    assert.equal(result.prediction, 'legitimate', 'Normal email predicted as legitimate');
    assert.ok(result.phishing_probability < 0.5, `Phishing probability should be < 0.5, got ${result.phishing_probability}`);
    assert.ok(result.legitimate_probability > 0.5, `Legitimate probability should be > 0.5, got ${result.legitimate_probability}`);
    assert.equal(result.model, 'TF-IDF + Logistic Regression', 'Model name correctly identified');
  });

  await t.test('2. Obvious phishing email classification', async () => {
    const phishingText = `URGENT: Immediate payment wire authorization required immediately!
Statutory remittance directive has been issued. Click here to verify your account credentials:
http://malicious-phishing-login.online/verify-bank-account
Failure to comply immediately will result in directory suspension.`;

    const result = await queryMLPrediction(phishingText);
    assert.equal(result.status, 'SUCCESS', 'ML prediction succeeded');
    assert.equal(result.prediction, 'phishing', 'Adversarial email predicted as phishing');
    assert.ok(result.phishing_probability >= 0.6, `Phishing probability should be >= 0.6, got ${result.phishing_probability}`);
    assert.ok(result.top_features && result.top_features.length > 0, 'Salient TF-IDF features returned');
    
    // Check that top phishing indicators are present in explainability features
    const featureTerms = result.top_features.map(f => f.term);
    const hasPhishIndicator = featureTerms.some(term => 
      ['urgent', 'immediately', 'wire', 'account', 'url_token', 'credentials', 'payment', 'authorization'].includes(term)
    );
    assert.ok(hasPhishIndicator, `Top features should include phishing indicators: ${featureTerms.join(', ')}`);
  });

  await t.test('3. Short email handling', async () => {
    const shortText = 'Noted, thanks!';
    const result = await queryMLPrediction(shortText);
    // Short emails should not crash and should produce a valid probability
    assert.ok(result.status === 'SUCCESS' || result.status === 'UNAVAILABLE');
    if (result.status === 'SUCCESS') {
      assert.ok(typeof result.phishing_probability === 'number');
      assert.ok(result.phishing_probability >= 0 && result.phishing_probability <= 1);
    }
  });

  await t.test('4. Empty email handling', async () => {
    const emptyResults = await Promise.all([
      queryMLPrediction(''),
      queryMLPrediction('    \n\t  '),
      queryMLPrediction(null),
      queryMLPrediction(undefined)
    ]);

    for (const res of emptyResults) {
      assert.equal(res.prediction, 'UNAVAILABLE', 'Empty text yields UNAVAILABLE prediction');
      assert.equal(res.phishing_probability, null, 'Empty text yields null phishing probability');
      assert.ok(res.status === 'EMPTY_INPUT' || res.status === 'UNAVAILABLE');
    }
  });

  await t.test('5. Malformed request handling', async () => {
    // Malformed types passed to evaluateAIThreat
    const malformedEvaluations = await Promise.all([
      evaluateAIThreat({ subject: null, body: null }),
      evaluateAIThreat({}),
      evaluateAIThreat({ subject: 12345, body: {} })
    ]);

    for (const evalResult of malformedEvaluations) {
      assert.ok(evalResult, 'Handled malformed input without unhandled exception');
      assert.ok(evalResult.model === 'TF-IDF + Logistic Regression');
      assert.ok(Array.isArray(evalResult.topFeatures));
    }
  });

  await t.test('6. ML service unavailable fallback (Never fabricates predictions)', async () => {
    // Pass mock options where ML is unavailable
    const unavailableResult = await evaluateAIThreat(
      { subject: 'Important message', body: 'Test content' },
      { mlResult: { prediction: 'UNAVAILABLE', status: 'UNAVAILABLE', phishing_probability: null } }
    );

    assert.equal(unavailableResult.isMlAvailable, false, 'isMlAvailable is false');
    assert.equal(unavailableResult.prediction, 'UNAVAILABLE', 'AI prediction strictly reported as UNAVAILABLE');
    assert.equal(unavailableResult.phishingProbability, null, 'Phishing probability is strictly null');
    assert.equal(unavailableResult.status, 'UNAVAILABLE', 'Status marked as UNAVAILABLE');

    // Verify Evidence Fusion when ML is unavailable
    const fusion = calculateEvidenceFusion({
      parsedEmail: {
        fromParsed: { address: 'cfo@company.com' },
        replyToMismatch: false,
        auth: { spf: { result: 'PASS' }, dkim: { result: 'PASS' }, dmarc: { result: 'PASS' } },
        attachments: []
      },
      aiThreat: unavailableResult,
      iocs: [],
      geoInfo: { isProxyOrVpn: false, country: 'India' },
      weights: DEFAULT_FUSION_WEIGHTS
    });

    // Layer 1 (AI/NLP Threat Detection) should contribute 0 points when ML is unavailable
    const aiLayerFactor = fusion.factors.find(f => f.id === 'ai-nlp-analysis');
    assert.ok(aiLayerFactor, 'AI/NLP factor present in evidence fusion breakdown');
    assert.equal(aiLayerFactor.points, 0, 'AI layer contributes 0 points when ML service is unavailable');
    assert.ok(aiLayerFactor.evidence.includes('UNAVAILABLE'), 'Factor detail clearly notes ML unavailable');
    assert.ok(typeof fusion.threatScore === 'number', 'Final threat score computed successfully from remaining layers');
  });

  await t.test('7. Complete End-to-End Forensic Flow (.eml -> ML -> Evidence Fusion)', async () => {
    const rawEml = `From: "Finance Controller" <billing@secure-internal-update.online>
Reply-To: <external-offshore-payout@proton.me>
To: <target-employee@enterprise.in>
Subject: URGENT: Wire Remittance Verification Directive
Date: Fri, 06 Sep 2026 12:00:00 +0530
Received: from mail.secure-internal-update.online (185.220.101.45) by mail.enterprise.in; Fri, 06 Sep 2026 12:00:01 +0530
Received-SPF: fail
Authentication-Results: mail.enterprise.in; dkim=fail; dmarc=fail
Content-Disposition: attachment; filename="wire_directive_bypass.pdf.exe"
Content-Type: text/plain; charset="utf-8"

Expedite statutory allocation transfer of INR 2,50,00,000 immediately.
Wire remittance directive must be signed and verified immediately to avoid suspension.
Visit http://secure-internal-update.online/auth-portal/wire-release now.`;

    // 1. Email Parser
    const parsedEmail = await parseEmailContent(rawEml);
    assert.equal(parsedEmail.fromParsed.address, 'billing@secure-internal-update.online');
    assert.equal(parsedEmail.replyToMismatch, true, 'Reply-to mismatch detected');
    assert.equal(parsedEmail.auth.spf.result, 'FAIL');
    assert.equal(parsedEmail.auth.dkim.result, 'FAIL');
    assert.equal(parsedEmail.attachments.length, 1);
    assert.equal(parsedEmail.attachments[0].isSuspicious, true);

    // 2. IOC Extraction
    parsedEmail.urls = ['http://secure-internal-update.online/auth-portal/wire-release'];
    const iocs = extractAllIOCs(parsedEmail);
    assert.ok(iocs.some(i => i.type === 'IP' && i.value === '185.220.101.45'));
    assert.ok(iocs.some(i => i.type === 'DOMAIN' && i.value === 'secure-internal-update.online'));

    // 3. Real ML Model Prediction
    const aiThreat = await evaluateAIThreat(parsedEmail);
    assert.equal(aiThreat.isMlAvailable, true, 'ML service evaluated the email content');
    assert.equal(aiThreat.prediction, 'PHISHING', 'ML correctly predicted phishing');
    assert.ok(aiThreat.phishingProbability >= 60, `High phishing probability: ${aiThreat.phishingProbability}%`);
    assert.equal(aiThreat.model, 'TF-IDF + Logistic Regression');

    // 4. Geo / ASN Intelligence
    const geoInfo = await resolveIPGeo(parsedEmail.originatingIP);
    assert.equal(geoInfo.country, 'Germany');
    assert.equal(geoInfo.isProxyOrVpn, true);

    // 5. Evidence Fusion & Risk Scoring
    const fusion = calculateEvidenceFusion({
      parsedEmail,
      aiThreat,
      iocs,
      geoInfo,
      weights: DEFAULT_FUSION_WEIGHTS
    });

    // Verify ML is ONE of the evidence sources and does NOT alone determine the score
    assert.ok(fusion.threatScore >= 70 && fusion.threatScore <= 100, `Multi-layer score calibrated: ${fusion.threatScore}/100`);
    assert.ok(['HIGH', 'CRITICAL'].includes(fusion.riskLevel), `Risk level classified: ${fusion.riskLevel}`);
    assert.equal(fusion.factors.length, 6, 'All 6 evidence layers are active');

    const aiFactor = fusion.factors.find(f => f.id === 'ai-nlp-analysis');
    assert.ok(aiFactor.points > 0, `AI factor scored points (${aiFactor.points}/25)`);
    assert.ok(aiFactor.points <= 25, 'AI factor respects max weight ceiling of 25');

    // Verify other forensic layers also contributed
    const headerFactor = fusion.factors.find(f => f.id === 'header-forensics');
    assert.ok(headerFactor.points > 0, 'Header/Authentication layer contributed points');

    const attachFactor = fusion.factors.find(f => f.id === 'attachment-analysis');
    assert.ok(attachFactor.points > 0, 'Attachment forensics layer contributed points');

    const networkFactor = fusion.factors.find(f => f.id === 'geo-asn-context');
    assert.ok(networkFactor.points > 0, 'Geo/Network infrastructure layer contributed points');
  });

});
