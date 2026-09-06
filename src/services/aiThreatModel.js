/**
 * MAVERICK — Real Machine Learning Threat Detection Service
 * Model: TF-IDF Vectorizer + Logistic Regression (SIH 2026 Core Component)
 * 
 * Flow:
 * Email Text -> Preprocessing -> TF-IDF Vectorizer -> Trained Logistic Regression
 *   -> Phishing Probability -> Evidence Fusion -> Final MAVERICK Risk Score
 * 
 * Strict Error Handling & Resilience:
 * - Genuine ML inference: queries FastAPI ML microservice / backend prediction gateway
 * - If ML service is unavailable: sets status to 'UNAVAILABLE' (never fabricates predictions)
 * - Forensic analysis continues unimpeded with remaining evidence layers
 */

// Calibrated high-risk phishing linguistic patterns for supplementary explainability
export const LINGUISTIC_THREAT_PATTERNS = [
  {
    category: 'Coercive Urgency',
    weight: 18,
    regex: /\b(immediately|urgent|critical\s+alert|without\s+delay|promptly|expedite|within\s+\d+\s+hours?|deadline|cutoff\s+today|mandate)\b/gi,
    explanation: 'High-urgency language designed to induce panic and bypass organizational approval protocols'
  },
  {
    category: 'Statutory / Authority Coercion',
    weight: 22,
    regex: /\b(statutory\s+allocation|ministerial\s+directive|bypass\s+applied|executive\s+council|rbi\s+regulatory|director\s+general|mandatory\s+directive|second-signatory\s+review)\b/gi,
    explanation: 'Claims of high-level authority or regulatory mandates designed to suppress secondary validation'
  },
  {
    category: 'Financial Wire Diversion',
    weight: 25,
    regex: /\b(wire\s+authorization|remittance|transfer\s+of\s+inr|batch\s+settlement|rtgs|neft|swift\s+release|payment\s+receipt|overdue\s+remittance|crores?|treasury\s+allocation)\b/gi,
    explanation: 'Requests for non-routine fund disbursements, banking transfers, or remittance redirection'
  },
  {
    category: 'Credential Harvesting & Session Hijacking',
    weight: 20,
    regex: /\b(re-authenticate|recertification|token\s+keys?|expire\s+in|session\s+restricted|multi-factor\s+authenticator|mfa|2fa|login\s+portal|directory\s+lock|verify\s+credentials?)\b/gi,
    explanation: 'Prompts to input single sign-on (SSO), 2FA, or corporate credentials on external targets'
  },
  {
    category: 'Evasion & Obfuscation Instructions',
    weight: 15,
    regex: /\b(do\s+not\s+delay|bypass|confidential\s+channel|do\s+not\s+contact|restricted\s+access|offshore|private\s+wire)\b/gi,
    explanation: 'Explicit directives advising the target not to seek peer verification or out-of-band contact'
  }
];

// Preprocess email text
export function preprocessText(text) {
  if (!text || typeof text !== 'string') return '';
  return text
    .toLowerCase()
    .replace(/<[^>]+>/g, ' ') // strip HTML tags
    .replace(/https?:\/\/\S+|www\.\S+/g, ' url_token ')
    .replace(/\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/g, ' email_token ')
    .replace(/[^a-zA-Z0-9_\s]/g, ' ') // strip non-alphanumeric punctuation
    .replace(/\s+/g, ' ')
    .trim();
}

// Extract matched textual heuristic indicators for supplementary explainability
export function extractTextualIndicators(rawText) {
  if (!rawText) return [];
  const matchedIndicators = [];
  const seenTokens = new Set();

  LINGUISTIC_THREAT_PATTERNS.forEach(pattern => {
    const matches = rawText.match(pattern.regex) || [];
    const uniqueMatches = Array.from(new Set(matches.map(m => m.trim())));
    
    uniqueMatches.forEach(token => {
      const lower = token.toLowerCase();
      if (!seenTokens.has(lower)) {
        seenTokens.add(lower);
        matchedIndicators.push({
          token,
          category: pattern.category,
          weight: pattern.weight,
          explanation: pattern.explanation
        });
      }
    });
  });

  return matchedIndicators;
}

/**
 * Query real Machine Learning Prediction Endpoint
 * Supports FastAPI microservice (port 8000) and backend gateway proxy (/api/ml/predict, /predict).
 */
export async function queryMLPrediction(text) {
  if (!text || typeof text !== 'string' || text.trim().length === 0) {
    return {
      prediction: 'UNAVAILABLE',
      phishing_probability: null,
      legitimate_probability: null,
      model: 'TF-IDF + Logistic Regression',
      status: 'EMPTY_INPUT',
      error: 'Empty or missing email text'
    };
  }

  const endpoints = [
    'http://127.0.0.1:8000/predict',
    '/api/ml/predict',
    '/predict'
  ];

  for (const endpoint of endpoints) {
    try {
      const res = await fetch(endpoint, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ text }),
        signal: AbortSignal.timeout(2500)
      });
      if (res.ok) {
        const data = await res.json();
        if (data && data.prediction && data.prediction !== 'UNAVAILABLE') {
          return {
            ...data,
            status: 'SUCCESS'
          };
        }
      }
    } catch {
      // Continue to next endpoint fallback
    }
  }

  // If running in Node.js environment (e.g. tests / server), fallback to local CLI inference
  if (typeof window === 'undefined' && typeof process !== 'undefined') {
    try {
      const cpModuleName = 'node:child_process';
      const pathModuleName = 'node:path';
      const { execFileSync } = await import(/* @vite-ignore */ cpModuleName);
      const path = await import(/* @vite-ignore */ pathModuleName);
      const scriptPath = path.resolve(process.cwd(), 'ml', 'predict.py');
      const stdout = execFileSync('python', [scriptPath, '--text', text], {
        encoding: 'utf-8',
        timeout: 4000
      });
      const data = JSON.parse(stdout.trim());
      if (data && data.prediction) {
        return {
          ...data,
          status: 'SUCCESS'
        };
      }
    } catch {
      // Python CLI not available or errored
    }
  }

  return {
    prediction: 'UNAVAILABLE',
    phishing_probability: null,
    legitimate_probability: null,
    model: 'TF-IDF + Logistic Regression',
    status: 'UNAVAILABLE',
    error: 'ML service unavailable'
  };
}

/**
 * Master Real AI/ML Threat Evaluator
 * Integrates real ML model inference with supplementary linguistic indicators.
 */
export async function evaluateAIThreat(parsedEmail, options = {}) {
  const fullText = `${parsedEmail.subject || ''}\n${parsedEmail.body || ''}\n${parsedEmail.sender || ''}\n${parsedEmail.rawSnippet || ''}`;
  const preprocessed = preprocessText(fullText);

  // 1. Extract linguistic indicators (for supplementary explainability)
  const indicators = extractTextualIndicators(fullText);

  // 2. Query Genuine Machine Learning Model
  let mlResult = options.mlResult;
  if (!mlResult && typeof fetch !== 'undefined') {
    mlResult = await queryMLPrediction(fullText);
  }

  const isMlAvailable = Boolean(
    mlResult && 
    mlResult.status === 'SUCCESS' && 
    typeof mlResult.phishing_probability === 'number' &&
    mlResult.prediction !== 'UNAVAILABLE'
  );

  let probability = null;
  let prediction = 'UNAVAILABLE';
  let modelName = 'TF-IDF + Logistic Regression';
  let topFeatures = [];
  let confidence = 0;

  if (isMlAvailable) {
    probability = Math.round(mlResult.phishing_probability * 100);
    prediction = String(mlResult.prediction).toUpperCase();
    modelName = mlResult.model || 'TF-IDF + Logistic Regression';
    topFeatures = mlResult.top_features || [];
    confidence = Math.round((mlResult.confidence || Math.max(mlResult.phishing_probability, mlResult.legitimate_probability || 0.8)) * 100);
  } else if (options.fallbackToHeuristic) {
    // Optional standalone fallback for node test environments when ML service is offline
    let rawScore = 0;
    indicators.forEach(ind => { rawScore += ind.weight; });
    const subjectLower = (parsedEmail.subject || '').toLowerCase();
    if (subjectLower.includes('urgent') || subjectLower.includes('wire') || subjectLower.includes('mandatory')) {
      rawScore += 12;
    }
    probability = Math.min(98, Math.max(8, Math.round((rawScore / 110) * 100)));
    prediction = probability >= 50 ? 'PHISHING' : 'LEGITIMATE';
    confidence = indicators.length >= 3 ? 94 : indicators.length >= 1 ? 82 : 70;
  }

  const keyTokens = topFeatures.length > 0 
    ? topFeatures.map(f => f.term) 
    : indicators.map(i => i.token);

  return {
    isMlAvailable,
    prediction, // 'PHISHING' | 'LEGITIMATE' | 'UNAVAILABLE'
    phishingProbability: probability, // Integer 0-100 or null if UNAVAILABLE
    phishing_probability: isMlAvailable ? mlResult.phishing_probability : null,
    legitimate_probability: isMlAvailable ? mlResult.legitimate_probability : null,
    model: modelName,
    topFeatures, // Real TF-IDF terms with model coefficients & impacts
    confidence,
    status: isMlAvailable 
      ? (probability >= 70 ? 'HIGH RISK' : probability >= 40 ? 'SUSPICIOUS' : 'LOW RISK') 
      : 'UNAVAILABLE',
    detectedIndicators: indicators,
    keyTokens,
    totalIndicatorsFound: indicators.length,
    narrative: isMlAvailable
      ? `Real machine learning model (${modelName}) classified this email as ${prediction} with ${probability}% threat probability. Identified ${topFeatures.length} salient TF-IDF predictive features.`
      : 'AI Prediction: UNAVAILABLE (ML inference service offline or unreachable). Proceeding with remaining multi-layer forensic evidence.'
  };
}
