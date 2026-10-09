/**
 * MAVERICK — Persistent Email Case Database Layer
 * Smart India Hackathon 2026
 * 
 * Provides PostgreSQL persistence using Prisma ORM with:
 * - Unique MAV-2026-XXXXXXXX Case IDs
 * - Threat score DESC priority ordering
 * - Strict duplicate detection using SHA-256 email content hash
 * - Graceful DB availability checks
 * - SOC Case Filtering, Pagination, and Archival
 */

import crypto from 'node:crypto';
import { PrismaClient } from '@prisma/client';
import { getThreatPriority } from '../src/services/priorityHelper.js';
import { generateCaseId } from '../src/services/forensicReportService.js';

let prismaInstance = null;
let testStore = null; // Isolated test store for unit tests when live DB is not running

export class DatabaseUnavailableError extends Error {
  constructor(message = 'Database is unavailable or DATABASE_URL is unconfigured') {
    super(message);
    this.name = 'DatabaseUnavailableError';
    this.code = 'DB_UNAVAILABLE';
  }
}

/**
 * Sanitizes raw database error messages to prevent credential/URL leakage.
 */
export function sanitizeDbError(err) {
  if (!err) return 'Database is unavailable';
  const msg = typeof err === 'string' ? err : err.message || '';
  const sanitized = msg.replace(/postgresql:\/\/[^@\s]+@[^\s/]+/gi, 'postgresql://[REDACTED]@[REDACTED]');
  if (/can't reach database server|connection refused|connect econnrefused|timeout|etimedout/i.test(sanitized)) {
    return 'Database host unreachable or connection timed out. Verify PostgreSQL host and network configuration.';
  }
  if (/password authentication failed|authentication failed/i.test(sanitized)) {
    return 'Database authentication failed. Please verify credentials in DATABASE_URL.';
  }
  if (/database ".*" does not exist/i.test(sanitized)) {
    return 'Target PostgreSQL database does not exist.';
  }
  if (/relation ".*" does not exist|table.*does not exist/i.test(sanitized)) {
    return 'Database schema missing. Execute "npx prisma migrate deploy" to apply migrations.';
  }
  if (/DATABASE_URL.*not configured|unconfigured/i.test(sanitized)) {
    return 'DATABASE_URL environment variable is not configured.';
  }
  return sanitized.slice(0, 150);
}

/**
 * Normalizes PostgreSQL connection string for cloud providers (Neon SSL requirements)
 */
export function normalizeDatabaseUrl(url) {
  if (!url || typeof url !== 'string') return url;
  let normalized = url.trim();
  if ((normalized.startsWith('"') && normalized.endsWith('"')) || (normalized.startsWith("'") && normalized.endsWith("'"))) {
    normalized = normalized.slice(1, -1).trim();
  }
  // Neon PostgreSQL requires SSL mode (sslmode=require)
  if ((normalized.includes('.neon.tech') || normalized.includes('neon.') || normalized.includes('aws.neon')) && !normalized.includes('sslmode=')) {
    normalized += normalized.includes('?') ? '&sslmode=require' : '?sslmode=require';
  }
  return normalized;
}

/**
 * Ensures email_cases table and indexes exist safely and idempotently
 */
let schemaEnsured = false;
const DDL_STATEMENTS = [
  `CREATE TABLE IF NOT EXISTS "email_cases" (
    "id" TEXT NOT NULL,
    "caseId" TEXT NOT NULL,
    "subject" TEXT NOT NULL DEFAULT '(No Subject)',
    "sender" TEXT NOT NULL DEFAULT 'unknown@sender.local',
    "recipient" TEXT NOT NULL DEFAULT 'unknown@recipient.local',
    "receivedAt" TIMESTAMP(3),
    "analyzedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "threatScore" INTEGER NOT NULL DEFAULT 0,
    "priority" TEXT NOT NULL DEFAULT 'Low',
    "classification" TEXT NOT NULL DEFAULT 'Legitimate',
    "confidence" DOUBLE PRECISION NOT NULL DEFAULT 0.0,
    "phishingProbability" DOUBLE PRECISION,
    "legitimateProbability" DOUBLE PRECISION,
    "riskSummary" TEXT,
    "originalFilename" TEXT,
    "emailHash" TEXT NOT NULL,
    "status" TEXT NOT NULL DEFAULT 'active',
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "headers" JSONB,
    "iocs" JSONB,
    "geoIntelligence" JSONB,
    "authenticationResults" JSONB,
    "attachmentFindings" JSONB,
    "evidenceFusion" JSONB,
    "recommendations" JSONB,
    "timeline" JSONB,
    "forensicMetadata" JSONB,
    CONSTRAINT "email_cases_pkey" PRIMARY KEY ("id")
  )`,
  `CREATE UNIQUE INDEX IF NOT EXISTS "email_cases_caseId_key" ON "email_cases"("caseId")`,
  `CREATE INDEX IF NOT EXISTS "email_cases_threatScore_idx" ON "email_cases"("threatScore" DESC)`,
  `CREATE INDEX IF NOT EXISTS "email_cases_createdAt_idx" ON "email_cases"("createdAt" DESC)`,
  `CREATE INDEX IF NOT EXISTS "email_cases_priority_idx" ON "email_cases"("priority")`,
  `CREATE INDEX IF NOT EXISTS "email_cases_classification_idx" ON "email_cases"("classification")`,
  `CREATE INDEX IF NOT EXISTS "email_cases_status_idx" ON "email_cases"("status")`,
  `CREATE INDEX IF NOT EXISTS "email_cases_emailHash_idx" ON "email_cases"("emailHash")`
];

export async function ensureSchemaExists(prisma) {
  if (schemaEnsured || !prisma) return;
  try {
    for (const stmt of DDL_STATEMENTS) {
      await prisma.$executeRawUnsafe(stmt);
    }
    schemaEnsured = true;
  } catch (err) {
    // If DDL execution is restricted or table is already managed, log sanitized notice and proceed
    console.warn('[MAVERICK DB] Schema check notice:', sanitizeDbError(err));
  }
}

/**
 * Initializes and retrieves the Prisma Client singleton
 */
export function getPrismaClient() {
  const dbUrl = process.env.DATABASE_URL;
  if (!dbUrl || !dbUrl.trim() || dbUrl.includes('placeholder') || dbUrl.includes('user:password@localhost')) {
    return null;
  }
  if (globalThis.__maverickPrisma) return globalThis.__maverickPrisma;
  if (prismaInstance) return prismaInstance;
  try {
    const normalizedDbUrl = normalizeDatabaseUrl(dbUrl);
    prismaInstance = new PrismaClient({
      datasources: {
        db: {
          url: normalizedDbUrl
        }
      },
      log: process.env.NODE_ENV === 'development' ? ['warn', 'error'] : ['error']
    });
    globalThis.__maverickPrisma = prismaInstance;
    return prismaInstance;
  } catch (err) {
    console.warn('[MAVERICK DB] Failed to instantiate PrismaClient:', sanitizeDbError(err));
    return null;
  }
}

/**
 * Sets an isolated mock store for test execution
 */
export function setTestStore(store) {
  testStore = store;
}

export function getTestStore() {
  return testStore;
}

export function resetTestStore() {
  testStore = null;
  schemaEnsured = false;
}

/**
 * Checks whether PostgreSQL is reachable
 */
export async function isDatabaseAvailable() {
  if (testStore) return true;
  const prisma = getPrismaClient();
  if (!prisma) return false;
  try {
    const timeoutPromise = new Promise((_, reject) =>
      setTimeout(() => reject(new Error('Database ping timeout')), 7000)
    );
    await Promise.race([
      prisma.$queryRaw`SELECT 1`,
      timeoutPromise
    ]);
    return true;
  } catch {
    return false;
  }
}

/**
 * Computes a deterministic SHA-256 hash for duplicate email identification
 */
export function computeEmailHash(content) {
  if (!content) return crypto.createHash('sha256').update(Date.now().toString()).digest('hex');
  const normalized = typeof content === 'string' ? content.trim() : JSON.stringify(content);
  return crypto.createHash('sha256').update(normalized).digest('hex');
}

/**
 * Saves or updates an analyzed email investigation in PostgreSQL
 */
export async function saveCase(payload) {
  const {
    email = {},
    fusion = {},
    aiThreat = null,
    iocs = [],
    geoInfo = null,
    geoList = [],
    emailAuth = null,
    attachments = [],
    campaign = null,
    timeline = [],
    recommendations = [],
    originalFilename = null,
    rawContent = ''
  } = payload;

  const threatScore = typeof fusion.threatScore === 'number'
    ? fusion.threatScore
    : (typeof payload.threatScore === 'number' ? payload.threatScore : 0);

  const priority = getThreatPriority(threatScore);
  const classification = payload.classification ||
    (threatScore >= 60 ? 'Phishing' : threatScore >= 30 ? 'Suspicious' : 'Legitimate');

  const confidence = typeof aiThreat?.confidence === 'number'
    ? aiThreat.confidence
    : (typeof aiThreat?.phishingProbability === 'number' ? aiThreat.phishingProbability : 85.0);

  const phishingProb = typeof aiThreat?.phishingProbability === 'number'
    ? aiThreat.phishingProbability
    : (typeof payload.phishingProbability === 'number' ? payload.phishingProbability : null);

  const legitimateProb = typeof aiThreat?.legitimateProbability === 'number'
    ? aiThreat.legitimateProbability
    : (typeof payload.legitimateProbability === 'number' ? payload.legitimateProbability : null);

  const subject = email.subject || payload.subject || '(No Subject)';
  const sender = email.sender || email.from || payload.sender || 'unknown@sender.local';
  const recipient = email.recipient || email.to || payload.recipient || 'unknown@recipient.local';

  // Compute or reuse email hash for duplicate detection
  const emailHash = payload.emailHash || computeEmailHash(rawContent || email.rawSnippet || `${sender}|${subject}|${recipient}`);

  const riskSummary = payload.riskSummary ||
    (fusion.verifiedReasons && fusion.verifiedReasons.length > 0
      ? fusion.verifiedReasons.slice(0, 3).join('. ') + '.'
      : `Threat Score: ${threatScore}/100 (${priority} Priority, ${classification})`);

  // --- 1. Test Store Branch (for test fixtures when offline) ---
  if (testStore) {
    // Check duplicate
    const existing = testStore.find(c => c.emailHash === emailHash);
    if (existing) {
      existing.analyzedAt = new Date().toISOString();
      existing.updatedAt = new Date().toISOString();
      existing.status = 'active'; // Reopen if archived
      existing.threatScore = threatScore;
      existing.priority = priority;
      existing.classification = classification;
      existing.evidenceFusion = fusion;
      existing.notes = existing.notes || [];
      existing.notes.push({
        id: Date.now(),
        timestamp: new Date().toISOString(),
        text: 'Email rescanned. Existing case updated with new threat intelligence.'
      });
      return { case: existing, caseId: existing.caseId, isDuplicate: true };
    }

    const caseId = payload.caseId && /^MAV-2026-[A-F0-9]{8}$/i.test(payload.caseId)
      ? payload.caseId
      : generateCaseId(sender);

    const newRecord = {
      id: crypto.randomUUID(),
      caseId,
      subject,
      sender,
      recipient,
      receivedAt: email.date ? new Date(email.date).toISOString() : new Date().toISOString(),
      analyzedAt: new Date().toISOString(),
      threatScore,
      priority,
      classification,
      confidence,
      phishingProbability: phishingProb,
      legitimateProbability: legitimateProb,
      riskSummary,
      originalFilename: originalFilename || email.filename || null,
      emailHash,
      status: 'active',
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
      headers: email.headers || null,
      iocs,
      geoIntelligence: { geoInfo, geoList },
      authenticationResults: emailAuth,
      attachmentFindings: attachments,
      evidenceFusion: fusion,
      recommendations,
      timeline,
      forensicMetadata: { campaign }
    };
    testStore.push(newRecord);
    return { case: newRecord, caseId: newRecord.caseId, isDuplicate: false };
  }

  // --- 2. Live PostgreSQL via Prisma Transaction Branch ---
  const prisma = getPrismaClient();
  if (!prisma) {
    throw new DatabaseUnavailableError('Database is unavailable or DATABASE_URL is not configured.');
  }

  await ensureSchemaExists(prisma);

  try {
    return await prisma.$transaction(async (tx) => {
      // Duplicate check using emailHash
      const existingCase = await tx.emailCase.findFirst({
        where: { emailHash }
      });

      if (existingCase) {
        // Reopen / update existing case
        const updatedCase = await tx.emailCase.update({
          where: { id: existingCase.id },
          data: {
            analyzedAt: new Date(),
            threatScore,
            priority,
            classification,
            confidence,
            phishingProbability: phishingProb,
            legitimateProbability: legitimateProb,
            riskSummary,
            status: 'active', // Reopen if archived
            evidenceFusion: fusion,
            iocs,
            authenticationResults: emailAuth,
            attachmentFindings: attachments,
            geoIntelligence: { geoInfo, geoList },
            recommendations,
            timeline,
            forensicMetadata: { campaign }
          }
        });
        return { case: updatedCase, caseId: updatedCase.caseId, isDuplicate: true };
      }

      // Generate unique Case ID (preserve provided caseId if valid MAV format)
      let caseId = payload.caseId && /^MAV-2026-[A-F0-9]{8}$/i.test(payload.caseId)
        ? payload.caseId
        : generateCaseId(sender);

      // Ensure uniqueness
      let collisionCheck = await tx.emailCase.findUnique({ where: { caseId } });
      while (collisionCheck) {
        caseId = generateCaseId();
        collisionCheck = await tx.emailCase.findUnique({ where: { caseId } });
      }

      const createdCase = await tx.emailCase.create({
        data: {
          id: crypto.randomUUID(),
          caseId,
          subject,
          sender,
          recipient,
          receivedAt: email.date ? new Date(email.date) : new Date(),
          analyzedAt: new Date(),
          threatScore,
          priority,
          classification,
          confidence,
          phishingProbability: phishingProb,
          legitimateProbability: legitimateProb,
          riskSummary,
          originalFilename: originalFilename || email.filename || null,
          emailHash,
          status: 'active',
          headers: email.headers || null,
          iocs,
          geoIntelligence: { geoInfo, geoList },
          authenticationResults: emailAuth,
          attachmentFindings: attachments,
          evidenceFusion: fusion,
          recommendations,
          timeline,
          forensicMetadata: { campaign }
        }
      });

      return { case: createdCase, caseId: createdCase.caseId, isDuplicate: false };
    });
  } catch (err) {
    const safeError = sanitizeDbError(err);
    console.error('[MAVERICK DB] Failed to save case in database:', safeError);
    throw new DatabaseUnavailableError(`Database save failed: ${safeError}`);
  }
}

/**
 * Retrieves cases sorted by threatScore DESC, createdAt DESC with filters & pagination
 */
export async function getCases({
  priority,
  classification,
  status = 'active',
  page = 1,
  limit = 20,
  search = ''
} = {}) {
  const pageNum = Math.max(1, parseInt(page, 10) || 1);
  const limitNum = Math.min(100, Math.max(1, parseInt(limit, 10) || 20));
  const skip = (pageNum - 1) * limitNum;

  // --- Test Store Branch ---
  if (testStore) {
    let filtered = [...testStore];

    // Status filter
    if (status && status !== 'all') {
      filtered = filtered.filter(c => (c.status || 'active').toLowerCase() === status.toLowerCase());
    }

    // Priority filter
    if (priority) {
      filtered = filtered.filter(c => (c.priority || '').toLowerCase() === priority.toLowerCase());
    }

    // Classification filter
    if (classification) {
      filtered = filtered.filter(c => (c.classification || '').toLowerCase() === classification.toLowerCase());
    }

    // Search query
    if (search && search.trim()) {
      const q = search.trim().toLowerCase();
      filtered = filtered.filter(c =>
        (c.caseId && c.caseId.toLowerCase().includes(q)) ||
        (c.subject && c.subject.toLowerCase().includes(q)) ||
        (c.sender && c.sender.toLowerCase().includes(q))
      );
    }

    // Sort: threatScore DESC, then createdAt DESC
    filtered.sort((a, b) => {
      const scoreDiff = (b.threatScore || 0) - (a.threatScore || 0);
      if (scoreDiff !== 0) return scoreDiff;
      return new Date(b.createdAt || 0) - new Date(a.createdAt || 0);
    });

    const total = filtered.length;
    const paginated = filtered.slice(skip, skip + limitNum);

    return {
      cases: paginated,
      total,
      page: pageNum,
      limit: limitNum,
      totalPages: Math.ceil(total / limitNum) || 1
    };
  }

  // --- Live PostgreSQL via Prisma Branch ---
  const prisma = getPrismaClient();
  if (!prisma) {
    throw new DatabaseUnavailableError();
  }

  await ensureSchemaExists(prisma);

  try {
    const where = {};

    if (status && status !== 'all') {
      where.status = { equals: status, mode: 'insensitive' };
    }

    if (priority) {
      where.priority = { equals: priority, mode: 'insensitive' };
    }

    if (classification) {
      where.classification = { equals: classification, mode: 'insensitive' };
    }

    if (search && search.trim()) {
      const q = search.trim();
      where.OR = [
        { caseId: { contains: q, mode: 'insensitive' } },
        { subject: { contains: q, mode: 'insensitive' } },
        { sender: { contains: q, mode: 'insensitive' } }
      ];
    }

    const [total, cases] = await Promise.all([
      prisma.emailCase.count({ where }),
      prisma.emailCase.findMany({
        where,
        orderBy: [
          { threatScore: 'desc' },
          { createdAt: 'desc' }
        ],
        skip,
        take: limitNum
      })
    ]);

    return {
      cases,
      total,
      page: pageNum,
      limit: limitNum,
      totalPages: Math.ceil(total / limitNum) || 1
    };
  } catch (err) {
    const safeError = sanitizeDbError(err);
    console.error('[MAVERICK DB] Failed to fetch cases:', safeError);
    throw new DatabaseUnavailableError(`Database query failed: ${safeError}`);
  }
}

/**
 * Retrieves a single complete investigation case by Case ID
 */
export async function getCaseByCaseId(caseId) {
  if (!caseId) return null;
  const cleanId = caseId.trim();

  // Test Store
  if (testStore) {
    return testStore.find(c => c.caseId.toLowerCase() === cleanId.toLowerCase()) || null;
  }

  const prisma = getPrismaClient();
  if (!prisma) {
    throw new DatabaseUnavailableError();
  }

  await ensureSchemaExists(prisma);

  try {
    return await prisma.emailCase.findUnique({
      where: { caseId: cleanId }
    });
  } catch (err) {
    const safeError = sanitizeDbError(err);
    console.error(`[MAVERICK DB] Failed to fetch case ${cleanId}:`, safeError);
    throw new DatabaseUnavailableError(`Database lookup failed: ${safeError}`);
  }
}

/**
 * Updates case status (e.g. 'archived', 'active')
 */
export async function updateCaseStatus(caseId, status) {
  if (!caseId) return null;
  const cleanId = caseId.trim();

  // Test Store
  if (testStore) {
    const item = testStore.find(c => c.caseId.toLowerCase() === cleanId.toLowerCase());
    if (item) {
      item.status = status;
      item.updatedAt = new Date().toISOString();
      return item;
    }
    return null;
  }

  const prisma = getPrismaClient();
  if (!prisma) {
    throw new DatabaseUnavailableError();
  }

  await ensureSchemaExists(prisma);

  try {
    return await prisma.emailCase.update({
      where: { caseId: cleanId },
      data: { status }
    });
  } catch (err) {
    const safeError = sanitizeDbError(err);
    console.error(`[MAVERICK DB] Failed to update case ${cleanId}:`, safeError);
    throw new DatabaseUnavailableError(`Database update failed: ${safeError}`);
  }
}

/**
 * Computes dashboard statistics from real database records
 */
export async function getCaseStats() {
  // Test Store
  if (testStore) {
    const active = testStore.filter(c => (c.status || 'active').toLowerCase() !== 'archived');
    const critical = active.filter(c => (c.priority || '').toLowerCase() === 'critical').length;
    const high = active.filter(c => (c.priority || '').toLowerCase() === 'high').length;
    const medium = active.filter(c => (c.priority || '').toLowerCase() === 'medium').length;
    const low = active.filter(c => (c.priority || '').toLowerCase() === 'low').length;

    const topThreats = [...active]
      .sort((a, b) => (b.threatScore || 0) - (a.threatScore || 0))
      .slice(0, 4)
      .map(c => ({
        caseId: c.caseId,
        subject: c.subject,
        threatScore: c.threatScore,
        priority: c.priority,
        classification: c.classification
      }));

    return {
      totalCases: active.length,
      critical,
      high,
      medium,
      low,
      topThreats
    };
  }

  const prisma = getPrismaClient();
  if (!prisma) {
    throw new DatabaseUnavailableError();
  }

  await ensureSchemaExists(prisma);

  try {
    const activeWhere = { status: { not: 'archived' } };

    const [totalCases, critical, high, medium, low, topCases] = await Promise.all([
      prisma.emailCase.count({ where: activeWhere }),
      prisma.emailCase.count({ where: { ...activeWhere, priority: { equals: 'Critical', mode: 'insensitive' } } }),
      prisma.emailCase.count({ where: { ...activeWhere, priority: { equals: 'High', mode: 'insensitive' } } }),
      prisma.emailCase.count({ where: { ...activeWhere, priority: { equals: 'Medium', mode: 'insensitive' } } }),
      prisma.emailCase.count({ where: { ...activeWhere, priority: { equals: 'Low', mode: 'insensitive' } } }),
      prisma.emailCase.findMany({
        where: activeWhere,
        orderBy: [
          { threatScore: 'desc' },
          { createdAt: 'desc' }
        ],
        take: 4,
        select: {
          caseId: true,
          subject: true,
          threatScore: true,
          priority: true,
          classification: true
        }
      })
    ]);

    return {
      totalCases,
      critical,
      high,
      medium,
      low,
      topThreats: topCases
    };
  } catch (err) {
    const safeError = sanitizeDbError(err);
    console.error('[MAVERICK DB] Failed to compile case statistics:', safeError);
    throw new DatabaseUnavailableError(`Database stats failed: ${safeError}`);
  }
}
