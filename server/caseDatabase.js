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
 * Initializes and retrieves the Prisma Client singleton
 */
export function getPrismaClient() {
  if (prismaInstance) return prismaInstance;
  const dbUrl = process.env.DATABASE_URL;
  if (!dbUrl || !dbUrl.trim() || dbUrl.includes('placeholder')) {
    return null;
  }
  try {
    prismaInstance = new PrismaClient({
      log: process.env.NODE_ENV === 'development' ? ['warn', 'error'] : ['error']
    });
    return prismaInstance;
  } catch (err) {
    console.warn('[MAVERICK DB] Failed to instantiate PrismaClient:', err.message);
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
}

/**
 * Checks whether PostgreSQL is reachable
 */
export async function isDatabaseAvailable() {
  if (testStore) return true;
  const prisma = getPrismaClient();
  if (!prisma) return false;
  try {
    await prisma.$queryRaw`SELECT 1`;
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

  // --- 2. Live PostgreSQL via Prisma Branch ---
  const prisma = getPrismaClient();
  if (!prisma) {
    throw new DatabaseUnavailableError();
  }

  try {
    // Duplicate check using emailHash
    const existingCase = await prisma.emailCase.findFirst({
      where: { emailHash }
    });

    if (existingCase) {
      // Reopen / update existing case
      const updatedCase = await prisma.emailCase.update({
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

    // Generate unique Case ID
    let caseId = payload.caseId && /^MAV-2026-[A-F0-9]{8}$/i.test(payload.caseId)
      ? payload.caseId
      : generateCaseId(sender);

    // Ensure uniqueness
    let collisionCheck = await prisma.emailCase.findUnique({ where: { caseId } });
    while (collisionCheck) {
      caseId = generateCaseId();
      collisionCheck = await prisma.emailCase.findUnique({ where: { caseId } });
    }

    const createdCase = await prisma.emailCase.create({
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
  } catch (err) {
    console.error('[MAVERICK DB] Failed to save case in database:', err.message);
    throw new DatabaseUnavailableError(`Database save failed: ${err.message}`);
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
    console.error('[MAVERICK DB] Failed to fetch cases:', err.message);
    throw new DatabaseUnavailableError(`Database query failed: ${err.message}`);
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

  try {
    return await prisma.emailCase.findUnique({
      where: { caseId: cleanId }
    });
  } catch (err) {
    console.error(`[MAVERICK DB] Failed to fetch case ${cleanId}:`, err.message);
    throw new DatabaseUnavailableError(`Database lookup failed: ${err.message}`);
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

  try {
    return await prisma.emailCase.update({
      where: { caseId: cleanId },
      data: { status }
    });
  } catch (err) {
    console.error(`[MAVERICK DB] Failed to update case ${cleanId}:`, err.message);
    throw new DatabaseUnavailableError(`Database update failed: ${err.message}`);
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
    console.error('[MAVERICK DB] Failed to compile case statistics:', err.message);
    throw new DatabaseUnavailableError(`Database stats failed: ${err.message}`);
  }
}
