/**
 * MAVERICK — Database-Backed Case Management Service
 * Smart India Hackathon 2026
 * 
 * Provides PostgreSQL persistence and priority queue access for email investigations.
 * - Authoritative threatScore, priority, and classification from Evidence Fusion
 * - Case Queue sorting by threatScore DESC, createdAt DESC
 * - Duplicate email detection using SHA-256 hash
 * - Soft archiving (no destructive deletion)
 * - Safe error handling when database is unavailable (never pretends cases are saved)
 */

import { getApiBaseUrl } from './apiConfig.js';
import { getThreatPriority, getPriorityStyle } from './priorityHelper.js';
import { generateCaseId } from './forensicReportService.js';
import { classifyIP, IP_CLASSIFICATION } from './emailParser.js';

export { getThreatPriority, getPriorityStyle, generateCaseId };

/**
 * Normalizes case geoIntelligence so that legacy/cached cases accurately reflect
 * RFC 5737 / RFC 3849 documentation and reserved taxonomy instead of generic PRIVATE.
 */
export function normalizeCaseGeoIntelligence(caseItem) {
  if (!caseItem || !caseItem.geoIntelligence) return caseItem;

  const sanitize = (r) => {
    if (!r || !r.ip) return r;
    const cls = classifyIP(r.ip);
    if (cls === IP_CLASSIFICATION.TEST_NET_IP) {
      return {
        ...r,
        classification: IP_CLASSIFICATION.TEST_NET_IP,
        role: 'RESERVED / TEST-NET',
        roleLabel: 'Documentation / TEST-NET (RFC 5737)',
        status: 'PRIVATE_IP',
        lookupStatus: 'PRIVATE_IP',
        isPrivate: true,
        geoAvailable: false,
        country: 'Documentation / Test Network',
        countryCode: 'TEST',
        region: 'RFC 5737 / RFC 3849 Benchmark & Documentation Range',
        city: 'Reserved Test-Net Subnet',
        isp: 'IANA Special-Purpose (Documentation)',
        asn: 'N/A (Documentation Subnet)',
        asnOrg: 'IANA Special-Purpose (Documentation)',
        networkType: 'Documentation / TEST-NET Subnet (RFC 5737)',
        observedEvidence: `IP ${r.ip} belongs to documentation/example address space (${cls} - RFC 5737 / RFC 3849).`,
        inferredContext: 'Non-routable documentation address used in test scenarios or documentation; excluded from public geolocation.'
      };
    } else if (cls === IP_CLASSIFICATION.LOOPBACK_IP) {
      return {
        ...r,
        classification: IP_CLASSIFICATION.LOOPBACK_IP,
        role: 'LOOPBACK',
        roleLabel: 'Loopback Address',
        status: 'PRIVATE_IP',
        lookupStatus: 'PRIVATE_IP',
        isPrivate: true,
        geoAvailable: false,
        country: 'Loopback / Host-Local Network',
        countryCode: 'LOK',
        region: 'Local Host System Interface',
        city: 'Localhost (Loopback)',
        isp: 'Host Software Loopback',
        asn: 'N/A (Loopback Interface)',
        networkType: 'Host-Local Loopback (RFC 1122)'
      };
    } else if (cls === IP_CLASSIFICATION.LINK_LOCAL_IP) {
      return {
        ...r,
        classification: IP_CLASSIFICATION.LINK_LOCAL_IP,
        role: 'LINK_LOCAL',
        roleLabel: 'Link-Local Address (RFC 3927)',
        status: 'PRIVATE_IP',
        lookupStatus: 'PRIVATE_IP',
        isPrivate: true,
        geoAvailable: false,
        country: 'Link-Local Network',
        countryCode: 'LL',
        region: 'Auto-Configured Segment',
        city: 'Link-Local Subnet',
        isp: 'Link-Local Infrastructure',
        asn: 'N/A (Link-Local)',
        networkType: 'Link-Local Subnet (RFC 3927)'
      };
    }
    return r;
  };

  const newGeoInfo = sanitize(caseItem.geoIntelligence.geoInfo);
  const newGeoList = Array.isArray(caseItem.geoIntelligence.geoList)
    ? caseItem.geoIntelligence.geoList.map(sanitize)
    : [];

  return {
    ...caseItem,
    geoIntelligence: {
      ...caseItem.geoIntelligence,
      geoInfo: newGeoInfo,
      geoList: newGeoList
    }
  };
}

/**
 * Fetches stored email cases from PostgreSQL backend with filtering & pagination
 * Default order: threatScore DESC, createdAt DESC
 * 
 * @param {Object} [params]
 * @param {string} [params.priority] - 'Critical' | 'High' | 'Medium' | 'Low'
 * @param {string} [params.classification] - 'Phishing' | 'Suspicious' | 'Legitimate'
 * @param {string} [params.status] - 'active' (default) | 'archived' | 'all'
 * @param {number} [params.page] - 1-based page number
 * @param {number} [params.limit] - items per page (default 20, max 100)
 * @param {string} [params.search] - query across subject, sender, caseId
 * @returns {Promise<{ cases: Array, total: number, page: number, limit: number, totalPages: number, isDbUnavailable?: boolean, error?: string }>}
 */
export async function fetchCases({
  priority,
  classification,
  status = 'active',
  page = 1,
  limit = 20,
  search = ''
} = {}) {
  const baseUrl = getApiBaseUrl();
  const queryParams = new URLSearchParams();

  if (priority && priority !== 'All') queryParams.set('priority', priority);
  if (classification && classification !== 'All') queryParams.set('classification', classification);
  if (status) queryParams.set('status', status);
  if (page) queryParams.set('page', String(page));
  if (limit) queryParams.set('limit', String(limit));
  if (search && search.trim()) queryParams.set('search', search.trim());
  queryParams.set('format', 'envelope');

  const endpoint = `${baseUrl}/api/cases?${queryParams.toString()}`;

  try {
    const res = await fetch(endpoint, {
      method: 'GET',
      headers: { 'Accept': 'application/json' }
    });

    if (res.status === 503) {
      return {
        cases: [],
        total: 0,
        page: 1,
        limit,
        totalPages: 1,
        isDbUnavailable: true,
        error: 'Database is currently unavailable. Scanned emails are not persistently stored.'
      };
    }

    if (res.status === 405) {
      return {
        cases: [],
        total: 0,
        page: 1,
        limit,
        totalPages: 1,
        isDbUnavailable: true,
        error: 'Gateway routing error: HTTP 405 Method Not Allowed. Backend route does not support this method.'
      };
    }

    const contentType = res.headers.get('content-type') || '';
    if (!res.ok) {
      throw new Error(`Failed to load cases: HTTP ${res.status}`);
    }

    if (!contentType.includes('application/json')) {
      return {
        cases: [],
        total: 0,
        page: 1,
        limit,
        totalPages: 1,
        isDbUnavailable: true,
        error: 'Unable to connect to database gateway (server returned non-JSON response).'
      };
    }

    const data = await res.json();
    if (Array.isArray(data)) {
      const totalHeader = res.headers.get('X-Total-Count');
      const pageHeader = res.headers.get('X-Page');
      const totalPagesHeader = res.headers.get('X-Total-Pages');
      return {
        cases: data.map(normalizeCaseGeoIntelligence),
        total: totalHeader ? parseInt(totalHeader, 10) : data.length,
        page: pageHeader ? parseInt(pageHeader, 10) : page,
        limit,
        totalPages: totalPagesHeader ? parseInt(totalPagesHeader, 10) : 1,
        isDbUnavailable: false
      };
    }

    return {
      cases: (data.cases || []).map(normalizeCaseGeoIntelligence),
      total: data.total || (data.cases ? data.cases.length : 0),
      page: data.page || page,
      limit: data.limit || limit,
      totalPages: data.totalPages || 1,
      isDbUnavailable: false
    };
  } catch (err) {
    console.warn('[MAVERICK CaseStore] fetchCases failed:', err.message);
    return {
      cases: [],
      total: 0,
      page: 1,
      limit,
      totalPages: 1,
      isDbUnavailable: true,
      error: 'Unable to connect to database gateway.'
    };
  }
}

/**
 * Fetches a single complete investigation case by Case ID
 * 
 * @param {string} caseId
 * @returns {Promise<Object|null>}
 */
export async function fetchCaseById(caseId) {
  if (!caseId) return null;
  const baseUrl = getApiBaseUrl();
  const endpoint = `${baseUrl}/api/cases/${encodeURIComponent(caseId.trim())}`;

  try {
    const res = await fetch(endpoint, {
      method: 'GET',
      headers: { 'Accept': 'application/json' }
    });

    if (!res.ok) {
      if (res.status === 404) return null;
      throw new Error(`HTTP ${res.status}`);
    }

    const item = await res.json();
    return normalizeCaseGeoIntelligence(item);
  } catch (err) {
    console.warn(`[MAVERICK CaseStore] fetchCaseById(${caseId}) failed:`, err.message);
    return null;
  }
}

/**
 * Saves a completed email investigation into PostgreSQL.
 * Must be executed AFTER final Evidence Fusion threat score is determined.
 * 
 * @param {Object} analysisResult
 * @returns {Promise<{ success: boolean, caseId?: string, isDuplicate?: boolean, case?: Object, error?: string, isDbUnavailable?: boolean }>}
 */
export async function persistCaseInvestigation(analysisResult) {
  if (!analysisResult) {
    return { success: false, error: 'No analysis result provided for persistence' };
  }

  const baseUrl = getApiBaseUrl();
  const endpoint = `${baseUrl}/api/cases`;

  const payload = {
    caseId: analysisResult.caseId || analysisResult.caseItem?.caseId || null,
    emailHash: analysisResult.emailHash || analysisResult.caseItem?.sha256 || null,
    email: analysisResult.email || {},
    fusion: analysisResult.fusion || {},
    aiThreat: analysisResult.aiThreat || null,
    iocs: analysisResult.iocs || [],
    geoInfo: analysisResult.geoInfo || null,
    geoList: analysisResult.geoList || [],
    emailAuth: analysisResult.emailAuth || null,
    attachments: analysisResult.email?.attachments || [],
    campaign: analysisResult.campaign || null,
    timeline: analysisResult.report?.timeline || analysisResult.timeline || [],
    recommendations: analysisResult.report?.recommendations || analysisResult.recommendations || [],
    originalFilename: analysisResult.email?.filename || analysisResult.filename || null,
    rawContent: analysisResult.email?.rawSnippet || ''
  };

  try {
    const res = await fetch(endpoint, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    });

    const contentType = res.headers.get('content-type') || '';

    if (res.status === 503) {
      const errBody = contentType.includes('application/json')
        ? await res.json().catch(() => ({}))
        : {};
      return {
        success: false,
        isDbUnavailable: true,
        error: errBody.error || 'Analysis completed, but the case could not be saved. Database is unavailable. Please retry saving the case.'
      };
    }

    if (res.status === 405) {
      return {
        success: false,
        isDbUnavailable: true,
        error: 'Failed to save case (HTTP 405 Method Not Allowed). The backend route does not support POST or static rewrite captured the request.'
      };
    }

    if (!res.ok) {
      const errBody = contentType.includes('application/json')
        ? await res.json().catch(() => ({}))
        : {};
      return {
        success: false,
        isDbUnavailable: res.status >= 500,
        error: errBody.error || `Failed to save case (HTTP ${res.status})`
      };
    }

    if (!contentType.includes('application/json')) {
      return {
        success: false,
        isDbUnavailable: true,
        error: 'Failed to save case: Server returned non-JSON response instead of case confirmation.'
      };
    }

    const data = await res.json();
    return {
      success: true,
      caseId: data.caseId,
      isDuplicate: Boolean(data.isDuplicate),
      case: data.case
    };
  } catch (err) {
    console.warn('[MAVERICK CaseStore] persistCaseInvestigation failed:', err.message);
    return {
      success: false,
      isDbUnavailable: true,
      error: 'Analysis completed, but the case could not be saved. Please retry saving the case.'
    };
  }
}

/**
 * Updates case status (e.g. 'archived', 'active')
 * 
 * @param {string} caseId
 * @param {string} status
 * @returns {Promise<{ success: boolean, case?: Object, error?: string }>}
 */
export async function archiveCase(caseId, status = 'archived', options = {}) {
  if (!caseId) return { success: false, error: 'Missing caseId' };
  const baseUrl = getApiBaseUrl();
  const endpoint = `${baseUrl}/api/cases/${encodeURIComponent(caseId.trim())}`;

  try {
    const res = await fetch(endpoint, {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ 
        status,
        actor: options.actor,
        note: options.note
      })
    });

    if (!res.ok) {
      const errBody = await res.json().catch(() => ({}));
      return { success: false, error: errBody.error || `HTTP ${res.status}` };
    }

    const data = await res.json();
    return { success: true, case: data.case };
  } catch (err) {
    return { success: false, error: err.message };
  }
}

/**
 * Fetches aggregated case statistics from real database data
 * 
 * @returns {Promise<{ totalCases: number, critical: number, high: number, medium: number, low: number, topThreats: Array, isDbUnavailable?: boolean, phishingDetections?: number, openCases?: number, severityDistribution?: Array, recentActivity?: Array }>}
 */
export async function fetchCaseStats() {
  const baseUrl = getApiBaseUrl();
  const endpoint = `${baseUrl}/api/cases/stats`;

  try {
    const res = await fetch(endpoint, {
      method: 'GET',
      headers: { 'Accept': 'application/json' }
    });

    if (res.ok) {
      const data = await res.json();
      return {
        ...data,
        isDbUnavailable: false
      };
    }
    return {
      totalCases: 0,
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
      phishingDetections: 0,
      openCases: 0,
      severityDistribution: [],
      recentActivity: [],
      topThreats: [],
      isDbUnavailable: true
    };
  } catch (err) {
    console.warn('[MAVERICK CaseStore] fetchCaseStats failed:', err.message);
    return {
      totalCases: 0,
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
      phishingDetections: 0,
      openCases: 0,
      severityDistribution: [],
      recentActivity: [],
      topThreats: [],
      isDbUnavailable: true
    };
  }
}

// Backward-compatibility adapters for legacy local views
export function getStoredCases() {
  return [];
}

export function saveCases() {
  // No-op in database-backed mode
}

export function createCaseFromAnalysis(analysisResult) {
  const threatScore = analysisResult.fusion?.threatScore || 0;
  const priority = getThreatPriority(threatScore);
  const caseId = generateCaseId(analysisResult.email?.sender);

  // Return formatted case model immediately for in-memory view
  return {
    caseId,
    sha256: analysisResult.email?.sha256 || null,
    emailHash: analysisResult.email?.sha256 || null,
    title: `Forensic Investigation: ${analysisResult.email?.subject || 'Suspicious Email Ingestion'}`,
    priority: priority.toUpperCase(),
    threatScore,
    riskScore: threatScore,
    status: 'active',
    assignedAnalyst: 'Analyst (SOC Lead)',
    creationTime: new Date().toLocaleString('en-IN', { timeZone: 'Asia/Kolkata' }) + ' IST',
    affectedTargets: 1,
    threatActorGroup: analysisResult.campaign?.campaignId ? `Correlated Cluster (${analysisResult.campaign.campaignId})` : 'Unassigned Actor',
    campaignId: analysisResult.campaign?.campaignId || 'TC-001',
    iocsCount: analysisResult.iocs?.length || 0,
    primaryVector: analysisResult.email?.replyToMismatch ? 'Reply-To Mismatch / Forged Domain' : 'Suspicious Email Ingress',
    summary: `Analyzed email from "${analysisResult.email?.sender || 'Unknown'}". Threat Score: ${threatScore}/100.`,
    containmentStatus: {
      mailboxPurged: false,
      domainBlocked: false,
      ipBlocked: false,
      credentialsRevoked: false
    },
    notes: []
  };
}

export async function addCaseNote(caseId, noteText, author = 'Analyst (SOC Lead)') {
  if (!caseId || !noteText) return { success: false, error: 'Missing caseId or noteText' };
  const baseUrl = getApiBaseUrl();
  const endpoint = `${baseUrl}/api/cases/${encodeURIComponent(caseId.trim())}`;
  try {
    const res = await fetch(endpoint, {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ note: noteText, actor: author })
    });
    if (!res.ok) {
      const errBody = await res.json().catch(() => ({}));
      return { success: false, error: errBody.error || `HTTP ${res.status}` };
    }
    const data = await res.json();
    return { success: true, case: data.case };
  } catch (err) {
    return { success: false, error: err.message };
  }
}

export async function updateCaseStatus(caseId, status, options = {}) {
  return archiveCase(caseId, status, options);
}

export function toggleCaseContainment() {
  return [];
}
