/**
 * MAVERICK — Case Management Store
 * Smart India Hackathon 2026
 * 
 * Manages incident response cases:
 * - Case ID: CAS-2026-XXXX / MV-XXX
 * - Status: UNDER INVESTIGATION (🟡) | CONFIRMED THREAT (🔴) | FALSE POSITIVE (🟢) | CLOSED (⚫)
 * - Analyst notes log with timestamps
 * - Containment actions state (quarantine mailbox, block domain, block IP, revoke credentials)
 * - Relationships between Cases, Ingested Emails, IOCs, Threat Intel, and Campaigns
 * - In-memory and localStorage persistence
 */

const STORAGE_KEY = 'maverick_soc_cases_v1';

export const INITIAL_CASES = [
  {
    caseId: 'CAS-2026-0881',
    title: 'Nation-State Targeted BEC Wire Diversion Campaign',
    priority: 'CRITICAL',
    riskScore: 92,
    status: 'UNDER INVESTIGATION',
    assignedAnalyst: 'Analyst-Alpha (Deepak R.)',
    creationTime: '2026-09-05 10:15:00 IST',
    affectedTargets: 6,
    threatActorGroup: 'UNC4219 (Lookalike Domain Cluster)',
    campaignId: 'TC-001',
    iocsCount: 14,
    primaryVector: 'Executive Impersonation / Reply-To Mismatch',
    summary: 'Spearphishing BEC using deceptive domain internal-corp-portal.online targeting treasury controller for unauthorized wire allocation.',
    containmentStatus: {
      mailboxPurged: false,
      domainBlocked: true,
      ipBlocked: true,
      credentialsRevoked: true
    },
    notes: [
      { id: 1, author: 'Analyst-Alpha', timestamp: '2026-09-05 10:20 IST', text: 'Originating IP 185.220.101.45 verified as Tor exit relay in Germany (AS9009).' },
      { id: 2, author: 'Analyst-Alpha', timestamp: '2026-09-05 10:45 IST', text: 'Reply-To mismatch flagged: external-offshore-treasury@proton.me. Domain blocked in gateway.' }
    ]
  },
  {
    caseId: 'CAS-2026-0880',
    title: 'Mass Reverse-Proxy Quishing Bypassing Secure Email Gateways',
    priority: 'HIGH',
    riskScore: 88,
    status: 'CONFIRMED THREAT',
    assignedAnalyst: 'Analyst-Gamma (Siddharth K.)',
    creationTime: '2026-09-05 09:30:22 IST',
    affectedTargets: 14,
    threatActorGroup: 'Storm-1113 Phishlet Kit',
    campaignId: 'TC-002',
    iocsCount: 16,
    primaryVector: 'QR Code Redirection Vector',
    summary: 'High-density QR code embedding reverse-proxy phishlet hosted in Netherlands targeting 2FA authentication tokens.',
    containmentStatus: {
      mailboxPurged: true,
      domainBlocked: true,
      ipBlocked: true,
      credentialsRevoked: true
    },
    notes: [
      { id: 1, author: 'Analyst-Gamma', timestamp: '2026-09-05 09:35 IST', text: '14 user mailboxes quarantined; domain secure-login-okta.me sinkholed.' }
    ]
  },
  {
    caseId: 'CAS-2026-0879',
    title: 'Double-Extension Ransomware Dropper via Spoofed Remittance',
    priority: 'CRITICAL',
    riskScore: 98,
    status: 'CONFIRMED THREAT',
    assignedAnalyst: 'Analyst-Beta (Pooja M.)',
    creationTime: '2026-09-04 18:10:00 IST',
    affectedTargets: 2,
    threatActorGroup: 'AgentTesla Dropper Affiliate',
    campaignId: 'TC-003',
    iocsCount: 8,
    primaryVector: 'Double-Extension Payload (.pdf.exe)',
    summary: 'PE32 executable disguised as remittance invoice attempting process injection on procurement workstation.',
    containmentStatus: {
      mailboxPurged: true,
      domainBlocked: true,
      ipBlocked: true,
      credentialsRevoked: false
    },
    notes: [
      { id: 1, author: 'Analyst-Beta', timestamp: '2026-09-04 18:15 IST', text: 'SHA256 pushed to EDR blocklist; host quarantined from corporate LAN.' }
    ]
  }
];

export function getStoredCases() {
  try {
    const data = localStorage.getItem(STORAGE_KEY);
    if (data) {
      const parsed = JSON.parse(data);
      if (Array.isArray(parsed) && parsed.length > 0) return parsed;
    }
  } catch {
    // localStorage unavailable
  }
  return [...INITIAL_CASES];
}

export function saveCases(cases) {
  try {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(cases));
  } catch {
    // ignore
  }
}

export function addCaseNote(caseId, noteText, author = 'Analyst (SOC Lead)') {
  const cases = getStoredCases();
  const target = cases.find(c => c.caseId === caseId);
  if (target) {
    if (!target.notes) target.notes = [];
    target.notes.push({
      id: Date.now(),
      author,
      timestamp: new Date().toLocaleString('en-IN', { timeZone: 'Asia/Kolkata' }) + ' IST',
      text: noteText
    });
    saveCases(cases);
  }
  return cases;
}

export function updateCaseStatus(caseId, status) {
  const cases = getStoredCases();
  const target = cases.find(c => c.caseId === caseId);
  if (target) {
    target.status = status;
    saveCases(cases);
  }
  return cases;
}

export function toggleCaseContainment(caseId, actionKey) {
  const cases = getStoredCases();
  const target = cases.find(c => c.caseId === caseId);
  if (target) {
    if (!target.containmentStatus) target.containmentStatus = {};
    target.containmentStatus[actionKey] = !target.containmentStatus[actionKey];
    saveCases(cases);
  }
  return cases;
}

export function createCaseFromAnalysis(analysisResult) {
  const cases = getStoredCases();
  const newCaseId = `CAS-2026-0${cases.length + 882}`;
  
  const newCase = {
    caseId: newCaseId,
    title: `Forensic Investigation: ${analysisResult.email?.subject || 'Suspicious Email Ingestion'}`,
    priority: analysisResult.fusion?.threatScore >= 80 ? 'CRITICAL' : analysisResult.fusion?.threatScore >= 50 ? 'HIGH' : 'MEDIUM',
    riskScore: analysisResult.fusion?.threatScore || 85,
    status: 'UNDER INVESTIGATION',
    assignedAnalyst: 'Analyst-Alpha (SOC Lead)',
    creationTime: new Date().toLocaleString('en-IN', { timeZone: 'Asia/Kolkata' }) + ' IST',
    affectedTargets: 1,
    threatActorGroup: analysisResult.campaign?.campaignId ? `Correlated Cluster (${analysisResult.campaign.campaignId})` : 'Unassigned Actor',
    campaignId: analysisResult.campaign?.campaignId || 'TC-001',
    iocsCount: analysisResult.iocs?.length || 6,
    primaryVector: analysisResult.email?.replyToMismatch ? 'Reply-To Mismatch / Forged Domain' : 'Suspicious Email Ingress',
    summary: `Analyzed email from "${analysisResult.email?.sender || 'Unknown'}" targeting "${analysisResult.email?.recipient || 'Unknown'}". AI probability: ${analysisResult.aiThreat?.phishingProbability || 0}%, Fusion score: ${analysisResult.fusion?.threatScore || 0}/100.`,
    containmentStatus: {
      mailboxPurged: false,
      domainBlocked: false,
      ipBlocked: false,
      credentialsRevoked: false
    },
    notes: [
      {
        id: Date.now(),
        author: 'MAVERICK AI Engine',
        timestamp: new Date().toLocaleString('en-IN', { timeZone: 'Asia/Kolkata' }) + ' IST',
        text: `Automated case initiated. Evidence fusion calculated risk score ${analysisResult.fusion?.threatScore || 0}/100 (${analysisResult.fusion?.riskLevel || 'HIGH'}).`
      }
    ]
  };

  const updated = [newCase, ...cases];
  saveCases(updated);
  return newCase;
}
