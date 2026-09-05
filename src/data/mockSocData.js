// MAVERICK Cybersecurity SOC Dataset (Smart India Hackathon 2026)

export const SOC_SUMMARY = {
  activeDefcon: "DEFCON 2",
  defconStatus: "ELEVATED THREAT POSTURE",
  scanned24h: 28492,
  maliciousBlocked: 1438,
  suspiciousQuarantined: 389,
  zeroDayPhishingCampaigns: 14,
  meanTimeToDetect: "4.2s",
  meanTimeToMitigate: "18.6s",
  aiModelAccuracy: "99.82%",
  falsePositiveRate: "0.03%",
  aiEngineStatus: "ONLINE (MAVERICK Neural-v4.2-Hybrid)",
  lastRuleUpdate: "2 mins ago (SIH-THREAT-SIG-2026.09)",
};

export const THREAT_VELOCITY_DATA = [
  { time: "00:00", scanned: 820, blocked: 42, suspicious: 12 },
  { time: "02:00", scanned: 640, blocked: 31, suspicious: 9 },
  { time: "04:00", scanned: 510, blocked: 26, suspicious: 7 },
  { time: "06:00", scanned: 940, blocked: 58, suspicious: 18 },
  { time: "08:00", scanned: 1820, blocked: 114, suspicious: 32 },
  { time: "10:00", scanned: 2950, blocked: 198, suspicious: 45 },
  { time: "12:00", scanned: 3410, blocked: 240, suspicious: 64 },
  { time: "14:00", scanned: 3820, blocked: 285, suspicious: 71 },
  { time: "16:00", scanned: 3120, blocked: 215, suspicious: 52 },
  { time: "18:00", scanned: 2310, blocked: 142, suspicious: 38 },
  { time: "20:00", scanned: 1720, blocked: 89, suspicious: 24 },
  { time: "22:00", scanned: 1120, blocked: 56, suspicious: 15 },
];

export const ATTACK_VECTORS = [
  { name: "QR Quishing", value: 38, count: 546, color: "#06b6d4" }, // cyan
  { name: "Executive BEC", value: 24, count: 345, color: "#ef4444" }, // red
  { name: "Credential Harvest", value: 20, count: 287, color: "#f59e0b" }, // amber
  { name: "Payload Attachment", value: 12, count: 172, color: "#a855f7" }, // purple
  { name: "Homograph Domain", value: 6, count: 88, color: "#3b82f6" }, // blue
];

export const MITRE_TACTICS = [
  {
    techniqueId: "T1566.002",
    name: "Spearphishing Link",
    tactic: "Initial Access",
    threatCount: 742,
    severity: "CRITICAL",
    confidence: "99.4%",
    activeInLast24h: true
  },
  {
    techniqueId: "T1566.001",
    name: "Spearphishing Attachment (Macro/OneNote)",
    tactic: "Initial Access",
    threatCount: 312,
    severity: "HIGH",
    confidence: "98.1%",
    activeInLast24h: true
  },
  {
    techniqueId: "T1583.001",
    name: "Acquire Domains: Typosquatting",
    tactic: "Resource Development",
    threatCount: 220,
    severity: "HIGH",
    confidence: "96.5%",
    activeInLast24h: true
  },
  {
    techniqueId: "T1056.004",
    name: "Credential API Redirection",
    tactic: "Credential Access",
    threatCount: 164,
    severity: "CRITICAL",
    confidence: "99.1%",
    activeInLast24h: true
  },
  {
    techniqueId: "T1534",
    name: "Internal Spearphishing (Compromised O365)",
    tactic: "Lateral Movement",
    threatCount: 94,
    severity: "CRITICAL",
    confidence: "97.8%",
    activeInLast24h: false
  },
  {
    techniqueId: "T1027",
    name: "Obfuscated QR Vector / Base64 Polyglot",
    tactic: "Defense Evasion",
    threatCount: 388,
    severity: "HIGH",
    confidence: "98.9%",
    activeInLast24h: true
  }
];

export const LIVE_THREAT_FEED = [
  {
    id: "THREAT-2026-9041",
    timestamp: "11:42:08",
    sender: "cfo-payroll-update@micros0ft-support-365.online",
    displaySender: "Satya Nadella <cfo-payroll-update@micros0ft-support-365.online>",
    recipient: "finance.controller@gov-organization.in",
    subject: "URGENT: Executive Wire Authorization - SIH-Q3 Treasury Allocation",
    threatCategory: "Business Email Compromise (BEC)",
    riskScore: 98,
    status: "QUARANTINED",
    spf: "FAIL",
    dkim: "FAIL",
    dmarc: "FAIL",
    ipOrigin: "185.220.101.45 (AS9009 - M247 Europe)",
    country: "DE",
    maliciousIndicators: ["Punycode Domain", "Urgency Urge NLP Trigger", "Unusual Wire Pattern", "Known Tor Exit Node"],
    targetedRole: "Chief Financial Officer"
  },
  {
    id: "THREAT-2026-9040",
    timestamp: "11:39:15",
    sender: "qr-authenticator@secure-login-okta.me",
    displaySender: "IT Global Security <qr-authenticator@secure-login-okta.me>",
    recipient: "devops-lead@gov-organization.in",
    subject: "MANDATORY: Upgrade Multi-Factor Token via Attached QR Barcode",
    threatCategory: "Quishing (QR Code Phishing)",
    riskScore: 95,
    status: "BLOCKED",
    spf: "SOFTFAIL",
    dkim: "PASS (Forged Domain)",
    dmarc: "FAIL",
    ipOrigin: "45.154.255.82 (AS202425 - IP Volume Inc)",
    country: "NL",
    maliciousIndicators: ["Embedded High-Density QR", "Zero-day Redirection Target", "Reverse Proxy Phishlets"],
    targetedRole: "DevOps Engineer"
  },
  {
    id: "THREAT-2026-9039",
    timestamp: "11:35:42",
    sender: "vendor-invoicing@standardchartered-in.cc",
    displaySender: "Accounts Billing <vendor-invoicing@standardchartered-in.cc>",
    recipient: "procurement@gov-organization.in",
    subject: "Overdue Remittance Advice: Invoice #IN-2026-8849.pdf.exe",
    threatCategory: "Malware Delivery / Trojan-Dropper",
    riskScore: 99,
    status: "PURGED & ISOLATED",
    spf: "FAIL",
    dkim: "NONE",
    dmarc: "FAIL",
    ipOrigin: "193.106.191.12 (AS44034 - HiChina Web)",
    country: "RU",
    maliciousIndicators: ["Double Extension Payload", "AgentTesla Signatures", "Process Hollowing Shellcode"],
    targetedRole: "Procurement Officer"
  },
  {
    id: "THREAT-2026-9038",
    timestamp: "11:30:19",
    sender: "notifications@github-security-alert.live",
    displaySender: "GitHub Enterprise Alerts <notifications@github-security-alert.live>",
    recipient: "sih.core-team@gov-organization.in",
    subject: "[Security Notification] Personal Access Token leaked in public repo",
    threatCategory: "Credential Harvesting",
    riskScore: 91,
    status: "BLOCKED",
    spf: "PASS (Free Relayer)",
    dkim: "NONE",
    dmarc: "FAIL",
    ipOrigin: "103.208.220.14 (AS13335 - Cloudflare Proxied)",
    country: "SG",
    maliciousIndicators: ["Fake GitHub OAuth Page", "Session Hijacking Kit", "Fast Flux DNS"],
    targetedRole: "Senior Systems Architect"
  },
  {
    id: "THREAT-2026-9037",
    timestamp: "11:24:50",
    sender: "newsletter@trusted-cloud-partners.com",
    displaySender: "AWS Tech Brief <newsletter@trusted-cloud-partners.com>",
    recipient: "cloud-admin@gov-organization.in",
    subject: "AWS Cloud Architecture Monthly Digest - September 2026",
    threatCategory: "Benign / Verified",
    riskScore: 12,
    status: "DELIVERED",
    spf: "PASS",
    dkim: "PASS",
    dmarc: "PASS",
    ipOrigin: "54.240.27.112 (AS16509 - Amazon.com)",
    country: "US",
    maliciousIndicators: [],
    targetedRole: "Cloud Engineer"
  },
  {
    id: "THREAT-2026-9036",
    timestamp: "11:18:02",
    sender: "hr-benefits@portal-adp-reimburse.top",
    displaySender: "Global HR Payroll Desk <hr-benefits@portal-adp-reimburse.top>",
    recipient: "staff-all@gov-organization.in",
    subject: "Immediate Action Required: Inflationary Stipend Benefit Survey",
    threatCategory: "Social Engineering Phish",
    riskScore: 89,
    status: "QUARANTINED",
    spf: "FAIL",
    dkim: "FAIL",
    dmarc: "FAIL",
    ipOrigin: "194.26.29.110 (AS48693 - HostRoyale)",
    country: "RO",
    maliciousIndicators: ["Mass Recipient Distribution", "Brand Impersonation (ADP)", "Credential Logging Form"],
    targetedRole: "All Employees"
  }
];

export const INCIDENT_CASES = [
  {
    caseId: "CAS-2026-0881",
    title: "Nation-State Targeted BEC Campaign against SIH-2026 Key Officials",
    priority: "CRITICAL",
    riskScore: 98,
    affectedTargets: 6,
    threatActorGroup: "UNC4219 (Suspected CozyBear affiliate)",
    attackStage: "Initial Access & Reconnaissance",
    primaryVector: "Executive Impersonation / Homoglyph Domain",
    assignedAnalyst: "Analyst-Alpha (Deepak R.)",
    creationTime: "2026-09-05 10:15:00 IST",
    status: "INVESTIGATING",
    iocsCount: 24,
    mitreTactics: ["T1566.002", "T1583.001", "T1056"],
    summary: "High-entropy spearphishing campaign using lookalike domain `micros0ft-support-365.online` attempting wire-diversion against state finance officials."
  },
  {
    caseId: "CAS-2026-0880",
    title: "Mass Quishing (QR-Code Phishing) bypassing Secure Email Gateways",
    priority: "HIGH",
    riskScore: 95,
    affectedTargets: 14,
    threatActorGroup: "Storm-1113 QuishKit",
    attackStage: "Credential Harvest via Reverse-Proxy Phishlet",
    primaryVector: "QR Code Vector embedded in SVG/PDF",
    assignedAnalyst: "Analyst-Gamma (Siddharth K.)",
    creationTime: "2026-09-05 09:30:22 IST",
    status: "CONTAINED",
    iocsCount: 16,
    mitreTactics: ["T1027", "T1566.002"],
    summary: "SVG-encoded high-density QR codes targeting 2FA authentication tokens via real-time reverse proxy servers hosted in Netherlands."
  },
  {
    caseId: "CAS-2026-0879",
    title: "Double-Extension Ransomware Dropper via Spoofed Vendor Remittance",
    priority: "CRITICAL",
    riskScore: 99,
    affectedTargets: 2,
    threatActorGroup: "LockBit 4.0 Subcontractor",
    attackStage: "Execution via Process Injection",
    primaryVector: "Malicious Attachment `Remittance_Advice.pdf.exe`",
    assignedAnalyst: "Analyst-Beta (Pooja S.)",
    creationTime: "2026-09-05 08:44:11 IST",
    status: "REMEDIATED",
    iocsCount: 31,
    mitreTactics: ["T1566.001", "T1059", "T1486"],
    summary: "Polyglot executable hidden inside obfuscated PDF structure attempting AMSI bypass and LSASS memory dumping."
  },
  {
    caseId: "CAS-2026-0876",
    title: "Compromised M365 Tenant Session Hijack & Lateral Mail Forwarding",
    priority: "MEDIUM",
    riskScore: 78,
    affectedTargets: 1,
    threatActorGroup: "Unknown Cybercrime Syndicate",
    attackStage: "Lateral Movement & Persistence",
    primaryVector: "Stolen AiTM Refresh Token",
    assignedAnalyst: "Analyst-Delta (Ananya M.)",
    creationTime: "2026-09-04 18:22:45 IST",
    status: "RESOLVED",
    iocsCount: 9,
    mitreTactics: ["T1534", "T1114"],
    summary: "Internal mail forwarding rule created silently on compromised mailbox to forward financial drafts to external protonmail address."
  }
];

export const GEO_ASN_SAMPLE = [
  { country: "Netherlands", code: "NL", count: 480, lat: 52.3676, lng: 4.9041, asn: "AS202425 (IP Volume Inc)" },
  { country: "Germany", code: "DE", count: 320, lat: 51.1657, lng: 10.4515, asn: "AS9009 (M247 Ltd)" },
  { country: "Russia", code: "RU", count: 290, lat: 61.524, lng: 105.3188, asn: "AS44034 (HiChina / HostWeb)" },
  { country: "Romania", code: "RO", count: 185, lat: 45.9432, lng: 24.9668, asn: "AS48693 (HostRoyale Inc)" },
  { country: "Singapore", code: "SG", count: 95, lat: 1.3521, lng: 103.8198, asn: "AS13335 (Cloudflare Tor)" },
  { country: "United States", code: "US", count: 68, lat: 37.0902, lng: -95.7129, asn: "AS16509 (AWS Relayers)" },
];

export const PIPELINE_STEPS = [
  { id: "dashboard", label: "1. Dashboard", icon: "LayoutDashboard", badge: "Live SOC" },
  { id: "email-analysis", label: "2. Email Analysis", icon: "MailSearch", badge: "Parser" },
  { id: "analysis-results", label: "3. Analysis Results", icon: "ShieldAlert", badge: "AI Verdict" },
  { id: "ioc-intel", label: "4. IOC Intelligence", icon: "Binary", badge: "Threat Feeds" },
  { id: "geo-asn", label: "5. GeoLocation & ASN", icon: "Globe2", badge: "Infrastructure" },
  { id: "threat-graph", label: "6. Threat Graph", icon: "GitFork", badge: "React Flow" },
  { id: "investigation-case", label: "7. Investigation Case", icon: "Briefcase", badge: "Active War Room" },
  { id: "forensic-report", label: "8. Forensic Report", icon: "FileText", badge: "Automated PDF/Doc" },
];
