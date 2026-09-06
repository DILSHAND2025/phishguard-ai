/**
 * MAVERICK — Controlled Synthetic Attack Scenarios
 * Smart India Hackathon 2026
 * 
 * High-fidelity synthetic email vectors clearly marked as SYNTHETIC/DEMO.
 * Used for reproducible demonstrations, testing, and offline presentation.
 */

export const SYNTHETIC_SCENARIOS = [
  {
    id: 'ceo-bec',
    name: 'Executive Wire BEC (Statutory Bypass)',
    category: 'Business Email Compromise (BEC)',
    tag: 'DEMO / SYNTHETIC',
    summary: 'Forged CFO authorization targeting state treasury department with coercive bypass instructions and proton.me reply-to redirect.',
    sender: 'Satya N. (Executive Desk) <cfo-finance-update@internal-corp-portal.online>',
    recipient: 'treasury-controller@gov-organization.in',
    subject: 'URGENT: Executive Wire Authorization - SIH-Q3 Allocation',
    date: 'Fri, 05 Sep 2026 11:41:50 +0530 (IST)',
    replyTo: 'external-offshore-treasury@proton.me',
    returnPath: 'bounces@unverified-relay-mailer.top',
    originatingIP: '185.220.101.45',
    asn: 'AS9009',
    asnOrg: 'M247 Ltd Europe',
    country: 'Germany',
    countryCode: 'DE',
    networkType: 'Tor Exit / Anonymizing Relay',
    spfResult: 'SOFTFAIL (IP 185.220.101.45 not authorized)',
    dkimResult: 'FAIL (Invalid Cryptographic Signature)',
    dmarcResult: 'FAIL (Policy: Reject / Quarantine Enforced)',
    replyToMismatch: true,
    returnPathMismatch: true,
    urls: [
      'http://internal-corp-portal.online/auth-portal/wire-release',
      'http://auth.secure-sso-verify.me/token'
    ],
    ips: [
      '185.220.101.45',
      '45.154.255.82',
      '194.26.29.110'
    ],
    attachments: [
      {
        filename: 'Wire_Remittance_Directive.pdf.exe',
        size: '242.6 KB',
        rawSizeBytes: 248420,
        flag: 'Double Extension / Obfuscated PE32 Executable',
        isSuspicious: true,
        md5: '7d1a293b6e8f4c102948a7b6c5d4e3f2',
        sha1: '9a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d3e2f1a0b',
        sha256: '8f4c102948a7b6c5d4e3f27d1a293b6e8f4c102948a7b6c5d4e3f27d1a293b6e'
      }
    ],
    bodyText: `Treasury Controller,

Expedite statutory allocation transfer of INR 4,85,00,000 immediately for critical infrastructure procurement.
Ministerial Directive bypass applied by Executive Council.
Do not delay processing for standard second-signatory review.
Verification documents and Swift release tokens attached.

Satya N.
Executive Operations Office`,
    rawSnippet: `Delivered-To: treasury-controller@gov-organization.in
Received: from mail-relay-fra.internal-corp-portal.online (185.220.101.45)
        by mail.gov-organization.in with ESMTP id p4csp392873;
        Fri, 05 Sep 2026 11:41:50 +0530 (IST)
Received: from reverse-proxy-ams.node (45.154.255.82)
        by mail-relay-fra.internal-corp-portal.online with SMTP;
        Fri, 05 Sep 2026 06:11:48 +0000
Return-Path: <bounces@unverified-relay-mailer.top>
Received-SPF: softfail (mail.gov-organization.in: domain of cfo-finance-update@internal-corp-portal.online does not designate 185.220.101.45)
Authentication-Results: mail.gov-organization.in;
       dkim=fail (bad signature) header.i=@internal-corp-portal.online;
       dmarc=fail (p=REJECT sp=REJECT)
From: "Satya N. (Executive Desk)" <cfo-finance-update@internal-corp-portal.online>
Reply-To: <external-offshore-treasury@proton.me>
To: <treasury-controller@gov-organization.in>
Subject: URGENT: Executive Wire Authorization - SIH-Q3 Allocation
Date: Fri, 05 Sep 2026 11:41:50 +0530
Message-ID: <SIH-2026-MIME-8841@internal-corp-portal.online>
Content-Type: multipart/mixed; boundary="====_MIME_BOUNDARY_SIH_001_===="

--====_MIME_BOUNDARY_SIH_001_====
Content-Type: text/plain; charset="utf-8"
Content-Transfer-Encoding: 7bit

Treasury Controller,
Expedite statutory allocation transfer of INR 4,85,00,000 immediately for critical infrastructure.
Ministerial Directive bypass applied. Verification documents attached.

--====_MIME_BOUNDARY_SIH_001_====
Content-Type: application/octet-stream; name="Wire_Remittance_Directive.pdf.exe"
Content-Disposition: attachment; filename="Wire_Remittance_Directive.pdf.exe"
Content-Transfer-Encoding: base64

TVqQAAMAAAAEAAAA//8AALgAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA...
--====_MIME_BOUNDARY_SIH_001_====--`
  },

  {
    id: 'bank-phishing',
    name: 'State Treasury Banking Phish',
    category: 'Credential Phishing / Impersonation',
    tag: 'DEMO / SYNTHETIC',
    summary: 'Deceptive financial advisory claiming impending RTGS portal suspension; lures recipient to fake authorization portal.',
    sender: 'State Bank Central Remittance <alerts@sbi-treasury-gateway.cc>',
    recipient: 'accounts-payable@gov-organization.in',
    subject: 'MANDATORY: RTGS/NEFT Corporate Token Recertification Required',
    date: 'Fri, 05 Sep 2026 10:15:22 +0530 (IST)',
    replyTo: 're-auth-desk@sbi-treasury-gateway.cc',
    returnPath: 'bounce-gateway@unregistered-host.org',
    originatingIP: '104.21.36.45',
    asn: 'AS13335',
    asnOrg: 'Cloudflare Edge Transit',
    country: 'United States',
    countryCode: 'US',
    networkType: 'Commercial CDN / Proxied Egress',
    spfResult: 'FAIL (IP 104.21.36.45 is not an authorized sender for sbi.co.in)',
    dkimResult: 'FAIL (Header missing or unsigned)',
    dmarcResult: 'FAIL (Alignment policy violation)',
    replyToMismatch: false,
    returnPathMismatch: true,
    urls: [
      'https://sbi-treasury-gateway.cc/epay/token-sync',
      'http://104.21.36.45/verify-certificate'
    ],
    ips: [
      '104.21.36.45',
      '172.67.182.204'
    ],
    attachments: [
      {
        filename: 'Token_Synchronization_Guide.pdf',
        size: '118.4 KB',
        rawSizeBytes: 121240,
        flag: 'Embedded Hyperlink Redirection Target',
        isSuspicious: false,
        md5: '4a3b2c1d0e9f8a7b6c5d4e3f2a1b0c9d',
        sha1: '1f2e3d4c5b6a798091a2b3c4d5e6f7a8b9c0d1e2',
        sha256: '9f8e7d6c5b4a3a2b1c0d9e8f7a6b5c4d3e2f1a0b4a3b2c1d0e9f8a7b6c5d4e3f'
      }
    ],
    bodyText: `Attn: Corporate Accounts Officer,

Due to updated RBI regulatory directives, your institutional RTGS batch settlement credentials will expire in 4 hours.
Failure to renew token keys will cause temporary suspension of outgoing NEFT and RTGS remittance clearing.

Please authenticate immediately via the Secure Corporate Settlement Gateway:
https://sbi-treasury-gateway.cc/epay/token-sync

State Bank Remittance Cell`,
    rawSnippet: `Delivered-To: accounts-payable@gov-organization.in
Received: from edge-proxy.cloudflare.com (104.21.36.45)
        by mail.gov-organization.in with ESMTP id q9rt48192;
        Fri, 05 Sep 2026 10:15:22 +0530 (IST)
Return-Path: <bounce-gateway@unregistered-host.org>
Received-SPF: fail (mail.gov-organization.in: 104.21.36.45 is not designated sender)
Authentication-Results: mail.gov-organization.in;
       dkim=none (no signature);
       dmarc=fail (p=REJECT)
From: "State Bank Central Remittance" <alerts@sbi-treasury-gateway.cc>
Reply-To: <re-auth-desk@sbi-treasury-gateway.cc>
To: <accounts-payable@gov-organization.in>
Subject: MANDATORY: RTGS/NEFT Corporate Token Recertification Required
Date: Fri, 05 Sep 2026 10:15:22 +0530
Message-ID: <BANK-ALERT-20260905-19942@sbi-treasury-gateway.cc>

Attn: Corporate Accounts Officer,
Due to updated RBI regulatory directives, your institutional RTGS credentials will expire in 4 hours.
Please authenticate immediately via: https://sbi-treasury-gateway.cc/epay/token-sync`
  },

  {
    id: 'malware-dropper',
    name: 'Polyglot AgentTesla Trojan Dropper',
    category: 'Malware Delivery / PE Dropper',
    tag: 'DEMO / SYNTHETIC',
    summary: 'Disguised vendor invoice with hidden PE32 executable header and DLL injection routine targeting procurement workstations.',
    sender: 'Accounts Billing Desk <vendor-invoicing@standardchartered-in.cc>',
    recipient: 'procurement@gov-organization.in',
    subject: 'Overdue Remittance Advice: Invoice #IN-2026-8849.pdf.exe',
    date: 'Fri, 05 Sep 2026 11:35:42 +0530 (IST)',
    replyTo: 'dropzone@darknet-c2-listener.top',
    returnPath: 'mailer@relay-hichina.net',
    originatingIP: '193.106.191.12',
    asn: 'AS44034',
    asnOrg: 'HiChina Web Hosting',
    country: 'Russia',
    countryCode: 'RU',
    networkType: 'Hosting / Bulletproof Infrastructure',
    spfResult: 'FAIL (IP 193.106.191.12 rejected by SPF)',
    dkimResult: 'FAIL (Cryptographic signature absent)',
    dmarcResult: 'FAIL (Policy: Reject)',
    replyToMismatch: true,
    returnPathMismatch: true,
    urls: [
      'http://darknet-c2-listener.top/gate.php',
      'http://193.106.191.12/payload/stage2.bin'
    ],
    ips: [
      '193.106.191.12',
      '91.240.118.50'
    ],
    attachments: [
      {
        filename: 'Remittance_Advice_IN-2026-8849.pdf.exe',
        size: '348.2 KB',
        rawSizeBytes: 356556,
        flag: 'Double Extension / Obfuscated PE32 Executable Binary',
        isSuspicious: true,
        md5: 'e1d2c3b4a5f60718293a4b5c6d7e8f90',
        sha1: '0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b',
        sha256: '3f2e1d0c9b8a7f6e5d4c3b2a109876543210fedcba9876543210abcdef123456'
      }
    ],
    bodyText: `Dear Procurement Team,

Attached please find payment receipt and reconciled ledger summary for Purchase Order #PO-9912.
Kindly review discrepancies on page 2 immediately before dispatch cutoff today.

Regards,
Vendor Accounts Support`,
    rawSnippet: `Delivered-To: procurement@gov-organization.in
Received: from c2-relay.hichina.net (193.106.191.12)
        by mail.gov-organization.in with ESMTP id m203948;
        Fri, 05 Sep 2026 11:35:42 +0530 (IST)
Return-Path: <mailer@relay-hichina.net>
Received-SPF: fail (mail.gov-organization.in: 193.106.191.12 not permitted)
Authentication-Results: mail.gov-organization.in;
       dkim=fail;
       dmarc=fail (p=REJECT)
From: "Accounts Billing Desk" <vendor-invoicing@standardchartered-in.cc>
Reply-To: <dropzone@darknet-c2-listener.top>
To: <procurement@gov-organization.in>
Subject: Overdue Remittance Advice: Invoice #IN-2026-8849.pdf.exe
Date: Fri, 05 Sep 2026 11:35:42 +0530
Content-Disposition: attachment; filename="Remittance_Advice_IN-2026-8849.pdf.exe"`
  },

  {
    id: 'credential-harvesting',
    name: 'Okta / Microsoft 365 Phishlet SSO',
    category: 'Credential Harvesting',
    tag: 'DEMO / SYNTHETIC',
    summary: 'Reverse-proxy phishlet mimicking enterprise SSO authentication portal to bypass two-factor authentication tokens.',
    sender: 'IT Global Security Desk <qr-authenticator@secure-login-okta.me>',
    recipient: 'devops-lead@gov-organization.in',
    subject: 'MANDATORY: Re-authenticate Corporate 2FA Session',
    date: 'Fri, 05 Sep 2026 11:39:15 +0530 (IST)',
    replyTo: 'identity-verify@secure-login-okta.me',
    returnPath: 'daemon@reverse-proxy-nl.net',
    originatingIP: '45.154.255.82',
    asn: 'AS202425',
    asnOrg: 'IP Volume Inc',
    country: 'Netherlands',
    countryCode: 'NL',
    networkType: 'Commercial Hosting / Proxy Farm',
    spfResult: 'SOFTFAIL (IP 45.154.255.82 designated as unverified relay)',
    dkimResult: 'FAIL (Cryptographic signature forged)',
    dmarcResult: 'FAIL (DMARC policy rejection)',
    replyToMismatch: false,
    returnPathMismatch: true,
    urls: [
      'https://auth.secure-sso-verify.me/token?session=9941a',
      'https://secure-login-okta.me/mfa/sync'
    ],
    ips: [
      '45.154.255.82',
      '185.220.101.45'
    ],
    attachments: [
      {
        filename: 'Authenticator_Sync_Barcode.svg',
        size: '14.8 KB',
        rawSizeBytes: 15155,
        flag: 'High-Density SVG with Embedded External Javascript Vector',
        isSuspicious: true,
        md5: '8b7a6c5d4e3f2a1b0c9d8e7f6a5b4c3d',
        sha1: '3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d',
        sha256: '5a4b3c2d1e0f9a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d3e2f1a0b9c8d7e6f5a4b'
      }
    ],
    bodyText: `DevOps Team,

Our identity access management system detected anomalous activity on your Active Directory account from an unrecognized subnet.
As part of emergency defense protocols, your session tokens have been restricted.

Re-authenticate your Multi-Factor Authenticator token immediately to prevent directory lock:
https://auth.secure-sso-verify.me/token?session=9941a

Identity Access Operations`,
    rawSnippet: `Delivered-To: devops-lead@gov-organization.in
Received: from phishlet-node.reverse-proxy-nl.net (45.154.255.82)
        by mail.gov-organization.in with ESMTP id ok9924;
        Fri, 05 Sep 2026 11:39:15 +0530 (IST)
Return-Path: <daemon@reverse-proxy-nl.net>
Received-SPF: softfail (mail.gov-organization.in: domain does not authorize 45.154.255.82)
Authentication-Results: mail.gov-organization.in;
       dkim=fail;
       dmarc=fail (p=REJECT)
From: "IT Global Security Desk" <qr-authenticator@secure-login-okta.me>
To: <devops-lead@gov-organization.in>
Subject: MANDATORY: Re-authenticate Corporate 2FA Session
Date: Fri, 05 Sep 2026 11:39:15 +0530

DevOps Team,
Re-authenticate your Multi-Factor Authenticator token immediately:
https://auth.secure-sso-verify.me/token?session=9941a`
  },

  {
    id: 'shared-campaign',
    name: 'Multi-Vector Correlated Campaign (Cluster TC-001)',
    category: 'Targeted Campaign Infrastructure',
    tag: 'DEMO / SYNTHETIC',
    summary: 'Correlated attack campaign spanning 3 distinct phishing emails sharing common Tor relay IP 185.220.101.45, AS9009, and typosquat domain infrastructure.',
    sender: 'Advisory Bulletin <security@portal-gov-advisory.online>',
    recipient: 'all-officials@gov-organization.in',
    subject: 'CRITICAL ALERT: Emergency Network Security Protocol Update',
    date: 'Fri, 05 Sep 2026 11:50:00 +0530 (IST)',
    replyTo: 'support@internal-corp-portal.online',
    returnPath: 'bounces@unverified-relay-mailer.top',
    originatingIP: '185.220.101.45',
    asn: 'AS9009',
    asnOrg: 'M247 Ltd Europe',
    country: 'Germany',
    countryCode: 'DE',
    networkType: 'Tor Exit / Shared Attack Infrastructure',
    spfResult: 'FAIL (IP 185.220.101.45 unauthorized)',
    dkimResult: 'FAIL (Signature mismatch)',
    dmarcResult: 'FAIL (Enforced quarantine)',
    replyToMismatch: true,
    returnPathMismatch: true,
    urls: [
      'http://internal-corp-portal.online/auth-portal/wire-release',
      'http://portal-gov-advisory.online/patch-installer'
    ],
    ips: [
      '185.220.101.45',
      '45.154.255.82',
      '194.26.29.110'
    ],
    attachments: [
      {
        filename: 'Security_Patch_Installer.exe',
        size: '512.0 KB',
        rawSizeBytes: 524288,
        flag: 'Direct Executable Payload / Suspicious PE Header',
        isSuspicious: true,
        md5: '9f8e7d6c5b4a3a2b1c0d9e8f7a6b5c4d',
        sha1: '4a3b2c1d0e9f8a7b6c5d4e3f2a1b0c9d8e7f6a5b',
        sha256: '7d1a293b6e8f4c102948a7b6c5d4e3f27d1a293b6e8f4c102948a7b6c5d4e3f2'
      }
    ],
    bodyText: `Urgent notice to all executive officers:
Install the mandatory security update to safeguard against zero-day vulnerabilities.
Software package attached. Execute immediately.`,
    rawSnippet: `Delivered-To: all-officials@gov-organization.in
Received: from mail-relay-fra.internal-corp-portal.online (185.220.101.45)
        by mail.gov-organization.in with ESMTP id t99881;
        Fri, 05 Sep 2026 11:50:00 +0530 (IST)
From: "Advisory Bulletin" <security@portal-gov-advisory.online>
Reply-To: <support@internal-corp-portal.online>
Return-Path: <bounces@unverified-relay-mailer.top>
Subject: CRITICAL ALERT: Emergency Network Security Protocol Update
Date: Fri, 05 Sep 2026 11:50:00 +0530`
  }
];

export function getScenarioById(id) {
  return SYNTHETIC_SCENARIOS.find(s => s.id === id) || SYNTHETIC_SCENARIOS[0];
}
