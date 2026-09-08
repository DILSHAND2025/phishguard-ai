import React, { useState, useEffect, useCallback } from 'react';
import { Navbar } from './components/layout/Navbar';
import { Sidebar } from './components/layout/Sidebar';
import { Dashboard } from './pages/Dashboard';
import { EmailAnalysisPage } from './pages/EmailAnalysisPage';
import { AnalysisResultsPage } from './pages/AnalysisResultsPage';
import { IocIntelPage } from './pages/IocIntelPage';
import { GeoAsnPage } from './pages/GeoAsnPage';
import { ThreatGraphPage } from './pages/ThreatGraphPage';
import { InvestigationCasePage } from './pages/InvestigationCasePage';
import { ForensicReportPage } from './pages/ForensicReportPage';
import { SettingsPage } from './pages/SettingsPage';
import { LoginPage } from './pages/LoginPage';
import { QuickScanModal } from './components/dashboard/QuickScanModal';

// Authentication & Session Guard
import { getCurrentUser, logout } from './services/authService';

// Core Forensic & Intelligence Services
import { parseEmailContent, extractNetworkIndicators } from './services/emailParser';
import { extractAllIOCs } from './services/iocExtractor';
import { evaluateAIThreat } from './services/aiThreatModel';
import { resolveIPGeo } from './services/geoAsnService';
import { defaultGeoService } from './services/geoLocationService';
import { calculateEvidenceFusion, DEFAULT_FUSION_WEIGHTS } from './services/evidenceFusion';
import { correlateThreatCampaigns } from './services/campaignCorrelator';
import { createCaseFromAnalysis } from './services/caseStore';
import { analyzeAttachment } from './services/attachmentForensics';
import { analyzeEmailAuthentication } from './services/emailAuthService';
import { defaultHashReputationService } from './services/hashReputationService';
import { SYNTHETIC_SCENARIOS } from './data/syntheticScenarios';

import './App.css';

// Dynamic Base Detection for Vercel (root '/'), GitHub Pages ('/maverick/'), or custom domains
const RAW_BASE = import.meta.env.BASE_URL || '/';
const BASE_PREFIX = RAW_BASE.replace(/\/$/, ''); // '' for root domain (Vercel), '/maverick' for subpath

// Canonical mapping of views to relative sub-paths
const VIEW_TO_REL_PATH = {
  'dashboard': '/dashboard',
  'email-analysis': '/email-analysis',
  'analysis-results': '/analysis-results',
  'ioc-intel': '/ioc-intel',
  'threat-graph': '/threat-graph',
  'geo-asn': '/geo-asn',
  'investigation-case': '/cases',
  'forensic-report': '/reports',
  'settings': '/settings'
};

const REL_PATH_TO_VIEW = {
  '': 'dashboard',
  '/': 'dashboard',
  '/dashboard': 'dashboard',
  '/email-analysis': 'email-analysis',
  '/analysis-results': 'analysis-results',
  '/ioc-intel': 'ioc-intel',
  '/threat-graph': 'threat-graph',
  '/geo-asn': 'geo-asn',
  '/cases': 'investigation-case',
  '/investigation-case': 'investigation-case',
  '/reports': 'forensic-report',
  '/forensic-report': 'forensic-report',
  '/settings': 'settings'
};

function getUrlForView(viewId) {
  const rel = VIEW_TO_REL_PATH[viewId] || '/dashboard';
  return `${BASE_PREFIX}${rel}`;
}

function getRootUrl() {
  return BASE_PREFIX ? `${BASE_PREFIX}/` : '/';
}

function getViewFromCurrentLocation() {
  let pathname = window.location.pathname.replace(/\/$/, '');

  // Strip BASE_PREFIX if configured and present
  if (BASE_PREFIX && pathname.startsWith(BASE_PREFIX)) {
    pathname = pathname.slice(BASE_PREFIX.length);
  }

  // Tolerate '/maverick' prefix even if deployed to root (e.g. legacy bookmark or redirect)
  if (pathname.startsWith('/maverick')) {
    pathname = pathname.slice('/maverick'.length);
  }

  if (!pathname || pathname === '') pathname = '/';
  return REL_PATH_TO_VIEW[pathname] || 'dashboard';
}

function getInitialView(user) {
  const targetView = getViewFromCurrentLocation();
  const root = getRootUrl();
  const currentClean = window.location.pathname.replace(/\/$/, '') || '/';
  const rootClean = root.replace(/\/$/, '') || '/';

  if (!user) {
    // Unauthenticated: if user tries to directly access any internal route, redirect to root
    if (currentClean !== rootClean) {
      window.history.replaceState(null, '', root);
    }
    return 'dashboard';
  }

  // Authenticated: if user is at root, redirect to dashboard URL
  if (currentClean === rootClean) {
    window.history.replaceState(null, '', getUrlForView('dashboard'));
    return 'dashboard';
  }

  return targetView;
}

function App() {
  const [currentUser, setCurrentUser] = useState(() => getCurrentUser());
  const [currentView, setCurrentView] = useState(() => getInitialView(currentUser));
  const [isScanModalOpen, setIsScanModalOpen] = useState(false);
  const [selectedCase, setSelectedCase] = useState(null);
  const [currentAnalysis, setCurrentAnalysis] = useState(null);
  const [fusionWeights, setFusionWeights] = useState(() => {
    try {
      const saved = localStorage.getItem('maverick_weights');
      if (saved) return JSON.parse(saved);
    } catch {
      // ignore
    }
    return DEFAULT_FUSION_WEIGHTS;
  });

  // Handle browser URL history back/forward navigation
  useEffect(() => {
    const handlePopState = () => {
      const activeUser = getCurrentUser();
      if (!activeUser) {
        setCurrentUser(null);
        window.history.replaceState(null, '', getRootUrl());
      } else {
        setCurrentUser(activeUser);
        const view = getViewFromCurrentLocation();
        setCurrentView(view);
      }
    };

    window.addEventListener('popstate', handlePopState);
    return () => window.removeEventListener('popstate', handlePopState);
  }, []);

  // Protected route navigation dispatcher
  const handleViewChange = useCallback((viewId) => {
    const activeUser = getCurrentUser();
    if (!activeUser) {
      setCurrentUser(null);
      window.history.replaceState(null, '', getRootUrl());
      return;
    }

    setCurrentView(viewId);
    window.history.pushState(null, '', getUrlForView(viewId));
  }, []);

  // Authentication callback: called on successful Google OAuth
  const handleLoginSuccess = (user) => {
    setCurrentUser(user);
    setCurrentView('dashboard');
    window.history.pushState(null, '', getUrlForView('dashboard'));
  };

  // Sign out callback: clears session and returns to login screen
  const handleLogout = () => {
    logout();
    setCurrentUser(null);
    setCurrentView('dashboard');
    window.history.replaceState(null, '', getRootUrl());
  };

  // Master end-to-end forensic analysis pipeline
  const runFullAnalysis = useCallback(async (emailInput) => {
    try {
      let parsedEmail = emailInput;

      // If raw string was passed
      if (typeof emailInput === 'string') {
        parsedEmail = await parseEmailContent(emailInput);
      } else if (emailInput && !emailInput.fromParsed) {
        // If scenario or partial object was passed with rawSnippet
        if (emailInput.rawSnippet) {
          parsedEmail = await parseEmailContent(emailInput.rawSnippet);
          if (emailInput.name) parsedEmail.scenarioName = emailInput.name;
          if (emailInput.category) parsedEmail.category = emailInput.category;
          if (emailInput.tag) parsedEmail.tag = emailInput.tag;
          if (emailInput.urls) parsedEmail.urls = emailInput.urls;
          if (emailInput.ips) parsedEmail.ips = emailInput.ips;
          if (emailInput.attachments) parsedEmail.attachments = emailInput.attachments;
        } else {
          // Normalize generic feed item
          parsedEmail = {
            sender: emailInput.sender || emailInput.displaySender || 'Unknown Sender',
            recipient: emailInput.recipient || 'target@gov-organization.in',
            subject: emailInput.subject || 'Suspicious Email Ingress',
            date: emailInput.timestamp || new Date().toLocaleString(),
            originatingIP: emailInput.ipOrigin ? emailInput.ipOrigin.split(' ')[0] : '185.220.101.45',
            rawSnippet: `From: ${emailInput.sender}\nTo: ${emailInput.recipient}\nSubject: ${emailInput.subject}\nIP: ${emailInput.ipOrigin}`,
            urls: ['http://internal-corp-portal.online/auth-portal/wire-release'],
            ips: [emailInput.ipOrigin ? emailInput.ipOrigin.split(' ')[0] : '185.220.101.45'],
            attachments: [
              {
                filename: 'Wire_Remittance_Directive.pdf.exe',
                size: '242.6 KB',
                flag: 'Double Extension / Obfuscated PE32 Executable',
                isSuspicious: true,
                sha256: '8f4c102948a7b6c5d4e3f27d1a293b6e8f4c102948a7b6c5d4e3f27d1a293b6e'
              }
            ],
            auth: {
              spf: { result: emailInput.spf || 'SOFTFAIL' },
              dkim: { result: emailInput.dkim || 'FAIL' },
              dmarc: { result: emailInput.dmarc || 'FAIL' }
            }
          };
        }
      }

      // 1. Automated IOC Extraction
      const iocs = extractAllIOCs(parsedEmail);

      // 2. Real AI/ML Threat Analysis (TF-IDF + Logistic Regression)
      const aiThreat = await evaluateAIThreat(parsedEmail);

      // 3. Static Attachment Forensics & Hash Threat Reputation
      if (parsedEmail.attachments && parsedEmail.attachments.length > 0) {
        parsedEmail.attachments = await Promise.all(
          parsedEmail.attachments.map(async (att, idx) => {
            let record = att;
            if (!att.observed) {
              record = await analyzeAttachment({
                filename: att.filename,
                content: att.content || null,
                mimeType: att.mimeType || 'application/octet-stream',
                index: idx,
                knownHashes: { sha256: att.sha256, sha1: att.sha1, md5: att.md5 }
              });
            }
            if (record.sha256 && !record.reputation) {
              record.reputation = await defaultHashReputationService.checkHash(record.sha256);
            }
            return record;
          })
        );
      }

      // 4. Network Indicators & Multi-IP GeoLocation
      const networkIndicators = extractNetworkIndicators(parsedEmail);
      const geoList = await defaultGeoService.resolveAllIPs(networkIndicators);
      const geoInfo = geoList.find(g => g.role === 'SOURCE' && !g.isPrivate) || 
                      geoList.find(g => !g.isPrivate && g.status === 'SUCCESS') || 
                      geoList[0] || 
                      await resolveIPGeo(parsedEmail.originatingIP || '185.220.101.45');

      // 5. Live Email Authentication & DNS Forensics
      let emailAuth = null;
      const rawSnippetText = parsedEmail.rawSnippet || (typeof emailInput === 'string' ? emailInput : '');
      if (rawSnippetText) {
        const authEndpoints = [
          '/api/email-authentication',
          'http://localhost:5000/api/email-authentication',
          'http://127.0.0.1:5000/api/email-authentication'
        ];

        for (const endpoint of authEndpoints) {
          try {
            const res = await fetch(endpoint, {
              method: 'POST',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify({ email: rawSnippetText }),
              signal: AbortSignal.timeout(2500)
            });
            if (res.ok) {
              emailAuth = await res.json();
              if (emailAuth) break;
            }
          } catch {
            // Try next endpoint fallback
          }
        }
        if (!emailAuth) {
          emailAuth = await analyzeEmailAuthentication(rawSnippetText);
        }
      }
      parsedEmail.emailAuth = emailAuth;

      // 6. Multi-Factor Evidence Fusion
      const fusion = calculateEvidenceFusion({
        parsedEmail,
        aiThreat,
        iocs,
        geoInfo,
        geoList,
        emailAuth,
        weights: fusionWeights
      });

      // 7. Threat Campaign Correlation
      const campaigns = correlateThreatCampaigns([parsedEmail]);
      const primaryCampaign = campaigns[0] || null;

      // 8. Case Creation / Linkage
      const caseItem = createCaseFromAnalysis({
        email: parsedEmail,
        fusion,
        aiThreat,
        iocs,
        campaign: primaryCampaign
      });

      const analysisResult = {
        email: parsedEmail,
        emailAuth,
        iocs,
        aiThreat,
        geoInfo,
        geoList,
        networkIndicators,
        fusion,
        campaign: primaryCampaign,
        caseItem
      };

      setCurrentAnalysis(analysisResult);
      setSelectedCase(caseItem);
      return analysisResult;
    } catch (err) {
      console.error('Error running forensic analysis pipeline:', err);
      return null;
    }
  }, [fusionWeights]);

  // Run initial baseline analysis on mount with first scenario
  useEffect(() => {
    if (currentUser) {
      runFullAnalysis(SYNTHETIC_SCENARIOS[0]);
    }
  }, [currentUser, runFullAnalysis]);

  const handleStartQuickScan = async (presetOrRaw) => {
    setIsScanModalOpen(false);
    await runFullAnalysis(presetOrRaw);
    handleViewChange('analysis-results');
  };

  const handleInspectEmail = async (emailItem) => {
    await runFullAnalysis(emailItem);
    handleViewChange('analysis-results');
  };

  const handleSelectCase = (caseItem) => {
    setSelectedCase(caseItem);
    handleViewChange('investigation-case');
  };

  const handleUpdateWeights = (newWeights) => {
    setFusionWeights(newWeights);
    // Re-evaluate current analysis with new weights if exists
    if (currentAnalysis?.email) {
      const updatedFusion = calculateEvidenceFusion({
        parsedEmail: currentAnalysis.email,
        aiThreat: currentAnalysis.aiThreat,
        iocs: currentAnalysis.iocs,
        geoInfo: currentAnalysis.geoInfo,
        geoList: currentAnalysis.geoList,
        emailAuth: currentAnalysis.emailAuth,
        weights: newWeights
      });
      setCurrentAnalysis(prev => ({ ...prev, fusion: updatedFusion }));
    }
  };

  // ROUTE GUARD: If user is not authenticated, render Login Page as the FIRST screen
  if (!currentUser) {
    return <LoginPage onLoginSuccess={handleLoginSuccess} />;
  }

  const renderCurrentView = () => {
    switch (currentView) {
      case 'dashboard':
        return (
          <Dashboard
            onViewChange={handleViewChange}
            onOpenScan={() => setIsScanModalOpen(true)}
            onInspectEmail={handleInspectEmail}
            onSelectCase={handleSelectCase}
          />
        );
      case 'email-analysis':
        return (
          <EmailAnalysisPage
            onViewChange={handleViewChange}
            currentAnalysis={currentAnalysis}
            onRunAnalysis={runFullAnalysis}
          />
        );
      case 'analysis-results':
        return (
          <AnalysisResultsPage
            onViewChange={handleViewChange}
            currentAnalysis={currentAnalysis}
          />
        );
      case 'ioc-intel':
        return (
          <IocIntelPage
            onViewChange={handleViewChange}
            currentAnalysis={currentAnalysis}
          />
        );
      case 'geo-asn':
        return (
          <GeoAsnPage
            onViewChange={handleViewChange}
            currentAnalysis={currentAnalysis}
          />
        );
      case 'threat-graph':
        return (
          <ThreatGraphPage
            onViewChange={handleViewChange}
            currentAnalysis={currentAnalysis}
          />
        );
      case 'investigation-case':
        return (
          <InvestigationCasePage
            onViewChange={handleViewChange}
            selectedCase={selectedCase}
            currentAnalysis={currentAnalysis}
          />
        );
      case 'forensic-report':
        return (
          <ForensicReportPage
            onViewChange={handleViewChange}
            currentAnalysis={currentAnalysis}
          />
        );
      case 'settings':
        return (
          <SettingsPage
            fusionWeights={fusionWeights}
            onUpdateWeights={handleUpdateWeights}
          />
        );
      default:
        return (
          <Dashboard
            onViewChange={handleViewChange}
            onOpenScan={() => setIsScanModalOpen(true)}
            onInspectEmail={handleInspectEmail}
            onSelectCase={handleSelectCase}
            currentAnalysis={currentAnalysis}
          />
        );
    }
  };

  return (
    <div className="min-h-screen bg-[#070b13] text-slate-100 flex flex-col selection:bg-cyan-500/30 selection:text-cyan-200">
      
      {/* Top Navbar */}
      <Navbar
        currentView={currentView}
        onViewChange={handleViewChange}
        onOpenScan={() => setIsScanModalOpen(true)}
        currentUser={currentUser}
        onLogout={handleLogout}
      />

      {/* Main Workspace Layout */}
      <div className="flex-1 flex overflow-hidden">
        
        {/* Collapsible/Sticky Sidebar */}
        <Sidebar
          currentView={currentView}
          onViewChange={handleViewChange}
          currentUser={currentUser}
          onLogout={handleLogout}
        />

        {/* Dynamic Page Content Viewport */}
        <main className="flex-1 overflow-y-auto p-4 sm:p-6 lg:p-8 bg-gradient-to-b from-[#070b13] via-[#080d19] to-[#060a14]">
          <div className="max-w-[1600px] mx-auto">
            {renderCurrentView()}
          </div>
        </main>
      </div>

      {/* Quick Email Threat Scanner Modal */}
      <QuickScanModal
        isOpen={isScanModalOpen}
        onClose={() => setIsScanModalOpen(false)}
        onStartAnalysis={handleStartQuickScan}
      />

    </div>
  );
}

export default App;
