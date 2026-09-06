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
import { parseEmailContent } from './services/emailParser';
import { extractAllIOCs } from './services/iocExtractor';
import { evaluateAIThreat } from './services/aiThreatModel';
import { resolveIPGeo } from './services/geoAsnService';
import { calculateEvidenceFusion, DEFAULT_FUSION_WEIGHTS } from './services/evidenceFusion';
import { correlateThreatCampaigns } from './services/campaignCorrelator';
import { getStoredCases, createCaseFromAnalysis } from './services/caseStore';
import { SYNTHETIC_SCENARIOS } from './data/syntheticScenarios';

import './App.css';

// Route path to internal view identifier mapping
const PATH_TO_VIEW = {
  '/maverick/': 'dashboard',
  '/maverick': 'dashboard',
  '/maverick/dashboard': 'dashboard',
  '/maverick/email-analysis': 'email-analysis',
  '/maverick/analysis-results': 'analysis-results',
  '/maverick/ioc-intel': 'ioc-intel',
  '/maverick/threat-graph': 'threat-graph',
  '/maverick/geo-asn': 'geo-asn',
  '/maverick/cases': 'investigation-case',
  '/maverick/investigation-case': 'investigation-case',
  '/maverick/reports': 'forensic-report',
  '/maverick/forensic-report': 'forensic-report',
  '/maverick/settings': 'settings'
};

const VIEW_TO_PATH = {
  'dashboard': '/maverick/dashboard',
  'email-analysis': '/maverick/email-analysis',
  'analysis-results': '/maverick/analysis-results',
  'ioc-intel': '/maverick/ioc-intel',
  'threat-graph': '/maverick/threat-graph',
  'geo-asn': '/maverick/geo-asn',
  'investigation-case': '/maverick/cases',
  'forensic-report': '/maverick/reports',
  'settings': '/maverick/settings'
};

function getInitialView(user) {
  const path = window.location.pathname.replace(/\/$/, '') || '/maverick';
  if (!user) {
    // Unauthenticated: if user tries to directly access any internal route, redirect to /maverick/
    if (path !== '/maverick') {
      window.history.replaceState(null, '', '/maverick/');
    }
    return 'dashboard';
  }

  // Authenticated: if user is at root /maverick, redirect to /maverick/dashboard
  if (path === '/maverick') {
    window.history.replaceState(null, '', '/maverick/dashboard');
    return 'dashboard';
  }

  return PATH_TO_VIEW[path] || PATH_TO_VIEW[path + '/'] || 'dashboard';
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
        window.history.replaceState(null, '', '/maverick/');
      } else {
        setCurrentUser(activeUser);
        const path = window.location.pathname.replace(/\/$/, '') || '/maverick';
        if (path === '/maverick') {
          window.history.replaceState(null, '', '/maverick/dashboard');
          setCurrentView('dashboard');
        } else {
          setCurrentView(PATH_TO_VIEW[path] || 'dashboard');
        }
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
      window.history.replaceState(null, '', '/maverick/');
      return;
    }

    setCurrentView(viewId);
    const targetPath = VIEW_TO_PATH[viewId] || '/maverick/dashboard';
    window.history.pushState(null, '', targetPath);
  }, []);

  // Authentication callback: called on successful Google OAuth
  const handleLoginSuccess = (user) => {
    setCurrentUser(user);
    setCurrentView('dashboard');
    window.history.pushState(null, '', '/maverick/dashboard');
  };

  // Sign out callback: clears session and returns to login screen
  const handleLogout = () => {
    logout();
    setCurrentUser(null);
    setCurrentView('dashboard');
    window.history.replaceState(null, '', '/maverick/');
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

      // 2. AI Threat Analysis
      const aiThreat = evaluateAIThreat(parsedEmail);

      // 3. GeoLocation & ASN Intelligence
      const geoInfo = await resolveIPGeo(parsedEmail.originatingIP || '185.220.101.45');

      // 4. Multi-Factor Evidence Fusion
      const fusion = calculateEvidenceFusion({
        parsedEmail,
        aiThreat,
        iocs,
        geoInfo,
        weights: fusionWeights
      });

      // 5. Threat Campaign Correlation
      const campaigns = correlateThreatCampaigns([parsedEmail]);
      const primaryCampaign = campaigns[0] || null;

      // 6. Case Creation / Linkage
      const caseItem = createCaseFromAnalysis({
        email: parsedEmail,
        fusion,
        aiThreat,
        iocs,
        campaign: primaryCampaign
      });

      const analysisResult = {
        email: parsedEmail,
        iocs,
        aiThreat,
        geoInfo,
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
