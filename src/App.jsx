import React, { useState } from 'react';
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
import { QuickScanModal } from './components/dashboard/QuickScanModal';
import './App.css';

function App() {
  const [currentView, setCurrentView] = useState('dashboard');
  const [isScanModalOpen, setIsScanModalOpen] = useState(false);
  const [inspectedEmail, setInspectedEmail] = useState(null);
  const [selectedCase, setSelectedCase] = useState(null);

  const handleStartAnalysis = (presetId) => {
    setIsScanModalOpen(false);
    setCurrentView('analysis-results');
  };

  const handleInspectEmail = (emailItem) => {
    setInspectedEmail(emailItem);
    setCurrentView('analysis-results');
  };

  const handleSelectCase = (caseItem) => {
    setSelectedCase(caseItem);
    setCurrentView('investigation-case');
  };

  const renderCurrentView = () => {
    switch (currentView) {
      case 'dashboard':
        return (
          <Dashboard
            onViewChange={setCurrentView}
            onOpenScan={() => setIsScanModalOpen(true)}
            onInspectEmail={handleInspectEmail}
            onSelectCase={handleSelectCase}
          />
        );
      case 'email-analysis':
        return (
          <EmailAnalysisPage
            onViewChange={setCurrentView}
            onInspectEmail={handleInspectEmail}
          />
        );
      case 'analysis-results':
        return (
          <AnalysisResultsPage
            onViewChange={setCurrentView}
            email={inspectedEmail}
          />
        );
      case 'ioc-intel':
        return (
          <IocIntelPage
            onViewChange={setCurrentView}
          />
        );
      case 'geo-asn':
        return (
          <GeoAsnPage
            onViewChange={setCurrentView}
          />
        );
      case 'threat-graph':
        return (
          <ThreatGraphPage
            onViewChange={setCurrentView}
          />
        );
      case 'investigation-case':
        return (
          <InvestigationCasePage
            onViewChange={setCurrentView}
            selectedCase={selectedCase}
          />
        );
      case 'forensic-report':
        return (
          <ForensicReportPage
            onViewChange={setCurrentView}
          />
        );
      default:
        return (
          <Dashboard
            onViewChange={setCurrentView}
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
        onViewChange={setCurrentView}
        onOpenScan={() => setIsScanModalOpen(true)}
      />

      {/* Main Workspace Layout */}
      <div className="flex-1 flex overflow-hidden">
        
        {/* Collapsible/Sticky Sidebar */}
        <Sidebar
          currentView={currentView}
          onViewChange={setCurrentView}
        />

        {/* Dynamic Page Content Viewport */}
        <main className="flex-1 overflow-y-auto p-4 sm:p-6 lg:p-8 bg-gradient-to-b from-[#070b13] via-[#080d19] to-[#060a12]">
          <div className="max-w-[1600px] mx-auto">
            {renderCurrentView()}
          </div>
        </main>
      </div>

      {/* Quick Email Threat Scanner Modal */}
      <QuickScanModal
        isOpen={isScanModalOpen}
        onClose={() => setIsScanModalOpen(false)}
        onStartAnalysis={handleStartAnalysis}
      />

    </div>
  );
}

export default App;

