import React, { useState, useEffect, useCallback } from 'react';
import { 
  Briefcase, 
  Search, 
  RefreshCw, 
  ChevronRight, 
  Archive, 
  RotateCcw, 
  AlertTriangle, 
  Inbox,
  Shield,
  Copy,
  Check,
  X,
  MessageSquare,
  User,
  ArrowRight
} from 'lucide-react';
import { 
  fetchCases, 
  archiveCase, 
  addCaseNote,
  updateCaseStatus,
  getThreatPriority, 
  getPriorityStyle 
} from '../services/caseStore.js';

export const InvestigationCasePage = ({ 
  onViewChange, 
  onOpenCase, 
  _currentAnalysis,
  dbError
}) => {
  const [cases, setCases] = useState([]);
  const [totalCases, setTotalCases] = useState(0);
  const [loading, setLoading] = useState(true);
  const [selectedPriority, setSelectedPriority] = useState('All');
  const [statusFilter, setStatusFilter] = useState('all'); // 'all' | 'active' | 'investigating' | 'closed' | 'archived'
  const [searchQuery, setSearchQuery] = useState('');
  const [currentPage, setCurrentPage] = useState(1);
  const [totalPages, setTotalPages] = useState(1);
  const [isDbUnavailable, setIsDbUnavailable] = useState(false);
  const [errorMessage, setErrorMessage] = useState(null);

  // Inspection Drawer State
  const [selectedCase, setSelectedCase] = useState(null);
  const [copiedHash, setCopiedHash] = useState(false);
  const [newNoteText, setNewNoteText] = useState('');
  const [isAddingNote, setIsAddingNote] = useState(false);
  const [isUpdatingStatus, setIsUpdatingStatus] = useState(false);

  // Load cases from PostgreSQL backend
  const loadCases = useCallback(async () => {
    setLoading(true);
    setErrorMessage(null);

    const result = await fetchCases({
      priority: selectedPriority === 'All' ? undefined : selectedPriority,
      status: statusFilter === 'all' ? undefined : statusFilter,
      page: currentPage,
      limit: 20,
      search: searchQuery
    });

    setCases(result.cases || []);
    setTotalCases(result.total || 0);
    setTotalPages(result.totalPages || 1);
    setIsDbUnavailable(Boolean(result.isDbUnavailable));

    if (result.isDbUnavailable && result.error) {
      setErrorMessage(result.error);
    }

    setLoading(false);
  }, [selectedPriority, statusFilter, currentPage, searchQuery]);

  useEffect(() => {
    loadCases();
  }, [loadCases]);

  // Handle Archive / Reopen toggle
  const handleToggleArchive = async (e, caseItem) => {
    e.stopPropagation();
    const newStatus = caseItem.status === 'archived' ? 'active' : 'archived';
    const res = await archiveCase(caseItem.caseId, newStatus, {
      actor: 'Analyst (SOC Lead)',
      note: `Case status changed to ${newStatus}`
    });
    if (res.success) {
      loadCases();
      if (selectedCase && selectedCase.caseId === caseItem.caseId) {
        setSelectedCase(prev => ({ ...prev, status: newStatus }));
      }
    } else {
      alert(`Failed to update case status: ${res.error || 'Unknown error'}`);
    }
  };

  // Handle Status change from Drawer
  const handleChangeStatus = async (newStatus) => {
    if (!selectedCase || selectedCase.status === newStatus) return;
    setIsUpdatingStatus(true);
    const res = await updateCaseStatus(selectedCase.caseId, newStatus, {
      actor: 'Analyst (SOC Lead)',
      note: `Analyst updated case workflow status to ${newStatus}`
    });
    setIsUpdatingStatus(false);
    if (res.success) {
      setSelectedCase(res.case || { ...selectedCase, status: newStatus });
      loadCases();
    } else {
      alert(`Failed to update status: ${res.error || 'Unknown error'}`);
    }
  };

  // Handle Note Submission
  const handleAddNote = async (e) => {
    e.preventDefault();
    if (!newNoteText.trim() || !selectedCase) return;
    setIsAddingNote(true);
    const res = await addCaseNote(selectedCase.caseId, newNoteText.trim(), 'Analyst (SOC Lead)');
    setIsAddingNote(false);
    if (res.success) {
      setNewNoteText('');
      // Update drawer case item with updated timeline
      if (res.case) {
        setSelectedCase(res.case);
      } else {
        const updatedTimeline = [
          ...(selectedCase.timeline || []),
          {
            timestamp: new Date().toISOString(),
            action: 'NOTE_ADDED',
            actor: 'Analyst (SOC Lead)',
            note: newNoteText.trim()
          }
        ];
        setSelectedCase({ ...selectedCase, timeline: updatedTimeline });
      }
      loadCases();
    } else {
      alert(`Failed to record note: ${res.error || 'Unknown error'}`);
    }
  };

  // Open case investigation without re-analyzing
  const handleCaseClick = (caseItem) => {
    setSelectedCase(caseItem);
  };

  const handleOpenFullAnalyzer = () => {
    if (!selectedCase) return;
    if (onOpenCase) {
      onOpenCase(selectedCase);
    } else if (onViewChange) {
      onViewChange('security-analyzer');
    }
  };

  const priorityTabs = [
    { id: 'All', label: 'All' },
    { id: 'Critical', label: 'Critical' },
    { id: 'High', label: 'High' },
    { id: 'Medium', label: 'Medium' },
    { id: 'Low', label: 'Low' }
  ];

  const statusTabs = [
    { id: 'all', label: 'All Cases' },
    { id: 'active', label: 'Active' },
    { id: 'investigating', label: 'Investigating' },
    { id: 'closed', label: 'Closed' },
    { id: 'archived', label: 'Archived' }
  ];

  return (
    <div className="space-y-6 pb-16 font-sans">
      
      {/* Page Header — Clean White Card */}
      <div className="rounded-2xl bg-white border border-slate-200 p-6 sm:p-7 shadow-2xs">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
          <div>
            <div className="flex items-center gap-2 text-cyan-700 text-xs font-mono mb-1.5 uppercase tracking-wider font-semibold">
              <span className="w-2 h-2 rounded-full bg-cyan-600"></span>
              MAVERICK • SOC INCIDENT MANAGEMENT
            </div>
            <div className="flex items-center gap-3">
              <h1 className="text-2xl font-bold tracking-tight text-slate-900 flex items-center gap-2.5">
                <Briefcase className="w-6 h-6 text-cyan-600" />
                <span>Cases</span>
              </h1>
              <span className="px-2.5 py-0.5 rounded-full text-xs font-mono font-bold bg-slate-100 text-slate-700 border border-slate-200">
                {totalCases} Cases
              </span>
            </div>
            <p className="text-xs text-slate-600 mt-1 max-w-2xl">
              Track, prioritize, and investigate email threats. Preserves raw evidence digests and records investigator audit trails.
            </p>
          </div>

          <div className="flex items-center gap-2.5">
            {/* Status Tabs Toggle */}
            <div className="flex items-center bg-slate-100 rounded-xl p-1 border border-slate-200 text-xs font-medium overflow-x-auto">
              {statusTabs.map(tab => (
                <button
                  key={tab.id}
                  onClick={() => { setStatusFilter(tab.id); setCurrentPage(1); }}
                  className={`px-3 py-1.5 rounded-lg transition-colors cursor-pointer whitespace-nowrap ${
                    statusFilter === tab.id
                      ? 'bg-white text-slate-900 shadow-2xs font-semibold'
                      : 'text-slate-600 hover:text-slate-900'
                  }`}
                >
                  {tab.label}
                </button>
              ))}
            </div>

            <button
              onClick={loadCases}
              disabled={loading}
              className="p-2.5 rounded-xl bg-white hover:bg-slate-50 border border-slate-200 text-slate-600 hover:text-slate-900 transition-all cursor-pointer shadow-2xs shrink-0"
              title="Refresh Cases"
            >
              <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin text-cyan-600' : ''}`} />
            </button>
          </div>
        </div>
      </div>

      {/* Database Availability Notice */}
      {(isDbUnavailable || dbError) && (
        <div className="rounded-xl bg-amber-50 border border-amber-200 p-4 text-xs text-amber-800 flex items-start gap-3 shadow-2xs">
          <AlertTriangle className="w-5 h-5 text-amber-600 shrink-0 mt-0.5" />
          <div className="space-y-1">
            <div className="font-semibold text-amber-900">Database Connection Notice</div>
            <p className="text-amber-800 leading-relaxed">
              {errorMessage || dbError || 'PostgreSQL database connection is unconfigured or offline. Set DATABASE_URL in your .env configuration to enable persistent storage.'}
            </p>
          </div>
        </div>
      )}

      {/* Filter and Search Bar */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
        
        {/* Search input */}
        <div className="relative flex-1 max-w-md">
          <Search className="w-4 h-4 absolute left-3.5 top-1/2 -translate-y-1/2 text-slate-400" />
          <input
            type="text"
            value={searchQuery}
            onChange={(e) => { setSearchQuery(e.target.value); setCurrentPage(1); }}
            placeholder="Search cases..."
            className="w-full pl-10 pr-4 py-2 rounded-xl bg-white border border-slate-200 text-slate-900 placeholder-slate-400 text-xs focus:outline-none focus:border-cyan-500 transition-colors shadow-2xs font-sans"
          />
        </div>

        {/* Priority Filter Pills */}
        <div className="flex items-center gap-1.5 flex-wrap">
          {priorityTabs.map((tab) => {
            const isSelected = selectedPriority === tab.id;
            return (
              <button
                key={tab.id}
                onClick={() => { setSelectedPriority(tab.id); setCurrentPage(1); }}
                className={`px-3 py-1.5 rounded-xl text-xs font-medium font-mono transition-all cursor-pointer ${
                  isSelected
                    ? tab.id === 'Critical'
                      ? 'bg-red-50 text-red-700 border border-red-300 font-bold shadow-2xs'
                      : tab.id === 'High'
                        ? 'bg-orange-50 text-orange-700 border border-orange-300 font-bold shadow-2xs'
                        : tab.id === 'Medium'
                          ? 'bg-amber-50 text-amber-700 border border-amber-300 font-bold shadow-2xs'
                          : tab.id === 'Low'
                            ? 'bg-emerald-50 text-emerald-700 border border-emerald-300 font-bold shadow-2xs'
                            : 'bg-cyan-50 text-cyan-800 border border-cyan-300 font-bold shadow-2xs'
                    : 'bg-white text-slate-600 hover:text-slate-900 hover:bg-slate-50 border border-slate-200'
                }`}
              >
                [{tab.label}]
              </button>
            );
          })}
        </div>
      </div>

      {/* Case Queue Table — Clean White Card */}
      <div className="rounded-2xl bg-white border border-slate-200 overflow-hidden shadow-2xs">
        
        {loading && cases.length === 0 ? (
          <div className="py-20 text-center space-y-3">
            <RefreshCw className="w-7 h-7 text-cyan-600 animate-spin mx-auto" />
            <p className="text-xs text-slate-500 font-mono">Loading cases from PostgreSQL database...</p>
          </div>
        ) : cases.length === 0 ? (
          <div className="py-20 text-center max-w-md mx-auto space-y-3">
            <Inbox className="w-10 h-10 text-slate-400 mx-auto" />
            <h3 className="text-sm font-semibold text-slate-800">No cases found in queue</h3>
            <p className="text-xs text-slate-500 leading-relaxed">
              {searchQuery || selectedPriority !== 'All' 
                ? 'No cases match your active filters. Try clearing the search or priority filter.'
                : 'Scanned emails will appear here prioritized by risk score once ingested.'}
            </p>
            <button
              onClick={() => onViewChange('email-analysis')}
              className="mt-2 px-4 py-2 rounded-xl bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-semibold cursor-pointer shadow-xs"
            >
              Ingest & Scan Email
            </button>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left font-mono text-xs border-collapse">
              <thead>
                <tr className="border-b border-slate-200 text-[11px] text-slate-500 uppercase tracking-wider bg-slate-50/80 font-semibold">
                  <th className="py-3 px-4 w-28">Priority</th>
                  <th className="py-3 px-3 text-center w-24">Score</th>
                  <th className="py-3 px-4 w-44">Case ID</th>
                  <th className="py-3 px-4 font-sans">Subject</th>
                  <th className="py-3 px-4">Sender</th>
                  <th className="py-3 px-4 w-36">Classification</th>
                  <th className="py-3 px-4 w-36">Date</th>
                  <th className="py-3 px-4 text-right w-24">Action</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100 font-sans">
                {cases.map((c) => {
                  const score = typeof c.threatScore === 'number' ? c.threatScore : 0;
                  const priority = c.priority || getThreatPriority(score);
                  const style = getPriorityStyle(priority);

                  const isCrit = priority.toLowerCase() === 'critical';
                  const isHigh = priority.toLowerCase() === 'high';
                  const isMed = priority.toLowerCase() === 'medium';

                  const dotColor = isCrit ? '🔴' : isHigh ? '🟠' : isMed ? '🟡' : '🟢';

                  return (
                    <tr
                      key={c.caseId || c.id}
                      onClick={() => handleCaseClick(c)}
                      className={`hover:bg-slate-50/80 transition-colors cursor-pointer group ${
                        isCrit ? 'bg-red-50/20' : ''
                      }`}
                    >
                      {/* Priority */}
                      <td className="py-3.5 px-4 whitespace-nowrap font-mono">
                        <span className="mr-1.5">{dotColor}</span>
                        <span className={`text-[10px] px-2 py-0.5 rounded uppercase border font-semibold ${style.badge}`}>
                          {priority}
                        </span>
                      </td>

                      {/* Threat Score (Highest risk visually prominent) */}
                      <td className="py-3.5 px-3 text-center font-mono font-bold">
                        <span className={`inline-flex items-center justify-center px-2 py-0.5 rounded text-xs border font-extrabold ${style.pill}`}>
                          {score}
                        </span>
                      </td>

                      {/* Case ID */}
                      <td className="py-3.5 px-4 font-mono font-bold text-cyan-700 group-hover:text-cyan-800 transition-colors whitespace-nowrap">
                        {c.caseId}
                      </td>

                      {/* Subject */}
                      <td className="py-3.5 px-4 max-w-sm">
                        <div className="font-semibold text-slate-900 group-hover:text-cyan-700 transition-colors truncate">
                          {c.subject || '(No Subject)'}
                        </div>
                        {c.riskSummary && (
                          <div className="text-[11px] text-slate-500 truncate mt-0.5 font-sans">
                            {c.riskSummary}
                          </div>
                        )}
                      </td>

                      {/* Sender */}
                      <td className="py-3.5 px-4 text-slate-600 max-w-xs truncate text-xs">
                        {c.sender}
                      </td>

                      {/* Classification */}
                      <td className="py-3.5 px-4 whitespace-nowrap font-mono text-xs">
                        <span className={`px-2 py-0.5 rounded text-[11px] font-medium border ${
                          (c.classification || '').toLowerCase() === 'phishing'
                            ? 'bg-red-50 text-red-700 border-red-200'
                            : (c.classification || '').toLowerCase() === 'suspicious'
                              ? 'bg-amber-50 text-amber-700 border-amber-200'
                              : 'bg-emerald-50 text-emerald-700 border-emerald-200'
                        }`}>
                          {c.classification || 'Phishing'}
                        </span>
                      </td>

                      {/* Date */}
                      <td className="py-3.5 px-4 text-slate-500 text-xs whitespace-nowrap font-mono">
                        {c.analyzedAt ? new Date(c.analyzedAt).toLocaleDateString('en-US', {
                          month: 'short',
                          day: 'numeric',
                          hour: '2-digit',
                          minute: '2-digit'
                        }) : (c.createdAt ? new Date(c.createdAt).toLocaleDateString() : 'N/A')}
                      </td>

                      {/* Action */}
                      <td className="py-3.5 px-4 text-right whitespace-nowrap font-mono">
                        <div className="flex items-center justify-end gap-1.5" onClick={(e) => e.stopPropagation()}>
                          <button
                            onClick={(e) => handleToggleArchive(e, c)}
                            className="p-1 rounded-md text-slate-400 hover:text-slate-700 hover:bg-slate-100 transition-colors cursor-pointer"
                            title={c.status === 'archived' ? 'Reopen Case' : 'Archive Case'}
                          >
                            {c.status === 'archived' ? (
                              <RotateCcw className="w-3.5 h-3.5" />
                            ) : (
                              <Archive className="w-3.5 h-3.5" />
                            )}
                          </button>
                          <ChevronRight className="w-4 h-4 text-slate-300 group-hover:text-cyan-600 transition-colors" />
                        </div>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}

        {/* Pagination Bar */}
        {totalPages > 1 && (
          <div className="py-3 px-4 border-t border-slate-100 flex items-center justify-between text-xs font-mono text-slate-600 bg-slate-50/50">
            <div>
              Page {currentPage} of {totalPages} ({totalCases} Total)
            </div>
            <div className="flex items-center gap-1.5">
              <button
                onClick={() => setCurrentPage(prev => Math.max(1, prev - 1))}
                disabled={currentPage === 1}
                className="px-2.5 py-1 rounded-lg bg-white border border-slate-200 disabled:opacity-40 hover:bg-slate-50 text-slate-700 cursor-pointer shadow-2xs"
              >
                Prev
              </button>
              <button
                onClick={() => setCurrentPage(prev => Math.min(totalPages, prev + 1))}
                disabled={currentPage === totalPages}
                className="px-2.5 py-1 rounded-lg bg-white border border-slate-200 disabled:opacity-40 hover:bg-slate-50 text-slate-700 cursor-pointer shadow-2xs"
              >
                Next
              </button>
            </div>
          </div>
        )}

      </div>

      {/* Case Inspection & Investigation Audit Drawer Modal */}
      {selectedCase && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-3 sm:p-5 bg-slate-900/60 backdrop-blur-xs font-sans animate-fade-in">
          <div className="w-full max-w-2xl bg-white rounded-2xl border border-slate-200 shadow-2xl overflow-hidden max-h-[90vh] flex flex-col">
            
            {/* Modal Header */}
            <div className="p-5 border-b border-slate-100 flex items-center justify-between gap-3 bg-slate-50/50">
              <div className="flex items-center gap-3">
                <div className="p-2 rounded-xl bg-cyan-50 border border-cyan-200 text-cyan-700">
                  <Shield className="w-5 h-5" />
                </div>
                <div>
                  <div className="flex items-center gap-2">
                    <h2 className="text-base font-bold text-slate-900 font-mono">
                      {selectedCase.caseId}
                    </h2>
                    <span className={`text-[10px] px-2 py-0.5 rounded font-mono font-bold uppercase border ${
                      selectedCase.status === 'archived'
                        ? 'bg-slate-100 text-slate-600 border-slate-200'
                        : selectedCase.status === 'investigating'
                          ? 'bg-cyan-50 text-cyan-800 border-cyan-200'
                          : selectedCase.status === 'closed'
                            ? 'bg-emerald-50 text-emerald-800 border-emerald-200'
                            : 'bg-amber-50 text-amber-800 border-amber-200'
                    }`}>
                      {selectedCase.status || 'Active'}
                    </span>
                  </div>
                  <p className="text-xs text-slate-500 font-sans mt-0.5">
                    Forensic evidence dossier and SOC investigator audit trail
                  </p>
                </div>
              </div>

              <div className="flex items-center gap-2">
                <span className={`text-xs font-mono font-extrabold px-2.5 py-1 rounded-lg border ${
                  (selectedCase.threatScore ?? 0) >= 80 
                    ? 'bg-red-50 text-red-700 border-red-300' 
                    : (selectedCase.threatScore ?? 0) >= 60 
                      ? 'bg-orange-50 text-orange-700 border-orange-300' 
                      : (selectedCase.threatScore ?? 0) >= 30 
                        ? 'bg-amber-50 text-amber-700 border-amber-300' 
                        : 'bg-emerald-50 text-emerald-700 border-emerald-300'
                }`}>
                  Score {selectedCase.threatScore ?? 0}/100
                </span>
                <button
                  onClick={() => setSelectedCase(null)}
                  className="p-1.5 rounded-lg text-slate-400 hover:text-slate-700 hover:bg-slate-100 transition-colors cursor-pointer"
                  title="Close inspection"
                >
                  <X className="w-5 h-5" />
                </button>
              </div>
            </div>

            {/* Modal Body */}
            <div className="p-5 sm:p-6 overflow-y-auto space-y-5 text-xs text-slate-700 flex-1">
              
              {/* Message Envelope Overview */}
              <div className="p-3.5 rounded-xl bg-slate-50 border border-slate-200/80 space-y-2">
                <div className="flex items-start justify-between gap-3">
                  <span className="font-semibold text-slate-900 text-sm leading-snug">
                    {selectedCase.subject || '(No Subject)'}
                  </span>
                  <span className="text-[11px] font-mono text-slate-500 whitespace-nowrap">
                    {selectedCase.classification || 'Phishing'}
                  </span>
                </div>
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 text-[11px] text-slate-600 font-mono pt-1">
                  <div>From: <strong className="text-slate-800 break-all">{selectedCase.sender || 'Unknown'}</strong></div>
                  <div>To: <strong className="text-slate-800 break-all">{selectedCase.recipient || 'Analyst'}</strong></div>
                  <div>Analyzed: <span className="text-slate-800">{selectedCase.analyzedAt ? new Date(selectedCase.analyzedAt).toLocaleString() : 'N/A'}</span></div>
                  <div>Created: <span className="text-slate-800">{selectedCase.createdAt ? new Date(selectedCase.createdAt).toLocaleString() : 'N/A'}</span></div>
                </div>
              </div>

              {/* Original Submitted Evidence SHA-256 Digest */}
              <div className="p-3.5 rounded-xl bg-white border border-slate-200 space-y-1.5 shadow-2xs">
                <div className="flex items-center justify-between">
                  <span className="text-[10px] uppercase font-bold text-slate-500 tracking-wider">
                    Evidence Integrity Seal (SHA-256 Digest)
                  </span>
                  <span className="text-[10px] text-emerald-700 font-medium font-mono flex items-center gap-1">
                    <span className="w-1.5 h-1.5 rounded-full bg-emerald-500"></span>
                    Verified Tamper-Evident
                  </span>
                </div>
                <div className="flex items-center justify-between gap-2 p-2 rounded-lg bg-slate-50 border border-slate-200">
                  <span className="font-mono text-slate-800 text-[11px] truncate">
                    {selectedCase.emailHash || selectedCase.sha256 || 'Unavailable in offline ingestion'}
                  </span>
                  {(selectedCase.emailHash || selectedCase.sha256) && (
                    <button
                      onClick={() => {
                        navigator.clipboard?.writeText(selectedCase.emailHash || selectedCase.sha256);
                        setCopiedHash(true);
                        setTimeout(() => setCopiedHash(false), 2000);
                      }}
                      className="p-1 rounded text-slate-500 hover:text-slate-900 transition-colors shrink-0 cursor-pointer"
                      title="Copy full SHA-256 hash"
                    >
                      {copiedHash ? <Check className="w-3.5 h-3.5 text-emerald-600" /> : <Copy className="w-3.5 h-3.5" />}
                    </button>
                  )}
                </div>
              </div>

              {/* Workflow Status Switcher */}
              <div className="space-y-1.5">
                <span className="text-[10px] uppercase font-bold text-slate-500 tracking-wider">
                  Update Workflow Status
                </span>
                <div className="flex items-center gap-1.5 flex-wrap">
                  {['active', 'investigating', 'closed', 'archived'].map(st => {
                    const isCur = selectedCase.status === st;
                    return (
                      <button
                        key={st}
                        onClick={() => handleChangeStatus(st)}
                        disabled={isCur || isUpdatingStatus}
                        className={`px-3 py-1 rounded-lg text-xs font-medium font-mono transition-colors cursor-pointer capitalize ${
                          isCur
                            ? 'bg-slate-900 text-white font-bold'
                            : 'bg-slate-100 hover:bg-slate-200 text-slate-700'
                        }`}
                      >
                        {st}
                      </button>
                    );
                  })}
                </div>
              </div>

              {/* Investigation Audit Trail & Timeline */}
              <div className="space-y-2">
                <div className="flex items-center justify-between">
                  <span className="text-[10px] uppercase font-bold text-slate-500 tracking-wider">
                    Investigation History & Audit Trail
                  </span>
                  <span className="text-[10px] font-mono text-slate-400">
                    {Array.isArray(selectedCase.timeline) ? selectedCase.timeline.length : 1} Event(s)
                  </span>
                </div>

                <div className="space-y-2 max-h-48 overflow-y-auto pr-1">
                  {Array.isArray(selectedCase.timeline) && selectedCase.timeline.length > 0 ? (
                    selectedCase.timeline.map((item, idx) => (
                      <div key={idx} className="p-2.5 rounded-lg bg-slate-50 border border-slate-200 space-y-1 text-xs">
                        <div className="flex items-center justify-between text-[10px] font-mono text-slate-500">
                          <span className="font-semibold text-slate-800 flex items-center gap-1">
                            <User className="w-3 h-3 text-slate-400" />
                            {item.actor || 'System'}
                          </span>
                          <span>{item.timestamp ? new Date(item.timestamp).toLocaleString() : 'T0'}</span>
                        </div>
                        <div className="text-slate-800 text-[11px] font-medium">
                          {item.note || item.action || item.name || 'Case inspection recorded'}
                        </div>
                      </div>
                    ))
                  ) : (
                    <div className="p-3 rounded-lg bg-slate-50 border border-slate-200 text-slate-500 text-[11px]">
                      Case ingested and initialized with automated forensic verification. No manual analyst notes recorded yet.
                    </div>
                  )}
                </div>
              </div>

              {/* Add Investigator Note Form */}
              <form onSubmit={handleAddNote} className="space-y-2 pt-1 border-t border-slate-100">
                <span className="text-[10px] uppercase font-bold text-slate-500 tracking-wider block">
                  Record Investigator Action / Note
                </span>
                <div className="flex items-center gap-2">
                  <input
                    type="text"
                    value={newNoteText}
                    onChange={(e) => setNewNoteText(e.target.value)}
                    placeholder="Enter investigator finding or triage note..."
                    className="flex-1 p-2.5 rounded-lg bg-slate-50 border border-slate-200 text-xs font-sans text-slate-900 placeholder-slate-400 focus:outline-none focus:bg-white focus:border-cyan-500 transition-colors"
                  />
                  <button
                    type="submit"
                    disabled={isAddingNote || !newNoteText.trim()}
                    className="px-3.5 py-2.5 rounded-lg bg-cyan-600 hover:bg-cyan-500 disabled:opacity-50 text-white font-semibold text-xs transition-colors cursor-pointer shrink-0 flex items-center gap-1.5"
                  >
                    <MessageSquare className="w-3.5 h-3.5" />
                    <span>{isAddingNote ? 'Saving...' : 'Add Note'}</span>
                  </button>
                </div>
              </form>

            </div>

            {/* Modal Footer */}
            <div className="p-4 bg-slate-50 border-t border-slate-100 flex items-center justify-between gap-3">
              <button
                type="button"
                onClick={() => setSelectedCase(null)}
                className="px-4 py-2 rounded-xl bg-white border border-slate-200 text-slate-700 font-semibold text-xs hover:bg-slate-100 transition-colors cursor-pointer"
              >
                Close
              </button>

              <button
                type="button"
                onClick={handleOpenFullAnalyzer}
                className="px-4 py-2 rounded-xl bg-slate-900 hover:bg-slate-800 text-white font-semibold text-xs shadow-xs transition-colors cursor-pointer flex items-center gap-1.5"
              >
                <span>Open in Security Analyzer</span>
                <ArrowRight className="w-4 h-4" />
              </button>
            </div>

          </div>
        </div>
      )}

    </div>
  );
};
