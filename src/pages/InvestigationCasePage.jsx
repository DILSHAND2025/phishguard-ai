import React, { useState, useEffect, useCallback } from 'react';
import { 
  Briefcase, 
  Search, 
  RefreshCw, 
  ChevronRight, 
  Archive, 
  RotateCcw, 
  AlertTriangle, 
  Inbox 
} from 'lucide-react';
import { 
  fetchCases, 
  archiveCase, 
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
  const [statusFilter, setStatusFilter] = useState('active'); // 'active' | 'archived'
  const [searchQuery, setSearchQuery] = useState('');
  const [currentPage, setCurrentPage] = useState(1);
  const [totalPages, setTotalPages] = useState(1);
  const [isDbUnavailable, setIsDbUnavailable] = useState(false);
  const [errorMessage, setErrorMessage] = useState(null);

  // Load cases from PostgreSQL backend
  const loadCases = useCallback(async () => {
    setLoading(true);
    setErrorMessage(null);

    const result = await fetchCases({
      priority: selectedPriority === 'All' ? undefined : selectedPriority,
      status: statusFilter,
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
    const res = await archiveCase(caseItem.caseId, newStatus);
    if (res.success) {
      loadCases();
    } else {
      alert(`Failed to update case status: ${res.error || 'Unknown error'}`);
    }
  };

  // Open case investigation without re-analyzing
  const handleCaseClick = (caseItem) => {
    if (onOpenCase) {
      onOpenCase(caseItem);
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
                {totalCases} {statusFilter === 'archived' ? 'Archived' : 'Active'}
              </span>
            </div>
            <p className="text-xs text-slate-600 mt-1 max-w-2xl">
              Review and prioritize analyzed email threats. Highest-risk emails appear at the top.
            </p>
          </div>

          <div className="flex items-center gap-2.5">
            {/* Active / Archived Toggle */}
            <div className="flex items-center bg-slate-100 rounded-xl p-1 border border-slate-200 text-xs font-medium">
              <button
                onClick={() => { setStatusFilter('active'); setCurrentPage(1); }}
                className={`px-3 py-1.5 rounded-lg transition-colors cursor-pointer ${
                  statusFilter === 'active'
                    ? 'bg-white text-slate-900 shadow-2xs font-semibold'
                    : 'text-slate-600 hover:text-slate-900'
                }`}
              >
                Active Cases
              </button>
              <button
                onClick={() => { setStatusFilter('archived'); setCurrentPage(1); }}
                className={`px-3 py-1.5 rounded-lg transition-colors cursor-pointer ${
                  statusFilter === 'archived'
                    ? 'bg-white text-slate-900 shadow-2xs font-semibold'
                    : 'text-slate-600 hover:text-slate-900'
                }`}
              >
                Archived
              </button>
            </div>

            <button
              onClick={loadCases}
              disabled={loading}
              className="p-2.5 rounded-xl bg-white hover:bg-slate-50 border border-slate-200 text-slate-600 hover:text-slate-900 transition-all cursor-pointer shadow-2xs"
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

    </div>
  );
};
