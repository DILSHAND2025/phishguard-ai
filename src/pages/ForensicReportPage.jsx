import React from 'react';
import { ForensicReport } from '../components/dashboard/ForensicReport.jsx';

export const ForensicReportPage = ({ onViewChange, currentAnalysis }) => {
  return (
    <ForensicReport 
      analysisResult={currentAnalysis} 
      onViewChange={onViewChange} 
    />
  );
};
