/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { useEffect, useState } from 'react';
import { AttachmentAnalysisView } from './components/AttachmentAnalysisView';
import { DocumentationModal } from './components/DocumentationModal';
import { EmailInputModal } from './components/EmailInputModal';
import { ExportReportModal } from './components/ExportReportModal';
import { HeaderAnalysisView } from './components/HeaderAnalysisView';
import { Navbar } from './components/Navbar';
import { OverviewDashboard } from './components/OverviewDashboard';
import { UrlAnalysisView } from './components/UrlAnalysisView';
import { SAMPLE_EMAILS, SampleEmailItem } from './data/sampleEmails';
import { AnalyzedAttachment, ManualTriageFormState, TriageReport } from './types';
import { runFullTriage, runManualTriage } from './utils/triageEngine';

export default function App() {
  const [report, setReport] = useState<TriageReport | null>(null);
  const [activeTab, setActiveTab] = useState<'overview' | 'headers' | 'urls' | 'attachments'>('overview');
  const [isInputModalOpen, setIsInputModalOpen] = useState(false);
  const [isExportModalOpen, setIsExportModalOpen] = useState(false);
  const [isDocsModalOpen, setIsDocsModalOpen] = useState(false);
  const [isAnalyzing, setIsAnalyzing] = useState(true);

  // Initialize with the realistic CEO Fraud BEC sample on mount
  useEffect(() => {
    async function init() {
      setIsAnalyzing(true);
      try {
        const initialReport = await runFullTriage(SAMPLE_EMAILS[0].rawEmail, 'eml');
        setReport(initialReport);
      } catch (err) {
        console.error('Failed to initialize triage report:', err);
      } finally {
        setIsAnalyzing(false);
      }
    }
    init();
  }, []);

  const handleLoadSample = async (sample: SampleEmailItem) => {
    setIsAnalyzing(true);
    try {
      const newReport = await runFullTriage(sample.rawEmail, 'eml');
      setReport(newReport);
      if (sample.highlightedModule !== 'all') {
        setActiveTab(sample.highlightedModule);
      } else {
        setActiveTab('overview');
      }
    } catch (err) {
      console.error('Failed to triage sample:', err);
    } finally {
      setIsAnalyzing(false);
    }
  };

  const handleSubmitRaw = async (raw: string, mode: 'eml' | 'raw_headers') => {
    setIsAnalyzing(true);
    try {
      const newReport = await runFullTriage(raw, mode);
      setReport(newReport);
      setActiveTab('overview');
    } catch (err) {
      console.error('Failed to triage raw email:', err);
    } finally {
      setIsAnalyzing(false);
    }
  };

  const handleSubmitManual = async (form: ManualTriageFormState) => {
    setIsAnalyzing(true);
    try {
      const newReport = await runManualTriage(form);
      setReport(newReport);
      setActiveTab('overview');
    } catch (err) {
      console.error('Failed to triage manual form:', err);
    } finally {
      setIsAnalyzing(false);
    }
  };

  const handleAddAttachment = (attachment: AnalyzedAttachment) => {
    if (!report) return;
    const updatedAttachments = [...report.attachmentAnalysis.attachments, attachment];
    const dangerousCount = updatedAttachments.filter((a) => a.riskLevel === 'dangerous').length;
    const reviewCount = updatedAttachments.filter((a) => a.riskLevel === 'review').length;
    const safeCount = updatedAttachments.filter((a) => a.riskLevel === 'safe').length;

    // Recalculate score
    let newScore = report.overallScore;
    if (attachment.riskLevel === 'dangerous') {
      newScore = Math.min(100, newScore + 30);
    } else if (attachment.riskLevel === 'review') {
      newScore = Math.min(100, newScore + 15);
    }

    setReport({
      ...report,
      overallScore: newScore,
      attachmentAnalysis: {
        ...report.attachmentAnalysis,
        attachments: updatedAttachments,
        totalAttachments: updatedAttachments.length,
        dangerousCount,
        reviewCount,
        safeCount,
      },
    });
  };

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 flex flex-col font-sans selection:bg-indigo-500 selection:text-white">
      {report && (
        <Navbar
          activeTab={activeTab}
          onSelectTab={setActiveTab}
          report={report}
          onOpenInputModal={() => setIsInputModalOpen(true)}
          onOpenExportModal={() => setIsExportModalOpen(true)}
          onOpenDocsModal={() => setIsDocsModalOpen(true)}
          onLoadSample={handleLoadSample}
        />
      )}

      {/* Main Container */}
      <main className="flex-1 max-w-7xl w-full mx-auto px-4 sm:px-6 lg:px-8 py-6">
        {isAnalyzing ? (
          <div className="flex flex-col items-center justify-center min-h-[60vh] space-y-4">
            <div className="w-10 h-10 border-3 border-indigo-500 border-t-transparent rounded-full animate-spin" />
            <div className="text-sm font-semibold text-slate-300">
              Running Deterministic Triage Heuristics...
            </div>
            <p className="text-xs text-slate-500">
              Verifying RFC 5322 headers, uncloaking redirect chains, scanning attachments
            </p>
          </div>
        ) : report ? (
          <div className="transition-opacity duration-300">
            {activeTab === 'overview' && (
              <OverviewDashboard
                report={report}
                onNavigateTab={setActiveTab}
                onOpenExport={() => setIsExportModalOpen(true)}
                onNewAnalysis={() => setIsInputModalOpen(true)}
              />
            )}

            {activeTab === 'headers' && (
              <HeaderAnalysisView headerAnalysis={report.headerAnalysis} />
            )}

            {activeTab === 'urls' && <UrlAnalysisView urlAnalysis={report.urlAnalysis} />}

            {activeTab === 'attachments' && (
              <AttachmentAnalysisView
                attachmentAnalysis={report.attachmentAnalysis}
                onAddAttachment={handleAddAttachment}
              />
            )}
          </div>
        ) : (
          <div className="text-center py-20">
            <p className="text-slate-400">No report loaded.</p>
          </div>
        )}
      </main>

      {/* Modals */}
      <EmailInputModal
        isOpen={isInputModalOpen}
        onClose={() => setIsInputModalOpen(false)}
        onSubmitRaw={handleSubmitRaw}
        onSubmitManual={handleSubmitManual}
        onLoadSample={handleLoadSample}
      />

      {report && (
        <ExportReportModal
          isOpen={isExportModalOpen}
          onClose={() => setIsExportModalOpen(false)}
          report={report}
        />
      )}

      <DocumentationModal
        isOpen={isDocsModalOpen}
        onClose={() => setIsDocsModalOpen(false)}
      />

      {/* Footer */}
      <footer className="border-t border-slate-900 bg-slate-950 py-4 text-center text-xs text-slate-500">
        <div className="max-w-7xl mx-auto px-4 flex flex-col sm:flex-row items-center justify-between gap-2">
          <span>Phishing Email Analyzer • SOC Incident Triage Suite</span>
          <span>100% Client-Side Deterministic Analysis • Zero External Network Exfiltration</span>
        </div>
      </footer>
    </div>
  );
}
