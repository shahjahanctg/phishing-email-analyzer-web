import React, { useState } from 'react';
import { Check, Copy, Download, FileCode, FileText, Printer, X } from 'lucide-react';
import { TriageReport } from '../types';
import { generateMarkdownReport } from '../utils/triageEngine';

interface ExportReportModalProps {
  isOpen: boolean;
  onClose: () => void;
  report: TriageReport;
}

export const ExportReportModal: React.FC<ExportReportModalProps> = ({ isOpen, onClose, report }) => {
  const [activeTab, setActiveTab] = useState<'markdown' | 'print' | 'json'>('markdown');
  const [copied, setCopied] = useState(false);

  if (!isOpen) return null;

  const markdownText = generateMarkdownReport(report);
  const jsonText = JSON.stringify(report, null, 2);

  const handleCopy = (text: string) => {
    navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const handlePrint = () => {
    window.print();
  };

  const handleDownloadJson = () => {
    const blob = new Blob([jsonText], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `phishing-triage-${Date.now()}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm overflow-y-auto">
      <div className="relative w-full max-w-4xl bg-slate-900 border border-slate-800 rounded-2xl shadow-2xl overflow-hidden my-8">
        {/* Modal Header */}
        <div className="p-5 border-b border-slate-800 flex items-center justify-between bg-slate-950/70">
          <div className="flex items-center gap-2.5">
            <div className="p-2 rounded-lg bg-indigo-500/20 text-indigo-400">
              <Download className="w-5 h-5" />
            </div>
            <div>
              <h3 className="text-base font-bold text-white">Export Incident Triage Report</h3>
              <p className="text-xs text-slate-400">
                Copy formatted SOC ticket Markdown, print/save PDF, or download raw JSON
              </p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="p-1.5 rounded-lg text-slate-400 hover:text-white hover:bg-slate-800 transition-colors"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Export Mode Tabs */}
        <div className="flex items-center justify-between border-b border-slate-800 bg-slate-950/40 px-5 text-xs font-semibold">
          <div className="flex">
            <button
              onClick={() => setActiveTab('markdown')}
              className={`px-4 py-3 flex items-center gap-2 border-b-2 transition-colors ${
                activeTab === 'markdown'
                  ? 'border-indigo-500 text-indigo-400 bg-slate-900/60'
                  : 'border-transparent text-slate-400 hover:text-slate-200'
              }`}
            >
              <FileText className="w-4 h-4" /> Markdown (SOC / Ticket)
            </button>
            <button
              onClick={() => setActiveTab('print')}
              className={`px-4 py-3 flex items-center gap-2 border-b-2 transition-colors ${
                activeTab === 'print'
                  ? 'border-indigo-500 text-indigo-400 bg-slate-900/60'
                  : 'border-transparent text-slate-400 hover:text-slate-200'
              }`}
            >
              <Printer className="w-4 h-4" /> Printable / PDF Report
            </button>
            <button
              onClick={() => setActiveTab('json')}
              className={`px-4 py-3 flex items-center gap-2 border-b-2 transition-colors ${
                activeTab === 'json'
                  ? 'border-indigo-500 text-indigo-400 bg-slate-900/60'
                  : 'border-transparent text-slate-400 hover:text-slate-200'
              }`}
            >
              <FileCode className="w-4 h-4" /> Raw JSON (SIEM)
            </button>
          </div>

          <div className="flex items-center gap-2">
            {activeTab === 'markdown' && (
              <button
                onClick={() => handleCopy(markdownText)}
                className="px-3 py-1.5 rounded-lg bg-indigo-600 hover:bg-indigo-500 text-white text-xs font-bold flex items-center gap-1.5 transition-colors"
              >
                {copied ? <Check className="w-3.5 h-3.5" /> : <Copy className="w-3.5 h-3.5" />}
                {copied ? 'Copied to Clipboard!' : 'Copy Markdown'}
              </button>
            )}
            {activeTab === 'print' && (
              <button
                onClick={handlePrint}
                className="px-3 py-1.5 rounded-lg bg-indigo-600 hover:bg-indigo-500 text-white text-xs font-bold flex items-center gap-1.5 transition-colors"
              >
                <Printer className="w-3.5 h-3.5" /> Print / Save as PDF
              </button>
            )}
            {activeTab === 'json' && (
              <button
                onClick={handleDownloadJson}
                className="px-3 py-1.5 rounded-lg bg-indigo-600 hover:bg-indigo-500 text-white text-xs font-bold flex items-center gap-1.5 transition-colors"
              >
                <Download className="w-3.5 h-3.5" /> Download .json File
              </button>
            )}
          </div>
        </div>

        {/* Tab Contents */}
        <div className="p-6">
          {activeTab === 'markdown' && (
            <div className="space-y-3">
              <p className="text-xs text-slate-400">
                Ready to paste directly into Jira tickets, ServiceNow incidents, Slack security channels, or email reports:
              </p>
              <pre className="p-4 rounded-xl bg-slate-950 border border-slate-800 font-mono text-xs text-slate-300 max-h-96 overflow-y-auto whitespace-pre-wrap select-all leading-relaxed">
                {markdownText}
              </pre>
            </div>
          )}

          {activeTab === 'print' && (
            <div className="space-y-4">
              <div className="p-4 rounded-xl bg-indigo-950/30 border border-indigo-800/40 text-xs text-indigo-300 flex items-center justify-between">
                <span>
                  Click <strong>&quot;Print / Save as PDF&quot;</strong> above to generate a clean, vector PDF document using your browser&apos;s native print engine.
                </span>
              </div>

              {/* Printable container */}
              <div
                id="printable-report"
                className="p-8 rounded-xl bg-white text-slate-900 space-y-6 max-h-[500px] overflow-y-auto border border-slate-300 shadow"
              >
                <div className="border-b pb-4">
                  <div className="flex items-center justify-between">
                    <h2 className="text-xl font-bold text-slate-900">Incident Triage Report</h2>
                    <span className="text-xs px-2.5 py-1 rounded bg-slate-900 text-white font-bold">
                      {report.phishingLikelihood}
                    </span>
                  </div>
                  <p className="text-xs text-slate-500 mt-1">Generated: {new Date(report.timestamp).toUTCString()}</p>
                </div>

                <div className="text-xs space-y-2">
                  <div>
                    <strong>Subject:</strong> {report.analyzedEmailSubject}
                  </div>
                  <div>
                    <strong>Phishing Score:</strong> {report.overallScore} / 100 ({report.confidence} Confidence)
                  </div>
                  <div>
                    <strong>Verdict:</strong> {report.verdictSummary}
                  </div>
                </div>

                {report.keyRedFlags.length > 0 && (
                  <div className="p-3 rounded bg-red-50 border border-red-200 text-xs">
                    <div className="font-bold text-red-800 mb-1">Key Red Flags:</div>
                    <ul className="list-disc pl-4 space-y-1 text-red-700">
                      {report.keyRedFlags.map((flag, idx) => (
                        <li key={idx}>{flag}</li>
                      ))}
                    </ul>
                  </div>
                )}

                <div className="text-xs space-y-4 pt-2">
                  <div className="border-t pt-2">
                    <h3 className="font-bold text-slate-800 mb-1">1. Header Analysis</h3>
                    <p className="text-slate-600">
                      Trust Score: {report.headerAnalysis.trustScore}/100 ({report.headerAnalysis.trustLevel}) | From:{' '}
                      {report.headerAnalysis.headers.from?.address} | Return-Path:{' '}
                      {report.headerAnalysis.headers.returnPath?.address}
                    </p>
                  </div>

                  <div className="border-t pt-2">
                    <h3 className="font-bold text-slate-800 mb-1">2. URL Analysis</h3>
                    <p className="text-slate-600">
                      Total URLs: {report.urlAnalysis.totalUrls} | High-Risk: {report.urlAnalysis.highRiskCount} | Anchor
                      Mismatches: {report.urlAnalysis.hasDisplayMismatch ? 'YES' : 'None'}
                    </p>
                  </div>

                  <div className="border-t pt-2">
                    <h3 className="font-bold text-slate-800 mb-1">3. Attachment Analysis</h3>
                    <p className="text-slate-600">
                      Total Attachments: {report.attachmentAnalysis.totalAttachments} | Dangerous:{' '}
                      {report.attachmentAnalysis.dangerousCount}
                    </p>
                  </div>
                </div>
              </div>
            </div>
          )}

          {activeTab === 'json' && (
            <div className="space-y-3">
              <p className="text-xs text-slate-400">
                Machine-readable JSON schema for SIEM correlation, SOAR webhooks, or automated ticket ingestion:
              </p>
              <pre className="p-4 rounded-xl bg-slate-950 border border-slate-800 font-mono text-[11px] text-slate-300 max-h-96 overflow-y-auto whitespace-pre-wrap select-all">
                {jsonText}
              </pre>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
