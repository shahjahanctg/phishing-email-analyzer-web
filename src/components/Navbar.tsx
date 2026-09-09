import React, { useState } from 'react';
import {
  BookOpen,
  ChevronDown,
  Download,
  FileSearch,
  Globe,
  LayoutDashboard,
  Mail,
  Paperclip,
  Shield,
  Sparkles,
  Upload,
} from 'lucide-react';
import { SAMPLE_EMAILS, SampleEmailItem } from '../data/sampleEmails';
import { TriageReport } from '../types';

interface NavbarProps {
  activeTab: 'overview' | 'headers' | 'urls' | 'attachments';
  onSelectTab: (tab: 'overview' | 'headers' | 'urls' | 'attachments') => void;
  report: TriageReport;
  onOpenInputModal: () => void;
  onOpenExportModal: () => void;
  onOpenDocsModal: () => void;
  onLoadSample: (sample: SampleEmailItem) => void;
}

export const Navbar: React.FC<NavbarProps> = ({
  activeTab,
  onSelectTab,
  report,
  onOpenInputModal,
  onOpenExportModal,
  onOpenDocsModal,
  onLoadSample,
}) => {
  const [showSamplesMenu, setShowSamplesMenu] = useState(false);

  return (
    <header className="sticky top-0 z-40 bg-slate-950/90 backdrop-blur-md border-b border-slate-800">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="flex items-center justify-between h-16 gap-4">
          {/* Brand Logo & Name */}
          <div className="flex items-center gap-3 shrink-0">
            <div className="w-9 h-9 rounded-xl bg-gradient-to-tr from-indigo-600 to-violet-500 flex items-center justify-center text-white shadow-md shadow-indigo-500/20">
              <Shield className="w-5 h-5" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <span className="font-bold text-white text-base tracking-tight">Phishing Analyzer</span>
                <span className="px-1.5 py-0.5 rounded text-[10px] font-mono font-bold bg-indigo-500/20 text-indigo-300 border border-indigo-500/30">
                  SOC TRIAGE
                </span>
              </div>
              <p className="text-[11px] text-slate-400 hidden sm:block">RFC 5322 • URL Heuristics • Attachment Droppers</p>
            </div>
          </div>

          {/* Center Navigation Tabs */}
          <nav className="hidden md:flex items-center gap-1 bg-slate-900/80 p-1 rounded-xl border border-slate-800 text-xs font-semibold">
            <button
              onClick={() => onSelectTab('overview')}
              className={`px-3 py-1.5 rounded-lg flex items-center gap-1.5 transition-all ${
                activeTab === 'overview'
                  ? 'bg-indigo-600 text-white shadow-sm'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800'
              }`}
            >
              <LayoutDashboard className="w-3.5 h-3.5" /> Overview
            </button>

            <button
              onClick={() => onSelectTab('headers')}
              className={`px-3 py-1.5 rounded-lg flex items-center gap-1.5 transition-all ${
                activeTab === 'headers'
                  ? 'bg-indigo-600 text-white shadow-sm'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800'
              }`}
            >
              <Mail className="w-3.5 h-3.5" /> Headers
              <span
                className={`text-[10px] px-1.5 py-0.2 rounded font-mono ${
                  report.headerAnalysis.trustScore < 60
                    ? 'bg-rose-500/30 text-rose-300'
                    : 'bg-slate-800 text-slate-400'
                }`}
              >
                {report.headerAnalysis.trustScore}%
              </span>
            </button>

            <button
              onClick={() => onSelectTab('urls')}
              className={`px-3 py-1.5 rounded-lg flex items-center gap-1.5 transition-all ${
                activeTab === 'urls'
                  ? 'bg-indigo-600 text-white shadow-sm'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800'
              }`}
            >
              <Globe className="w-3.5 h-3.5" /> URLs
              <span
                className={`text-[10px] px-1.5 py-0.2 rounded font-mono ${
                  report.urlAnalysis.highRiskCount > 0
                    ? 'bg-rose-500/30 text-rose-300'
                    : 'bg-slate-800 text-slate-400'
                }`}
              >
                {report.urlAnalysis.totalUrls}
              </span>
            </button>

            <button
              onClick={() => onSelectTab('attachments')}
              className={`px-3 py-1.5 rounded-lg flex items-center gap-1.5 transition-all ${
                activeTab === 'attachments'
                  ? 'bg-indigo-600 text-white shadow-sm'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800'
              }`}
            >
              <Paperclip className="w-3.5 h-3.5" /> Attachments
              <span
                className={`text-[10px] px-1.5 py-0.2 rounded font-mono ${
                  report.attachmentAnalysis.dangerousCount > 0
                    ? 'bg-rose-500/30 text-rose-300'
                    : 'bg-slate-800 text-slate-400'
                }`}
              >
                {report.attachmentAnalysis.totalAttachments}
              </span>
            </button>
          </nav>

          {/* Right Actions */}
          <div className="flex items-center gap-2">
            {/* Quick Samples Dropdown */}
            <div className="relative">
              <button
                onClick={() => setShowSamplesMenu(!showSamplesMenu)}
                className="px-2.5 sm:px-3 py-1.5 rounded-lg bg-slate-900 hover:bg-slate-800 border border-slate-800 text-xs text-slate-200 flex items-center gap-1.5 transition-colors"
                title="Select Realistic Sample Email"
              >
                <Sparkles className="w-3.5 h-3.5 text-amber-400" />
                <span className="hidden sm:inline">Samples</span>
                <ChevronDown className="w-3 h-3 text-slate-400" />
              </button>

              {showSamplesMenu && (
                <div
                  onMouseLeave={() => setShowSamplesMenu(false)}
                  className="absolute right-0 mt-2 w-72 bg-slate-900 border border-slate-800 rounded-xl shadow-2xl py-2 z-50 text-xs"
                >
                  <div className="px-3 py-1 text-[10px] font-bold text-slate-400 uppercase tracking-wider">
                    Load Benchmark Email:
                  </div>
                  {SAMPLE_EMAILS.map((s) => (
                    <button
                      key={s.id}
                      onClick={() => {
                        onLoadSample(s);
                        setShowSamplesMenu(false);
                      }}
                      className="w-full text-left px-3 py-2 hover:bg-slate-800 transition-colors flex flex-col"
                    >
                      <span className="font-semibold text-white truncate">{s.name}</span>
                      <span className="text-[11px] text-slate-400 truncate">{s.category}</span>
                    </button>
                  ))}
                </div>
              )}
            </div>

            {/* Load / Upload Email Button */}
            <button
              onClick={onOpenInputModal}
              className="px-3 py-1.5 rounded-lg bg-indigo-600 hover:bg-indigo-500 text-xs font-bold text-white flex items-center gap-1.5 shadow-sm transition-colors"
            >
              <Upload className="w-3.5 h-3.5" />
              <span className="hidden sm:inline">Triage New</span>
            </button>

            {/* Export Report Button */}
            <button
              onClick={onOpenExportModal}
              className="p-1.5 sm:px-2.5 sm:py-1.5 rounded-lg bg-slate-900 hover:bg-slate-800 border border-slate-800 text-xs text-slate-300 flex items-center gap-1 transition-colors"
              title="Export Report (Markdown / PDF / JSON)"
            >
              <Download className="w-3.5 h-3.5" />
              <span className="hidden md:inline">Export</span>
            </button>

            {/* Docs Modal Button */}
            <button
              onClick={onOpenDocsModal}
              className="p-1.5 rounded-lg bg-slate-900 hover:bg-slate-800 border border-slate-800 text-slate-400 hover:text-white transition-colors"
              title="Heuristics & ML Architecture"
            >
              <BookOpen className="w-4 h-4" />
            </button>
          </div>
        </div>

        {/* Mobile Navigation Tabs */}
        <div className="md:hidden flex items-center justify-around py-2 border-t border-slate-900 text-xs font-semibold">
          <button
            onClick={() => onSelectTab('overview')}
            className={`px-3 py-1 rounded-md ${
              activeTab === 'overview' ? 'bg-indigo-600 text-white' : 'text-slate-400'
            }`}
          >
            Overview
          </button>
          <button
            onClick={() => onSelectTab('headers')}
            className={`px-3 py-1 rounded-md ${
              activeTab === 'headers' ? 'bg-indigo-600 text-white' : 'text-slate-400'
            }`}
          >
            Headers ({report.headerAnalysis.trustScore}%)
          </button>
          <button
            onClick={() => onSelectTab('urls')}
            className={`px-3 py-1 rounded-md ${activeTab === 'urls' ? 'bg-indigo-600 text-white' : 'text-slate-400'}`}
          >
            URLs ({report.urlAnalysis.totalUrls})
          </button>
          <button
            onClick={() => onSelectTab('attachments')}
            className={`px-3 py-1 rounded-md ${
              activeTab === 'attachments' ? 'bg-indigo-600 text-white' : 'text-slate-400'
            }`}
          >
            Files ({report.attachmentAnalysis.totalAttachments})
          </button>
        </div>
      </div>
    </header>
  );
};
