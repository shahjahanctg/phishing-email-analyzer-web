import React from 'react';
import {
  AlertOctagon,
  AlertTriangle,
  ArrowRight,
  CheckCircle2,
  Copy,
  Download,
  ExternalLink,
  FileCheck,
  FileWarning,
  Globe,
  Mail,
  Network,
  Paperclip,
  Shield,
  ShieldAlert,
  ShieldCheck,
  Zap,
} from 'lucide-react';
import { TriageReport } from '../types';

interface OverviewDashboardProps {
  report: TriageReport;
  onNavigateTab: (tab: 'headers' | 'urls' | 'attachments') => void;
  onOpenExport: () => void;
  onNewAnalysis: () => void;
}

export const OverviewDashboard: React.FC<OverviewDashboardProps> = ({
  report,
  onNavigateTab,
  onOpenExport,
  onNewAnalysis,
}) => {
  const {
    timestamp,
    analyzedEmailSubject,
    overallScore,
    phishingLikelihood,
    confidence,
    verdictSummary,
    keyRedFlags,
    headerAnalysis,
    urlAnalysis,
    attachmentAnalysis,
    emailBodyText,
  } = report;

  const h = headerAnalysis.headers;

  const getLikelihoodTheme = (likelihood: TriageReport['phishingLikelihood']) => {
    switch (likelihood) {
      case 'Critical Risk':
        return {
          bg: 'bg-rose-950/40 border-rose-800/60',
          text: 'text-rose-400',
          badge: 'bg-rose-500/20 text-rose-300 border-rose-500/40',
          icon: <AlertOctagon className="w-8 h-8 text-rose-400" />,
          progress: 'bg-rose-500',
        };
      case 'High Risk':
        return {
          bg: 'bg-rose-950/25 border-rose-800/50',
          text: 'text-rose-400',
          badge: 'bg-rose-500/20 text-rose-300 border-rose-500/40',
          icon: <ShieldAlert className="w-8 h-8 text-rose-400" />,
          progress: 'bg-rose-500',
        };
      case 'Moderate Risk':
        return {
          bg: 'bg-amber-950/30 border-amber-800/50',
          text: 'text-amber-400',
          badge: 'bg-amber-500/20 text-amber-300 border-amber-500/40',
          icon: <AlertTriangle className="w-8 h-8 text-amber-400" />,
          progress: 'bg-amber-500',
        };
      case 'Low Risk':
        return {
          bg: 'bg-blue-950/30 border-blue-800/50',
          text: 'text-blue-400',
          badge: 'bg-blue-500/20 text-blue-300 border-blue-500/40',
          icon: <Shield className="w-8 h-8 text-blue-400" />,
          progress: 'bg-blue-500',
        };
      case 'Safe / Clean':
      default:
        return {
          bg: 'bg-emerald-950/30 border-emerald-800/50',
          text: 'text-emerald-400',
          badge: 'bg-emerald-500/20 text-emerald-300 border-emerald-500/40',
          icon: <ShieldCheck className="w-8 h-8 text-emerald-400" />,
          progress: 'bg-emerald-500',
        };
    }
  };

  const theme = getLikelihoodTheme(phishingLikelihood);

  return (
    <div className="space-y-6" id="overview-dashboard">
      {/* Master Phishing Likelihood Card */}
      <div className={`p-6 sm:p-8 rounded-2xl border ${theme.bg} shadow-lg relative overflow-hidden`}>
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-6">
          <div className="flex items-start gap-4">
            <div className="p-3 rounded-2xl bg-slate-950/80 border border-slate-800 shrink-0">
              {theme.icon}
            </div>
            <div>
              <div className="flex items-center gap-3 flex-wrap mb-1.5">
                <span className={`px-3 py-1 rounded-full text-xs font-bold uppercase tracking-wider border ${theme.badge}`}>
                  {phishingLikelihood}
                </span>
                <span className="text-xs font-medium text-slate-400">
                  Confidence: <span className="text-white font-semibold">{confidence}</span>
                </span>
                <span className="text-xs text-slate-500 font-mono">
                  Analyzed at {new Date(timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' })}
                </span>
              </div>
              <h2 className="text-2xl sm:text-3xl font-extrabold tracking-tight text-white mt-1">
                Phishing Score: <span className={theme.text}>{overallScore}</span>
                <span className="text-slate-500 text-lg font-normal"> / 100</span>
              </h2>
              <p className="text-sm text-slate-300 max-w-3xl mt-2 leading-relaxed">{verdictSummary}</p>
            </div>
          </div>

          {/* Quick Actions */}
          <div className="flex flex-wrap lg:flex-col items-center gap-2.5 shrink-0">
            <button
              onClick={onOpenExport}
              className="w-full sm:w-auto px-4 py-2.5 rounded-xl bg-indigo-600 hover:bg-indigo-500 text-white text-xs font-bold flex items-center justify-center gap-2 shadow-sm transition-all"
            >
              <Download className="w-4 h-4" /> Export Report (PDF / MD)
            </button>
            <button
              onClick={onNewAnalysis}
              className="w-full sm:w-auto px-4 py-2.5 rounded-xl bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-medium flex items-center justify-center gap-2 transition-all border border-slate-700"
            >
              <Zap className="w-4 h-4 text-amber-400" /> Triage New Email
            </button>
          </div>
        </div>

        {/* Score Progress Gauge */}
        <div className="mt-6 pt-6 border-t border-slate-800/80">
          <div className="flex justify-between text-xs font-mono text-slate-400 mb-2">
            <span>0 (Safe / Legitimate)</span>
            <span className="text-white font-bold">{overallScore}% Malicious Probability</span>
            <span>100 (Critical Phishing Attack)</span>
          </div>
          <div className="w-full bg-slate-950 h-3 rounded-full overflow-hidden p-0.5 border border-slate-800">
            <div
              className={`h-full rounded-full transition-all duration-700 ${theme.progress}`}
              style={{ width: `${Math.max(4, overallScore)}%` }}
            />
          </div>
        </div>
      </div>

      {/* Email Metadata Strip */}
      <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 text-xs grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3">
        <div>
          <span className="text-slate-500 block uppercase tracking-wider font-semibold text-[10px]">Subject:</span>
          <span className="font-semibold text-white truncate block mt-0.5" title={analyzedEmailSubject}>
            {analyzedEmailSubject || 'No Subject'}
          </span>
        </div>
        <div>
          <span className="text-slate-500 block uppercase tracking-wider font-semibold text-[10px]">From:</span>
          <span className="font-mono text-slate-200 truncate block mt-0.5" title={h.from?.address}>
            {h.from?.name ? `${h.from.name} <${h.from.address}>` : h.from?.address || 'Unknown'}
          </span>
        </div>
        <div>
          <span className="text-slate-500 block uppercase tracking-wider font-semibold text-[10px]">Return-Path:</span>
          <span className="font-mono text-slate-200 truncate block mt-0.5" title={h.returnPath?.address}>
            {h.returnPath?.address || 'Not specified'}
          </span>
        </div>
        <div>
          <span className="text-slate-500 block uppercase tracking-wider font-semibold text-[10px]">Date / Delivery:</span>
          <span className="font-mono text-slate-300 truncate block mt-0.5">
            {h.date || 'Not specified'}
          </span>
        </div>
      </div>

      {/* Prioritized Key Red Flags */}
      {keyRedFlags.length > 0 && (
        <div className="p-5 rounded-xl bg-slate-900 border border-slate-800">
          <h3 className="text-xs font-bold text-slate-400 uppercase tracking-wider mb-3 flex items-center gap-2">
            <AlertOctagon className="w-4 h-4 text-rose-400" /> Prioritized Security Red Flags ({keyRedFlags.length})
          </h3>
          <div className="space-y-2">
            {keyRedFlags.map((flag, idx) => (
              <div
                key={idx}
                className="flex items-start gap-2.5 p-3 rounded-lg bg-rose-950/20 border border-rose-900/40 text-xs text-rose-200"
              >
                <div className="w-1.5 h-1.5 rounded-full bg-rose-400 shrink-0 mt-1.5" />
                <span className="font-medium leading-relaxed">{flag}</span>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Tri-Module Triage Overview Cards */}
      <div>
        <h3 className="text-xs font-bold text-slate-400 uppercase tracking-wider mb-3">
          Triage Modules Breakdown
        </h3>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-5">
          {/* Module 1: Header Analysis */}
          <div
            onClick={() => onNavigateTab('headers')}
            className="group p-5 rounded-xl bg-slate-900 hover:bg-slate-850 border border-slate-800 hover:border-slate-700 cursor-pointer transition-all flex flex-col justify-between"
          >
            <div>
              <div className="flex items-center justify-between mb-3">
                <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider flex items-center gap-2">
                  <Mail className="w-4 h-4 text-indigo-400" /> Header Verification
                </span>
                <span
                  className={`text-xs px-2 py-0.5 rounded font-bold ${
                    headerAnalysis.trustScore >= 70
                      ? 'bg-emerald-500/20 text-emerald-300'
                      : headerAnalysis.trustScore >= 40
                      ? 'bg-amber-500/20 text-amber-300'
                      : 'bg-rose-500/20 text-rose-300'
                  }`}
                >
                  Trust: {headerAnalysis.trustScore}%
                </span>
              </div>

              <p className="text-xs text-slate-400 mb-3">
                Authentication protocols, From vs Return-Path domain alignment, and MTA hop chain.
              </p>

              <div className="space-y-2 text-xs font-mono">
                <div className="flex justify-between p-1.5 rounded bg-slate-950 border border-slate-800">
                  <span className="text-slate-500">SPF / DKIM / DMARC:</span>
                  <span className="text-slate-300">
                    {h.spf.status} / {h.dkim.status} / {h.dmarc.status}
                  </span>
                </div>
                <div className="flex justify-between p-1.5 rounded bg-slate-950 border border-slate-800">
                  <span className="text-slate-500">Received Hops:</span>
                  <span className="text-slate-300">{h.receivedChain.length} hop(s)</span>
                </div>
              </div>
            </div>

            <div className="mt-4 pt-3 border-t border-slate-800 flex items-center justify-between text-xs text-indigo-400 group-hover:text-indigo-300 font-semibold">
              <span>Inspect Headers Module</span>
              <ArrowRight className="w-3.5 h-3.5 group-hover:translate-x-0.5 transition-transform" />
            </div>
          </div>

          {/* Module 2: URL & Typosquat Analysis */}
          <div
            onClick={() => onNavigateTab('urls')}
            className="group p-5 rounded-xl bg-slate-900 hover:bg-slate-850 border border-slate-800 hover:border-slate-700 cursor-pointer transition-all flex flex-col justify-between"
          >
            <div>
              <div className="flex items-center justify-between mb-3">
                <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider flex items-center gap-2">
                  <Globe className="w-4 h-4 text-indigo-400" /> URL & Link Triage
                </span>
                <span
                  className={`text-xs px-2 py-0.5 rounded font-bold ${
                    urlAnalysis.highRiskCount > 0
                      ? 'bg-rose-500/20 text-rose-300'
                      : urlAnalysis.suspiciousCount > 0
                      ? 'bg-amber-500/20 text-amber-300'
                      : 'bg-emerald-500/20 text-emerald-300'
                  }`}
                >
                  {urlAnalysis.highRiskCount} High Risk
                </span>
              </div>

              <p className="text-xs text-slate-400 mb-3">
                Display text vs href mismatches, brand typosquatting, redirect chains, and high-risk TLDs.
              </p>

              <div className="space-y-2 text-xs font-mono">
                <div className="flex justify-between p-1.5 rounded bg-slate-950 border border-slate-800">
                  <span className="text-slate-500">Anchor Mismatches:</span>
                  <span className={urlAnalysis.hasDisplayMismatch ? 'text-rose-400 font-bold' : 'text-emerald-400'}>
                    {urlAnalysis.hasDisplayMismatch ? 'Detected (!)' : 'None'}
                  </span>
                </div>
                <div className="flex justify-between p-1.5 rounded bg-slate-950 border border-slate-800">
                  <span className="text-slate-500">Total URLs Scanned:</span>
                  <span className="text-slate-300">{urlAnalysis.totalUrls} link(s)</span>
                </div>
              </div>
            </div>

            <div className="mt-4 pt-3 border-t border-slate-800 flex items-center justify-between text-xs text-indigo-400 group-hover:text-indigo-300 font-semibold">
              <span>Inspect URLs Module</span>
              <ArrowRight className="w-3.5 h-3.5 group-hover:translate-x-0.5 transition-transform" />
            </div>
          </div>

          {/* Module 3: Attachment Analysis */}
          <div
            onClick={() => onNavigateTab('attachments')}
            className="group p-5 rounded-xl bg-slate-900 hover:bg-slate-850 border border-slate-800 hover:border-slate-700 cursor-pointer transition-all flex flex-col justify-between"
          >
            <div>
              <div className="flex items-center justify-between mb-3">
                <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider flex items-center gap-2">
                  <Paperclip className="w-4 h-4 text-indigo-400" /> Attachment Inspection
                </span>
                <span
                  className={`text-xs px-2 py-0.5 rounded font-bold ${
                    attachmentAnalysis.dangerousCount > 0
                      ? 'bg-rose-500/20 text-rose-300'
                      : attachmentAnalysis.reviewCount > 0
                      ? 'bg-amber-500/20 text-amber-300'
                      : 'bg-emerald-500/20 text-emerald-300'
                  }`}
                >
                  {attachmentAnalysis.dangerousCount} Dangerous
                </span>
              </div>

              <p className="text-xs text-slate-400 mb-3">
                Dangerous extensions, double-extension masking, macro-enabled docs, and nested archives.
              </p>

              <div className="space-y-2 text-xs font-mono">
                <div className="flex justify-between p-1.5 rounded bg-slate-950 border border-slate-800">
                  <span className="text-slate-500">Double Extensions:</span>
                  <span
                    className={
                      attachmentAnalysis.attachments.some((a) => a.isDoubleExtension)
                        ? 'text-rose-400 font-bold'
                        : 'text-slate-400'
                    }
                  >
                    {attachmentAnalysis.attachments.some((a) => a.isDoubleExtension) ? 'Detected (!)' : 'None'}
                  </span>
                </div>
                <div className="flex justify-between p-1.5 rounded bg-slate-950 border border-slate-800">
                  <span className="text-slate-500">Payload Count:</span>
                  <span className="text-slate-300">{attachmentAnalysis.totalAttachments} file(s)</span>
                </div>
              </div>
            </div>

            <div className="mt-4 pt-3 border-t border-slate-800 flex items-center justify-between text-xs text-indigo-400 group-hover:text-indigo-300 font-semibold">
              <span>Inspect Attachments Module</span>
              <ArrowRight className="w-3.5 h-3.5 group-hover:translate-x-0.5 transition-transform" />
            </div>
          </div>
        </div>
      </div>

      {/* Email Body Content Preview (Sanitized) */}
      {emailBodyText && (
        <div className="p-5 rounded-xl bg-slate-900 border border-slate-800">
          <div className="flex items-center justify-between mb-3">
            <h3 className="text-xs font-bold text-slate-400 uppercase tracking-wider">
              Email Body Plain-Text Representation
            </h3>
            <span className="text-[11px] text-slate-500">Safe Defanged View</span>
          </div>
          <div className="p-4 rounded-lg bg-slate-950 border border-slate-800/80 font-mono text-xs text-slate-300 max-h-64 overflow-y-auto whitespace-pre-wrap leading-relaxed select-text">
            {emailBodyText}
          </div>
        </div>
      )}
    </div>
  );
};
