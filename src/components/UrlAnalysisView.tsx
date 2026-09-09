import React, { useState } from 'react';
import {
  AlertCircle,
  AlertTriangle,
  ArrowRight,
  CheckCircle2,
  Copy,
  ExternalLink,
  Eye,
  Filter,
  Globe,
  HelpCircle,
  Link as LinkIcon,
  Shield,
  ShieldAlert,
  Unlink,
} from 'lucide-react';
import { AnalyzedUrl, UrlAnalysisResult } from '../types';

interface UrlAnalysisViewProps {
  urlAnalysis: UrlAnalysisResult;
}

export const UrlAnalysisView: React.FC<UrlAnalysisViewProps> = ({ urlAnalysis }) => {
  const [filterLevel, setFilterLevel] = useState<'all' | 'high-risk' | 'suspicious' | 'safe' | 'mismatch'>('all');
  const [copiedId, setCopiedId] = useState<string | null>(null);

  const { urls, totalUrls, highRiskCount, suspiciousCount, safeCount, hasDisplayMismatch } = urlAnalysis;

  // Defang URL for safe security analyst sharing: replaces http with hxxp, dots with [.]
  const defangUrl = (url: string): string => {
    return url.replace(/^https?:\/\//i, (m) => (m.toLowerCase().startsWith('https') ? 'hxxps://' : 'hxxp://')).replace(/\./g, '[.]');
  };

  const handleCopyDefanged = (url: AnalyzedUrl) => {
    navigator.clipboard.writeText(defangUrl(url.originalUrl));
    setCopiedId(url.id);
    setTimeout(() => setCopiedId(null), 2000);
  };

  const filteredUrls = urls.filter((u) => {
    if (filterLevel === 'all') return true;
    if (filterLevel === 'mismatch') return u.isDisplayMismatch;
    return u.riskLevel === filterLevel;
  });

  return (
    <div className="space-y-6" id="url-analysis-module">
      {/* Overview Metric Bar */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
        <div className="p-4 rounded-xl bg-slate-900 border border-slate-800">
          <div className="text-xs font-semibold text-slate-400 uppercase tracking-wider">Total URLs Found</div>
          <div className="text-2xl font-bold text-white mt-1">{totalUrls}</div>
          <div className="text-[11px] text-slate-500 mt-1">Extracted from body & links</div>
        </div>

        <div className="p-4 rounded-xl bg-slate-900 border border-slate-800">
          <div className="text-xs font-semibold text-rose-400 uppercase tracking-wider">High Risk URLs</div>
          <div className="text-2xl font-bold text-rose-400 mt-1">{highRiskCount}</div>
          <div className="text-[11px] text-slate-500 mt-1">Typosquats, IP hosts, homoglyphs</div>
        </div>

        <div className="p-4 rounded-xl bg-slate-900 border border-slate-800">
          <div className="text-xs font-semibold text-amber-400 uppercase tracking-wider">Suspicious</div>
          <div className="text-2xl font-bold text-amber-400 mt-1">{suspiciousCount}</div>
          <div className="text-[11px] text-slate-500 mt-1">Risky TLDs, deep subdomains</div>
        </div>

        <div className="p-4 rounded-xl bg-slate-900 border border-slate-800">
          <div className="text-xs font-semibold text-emerald-400 uppercase tracking-wider">Safe / Verified</div>
          <div className="text-2xl font-bold text-emerald-400 mt-1">{safeCount}</div>
          <div className="text-[11px] text-slate-500 mt-1">Known authenticated domains</div>
        </div>
      </div>

      {/* Anchor Text Mismatch Master Alert Banner */}
      {hasDisplayMismatch && (
        <div className="p-4 rounded-xl bg-rose-950/30 border border-rose-800/60 flex items-start gap-3.5">
          <div className="p-2 rounded-lg bg-rose-900/40 text-rose-300">
            <Unlink className="w-5 h-5" />
          </div>
          <div>
            <h4 className="text-sm font-bold text-rose-200">Deceptive Display Text vs Actual Target Href Detected</h4>
            <p className="text-xs text-rose-300/80 mt-1">
              One or more hyperlinks in this email present a familiar trusted URL to the recipient, while the underlying HTML
              anchor points to a completely different destination. This is a primary spear-phishing deception technique.
            </p>
          </div>
        </div>
      )}

      {/* Filter Tabs */}
      <div className="flex flex-wrap items-center justify-between gap-3 bg-slate-900 p-2.5 rounded-xl border border-slate-800">
        <div className="flex flex-wrap items-center gap-1.5 text-xs font-medium">
          <button
            onClick={() => setFilterLevel('all')}
            className={`px-3 py-1.5 rounded-lg transition-colors ${
              filterLevel === 'all' ? 'bg-indigo-600 text-white' : 'text-slate-400 hover:text-white hover:bg-slate-800'
            }`}
          >
            All URLs ({totalUrls})
          </button>
          {highRiskCount > 0 && (
            <button
              onClick={() => setFilterLevel('high-risk')}
              className={`px-3 py-1.5 rounded-lg transition-colors ${
                filterLevel === 'high-risk'
                  ? 'bg-rose-600 text-white'
                  : 'text-rose-400 hover:text-rose-300 hover:bg-rose-950/30'
              }`}
            >
              High Risk ({highRiskCount})
            </button>
          )}
          {suspiciousCount > 0 && (
            <button
              onClick={() => setFilterLevel('suspicious')}
              className={`px-3 py-1.5 rounded-lg transition-colors ${
                filterLevel === 'suspicious'
                  ? 'bg-amber-600 text-white'
                  : 'text-amber-400 hover:text-amber-300 hover:bg-amber-950/30'
              }`}
            >
              Suspicious ({suspiciousCount})
            </button>
          )}
          {safeCount > 0 && (
            <button
              onClick={() => setFilterLevel('safe')}
              className={`px-3 py-1.5 rounded-lg transition-colors ${
                filterLevel === 'safe'
                  ? 'bg-emerald-600 text-white'
                  : 'text-emerald-400 hover:text-emerald-300 hover:bg-emerald-950/30'
              }`}
            >
              Safe ({safeCount})
            </button>
          )}
          {hasDisplayMismatch && (
            <button
              onClick={() => setFilterLevel('mismatch')}
              className={`px-3 py-1.5 rounded-lg transition-colors ${
                filterLevel === 'mismatch'
                  ? 'bg-rose-800 text-white font-bold'
                  : 'text-rose-300 hover:bg-rose-950/40'
              }`}
            >
              Anchor Mismatches Only
            </button>
          )}
        </div>

        <div className="text-xs text-slate-500">
          Showing {filteredUrls.length} of {totalUrls} items
        </div>
      </div>

      {/* URL Detail Cards List */}
      {filteredUrls.length === 0 ? (
        <div className="p-12 text-center bg-slate-900 border border-slate-800 rounded-xl">
          <Globe className="w-8 h-8 text-slate-600 mx-auto mb-2" />
          <p className="text-sm text-slate-400 font-medium">No URLs found matching current filter.</p>
        </div>
      ) : (
        <div className="space-y-4">
          {filteredUrls.map((url) => {
            const isHigh = url.riskLevel === 'high-risk';
            const isSuspicious = url.riskLevel === 'suspicious';

            return (
              <div
                key={url.id}
                className={`rounded-xl border p-5 transition-all ${
                  isHigh
                    ? 'bg-slate-900/90 border-rose-800/50 shadow-sm'
                    : isSuspicious
                    ? 'bg-slate-900/80 border-amber-800/40'
                    : 'bg-slate-900/60 border-slate-800'
                }`}
              >
                {/* Card Header: Risk Badge, Host, Actions */}
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-3 border-b border-slate-800/80">
                  <div className="flex items-center gap-2.5 flex-wrap">
                    <span
                      className={`px-2.5 py-1 rounded-md text-xs font-bold uppercase tracking-wider inline-flex items-center gap-1.5 ${
                        isHigh
                          ? 'bg-rose-500/20 text-rose-300 border border-rose-500/40'
                          : isSuspicious
                          ? 'bg-amber-500/20 text-amber-300 border border-amber-500/40'
                          : 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/40'
                      }`}
                    >
                      {isHigh ? <ShieldAlert className="w-3.5 h-3.5" /> : isSuspicious ? <AlertTriangle className="w-3.5 h-3.5" /> : <Shield className="w-3.5 h-3.5" />}
                      {url.riskLevel} (Risk: {url.riskScore}/100)
                    </span>

                    {url.isDisplayMismatch && (
                      <span className="px-2 py-0.5 rounded text-[11px] font-bold bg-rose-600 text-white">
                        SPOOFED ANCHOR TEXT
                      </span>
                    )}

                    {url.isPunycode && (
                      <span className="px-2 py-0.5 rounded text-[11px] font-mono bg-purple-500/20 text-purple-300 border border-purple-500/30">
                        IDN Punycode
                      </span>
                    )}

                    {url.typosquatMatch && (
                      <span className="px-2 py-0.5 rounded text-[11px] font-semibold bg-rose-900/50 text-rose-300 border border-rose-700/50">
                        Typosquat: {url.typosquatMatch.matchedBrand}
                      </span>
                    )}
                  </div>

                  {/* Copy IOC (Defanged) Button */}
                  <button
                    onClick={() => handleCopyDefanged(url)}
                    className="self-start sm:self-auto px-2.5 py-1 rounded-lg text-xs bg-slate-800 hover:bg-slate-700 text-slate-300 flex items-center gap-1.5 transition-colors"
                    title="Copy safe defanged URL format (hxxps://...)"
                  >
                    <Copy className="w-3.5 h-3.5" />
                    {copiedId === url.id ? 'Copied Defanged IOC!' : 'Copy Defanged URL'}
                  </button>
                </div>

                {/* Display Text vs Actual Href Comparison (If Mismatched) */}
                {url.isDisplayMismatch && (
                  <div className="my-3 p-3.5 rounded-lg bg-rose-950/40 border border-rose-800/60 text-xs">
                    <div className="text-[11px] font-bold uppercase tracking-wider text-rose-400 mb-2 flex items-center gap-1.5">
                      <AlertCircle className="w-3.5 h-3.5" /> Deceptive Visual Impersonation
                    </div>
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-2 font-mono">
                      <div className="p-2 rounded bg-slate-950/80 border border-slate-800">
                        <span className="text-slate-500 text-[10px] block font-sans uppercase font-bold">User Sees (Anchor Text):</span>
                        <span className="text-emerald-400 font-semibold break-all">{url.displayText}</span>
                      </div>
                      <div className="p-2 rounded bg-rose-950/60 border border-rose-800/80">
                        <span className="text-rose-400 text-[10px] block font-sans uppercase font-bold">Actual Target (Hidden Href):</span>
                        <span className="text-rose-200 font-bold break-all">{url.originalUrl}</span>
                      </div>
                    </div>
                  </div>
                )}

                {/* Target Destination & Path */}
                <div className="mt-3 text-xs space-y-2">
                  <div className="flex items-start gap-2">
                    <span className="font-semibold text-slate-400 min-w-24">Full URL:</span>
                    <span className="font-mono text-slate-200 break-all select-all">{url.originalUrl}</span>
                  </div>

                  <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 pt-2 text-[11px] font-mono">
                    <div className="p-2 rounded bg-slate-950/60 border border-slate-800">
                      <span className="text-slate-500 block">Domain:</span>
                      <span className="text-slate-200 truncate block font-bold">{url.domain}</span>
                    </div>

                    <div className="p-2 rounded bg-slate-950/60 border border-slate-800">
                      <span className="text-slate-500 block">Subdomains:</span>
                      <span className="text-slate-200 truncate block">
                        {url.subdomain ? `${url.subdomain} (${url.subdomainDepth} levels)` : 'none'}
                      </span>
                    </div>

                    <div className="p-2 rounded bg-slate-950/60 border border-slate-800">
                      <span className="text-slate-500 block">TLD / Type:</span>
                      <span className={`${url.isHighRiskTld ? 'text-rose-400 font-bold' : 'text-slate-200'}`}>
                        {url.isIpAddress ? 'IP Hostname' : `.${url.tld}`}
                      </span>
                    </div>

                    <div className="p-2 rounded bg-slate-950/60 border border-slate-800">
                      <span className="text-slate-500 block">Domain Age Signal:</span>
                      <span className="text-slate-300 truncate block">{url.estimatedDomainAgeCategory}</span>
                    </div>
                  </div>

                  {/* Redirect Chain simulation */}
                  {url.simulatedRedirectChain.length > 1 && (
                    <div className="mt-3 p-3 rounded-lg bg-slate-950/70 border border-slate-800 text-xs">
                      <div className="text-[11px] font-semibold text-indigo-400 uppercase tracking-wider mb-2 flex items-center gap-1.5">
                        <ExternalLink className="w-3.5 h-3.5" /> Simulated Redirect Hop Chain
                      </div>
                      <div className="space-y-1.5 font-mono text-[11px]">
                        {url.simulatedRedirectChain.map((hop, hIdx) => (
                          <div key={hIdx} className="flex items-center gap-2 text-slate-300 truncate">
                            <span className="text-slate-500">Hop {hIdx + 1}:</span>
                            <span className="text-indigo-300 truncate">{hop.url}</span>
                            {hop.status && (
                              <span className="px-1.5 py-0.2 rounded bg-slate-800 text-slate-400 text-[10px]">
                                HTTP {hop.status}
                              </span>
                            )}
                          </div>
                        ))}
                      </div>
                    </div>
                  )}

                  {/* Red flags list for this URL */}
                  {url.flags.length > 0 && (
                    <div className="mt-3 space-y-1.5">
                      {url.flags.map((flag) => (
                        <div
                          key={flag.id}
                          className={`px-3 py-1.5 rounded-lg text-xs flex items-center gap-2 ${
                            flag.severity === 'critical'
                              ? 'bg-rose-950/30 text-rose-200 border border-rose-900/40'
                              : 'bg-amber-950/20 text-amber-200 border border-amber-900/30'
                          }`}
                        >
                          <span
                            className={`w-1.5 h-1.5 rounded-full ${
                              flag.severity === 'critical' ? 'bg-rose-500' : 'bg-amber-500'
                            }`}
                          />
                          <span className="font-semibold">{flag.title}:</span>
                          <span className="text-slate-300">{flag.description}</span>
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
};
