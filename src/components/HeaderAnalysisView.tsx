import React, { useState } from 'react';
import {
  AlertOctagon,
  AlertTriangle,
  ArrowRight,
  CheckCircle2,
  ChevronDown,
  ChevronRight,
  Copy,
  Globe,
  Info,
  Layers,
  Mail,
  Network,
  Server,
  Shield,
  ShieldAlert,
  ShieldCheck,
  Terminal,
} from 'lucide-react';
import { HeaderAnalysisResult } from '../types';

interface HeaderAnalysisViewProps {
  headerAnalysis: HeaderAnalysisResult;
}

export const HeaderAnalysisView: React.FC<HeaderAnalysisViewProps> = ({ headerAnalysis }) => {
  const [showRawHeaders, setShowRawHeaders] = useState(false);
  const [rawFilter, setRawFilter] = useState('');
  const [copiedRaw, setCopiedRaw] = useState(false);

  const { headers, trustScore, trustLevel, flags, scoreBreakdown } = headerAnalysis;

  const handleCopyRaw = () => {
    navigator.clipboard.writeText(headers.rawText);
    setCopiedRaw(true);
    setTimeout(() => setCopiedRaw(false), 2000);
  };

  const getScoreColor = (score: number) => {
    if (score >= 80) return 'text-emerald-600 dark:text-emerald-400 border-emerald-500/30 bg-emerald-500/10';
    if (score >= 60) return 'text-blue-600 dark:text-blue-400 border-blue-500/30 bg-blue-500/10';
    if (score >= 35) return 'text-amber-600 dark:text-amber-400 border-amber-500/30 bg-amber-500/10';
    return 'text-rose-600 dark:text-rose-400 border-rose-500/30 bg-rose-500/10';
  };

  const getAuthBadge = (status: string) => {
    const s = status.toLowerCase();
    if (s === 'pass') {
      return (
        <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-md text-xs font-semibold bg-emerald-500/15 text-emerald-700 dark:text-emerald-300 border border-emerald-500/30">
          <CheckCircle2 className="w-3.5 h-3.5" /> PASS
        </span>
      );
    }
    if (s === 'fail') {
      return (
        <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-md text-xs font-semibold bg-rose-500/15 text-rose-700 dark:text-rose-300 border border-rose-500/30">
          <AlertOctagon className="w-3.5 h-3.5" /> FAIL
        </span>
      );
    }
    if (s === 'softfail') {
      return (
        <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-md text-xs font-semibold bg-amber-500/15 text-amber-700 dark:text-amber-300 border border-amber-500/30">
          <AlertTriangle className="w-3.5 h-3.5" /> SOFTFAIL
        </span>
      );
    }
    return (
      <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-md text-xs font-semibold bg-slate-500/15 text-slate-700 dark:text-slate-300 border border-slate-500/30">
        <Info className="w-3.5 h-3.5" /> {status.toUpperCase() || 'NONE'}
      </span>
    );
  };

  const filteredRawHeaders = (Object.entries(headers.rawHeaders) as [string, string[]][]).filter(([key, values]) => {
    if (!rawFilter) return true;
    const filter = rawFilter.toLowerCase();
    return key.toLowerCase().includes(filter) || values.some((v: string) => v.toLowerCase().includes(filter));
  });

  const fromDomain = headers.from?.domain.toLowerCase();
  const returnPathDomain = headers.returnPath?.domain.toLowerCase();
  const replyToDomain = headers.replyTo?.domain.toLowerCase();

  const isReturnPathMismatch = fromDomain && returnPathDomain && fromDomain !== returnPathDomain;
  const isReplyToMismatch = fromDomain && replyToDomain && fromDomain !== replyToDomain;

  return (
    <div className="space-y-6" id="header-analysis-module">
      {/* Top Banner: Trust Score & Core Summary */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-5">
        {/* Trust Score Card */}
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-sm flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between mb-3">
              <span className="text-xs font-semibold tracking-wider text-slate-400 uppercase">Header Trust Score</span>
              <span className={`px-2.5 py-0.5 rounded-full text-xs font-medium border ${getScoreColor(trustScore)}`}>
                {trustLevel}
              </span>
            </div>
            <div className="flex items-baseline gap-3 my-2">
              <span className="text-4xl font-bold tracking-tight text-white">{trustScore}</span>
              <span className="text-slate-500 text-sm">/ 100</span>
            </div>
            <p className="text-xs text-slate-400 mt-2">
              {trustScore >= 75
                ? 'Cryptographic signatures and sender address alignment indicate standard authenticated delivery.'
                : trustScore >= 40
                ? 'Anomalies detected in authentication or routing headers warrant review.'
                : 'Severe authentication failure or domain spoofing detected. High likelihood of header forgery.'}
            </p>
          </div>

          {/* Progress bar */}
          <div className="w-full bg-slate-800 h-2 rounded-full mt-4 overflow-hidden">
            <div
              className={`h-full transition-all duration-500 ${
                trustScore >= 75 ? 'bg-emerald-500' : trustScore >= 50 ? 'bg-amber-500' : 'bg-rose-500'
              }`}
              style={{ width: `${Math.max(5, trustScore)}%` }}
            />
          </div>
        </div>

        {/* Sender Identity Alignment Matrix */}
        <div className="lg:col-span-2 bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-sm">
          <h4 className="text-xs font-semibold tracking-wider text-slate-400 uppercase mb-3 flex items-center gap-2">
            <Mail className="w-3.5 h-3.5 text-indigo-400" /> Sender Identity Alignment Matrix
          </h4>

          <div className="space-y-2.5 text-xs">
            {/* From */}
            <div className="flex flex-col sm:flex-row sm:items-center justify-between p-2.5 rounded-lg bg-slate-950/60 border border-slate-800/80 gap-1.5">
              <div className="flex items-center gap-2 min-w-32 text-slate-400">
                <span className="font-medium text-slate-300">From (Visible):</span>
              </div>
              <div className="font-mono text-slate-200 truncate flex-1">
                {headers.from?.name ? (
                  <span>
                    <span className="text-indigo-300 font-semibold">{headers.from.name}</span> &lt;{headers.from.address}&gt;
                  </span>
                ) : (
                  headers.from?.address || <span className="text-rose-400 italic">Missing Header</span>
                )}
              </div>
              <span className="text-[11px] font-mono px-2 py-0.5 rounded bg-slate-800 text-slate-300">
                domain: {headers.from?.domain || 'unknown'}
              </span>
            </div>

            {/* Return-Path */}
            <div
              className={`flex flex-col sm:flex-row sm:items-center justify-between p-2.5 rounded-lg border gap-1.5 ${
                isReturnPathMismatch
                  ? 'bg-rose-950/20 border-rose-800/50'
                  : 'bg-slate-950/60 border-slate-800/80'
              }`}
            >
              <div className="flex items-center gap-2 min-w-32">
                <span className="font-medium text-slate-300">Return-Path:</span>
                {isReturnPathMismatch && (
                  <span className="text-[10px] px-1.5 py-0.2 rounded bg-rose-500/20 text-rose-300 font-bold">
                    MISMATCH
                  </span>
                )}
              </div>
              <div className="font-mono text-slate-200 truncate flex-1">
                {headers.returnPath?.address || <span className="text-slate-500 italic">None</span>}
              </div>
              <span className={`text-[11px] font-mono px-2 py-0.5 rounded ${isReturnPathMismatch ? 'bg-rose-900/40 text-rose-300 font-semibold' : 'bg-slate-800 text-slate-300'}`}>
                domain: {headers.returnPath?.domain || 'none'}
              </span>
            </div>

            {/* Reply-To */}
            <div
              className={`flex flex-col sm:flex-row sm:items-center justify-between p-2.5 rounded-lg border gap-1.5 ${
                isReplyToMismatch
                  ? 'bg-amber-950/20 border-amber-800/50'
                  : 'bg-slate-950/60 border-slate-800/80'
              }`}
            >
              <div className="flex items-center gap-2 min-w-32">
                <span className="font-medium text-slate-300">Reply-To:</span>
                {isReplyToMismatch && (
                  <span className="text-[10px] px-1.5 py-0.2 rounded bg-amber-500/20 text-amber-300 font-bold">
                    DIVERTED
                  </span>
                )}
              </div>
              <div className="font-mono text-slate-200 truncate flex-1">
                {headers.replyTo ? (
                  <span>
                    {headers.replyTo.name && `${headers.replyTo.name} `}&lt;{headers.replyTo.address}&gt;
                  </span>
                ) : (
                  <span className="text-slate-500 italic">Aligned with From (standard)</span>
                )}
              </div>
              {headers.replyTo && (
                <span className={`text-[11px] font-mono px-2 py-0.5 rounded ${isReplyToMismatch ? 'bg-amber-900/40 text-amber-300 font-semibold' : 'bg-slate-800 text-slate-300'}`}>
                  domain: {headers.replyTo.domain}
                </span>
              )}
            </div>
          </div>
        </div>
      </div>

      {/* Authentication Verification Suite (SPF, DKIM, DMARC) */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-5">
        <h4 className="text-xs font-semibold tracking-wider text-slate-400 uppercase mb-4 flex items-center gap-2">
          <Shield className="w-3.5 h-3.5 text-indigo-400" /> Email Authentication Framework (RFC 7601)
        </h4>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          {/* SPF */}
          <div className="p-4 rounded-lg bg-slate-950/70 border border-slate-800">
            <div className="flex items-center justify-between mb-2">
              <span className="text-sm font-bold text-white tracking-wide">SPF (Sender Policy)</span>
              {getAuthBadge(headers.spf.status)}
            </div>
            <p className="text-xs text-slate-400 min-h-10">
              {headers.spf.status === 'pass'
                ? 'Sending server IP is authorized by the domain DNS SPF TXT record.'
                : headers.spf.status === 'fail'
                ? 'Sending server IP is unauthorized. Hard fail indicates unauthorized transmission.'
                : headers.spf.status === 'softfail'
                ? 'Server IP is not listed in domain SPF record (~all weak policy).'
                : 'No SPF evaluation record found in authentication headers.'}
            </p>
            {headers.spf.domain && (
              <div className="mt-2 text-[11px] font-mono text-slate-300 bg-slate-900 p-1.5 rounded truncate border border-slate-800">
                domain: {headers.spf.domain}
              </div>
            )}
          </div>

          {/* DKIM */}
          <div className="p-4 rounded-lg bg-slate-950/70 border border-slate-800">
            <div className="flex items-center justify-between mb-2">
              <span className="text-sm font-bold text-white tracking-wide">DKIM (Digital Sig)</span>
              {getAuthBadge(headers.dkim.status)}
            </div>
            <p className="text-xs text-slate-400 min-h-10">
              {headers.dkim.status === 'pass'
                ? 'Cryptographic digital signature verified intact; body was not modified.'
                : headers.dkim.status === 'fail'
                ? 'Cryptographic signature verification failed or signature was broken.'
                : headers.dkim.status === 'neutral'
                ? headers.dkim.details || 'DKIM signature present but unverified by local MTA.'
                : 'Email is unsigned; no cryptographic DKIM signature found.'}
            </p>
            {headers.dkim.domain && (
              <div className="mt-2 text-[11px] font-mono text-slate-300 bg-slate-900 p-1.5 rounded truncate border border-slate-800">
                d={headers.dkim.domain}
              </div>
            )}
          </div>

          {/* DMARC */}
          <div className="p-4 rounded-lg bg-slate-950/70 border border-slate-800">
            <div className="flex items-center justify-between mb-2">
              <span className="text-sm font-bold text-white tracking-wide">DMARC (Domain Alignment)</span>
              {getAuthBadge(headers.dmarc.status)}
            </div>
            <p className="text-xs text-slate-400 min-h-10">
              {headers.dmarc.status === 'pass'
                ? 'Visible From domain aligns with authenticated SPF or DKIM identifier.'
                : headers.dmarc.status === 'fail'
                ? 'Failed alignment. Visible From domain differs from authenticated identity.'
                : 'No published DMARC policy or evaluation report found for domain.'}
            </p>
            {headers.dmarc.domain && (
              <div className="mt-2 text-[11px] font-mono text-slate-300 bg-slate-900 p-1.5 rounded truncate border border-slate-800">
                header.from={headers.dmarc.domain}
              </div>
            )}
          </div>
        </div>
      </div>

      {/* Header Flags & Inconsistencies */}
      {flags.length > 0 && (
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-5">
          <h4 className="text-xs font-semibold tracking-wider text-slate-400 uppercase mb-3 flex items-center gap-2">
            <ShieldAlert className="w-3.5 h-3.5 text-rose-400" /> Flagged Header Inconsistencies ({flags.length})
          </h4>
          <div className="space-y-3">
            {flags.map((flag) => (
              <div
                key={flag.id}
                className={`p-3.5 rounded-lg border text-xs ${
                  flag.severity === 'critical'
                    ? 'bg-rose-950/20 border-rose-800/40 text-rose-200'
                    : flag.severity === 'high'
                    ? 'bg-rose-950/15 border-rose-800/30 text-rose-200'
                    : 'bg-amber-950/15 border-amber-800/30 text-amber-200'
                }`}
              >
                <div className="flex items-center gap-2 font-bold mb-1">
                  <span
                    className={`px-1.5 py-0.5 rounded text-[10px] uppercase font-mono ${
                      flag.severity === 'critical' ? 'bg-rose-600 text-white' : 'bg-amber-600 text-white'
                    }`}
                  >
                    {flag.severity}
                  </span>
                  <span>{flag.title}</span>
                </div>
                <p className="text-slate-300 mt-1">{flag.description}</p>
                {flag.evidence && (
                  <div className="mt-2 font-mono text-[11px] bg-slate-950/80 p-2 rounded border border-slate-800/80 text-slate-300 overflow-x-auto">
                    Evidence: {flag.evidence}
                  </div>
                )}
                {flag.recommendation && (
                  <p className="mt-1.5 text-slate-400 italic">Recommendation: {flag.recommendation}</p>
                )}
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Received Chain Visualizer */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-5">
        <div className="flex items-center justify-between mb-4">
          <h4 className="text-xs font-semibold tracking-wider text-slate-400 uppercase flex items-center gap-2">
            <Network className="w-3.5 h-3.5 text-indigo-400" /> Received Chain Routing Timeline ({headers.receivedChain.length} Hops)
          </h4>
          <span className="text-[11px] text-slate-400">Chronological MTA Transit</span>
        </div>

        {headers.receivedChain.length === 0 ? (
          <p className="text-xs text-slate-500 italic p-4 text-center">No Received header hops available in the input.</p>
        ) : (
          <div className="space-y-3 relative before:absolute before:left-4 before:top-4 before:bottom-4 before:w-0.5 before:bg-slate-800">
            {headers.receivedChain.map((hop, idx) => {
              const isOrigin = idx === headers.receivedChain.length - 1;
              const isFinal = idx === 0;

              return (
                <div key={hop.index} className="relative pl-10">
                  {/* Circle indicator */}
                  <div
                    className={`absolute left-2.5 top-3 -translate-x-1/2 w-3.5 h-3.5 rounded-full border-2 bg-slate-950 ${
                      hop.isSuspiciousRelay
                        ? 'border-rose-500 bg-rose-500/20'
                        : isOrigin
                        ? 'border-indigo-400 bg-indigo-500/30'
                        : isFinal
                        ? 'border-emerald-400 bg-emerald-500/30'
                        : 'border-slate-600'
                    }`}
                  />

                  <div className="p-3 rounded-lg bg-slate-950/60 border border-slate-800 text-xs">
                    <div className="flex flex-wrap items-center justify-between gap-2 mb-1.5">
                      <div className="flex items-center gap-2">
                        <span className="font-bold text-slate-300">Hop #{hop.index}</span>
                        {isOrigin && (
                          <span className="px-1.5 py-0.2 rounded text-[10px] font-mono bg-indigo-500/20 text-indigo-300 font-semibold">
                            ORIGINATING RELAY
                          </span>
                        )}
                        {isFinal && (
                          <span className="px-1.5 py-0.2 rounded text-[10px] font-mono bg-emerald-500/20 text-emerald-300 font-semibold">
                            FINAL DESTINATION MTA
                          </span>
                        )}
                        {hop.isSuspiciousRelay && (
                          <span className="px-1.5 py-0.2 rounded text-[10px] font-mono bg-rose-500/20 text-rose-300 font-semibold">
                            ANOMALOUS IP
                          </span>
                        )}
                        {hop.isPrivateIp && (
                          <span className="px-1.5 py-0.2 rounded text-[10px] font-mono bg-slate-800 text-slate-400">
                            RFC1918 Private IP
                          </span>
                        )}
                      </div>
                      {hop.timestamp && <span className="text-[11px] text-slate-500 font-mono">{hop.timestamp}</span>}
                    </div>

                    <div className="grid grid-cols-1 md:grid-cols-2 gap-2 text-slate-300 font-mono text-[11px] mt-2">
                      <div className="p-1.5 rounded bg-slate-900/90 border border-slate-800/80 truncate">
                        <span className="text-slate-500">from: </span>
                        <span className="text-slate-200">{hop.fromHost || 'unknown'}</span>
                        {hop.fromIp && <span className="text-indigo-400 font-semibold"> [{hop.fromIp}]</span>}
                      </div>
                      <div className="p-1.5 rounded bg-slate-900/90 border border-slate-800/80 truncate">
                        <span className="text-slate-500">by: </span>
                        <span className="text-slate-200">{hop.byHost || 'unknown'}</span>
                        {hop.protocol && <span className="text-slate-400"> with {hop.protocol}</span>}
                      </div>
                    </div>
                  </div>
                </div>
              );
            })}
          </div>
        )}
      </div>

      {/* Raw Headers Drawer / Explorer */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden">
        <button
          onClick={() => setShowRawHeaders(!showRawHeaders)}
          className="w-full p-4 flex items-center justify-between text-left hover:bg-slate-800/40 transition-colors"
        >
          <div className="flex items-center gap-2">
            <Terminal className="w-4 h-4 text-indigo-400" />
            <span className="text-sm font-semibold text-white">Raw RFC 5322 Headers Explorer</span>
            <span className="text-xs text-slate-500">({Object.keys(headers.rawHeaders).length} fields)</span>
          </div>
          <div className="flex items-center gap-2">
            {showRawHeaders ? <ChevronDown className="w-4 h-4 text-slate-400" /> : <ChevronRight className="w-4 h-4 text-slate-400" />}
          </div>
        </button>

        {showRawHeaders && (
          <div className="p-4 border-t border-slate-800 space-y-3 bg-slate-950">
            <div className="flex flex-col sm:flex-row items-stretch sm:items-center justify-between gap-3">
              <input
                type="text"
                value={rawFilter}
                onChange={(e) => setRawFilter(e.target.value)}
                placeholder="Filter headers (e.g. dkim, received, subject)..."
                className="px-3 py-1.5 text-xs bg-slate-900 border border-slate-800 rounded-lg text-white focus:outline-none focus:border-indigo-500"
              />
              <button
                onClick={handleCopyRaw}
                className="px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-xs text-slate-200 flex items-center justify-center gap-1.5 transition-colors"
              >
                <Copy className="w-3.5 h-3.5" />
                {copiedRaw ? 'Copied to clipboard' : 'Copy All Headers'}
              </button>
            </div>

            <div className="max-h-96 overflow-y-auto font-mono text-xs text-slate-300 space-y-2 p-2 bg-slate-900/60 rounded-lg border border-slate-800">
              {filteredRawHeaders.length === 0 ? (
                <div className="text-slate-500 p-2 italic">No headers match filter</div>
              ) : (
                filteredRawHeaders.map(([key, values]) => (
                  <div key={key} className="border-b border-slate-800/60 pb-1.5 last:border-0">
                    <span className="text-indigo-400 font-semibold">{key}: </span>
                    <span className="text-slate-300 break-all">{values.join('; ')}</span>
                  </div>
                ))
              )}
            </div>
          </div>
        )}
      </div>
    </div>
  );
};
