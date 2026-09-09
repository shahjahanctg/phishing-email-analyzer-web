import {
  AnalyzedAttachment,
  AnalyzedUrl,
  ManualTriageFormState,
  TriageReport,
} from '../types';
import { analyzeAttachments } from './attachmentAnalyzer';
import { parseRawEmail } from './emailMimeParser';
import { analyzeHeaders } from './headerParser';
import { analyzeUrls, extractUrlsFromText } from './urlAnalyzer';

/**
 * Runs full triage analysis on raw RFC 5322 or .eml string
 */
export async function runFullTriage(
  rawInput: string,
  inputMode: 'eml' | 'raw_headers' | 'manual' = 'eml',
  extraAttachments: {
    filename: string;
    filesize?: number;
    contentType?: string;
    contentDisposition?: string;
    dataBuffer?: ArrayBuffer;
  }[] = []
): Promise<TriageReport> {
  const mimeParsed = parseRawEmail(rawInput);

  // 1. Analyze Headers
  const headerAnalysis = analyzeHeaders(mimeParsed.rawHeaders || rawInput);

  // 2. Extract & Analyze URLs
  const extractedUrls = extractUrlsFromText(mimeParsed.bodyText, mimeParsed.bodyHtml);
  const urlAnalysis = analyzeUrls(extractedUrls);

  // 3. Combine attachments from MIME parsing with any extra uploaded files
  const combinedAttachments = [...mimeParsed.attachments, ...extraAttachments];
  const attachmentAnalysis = await analyzeAttachments(combinedAttachments);

  // 4. Compute Overall Phishing Likelihood (0 - 100)
  // Higher score = Higher malicious likelihood
  let overallScore = 0;
  const keyRedFlags: string[] = [];

  // Factor A: Header trust score impact (Header trust is 0-100 where 100 is trusted, 0 is spoofed)
  // Header malicious weight: up to 35 points
  const headerRisk = Math.max(0, 100 - headerAnalysis.trustScore);
  overallScore += Math.round((headerRisk / 100) * 35);

  // Factor B: URL risk impact
  // Up to 40 points
  if (urlAnalysis.highRiskCount > 0) {
    overallScore += Math.min(40, urlAnalysis.highRiskCount * 25);
  } else if (urlAnalysis.suspiciousCount > 0) {
    overallScore += Math.min(25, urlAnalysis.suspiciousCount * 12);
  }

  // Factor C: Attachment risk impact
  // Up to 45 points
  if (attachmentAnalysis.dangerousCount > 0) {
    overallScore += Math.min(45, attachmentAnalysis.dangerousCount * 30 + 15);
  } else if (attachmentAnalysis.reviewCount > 0) {
    overallScore += Math.min(20, attachmentAnalysis.reviewCount * 10);
  }

  // Factor D: Critical synergies (e.g. Display text mismatch + SPF fail = immediate critical)
  if (urlAnalysis.hasDisplayMismatch && headerAnalysis.trustScore < 50) {
    overallScore += 15;
  }
  if (attachmentAnalysis.dangerousCount > 0 && headerAnalysis.trustScore < 40) {
    overallScore += 15;
  }

  overallScore = Math.max(0, Math.min(100, overallScore));

  // Collect prioritized key red flags
  if (urlAnalysis.hasDisplayMismatch) {
    keyRedFlags.push('Deceptive Link Spoofing: Displayed hyperlink text differs from destination href');
  }
  if (headerAnalysis.flags.some((f) => f.id === 'hdr-return-path-mismatch')) {
    keyRedFlags.push('Sender Domain Mismatch: Envelope Return-Path does not align with visible From address');
  }
  if (headerAnalysis.flags.some((f) => f.id === 'hdr-reply-to-mismatch')) {
    keyRedFlags.push('Reply-To Diversion: Responses redirected to an external third-party mailbox');
  }
  if (headerAnalysis.flags.some((f) => f.id === 'hdr-spf-fail' || f.id === 'hdr-dmarc-fail')) {
    keyRedFlags.push('Email Authentication Failure: SPF or DMARC policy validation explicitly failed');
  }
  if (urlAnalysis.urls.some((u) => u.typosquatMatch)) {
    const typo = urlAnalysis.urls.find((u) => u.typosquatMatch)?.typosquatMatch;
    keyRedFlags.push(`Brand Impersonation / Typosquatting: Destination mimics ${typo?.matchedBrand} (${typo?.targetDomain})`);
  }
  if (urlAnalysis.urls.some((u) => u.isPunycode)) {
    keyRedFlags.push('IDN Homoglyph Attack: Hostname contains punycode unicode deception');
  }
  if (attachmentAnalysis.attachments.some((a) => a.isDoubleExtension)) {
    keyRedFlags.push('Double Extension Deception: Attachment masks executable format with harmless secondary extension');
  }
  if (attachmentAnalysis.attachments.some((a) => a.isDangerousExtension)) {
    keyRedFlags.push('High-Risk Attachment: Email carries executable binary or weaponized script');
  }
  if (attachmentAnalysis.attachments.some((a) => a.isMacroEnabledDoc)) {
    keyRedFlags.push('VBA Macro Document: Office attachment configured to execute automated code');
  }
  if (attachmentAnalysis.attachments.some((a) => a.isPasswordProtectedArchive)) {
    keyRedFlags.push('Encrypted Archive: Password-protected archive bypasses perimeter scanner inspection');
  }

  // Determine Likelihood Category
  let phishingLikelihood: TriageReport['phishingLikelihood'] = 'Safe / Clean';
  let confidence: TriageReport['confidence'] = 'High';
  let verdictSummary = '';

  if (overallScore >= 75) {
    phishingLikelihood = 'Critical Risk';
    verdictSummary =
      'High-confidence malicious phishing or spear-phishing attack. Multiple critical indicators detect spoofing, fraudulent credentials harvesting, or weaponized payload delivery.';
  } else if (overallScore >= 50) {
    phishingLikelihood = 'High Risk';
    verdictSummary =
      'Significant phishing characteristics identified. Authentication inconsistencies or suspicious links warrant immediate quarantine and user warning.';
  } else if (overallScore >= 25) {
    phishingLikelihood = 'Moderate Risk';
    confidence = 'Medium';
    verdictSummary =
      'Suspicious anomalies detected. Elements like unaligned reply addresses or newly observed URL patterns require analyst review before release.';
  } else if (overallScore >= 10) {
    phishingLikelihood = 'Low Risk';
    confidence = 'Medium';
    verdictSummary =
      'Minor configuration issues observed (e.g. missing optional headers or generic tracking links), but no active malware or credential deception detected.';
  } else {
    phishingLikelihood = 'Safe / Clean';
    verdictSummary =
      'Legitimate correspondence profile. SPF, DKIM, and DMARC alignment verified, and all embedded links point to authentic infrastructure.';
  }

  return {
    timestamp: new Date().toISOString(),
    analyzedEmailSubject: mimeParsed.subject || headerAnalysis.headers.subject || 'Untitled / No Subject',
    overallScore,
    phishingLikelihood,
    confidence,
    verdictSummary,
    keyRedFlags,
    headerAnalysis,
    urlAnalysis,
    attachmentAnalysis,
    emailBodyText: mimeParsed.bodyText,
    emailBodyHtml: mimeParsed.bodyHtml,
    rawInput,
    inputMode,
  };
}

/**
 * Runs triage on structured manual form input
 */
export async function runManualTriage(form: ManualTriageFormState): Promise<TriageReport> {
  // Construct a synthetic RFC 5322 header block
  const lines: string[] = [];
  if (form.from) lines.push(`From: ${form.from}`);
  if (form.returnPath) lines.push(`Return-Path: <${form.returnPath}>`);
  if (form.replyTo) lines.push(`Reply-To: ${form.replyTo}`);
  if (form.subject) lines.push(`Subject: ${form.subject}`);
  if (form.date) lines.push(`Date: ${form.date}`);
  lines.push(`Message-ID: <manual-triage-${Date.now()}@analyst.local>`);

  // Synthesize Authentication-Results
  const authParts: string[] = [];
  if (form.spfResult) authParts.push(`spf=${form.spfResult}`);
  if (form.dkimResult) authParts.push(`dkim=${form.dkimResult}`);
  if (form.dmarcResult) authParts.push(`dmarc=${form.dmarcResult}`);
  if (authParts.length > 0) {
    lines.push(`Authentication-Results: mx.local; ${authParts.join(' ')}`);
  }

  // Received hops
  if (form.receivedHopsText) {
    const rawHops = form.receivedHopsText.split('\n').filter((l) => l.trim());
    rawHops.forEach((hop) => {
      lines.push(`Received: ${hop.trim()}`);
    });
  }

  const rawHeaders = lines.join('\r\n');
  const syntheticEmail = `${rawHeaders}\r\n\r\n${form.bodyText}\r\n\r\n${form.urlsList}`;

  // Parse custom attachments from list
  const attachmentsToAnalyze: { filename: string; filesize?: number }[] = [];
  if (form.attachmentsList && form.attachmentsList.trim()) {
    form.attachmentsList
      .split('\n')
      .map((l) => l.trim())
      .filter(Boolean)
      .forEach((line) => {
        // May have format: filename, 12345
        const parts = line.split(',');
        const filename = parts[0].trim();
        const size = parts[1] ? parseInt(parts[1].trim(), 10) : undefined;
        attachmentsToAnalyze.push({ filename, filesize: size });
      });
  }

  return runFullTriage(syntheticEmail, 'manual', attachmentsToAnalyze);
}

/**
 * Generates an executive Markdown report for SOC/SIEM ticket pasting
 */
export function generateMarkdownReport(report: TriageReport): string {
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
  } = report;

  const h = headerAnalysis.headers;

  return `# 🛡️ Phishing Incident Triage Report
**Generated:** ${new Date(timestamp).toUTCString()}
**Analyst Engine:** Rule-Based Deterministic Triage Engine v1.0
**Target Subject:** \`${analyzedEmailSubject || 'N/A'}\`

---

## 🎯 Executive Verdict
- **Phishing Likelihood:** **${phishingLikelihood.toUpperCase()}** (Score: ${overallScore}/100)
- **Classification Confidence:** ${confidence}
- **Summary:** ${verdictSummary}

${
  keyRedFlags.length > 0
    ? `### 🚨 Prioritized Red Flags
${keyRedFlags.map((flag) => `- [!] **${flag}**`).join('\n')}
`
    : '*(No critical red flags detected)*'
}

---

## 1. Header Analysis (Trust Score: ${headerAnalysis.trustScore}/100 - ${headerAnalysis.trustLevel})
- **From:** \`${h.from?.name ? `${h.from.name} <${h.from.address}>` : h.from?.address || 'Missing'}\`
- **Return-Path:** \`${h.returnPath?.address || 'Missing'}\`
- **Reply-To:** \`${h.replyTo?.address || 'None (Defaults to From)'}\`
- **Message-ID:** \`${h.messageId || 'Missing'}\`
- **Authentication Results:**
  - **SPF:** \`${h.spf.status.toUpperCase()}\` ${h.spf.details ? `(${h.spf.details})` : ''}
  - **DKIM:** \`${h.dkim.status.toUpperCase()}\` ${h.dkim.domain ? `(d=${h.dkim.domain})` : ''}
  - **DMARC:** \`${h.dmarc.status.toUpperCase()}\`
- **Received Hop Count:** ${h.receivedChain.length} hop(s)
${
  headerAnalysis.flags.length > 0
    ? `\n**Header Anomalies:**
${headerAnalysis.flags.map((f) => `- [${f.severity.toUpperCase()}] **${f.title}**: ${f.description}`).join('\n')}`
    : ''
}

---

## 2. URL & Link Analysis (${urlAnalysis.totalUrls} URLs evaluated)
- **High-Risk URLs:** ${urlAnalysis.highRiskCount}
- **Suspicious URLs:** ${urlAnalysis.suspiciousCount}
- **Clean / Safe URLs:** ${urlAnalysis.safeCount}
- **Anchor Text Mismatches:** ${urlAnalysis.hasDisplayMismatch ? 'YES (Deception Found)' : 'None'}

${
  urlAnalysis.urls.length > 0
    ? `| Risk Level | Display Text | Actual Destination | Signals / Reason |
|:---|:---|:---|:---|
${urlAnalysis.urls
  .map(
    (u: AnalyzedUrl) =>
      `| **${u.riskLevel.toUpperCase()}** | \`${u.displayText || '(same)'}\` | \`${u.hostname}${u.path.slice(0, 30)}\` | ${u.flags.map((f) => f.title).join('; ') || 'Clean'} |`
  )
  .join('\n')}`
    : '*(No URLs found in email body)*'
}

---

## 3. Attachment Analysis (${attachmentAnalysis.totalAttachments} attachment(s))
- **Dangerous:** ${attachmentAnalysis.dangerousCount}
- **Review Needed:** ${attachmentAnalysis.reviewCount}
- **Safe:** ${attachmentAnalysis.safeCount}

${
  attachmentAnalysis.attachments.length > 0
    ? `| Risk | Filename | Primary Ext | Double Ext? | SHA-256 Hash | Flags |
|:---|:---|:---|:---|:---|:---|
${attachmentAnalysis.attachments
  .map(
    (a: AnalyzedAttachment) =>
      `| **${a.riskLevel.toUpperCase()}** | \`${a.filename}\` | \`.${a.primaryExtension}\` | ${a.isDoubleExtension ? '⚠️ YES' : 'No'} | \`${a.sha256?.slice(0, 16)}...\` | ${a.detectedIndicators.join(', ') || 'Standard'} |`
  )
  .join('\n')}`
    : '*(No attachments detected in email)*'
}

---
*Report generated securely by client-side deterministic inspection sandbox.*
`;
}
