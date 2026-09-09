import { AnalyzedUrl, RedirectHop, RiskFlag, TyposquatMatch, UrlAnalysisResult } from '../types';

// Top targeted brands in phishing campaigns
const MONITORED_BRANDS: { name: string; domain: string; keywords: string[] }[] = [
  { name: 'Microsoft', domain: 'microsoft.com', keywords: ['microsoft', 'office365', 'outlook', 'onedrive', 'azure', 'sharepoint', 'teams', 'live.com'] },
  { name: 'Google', domain: 'google.com', keywords: ['google', 'gmail', 'googleworkspace', 'drive'] },
  { name: 'PayPal', domain: 'paypal.com', keywords: ['paypal', 'paypal-me'] },
  { name: 'Apple', domain: 'apple.com', keywords: ['apple', 'icloud', 'appleid'] },
  { name: 'Amazon', domain: 'amazon.com', keywords: ['amazon', 'aws', 'prime'] },
  { name: 'Netflix', domain: 'netflix.com', keywords: ['netflix'] },
  { name: 'Chase Bank', domain: 'chase.com', keywords: ['chase', 'chaseonline'] },
  { name: 'Bank of America', domain: 'bankofamerica.com', keywords: ['bankofamerica', 'bofa'] },
  { name: 'Wells Fargo', domain: 'wellsfargo.com', keywords: ['wellsfargo'] },
  { name: 'DHL Express', domain: 'dhl.com', keywords: ['dhl', 'dhlexpress'] },
  { name: 'FedEx', domain: 'fedex.com', keywords: ['fedex'] },
  { name: 'USPS', domain: 'usps.com', keywords: ['usps', 'postal-service'] },
  { name: 'DocuSign', domain: 'docusign.com', keywords: ['docusign'] },
  { name: 'Adobe', domain: 'adobe.com', keywords: ['adobe', 'acrobat'] },
  { name: 'Coinbase', domain: 'coinbase.com', keywords: ['coinbase'] },
  { name: 'Binance', domain: 'binance.com', keywords: ['binance'] },
  { name: 'LinkedIn', domain: 'linkedin.com', keywords: ['linkedin'] },
  { name: 'Facebook / Meta', domain: 'facebook.com', keywords: ['facebook', 'instagram', 'meta'] },
  { name: 'Dropbox', domain: 'dropbox.com', keywords: ['dropbox'] },
  { name: 'Internal Revenue Service (IRS)', domain: 'irs.gov', keywords: ['irs', 'tax-refund'] },
];

// Well-known trusted apex domains that get instant safe classification unless path is anomalous
const TRUSTED_DOMAINS = new Set([
  'google.com', 'microsoft.com', 'apple.com', 'amazon.com', 'paypal.com',
  'netflix.com', 'github.com', 'linkedin.com', 'cloudflare.com', 'twitter.com',
  'x.com', 'youtube.com', 'wikipedia.org', 'adobe.com', 'chase.com',
]);

// Known high-abuse or high-risk TLDs frequently seen in bulk phishing
const HIGH_RISK_TLDS = new Set([
  'xyz', 'top', 'work', 'click', 'buzz', 'live', 'icu', 'gq', 'tk', 'ml', 'cf',
  'fit', 'surf', 'rest', 'bid', 'monster', 'hair', 'quest', 'cfd', 'cam', 'country',
  'stream', 'party', 'date', 'faith', 'racing', 'download', 'review', 'trade', 'loan',
]);

// Known URL shorteners
const SHORTENER_DOMAINS = new Set([
  'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'is.gd', 'buff.ly', 'ow.ly',
  'rebrand.ly', 'cutt.ly', 'shorturl.at', 'bl.ink', 't.ly', 'linktr.ee',
]);

// Sensitive phishing keywords in path or query
const SENSITIVE_KEYWORDS = [
  'login', 'signin', 'sign-in', 'log-in', 'verify', 'verification', 'authenticate',
  'account-update', 'billing', 'update-password', 'reset-password', 'confirm-identity',
  'secure-check', 'wallet', 'suspend', 'urgent-action', 'session-expired', 'reactivate',
  'webscr', 'cmd=_login-run', 'auth', 'authorize', 'recovery',
];

/**
 * Levenshtein distance calculation for string similarity
 */
function levenshteinDistance(s1: string, s2: string): number {
  const m = s1.length;
  const n = s2.length;
  const dp: number[][] = Array.from({ length: m + 1 }, () => Array(n + 1).fill(0));

  for (let i = 0; i <= m; i++) dp[i][0] = i;
  for (let j = 0; j <= n; j++) dp[0][j] = j;

  for (let i = 1; i <= m; i++) {
    for (let j = 1; j <= n; j++) {
      const cost = s1[i - 1] === s2[j - 1] ? 0 : 1;
      dp[i][j] = Math.min(
        dp[i - 1][j] + 1, // deletion
        dp[i][j - 1] + 1, // insertion
        dp[i - 1][j - 1] + cost // substitution
      );
    }
  }

  return dp[m][n];
}

/**
 * Checks typosquatting and combosquatting against known targeted brands
 */
function checkTyposquatting(domain: string, host: string): TyposquatMatch | undefined {
  const normalizedDomain = domain.toLowerCase();
  const domainNoTld = normalizedDomain.split('.')[0];
  const fullHost = host.toLowerCase();

  for (const brand of MONITORED_BRANDS) {
    const brandName = brand.keywords[0];
    const brandApex = brand.domain.split('.')[0];

    // If it is the legitimate apex domain, no typosquatting
    if (normalizedDomain === brand.domain || normalizedDomain.endsWith('.' + brand.domain)) {
      continue;
    }

    // 1. Check Subdomain Spoofing (e.g. login.paypal.com.evil-server.net)
    if (fullHost.includes(brandApex) && !fullHost.endsWith('.' + brand.domain)) {
      // It has the brand inside subdomains or domain name, but terminates in an external apex!
      return {
        matchedBrand: brand.name,
        targetDomain: brand.domain,
        similarity: 0.95,
        technique: 'subdomain_spoof',
      };
    }

    // 2. Check Combosquatting (e.g. paypal-security-verify.com, microsoft-login.xyz)
    if (domainNoTld.includes(brandApex) && domainNoTld !== brandApex) {
      return {
        matchedBrand: brand.name,
        targetDomain: brand.domain,
        similarity: 0.9,
        technique: 'combosquatting',
      };
    }

    // 3. Check Levenshtein distance for close typos (e.g. paypa1, micros0ft, appie)
    // Replace typical leetspeak substitutions
    const deobfuscated = domainNoTld
      .replace(/0/g, 'o')
      .replace(/1/g, 'l')
      .replace(/vv/g, 'w')
      .replace(/rn/g, 'm');

    const dist = levenshteinDistance(deobfuscated, brandApex);
    if (dist > 0 && dist <= 2 && Math.abs(deobfuscated.length - brandApex.length) <= 2) {
      return {
        matchedBrand: brand.name,
        targetDomain: brand.domain,
        similarity: 1 - dist / Math.max(deobfuscated.length, brandApex.length),
        technique: 'levenshtein',
      };
    }
  }

  return undefined;
}

/**
 * Decodes punycode ASCII representation (e.g. xn--...) to UTF-8
 */
function decodePunycodeSafe(host: string): { isPunycode: boolean; decoded?: string } {
  if (!host.includes('xn--')) {
    return { isPunycode: false };
  }
  try {
    // If browser supports URL with unicode
    const decoded = new URL(`http://${host}`).hostname;
    return { isPunycode: true, decoded };
  } catch {
    return { isPunycode: true, decoded: host };
  }
}

/**
 * Safe client-side redirect chain analyzer:
 * Detects URL parameters carrying redirect targets (e.g., ?url=, ?redirect=, ?dest=) or base64 redirects
 */
function simulateRedirectChain(initialUrl: string, isShortener: boolean): { chain: RedirectHop[]; finalDestination: string } {
  const chain: RedirectHop[] = [{ url: initialUrl, reason: 'Initial link from email' }];
  let currentUrl = initialUrl;

  try {
    const parsed = new URL(currentUrl);

    // Look for common redirect query parameters
    const redirectKeys = ['url', 'redirect', 'target', 'dest', 'destination', 'goto', 'link', 'u', 'next', 'r'];
    for (const key of redirectKeys) {
      const val = parsed.searchParams.get(key);
      if (val) {
        let candidate = val;
        // Check if base64 encoded URL
        if (/^[a-zA-Z0-9+/=]{16,}$/.test(val)) {
          try {
            const decoded = atob(val);
            if (decoded.startsWith('http://') || decoded.startsWith('https://')) {
              candidate = decoded;
            }
          } catch {
            // not base64
          }
        }

        if (candidate.startsWith('http://') || candidate.startsWith('https://')) {
          chain.push({
            url: candidate,
            status: 302,
            reason: `Query parameter '${key}' redirect target`,
          });
          currentUrl = candidate;
          break;
        }
      }
    }

    // If it's a known URL shortener, simulate unshortening
    if (isShortener && chain.length === 1) {
      chain.push({
        url: `${currentUrl} -> [Simulated shortener uncloak target]`,
        status: 301,
        reason: 'HTTP 301 Permanent Redirect via Shortener service',
      });
    }
  } catch {
    // ignore parse error
  }

  return {
    chain,
    finalDestination: currentUrl,
  };
}

/**
 * Extract raw URLs and HTML anchor tags with display text from email text
 */
export function extractUrlsFromText(bodyText: string, bodyHtml?: string): { url: string; displayText?: string }[] {
  const collected: { url: string; displayText?: string }[] = [];
  const seenUrls = new Set<string>();

  // 1. Extract from HTML if available (<a href="..." ...>display text</a>)
  if (bodyHtml) {
    const anchorRegex = /<a\s+(?:[^>]*?\s+)?href=["']([^"']+)["'][^>]*>([\s\S]*?)<\/a>/gi;
    let match: RegExpExecArray | null;
    while ((match = anchorRegex.exec(bodyHtml)) !== null) {
      const rawHref = match[1].trim();
      const rawText = match[2].replace(/<[^>]*>?/gm, '').trim(); // strip inner tags

      if (rawHref.startsWith('http://') || rawHref.startsWith('https://')) {
        collected.push({ url: rawHref, displayText: rawText || undefined });
        seenUrls.add(rawHref);
      }
    }
  }

  // 2. Extract Markdown links: [display text](url)
  const mdRegex = /\[([^\]]+)\]\((https?:\/\/[^\s\)]+)\)/g;
  let mdMatch: RegExpExecArray | null;
  while ((mdMatch = mdRegex.exec(bodyText)) !== null) {
    const displayText = mdMatch[1].trim();
    const url = mdMatch[2].trim();
    if (!seenUrls.has(url)) {
      collected.push({ url, displayText });
      seenUrls.add(url);
    }
  }

  // 3. Extract plain text URLs: https?://...
  const urlRegex = /(https?:\/\/[^\s<>"'{}|\\^`\[\]]+)/gi;
  let textMatch: RegExpExecArray | null;
  while ((textMatch = urlRegex.exec(bodyText)) !== null) {
    let url = textMatch[1].trim();
    // Strip trailing punctuation like . , ; )
    url = url.replace(/[.,;:)\]]+$/, '');

    if (!seenUrls.has(url)) {
      collected.push({ url });
      seenUrls.add(url);
    }
  }

  return collected;
}

/**
 * Analyzes an individual URL for phishing, typosquatting, spoofing, and evasion techniques
 */
export function analyzeSingleUrl(
  inputUrl: string,
  displayText?: string,
  index = 0
): AnalyzedUrl {
  const flags: RiskFlag[] = [];
  let riskScore = 0;

  let normalizedUrl = inputUrl.trim();
  let parsed: URL;
  let hostname = '';
  let protocol = 'http:';
  let path = '/';
  let searchParams: Record<string, string> = {};

  try {
    parsed = new URL(normalizedUrl);
    hostname = parsed.hostname.toLowerCase();
    protocol = parsed.protocol.toLowerCase();
    path = parsed.pathname;
    parsed.searchParams.forEach((v, k) => {
      searchParams[k] = v;
    });
  } catch {
    // If malformed, treat as high risk
    return {
      id: `url-${index}`,
      originalUrl: inputUrl,
      normalizedUrl: inputUrl,
      displayText,
      isDisplayMismatch: false,
      protocol: 'unknown',
      hostname: 'invalid-url',
      domain: 'invalid-url',
      subdomain: '',
      subdomainDepth: 0,
      tld: '',
      path: '',
      searchParams: {},
      isIpAddress: false,
      isPunycode: false,
      isShortener: false,
      simulatedRedirectChain: [{ url: inputUrl, reason: 'Malformed URL' }],
      finalDestination: inputUrl,
      isHighRiskTld: false,
      hasPhishingKeywords: false,
      flaggedKeywords: [],
      estimatedDomainAgeCategory: 'fresh / suspicious (< 30 days)',
      riskScore: 85,
      riskLevel: 'high-risk',
      flags: [
        {
          id: `malformed-url-${index}`,
          category: 'url',
          severity: 'high',
          title: 'Malformed or Unparsable URL',
          description: 'The URL does not conform to RFC 3986 URI standards, often used to bypass filters.',
          evidence: inputUrl,
        },
      ],
    };
  }

  // Domain & Subdomain decomposition
  const isIp = /^(\d{1,3}\.){3}\d{1,3}$/.test(hostname) || /^\[?[0-9a-fA-F:]+\]?$/.test(hostname);
  const hostParts = hostname.split('.');
  const tld = isIp ? '' : hostParts.slice(-1)[0] || '';
  const domain = isIp ? hostname : hostParts.slice(-2).join('.');
  const subdomain = isIp ? '' : hostParts.slice(0, -2).join('.');
  const subdomainDepth = subdomain ? subdomain.split('.').length : 0;

  // 1. DISPLAY TEXT VS ACTUAL HREF MISMATCH (Major Phishing Indicator)
  let isDisplayMismatch = false;
  let mismatchReason: string | undefined;

  if (displayText && displayText.trim()) {
    const cleanDisplay = displayText.trim().toLowerCase();
    // Check if display text pretends to be a domain or URL
    if (
      cleanDisplay.startsWith('http://') ||
      cleanDisplay.startsWith('https://') ||
      cleanDisplay.startsWith('www.') ||
      cleanDisplay.includes('.com') ||
      cleanDisplay.includes('.org') ||
      cleanDisplay.includes('.gov') ||
      cleanDisplay.includes('.net') ||
      cleanDisplay.includes('.edu')
    ) {
      // Extract apparent host from display text
      const apparentHostMatch = cleanDisplay.match(/(?:https?:\/\/)?(?:www\.)?([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/);
      if (apparentHostMatch) {
        const apparentHost = apparentHostMatch[1];
        if (!hostname.includes(apparentHost) && !apparentHost.includes(hostname)) {
          isDisplayMismatch = true;
          mismatchReason = `Link visually displays '${displayText}', but covertly navigates to '${hostname}'.`;
          riskScore += 45;
          flags.push({
            id: `url-mismatch-${index}`,
            category: 'url',
            severity: 'critical',
            title: 'Visual Anchor Text / Destination Mismatch',
            description: mismatchReason,
            evidence: `Display: ${displayText} | Actual Target: ${inputUrl}`,
            recommendation: 'Classic spear-phishing deception tactic. Never click this hyperlink.',
          });
        }
      }
    }
  }

  // 2. IP ADDRESS HOSTNAME DETECTION
  if (isIp) {
    riskScore += 35;
    flags.push({
      id: `url-ip-host-${index}`,
      category: 'url',
      severity: 'high',
      title: 'Direct IP Hostname Used',
      description: `URL points directly to an IP address (${hostname}) instead of a registered domain name, frequently used to evade domain reputation filters and DNS sinkholes.`,
      evidence: hostname,
    });
  }

  // 3. PUNYCODE / HOMOGRAPH ATTACK DETECTION
  const punycodeInfo = decodePunycodeSafe(hostname);
  if (punycodeInfo.isPunycode) {
    riskScore += 40;
    flags.push({
      id: `url-punycode-${index}`,
      category: 'url',
      severity: 'critical',
      title: 'Punycode / IDN Homoglyph Attack Detected',
      description: `Domain uses internationalized punycode encoding (${hostname}) which may appear identical to authentic characters (e.g. Cyrillic 'a' vs Latin 'a'). Decoded form: ${punycodeInfo.decoded}`,
      evidence: `${hostname} -> ${punycodeInfo.decoded}`,
    });
  }

  // 4. TYPOSQUATTING & COMBOSQUATTING
  const typosquatMatch = checkTyposquatting(domain, hostname);
  if (typosquatMatch) {
    riskScore += 40;
    flags.push({
      id: `url-typosquat-${index}`,
      category: 'url',
      severity: 'critical',
      title: `Brand Impersonation / Typosquatting (${typosquatMatch.matchedBrand})`,
      description: `The hostname closely mimics legitimate brand domain '${typosquatMatch.targetDomain}' using ${typosquatMatch.technique.replace('_', ' ')}. Similarity: ${Math.round(typosquatMatch.similarity * 100)}%.`,
      evidence: `Target: ${hostname} mimics ${typosquatMatch.targetDomain}`,
      recommendation: 'Immediate block. Highly targeted credential harvesting attack.',
    });
  }

  // 5. EXCESSIVE SUBDOMAIN DEPTH
  if (subdomainDepth >= 3) {
    riskScore += 20;
    flags.push({
      id: `url-deep-subdomains-${index}`,
      category: 'url',
      severity: 'medium',
      title: `Excessive Subdomain Depth (${subdomainDepth} levels)`,
      description: `Host contains ${subdomainDepth} nested subdomains (${subdomain}), a common evasion technique to pad strings and hide the real apex domain in mobile browsers.`,
      evidence: hostname,
    });
  }

  // 6. HIGH-RISK TLD
  const isHighRiskTld = HIGH_RISK_TLDS.has(tld.toLowerCase());
  if (isHighRiskTld) {
    riskScore += 20;
    flags.push({
      id: `url-risky-tld-${index}`,
      category: 'url',
      severity: 'medium',
      title: `High-Risk Top-Level Domain (.${tld})`,
      description: `The .${tld} TLD has statistically elevated rates of spam, bulletproof hosting, and malicious infrastructure.`,
      evidence: `.${tld}`,
    });
  }

  // 7. PHISHING SENSITIVE KEYWORDS
  const flaggedKeywords: string[] = [];
  const fullUrlLower = normalizedUrl.toLowerCase();
  for (const kw of SENSITIVE_KEYWORDS) {
    if (fullUrlLower.includes(kw)) {
      flaggedKeywords.push(kw);
    }
  }

  const hasPhishingKeywords = flaggedKeywords.length > 0;
  if (flaggedKeywords.length >= 2) {
    riskScore += 20;
    flags.push({
      id: `url-keywords-${index}`,
      category: 'url',
      severity: 'medium',
      title: 'Suspicious Authentication / Urgency Keywords in URL',
      description: `URL path/query includes sensitive tokens commonly targeted in phishing lures: ${flaggedKeywords.slice(0, 4).join(', ')}.`,
      evidence: flaggedKeywords.join(', '),
    });
  } else if (flaggedKeywords.length === 1 && (isHighRiskTld || isIp || typosquatMatch)) {
    riskScore += 15;
  }

  // 8. URL SHORTENER DETECTION & REDIRECT SIMULATION
  const isShortener = SHORTENER_DOMAINS.has(domain.toLowerCase()) || SHORTENER_DOMAINS.has(hostname);
  if (isShortener) {
    riskScore += 15;
    flags.push({
      id: `url-shortener-${index}`,
      category: 'url',
      severity: 'low',
      title: 'URL Shortening Service Employed',
      description: 'The link obscures the true target destination using a public URL redirection shortener.',
      evidence: domain,
    });
  }

  const redirectResult = simulateRedirectChain(normalizedUrl, isShortener);

  // 9. INSECURE PROTOCOL FOR AUTHENTICATION
  if (protocol === 'http:' && (hasPhishingKeywords || typosquatMatch)) {
    riskScore += 15;
    flags.push({
      id: `url-unencrypted-auth-${index}`,
      category: 'url',
      severity: 'medium',
      title: 'Cleartext HTTP Used for Sensitive Destination',
      description: 'The link uses unencrypted http:// rather than TLS/HTTPS, inconsistent with authentic enterprise login portals.',
    });
  }

  // 10. DOMAIN AGE ESTIMATION
  let estimatedDomainAgeCategory: AnalyzedUrl['estimatedDomainAgeCategory'] = 'established (> 1 year)';
  if (isHighRiskTld || isIp || punycodeInfo.isPunycode || (typosquatMatch && !TRUSTED_DOMAINS.has(domain))) {
    estimatedDomainAgeCategory = 'fresh / suspicious (< 30 days)';
  } else if (subdomainDepth >= 3 || isShortener) {
    estimatedDomainAgeCategory = 'unknown / dynamic';
  } else if (!TRUSTED_DOMAINS.has(domain)) {
    estimatedDomainAgeCategory = 'medium age (< 1 year)';
  }

  // If domain is known trusted and no severe flags, scale risk down
  if (TRUSTED_DOMAINS.has(domain) && !isDisplayMismatch && !punycodeInfo.isPunycode) {
    riskScore = Math.min(riskScore, 10);
  }

  // Clamp risk score
  riskScore = Math.max(0, Math.min(100, riskScore));

  let riskLevel: AnalyzedUrl['riskLevel'] = 'safe';
  if (riskScore >= 60) {
    riskLevel = 'high-risk';
  } else if (riskScore >= 25) {
    riskLevel = 'suspicious';
  }

  return {
    id: `url-${index}`,
    originalUrl: inputUrl,
    normalizedUrl,
    displayText,
    isDisplayMismatch,
    mismatchReason,
    protocol,
    hostname,
    domain,
    subdomain,
    subdomainDepth,
    tld,
    path,
    searchParams,
    isIpAddress: isIp,
    isPunycode: punycodeInfo.isPunycode,
    punycodeDecoded: punycodeInfo.decoded,
    isShortener,
    simulatedRedirectChain: redirectResult.chain,
    finalDestination: redirectResult.finalDestination,
    typosquatMatch,
    isHighRiskTld,
    hasPhishingKeywords,
    flaggedKeywords,
    estimatedDomainAgeCategory,
    riskScore,
    riskLevel,
    flags,
  };
}

/**
 * Analyzes a collection of URLs from an email
 */
export function analyzeUrls(extracted: { url: string; displayText?: string }[]): UrlAnalysisResult {
  const analyzedUrls: AnalyzedUrl[] = [];
  const globalFlags: RiskFlag[] = [];

  extracted.forEach((item, index) => {
    const res = analyzeSingleUrl(item.url, item.displayText, index);
    analyzedUrls.push(res);
  });

  const totalUrls = analyzedUrls.length;
  const highRiskCount = analyzedUrls.filter((u) => u.riskLevel === 'high-risk').length;
  const suspiciousCount = analyzedUrls.filter((u) => u.riskLevel === 'suspicious').length;
  const safeCount = analyzedUrls.filter((u) => u.riskLevel === 'safe').length;
  const hasDisplayMismatch = analyzedUrls.some((u) => u.isDisplayMismatch);

  if (hasDisplayMismatch) {
    globalFlags.push({
      id: 'urls-summary-mismatch',
      category: 'url',
      severity: 'critical',
      title: 'Deceptive Display-vs-Href Links Detected',
      description: 'One or more URLs in this email display a trusted brand in visible text while leading to external attacker infrastructure.',
    });
  }

  if (highRiskCount > 0) {
    globalFlags.push({
      id: 'urls-summary-high-risk',
      category: 'url',
      severity: 'high',
      title: `${highRiskCount} High-Risk Phishing URL(s) Identified`,
      description: 'Automated heuristics detected dangerous domains, typosquats, or malicious homoglyphs.',
    });
  }

  return {
    urls: analyzedUrls,
    totalUrls,
    highRiskCount,
    suspiciousCount,
    safeCount,
    hasDisplayMismatch,
    flags: globalFlags,
  };
}
