import {
  AuthProtocolResult,
  HeaderAnalysisResult,
  ParsedHeaders,
  ReceivedHop,
  RiskFlag,
} from '../types';

/**
 * Extracts email address and domain from an RFC 5322 address string.
 * E.g., "John Doe <johndoe@example.com>" -> { name: "John Doe", address: "johndoe@example.com", domain: "example.com" }
 */
export function parseEmailAddress(input: string): { name?: string; address: string; domain: string } | undefined {
  if (!input || !input.trim()) return undefined;
  const trimmed = input.trim();

  // Match: "Name" <user@domain.tld> or Name <user@domain.tld>
  const angleMatch = trimmed.match(/^(?:["']?([^"']*)["']?\s*)?<([a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})>$/);
  if (angleMatch) {
    const address = angleMatch[2].toLowerCase();
    const domain = address.split('@')[1] || '';
    return {
      name: angleMatch[1]?.trim() || undefined,
      address,
      domain,
    };
  }

  // Raw email user@domain.tld
  const directMatch = trimmed.match(/^([a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})$/);
  if (directMatch) {
    const address = directMatch[1].toLowerCase();
    const domain = address.split('@')[1] || '';
    return { address, domain };
  }

  // Fallback search for any email address pattern inside string
  const generalMatch = trimmed.match(/([a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/);
  if (generalMatch) {
    const address = generalMatch[1].toLowerCase();
    const domain = address.split('@')[1] || '';
    return { address, domain };
  }

  return undefined;
}

/**
 * Unfolds folded header lines per RFC 5322 (lines starting with whitespace are continuations)
 */
export function unfoldHeaders(rawHeadersText: string): Record<string, string[]> {
  const headersMap: Record<string, string[]> = {};
  if (!rawHeadersText) return headersMap;

  // Split into lines normalized by \n
  const lines = rawHeadersText.replace(/\r\n/g, '\n').replace(/\r/g, '\n').split('\n');
  let currentKey = '';
  let currentValue = '';

  for (const line of lines) {
    if (/^[ \t]/.test(line)) {
      // Continuation line
      if (currentKey) {
        currentValue += ' ' + line.trim();
      }
    } else {
      // Store previous header
      if (currentKey) {
        const lowerKey = currentKey.toLowerCase();
        if (!headersMap[lowerKey]) headersMap[lowerKey] = [];
        headersMap[lowerKey].push(currentValue.trim());
      }

      const colonIndex = line.indexOf(':');
      if (colonIndex > 0) {
        currentKey = line.slice(0, colonIndex).trim();
        currentValue = line.slice(colonIndex + 1).trim();
      } else {
        currentKey = '';
        currentValue = '';
      }
    }
  }

  // Save the final header
  if (currentKey) {
    const lowerKey = currentKey.toLowerCase();
    if (!headersMap[lowerKey]) headersMap[lowerKey] = [];
    headersMap[lowerKey].push(currentValue.trim());
  }

  return headersMap;
}

function isPrivateIp(ip: string): boolean {
  if (!ip) return false;
  if (ip === '127.0.0.1' || ip === '::1' || ip === 'localhost') return true;
  if (ip.startsWith('10.')) return true;
  if (ip.startsWith('192.168.')) return true;
  const match172 = ip.match(/^172\.(\d+)\./);
  if (match172) {
    const octet = parseInt(match172[1], 10);
    if (octet >= 16 && octet <= 31) return true;
  }
  return false;
}

/**
 * Parses Received header lines
 */
export function parseReceivedHeaders(receivedLines: string[]): ReceivedHop[] {
  if (!receivedLines || receivedLines.length === 0) return [];

  const hops: ReceivedHop[] = [];

  receivedLines.forEach((line, index) => {
    // E.g.: from mail.example.com (mail.example.com [198.51.100.2]) by mx.google.com with ESMTPS id ...; Wed, 08 Sep 2026 10:12:00 +0000
    const fromHostMatch = line.match(/\bfrom\s+([^\s;()]+)/i);
    const byHostMatch = line.match(/\bby\s+([^\s;()]+)/i);
    const ipMatch = line.match(/\[([0-9a-fA-F:.]+)\]/);
    const protocolMatch = line.match(/\bwith\s+([^\s;()]+)/i);
    const dateMatch = line.match(/;\s*([A-Za-z]{3},\s+.*)$/);

    const fromIp = ipMatch ? ipMatch[1] : undefined;
    const isPrivate = fromIp ? isPrivateIp(fromIp) : false;

    // Check if open relay or suspicious indicator
    const isSuspicious = Boolean(
      (fromIp && !isPrivate && (fromIp.startsWith('100.64.') || line.toLowerCase().includes('dynamic') || line.toLowerCase().includes('pool'))) ||
      line.toLowerCase().includes('unauthenticated')
    );

    hops.push({
      index: index + 1,
      fromHost: fromHostMatch ? fromHostMatch[1] : undefined,
      fromIp,
      byHost: byHostMatch ? byHostMatch[1] : undefined,
      protocol: protocolMatch ? protocolMatch[1] : undefined,
      timestamp: dateMatch ? dateMatch[1].trim() : undefined,
      isPrivateIp: isPrivate,
      isSuspiciousRelay: isSuspicious,
      raw: line,
    });
  });

  return hops;
}

/**
 * Parses SPF, DKIM, and DMARC results from Authentication-Results or Received-SPF headers
 */
export function parseAuthResults(headers: Record<string, string[]>): {
  spf: AuthProtocolResult;
  dkim: AuthProtocolResult;
  dmarc: AuthProtocolResult;
} {
  const spf: AuthProtocolResult = { status: 'none' };
  const dkim: AuthProtocolResult = { status: 'none' };
  const dmarc: AuthProtocolResult = { status: 'none' };

  // 1. Check Authentication-Results headers (RFC 7601 / RFC 8601)
  const authHeaders = headers['authentication-results'] || [];
  for (const authHeader of authHeaders) {
    // Check SPF
    const spfMatch = authHeader.match(/\bspf=([a-z]+)(?:\s+\(([^)]+)\))?(?:\s+smtp\.mailfrom=([^\s;]+))?/i);
    if (spfMatch && spf.status === 'none') {
      const st = spfMatch[1].toLowerCase();
      if (['pass', 'fail', 'softfail', 'neutral', 'none', 'temperror', 'permerror'].includes(st)) {
        spf.status = st as AuthProtocolResult['status'];
        spf.details = spfMatch[2];
        spf.domain = spfMatch[3];
        spf.rawHeader = authHeader;
      }
    }

    // Check DKIM
    const dkimMatch = authHeader.match(/\bdkim=([a-z]+)(?:\s+\(([^)]+)\))?(?:\s+header\.[id]=([^\s;]+))?/i);
    if (dkimMatch && dkim.status === 'none') {
      const st = dkimMatch[1].toLowerCase();
      if (['pass', 'fail', 'neutral', 'none', 'temperror', 'permerror'].includes(st)) {
        dkim.status = st as AuthProtocolResult['status'];
        dkim.details = dkimMatch[2];
        dkim.domain = dkimMatch[3];
        dkim.rawHeader = authHeader;
      }
    }

    // Check DMARC
    const dmarcMatch = authHeader.match(/\bdmarc=([a-z]+)(?:\s+\(([^)]+)\))?(?:\s+header\.from=([^\s;]+))?/i);
    if (dmarcMatch && dmarc.status === 'none') {
      const st = dmarcMatch[1].toLowerCase();
      if (['pass', 'fail', 'none', 'temperror', 'permerror'].includes(st)) {
        dmarc.status = st as AuthProtocolResult['status'];
        dmarc.details = dmarcMatch[2];
        dmarc.domain = dmarcMatch[3];
        dmarc.rawHeader = authHeader;
      }
    }
  }

  // 2. Fallback: Check Received-SPF
  if (spf.status === 'none') {
    const receivedSpf = (headers['received-spf'] || [])[0];
    if (receivedSpf) {
      const match = receivedSpf.match(/^([a-z]+)/i);
      if (match) {
        const st = match[1].toLowerCase();
        if (['pass', 'fail', 'softfail', 'neutral', 'none', 'temperror', 'permerror'].includes(st)) {
          spf.status = st as AuthProtocolResult['status'];
          spf.rawHeader = receivedSpf;
          const domainMatch = receivedSpf.match(/domain of\s+([^\s;]+)/i);
          if (domainMatch) spf.domain = domainMatch[1];
        }
      }
    }
  }

  // 3. Fallback: Check DKIM-Signature presence
  if (dkim.status === 'none' && headers['dkim-signature']?.length) {
    dkim.status = 'neutral';
    dkim.details = 'DKIM-Signature present on email (no MTA evaluation header found)';
    const dkimSig = headers['dkim-signature'][0];
    const dMatch = dkimSig.match(/d=([a-zA-Z0-9.-]+)/);
    if (dMatch) dkim.domain = dMatch[1];
  }

  return { spf, dkim, dmarc };
}

/**
 * Performs deep security analysis of RFC 5322 parsed headers
 */
export function analyzeHeaders(rawHeadersText: string): HeaderAnalysisResult {
  const rawHeaders = unfoldHeaders(rawHeadersText);
  const flags: RiskFlag[] = [];
  const scoreBreakdown: { factor: string; impact: number; description: string }[] = [];

  // Extract primary fields
  const fromStr = (rawHeaders['from'] || [])[0] || '';
  const returnPathStr = (rawHeaders['return-path'] || [])[0] || '';
  const replyToStr = (rawHeaders['reply-to'] || [])[0] || '';
  const subject = (rawHeaders['subject'] || [])[0] || '';
  const date = (rawHeaders['date'] || [])[0] || '';
  const messageId = (rawHeaders['message-id'] || [])[0] || '';
  const xOriginatingIp = (rawHeaders['x-originating-ip'] || [])[0]?.replace(/[\[\]]/g, '') || undefined;
  const xMailer = (rawHeaders['x-mailer'] || [])[0] || (rawHeaders['user-agent'] || [])[0] || undefined;
  const toHeaders = rawHeaders['to'] || [];

  const from = parseEmailAddress(fromStr);
  const returnPath = parseEmailAddress(returnPathStr);
  const replyTo = parseEmailAddress(replyToStr);

  const receivedChain = parseReceivedHeaders(rawHeaders['received'] || []);
  const authResults = parseAuthResults(rawHeaders);

  const parsed: ParsedHeaders = {
    from,
    to: toHeaders,
    replyTo,
    returnPath,
    subject,
    date,
    messageId,
    xOriginatingIp,
    xMailer,
    spf: authResults.spf,
    dkim: authResults.dkim,
    dmarc: authResults.dmarc,
    receivedChain,
    rawHeaders,
    rawText: rawHeadersText,
  };

  // Base score: 70
  let trustScore = 70;

  // 1. From header verification
  if (!from) {
    trustScore -= 30;
    flags.push({
      id: 'hdr-missing-from',
      category: 'header',
      severity: 'high',
      title: 'Missing or Malformed "From" Header',
      description: 'The email does not have a standard RFC 5322 From header, which is standard in malicious automated spam.',
    });
    scoreBreakdown.push({
      factor: 'Missing From header',
      impact: -30,
      description: 'Email lacks valid RFC 5322 From field.',
    });
  }

  // 2. Domain Alignment Check: From vs Return-Path (Envelope Sender)
  if (from && returnPath) {
    if (from.domain.toLowerCase() !== returnPath.domain.toLowerCase()) {
      // Check if subdomain of same parent
      const fromParts = from.domain.toLowerCase().split('.');
      const returnParts = returnPath.domain.toLowerCase().split('.');
      const fromBase = fromParts.slice(-2).join('.');
      const returnBase = returnParts.slice(-2).join('.');

      if (fromBase !== returnBase) {
        trustScore -= 28;
        flags.push({
          id: 'hdr-return-path-mismatch',
          category: 'header',
          severity: 'critical',
          title: 'Sender Domain Mismatch (From vs Return-Path)',
          description: `The visible sender domain (${from.domain}) does not match the actual envelope return address (${returnPath.domain}). This is a classic indicator of spoofed sender identities.`,
          evidence: `From: ${from.address} | Return-Path: ${returnPath.address}`,
          recommendation: 'Check if legitimate 3rd party bulk mailer or lookalike attacker domain.',
        });
        scoreBreakdown.push({
          factor: 'Envelope Mismatch',
          impact: -28,
          description: `From domain (${from.domain}) differs from Return-Path (${returnPath.domain}).`,
        });
      }
    }
  }

  // 3. Domain Alignment Check: From vs Reply-To (Reply Redirection)
  if (from && replyTo) {
    if (from.domain.toLowerCase() !== replyTo.domain.toLowerCase()) {
      trustScore -= 22;
      flags.push({
        id: 'hdr-reply-to-mismatch',
        category: 'header',
        severity: 'high',
        title: 'Reply-To Diversion Detected',
        description: `Replies are directed to an external or mismatched address (${replyTo.address}) instead of the sender domain (${from.domain}). Often used in Business Email Compromise (BEC) and phishing to harvest victim responses.`,
        evidence: `From: ${from.address} -> Reply-To: ${replyTo.address}`,
        recommendation: 'Do not reply. Verify legitimacy through an out-of-band communication channel.',
      });
      scoreBreakdown.push({
        factor: 'Reply-To Diversion',
        impact: -22,
        description: `Reply-To (${replyTo.domain}) does not match From (${from.domain}).`,
      });
    }
  }

  // 4. SPF Authentication
  if (authResults.spf.status === 'pass') {
    trustScore += 10;
    scoreBreakdown.push({
      factor: 'SPF Pass',
      impact: +10,
      description: 'Sending server IP is authorized in sender domain SPF record.',
    });
  } else if (authResults.spf.status === 'fail') {
    trustScore -= 25;
    flags.push({
      id: 'hdr-spf-fail',
      category: 'header',
      severity: 'critical',
      title: 'SPF Hard Failure (spf=fail)',
      description: 'The sending MTA is explicitly prohibited from transmitting mail on behalf of this domain per its published SPF policy.',
      evidence: authResults.spf.rawHeader || 'SPF result: fail',
      recommendation: 'Treat as high probability of forged sender address.',
    });
    scoreBreakdown.push({
      factor: 'SPF Hard Fail',
      impact: -25,
      description: 'Sending server failed domain SPF authentication.',
    });
  } else if (authResults.spf.status === 'softfail') {
    trustScore -= 15;
    flags.push({
      id: 'hdr-spf-softfail',
      category: 'header',
      severity: 'medium',
      title: 'SPF Soft Failure (spf=softfail)',
      description: 'Sending server is not authorized by the domain SPF record, but the domain policy is non-blocking (~all).',
    });
    scoreBreakdown.push({
      factor: 'SPF Softfail',
      impact: -15,
      description: 'Server IP not designated in domain SPF record.',
    });
  } else if (authResults.spf.status === 'none') {
    trustScore -= 8;
    flags.push({
      id: 'hdr-spf-none',
      category: 'header',
      severity: 'low',
      title: 'Missing SPF Authentication',
      description: 'No SPF evaluation record found in authentication headers.',
    });
    scoreBreakdown.push({
      factor: 'Missing SPF',
      impact: -8,
      description: 'No verified SPF record.',
    });
  }

  // 5. DKIM Authentication
  if (authResults.dkim.status === 'pass') {
    trustScore += 12;
    scoreBreakdown.push({
      factor: 'DKIM Pass',
      impact: +12,
      description: 'Cryptographic signature from sender domain verified intact.',
    });
  } else if (authResults.dkim.status === 'fail') {
    trustScore -= 25;
    flags.push({
      id: 'hdr-dkim-fail',
      category: 'header',
      severity: 'high',
      title: 'DKIM Verification Failed',
      description: 'The cryptographic DKIM signature failed verification or was altered in transit.',
      evidence: authResults.dkim.rawHeader || 'DKIM result: fail',
    });
    scoreBreakdown.push({
      factor: 'DKIM Fail',
      impact: -25,
      description: 'Digital signature invalid or broken.',
    });
  } else if (authResults.dkim.status === 'none') {
    trustScore -= 8;
    flags.push({
      id: 'hdr-dkim-none',
      category: 'header',
      severity: 'low',
      title: 'Missing DKIM Signature',
      description: 'Email does not contain a validated cryptographic DKIM signature.',
    });
    scoreBreakdown.push({
      factor: 'Missing DKIM',
      impact: -8,
      description: 'No valid DKIM signature.',
    });
  }

  // 6. DMARC Authentication
  if (authResults.dmarc.status === 'pass') {
    trustScore += 10;
    scoreBreakdown.push({
      factor: 'DMARC Pass',
      impact: +10,
      description: 'DMARC alignment passed with domain policy.',
    });
  } else if (authResults.dmarc.status === 'fail') {
    trustScore -= 25;
    flags.push({
      id: 'hdr-dmarc-fail',
      category: 'header',
      severity: 'critical',
      title: 'DMARC Alignment Failed',
      description: 'DMARC policy validation failed. The message failed both SPF alignment and DKIM alignment for the visible From domain.',
      evidence: authResults.dmarc.rawHeader || 'DMARC result: fail',
      recommendation: 'Reject or isolate message in quarantine.',
    });
    scoreBreakdown.push({
      factor: 'DMARC Fail',
      impact: -25,
      description: 'DMARC alignment failure.',
    });
  }

  // 7. Message-ID validation
  if (!messageId) {
    trustScore -= 12;
    flags.push({
      id: 'hdr-missing-msgid',
      category: 'header',
      severity: 'medium',
      title: 'Missing Message-ID Header',
      description: 'Legitimate mail transfer agents (MTAs) assign a unique RFC 5322 Message-ID to every transmission. Missing Message-ID is common in raw spam scripts.',
    });
    scoreBreakdown.push({
      factor: 'Missing Message-ID',
      impact: -12,
      description: 'RFC 5322 Message-ID absent.',
    });
  } else if (from && !messageId.includes(from.domain) && !messageId.includes('.')) {
    trustScore -= 8;
    flags.push({
      id: 'hdr-suspicious-msgid',
      category: 'header',
      severity: 'low',
      title: 'Anomalous Message-ID Structure',
      description: `The Message-ID (${messageId}) does not conform to common domain-scoped standards.`,
    });
  }

  // 8. Received Chain Verification
  if (receivedChain.length === 0) {
    trustScore -= 15;
    flags.push({
      id: 'hdr-no-received-hops',
      category: 'header',
      severity: 'medium',
      title: 'No Received Hops Present',
      description: 'Header text contains no "Received" lines, preventing verification of MTA routing history.',
    });
  } else {
    // Check for suspicious hops or excessive delays
    const suspiciousHops = receivedChain.filter((h) => h.isSuspiciousRelay);
    if (suspiciousHops.length > 0) {
      trustScore -= 12;
      flags.push({
        id: 'hdr-suspicious-relay',
        category: 'header',
        severity: 'medium',
        title: 'Suspicious Relay Hop Detected',
        description: `Found ${suspiciousHops.length} hop(s) originating from non-standard or dynamic IP ranges.`,
        evidence: suspiciousHops.map((h) => h.fromIp || h.fromHost).filter(Boolean).join(', '),
      });
      scoreBreakdown.push({
        factor: 'Suspicious Relay Hop',
        impact: -12,
        description: 'MTA hop in dynamic/unauthenticated IP space.',
      });
    }

    if (receivedChain.length >= 10) {
      flags.push({
        id: 'hdr-long-relay-chain',
        category: 'header',
        severity: 'low',
        title: 'Unusually Long Relay Chain',
        description: `Message traversed ${receivedChain.length} hops before delivery, which may indicate intentional routing obfuscation.`,
      });
    }
  }

  // Clamp score
  trustScore = Math.max(0, Math.min(100, Math.round(trustScore)));

  let trustLevel: HeaderAnalysisResult['trustLevel'] = 'High Trust';
  if (trustScore < 30) {
    trustLevel = 'Dangerous / Forged';
  } else if (trustScore < 60) {
    trustLevel = 'Suspicious';
  } else if (trustScore < 80) {
    trustLevel = 'Moderate Trust';
  }

  return {
    headers: parsed,
    trustScore,
    trustLevel,
    flags,
    scoreBreakdown,
  };
}
