# 🛡️ Phishing Email Analyzer (SOC Incident Triage Suite)

A specialized web application for security analysts, incident responders, and IT teams to rapidly triage suspicious emails across three core vectors: **Header Analysis (RFC 5322)**, **URL & Typosquatting Analysis**, and **Attachment Heuristic Inspection**.

---

## 🚀 Quickstart & Setup Instructions

### Prerequisites
- Node.js 18+ (or 20+)
- npm, pnpm, or yarn

### Installation
```bash
# 1. Clone the repository and navigate to root directory
cd phishing-email-analyzer

# 2. Install dependencies
npm install

# 3. Start the development server (binds to http://localhost:3000)
npm run dev
```

### Production Build
```bash
# Build production bundle to dist/
npm run build

# Preview production build
npm run preview
```

---

## 🎯 Architecture & Triage Philosophy

### 100% Client-Side Privacy & Determinism
- **Confidentiality:** Security analysts frequently handle confidential internal correspondence, employee PII, or executive wire instructions. This analyzer runs **100% of heuristics directly in the browser**.
- **No Third-Party Leakage:** Zero email headers, IP addresses, or file payloads leave the analyst's machine during triage.
- **Zero API Rate Limits:** Operates deterministically without blocking on paid, throttled, or unreliable external threat feeds.

---

## 🧩 Core Triage Modules

### 1. Header Analysis (RFC 5322)
- **RFC 5322 Unfolding:** Safely unfolds multi-line wrapped headers and parses standard addressing (`From`, `To`, `Cc`, `Return-Path`, `Reply-To`, `Subject`, `Date`, `Message-ID`, `X-Originating-IP`).
- **Sender Alignment Checks:**
  - **From vs Return-Path:** Identifies envelope spoofing where the displayed sender domain differs from the underlying bounce/envelope origin.
  - **Reply-To Diversion:** Detects Business Email Compromise (BEC) tactics where victim replies are covertly redirected to an external lookalike or freemail inbox.
- **Authentication Framework:**
  - Extracts RFC 7601 / 8601 `Authentication-Results` and `Received-SPF`.
  - Evaluates **SPF** (`pass`, `fail`, `softfail`, `neutral`, `none`).
  - Evaluates **DKIM** (`pass`, `fail`, `neutral`, domain alignment).
  - Evaluates **DMARC** (`pass`, `fail`, policy directives `reject`/`quarantine`).
- **Received Hop Timeline:** Traces the entire MTA routing journey from originating client IP through intermediate relays to the final delivery gateway, flagging RFC 1918 private IPs, dynamic pool relays, and obfuscation chains (&gt;10 hops).
- **Header Trust Score:** Computes a normalized 0–100% trust rating with clear itemized point breakdowns.

### 2. URL Analysis & Typosquatting
- **Anchor Text Mismatch Detection:** Compares the visually displayed text (`<a href="...">Display Text</a>` or markdown) against the actual target `href`. Detects deceptive links that pretend to be `https://paypal.com` or `https://microsoft.com` while routing to attacker infrastructure.
- **Brand Impersonation & Typosquatting:**
  - Employs Levenshtein distance calculations, leetspeak character substitutions (`0` for `o`, `1` for `l`, `rn` for `m`), and combosquatting checks against monitored high-value brands (Microsoft, Google, PayPal, Apple, Amazon, Netflix, Chase, Bank of America, DHL, FedEx, USPS, DocuSign, Coinbase, etc.).
- **IDN Homoglyph / Punycode Attacks:** Flags internationalized domain names (`xn--...`) that use lookalike Cyrillic/Greek unicode characters to impersonate Latin domains.
- **Evasion & Infrastructure Heuristics:**
  - Flags direct IP hostnames (`http://198.51.100.44/...`).
  - Detects excessive subdomain depth (`login.verify.account.paypal.com.attacker.com`).
  - Flags high-abuse TLDs (`.xyz`, `.top`, `.work`, `.click`, `.buzz`, `.live`, `.icu`, `.tk`, etc.).
  - Scans URL path/query for phishing credentials tokens (`login`, `signin`, `verify`, `billing`, `update-password`, `webscr`).
- **Simulated Redirect Chains:** Detects URL shorteners (`bit.ly`, `t.co`, `tinyurl`) and uncloaks query redirect parameters (`?redirect=`, `?url=`, `?dest=`, base64 payloads) up to safe limits.
- **IOC Defanging:** Provides a one-click copy button for defanged links (`hxxps://target[.]xyz`) for safe SOC sharing.

### 3. Attachment Analysis & Heuristics
- **Dangerous Extensions:** Flags direct executables and weaponized script formats (`.exe`, `.scr`, `.bat`, `.cmd`, `.ps1`, `.vbs`, `.js`, `.hta`, `.cpl`, `.msi`).
- **Double Extension Detection:** Detects deceptive masking such as `INVOICE.pdf.exe` or `STATEMENT.docx.js`, as well as hidden Unicode Right-To-Left Override (`\u202E`) characters.
- **Macro-Enabled Documents:** Flags VBA-capable Office formats (`.docm`, `.xlsm`, `.pptm`) and legacy binary formats (`.doc`, `.xls`).
- **Mark-of-the-Web (MotW) Evasion:** Flags container disk images (`.iso`, `.img`, `.vhd`) used by threat actors to bypass browser download marks.
- **In-Browser Archive Inspection:** Integrates `JSZip` to unpack and inspect ZIP archives directly in memory, detecting nested dangerous executables, scripts, or encrypted files.
- **Cryptographic SHA-256 Hashing:** Computes real client-side SHA-256 hashes using the Web Crypto API (`crypto.subtle.digest`) for immediate threat intel lookups.

---

## 🧪 Included Realistic Samples

Four pre-configured scenario samples are selectable from the **Samples** dropdown:

1. **Sample 1: Executive CEO Fraud / BEC (Pure-Header Spoof)**
   - *Attack Type:* Business Email Compromise requesting an urgent wire transfer.
   - *Key Indicators:* DMARC failure, SPF softfail, visible From (`sarah.jenkins@acmecorp.com`) mismatching Return-Path (`freemail-bulletproof.top`), Reply-To diverted to external gmail-relay.
2. **Sample 2: Microsoft 365 Credential Harvest (URL Phishing & Typosquatting)**
   - *Attack Type:* Password expiration credential phishing lure.
   - *Key Indicators:* Visual display text shows `https://login.microsoftonline.com/...` while `href` routes to `https://login.micros0ft-verify-portal.xyz/...`, typosquatting `micros0ft`, high-risk `.xyz` and `.live` redirect targets.
3. **Sample 3: Weaponized Invoice Dropper (Malicious Attachments)**
   - *Attack Type:* Overdue payment lure delivering malware droppers.
   - *Key Indicators:* Attached `INVOICE_OCT2026_STATEMENT.pdf.exe` (double extension), `Remittance_Macro_Guide.docm` (VBA macro document), and `Supporting_Vouchers_Encrypted.zip` with nested binaries.
4. **Sample 4: Legitimate Benchmark (Clean GitHub Security Notification)**
   - *Type:* Clean baseline control notification.
   - *Key Indicators:* Fully passing SPF, DKIM (`d=github.com`), and DMARC alignment; authentic URLs with zero mismatches; clean 100% trust score.

---

## 🛠️ Input Methods

1. **Upload .EML / .TXT:** Drag and drop exported email files or select from disk.
2. **Paste RFC 5322 Raw Text:** Direct copy-paste of raw email headers and body.
3. **Structured Manual Form:** Input individual fields (`From`, `Return-Path`, `SPF/DKIM/DMARC` dropdowns, `Received` hops, URLs, attachments) for quick manual triage.
4. **Ad-Hoc Attachment Drop:** Drag and drop local files into the Attachment module to immediately test file heuristics and calculate SHA-256 hashes.

---

## 📤 Export Formats

- **SOC Ticket Markdown:** Formatted, copy-pasteable Markdown report ready for Jira, ServiceNow, or SIEM incident tickets.
- **Printable / PDF Export:** Clean browser print view formatted for PDF generation (`window.print()`).
- **Machine-Readable JSON:** Structured JSON output for SOAR webhooks, automation pipelines, and ticket correlation.

---

## 🔮 Non-Goals & Future Extensibility (ML & Threat Feeds)

- **ML / Bayesian Classification:** The current MVP deliberately employs deterministic rule-based heuristics for speed, explainability, and privacy. Future modules can plug in:
  - Natural language urgency / social engineering tone analysis.
  - Bayesian token classification trained on enterprise spam corpuses.
- **External Threat Intel Integrations:**
  - Modular hooks are provided in `src/types.ts` and `src/utils/triageEngine.ts` to connect external APIs (VirusTotal, URLScan.io, WHOIS/RDAP) when API keys are configured.
- **Sandboxing:** Dynamic malware execution/detonation is out of scope for a client-side triage tool; analysts can copy the generated SHA-256 hashes and defanged URLs for sandboxing in isolated environments.
