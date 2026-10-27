/**
 * Sentinel AI - Deep URL Threat & Phishing Detection Engine
 * Client-side heuristic analysis, brand spoofing detector, typosquatting scanner, and risk scoring.
 */

const KNOWN_BRANDS = [
  { name: 'PayPal', domain: 'paypal.com', variants: ['paypal', 'paypa1', 'paypaI', 'pay-pal', 'paypaal'] },
  { name: 'Google', domain: 'google.com', variants: ['google', 'goog1e', 'g00gle', 'googel', 'googl'] },
  { name: 'Apple', domain: 'apple.com', variants: ['apple', 'app1e', 'app-le', 'appl-id'] },
  { name: 'Microsoft', domain: 'microsoft.com', variants: ['microsoft', 'micros0ft', 'micro-soft', 'msft', 'live-login', 'office365'] },
  { name: 'Amazon', domain: 'amazon.com', variants: ['amazon', 'arnazon', 'amaz0n', 'amazn', 'amz-order'] },
  { name: 'Netflix', domain: 'netflix.com', variants: ['netflix', 'netf1ix', 'net-flix', 'netfIix'] },
  { name: 'Facebook / Meta', domain: 'facebook.com', variants: ['facebook', 'faceb00k', 'face-book', 'meta-support'] },
  { name: 'Instagram', domain: 'instagram.com', variants: ['instagram', '1nstagram', 'insta-verify', 'ig-badge'] },
  { name: 'Chase Bank', domain: 'chase.com', variants: ['chase', 'chase-online', 'chasebank', 'chase-verify'] },
  { name: 'Bank of America', domain: 'bankofamerica.com', variants: ['bankofamerica', 'bofa', 'bofa-online', 'bofa-verify'] },
  { name: 'Binance', domain: 'binance.com', variants: ['binance', 'b1nance', 'binance-trade', 'binance-wallet'] },
  { name: 'Coinbase', domain: 'coinbase.com', variants: ['coinbase', 'c0inbase', 'coinbase-pro', 'coinbase-wallet'] },
  { name: 'Discord', domain: 'discord.com', variants: ['discord', 'd1scord', 'discord-nitro', 'free-nitro'] },
  { name: 'Steam', domain: 'steampowered.com', variants: ['steam', 'steampowered', 'steamcommunity', 'steam-gift'] },
  { name: 'Roblox', domain: 'roblox.com', variants: ['roblox', 'r0blox', 'free-robux', 'roblox-verify'] },
  { name: 'DHL', domain: 'dhl.com', variants: ['dhl', 'dhl-tracking', 'dhl-delivery', 'dhl-express'] },
  { name: 'USPS', domain: 'usps.com', variants: ['usps', 'usps-tracking', 'usps-package', 'usps-redelivery'] }
];

const SUSPICIOUS_TLDS = new Set([
  'top', 'xyz', 'zip', 'mov', 'tk', 'ml', 'ga', 'cf', 'gq', 'work', 'click',
  'buzz', 'rest', 'country', 'fit', 'surf', 'stream', 'kim', 'racing',
  'download', 'loan', 'win', 'gdn', 'bid', 'bar', 'icu', 'cam', 'sbs', 'monster'
]);

const URL_SHORTENERS = new Set([
  'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'is.gd', 'cutt.ly',
  'ow.ly', 'rb.gy', 'shorturl.at', 'bl.ink', 'buff.ly', 'tiny.cc'
]);

const PHISHING_KEYWORDS = [
  { keyword: 'login', label: 'Credential Login Form' },
  { keyword: 'signin', label: 'Sign-in Portal' },
  { keyword: 'verify', label: 'Verification Hook' },
  { keyword: 'verification', label: 'Account Verification' },
  { keyword: 'update-billing', label: 'Payment / Billing Urgency' },
  { keyword: 'billing', label: 'Billing Claim' },
  { keyword: 'account-suspended', label: 'Suspension Threat' },
  { keyword: 'suspended', label: 'Account Lockdown Bait' },
  { keyword: 'security-alert', label: 'Fake Security Warning' },
  { keyword: 'wallet-connect', label: 'Crypto Wallet Drainer Target' },
  { keyword: 'claim-reward', label: 'Prize / Reward Lure' },
  { keyword: 'giveaway', label: 'Fake Giveaway Bait' },
  { keyword: '2fa-recover', label: '2FA Bypass Attempt' },
  { keyword: 'confirm-identity', label: 'Identity Theft Form' },
  { keyword: 'kyc', label: 'KYC Verification Bait' },
  { keyword: 'free-gift', label: 'Lure Keyword' },
  { keyword: 'invoice', label: 'Invoice Phishing Vector' }
];

class URLThreatDetector {
  /**
   * Find any URLs inside arbitrary message text
   */
  static extractURLs(text) {
    if (!text || typeof text !== 'string') return [];
    // Match http/https URLs or bare domains like example.com/path
    const urlRegex = /(https?:\/\/[^\s<>"'{}|\\^`]+|(?:www\.)[^\s<>"'{}|\\^`]+|[a-zA-Z0-9][-a-zA-Z0-9]{1,62}\.(?:com|org|net|edu|gov|io|co|ai|info|biz|top|xyz|zip|me|app|dev|site|online|store|tech|pro|tv|cc|us|uk|de|ru|cn|in)[^\s<>"'{}|\\^`]*)/gi;
    const matches = text.match(urlRegex) || [];
    return [...new Set(matches.map(u => u.replace(/[.,;!?)]+$/, '')))];
  }

  /**
   * Calculate Shannon Entropy of a string (measures randomness/obfuscation)
   */
  static calculateEntropy(str) {
    if (!str) return 0;
    const len = str.length;
    const freq = {};
    for (let i = 0; i < len; i++) {
      const ch = str[i];
      freq[ch] = (freq[ch] || 0) + 1;
    }
    let entropy = 0;
    for (const ch in freq) {
      const p = freq[ch] / len;
      entropy -= p * Math.log2(p);
    }
    return entropy;
  }

  /**
   * Levenshtein Distance for typosquatting checks
   */
  static levenshtein(a, b) {
    if (a.length === 0) return b.length;
    if (b.length === 0) return a.length;
    const matrix = [];
    for (let i = 0; i <= b.length; i++) matrix[i] = [i];
    for (let j = 0; j <= a.length; j++) matrix[0][j] = j;

    for (let i = 1; i <= b.length; i++) {
      for (let j = 1; j <= a.length; j++) {
        if (b.charAt(i - 1) === a.charAt(j - 1)) {
          matrix[i][j] = matrix[i - 1][j - 1];
        } else {
          matrix[i][j] = Math.min(
            matrix[i - 1][j - 1] + 1, // substitution
            matrix[i][j - 1] + 1,     // insertion
            matrix[i - 1][j] + 1      // deletion
          );
        }
      }
    }
    return matrix[b.length][a.length];
  }

  /**
   * Deep Analysis of a URL string
   */
  static analyze(rawUrl) {
    let urlString = rawUrl.trim();
    if (!/^https?:\/\//i.test(urlString)) {
      urlString = 'http://' + urlString;
    }

    let parsed;
    try {
      parsed = new URL(urlString);
    } catch (e) {
      return {
        valid: false,
        rawUrl,
        error: 'Malformed or unparseable URL string.'
      };
    }

    const flags = [];
    let score = 0;
    const recommendations = [];

    const hostname = parsed.hostname.toLowerCase();
    const protocol = parsed.protocol.replace(':', '').toLowerCase();
    const pathname = parsed.pathname;
    const search = parsed.search;
    const port = parsed.port;
    const rawTarget = rawUrl;

    // 1. IP Address Host Check (e.g. http://192.168.1.1 or public IP)
    const ipv4Regex = /^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/;
    const isIP = ipv4Regex.test(hostname) || /^[0-9a-f:]+$/i.test(hostname);
    if (isIP) {
      score += 45;
      flags.push({
        type: 'danger',
        category: 'IP Host Indicator',
        title: 'Direct IP Address Host',
        desc: `Hostname "${hostname}" is a raw numeric IP instead of a registered domain. Phishing sites frequently use raw IPs to bypass DNS reputation filtering.`
      });
      recommendations.push('Do not enter personal or financial details on raw IP web addresses.');
    }

    // Parse Domain Components
    const hostParts = hostname.split('.');
    const tld = hostParts.length > 1 ? hostParts[hostParts.length - 1] : '';
    const apexDomain = hostParts.length >= 2 ? hostParts.slice(-2).join('.') : hostname;
    const domainNameWithoutTld = hostParts.length >= 2 ? hostParts[hostParts.length - 2] : hostname;
    const subdomains = hostParts.length > 2 ? hostParts.slice(0, -2).join('.') : '';

    // 2. Protocol Check (HTTP vs HTTPS)
    if (protocol === 'http') {
      score += 15;
      flags.push({
        type: 'warning',
        category: 'Insecure Protocol',
        title: 'Cleartext HTTP (Unencrypted)',
        desc: 'The link uses insecure HTTP without SSL/TLS encryption. Sensitive data can be intercepted in transit.'
      });
      recommendations.push('Verify if an HTTPS version exists before interacting.');
    }

    // 3. Suspicious / Abused TLD
    if (SUSPICIOUS_TLDS.has(tld)) {
      score += 30;
      flags.push({
        type: 'danger',
        category: 'Suspicious TLD',
        title: `High-Risk Top-Level Domain (.${tld})`,
        desc: `The .${tld} TLD has a statistically disproportionate rate of abuse in malicious campaigns, phishing kits, and automated malware delivery.`
      });
    }

    // 4. URL Shortener Detection
    if (URL_SHORTENERS.has(hostname) || URL_SHORTENERS.has(apexDomain)) {
      score += 25;
      flags.push({
        type: 'warning',
        category: 'URL Masking',
        title: 'Shortened URL (Hidden Destination)',
        desc: `Host "${hostname}" is a URL shortener. Shortened links intentionally conceal the true target page until clicked.`
      });
      recommendations.push('Expand this shortened URL using an unshortener tool to inspect the final landing page before browsing.');
    }

    // 5. Brand Spoofing & Phishing Target Impersonation
    let brandSpoofed = null;
    for (const brand of KNOWN_BRANDS) {
      const isOfficialApex = apexDomain === brand.domain || hostname === brand.domain || hostname.endsWith('.' + brand.domain);

      // Check if brand is mentioned in subdomains or path while NOT on official domain
      const inSubdomain = subdomains.toLowerCase().includes(brand.name.toLowerCase().replace(/[^a-z0-9]/g, '')) ||
        brand.variants.some(v => subdomains.toLowerCase().includes(v));
      const inPath = pathname.toLowerCase().includes(brand.name.toLowerCase().replace(/[^a-z0-9]/g, '')) ||
        brand.variants.some(v => pathname.toLowerCase().includes(v));

      if (!isOfficialApex && (inSubdomain || inPath)) {
        brandSpoofed = brand;
        score += 50;
        flags.push({
          type: 'danger',
          category: 'Brand Impersonation',
          title: `Spoofing Target: ${brand.name}`,
          desc: `The link references ${brand.name} in its ${inSubdomain ? 'subdomain' : 'path'}, but the real apex host is "${apexDomain}". This is a classic credential harvesting tactic.`
        });
        recommendations.push(`Official ${brand.name} operations always use "${brand.domain}". Avoid logging in or entering credentials.`);
        break;
      }

      // Check typosquatting on the domain itself (e.g. paypa1.com, micros0ft.com)
      if (!isOfficialApex && hostParts.length >= 2) {
        const brandCore = brand.domain.split('.')[0];
        const dist = URLThreatDetector.levenshtein(domainNameWithoutTld, brandCore);
        const isLookalike = (dist === 1 && domainNameWithoutTld.length > 3) ||
          (dist === 2 && domainNameWithoutTld.length > 6) ||
          brand.variants.includes(domainNameWithoutTld);

        if (isLookalike) {
          brandSpoofed = brand;
          score += 55;
          flags.push({
            type: 'danger',
            category: 'Typosquatting Lookalike',
            title: `Deceptive Lookalike of ${brand.name}`,
            desc: `Domain "${apexDomain}" closely mimics "${brand.domain}" (edit distance: ${dist}). Scammers register lookalike domains to trick unsuspecting users.`
          });
          recommendations.push(`Check spelling carefully. The genuine site is https://${brand.domain}`);
          break;
        }
      }
    }

    // 6. Punycode / Internationalized Homograph Attack (xn--)
    if (hostname.includes('xn--')) {
      score += 40;
      flags.push({
        type: 'danger',
        category: 'Homograph Attack',
        title: 'Punycode Encoded Domain (xn--)',
        desc: `Hostname contains punycode ("xn--"). Attackers use Cyrillic or Greek homoglyphs (e.g. 'а' instead of Latin 'a') to create visually indistinguishable phishing links.`
      });
      recommendations.push('Do not trust visually authentic looking characters in punycode domains.');
    }

    // 7. HTTP Authentication Obfuscation (@ trick)
    if (rawTarget.includes('@')) {
      score += 40;
      flags.push({
        type: 'danger',
        category: 'Authority Confusion',
        title: 'Embedded Credential / Redirection Sign (@)',
        desc: 'URL contains "@". Browsers treat text before "@" as basic auth credentials and secretly route you to the host AFTER the "@" symbol.'
      });
      recommendations.push('Be cautious: what looks like a trusted domain before "@" is completely ignored by the web browser.');
    }

    // 8. Excessive Subdomains (Domain Stacking)
    if (hostParts.length > 4) {
      score += 20;
      flags.push({
        type: 'warning',
        category: 'Domain Structure',
        title: 'Deep Subdomain Stacking',
        desc: `Host contains ${hostParts.length} levels (${hostname}). Phishers chain subdomains to push the actual domain off the screen on mobile browsers.`
      });
    }

    // 9. Excessive Hyphens in Domain
    const hyphenCount = (domainNameWithoutTld.match(/-/g) || []).length;
    if (hyphenCount >= 2) {
      score += 15;
      flags.push({
        type: 'warning',
        category: 'Domain Anomaly',
        title: `Hyphen-Heavy Domain (${hyphenCount} hyphens)`,
        desc: `"${domainNameWithoutTld}" contains multiple hyphens, a signature pattern in automated phishing domain generation.`
      });
    }

    // 10. Phishing & Urgency Keywords in Path / Query
    const matchedKeywords = [];
    const lowerFullUrl = urlString.toLowerCase();
    for (const item of PHISHING_KEYWORDS) {
      if (lowerFullUrl.includes(item.keyword)) {
        matchedKeywords.push(item);
      }
    }
    if (matchedKeywords.length > 0) {
      const keywordScore = Math.min(matchedKeywords.length * 10, 30);
      score += keywordScore;
      flags.push({
        type: matchedKeywords.length >= 2 ? 'danger' : 'warning',
        category: 'Urgency & Baits',
        title: `Suspicious Security / Action Keywords (${matchedKeywords.length})`,
        desc: `Detected keyword patterns: ${matchedKeywords.map(m => `"${m.keyword}" (${m.label})`).join(', ')}.`
      });
    }

    // 11. High String Entropy (Machine Generated String)
    const domainEntropy = URLThreatDetector.calculateEntropy(domainNameWithoutTld);
    if (domainEntropy > 3.9 && domainNameWithoutTld.length > 10) {
      score += 15;
      flags.push({
        type: 'warning',
        category: 'Cryptographic Entropy',
        title: 'High Hostname Randomness (DGA Marker)',
        desc: `Domain "${domainNameWithoutTld}" exhibits high entropy (${domainEntropy.toFixed(2)} bits/char), indicating potential Domain Generation Algorithm (DGA) usage.`
      });
    }

    // 12. Non-Standard Port
    if (port && port !== '80' && port !== '443') {
      score += 15;
      flags.push({
        type: 'warning',
        category: 'Network Port',
        title: `Non-Standard Port (:${port})`,
        desc: `Service runs on uncommon port ${port} rather than standard HTTP(S) ports.`
      });
    }

    // 13. Legitimate Domain Validation Boost (Safety Deduction)
    const trustedApexDomains = new Set([
      'google.com', 'github.com', 'microsoft.com', 'apple.com', 'wikipedia.org',
      'youtube.com', 'linkedin.com', 'amazon.com', 'cloudflare.com', 'stackoverflow.com',
      'gov', 'edu', 'mozilla.org', 'w3.org'
    ]);
    const isTrusted = trustedApexDomains.has(apexDomain) || Array.from(trustedApexDomains).some(d => apexDomain.endsWith('.' + d));
    if (isTrusted && !rawTarget.includes('@') && protocol === 'https') {
      score = Math.max(0, score - 30);
    }

    // Clamp score
    const finalScore = Math.min(100, Math.max(0, score));

    // Determine Verdict Category
    let verdict = 'SAFE';
    let verdictClass = 'verdict-safe';
    let color = '#00f59b';

    if (finalScore >= 70) {
      verdict = 'DANGEROUS PHISHING';
      verdictClass = 'verdict-danger';
      color = '#ff3366';
      if (recommendations.length === 0) {
        recommendations.push('Do NOT visit this link or input passwords, PINs, or credentials.');
      }
    } else if (finalScore >= 40) {
      verdict = 'SUSPICIOUS';
      verdictClass = 'verdict-suspicious';
      color = '#ffaa00';
      if (recommendations.length === 0) {
        recommendations.push('Exercise strong caution. Confirm sender identity via a secondary channel.');
      }
    } else if (finalScore >= 20) {
      verdict = 'LOW RISK / CAUTION';
      verdictClass = 'verdict-caution';
      color = '#00d4ff';
      if (recommendations.length === 0) {
        recommendations.push('General caution advised. Ensure SSL certificate matches the intended company.');
      }
    } else {
      verdict = 'VERIFIED SAFE';
      verdictClass = 'verdict-safe';
      color = '#00f59b';
      recommendations.push('Link adheres to standard security heuristics and trusted domain conventions.');
    }

    return {
      valid: true,
      rawUrl,
      sanitizedUrl: urlString,
      components: {
        protocol,
        hostname,
        subdomains: subdomains || '(none)',
        apexDomain,
        domainNameWithoutTld,
        tld: tld ? '.' + tld : '(none)',
        port: port || (protocol === 'https' ? '443' : '80'),
        pathname: pathname || '/',
        search: search || '(none)',
        hash: parsed.hash || '(none)'
      },
      stats: {
        score: finalScore,
        verdict,
        verdictClass,
        color,
        flagsCount: flags.length,
        entropy: domainEntropy.toFixed(2),
        isIP,
        isTrusted
      },
      flags,
      recommendations
    };
  }
}

// Export for usage in app.js
if (typeof window !== 'undefined') {
  window.URLThreatDetector = URLThreatDetector;
}
