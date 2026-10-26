// ═══════════════════════════════════════════════════════════
// PhishGuard - Core Detection Engine (shared by popup & bg)
// ═══════════════════════════════════════════════════════════

const POPULAR_DOMAINS = [
  "google", "facebook", "instagram", "twitter", "paypal",
  "amazon", "apple", "microsoft", "netflix", "linkedin",
  "youtube", "whatsapp", "telegram", "gmail", "yahoo",
  "outlook", "dropbox", "github", "reddit", "ebay",
  "bankofamerica", "wellsfargo", "chase", "citibank",
  "hdfc", "icici", "sbi", "axis", "kotak"
];

const SUSPICIOUS_KEYWORDS = [
  "login", "signin", "sign-in", "verify", "verification",
  "secure", "account", "update", "confirm", "banking",
  "password", "credential", "authenticate", "wallet",
  "free", "winner", "prize", "urgent", "limited",
  "suspended", "blocked", "alert", "warning", "click"
];

const LOOKALIKE_MAP = {
  '0': 'o', '1': 'l', '3': 'e', '4': 'a',
  '5': 's', '6': 'g', '7': 't', '8': 'b',
  '@': 'a', '$': 's', 'vv': 'w', 'rn': 'm'
};

// ── 1. Lookalike Domain Check ────────────────────────────
function checkLookalikeDomain(hostname) {
  let normalised = hostname.toLowerCase().replace(/^www\./, '');
  // Replace look-alike characters
  for (const [fake, real] of Object.entries(LOOKALIKE_MAP)) {
    normalised = normalised.split(fake).join(real);
  }
  // Remove TLD
  const domainBase = normalised.split('.')[0];

  for (const brand of POPULAR_DOMAINS) {
    if (domainBase !== brand && levenshtein(domainBase, brand) <= 2 && domainBase.length > 3) {
      return { detected: true, matchedBrand: brand };
    }
    // Check if brand is contained within a longer fake domain
    if (domainBase !== brand && domainBase.includes(brand) && domainBase.length > brand.length) {
      return { detected: true, matchedBrand: brand };
    }
  }
  return { detected: false };
}

// Levenshtein distance algorithm
function levenshtein(a, b) {
  const dp = Array.from({ length: a.length + 1 }, (_, i) =>
    Array.from({ length: b.length + 1 }, (_, j) => (i === 0 ? j : j === 0 ? i : 0))
  );
  for (let i = 1; i <= a.length; i++) {
    for (let j = 1; j <= b.length; j++) {
      dp[i][j] = a[i-1] === b[j-1]
        ? dp[i-1][j-1]
        : 1 + Math.min(dp[i-1][j], dp[i][j-1], dp[i-1][j-1]);
    }
  }
  return dp[a.length][b.length];
}

// ── 2. Suspicious Keywords in URL ───────────────────────
function checkSuspiciousKeywords(url) {
  const lower = url.toLowerCase();
  const found = SUSPICIOUS_KEYWORDS.filter(k => lower.includes(k));
  return { detected: found.length >= 2, keywords: found.slice(0, 3) };
}

// ── 3. IP Address as URL ─────────────────────────────────
function checkIPUrl(hostname) {
  const ipv4 = /^(\d{1,3}\.){3}\d{1,3}$/;
  return { detected: ipv4.test(hostname) };
}

// ── 4. SSL / HTTPS Check ────────────────────────────────
function checkSSL(url) {
  return { secure: url.startsWith('https://') };
}

// ── 5. URL Length & Complexity ──────────────────────────
function checkURLComplexity(url) {
  const suspicious =
    url.length > 100 ||
    (url.match(/-/g) || []).length > 4 ||
    (url.match(/\./g) || []).length > 5;
  return { suspicious, length: url.length };
}

// ── 6. VirusTotal API Check ─────────────────────────────
async function checkVirusTotal(url, apiKey) {
  if (!apiKey) return { checked: false, reason: "No API key" };

  try {
    // Encode URL to base64 (VT API v3 requirement)
    const urlId = btoa(url).replace(/=/g, '');
    const response = await fetch(`https://www.virustotal.com/api/v3/urls/${urlId}`, {
      headers: { 'x-apikey': apiKey }
    });

    if (response.status === 404) {
      // URL not in VT database — submit it
      await submitToVirusTotal(url, apiKey);
      return { checked: true, malicious: 0, suspicious: 0, total: 0, fresh: true };
    }

    if (!response.ok) return { checked: false, reason: `API Error: ${response.status}` };

    const data = await response.json();
    const stats = data?.data?.attributes?.last_analysis_stats || {};
    return {
      checked: true,
      malicious: stats.malicious || 0,
      suspicious: stats.suspicious || 0,
      total: (stats.malicious || 0) + (stats.suspicious || 0) +
             (stats.harmless || 0) + (stats.undetected || 0)
    };
  } catch (e) {
    return { checked: false, reason: "Network error" };
  }
}

async function submitToVirusTotal(url, apiKey) {
  try {
    await fetch('https://www.virustotal.com/api/v3/urls', {
      method: 'POST',
      headers: { 'x-apikey': apiKey, 'content-type': 'application/x-www-form-urlencoded' },
      body: `url=${encodeURIComponent(url)}`
    });
  } catch (e) {}
}

// ── 7. Master Scoring Engine ────────────────────────────
async function analyseURL(url, apiKey) {
  let score = 0;
  const results = {};

  try {
    const parsed = new URL(url);
    const hostname = parsed.hostname;

    // SSL check
    const ssl = checkSSL(url);
    results.ssl = ssl;
    if (!ssl.secure) score += 20;

    // IP URL check
    const ip = checkIPUrl(hostname);
    results.ip = ip;
    if (ip.detected) score += 35;

    // Lookalike check
    const lookalike = checkLookalikeDomain(hostname);
    results.lookalike = lookalike;
    if (lookalike.detected) score += 40;

    // Suspicious keywords
    const keywords = checkSuspiciousKeywords(url);
    results.keywords = keywords;
    if (keywords.detected) score += 20;

    // URL complexity
    const complexity = checkURLComplexity(url);
    results.complexity = complexity;
    if (complexity.suspicious) score += 10;

    // VirusTotal
    const vt = await checkVirusTotal(url, apiKey);
    results.virustotal = vt;
    if (vt.checked && vt.malicious > 0) score += Math.min(vt.malicious * 10, 50);
    if (vt.checked && vt.suspicious > 0) score += Math.min(vt.suspicious * 5, 20);

  } catch (e) {
    results.error = e.message;
  }

  // Clamp score to 100
  score = Math.min(score, 100);

  // Risk level
  let level, label, description;
  if (score <= 20) {
    level = "safe";
    label = "✅ SAFE";
    description = "No threats detected. This site appears legitimate.";
  } else if (score <= 55) {
    level = "suspicious";
    label = "⚠️ SUSPICIOUS";
    description = "Some risk indicators found. Proceed with caution.";
  } else {
    level = "dangerous";
    label = "🚨 DANGEROUS";
    description = "High risk! This site shows multiple phishing indicators.";
  }

  return { score, level, label, description, results };
}
