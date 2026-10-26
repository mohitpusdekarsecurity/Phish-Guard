// ═══════════════════════════════════════════════════════════
// PhishGuard - Popup Controller
// ═══════════════════════════════════════════════════════════

// Import detector (loaded via manifest as separate script)
// All functions from detector.js are available globally

document.addEventListener('DOMContentLoaded', async () => {
  await loadApiKeyStatus();
  await runScan();
  setupEventListeners();
});

// ── Get current tab URL ──────────────────────────────────
async function getCurrentTab() {
  return new Promise(resolve => {
    chrome.tabs.query({ active: true, currentWindow: true }, tabs => {
      resolve(tabs[0]);
    });
  });
}

// ── Load API Key Status ──────────────────────────────────
async function loadApiKeyStatus() {
  const result = await chrome.storage.local.get('vtApiKey');
  const apiStatus = document.getElementById('apiStatus');
  if (result.vtApiKey) {
    apiStatus.textContent = '✓ Set';
    apiStatus.className = 'api-is-set';
  } else {
    apiStatus.textContent = 'Not Set';
    apiStatus.className = 'api-not-set';
  }
  return result.vtApiKey || null;
}

// ── Main Scan Function ───────────────────────────────────
async function runScan() {
  const tab = await getCurrentTab();
  if (!tab || !tab.url) return;

  const url = tab.url;

  // Show URL (truncated)
  const urlDisplay = document.getElementById('currentUrl');
  urlDisplay.textContent = url.length > 50 ? url.substring(0, 50) + '...' : url;

  // Skip chrome:// and extension pages
  if (url.startsWith('chrome://') || url.startsWith('chrome-extension://') || url.startsWith('about:')) {
    setRiskCard('safe', '✅ Safe', 0, 'Internal browser page — no scan needed.');
    setAllChecksNA();
    return;
  }

  // Get API key
  const result = await chrome.storage.local.get('vtApiKey');
  const apiKey = result.vtApiKey || null;

  // Show scanning state
  setRiskCard('scanning', '⏳ Scanning...', '--', 'Running checks...');

  try {
    const analysis = await analyseURL(url, apiKey);
    displayResults(analysis);
  } catch (e) {
    setRiskCard('safe', '❓ Error', 0, 'Could not analyse this page.');
  }
}

// ── Display Full Results ─────────────────────────────────
function displayResults(analysis) {
  const { score, level, label, description, results } = analysis;

  // Risk card
  setRiskCard(level, label, score, description);

  // VirusTotal
  const vtEl = document.getElementById('vtResult');
  if (results.virustotal?.checked) {
    const vt = results.virustotal;
    if (vt.malicious > 0) {
      setTag(vtEl, `${vt.malicious}/${vt.total} engines flagged`, 'fail');
    } else if (vt.suspicious > 0) {
      setTag(vtEl, `${vt.suspicious} suspicious`, 'warn');
    } else if (vt.fresh) {
      setTag(vtEl, 'Submitted for scan', 'warn');
    } else {
      setTag(vtEl, `Clean (${vt.total} engines)`, 'pass');
    }
  } else {
    setTag(vtEl, 'No API key', '');
  }

  // Lookalike
  const lookaEl = document.getElementById('lookaResult');
  if (results.lookalike?.detected) {
    setTag(lookaEl, `Mimics "${results.lookalike.matchedBrand}"`, 'fail');
  } else {
    setTag(lookaEl, 'None detected', 'pass');
  }

  // SSL
  const sslEl = document.getElementById('sslResult');
  if (results.ssl?.secure) {
    setTag(sslEl, 'HTTPS ✓', 'pass');
  } else {
    setTag(sslEl, 'No HTTPS ✗', 'fail');
  }

  // Suspicious Keywords
  const suspEl = document.getElementById('suspResult');
  if (results.keywords?.detected) {
    setTag(suspEl, results.keywords.keywords.join(', '), 'fail');
  } else {
    setTag(suspEl, 'None found', 'pass');
  }

  // IP URL
  const ipEl = document.getElementById('ipResult');
  if (results.ip?.detected) {
    setTag(ipEl, 'IP used as URL ⚠️', 'fail');
  } else {
    setTag(ipEl, 'Domain name ✓', 'pass');
  }

  // Send result to background for badge update
  chrome.runtime.sendMessage({
    action: 'updateBadge',
    level: analysis.level,
    score: analysis.score
  });
}

// ── UI Helpers ───────────────────────────────────────────
function setRiskCard(level, label, score, desc) {
  const card = document.getElementById('riskCard');
  card.className = `risk-card ${level}`;
  document.getElementById('riskIcon').textContent =
    level === 'safe' ? '✅' : level === 'suspicious' ? '⚠️' : level === 'dangerous' ? '🚨' : '⏳';
  document.getElementById('riskLabel').textContent =
    level === 'safe' ? 'SAFE' : level === 'suspicious' ? 'SUSPICIOUS' : level === 'dangerous' ? 'DANGEROUS' : 'SCANNING';
  document.getElementById('riskScore').textContent = score === '--' ? '--' : `${score}/100`;
  document.getElementById('riskDesc').textContent = desc;
}

function setTag(el, text, type) {
  el.textContent = text;
  el.className = `detail-val ${type}`;
}

function setAllChecksNA() {
  ['vtResult','lookaResult','sslResult','suspResult','ipResult'].forEach(id => {
    setTag(document.getElementById(id), 'N/A', '');
  });
}

// ── Event Listeners ──────────────────────────────────────
function setupEventListeners() {
  // Toggle API section
  document.getElementById('apiToggle').addEventListener('click', () => {
    const body = document.getElementById('apiBody');
    body.style.display = body.style.display === 'none' ? 'block' : 'none';
  });

  // Save API Key
  document.getElementById('saveApiKey').addEventListener('click', async () => {
    const key = document.getElementById('apiKeyInput').value.trim();
    if (!key) return;
    await chrome.storage.local.set({ vtApiKey: key });
    const apiStatus = document.getElementById('apiStatus');
    apiStatus.textContent = '✓ Set';
    apiStatus.className = 'api-is-set';
    document.getElementById('apiBody').style.display = 'none';
    document.getElementById('apiKeyInput').value = '';
    await runScan(); // Rescan with the new key
  });

  // Rescan button
  document.getElementById('rescanBtn').addEventListener('click', async () => {
    await runScan();
  });
}
