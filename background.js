// ═══════════════════════════════════════════════════════════
// PhishGuard - Background Service Worker
// Runs silently in the background, watches every page load
// ═══════════════════════════════════════════════════════════

importScripts('detector.js');

// ── Listen for tab updates ───────────────────────────────
chrome.tabs.onUpdated.addListener(async (tabId, changeInfo, tab) => {
  if (changeInfo.status !== 'complete') return;
  if (!tab.url || tab.url.startsWith('chrome://') || tab.url.startsWith('chrome-extension://')) return;

  const result = await chrome.storage.local.get('vtApiKey');
  const apiKey = result.vtApiKey || null;

  try {
    const analysis = await analyseURL(tab.url, apiKey);
    updateBadge(tabId, analysis.level, analysis.score);

    // Show notification for dangerous sites
    if (analysis.level === 'dangerous') {
      chrome.notifications.create(`phish-${tabId}`, {
        type: 'basic',
        iconUrl: '../icons/icon48.png',
        title: '🚨 PhishGuard Warning!',
        message: `Dangerous site detected!\nRisk Score: ${analysis.score}/100\n${tab.url.substring(0, 60)}...`,
        priority: 2
      });
    }

    // Store result for this tab
    await chrome.storage.local.set({ [`tab_${tabId}`]: analysis });
  } catch (e) {
    console.error('PhishGuard background error:', e);
  }
});

// ── Update Extension Badge ───────────────────────────────
function updateBadge(tabId, level, score) {
  const colors = {
    safe: '#00c853',
    suspicious: '#ff9800',
    dangerous: '#f44336'
  };
  const texts = {
    safe: '✓',
    suspicious: '!',
    dangerous: '!!'
  };

  chrome.action.setBadgeBackgroundColor({
    color: colors[level] || '#555',
    tabId
  });
  chrome.action.setBadgeText({
    text: texts[level] || '?',
    tabId
  });
}

// ── Listen for messages from popup ──────────────────────
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.action === 'updateBadge') {
    chrome.tabs.query({ active: true, currentWindow: true }, tabs => {
      if (tabs[0]) updateBadge(tabs[0].id, message.level, message.score);
    });
  }
});
