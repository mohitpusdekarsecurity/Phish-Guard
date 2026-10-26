// ═══════════════════════════════════════════════════════════
// PhishGuard - Content Script
// Injected into every webpage to detect suspicious forms
// ═══════════════════════════════════════════════════════════

(function () {
  'use strict';

  // Only run once
  if (window.__phishguard_loaded) return;
  window.__phishguard_loaded = true;

  // ── Detect suspicious password/login forms ────────────
  function checkForSuspiciousForms() {
    const forms = document.querySelectorAll('form');
    const inputs = document.querySelectorAll('input[type="password"], input[type="email"]');

    // If page has login form but no HTTPS → very suspicious
    if (inputs.length > 0 && window.location.protocol !== 'https:') {
      showWarningBanner(
        '⚠️ PhishGuard Warning: This page is collecting sensitive data (passwords/emails) WITHOUT a secure HTTPS connection!'
      );
      return;
    }

    // Check for hidden form actions pointing to different domain
    forms.forEach(form => {
      const action = form.action;
      if (action && action.startsWith('http')) {
        try {
          const formDomain = new URL(action).hostname;
          const pageDomain = window.location.hostname;
          if (formDomain !== pageDomain && inputs.length > 0) {
            showWarningBanner(
              `⚠️ PhishGuard Warning: This form submits your data to a DIFFERENT domain (${formDomain}). This is a common phishing trick!`
            );
          }
        } catch (e) {}
      }
    });
  }

  // ── Show a banner warning on dangerous pages ──────────
  function showWarningBanner(message) {
    // Don't add twice
    if (document.getElementById('phishguard-banner')) return;

    const banner = document.createElement('div');
    banner.id = 'phishguard-banner';
    banner.style.cssText = `
      position: fixed;
      top: 0;
      left: 0;
      right: 0;
      z-index: 2147483647;
      background: linear-gradient(90deg, #b71c1c, #d32f2f);
      color: white;
      padding: 12px 20px;
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
      font-size: 14px;
      font-weight: 500;
      text-align: center;
      box-shadow: 0 2px 10px rgba(0,0,0,0.5);
      display: flex;
      align-items: center;
      justify-content: center;
      gap: 12px;
    `;

    banner.innerHTML = `
      <span>${message}</span>
      <button onclick="document.getElementById('phishguard-banner').remove()" style="
        background: rgba(255,255,255,0.2);
        border: 1px solid rgba(255,255,255,0.4);
        color: white;
        padding: 4px 12px;
        border-radius: 4px;
        cursor: pointer;
        font-size: 12px;
        white-space: nowrap;
      ">Dismiss</button>
    `;

    document.body.insertBefore(banner, document.body.firstChild);
  }

  // Run checks after DOM loads
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', checkForSuspiciousForms);
  } else {
    checkForSuspiciousForms();
  }

})();
