# 🛡️ PhishGuard - Phishing Detection Browser Extension

> A real-time browser extension that detects phishing and malicious URLs using multiple threat intelligence techniques.

![PhishGuard Demo](demo.png)

---

## 🔍 What It Does

PhishGuard automatically analyses every website you visit and gives it a **Risk Score from 0–100** based on:

| Check | Description |
|-------|-------------|
| 🔍 VirusTotal API | Cross-checks URL against 90+ antivirus engines |
| 🎭 Lookalike Domain | Detects fake domains mimicking brands (paypa1.com, g00gle.com) |
| 🔒 HTTPS Check | Flags sites collecting data without SSL |
| ⚠️ Suspicious Keywords | Detects phishing keywords in the URL |
| 🌐 IP-based URL | Flags URLs using raw IP addresses |
| 📋 Form Hijacking | Detects forms that send data to a different domain |

---

## 🚦 Risk Levels

| Score | Level | Meaning |
|-------|-------|---------|
| 0–20 | ✅ Safe | No threats detected |
| 21–55 | ⚠️ Suspicious | Some risk indicators — proceed with caution |
| 56–100 | 🚨 Dangerous | High risk phishing site — do NOT enter credentials |

---

## 🛠️ Tech Stack

- **JavaScript** (Chrome Extension Manifest V3)
- **VirusTotal API v3** (threat intelligence)
- **Levenshtein Distance Algorithm** (lookalike domain detection)
- **Chrome Storage API** (save API key locally)
- **Chrome Notifications API** (alert on dangerous sites)

---

## 📦 Installation (Developer Mode)

### Step 1 — Download the project
```bash
git clone https://github.com/yourusername/phishguard.git
```

### Step 2 — Open Chrome Extensions
- Open Chrome browser
- Type `chrome://extensions` in the address bar
- Press Enter

### Step 3 — Enable Developer Mode
- Toggle **"Developer mode"** ON (top right corner)

### Step 4 — Load the Extension
- Click **"Load unpacked"**
- Select the `phishguard` folder
- PhishGuard icon will appear in your toolbar ✅

### Step 5 — Add VirusTotal API Key (Free)
1. Go to [virustotal.com](https://virustotal.com)
2. Create a free account
3. Click your profile → **API Key**
4. Copy the key
5. Click the PhishGuard icon → ⚙️ settings → paste your key

---

## 🧪 How to Test It

Test on these intentionally vulnerable/safe sites:

```
# Should show SAFE
https://google.com
https://github.com

# Should show SUSPICIOUS (HTTP, no SSL)
http://example.com

# Test in your local lab (DVWA)
http://localhost/dvwa
```

---

## 📁 Project Structure

```
phishguard/
│
├── manifest.json          # Extension configuration
├── popup.html             # Extension popup UI
├── popup.js               # Popup logic & UI controller
├── popup.css              # Styling
│
├── src/
│   ├── detector.js        # Core detection engine
│   ├── background.js      # Background service worker
│   └── content.js         # Injected into web pages
│
└── icons/
    ├── icon16.png
    ├── icon48.png
    └── icon128.png
```

---

## 🔬 Detection Algorithms

### Lookalike Domain Detection
Uses the **Levenshtein Distance Algorithm** to find domains within 2 character edits of popular brands:
```
paypa1.com  →  paypal.com  (distance: 1) ✓ FLAGGED
g00gle.com  →  google.com  (distance: 2) ✓ FLAGGED
amazon.com  →  amazon.com  (distance: 0) ✓ SAFE
```

### Risk Scoring System
```
IP as URL detected     → +35 points
Lookalike domain       → +40 points
No HTTPS               → +20 points
Suspicious keywords    → +20 points
URL complexity         → +10 points
VirusTotal detections  → +10 per engine (max 50)
```

---

## 🔮 Future Improvements

- [ ] Machine learning model for better detection
- [ ] Whitelist trusted domains
- [ ] Export scan history as PDF report
- [ ] Firefox support
- [ ] Domain age checking (new domains = more suspicious)

---

## 👨‍💻 Author

**Your Name**  
B.Tech (ENTC) | CEH Aspirant  
[LinkedIn](#) | [GitHub](#)

---

## ⚠️ Disclaimer

This tool is built for **educational and cybersecurity awareness purposes only**. Always test on your own systems or with explicit permission.

---

## 📄 License

MIT License — Free to use and modify
