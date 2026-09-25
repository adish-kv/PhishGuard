// PhishGuard WebExtension Service Worker
// Handles real-time URL auto-scanning via PhishGuard backend API (FastAPI)

const API_ENDPOINT = "http://127.0.0.1:8000/api/v1/analyze";
const SCAN_CACHE = new Map();
let autoProtectionEnabled = true;

// Initialize configuration on startup
chrome.runtime.onInstalled.addListener(() => {
  chrome.storage.local.set({
    autoProtection: true,
    scanHistory: [],
    blockedCount: 0
  });
  console.log("[PhishGuard] Background Service Worker initialized.");
});

// Load storage settings
chrome.storage.local.get(["autoProtection"], (result) => {
  if (result.autoProtection !== undefined) {
    autoProtectionEnabled = result.autoProtection;
  }
});

// Listen for settings changes
chrome.storage.onChanged.addListener((changes) => {
  if (changes.autoProtection) {
    autoProtectionEnabled = changes.autoProtection.newValue;
  }
});

// Helper: check if URL is internal or safe scheme
function isExcludedUrl(url) {
  if (!url) return true;
  return (
    url.startsWith("chrome://") ||
    url.startsWith("chrome-extension://") ||
    url.startsWith("about:") ||
    url.startsWith("edge://") ||
    url.startsWith("http://127.0.0.1") ||
    url.startsWith("http://localhost")
  );
}

// Perform URL Analysis against backend
async function scanUrl(url) {
  if (isExcludedUrl(url)) {
    return { url, is_phishing: false, threat_level: "SAFE", risk_score: 0 };
  }

  if (SCAN_CACHE.has(url)) {
    return SCAN_CACHE.get(url);
  }

  try {
    const response = await fetch(API_ENDPOINT, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url })
    });

    if (!response.ok) {
      throw new Error(`HTTP ${response.status}`);
    }

    const data = await response.json();
    SCAN_CACHE.set(url, data);

    // Save to local history
    chrome.storage.local.get(["scanHistory", "blockedCount"], (res) => {
      const history = res.scanHistory || [];
      history.unshift({
        url,
        timestamp: new Date().toISOString(),
        threat_level: data.threat_level,
        risk_score: data.risk_score,
        verdict: data.verdict
      });
      // Keep last 50 entries
      const updatedHistory = history.slice(0, 50);
      let blockedCount = res.blockedCount || 0;
      if (data.is_phishing || data.threat_level === "CRITICAL" || data.threat_level === "HIGH") {
        blockedCount += 1;
      }
      chrome.storage.local.set({ scanHistory: updatedHistory, blockedCount });
    });

    return data;
  } catch (error) {
    console.error("[PhishGuard] Backend connection error:", error);
    return {
      url,
      is_phishing: false,
      threat_level: "UNKNOWN",
      risk_score: 0,
      error: "Backend unavailable"
    };
  }
}

// Auto-Scan Listener: Intercept web navigation
chrome.webNavigation.onBeforeNavigate.addListener(async (details) => {
  if (details.frameId !== 0) return; // Main frame only
  if (!autoProtectionEnabled) return;

  const { tabId, url } = details;
  if (isExcludedUrl(url)) return;

  const result = await scanUrl(url);

  if (result.is_phishing || result.threat_level === "CRITICAL" || result.threat_level === "HIGH") {
    console.warn(`[PhishGuard Threat Detected] ${url} | Level: ${result.threat_level}`);
    
    // Send message to tab content script to render block interstitial screen
    chrome.tabs.sendMessage(tabId, {
      action: "BLOCK_PAGE",
      data: result
    }).catch(() => {
      // Tab may not be fully loaded yet; fallback retry on updated
    });
  }
});

// Listener for messages from Popup UI
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === "MANUAL_SCAN") {
    scanUrl(request.url).then((result) => sendResponse({ success: true, data: result }));
    return true; // Keep message channel open for async response
  } else if (request.action === "GET_STATUS") {
    sendResponse({ autoProtection: autoProtectionEnabled });
  }
});
