// PhishGuard Content Script: Interstitial Threat Warning Block Screen

chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === "BLOCK_PAGE") {
    renderWarningScreen(request.data);
  }
});

function renderWarningScreen(data) {
  if (document.getElementById("phishguard-interstitial-overlay")) return;

  const overlay = document.createElement("div");
  overlay.id = "phishguard-interstitial-overlay";
  overlay.style.cssText = `
    position: fixed;
    top: 0;
    left: 0;
    width: 100vw;
    height: 100vh;
    background-color: #0f172a;
    color: #f8fafc;
    z-index: 999999999;
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    padding: 24px;
    box-sizing: border-box;
  `;

  const container = document.createElement("div");
  container.style.cssText = `
    max-width: 600px;
    width: 100%;
    background-color: #1e293b;
    border: 1px solid #334155;
    border-radius: 12px;
    padding: 32px;
    box-shadow: 0 20px 25px -5px rgba(0, 0, 0, 0.5);
    text-align: center;
  `;

  const brandName = data.typosquat_details?.target_brand ? data.typosquat_details.target_brand.toUpperCase() : "AUTHENTIC BRAND";
  const editDist = data.typosquat_details?.edit_distance ?? "N/A";

  container.innerHTML = `
    <div style="display: flex; justify-content: center; margin-bottom: 20px;">
      <div style="background-color: #ef4444; width: 64px; height: 64px; border-radius: 50%; display: flex; align-items: center; justify-content: center;">
        <svg width="36" height="36" viewBox="0 0 24 24" fill="none" stroke="white" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round">
          <path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/>
          <line x1="12" y1="9" x2="12" y2="13"/>
          <line x1="12" y1="17" x2="12.01" y2="17"/>
        </svg>
      </div>
    </div>
    
    <h1 style="color: #ef4444; margin: 0 0 8px 0; font-size: 26px; font-weight: 700;">Phishing Site Blocked</h1>
    <p style="color: #94a3b8; font-size: 14px; margin-bottom: 24px;">PhishGuard AI engine detected a dangerous zero-day typosquat or spoofed page.</p>

    <div style="background-color: #0f172a; border-radius: 8px; padding: 16px; margin-bottom: 24px; text-align: left; border-left: 4px solid #ef4444;">
      <div style="margin-bottom: 8px;">
        <span style="color: #64748b; font-size: 12px; font-weight: 600; text-transform: uppercase;">Flagged URL</span>
        <div style="color: #f1f5f9; font-family: monospace; font-size: 13px; word-break: break-all; margin-top: 2px;">${escapeHtml(data.url || window.location.href)}</div>
      </div>
      <div style="display: flex; justify-content: space-between; margin-top: 12px;">
        <div>
          <span style="color: #64748b; font-size: 12px; font-weight: 600; text-transform: uppercase;">Threat Level</span>
          <div style="color: #ef4444; font-weight: 700; font-size: 14px;">${escapeHtml(data.threat_level || "CRITICAL")}</div>
        </div>
        <div>
          <span style="color: #64748b; font-size: 12px; font-weight: 600; text-transform: uppercase;">Risk Score</span>
          <div style="color: #f8fafc; font-weight: 700; font-size: 14px;">${data.risk_score || 98.5} / 100</div>
        </div>
        <div>
          <span style="color: #64748b; font-size: 12px; font-weight: 600; text-transform: uppercase;">Target Brand</span>
          <div style="color: #3b82f6; font-weight: 700; font-size: 14px;">${escapeHtml(brandName)}</div>
        </div>
      </div>
    </div>

    <div style="display: flex; gap: 12px; justify-content: center;">
      <button id="phishguard-btn-safe" style="background-color: #2563eb; color: white; border: none; padding: 12px 24px; border-radius: 6px; font-weight: 600; font-size: 14px; cursor: pointer;">
        Back to Safety
      </button>
      <button id="phishguard-btn-proceed" style="background-color: transparent; color: #94a3b8; border: 1px solid #475569; padding: 12px 20px; border-radius: 6px; font-weight: 500; font-size: 13px; cursor: pointer;">
        Proceed Anyway (Unsafe)
      </button>
    </div>
  `;

  overlay.appendChild(container);
  document.body.appendChild(overlay);

  document.getElementById("phishguard-btn-safe").addEventListener("click", () => {
    window.history.back();
  });

  document.getElementById("phishguard-btn-proceed").addEventListener("click", () => {
    overlay.remove();
  });
}

function escapeHtml(str) {
  return str.replace(/[&<>'"]/g, 
    tag => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', "'": '&#39;', '"': '&quot;' }[tag] || tag)
  );
}
