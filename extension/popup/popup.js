document.addEventListener("DOMContentLoaded", () => {
  const toggle = document.getElementById("autoProtectToggle");
  const statusBadge = document.getElementById("statusBadge");
  const urlInput = document.getElementById("urlInput");
  const scanBtn = document.getElementById("scanBtn");
  const resultBox = document.getElementById("resultBox");
  const verdictText = document.getElementById("verdictText");
  const riskScore = document.getElementById("riskScore");
  const resultDetails = document.getElementById("resultDetails");
  const historyList = document.getElementById("historyList");

  // Load current toggle state & history
  chrome.storage.local.get(["autoProtection", "scanHistory"], (data) => {
    if (data.autoProtection !== undefined) {
      toggle.checked = data.autoProtection;
      updateStatusBadge(data.autoProtection);
    }
    if (data.scanHistory) {
      renderHistory(data.scanHistory);
    }
  });

  // Auto populate current tab URL in input box
  chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
    if (tabs.length > 0 && tabs[0].url && !tabs[0].url.startsWith("chrome://")) {
      urlInput.value = tabs[0].url;
    }
  });

  toggle.addEventListener("change", () => {
    const isEnabled = toggle.checked;
    chrome.storage.local.set({ autoProtection: isEnabled });
    updateStatusBadge(isEnabled);
  });

  function updateStatusBadge(enabled) {
    if (enabled) {
      statusBadge.textContent = "Active";
      statusBadge.style.backgroundColor = "#dcfce7";
      statusBadge.style.color = "#166534";
    } else {
      statusBadge.textContent = "Paused";
      statusBadge.style.backgroundColor = "#fee2e2";
      statusBadge.style.color = "#991b1b";
    }
  }

  scanBtn.addEventListener("click", () => {
    const url = urlInput.value.trim();
    if (!url) return;

    scanBtn.disabled = true;
    scanBtn.textContent = "Scanning...";
    resultBox.classList.add("hidden");

    chrome.runtime.sendMessage({ action: "MANUAL_SCAN", url }, (response) => {
      scanBtn.disabled = false;
      scanBtn.textContent = "Scan";

      if (response && response.success && response.data) {
        displayResult(response.data);
        // Refresh history
        chrome.storage.local.get(["scanHistory"], (data) => {
          if (data.scanHistory) renderHistory(data.scanHistory);
        });
      } else {
        alert("Failed to contact PhishGuard backend. Ensure API server is running on http://127.0.0.1:8000.");
      }
    });
  });

  function displayResult(data) {
    resultBox.classList.remove("hidden");
    const level = data.threat_level || "SAFE";
    verdictText.textContent = level;
    verdictText.className = `verdict ${level}`;
    riskScore.textContent = `${data.risk_score || 0} / 100`;

    let details = `Verdict: ${data.verdict || "Analysis Complete"}`;
    if (data.typosquat_details && data.typosquat_details.target_brand) {
      details += `<br><strong>Zero-Day Typosquat:</strong> Target "${data.typosquat_details.target_brand}" (Edit Dist: ${data.typosquat_details.edit_distance})`;
    }
    resultDetails.innerHTML = details;
  }

  function renderHistory(items) {
    if (!items || items.length === 0) {
      historyList.innerHTML = '<div class="empty-history">No recent scans recorded.</div>';
      return;
    }

    historyList.innerHTML = items.slice(0, 10).map((item) => `
      <div class="history-item">
        <span class="history-url" title="${escapeHtml(item.url)}">${escapeHtml(item.url)}</span>
        <span class="history-badge badge-${item.threat_level}">${item.threat_level}</span>
      </div>
    `).join("");
  }

  function escapeHtml(str) {
    return str.replace(/[&<>'"]/g, tag => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', "'": '&#39;', '"': '&quot;' }[tag] || tag));
  }
});
