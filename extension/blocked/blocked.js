/**
 * ⚡ CYBERPUNK PHISH-SHIELD — Interstitial Warning Controller
 * Handles diagnostic URL rendering and session bypass whitelist actions.
 */

document.addEventListener("DOMContentLoaded", () => {
  const urlParams = new URLSearchParams(window.location.search);
  const targetUrl = urlParams.get("url") || "Unknown Host";
  const rawScore = urlParams.get("score") || "90";
  const reason = urlParams.get("reason") || "AI Phishing Classifier Flagged High Threat";

  const targetUrlDisplay = document.getElementById("targetUrlDisplay");
  const scoreDisplay = document.getElementById("scoreDisplay");
  const reasonDisplay = document.getElementById("reasonDisplay");

  const safetyBtn = document.getElementById("safetyBtn");
  const bypassBtn = document.getElementById("bypassBtn");

  targetUrlDisplay.textContent = targetUrl;
  scoreDisplay.textContent = `${Math.round(parseFloat(rawScore))}%`;
  reasonDisplay.textContent = reason;

  safetyBtn.addEventListener("click", () => {
    if (window.history.length > 1) {
      window.history.back();
    } else {
      window.close();
    }
  });

  bypassBtn.addEventListener("click", () => {
    const confirmBypass = confirm("⚠️ SECURITY WARNING:\nYou are choosing to bypass the Cyberpunk Phish-Shield defense grid. This domain may attempt to harvest credentials or install malware.\n\nProceed to site?");
    if (confirmBypass) {
      chrome.runtime.sendMessage({ type: "WHITELIST_URL", url: targetUrl }, (response) => {
        window.location.href = targetUrl;
      });
    }
  });
});
