/**
 * ⚡ CYBERPUNK PHISH-SHIELD — Service Worker (Manifest V3)
 * Handles redirect monitoring, backend API sync, badge state, caching, and interstitial triggers.
 */

importScripts("ml_ondevice.js");

const API_BACKEND_URL = "http://127.0.0.1:5000/api/analyze";
const CACHE_TTL_MS = 24 * 60 * 60 * 1000; // 24 hours
const redirectChains = new Map(); // tabId -> list of redirected URLs

// Initialize default storage on install
if (typeof chrome !== "undefined" && chrome.runtime && chrome.runtime.onInstalled) {
  chrome.runtime.onInstalled.addListener(() => {
    if (chrome.storage && chrome.storage.local) {
      chrome.storage.local.set({
        cached_analyses: {},
        whitelisted_urls: [],
        threat_history: []
      });
    }
    console.log("⚡ [PHISH-SHIELD] Background Service Worker Initialized.");
  });
}

// Helper to update extension Action Badge
function updateBadge(tabId, status, score) {
  if (typeof chrome === "undefined" || !chrome.action) return;
  let badgeText = "SAFE";
  let badgeColor = "#00ff88"; // Green

  if (status === "DANGER" || score >= 75) {
    badgeText = "ALERT";
    badgeColor = "#ff0055"; // Pink / Red
  } else if (status === "WARN" || score >= 40) {
    badgeText = "WARN";
    badgeColor = "#ffb700"; // Amber
  }

  try {
    chrome.action.setBadgeText({ tabId, text: badgeText });
    chrome.action.setBadgeBackgroundColor({ tabId, color: badgeColor });
  } catch (e) {
    console.warn("Unable to update action badge:", e);
  }
}

// Redirect Chain Mapping via webNavigation
if (typeof chrome !== "undefined" && chrome.webNavigation && chrome.webNavigation.onBeforeRedirect) {
  chrome.webNavigation.onBeforeRedirect.addListener((details) => {
    if (details.frameId !== 0) return;
    const tabId = details.tabId;
    if (!redirectChains.has(tabId)) {
      redirectChains.set(tabId, []);
    }
    const chain = redirectChains.get(tabId);
    chain.push({
      from: details.url,
      to: details.redirectUrl,
      timestamp: Date.now()
    });
    console.log(`🔀 [REDIRECT TRACKER] Tab ${tabId}: ${details.url} -> ${details.redirectUrl}`);
  });
}

// Navigation Listener: webNavigation.onCommitted (Guaranteed target URL)
if (typeof chrome !== "undefined" && chrome.webNavigation && chrome.webNavigation.onCommitted) {
  chrome.webNavigation.onCommitted.addListener((details) => {
    if (details.frameId === 0 && details.url) {
      const url = details.url;
      if (!url.startsWith("chrome://") && !url.startsWith("chrome-extension://") && !url.startsWith("edge://") && !url.startsWith("about:")) {
        analyzeTabUrl(details.tabId, url);
      }
    }
  });
}

// Fallback Tab update listener
if (typeof chrome !== "undefined" && chrome.tabs && chrome.tabs.onUpdated) {
  chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
    const targetUrl = changeInfo.url || tab.pendingUrl || tab.url;
    if (targetUrl && !targetUrl.startsWith("chrome://") && !targetUrl.startsWith("chrome-extension://") && !targetUrl.startsWith("edge://") && !targetUrl.startsWith("about:")) {
      analyzeTabUrl(tabId, targetUrl);
    }
  });
}

async function analyzeTabUrl(tabId, rawUrl) {
  if (typeof chrome === "undefined" || !chrome.storage || !chrome.storage.local || !rawUrl) return;

  // Check if URL is whitelisted by user session
  try {
    const storage = await chrome.storage.local.get(["whitelisted_urls", "cached_analyses"]);
    const whitelist = storage.whitelisted_urls || [];
    if (whitelist.includes(rawUrl)) {
      updateBadge(tabId, "SAFE", 0);
      return;
    }

    const cachedMap = storage.cached_analyses || {};
    const cacheEntry = cachedMap[rawUrl];
    
    // 1. Check local cache (24 hours TTL)
    if (cacheEntry && (Date.now() - cacheEntry.timestamp < CACHE_TTL_MS)) {
      processAnalysisResult(tabId, rawUrl, cacheEntry.data);
      return;
    }

    // 2. Sub-10ms On-Device Local Scoring
    const localResult = OnDeviceML.predictClientRiskScore(rawUrl);
    updateBadge(tabId, localResult.status, localResult.riskScore);

    // If local score is extremely dangerous (>85%), trigger block page immediately
    if (localResult.riskScore >= 85) {
      triggerInterstitial(tabId, rawUrl, localResult.riskScore, "High-Risk Heuristics Detected");
      return;
    }

    // 3. Backend REST API Request
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 3000); // 3s timeout

    const response = await fetch(API_BACKEND_URL, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url: rawUrl }),
      signal: controller.signal
    });
    clearTimeout(timeoutId);

    if (response.ok) {
      const data = await response.json();
      
      // Save in local cache
      cachedMap[rawUrl] = { timestamp: Date.now(), data: data };
      await chrome.storage.local.set({ cached_analyses: cachedMap });

      processAnalysisResult(tabId, rawUrl, data);
    } else {
      processAnalysisResult(tabId, rawUrl, createFallbackData(rawUrl, localResult));
    }
  } catch (err) {
    const localResult = OnDeviceML.predictClientRiskScore(rawUrl);
    processAnalysisResult(tabId, rawUrl, createFallbackData(rawUrl, localResult));
  }
}

function processAnalysisResult(tabId, url, data) {
  updateBadge(tabId, data.status, data.riskScore || data.risk_score);

  const score = data.riskScore !== undefined ? data.riskScore : data.risk_score;
  
  if (score >= 40 && typeof chrome !== "undefined" && chrome.storage && chrome.storage.local) {
    chrome.storage.local.get(["threat_history"], (res) => {
      const history = res.threat_history || [];
      history.unshift({ url, score, status: data.status, timestamp: Date.now() });
      chrome.storage.local.set({ threat_history: history.slice(0, 50) });
    });
  }

  // Interstitial block check (> 80% risk score)
  if (score >= 80) {
    triggerInterstitial(tabId, url, score, data.verdict || "AI Phishing Classifier Flagged High Threat");
  }
}

function triggerInterstitial(tabId, targetUrl, score, reason) {
  if (typeof chrome === "undefined" || !chrome.runtime || !chrome.tabs) return;
  const blockUrl = chrome.runtime.getURL("blocked/blocked.html") + 
    `?url=${encodeURIComponent(targetUrl)}` + 
    `&score=${encodeURIComponent(score)}` +
    `&reason=${encodeURIComponent(reason)}`;
  
  try {
    chrome.tabs.update(tabId, { url: blockUrl });
  } catch (e) {
    console.warn("Failed to update tab URL for interstitial block:", e);
  }
}

function createFallbackData(url, localResult) {
  return {
    url: url,
    risk_score: localResult.riskScore,
    status: localResult.status,
    verdict: localResult.status === "DANGER" ? "HEURISTIC_PHISHING_ALERT" : (localResult.status === "WARN" ? "SUSPICIOUS_ANOMALY" : "VERIFIED_SAFE"),
    checklist: [
      { name: "On-Device Engine", status: localResult.status === "DANGER" ? "FAIL" : "PASS", value: `Score: ${localResult.riskScore}%` },
      { name: "Backend Status", status: "WARN", value: "Offline / Standalone Fallback" }
    ],
    details: localResult.features
  };
}

// Handle runtime messages from content script & popup
if (typeof chrome !== "undefined" && chrome.runtime && chrome.runtime.onMessage) {
  chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (message.type === "DOM_AUDIT_ALERT") {
      if (sender.tab?.id) {
        updateBadge(sender.tab.id, "DANGER", 90);
        if (message.severity === "HIGH") {
          triggerInterstitial(sender.tab.id, message.details.pageUrl, 92, message.reason);
        }
      }
    } else if (message.type === "GET_REDIRECT_CHAIN") {
      const chain = redirectChains.get(message.tabId) || [];
      sendResponse({ chain });
    } else if (message.type === "WHITELIST_URL") {
      if (chrome.storage && chrome.storage.local) {
        chrome.storage.local.get(["whitelisted_urls"], (res) => {
          const list = res.whitelisted_urls || [];
          if (!list.includes(message.url)) {
            list.push(message.url);
            chrome.storage.local.set({ whitelisted_urls: list });
          }
          sendResponse({ status: "ok" });
        });
      }
      return true;
    }
  });
}
