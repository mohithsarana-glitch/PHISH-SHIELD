/**
 * ⚡ CYBERPUNK PHISH-SHIELD — On-Device Lightweight ML Engine
 * Executes client-side Random Forest / Heuristic probability scoring in sub-10ms.
 */

(function (root) {
  const HIGH_RISK_KEYWORDS = [
    "otp", "cvv", "verify", "login", "bank", "account", "secure",
    "update", "signin", "auth", "paypal", "free", "gift", "billing",
    "credential", "passcode", "security", "wallet", "crypto"
  ];

  function isIpAddress(hostname) {
    const ipv4 = /^(\d{1,3}\.){3}\d{1,3}$/;
    const ipv6 = /^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$/;
    return ipv4.test(hostname) || ipv6.test(hostname);
  }

  function extractClientFeatures(rawUrl) {
    let parsed;
    try {
      parsed = new URL(rawUrl.includes("://") ? rawUrl : "http://" + rawUrl);
    } catch (e) {
      parsed = { hostname: "", pathname: "", search: "", protocol: "http:" };
    }

    const hostname = parsed.hostname || "";
    const fullPath = (parsed.pathname + parsed.search).toLowerCase();

    const parts = hostname.split(".").filter(Boolean);
    const numSubdomains = parts.length > 2 ? parts.length - 2 : 0;

    const urlLength = rawUrl.length;
    const hasAtSymbol = rawUrl.includes("@") ? 1 : 0;
    const numHyphens = (rawUrl.match(/-/g) || []).length;
    const isIp = isIpAddress(hostname) ? 1 : 0;

    let keywordCount = 0;
    HIGH_RISK_KEYWORDS.forEach((kw) => {
      if (fullPath.includes(kw) || hostname.toLowerCase().includes(kw)) {
        keywordCount++;
      }
    });

    const numDigits = (rawUrl.match(/\d/g) || []).length;
    const isHttps = parsed.protocol === "https:" ? 1 : 0;

    return {
      urlLength,
      numSubdomains,
      hasAtSymbol,
      numHyphens,
      isIp,
      keywordCount,
      numDigits,
      isHttps,
      hostname,
    };
  }

  function predictClientRiskScore(rawUrl) {
    const feats = extractClientFeatures(rawUrl);
    let score = 5.0; // Baseline safety score

    // 1. IP Address in Hostname (+45%)
    if (feats.isIp) {
      score += 45.0;
    }

    // 2. '@' Symbol in URL (+30%)
    if (feats.hasAtSymbol) {
      score += 30.0;
    }

    // 3. Excessive Subdomains (>3 subdomains +25%)
    if (feats.numSubdomains >= 3) {
      score += 25.0;
    } else if (feats.numSubdomains >= 2) {
      score += 12.0;
    }

    // 4. Excessive Hyphens (>3 hyphens +18%)
    if (feats.numHyphens >= 4) {
      score += 22.0;
    } else if (feats.numHyphens >= 2) {
      score += 10.0;
    }

    // 5. Urgency / Phishing Keywords (+15% per token, max 40%)
    if (feats.keywordCount > 0) {
      score += Math.min(feats.keywordCount * 15.0, 40.0);
    }

    // 6. Non-HTTPS insecure protocol on sensitive login keywords (+20%)
    if (!feats.isHttps && (feats.keywordCount > 0 || feats.isIp)) {
      score += 20.0;
    }

    // 7. Excessive URL Length (>70 chars +15%)
    if (feats.urlLength > 100) {
      score += 20.0;
    } else if (feats.urlLength > 70) {
      score += 12.0;
    }

    // 8. Digit density ratio (+10%)
    if (feats.numDigits > 15) {
      score += 12.0;
    }

    const finalScore = Math.min(100.0, Math.max(0.0, Math.round(score * 10) / 10));

    let status = "SAFE";
    if (finalScore >= 75.0) status = "DANGER";
    else if (finalScore >= 40.0) status = "WARN";

    return {
      riskScore: finalScore,
      status: status,
      isLocalPrediction: true,
      features: feats,
    };
  }

  const OnDeviceML = {
    extractClientFeatures,
    predictClientRiskScore,
  };

  if (typeof module !== "undefined" && module.exports) {
    module.exports = OnDeviceML;
  } else {
    root.OnDeviceML = OnDeviceML;
  }
})(typeof self !== "undefined" ? self : this);
