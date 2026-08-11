/**
 * ⚡ CYBERPUNK PHISH-SHIELD — Content Script DOM Auditor
 * Scans page forms, external credential post targets, and hidden exploit iframes.
 */

(function () {
  console.log("⚡ [PHISH-SHIELD] Content Script Active on:", window.location.hostname);

  function auditForms() {
    const currentHost = window.location.hostname.toLowerCase();
    const forms = document.querySelectorAll("form");

    forms.forEach((form, idx) => {
      const actionAttr = form.getAttribute("action");
      if (!actionAttr) return;

      let targetHost = "";
      try {
        const targetUrl = new URL(actionAttr, window.location.href);
        targetHost = targetUrl.hostname.toLowerCase();
      } catch (e) {
        return;
      }

      if (!targetHost || targetHost === currentHost) return;

      // Check if form collects sensitive credentials (password, OTP, email, card)
      const inputs = form.querySelectorAll("input");
      let collectsCredentials = false;

      inputs.forEach((input) => {
        const type = (input.getAttribute("type") || "").toLowerCase();
        const name = (input.getAttribute("name") || "").toLowerCase();
        const id = (input.getAttribute("id") || "").toLowerCase();

        if (
          type === "password" ||
          name.includes("pass") ||
          name.includes("otp") ||
          name.includes("cvv") ||
          name.includes("card") ||
          id.includes("pass") ||
          id.includes("login")
        ) {
          collectsCredentials = true;
        }
      });

      if (collectsCredentials) {
        console.warn(`🚨 [DOM AUDIT] Form #${idx} posts credentials to external host: ${targetHost}`);
        chrome.runtime.sendMessage({
          type: "DOM_AUDIT_ALERT",
          severity: "HIGH",
          reason: `Form credential exfiltration detected! Post target '${targetHost}' differs from page host '${currentHost}'.`,
          details: {
            pageUrl: window.location.href,
            pageHost: currentHost,
            targetHost: targetHost,
            formAction: actionAttr
          }
        });
      }
    });
  }

  function auditHiddenIframes() {
    const iframes = document.querySelectorAll("iframe");

    iframes.forEach((iframe, idx) => {
      const style = window.getComputedStyle(iframe);
      const width = parseFloat(style.width) || iframe.width || 0;
      const height = parseFloat(style.height) || iframe.height || 0;
      const opacity = parseFloat(style.opacity);
      const display = style.display;
      const visibility = style.visibility;

      const isHidden =
        opacity === 0 ||
        display === "none" ||
        visibility === "hidden" ||
        (width <= 2 && height <= 2);

      const src = iframe.getAttribute("src") || "";

      if (isHidden && src && !src.startsWith("about:") && !src.startsWith("javascript:")) {
        console.warn(`🚨 [DOM AUDIT] Hidden micro iframe detected: ${src} (Dimensions: ${width}x${height}, Opacity: ${opacity})`);
        chrome.runtime.sendMessage({
          type: "DOM_AUDIT_ALERT",
          severity: "MEDIUM",
          reason: "Hidden cross-site iframe detected masking background data transmission.",
          details: {
            pageUrl: window.location.href,
            iframeSrc: src,
            dimensions: `${width}x${height}`
          }
        });
      }
    });
  }

  // Execute audits on DOM load
  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", () => {
      auditForms();
      auditHiddenIframes();
    });
  } else {
    auditForms();
    auditHiddenIframes();
  }

  // Monitor dynamic DOM changes (single-page applications)
  const observer = new MutationObserver(() => {
    auditForms();
    auditHiddenIframes();
  });

  observer.observe(document.body || document.documentElement, {
    childList: true,
    subtree: true
  });
})();
