// PhishiFy Content Script - Full Email Analysis
(function () {
  const LOG_PREFIX = '[PhishDetect]';

  // Basic DOM extractors for Gmail
  function getVisibleText(el) { return el ? el.textContent.trim() : ''; }
  function getHref(a) { return a ? (a.href || a.getAttribute('href') || '') : ''; }

  function extractEmailContent() {
    // These selectors are specific to Gmail's current DOM structure
    // Sender extraction
    let senderEl = document.querySelector('span[email]');
    let sender = senderEl ? senderEl.getAttribute('email') : '';

    // Subject extraction
    let subjectEl = document.querySelector('h2[data-thread-perm-id]');
    let subject = getVisibleText(subjectEl);

    // Body extraction
    let bodyEl = document.querySelector('.a3s.aiL'); // Main email body container
    let bodyText = getVisibleText(bodyEl);

    // Links extraction
    let links = [];
    if (bodyEl) {
      let anchors = bodyEl.querySelectorAll('a');
      anchors.forEach(a => {
        let href = getHref(a);
        if (href) links.push({ text: getVisibleText(a), url: href });
      });
    }

    // Attachments extraction metadata (names/types)
    let attachments = [];
    let attachmentNodes = document.querySelectorAll('.aQy'); // Attachment container class
    attachmentNodes.forEach(node => {
        attachments.push({ name: getVisibleText(node) });
    });

    return { sender, subject, bodyText, links, attachments };
  }

  // Inject a small banner for scanning status
  function showStatusBanner(status, severity) {
    let existing = document.getElementById('phishify-banner');
    if (existing) existing.remove();

    let banner = document.createElement('div');
    banner.id = 'phishify-banner';
    banner.style.cssText = `
      position: fixed; top: 0; left: 0; width: 100%; z-index: 999999;
      padding: 10px; text-align: center; font-weight: bold; font-family: sans-serif;
      transition: all 0.3s ease; box-shadow: 0 2px 5px rgba(0,0,0,0.2);
    `;

    if (severity === 'high') {
      banner.style.backgroundColor = '#ff4d4f'; banner.style.color = '#fff';
    } else if (severity === 'low') {
      banner.style.backgroundColor = '#52c41a'; banner.style.color = '#fff';
    } else {
      banner.style.backgroundColor = '#faad14'; banner.style.color = '#fff';
    }

    banner.innerText = status;
    document.body.prepend(banner);

    // Auto-remove banner after 5 seconds for ALL emails (safe or malicious)
    setTimeout(() => {
      if (document.getElementById('phishify-banner')) {
        banner.remove();
      }
    }, 5000);
  }

  // Trigger scanning when clicking an email or periodically
  function scanEmail() {
    try {
      const emailData = extractEmailContent();
      if (!emailData.bodyText && !emailData.sender) return; // No open email detected

      console.log(LOG_PREFIX, 'Scanning full email content...');
      showStatusBanner('PhishiFy: Scanning email content...', 'medium');

      chrome.runtime.sendMessage(
        { action: "analyze_email", data: emailData },
        response => {
          if (chrome.runtime.lastError) {
            console.warn(LOG_PREFIX, 'Analysis server connection error:', chrome.runtime.lastError.message);
            return;
          }
          if (!response || response.error) {
            showStatusBanner('PhishiFy: Error contacting analysis server.', 'medium');
            return;
          }

          const { result } = response;
          if (result.label === 'phishing') {
            showStatusBanner('Phishing Alert! (' + (result.probability * 100).toFixed(1) + '% Confidence)', 'high');
          } else {
            showStatusBanner('This email appears safe (' + ((1 - result.probability) * 100).toFixed(1) + '% safe)', 'low');
          }
        }
      );
    } catch (e) {
      console.warn(LOG_PREFIX, "Error scanning email:", e);
    }
  }

  // Initial and observed scans
  setInterval(() => {
    // Run mostly when URL changes or thread view changes (simple hacky observer for MVP)
    let currentThread = document.querySelector('h2[data-thread-perm-id]');
    if (currentThread && currentThread.dataset.scanned !== "true") {
      currentThread.dataset.scanned = "true";
      scanEmail();
    }
  }, 2000);

})();