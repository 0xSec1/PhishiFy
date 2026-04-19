console.log("[PhishDetector] Background Loaded");

// No more caching!
let globalStats = { checked: 0, clean: 0, suspicious: 0 };

// -------------------- MAIN MESSAGE HANDLER --------------------
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {

  if (message.action === "get_stats") {
    sendResponse(globalStats);
    return false; // synchronous
  }

  // -------------------- FULL EMAIL AI CHECK --------------------
  if (message.action === "analyze_email" && message.data) {
    const payload = message.data;
    
    (async () => {
      try {
        const res = await fetch("http://127.0.0.1:5000/predict_email", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(payload),
        });
        
        const data = await res.json();

        if (data.label === "phishing") {
          globalStats.suspicious++;
        } else {
          globalStats.clean++;
        }
        globalStats.checked++;

        sendResponse({ result: data });
      } catch (err) {
        console.error("[Background] AI API error:", err);
        sendResponse({ error: "Failed to query backend", result: { label: "error", probability: 0 } });
      }
    })();
    return true; // asynchronous
  }
});
