document.addEventListener("DOMContentLoaded", () => {
    const scannedEl = document.getElementById("stat-scanned");
    const cleanEl = document.getElementById("stat-clean");
    const phishEl = document.getElementById("stat-phish");
    const openDashboardBtn = document.getElementById("open-dashboard");
  
    // Load Stats on pop-up open
    chrome.runtime.sendMessage({ action: "get_stats" }, (stats) => {
      if (stats) {
        scannedEl.innerText = stats.checked || 0;
        cleanEl.innerText = stats.clean || 0;
        phishEl.innerText = stats.suspicious || 0;
      }
    });
  
    // Open full Dashboard webpage
    openDashboardBtn.addEventListener("click", () => {
      chrome.tabs.create({ url: chrome.runtime.getURL("dashboard/index.html") });
    });
  });