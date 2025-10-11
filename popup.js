document.addEventListener("DOMContentLoaded", async () => {
  const checkedEl = document.getElementById("checked");
  const cleanEl = document.getElementById("clean");
  const suspiciousEl = document.getElementById("suspicious");
  const statusMsg = document.getElementById("statusMsg");
  const clearBtn = document.getElementById("clearCache");

  //Get stats from background
  chrome.runtime.sendMessage({action:"get_stats"}, (stats) => {
    checkedEl.textContent = stats.checked || 0;
    cleanEl.textContent = stats.clean || 0;
    suspiciousEl.textContent = stats.suspicious || 0;
  });

  //Clear cache Button handler
  clearBtn.addEventListener("click", () => {
    chrome.runtime.sendMessage({action: "clear_cache"}, (res) => {
      if(res?.success){
        statusMsg.textContent = "Cache Cleared";
        setTimeout(() => (statusMsg.textContent = ""), 2000);
      }else{
        statusMsg.textContent = "Failed To Clear Cache";
        setTimeout(() => (statusMsg.textContent = ""), 2000);
      }
    });
  });
});
