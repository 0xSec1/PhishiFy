console.log("Background Loaded");

const VT_CACHE_KEY = "VT_CACHE";
const CACHE_TTL_MS = 24 * 60 * 60 * 1000; //24 Hours
let globalStats = {checked: 0, clean: 0, suspicious: 0};

//Get cache objct from storage
function getPersistentCache(){
  return new Promise((resolve) => {
    try{
      chrome.storage.local.get([VT_CACHE_KEY], (res) => {
        resolve(res[VT_CACHE_KEY] || {});
      });
    }catch(e){
      console.warn("[Background] Storage get failed", e);
      resolve({});
    }
  });
}

function setPersistentCache(obj){
  return new Promise((resolve) => {
    try{
      const toStore = {};
      toStore[VT_CACHE_KEY] = obj;
      chrome.storage.local.set(toStore, () => resolve());
    }catch(e){
      console.warn("[Background] storage set failed", e);
      resolve();
    }
  });
}

function updateGlobalStats(vtStats){
  globalStats.checked++;
  const maliciousCount = vtStats?.mailcious || 0;
  if(maliciousCount > 0){
    globalStats.suspicious++;
  }else{
    globalStats.clean++;
  }
}

chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {

  if(request.action == "get_stats"){
    sendResponse(globalStats);
    return;
  }

  if(request.action == "clear_cache"){
    chrome.storage.local.remove(VT_CACHE_KEY, () => {
      globalStats = {checked: 0, clean: 0, suspicious: 0};
      console.log("Cache Cleared");
      sendResponse({success: true});
    });
    return true;
  }

  if(request.action == "check_url"){
    const href = request.url;

    (async() => {
      try{
        const cache = await getPersistentCache();
        const entry = cache[href];
        const now = Date.now();

        //If Cached return cache
        if(entry && (now - entry.ts) < CACHE_TTL_MS && entry.stats){
          sendResponse({stats: entry.stats, cached: true});
          return;
        }

        //Get API Key
        const data = await new Promise((res) => chrome.storage.local.get(["VT_API_KEY"], res));
        const apiKey = data.VT_API_KEY;
        if(!apiKey){
          sendResponse({error: "API Not set in option"});
          return;
        }

        const submitRep = await fetch("https://www.virustotal.com/api/v3/urls",{
          method: "POST",
          headers: {
            "x-apikey": apiKey,
            "Content-Type": "application/x-www-form-urlencoded"
          },

          body: `url=${encodeURIComponent(href)}`
        });

        if(!submitRep.ok){
          console.error("VT Submit failed:",submitRep.status);
          sendResponse({error: `Submit failed (${submitRep.status})`});
          return;
        }

        const submitData = await submitRep.json();
        const analysisId  = submitData?.data?.id;
        if(!analysisId){
          sendResponse({error: "No analysis ID returned"});
          return;
        }

        const resultRep = await fetch(`https://www.virustotal.com/api/v3/analyses/${analysisId}`,
          {headers:{"x-apikey": apiKey}}
        );

        if(!resultRep.ok){
          console.error("VT Result fetch failed:", resultRep.status);
          sendResponse({error:`Result fetch failed (${resultRep.status})`});
          return;
        }

        const resultData = await resultRep.json();
        const vtStats = resultData?.data?.attributes?.stats || {};
        sendResponse({vtStats});

        //Update persistent cache url
        cache[href] = {vtStats, ts:Date.now()};
        await setPersistentCache(cache);

        sendResponse({vtStats, cached: false});
        updateGlobalStats(vtStats);
      }catch(err){
        console.error("VT API Error:", err);
        sendResponse({error: "Failed to query VT"});
      }
    })();
    return true;  //keep msg channel open
  }
});

