console.log("Background Loaded");
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if(request.action == "check_url"){
    const href = request.url;

    chrome.storage.local.get(["VT_API_KEY"], async(data) => {
      const apiKey = data.VT_API_KEY;
      if(!apiKey){
        sendResponse({error: "API Not set in option"});
        return;
      }

      try{
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
        const stats = resultData?.data?.attributes?.stats || {};
        sendResponse({stats});

      }catch(err){
        console.error("VT API Error:",err);
        sendResponse({error: "Failed to query Virustotal"});
      }
    });
    return true;  //keep msg channel open
  }
})
