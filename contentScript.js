// Basic Anchor Discovery + logging + dynamic observation
(function(){
  const LOG_PREFIX = '[PhishDetect]';

  //Get visible text of an element
  function getVisibleText(el){
    try{
      return el.textContent ? el.textContent.trim() : '';
    }catch(e){
      return '';
    }
  }

  //Return href string
  function getHref(a){
    try{
      return a.href || a.getAttribute('href') || '';
    }catch(e){
      return '';
    }
  }

  //Get Root Domain
  function getRootDomain(url){
    try{
      const hostname = new URL(url).hostname;
      const parts = hostname.split(".");
      return parts.slice(-2).join(".");
    }catch{
      return null;
    }
  }

  //Check visible text with href
  //TODO-> Check for punnycode
  function heuristicCheck(visibleText, href){
    try{
      const rootDomain = getRootDomain(href);
      if(!rootDomain){
        return true;  //Invalid -- suspicious
      }
      if(!visibleText.toLowerCase().includes(rootDomain)){
        return true;  //mismatch -- suspicious
      }
      return false;
    }catch{
      return true;
    }
  }

  //Check for Provider
  function getAnchorSelector(){
    if(window.location.hostname.includes("mail.google.com")){
      return "div.a3s a"; //Gmail
    }
    // Use When needed
    // if(window.location.hostname.includes("outlook.office.com")){
    //   return "div[data-msg-id] a";  //Outlook
    // }
    return "a"; //Fallback
  }

  //TODO->safeGetFromStorage, and virustotal check fixes

  //Find anchor within root node
  function findAnchors(root = document){
    //Narrow it use Array.from if needed to use array methods
    const selector = getAnchorSelector();
    const anchors = root.querySelectorAll(selector);
    const results = [];

    anchors.forEach(a => {
      try{
        const visibleText = getVisibleText(a);
        const href = getHref(a);
        if(!href) return;

        //Highlight Suspicious links
        if(isSuspicious(visibleText, href)){
          a.style.border = "2px solid red";
          a.style.backgroundColor = "rgba(255,0,0,0.1)";
          a.title = LOG_PREFIX + "Suspicious Link";
        }
        results.push({
          visibleText,
          href,
          location: window.location.href
        });
        checkWithVirusTotal(a.href);
      }catch(e){
        console.error(LOG_PREFIX,'error reading anchor',e);
      }
    });

    if(results.length){
      console.log(LOG_PREFIX,'found anchors in mail body:',results);
    }
    return results;
  }

  // Check Suspicious Links
  function isSuspicious(visibleText, href){
    try{
      const url = new URL(href);
      const hostname = url.hostname.toLowerCase();
      const rootDomain = getRootDomain(href);

      //If Whitelist --> Not suspicious
      if(WHITELIST_DOMAINS.includes(hostname)) return false;
      //If contain root domain in text --> NOT suspicious
      if(visibleText.toLowerCase().includes(rootDomain)) return false;

      return true;  //Suspicious
    }catch{
      return true; //Invalid url -> Suspicious
    }
  }

  function checkWithVirusTotal(href){
    chrome.runtime.sendMessage({action: "check_url", url: href}, (response) => {
      if (!response || response.error){
        console.warn("[PhishDetect] VT Check Error:", response?.error);
        return;
      }

      const stats = response.stats;
      if(stats && stats.malicious > 0){
        console.warn("Suspicious Link detected", href, stats);
      }else{
        console.log("Link is clean:", href);
      }
    });
  }

  //Debounce helper
  function debounce(fn, wait = 250){
    let t = null;
    return function(...args){
      clearTimeout(t);
      t = setTimeout(() => fn.apply(this, args), wait);
    };
  }


  //Observe DOM Changes
  const observer = new MutationObserver(debounce(mutations => {
    //TODO:-> refine which mutation to handle, for now find anchors
    findAnchors();
  }, 300));

  try{
    observer.observe(document.documentElement || document.body, {
      childList: true,
      subtree: true
    });
    console.log(LOG_PREFIX,'mutation observer attached');
  }catch(e){
    console.warn(LOG_PREFIX,'could not attach mutation observer',e);
  }

  //Initial Scan
  findAnchors();
  //Small Debug helper
  window._phishDetect = {
    findAnchors: () => findAnchors(document)
  };
})();
