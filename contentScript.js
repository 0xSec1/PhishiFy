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

  //Find anchor within root node
  function findAnchors(root = document){
    //Narrow it 
    const anchors = Array.from(root.querySelectorAll('a'));
    const results = [];

    anchors.forEach(a => {
      try{
        const visibleText = getVisibleText(a);
        const href = getHref(a);
        if(!href) return;
        results.push({
          visibleText,
          href,
          location: window.location.href
        });
      }catch(e){
        console.error(LOG_PREFIX,'error reading anchor',e);
      }
    });

    if(results.length){
      console.log(LOG_PREFIX,'found anchors:',results);
    }
    return results;
  }

  //Debounce helper
  function debounce(fn, wait = 250){
    let t = null;
    return function(...args){
      clearTimeout(t);
      t = setTimeout(() => fn.apply(this, args), wait);
    };
  }

  //Initial Scan
  findAnchors();

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

  //Small Debug helper
  window._phishDetect = {
    findAnchors: () => findAnchors(document)
  };
})();
