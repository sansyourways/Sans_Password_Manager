const status = document.getElementById("status");
document.getElementById("fill").addEventListener("click", async () => {
  const record = document.getElementById("record").value.trim();
  const master = document.getElementById("master").value;
  document.getElementById("master").value = "";
  if (!/^\d+$/.test(record) || !master) { status.textContent = "Record ID and master password are required."; return; }
  const [tab] = await chrome.tabs.query({active: true, currentWindow: true});
  const url = new URL(tab.url); status.textContent = "Requesting a domain-bound record…";
  chrome.runtime.sendNativeMessage("xyz.sansyourways.spm", {action:"get", record, host:url.hostname, master}, async response => {
    master.replace?.(/./g, "0");
    if (chrome.runtime.lastError || !response?.ok) { status.textContent = response?.error || chrome.runtime.lastError?.message || "Request failed."; return; }
    await chrome.scripting.executeScript({target:{tabId:tab.id}, func:(u,p)=>{
      const visible=e=>e.offsetParent!==null&&!e.disabled&&!e.readOnly;
      const passwords=[...document.querySelectorAll('input[type="password"]')].filter(visible);
      const users=[...document.querySelectorAll('input[type="email"],input[autocomplete="username"],input[type="text"]')].filter(visible);
      const set=(el,v)=>{if(!el)return;el.focus();el.value=v;el.dispatchEvent(new Event('input',{bubbles:true}));el.dispatchEvent(new Event('change',{bubbles:true}));};
      set(users[0],u);set(passwords[0],p);
    }, args:[response.username,response.password]});
    response.password = ""; status.textContent = "Filled after exact hostname verification.";
  });
});
