const status = document.getElementById("status");
document.getElementById("fill").addEventListener("click", async () => {
  const record = document.getElementById("record").value.trim();
  let master = document.getElementById("master").value;
  document.getElementById("master").value = "";
  if (!/^\d+$/.test(record) || !master) { status.textContent = "Record ID and master password are required."; return; }
  const [tab] = await chrome.tabs.query({active: true, currentWindow: true});
  const url = new URL(tab.url); status.textContent = "Requesting a domain-bound record…";
  chrome.runtime.sendNativeMessage("xyz.sansyourways.spm", {action:"get", record, host:url.hostname, master}, async response => {
    master = "";
    if (chrome.runtime.lastError || !response?.ok) { status.textContent = response?.error || chrome.runtime.lastError?.message || "Request failed."; return; }
    // spmFillForm from fill.js, the same function the universal extension
    // injects. This copy used to be its own inline function and had drifted:
    // it assigned el.value directly, which a framework that tracks its own
    // state ignores -- the field looked filled and the form submitted empty.
    await chrome.scripting.executeScript({target:{tabId:tab.id}, func:spmFillForm,
      args:[response.username,response.password]});
    response.password = ""; status.textContent = "Filled after exact hostname verification.";
  });
});
