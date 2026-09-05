"use strict";

const api = globalThis.browser || globalThis.chrome;
const $ = id => document.getElementById(id);
let tab;
let host;
// The page's scheme, sent with every request. The core refuses an
// https-bound record on an http page, and refuses it again when the scheme
// is missing -- so omitting this would silently stop autofill, not weaken it.
let scheme;

function call(message) {
  const payload={channel:"spm", ...message};
  if (globalThis.browser) return browser.runtime.sendMessage(payload);
  return new Promise(resolve => chrome.runtime.sendMessage(payload, response =>
    resolve(response || {ok:false,error:chrome.runtime.lastError?.message || "Extension request failed."})));
}

function setStatus(message, error=false) {
  $("status").textContent = message;
  $("status").classList.toggle("error", error);
}

async function fill(record) {
  setStatus("Verifying the hostname and retrieving the selected account…");
  const response = await call({action:"get", record, host, scheme});
  if (!response?.ok) return setStatus(response?.error || "Could not retrieve that account.", true);
  // spmFillForm lives in fill.js so the test drives the same function this
  // ships, rather than a copy of it that could drift without either failing.
  await api.scripting.executeScript({target:{tabId:tab.id}, func:spmFillForm,
    args:[response.username,response.password]});
  response.password = "";
  setStatus("Filled after verifying the hostname and the page's scheme.");
}

function showAccounts(matches) {
  $("unlock").classList.add("hidden");
  $("accounts").classList.remove("hidden");
  const list = $("accountList"); list.replaceChildren();
  for (const account of matches) {
    const button = document.createElement("button"); button.type="button"; button.className="account";
    button.append(document.createTextNode(account.label || `Record ${account.id}`));
    const detail=document.createElement("small"); detail.textContent=account.username || "No username"; button.append(detail);
    button.addEventListener("click",()=>fill(account.id)); list.append(button);
  }
  setStatus(matches.length ? "Choose an account to fill." : "No accounts are bound to this page.");
}

async function list() {
  const response=await call({action:"list",host,scheme});
  if (response?.ok) showAccounts(response.matches || []);
  else { $("accounts").classList.add("hidden"); $("unlock").classList.remove("hidden"); setStatus(response?.error || "Unlock SPM to continue.",false); }
}

$("unlockButton").addEventListener("click",async()=>{
  let master=$("master").value; $("master").value="";
  if (!master) return setStatus("Enter your master password.",true);
  setStatus("Unlocking locally…");
  const response=await call({action:"unlock",host,scheme,master}); master="";
  if (!response?.ok) return setStatus(response?.error || "Unlock failed.",true);
  showAccounts(response.matches || []);
});
$("refresh").addEventListener("click",list);
$("lock").addEventListener("click",async()=>{ await call({action:"lock"}); $("accounts").classList.add("hidden"); $("unlock").classList.remove("hidden"); setStatus("SPM is locked."); });

(async()=>{
  [tab]=await api.tabs.query({active:true,currentWindow:true});
  try { const url=new URL(tab.url); if (!/^https?:$/.test(url.protocol)) throw new Error(); host=url.hostname; scheme=url.protocol.replace(":",""); $("host").textContent=host; await list(); }
  catch { setStatus("Open an HTTP or HTTPS page before using autofill.",true); }
})().catch(error=>setStatus(error.message,true));
