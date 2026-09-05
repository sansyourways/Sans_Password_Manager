"use strict";

const api = globalThis.browser || globalThis.chrome;
const $ = id => document.getElementById(id);
let tab;
let host;
// The page's scheme, sent with every request. The core refuses an
// https-bound record on an http page, and refuses it again when the scheme
// is missing -- so omitting this would silently stop autofill, not weaken it.
let scheme;

/* How long an unlocked session stays usable with nothing happening.
 *
 * This used to be a fixed five minutes settable only by an environment
 * variable, which the extension cannot reach -- so in practice it was not
 * settable at all, and it is what ends a session in normal use. Measurement
 * is what moved this: a connected native port keeps the MV3 service worker
 * alive well past the ten minutes this was assumed to survive, so the timeout
 * SPM chooses is the binding constraint rather than the browser's.
 *
 * The list is bounded and the host clamps whatever arrives, because a longer
 * window means the master password sits in the host's memory for longer. The
 * default is unchanged.
 */
const LOCK_CHOICES = [[60, "1 minute"], [300, "5 minutes"], [900, "15 minutes"],
                      [1800, "30 minutes"], [3600, "1 hour"]];
const DEFAULT_LOCK = 300;

function readSetting() {
  return new Promise((resolve) => {
    try { api.storage.local.get({idle: DEFAULT_LOCK}, (value) => resolve(value?.idle ?? DEFAULT_LOCK)); }
    catch { resolve(DEFAULT_LOCK); }
  });
}

function writeSetting(idle) {
  try { api.storage.local.set({idle}); } catch { /* a preference, not state */ }
}

function describeSession(info) {
  if (!info?.ok || !info.unlocked) return "";
  const minutes = Math.round((info.expires_in || 0) / 60);
  const window = LOCK_CHOICES.find(([value]) => value === info.idle);
  const after = window ? window[1] : `${Math.round((info.idle || 0) / 60)} minutes`;
  if (info.expires_in < 60) return `Locks in under a minute · idle limit ${after}`;
  return `Locks in about ${minutes} minute${minutes === 1 ? "" : "s"} · idle limit ${after}`;
}

async function showSession() {
  $("session").textContent = describeSession(await call({action: "status"}));
}

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
  showSession();
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
  const idle=Number($("lockAfter").value)||DEFAULT_LOCK;
  writeSetting(idle);
  setStatus("Unlocking locally…");
  const response=await call({action:"unlock",host,scheme,master,idle}); master="";
  if (!response?.ok) return setStatus(response?.error || "Unlock failed.",true);
  showAccounts(response.matches || []);
});
$("refresh").addEventListener("click",list);
$("lock").addEventListener("click",async()=>{ await call({action:"lock"}); $("accounts").classList.add("hidden"); $("unlock").classList.remove("hidden"); setStatus("SPM is locked."); });

(async()=>{
  const chosen=await readSetting();
  const picker=$("lockAfter");
  for (const [value,label] of LOCK_CHOICES) {
    const option=document.createElement("option");
    option.value=String(value); option.textContent=label;
    option.selected=value===chosen;
    picker.append(option);
  }
  [tab]=await api.tabs.query({active:true,currentWindow:true});
  try { const url=new URL(tab.url); if (!/^https?:$/.test(url.protocol)) throw new Error(); host=url.hostname; scheme=url.protocol.replace(":",""); $("host").textContent=host; await list(); }
  catch { setStatus("Open an HTTP or HTTPS page before using autofill.",true); }
})().catch(error=>setStatus(error.message,true));
