"use strict";

const api = globalThis.browser || globalThis.chrome;
const HOST = "xyz.sansyourways.spm";
let port = null;
let sequence = 0;
const pending = new Map();

function rejectPending(message) {
  for (const {reject} of pending.values()) reject(new Error(message));
  pending.clear();
}

function connect() {
  if (port) return port;
  port = api.runtime.connectNative(HOST);
  port.onMessage.addListener(message => {
    const waiter = pending.get(message.id);
    if (!waiter) return;
    pending.delete(message.id);
    waiter.resolve(message);
  });
  port.onDisconnect.addListener(() => {
    const message = api.runtime.lastError?.message || "SPM native host disconnected.";
    port = null;
    unlocked = false;
    rejectPending(message);
  });
  return port;
}

function nativeRequest(message) {
  return new Promise((resolve, reject) => {
    const id = String(++sequence);
    pending.set(id, {resolve, reject});
    try { connect().postMessage({...message, id}); }
    catch (error) { pending.delete(id); reject(error); }
  });
}

/* ---------------------------------------------------------------------------
 * The in-field picker.
 *
 * One rule holds this together: a message from a page frame is told what host
 * it is on, never asked. `sender.url` is written by the browser, so it is the
 * only statement about the page that the page cannot influence -- a content
 * script that supplied its own hostname would be supplying a hostname an
 * attacker could eventually choose, and the whole point of the bridge is that
 * a record reaches exactly the site it is bound to.
 *
 * The account list never crosses into the page. The content script is told how
 * many accounts matched and nothing more; the list itself is handed to
 * menu.html, which runs at this extension's origin inside an iframe.
 * ------------------------------------------------------------------------- */

const MENU_TTL_MS = 60000;
const EXTENSION_PREFIX = api.runtime.getURL("");
const menus = new Map();
// Whether the native host currently holds an unlocked session. Tracked so a
// focused login field on a locked browser does not start the host and run a
// vault read per keystroke-worth of focus; the host remains the authority and
// refuses anyway.
let unlocked = false;

const LOCKED = "SPM is locked or the session expired";
const REFUSED = "SPM refused the request";

function pageContext(sender) {
  if (!sender || typeof sender.url !== "string" || !sender.tab) return null;
  let url;
  try { url = new URL(sender.url); } catch { return null; }
  if (url.protocol !== "http:" && url.protocol !== "https:") return null;
  // Only the top-level frame. A login form inside a cross-origin iframe is a
  // standard credential-theft pattern, and this extension cannot tell a
  // same-origin embed from a hostile one without reading the tab's own URL,
  // which needs a permission worth more than the case it would enable. So the
  // whole class is refused, and refused here rather than in the page.
  if (sender.frameId !== 0) return null;
  return {host: url.hostname, scheme: url.protocol.replace(":", ""), tabId: sender.tab.id};
}

function fromExtensionPage(sender) {
  return Boolean(sender && typeof sender.url === "string" && sender.url.startsWith(EXTENSION_PREFIX));
}

function sweep() {
  const now = Date.now();
  for (const [key, entry] of menus) if (now - entry.at > MENU_TTL_MS) menus.delete(key);
}

function entryFor(message, sender, page) {
  sweep();
  const entry = menus.get(String(message?.nonce || ""));
  if (!entry) return null;
  if (page && (entry.tabId !== page.tabId || entry.host !== page.host)) return null;
  if (!page && !fromExtensionPage(sender)) return null;
  return entry;
}

async function handleMenu(action, message, sender) {
  if (action === "menu-open") {
    const page = pageContext(sender);
    if (!page || !unlocked) return {ok: false};
    const response = await nativeRequest({action: "list", host: page.host, scheme: page.scheme});
    if (!response?.ok) {
      if (response?.error === LOCKED) unlocked = false;
      return {ok: false};
    }
    const matches = response.matches || [];
    if (!matches.length) return {ok: false};
    const nonce = crypto.randomUUID();
    menus.set(nonce, {...page, matches, chosen: null, at: Date.now()});
    // The count, not the accounts. It is what the menu has to be sized to, and
    // it is the one thing the page can infer anyway from the overlay's height.
    return {ok: true, nonce, count: matches.length};
  }

  if (action === "menu-rows") {
    const entry = entryFor(message, sender, null);
    return entry ? {ok: true, matches: entry.matches} : {ok: false};
  }

  if (action === "menu-choose") {
    const entry = entryFor(message, sender, null);
    if (!entry) return {ok: false};
    const record = String(message.record || "");
    if (!entry.matches.some((match) => String(match.id) === record)) return {ok: false};
    entry.chosen = record;
    // Bounced back through the content script rather than filled from here, so
    // that the browser re-attests the frame's URL at the moment of the fill.
    api.tabs.sendMessage(entry.tabId, {channel: "spm", action: "menu-commit-request", nonce: message.nonce},
                         {frameId: 0}).catch(() => {});
    return {ok: true};
  }

  if (action === "menu-key") {
    const page = pageContext(sender);
    const entry = entryFor(message, sender, page);
    if (!page || !entry) return {ok: false};
    api.runtime.sendMessage({channel: "spm-menu", nonce: message.nonce, key: String(message.key || "")})
      .catch(() => {});
    return {ok: true};
  }

  if (action === "menu-commit") {
    const page = pageContext(sender);
    const entry = entryFor(message, sender, page);
    if (!page || !entry || !entry.chosen) return {ok: false, error: REFUSED};
    // Single use. A menu fills once, and the record it fills is the record the
    // user picked in it.
    menus.delete(String(message.nonce));
    if (entry.scheme !== page.scheme) return {ok: false, error: REFUSED};
    // host and scheme come from `page`, read from the browser now, not from
    // the entry recorded when the list was built. The page can navigate
    // between the menu opening and the choice landing, and a fill aimed at
    // where the user used to be is the failure this re-read exists to stop.
    return await nativeRequest({action: "get", record: entry.chosen, host: page.host, scheme: page.scheme});
  }

  if (action === "menu-close") {
    menus.delete(String(message?.nonce || ""));
    return {ok: true};
  }

  return {ok: false, error: REFUSED};
}

const MENU_ACTIONS = new Set(["menu-open", "menu-rows", "menu-choose", "menu-key", "menu-commit", "menu-close"]);

api.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (!message || message.channel !== "spm") return false;
  if (MENU_ACTIONS.has(message.action)) {
    handleMenu(message.action, message, sender).then(sendResponse)
      .catch(() => sendResponse({ok: false, error: REFUSED}));
    return true;
  }
  // Everything else is the popup's channel: unlock, lock, list, get, each
  // carrying the host the popup read from the active tab. A page frame reaching
  // this branch would be naming its own hostname, so it does not get to.
  if (pageContext(sender) || (sender?.tab && !fromExtensionPage(sender))) {
    sendResponse({ok: false, error: REFUSED});
    return false;
  }
  nativeRequest(message).then((response) => {
    if (message.action === "unlock" && response?.ok) unlocked = true;
    if (message.action === "lock") unlocked = false;
    if (response?.error === LOCKED) unlocked = false;
    sendResponse(response);
  }).catch(error => sendResponse({ok: false, error: error.message}));
  return true;
});
