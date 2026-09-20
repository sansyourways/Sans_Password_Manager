"use strict";

/* The in-field picker, page side.
 *
 * This script runs in the page's frame but not in the page's world, and it is
 * deliberately the least trusted part of the feature. It never learns which
 * accounts matched: it asks the background for a count, anchors an iframe, and
 * the account list is rendered inside that iframe by menu.js at the extension
 * origin, where page script cannot reach it.
 *
 * Three things this file is responsible for, and nothing else:
 *   - deciding a focused field looks like a login field
 *   - placing the menu next to it and keeping it there
 *   - performing the fill with the one credential it is handed at the end
 *
 * It never tells the background which host it is on. The background reads that
 * from the browser's own view of the sender, because a hostname this script
 * supplied would be a hostname the page could eventually choose.
 */

const api = globalThis.browser || globalThis.chrome;

const ROW_HEIGHT = 44;
const VISIBLE_ROWS = 4;
const MIN_WIDTH = 240;
const MAX_WIDTH = 360;
const KEYS = ["ArrowDown", "ArrowUp", "Enter", "Escape", "Tab"];

let menu = null;
// A fill focuses the boxes it writes, which is a focus event like any other
// and would reopen the picker on top of the credential it just placed. The
// window is short and deliberate: long enough to swallow the fill's own focus,
// short enough that a user who wants a different account only has to click.
let suppressUntil = 0;

function send(message) {
  const payload = {channel: "spm", ...message};
  if (globalThis.browser) return browser.runtime.sendMessage(payload).catch(() => null);
  return new Promise((resolve) => {
    try { chrome.runtime.sendMessage(payload, (response) => { void chrome.runtime.lastError; resolve(response || null); }); }
    catch { resolve(null); }
  });
}

/* A password box is a login field. A text or email box is one when it is
 * labelled as a username, or when it shares a form with a password box --
 * which is the shape of every login form and of almost nothing else. Guessing
 * more widely would put a credential menu on search bars and comment fields.
 */
function isLoginField(element) {
  if (!(element instanceof HTMLInputElement) || element.disabled || element.readOnly) return false;
  if (element.type === "password") return true;
  if (element.type !== "text" && element.type !== "email") return false;
  const autocomplete = (element.getAttribute("autocomplete") || "").toLowerCase();
  if (autocomplete.includes("username") || autocomplete.includes("email")) return true;
  return Boolean((element.form || document).querySelector('input[type="password"]'));
}

/* Take the menu off the page. `dismiss` is the half that does not tell the
 * background, which matters during a commit: the nonce is what the background
 * looks the pending choice up by, so releasing it there would refuse the fill
 * the user just asked for. */
function dismiss() {
  if (!menu) return null;
  const {nonce, shell} = menu;
  menu = null;
  shell.remove();
  return nonce;
}

function close() {
  const nonce = dismiss();
  if (nonce) send({action: "menu-close", nonce});
}

function place() {
  if (!menu) return;
  const box = menu.field.getBoundingClientRect();
  const width = Math.min(MAX_WIDTH, Math.max(MIN_WIDTH, box.width));
  const height = Math.min(VISIBLE_ROWS, menu.count) * ROW_HEIGHT + 2;
  // Below the field, unless there is no room below and there is room above.
  const below = box.bottom + height <= window.innerHeight || box.top < height;
  const top = below ? box.bottom : box.top - height;
  menu.frame.style.setProperty("width", `${width}px`, "important");
  menu.frame.style.setProperty("height", `${height}px`, "important");
  menu.frame.style.setProperty("top", `${Math.round(top)}px`, "important");
  menu.frame.style.setProperty("left", `${Math.round(box.left)}px`, "important");
}

async function open(field) {
  close();
  if (Date.now() < suppressUntil) return;
  const response = await send({action: "menu-open"});
  if (!response || !response.ok || !response.count) {
    // Nothing to fill. The one useful thing left to say is a look-alike caution,
    // and only once per page so a focused field does not nag.
    if (response && response.warning && !cautioned) {
      cautioned = true;
      showPhishingCaution(response.warning);
    }
    return;
  }
  if (document.activeElement !== field) return;

  // The shadow root is here for CSS, not for safety: it stops the page's own
  // stylesheet from reaching the frame element and hiding or moving it. The
  // security boundary is the iframe's origin, one line below -- a shadow root
  // still lives in this document and a determined page can walk to it.
  const shell = document.createElement("div");
  const root = shell.attachShadow({mode: "closed"});
  const frame = document.createElement("iframe");
  frame.setAttribute("title", "Sans Password Manager accounts");
  frame.src = `${api.runtime.getURL("menu.html")}#${response.nonce}`;
  frame.style.cssText = "all:initial;position:fixed;z-index:2147483647;border:0;"
    + "color-scheme:light dark;box-shadow:0 6px 24px rgba(0,0,0,.35);border-radius:10px;";
  root.append(frame);
  (document.body || document.documentElement).append(shell);

  menu = {nonce: response.nonce, count: response.count, field, shell, frame, selected: false};
  place();
}

/* The gesture rule. A page can call field.focus() and it can dispatch a
 * KeyboardEvent that looks exactly like Enter, but it cannot forge isTrusted:
 * the browser sets it, and only for input the user really produced. Opening
 * the menu is not gated on it, because opening reveals nothing; choosing an
 * account is, because choosing is the fill.
 */
function onKeyDown(event) {
  if (!menu || event.target !== menu.field || !event.isTrusted) return;
  if (!KEYS.includes(event.key)) return;
  if (event.key === "Escape" || event.key === "Tab") { close(); return; }
  // Enter belongs to the form until the user has actually moved into the menu,
  // otherwise the picker would swallow the submit of anyone typing a password
  // by hand.
  if (event.key === "Enter" && !menu.selected) return;
  if (event.key !== "Enter") menu.selected = true;
  event.preventDefault();
  event.stopPropagation();
  send({action: "menu-key", nonce: menu.nonce, key: event.key});
}

async function commit(nonce) {
  if (!menu || menu.nonce !== nonce) return;
  dismiss();
  suppressUntil = Date.now() + 800;
  const response = await send({action: "menu-commit", nonce});
  if (!response || !response.ok) return;
  // spmFillForm comes from fill.js, which is listed ahead of this file and
  // shares this isolated world. It is the same function the popup injects and
  // the same one tests/extension-fill.mjs drives.
  spmFillForm(response.username, response.password);
  response.username = "";
  response.password = "";
}

/* ----- save-on-submit (roadmap 39) and generate (roadmap 40) -------------
 * The host and scheme are never supplied from here: the save message carries
 * only the credential, and the background reads the host from the browser's own
 * view of this frame, exactly as the picker does. */
function spmVisible(el) {
  return el && el.offsetParent !== null && !el.disabled && !el.readOnly;
}

function captureFrom(form) {
  const scope = form && form.querySelectorAll ? form : document;
  const pw = [...scope.querySelectorAll('input[type="password"]')].filter(spmVisible)[0];
  if (!pw || !pw.value) return null;
  const user = [...scope.querySelectorAll(
    'input[type="email"],input[autocomplete="username"],input[type="text"]')].filter(spmVisible)[0];
  return {username: user ? user.value : "", password: pw.value};
}

let banner = null;
let cautioned = false;
function closeBanner() { if (banner) { banner.remove(); banner = null; } }

/* ----- look-alike / phishing caution (roadmap 35) ------------------------
 * Shown when the page is bound to no account but resembles one the vault knows.
 * A closed shadow root, like the save banner: the page cannot read the name of
 * the site it is imitating out of our warning. It never blocks -- it says a
 * true, local thing ("this looks like somewhere you have an account") and lets
 * the person decide. */
let caution = null;
function closeCaution() { if (caution) { caution.remove(); caution = null; } }
function showPhishingCaution(warning) {
  closeCaution();
  const how = {
    homoglyph: "uses look-alike characters imitating",
    lookalike: "reads like a swapped-character copy of",
    typosquat: "is one keystroke away from",
  }[warning.reason] || "resembles";
  const shell = document.createElement("div");
  const root = shell.attachShadow({mode: "closed"});
  const box = document.createElement("div");
  box.setAttribute("style", "all:initial;position:fixed;z-index:2147483647;right:16px;bottom:16px;"
    + "font:14px system-ui,sans-serif;background:#3a1d1d;color:#ffe9e5;padding:14px 16px;"
    + "border-left:4px solid #e06a5a;border-radius:10px;box-shadow:0 6px 24px rgba(0,0,0,.4);"
    + "max-width:320px;color-scheme:dark");
  const msg = document.createElement("div");
  msg.textContent = "This site " + how + " " + warning.suspected
    + ", where you have an account. If you did not mean to come here, do not enter those credentials.";
  msg.setAttribute("style", "margin:0 0 10px;line-height:1.4");
  const ok = document.createElement("button");
  ok.textContent = "Dismiss";
  ok.setAttribute("style", "all:initial;cursor:pointer;border-radius:8px;padding:8px 14px;"
    + "font:700 13px system-ui;background:#e06a5a;color:#2a1210");
  ok.addEventListener("click", closeCaution);
  box.append(msg, ok);
  root.append(box);
  (document.body || document.documentElement).append(shell);
  caution = shell;
  setTimeout(closeCaution, 20000);
}
function showSaveBanner(cred) {
  closeBanner();
  const shell = document.createElement("div");
  const root = shell.attachShadow({mode: "closed"});
  const box = document.createElement("div");
  box.setAttribute("style", "all:initial;position:fixed;z-index:2147483647;right:16px;bottom:16px;"
    + "font:14px system-ui,sans-serif;background:#16161a;color:#f5f5f7;padding:14px 16px;"
    + "border-radius:10px;box-shadow:0 6px 24px rgba(0,0,0,.35);max-width:300px;color-scheme:light dark");
  const msg = document.createElement("div");
  msg.textContent = "Save this password to SPM?";
  msg.setAttribute("style", "margin:0 0 10px");
  const save = document.createElement("button");
  save.textContent = "Save";
  save.setAttribute("style", "all:initial;cursor:pointer;border-radius:8px;padding:8px 14px;font:700 14px system-ui;"
    + "background:#d8d2ff;color:#17131f;margin-right:8px");
  const no = document.createElement("button");
  no.textContent = "Not now";
  no.setAttribute("style", "all:initial;cursor:pointer;border-radius:8px;padding:8px 14px;font:14px system-ui;background:#34343b;color:#eee");
  const status = document.createElement("div");
  status.setAttribute("style", "margin-top:8px;min-height:16px;color:#a9a9b2;font-size:12px");
  save.addEventListener("click", async (event) => {
    if (!event.isTrusted) return;
    save.disabled = true;
    status.textContent = "Saving…";
    const response = await send({action: "menu-save", username: cred.username, password: cred.password});
    cred.password = "";
    if (response && response.ok) { status.textContent = "Saved to SPM."; setTimeout(closeBanner, 1200); }
    else { status.textContent = "Could not save — is SPM unlocked?"; save.disabled = false; }
  });
  no.addEventListener("click", () => { cred.password = ""; closeBanner(); });
  box.append(msg, save, no, status);
  root.append(box);
  (document.body || document.documentElement).append(shell);
  banner = shell;
  setTimeout(closeBanner, 15000);
}

function isNewPasswordField(el) {
  if (!(el instanceof HTMLInputElement) || el.type !== "password" || !spmVisible(el)) return false;
  if ((el.getAttribute("autocomplete") || "").toLowerCase().includes("new-password")) return true;
  // A sign-up/change form has a password box and a confirm box.
  return [...(el.form || document).querySelectorAll('input[type="password"]')].filter(spmVisible).length >= 2;
}

let gen = null;
function closeGen() { if (gen) { gen.remove(); gen = null; } }
function showGenerate(field) {
  closeGen();
  const shell = document.createElement("div");
  const root = shell.attachShadow({mode: "closed"});
  const btn = document.createElement("button");
  btn.textContent = "Generate strong password";
  const rect = field.getBoundingClientRect();
  btn.setAttribute("style", "all:initial;position:fixed;z-index:2147483647;font:12px system-ui,sans-serif;"
    + "cursor:pointer;background:#d8d2ff;color:#17131f;border-radius:8px;padding:6px 10px;box-shadow:0 4px 14px rgba(0,0,0,.3);"
    + `top:${Math.round(rect.bottom + 4)}px;left:${Math.round(rect.left)}px`);
  btn.addEventListener("click", (event) => {
    if (!event.isTrusted) return;
    const value = spmGeneratePassword(20);
    const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value").set;
    for (const p of [...(field.form || document).querySelectorAll('input[type="password"]')].filter(spmVisible)) {
      p.focus();
      setter.call(p, value);
      p.dispatchEvent(new Event("input", {bubbles: true}));
      p.dispatchEvent(new Event("change", {bubbles: true}));
    }
    closeGen();
  });
  root.append(btn);
  (document.body || document.documentElement).append(shell);
  gen = shell;
}

document.addEventListener("submit", (event) => {
  if (!event.isTrusted) return;
  const cred = captureFrom(event.target);
  if (cred) showSaveBanner(cred);
}, true);

document.addEventListener("focusin", (event) => {
  if (isLoginField(event.target)) open(event.target);
  else close();
  if (isNewPasswordField(event.target)) showGenerate(event.target);
  else closeGen();
}, true);
document.addEventListener("keydown", onKeyDown, true);
window.addEventListener("scroll", () => { place(); closeGen(); }, true);
window.addEventListener("resize", () => { place(); closeGen(); }, true);
window.addEventListener("pagehide", () => { close(); closeGen(); closeBanner(); });

api.runtime.onMessage.addListener((message) => {
  if (!message || message.channel !== "spm") return false;
  if (message.action === "menu-commit-request") commit(message.nonce);
  if (message.action === "menu-close") close();
  return false;
});
