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
  if (!response || !response.ok || !response.count) return;
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

document.addEventListener("focusin", (event) => {
  if (isLoginField(event.target)) open(event.target);
  else close();
}, true);
document.addEventListener("keydown", onKeyDown, true);
window.addEventListener("scroll", place, true);
window.addEventListener("resize", place, true);
window.addEventListener("pagehide", close);

api.runtime.onMessage.addListener((message) => {
  if (!message || message.channel !== "spm") return false;
  if (message.action === "menu-commit-request") commit(message.nonce);
  if (message.action === "menu-close") close();
  return false;
});
