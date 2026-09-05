"use strict";

/* The in-field picker, extension side.
 *
 * This document is the account list. It runs at the extension's origin, so the
 * page hosting the iframe cannot read the labels or usernames rendered here,
 * cannot script the buttons, and cannot see which row is highlighted.
 *
 * It never receives a password. Choosing a row tells the background which
 * record was chosen; the credential is fetched afterwards and handed straight
 * to the content script that performs the fill.
 */

const api = globalThis.browser || globalThis.chrome;
const nonce = location.hash.slice(1);
const list = document.getElementById("accounts");
let rows = [];
let index = -1;
// The rows arrive asynchronously, and the keys arrive from a field the user is
// already typing in -- so an arrow key can land before there is anything to
// move through. Holding them until the list exists is the difference between
// "the first ArrowDown does nothing" and a picker that behaves the same way
// every time.
let ready = false;
const queued = [];

function send(message) {
  const payload = {channel: "spm", nonce, ...message};
  if (globalThis.browser) return browser.runtime.sendMessage(payload).catch(() => null);
  return new Promise((resolve) => {
    chrome.runtime.sendMessage(payload, (response) => { void chrome.runtime.lastError; resolve(response || null); });
  });
}

function highlight(next) {
  if (!rows.length) return;
  index = (next + rows.length) % rows.length;
  rows.forEach((button, position) => {
    const selected = position === index;
    button.setAttribute("aria-selected", String(selected));
    if (selected) button.scrollIntoView({block: "nearest"});
  });
}

function onKey(key) {
  if (!ready) { queued.push(key); return; }
  if (key === "ArrowDown") highlight(index + 1);
  else if (key === "ArrowUp") highlight(index - 1);
  else if (key === "Enter") choose(index);
}

function choose(position) {
  if (position < 0 || position >= rows.length) return;
  send({action: "menu-choose", record: rows[position].dataset.record});
}

function render(matches) {
  list.replaceChildren();
  rows = matches.map((account) => {
    const item = document.createElement("li");
    const button = document.createElement("button");
    button.type = "button";
    button.setAttribute("role", "option");
    button.setAttribute("aria-selected", "false");
    button.dataset.record = String(account.id);
    const label = document.createElement("b");
    label.textContent = account.label || `Record ${account.id}`;
    const username = document.createElement("small");
    username.textContent = account.username || "No username";
    button.append(label, username);
    item.append(button);
    list.append(item);
    return button;
  });
  rows.forEach((button, position) => button.addEventListener("click", () => choose(position)));
  if (!rows.length) {
    const empty = document.createElement("p");
    empty.textContent = "No accounts are bound to this page.";
    list.append(empty);
  }
  ready = true;
  while (queued.length) onKey(queued.shift());
}

// Arrow keys arrive from the background rather than from this document,
// because the field the user is typing in keeps focus and this frame never
// receives the keystroke. The background only forwards keys a content script
// reported as trusted, so a page cannot drive this list from the outside.
api.runtime.onMessage.addListener((message) => {
  if (!message || message.channel !== "spm-menu" || message.nonce !== nonce) return false;
  onKey(message.key);
  return false;
});

(async () => {
  const response = await send({action: "menu-rows"});
  render(response && response.ok ? response.matches || [] : []);
})();
