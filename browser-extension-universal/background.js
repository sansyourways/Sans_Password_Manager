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

api.runtime.onMessage.addListener((message, _sender, sendResponse) => {
  if (!message || message.channel !== "spm") return false;
  nativeRequest(message).then(sendResponse).catch(error => sendResponse({ok:false, error:error.message}));
  return true;
});
