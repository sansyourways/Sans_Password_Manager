"use strict";

/* The function injected into the page to fill a credential.
 *
 * Its own file because two things need to be the same function: the popup,
 * which hands it to scripting.executeScript, and the test that drives it
 * against a real form. A copy in the test would drift from the copy that
 * ships, and the drift would be invisible -- both would pass.
 *
 * scripting.executeScript serialises this by source, so it must reference
 * nothing outside itself.
 */
function spmFillForm(username, password) {
  // offsetParent is null for display:none and for anything inside it, which is
  // how a hidden honeypot field or a collapsed second form is skipped. A
  // disabled or readonly field is skipped because writing to one produces a
  // value the page will not submit and the user cannot see is wrong.
  const visible = element =>
    element.offsetParent !== null && !element.disabled && !element.readOnly;
  const passwords = [...document.querySelectorAll('input[type="password"]')].filter(visible);
  const users = [...document.querySelectorAll(
    'input[type="email"],input[autocomplete="username"],input[type="text"]')].filter(visible);
  const set = (element, value) => {
    if (!element) return;
    element.focus();
    // The prototype's setter, not element.value. A framework that tracks its
    // own state patches the instance property, so assigning through it updates
    // the DOM and leaves the framework believing the field is still empty --
    // the form then submits nothing, having looked filled the whole time.
    const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value").set;
    setter.call(element, value);
    element.dispatchEvent(new Event("input", { bubbles: true }));
    element.dispatchEvent(new Event("change", { bubbles: true }));
  };
  set(users[0], username);
  set(passwords[0], password);
}

if (typeof module !== "undefined" && module.exports) module.exports = { spmFillForm };
