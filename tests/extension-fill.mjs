/* Drives the injected fill against a real page in a real browser.
 *
 * This is the function that writes a password into someone's login form, and
 * the ways it fails are all silent: a field that looks filled and submits
 * empty, a hidden honeypot filled instead of the real box, a value written
 * without the events a framework listens for. None of that is visible from
 * reading it, and none of it fails a unit test of the surrounding code.
 *
 * It drives fill.js itself -- the same file both extensions ship -- rather
 * than a copy, because a copy would drift and both would keep passing.
 */
import { readFileSync } from "node:fs";
import { argv, env, exit } from "node:process";

const [, , fillPath, pageUrl, puppeteerPath] = argv;
const puppeteer = (await import(puppeteerPath)).default;
const fillSource = readFileSync(fillPath, "utf8");

const failures = [];
const check = (ok, message) => { if (!ok) failures.push(message); };

const browser = await puppeteer.launch({
  executablePath: env.CHROMIUM_BIN || "/usr/bin/chromium",
  headless: true,
  args: ["--no-sandbox", "--disable-dev-shm-usage"],
});
try {
  const page = await browser.newPage();
  await page.goto(pageUrl, { waitUntil: "domcontentloaded" });
  await page.evaluate(fillSource);
  await page.evaluate(() => spmFillForm("avery@example.invalid", "Correct-Horse-Battery-9!"));

  const state = await page.evaluate(() => ({
    user: document.getElementById("username").value,
    // Read through the prototype getter: the page installs its own accessor,
    // so asking the element would report whatever the framework kept rather
    // than what the DOM will actually submit.
    password: window.__nativeValue(),
    honeypot: document.getElementById("honeypot").value,
    disabled: document.getElementById("disabled-pw").value,
    readonly: document.getElementById("readonly-user").value,
    // What a framework that tracks its own state would have seen. The page
    // records it from the input event rather than from the DOM property.
    swallowed: window.__frameworkSlot(),
    events: window.__events || [],
  }));

  check(state.user === "avery@example.invalid",
        `the visible username was not filled: ${JSON.stringify(state.user)}`);
  check(state.password === "Correct-Horse-Battery-9!",
        `the visible password was not filled: ${JSON.stringify(state.password)}`);

  // A hidden field is a honeypot as often as it is an oversight, and filling
  // one is how an autofill announces itself to a page that was watching.
  check(state.honeypot === "", "a display:none field was filled");
  check(state.disabled === "", "a disabled field was filled");
  check(state.readonly === "", "a readonly field was filled");

  // The reason the prototype setter exists. Assigning element.value directly
  // updates the DOM and leaves a framework believing the field is empty, so
  // the form submits nothing while looking filled. The legacy extension did
  // exactly that until 4.4.1.
  check(state.swallowed === "",
        "the fill went through the page's own value setter, so a framework "
        + "that owns the field would have swallowed it and submitted nothing");
  check(state.events.includes("input") && state.events.includes("change"),
        `the fill dispatched ${JSON.stringify(state.events)}`);
} finally {
  await browser.close();
}

if (failures.length) {
  for (const line of failures) process.stderr.write(`  ${line}\n`);
  exit(1);
}
console.log("  fill: the visible fields are filled, hidden and disabled ones are not, "
            + "and a framework sees the value");
