/* Drives the in-field picker end to end, in a real browser, against a real
 * login form, through the real native host and the real vault.
 *
 * The popup could never be tested this way. It depends on `activeTab`, which
 * Chromium grants only for a genuine gesture on the toolbar action, and a
 * synthesised click is not one -- so the browser-extension roadmap recorded
 * that round trip as unreachable. The in-field path does not use `activeTab`
 * at all: a content script and an extension-origin iframe need no such grant,
 * so everything below is the shipped path rather than a stand-in for it.
 *
 * What is asserted here is the set of properties that separate autofill from a
 * credential leak. Each one is written so that removing the code that enforces
 * it fails the test:
 *
 *   - the account list is rendered at the extension's origin, and the page
 *     cannot read it
 *   - a synthetic Enter, which is what a hostile page can produce, fills
 *     nothing; a real keypress fills
 *   - an https-bound record is not offered on an http page
 *   - a login field inside a cross-origin iframe gets no picker at all
 *   - the nonce is load-bearing: the menu with a stale one lists nothing
 */
import { createServer } from "node:http";
import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { argv, env, exit } from "node:process";

const [, , distDir, fixturesDir, puppeteerPath] = argv;
const puppeteer = (await import(puppeteerPath)).default;

const MASTER = env.EXT_MASTER || "";
const SECRET = env.EXT_SECRET || "";
const SECURE_ONLY = env.EXT_SECURE_SECRET || "";

const failures = [];
const check = (ok, message) => { if (!ok) failures.push(message); };
const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

/* Two origins. The second exists only to be embedded by the first, because
 * "same site in a cross-origin iframe" is the shape of the attack this refuses
 * and a different port is a different origin. */
async function serve(extra = {}) {
  const server = createServer(async (request, response) => {
    const path = request.url.split("?")[0];
    if (extra[path]) {
      response.writeHead(200, {"content-type": "text/html; charset=utf-8"});
      response.end(extra[path]);
      return;
    }
    try {
      const body = await readFile(join(fixturesDir, path.replace(/^\/+/, "")));
      response.writeHead(200, {"content-type": "text/html; charset=utf-8"});
      response.end(body);
    } catch {
      response.writeHead(404).end("no");
    }
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  return {server, port: server.address().port};
}

const inner = await serve();
const outer = await serve({
  "/embed.html": `<!doctype html><meta charset="utf-8"><title>Embedded login</title>
<p>A login form from another origin.</p>
<iframe id="frame" src="http://127.0.0.1:${inner.port}/login-form.html"
        width="420" height="260"></iframe>`,
});

const browser = await puppeteer.launch({
  executablePath: env.CHROMIUM_BIN || "/usr/bin/chromium",
  headless: true,
  userDataDir: env.EXT_PROFILE,
  args: ["--no-sandbox", "--disable-dev-shm-usage",
         `--disable-extensions-except=${distDir}`, `--load-extension=${distDir}`],
});

const pageState = (page) => page.evaluate(() => ({
  user: document.getElementById("username").value,
  password: window.__nativeValue(),
  honeypot: document.getElementById("honeypot").value,
  disabled: document.getElementById("disabled-pw").value,
  readonly: document.getElementById("readonly-user").value,
  markup: document.documentElement.outerHTML,
  // Everything the hostile page managed to capture by forcing roots open.
  stolen: (window.__stolenRoots || []).map((root) => root.innerHTML).join("\n"),
  openRoots: [...document.querySelectorAll("*")].filter((node) => node.shadowRoot !== null).length,
}));

/* Waits for the picker AND for its rows. Returning a frame whose list has not
 * arrived yet makes every keyboard assertion below a coin toss -- an ArrowDown
 * delivered to an empty list moves nothing, and the test then blames the fill.
 * That flake was real, and it is why the menu now queues keys until it has
 * rendered; this waits properly rather than relying on that alone. */
async function menuFrame(page, timeout = 8000) {
  const deadline = Date.now() + timeout;
  while (Date.now() < deadline) {
    const frame = page.frames().find((f) => f.url().includes("menu.html"));
    if (frame) {
      try {
        await frame.waitForSelector("button,p", {timeout: deadline - Date.now()});
        return frame;
      } catch { return null; }
    }
    await sleep(100);
  }
  return null;
}

/* A page that wants the account list patches attachShadow before anything
 * else runs and keeps every root handed out. Against page-world UI that works,
 * which is why "we used a closed shadow root" is not an answer on its own.
 *
 * Here it captures nothing, and the reason is worth asserting rather than
 * assuming: a content script runs in an isolated world with its own
 * Element.prototype, so the page's patch is not the function the content
 * script calls. evaluateOnNewDocument runs at document start, ahead of the
 * document_idle injection, which is the ordering a real page would have.
 */
/* Waits for the fill to land instead of sleeping a magic number.
 *
 * A commit runs a real vault decryption in a subprocess, so how long it takes
 * is a property of the machine rather than of the code under test. A fixed
 * sleep that is long enough today fails the moment the box is busy, and it
 * fails as "the password was not filled" -- which reads like a defect in the
 * fill. Waiting for the condition removes the clock from the assertion.
 *
 * A negative assertion still uses a fixed wait, because there is no event to
 * wait for when the correct outcome is that nothing happens.
 */
async function waitForFill(page, timeout = 8000) {
  const deadline = Date.now() + timeout;
  while (Date.now() < deadline) {
    const filled = await page.evaluate(() => window.__nativeValue() !== "");
    if (filled) break;
    await sleep(100);
  }
  return pageState(page);
}

async function openLogin() {
  const page = await browser.newPage();
  await page.evaluateOnNewDocument(() => {
    window.__stolenRoots = [];
    const real = Element.prototype.attachShadow;
    Element.prototype.attachShadow = function (init) {
      const root = real.call(this, {...init, mode: "open"});
      window.__stolenRoots.push(root);
      return root;
    };
  });
  await page.goto(`http://127.0.0.1:${outer.port}/login-form.html`, {waitUntil: "domcontentloaded"});
  await sleep(400);           // document_idle injection
  await page.click("#username");
  return page;
}

try {
  const target = await browser.waitForTarget(
    (t) => t.type() === "service_worker" && t.url().startsWith("chrome-extension://"),
    {timeout: 30000});
  const runtimeId = new URL(target.url()).host;

  // Unlock the way the popup does: an extension page asking the background,
  // which asks the native host, which runs the CLI against the test vault. If
  // the native host were not reachable this fails here rather than silently
  // producing an empty picker for every assertion below.
  const popup = await browser.newPage();
  await popup.goto(`chrome-extension://${runtimeId}/popup.html`, {waitUntil: "domcontentloaded"});
  const unlock = await popup.evaluate((master) => new Promise((resolve) => {
    chrome.runtime.sendMessage({channel: "spm", action: "unlock", host: "127.0.0.1", scheme: "http", master},
                               (response) => resolve(response || {ok: false, error: "no response"}));
  }), MASTER);
  check(unlock.ok === true, `the native host did not unlock: ${JSON.stringify(unlock)}`);
  await popup.close();
  if (!unlock.ok) throw new Error("cannot exercise the picker without a session");

  /* ---- the menu appears, at the extension's origin ---- */
  let page = await openLogin();
  let frame = await menuFrame(page);
  check(frame !== null, "focusing a login field opened no picker");
  check(frame !== null && frame.url().startsWith(`chrome-extension://${runtimeId}/menu.html`),
        `the picker is not served from the extension origin: ${frame && frame.url()}`);

  const labels = frame ? await frame.$$eval("button", (nodes) =>
    nodes.map((node) => node.textContent)) : [];
  // Three records are bound to this host in the fixture vault; one of them is
  // https-bound, and this page is http. The list and the fill have to agree,
  // or the user picks an account and is refused for no visible reason.
  check(labels.length === 2,
        `the picker offered ${labels.length} accounts, expected 2 (the https-bound one is not fillable here)`);
  check(!labels.some((text) => text.includes("Secure Only")),
        "an https-bound record was offered on an http page");

  let state = await pageState(page);
  // The page's own document -- everything page script can serialise.
  check(!state.markup.includes("Local Demo") && !state.markup.includes("avery@example.invalid"),
        "the account list is in the page's own DOM");
  check(!state.markup.includes(SECRET), "a password reached the page's DOM");
  // The picker's host element is in the page, and stays shut: the root is
  // closed, and the page's attachShadow patch never saw it created because the
  // content script does not share the page's prototypes.
  check(state.openRoots === 0, "the picker's shadow root is reachable from the page");
  check(state.stolen === "", "page script intercepted the picker's shadow root");

  /* ---- only what was offered can be chosen ---- */
  // The menu is extension code, so this is not something a page can reach; it
  // is the invariant that stops a bug in the picker from becoming a fill of a
  // record the picker deliberately withheld -- here, the https-bound one that
  // the downgrade rule kept off this http page.
  let smuggled;
  try {
    smuggled = await frame.evaluate(() => new Promise((resolve) => {
      chrome.runtime.sendMessage(
        {channel: "spm", nonce: location.hash.slice(1), action: "menu-choose", record: "3"},
        (response) => resolve(response || {ok: false}));
    }));
  } catch (error) {
    // The picker tore itself down mid-call, which only happens when the
    // request was accepted and a fill was dispatched.
    smuggled = {ok: true, note: String(error).slice(0, 80)};
  }
  check(smuggled.ok === false,
        `the picker accepted a record it never offered: ${JSON.stringify(smuggled)}`);
  await sleep(500);
  state = await pageState(page);
  check(state.password === "", "a record the picker never offered was filled");

  /* ---- a real click fills, through the prototype setter ---- */
  try { await frame.click("button"); }
  catch (error) { check(false, `the picker vanished before it could be clicked: ${error}`); }
  state = await waitForFill(page);
  check(state.user === "avery@example.invalid", `the username was not filled: ${JSON.stringify(state.user)}`);
  check(state.password === SECRET, `the password was not filled: ${JSON.stringify(state.password)}`);
  check(state.honeypot === "" && state.disabled === "" && state.readonly === "",
        "the in-field fill wrote to a hidden, disabled or readonly box");
  check(!state.markup.includes(SECURE_ONLY) || SECURE_ONLY === "",
        "the https-bound record's password reached an http page");
  await page.close();

  /* ---- no silent autofill ---- */
  // Exactly what a hostile page can do: focus the field and dispatch the keys
  // that would confirm a selection. isTrusted is false, so the content script
  // drops them; nothing is highlighted and nothing is filled. Its own page,
  // because a mutant that lets this through must fail here rather than take
  // the next block's frame handle down with it.
  page = await openLogin();
  check((await menuFrame(page)) !== null, "the picker did not open for the gesture pass");
  await page.evaluate(() => {
    const field = document.getElementById("username");
    field.focus();
    for (const key of ["ArrowDown", "ArrowDown", "Enter"]) {
      field.dispatchEvent(new KeyboardEvent("keydown", {key, bubbles: true, cancelable: true}));
    }
  });
  // Long enough that a fill would have landed. A commit runs a vault
  // decryption in a subprocess, so a short wait here reports "nothing was
  // filled" for a gate that is not there at all -- which is how removing the
  // isTrusted check once passed this test.
  await sleep(6000);
  state = await pageState(page);
  check(state.user === "" && state.password === "",
        `a synthetic keypress filled the form: ${JSON.stringify(state)}`);

  // The positive control, on the same page and the same menu: real keys fill.
  // Without it, "nothing was filled" could equally mean the picker had already
  // closed, the session had expired, or the harness was broken -- and every one
  // of those reads as a pass.
  await page.keyboard.press("ArrowDown");
  await sleep(200);
  await page.keyboard.press("Enter");
  state = await waitForFill(page);
  check(state.password === SECRET,
        "the gesture pass proved nothing: real keys did not fill either, so the "
        + "empty form above is not evidence that the synthetic ones were refused");
  await page.close();

  /* ---- keyboard navigation, with real keys ---- */
  page = await openLogin();
  frame = await menuFrame(page);
  check(frame !== null, "the picker did not reopen for the keyboard pass");
  await page.keyboard.press("ArrowDown");
  await sleep(200);
  await page.keyboard.press("Enter");
  state = await waitForFill(page);
  check(state.password === SECRET,
        `arrow keys and Enter did not fill: ${JSON.stringify(state.password)}`);
  await page.close();

  /* ---- Escape closes it ---- */
  page = await openLogin();
  check((await menuFrame(page)) !== null, "the picker did not open for the escape pass");
  await page.keyboard.press("Escape");
  await sleep(400);
  check(page.frames().every((f) => !f.url().includes("menu.html")),
        "Escape left the picker open");
  await page.close();

  /* ---- never inside a cross-origin iframe ---- */
  page = await browser.newPage();
  await page.goto(`http://127.0.0.1:${outer.port}/embed.html`, {waitUntil: "domcontentloaded"});
  await sleep(500);
  const embedded = page.frames().find((f) => f.url().includes(`:${inner.port}/login-form.html`));
  check(embedded !== undefined, "the cross-origin fixture did not load");
  if (embedded) {
    await embedded.click("#username");
    await sleep(800);
    check(page.frames().every((f) => !f.url().includes("menu.html")),
          "a login field inside a cross-origin iframe was offered a picker");
    const embeddedState = await embedded.evaluate(() => ({
      user: document.getElementById("username").value,
      password: window.__nativeValue(),
    }));
    check(embeddedState.user === "" && embeddedState.password === "",
          "a cross-origin iframe was filled");
  }
  await page.close();

  /* ---- the page cannot talk to the extension at all ---- */
  page = await openLogin();
  const reachable = await page.evaluate(() => typeof chrome !== "undefined" && Boolean(chrome.runtime?.sendMessage));
  check(reachable === false, "page script can reach the extension's message channel");
  await page.close();

  /* ---- the nonce is load-bearing ---- */
  const stale = await browser.newPage();
  await stale.goto(`chrome-extension://${runtimeId}/menu.html#not-a-real-nonce`,
                   {waitUntil: "domcontentloaded"});
  await sleep(600);
  const staleText = await stale.evaluate(() => document.body.textContent);
  check(!staleText.includes("Local Demo"),
        "the picker listed accounts for a nonce the background never issued");
  await stale.close();
} finally {
  await browser.close();
  inner.server.close();
  outer.server.close();
}

if (failures.length) {
  for (const line of failures) process.stderr.write(`  ${line}\n`);
  exit(1);
}
console.log("  picker: opens at the extension origin, hides the list from the page, "
            + "refuses a synthetic keypress and a cross-origin frame, and fills on a real one");
