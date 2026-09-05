/* The security-key unlock, driven through a real WebAuthn ceremony.
 *
 * Everything else about this feature can be asserted over HTTP with a
 * stand-in secret, and regression.sh does exactly that. What no amount of
 * curl can answer is the only question the design actually rests on: does a
 * security key hand back the same 32 bytes for the same salt, every time,
 * across two independent ceremonies in two different page loads?
 *
 * Chromium's virtual authenticator implements the PRF extension, so the answer
 * is measured here rather than assumed. If it ever stopped being deterministic
 * the vault would simply stop opening, and no unit test would have noticed.
 */
import { argv, env, exit } from "node:process";

const [, , baseUrl, master, puppeteerPath] = argv;
// The one record this vault holds. Named by the caller, because the vault is
// built by whoever starts the dashboard.
const username = env.HW_USERNAME || "user@example.invalid";
const puppeteer = (await import(puppeteerPath)).default;

const failures = [];
const check = (ok, message) => { if (!ok) failures.push(message); };

// Every wait in this file is a navigation that either happens or times out
// after thirty seconds, and "Navigation timeout of 30000 ms exceeded" names
// none of them. A defect that reads the same wherever it is costs more to find
// than it did to write, so each wait says what it was waiting for.
let stage = "startup";
const at = (name, fn) => { stage = name; return fn(); };

const browser = await puppeteer.launch({
  executablePath: env.CHROMIUM_BIN || "/usr/bin/chromium",
  headless: true,
  args: ["--no-sandbox", "--disable-dev-shm-usage"],
});

const page = await browser.newPage();
const cdp = await page.createCDPSession();
await cdp.send("WebAuthn.enable");
const { authenticatorId } = await cdp.send("WebAuthn.addVirtualAuthenticator", {
  options: {
    protocol: "ctap2",
    ctap2Version: "ctap2_1",
    transport: "usb",
    // Discoverable, so the sign-in page can ask for "whatever you hold"
    // instead of publishing which credential ids exist.
    hasResidentKey: true,
    hasUserVerification: true,
    // The extension this whole feature is built on. Without it the enrolment
    // must refuse rather than enrol a key that can never open the vault.
    hasPrf: true,
    isUserVerified: true,
    automaticPresenceSimulation: true,
  },
});

const signIn = () => at("signing in with the master password", async () => {
  await page.goto(`${baseUrl}/login`, { waitUntil: "domcontentloaded" });
  await page.type("#pw", master);
  await Promise.all([
    page.waitForNavigation({ waitUntil: "domcontentloaded" }),
    page.click("button[type=submit]"),
  ]);
});

const coldPage = (name) => at(name, async () => {
  await page.goto(`${baseUrl}/logout`, { waitUntil: "domcontentloaded" });
  await page.deleteCookie(...(await page.cookies()));
  await page.goto(`${baseUrl}/login`, { waitUntil: "domcontentloaded" });
  // The button is revealed by the bootstrap, which carries a salt only when a
  // key is actually enrolled. A page that showed it unconditionally would be
  // offering an unlock that cannot work.
  await page.waitForFunction(
    () => { const el = document.getElementById("hardware-unlock"); return el && !el.hidden; },
    { timeout: 10000 });
});

const unlockWithKey = (name) => at(name, () => Promise.all([
  page.waitForNavigation({ waitUntil: "domcontentloaded", timeout: 30000 }),
  page.click("#hardware-btn"),
]));

try {
  await signIn();

  /* ----- enrolment ------------------------------------------------------ */
  await page.goto(`${baseUrl}/hardware/settings`, { waitUntil: "domcontentloaded" });
  check(await page.$("#hardware-enrol") !== null,
        "the security-key manager did not render its enrol button");
  await page.type("#hardware-label", "Regression key");
  await at("enrolling the security key", () => Promise.all([
    page.waitForNavigation({ waitUntil: "domcontentloaded", timeout: 30000 }),
    page.click("#hardware-enrol"),
  ]));
  const enrolled = await page.evaluate(() =>
    Array.from(document.querySelectorAll("[data-forget]"))
         .map((b) => b.getAttribute("data-forget")));
  check(enrolled.length === 1,
        `after enrolment the manager lists ${enrolled.length} keys, not 1`);
  check(await page.evaluate(() => document.body.textContent.includes("Regression key")),
        "the label typed at enrolment is not shown on the manager");

  const credentials = await cdp.send("WebAuthn.getCredentials", { authenticatorId });
  check(credentials.credentials.length === 1,
        "the authenticator did not keep the credential");
  check(credentials.credentials[0].isResidentCredential === true,
        "the credential is not discoverable, so a cold sign-in could not find it");

  /* ----- a cold unlock, in a browser that has forgotten everything ------- */
  await coldPage("returning to a signed-out sign-in page");
  await unlockWithKey("opening the vault with the enrolled key");
  const landed = new URL(page.url()).pathname;
  check(landed === "/", `the security key did not open the vault; landed on ${landed}`);
  // Reached the vault, not merely a page that is not the login form. The
  // record only exists inside the encrypted file, so seeing it is proof the
  // key envelope was opened by 32 bytes that came out of an authenticator.
  await page.goto(`${baseUrl}/passwords`, { waitUntil: "domcontentloaded" });
  const listed = await page.evaluate(() =>
    Array.from(document.querySelectorAll("[data-row]"))
         .map((row) => row.textContent).join(" "));
  check(listed.includes(username),
        `the security-key session cannot read the vault it just opened (no ${username} in the list)`);

  /* ----- the same key, a second time ------------------------------------ */
  // The determinism the whole design rests on. One successful ceremony could
  // be luck; a session that opens again from a clean cookie jar is the PRF
  // returning the same bytes for the same salt.
  await coldPage("signing out again for the second unlock");
  await unlockWithKey("opening the vault a second time with the same key");
  check(new URL(page.url()).pathname === "/",
        "the second unlock with the same key failed, so the PRF is not deterministic");

  /* ----- a different key opens nothing ---------------------------------- */
  // A second authenticator, enrolled with nothing. Its PRF answers, and the
  // bytes are simply not the ones the envelope was sealed under -- which is
  // the entire security argument, measured rather than asserted.
  await cdp.send("WebAuthn.removeVirtualAuthenticator", { authenticatorId });
  const other = await cdp.send("WebAuthn.addVirtualAuthenticator", {
    options: {
      protocol: "ctap2", ctap2Version: "ctap2_1", transport: "usb",
      hasResidentKey: true, hasUserVerification: true, hasPrf: true,
      isUserVerified: true, automaticPresenceSimulation: true,
    },
  });
  await coldPage("signing out for the unenrolled key");
  stage = "trying the vault with a key that was never enrolled";
  await page.click("#hardware-btn");
  // Waits for the refusal to be reported rather than for a fixed interval: a
  // negative assertion measured on a short clock reports silence as success.
  await page.waitForFunction(
    () => document.getElementById("hardware-status").textContent.trim().length > 0,
    { timeout: 30000 });
  check(new URL(page.url()).pathname === "/login",
        "an unenrolled security key opened the vault");
  void other;
} catch (error) {
  failures.push(`while ${stage}: ${error && error.message ? error.message : error}`);
} finally {
  await browser.close();
}

if (failures.length) {
  for (const message of failures) console.error(`  FAIL ${message}`);
  console.error(`dashboard security keys: ${failures.length} failure(s)`);
  exit(1);
}
console.log("  dashboard: a security key enrols, opens the vault twice, and a different key does not");
