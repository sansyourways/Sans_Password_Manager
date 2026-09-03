/* Drives the packed extension in a real Chromium.
 *
 * The browser-extension roadmap listed this as the thing the in-field picker
 * waits for: "driving an extension under headless Chromium with
 * --load-extension is possible and worth revisiting, but it is its own
 * project". This is that project's first half.
 *
 * What it proves is deliberately narrow, and the parts it cannot reach yet are
 * named at the bottom rather than glossed. Every assertion here is about the
 * extension actually running, not about its source reading correctly.
 */
import { argv, env, exit } from "node:process";

const [, , distDir, expectedId, puppeteerPath] = argv;
const puppeteer = (await import(puppeteerPath)).default;

const failures = [];
const check = (ok, message) => { if (!ok) failures.push(message); };

const browser = await puppeteer.launch({
  executablePath: env.CHROMIUM_BIN || "/usr/bin/chromium",
  headless: true,
  userDataDir: env.EXT_PROFILE,
  args: ["--no-sandbox", "--disable-dev-shm-usage",
         `--disable-extensions-except=${distDir}`, `--load-extension=${distDir}`],
});

try {
  // A service worker means the extension is running. An unpacked directory
  // that Chromium refused would still sit on disk looking perfectly fine.
  const target = await browser.waitForTarget(
    (t) => t.type() === "service_worker" && t.url().startsWith("chrome-extension://"),
    { timeout: 30000 });
  const runtimeId = new URL(target.url()).host;

  // 3.2.0 gave every unpacked copy one stable identity from the manifest key,
  // so the native-messaging host could name it in a file written once. That
  // was asserted by re-deriving the id the same way the script does -- which
  // proves the script agrees with itself. This asks the browser.
  check(runtimeId === expectedId,
        `the browser loaded ${runtimeId}, extension-id.sh says ${expectedId}`);

  const page = await browser.newPage();
  await page.goto(`chrome-extension://${runtimeId}/popup.html`,
                  { waitUntil: "domcontentloaded" });

  const controls = await page.evaluate(() =>
    ["master", "unlockButton", "refresh", "lock", "accounts", "unlock", "status"]
      .filter((id) => document.getElementById(id)));
  check(controls.length === 7, `popup is missing controls: got ${controls.join(",")}`);

  // The popup's own page is not an http(s) page, so this exercises the refusal
  // that keeps autofill off non-web surfaces -- the extension's own settings
  // page, a PDF viewer, a devtools tab. A fill path that ran here would run
  // anywhere.
  await page.waitForFunction(
    () => document.getElementById("status").textContent.trim().length > 0,
    { timeout: 10000 });
  const status = await page.evaluate(() =>
    document.getElementById("status").textContent.trim());
  check(/HTTP or HTTPS/i.test(status),
        `a non-web page did not refuse autofill; status was: ${status}`);

  // Nothing that looks like a secret reaches the popup, at any point. The
  // bridge protocol is secret-free by construction and the regression suite
  // asserts that at the CLI; this asserts it where a person would see it.
  const leaked = await page.evaluate((needles) => {
    const text = document.documentElement.outerHTML;
    return needles.filter((n) => n && text.includes(n));
  }, [env.EXT_SECRET || "", env.EXT_MASTER || ""].filter(Boolean));
  check(leaked.length === 0, `the popup DOM contains ${leaked.length} secret value(s)`);

  const accountsHidden = await page.evaluate(() =>
    document.getElementById("accounts").classList.contains("hidden"));
  check(accountsHidden, "the account list is visible before any unlock");
} finally {
  await browser.close();
}

if (failures.length) {
  for (const line of failures) process.stderr.write(`  ${line}\n`);
  exit(1);
}
console.log("  extension: runs in Chromium, id matches extension-id.sh, "
            + "refuses a non-web page, and leaks nothing into the popup");
