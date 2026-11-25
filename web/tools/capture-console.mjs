#!/usr/bin/env node
/**
 * capture-console.mjs - screenshot the Fleet Filter fleet console for visual inspection.
 *
 * Purpose: give the console a repeatable visual-capture step. The console is a server-rendered
 * app behind Apache HTTP basic auth, so a screenshot tool has to authenticate the way a browser
 * does. Passing credentials as URL userinfo (`http://admin:pw@host/`) does not work here - Apache
 * answers 401 to the pre-authenticated form that some clients build - so this script authenticates
 * with Playwright's `context.setHTTPCredentials`, which sends a correct `Authorization` header on
 * every request including subresources.
 *
 * Output: one PNG per (route x viewport) plus a JSON manifest recording the HTTP status, byte size
 * and sha256 of each capture. The manifest is what makes a later run comparable: a changed sha256
 * for a route means the rendered page changed, and the statuses catch a route that started erroring
 * without producing an obviously different picture.
 *
 * Usage:
 *   node web/tools/capture-console.mjs --password-file /root/.fleet-filter-ui-admin-password
 *   node web/tools/capture-console.mjs --url https://127.0.0.1:8188 --out /tmp/shots
 *   node web/tools/capture-console.mjs --routes /,/installs --viewports 1440x900
 *
 * Defaults: url https://127.0.0.1:8188, user admin,
 *   routes /,/installs,/detections,/containers,/reports,
 * viewports 1440x900 and 390x844, out data/artifacts/console-<UTC date> (resolved from the repo).
 */

import { createHash } from "node:crypto";
import { createRequire } from "node:module";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { mkdirSync, readFileSync, writeFileSync, existsSync } from "node:fs";

// A bare `import ... from "playwright"` fails here: ESM resolution ignores NODE_PATH, and on this
// host playwright lives in the global directory (/usr/local/lib/node_modules/playwright) rather than
// in a local node_modules. require() does honour NODE_PATH and the global prefix, so resolve through
// it and allow an explicit override for hosts that keep playwright elsewhere.
const { chromium } = createRequire(import.meta.url)(process.env.PLAYWRIGHT_MODULE || "playwright");

const REPO = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..");
const CHROME = process.env.CHROME_PATH || "/opt/google/chrome/chrome";

/** Parse `--key value` / `--key=value` arguments, falling back to documented defaults. */
function args(argv) {
  const parsed = {};
  for (let i = 0; i < argv.length; i += 1) {
    const token = argv[i];
    if (!token.startsWith("--")) continue;
    const eq = token.indexOf("=");
    if (eq > -1) {
      parsed[token.slice(2, eq)] = token.slice(eq + 1);
    } else {
      parsed[token.slice(2)] = argv[i + 1] && !argv[i + 1].startsWith("--") ? argv[++i] : "true";
    }
  }
  const utcDate = new Date().toISOString().slice(0, 10);
  return {
    url: parsed.url || "https://127.0.0.1:8188",
    user: parsed.user || "admin",
    passwordFile: parsed["password-file"] || "/root/.fleet-filter-ui-admin-password",
    password: parsed.password || process.env.PT_UI_PASSWORD || "",
    routes: (parsed.routes || "/,/installs,/detections,/containers,/reports").split(",").filter(Boolean),
    viewports: (parsed.viewports || "1440x900,390x844")
      .split(",")
      .filter(Boolean)
      .map((spec) => {
        const [width, height] = spec.split("x").map(Number);
        return { label: spec.replace("x", "x"), width, height };
      }),
    out: parsed.out || join(REPO, "data", "artifacts", `console-${utcDate}`),
  };
}

/** Resolve the basic-auth password from a file (sudo-readable on this host) or a direct value. */
function resolvePassword(opts) {
  if (opts.password) return opts.password;
  if (!existsSync(opts.passwordFile)) {
    throw new Error(`no password: set --password or PT_UI_PASSWORD, or make ${opts.passwordFile} readable`);
  }
  return readFileSync(opts.passwordFile, "utf8").trim();
}

/** Render one route at one viewport and write the PNG; returns the manifest row. */
async function capture(context, url, route, viewport, outDir) {
  const page = await context.newPage();
  await page.setViewportSize({ width: viewport.width, height: viewport.height });
  const response = await page.goto(`${url}${route}`, { waitUntil: "networkidle", timeout: 30000 });
  // The app renders synchronously, but webfonts settle after load; waiting once per page keeps the
  // glyph metrics in the screenshot identical to what a human looking at the page would see.
  await page.evaluate(() => (document.fonts ? document.fonts.ready : Promise.resolve()));
  const file = join(outDir, `${route === "/" ? "index" : route.slice(1).replace(/\//g, "-")}-${viewport.label}.png`);
  await page.screenshot({ path: file, fullPage: true });
  const bytes = readFileSync(file);
  await page.close();
  return {
    route,
    viewport: viewport.label,
    status: response ? response.status() : null,
    file: file.replace(`${REPO}/`, ""),
    bytes: bytes.length,
    sha256: createHash("sha256").update(bytes).digest("hex").slice(0, 16),
  };
}

async function main() {
  const opts = args(process.argv.slice(2));
  const password = resolvePassword(opts);
  mkdirSync(opts.out, { recursive: true });

  const browser = await chromium.launch({
    executablePath: CHROME,
    args: ["--no-sandbox", "--disable-setuid-sandbox", "--disable-gpu"],
  });
  const manifest = { url: opts.url, capturedAt: new Date().toISOString(), captures: [] };
  try {
    for (const viewport of opts.viewports) {
      // PTN-04 moved the published listener to TLS. The certificate is issued for
      // build01.lab and this tool connects to 127.0.0.1, so the name never matches; that
      // mismatch is expected and must not be reported as a rendering failure. The certificate itself
      // is verified out-of-band (see docs/CONSOLE.md), not by this tool.
      const context = await browser.newContext({
        viewport: { width: viewport.width, height: viewport.height },
        ignoreHTTPSErrors: true,
      });
      // Basic auth belongs on the context, not the URL: subresources and redirects must carry it too.
      await context.setHTTPCredentials({ username: opts.user, password });
      for (const route of opts.routes) {
        manifest.captures.push(await capture(context, opts.url, route, viewport, opts.out));
      }
      await context.close();
    }
  } finally {
    await browser.close();
  }

  writeFileSync(join(opts.out, "manifest.json"), `${JSON.stringify(manifest, null, 2)}\n`);
  for (const c of manifest.captures) {
    console.log(`${String(c.status).padEnd(4)} ${c.route.padEnd(12)} ${c.viewport.padEnd(9)} ${String(c.bytes).padStart(8)}B  ${c.file}`);
  }
  console.log(`manifest: ${join(opts.out, "manifest.json")}`);
}

main().catch((error) => {
  console.error(`capture failed: ${error.message}`);
  process.exit(1);
});
