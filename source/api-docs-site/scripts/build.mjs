// Builds the static API-reference site into ./dist.
//
// Multi-service + multi-version. The **source of truth for released versions is
// GitHub Release assets** (permanent, unlike Actions artifacts): each service's
// release attaches `<service>.json` + `<service>.json.sha256`. This script lists
// releases for the `{tenants,ddns,tunneller}-v*` tags, dedups spec content by its
// sha256 (identical specs across releases share one file), downloads each distinct
// spec, and emits `dist/versions.json`. The in-repo committed spec is always added
// as the `dev` entry, so the site renders even before any release exists.
//
// Requires only Node 22 built-ins (global fetch). No runtime npm dependencies.

import { fileURLToPath } from "node:url";
import { existsSync } from "node:fs";
import { cp, mkdir, readdir, rm, writeFile } from "node:fs/promises";
import path from "node:path";

// Pinned Scalar standalone — the same renderer the wardnet daemon vendors. Fetched
// at build time and vendored into dist/ so the deployed site has no runtime CDN
// dependency; app.js falls back to this URL if the vendored copy is missing.
const SCALAR_VERSION = "1.52.5";
const SCALAR_URL = `https://cdn.jsdelivr.net/npm/@scalar/api-reference@${SCALAR_VERSION}`;

const SCRIPT_DIR = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.join(SCRIPT_DIR, "..");
const DIST = path.join(ROOT, "dist");
const PUBLIC = path.join(ROOT, "public");
const IN_REPO_SPECS = path.join(ROOT, "..", "docs", "openapi"); // source/docs/openapi

// owner/repo — set automatically in GitHub Actions; overridable locally.
const REPO = process.env.GITHUB_REPOSITORY || process.env.DOCS_REPO || "";
const TOKEN = process.env.GITHUB_TOKEN || process.env.GH_TOKEN || "";

const ghHeaders = (accept = "application/vnd.github+json") => {
  const h = { Accept: accept, "User-Agent": "wardnet-docs-build" };
  if (TOKEN) h.Authorization = `Bearer ${TOKEN}`;
  return h;
};

/** Newest-first SemVer comparison (services use pure SemVer; a prerelease sorts
 * below its release). Returns >0 when a > b. */
function cmpVersion(a, b) {
  const [ca, pa] = a.split("-");
  const [cb, pb] = b.split("-");
  const na = ca.split(".").map(Number);
  const nb = cb.split(".").map(Number);
  for (let i = 0; i < 3; i++) {
    if ((na[i] || 0) !== (nb[i] || 0)) return (na[i] || 0) - (nb[i] || 0);
  }
  if (!pa && pb) return 1;
  if (pa && !pb) return -1;
  // Numeric-aware so prerelease counters order correctly (rc.2 < rc.10), per SemVer.
  if (pa && pb) return pa.localeCompare(pb, undefined, { numeric: true });
  return 0;
}

async function listReleases() {
  if (!REPO) {
    console.warn(
      "[docs] GITHUB_REPOSITORY/DOCS_REPO unset — building dev-only (no released versions)",
    );
    return [];
  }
  const out = [];
  for (let page = 1; page <= 10; page++) {
    const url = `https://api.github.com/repos/${REPO}/releases?per_page=100&page=${page}`;
    const res = await fetch(url, { headers: ghHeaders() });
    if (!res.ok) {
      console.warn(`[docs] releases fetch failed (${res.status}) — dev-only`);
      return out;
    }
    const batch = await res.json();
    out.push(...batch);
    if (batch.length < 100) break;
  }
  return out;
}

async function download(url, headers) {
  const res = await fetch(url, { headers });
  if (!res.ok) throw new Error(`download ${url} -> ${res.status}`);
  return Buffer.from(await res.arrayBuffer());
}

async function main() {
  await rm(DIST, { recursive: true, force: true });
  await mkdir(DIST, { recursive: true });
  await cp(PUBLIC, DIST, { recursive: true });

  const releases = await listReleases().catch((e) => {
    console.warn(`[docs] release listing errored (${e.message}) — dev-only`);
    return [];
  });

  // Single source of truth for the service set: the committed spec files. A new
  // service appears on the site automatically once its spec is committed (the
  // Release-asset name `<service>.json` already matches these basenames).
  const serviceNames = (existsSync(IN_REPO_SPECS) ? await readdir(IN_REPO_SPECS) : [])
    .filter((f) => f.endsWith(".json"))
    .map((f) => f.slice(0, -".json".length))
    .sort();

  const services = {};

  for (const service of serviceNames) {
    const entries = [];
    const specDir = path.join(DIST, "specs", service);
    await mkdir(specDir, { recursive: true });

    // dev entry from the committed in-repo spec (always present).
    const devPath = path.join(IN_REPO_SPECS, `${service}.json`);
    if (existsSync(devPath)) {
      await cp(devPath, path.join(specDir, "dev.json"));
      entries.push({ version: "dev", spec: `specs/${service}/dev.json`, prerelease: false });
    }

    // released versions from GitHub Release assets, deduped by content hash.
    const prefix = `${service}-v`;
    const byHash = new Map(); // sha256 -> stored filename
    for (const rel of releases) {
      if (rel.draft || !rel.tag_name?.startsWith(prefix)) continue;
      const version = rel.tag_name.slice(prefix.length);
      const jsonAsset = rel.assets?.find((a) => a.name === `${service}.json`);
      const shaAsset = rel.assets?.find((a) => a.name === `${service}.json.sha256`);
      if (!jsonAsset || !shaAsset) continue;
      try {
        const sha = (await download(shaAsset.url, ghHeaders("application/octet-stream")))
          .toString()
          .trim();
        let stored = byHash.get(sha);
        if (!stored) {
          const spec = await download(jsonAsset.url, ghHeaders("application/octet-stream"));
          stored = `${sha}.json`;
          await writeFile(path.join(specDir, stored), spec);
          byHash.set(sha, stored);
        }
        entries.push({
          version,
          sha256: sha,
          spec: `specs/${service}/${stored}`,
          prerelease: Boolean(rel.prerelease),
        });
      } catch (e) {
        console.warn(`[docs] ${service} ${version}: ${e.message} — skipping`);
      }
    }

    // dev first, then releases newest-first.
    const released = entries.filter((e) => e.version !== "dev").sort((a, b) => cmpVersion(b.version, a.version));
    const dev = entries.filter((e) => e.version === "dev");
    services[service] = [...dev, ...released];
    console.log(`[docs] ${service}: ${services[service].length} version(s)`);
  }

  // Emit the pinned Scalar version alongside the data so app.js reads the CDN
  // fallback URL from here — one pin, no drift between the vendored copy and the
  // runtime fallback.
  await writeFile(
    path.join(DIST, "versions.json"),
    JSON.stringify({ scalar: { version: SCALAR_VERSION, url: SCALAR_URL }, services }, null, 2),
  );

  // 404 fallback for GitHub Pages (SPA-style deep links).
  await cp(path.join(DIST, "index.html"), path.join(DIST, "404.html"));

  // Vendor the Scalar standalone renderer (best-effort; app.js falls back to CDN).
  try {
    await mkdir(path.join(DIST, "vendor"), { recursive: true });
    const scalar = await download(SCALAR_URL, { "User-Agent": "wardnet-docs-build" });
    await writeFile(path.join(DIST, "vendor", "scalar.js"), scalar);
    console.log(`[docs] vendored Scalar ${SCALAR_VERSION} (${scalar.length} bytes)`);
  } catch (e) {
    console.warn(`[docs] could not vendor Scalar (${e.message}) — site will load it from CDN`);
  }

  console.log(`[docs] built -> ${DIST}`);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
