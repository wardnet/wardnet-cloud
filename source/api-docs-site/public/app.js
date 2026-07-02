// Renders the Scalar reference for the selected service+version, and injects the
// service/version pickers at the top of Scalar's own left navigation drawer
// (mirrors how the wardnet daemon injects its brand mark into the sidebar).
//
// Selection lives in the URL (?service=&version=) so a picker change is a plain
// reload — no re-init dance.
//
// Scalar config mirrors the daemon's self-hosted /api/docs: the Ask-AI composer
// and the "Create MCP Server" / client button are disabled.

// CDN fallback used only if the vendored bundle is missing. The pinned version
// comes from versions.json (emitted by build.mjs) so it can't drift from the
// vendored copy; this bare-package URL is a last resort if that field is absent.
const DEFAULT_SCALAR = "https://cdn.jsdelivr.net/npm/@scalar/api-reference";

async function main() {
  const doc = document.getElementById("doc");
  let data;
  try {
    data = await (await fetch("./versions.json")).json();
  } catch {
    doc.textContent = "Failed to load versions.json";
    return;
  }

  const services = Object.keys(data.services).filter((s) => data.services[s].length > 0);
  if (services.length === 0) {
    doc.textContent = "No API specs available yet.";
    return;
  }

  const params = new URLSearchParams(location.search);
  let service = params.get("service");
  if (!services.includes(service)) service = services[0];

  const versions = data.services[service];
  let version = params.get("version");
  let current = versions.find((v) => v.version === version);
  if (!current) {
    current = versions[0];
    version = current.version;
  }

  injectSidebarNav(services, service, versions, version);
  loadScalar(current.spec, data.scalar?.url || DEFAULT_SCALAR);
}

// Build the picker block that lives at the top of Scalar's sidebar.
function buildNav(services, service, versions, version) {
  const nav = document.createElement("div");
  nav.className = "wardnet-nav";
  nav.innerHTML =
    '<img class="wardnet-logo" src="./wardnet-logo.svg" alt="Wardnet" />' +
    '<div class="wardnet-subtitle">Cloud · API Reference</div>';

  const svcSel = document.createElement("select");
  svcSel.setAttribute("aria-label", "Service");
  for (const s of services) {
    const o = document.createElement("option");
    o.value = s;
    o.textContent = s;
    o.selected = s === service;
    svcSel.append(o);
  }
  // Switching service resets to that service's default (first) version.
  svcSel.onchange = () => {
    location.search = `?service=${encodeURIComponent(svcSel.value)}`;
  };

  const verSel = document.createElement("select");
  verSel.setAttribute("aria-label", "Version");
  for (const v of versions) {
    const o = document.createElement("option");
    o.value = v.version;
    o.textContent = v.version + (v.prerelease ? " (pre-release)" : "");
    o.selected = v.version === version;
    verSel.append(o);
  }
  verSel.onchange = () => {
    location.search = `?service=${encodeURIComponent(service)}&version=${encodeURIComponent(verSel.value)}`;
  };

  nav.append(labelled("Service", svcSel), labelled("Version", verSel));
  return nav;
}

function labelled(text, control) {
  const wrap = document.createElement("label");
  wrap.className = "wardnet-field";
  const span = document.createElement("span");
  span.textContent = text;
  wrap.append(span, control);
  return wrap;
}

// Scalar has no top-of-sidebar slot config (github.com/scalar/scalar/discussions/914),
// so watch for the sidebar to mount and prepend our picker block, then stop
// observing — leaving it connected would run a whole-document querySelector on
// every Scalar DOM mutation for the life of the page.
function injectSidebarNav(services, service, versions, version) {
  let observer;
  const insert = () => {
    const sidebar = document.querySelector(".t-doc__sidebar");
    if (!sidebar || sidebar.querySelector(".wardnet-nav")) return;
    sidebar.prepend(buildNav(services, service, versions, version));
    observer?.disconnect();
  };
  observer = new MutationObserver(insert);
  observer.observe(document.body, { childList: true, subtree: true });
  insert();
}

function loadScalar(specUrl, fallbackUrl) {
  const mount = () => {
    // Scalar programmatic API (window.Scalar from the standalone bundle) — the
    // same config the daemon uses at /api/docs.
    window.Scalar.createApiReference("#doc", {
      url: specUrl,
      agent: { disabled: true },
      mcp: { disabled: true },
      showDeveloperTools: "never",
      hideClientButton: true,
      hideDarkModeToggle: true,
    });
  };
  const fail = () => {
    document.getElementById("doc").textContent =
      "Failed to load the API reference renderer.";
  };
  const s = document.createElement("script");
  s.src = "./vendor/scalar.js";
  s.onload = mount;
  s.onerror = () => {
    const cdn = document.createElement("script");
    cdn.src = fallbackUrl;
    cdn.onload = mount;
    cdn.onerror = fail;
    document.body.append(cdn);
  };
  document.body.append(s);
}

main();
