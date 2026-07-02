# Wardnet Cloud — API reference site

A static GitHub Pages site that renders every service's OpenAPI spec
(`tenants`, `ddns`, `tunneller`) at every published version, using
[Scalar](https://github.com/scalar/scalar) — the same renderer the wardnet
daemon vendors.

## How it works

- **Spec source of truth = GitHub Release assets.** Each service release attaches
  `<service>.json` + `<service>.json.sha256` (see `release-service.yml`). Release
  assets are permanent (unlike Actions artifacts, which expire), so they are the
  durable multi-version store.
- `scripts/build.mjs` (Node 22, no npm deps) lists the `{tenants,ddns,tunneller}-v*`
  releases, dedups spec content by sha256, downloads each distinct spec into
  `dist/specs/<service>/`, and emits `dist/versions.json`. The committed in-repo
  spec (`source/docs/openapi/<service>.json`) is always added as the `dev` entry,
  so the site works before any release exists.
- `public/` (the HTML shell + pickers + styles) is copied into `dist/`; the Scalar
  standalone is vendored into `dist/vendor/scalar.js` (CDN fallback in `app.js`).

## Build locally

```sh
# dev-only (no released versions): renders the committed in-repo specs
node scripts/build.mjs

# include released versions (needs a token for private repos):
DOCS_REPO=<owner>/wardnet-cloud GITHUB_TOKEN=$(gh auth token) node scripts/build.mjs

# then serve the output
python3 -m http.server -d dist 8000   # http://localhost:8000
```

In CI `GITHUB_REPOSITORY` and `GITHUB_TOKEN` are set automatically.

## Deployment

`.github/workflows/deploy-docs-site.yml` builds and publishes `dist/` to GitHub
Pages on every push to `main` (refreshes the `dev` spec), on every published
release (a new version appeared), and on manual dispatch.

**One-time setup:** enable Pages with **Source = GitHub Actions** in the repo
Settings → Pages.
