# Guardiantus AV — website

Static marketing and documentation site. No framework, no build step — the same
rule the product follows.

## Deploy to Vercel

The `site/` directory is the whole deployment. Nothing is compiled.

**From the dashboard**

1. Import the repository at [vercel.com/new](https://vercel.com/new).
2. Set **Root Directory** to `site`.
3. Framework preset: **Other**. Leave build and output commands empty.
4. Deploy.

**From the CLI**

```bash
cd site
vercel --prod
```

`vercel.json` sets `cleanUrls` (so `/features` serves `features.html`) and the
security headers, including a CSP with no inline script or style.

## Pages

| File | Purpose |
|---|---|
| `index.html` | Landing page — value, features, how it works, FAQ |
| `features.html` | Every feature and tool, grouped by subsystem |
| `download.html` | Desktop app downloads plus pip install options |
| `setup.html` | Six-step setup plus the self-test files |
| `demo.html` | Threat Lab — the interactive minigame |
| `terms.html` | Terms of Use |

## Assets

| File | Purpose |
|---|---|
| `assets/css/site.css` | Design system, shared with the product dashboard |
| `assets/js/site.js` | Theme, mobile nav, copy buttons |
| `assets/js/engine.js` | Browser port of the four detection layers |
| `assets/js/samples.js` | Threat Lab sample files |
| `assets/js/demo.js` | Threat Lab game logic |
| `assets/js/download.js` | Platform detection for the download page's primary button |

## Desktop app downloads

`download.html` links directly to `github.com/aquaxs1/Guardiantus-AV/releases/latest/download/<asset>`,
which always resolves to the newest published release — no version bump needed
on this site when a new build ships. The binaries themselves come from
`.github/workflows/release.yml` (see `packaging/README.md` in the repo root),
built on real Windows, Intel Mac, Apple Silicon Mac and Linux runners. They are
not code-signed, which the page explains along with how to get past the
resulting OS warnings.

## The Threat Lab

`engine.js` is a real port of `guardiantus/core` — hash signatures, pattern
signatures, the YARA rule set and the heuristic scorer. Verdicts in the game are
computed, not scripted, which is why dropping your own file in gives a genuine
answer.

Not ported: the full signature feed, native YARA, PE section parsing and archive
unpacking. Those live in the desktop product.

Everything runs client-side. No file, hash or byte leaves the browser, and the
site sets no cookies and runs no analytics.

## Editing

Plain HTML. The header and footer are repeated per page; keep them in sync when
you change navigation. Adding a page means adding it to:

1. `NAV_ITEMS` markup in each page header
2. The footer quick links
3. `sitemap.xml`
