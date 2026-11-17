# Guardiantus AV — website

The site at <https://guardiantus-av.vercel.app>. Plain HTML, CSS and JavaScript: no build
step, no framework, nothing loaded from another host.

| File | What it is |
| --- | --- |
| `index.html` | Landing page |
| `features.html` | Features & tools |
| `demo.html` | Threat Lab |
| `setup.html` | Setup |
| `download.html` | Download |
| `terms.html` | Terms of Use |
| `404.html` | Shown for any address that does not exist |
| `assets/site.css` | This project's accent colour and anything only this site needs |
| `assets/scene.js` | The 3D scene in the page header |
| `assets/aqx/` | The look and behaviour shared by all AquAxs project sites |

## The shared part

`assets/aqx/` is the same in every project site: the stylesheet (`aqx.css`),
the interactions (`aqx.js`), the 3D stage (`stage.js`), three.js and the three
typefaces. It follows the portfolio at aqua.is-a.dev: a black sky with slow
dots, glass cards that lean towards the pointer, Bodoni Moda headlines.
Change the accent in `assets/site.css` (`--ac`, `--ac-hi`), not in `aqx.css`.

## The 3D scene

`assets/scene.js` exports one function that builds its objects into
`stage.frame`. The stage (`assets/aqx/stage.js`) does the rest: camera, lights,
resizing, pointer and touch, pausing off screen. With reduced motion the scene
is one still frame; without WebGL a glow in the accent colour stays instead.

## Preview

Links have no `.html` (Vercel serves `/download` from `download.html`), so open
the folder through a server that does the same:

```bash
npx serve site
```

## Deploy

Vercel, root directory `site`, no build command. `vercel.json` sets clean URLs
and the security headers. The site sets no cookies and stores nothing.

## The Threat Lab

`demo.html` is the interactive minigame. `assets/js/engine.js` is a real port of
`guardiantus/core` — hash signatures, pattern signatures, the YARA rule set and the
heuristic scorer — so verdicts are computed, not scripted, and dropping your own file in gives
a genuine answer. `assets/js/samples.js` holds the sample files and `assets/js/demo.js` the
game. Those three files are unchanged by the redesign; the page only gives them new styles
(`assets/site.css`, the Threat Lab section) and the icon sprite they draw from.

Not ported: the full signature feed, native YARA, PE section parsing and archive unpacking.
Those live in the desktop product. Everything runs client-side: no file, hash or byte leaves
the browser.

## Desktop app downloads

`download.html` links directly to
`github.com/aquaxs1/Guardiantus-AV/releases/latest/download/<asset>`, which always resolves to
the newest published release. `assets/js/download.js` only picks the visitor's build as the
primary button. `packaging/check_download_links.py` (run by
`.github/workflows/download-links.yml`) checks that every asset name on the site is one the
release workflow builds — run it after touching the download page.

## Privacy notice

`terms.html#privacy` describes what the site, the downloads and the software process. Update
it when either one starts sending or storing something new.
