# 🦅 BugHawk — Session Summary

## Features Added

### 1. Parameter Diffing (URL Parser)
- Created `src/lib/diff.js` — `diffUrls()` compares two URL parse results, returns added/removed/changed with per-base grouping and parameter-level diffs
- Added `sessionSignature()` to fingerprint a session hash
- Added **Diff lens** to URL Parser — compares current data against any saved session, shows added (green), removed (red), changed groups
- Added JSON export for diff results
- 19 unit tests in `src/lib/diff.test.js`

### 2. JWT Decoder Tab
- Created `src/lib/jwt.js` — decodes JWTs, flags security issues (alg:none, forgeable, expired, injection in claims)
- Created `src/components/JwtDecoder/JwtDecoderTab.jsx` — paste JWT, see decoded header/payload, issue flags, copy to clipboard
- Added command palette entry (`Ctrl+K` > "Go to JWT Decoder")
- Linked in sidebar

### 3. Project Zip Importer
- Added `jszip` dependency
- Created `src/lib/project-import.js` — file-name pattern matching + content parsers for 6 formats (hostlist, urllist, nuclei, gnmap, cariddi, jsfile)
- Two-stage detection: filename matching first, then content-based fallback
- Created `src/components/ProjectImport/ProjectImportModal.jsx` — drag/select .zip, shows grouped preview of detected files with checkboxes, imports to correct tabs
- **Content-based fallback** — auto-detects URL lists vs host lists, nuclei JSONL, nmap XML, GNMAP, Cariddi format
- Added **nmap XML parser** (not just GNMAP)
- Added **JS file support** (routes .js files to JS Recon tab)
- Added **scope file support** (routes scope files to Subdomains)
- Added `+` button in TopBar + command palette entry
- 24 unit tests in `src/lib/project-import.test.js`

### 4. Dorks Trimming
- Removed `Internal / Misc` category entirely (low-signal dorks)
- Removed `Backups & Dumps` category entirely
- Trimmed ~48 low-signal dorks from SECRETS, APIKEYS, PRIVATE_KEYS, FILES, ORG categories
- Total GitHub dorks reduced from 340 to 265

### 5. Vite Config — Dynamic Base Path
- `vite.config.js` — `base` now reads from `VITE_BASE_PATH` env var, falls back to `/bughawk/` for GitHub Pages

### 6. Wipe Project Data (Settings)
- Added `clearProjectData(projectId)` in `src/lib/storage.js` — deletes all `bbd:project:<id>:*` keys from IndexedDB
- Renamed "Clear {name} hosts" to **"Wipe {name} data"** — now clears subdomains, URLs, ports, findings, sessions, JS recon, activity, notes, scope, assets, everything
- Added confirmation dialog before wipe

### 7. Clear All Data on Logout
- Added `clearAllData()` in `src/lib/storage.js` — deletes ALL IndexedDB keys except `bbd:auth` (keeps login gate)
- Logout now wipes all project data before locking and reloading

### 8. ESLint Config Cleanup
- Removed `'jsrecon/**'` from eslint ignore list since the directory was deleted

### 9. README Overhaul
- Complete rewrite with detailed documentation for every tab
- Added Project Import section with detection examples table (20+ filename patterns)
- Added full format reference table (9 parsers)
- Added project layout, FAQ, and security model docs
- Updated authors (mehulgupta1, manojxshrestha)

### 10. UI Polish
- Navbar icon buttons — circular (50% border-radius), surface background, accent hover color
- **+** import button and **sun/moon** theme toggle styled as circular icon buttons
- Import zone "+" — 64px circular button with accent background
- Restored `icon` field to all command palette entries with text-based symbols (circle, diamond, diamond-filled, arrow, gear, box, etc.)
- Restored sidebar icons with same text symbols

---

## Things Removed

### 1. All Emojis from Codebase
- Every emoji removed across 25+ files — components (`Sidebar.jsx`, `TopBar.jsx`, `SubdomainTab.jsx`, `PortTab.jsx`, `Dashboard.jsx`, `DorksTab.jsx`, `JsReconTab.jsx`, `ReconUrlParser.jsx`, `NotebookTab.jsx`, `SurfaceTab.jsx`, `AssetsTab.jsx`, `TechStackTab.jsx`, `FindingsTab.jsx`, `SettingsTab.jsx`, `ScopeTab.jsx`, `LoginGate.jsx`, etc.), hooks (`usePorts.js`), and lib files (`apikeys.js`, `portexporter.js`, `portparser.js`)
- Replaced with text labels, CSS-styled symbols, or removed where redundant

### 2. `test-data/` directory (10 files, ~8MB)
- `diff-1-baseline.txt`, `diff-2-later.txt` — diff test fixtures
- `nmap-rich.xml` — nmap sample
- `sample-mixed.txt`, `sample-ports.txt`, `sample-ports-many.txt` — port scan samples
- `sample-scope-hackerone.txt` — scope sample
- `subdomains-100k.txt`, `subdomains-10k.txt` — large subdomain lists

### 3. `jsrecon/samples/` directory (6 files)
- `admin.chunk.js`, `app.bundle.js`, `clean.vendor.js` — sample JS files for manual JS Recon testing
- `js-urls-500.txt` — 500 JS URLs
- `urls.api.js`, `urls.subdomains.js` — sample JS with API endpoints

### 4. `test_httpx.jsonl` (10 lines)
- Leftover httpx sample data, not referenced anywhere

### 5. CI Workflow Fix
- Removed `continue-on-error: true` from `.github/workflows/ci.yml` since lint was now clean

### 6. Vite 8 to 7 Downgrade
- `vite: ^8.1.5` to `^7.0.0` because `@vitejs/plugin-react@4.7.0` does not support Vite 8 (peer dep conflict). CI was failing on `npm ci`.

---

## Files Created (14 new)

| File | Purpose |
|---|---|
| `src/lib/diff.js` | URL diff engine |
| `src/lib/diff.test.js` | 19 diff tests |
| `src/lib/jwt.js` | JWT decode + security analysis |
| `src/lib/jwt.test.js` | JWT tests |
| `src/lib/project-import.js` | Zip import detection + parsers |
| `src/lib/project-import.test.js` | 24 import tests |
| `src/components/JwtDecoder/JwtDecoderTab.jsx` | JWT decoder tab |
| `src/components/ProjectImport/ProjectImportModal.jsx` | Import modal |


## Git History (7 commits)

```
bb883e1 — fix: circular icon buttons in navbar, sun/moon theme
fa186b4 — feat: wipe project data (all tabs) in Settings, import zone icon
809efcc — feat: clear all project data on logout
2136362 — docs: expand project import docs with detection examples
005e10a — fix: restore icon fields with text symbols (remove emojis only)
86fca7c — feat: broaden project import with content-based fallback, JS/XML/scope
6fdbfa7 — feat: add deployment config with SPA routing and JS proxy function
7aa4654 — chore: remove unused jsrecon/samples directory
7b76b7a — fix: downgrade vite to ^7.0.0 for plugin-react compatibility
c91be41 — feat: project zip import, URL parser diff, JWT decoder, dorks trimming, emoji cleanup, README overhaul
```

---

## Current State

- **155 unit tests**, 0 lint errors, clean build
- **96.2 KB** gzipped JS, **12.2 KB** gzipped CSS
- GitHub Pages at **https://mehulgupta1.github.io/bughawk/** (needs Pages source set to `gh-pages` branch)
