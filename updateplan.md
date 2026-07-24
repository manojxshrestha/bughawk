# BugHawk — Update Plan for Opus 4.8

## Context

BugHawk is a private, in-browser bug-bounty recon workspace (Vite 5 + React 18). All data lives in IndexedDB. The repo is at https://github.com/mehulgupta1/bughawk.

## What Has Been Implemented (Recent Commits)

### 1. Project Zip Importer
- `src/lib/project-import.js` — Two-stage detection (filename + content-based fallback)
- `src/components/ProjectImport/ProjectImportModal.jsx` — Drag/select .zip, grouped preview, checkbox selection
- 24 unit tests in `src/lib/project-import.test.js`
- **Supported formats**: host lists, URL lists, nuclei JSONL, nmap XML/GNMAP, Cariddi output, raw JS files, scope files
- **Content fallback**: auto-detects URL lists vs host lists, nuclei JSONL, nmap XML, Cariddi, GNMAP format from file content when filename is unrecognized
- Hint text in the import zone should be updated to show realistic examples

### 2. URL Parser — Diff Lens
- `src/lib/diff.js` — `diffUrls()` compares two URL parse results, returns added/removed/changed with per-base grouping and parameter-level diffs
- `sessionSignature()` hashes a session for identity comparison
- Added "Diff" button on session cards and in the lens bar
- Diff view shows added (green), removed (red), and changed groups
- JSON export for diff results

### 3. JWT Decoder Tab
- `src/lib/jwt.js` — Decodes JWTs without verification, flags: alg:none, forgeable (RS256->HS256), expired, injection in claims
- `src/components/JwtDecoder/JwtDecoderTab.jsx` — Full tab UI
- Linked in sidebar and command palette

### 4. GitHub Dorks — Trimming
- Removed `Internal / Misc` and `Backups & Dumps` categories (low-signal)
- Trimmed ~48 low-signal dorks from SECRETS, APIKEYS, PRIVATE_KEYS, FILES, ORG
- Total: 340 → 265 GitHub dorks

### 5. Dynamic Base Path & JS Proxy
- `vite.config.js` — `base` reads from `VITE_BASE_PATH` env var, falls back to `/bughawk/` for GitHub Pages

### 6. Data Management — Wipe & Logout
- **Wipe project data** in Settings: `clearProjectData(projectId)` in storage.js — deletes all `bbd:project:<id>:*` keys
- **Logout clears everything**: `clearAllData()` deletes ALL IndexedDB keys except `bbd:auth`
- Renamed "Clear hosts" -> "Wipe {project} data" with confirmation dialog

### 7. Emoji Removal
- Stripped all emojis across 25+ files (components, hooks, lib)
- Replaced with text labels or CSS-styled symbols
- Restored icon fields with geometric text symbols after over-aggressive removal

### 8. CI Fixes
- Downgraded Vite 8 -> 7 for `@vitejs/plugin-react` compat
- Removed `continue-on-error: true` from CI workflow (lint now clean)
- Removed `'jsrecon/**'` from ESLint ignores

### 9. Cleanup
- Removed `test-data/` directory (10 files, 8MB)
- Removed `jsrecon/samples/` directory (6 sample files)
- Removed `test_httpx.jsonl`
- Removed unused `claude-code-prompt-bug-bounty-dashboard.md`

### 10. README & Docs
- Full README rewrite with detailed tab reference
- Project import detection examples table (20+ patterns)
- Format reference table (9 parsers)
- `bughawk.md` — session summary with git history
- This file: `updateplan.md`

## What Needs Attention / Next Steps

### High Priority

1. **GitHub Pages is configured wrong**
   - Repo Pages setting is set to `main` branch `/docs` path
   - The deploy workflow pushes to `gh-pages` branch
   - Fix: Go to repo Settings > Pages, change source to `gh-pages` branch, `/ (root)`
   - Or switch to "GitHub Actions" if the option is available

2. **CI still failing on `npm ci`**
   - Fix was supposed to be the Vite 7 downgrade but the lockfile might still reference Vite 8
   - Verify: `npm ls vite` should show `vite@7.x`, and `npm ci` should pass
   - Check the latest workflow run on GitHub

3. **Import modal needs polish**
   - After successful import, navigate to the target tab so user sees data immediately
   - Show a toast with per-tab breakdown of what was imported
   - Handle the case where the same file matches both by name AND content (avoid double-counting)

### Medium Priority

5. **JWT Decoder improvements**
   - Would benefit from a "paste from clipboard" button
   - Could add JWT scanning across all saved URL sessions (cross-tab)
   - Add known JWT library vulnerability detection (e.g., jsonwebtoken CVEs)

6. **Diff view enhancements**
   - Currently shows added/removed counts but not per-URL diffs inline
   - Could add a "merge" action to combine two sessions
   - Parameter-level diff could show old vs new values side by side

7. **Import format coverage**
   - Add support for `subfinder -oD` directory structure (multiple files in folders)
   - Add `amass` enum output format
   - Add `httpx -jsonl` with tech extraction to populate Tech Stack tab
   - Add `gospider`, `haktrails` URL output formats

8. **Error handling for IndexedDB**
   - Some users on private/incognito mode get IndexedDB errors
   - Add graceful fallback or clear error message
   - Storage quota management warning when approaching limits

### Low Priority

9. **Search/filter in Import modal**
   - Search box to filter detected files by name
   - Select-all / deselect-all per tab group

10. **Batch operations across projects**
    - Export all projects as a single .zip
    - Bulk-import findings from multiple projects

11. **Mobile responsiveness**
    - The table views (Subdomains, URL Parser) don't scale well below 1024px
    - Sidebar collapses but content tables don't have horizontal scroll

12. **Theme consistency**
    - Some nested elements use hardcoded colors instead of CSS variables
    - Modal overlays missing transition animations

## Key Architecture Notes

- **Storage**: All data in IndexedDB via `idb` library. Keys prefixed `bbd:`. Project data uses `bbd:project:<id>:<type>` pattern. See `src/lib/storage.js` KEYS export.
- **Web Workers**: URL parser (`parser.worker.js`), JS recon (`jsrecon.worker.js`), wordlist cleaning (`clean.worker.js`) run in workers to keep UI responsive.
- **Auth**: `src/lib/auth.js` — salted SHA-256 in IndexedDB + sessionStorage flag. Local gate only, not real security.
- **Proxy**: `/__jsproxy` endpoint for CORS-free JS fetching. Vite plugin in dev, requires a serverless/backend equivalent in production.
- **Tests**: Node `--test` runner (no Jest/Vitest). Tests in `src/lib/*.test.js`. Run with `npm test`.

## Useful Commands

```bash
npm run dev          # Dev server at localhost:5173
npm run build        # Production build to dist/
npm run serve        # Build + serve at localhost:5050
npm test             # Run unit tests
npm run lint         # ESLint

```
