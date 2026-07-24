<div align="center">

# 🦅 BugHawk

**A private, in-browser bug-bounty recon workspace.**

Organize an entire recon engagement — subdomains, ports, assets, JavaScript secrets, URLs, dorks, wordlists, findings — in one fast local dashboard. No backend, no accounts, no telemetry. Every byte lives in your own browser.

</div>

---

## Table of Contents

- [What is BugHawk?](#what-is-bughawk)
- [Quick Start](#quick-start)
- [Scripts](#scripts)
- [Project Import](#project-import)
- [Tab Reference](#tab-reference)
  - [Dashboard](#dashboard)
  - [Scope](#scope)
  - [Subdomains](#subdomains)
  - [Port Scan](#port-scan)
  - [Assets](#assets)
  - [URL Parser](#url-parser)
  - [JS Recon](#js-recon)
  - [Attack Surface](#attack-surface)
  - [HTTP Analyzer](#http-analyzer)
  - [Tech Stack](#tech-stack)
  - [Findings](#findings)
  - [Notebook](#notebook)
  - [GitHub Dorks](#github-dorks)
  - [Google Dorks](#google-dorks)
  - [Wordlists](#wordlists)
  - [Settings](#settings)
- [Security Model](#security-model)
- [Tech Stack](#tech-stack)
- [FAQ](#faq)
- [Contributing](#contributing)
- [License](#license)

---

## What is BugHawk?

BugHawk is a single-page web app that runs on your machine and acts as the **central notebook + toolkit for a bug-bounty or pentest recon workflow**. Instead of juggling dozens of text files, spreadsheets, and terminal outputs, you paste your tool output (httpx, subfinder, nmap, katana, gau) into BugHawk and it parses, dedupes, organizes, cross-links, and lets you export it — all offline.

**Core ideas:**

- **Local-first & private.** All data is stored in your browser's IndexedDB. Nothing is uploaded anywhere. There is no server that holds your data.
- **Project-based.** Each target/program is a "project". Switch between them; each keeps its own subdomains, findings, notes, etc.
- **Import what you already have.** BugHawk doesn't run scanners for you — it ingests the output of the tools you already use and makes it usable. You can even import a whole project from a `.zip` archive.
- **Cross-linked.** Data flows between tabs: JS secrets become Findings, discovered domains become Subdomains, IPs group by status, and so on.

> **Ethics & scope.** BugHawk is for **authorized** security testing, bug-bounty programs, CTFs, and education. Only test assets you have explicit permission to test.

---

## Quick Start

```bash
git clone https://github.com/mehulgupta1/bughawk.git
cd bughawk
npm install
npm run dev        # opens the dev server (http://localhost:5173)
```

**First launch:** you will be asked to create a **username + password**. This locks the workspace on this browser. (It is a local convenience lock, not server-grade auth — see [Security model](#security-model).)

### Run it privately (no dev server)

For day-to-day private use, one command builds the app and serves it on a fixed local port:

```bash
npm run serve     # builds, then serves at http://localhost:5050
```

On Windows you can just double-click **`start-app.bat`** — it builds, launches the server, and opens your browser. Use this fixed URL (`:5050`) as your permanent home so your saved data does not split across ports (see [FAQ](#faq)).

---

## Scripts

| Command | What it does |
|---|---|
| `npm run dev` | Vite dev server with hot reload (development) |
| `npm run build` | Production build into `dist/` |
| `npm run serve` | Build + serve privately at `http://localhost:5050` |
| `npm start` | Serve an existing `dist/` build |
| `npm test` | Run the engine unit tests (`node --test`) |
| `npm run lint` | Run ESLint |

---

## Project Import

BugHawk can import an entire recon project from a `.zip` file. This is useful when you receive reconnaissance output from a teammate, a CI pipeline, or your own automation.

### How it works

Click the `+` button in the top bar (or use the command palette via `Ctrl/⌘+K` and type "Import"). Select a `.zip` file. BugHawk scans every file inside and uses a two-stage detection system:

1. **Filename matching** — recognizes files by common naming patterns (`subdomains.txt`, `urls.txt`, `nuclei.jsonl`, `nmap.xml`, `*.js`, `scope.txt`, etc.)
2. **Content-based fallback** — if the filename isn't recognized, the file content is analyzed to detect format

### Detection examples

| Filename in zip | How it is detected | Destination tab |
|---|---|---|
| `subdomains.txt` | filename contains "subdomain" | Subdomains |
| `live.txt`, `alive.txt` | filename matches | Subdomains |
| `all.txt`, `hosts.txt`, `resolved.txt` | filename matches | Subdomains |
| `urls.txt`, `allurls.txt` | filename contains "url" | URL Parser |
| `crawled.txt`, `gau.txt`, `katana.txt` | filename contains "crawl", "gau", "katana" | URL Parser |
| `endpoints.txt`, `wayback.txt` | filename matches | URL Parser |
| `unknown.txt` with URLs (https://...) | content detection | URL Parser |
| `unknown.txt` with hosts (api.example.com) | content detection | Subdomains |
| `nuclei.jsonl`, `nuclei-output.txt` | filename contains "nuclei" | Findings |
| `unknown.jsonl` con nuclei JSON | content detection (JSONL) | Findings |
| `cariddi.txt` | filename contains "cariddi" | Findings |
| `nmap.xml`, `scan.gnmap`, `nmap-output.txt` | filename contains "nmap", `.gnmap`, or `.nmap` extension | Port Scan |
| `unknown.xml` con `<nmaprun>` | content detection (XML) | Port Scan |
| `app.bundle.js`, `main.chunk.js` | `.js` extension | JS Recon |
| `scope.txt`, `in-scope.txt` | filename contains "scope" | Subdomains |

### File formats and parsers

| Format | Extension | What gets parsed |
|---|---|---|
| **httpx JSONL** | `.jsonl`, `.txt` | Subdomains + URL Parser (status, title, tech, CNAME, IP, length) |
| **nmap XML** | `.xml` | Port Scan (hosts, ports, services, versions) |
| **nmap GNMAP** | `.gnmap`, `.nmap`, `.txt` | Port Scan (hosts, ports, services) |
| **plain host list** | `.txt` | Subdomains (one host per line) |
| **URL list** | `.txt` | URL Parser (one URL per line) |
| **nuclei JSONL** | `.jsonl`, `.txt` | Findings (template name, severity, host, extract) |
| **nuclei plain text** | `.txt` | Findings (one host per line) |
| **cariddi output** | `.txt` | Findings (URL + severity tag) |
| **raw JS files** | `.js` | JS Recon (secrets, endpoints, API keys, AST analysis) |
| **scope / program** | `.txt` | Subdomains (one domain per line, supports `*.` wildcards) |

The import modal shows a grouped preview of everything detected before you confirm — each file listed under its destination tab with line count and item count, so you know exactly what will be ingested before committing.

---

## Tab Reference

### Dashboard

Your at-a-glance overview for the active project:

- **Total subdomains** with status-code breakdown (donut chart + spectrum visualization)
- **Tech distribution** — which technologies appear across your hosts
- **Activity feed** — recent imports and changes across all tabs
- **Flagged hosts** — hosts matching admin/dev/staging keywords
- **Recon progress** — overview of data completeness per tab
- **New since last visit** — highlights what changed
- **Heatmap** — visual density of subdomains
- **Trend chart** — how your data set has grown over time
- **Quick notes** scratchpad

### Scope

Define what is **in scope** and **out of scope** for the program (root domains, wildcards like `*.example.com`, explicit excludes). Once scope is set, other tabs become scope-aware:

- Out-of-scope subdomains and URLs can be hidden or flagged
- Prevents wasted time on assets you should not touch
- Includes a diff view to see scope changes when a program updates its scope table

### Subdomains

The heart of the tool. Paste or import subdomain data in several formats:

- **httpx JSONL** (recommended — carries status, title, tech, IP, CNAME, length, redirect location, and any extra fields)
- Bracket format (`host [200] [title] [tech]`)
- Space/CSV-separated, or a plain list of hosts

**Features:**

- **Virtualized table** that stays smooth at 100,000+ rows
- **Dynamic columns** — the table adapts to whatever fields your data has (Title, CNAME, IP, Tech, Length, plus any extra httpx fields). Toggle columns via the **Columns** menu
- **Status filtering** — 2xx/3xx/4xx/5xx pills, full-text search, and sorting
- **Status history** per host — track when a host's status changed across imports
- **Smart-flagging** by keyword (e.g. flag anything matching `admin`, `dev`, `staging`)
- **Audit state** per host — untested / testing / vulnerable / safe
- **Clickable hosts** open in new tabs; CNAME column surfaces takeover candidates (dead host pointing at an S3 bucket)
- **Bulk operations**, export by status (`.txt`/`.csv`), and in-app saved sessions

### Port Scan

Import **nmap** (XML) or masscan-style output. Parses hosts, open ports, services, versions, and banners into a browsable table.

**Features:**

- Per-host detail view with all open ports
- **Port diffing** between two scans — see exactly what opened, closed, or changed (service, version, banner) with a color-coded diff view
- **Saved sessions** — save and reload scan results
- **CVE hints** — derived from detected service versions, including CISA KEV tagging for actively exploited vulnerabilities
- KEV pill filter to focus on actively exploited CVEs

### Assets

A raw-asset vault with three buckets — **Subdomains**, **URLs**, **JS Files** — plus a derived **IPs** view:

- **Smart import** auto-routes a mixed dump into the right bucket
- Dedupes, tags sources, tracks "new since last seen"
- Detects **dead endpoints** — URLs whose host returns 404/5xx in your Subdomains data
- **IPs tab**: pulls every unique IP from your subdomains and groups them by HTTP status (all 200 IPs, all 301 IPs) with per-group copy/export. Great for spotting infrastructure to probe directly
- Full vault export/import as JSON

### URL Parser

Paste a large list of URLs (gau/katana/waymore output). Parses them in a **Web Worker** and extracts signals — without freezing the UI.

**Multi-lens views:**

| Lens | What it shows |
|---|---|
| **Categories** | URLs grouped by risk categories (secrets, auth, endpoints, etc.) with severity and confidence filters |
| **Endpoints** | Unique endpoint templates (path patterns) ranked by frequency or rarity. Drill into any template to see all matching URLs |
| **Parameters** | All unique parameter names with their value types, endpoint, and host counts. One-click ffuf command generation |
| **JWTs** | Detected and decoded JWT tokens from query strings with algorithm, expiration, issuer, subject, and security issue flags (alg:none, forgeable, expired) |
| **IDOR Matrix** | Endpoint templates organized by HTTP verb for IDOR testing |
| **Env Drift** | Shared paths across hosts — shows response inconsistencies that may indicate staging vs. production |
| **Diff** | Compare the current parsed data against a saved session. Shows added and removed URLs with per-line changes |

**Other features:**

- Dedup, entropy threshold, custom regex signatures
- Export CSV or TXT
- Save and reload sessions
- Wordlist integration — send parameters or paths to the Wordlists tab

### JS Recon

Deep JavaScript analysis. Give it raw JS, a list of `.js` URLs, or local `.js` files:

- **Secrets & API keys** — ~260 rules across cloud, third-party, DB, and private-key categories with confidence scoring
- **Security misconfigurations**, endpoints, webpack chunks, source maps, framework fingerprints, parameters, domains, GraphQL operations, and juicy paths
- **AST pass** (acorn) recovers runtime-built endpoints that regex misses, e.g. `"/api/" + v`, `` `/api/${id}` ``, `fetch(u)`

**Features:**

- **CORS-free**: the browser calls a same-origin `/__jsproxy?url=...` helper and the Node process fetches the target server-side
- **Worker pool** parallelizes across CPU cores
- By-file and Merged views with pagination, per-file risk score
- **Recursive scanning** of discovered chunks and source maps
- **Diff mode** — only process new JS since last scan
- Markdown/JSON report export, ready-to-run nuclei/httpx/ffuf/curl commands
- Cross-tab actions: send a secret to Findings, send domains to Subdomains

### Attack Surface

A visual graph tying your data together — domains, hosts, endpoints, and their relationships — so you can see the shape of the target's exposed surface rather than a flat list.

### HTTP Analyzer

Paste a raw HTTP request/response (or headers) and it flags security-relevant issues:

- Missing or weak security headers (HSTS, CSP, X-Frame-Options, etc.)
- Permissive CORS policies
- Dangerous cookie flags (missing Secure, HttpOnly, SameSite)
- Information disclosure
- Secrets in the response body
- Each issue comes with a severity rating

### Tech Stack

Aggregates the technologies detected across all your hosts into a searchable breakdown: which tech, how many hosts, which hosts. Handy for answering "show me everything running Tomcat / WordPress / GraphQL."

### Findings

Your vulnerability tracker:

- Log findings with title, host, severity, and notes
- Filter and search across all findings
- Findings pushed in from other tabs automatically (e.g. a secret found in JS Recon)
- Export for reporting (Markdown)

### Notebook

Free-form markdown notes per project — methodology, payloads that worked, credentials to remember, next steps. Pinned notes stay at the top.

### GitHub Dorks

A curated library of **265 GitHub dork templates** across categories — secrets, API keys, private keys, cloud keys, third-party tokens, sensitive files, DB connection strings, login panels, cloud-storage buckets (S3/Azure/GCS/Drive), and more. Paste your target domain once and every dork becomes a one-click search link with the target substituted in.

You can add your own dorks and create new categories.

### Google Dorks

A large library of **Google search dork templates** organized by category. Same workflow — enter your target, get one-click Google search links for each dork.

### Wordlists

Store and manage fuzzing wordlists in-app:

- Add lists by pasting or drag-and-drop a `.txt` file
- Tag them by category and variant
- Filter by name or content
- Export and import all lists as JSON for backup or transfer between browsers/ports
- Integrates with URL Parser — send discovered parameters and paths directly to the Wordlists tab

### Settings

- **Security** — change your username/password (requires the current password) and log out
- **API Keys vault** — store keys for common recon tools (subfinder's 20+ providers, Chaos, Findomain, GitHub, Shodan, VirusTotal) in a tabbed vault. Export them as a ready-to-use config file (subfinder YAML or `.env`). Keys are stored locally in your browser only
- Theme toggle (light/dark) and other preferences

---

## Security Model

Please read this before relying on BugHawk for anything sensitive:

- **The login is a local lock, not real authentication.** Your password is hashed (salted SHA-256) and checked in-browser to gate the UI. Anyone with access to the machine or browser profile can reach the underlying IndexedDB. Treat BugHawk as a personal, single-user tool on a machine you control.
- **`/__jsproxy` is an open, localhost-only fetch helper.** It will fetch any URL it is handed. It is bound to `127.0.0.1` by design — **do not expose the dev/serve port to an untrusted network**, or you turn your machine into an open proxy.
- **API keys and stored data are not encrypted at rest** beyond the browser's own storage. Do not use this on a shared or public computer.
- **No data leaves your machine** — there is no backend, analytics, or phone-home.

---

## Tech Stack

- **Vite 5** + **React 18** (single-page app)
- **IndexedDB** via [`idb`](https://github.com/jakearchibald/idb) for all persistence (per-project)
- **Web Workers** for heavy parsing and scanning (URL parser, JS recon, wordlist cleaning) so the UI never blocks
- **acorn** for AST-based endpoint recovery in JS Recon
- **jszip** for `.zip` project import
- Zero runtime backend — a tiny zero-dependency Node server (`server.mjs`) only serves the built files + the `/__jsproxy` helper for private use

### Project layout

```
src/
  components/*   one folder per tab (Subdomains, JsRecon, Assets, ...)
  lib/*          pure, DOM-free engines + IndexedDB storage (storage.js)
  hooks/*        project/data React hooks
  **/<x>.worker.js  Web Workers for heavy scans
  styles/*       CSS (BugHawk theme via CSS variables)
server.mjs       zero-dep production server (dist/ + /__jsproxy)
vite.config.js   dev/preview server + jsProxyPlugin (CORS-free fetch)

```

---

## FAQ

**Where is my data? Can I move it to another computer?**

It is in your browser's IndexedDB, scoped to the exact origin (`protocol://host:port`). Data saved on `localhost:5173` is **not** visible on `localhost:5050` — different port = different storage. Use each tab's Export/Import (Wordlists, Assets vault, Subdomain sessions, Findings) to move data between origins or machines, and pick **one URL** (e.g. the `:5050` private server) as your permanent home.

**Does it run the scanners (subfinder, nmap, httpx) for me?**

No. BugHawk organizes and analyzes the **output** of those tools. You run the tools; you paste or import the results.

**Can I use it alongside Burp Suite?**

Yes — Burp on `127.0.0.1:8080` and BugHawk on `127.0.0.1:5050` do not conflict.

**Is it safe to make my repo or dev server public?**

The *code* is fine to open-source. Do **not** expose the running **dev/serve port** to the internet (see [Security model](#security-model)).

---

## Contributing

Contributions welcome — see [CONTRIBUTING.md](CONTRIBUTING.md). Run `npm run lint` and `npm test` before opening a PR.

## License

[MIT](LICENSE)

## Author

- [mehulgupta1](https://github.com/mehulgupta1)
- [manojxshrestha](https://github.com/manojxshrestha)
