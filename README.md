<div align="center">

```
   ╔══════════════════════════════════════════════════════╗
   ║   C A S D E                                          ║
   ║   Continuous Attack Surface & Diff Engine            ║
   ╚══════════════════════════════════════════════════════╝
```

**A "git" for recon.** Learn a target's attack surface over time, diff every
change, extract intelligence from JS, score parameters, fuzz with feedback,
correlate out-of-band callbacks, and triage findings — all in one pipeline.

`Go` · `Python` · `Node` · `SQLite`

[![Go](https://img.shields.io/badge/Go-1.22+-00ADD8?logo=go&logoColor=white)](https://go.dev)
[![License](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![SQLite](https://img.shields.io/badge/SQLite-3-003B57?logo=sqlite&logoColor=white)](https://sqlite.org)

</div>

---

> ## ⚠️ Authorized Use Only
>
> CASDE is intended **exclusively** for:
>
> - Bug bounty programs with explicit scope (HackerOne, Bugcrowd, etc.)
> - Penetration testing engagements with a signed contract / defined scope
> - Your own infrastructure or lab environments (CTF, homelab)
>
> Continuous attack-surface monitoring **without authorization** may violate
> local laws and the target's Terms of Service. The author is not responsible
> for misuse. **Always respect scope.**

---

## Table of Contents

- [Why CASDE?](#why-casde)
- [Features](#features)
- [Modules](#modules)
- [Requirements](#requirements)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [CLI Reference](#cli-reference)
- [Workflows](#workflows)
- [Architecture](#architecture)
- [Design Decisions](#design-decisions)
- [Database Schema](#database-schema)
- [Testing](#testing)
- [Roadmap](#roadmap)
- [Contributing](#contributing)
- [License](#license)

---

## Why CASDE?

Most recon tooling (subfinder, httpx, nuclei, ffuf) is **stateless**: it answers
*"what does the target look like right now?"*.

CASDE answers a different question:

> **"What changed about this target since I last looked, and is it relevant?"**

Instead of point-in-time scans, it builds a **versioned history** of a target —
like a `git` repository for recon. Each monitoring run is a **commit**; diffs
surface new assets, removed assets, and content changes that actually matter.
On top of that foundation, it chains the rest of the recon workflow:

1. **Watch** the surface (state tracking, like git)
2. **Mine** it (JS AST → endpoints, routes, secrets)
3. **Prioritize** it (semantic parameter scoring)
4. **Attack** it (feedback-guided fuzzing)
5. **Correlate** it (out-of-band callbacks)
6. **Remember** it (findings database for pattern analysis)

---

## Features

- **Git-style state tracking** — commits, parent links, diff summaries, idempotent
  runs. No changes → same commit hash, just like git.
- **Real JS AST parsing** — endpoints from `fetch`/`axios`/`XHR` (including
  template literals and string concatenation), router configs, and
  entropy-filtered secrets with **truncated previews** (never full values).
- **Semantic parameter scoring** — IDOR/SSRF/LFI/auth-aware ranking with
  source provenance (JS, Wayback, GAU, user).
- **Feedback-guided fuzzer** — a simple genetic algorithm mutates the best
  payloads across generations; anomaly scoring detects echo/reflection,
  response size deltas, 5xx errors, and `SLEEP()`-style time anomalies.
- **OOB correlator** — self-hosted mini-Collaborator listener plus an
  Interactsh client; callbacks are token-correlated (subdomain, path, or
  query) and persisted.
- **Findings database** — every module writes into a shared, deduplicated
  store with severity, status, category, payload, and signals; triage with
  one command.
- **No reinvented wheels** — subfinder/amass/nuclei/ffuf are first-class
  subprocess citizens; CASDE orchestrates and correlates, it does not
  re-scan from scratch.
- **Pure-Go SQLite** (`modernc.org/sqlite`) — no CGO, static cross-compiles,
  and a `Store` interface that ports cleanly to Postgres for teams.

---

## Modules

| # | Module | Status | Description |
|---|--------|--------|-------------|
| 1 | **State Tracker** | ✅ MVP | Snapshot + diff + versioning (like git) |
| 2 | **JS AST Extractor** | ✅ MVP | Real AST parsing (esprima) for endpoints/routes/secrets |
| 3 | **Parameter Scoring Engine** | ✅ MVP | Semantic risk scoring (IDOR/SSRF/LFI/auth) |
| 4 | **Feedback-Guided Fuzzer** | ✅ MVP | Genetic mutation + anomaly-driven scoring |
| 5 | **OOB Correlator** | ✅ MVP | Local listener / Interactsh callback correlation |
| 6 | **Findings Database** | ✅ MVP | Per-target pattern analysis over time |

---

## Requirements

| Tool | Version | Used by |
|------|---------|---------|
| Go | 1.22+ | Core (all modules) |
| Node.js | 18+ | Module 2 (AST parsing) |
| Python | 3.9+ | Module 3 (stdlib only, no deps) |
| SQLite CLI | optional | Database inspection |

### Module 2 dependency (esprima)

```bash
npm install -g esprima
# or via make
make jsast-deps
```

---

## Installation

```bash
git clone git@github.com:fxlpz/casde.git
cd casde
make build          # or: go build -o bin/casde ./cmd/state-tracker
./bin/casde --help
```

The binary is self-contained: the SQLite schema is embedded via `go:embed`,
so it works from any working directory. The Python scorer (module 3) and the
Node parser (module 2) are invoked by path — run from the repo root, or set
`CASDE_TOOLS` / `CASDE_PYTHON` to point elsewhere.

---

## Quick Start

```bash
# 1. Monitor a target — first run creates the DB, everything is "added"
./bin/casde state --target target.com --urls urls.txt --db casde.db

# 2. Run again later — only meaningful changes are reported
./bin/casde state --target target.com --urls urls.txt --db casde.db
# → 2 novo(s), 0 removido(s), 1 alterado(s)

# 3. Extract intelligence from a JS bundle
./bin/casde jsast --url https://target.com/js/app.js --db casde.db

# 4. Score parameters found in step 3
./bin/casde params --params "id,url,file,debug,callback,user_id"

# 5. Fuzz the highest-scoring parameter
./bin/casde fuzz --target "https://target.com/proxy?url={{{FUZZ}}}" --db casde.db

# 6. Correlate blind bugs
./bin/casde oob listen --addr :8081 --domain probe.local --db casde.db

# 7. Review everything
./bin/casde findings list --db casde.db
```

`urls.txt` format: one URL per line, `#` comments allowed.

---

## CLI Reference

### Global

```bash
casde <module> [flags]
```

| Command | Module | Purpose |
|---------|--------|---------|
| `state` | 1 | Run the state tracker (snapshot + diff + commit) |
| `targets` | 1 | List monitored targets |
| `history` | 1 | Show commit history for a target |
| `jsast` | 2 | Extract endpoints/routes/secrets from JS |
| `params` | 3 | Score parameters by semantic risk |
| `fuzz` | 4 | Feedback-guided fuzzing |
| `oob` | 5 | Start the OOB callback listener |
| `findings` | 6 | List / triage findings |

### `casde state`

| Flag | Default | Description |
|------|---------|-------------|
| `--target` | *(required)* | Target name (e.g. `target.com`) |
| `--urls` | *(required)* | File with one URL per line |
| `--db` | `casde.db` | SQLite database path |
| `--concurrency` | `10` | Parallel workers |
| `--timeout` | `60` | Overall timeout in seconds |

### `casde jsast`

| Flag | Default | Description |
|------|---------|-------------|
| `--url` | — | Remote JS bundle to download and analyze |
| `--file` | — | Local JS file to analyze (mutually exclusive with `--url`) |
| `--out` | — | Directory to save full JSON results |
| `--db` | — | Register endpoints/secrets as findings |
| `--timeout` | `30` | Download timeout in seconds |

### `casde params`

| Flag | Default | Description |
|------|---------|-------------|
| `--params` | — | Comma-separated list (e.g. `id,url,file,debug`) |
| `--file` | — | JSON file with `{"params":[...],"sources":{...}}` |
| `--sources` | `js` | Source labels (e.g. `js,wayback,gau`) |

### `casde fuzz`

| Flag | Default | Description |
|------|---------|-------------|
| `--target` | *(required)* | URL with `{{{FUZZ}}}` placeholder |
| `--param` | — | Parameter name (when target has no placeholder) |
| `--method` | `GET` | `GET` or `POST` |
| `--data` | — | POST body with `{{{FUZZ}}}` |
| `--headers` | — | Extra headers, `|`-separated (`X-Token: abc\|X-Debug: 1`) |
| `--concurrency` | `8` | Parallel workers |
| `--generations` | `4` | Genetic generations |
| `--population` | `24` | Payloads per generation |
| `--db` | — | Persist findings to the findings DB |
| `--json` | `false` | Full JSON output |

### `casde oob`

```bash
casde oob listen [--addr :8080] [--domain probe.local] [--db casde.db]
```

| Flag | Default | Description |
|------|---------|-------------|
| `--addr` | `:8080` | Listener address (use `:8081` if Burp owns 8080) |
| `--domain` | `probe.local` | Base domain; `token.<domain>` = correlation |
| `--db` | — | Persist received callbacks |

### `casde findings`

```bash
casde findings list [--target T] [--status S] [--db casde.db]
casde findings set --id N --status S --severity V [--db casde.db]
```

| Flag | Values |
|------|--------|
| `--status` | `open`, `confirmed`, `false_positive`, `duplicate`, `out_of_scope` |
| `--severity` | `critical`, `high`, `medium`, `low`, `info` |

---

## Workflows

### Bug bounty pipeline

```bash
# 1. Surface discovery (external tools feed CASDE)
subfinder -d target.com -silent | httpx -silent | cut -d/ -f1-3 | sort -u > hosts.txt

# 2. Collect JS bundles
gau target.com --subs | grep -E '\.js' | sort -u > js_urls.txt

# 3. Mine bundles → endpoints + secrets (persisted to findings)
while read u; do
  ./bin/casde jsast --url "$u" --db casde.db
done < js_urls.txt

# 4. Score parameters found in JS + Wayback
./bin/casde params --file params.json

# 5. Fuzz the hot parameters (SSRF, LFI, SQLi...) with OOB hooks
./bin/casde oob listen --addr :8081 --domain probe.local --db casde.db &
./bin/casde fuzz --target "https://target.com/api/fetch?url={{{FUZZ}}}" \
  --db casde.db --generations 5 --population 32

# 6. Triage everything
./bin/casde findings list --status open --db casde.db
```

### Continuous monitoring (cron)

```cron
# Every 6 hours, snapshot the surface and log changes
0 */6 * * * cd ~/CASDE && ./bin/casde state --target target.com --urls urls.txt --db casde.db >> casde.log 2>&1
```

Recon changes in the diff (`casde history`) feed the JS/params/fuzz pipeline
only when something actually changed — no wasted scans.

### Lab / CTF

```bash
# Point it at your local lab (DVWA, juice-shop, HTB/THM box)
./bin/casde state --target lab.local --urls urls.txt --db lab.db
./bin/casde fuzz --target "http://127.0.0.1:8080/vulnerabilities/sqli/?id={{{FUZZ}}}" --db lab.db
```

---

## Architecture

```
cmd/
└── state-tracker/          # unified CLI (state/targets/history/jsast/params/fuzz/oob/findings)
internal/
├── store/                  # persistence boundary (interface)
│   ├── store.go            #   Store interface + Finding/OobCallback models
│   ├── sqlite.go           #   SQLite implementation (modernc.org/sqlite, no CGO)
│   ├── schema.sql          #   full schema (embedded via go:embed)
│   └── embed.go            #   go:embed wiring
├── fetch/                  # HTTP state collection + header normalization
├── diff/                   # git-like diffing + commit hashing
├── tracker/                # orchestration (parallel worker pool)
├── fuzz/                   # feedback-guided fuzzer (genetic mutation + anomaly scoring)
└── oob/                    # OOB correlator (local listener + Interactsh client)
python/
└── param_scorer.py         # Module 3: semantic parameter scoring (stdlib only)
tools/
└── js_ast_extract.js       # Module 2: esprima AST walker (endpoints/routes/secrets)
```

**Stack:** Go core (concurrency) · Python analysis layer (semantic scoring) ·
Node AST parsing (esprima) · SQLite local / Postgres for teams · TUI (planned).

---

## Design Decisions

1. **Header normalization.** Volatile headers (`Date`, `Set-Cookie`, `Cf-Ray`,
   `X-Trace-Id`) are excluded from diffs, so you see semantic changes instead
   of CDN noise. Editable in `internal/fetch/fetch.go`.

2. **Network failure ≠ removal.** An asset that fails to respond becomes a
   snapshot with status 0 ("unobserved") but is **not** reported as removed.
   Prevents false positives against flaky targets.

3. **Idempotent runs, git-style commits.** No changes → same commit hash and an
   empty diff. An "empty" commit is still recorded, proving monitoring
   continuity at that timestamp.

4. **Controlled concurrency.** Worker pools (default 10) keep the load polite
   on both the target and the database; SQLite runs in WAL mode.

5. **Atomic persistence.** Snapshots + commit are written in a single SQLite
   transaction. A failed run leaves no partial state.

6. **Feedback over brute force.** The fuzzer keeps a population of payloads,
   scores responses for anomalies, and mutates the best performers across
   generations — a simple genetic algorithm instead of blind wordlists.

7. **Secrets stay truncated.** The JS AST extractor never prints full secret
   values — only length, entropy and a short preview.

8. **Pure-Go SQLite.** `modernc.org/sqlite` avoids CGO, keeping cross-compiles
   static and builds reproducible.

9. **One findings store.** Every module writes to the same deduplicated
   `findings` table, so per-target pattern analysis is a single query.

---

## Database Schema

| Table | Purpose |
|-------|---------|
| `targets` | monitored target (unique name) |
| `assets` | stable URL (`target_id`, `url`, `method`, `first/last_seen`) |
| `commits` | a run (`commit_hash`, `parent_id`, `summary` JSON, `created_at`) |
| `snapshots` | asset state per commit (`status`, `body_hash`, `headers`) |
| `findings` | every finding (module, category, severity, status, payload, signals) |
| `oob_callbacks` | out-of-band callbacks received (token, source, protocol, UA) |
| `v_current_state` | view: latest state of every asset |

`commits.summary` stores the diff as JSON (new/removed/changed), so history can
be reconstructed without recomputing. `findings` is denormalized per target for
fast pattern queries and uses `UNIQUE` upserts to avoid duplicate noise.

Inspect with the SQLite CLI:

```bash
sqlite3 casde.db "SELECT name FROM sqlite_master WHERE type='table';"
sqlite3 casde.db "SELECT status, count(*) FROM findings GROUP BY status;"
```

---

## Testing

```bash
make test    # or: go test ./...
make vet     # or: go vet ./...
```

Current coverage: 9 tests across `internal/fuzz` (mutation, crossover, echo /
size / time anomaly detection, context cancellation) and `internal/store`
(schema creation, finding dedup + triage, OOB callback persistence).

---

## Roadmap

- [ ] Asset discovery (subfinder/amass) feeding the tracker automatically
- [ ] Per-field header diffs + TLS certificate fingerprinting
- [ ] Compressed body diffs for content analysis
- [ ] `diff --from <commit> --to <commit>` CLI
- [ ] Interactsh polling loop (DNS callbacks) in the OOB correlator
- [ ] TUI (Bubble Tea / Textual)
- [ ] Postgres backend for team use
- [ ] CI pipeline (build, vet, test) via GitHub Actions

---

## Contributing

PRs are welcome. Please keep the scope of each PR focused, add tests for new
logic, and make sure the legal disclaimer stays visible in every new module.

---

## License

MIT — see [LICENSE](LICENSE).
