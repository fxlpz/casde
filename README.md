<div align="center">

# CASDE

**Continuous Attack Surface & Diff Engine**

A "git" for recon. Moves away from point-in-time scanning toward a system that
**learns a target's attack surface over time** and alerts on meaningful changes.

`Go` · `Python` · `Node` · `SQLite`

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

## Overview

Most recon tooling (subfinder, httpx, nuclei, ffuf) is **stateless**: it answers
"what does the target look like right now?". CASDE answers a different question:

> "What changed about this target since I last looked, and is it relevant?"

It keeps a versioned history of a target's attack surface, like a `git`
repository for recon. Each run is a **commit**; diffs surface new assets,
removed assets, and content changes that actually matter. On top of that, it
extracts intelligence from JS bundles, scores parameters by semantic risk, runs
a feedback-guided fuzzer, correlates out-of-band callbacks, and stores every
finding for per-target pattern analysis over time.

## Modules

| # | Module | Status |
|---|--------|--------|
| 1 | **State Tracker** — snapshot + diff + versioning (like git) | ✅ MVP |
| 2 | **JS AST Extractor** — real AST parsing for endpoints/routes/secrets | ✅ MVP |
| 3 | **Parameter Scoring Engine** — semantic risk scoring (IDOR/SSRF/LFI) | ✅ MVP |
| 4 | **Feedback-Guided Fuzzer** — response-anomaly-driven mutation | ✅ MVP |
| 5 | **OOB Correlator** — local listener / Interactsh callback correlation | ✅ MVP |
| 6 | **Findings Database** — per-target pattern analysis over time | ✅ MVP |

## Requirements

- **Go 1.22+** (core)
- **Node 18+** + `esprima` for Module 2: `npm install -g esprima`
- **Python 3.9+** for Module 3 (stdlib only, no deps)
- (optional) SQLite CLI for inspection

## Build

```bash
make build
# or: go build -o bin/casde ./cmd/state-tracker
```

## Usage

```bash
casde <module> [flags]
```

### Module 1: State Tracker

```bash
# 1st run: creates the DB; every asset is reported as "added"
casde state --target target.com --urls urls.txt --db casde.db

# subsequent runs: diffs against the previous commit
casde state --target target.com --urls urls.txt --db casde.db

# inspect targets and commit history
casde targets --db casde.db
casde history --target target.com --db casde.db
```

`urls.txt` format: one URL per line (`#` comments allowed).

### Module 2: JS AST Extractor

```bash
# analyze a remote bundle
casde jsast --url https://target.com/js/app.js

# analyze a local file, register findings in the DB
casde jsast --file bundle.js --db casde.db

# save full JSON output to a directory
casde jsast --url https://target.com/js/app.js --out js_scan/
```

Extracts fetch/axios/XHR endpoints (including template literals and string
concatenation), router configs, and **entropy-filtered secrets** — always
shown as truncated previews, never full values.

### Module 3: Parameter Scoring Engine

```bash
# score a list of parameters
casde params --params "id,url,file,debug,callback,user_id"

# score from a JSON file with source provenance
casde params --file params.json
```

`params.json` format:

```json
{
  "params": ["id", "url", "redirect"],
  "sources": {
    "id": ["js", "wayback"],
    "url": ["js"]
  }
}
```

### Module 4: Feedback-Guided Fuzzer

```bash
# GET target with {{{FUZZ}}} placeholder
casde fuzz --target "https://target.com/search?q={{{FUZZ}}}"

# POST with body placeholder, custom headers, persist findings
casde fuzz --target "https://target.com/login" --method POST \
  --data "user=admin&pass={{{FUZZ}}}" --headers "X-Token: abc" \
  --db casde.db

# tune the genetic search
casde fuzz --target "https://target.com/api?file={{{FUZZ}}}" \
  --generations 4 --population 24 --concurrency 8
```

The fuzzer keeps a population of payloads, mutates the best performers across
generations (simple genetic algorithm), and scores responses by anomaly:
reflection/echo, response size delta, 5xx status, and time anomalies
(`SLEEP()`-style delays).

### Module 5: OOB Correlator

```bash
# start the local callback listener (self-hosted mini-Collaborator)
casde oob listen --addr :8080 --domain probe.local --db casde.db
```

Inject `http://<token>.probe.local/cb` into your payloads (SSRF, blind XSS,
SSTI, template injection). Any request hitting the listener is correlated by
token (subdomain, `/cb/<token>` path, or `?token=` query) and persisted to the
findings DB. Interactsh integration is available in `internal/oob/oob.go`.

### Module 6: Findings Database

```bash
# list findings, optionally filtered
casde findings list --db casde.db
casde findings list --target target.com --status open --db casde.db

# triage: mark confirmed / false positive / duplicate / out of scope
casde findings set --id 42 --status confirmed --severity high --db casde.db
```

Modules 2, 4 and 5 automatically persist findings when `--db` is provided.

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
schema.sql                  # schema source of truth (embedded into the binary)
```

**Stack:** Go core (concurrency) · Python analysis layer (semantic scoring) ·
Node AST parsing (esprima) · SQLite local / Postgres for teams · TUI (planned).

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

6. **No reinvented wheels.** subfinder/amass/nuclei/ffuf are first-class
   subprocess citizens in the pipeline; CASDE orchestrates and correlates,
   it does not re-scan from scratch.

7. **Secrets stay truncated.** The JS AST extractor never prints full secret
   values — only length, entropy and a short preview.

8. **Pure-Go SQLite.** `modernc.org/sqlite` avoids CGO, keeping cross-compiles
   static and builds reproducible.

## Database Schema (summary)

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
fast pattern queries and supports `UNIQUE` upserts to avoid duplicate noise.

## Roadmap

- [ ] Asset discovery (subfinder/amass) feeding the tracker automatically
- [ ] Per-field header diffs + TLS certificate fingerprinting
- [ ] Compressed body diffs for content analysis
- [ ] `diff --from <commit> --to <commit>` CLI
- [ ] Interactsh polling loop (DNS callbacks) in the OOB correlator
- [ ] TUI (Bubble Tea / Textual)
- [ ] Postgres backend for team use

## License

MIT — see [LICENSE](LICENSE).
