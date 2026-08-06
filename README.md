<div align="center">

# CASDE

**Continuous Attack Surface & Diff Engine**

A "git" for recon. Moves away from point-in-time scanning toward a system that
**learns a target's attack surface over time** and alerts on meaningful changes.

`Go` · `Python` · `SQLite` · `TUI`

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
removed assets, and content changes that actually matter.

## Modules

| # | Module | Status |
|---|--------|--------|
| 1 | **State Tracker** — snapshot + diff + versioning (like git) | ✅ MVP |
| 2 | **JS AST Extractor** — real AST parsing for endpoints/routes/secrets | ⏳ planned |
| 3 | **Parameter Scoring Engine** — semantic risk scoring (IDOR/SSRF/LFI) | ⏳ planned |
| 4 | **Feedback-Guided Fuzzer** — response-anomaly-driven mutation | ⏳ planned |
| 5 | **OOB Correlator** — Interactsh / Collaborator callback correlation | ⏳ planned |
| 6 | **Findings Database** — per-target pattern analysis over time | ⏳ planned |

## Quick Start (Module 1: State Tracker)

### Requirements

- Go 1.22+
- (optional) SQLite CLI for inspection

### Build

```bash
make build
# or: go build -o bin/state-tracker ./cmd/state-tracker
```

### Usage

```bash
# 1st run: creates the DB; every asset is reported as "added"
./bin/state-tracker run --target target.com --urls urls.txt --db casde.db

# subsequent runs: diffs against the previous commit
./bin/state-tracker run --target target.com --urls urls.txt --db casde.db

# inspect targets and commit history
./bin/state-tracker targets --db casde.db
./bin/state-tracker history --target target.com --db casde.db
```

`urls.txt` format: one URL per line (`#` comments allowed).

### Example output

```json
{
  "target": "target.com",
  "changes": [
    {
      "url": "https://target.com/js/app.js",
      "kind": "changed",
      "old_status": 200,
      "new_status": 200,
      "reason": "body"
    }
  ],
  "added": [
    { "url": "https://admin.target.com", "kind": "added" }
  ],
  "removed": [
    { "url": "https://old.target.com", "kind": "removed" }
  ],
  "unchanged": 12
}
```

## Architecture

```
cmd/
└── state-tracker/          # CLI entrypoint (run / targets / history)
internal/
├── store/                  # persistence boundary (interface)
│   ├── store.go            #   Store interface (SQLite today, Postgres-ready)
│   └── sqlite.go           #   SQLite implementation
├── fetch/                  # HTTP state collection + header normalization
├── diff/                   # git-like diffing + commit hashing
└── tracker/                # orchestration (parallel worker pool)
schema.sql                  # full schema (targets/assets/commits/snapshots)
```

**Stack:** Go core (concurrency) · Python analysis layer (planned: AST parsing,
semantic scoring) · SQLite local / Postgres for teams · TUI (planned).

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

4. **Controlled concurrency.** A worker pool (default 10) keeps the load polite
   on both the target and the database; SQLite runs in WAL mode.

5. **Atomic persistence.** Snapshots + commit are written in a single SQLite
   transaction. A failed run leaves no partial state.

## Database Schema (summary)

| Table | Purpose |
|-------|---------|
| `targets` | monitored target (unique name) |
| `assets` | stable URL (`target_id`, `url`, `method`, `first/last_seen`) |
| `commits` | a run (`commit_hash`, `parent_id`, `summary` JSON, `created_at`) |
| `snapshots` | asset state per commit (`status`, `body_hash`, `headers`) |
| `v_current_state` | view: latest state of every asset |

`commits.summary` stores the diff as JSON (new/removed/changed), so history can
be reconstructed without recomputing.

## Roadmap

- [ ] **Module 2:** JS AST Extractor (`@babel/parser`/tree-sitter) for
      fetch/axios/XHR endpoints, router configs, entropy-filtered secrets
- [ ] Asset discovery (subfinder/amass) feeding the tracker automatically
- [ ] Per-field header diffs + TLS certificate fingerprinting
- [ ] Compressed body diffs for content analysis
- [ ] `diff --from <commit> --to <commit>` CLI
- [ ] TUI (Bubble Tea / Textual)
- [ ] Postgres backend for team use

## License

MIT — see [LICENSE](LICENSE).
