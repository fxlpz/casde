# CASDE - Continuous Attack Surface & Diff Engine

> ⚠️ **USO RESPONSÁVEL (AVISO LEGAL)**
> Esta ferramenta é destinada **exclusivamente** a:
> - Programas de Bug Bounty com escopo autorizado (HackerOne, Bugcrowd, etc.)
> - Engajamentos de pentest com contrato/escopo definido por escrito
> - Ambientes próprios ou de laboratório (CTF, homelab, infraestrutura sua)
>
> Monitoramento contínuo de superfície de ataque **sem autorização** pode violar
> leis locais e os termos de serviço do alvo. O autor não se responsabiliza pelo
> uso indevido. Respeite sempre o escopo.

## O que é

CASDE sai do modelo "scanner pontual" e entra no modelo "sistema que aprende o
comportamento de um alvo ao longo do tempo e alerta sobre mudanças relevantes de
superfície de ataque". É um "git" de recon.

Stack planejada:
- **Go**: core/orquestração (concorrência para recon distribuído)
- **Python**: análise/scoring (parsing AST, heurísticas, scoring semântico)
- **SQLite** (local) → **Postgres** (equipe, abstração pronta)
- **TUI** (Textual/Bubble Tea) para operação sem browser

## Módulos (ordem de prioridade)

| # | Módulo | Status |
|---|--------|--------|
| 1 | **State Tracker** (snapshot + diff + versionamento tipo git) | ✅ MVP funcional |
| 2 | JS AST Extractor (fetch/axios/XHR, rotas, secrets por entropia) | ⏳ próximo |
| 3 | Parameter Scoring Engine (JS + Wayback + GAU, scoring semântico) | ⏳ |
| 4 | Feedback-Guided Fuzzer (mutação por anomalias de resposta) | ⏳ |
| 5 | OOB Correlator (Interactsh / Collaborator) | ⏳ |
| 6 | Findings Database (histórico de achados por alvo) | ⏳ |

## Estado atual: State Tracker (módulo 1)

Faz snapshot de assets (status + headers normalizados + hash SHA-256 do body),
compara com o snapshot anterior salvo em SQLite e reporta o diff em JSON
estruturado, versionando cada execução como um "commit".

### Estrutura

```
CASDE/
├── cmd/state-tracker/main.go     # CLI (run, targets, history)
├── internal/
│   ├── store/store.go            # interface Store (SQLite hoje, Postgres depois)
│   ├── store/sqlite.go           # implementação SQLite
│   ├── fetch/fetch.go            # coleta de estado HTTP + normalização headers
│   ├── diff/diff.go              # lógica de diff tipo git + commit hash
│   └── tracker/tracker.go        # orquestração (worker pool paralelo)
├── schema.sql                    # schema completo (targets/assets/snapshots/commits/view)
├── test_server.py                # servidor local para testes de diff
├── test_urls.txt                 # lista de assets de exemplo
└── bin/state-tracker             # binário compilado
```

### Como usar

```bash
# build
cd /home/fxlpz/Projetos/CASDE
go build -o bin/state-tracker ./cmd/state-tracker

# 1ª execução (cria o banco, tudo vira "added")
./bin/state-tracker run --target target.com --urls urls.txt --db casde.db

# execuções seguintes (diferenciam added/removed/changed)
./bin/state-tracker run --target target.com --urls urls.txt --db casde.db

# listar alvos e ver histórico de commits
./bin/state-tracker targets --db casde.db
./bin/state-tracker history --target target.com --db casde.db
```

Flags: `--target` (obrigatório), `--urls` (arquivo, obrigatório), `--db`
(default `casde.db`), `--concurrency` (default 10), `--timeout` (default 60s).

### Design decisions (deliberadas)

1. **Normalização de headers**: `Date`, `Set-Cookie`, `Cf-Ray`, `X-Trace-Id` etc.
   são ignorados no diff (voláteis). Captura mudanças semânticas, não ruído de CDN.
   → veja `headersVolateis` em `internal/fetch/fetch.go` (editável).

2. **Falha de rede ≠ removido**: um asset com erro de rede vira snapshot status 0
   (não observado), mas **não** conta como `removed` — evita falso-positivo em
   alvo instável. Decisão deliberada.

3. **Idempotência**: rodar duas vezes sem mudanças produz diff vazio e o **mesmo
   commit hash** (como git). Um "commit vazio" ainda é salvo para provar
   continuidade do monitoramento naquela hora.

4. **Concorrência controlada**: worker pool (default 10) limita a carga no alvo
   (polidez) e no banco; SQLite com `journal_mode=WAL` para gravação segura.

5. **Atomicidade**: snapshots + commit são gravados numa transação SQLite única.

### Schema (resumo)

- `targets` — alvo monitorado (nome único)
- `assets` — URL estável (target_id, url, method, first/last_seen)
- `commits` — execução (target_id, commit_hash, parent_id, summary JSON, created_at)
- `snapshots` — estado do asset num commit (asset_id, commit_id, status, hash, headers)
- `v_current_state` — view com o estado mais recente de cada asset

Detalhe: `commits.summary` guarda o diff como JSON (novos/removidos/alterados),
permitindo reconstituir a história sem recomputar.

### Limitações e próximos passos

**Limitações (v0):**
- Não detecta "removido" se a URL simplesmente saiu da lista monitorada sem
  aparecer no estado atual (módulo de asset discovery ainda não existe; remove
  se você editar a lista, mas via diff correto).
- Headers granular: compara JSON inteiro (heads), mas não sinaliza diffs
  específicos de header campo a campo (ex.: "só `server` mudou"). Melhoria:
  diff de headers por campo.
- Sem cron/TUI ainda; CLI pura.

**Próximos:**
- [ ] Módulo 2: JS AST Scanner (via node/@babel ou tree-sitter subprocess)
- [ ] asset discovery (subfinder/amass) alimentando o tracker automaticamente
- [ ] diff de headers campo a campo + certs (TLS cert fingerprint)
- [ ] armazenar body diffs gzipped para análise de conteúdo
- [ ] CLI `diff --from <commit> --to <commit>`