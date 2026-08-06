-- ============================================================================
-- CASDE - State Tracker schema (SQLite)
-- ----------------------------------------------------------------------------
-- Modelo de dados inspirado em git: cada execução do tracker produz um
-- "commit" que referencia snapshots de assets. Um asset é uma URL estável
-- (ex: https://api.target.com). Cada snapshot captura o estado observado
-- daquele asset num dado momento (headers + hash do body).
--
-- Abstração: todas as queries do módulo store usam apenas este schema.
-- Para Postgres em time, basta trocar a camada de conexão e adaptar
-- tipos (TEXT->JSONB etc), mantendo a mesma semântica de commits/snapshots.
-- ============================================================================

PRAGMA journal_mode = WAL;
PRAGMA foreign_keys = ON;

-- Alvo de recon (programa, empresa, domínio raiz). Um "repositório".
CREATE TABLE IF NOT EXISTS targets (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    name        TEXT NOT NULL UNIQUE,          -- ex: "target.com"
    created_at  TEXT NOT NULL DEFAULT (datetime('now'))
);

-- Asset: uma URL estável monitorada dentro de um target.
CREATE TABLE IF NOT EXISTS assets (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    target_id   INTEGER NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
    url         TEXT NOT NULL,                 -- URL canônica do asset
    method      TEXT NOT NULL DEFAULT 'GET',
    first_seen  TEXT NOT NULL DEFAULT (datetime('now')),
    last_seen   TEXT NOT NULL DEFAULT (datetime('now')),
    UNIQUE (target_id, url, method)
);
CREATE INDEX IF NOT EXISTS idx_assets_target ON assets(target_id);

-- Commit: uma execução do tracker. `summary` guarda o diff estruturado em JSON
-- (novos assets, removidos, alterados, inalterados) para consulta rápida.
-- Definido antes de snapshots porque snapshots referencia commits.
CREATE TABLE IF NOT EXISTS commits (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    target_id   INTEGER NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
    commit_hash TEXT NOT NULL,                 -- SHA-256 do estado agregado
    parent_id   INTEGER REFERENCES commits(id),-- commit anterior (para diff)
    summary     TEXT,                          -- JSON do diff
    created_at  TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_commits_target ON commits(target_id, created_at DESC);

-- Snapshot: estado observado de um asset numa execução.
CREATE TABLE IF NOT EXISTS snapshots (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    asset_id     INTEGER NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    commit_id    INTEGER NOT NULL REFERENCES commits(id) ON DELETE CASCADE,
    status_code  INTEGER,                      -- 200, 301, 403, ...
    body_hash    TEXT NOT NULL,                -- SHA-256 hex do body ("" se vazio)
    body_size    INTEGER NOT NULL DEFAULT 0,
    headers_json TEXT NOT NULL,                -- JSON: header -> valor (normalizado)
    captured_at  TEXT NOT NULL DEFAULT (datetime('now')),
    UNIQUE (asset_id, commit_id)
);
CREATE INDEX IF NOT EXISTS idx_snapshots_asset_commit ON snapshots(asset_id, commit_id);

-- ============================================================================
-- Views auxiliares (consultas comuns)
-- ============================================================================

-- Último snapshot de cada asset (estado "atual" do alvo).
CREATE VIEW IF NOT EXISTS v_current_state AS
SELECT a.id AS asset_id, a.url, a.method, s.status_code, s.body_hash,
       s.body_size, s.headers_json, s.captured_at
FROM assets a
JOIN snapshots s ON s.asset_id = a.id
JOIN commits c ON c.id = s.commit_id
WHERE c.id = (SELECT MAX(id) FROM commits WHERE target_id = a.target_id);

-- ============================================================================
-- Módulo 6: Findings Database
-- ============================================================================
-- Registra TODO achado (inclusive descartados/false positive) com metadados
-- suficientes para análise de padrão por alvo ao longo do tempo:
-- qual módulo gerou, qual parâmetro, qual payload, sinais, severidade.
-- A coluna `raw` guarda o JSON completo do achado (payload, resposta, sinais).

CREATE TABLE IF NOT EXISTS findings (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    target_id       INTEGER REFERENCES targets(id) ON DELETE CASCADE,
    target_name     TEXT NOT NULL,               -- denormalizado p/ consultas rápidas
    url             TEXT NOT NULL,               -- URL/endpoint onde o achado ocorreu
    module          TEXT NOT NULL,               -- fuzz | jsast | params | oob | state
    category        TEXT NOT NULL,               -- sqli | xss | ssrf | idor | lfi | oob | info | other
    severity        TEXT NOT NULL DEFAULT 'info',-- critical | high | medium | low | info
    status          TEXT NOT NULL DEFAULT 'open',-- open | confirmed | false_positive | duplicate | out_of_scope
    param           TEXT,                        -- parâmetro/asset envolvido
    payload         TEXT,                        -- payload utilizado (se aplicável)
    signal          TEXT,                        -- resumo do sinal (ex: "echo,status_5xx")
    confidence      REAL DEFAULT 0.5,            -- 0..1 confiança
    raw             TEXT,                        -- JSON completo do achado
    first_seen      TEXT NOT NULL DEFAULT (datetime('now')),
    last_seen       TEXT NOT NULL DEFAULT (datetime('now')),
    UNIQUE (target_name, url, module, category, param, payload)
);
CREATE INDEX IF NOT EXISTS idx_findings_target ON findings(target_name, first_seen DESC);
CREATE INDEX IF NOT EXISTS idx_findings_status ON findings(status);

-- Callbacks OOB recebidos (módulo 5), correlacionados ou não.
CREATE TABLE IF NOT EXISTS oob_callbacks (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    token       TEXT NOT NULL,                   -- token de correlação do payload
    source      TEXT NOT NULL,                   -- local | interactsh
    protocol    TEXT NOT NULL DEFAULT 'http',    -- http | dns
    remote_ip   TEXT,
    user_agent  TEXT,
    path        TEXT,
    headers     TEXT,
    body        TEXT,
    raw         TEXT,
    received_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_oob_token ON oob_callbacks(token);
