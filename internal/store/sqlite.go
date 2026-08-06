package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"time"

	_ "modernc.org/sqlite" // driver SQLite puro-Go (sem CGO, fácil de compilar/cross-compile)
)

// SQLiteStore implementa Store em SQLite.
//
// Decisão: modernc.org/sqlite (registo.sqlite namespace) em vez de mattn
// (CGO) para permitir cross-compile estático e build sem toolchain C.
// Para Postgres, bastaria criar um PostgresStore que implementa a mesma
// interface e trocar no main.
type SQLiteStore struct {
	db *sql.DB
}

// NewSQLiteStore abre (e cria se necessário) o arquivo de banco.
func NewSQLiteStore(path string) (*SQLiteStore, error) {
	// Garantir que o diretório pai exista.
	if dir := dirOf(path); dir != "" {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return nil, fmt.Errorf("criar diretório do banco: %w", err)
		}
	}
	// _pragma=foreign_keys(1) e WAL via DSN (garante por conexão).
	dsn := "file:" + path + "?_pragma=foreign_keys(1)&_pragma=journal_mode(WAL)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("abrir sqlite: %w", err)
	}
	// Pool pequeno: SQLite em WAL suporta multi-ler mas gravação é serializada.
	db.SetMaxOpenConns(1)
	return &SQLiteStore{db: db}, nil
}

func (s *SQLiteStore) Close() error { return s.db.Close() }

func dirOf(p string) string {
	for i := len(p) - 1; i >= 0; i-- {
		if p[i] == '/' {
			return p[:i]
		}
	}
	return ""
}

func now() string { return time.Now().UTC().Format(time.RFC3339) }

// Init aplica o schema. Como lidamos com multi-statement, lemos o arquivo
// schema.sql e executamos statement por statement (o driver modernc não
// executa múltiplos statements num único Exec fácil com comentários).
func (s *SQLiteStore) Init(ctx context.Context) error {
	schema, err := os.ReadFile("schema.sql")
	if err != nil {
		// Fallback: também aceita schema embutido abaixo (defesa).
		_, err = s.db.ExecContext(ctx, builtinSchema)
		return err
	}
	// modernc aceita múltiplos statements separados por ; quando não há
	// parâmetros. Comentários SQL (--) são aceitos.
	if _, err := s.db.ExecContext(ctx, string(schema)); err != nil {
		return fmt.Errorf("aplicar schema: %w", err)
	}
	return nil
}

func (s *SQLiteStore) Ping(ctx context.Context) error { return s.db.PingContext(ctx) }

func (s *SQLiteStore) GetOrCreateTarget(ctx context.Context, name string) (int64, error) {
	var id int64
	err := s.db.QueryRowContext(ctx,
		"INSERT INTO targets(name) VALUES(?) ON CONFLICT(name) DO UPDATE SET name=excluded.name RETURNING id",
		name).Scan(&id)
	if err != nil {
		return 0, err
	}
	return id, nil
}

func (s *SQLiteStore) ListTargets(ctx context.Context) ([]string, error) {
	rows, err := s.db.QueryContext(ctx, "SELECT name FROM targets ORDER BY name")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			return nil, err
		}
		out = append(out, n)
	}
	return out, rows.Err()
}

func (s *SQLiteStore) UpsertAsset(ctx context.Context, targetID int64, url, method string) (int64, error) {
	var id int64
	err := s.db.QueryRowContext(ctx, `
		INSERT INTO assets(target_id, url, method, first_seen, last_seen)
		VALUES(?, ?, ?, ?, ?)
		ON CONFLICT(target_id, url, method) DO UPDATE SET last_seen=excluded.last_seen
		RETURNING id`,
		targetID, url, method, now(), now()).Scan(&id)
	if err != nil {
		return 0, err
	}
	return id, nil
}

func (s *SQLiteStore) ListAssetsByTarget(ctx context.Context, targetID int64) ([]Asset, error) {
	rows, err := s.db.QueryContext(ctx,
		"SELECT id, target_id, url, method, first_seen, last_seen FROM assets WHERE target_id=? ORDER BY url",
		targetID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Asset
	for rows.Next() {
		var a Asset
		var fs, ls string
		if err := rows.Scan(&a.ID, &a.TargetID, &a.URL, &a.Method, &fs, &ls); err != nil {
			return nil, err
		}
		a.FirstSeen, _ = time.Parse(time.RFC3339, fs)
		a.LastSeen, _ = time.Parse(time.RFC3339, ls)
		out = append(out, a)
	}
	return out, rows.Err()
}

// SaveExecution grava snapshots + commit numa transação atômica.
// parentID == nil => primeiro commit do target.
func (s *SQLiteStore) SaveExecution(ctx context.Context, targetID int64, snaps []Snapshot,
	summary DiffSummary, parentID *int64) (*Commit, error) {

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	summaryJSON, _ := json.Marshal(summary)

	var parent any
	if parentID != nil {
		parent = *parentID
	}
	res, err := tx.ExecContext(ctx, `
		INSERT INTO commits(target_id, commit_hash, parent_id, summary, created_at)
		VALUES(?, ?, ?, ?, ?)`,
		targetID, summary.CommitHash, parent, string(summaryJSON), now())
	if err != nil {
		return nil, fmt.Errorf("inserir commit: %w", err)
	}
	commitID, _ := res.LastInsertId()

	for i := range snaps {
		snaps[i].CommitID = commitID
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO snapshots(asset_id, commit_id, status_code, body_hash, body_size, headers_json, captured_at)
			VALUES(?, ?, ?, ?, ?, ?, ?)`,
			snaps[i].AssetID, commitID, snaps[i].StatusCode,
			snaps[i].BodyHash, snaps[i].BodySize, snaps[i].HeadersJSON, now()); err != nil {
			return nil, fmt.Errorf("inserir snapshot %s: %w", snaps[i].AssetID, err)
		}
	}

	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return &Commit{ID: commitID, TargetID: targetID, CommitHash: summary.CommitHash,
		ParentID: parentID, Summary: string(summaryJSON), CreatedAt: time.Now().UTC()}, nil
}

func (s *SQLiteStore) GetLatestCommit(ctx context.Context, targetID int64) (*Commit, error) {
	var c Commit
	var parent sql.NullInt64
	var summary sql.NullString
	var created string
	err := s.db.QueryRowContext(ctx,
		"SELECT id, target_id, commit_hash, parent_id, summary, created_at FROM commits WHERE target_id=? ORDER BY id DESC LIMIT 1",
		targetID).Scan(&c.ID, &c.TargetID, &c.CommitHash, &parent, &summary, &created)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if parent.Valid {
		p := parent.Int64
		c.ParentID = &p
	}
	if summary.Valid {
		c.Summary = summary.String
	}
	c.CreatedAt = parseTime(created)
	return &c, nil
}

func (s *SQLiteStore) GetCommitByID(ctx context.Context, id int64) (*Commit, error) {
	var c Commit
	var parent sql.NullInt64
	var summary sql.NullString
	var created string
	err := s.db.QueryRowContext(ctx,
		"SELECT id, target_id, commit_hash, parent_id, summary, created_at FROM commits WHERE id=?",
		id).Scan(&c.ID, &c.TargetID, &c.CommitHash, &parent, &summary, &created)
	if err != nil {
		return nil, err
	}
	if parent.Valid {
		p := parent.Int64
		c.ParentID = &p
	}
	if summary.Valid {
		c.Summary = summary.String
	}
	c.CreatedAt = parseTime(created)
	return &c, nil
}

// parseTime converte os timestamps do SQLite (formato datetime('now') = "YYYY-MM-DD HH:MM:SS" em UTC) para time.Time.
func parseTime(s string) time.Time {
	if t, err := time.Parse("2006-01-02 15:04:05", s); err == nil {
		return t.UTC()
	}
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t.UTC()
	}
	return time.Time{}
}

func (s *SQLiteStore) GetSnapshotsForCommit(ctx context.Context, commitID int64) ([]Snapshot, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT s.id, s.asset_id, s.commit_id, s.status_code, s.body_hash, s.body_size, s.headers_json, s.captured_at
		FROM snapshots s WHERE s.commit_id=?`, commitID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Snapshot
	for rows.Next() {
		var sn Snapshot
		var captured string
		if err := rows.Scan(&sn.ID, &sn.AssetID, &sn.CommitID, &sn.StatusCode,
			&sn.BodyHash, &sn.BodySize, &sn.HeadersJSON, &captured); err != nil {
			return nil, err
		}
		sn.CapturedAt = parseTime(captured)
		out = append(out, sn)
	}
	return out, rows.Err()
}

// builtinSchema fallback: mesmo schema (para uso sem ler do disco).
const builtinSchema = `
CREATE TABLE IF NOT EXISTS targets (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL UNIQUE, created_at TEXT NOT NULL DEFAULT (datetime('now')));
CREATE TABLE IF NOT EXISTS assets (id INTEGER PRIMARY KEY AUTOINCREMENT, target_id INTEGER NOT NULL REFERENCES targets(id) ON DELETE CASCADE, url TEXT NOT NULL, method TEXT NOT NULL DEFAULT 'GET', first_seen TEXT NOT NULL DEFAULT (datetime('now')), last_seen TEXT NOT NULL DEFAULT (datetime('now')), UNIQUE(target_id, url, method));
CREATE TABLE IF NOT EXISTS commits (id INTEGER PRIMARY KEY AUTOINCREMENT, target_id INTEGER NOT NULL REFERENCES targets(id) ON DELETE CASCADE, commit_hash TEXT NOT NULL, parent_id INTEGER REFERENCES commits(id), summary TEXT, created_at TEXT NOT NULL DEFAULT (datetime('now')));
CREATE TABLE IF NOT EXISTS snapshots (id INTEGER PRIMARY KEY AUTOINCREMENT, asset_id INTEGER NOT NULL REFERENCES assets(id) ON DELETE CASCADE, commit_id INTEGER NOT NULL REFERENCES commits(id) ON DELETE CASCADE, status_code INTEGER, body_hash TEXT NOT NULL, body_size INTEGER NOT NULL DEFAULT 0, headers_json TEXT NOT NULL, captured_at TEXT NOT NULL DEFAULT (datetime('now')), UNIQUE(asset_id, commit_id));
CREATE INDEX IF NOT EXISTS idx_snapshots_asset_commit ON snapshots(asset_id, commit_id);
CREATE INDEX IF NOT EXISTS idx_commits_target ON commits(target_id, created_at DESC);
`