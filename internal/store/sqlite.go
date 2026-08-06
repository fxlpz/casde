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

// Init aplica o schema embutido (go:embed) ao banco.
// Como o driver modernc executa múltiplos statements com comentários SQL,
// basta um Exec com o schema completo.
func (s *SQLiteStore) Init(ctx context.Context) error {
	if _, err := s.db.ExecContext(ctx, schemaSQL); err != nil {
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
			return nil, fmt.Errorf("inserir snapshot asset %d: %w", snaps[i].AssetID, err)
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

// --- Módulo 6: Findings Database ------------------------------------------

func (s *SQLiteStore) UpsertFinding(ctx context.Context, f Finding) (int64, error) {
	nowTs := now()
	res, err := s.db.ExecContext(ctx, `
		INSERT INTO findings (target_name, url, module, category, severity, status,
		                      param, payload, signal, confidence, raw, first_seen, last_seen)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(target_name, url, module, category, param, payload)
		DO UPDATE SET last_seen=excluded.last_seen,
		              signal=excluded.signal,
		              confidence=excluded.confidence,
		              raw=excluded.raw,
		              status=CASE WHEN findings.status='open' THEN 'open' ELSE findings.status END`,
		f.TargetName, f.URL, f.Module, f.Category, f.Severity, f.Status,
		f.Param, f.Payload, f.Signal, f.Confidence, f.Raw, nowTs, nowTs)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

func (s *SQLiteStore) ListFindings(ctx context.Context, target, status string) ([]Finding, error) {
	q := "SELECT id, target_name, url, module, category, severity, status, param, payload, signal, confidence, raw, first_seen, last_seen FROM findings WHERE 1=1"
	var args []any
	if target != "" {
		q += " AND target_name=?"
		args = append(args, target)
	}
	if status != "" {
		q += " AND status=?"
		args = append(args, status)
	}
	q += " ORDER BY first_seen DESC"

	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Finding
	for rows.Next() {
		var f Finding
		var first, last string
		if err := rows.Scan(&f.ID, &f.TargetName, &f.URL, &f.Module, &f.Category,
			&f.Severity, &f.Status, &f.Param, &f.Payload, &f.Signal,
			&f.Confidence, &f.Raw, &first, &last); err != nil {
			return nil, err
		}
		f.FirstSeen = parseTime(first)
		f.LastSeen = parseTime(last)
		out = append(out, f)
	}
	return out, rows.Err()
}

func (s *SQLiteStore) SetFindingStatus(ctx context.Context, id int64, status, severity string) error {
	_, err := s.db.ExecContext(ctx,
		"UPDATE findings SET status=?, severity=?, last_seen=? WHERE id=?",
		status, severity, now(), id)
	return err
}

func (s *SQLiteStore) SaveOobCallback(ctx context.Context, c OobCallback) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO oob_callbacks (token, source, protocol, remote_ip, user_agent, path, headers, body, raw, received_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		c.Token, c.Source, c.Protocol, c.RemoteIP, c.UserAgent, c.Path, c.Headers, c.Body, c.Raw, now())
	return err
}

func (s *SQLiteStore) ListOobCallbacks(ctx context.Context, token string) ([]OobCallback, error) {
	q := "SELECT id, token, source, protocol, remote_ip, user_agent, path, headers, body, raw, received_at FROM oob_callbacks"
	var args []any
	if token != "" {
		q += " WHERE token=?"
		args = append(args, token)
	}
	q += " ORDER BY received_at DESC"
	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []OobCallback
	for rows.Next() {
		var c OobCallback
		var rec string
		if err := rows.Scan(&c.ID, &c.Token, &c.Source, &c.Protocol, &c.RemoteIP,
			&c.UserAgent, &c.Path, &c.Headers, &c.Body, &c.Raw, &rec); err != nil {
			return nil, err
		}
		c.Received = parseTime(rec)
		out = append(out, c)
	}
	return out, rows.Err()
}