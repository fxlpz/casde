// Package store define a camada de persistência do CASDE.
//
// Design: a interface Store é a fronteira entre o domínio (tracker/diff) e o
// banco. A implementação concreta hoje é SQLite (uso individual), mas a
// interface foi desenhada para permitir um backend Postgres em uso em equipe
// sem tocar no resto do código.
package store

import (
	"context"
	"time"
)

// Asset é uma URL estável monitorada dentro de um target.
type Asset struct {
	ID        int64
	TargetID  int64
	URL       string
	Method    string
	FirstSeen time.Time
	LastSeen  time.Time
}

// Snapshot é o estado observado de um asset numa execução.
type Snapshot struct {
	ID          int64
	AssetID     int64
	CommitID    int64
	StatusCode  int
	BodyHash    string
	BodySize    int
	HeadersJSON string
	CapturedAt  time.Time
}

// Finding é um achado registrado pelo módulo 6 (Findings Database).
// `Raw` guarda o JSON completo do achado (payload, resposta, sinais).
type Finding struct {
	ID         int64
	TargetName string
	URL        string
	Module     string // fuzz | jsast | params | oob | state
	Category   string // sqli | xss | ssrf | idor | lfi | oob | info | other
	Severity   string // critical | high | medium | low | info
	Status     string // open | confirmed | false_positive | duplicate | out_of_scope
	Param      string
	Payload    string
	Signal     string
	Confidence float64
	Raw        string
	FirstSeen  time.Time
	LastSeen   time.Time
}

// Commit representa uma execução completa do tracker para um target.
type Commit struct {
	ID         int64
	TargetID   int64
	CommitHash string
	ParentID   *int64
	Summary    string // JSON estruturado do diff
	CreatedAt  time.Time
}

// DiffSummary é o resultado estruturado de uma execução (gravado em commits.summary).
type DiffSummary struct {
	Target      string   `json:"target"`
	CommitHash  string   `json:"commit_hash"`
	NewAssets   []string `json:"new_assets"`
	Removed     []string `json:"removed_assets"`
	Changed     []string `json:"changed_assets"`
	Unchanged   int      `json:"unchanged_assets"`
	AssetsTotal int      `json:"assets_total"`
}

// Store é a interface de persistência. Implementações: SQLiteStore (agora),
// futuramente PostgresStore.
type Store interface {
	// Init aplica o schema (idempotente).
	Init(ctx context.Context) error

	// Target management.
	GetOrCreateTarget(ctx context.Context, name string) (int64, error)
	ListTargets(ctx context.Context) ([]string, error)

	// Asset management.
	UpsertAsset(ctx context.Context, targetID int64, url, method string) (int64, error)
	// SetAssetInactive marca um asset como não observado na última execução
	// (usado pelo diff para detectar remoção sem apagar histórico).
	// NOTA: MVP v0 usa presença/ausência no commit; inactive é evolução futura.
	ListAssetsByTarget(ctx context.Context, targetID int64) ([]Asset, error)

	// Snapshot + commit (transação atômica por execução).
	SaveExecution(ctx context.Context, targetID int64, snapshots []Snapshot,
		summary DiffSummary, parentID *int64) (*Commit, error)

	// Consulta: snapshots do commit anterior (para diffing).
	GetCommitByID(ctx context.Context, id int64) (*Commit, error)
	GetLatestCommit(ctx context.Context, targetID int64) (*Commit, error)
	GetSnapshotsForCommit(ctx context.Context, commitID int64) ([]Snapshot, error)

	// Módulo 6: Findings Database.
	UpsertFinding(ctx context.Context, f Finding) (int64, error)
	ListFindings(ctx context.Context, target, status string) ([]Finding, error)
	SetFindingStatus(ctx context.Context, id int64, status, severity string) error
	SaveOobCallback(ctx context.Context, c OobCallback) error
	ListOobCallbacks(ctx context.Context, token string) ([]OobCallback, error)
}

// OobCallback é um callback de rede correlacionado (módulo 5).
type OobCallback struct {
	ID        int64
	Token     string
	Source    string // local | interactsh
	Protocol  string // http | dns
	RemoteIP  string
	UserAgent string
	Path      string
	Headers   string
	Body      string
	Raw       string
	Received  time.Time
}
