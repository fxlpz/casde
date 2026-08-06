// Package tracker orquestra o ciclo completo do State Tracker:
//
//	1. Garante o target no banco
//	2. Busca o commit anterior (para diff)
//	3. Coleta snapshots dos assets (paralelo, com limite de concorrência)
//	4. Calcula o diff e o commit hash
//	5. Persiste snapshots + commit numa transação atômica
//	6. Retorna o diff estruturado
//
// Concorrência: usa um worker pool com limite configurável (default 10).
// Isso controla a carga no alvo (polidez) e no banco.
package tracker

import (
	"context"
	"fmt"
	"log"
	"sync"

	"github.com/fxlpz/casde/internal/diff"
	"github.com/fxlpz/casde/internal/fetch"
	"github.com/fxlpz/casde/internal/store"
)

// Config controla o comportamento de uma execução.
type Config struct {
	Target         string            // nome do alvo (programa/domínio)
	URLs           []string          // lista de assets a monitorar
	Concurrency    int               // workers paralelos (default 10)
	RequestHeaders map[string]string // headers extras nas requisições
}

// Tracker executa o ciclo de snapshot + diff + persistência.
type Tracker struct {
	store store.Store
	cfg   Config
	log   *log.Logger
}

// New cria um Tracker com a store dada.
func New(s store.Store, cfg Config) *Tracker {
	if cfg.Concurrency <= 0 {
		cfg.Concurrency = 10
	}
	return &Tracker{store: s, cfg: cfg, log: log.Default()}
}

// Run executa um ciclo completo e retorna o diff.
//
// O fluxo é idempotente: rodar duas vezes seguidas sem mudanças no alvo
// produz um commit com hash igual e diff vazio (nada "novo").
func (t *Tracker) Run(ctx context.Context) (*diff.Result, *store.Commit, error) {
	targetID, err := t.store.GetOrCreateTarget(ctx, t.cfg.Target)
	if err != nil {
		return nil, nil, fmt.Errorf("garantir target: %w", err)
	}

	// Estado anterior (commit mais recente) para o diff.
	prevStates, parentID, err := t.previousState(ctx, targetID)
	if err != nil {
		return nil, nil, err
	}

	// Coleta paralela dos assets (já com AssetID para persistência).
	snapshots, err := t.collectWithIDs(ctx, targetID)
	if err != nil {
		return nil, nil, err
	}

	// Diff + hash do commit.
	states := snapshotsToStates(snapshots, t.cfg.URLs)
	res := diff.Compare(t.cfg.Target, states, prevStates)
	commitHash := diff.CommitHash(t.cfg.Target, states)
	summary := diff.ToSummary(res, commitHash)

	// Persistência atômica (snapshots + commit).
	commit, err := t.store.SaveExecution(ctx, targetID, snapshots, summary, parentID)
	if err != nil {
		return nil, nil, fmt.Errorf("persistir execução: %w", err)
	}

	// Commit "vazio" (sem mudanças) ainda é registrado: útil para provar que
	// o monitoramento rodou naquele horário (continuidade do tracking).
	return &res, commit, nil
}

// previousState carrega os snapshots do commit anterior (se existir),
// montando SnapshotState com a URL correta via join com assets.
func (t *Tracker) previousState(ctx context.Context, targetID int64) ([]diff.SnapshotState, *int64, error) {
	prev, err := t.store.GetLatestCommit(ctx, targetID)
	if err != nil {
		return nil, nil, fmt.Errorf("buscar commit anterior: %w", err)
	}
	if prev == nil {
		return nil, nil, nil // primeiro commit
	}
	snaps, err := t.store.GetSnapshotsForCommit(ctx, prev.ID)
	if err != nil {
		return nil, nil, fmt.Errorf("ler snapshots anteriores: %w", err)
	}
	assets, err := t.store.ListAssetsByTarget(ctx, targetID)
	if err != nil {
		return nil, nil, err
	}
	urlByAsset := map[int64]string{}
	for _, a := range assets {
		urlByAsset[a.ID] = a.URL
	}
	states := make([]diff.SnapshotState, 0, len(snaps))
	for _, s := range snaps {
		states = append(states, diff.SnapshotState{
			URL:         urlByAsset[s.AssetID],
			StatusCode:  s.StatusCode,
			BodyHash:    s.BodyHash,
			HeadersJSON: s.HeadersJSON,
		})
	}
	pid := prev.ID
	return states, &pid, nil
}

// collectWithIDs faz snapshot de todos os assets com worker pool e retorna
// snapshots já vinculados ao AssetID (necessário para persistência correta).
func (t *Tracker) collectWithIDs(ctx context.Context, targetID int64) ([]store.Snapshot, error) {
	// Upsert de todos os assets (garante existência e atualiza last_seen).
	ids := make([]int64, 0, len(t.cfg.URLs))
	for _, u := range t.cfg.URLs {
		id, err := t.store.UpsertAsset(ctx, targetID, u, "GET")
		if err != nil {
			return nil, fmt.Errorf("upsert asset %s: %w", u, err)
		}
		ids = append(ids, id)
	}

	type job struct {
		idx int
		id  int64
		url string
	}
	jobs := make(chan job, len(t.cfg.URLs))
	for i := range t.cfg.URLs {
		jobs <- job{idx: i, id: ids[i], url: t.cfg.URLs[i]}
	}
	close(jobs)

	out := make([]store.Snapshot, len(t.cfg.URLs))
	var wg sync.WaitGroup
	var mu sync.Mutex

	workers := t.cfg.Concurrency
	if workers > len(t.cfg.URLs) {
		workers = len(t.cfg.URLs)
	}
	if workers < 1 {
		workers = 1
	}

	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range jobs {
				if ctx.Err() != nil {
					return
				}
				fr := fetch.Snapshot(ctx, j.url, t.cfg.RequestHeaders)
				hj, _ := fetch.HeadersJSON(fr.Headers)
				if fr.Error != "" {
					// Falha de rede: snapshot com status 0 e hash vazio.
					// Não conta como "removed" (decisão do diff), apenas como
					// estado não observado. Log para diagnóstico.
					t.log.Printf("[warn] %s: %s", j.url, fr.Error)
				}
				mu.Lock()
				out[j.idx] = store.Snapshot{
					AssetID:     j.id,
					StatusCode:  fr.StatusCode,
					BodyHash:    fr.BodyHash,
					BodySize:    fr.BodySize,
					HeadersJSON: hj,
				}
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	return out, ctx.Err()
}

// snapshotsToStates converte store.Snapshot em diff.SnapshotState com URL.
func snapshotsToStates(snaps []store.Snapshot, urls []string) []diff.SnapshotState {
	states := make([]diff.SnapshotState, 0, len(snaps))
	for i, s := range snaps {
		u := ""
		if i < len(urls) {
			u = urls[i]
		}
		states = append(states, diff.SnapshotState{
			URL:         u,
			StatusCode:  s.StatusCode,
			BodyHash:    s.BodyHash,
			HeadersJSON: s.HeadersJSON,
		})
	}
	return states
}
