package store

import (
	"context"
	"path/filepath"
	"testing"
)

// TestInitSchemaCriaTabelas: o schema embutido cria todas as tabelas do
// módulo 6 (findings, oob_callbacks) além das do módulo 1.
func TestInitSchemaCriaTabelas(t *testing.T) {
	st, err := NewSQLiteStore(filepath.Join(t.TempDir(), "casde_test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ctx := context.Background()
	if err := st.Init(ctx); err != nil {
		t.Fatal(err)
	}

	for _, table := range []string{"targets", "assets", "commits", "snapshots",
		"findings", "oob_callbacks"} {
		var n int
		err := st.db.QueryRowContext(ctx,
			"SELECT count(*) FROM sqlite_master WHERE type='table' AND name=?", table).Scan(&n)
		if err != nil {
			t.Fatalf("query tabela %s: %v", table, err)
		}
		if n != 1 {
			t.Fatalf("tabela %s não criada pelo schema", table)
		}
	}
}

// TestUpsertFindingDeduplica: mesmo achado não duplica (UNIQUE) e atualiza
// last_seen via ON CONFLICT.
func TestUpsertFindingDeduplica(t *testing.T) {
	st, err := NewSQLiteStore(filepath.Join(t.TempDir(), "casde_test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ctx := context.Background()
	if err := st.Init(ctx); err != nil {
		t.Fatal(err)
	}

	f := Finding{
		TargetName: "target.com",
		URL:        "https://target.com/api",
		Module:     "fuzz",
		Category:   "sqli",
		Severity:   "medium",
		Status:     "open",
		Param:      "id",
		Payload:    "' OR 1=1--",
		Signal:     "status_5xx",
		Confidence: 0.7,
		Raw:        `{"x":1}`,
	}
	if _, err := st.UpsertFinding(ctx, f); err != nil {
		t.Fatal(err)
	}
	// Mesmo achado de novo (idempotente).
	if _, err := st.UpsertFinding(ctx, f); err != nil {
		t.Fatal(err)
	}

	list, err := st.ListFindings(ctx, "target.com", "")
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 1 {
		t.Fatalf("esperava 1 achado (dedup), got %d", len(list))
	}

	// Triagem.
	if err := st.SetFindingStatus(ctx, list[0].ID, "confirmed", "high"); err != nil {
		t.Fatal(err)
	}
	list2, _ := st.ListFindings(ctx, "target.com", "confirmed")
	if len(list2) != 1 || list2[0].Severity != "high" {
		t.Fatalf("triagem não aplicada: %+v", list2)
	}
}

// TestSaveOobCallback: callback OOB persiste e é listável por token.
func TestSaveOobCallback(t *testing.T) {
	st, err := NewSQLiteStore(filepath.Join(t.TempDir(), "casde_test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ctx := context.Background()
	if err := st.Init(ctx); err != nil {
		t.Fatal(err)
	}

	if err := st.SaveOobCallback(ctx, OobCallback{
		Token: "abc123", Source: "local", Protocol: "http",
		RemoteIP: "203.0.113.9", UserAgent: "test",
	}); err != nil {
		t.Fatal(err)
	}

	cbs, err := st.ListOobCallbacks(ctx, "abc123")
	if err != nil {
		t.Fatal(err)
	}
	if len(cbs) != 1 || cbs[0].RemoteIP != "203.0.113.9" {
		t.Fatalf("callback não recuperado: %+v", cbs)
	}
}
