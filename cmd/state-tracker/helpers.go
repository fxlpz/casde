package main

import (
	"context"
	"fmt"
	"os"

	"github.com/fxlpz/casde/internal/store"
)

// openStore abre o banco e aplica o schema embutido (go:embed).
func openStore(db string) (*store.SQLiteStore, error) {
	st, err := store.NewSQLiteStore(db)
	if err != nil {
		return nil, err
	}
	if err := st.Init(context.Background()); err != nil {
		st.Close()
		return nil, fmt.Errorf("schema: %w", err)
	}
	return st, nil
}

// exitErro imprime e encerra com código 1.
func exitErro(err error) {
	fmt.Fprintf(os.Stderr, "ERRO: %v\n", err)
	os.Exit(1)
}