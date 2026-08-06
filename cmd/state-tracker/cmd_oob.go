package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/fxlpz/casde/internal/oob"
	"github.com/fxlpz/casde/internal/store"
)

// cmdOOB: `casde oob listen` sobe o listener local de callbacks.
// Teste rápido: injete em payloads URLs tipo http://<token>.probe.local/cb
// e o listener correlaciona (token = subdomínio).
func cmdOOB(ctx context.Context, args []string) {
	// Aceita `casde oob listen ...` e `casde oob ...`.
	if len(args) > 0 && args[0] == "listen" {
		args = args[1:]
	}
	fs := flag.NewFlagSet("oob", flag.ExitOnError)
	addr := fs.String("addr", ":8080", "endereço do listener (ex: 0.0.0.0:8080)")
	domain := fs.String("domain", "probe.local", "domínio base (token.<domain> = correlação)")
	db := fs.String("db", "", "registrar callbacks no findings DB (opcional)")
	_ = fs.Parse(args)

	corr, err := oob.New(oob.Config{
		Mode:       "local",
		Domain:     *domain,
		ListenAddr: *addr,
	})
	if err != nil {
		exitErro(err)
	}
	defer corr.Close()

	// Registrar callbacks recebidos no banco (módulo 6), se --db.
	var st *store.SQLiteStore
	if *db != "" {
		st, err = openStore(*db)
		if err != nil {
			exitErro(err)
		}
		defer st.Close()
		corr.OnCallback(func(c oob.Callback) {
			rec := store.OobCallback{
				Token:     c.Token,
				Source:    c.Source,
				Protocol:  c.Protocol,
				RemoteIP:  c.RemoteIP,
				UserAgent: c.UserAgent,
				Path:      c.Path,
				Headers:   c.Headers,
				Body:      c.Body,
				Raw:       c.Raw,
			}
			if err := st.SaveOobCallback(context.Background(), rec); err != nil {
				fmt.Fprintf(os.Stderr, "[oob] erro ao persistir callback: %v\n", err)
			} else if c.Token != "" {
				fmt.Printf("[oob] callback %s persistido (token=%s)\n", c.Path, c.Token)
			}
		})
	}

	fmt.Printf("OOB listener ativo em http://%s\n", *addr)
	fmt.Printf("Injete nos payloads: http://<token>%s.<%s>/cb  (ex: http://abc123.probe.local/cb)\n", "", *domain)
	fmt.Println("Pressione Ctrl+C para encerrar.")

	// Loop de espera com persistência dos callbacks.
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	for {
		select {
		case <-sig:
			fmt.Println("\nencerrando...")
			return
		case <-ctx.Done():
			return
		}
	}
}
