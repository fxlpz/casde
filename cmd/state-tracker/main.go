// CASDE - Continuous Attack Surface & Diff Engine
//
// Uso: state-tracker é o módulo 1 (State Tracker).
//
// AVISO LEGAL / USO RESPONSÁVEL:
// Esta ferramenta é destinada EXCLUSIVAMENTE a:
//   - Programas de Bug Bounty com escopo autorizado (HackerOne, Bugcrowd, etc.)
//   - Engajamentos de pentest com contrato/escopo definido por escrito
//   - Ambientes próprios ou de laboratório (CTF, homelab)
//
// O monitoramento contínuo de superfície de ataque sem autorização pode
// violar leis locais e os termos de serviço do alvo. O autor não se
// responsabiliza pelo uso indevido.
//
// Uso:
//
//	state-tracker run --target target.com --urls urls.txt [--db casde.db] [--concurrency 10]
//	state-tracker targets [--db casde.db]        # lista targets monitorados
//	state-tracker history --target target.com [--db casde.db]  # histórico de commits
package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/fxlpz/casde/internal/diff"
	"github.com/fxlpz/casde/internal/store"
	"github.com/fxlpz/casde/internal/tracker"
)

const banner = `
  ╔══════════════════════════════════════════════════╗
  ║  CASDE - Continuous Attack Surface & Diff Engine ║
  ║  Módulo 1: State Tracker (MVP)                   ║
  ║  Uso autorizado: bug bounty / pentest / labs     ║
  ╚══════════════════════════════════════════════════╝
`

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(1)
	}
	fmt.Println(strings.TrimSuffix(banner, "\n"))
	ctx := context.Background()

	switch os.Args[1] {
	case "run":
		cmdRun(ctx, os.Args[2:])
	case "targets":
		cmdTargets(ctx, os.Args[2:])
	case "history":
		cmdHistory(ctx, os.Args[2:])
	case "help", "-h", "--help":
		usage()
	default:
		fmt.Fprintf(os.Stderr, "comando desconhecido: %s\n", os.Args[1])
		usage()
		os.Exit(1)
	}
}

func usage() {
	fmt.Print(`CASDE - State Tracker

Comandos:
  run      Executa um ciclo de snapshot + diff + persistência
  targets  Lista alvos monitorados
  history  Mostra histórico de commits de um alvo

Exemplos:
  casde run --target target.com --urls urls.txt
  casde run --target target.com --urls urls.txt --db casde.db --concurrency 20
  casde targets --db casde.db
  casde history --target target.com --db casde.db
`)
}

// runFlags são os flags do subcomando run.
type runFlags struct {
	target      string
	urlsFile    string
	db          string
	concurrency int
	timeout     int
}

func parseRunFlags(args []string) runFlags {
	fs := flag.NewFlagSet("run", flag.ExitOnError)
	var f runFlags
	fs.StringVar(&f.target, "target", "", "nome do alvo (obrigatório)")
	fs.StringVar(&f.urlsFile, "urls", "", "arquivo com uma URL por linha (obrigatório)")
	fs.StringVar(&f.db, "db", "casde.db", "caminho do banco SQLite")
	fs.IntVar(&f.concurrency, "concurrency", 10, "workers paralelos")
	fs.IntVar(&f.timeout, "timeout", 60, "timeout total em segundos")
	_ = fs.Parse(args)
	return f
}

func cmdRun(ctx context.Context, args []string) {
	f := parseRunFlags(args)
	if f.target == "" || f.urlsFile == "" {
		fmt.Fprintln(os.Stderr, "ERRO: --target e --urls são obrigatórios")
		usage()
		os.Exit(1)
	}

	urls, err := readLines(f.urlsFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERRO: ler urls: %v\n", err)
		os.Exit(1)
	}
	if len(urls) == 0 {
		fmt.Fprintln(os.Stderr, "ERRO: nenhuma URL no arquivo")
		os.Exit(1)
	}

	st, err := store.NewSQLiteStore(f.db)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERRO: abrir banco: %v\n", err)
		os.Exit(1)
	}
	defer st.Close()

	if err := st.Init(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "ERRO: schema: %v\n", err)
		os.Exit(1)
	}

	ctx, cancel := context.WithTimeout(ctx, time.Duration(f.timeout)*time.Second)
	defer cancel()

	tr := tracker.New(st, tracker.Config{
		Target:      f.target,
		URLs:        urls,
		Concurrency: f.concurrency,
	})

	fmt.Printf("→ alvo: %s\n→ assets: %d\n→ db: %s\n\n", f.target, len(urls), f.db)

	res, commit, err := tr.Run(ctx)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERRO: %v\n", err)
		os.Exit(1)
	}

	out, _ := diff.JSON(*res)
	fmt.Println(out)

	if commit != nil {
		fmt.Printf("\n→ commit %s (%s)\n", commit.CommitHash[:12], commit.CreatedAt.Format(time.RFC3339))
	}
	if len(res.Added) == 0 && len(res.Removed) == 0 && len(res.Changed) == 0 {
		fmt.Println("→ sem mudanças desde o commit anterior")
	} else {
		fmt.Printf("→ %d novo(s), %d removido(s), %d alterado(s)\n",
			len(res.Added), len(res.Removed), len(res.Changed))
	}
}

func cmdTargets(ctx context.Context, args []string) {
	fs := flag.NewFlagSet("targets", flag.ExitOnError)
	db := fs.String("db", "casde.db", "caminho do banco SQLite")
	_ = fs.Parse(args)

	st, err := store.NewSQLiteStore(*db)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERRO: %v\n", err)
		os.Exit(1)
	}
	defer st.Close()
	if err := st.Init(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "ERRO: %v\n", err)
		os.Exit(1)
	}
	targets, err := st.ListTargets(ctx)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERRO: %v\n", err)
		os.Exit(1)
	}
	for _, t := range targets {
		fmt.Println(t)
	}
}

func cmdHistory(ctx context.Context, args []string) {
	fs := flag.NewFlagSet("history", flag.ExitOnError)
	target := fs.String("target", "", "nome do alvo")
	db := fs.String("db", "casde.db", "caminho do banco SQLite")
	_ = fs.Parse(args)
	if *target == "" {
		fmt.Fprintln(os.Stderr, "ERRO: --target obrigatório")
		os.Exit(1)
	}

	st, err := store.NewSQLiteStore(*db)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERRO: %v\n", err)
		os.Exit(1)
	}
	defer st.Close()
	if err := st.Init(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "ERRO: %v\n", err)
		os.Exit(1)
	}

	tid, err := st.GetOrCreateTarget(ctx, *target)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERRO: %v\n", err)
		os.Exit(1)
	}

	// Percorre a cadeia de commits (parent_id) e imprime resumo.
	cur, err := st.GetLatestCommit(ctx, tid)
	if err != nil || cur == nil {
		if err != nil {
			fmt.Fprintf(os.Stderr, "ERRO: %v\n", err)
		} else {
			fmt.Printf("nenhum commit para %s\n", *target)
		}
		os.Exit(0)
	}
	fmt.Printf("histórico de commits para %s:\n", *target)
	for cur != nil {
		summary := "sem resumo"
		if cur.Summary != "" {
			summary = cur.Summary
		}
		fmt.Printf("  %s  %s  %s\n", cur.CreatedAt.Format(time.RFC3339), cur.CommitHash[:12], summary)
		if cur.ParentID == nil {
			break
		}
		cur, err = st.GetCommitByID(ctx, *cur.ParentID)
		if err != nil {
			break
		}
	}
}

// readLines lê um arquivo de URLs (uma por linha, ignora vazias e #).
func readLines(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		out = append(out, line)
	}
	return out, sc.Err()
}
