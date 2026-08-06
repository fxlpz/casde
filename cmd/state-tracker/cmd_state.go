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
	"github.com/fxlpz/casde/internal/tracker"
)

// runFlags são os flags do subcomando state.
type runFlags struct {
	target      string
	urlsFile    string
	db          string
	concurrency int
	timeout     int
}

func parseRunFlags(args []string) runFlags {
	fs := flag.NewFlagSet("state", flag.ExitOnError)
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
		exitErro(fmt.Errorf("ler urls: %w", err))
	}
	if len(urls) == 0 {
		fmt.Fprintln(os.Stderr, "ERRO: nenhuma URL no arquivo")
		os.Exit(1)
	}

	st, err := openStore(f.db)
	if err != nil {
		exitErro(err)
	}
	defer st.Close()

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
		exitErro(err)
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

	st, err := openStore(*db)
	if err != nil {
		exitErro(err)
	}
	defer st.Close()
	targets, err := st.ListTargets(ctx)
	if err != nil {
		exitErro(err)
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

	st, err := openStore(*db)
	if err != nil {
		exitErro(err)
	}
	defer st.Close()

	tid, err := st.GetOrCreateTarget(ctx, *target)
	if err != nil {
		exitErro(err)
	}

	cur, err := st.GetLatestCommit(ctx, tid)
	if err != nil {
		exitErro(err)
	}
	if cur == nil {
		fmt.Printf("nenhum commit para %s\n", *target)
		return
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
