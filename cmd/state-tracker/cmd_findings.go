package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strings"
)

// cmdFindings: `casde findings list` e `casde findings set`.
func cmdFindings(ctx context.Context, args []string) {
	if len(args) < 1 {
		fmt.Fprintln(os.Stderr, "ERRO: subcomando findings: list | set")
		os.Exit(1)
	}
	switch args[0] {
	case "list":
		cmdFindingsList(ctx, args[1:])
	case "set":
		cmdFindingsSet(ctx, args[1:])
	default:
		fmt.Fprintf(os.Stderr, "ERRO: subcomando findings desconhecido: %s\n", args[0])
		os.Exit(1)
	}
}

func cmdFindingsList(ctx context.Context, args []string) {
	fs := flag.NewFlagSet("findings list", flag.ExitOnError)
	target := fs.String("target", "", "filtrar por alvo")
	status := fs.String("status", "", "filtrar por status (open, confirmed, false_positive...)")
	db := fs.String("db", "casde.db", "caminho do banco SQLite")
	_ = fs.Parse(args)

	st, err := openStore(*db)
	if err != nil {
		exitErro(err)
	}
	defer st.Close()

	findings, err := st.ListFindings(ctx, *target, *status)
	if err != nil {
		exitErro(err)
	}
	if len(findings) == 0 {
		fmt.Println("nenhum achado")
		return
	}
	fmt.Printf("achados: %d\n\n", len(findings))
	fmt.Printf("%-4s %-8s %-8s %-7s %-10s %-12s %-36s %s\n",
		"ID", "SEV", "STATUS", "MÓDULO", "CATEGORIA", "PARAM", "URL", "SINAL")
	fmt.Println(strings.Repeat("-", 140))
	for _, f := range findings {
		fmt.Printf("%-4d %-8s %-8s %-7s %-10s %-12s %-36s %s\n",
			f.ID, f.Severity, f.Status, f.Module, f.Category,
			trunc(f.Param, 12), trunc(f.URL, 36), trunc(f.Signal, 40))
	}
}

func cmdFindingsSet(ctx context.Context, args []string) {
	fs := flag.NewFlagSet("findings set", flag.ExitOnError)
	id := fs.Int64("id", 0, "ID do achado (obrigatório)")
	status := fs.String("status", "", "novo status: confirmed | false_positive | duplicate | out_of_scope")
	severity := fs.String("severity", "", "nova severidade: critical | high | medium | low | info")
	db := fs.String("db", "casde.db", "caminho do banco SQLite")
	_ = fs.Parse(args)

	if *id == 0 {
		fmt.Fprintln(os.Stderr, "ERRO: --id obrigatório")
		os.Exit(1)
	}
	if *status == "" && *severity == "" {
		fmt.Fprintln(os.Stderr, "ERRO: informe --status e/ou --severity")
		os.Exit(1)
	}

	st, err := openStore(*db)
	if err != nil {
		exitErro(err)
	}
	defer st.Close()

	if err := st.SetFindingStatus(ctx, *id, *status, *severity); err != nil {
		exitErro(err)
	}
	fmt.Printf("achado %d atualizado (status=%s severity=%s)\n", *id, orDash(*status), orDash(*severity))
}

func trunc(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-1] + "…"
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}
