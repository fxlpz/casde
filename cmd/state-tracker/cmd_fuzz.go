package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/fxlpz/casde/internal/fuzz"
	"github.com/fxlpz/casde/internal/store"
)

func cmdFuzz(ctx context.Context, args []string) {
	fs := flag.NewFlagSet("fuzz", flag.ExitOnError)
	target := fs.String("target", "", "URL com {{{FUZZ}}} (ex: https://x.com/api?file={{{FUZZ}}})")
	param := fs.String("param", "", "nome do parâmetro para injetar (se target não tem {{{FUZZ}}})")
	method := fs.String("method", "GET", "GET ou POST")
	data := fs.String("data", "", "body POST com {{{FUZZ}}} (ex: user=admin&pass={{{FUZZ}}})")
	headers := fs.String("headers", "", "headers extras separados por | (ex: X-Token: abc|X-Debug: 1)")
	concurrency := fs.Int("concurrency", 8, "workers paralelos")
	generations := fs.Int("generations", 4, "número de gerações")
	population := fs.Int("population", 24, "população por geração")
	db := fs.String("db", "", "registrar achados no findings DB (opcional)")
	jsonOut := fs.Bool("json", false, "saída JSON completa")
	_ = fs.Parse(args)

	if *target == "" {
		fmt.Fprintln(os.Stderr, "ERRO: --target obrigatório (use {{{FUZZ}}} no lugar do valor)")
		os.Exit(1)
	}

	cfg := fuzz.Config{
		Target:      *target,
		Param:       *param,
		Method:      *method,
		Data:        *data,
		Concurrency: *concurrency,
		Generations: *generations,
		Population:  *population,
	}
	if *headers != "" {
		cfg.Headers = append(cfg.Headers, splitHeaders(*headers)...)
	}

	fmt.Printf("→ alvo: %s\n→ método: %s\n→ gerações: %d · população: %d · workers: %d\n\n",
		*target, *method, *generations, *population, *concurrency)

	fz := fuzz.New(cfg)
	start := time.Now()
	res, err := fz.Run(ctx)
	if err != nil {
		exitErro(err)
	}
	elapsed := time.Since(start).Round(time.Millisecond)

	if *jsonOut {
		out, _ := json.MarshalIndent(res, "", "  ")
		fmt.Println(string(out))
	} else {
		fmt.Printf("requests: %d · tempo: %s\n", res.TotalRequests, elapsed)
		if res.Best != nil {
			fmt.Printf("melhor achado: %q fitness=%.2f sinais=%v\n",
				res.Best.Value, res.Best.Fitness, res.Best.Anomaly)
		}
		fmt.Println("\n— achados por fitness —")
		for _, f := range res.Findings {
			fmt.Printf("  %.2f  %-40q  status=%d size=%d lat=%s %v\n",
				f.Fitness, f.Value, f.Status, f.Size, f.Latency.Round(time.Millisecond), f.Anomaly)
		}
		if len(res.Findings) == 0 {
			fmt.Println("  (nenhum achado acima do limiar)")
		}
	}

	// Persistir achados (módulo 6).
	if *db != "" && len(res.Findings) > 0 {
		st, err := openStore(*db)
		if err != nil {
			exitErro(err)
		}
		defer st.Close()
		n := 0
		for _, f := range res.Findings {
			signal := strings.Join(f.Anomaly, ",")
			raw, _ := json.Marshal(f)
			_, err := st.UpsertFinding(ctx, store.Finding{
				TargetName: *target,
				URL:        *target,
				Module:     "fuzz",
				Category:   classifyPayload(f.Value),
				Severity:   severityFor(f),
				Status:     "open",
				Param:      *param,
				Payload:    f.Value,
				Signal:     signal,
				Confidence: confidenceFor(f),
				Raw:        string(raw),
			})
			if err == nil {
				n++
			}
		}
		fmt.Printf("→ %d achados persistidos em %s\n", n, *db)
	}
}

func splitHeaders(s string) []string {
	return strings.Split(s, "|")
}

// classifyPayload tenta inferir a categoria pelo payload (heurística simples).
func classifyPayload(p string) string {
	lower := strings.ToLower(p)
	switch {
	case strings.Contains(lower, "select"), strings.Contains(lower, "union"), strings.Contains(lower, "sleep("):
		return "sqli"
	case strings.Contains(lower, "<script"), strings.Contains(lower, "onerror"):
		return "xss"
	case strings.Contains(lower, "{{"), strings.Contains(lower, "${"), strings.Contains(lower, "<%="):
		return "ssti"
	case strings.Contains(lower, "etc/passwd"), strings.Contains(lower, "win.ini"), strings.Contains(lower, "..%2f"):
		return "lfi"
	case strings.Contains(lower, "169.254"), strings.Contains(lower, "127.0.0.1"), strings.Contains(lower, "file://"):
		return "ssrf"
	case strings.Contains(lower, ";"), strings.Contains(lower, "|"), strings.Contains(lower, "$("):
		return "cmdi"
	default:
		return "other"
	}
}

func severityFor(f fuzz.Payload) string {
	if f.Echo {
		return "high"
	}
	for _, a := range f.Anomaly {
		if strings.Contains(a, "time_anomaly") {
			return "high"
		}
		if strings.Contains(a, "status_5xx") {
			return "medium"
		}
	}
	return "low"
}

func confidenceFor(f fuzz.Payload) float64 {
	c := 0.3 + f.Fitness*0.1
	if c > 0.9 {
		c = 0.9
	}
	if c < 0.3 {
		c = 0.3
	}
	return c
}
