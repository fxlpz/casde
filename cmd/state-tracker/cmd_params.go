package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

// paramScorerPath resolve o script Python de scoring (python/param_scorer.py).
func paramScorerPath() string {
	if p := os.Getenv("CASDE_PYTHON"); p != "" {
		return p
	}
	for _, p := range []string{
		"python/param_scorer.py", "../python/param_scorer.py",
		"/home/fxlpz/Projetos/CASDE/python/param_scorer.py", "python3",
	} {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return "python/param_scorer.py"
}

func cmdParams(ctx context.Context, args []string) {
	fs := flag.NewFlagSet("params", flag.ExitOnError)
	params := fs.String("params", "", "lista separada por vírgula (ex: id,url,file,debug)")
	file := fs.String("file", "", "arquivo JSON com {params:[], sources:{}}")
	sources := fs.String("sources", "js", "fontes (ex: js,wayback,gau)")
	_ = fs.Parse(args)

	var data struct {
		Params  []string          `json:"params"`
		Sources map[string][]string `json:"sources"`
	}
	if *file != "" {
		b, err := os.ReadFile(*file)
		if err != nil {
			exitErro(err)
		}
		if err := json.Unmarshal(b, &data); err != nil {
			exitErro(fmt.Errorf("parse %s: %w", *file, err))
		}
	} else if *params != "" {
		data.Params = strings.Split(*params, ",")
		data.Sources = map[string][]string{}
		for _, p := range data.Params {
			p = strings.TrimSpace(p)
			data.Sources[p] = strings.Split(*sources, ",")
		}
	} else {
		fmt.Fprintln(os.Stderr, "ERRO: informe --params ou --file")
		os.Exit(1)
	}

	in, _ := json.Marshal(&data)
	tmp, err := os.CreateTemp("", "casde_params_*.json")
	if err != nil {
		exitErro(err)
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(in); err != nil {
		exitErro(err)
	}
	tmp.Close()

	script := paramScorerPath()
	cmd := exec.CommandContext(ctx, "python3", script, tmp.Name())
	out, err := cmd.CombinedOutput()
	if err != nil {
		fmt.Fprintf(os.Stderr, "erro no scorer Python: %v\n%s\n", err, out)
		os.Exit(1)
	}
	// Imprime o ranking bonito (o Python já dá JSON ordenado).
	var ranked struct {
		Total   int `json:"total"`
		Ranking []struct {
			Param    string   `json:"param"`
			Score    float64  `json:"score"`
			Category string   `json:"category"`
			Why      []string `json:"why"`
		} `json:"ranking"`
	}
	if err := json.Unmarshal(out, &ranked); err != nil {
		fmt.Println(string(out))
		return
	}
	fmt.Printf("total de parâmetros: %d\n\n", ranked.Total)
	fmt.Printf("%-16s %8s  %-14s %s\n", "PARAM", "SCORE", "CATEGORIA", "PORQUÊ")
	fmt.Println(strings.Repeat("-", 60))
	for _, r := range ranked.Ranking {
		fmt.Printf("%-16s %8.2f  %-14s %s\n", r.Param, r.Score, r.Category, strings.Join(r.Why, "; "))
	}
	_ = ctx
}