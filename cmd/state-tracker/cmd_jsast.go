package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/fxlpz/casde/internal/store"
)

// jsastResult é a saída do parser Node (tools/js_ast_extract.js).
type jsastResult struct {
	File      string `json:"file"`
	Endpoints []string `json:"endpoints"`
	Routes    []string `json:"routes"`
	Secrets   []struct {
		Key       string `json:"key"`
		ValuePreview string `json:"value_preview"`
		ValueLength  int    `json:"value_length"`
		Entropy      float64 `json:"entropy"`
		Source       string `json:"source"`
	} `json:"secrets"`
	Stats struct {
		EndpointsFound int `json:"endpoints_found"`
		RoutesFound    int `json:"routes_found"`
		SecretsFound   int `json:"secrets_found"`
	} `json:"stats"`
}

// toolPath resolve o caminho do script Node (tools/js_ast_extract.js).
func toolPath() string {
	// Tenta a partir do cwd (repo checkout) ou da env CASDE_TOOLS.
	if p := os.Getenv("CASDE_TOOLS"); p != "" {
		return filepath.Join(p, "js_ast_extract.js")
	}
	for _, base := range []string{"tools", "../tools", "../../tools", "../.."} {
		p := filepath.Join(base, "js_ast_extract.js")
		if _, err := os.Stat(p); err == nil {
			abs, _ := filepath.Abs(p)
			return abs
		}
	}
	return "tools/js_ast_extract.js"
}

func cmdJSAST(ctx context.Context, args []string) {
	fs := flag.NewFlagSet("jsast", flag.ExitOnError)
	url := fs.String("url", "", "URL do bundle JS para baixar e analisar")
	file := fs.String("file", "", "arquivo JS local para analisar")
	outDir := fs.String("out", "", "diretório para salvar resultados JSON (opcional)")
	db := fs.String("db", "", "registrar endpoints/secrets como findings (opcional)")
	timeout := fs.Int("timeout", 30, "timeout de download em segundos")
	_ = fs.Parse(args)

	if *url == "" && *file == "" {
		fmt.Fprintln(os.Stderr, "ERRO: informe --url ou --file")
		os.Exit(1)
	}

	// Obter o JS (baixar ou ler local).
	tmpPath := *file
	if *file == "" {
		f, err := os.CreateTemp("", "casde_js_*.js")
		if err != nil {
			exitErro(err)
		}
		defer os.Remove(f.Name())
		if err := downloadJS(ctx, *url, f, *timeout); err != nil {
			exitErro(err)
		}
		tmpPath = f.Name()
	}

	// Chamar o parser Node.
	script := toolPath()
	if script == "" || script == "tools/js_ast_extract.js" {
		// Tenta resolver relativamente via exec (node procura em PATH? não).
		// Procuramos em diretórios conhecidos.
		for _, p := range []string{
			"tools/js_ast_extract.js", "../tools/js_ast_extract.js",
			"/home/fxlpz/Projetos/CASDE/tools/js_ast_extract.js", ".",
		} {
			if _, err := os.Stat(p); err == nil {
				script = p
				break
			}
		}
	}
	cmd := exec.CommandContext(ctx, "node", script, tmpPath)
	cmd.Env = append(os.Environ(), "NODE_PATH=/usr/local/lib/node_modules")
	out, err := cmd.CombinedOutput()
	if err != nil {
		fmt.Fprintf(os.Stderr, "erro no parser Node (verifique node+esprima): %v\n%s\n", err, out)
		os.Exit(1)
	}

	var res jsastResult
	if err := json.Unmarshal(out, &res); err != nil {
		fmt.Fprintf(os.Stderr, "parse da saída Node: %v\n%s\n", err, out)
		os.Exit(1)
	}

	// Imprime resumo.
	fmt.Printf("arquivo: %s\nendpoints: %d\nroutes: %d\nsecrets: %d\n",
		tmpPath, res.Stats.EndpointsFound, res.Stats.RoutesFound, res.Stats.SecretsFound)
	fmt.Println("\n— endpoints —")
	for _, e := range res.Endpoints {
		fmt.Println("  " + e)
	}
	if len(res.Routes) > 0 {
		fmt.Println("\n— routes —")
		for _, r := range res.Routes {
			fmt.Println("  " + r)
		}
	}
	if len(res.Secrets) > 0 {
		fmt.Println("\n— secrets (preview truncado) —")
		for _, s := range res.Secrets {
			fmt.Printf("  [%s] %s: %s (len=%d, entropy=%.2f)\n",
				s.Source, s.Key, s.ValuePreview, s.ValueLength, s.Entropy)
		}
	}

	// Salvaguarda em --db (módulo 6).
	if *db != "" && (len(res.Endpoints) > 0 || len(res.Secrets) > 0) {
		st, err := openStore(*db)
		if err != nil {
			exitErro(err)
		}
		defer st.Close()
		target := *url
		if target == "" {
			target = *file
		}
		for _, e := range res.Endpoints {
			_, _ = st.UpsertFinding(ctx, store.Finding{
				TargetName: target,
				URL:        e,
				Module:     "jsast",
				Category:   "info",
				Severity:   "info",
				Status:     "open",
				Param:      "endpoint",
				Signal:     "endpoint extraído de bundle JS",
				Confidence: 0.6,
				Raw:        fmt.Sprintf(`{"endpoint":%q}`, e),
			})
		}
		for _, s := range res.Secrets {
			_, _ = st.UpsertFinding(ctx, store.Finding{
				TargetName: target,
				URL:        *url,
				Module:     "jsast",
				Category:   "secret",
				Severity:   "high",
				Status:     "open",
				Param:      s.Key,
				Signal:     fmt.Sprintf("secret por %s, entropy=%.2f", s.Source, s.Entropy),
				Confidence: 0.7,
				Raw:        fmt.Sprintf(`{"key":%q,"length":%d}`, s.Key, s.ValueLength),
			})
		}
		fmt.Printf("\n→ registrados %d findings no banco de %s\n", len(res.Endpoints)+len(res.Secrets), *db)
	}

	// Salvar JSON.
	if *outDir != "" {
		os.MkdirAll(*outDir, 0o755)
		name := ""
		if *url != "" {
			name = sanitize(*url)
		} else {
			name = filepath.Base(*file)
		}
		p := filepath.Join(*outDir, name+".json")
		_ = os.WriteFile(p, out, 0o644)
		fmt.Printf("→ JSON salvo em %s\n", p)
	}

	if ctx.Err() != nil {
		exitErro(ctx.Err())
	}
}

func downloadJS(ctx context.Context, url string, f *os.File, timeout int) error {
	cctx, cancel := context.WithTimeout(ctx, time.Duration(timeout)*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(cctx, "GET", url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (casde-jsast)")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("HTTP %d ao baixar %s", resp.StatusCode, url)
	}
	_, err = io.Copy(f, resp.Body)
	return err
}

func sanitize(s string) string {
	s = strings.ReplaceAll(s, "://", "_")
	s = strings.ReplaceAll(s, "/", "_")
	s = strings.ReplaceAll(s, "?", "_")
	s = strings.ReplaceAll(s, "&", "_")
	return s
}