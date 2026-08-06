// Package fetch coleta o estado observável de um asset (URL).
//
// Snapshot = status code + headers normalizados + hash SHA-256 do body.
// A normalização de headers é deliberada: remove cabeçalhos voláteis
// (Date, Set-Cookie com valores dinâmicos, Cf-Ray, X-Trace-Id, etc) para que
// o diff reflita mudanças SEMÂNTICAS de superfície, não ruído de CDN.
package fetch

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"time"
)

// Result é o estado observado de um asset numa coleta.
type Result struct {
	URL        string            `json:"url"`
	StatusCode int               `json:"status_code"`
	Headers    map[string]string `json:"headers"`
	BodyHash   string            `json:"body_hash"`
	BodySize   int               `json:"body_size"`
	Error      string            `json:"error,omitempty"` // preenchido se falhou
	FetchedAt  time.Time         `json:"fetched_at"`
}

// HeadersVolateis: normalização ignora estes cabeçalhos no diff.
// Lista extensível por config (--ignore-header pode ser adicionado depois).
var headersVolateis = map[string]bool{
	"date":             true,
	"server":           false, // server é relevante! (mudança de stack)
	"cf-ray":           true,
	"x-trace-id":       true,
	"x-request-id":     true,
	"x-amz-request-id": true,
	"x-amz-id-2":       true,
	"set-cookie":       true, // cookies dinâmicos (sessão) = ruído
	"x-powered-by":     false, // relevante (tech fingerprint)
}

// IsVolatile retorna true se o header deve ser ignorado no diff.
func IsVolatile(h string) bool {
	v, ok := headersVolateis[strings.ToLower(h)]
	return ok && v
}

// Client padrão com timeout + limite de body.
func defaultClient() *http.Client {
	return &http.Client{
		Timeout: 15 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			// Só seguimos até 3 redirects (evita loops).
			if len(via) >= 3 {
				return fmt.Errorf("muitos redirects")
			}
			return nil
		},
	}
}

// Snapshot busca a URL e produz o estado observado.
// ctx pode carregar timeout. Se a requisição falhar (rede, DNS, TLS), o
// Result é retornado com Error preenchido e sem hash — o tracker decide
// como tratar (falha = asset inacessível, não necessariamente removido).
func Snapshot(ctx context.Context, url string, headers map[string]string) Result {
	start := time.Now()
	r := Result{URL: url, FetchedAt: time.Now().UTC()}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		r.Error = fmt.Sprintf("request inválido: %v", err)
		return r
	}
	// UA padrão de recon (configurável depois).
	req.Header.Set("User-Agent", "CASDE/0.1 (continuous attack surface tracker)")
	for k, v := range headers {
		req.Header.Set(k, v)
	}

	client := defaultClient()
	resp, err := client.Do(req)
	if err != nil {
		r.Error = fmt.Sprintf("falha de rede: %v", err)
		return r
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 2<<20)) // máx 2 MB
	if err != nil {
		r.Error = fmt.Sprintf("ler body: %v", err)
		return r
	}

	r.StatusCode = resp.StatusCode
	r.BodySize = len(body)
	h := sha256.Sum256(body)
	r.BodyHash = hex.EncodeToString(h[:])
	r.Headers = NormalizeHeaders(resp.Header)

	_ = start
	return r
}

// NormalizeHeaders converte http.Header para mapa ordenável, ignorando
// cabeçalhos voláteis e normalizando chaves (lowercase).
func NormalizeHeaders(h http.Header) map[string]string {
	out := map[string]string{}
	for k, vv := range h {
		lk := strings.ToLower(k)
		if IsVolatile(lk) {
			continue
		}
		if len(vv) > 0 {
			out[lk] = strings.Join(vv, ", ")
		}
	}
	return out
}

// HeadersJSON serializa o mapa de headers de forma determinística
// (chaves ordenadas) para armazenar no SQLite.
func HeadersJSON(m map[string]string) (string, error) {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	ordered := make(map[string]string, len(m))
	for _, k := range keys {
		ordered[k] = m[k]
	}
	b, err := json.Marshal(ordered)
	return string(b), err
}
