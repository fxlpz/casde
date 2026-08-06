// Package oob implementa o OOB Correlator (Módulo 5).
//
// Correlaciona vulnerabilidades "blind" (SSRF, XSS blind, template injection
// sem output) via callbacks de rede. Duas modalidades:
//
//  1. Listener local (self-hosted, estilo mini-Collaborator):
//     um servidor HTTP/DNS na porta 8080 recebe callbacks em
//     http://<token>.<domain> e correlaciona com o payload que gerou.
//
//  2. Interactsh (cliente): envia o domínio gerado pelo Interactsh público
//     (oob.interactsh.com) ou self-hosted, e consulta a API de polling para
//     receber os callbacks.
//
// O fluxo:
//
//	oob := oob.New(oob.Config{Mode: "local", Domain: "probe.local"})
//	token := oob.NewToken("payload-X")     // gera domínio único p/ payload
//	// injeta token no payload e envia ao alvo
//	oob.Wait(ctx, token, 30*time.Second)   // espera callback
//	oob.Result(token)                       // correlaciona
package oob

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Callback é um evento OOB recebido.
type Callback struct {
	ID        string    `json:"id"`
	Token     string    `json:"token"`     // token do payload
	Source    string    `json:"source"`    // local | interactsh
	Protocol  string    `json:"protocol"`  // http | dns
	RemoteIP  string    `json:"remote_ip"` // IP de origem do callback
	UserAgent string    `json:"user_agent"`
	Path      string    `json:"path"`
	Headers   string    `json:"headers"` // dump curto de headers
	Body      string    `json:"body"`    // corpo (limitado)
	Raw       string    `json:"raw"`
	At        time.Time `json:"at"`
}

// Config do correlator.
type Config struct {
	Mode         string // "local" (listener embutido) | "interactsh"
	Domain       string // domínio base (local: probe.local) ou do Interactsh
	ListenAddr   string // local: endereço do listener (default :8080)
	InteractURL  string // interactsh: URL da API (default https://interactsh.com)
	Token        string // interactsh: token da conta (opcional)
	PollInterval time.Duration
}

// Correlator gerencia tokens e callbacks.
type Correlator struct {
	cfg        Config
	log        *log.Logger
	mu         sync.Mutex
	byToken    map[string][]Callback
	onCallback func(Callback) // hook opcional (persistência, alerta)
	server     *http.Server
	client     *http.Client
}

// OnCallback registra um hook chamado a cada callback recebido.
// Útil para persistir em banco ou disparar alertas sem polling.
func (c *Correlator) OnCallback(fn func(Callback)) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.onCallback = fn
}

// New cria o correlator e (em modo local) inicia o listener.
func New(cfg Config) (*Correlator, error) {
	if cfg.Mode == "" {
		cfg.Mode = "local"
	}
	if cfg.Domain == "" {
		cfg.Domain = "probe.local"
	}
	if cfg.ListenAddr == "" {
		cfg.ListenAddr = ":8080"
	}
	if cfg.InteractURL == "" {
		cfg.InteractURL = "https://interactsh.com"
	}
	if cfg.PollInterval <= 0 {
		cfg.PollInterval = 5 * time.Second
	}
	c := &Correlator{
		cfg:     cfg,
		log:     log.Default(),
		byToken: map[string][]Callback{},
		client:  &http.Client{Timeout: 15 * time.Second},
	}
	if cfg.Mode == "local" {
		if err := c.startLocalListener(); err != nil {
			return nil, err
		}
	}
	return c, nil
}

// startLocalListener sobe o servidor HTTP que recebe callbacks.
func (c *Correlator) startLocalListener() error {
	mux := http.NewServeMux()
	mux.HandleFunc("/", c.handleLocal)
	ln, err := net.Listen("tcp", c.cfg.ListenAddr)
	if err != nil {
		return fmt.Errorf("listener OOB: %w", err)
	}
	c.server = &http.Server{Handler: mux}
	go c.server.Serve(ln)
	host, _, _ := net.SplitHostPort(ln.Addr().String())
	c.log.Printf("[oob] listener local em http://%s (domínio: %s)", ln.Addr().String(), c.cfg.Domain)
	if host == "0.0.0.0" || host == "" || host == "::" {
		host = "127.0.0.1"
	}
	_ = host
	return nil
}

// handleLocal processa qualquer GET/POST no listener e extrai o token do host
// (formato: <token>.<domain>) ou do path.
func (c *Correlator) handleLocal(w http.ResponseWriter, r *http.Request) {
	token := ""
	host := r.Host
	// Extrai token do subdomínio apenas se o host termina com o domínio base
	// (evita falsos tokens como "127" quando o host é um IP).
	if strings.HasSuffix(host, "."+c.cfg.Domain) {
		token = strings.TrimSuffix(host, "."+c.cfg.Domain)
		if i := strings.LastIndex(token, "."); i >= 0 {
			token = token[i+1:]
		}
	}
	if token == "" {
		// fallback: ?token= ou path /cb/<token>
		token = r.URL.Query().Get("token")
		if token == "" {
			parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
			if len(parts) >= 2 && parts[0] == "cb" {
				token = parts[1]
			}
		}
	}

	body, _ := io.ReadAll(io.LimitReader(r.Body, 8<<10))
	cb := Callback{
		ID:        randHex(8),
		Token:     token,
		Source:    "local",
		Protocol:  "http",
		RemoteIP:  r.RemoteAddr,
		UserAgent: r.Header.Get("User-Agent"),
		Path:      r.URL.Path,
		Headers:   fmt.Sprintf("%s %s %s | %s", r.Method, r.URL.RequestURI(), r.Proto, uaShort(r.Header)),
		Body:      string(body),
		At:        time.Now().UTC(),
	}
	c.mu.Lock()
	if token != "" {
		c.byToken[token] = append(c.byToken[token], cb)
	}
	hook := c.onCallback
	c.mu.Unlock()
	if hook != nil {
		hook(cb)
	}
	c.log.Printf("[oob] callback token=%s src=%s ua=%s path=%s", token, r.RemoteAddr, cb.UserAgent, r.URL.Path)

	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintf(w, `{"received":true,"token":%q}`, token)
}

// NewToken gera um identificador único para um payload e retorna o domínio
// completo a injetar (ex.: a1b2c3.probe.local).
func (c *Correlator) NewToken(payloadID string) string {
	tok := randHex(8)
	if c.cfg.Mode == "local" {
		return tok + "." + c.cfg.Domain
	}
	// interactsh: <correlation-id>.<domain>
	return tok + "." + c.cfg.Domain
}

// PayloadToken extrai o token puro (sem domínio) de um domínio gerado.
func PayloadToken(domain string) string {
	if i := strings.Index(domain, "."); i > 0 {
		return domain[:i]
	}
	return domain
}

// Wait bloqueia até o callback do token (ou timeout).
func (c *Correlator) Wait(ctx context.Context, domain string, timeout time.Duration) bool {
	tok := PayloadToken(domain)
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		c.mu.Lock()
		n := len(c.byToken[tok])
		c.mu.Unlock()
		if n > 0 {
			return true
		}
		select {
		case <-ctx.Done():
			return false
		case <-time.After(500 * time.Millisecond):
		}
	}
	return false
}

// Result retorna os callbacks correlacionados a um token.
func (c *Correlator) Result(domain string) []Callback {
	tok := PayloadToken(domain)
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]Callback{}, c.byToken[tok]...)
}

// Close encerra o listener.
func (c *Correlator) Close() {
	if c.server != nil {
		c.server.Close()
	}
}

// --- Interactsh client (esqueleto funcional) ---

// interactshRegister registra um domínio de correlação no servidor Interactsh.
func (c *Correlator) interactshRegister() (string, error) {
	// Interactsh público usa API REST: POST /register com correlation-id.
	// Este é um cliente mínimo; o projeto discovery/interactsh tem a impl completa.
	corrID := randHex(8)
	body := fmt.Sprintf(`{"publicKey":"","correlationId":"%s"}`, corrID)
	req, err := http.NewRequest("POST", c.cfg.InteractURL+"/register", strings.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return "", fmt.Errorf("interactsh register: status %d", resp.StatusCode)
	}
	var out struct {
		ID string `json:"id"`
	}
	json.NewDecoder(resp.Body).Decode(&out)
	c.cfg.Domain = out.ID
	return out.ID, nil
}

func randHex(n int) string {
	b := make([]byte, n)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func uaShort(h http.Header) string {
	ua := h.Get("User-Agent")
	if len(ua) > 40 {
		return ua[:40]
	}
	return ua
}
