package fuzz

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

// TestMutateNaoVazio: mutação nunca devolve payload vazio.
func TestMutateNaoVazio(t *testing.T) {
	for _, seed := range []string{"' OR 1=1--", "<script>alert(1)</script>", "normal"} {
		for i := 0; i < 50; i++ {
			m := mutate(seed)
			if m == "" {
				t.Fatalf("mutate(%q) retornou vazio", seed)
			}
			if strings.Contains(m, "{{{FUZZ}}}") {
				t.Fatalf("mutate(%q) manteve placeholder: %q", seed, m)
			}
		}
	}
}

// TestCrossoverMistura: crossover combina prefixo/sufixo dos pais.
func TestCrossoverMistura(t *testing.T) {
	c := crossover("AAA", "BBB")
	if c != "AAB" && c != "ABB" {
		t.Fatalf("crossover inesperado: %q", c)
	}
}

// TestScoreDetectaEcho: resposta que reflete o payload ganha anomalia echo.
func TestScoreDetectaEcho(t *testing.T) {
	f := New(Config{Population: 4})
	resp := fakeResponse("corpo com xyz123 refletido")
	p := f.score("xyz123", resp, 100, 120*time.Millisecond, 100, 5*time.Millisecond)
	if !hasAnomaly(p, "echo") {
		t.Fatalf("esperava anomalia echo, got %v", p.Anomaly)
	}
}

// TestScoreDetectaSizeDelta: mudança grande de tamanho vira anomalia.
func TestScoreDetectaSizeDelta(t *testing.T) {
	f := New(Config{Population: 4})
	resp := fakeResponse(strings.Repeat("x", 500))
	p := f.score("p", resp, 1000, 120*time.Millisecond, 100, 5*time.Millisecond)
	if !hasAnomalyPrefix(p, "size_delta") {
		t.Fatalf("esperava size_delta, got %v", p.Anomaly)
	}
}

// TestScoreDetectaTimeAnomaly: latência muito acima da baseline vira anomalia.
func TestScoreDetectaTimeAnomaly(t *testing.T) {
	f := New(Config{Population: 4})
	resp := fakeResponse("ok")
	// baseline 5ms; latência 3s
	p := f.score("p", resp, 100, 3*time.Second, 100, 5*time.Millisecond)
	if !hasAnomalyPrefix(p, "time_anomaly") {
		t.Fatalf("esperava time_anomaly, got %v", p.Anomaly)
	}
}

// TestRunRespeitaContexto: Run com contexto cancelado falha rápido (sem rede).
func TestRunRespeitaContexto(t *testing.T) {
	f := New(Config{
		Target:      "http://127.0.0.1:1/x?q={{{FUZZ}}}", // porta 1: sem serviço
		Concurrency: 2,
		Generations: 1,
		Population:  4,
		Timeout:     time.Second,
	})
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // contexto já cancelado
	_, err := f.Run(ctx)
	if err == nil {
		t.Fatal("esperava erro com contexto cancelado")
	}
}

// --- helpers ---

func fakeResponse(body string) *http.Response {
	return &http.Response{
		StatusCode: 200,
		Body:       io.NopCloser(strings.NewReader(body)),
		Header:     http.Header{},
	}
}

func hasAnomaly(p Payload, name string) bool {
	for _, a := range p.Anomaly {
		if a == name {
			return true
		}
	}
	return false
}

func hasAnomalyPrefix(p Payload, prefix string) bool {
	for _, a := range p.Anomaly {
		if strings.HasPrefix(a, prefix) {
			return true
		}
	}
	return false
}
