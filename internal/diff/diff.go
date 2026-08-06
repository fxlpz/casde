// Package diff implementa a lógica de comparação de estado entre execuções.
//
// O modelo é inspirado em git: cada execução produz um "commit" e o diff
// compara o conjunto de snapshots atual contra o commit anterior.
//
// Comparação por URL: dois snapshots são "o mesmo asset" quando têm a mesma
// URL (canônica). A mudança é detectada por: status code, body hash ou
// headers (já normalizados no fetch).
package diff

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"

	"github.com/fxlpz/casde/internal/store"
)

// ChangeKind descreve o tipo de mudança de um asset.
type ChangeKind string

const (
	KindAdded    ChangeKind = "added"    // asset novo (não existia no commit anterior)
	KindRemoved  ChangeKind = "removed"  // asset sumiu do snapshot atual
	KindChanged  ChangeKind = "changed"  // asset mudou (hash/status/headers)
	KindUnchanged ChangeKind = "unchanged"
)

// Item é uma linha do diff (por asset).
type Item struct {
	URL         string     `json:"url"`
	Kind        ChangeKind `json:"kind"`
	OldStatus   *int       `json:"old_status,omitempty"`
	NewStatus   *int       `json:"new_status,omitempty"`
	OldBodyHash string     `json:"old_body_hash,omitempty"`
	NewBodyHash string     `json:"new_body_hash,omitempty"`
	Reason      string     `json:"reason,omitempty"` // por que mudou
}

// Result é o diff completo entre dois commits.
type Result struct {
	Target    string `json:"target"`
	Changed   []Item `json:"changes"`
	Added     []Item `json:"added"`
	Removed   []Item `json:"removed"`
	Unchanged int    `json:"unchanged"`
}

// keyFor gera a chave canônica de um snapshot (URL já é única por asset).
// Usamos a URL como chave de identidade entre commits.
func keyFor(url string) string { return url }

// Compare produz o diff entre o estado atual (cur) e o anterior (prev).
// prev == nil => primeiro commit (tudo é "added").
//
// Regra de detecção de mudança:
//   - URL presente em cur mas não em prev => added
//   - URL presente em prev mas não em cur => removed
//   - URL nos dois, mas status/hash/headers diferentes => changed
//
// NOTA: falhas de rede (Result.Error != "") são tratadas como "asset com
// estado não observado" e NÃO contam como removed (evita falso-positivo de
// remoção quando o alvo está instável). Decisão deliberada de design.
func Compare(target string, cur []SnapshotState, prev []SnapshotState) Result {
	res := Result{Target: target}

	curMap := map[string]SnapshotState{}
	for _, s := range cur {
		curMap[keyFor(s.URL)] = s
	}
	prevMap := map[string]SnapshotState{}
	for _, s := range prev {
		prevMap[keyFor(s.URL)] = s
	}

	// Chaves únicas ordenadas (saída determinística).
	keys := map[string]bool{}
	for k := range curMap {
		keys[k] = true
	}
	for k := range prevMap {
		keys[k] = true
	}
	sorted := make([]string, 0, len(keys))
	for k := range keys {
		sorted = append(sorted, k)
	}
	sort.Strings(sorted)

	for _, k := range sorted {
		c, inCur := curMap[k]
		p, inPrev := prevMap[k]

		switch {
		case !inCur && !inPrev:
			continue // impossível
		case inCur && !inPrev:
			res.Added = append(res.Added, Item{
				URL: c.URL, Kind: KindAdded,
				NewStatus: intPtr(c.StatusCode), NewBodyHash: c.BodyHash,
				Reason: "asset não observado no commit anterior",
			})
		case !inCur && inPrev:
			res.Removed = append(res.Removed, Item{
				URL: p.URL, Kind: KindRemoved,
				OldStatus: intPtr(p.StatusCode), OldBodyHash: p.BodyHash,
				Reason: "asset ausente no snapshot atual",
			})
		default:
			if snapshotsEqual(p, c) {
				res.Unchanged++
			} else {
				res.Changed = append(res.Changed, Item{
					URL: c.URL, Kind: KindChanged,
					OldStatus: intPtr(p.StatusCode), NewStatus: intPtr(c.StatusCode),
					OldBodyHash: p.BodyHash, NewBodyHash: c.BodyHash,
					Reason: changeReason(p, c),
				})
			}
		}
	}
	return res
}

// SnapshotState é a visão de snapshot usada no diff (desacoplada do store).
type SnapshotState struct {
	URL         string
	StatusCode  int
	BodyHash    string
	HeadersJSON string
}

// snapshotsEqual compara status + hash + headers.
func snapshotsEqual(a, b SnapshotState) bool {
	return a.StatusCode == b.StatusCode &&
		a.BodyHash == b.BodyHash &&
		a.HeadersJSON == b.HeadersJSON
}

func changeReason(prev, cur SnapshotState) string {
	var reasons []string
	if prev.StatusCode != cur.StatusCode {
		reasons = append(reasons, "status")
	}
	if prev.BodyHash != cur.BodyHash {
		reasons = append(reasons, "body")
	}
	if prev.HeadersJSON != cur.HeadersJSON {
		reasons = append(reasons, "headers")
	}
	if len(reasons) == 0 {
		return "desconhecido"
	}
	return joinReasons(reasons)
}

func joinReasons(r []string) string {
	out := ""
	for i, s := range r {
		if i > 0 {
			out += ", "
		}
		out += s
	}
	return out
}

func intPtr(v int) *int { return &v }

// CommitHash calcula o hash do estado agregado (identifica o commit).
// Inclui target + todos os snapshots ordenados. Se o estado não mudou em
// relação ao anterior, o hash é igual => "commit vazio" (nada mudou).
func CommitHash(target string, states []SnapshotState) string {
	h := sha256.New()
	h.Write([]byte(target))
	sort.Slice(states, func(i, j int) bool { return states[i].URL < states[j].URL })
	for _, s := range states {
		h.Write([]byte(s.URL))
		h.Write([]byte{0})
		h.Write([]byte(itoa(s.StatusCode)))
		h.Write([]byte{0})
		h.Write([]byte(s.BodyHash))
		h.Write([]byte{0})
		h.Write([]byte(s.HeadersJSON))
		h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil))
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}

// ToSummary converte o Result para o formato persistido (store.DiffSummary).
func ToSummary(res Result, commitHash string) store.DiffSummary {
	var added, removed, changed []string
	for _, a := range res.Added {
		added = append(added, a.URL)
	}
	for _, r := range res.Removed {
		removed = append(removed, r.URL)
	}
	for _, c := range res.Changed {
		changed = append(changed, c.URL)
	}
	return store.DiffSummary{
		Target:      res.Target,
		CommitHash:  commitHash,
		NewAssets:   added,
		Removed:     removed,
		Changed:     changed,
		Unchanged:   res.Unchanged,
		AssetsTotal: len(added) + len(removed) + len(changed) + res.Unchanged,
	}
}

// JSON serializa o Result de forma legível (saída principal da CLI).
func JSON(res Result) (string, error) {
	b, err := json.MarshalIndent(res, "", "  ")
	return string(b), err
}
