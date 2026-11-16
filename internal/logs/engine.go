package logs

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

type Engine struct {
	mu          sync.RWMutex
	entries     []Entry
	maxEntries  int
	rules       []AlertRule
	alerts      []AlertEvent
	ruleHistory map[string][]time.Time
	httpClient  *http.Client
}

func NewEngine(maxEntries int, rules []AlertRule) *Engine {
	if maxEntries <= 0 {
		maxEntries = 10000
	}
	return &Engine{
		maxEntries:  maxEntries,
		rules:       rules,
		ruleHistory: make(map[string][]time.Time),
		httpClient:  &http.Client{Timeout: 5 * time.Second},
	}
}

func (e *Engine) AddRule(rule AlertRule) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.rules = append(e.rules, rule)
}

func (e *Engine) IngestLine(line, source string) Entry {
	entry := ParseLine(line, source)
	e.IngestEntry(entry)
	return entry
}

func (e *Engine) IngestEntry(entry Entry) {
	e.mu.Lock()
	if len(e.entries) >= e.maxEntries {
		copy(e.entries, e.entries[1:])
		e.entries[len(e.entries)-1] = entry
	} else {
		e.entries = append(e.entries, entry)
	}
	triggered := e.evaluateRulesLocked(entry)
	e.mu.Unlock()

	for _, ev := range triggered {
		e.dispatchWebhook(ev)
	}
}

func (e *Engine) evaluateRulesLocked(entry Entry) []struct {
	ev  AlertEvent
	url string
} {
	var toDispatch []struct {
		ev  AlertEvent
		url string
	}
	now := entry.Timestamp
	if now.IsZero() {
		now = time.Now().UTC()
	}

	for _, rule := range e.rules {
		if rule.Level != "" && entry.Level != rule.Level {
			continue
		}
		if rule.Category != "" && entry.Category != rule.Category {
			continue
		}
		if rule.Pattern != "" && !strings.Contains(strings.ToLower(entry.Message), strings.ToLower(rule.Pattern)) {
			continue
		}
		win := time.Duration(max(1, rule.WindowSec)) * time.Second
		cutoff := now.Add(-win)
		hist := e.ruleHistory[rule.Name]
		var kept []time.Time
		for _, ts := range hist {
			if !ts.Before(cutoff) {
				kept = append(kept, ts)
			}
		}
		kept = append(kept, now)
		e.ruleHistory[rule.Name] = kept

		if len(kept) >= max(1, rule.Threshold) {
			ev := AlertEvent{
				RuleName:    rule.Name,
				Severity:    string(entry.Level),
				Message:     fmt.Sprintf("Rule %q triggered (%d matches in %ds): %s", rule.Name, len(kept), rule.WindowSec, entry.Message),
				Count:       len(kept),
				TriggeredAt: time.Now().UTC(),
			}
			e.alerts = append(e.alerts, ev)
			if rule.WebhookURL != "" {
				toDispatch = append(toDispatch, struct {
					ev  AlertEvent
					url string
				}{ev: ev, url: rule.WebhookURL})
			}
		}
	}
	return toDispatch
}

func (e *Engine) dispatchWebhook(item struct {
	ev  AlertEvent
	url string
}) {
	body, err := json.Marshal(item.ev)
	if err != nil {
		return
	}
	req, err := http.NewRequest(http.MethodPost, item.url, bytes.NewReader(body))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := e.httpClient.Do(req)
	if err == nil {
		_ = resp.Body.Close()
	}
}

func (e *Engine) Query(q Query) []Entry {
	e.mu.RLock()
	defer e.mu.RUnlock()

	limit := q.Limit
	if limit <= 0 {
		limit = 200
	}
	searchLower := strings.ToLower(q.Search)
	var out []Entry
	for i := len(e.entries) - 1; i >= 0; i-- {
		ent := e.entries[i]
		if !q.From.IsZero() && ent.Timestamp.Before(q.From) {
			continue
		}
		if !q.To.IsZero() && ent.Timestamp.After(q.To) {
			continue
		}
		if q.Level != "" && ent.Level != q.Level {
			continue
		}
		if q.Category != "" && ent.Category != q.Category {
			continue
		}
		if searchLower != "" && !strings.Contains(strings.ToLower(ent.Raw), searchLower) {
			continue
		}
		out = append(out, ent)
		if len(out) >= limit {
			break
		}
	}
	return out
}

func (e *Engine) Alerts() []AlertEvent {
	e.mu.RLock()
	defer e.mu.RUnlock()
	out := make([]AlertEvent, len(e.alerts))
	copy(out, e.alerts)
	return out
}

type Stats struct {
	TotalEntries   int            `json:"total_entries"`
	ErrorCount     int            `json:"error_count"`
	ByLevel        map[string]int `json:"by_level"`
	ByCategory     map[string]int `json:"by_category"`
	ByFormat       map[string]int `json:"by_format"`
	AnomalyDetected bool          `json:"anomaly_detected"`
	AnomalyReason  string         `json:"anomaly_reason,omitempty"`
}

// AnalyzeStats computes distributions and detects error-rate spikes per minute using z-score > 2.0.
func (e *Engine) AnalyzeStats(bucketSize time.Duration) Stats {
	e.mu.RLock()
	defer e.mu.RUnlock()

	if bucketSize <= 0 {
		bucketSize = time.Minute
	}
	st := Stats{
		TotalEntries: len(e.entries),
		ByLevel:      make(map[string]int),
		ByCategory:   make(map[string]int),
		ByFormat:     make(map[string]int),
	}

	buckets := make(map[int64]int)
	var latestBucket int64
	for _, ent := range e.entries {
		st.ByLevel[string(ent.Level)]++
		st.ByCategory[ent.Category]++
		st.ByFormat[ent.Format]++
		b := ent.Timestamp.UnixNano() / bucketSize.Nanoseconds()
		if b > latestBucket {
			latestBucket = b
		}
		if ent.Level == LevelError || ent.Level == LevelFatal {
			st.ErrorCount++
			buckets[b]++
		}
	}

	if len(buckets) >= 3 {
		var vals []float64
		for b, cnt := range buckets {
			if b != latestBucket {
				vals = append(vals, float64(cnt))
			}
		}
		if len(vals) >= 2 {
			mean, std := meanStdDev(vals)
			latest := float64(buckets[latestBucket])
			if latest >= 3 && latest > mean+2.0*std {
				st.AnomalyDetected = true
				st.AnomalyReason = fmt.Sprintf("error spike in latest bucket: %.0f errors (baseline mean=%.2f, std=%.2f)", latest, mean, std)
			}
		}
	}
	return st
}

func meanStdDev(vals []float64) (float64, float64) {
	var sum float64
	for _, v := range vals {
		sum += v
	}
	mean := sum / float64(len(vals))
	var sq float64
	for _, v := range vals {
		d := v - mean
		sq += d * d
	}
	return mean, math.Sqrt(sq / float64(len(vals)))
}

// TailFile reads existing lines from path and streams newly appended lines until ctx is cancelled.
func TailFile(ctx context.Context, path string, engine *Engine, pollInterval time.Duration) error {
	if pollInterval <= 0 {
		pollInterval = 200 * time.Millisecond
	}
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()

	reader := bufio.NewReader(f)
	source := filepath.Base(path)
	for {
		line, err := reader.ReadString('\n')
		if len(line) > 0 {
			trimmed := strings.TrimRight(line, "\r\n")
			if trimmed != "" {
				engine.IngestLine(trimmed, source)
			}
		}
		if err == io.EOF {
			select {
			case <-ctx.Done():
				return nil
			case <-time.After(pollInterval):
			}
			continue
		}
		if err != nil {
			return err
		}
	}
}

// ArchiveFile compresses srcPath to dstDir/<name>.<timestamp>.gz.
func ArchiveFile(srcPath, dstDir string) (string, error) {
	if err := os.MkdirAll(dstDir, 0o755); err != nil {
		return "", err
	}
	in, err := os.Open(srcPath)
	if err != nil {
		return "", err
	}
	defer in.Close()

	base := filepath.Base(srcPath)
	outName := fmt.Sprintf("%s.%s.gz", base, time.Now().UTC().Format("20060102T150405Z"))
	outPath := filepath.Join(dstDir, outName)
	out, err := os.Create(outPath)
	if err != nil {
		return "", err
	}
	defer out.Close()

	gz := gzip.NewWriter(out)
	if _, err := io.Copy(gz, in); err != nil {
		_ = gz.Close()
		return "", err
	}
	if err := gz.Close(); err != nil {
		return "", err
	}
	return outPath, nil
}
