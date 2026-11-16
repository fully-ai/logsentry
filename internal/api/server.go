package api

import (
	_ "embed"
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"github.com/fully-ai/logsentry/internal/logs"
)

//go:embed index.html
var indexHTML []byte

func NewHandler(engine *logs.Engine) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write(indexHTML)
	})

	mux.HandleFunc("/api/health", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})

	mux.HandleFunc("/api/ingest", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		var req struct {
			Source string   `json:"source"`
			Lines  []string `json:"lines"`
		}
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 2<<20)).Decode(&req); err != nil {
			http.Error(w, "invalid JSON", http.StatusBadRequest)
			return
		}
		if req.Source == "" {
			req.Source = "http"
		}
		for _, line := range req.Lines {
			if line != "" {
				engine.IngestLine(line, req.Source)
			}
		}
		writeJSON(w, http.StatusCreated, map[string]int{"ingested": len(req.Lines)})
	})

	mux.HandleFunc("/api/logs", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		query := logs.Query{
			Level:    logs.Level(q.Get("level")),
			Category: q.Get("category"),
			Search:   q.Get("q"),
		}
		if lim, err := strconv.Atoi(q.Get("limit")); err == nil && lim > 0 {
			query.Limit = lim
		}
		if fromStr := q.Get("from"); fromStr != "" {
			if t, err := time.Parse(time.RFC3339, fromStr); err == nil {
				query.From = t
			}
		}
		if toStr := q.Get("to"); toStr != "" {
			if t, err := time.Parse(time.RFC3339, toStr); err == nil {
				query.To = t
			}
		}
		writeJSON(w, http.StatusOK, map[string]any{"entries": engine.Query(query)})
	})

	mux.HandleFunc("/api/stats", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, engine.AnalyzeStats(time.Minute))
	})

	mux.HandleFunc("/api/alerts", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{"alerts": engine.Alerts()})
	})

	mux.HandleFunc("/api/rules", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		var rule logs.AlertRule
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&rule); err != nil || rule.Name == "" {
			http.Error(w, "invalid rule payload", http.StatusBadRequest)
			return
		}
		engine.AddRule(rule)
		writeJSON(w, http.StatusCreated, rule)
	})

	return mux
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}
