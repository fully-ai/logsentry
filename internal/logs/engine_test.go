package logs

import (
	"compress/gzip"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestMultiFormatParserAndClassification(t *testing.T) {
	j := ParseLine(`{"timestamp":"2026-11-16T10:00:00Z","level":"error","msg":"database deadlock detected"}`, "app")
	if j.Format != "json" || j.Level != LevelError || j.Category != "database_error" {
		t.Fatalf("unexpected json entry: %+v", j)
	}

	n := ParseLine(`10.0.0.5 - - [16/Nov/2026:10:01:00 +0000] "GET /api/login HTTP/1.1" 502 124 "-" "curl/8.0"`, "nginx")
	if n.Format != "access" || n.Level != LevelError || n.Category != "http_5xx" {
		t.Fatalf("unexpected access entry: %+v", n)
	}

	s := ParseLine(`<34>Nov 16 10:02:00 web01 sshd[1234]: Authentication failed for admin`, "syslog")
	if s.Format != "syslog" || s.Category != "auth_failure" {
		t.Fatalf("unexpected syslog entry: %+v", s)
	}

	g := ParseLine(`2026-11-16T10:03:00Z WARN upstream timeout while reading body`, "worker")
	if g.Format != "generic" || g.Level != LevelWarn || g.Category != "timeout" {
		t.Fatalf("unexpected generic entry: %+v", g)
	}
}

func TestAnomalyDetectionRulesWebhooksTailAndArchive(t *testing.T) {
	var webhookHits int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var ev AlertEvent
		if err := json.NewDecoder(r.Body).Decode(&ev); err == nil && ev.RuleName == "auth-burst" {
			webhookHits++
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	engine := NewEngine(1000, []AlertRule{
		{
			Name:       "auth-burst",
			Category:   "auth_failure",
			Threshold:  2,
			WindowSec:  120,
			WebhookURL: srv.URL,
		},
	})

	base := time.Date(2026, 11, 16, 12, 0, 0, 0, time.UTC)
	// Baseline minutes: 1 error per minute
	for m := 0; m < 4; m++ {
		engine.IngestEntry(Entry{
			Timestamp: base.Add(time.Duration(m) * time.Minute),
			Format:    "json",
			Level:     LevelError,
			Category:  "timeout",
			Message:   "timeout",
			Raw:       "timeout",
		})
	}
	// Spike in minute 5: 6 errors
	for i := 0; i < 6; i++ {
		engine.IngestEntry(Entry{
			Timestamp: base.Add(5 * time.Minute),
			Format:    "json",
			Level:     LevelError,
			Category:  "auth_failure",
			Message:   "invalid password",
			Raw:       "invalid password",
		})
	}

	stats := engine.AnalyzeStats(time.Minute)
	if !stats.AnomalyDetected {
		t.Fatalf("expected error spike anomaly to be detected, got %+v", stats)
	}
	if len(engine.Alerts()) == 0 || webhookHits == 0 {
		t.Fatalf("expected rule alerts and webhook hits, alerts=%d hits=%d", len(engine.Alerts()), webhookHits)
	}

	// TailFile & ArchiveFile
	tmp := t.TempDir()
	logPath := filepath.Join(tmp, "app.log")
	if err := os.WriteFile(logPath, []byte("2026-11-16T12:10:00Z INFO startup complete\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 250*time.Millisecond)
	defer cancel()
	_ = TailFile(ctx, logPath, engine, 50*time.Millisecond)

	res := engine.Query(Query{Search: "startup"})
	if len(res) != 1 {
		t.Fatalf("expected tailed log entry, got %d", len(res))
	}

	gzPath, err := ArchiveFile(logPath, filepath.Join(tmp, "arch"))
	if err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(gzPath)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	gr, err := gzip.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}
	defer gr.Close()
	raw, _ := io.ReadAll(gr)
	if string(raw) != "2026-11-16T12:10:00Z INFO startup complete\n" {
		t.Fatalf("unexpected archived content: %q", string(raw))
	}
}
