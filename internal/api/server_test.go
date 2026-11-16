package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/fully-ai/logsentry/internal/logs"
)

func TestAPIIngestQueryRulesAndStats(t *testing.T) {
	engine := logs.NewEngine(1000, nil)
	h := NewHandler(engine)

	ruleBody := bytes.NewBufferString(`{"name":"err-rule","level":"ERROR","threshold":1,"window_sec":60}`)
	reqRule := httptest.NewRequest(http.MethodPost, "/api/rules", ruleBody)
	wRule := httptest.NewRecorder()
	h.ServeHTTP(wRule, reqRule)
	if wRule.Code != http.StatusCreated {
		t.Fatalf("expected 201 for rule creation, got %d", wRule.Code)
	}

	ingestBody := bytes.NewBufferString(`{"source":"api","lines":["2026-11-16T10:00:00Z ERROR database timeout","2026-11-16T10:00:05Z INFO healthy"]}`)
	reqIng := httptest.NewRequest(http.MethodPost, "/api/ingest", ingestBody)
	wIng := httptest.NewRecorder()
	h.ServeHTTP(wIng, reqIng)
	if wIng.Code != http.StatusCreated {
		t.Fatalf("expected 201 for ingest, got %d", wIng.Code)
	}

	wLogs := httptest.NewRecorder()
	h.ServeHTTP(wLogs, httptest.NewRequest(http.MethodGet, "/api/logs?level=ERROR&q=database", nil))
	if wLogs.Code != http.StatusOK {
		t.Fatalf("expected 200 for query, got %d", wLogs.Code)
	}
	var res struct {
		Entries []logs.Entry `json:"entries"`
	}
	if err := json.Unmarshal(wLogs.Body.Bytes(), &res); err != nil || len(res.Entries) != 1 {
		t.Fatalf("expected 1 filtered entry, got %+v (err=%v)", res, err)
	}

	wAlerts := httptest.NewRecorder()
	h.ServeHTTP(wAlerts, httptest.NewRequest(http.MethodGet, "/api/alerts", nil))
	var alertRes struct {
		Alerts []logs.AlertEvent `json:"alerts"`
	}
	if err := json.Unmarshal(wAlerts.Body.Bytes(), &alertRes); err != nil || len(alertRes.Alerts) != 1 {
		t.Fatalf("expected 1 alert event, got %+v", alertRes)
	}

	// Time-range filtering
	wRange := httptest.NewRecorder()
	h.ServeHTTP(wRange, httptest.NewRequest(http.MethodGet, "/api/logs?from=2026-11-16T10:00:02Z&to=2026-11-16T10:00:10Z", nil))
	var rangeRes struct {
		Entries []logs.Entry `json:"entries"`
	}
	if err := json.Unmarshal(wRange.Body.Bytes(), &rangeRes); err != nil || len(rangeRes.Entries) != 1 {
		t.Fatalf("expected 1 entry in time range, got %+v", rangeRes)
	}

	// Invalid rule name rejected
	wBadRule := httptest.NewRecorder()
	h.ServeHTTP(wBadRule, httptest.NewRequest(http.MethodPost, "/api/rules", bytes.NewBufferString(`{"threshold":1}`)))
	if wBadRule.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for missing rule name, got %d", wBadRule.Code)
	}
}
