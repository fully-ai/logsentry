# Architecture — LogSentry

## Components

- `internal/logs/parser.go`: Format detection and parsing for JSON lines, Nginx/Apache Combined access logs, Syslog RFC3164, and timestamped application logs, paired with keyword/status error classification.
- `internal/logs/engine.go`: Thread-safe bounded ring buffer, sliding-window alert rule evaluator with HTTP webhook dispatch, z-score per-minute error-spike anomaly detector, real-time file tailer (`TailFile`), and gzip archiver (`ArchiveFile`).
- `internal/api/server.go`: REST endpoints (`/api/ingest`, `/api/logs`, `/api/stats`, `/api/alerts`, `/api/rules`) and embedded HTML dashboard.
