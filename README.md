# LogSentry

Real-time log ingestion, multi-format parsing, error classification, anomaly detection, and alerting system written in Go.

## Features

- **Multi-Format Parsing**: Automatically parses JSON lines, Nginx/Apache Combined access logs, Syslog RFC3164, and timestamped application logs.
- **Real-Time Tailing & HTTP Ingestion**: Tail local log files (`-file`) or push structured batches via `POST /api/ingest`.
- **Error Classification**: Categorizes entries into `http_5xx`, `http_4xx`, `auth_failure`, `timeout`, `database_error`, `crash`, and `resource_exhaustion`.
- **Statistical Anomaly Detection**: Flags error spikes in the latest time bucket exceeding `mean + 2*stddev` of baseline buckets.
- **Configurable Alerts & Webhooks**: Define sliding-window threshold rules with optional HTTP webhook delivery.
- **Log Archiving & Dashboard**: Compress historical logs to `.gz` archives and monitor logs/alerts via the built-in web UI.

## Installation & Usage

```bash
git clone https://github.com/fully-ai/logsentry.git
cd logsentry
go build -o logsentry ./cmd/logsentry
./logsentry serve -addr 127.0.0.1:8095 -file /var/log/app.log
```

## Testing

```bash
go vet ./...
go test -v -race ./...
```

## License

Apache License 2.0 — see [LICENSE](LICENSE).
