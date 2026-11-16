package logs

import (
	"encoding/json"
	"regexp"
	"strconv"
	"strings"
	"time"
)

var (
	nginxRe = regexp.MustCompile(`^(\S+)\s+\S+\s+(\S+)\s+\[([^\]]+)\]\s+"([A-Z]+)\s+(\S+)\s+[^"]+"\s+(\d{3})\s+(\d+|-)`)
	syslogRe = regexp.MustCompile(`^(?:<\d+>)?([A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+([^\[:]+)(?:\[\d+\])?:\s+(.*)$`)
	genericRe = regexp.MustCompile(`^(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)\s+(DEBUG|INFO|WARN|WARNING|ERROR|FATAL|CRITICAL)\s+(.*)$`)
)

// ParseLine parses JSON lines, Nginx/Apache Combined access logs, Syslog RFC3164, or timestamped text logs.
func ParseLine(line, source string) Entry {
	trimmed := strings.TrimSpace(line)
	now := time.Now().UTC()

	// 1. JSON log
	if strings.HasPrefix(trimmed, "{") {
		var raw map[string]any
		if err := json.Unmarshal([]byte(trimmed), &raw); err == nil {
			e := Entry{
				Timestamp: now,
				Format:    "json",
				Level:     LevelInfo,
				Source:    source,
				Raw:       trimmed,
				Fields:    make(map[string]string),
			}
			for _, k := range []string{"ts", "timestamp", "time", "@timestamp"} {
				if v, ok := raw[k].(string); ok {
					if parsed, err := parseAnyTime(v); err == nil {
						e.Timestamp = parsed
						break
					}
				}
			}
			if lvl, ok := raw["level"].(string); ok {
				e.Level = normalizeLevel(lvl)
			} else if lvl, ok := raw["severity"].(string); ok {
				e.Level = normalizeLevel(lvl)
			}
			for _, mk := range []string{"msg", "message", "error"} {
				if m, ok := raw[mk].(string); ok && m != "" {
					e.Message = m
					break
				}
			}
			if e.Message == "" {
				e.Message = trimmed
			}
			for k, v := range raw {
				if s, ok := v.(string); ok {
					e.Fields[k] = s
				}
			}
			e.Category = Classify(e.Message, e.Level, 0)
			return e
		}
	}

	// 2. Nginx / Apache Combined
	if m := nginxRe.FindStringSubmatch(trimmed); m != nil {
		status, _ := strconv.Atoi(m[6])
		ts, err := time.Parse("02/Jan/2006:15:04:05 -0700", m[3])
		if err != nil {
			ts = now
		}
		lvl := LevelInfo
		if status >= 500 {
			lvl = LevelError
		} else if status >= 400 {
			lvl = LevelWarn
		}
		msg := m[4] + " " + m[5] + " -> " + m[6]
		return Entry{
			Timestamp: ts.UTC(),
			Format:    "access",
			Level:     lvl,
			Source:    source,
			Category:  Classify(msg, lvl, status),
			Message:   msg,
			Raw:       trimmed,
			Fields:    map[string]string{"client_ip": m[1], "method": m[4], "path": m[5], "status": m[6]},
		}
	}

	// 3. Syslog RFC3164
	if m := syslogRe.FindStringSubmatch(trimmed); m != nil {
		ts, err := time.Parse("Jan _2 15:04:05", m[1])
		if err == nil {
			ts = ts.AddDate(now.Year(), 0, 0).UTC()
		} else {
			ts = now
		}
		lvl := inferLevelFromText(m[4])
		return Entry{
			Timestamp: ts,
			Format:    "syslog",
			Level:     lvl,
			Source:    m[2] + "/" + m[3],
			Category:  Classify(m[4], lvl, 0),
			Message:   m[4],
			Raw:       trimmed,
			Fields:    map[string]string{"host": m[2], "program": m[3]},
		}
	}

	// 4. Generic timestamped log
	if m := genericRe.FindStringSubmatch(trimmed); m != nil {
		ts, err := parseAnyTime(m[1])
		if err != nil {
			ts = now
		}
		lvl := normalizeLevel(m[2])
		return Entry{
			Timestamp: ts,
			Format:    "generic",
			Level:     lvl,
			Source:    source,
			Category:  Classify(m[3], lvl, 0),
			Message:   m[3],
			Raw:       trimmed,
		}
	}

	// Fallback unstructured line
	lvl := inferLevelFromText(trimmed)
	return Entry{
		Timestamp: now,
		Format:    "raw",
		Level:     lvl,
		Source:    source,
		Category:  Classify(trimmed, lvl, 0),
		Message:   trimmed,
		Raw:       trimmed,
	}
}

func Classify(msg string, lvl Level, httpStatus int) string {
	lower := strings.ToLower(msg)
	if httpStatus >= 500 {
		return "http_5xx"
	}
	if httpStatus >= 400 {
		return "http_4xx"
	}
	switch {
	case strings.Contains(lower, "panic") || strings.Contains(lower, "segfault") || strings.Contains(lower, "fatal"):
		return "crash"
	case strings.Contains(lower, "unauthorized") || strings.Contains(lower, "authentication failed") || strings.Contains(lower, "invalid password") || strings.Contains(lower, "permission denied"):
		return "auth_failure"
	case strings.Contains(lower, "timeout") || strings.Contains(lower, "deadline exceeded"):
		return "timeout"
	case strings.Contains(lower, "sql") || strings.Contains(lower, "database") || strings.Contains(lower, "deadlock"):
		return "database_error"
	case strings.Contains(lower, "out of memory") || strings.Contains(lower, "no space left"):
		return "resource_exhaustion"
	case lvl == LevelError || lvl == LevelFatal:
		return "general_error"
	default:
		return "normal"
	}
}

func normalizeLevel(s string) Level {
	switch strings.ToUpper(strings.TrimSpace(s)) {
	case "DEBUG":
		return LevelDebug
	case "WARN", "WARNING":
		return LevelWarn
	case "ERROR", "ERR":
		return LevelError
	case "FATAL", "CRITICAL", "CRIT":
		return LevelFatal
	default:
		return LevelInfo
	}
}

func inferLevelFromText(s string) Level {
	upper := strings.ToUpper(s)
	switch {
	case strings.Contains(upper, "FATAL") || strings.Contains(upper, "PANIC"):
		return LevelFatal
	case strings.Contains(upper, "ERROR") || strings.Contains(upper, "FAILED"):
		return LevelError
	case strings.Contains(upper, "WARN"):
		return LevelWarn
	default:
		return LevelInfo
	}
}

func parseAnyTime(s string) (time.Time, error) {
	for _, layout := range []string{
		time.RFC3339Nano,
		time.RFC3339,
		"2006-01-02 15:04:05",
		"2006-01-02T15:04:05",
	} {
		if t, err := time.Parse(layout, s); err == nil {
			return t.UTC(), nil
		}
	}
	return time.Time{}, strconv.ErrSyntax
}
