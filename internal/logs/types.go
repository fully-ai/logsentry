package logs

import "time"

type Level string

const (
	LevelDebug Level = "DEBUG"
	LevelInfo  Level = "INFO"
	LevelWarn  Level = "WARN"
	LevelError Level = "ERROR"
	LevelFatal Level = "FATAL"
)

type Entry struct {
	Timestamp time.Time         `json:"timestamp"`
	Format    string            `json:"format"`
	Level     Level             `json:"level"`
	Source    string            `json:"source"`
	Category  string            `json:"category"`
	Message   string            `json:"message"`
	Raw       string            `json:"raw"`
	Fields    map[string]string `json:"fields,omitempty"`
}

type Query struct {
	From     time.Time
	To       time.Time
	Level    Level
	Category string
	Search   string
	Limit    int
}

type AlertRule struct {
	Name        string `json:"name"`
	Category    string `json:"category,omitempty"`
	Level       Level  `json:"level,omitempty"`
	Pattern     string `json:"pattern,omitempty"`
	Threshold   int    `json:"threshold"`
	WindowSec   int    `json:"window_sec"`
	WebhookURL  string `json:"webhook_url,omitempty"`
}

type AlertEvent struct {
	RuleName    string    `json:"rule_name"`
	Severity    string    `json:"severity"`
	Message     string    `json:"message"`
	Count       int       `json:"count"`
	TriggeredAt time.Time `json:"triggered_at"`
}
