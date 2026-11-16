package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/fully-ai/logsentry/internal/api"
	"github.com/fully-ai/logsentry/internal/logs"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: logsentry <serve|archive|analyze> [flags]")
		os.Exit(1)
	}

	switch os.Args[1] {
	case "serve":
		runServe(os.Args[2:])
	case "archive":
		runArchive(os.Args[2:])
	case "analyze":
		runAnalyze(os.Args[2:])
	default:
		fmt.Println("Usage: logsentry <serve|archive|analyze> [flags]")
		os.Exit(1)
	}
}

func runServe(args []string) {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	addr := fs.String("addr", "127.0.0.1:8095", "HTTP dashboard listen address")
	watchFile := fs.String("file", "", "Optional log file path to tail in real time")
	rulesFile := fs.String("rules", "", "Optional JSON alert rules file")
	_ = fs.Parse(args)

	var rules []logs.AlertRule
	if *rulesFile != "" {
		raw, err := os.ReadFile(*rulesFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "failed to read rules: %v\n", err)
			os.Exit(1)
		}
		if err := json.Unmarshal(raw, &rules); err != nil {
			fmt.Fprintf(os.Stderr, "invalid rules JSON: %v\n", err)
			os.Exit(1)
		}
	}

	engine := logs.NewEngine(20000, rules)
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	if *watchFile != "" {
		go func() {
			if err := logs.TailFile(ctx, *watchFile, engine, 200*time.Millisecond); err != nil {
				fmt.Fprintf(os.Stderr, "tail error: %v\n", err)
			}
		}()
	}

	srv := &http.Server{Addr: *addr, Handler: api.NewHandler(engine)}
	go func() {
		<-ctx.Done()
		_ = srv.Shutdown(context.Background())
	}()

	fmt.Printf("LogSentry listening on http://%s\n", *addr)
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		fmt.Fprintf(os.Stderr, "server error: %v\n", err)
		os.Exit(1)
	}
}

func runArchive(args []string) {
	fs := flag.NewFlagSet("archive", flag.ExitOnError)
	src := fs.String("file", "", "Log file to archive")
	dst := fs.String("dir", "./archives", "Destination archive directory")
	_ = fs.Parse(args)

	if *src == "" {
		fmt.Fprintln(os.Stderr, "error: -file is required")
		os.Exit(2)
	}
	outPath, err := logs.ArchiveFile(*src, *dst)
	if err != nil {
		fmt.Fprintf(os.Stderr, "archive failed: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("Archived:", outPath)
}

func runAnalyze(args []string) {
	fs := flag.NewFlagSet("analyze", flag.ExitOnError)
	src := fs.String("file", "", "Log file to analyze")
	_ = fs.Parse(args)
	if *src == "" {
		fmt.Fprintln(os.Stderr, "error: -file is required")
		os.Exit(2)
	}
	raw, err := os.ReadFile(*src)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error reading file: %v\n", err)
		os.Exit(1)
	}
	engine := logs.NewEngine(50000, nil)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_ = ctx
	for _, line := range splitLines(string(raw)) {
		engine.IngestLine(line, *src)
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	_ = enc.Encode(engine.AnalyzeStats(time.Minute))
}

func splitLines(s string) []string {
	var out []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' {
			if i > start {
				out = append(out, s[start:i])
			}
			start = i + 1
		}
	}
	if start < len(s) {
		out = append(out, s[start:])
	}
	return out
}
