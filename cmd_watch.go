package main

import (
	"encoding/json"
	"fmt"
	"time"

	"gopkg.in/yaml.v3"
)

type watchConfig struct {
	Enabled       bool
	UntilOK       bool
	Interval      time.Duration
	Timeout       time.Duration
	MaxIterations int
}

func normalizeWatchConfig(enabled, untilOK bool, interval, timeout time.Duration, maxIterations int) (watchConfig, error) {
	if untilOK {
		enabled = true
	}
	if enabled && interval <= 0 {
		return watchConfig{}, fmt.Errorf("--interval must be greater than zero")
	}
	if maxIterations < 0 {
		return watchConfig{}, fmt.Errorf("--max-iterations cannot be negative")
	}
	return watchConfig{
		Enabled:       enabled,
		UntilOK:       untilOK,
		Interval:      interval,
		Timeout:       timeout,
		MaxIterations: maxIterations,
	}, nil
}

func watchLoop(cfg watchConfig, format outputFormat, run func() (any, bool, error), renderRaw func(any)) error {
	deadline := time.Time{}
	if cfg.Timeout > 0 {
		deadline = time.Now().Add(cfg.Timeout)
	}
	iteration := 0
	for {
		iteration++
		result, healthy, err := run()
		if err != nil {
			return err
		}
		switch format {
		case outputJSON:
			_ = json.NewEncoder(stdoutWriter{}).Encode(map[string]any{
				"timestamp": time.Now().UTC().Format(time.RFC3339),
				"iteration": iteration,
				"healthy":   healthy,
				"result":    result,
			})
		case outputYAML:
			_ = yaml.NewEncoder(stdoutWriter{}).Encode(map[string]any{
				"timestamp": time.Now().UTC().Format(time.RFC3339),
				"iteration": iteration,
				"healthy":   healthy,
				"result":    result,
			})
		default:
			if iteration > 1 {
				fmt.Println()
			}
			fmt.Printf("[%s] iteration %d\n\n", time.Now().Format("2006-01-02 15:04:05"), iteration)
			renderRaw(result)
		}
		if cfg.UntilOK && healthy {
			return nil
		}
		if cfg.MaxIterations > 0 && iteration >= cfg.MaxIterations {
			if cfg.UntilOK && !healthy {
				return fmt.Errorf("condition not healthy after %d iteration(s)", iteration)
			}
			return nil
		}
		if !deadline.IsZero() && time.Now().Add(cfg.Interval).After(deadline) {
			if cfg.UntilOK && !healthy {
				return fmt.Errorf("condition not healthy before timeout")
			}
			return nil
		}
		time.Sleep(cfg.Interval)
	}
}

type stdoutWriter struct{}

func (stdoutWriter) Write(p []byte) (int, error) {
	return fmt.Print(string(p))
}
