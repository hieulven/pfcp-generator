package stats

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
)

// Reporter outputs statistics to console and/or file.
type Reporter struct {
	collector  *Collector
	intervalSec int
	exportFile string
}

// NewReporter creates a new statistics reporter.
func NewReporter(collector *Collector, intervalSec int, exportFile string) *Reporter {
	return &Reporter{
		collector:  collector,
		intervalSec: intervalSec,
		exportFile: exportFile,
	}
}

// StartPeriodicReport begins periodic statistics reporting in a goroutine.
func (r *Reporter) StartPeriodicReport(ctx context.Context) {
	if r.intervalSec <= 0 {
		return
	}

	go func() {
		ticker := time.NewTicker(time.Duration(r.intervalSec) * time.Second)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				fmt.Println(r.FormatReport())
			}
		}
	}()
}

// PrintFinalReport prints the final statistics summary.
func (r *Reporter) PrintFinalReport() {
	r.collector.Finish()
	fmt.Println(r.FormatReport())
}

// ExportJSON exports statistics to a JSON file.
func (r *Reporter) ExportJSON() error {
	if r.exportFile == "" {
		return nil
	}

	snap := r.collector.Snapshot()
	min, avg, max, p99 := snap.ResponseTimeStats()

	export := map[string]interface{}{
		"start_time":   snap.StartTime.Format(time.RFC3339),
		"end_time":     snap.EndTime.Format(time.RFC3339),
		"duration_sec": snap.Duration().Seconds(),
		"messages":     map[string]interface{}{},
		"sessions": map[string]interface{}{
			"established": snap.SessionsEstablished,
			"modified":    snap.SessionsModified,
			"deleted":     snap.SessionsDeleted,
			"failed":      snap.SessionsFailed,
			"active":      snap.ActiveSessions,
		},
		"response_times_ms": map[string]interface{}{
			"min": float64(min) / float64(time.Millisecond),
			"avg": float64(avg) / float64(time.Millisecond),
			"max": float64(max) / float64(time.Millisecond),
			"p99": float64(p99) / float64(time.Millisecond),
		},
	}

	totalSent := snap.TotalSent()
	duration := snap.Duration().Seconds()
	if duration > 0 {
		export["throughput_msg_per_sec"] = float64(totalSent) / duration
	}

	msgs := export["messages"].(map[string]interface{})
	for name, s := range snap.MessageStats {
		msgs[name] = map[string]interface{}{
			"sent":       s.Sent,
			"received":   s.Received,
			"success":    s.Success,
			"failed":     s.Failed,
			"timeout":    s.Timeout,
			"retransmit": s.Retransmit,
		}
	}

	data, err := json.MarshalIndent(export, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal stats JSON: %w", err)
	}

	if err := os.WriteFile(r.exportFile, data, 0644); err != nil {
		return fmt.Errorf("failed to write stats file %s: %w", r.exportFile, err)
	}

	log.WithField("file", r.exportFile).Info("Statistics exported to JSON")
	return nil
}

// FormatReport generates a formatted statistics report string.
func (r *Reporter) FormatReport() string {
	snap := r.collector.Snapshot()
	elapsed := snap.Duration()
	min, avg, max, p99 := snap.ResponseTimeStats()

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("\n=== PFCP Generator Statistics (elapsed: %s) ===\n", elapsed.Round(time.Second)))
	sb.WriteString("Messages:\n")

	// Sort message types for consistent output
	typeNames := make([]string, 0, len(snap.MessageStats))
	for name := range snap.MessageStats {
		typeNames = append(typeNames, name)
	}
	sort.Strings(typeNames)

	for _, name := range typeNames {
		s := snap.MessageStats[name]
		sb.WriteString(fmt.Sprintf("  %-30s sent=%-5d recv=%-5d success=%-5d fail=%-5d timeout=%-5d\n",
			name+":", s.Sent, s.Received, s.Success, s.Failed, s.Timeout))
	}

	sb.WriteString("Sessions:\n")
	sb.WriteString(fmt.Sprintf("  Established: %d  |  Active: %d  |  Deleted: %d  |  Failed: %d\n",
		snap.SessionsEstablished, snap.ActiveSessions, snap.SessionsDeleted, snap.SessionsFailed))

	if len(snap.ResponseTimes) > 0 {
		sb.WriteString("Response Times:\n")
		sb.WriteString(fmt.Sprintf("  Min: %s  |  Avg: %s  |  Max: %s  |  P99: %s\n",
			min.Round(time.Microsecond), avg.Round(time.Microsecond),
			max.Round(time.Microsecond), p99.Round(time.Microsecond)))
	}

	totalSent := snap.TotalSent()
	if elapsed.Seconds() > 0 {
		sb.WriteString("Throughput:\n")
		sb.WriteString(fmt.Sprintf("  %.1f msg/s\n", float64(totalSent)/elapsed.Seconds()))
	}

	sb.WriteString("================================================\n")
	return sb.String()
}
