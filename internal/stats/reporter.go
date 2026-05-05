package stats

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	log "github.com/sirupsen/logrus"
)

// Reporter outputs statistics to console and/or file.
type Reporter struct {
	collector   *Collector
	intervalSec int
	exportFile  string
	targetTPS   int
	getTargetTPS func() int // live getter, overrides targetTPS if set

	// Live dashboard state (only accessed from dashboard goroutine)
	prevSent  uint64
	prevTime  time.Time
	dashLines int
}

// NewReporter creates a new statistics reporter.
func NewReporter(collector *Collector, intervalSec int, exportFile string) *Reporter {
	return &Reporter{
		collector:   collector,
		intervalSec: intervalSec,
		exportFile:  exportFile,
	}
}

// SetTargetTPS sets the target TPS for dashboard display.
func (r *Reporter) SetTargetTPS(tps int) {
	r.targetTPS = tps
}

// SetTargetTPSFunc sets a live getter for target TPS (for runtime tuning).
// When set, this overrides the static targetTPS value.
func (r *Reporter) SetTargetTPSFunc(fn func() int) {
	r.getTargetTPS = fn
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
	elapsed := snap.Duration()

	export := map[string]interface{}{
		"start_time":   snap.StartTime.Format(time.RFC3339),
		"end_time":     snap.EndTime.Format(time.RFC3339),
		"duration_sec": elapsed.Seconds(),
		"messages":     map[string]interface{}{},
		"sessions": map[string]interface{}{
			"established": snap.SessionsEstablished,
			"modified":    snap.SessionsModified,
			"deleted":     snap.SessionsDeleted,
			"failed":      snap.SessionsFailed,
			"active":      snap.ActiveSessions,
		},
		"response_times_ms": map[string]interface{}{
			"min": float64(snap.RespMin) / float64(time.Millisecond),
			"avg": float64(snap.RespAvg) / float64(time.Millisecond),
			"max": float64(snap.RespMax) / float64(time.Millisecond),
			"p50": float64(snap.RespP50) / float64(time.Millisecond),
			"p95": float64(snap.RespP95) / float64(time.Millisecond),
			"p99": float64(snap.RespP99) / float64(time.Millisecond),
		},
	}

	totalSent := snap.TotalSent()
	duration := elapsed.Seconds()
	if duration > 0 {
		export["tps"] = float64(totalSent) / duration
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

	if snap.RespCount > 0 {
		sb.WriteString("Response Times:\n")
		sb.WriteString(fmt.Sprintf("  Min: %s  |  Avg: %s  |  Max: %s  |  P99: %s\n",
			snap.RespMin.Round(time.Microsecond), snap.RespAvg.Round(time.Microsecond),
			snap.RespMax.Round(time.Microsecond), snap.RespP99.Round(time.Microsecond)))
	}

	totalSent := snap.TotalSent()
	if elapsed.Seconds() > 0 {
		sb.WriteString("TPS:\n")
		sb.WriteString(fmt.Sprintf("  %.1f msg/s\n", float64(totalSent)/elapsed.Seconds()))
	}

	sb.WriteString("================================================\n")
	return sb.String()
}

// ─── Live Dashboard ──────────────────────────────────────────────────

// StartLiveDashboard starts a 1-second live dashboard on the terminal.
// Returns a stop function that blocks until the goroutine exits.
func (r *Reporter) StartLiveDashboard(ctx context.Context) (stop func()) {
	done := make(chan struct{})
	stopped := make(chan struct{})

	go func() {
		defer close(stopped)
		ticker := time.NewTicker(1 * time.Second)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-done:
				return
			case <-ticker.C:
				r.renderDashboard()
			}
		}
	}()

	return func() {
		select {
		case <-done:
		default:
			close(done)
		}
		<-stopped
	}
}

func (r *Reporter) renderDashboard() {
	dashboard := r.FormatDashboard()
	lines := strings.Count(dashboard, "\n")
	if r.dashLines > 0 {
		// Move cursor up and clear to end of screen
		fmt.Printf("\033[%dA\033[J", r.dashLines)
	}
	fmt.Print(dashboard)
	r.dashLines = lines
}

// PrintFinalDashboard renders the final dashboard state.
func (r *Reporter) PrintFinalDashboard() {
	r.collector.Finish()
	r.renderDashboard()
}

// FormatDashboard generates a formatted dashboard with box-drawing characters.
func (r *Reporter) FormatDashboard() string {
	snap := r.collector.Snapshot()
	elapsed := snap.Duration()
	totalSent := snap.TotalSent()

	var totalRecv uint64
	for _, ms := range snap.MessageStats {
		totalRecv += ms.Received
	}

	// Compute current TPS (over last interval)
	now := time.Now()
	var currentTPS float64
	if !r.prevTime.IsZero() {
		dt := now.Sub(r.prevTime).Seconds()
		if dt > 0 {
			currentTPS = float64(totalSent-r.prevSent) / dt
		}
	}
	avgTPS := float64(0)
	if elapsed.Seconds() > 0 {
		avgTPS = float64(totalSent) / elapsed.Seconds()
	}
	r.prevSent = totalSent
	r.prevTime = now

	// Table dimensions: total width = 80
	// Full-width inner = 78, table cols sum = 73 (78 - 5 inner borders)
	const W = 80
	const inner = W - 2 // 78
	cols := [6]int{22, 11, 11, 11, 9, 9}
	// sum(cols) = 73, + 5 inner │ = 78 = inner ✓

	var sb strings.Builder

	// ─── Helper closures ───

	fullSep := func(left, fill, right string) {
		sb.WriteString(left + strings.Repeat(fill, inner) + right + "\n")
	}

	fullRow := func(content string) {
		vLen := utf8.RuneCountInString(content)
		if vLen < inner {
			content += strings.Repeat(" ", inner-vLen)
		}
		sb.WriteString("│" + content + "│\n")
	}

	tblSepParts := func() []string {
		parts := make([]string, len(cols))
		for i, cw := range cols {
			parts[i] = strings.Repeat("─", cw)
		}
		return parts
	}

	tblSep := func(left, cross, right string) {
		sb.WriteString(left + strings.Join(tblSepParts(), cross) + right + "\n")
	}

	tblRow := func(cells [6]string) {
		padded := make([]string, 6)
		for i, cell := range cells {
			w := cols[i]
			vLen := utf8.RuneCountInString(cell)
			if vLen < w {
				if i == 0 {
					cell += strings.Repeat(" ", w-vLen) // left-align
				} else {
					cell = strings.Repeat(" ", w-vLen) + cell // right-align
				}
			}
			padded[i] = cell
		}
		sb.WriteString("│" + strings.Join(padded, "│") + "│\n")
	}

	// ─── Title ───
	fullSep("┌", "─", "┐")
	title := "PFCP Generator - Stress Test Dashboard"
	pad := (inner - len(title)) / 2
	fullRow(strings.Repeat(" ", pad) + title)

	// ─── TPS & Elapsed ───
	fullSep("├", "─", "┤")
	displayTargetTPS := r.targetTPS
	if r.getTargetTPS != nil {
		displayTargetTPS = r.getTargetTPS()
	}
	if displayTargetTPS > 0 {
		fullRow(fmt.Sprintf(" Elapsed: %-14s TPS: %s current / %s avg  (target: %s)",
			fmtDuration(elapsed), fmtNum(uint64(currentTPS)), fmtNum(uint64(avgTPS)), fmtNum(uint64(displayTargetTPS))))
	} else {
		fullRow(fmt.Sprintf(" Elapsed: %-14s TPS: %s current / %s avg",
			fmtDuration(elapsed), fmtNum(uint64(currentTPS)), fmtNum(uint64(avgTPS))))
	}
	fullRow(fmt.Sprintf(" Total Sent: %-14s Total Received: %s",
		fmtNum(totalSent), fmtNum(totalRecv)))

	// ─── Sessions ───
	fullSep("├", "─", "┤")
	active := snap.ActiveSessions
	if active < 0 {
		active = 0
	}
	fullRow(fmt.Sprintf(" Sessions   Established: %-9s Active: %-9s Deleted: %-9s Failed: %s",
		fmtNum(snap.SessionsEstablished), fmtNum(uint64(active)),
		fmtNum(snap.SessionsDeleted), fmtNum(snap.SessionsFailed)))

	// ─── Response Times ───
	fullSep("├", "─", "┤")
	if snap.RespCount > 0 {
		fullRow(fmt.Sprintf(" Response   Min: %-10s Avg: %-10s P99: %-10s Max: %s",
			fmtRespTime(snap.RespMin), fmtRespTime(snap.RespAvg),
			fmtRespTime(snap.RespP99), fmtRespTime(snap.RespMax)))
	} else {
		fullRow(" Response   (no data)")
	}

	// ─── Message Type Table ───
	tblSep("├", "┬", "┤")
	tblRow([6]string{" Message Type", "     Sent ", "     Recv ", "  Success ", " Failed ", " Timeout "})
	tblSep("├", "┼", "┤")

	typeNames := make([]string, 0, len(snap.MessageStats))
	for name := range snap.MessageStats {
		typeNames = append(typeNames, name)
	}
	sort.Strings(typeNames)

	for _, name := range typeNames {
		s := snap.MessageStats[name]
		tblRow([6]string{
			" " + abbrevType(name),
			fmtNum(s.Sent) + " ",
			fmtNum(s.Received) + " ",
			fmtNum(s.Success) + " ",
			fmtNum(s.Failed) + " ",
			fmtNum(s.Timeout) + " ",
		})
	}

	if len(typeNames) == 0 {
		tblRow([6]string{" (no data)", "", "", "", "", ""})
	}

	tblSep("└", "┴", "┘")

	return sb.String()
}

// ─── Formatting Helpers ──────────────────────────────────────────────

func abbrevType(name string) string {
	abbrevs := map[string]string{
		"SessionEstablishmentRequest":  "Establishment Req",
		"SessionEstablishmentResponse": "Establishment Resp",
		"SessionModificationRequest":   "Modification Req",
		"SessionModificationResponse":  "Modification Resp",
		"SessionDeletionRequest":       "Deletion Req",
		"SessionDeletionResponse":      "Deletion Resp",
		"AssociationSetupRequest":      "Association Req",
		"AssociationSetupResponse":     "Association Resp",
		"HeartbeatRequest":             "Heartbeat Req",
		"HeartbeatResponse":            "Heartbeat Resp",
	}
	if short, ok := abbrevs[name]; ok {
		return short
	}
	return name
}

func fmtNum(n uint64) string {
	s := fmt.Sprintf("%d", n)
	if len(s) <= 3 {
		return s
	}
	var result []byte
	for i, c := range s {
		if i > 0 && (len(s)-i)%3 == 0 {
			result = append(result, ',')
		}
		result = append(result, byte(c))
	}
	return string(result)
}

func fmtDuration(d time.Duration) string {
	d = d.Round(time.Second)
	h := int(d.Hours())
	m := int(d.Minutes()) % 60
	s := int(d.Seconds()) % 60
	if h > 0 {
		return fmt.Sprintf("%dh%02dm%02ds", h, m, s)
	}
	return fmt.Sprintf("%dm%02ds", m, s)
}

func fmtRespTime(d time.Duration) string {
	if d == 0 {
		return "0"
	}
	us := d.Microseconds()
	if us < 1000 {
		return fmt.Sprintf("%dus", us)
	}
	ms := float64(us) / 1000.0
	if ms < 10 {
		return fmt.Sprintf("%.3fms", ms)
	}
	if ms < 100 {
		return fmt.Sprintf("%.2fms", ms)
	}
	if ms < 1000 {
		return fmt.Sprintf("%.1fms", ms)
	}
	s := ms / 1000.0
	return fmt.Sprintf("%.2fs", s)
}
