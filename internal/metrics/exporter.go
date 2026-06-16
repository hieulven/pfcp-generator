// Package metrics exposes a Prometheus text-exposition endpoint backed by
// the existing stats.Collector. It performs no extra instrumentation —
// every scrape simply renders a snapshot of counters already maintained by
// the collector.
package metrics

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"sort"
	"strings"

	log "github.com/sirupsen/logrus"

	"pfcp-generator/internal/stats"
)

// Exporter serves a Prometheus /metrics endpoint over HTTP.
type Exporter struct {
	collector *stats.Collector
	addr      string
	path      string
	server    *http.Server
}

// NewExporter creates a new Prometheus exporter for the given collector.
func NewExporter(collector *stats.Collector, addr, path string) *Exporter {
	if path == "" {
		path = "/metrics"
	}
	return &Exporter{
		collector: collector,
		addr:      addr,
		path:      path,
	}
}

// Start launches the HTTP server in a background goroutine and shuts it
// down when ctx is cancelled. It returns once the listener is bound, or an
// error if the listener could not be created.
func (e *Exporter) Start(ctx context.Context) error {
	listener, err := net.Listen("tcp", e.addr)
	if err != nil {
		return fmt.Errorf("metrics exporter listen on %s: %w", e.addr, err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc(e.path, e.handleMetrics)
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	e.server = &http.Server{Handler: mux}

	log.WithField("addr", listener.Addr().String()).WithField("path", e.path).Info("Prometheus metrics exporter started")

	go func() {
		if err := e.server.Serve(listener); err != nil && err != http.ErrServerClosed {
			log.WithError(err).Warn("Metrics exporter stopped unexpectedly")
		}
	}()

	go func() {
		<-ctx.Done()
		_ = e.server.Close()
	}()

	return nil
}

func (e *Exporter) handleMetrics(w http.ResponseWriter, r *http.Request) {
	snap := e.collector.Snapshot()
	w.Header().Set("Content-Type", "text/plain; version=0.0.4")
	var sb strings.Builder
	writeMessagesSent(&sb, snap)
	writeMessagesReceived(&sb, snap)
	writeResponseDuration(&sb, e.collector)
	writeActiveSessions(&sb, snap)
	writeMessagesTimeout(&sb, snap)
	if _, err := w.Write([]byte(sb.String())); err != nil {
		log.WithError(err).Debug("Failed to write metrics response")
	}
}

// sortedMsgTypes returns the message type keys of a snapshot in a stable order.
func sortedMsgTypes(snap *stats.CollectorSnapshot) []string {
	types := make([]string, 0, len(snap.MessageStats))
	for t := range snap.MessageStats {
		types = append(types, t)
	}
	sort.Strings(types)
	return types
}

func writeMessagesSent(sb *strings.Builder, snap *stats.CollectorSnapshot) {
	sb.WriteString("# HELP pfcp_messages_sent_total Total number of PFCP messages sent, by message type.\n")
	sb.WriteString("# TYPE pfcp_messages_sent_total counter\n")
	for _, t := range sortedMsgTypes(snap) {
		fmt.Fprintf(sb, "pfcp_messages_sent_total{msg_type=%q} %d\n", t, snap.MessageStats[t].Sent)
	}
}

func writeMessagesReceived(sb *strings.Builder, snap *stats.CollectorSnapshot) {
	sb.WriteString("# HELP pfcp_messages_received_total Total number of PFCP responses received, by message type and result.\n")
	sb.WriteString("# TYPE pfcp_messages_received_total counter\n")
	for _, t := range sortedMsgTypes(snap) {
		s := snap.MessageStats[t]
		fmt.Fprintf(sb, "pfcp_messages_received_total{msg_type=%q,result=\"success\"} %d\n", t, s.Success)
		fmt.Fprintf(sb, "pfcp_messages_received_total{msg_type=%q,result=\"failed\"} %d\n", t, s.Failed)
	}
}

func writeMessagesTimeout(sb *strings.Builder, snap *stats.CollectorSnapshot) {
	sb.WriteString("# HELP pfcp_messages_timeout_total Total number of PFCP requests that timed out waiting for a UPF response, by message type.\n")
	sb.WriteString("# TYPE pfcp_messages_timeout_total counter\n")
	for _, t := range sortedMsgTypes(snap) {
		fmt.Fprintf(sb, "pfcp_messages_timeout_total{msg_type=%q} %d\n", t, snap.MessageStats[t].Timeout)
	}
}

func writeActiveSessions(sb *strings.Builder, snap *stats.CollectorSnapshot) {
	sb.WriteString("# HELP pfcp_active_sessions Current number of active PFCP sessions.\n")
	sb.WriteString("# TYPE pfcp_active_sessions gauge\n")
	fmt.Fprintf(sb, "pfcp_active_sessions %d\n", snap.ActiveSessions)
}

func writeResponseDuration(sb *strings.Builder, collector *stats.Collector) {
	sb.WriteString("# HELP pfcp_response_duration_seconds PFCP request/response round-trip latency.\n")
	sb.WriteString("# TYPE pfcp_response_duration_seconds histogram\n")
	bounds, cumulative := collector.ResponseTimes.CumulativeBuckets()
	for i, bound := range bounds {
		le := "+Inf"
		if i < len(bounds)-1 {
			le = formatSeconds(bound)
		}
		fmt.Fprintf(sb, "pfcp_response_duration_seconds_bucket{le=%q} %d\n", le, cumulative[i])
	}
	fmt.Fprintf(sb, "pfcp_response_duration_seconds_sum %s\n", formatSeconds(collector.ResponseTimes.Sum()))
	fmt.Fprintf(sb, "pfcp_response_duration_seconds_count %d\n", collector.ResponseTimes.Count())
}

// formatSeconds converts a nanosecond duration into a decimal seconds string.
func formatSeconds(ns int64) string {
	return fmt.Sprintf("%.9f", float64(ns)/1e9)
}
