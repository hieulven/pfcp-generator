package metrics

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"pfcp-generator/internal/stats"
)

func TestExporterServesExpectedMetrics(t *testing.T) {
	collector := stats.NewCollector()
	collector.RecordSent("Session Establishment Request")
	collector.RecordSent("Session Establishment Request")
	collector.RecordReceived("Session Establishment Request")
	collector.RecordSuccess("Session Establishment Request", 2*time.Millisecond)
	collector.RecordFailure("Session Establishment Request")
	collector.RecordTimeout("Session Establishment Request")
	collector.RecordSessionEstablished()

	exporter := NewExporter(collector, "127.0.0.1:0", "/metrics")

	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	rec := httptest.NewRecorder()
	exporter.handleMetrics(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", rec.Code)
	}

	body := rec.Body.String()

	expectedSubstrings := []string{
		`pfcp_messages_sent_total{msg_type="Session Establishment Request"} 2`,
		`pfcp_messages_received_total{msg_type="Session Establishment Request",result="success"} 1`,
		`pfcp_messages_received_total{msg_type="Session Establishment Request",result="failed"} 1`,
		`pfcp_messages_timeout_total{msg_type="Session Establishment Request"} 1`,
		`pfcp_active_sessions 1`,
		"pfcp_response_duration_seconds_bucket",
		"pfcp_response_duration_seconds_sum",
		"pfcp_response_duration_seconds_count 1",
	}

	for _, want := range expectedSubstrings {
		if !strings.Contains(body, want) {
			t.Errorf("expected metrics output to contain %q, got:\n%s", want, body)
		}
	}
}

// TestExporterStartServesOverHTTP exercises the full lifecycle: Start binds a
// real listener, /metrics and /healthz respond, and cancelling the context
// shuts the server down.
func TestExporterStartServesOverHTTP(t *testing.T) {
	collector := stats.NewCollector()
	collector.RecordSent("Heartbeat Request")
	collector.RecordSuccess("Heartbeat Request", 3*time.Millisecond)

	// Reserve a free port, then release it for the exporter to bind.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to reserve port: %v", err)
	}
	addr := ln.Addr().String()
	ln.Close()

	ctx, cancel := context.WithCancel(context.Background())
	exporter := NewExporter(collector, addr, "/metrics")
	if err := exporter.Start(ctx); err != nil {
		t.Fatalf("Start returned error: %v", err)
	}

	// /metrics returns recorded data.
	resp, err := http.Get("http://" + addr + "/metrics")
	if err != nil {
		t.Fatalf("GET /metrics failed: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /metrics status = %d", resp.StatusCode)
	}
	if !strings.Contains(string(body), `pfcp_messages_sent_total{msg_type="Heartbeat Request"} 1`) {
		t.Errorf("unexpected /metrics body:\n%s", body)
	}

	// /healthz returns 200 with a non-empty body.
	hResp, err := http.Get("http://" + addr + "/healthz")
	if err != nil {
		t.Fatalf("GET /healthz failed: %v", err)
	}
	hBody, _ := io.ReadAll(hResp.Body)
	hResp.Body.Close()
	if hResp.StatusCode != http.StatusOK {
		t.Errorf("GET /healthz status = %d, want 200", hResp.StatusCode)
	}
	if strings.TrimSpace(string(hBody)) != "ok" {
		t.Errorf("GET /healthz body = %q, want %q", string(hBody), "ok\n")
	}

	// Cancelling the context shuts the server down.
	cancel()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := http.Get("http://" + addr + "/metrics"); err != nil {
			return // server is down, as expected
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Errorf("server still serving after context cancel")
}

// TestExporterStartPortInUse verifies Start surfaces a bind error.
func TestExporterStartPortInUse(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to bind holding listener: %v", err)
	}
	defer ln.Close()

	exporter := NewExporter(stats.NewCollector(), ln.Addr().String(), "/metrics")
	if err := exporter.Start(context.Background()); err == nil {
		t.Errorf("expected Start to fail on port already in use, got nil")
	}
}

func TestExporterEmptyCollector(t *testing.T) {
	collector := stats.NewCollector()
	exporter := NewExporter(collector, "127.0.0.1:0", "/metrics")

	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	rec := httptest.NewRecorder()
	exporter.handleMetrics(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "pfcp_active_sessions 0") {
		t.Errorf("expected pfcp_active_sessions 0 in empty collector output")
	}
}
