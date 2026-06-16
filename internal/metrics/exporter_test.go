package metrics

import (
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
