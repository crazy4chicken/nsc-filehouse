package httpapi

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// accessLogRecords runs one request through the access log middleware and
// returns the structured records it emitted.
func accessLogRecords(t *testing.T, level slog.Level, path string, status int) []map[string]any {
	t.Helper()
	var buffer bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buffer, &slog.HandlerOptions{Level: level}))
	handler := AccessLog(logger)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(status)
	}))
	handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, path, nil))

	records := make([]map[string]any, 0, 1)
	for _, line := range strings.Split(strings.TrimSpace(buffer.String()), "\n") {
		if line == "" {
			continue
		}
		var record map[string]any
		if err := json.Unmarshal([]byte(line), &record); err != nil {
			t.Fatalf("decode log record %q: %v", line, err)
		}
		records = append(records, record)
	}
	return records
}

// TestAccessLogSilencesProbes covers the probe contract: a host polls both
// endpoints continuously, so they are debug-level noise at the default level
// and observable again with FILEHOUSE_LOG_LEVEL=debug.
func TestAccessLogSilencesProbes(t *testing.T) {
	for _, path := range []string{pathHealthz, pathReadyz} {
		if records := accessLogRecords(t, slog.LevelInfo, path, http.StatusOK); len(records) != 0 {
			t.Fatalf("%s logged %d record(s) at info level, want none: %v", path, len(records), records)
		}
		records := accessLogRecords(t, slog.LevelDebug, path, http.StatusOK)
		if len(records) != 1 {
			t.Fatalf("%s logged %d record(s) at debug level, want 1", path, len(records))
		}
		if records[0]["level"] != "DEBUG" || records[0]["path"] != path || records[0]["status"] != float64(http.StatusOK) {
			t.Fatalf("%s: record = %v", path, records[0])
		}
	}
}

// TestAccessLogLevelsTraffic covers the rest of the mapping: data-plane
// requests stay at info, server errors at error, and a failing probe stays at
// debug because the probe logs the failing dependency itself.
func TestAccessLogLevelsTraffic(t *testing.T) {
	cases := []struct {
		path   string
		status int
		want   int
	}{
		{"/api/v1/buckets", http.StatusOK, 1},
		{"/api/v1/buckets", http.StatusServiceUnavailable, 1},
		{pathReadyz, http.StatusServiceUnavailable, 0},
	}
	for _, testCase := range cases {
		records := accessLogRecords(t, slog.LevelInfo, testCase.path, testCase.status)
		if len(records) != testCase.want {
			t.Fatalf("%s %d logged %d record(s) at info level, want %d", testCase.path, testCase.status, len(records), testCase.want)
		}
		if testCase.want == 0 {
			continue
		}
		wantLevel := "INFO"
		if testCase.status >= http.StatusInternalServerError {
			wantLevel = "ERROR"
		}
		if records[0]["level"] != wantLevel {
			t.Fatalf("%s %d: level = %v, want %s", testCase.path, testCase.status, records[0]["level"], wantLevel)
		}
	}
}
