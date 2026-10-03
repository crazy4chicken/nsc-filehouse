package iamauth

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"sort"
	"strings"
	"time"
)

// registeredBy identifies this service in the teamusers permission registry.
const registeredBy = "filehouse"

// defaultRegisterTimeout bounds one permission registration request.
const defaultRegisterTimeout = 10 * time.Second

// Register upserts every key in Catalog through POST {baseURL}/permissions/
// with the supplied admin bearer token.
//
// Registration is idempotent: teamusers treats the endpoint as an upsert keyed
// by the permission string. Only HTTP 200 counts as success; failures are
// aggregated and reported together with the keys that did register, so a
// partially applied catalog is always visible to the operator.
func Register(ctx context.Context, baseURL, token string, hc *http.Client, log *slog.Logger) ([]string, error) {
	base := strings.TrimRight(strings.TrimSpace(baseURL), "/")
	if base == "" {
		return nil, errors.New("iam: base URL is required to register permissions")
	}
	if strings.TrimSpace(token) == "" {
		return nil, errors.New("iam: an admin bearer token is required to register permissions")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	client := hc
	if client == nil {
		client = &http.Client{Timeout: defaultRegisterTimeout}
	}
	logger := log
	if logger == nil {
		logger = discardLogger()
	}

	registered := make([]string, 0, len(Catalog))
	var failures []error
	for _, entry := range Catalog {
		if err := registerPermission(ctx, base, token, client, entry); err != nil {
			failures = append(failures, err)
			logger.Error("iam: permission registration failed", "key", entry.Key, "error", err.Error())
			continue
		}
		registered = append(registered, entry.Key)
	}
	sort.Strings(registered)

	if len(failures) > 0 {
		return registered, fmt.Errorf("iam: register permissions: %w", errors.Join(failures...))
	}
	return registered, nil
}

// registerPermission performs one catalog upsert.
func registerPermission(ctx context.Context, base, token string, client *http.Client, entry CatalogEntry) error {
	body, err := json.Marshal(struct {
		Key          string `json:"key"`
		Description  string `json:"description"`
		RegisteredBy string `json:"registered_by"`
	}{Key: entry.Key, Description: entry.Description, RegisteredBy: registeredBy})
	if err != nil {
		return fmt.Errorf("register %s: encode request: %w", entry.Key, err)
	}

	request, err := http.NewRequestWithContext(ctx, http.MethodPost, base+"/permissions/", bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("register %s: create request: %w", entry.Key, err)
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Authorization", "Bearer "+token)

	response, err := client.Do(request)
	if err != nil {
		return fmt.Errorf("register %s: %w", entry.Key, err)
	}
	defer response.Body.Close()
	// The teamusers permission registry answers 201 Created for an upsert and
	// 200 OK when the row is unchanged; any other status is a failure.
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return fmt.Errorf("register %s: HTTP %d: %s", entry.Key, response.StatusCode, responseDetail(response.Body))
	}
	// Drain a bounded amount so the connection can be reused.
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, maxTokenResponseBytes))
	return nil
}
