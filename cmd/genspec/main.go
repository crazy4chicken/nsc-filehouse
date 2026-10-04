// Command genspec renders docs/public/openapi.yaml from the routes mounted on
// the HTTP router and the operation metadata declared in internal/httpapi.
//
// It is invoked by the docs build (pnpm docs:build) from the repository root
// and exits non-zero when the router and the metadata diverge.
package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/crazy4chicken/nsc-teamusers/apidocs/go"

	"github.com/crazy4chicken/nsc-filehouse/internal/httpapi"
)

func main() {
	if err := generate(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func generate() error {
	router := httpapi.NewServer(httpapi.Options{}).Router()
	operations, err := apidocs.Collect(router, httpapi.DocOperations, httpapi.DocPermission)
	if err != nil {
		return fmt.Errorf("collect API operations: %w", err)
	}

	specPath := filepath.Join("docs", "public", "openapi.yaml")
	if err := writeSpec(specPath, operations); err != nil {
		return fmt.Errorf("write OpenAPI document: %w", err)
	}
	return nil
}

// writeSpec atomically replaces path with the emitted OpenAPI document.
func writeSpec(path string, operations []apidocs.Operation) error {
	directory := filepath.Dir(path)
	if err := os.MkdirAll(directory, 0o755); err != nil {
		return fmt.Errorf("create output directory: %w", err)
	}
	temporary, err := os.CreateTemp(directory, ".spec.tmp-*")
	if err != nil {
		return fmt.Errorf("create temporary file: %w", err)
	}
	temporaryName := temporary.Name()
	defer os.Remove(temporaryName)
	options := apidocs.EmitOptions{
		Title:   "Filehouse API",
		Version: "0.1.0",
		Servers: []apidocs.Server{{
			URL:         "http://localhost:8080",
			Description: "Local development",
		}},
		SecurityScheme: apidocs.SecurityScheme{
			Name:         "bearerAuth",
			Type:         "http",
			Scheme:       "bearer",
			BearerFormat: "EdDSA JWT",
		},
		PermissionExtension: "x-teamusers-permission",
	}
	if err := apidocs.Emit(operations, temporary, options); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("emit document: %w", err)
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("sync temporary file: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("close temporary file: %w", err)
	}
	if err := os.Rename(temporaryName, path); err != nil {
		return fmt.Errorf("replace document: %w", err)
	}
	return nil
}
