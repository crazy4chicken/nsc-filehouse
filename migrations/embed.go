// Package migrations embeds the goose SQL migrations applied by internal/store.
package migrations

import "embed"

// FS holds every migration file, rooted at the migrations directory.
//
//go:embed *.sql
var FS embed.FS
