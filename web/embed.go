// Package web provides embedded static files for the LOXTU web application.
package web

import "embed"

// StaticFiles embeds the entire web/static directory into the binary.
// This eliminates the runtime dependency on the ./web/static/ filesystem path.
//
//go:embed static
var StaticFiles embed.FS
