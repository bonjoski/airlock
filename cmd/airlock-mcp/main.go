// Command airlock-mcp provides a standalone Model Context Protocol (MCP) stdio server
// for AI coding assistants (Gemini CLI, Claude Desktop, Cursor, etc.).
package main

import (
	"context"
	"fmt"
	"os"

	"github.com/bonjoski/airlock/pkg/mcp"
)

var (
	version = "0.5.0"
)

func main() {
	server := mcp.NewServer(os.Stdin, os.Stdout, mcp.WithVersion(version))
	if err := server.Serve(context.Background()); err != nil {
		fmt.Fprintf(os.Stderr, "airlock-mcp: server error: %v\n", err)
		os.Exit(1)
	}
}
