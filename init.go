package main

import (
	"embed"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

//go:embed templates/policies/*.yaml
var policyTemplates embed.FS

// runInit scaffolds a new faultwall.yaml in the current directory
// based on a named template (balanced | strict | permissive).
func runInit(args []string) error {
	template := "balanced"
	output := "faultwall.yaml"
	force := false

	for i, arg := range args {
		switch arg {
		case "--strict":
			template = "strict"
		case "--permissive":
			template = "permissive"
		case "--balanced":
			template = "balanced"
		case "--template":
			if i+1 < len(args) {
				template = args[i+1]
			}
		case "-o", "--output":
			if i+1 < len(args) {
				output = args[i+1]
			}
		case "-f", "--force":
			force = true
		case "-h", "--help":
			printInitHelp()
			return nil
		}
	}

	// Check destination
	if _, err := os.Stat(output); err == nil && !force {
		return fmt.Errorf("%s already exists (use --force to overwrite)", output)
	}

	// Load embedded template
	src := fmt.Sprintf("templates/policies/%s.yaml", template)
	data, err := policyTemplates.ReadFile(src)
	if err != nil {
		valid := []string{"balanced", "strict", "permissive"}
		return fmt.Errorf("unknown template %q (valid: %s)", template, strings.Join(valid, ", "))
	}

	if err := os.MkdirAll(filepath.Dir(output), 0755); err != nil && output != filepath.Base(output) {
		return fmt.Errorf("failed to create output dir: %w", err)
	}

	f, err := os.Create(output)
	if err != nil {
		return fmt.Errorf("failed to create %s: %w", output, err)
	}
	defer f.Close()
	if _, err := io.Copy(f, strings.NewReader(string(data))); err != nil {
		return fmt.Errorf("failed to write %s: %w", output, err)
	}

	fmt.Printf("✅ Created %s (%s template)\n", output, template)
	fmt.Println()
	fmt.Println("Next steps:")
	fmt.Printf("  1. Edit %s — rename 'my-agent' to your actual agent name\n", output)
	fmt.Println("  2. Start FaultWall:")
	fmt.Printf("       faultwall --proxy --policies %s\n", output)
	fmt.Println("  3. Point your agent at port 5433 with application_name set:")
	fmt.Println("       postgres://user:pass@localhost:5433/db?application_name=agent:my-agent:mission:default")
	fmt.Println()
	return nil
}

func printInitHelp() {
	fmt.Println(`faultwall init — scaffold a new policy file

Usage:
  faultwall init [flags]

Flags:
  --balanced      Balanced policy (default) — blocks destructive ops, allows reads/writes
  --strict        Read-only policy — blocks all writes
  --permissive    Catastrophic-only — blocks DROP/TRUNCATE/GRANT
  --template NAME Explicit template name (balanced|strict|permissive)
  -o, --output    Output filename (default: faultwall.yaml)
  -f, --force     Overwrite existing file
  -h, --help      Show this help

Examples:
  faultwall init                   # drops balanced faultwall.yaml
  faultwall init --strict          # read-only starter
  faultwall init --permissive -o dev.yaml`)
}

// runAgentURL prints a ready-to-use postgres connection string.
func runAgentURL(args []string) error {
	agent := "my-agent"
	mission := "default"
	host := "localhost"
	port := "5433"
	user := "postgres"
	pass := "postgres"
	db := "postgres"

	for i, arg := range args {
		switch arg {
		case "--agent":
			if i+1 < len(args) {
				agent = args[i+1]
			}
		case "--mission":
			if i+1 < len(args) {
				mission = args[i+1]
			}
		case "--host":
			if i+1 < len(args) {
				host = args[i+1]
			}
		case "--port":
			if i+1 < len(args) {
				port = args[i+1]
			}
		case "--user":
			if i+1 < len(args) {
				user = args[i+1]
			}
		case "--password":
			if i+1 < len(args) {
				pass = args[i+1]
			}
		case "--db":
			if i+1 < len(args) {
				db = args[i+1]
			}
		case "-h", "--help":
			fmt.Println(`faultwall agent-url — print a ready-to-use connection string

Usage:
  faultwall agent-url [flags]

Flags:
  --agent NAME       Agent name (default: my-agent)
  --mission NAME     Mission name (default: default)
  --host HOST        DB host (default: localhost)
  --port PORT        FaultWall proxy port (default: 5433)
  --user USER        DB user (default: postgres)
  --password PASS    DB password (default: postgres)
  --db DBNAME        Database name (default: postgres)`)
			return nil
		}
	}

	appName := fmt.Sprintf("agent:%s:mission:%s", agent, mission)
	url := fmt.Sprintf("postgres://%s:%s@%s:%s/%s?application_name=%s",
		user, pass, host, port, db, appName)
	fmt.Println(url)
	return nil
}
