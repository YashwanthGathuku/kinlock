// Command kinlock-gateway is an MCP server (stdio) that guards a downstream MCP server with
// the Kinlock Authority core.
//
//	kinlock-gateway -config ../data/gateway.example.json -policy ../data/policy.example.json -fake
//	kinlock-gateway -config gw.json -policy policy.json -- downstream-server --its-flags
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/exec"

	"github.com/YashwanthGathuku/kinlock/go/internal/authority"
	"github.com/YashwanthGathuku/kinlock/go/internal/gateway"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func main() {
	cfgPath := flag.String("config", "data/gateway.example.json", "tool mapping")
	policyPath := flag.String("policy", "data/policy.example.json", "policy file")
	fake := flag.Bool("fake", false, "use the in-process fake downstream instead of a command")
	frozen := flag.Bool("frozen", false, "start with the safety lock on")
	flag.Parse()
	if err := run(*cfgPath, *policyPath, *fake, *frozen, flag.Args()); err != nil {
		log.Fatal(err)
	}
}

func run(cfgPath, policyPath string, fake, frozen bool, downstreamCmd []string) error {
	ctx := context.Background()
	cfg, err := gateway.LoadConfig(cfgPath)
	if err != nil {
		return err
	}
	policy, err := os.ReadFile(policyPath)
	if err != nil {
		return err
	}
	core, err := authority.New(ctx)
	if err != nil {
		return err
	}
	defer core.Close(ctx)

	var down gateway.Downstream
	switch {
	case fake:
		down = gateway.NewFakeDownstream()
	case len(downstreamCmd) > 0:
		client := mcp.NewClient(&mcp.Implementation{Name: "kinlock-gateway", Version: "0.1.0"}, nil)
		cs, err := client.Connect(ctx, &mcp.CommandTransport{Command: exec.Command(downstreamCmd[0], downstreamCmd[1:]...)}, nil)
		if err != nil {
			return fmt.Errorf("downstream: %w", err)
		}
		defer cs.Close()
		down = gateway.MCPDownstream{Session: cs}
	default:
		return fmt.Errorf("give a downstream command after --, or -fake")
	}
	g, err := gateway.New(core, cfg, policy, down)
	if err != nil {
		return err
	}
	g.Frozen = func() bool { return frozen }
	return g.Server().Run(ctx, &mcp.StdioTransport{})
}
