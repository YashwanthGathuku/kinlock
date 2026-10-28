package gateway

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"
	_ "time/tzdata" // the policy names an IANA zone; don't depend on the host having tzdata

	"github.com/YashwanthGathuku/kinlock/go/internal/authority"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// Status values in a use_tool result.
const (
	StatusForwarded = "forwarded" // allowed and sent to the downstream
	StatusPassed    = "passed"    // read-only, sent without a decision
	StatusHeld      = "held"      // waiting for a person (HOLD) or the owner herself (OWNER)
	StatusDenied    = "denied"    // refused; nothing was sent
	StatusFailed    = "failed"    // allowed, but the downstream refused or failed
)

// Voice is the channel agent requests arrive on, as in the Python server.
const Voice = "voice"

// Result is what use_tool returns.
type Result struct {
	Status    string   `json:"status"`
	Outcome   string   `json:"outcome,omitempty"`
	Direction string   `json:"direction,omitempty"`
	RequestID string   `json:"request_id,omitempty"`
	Reasons   []string `json:"reasons,omitempty"`
	Signals   []string `json:"signals,omitempty"`
	Output    string   `json:"output,omitempty"`
	Message   string   `json:"message"`
}

// Gateway decides tool calls with the Rust core and forwards the allowed ones.
type Gateway struct {
	Core       *authority.Core
	Config     *Config
	Policy     json.RawMessage // the whole policy file
	Firewall   json.RawMessage // its "firewall" section, if any
	Downstream Downstream
	Frozen     func() bool      // the owner's safety lock; nil means off
	Now        func() time.Time // nil means time.Now
	loc        *time.Location
}

// New builds a gateway from a policy file's bytes.
func New(core *authority.Core, cfg *Config, policy []byte, down Downstream) (*Gateway, error) {
	var p map[string]json.RawMessage
	if err := json.Unmarshal(policy, &p); err != nil {
		return nil, fmt.Errorf("policy: %w", err)
	}
	g := &Gateway{Core: core, Config: cfg, Policy: policy, Firewall: p["firewall"], Downstream: down, loc: time.UTC}
	var tz string
	if raw, ok := p["timezone"]; ok && json.Unmarshal(raw, &tz) == nil && tz != "" {
		loc, err := time.LoadLocation(tz)
		if err != nil {
			return nil, fmt.Errorf("policy timezone %q: %w", tz, err)
		}
		g.loc = loc
	}
	return g, nil
}

func newRequestID() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return "gw-" + hex.EncodeToString(b)
}

func (g *Gateway) localHour() int {
	now := time.Now
	if g.Now != nil {
		now = g.Now
	}
	return now().In(g.loc).Hour()
}

// Use decides one call and forwards it only if the core allows it.
func (g *Gateway) Use(ctx context.Context, tool string, args map[string]any, onCall bool, requestedBy string) Result {
	if g.Downstream == nil {
		return Result{Status: StatusDenied, Message: "No service is connected to Kinlock, so there's nothing to call."}
	}
	if args == nil {
		args = map[string]any{}
	}
	if g.Config.IsReadOnly(tool) {
		return g.forward(ctx, tool, args, Result{Status: StatusPassed})
	}
	id := newRequestID()
	if _, ok := g.Config.Rule(tool); !ok {
		return Result{Status: StatusHeld, Outcome: "HOLD", RequestID: id, Reasons: []string{"nobody mapped this tool, so Kinlock can't judge it"},
			Message: fmt.Sprintf("Kinlock doesn't know what %s does, so a person has to decide. Nothing was sent.", tool)}
	}
	var risk []string
	if onCall {
		risk = []string{"inbound_call"}
	}
	action, err := g.Config.ActionFor(id, tool, args, risk, strings.TrimSpace(requestedBy))
	if err != nil {
		return Result{Status: StatusDenied, RequestID: id, Reasons: []string{err.Error()}, Message: "Kinlock couldn't read that request, so it refused. Nothing was sent."}
	}
	frozen := g.Frozen != nil && g.Frozen()
	d, _, err := g.Core.EvaluateAction(ctx, authority.EvaluateInput{
		Action: action, Policy: g.Policy, Firewall: g.Firewall, Channel: Voice, Frozen: frozen, LocalHour: g.localHour(),
	})
	if err != nil {
		// Fail closed: an error anywhere in the decision is a refusal.
		return Result{Status: StatusDenied, RequestID: id, Reasons: []string{err.Error()}, Message: "Kinlock couldn't decide, so it refused. Nothing was sent."}
	}
	var failed []string
	for _, c := range d.Checks {
		if !c.OK {
			failed = append(failed, c.Text)
		}
	}
	r := Result{Outcome: d.Outcome, Direction: d.Direction, RequestID: id, Reasons: failed, Signals: d.Signals}
	switch d.Outcome {
	case "ALLOW":
		if d.Direction == "spend" {
			// The gateway keeps no record of today's spending, so it can't apply daily
			// limits. Money never moves on its say-so alone.
			r.Status, r.Outcome = StatusHeld, "HOLD"
			r.Reasons = append(r.Reasons, "the Go gateway doesn't track today's spending; approve it in Kinlock")
			r.Message = "That spends money, so it waits for Kinlock to approve it. Nothing was sent."
			return r
		}
		return g.forward(ctx, tool, args, r)
	case "DENY":
		r.Status = StatusDenied
		r.Message = "Kinlock refused that. Nothing was sent."
	case "OWNER":
		r.Status = StatusHeld
		r.Message = "Only the owner herself can approve that. Nothing was sent."
	default:
		r.Status = StatusHeld
		r.Message = "That waits for a person to approve it. Nothing was sent."
	}
	return r
}

func (g *Gateway) forward(ctx context.Context, tool string, args map[string]any, r Result) Result {
	out, err := g.Downstream.CallTool(ctx, tool, args)
	if err != nil {
		r.Status = StatusFailed
		r.Reasons = append(r.Reasons, err.Error())
		r.Message = fmt.Sprintf("The service refused: %s.", err)
		return r
	}
	if r.Status == "" {
		r.Status = StatusForwarded
	}
	r.Output = out
	r.Message = out
	return r
}

// GuardedTool describes how one downstream tool is guarded.
type GuardedTool struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Guard       string `json:"guard"`
}

// Guarded lists the downstream's tools and how each is guarded.
func (g *Gateway) Guarded(ctx context.Context) ([]GuardedTool, error) {
	if g.Downstream == nil {
		return nil, nil
	}
	tools, err := g.Downstream.ListTools(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]GuardedTool, 0, len(tools))
	for _, t := range tools {
		how := "not mapped: held for a person"
		if g.Config.IsReadOnly(t.Name) {
			how = "passes through (read-only)"
		} else if r, ok := g.Config.Rule(t.Name); ok {
			how = r.Category + ": " + strings.ReplaceAll(r.Verb, "_", " ")
		}
		out = append(out, GuardedTool{t.Name, t.Description, how})
	}
	return out, nil
}

// UseToolArgs are use_tool's arguments, the same as the Python server's.
type UseToolArgs struct {
	Tool        string         `json:"tool" jsonschema:"the downstream tool to call (see list_guarded_tools)"`
	Arguments   map[string]any `json:"arguments,omitempty" jsonschema:"the tool's arguments"`
	OnCall      bool           `json:"on_call,omitempty" jsonschema:"set if the owner is on a call she didn't place"`
	RequestedBy string         `json:"requested_by,omitempty" jsonschema:"who asked, if not the owner"`
}

// GuardedList is list_guarded_tools' result.
type GuardedList struct {
	Tools []GuardedTool `json:"tools"`
}

// Server builds the MCP server: use_tool and list_guarded_tools.
func (g *Gateway) Server() *mcp.Server {
	s := mcp.NewServer(&mcp.Implementation{Name: "kinlock-gateway", Version: "0.1.0"}, nil)
	mcp.AddTool(s, &mcp.Tool{
		Name:        "use_tool",
		Description: "Call a tool on a service connected through Kinlock (see list_guarded_tools). Kinlock checks it first; tools it doesn't know are held for a person.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in UseToolArgs) (*mcp.CallToolResult, Result, error) {
		r := g.Use(ctx, in.Tool, in.Arguments, in.OnCall, in.RequestedBy)
		res := &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: r.Message}}}
		res.IsError = r.Status == StatusDenied || r.Status == StatusFailed
		return res, r, nil
	})
	mcp.AddTool(s, &mcp.Tool{
		Name:        "list_guarded_tools",
		Description: "List the connected service's tools and how Kinlock guards each one.",
		Annotations: &mcp.ToolAnnotations{ReadOnlyHint: true},
	}, func(ctx context.Context, _ *mcp.CallToolRequest, _ struct{}) (*mcp.CallToolResult, GuardedList, error) {
		t, err := g.Guarded(ctx)
		return nil, GuardedList{Tools: t}, err
	})
	return s
}
