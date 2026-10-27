package gateway

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// Downstream is what actually carries out an allowed call.
type Downstream interface {
	ListTools(ctx context.Context) ([]ToolSpec, error)
	CallTool(ctx context.Context, name string, args map[string]any) (string, error)
}

// ToolSpec names a downstream tool.
type ToolSpec struct {
	Name        string
	Description string
}

// Call is one call the fake downstream received.
type Call struct {
	Name string
	Args map[string]any
}

// FakeDownstream is an in-process stand-in that records calls. Nothing leaves the process.
type FakeDownstream struct {
	mu     sync.Mutex
	Tools  []ToolSpec
	Refuse map[string]string
	calls  []Call
}

// NewFakeDownstream has the same tools as the Python FakeDownstream.
func NewFakeDownstream() *FakeDownstream {
	return &FakeDownstream{Tools: []ToolSpec{
		{"send_message", "Send a text message to someone."},
		{"place_call", "Phone someone."},
		{"unlock_front_door", "Unlock the smart lock on the front door."},
		{"lock_front_door", "Lock the front door."},
		{"install_app", "Install an app on the owner's computer."},
		{"start_screen_share", "Let someone see and control the owner's screen."},
		{"change_recovery_email", "Change the recovery email of an online account."},
		{"refill_prescription", "Ask the pharmacy to refill a prescription."},
		{"buy", "Buy something from a shop."},
		{"check_weather", "Read the weather forecast."},
		{"delete_photos", "Delete photos from the owner's library."},
	}}
}

// ListTools implements Downstream.
func (f *FakeDownstream) ListTools(context.Context) ([]ToolSpec, error) { return f.Tools, nil }

// CallTool implements Downstream.
func (f *FakeDownstream) CallTool(_ context.Context, name string, args map[string]any) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	known := false
	for _, t := range f.Tools {
		known = known || t.Name == name
	}
	if !known {
		return "", fmt.Errorf("the service has no tool called %s", name)
	}
	if msg, ok := f.Refuse[name]; ok {
		return "", errors.New(msg)
	}
	f.calls = append(f.calls, Call{name, args})
	if name == "check_weather" {
		return "Sunny, high of 64.", nil
	}
	return fmt.Sprintf("(simulated) %s done", name), nil
}

// Calls returns what was forwarded so far.
func (f *FakeDownstream) Calls() []Call {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]Call(nil), f.calls...)
}

// MCPDownstream forwards to a real MCP server through a client session.
type MCPDownstream struct{ Session *mcp.ClientSession }

// ListTools implements Downstream.
func (m MCPDownstream) ListTools(ctx context.Context) ([]ToolSpec, error) {
	var out []ToolSpec
	for t, err := range m.Session.Tools(ctx, nil) {
		if err != nil {
			return nil, err
		}
		out = append(out, ToolSpec{t.Name, t.Description})
	}
	return out, nil
}

// CallTool implements Downstream.
func (m MCPDownstream) CallTool(ctx context.Context, name string, args map[string]any) (string, error) {
	res, err := m.Session.CallTool(ctx, &mcp.CallToolParams{Name: name, Arguments: args})
	if err != nil {
		return "", err
	}
	var parts []string
	for _, c := range res.Content {
		if t, ok := c.(*mcp.TextContent); ok {
			parts = append(parts, t.Text)
		}
	}
	text := strings.Join(parts, "\n")
	if res.IsError {
		return "", errors.New(text)
	}
	return text, nil
}
