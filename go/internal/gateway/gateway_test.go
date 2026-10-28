package gateway

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/YashwanthGathuku/kinlock/go/internal/authority"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

var core *authority.Core

func TestMain(m *testing.M) {
	c, err := authority.New(context.Background())
	if err != nil {
		panic(err)
	}
	core = c
	code := m.Run()
	_ = c.Close(context.Background())
	os.Exit(code)
}

func data(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", "..", "data", name))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func newGateway(t *testing.T) (*Gateway, *FakeDownstream) {
	t.Helper()
	cfg, err := ParseConfig(data(t, "gateway.example.json"))
	if err != nil {
		t.Fatal(err)
	}
	down := NewFakeDownstream()
	g, err := New(core, cfg, data(t, "policy.example.json"), down)
	if err != nil {
		t.Fatal(err)
	}
	// Mid-afternoon in the owner's zone, outside night hours.
	g.Now = func() time.Time { return time.Date(2026, 10, 27, 18, 0, 0, 0, time.UTC) }
	return g, down
}

func TestReadOnlyPassesThrough(t *testing.T) {
	g, down := newGateway(t)
	r := g.Use(context.Background(), "check_weather", nil, false, "")
	if r.Status != StatusPassed || r.Output != "Sunny, high of 64." || len(down.Calls()) != 1 {
		t.Fatalf("got %+v", r)
	}
}

func TestUnmappedToolIsHeld(t *testing.T) {
	g, down := newGateway(t)
	r := g.Use(context.Background(), "delete_photos", map[string]any{"album": "all"}, false, "")
	if r.Status != StatusHeld || r.Outcome != "HOLD" || len(down.Calls()) != 0 {
		t.Fatalf("got %+v", r)
	}
}

func TestAllowForwards(t *testing.T) {
	g, down := newGateway(t)
	r := g.Use(context.Background(), "lock_front_door", nil, false, "")
	if r.Outcome != "ALLOW" || r.Status != StatusForwarded || r.Output != "(simulated) lock_front_door done" {
		t.Fatalf("got %+v", r)
	}
	if c := down.Calls(); len(c) != 1 || c[0].Name != "lock_front_door" {
		t.Fatalf("calls %+v", c)
	}
}

func TestScamInstallIsNotForwarded(t *testing.T) {
	g, down := newGateway(t)
	r := g.Use(context.Background(), "install_app", map[string]any{"app": "AnyDesk", "said": "microsoft support told me to"}, true, "Microsoft Support")
	if r.Status != StatusDenied && r.Status != StatusHeld {
		t.Fatalf("a remote tool on a call must not run, got %+v", r)
	}
	if len(down.Calls()) != 0 {
		t.Fatalf("nothing may be forwarded, got %+v", down.Calls())
	}
}

func TestOutcomesNeverForwardUnlessAllow(t *testing.T) {
	g, _ := newGateway(t)
	cases := []struct {
		tool string
		args map[string]any
	}{
		{"unlock_front_door", map[string]any{"visitor": "Steve"}},
		{"start_screen_share", map[string]any{"with": "caller"}},
		{"change_recovery_email", map[string]any{"account": "Bank", "new_email": "x@evil.example"}},
		{"buy", map[string]any{"merchant": "Fresh Market", "amount_dollars": 20, "category": "groceries"}},
		{"buy", map[string]any{"merchant": "CryptoCash", "amount_dollars": 500}},
		{"send_message", map[string]any{"to": "Anna", "text": "hi"}},
		{"refill_prescription", map[string]any{"pharmacy": "Corner Pharmacy"}},
		{"place_call", map[string]any{"to": "Anna"}},
	}
	for _, c := range cases {
		down := NewFakeDownstream()
		g.Downstream = down
		r := g.Use(context.Background(), c.tool, c.args, false, "")
		forwarded := len(down.Calls()) > 0
		if forwarded != (r.Outcome == "ALLOW") {
			t.Errorf("%s: outcome %s but forwarded=%v", c.tool, r.Outcome, forwarded)
		}
		if r.Direction == "increase" && r.Outcome == "ALLOW" {
			t.Errorf("%s: voice allowed an increase", c.tool)
		}
		if r.Status == StatusDenied && r.Outcome == "" {
			t.Errorf("%s: refused before the core decided: %v", c.tool, r.Reasons)
		}
		if r.Direction == "spend" && forwarded {
			t.Errorf("%s: the gateway moved money on its own", c.tool)
		}
	}
}

func TestFrozenBlocksSpendingAndOddPolicyFailsClosed(t *testing.T) {
	g, down := newGateway(t)
	g.Frozen = func() bool { return true }
	r := g.Use(context.Background(), "buy", map[string]any{"merchant": "Fresh Market", "amount_dollars": "12.50"}, false, "")
	if r.Outcome == "ALLOW" || len(down.Calls()) != 0 {
		t.Fatalf("frozen spending went through: %+v", r)
	}
	r = g.Use(context.Background(), "buy", map[string]any{"merchant": "Fresh Market", "amount_dollars": "lots"}, false, "")
	if r.Status != StatusDenied || len(down.Calls()) != 0 {
		t.Fatalf("an unreadable amount must be refused: %+v", r)
	}
	g.Policy = json.RawMessage(`{"night_hours": "not a pair"}`)
	r = g.Use(context.Background(), "lock_front_door", nil, false, "")
	if r.Status == StatusForwarded {
		t.Fatalf("a broken policy must never forward: %+v", r)
	}
}

func TestDownstreamRefusalIsReported(t *testing.T) {
	g, down := newGateway(t)
	down.Refuse = map[string]string{"lock_front_door": "the lock is offline"}
	r := g.Use(context.Background(), "lock_front_door", nil, false, "")
	if r.Status != StatusFailed {
		t.Fatalf("got %+v", r)
	}
}

func TestActionForMatchesPythonMapping(t *testing.T) {
	cfg, _ := ParseConfig(data(t, "gateway.example.json"))
	a, err := cfg.ActionFor("r1", "buy", map[string]any{"merchant": "Fresh Market", "amount_dollars": 19.995, "note": "milk"}, nil, "")
	if err != nil {
		t.Fatal(err)
	}
	if a["target"] != "Fresh Market" || a["amount_cents"] != int64(2000) || a["category"] != "money" {
		t.Fatalf("got %+v", a)
	}
	if d := a["details"].(map[string]any); len(d) != 1 || d["note"] != "milk" {
		t.Fatalf("details %+v", d)
	}
	a, _ = cfg.ActionFor("r2", "lock_front_door", map[string]any{}, nil, "")
	if a["target"] != "front door" {
		t.Fatalf("literal target: %+v", a)
	}
	if _, err := ParseConfig([]byte(`{"tools":{"x":{"verb":"y"}}}`)); err == nil {
		t.Fatal("a rule without a category must be rejected")
	}
}

func TestOverMCP(t *testing.T) {
	ctx := context.Background()
	g, down := newGateway(t)
	st, ct := mcp.NewInMemoryTransports()
	ss, err := g.Server().Connect(ctx, st, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer ss.Close()
	cs, err := mcp.NewClient(&mcp.Implementation{Name: "test-agent", Version: "0"}, nil).Connect(ctx, ct, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer cs.Close()

	call := func(args map[string]any) Result {
		t.Helper()
		res, err := cs.CallTool(ctx, &mcp.CallToolParams{Name: "use_tool", Arguments: args})
		if err != nil {
			t.Fatal(err)
		}
		b, _ := json.Marshal(res.StructuredContent)
		var r Result
		if err := json.Unmarshal(b, &r); err != nil {
			t.Fatal(err)
		}
		return r
	}
	if r := call(map[string]any{"tool": "lock_front_door"}); r.Status != StatusForwarded {
		t.Fatalf("lock: %+v", r)
	}
	if r := call(map[string]any{"tool": "delete_photos", "arguments": map[string]any{"album": "all"}}); r.Status != StatusHeld {
		t.Fatalf("unmapped: %+v", r)
	}
	if r := call(map[string]any{"tool": "install_app", "arguments": map[string]any{"app": "AnyDesk"}, "on_call": true, "requested_by": "Microsoft Support"}); r.Status == StatusForwarded {
		t.Fatalf("scam install forwarded: %+v", r)
	}
	if n := len(down.Calls()); n != 1 {
		t.Fatalf("only the lock should reach the downstream, got %d calls", n)
	}

	res, err := cs.CallTool(ctx, &mcp.CallToolParams{Name: "list_guarded_tools", Arguments: map[string]any{}})
	if err != nil || res.IsError {
		t.Fatalf("list: %v %+v", err, res)
	}
	b, _ := json.Marshal(res.StructuredContent)
	var gl GuardedList
	_ = json.Unmarshal(b, &gl)
	guard := map[string]string{}
	for _, x := range gl.Tools {
		guard[x.Name] = x.Guard
	}
	if guard["delete_photos"] != "not mapped: held for a person" || guard["check_weather"] != "passes through (read-only)" || guard["buy"] != "money: purchase" {
		t.Fatalf("guards %+v", guard)
	}
}

// The gateway also forwards to a real MCP downstream through the client session.
func TestMCPDownstream(t *testing.T) {
	ctx := context.Background()
	ds := mcp.NewServer(&mcp.Implementation{Name: "door", Version: "0"}, nil)
	locked := false
	mcp.AddTool(ds, &mcp.Tool{Name: "lock_front_door", Description: "Lock it."}, func(context.Context, *mcp.CallToolRequest, struct{}) (*mcp.CallToolResult, any, error) {
		locked = true
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: "locked"}}}, nil, nil
	})
	st, ct := mcp.NewInMemoryTransports()
	ss, err := ds.Connect(ctx, st, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer ss.Close()
	cs, err := mcp.NewClient(&mcp.Implementation{Name: "kinlock-gateway", Version: "0"}, nil).Connect(ctx, ct, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer cs.Close()
	g, _ := newGateway(t)
	g.Downstream = MCPDownstream{Session: cs}
	if r := g.Use(ctx, "lock_front_door", nil, false, ""); r.Status != StatusForwarded || r.Output != "locked" || !locked {
		t.Fatalf("got %+v locked=%v", r, locked)
	}
	tools, err := g.Guarded(ctx)
	if err != nil || len(tools) != 1 || tools[0].Guard != "home: lock door" {
		t.Fatalf("guarded %+v %v", tools, err)
	}
}
