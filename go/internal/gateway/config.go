// Package gateway is an MCP server that puts the Kinlock Authority core in front of a
// downstream MCP server (or any Downstream).
//
// An agent calls the gateway's use_tool with a downstream tool name and arguments. The
// gateway maps the tool to an action with data/gateway.example.json, asks the Rust core
// (through WebAssembly) to decide, and:
//
//   - ALLOW: forwards the call to the downstream and returns its result;
//   - DENY: refuses and does not call the downstream;
//   - HOLD / OWNER: returns "held"; nothing is forwarded. A person has to approve it in
//     Kinlock (approval state lives in the Python service, not here);
//   - a tool nobody mapped is held, without asking the core: nobody said what it does;
//   - a tool listed read_only is forwarded at once (it changes nothing);
//   - any error from the core is a refusal.
package gateway

import (
	"encoding/json"
	"fmt"
	"math"
	"os"
	"sort"
	"strconv"
	"strings"
)

// ToolRule says what a downstream tool does, in the same shape as the Python ToolRule.
type ToolRule struct {
	Category string    `json:"category"`
	Verb     string    `json:"verb"`
	Target   string    `json:"target,omitempty"`  // argument naming what is acted on; "=literal" for a fixed target
	Amount   string    `json:"amount,omitempty"`  // argument holding a dollar amount
	Details  *[]string `json:"details,omitempty"` // arguments copied into details; nil means all others
}

// Config is the tool mapping (data/gateway.example.json).
type Config struct {
	Tools    map[string]ToolRule `json:"tools"`
	ReadOnly []string            `json:"read_only"`
}

// LoadConfig reads a mapping file.
func LoadConfig(path string) (*Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return ParseConfig(b)
}

// ParseConfig parses a mapping, rejecting rules without a category or verb.
func ParseConfig(b []byte) (*Config, error) {
	var c Config
	if err := json.Unmarshal(b, &c); err != nil {
		return nil, fmt.Errorf("gateway config: %w", err)
	}
	for name, r := range c.Tools {
		if strings.TrimSpace(r.Category) == "" || strings.TrimSpace(r.Verb) == "" {
			return nil, fmt.Errorf("gateway config: tool %q needs a category and a verb", name)
		}
	}
	return &c, nil
}

// IsReadOnly reports whether the config (not the downstream) says the tool changes nothing.
func (c *Config) IsReadOnly(tool string) bool {
	for _, t := range c.ReadOnly {
		if t == tool {
			return true
		}
	}
	return false
}

// Rule returns the mapping for a tool, if any.
func (c *Config) Rule(tool string) (ToolRule, bool) {
	r, ok := c.Tools[tool]
	return r, ok
}

func argString(v any) string {
	switch x := v.(type) {
	case nil:
		return "None"
	case string:
		return x
	case bool:
		if x {
			return "True"
		}
		return "False"
	case float64:
		if x == math.Trunc(x) && math.Abs(x) < 1e16 {
			return strconv.FormatFloat(x, 'f', -1, 64)
		}
		return strconv.FormatFloat(x, 'g', -1, 64)
	case json.Number:
		return x.String()
	case int:
		return strconv.Itoa(x)
	case int64:
		return strconv.FormatInt(x, 10)
	default:
		b, _ := json.Marshal(x)
		return string(b)
	}
}

func dollarsToCents(v any) (int64, error) {
	var f float64
	switch x := v.(type) {
	case nil:
		return 0, nil
	case float64:
		f = x
	case float32:
		f = float64(x)
	case int:
		f = float64(x)
	case int64:
		f = float64(x)
	case json.Number:
		g, err := x.Float64()
		if err != nil {
			return 0, err
		}
		f = g
	case string:
		g, err := strconv.ParseFloat(strings.TrimSpace(x), 64)
		if err != nil {
			return 0, fmt.Errorf("amount %q is not a number", x)
		}
		f = g
	default:
		return 0, fmt.Errorf("amount %v is not a number", v)
	}
	if math.IsNaN(f) || math.IsInf(f, 0) || math.Abs(f) > 1e15 {
		return 0, fmt.Errorf("amount %v is out of range", v)
	}
	return int64(math.RoundToEven(f * 100)), nil // Python: int(round(x * 100))
}

// ActionFor builds the AgentAction JSON for a mapped tool, like Python GatewayConfig.action_for.
func (c *Config) ActionFor(requestID, tool string, args map[string]any, risk []string, requester string) (map[string]any, error) {
	rule, ok := c.Tools[tool]
	if !ok {
		return nil, fmt.Errorf("tool %q is not mapped", tool)
	}
	target := ""
	switch {
	case strings.HasPrefix(rule.Target, "="):
		target = rule.Target[1:]
	case rule.Target != "":
		if v, ok := args[rule.Target]; ok {
			target = argString(v)
		}
	}
	details := map[string]any{}
	if rule.Details != nil {
		for _, k := range *rule.Details {
			if v, ok := args[k]; ok {
				details[k] = v
			}
		}
	} else {
		for k, v := range args {
			if k != rule.Target && k != rule.Amount {
				details[k] = v
			}
		}
	}
	var amount int64
	if rule.Amount != "" {
		a, err := dollarsToCents(args[rule.Amount])
		if err != nil {
			return nil, err
		}
		amount = a
	}
	if risk == nil {
		risk = []string{}
	}
	sort.Strings(risk)
	return map[string]any{
		"request_id":   requestID,
		"category":     rule.Category,
		"verb":         rule.Verb,
		"target":       target,
		"details":      details,
		"risk":         risk,
		"reversible":   true,
		"requester":    requester,
		"amount_cents": amount,
	}, nil
}
