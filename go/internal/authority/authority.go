// Package authority runs the Kinlock Authority Rust core, compiled to WebAssembly, inside Go.
//
// The module is vendored next to this file (kinlock_authority.wasm) with a lock
// (kinlock_authority.lock.json) naming the kinlock-authority commit it was built from and its
// sha256. New refuses to start if the embedded bytes don't match the lock.
//
// One call: a JSON request {"op": ..., "input": ...} goes in, the same JSON the Python
// reference returns comes out. A trap inside the module (a Rust panic) is returned as an
// error and the instance is thrown away; callers must treat any error as a refusal.
package authority

import (
	"context"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sync"

	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/api"
)

//go:embed kinlock_authority.wasm
var wasmBytes []byte

//go:embed kinlock_authority.lock.json
var lockBytes []byte

// Lock is the provenance record for the embedded module.
type Lock struct {
	Repo   string `json:"repo"`
	Commit string `json:"commit"`
	Wasm   struct {
		File   string `json:"file"`
		SHA256 string `json:"sha256"`
	} `json:"wasm"`
	Vectors struct {
		Dir   string            `json:"dir"`
		Files map[string]string `json:"files"`
	} `json:"vectors"`
}

// ReadLock parses the embedded lock.
func ReadLock() (Lock, error) {
	var l Lock
	err := json.Unmarshal(lockBytes, &l)
	return l, err
}

// Core is one instance of the module. It is safe for concurrent use; calls are serialised.
type Core struct {
	mu       sync.Mutex
	rt       wazero.Runtime
	compiled wazero.CompiledModule
	mod      api.Module
	n        int
}

// New checks the embedded module against its lock and compiles it.
func New(ctx context.Context) (*Core, error) {
	lock, err := ReadLock()
	if err != nil {
		return nil, fmt.Errorf("authority lock unreadable: %w", err)
	}
	sum := sha256.Sum256(wasmBytes)
	if got := hex.EncodeToString(sum[:]); got != lock.Wasm.SHA256 {
		return nil, fmt.Errorf("embedded authority module sha256 %s does not match its lock %s", got, lock.Wasm.SHA256)
	}
	rt := wazero.NewRuntime(ctx)
	compiled, err := rt.CompileModule(ctx, wasmBytes)
	if err != nil {
		_ = rt.Close(ctx)
		return nil, fmt.Errorf("authority module does not compile: %w", err)
	}
	return &Core{rt: rt, compiled: compiled}, nil
}

// Close releases the runtime.
func (c *Core) Close(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.rt.Close(ctx)
}

func (c *Core) instance(ctx context.Context) (api.Module, error) {
	if c.mod != nil {
		return c.mod, nil
	}
	c.n++
	mod, err := c.rt.InstantiateModule(ctx, c.compiled, wazero.NewModuleConfig().WithName(fmt.Sprintf("kinlock-authority-%d", c.n)))
	if err != nil {
		return nil, err
	}
	for _, name := range []string{"kinlock_input", "kinlock_run", "kinlock_output"} {
		if mod.ExportedFunction(name) == nil {
			_ = mod.Close(ctx)
			return nil, fmt.Errorf("authority module has no export %q", name)
		}
	}
	c.mod = mod
	return mod, nil
}

// Raw sends request bytes ({"op","input"}) and returns the reply bytes.
func (c *Core) Raw(ctx context.Context, request []byte) ([]byte, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	out, err := c.raw(ctx, request)
	if err != nil && c.mod != nil {
		// Never reuse an instance after a trap or a bad read: its memory is suspect.
		_ = c.mod.Close(ctx)
		c.mod = nil
	}
	return out, err
}

func (c *Core) raw(ctx context.Context, request []byte) ([]byte, error) {
	mod, err := c.instance(ctx)
	if err != nil {
		return nil, err
	}
	if uint64(len(request)) > 1<<30 {
		return nil, errors.New("authority request too large")
	}
	n := uint64(len(request))
	res, err := mod.ExportedFunction("kinlock_input").Call(ctx, n)
	if err != nil {
		return nil, fmt.Errorf("authority module trapped: %w", err)
	}
	ptr := uint32(res[0])
	if !mod.Memory().Write(ptr, request) {
		return nil, errors.New("authority input buffer out of range")
	}
	res, err = mod.ExportedFunction("kinlock_run").Call(ctx, n)
	if err != nil {
		return nil, fmt.Errorf("authority module trapped: %w", err)
	}
	outLen := uint32(res[0])
	res, err = mod.ExportedFunction("kinlock_output").Call(ctx)
	if err != nil {
		return nil, fmt.Errorf("authority module trapped: %w", err)
	}
	b, ok := mod.Memory().Read(uint32(res[0]), outLen)
	if !ok {
		return nil, errors.New("authority output buffer out of range")
	}
	return append([]byte(nil), b...), nil
}

// Call runs one operation. input is marshalled with encoding/json (json.RawMessage keeps
// its bytes). A reply of {"error": msg} is returned as an error.
func (c *Core) Call(ctx context.Context, op string, input any) (json.RawMessage, error) {
	req, err := json.Marshal(struct {
		Op    string `json:"op"`
		Input any    `json:"input"`
	}{op, input})
	if err != nil {
		return nil, err
	}
	out, err := c.Raw(ctx, req)
	if err != nil {
		return nil, err
	}
	var probe struct {
		Error *string `json:"error"`
	}
	if json.Unmarshal(out, &probe) == nil && probe.Error != nil {
		return nil, fmt.Errorf("authority: %s", *probe.Error)
	}
	return out, nil
}

// Decision is the part of an evaluate_action reply the gateway acts on.
type Decision struct {
	Outcome   string `json:"outcome"`
	Direction string `json:"direction"`
	Category  string `json:"category"`
	Checks    []struct {
		Code string `json:"code"`
		OK   bool   `json:"ok"`
		Text string `json:"text"`
	} `json:"checks"`
	Signals        []string        `json:"signals"`
	CooloffSeconds float64         `json:"cooloff_seconds"`
	Quorum         json.RawMessage `json:"quorum"`
}

// EvaluateInput is the input to the evaluate_action operation.
type EvaluateInput struct {
	Action    map[string]any  `json:"action"`
	Policy    json.RawMessage `json:"policy"`
	Firewall  json.RawMessage `json:"firewall,omitempty"`
	Channel   string          `json:"channel"`
	Frozen    bool            `json:"frozen"`
	History   map[string]any  `json:"history,omitempty"`
	LocalHour int             `json:"local_hour"`
}

// EvaluateAction decides one agent action.
func (c *Core) EvaluateAction(ctx context.Context, in EvaluateInput) (Decision, json.RawMessage, error) {
	raw, err := c.Call(ctx, "evaluate_action", in)
	if err != nil {
		return Decision{}, nil, err
	}
	var d Decision
	if err := json.Unmarshal(raw, &d); err != nil {
		return Decision{}, nil, err
	}
	switch d.Outcome {
	case "ALLOW", "HOLD", "OWNER", "DENY":
	default:
		return Decision{}, nil, fmt.Errorf("authority returned unknown outcome %q", d.Outcome)
	}
	return d, raw, nil
}
