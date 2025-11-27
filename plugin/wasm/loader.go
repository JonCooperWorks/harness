package wasm

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/api"
	"github.com/tetratelabs/wazero/imports/wasi_snapshot_preview1"
)

// WASMLoader loads WASM plugins using wazero.
type WASMLoader struct {
	runtime wazero.Runtime
	ctx     context.Context
}

// NewWASMLoader creates a loader with a WASI runtime ready to instantiate plugins.
func NewWASMLoader() (*WASMLoader, error) {
	ctx := context.Background()
	runtime := wazero.NewRuntime(ctx)

	if _, err := wasi_snapshot_preview1.Instantiate(ctx, runtime); err != nil {
		_ = runtime.Close(ctx)
		return nil, fmt.Errorf("failed to instantiate WASI: %w", err)
	}

	return &WASMLoader{runtime: runtime, ctx: ctx}, nil
}

// Close releases wazero runtime resources.
func (wl *WASMLoader) Close() error {
	return wl.runtime.Close(wl.ctx)
}

// Load compiles and instantiates a WASM plugin from raw bytes.
func (wl *WASMLoader) Load(data []byte, name string) (*WASMPlugin, error) {
	compiled, err := wl.runtime.CompileModule(wl.ctx, data)
	if err != nil {
		return nil, fmt.Errorf("failed to compile WASM module: %w", err)
	}

	config := wazero.NewModuleConfig().WithName(name)
	instance, err := wl.runtime.InstantiateModule(wl.ctx, compiled, config)
	if err != nil {
		_ = compiled.Close(wl.ctx)
		return nil, fmt.Errorf("failed to instantiate module: %w", err)
	}

	mallocFn := instance.ExportedFunction("malloc")
	if mallocFn == nil {
		_ = instance.Close(wl.ctx)
		_ = compiled.Close(wl.ctx)
		return nil, fmt.Errorf("WASM module %q must export a malloc function", name)
	}

	freeFn := instance.ExportedFunction("free")
	if freeFn == nil {
		_ = instance.Close(wl.ctx)
		_ = compiled.Close(wl.ctx)
		return nil, fmt.Errorf("WASM module %q must export a free function", name)
	}

	paramCount := len(freeFn.Definition().ParamTypes())
	if paramCount != 1 && paramCount != 2 {
		_ = instance.Close(wl.ctx)
		_ = compiled.Close(wl.ctx)
		return nil, fmt.Errorf("free function must accept 1 (ptr) or 2 (ptr,len) parameters, got %d", paramCount)
	}

	return &WASMPlugin{
		name:         name,
		instance:     instance,
		runtime:      wl.runtime,
		compiled:     compiled,
		ctx:          wl.ctx,
		malloc:       mallocFn,
		free:         freeFn,
		freeTakesLen: paramCount == 2,
	}, nil
}

// WASMPlugin implements the Plugin interface for WASM modules.
type WASMPlugin struct {
	name         string
	instance     api.Module
	runtime      wazero.Runtime
	compiled     wazero.CompiledModule
	ctx          context.Context
	malloc       api.Function
	free         api.Function
	freeTakesLen bool
}

// Close shuts down the module instance and releases compiled code.
func (wp *WASMPlugin) Close() error {
	if wp.instance != nil {
		_ = wp.instance.Close(wp.ctx)
	}
	if wp.compiled != nil {
		return wp.compiled.Close(wp.ctx)
	}
	return nil
}

// Name returns the plugin name, preferring the WASM exported name().
func (wp *WASMPlugin) Name() string {
	fn := wp.instance.ExportedFunction("name")
	if fn != nil {
		if result, err := wp.callStringFunction(fn); err == nil && result != "" {
			return result
		}
	}
	return wp.name
}

// Description returns the plugin description by calling description().
func (wp *WASMPlugin) Description() string {
	fn := wp.instance.ExportedFunction("description")
	if fn == nil {
		return "WASM plugin"
	}

	result, err := wp.callStringFunction(fn)
	if err != nil {
		return "WASM plugin"
	}

	return result
}

// JSONSchema fetches the plugin schema via json_schema().
func (wp *WASMPlugin) JSONSchema() string {
	fn := wp.instance.ExportedFunction("json_schema")
	if fn == nil {
		return "{}"
	}

	result, err := wp.callStringFunction(fn)
	if err != nil {
		return "{}"
	}

	return result
}

// Execute calls the exported execute(args_ptr, args_len) function.
func (wp *WASMPlugin) Execute(ctx context.Context, args json.RawMessage) (interface{}, error) {
	fn := wp.instance.ExportedFunction("execute")
	if fn == nil {
		return nil, fmt.Errorf("execute function not found in WASM module")
	}

	argsBytes := []byte(string(args))
	argsPtr, argsLen, err := wp.allocateGuestBuffer(ctx, argsBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to allocate memory for args: %w", err)
	}
	defer wp.freeGuestBuffer(ctx, argsPtr, argsLen)

	results, err := fn.Call(ctx, uint64(argsPtr), uint64(argsLen))
	if err != nil {
		return nil, fmt.Errorf("failed to execute WASM function: %w", err)
	}

	if len(results) < 2 {
		return nil, fmt.Errorf("execute function returned insufficient results (expected 2: ptr, len)")
	}

	resultPtr := uint32(results[0])
	resultLen := uint32(results[1])
	if resultPtr == 0 && resultLen == 0 {
		return nil, fmt.Errorf("execute function returned null result")
	}

	mem := wp.instance.Memory()
	if mem == nil {
		return nil, fmt.Errorf("WASM module has no memory")
	}

	resultBytes, ok := mem.Read(resultPtr, resultLen)
	if !ok {
		return nil, fmt.Errorf("failed to read result from WASM memory at ptr=%d, len=%d", resultPtr, resultLen)
	}

	var result interface{}
	if err := json.Unmarshal(resultBytes, &result); err != nil {
		return nil, fmt.Errorf("failed to parse JSON result: %w", err)
	}

	return result, nil
}

// callStringFunction expects the WASM function to return a (ptr,len) string pair.
func (wp *WASMPlugin) callStringFunction(fn api.Function) (string, error) {
	results, err := fn.Call(wp.ctx)
	if err != nil {
		return "", fmt.Errorf("failed to call function: %w", err)
	}

	if len(results) < 2 {
		return "", fmt.Errorf("function returned insufficient results (expected 2: ptr, len)")
	}

	ptr := uint32(results[0])
	length := uint32(results[1])
	if ptr == 0 && length == 0 {
		return "", nil
	}

	mem := wp.instance.Memory()
	if mem == nil {
		return "", fmt.Errorf("WASM module has no memory")
	}

	bytes, ok := mem.Read(ptr, length)
	if !ok {
		return "", fmt.Errorf("failed to read memory at ptr=%d, len=%d", ptr, length)
	}

	return string(bytes), nil
}

// allocateGuestBuffer uses the module's malloc/free to write data into guest memory.
func (wp *WASMPlugin) allocateGuestBuffer(ctx context.Context, data []byte) (uint32, uint32, error) {
	if len(data) == 0 {
		return 0, 0, nil
	}

	ptr, err := wp.callMalloc(ctx, uint32(len(data)))
	if err != nil {
		return 0, 0, err
	}

	mem := wp.instance.Memory()
	if mem == nil {
		return 0, 0, fmt.Errorf("WASM module has no memory")
	}

	if !mem.Write(ptr, data) {
		wp.freeGuestBuffer(ctx, ptr, uint32(len(data)))
		return 0, 0, fmt.Errorf("failed to write args to WASM memory")
	}

	return ptr, uint32(len(data)), nil
}

func (wp *WASMPlugin) callMalloc(ctx context.Context, size uint32) (uint32, error) {
	results, err := wp.malloc.Call(ctx, uint64(size))
	if err != nil {
		return 0, fmt.Errorf("malloc failed: %w", err)
	}
	if len(results) == 0 {
		return 0, fmt.Errorf("malloc returned no result")
	}

	ptr := uint32(results[0])
	if ptr == 0 {
		return 0, fmt.Errorf("malloc returned null pointer")
	}
	return ptr, nil
}

func (wp *WASMPlugin) freeGuestBuffer(ctx context.Context, ptr, length uint32) {
	if ptr == 0 {
		return
	}

	params := []uint64{uint64(ptr)}
	if wp.freeTakesLen {
		params = append(params, uint64(length))
	}

	_, _ = wp.free.Call(ctx, params...)
}
