package experimental_test

import (
	"context"
	"runtime"
	"testing"

	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/api"
	"github.com/tetratelabs/wazero/experimental"
	"github.com/tetratelabs/wazero/internal/platform"
	"github.com/tetratelabs/wazero/internal/testing/binaryencoding"
	"github.com/tetratelabs/wazero/internal/wasm"
)

// uncheckedMemoryModule exports load(addr) and store(addr, v) on i32 at
// offset 0, load_max(addr) at the largest offset, and grow(pages).
func uncheckedMemoryModule() []byte {
	i32, max := wasm.ValueTypeI32, uint32(10)
	return binaryencoding.EncodeModule(&wasm.Module{
		TypeSection: []wasm.FunctionType{
			{Params: []wasm.ValueType{i32}, Results: []wasm.ValueType{i32}, ParamNumInUint64: 1, ResultNumInUint64: 1},
			{Params: []wasm.ValueType{i32, i32}, ParamNumInUint64: 2},
		},
		FunctionSection: []wasm.Index{0, 1, 0, 0},
		MemorySection:   &wasm.Memory{Min: 1, Cap: 1, Max: max, IsMaxEncoded: true},
		CodeSection: []wasm.Code{
			{Body: []byte{wasm.OpcodeLocalGet, 0, wasm.OpcodeI32Load, 2, 0, wasm.OpcodeEnd}},
			{Body: []byte{wasm.OpcodeLocalGet, 0, wasm.OpcodeLocalGet, 1, wasm.OpcodeI32Store, 2, 0, wasm.OpcodeEnd}},
			// i32.load offset=0xffffffff
			{Body: []byte{wasm.OpcodeLocalGet, 0, wasm.OpcodeI32Load, 0, 0xff, 0xff, 0xff, 0xff, 0x0f, wasm.OpcodeEnd}},
			{Body: []byte{wasm.OpcodeLocalGet, 0, wasm.OpcodeMemoryGrow, 0, wasm.OpcodeEnd}},
		},
		ExportSection: []wasm.Export{
			{Name: "load", Type: wasm.ExternTypeFunc, Index: 0},
			{Name: "store", Type: wasm.ExternTypeFunc, Index: 1},
			{Name: "load_max", Type: wasm.ExternTypeFunc, Index: 2},
			{Name: "grow", Type: wasm.ExternTypeFunc, Index: 3},
		},
	})
}

func TestWithUncheckedMemoryAccess(t *testing.T) {
	if !platform.ReservedMemorySupported || !platform.CompilerSupported() {
		t.Skip("unchecked memory is not supported on this platform")
	}
	ctx := context.Background()
	r := wazero.NewRuntimeWithConfig(ctx, wazero.NewRuntimeConfigCompiler())
	defer r.Close(ctx)

	call := func(t *testing.T, mod api.Module, name string, args ...uint64) (uint64, error) {
		t.Helper()
		res, err := mod.ExportedFunction(name).Call(ctx, args...)
		if err != nil || len(res) == 0 {
			return 0, err
		}
		return res[0], nil
	}
	const page = 65536

	t.Run("checked", func(t *testing.T) {
		mod, err := r.Instantiate(ctx, uncheckedMemoryModule())
		if err != nil {
			t.Fatal(err)
		}
		defer mod.Close(ctx)
		if _, err := call(t, mod, "load", page); err == nil {
			t.Fatal("expected an out of bounds trap")
		}
	})

	t.Run("unchecked", func(t *testing.T) {
		compiled, err := r.CompileModule(experimental.WithUncheckedMemoryAccess(ctx), uncheckedMemoryModule())
		if err != nil {
			t.Fatal(err)
		}
		// Instantiation needs no option: the reservation comes with the
		// compiled module.
		mod, err := r.InstantiateModule(ctx, compiled, wazero.NewModuleConfig().WithName("unchecked"))
		if err != nil {
			t.Fatal(err)
		}
		defer mod.Close(ctx)

		if _, err := call(t, mod, "store", 100, 42); err != nil {
			t.Fatal(err)
		}
		if v, err := call(t, mod, "load", 100); err != nil || v != 42 {
			t.Fatalf("load(100) = %d, %v", v, err)
		}

		// Past the end: no trap, and it stays inside the reservation.
		if _, err := call(t, mod, "store", page+8, 7); err != nil {
			t.Fatalf("store past the end: %v", err)
		}
		if v, err := call(t, mod, "load", page+8); err != nil || v != 7 {
			t.Fatalf("load past the end = %d, %v", v, err)
		}
		if _, err := call(t, mod, "load_max", 0xffffffff); err != nil {
			t.Fatalf("load at the largest address: %v", err)
		}

		// Growing over it zeroes what was written there.
		if prev, err := call(t, mod, "grow", 1); err != nil || prev != 1 {
			t.Fatalf("grow = %d, %v", prev, err)
		}
		if v, err := call(t, mod, "load", page+8); err != nil || v != 0 {
			t.Fatalf("load after grow = %d, %v", v, err)
		}
		if got := mod.Memory().Size(); got != 2*page {
			t.Fatalf("size %d", got)
		}

		// The maximum still applies.
		if prev, err := call(t, mod, "grow", 100); err != nil || int32(prev) != -1 {
			t.Fatalf("grow past max = %d, %v", int32(prev), err)
		}
	})
}

// A module can be closed while a host function it called is still running,
// and that function may access the memory afterwards.
func TestWithUncheckedMemoryAccess_closeDuringHostCall(t *testing.T) {
	if !platform.ReservedMemorySupported || !platform.CompilerSupported() {
		t.Skip("unchecked memory is not supported on this platform")
	}
	ctx := context.Background()
	r := wazero.NewRuntimeWithConfig(ctx, wazero.NewRuntimeConfigCompiler())
	defer r.Close(ctx)

	entered, release, done := make(chan struct{}), make(chan struct{}), make(chan struct{})
	_, err := r.NewHostModuleBuilder("env").NewFunctionBuilder().
		WithFunc(func(ctx context.Context, m api.Module) {
			close(entered)
			<-release
			m.Memory().WriteUint32Le(8, 1) // After the module was closed.
			_, _ = m.Memory().ReadUint32Le(8)
		}).Export("block").Instantiate(ctx)
	if err != nil {
		t.Fatal(err)
	}
	bin := binaryencoding.EncodeModule(&wasm.Module{
		TypeSection:     []wasm.FunctionType{{}},
		ImportSection:   []wasm.Import{{Module: "env", Name: "block", Type: wasm.ExternTypeFunc, DescFunc: 0}},
		FunctionSection: []wasm.Index{0},
		MemorySection:   &wasm.Memory{Min: 1, Cap: 1, Max: 1, IsMaxEncoded: true},
		CodeSection:     []wasm.Code{{Body: []byte{wasm.OpcodeCall, 0, wasm.OpcodeEnd}}},
		ExportSection:   []wasm.Export{{Name: "run", Type: wasm.ExternTypeFunc, Index: 1}},
	})
	compiled, err := r.CompileModule(experimental.WithUncheckedMemoryAccess(ctx), bin)
	if err != nil {
		t.Fatal(err)
	}
	mod, err := r.InstantiateModule(ctx, compiled, wazero.NewModuleConfig().WithName("closing"))
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		defer close(done)
		_, _ = mod.ExportedFunction("run").Call(ctx)
	}()
	<-entered
	if err := mod.Close(ctx); err != nil {
		t.Fatal(err)
	}
	runtime.GC() // The memory is still reachable from the running call.
	close(release)
	<-done
}
