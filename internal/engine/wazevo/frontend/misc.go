package frontend

import (
	"github.com/ChrisRx/wazero/internal/engine/wazevo/ssa"
	"github.com/ChrisRx/wazero/internal/wasm"
)

func FunctionIndexToFuncRef(idx wasm.Index) ssa.FuncRef {
	return ssa.FuncRef(idx)
}
