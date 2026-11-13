package bench

import (
	"testing"

	"github.com/ChrisRx/wazero/api"
	"github.com/ChrisRx/wazero/internal/wasm"
	"github.com/ChrisRx/wazero/internal/wasm/binary"
)

func BenchmarkCodec(b *testing.B) {
	b.Run("binary.DecodeModule", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			if _, err := binary.DecodeModule(caseWasm, api.CoreFeaturesV2, wasm.MemoryLimitPages, false, false, false); err != nil {
				b.Fatal(err)
			}
		}
	})
}
