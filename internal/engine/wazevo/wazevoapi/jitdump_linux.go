package wazevoapi

import (
	"encoding/binary"
	"os"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"unsafe"
)

// jitdump writes the compiled machine code in perf's jitdump format
// (tools/perf/Documentation/jitdump-specification.txt in the Linux tree),
// next to the perf map, so `perf inject --jit` can turn samples in JIT code
// into annotatable symbols:
//
//	perf record -k mono -g -- ./program   # built with -tags perfmap
//	perf inject --jit -i perf.data -o perf.jit.data
//	perf annotate -i perf.jit.data
//
// It is enabled with the perfmap build tag, like PerfMap.
type jitdump struct {
	fh    *os.File
	index uint64
}

var jitDump *jitdump

func initJitdump() {
	var mach uint32
	switch runtime.GOARCH {
	case "amd64":
		mach = 62 // EM_X86_64
	case "arm64":
		mach = 183 // EM_AARCH64
	default:
		return
	}
	dir := os.Getenv("JITDUMPDIR")
	if dir == "" {
		dir = "/tmp"
	}
	fh, err := os.OpenFile(dir+"/jit-"+strconv.Itoa(os.Getpid())+".dump", os.O_CREATE|os.O_TRUNC|os.O_RDWR, 0o644)
	if err != nil {
		panic(err)
	}
	// perf finds the dump through this executable mapping of it.
	if _, err := syscall.Mmap(int(fh.Fd()), 0, os.Getpagesize(), syscall.PROT_READ|syscall.PROT_EXEC, syscall.MAP_PRIVATE); err != nil {
		panic(err)
	}
	header := make([]byte, 0, 40)
	header = binary.LittleEndian.AppendUint32(header, 0x4A695444) // "JiTD"
	header = binary.LittleEndian.AppendUint32(header, 1)          // version
	header = binary.LittleEndian.AppendUint32(header, 40)         // header size
	header = binary.LittleEndian.AppendUint32(header, mach)
	header = binary.LittleEndian.AppendUint32(header, 0) // padding
	header = binary.LittleEndian.AppendUint32(header, uint32(os.Getpid()))
	header = binary.LittleEndian.AppendUint64(header, monotonicNanos())
	header = binary.LittleEndian.AppendUint64(header, 0) // flags
	if _, err := fh.Write(header); err != nil {
		panic(err)
	}
	jitDump = &jitdump{fh: fh}
}

// codeLoad records the machine code at [addr, addr+size) as name.
func (j *jitdump) codeLoad(addr uintptr, size uint64, name string) {
	const recordHeader, loadFields = 16, 40
	total := recordHeader + loadFields + len(name) + 1 + int(size)
	b := make([]byte, 0, total)
	b = binary.LittleEndian.AppendUint32(b, 0) // JIT_CODE_LOAD
	b = binary.LittleEndian.AppendUint32(b, uint32(total))
	b = binary.LittleEndian.AppendUint64(b, monotonicNanos())
	b = binary.LittleEndian.AppendUint32(b, uint32(os.Getpid()))
	b = binary.LittleEndian.AppendUint32(b, uint32(syscall.Gettid()))
	b = binary.LittleEndian.AppendUint64(b, uint64(addr)) // vma
	b = binary.LittleEndian.AppendUint64(b, uint64(addr)) // code address
	b = binary.LittleEndian.AppendUint64(b, size)
	b = binary.LittleEndian.AppendUint64(b, j.index)
	j.index++
	b = append(b, name...)
	b = append(b, 0)
	// addr is executable memory mapped outside the Go heap.
	code := *(*unsafe.Pointer)(unsafe.Pointer(&addr))
	b = append(b, unsafe.Slice((*byte)(code), size)...)
	if _, err := j.fh.Write(b); err != nil {
		panic(err)
	}
}

// flush records whole functions from perf map entries, which can be
// per block: entries of one function are merged, named without the block
// suffix.
func (j *jitdump) flush(addr uintptr, functionOffsets []int, entries []entry) {
	type span struct {
		start, end uintptr
		name       string
	}
	var spans []span
	byIndex := map[int]int{}
	for _, e := range entries {
		start := uintptr(e.offset) + addr + uintptr(functionOffsets[e.index])
		end := start + uintptr(e.size)
		name, _, _ := strings.Cut(e.name, ":::::")
		if i, ok := byIndex[e.index]; ok && spans[i].name == name {
			spans[i].start = min(spans[i].start, start)
			spans[i].end = max(spans[i].end, end)
			continue
		}
		byIndex[e.index] = len(spans)
		spans = append(spans, span{start, end, name})
	}
	for _, s := range spans {
		j.codeLoad(s.start, uint64(s.end-s.start), s.name)
	}
}

func monotonicNanos() uint64 {
	var ts syscall.Timespec
	const clockMonotonic = 1
	if _, _, errno := syscall.RawSyscall(syscall.SYS_CLOCK_GETTIME, clockMonotonic, uintptr(unsafe.Pointer(&ts)), 0); errno != 0 {
		return 0
	}
	return uint64(ts.Sec)*1e9 + uint64(ts.Nsec)
}
