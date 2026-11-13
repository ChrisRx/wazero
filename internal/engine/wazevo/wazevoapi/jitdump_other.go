//go:build !linux

package wazevoapi

// jitdump is only supported on Linux, where perf reads it.
type jitdump struct{}

var jitDump *jitdump

func initJitdump() {}

func (j *jitdump) codeLoad(uintptr, uint64, string) {}

func (j *jitdump) flush(uintptr, []int, []entry) {}
