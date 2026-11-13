package expctxkeys

// MemoryAllocatorKey is a context.Context key for the experimental memory allocator.
type MemoryAllocatorKey struct{}

// UncheckedMemoryKey is a context.Context key for compiling without memory
// bounds checks.
type UncheckedMemoryKey struct{}
