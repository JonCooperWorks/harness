package crypto

// zeroize overwrites a byte slice with zeros to clear sensitive data from memory.
// This is a defense-in-depth measure - Go's garbage collector does not guarantee
// immediate collection, but explicit zeroization ensures secrets are cleared
// as soon as they're no longer needed.
//
// Note: The Go compiler may optimize away zeroization in some cases.
// For critical applications, consider using a memory-safe language or
// hardware-backed key storage that never exposes key material.
func zeroize(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
