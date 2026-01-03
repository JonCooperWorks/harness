package keystore

// zeroize overwrites a byte slice with zeros to clear sensitive data from memory.
// This is a defense-in-depth measure - Go's garbage collector does not guarantee
// immediate collection, but explicit zeroization ensures secrets are cleared
// as soon as they're no longer needed.
func zeroize(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// zeroize32 overwrites a 32-byte array with zeros.
func zeroize32(b *[32]byte) {
	for i := range b {
		b[i] = 0
	}
}
