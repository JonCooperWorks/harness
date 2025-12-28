package crypto

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
)

// HashPublicKey computes the SHA-256 hash of an Ed25519 public key.
// This is used for identity binding in signature transcripts.
func HashPublicKey(pub ed25519.PublicKey) [32]byte {
	return sha256.Sum256(pub)
}

// appendLengthPrefixed appends a length-prefixed field to a byte slice.
// The length is encoded as a uint32 (4 bytes, big-endian) followed by the field bytes.
func appendLengthPrefixed(buf []byte, field []byte) []byte {
	lengthBuf := make([]byte, 4)
	binary.BigEndian.PutUint32(lengthBuf, uint32(len(field)))
	buf = append(buf, lengthBuf...)
	buf = append(buf, field...)
	return buf
}

// BuildEOTranscript builds the canonical EO (Exploit Owner) signature transcript
// according to HCEEP v0.3 specification (RFC section 5.1).
//
// The transcript structure is:
//  1. Context string (length-prefixed): "harness-payload-signature-v1"
//  2. Protocol version (uint32, big-endian)
//  3. Flags (uint32, big-endian)
//  4. H(pk_EO) (32 bytes, fixed-length)
//  5. H(pk_T) (32 bytes, fixed-length)
//  6. H(pk_H) (32 bytes, fixed-length)
//  7. Metadata (length-prefixed)
//  8. Encrypted payload blob (length-prefixed)
//
// All variable-length fields are length-prefixed with uint32 (big-endian).
// Fixed-length fields (hashes, version, flags) are not length-prefixed.
func BuildEOTranscript(context string, version, flags uint32, pkEO, pkT, pkH ed25519.PublicKey, metadata, encryptedPayload []byte) ([]byte, error) {
	if len(pkEO) != ed25519.PublicKeySize {
		return nil, errors.New("invalid Exploit Owner public key size")
	}
	if len(pkT) != ed25519.PublicKeySize {
		return nil, errors.New("invalid Target public key size")
	}
	if len(pkH) != ed25519.PublicKeySize {
		return nil, errors.New("invalid Harness public key size")
	}

	var transcript []byte

	// 1. Context string (length-prefixed)
	contextBytes := []byte(context)
	transcript = appendLengthPrefixed(transcript, contextBytes)

	// 2. Protocol version (uint32, big-endian)
	versionBuf := make([]byte, 4)
	binary.BigEndian.PutUint32(versionBuf, version)
	transcript = append(transcript, versionBuf...)

	// 3. Flags (uint32, big-endian)
	flagsBuf := make([]byte, 4)
	binary.BigEndian.PutUint32(flagsBuf, flags)
	transcript = append(transcript, flagsBuf...)

	// 4. H(pk_EO) (32 bytes, fixed-length)
	hashEO := HashPublicKey(pkEO)
	transcript = append(transcript, hashEO[:]...)

	// 5. H(pk_T) (32 bytes, fixed-length)
	hashT := HashPublicKey(pkT)
	transcript = append(transcript, hashT[:]...)

	// 6. H(pk_H) (32 bytes, fixed-length)
	hashH := HashPublicKey(pkH)
	transcript = append(transcript, hashH[:]...)

	// 7. Metadata (length-prefixed)
	transcript = appendLengthPrefixed(transcript, metadata)

	// 8. Encrypted payload blob (length-prefixed)
	transcript = appendLengthPrefixed(transcript, encryptedPayload)

	return transcript, nil
}

// BuildTargetTranscript builds the canonical Target signature transcript
// according to HCEEP v0.3 specification (RFC section 5.2).
//
// The transcript structure is:
//  1. Context string (length-prefixed): "harness-client-signature-v1"
//  2. Protocol version (uint32, big-endian)
//  3. Flags (uint32, big-endian)
//  4. H(pk_EO) (32 bytes, fixed-length)
//  5. H(pk_T) (32 bytes, fixed-length)
//  6. H(pk_H) (32 bytes, fixed-length)
//  7. Encrypted payload blob (length-prefixed)
//  8. Encrypted arguments (length-prefixed)
//  9. Expiration timestamp (uint64, big-endian)
//
// All variable-length fields are length-prefixed with uint32 (big-endian).
// Fixed-length fields (hashes, version, flags, expiration) are not length-prefixed.
func BuildTargetTranscript(context string, version, flags uint32, pkEO, pkT, pkH ed25519.PublicKey, encryptedPayload, encryptedArgs []byte, expiration int64) ([]byte, error) {
	if len(pkEO) != ed25519.PublicKeySize {
		return nil, errors.New("invalid Exploit Owner public key size")
	}
	if len(pkT) != ed25519.PublicKeySize {
		return nil, errors.New("invalid Target public key size")
	}
	if len(pkH) != ed25519.PublicKeySize {
		return nil, errors.New("invalid Harness public key size")
	}

	var transcript []byte

	// 1. Context string (length-prefixed)
	contextBytes := []byte(context)
	transcript = appendLengthPrefixed(transcript, contextBytes)

	// 2. Protocol version (uint32, big-endian)
	versionBuf := make([]byte, 4)
	binary.BigEndian.PutUint32(versionBuf, version)
	transcript = append(transcript, versionBuf...)

	// 3. Flags (uint32, big-endian)
	flagsBuf := make([]byte, 4)
	binary.BigEndian.PutUint32(flagsBuf, flags)
	transcript = append(transcript, flagsBuf...)

	// 4. H(pk_EO) (32 bytes, fixed-length)
	hashEO := HashPublicKey(pkEO)
	transcript = append(transcript, hashEO[:]...)

	// 5. H(pk_T) (32 bytes, fixed-length)
	hashT := HashPublicKey(pkT)
	transcript = append(transcript, hashT[:]...)

	// 6. H(pk_H) (32 bytes, fixed-length)
	hashH := HashPublicKey(pkH)
	transcript = append(transcript, hashH[:]...)

	// 7. Encrypted payload blob (length-prefixed)
	transcript = appendLengthPrefixed(transcript, encryptedPayload)

	// 8. Encrypted arguments (length-prefixed)
	transcript = appendLengthPrefixed(transcript, encryptedArgs)

	// 9. Expiration timestamp (uint64, big-endian)
	expirationBuf := make([]byte, 8)
	binary.BigEndian.PutUint64(expirationBuf, uint64(expiration))
	transcript = append(transcript, expirationBuf...)

	return transcript, nil
}

// VerifyIdentityHashes verifies that the identity hashes in a transcript match
// the expected public keys. This prevents key substitution attacks.
func VerifyIdentityHashes(transcript []byte, expectedPkEO, expectedPkT, expectedPkH ed25519.PublicKey) error {
	// Extract identity hashes from transcript
	// After context (length-prefixed), version (4), flags (4)
	// Position: after context length + context bytes + 4 + 4

	// Read context length
	if len(transcript) < 4 {
		return errors.New("transcript too short for context length")
	}
	contextLen := int(binary.BigEndian.Uint32(transcript[0:4]))

	// Position after context
	pos := 4 + contextLen

	// Skip version (4 bytes) and flags (4 bytes)
	if len(transcript) < pos+8 {
		return errors.New("transcript too short for version and flags")
	}
	pos += 8

	// Extract H(pk_EO) (32 bytes)
	if len(transcript) < pos+32 {
		return errors.New("transcript too short for H(pk_EO)")
	}
	hashEO := transcript[pos : pos+32]
	pos += 32

	// Extract H(pk_T) (32 bytes)
	if len(transcript) < pos+32 {
		return errors.New("transcript too short for H(pk_T)")
	}
	hashT := transcript[pos : pos+32]
	pos += 32

	// Extract H(pk_H) (32 bytes)
	if len(transcript) < pos+32 {
		return errors.New("transcript too short for H(pk_H)")
	}
	hashH := transcript[pos : pos+32]

	// Verify hashes match expected public keys
	expectedHashEO := HashPublicKey(expectedPkEO)
	expectedHashT := HashPublicKey(expectedPkT)
	expectedHashH := HashPublicKey(expectedPkH)

	if !equalBytes(hashEO, expectedHashEO[:]) {
		return fmt.Errorf("H(pk_EO) mismatch: expected %x, got %x", expectedHashEO[:], hashEO)
	}
	if !equalBytes(hashT, expectedHashT[:]) {
		return fmt.Errorf("H(pk_T) mismatch: expected %x, got %x", expectedHashT[:], hashT)
	}
	if !equalBytes(hashH, expectedHashH[:]) {
		return fmt.Errorf("H(pk_H) mismatch: expected %x, got %x", expectedHashH[:], hashH)
	}

	return nil
}

// equalBytes performs constant-time comparison of two byte slices.
func equalBytes(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	result := byte(0)
	for i := range a {
		result |= a[i] ^ b[i]
	}
	return result == 0
}
