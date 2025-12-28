package crypto

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"testing"
)

func TestHashPublicKey(t *testing.T) {
	// Generate test key
	pubKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	// Hash the public key
	hash := HashPublicKey(pubKey)

	// Verify it's 32 bytes (SHA-256 output)
	if len(hash) != 32 {
		t.Errorf("HashPublicKey() returned hash of length %d, want 32", len(hash))
	}

	// Verify it matches SHA-256 of the public key
	expectedHash := sha256.Sum256(pubKey)
	if hash != expectedHash {
		t.Errorf("HashPublicKey() = %x, want %x", hash, expectedHash)
	}

	// Test with different keys produce different hashes
	pubKey2, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate second key: %v", err)
	}
	hash2 := HashPublicKey(pubKey2)
	if hash == hash2 {
		t.Error("HashPublicKey() returned same hash for different keys")
	}

	// Test consistency (same key produces same hash)
	hash3 := HashPublicKey(pubKey)
	if hash != hash3 {
		t.Error("HashPublicKey() is not consistent for same key")
	}
}

func TestBuildEOTranscript(t *testing.T) {
	// Generate test keys
	pkEO, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate EO key: %v", err)
	}
	pkT, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate Target key: %v", err)
	}
	pkH, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate Harness key: %v", err)
	}

	tests := []struct {
		name            string
		context         string
		version         uint32
		flags           uint32
		metadata        []byte
		encryptedPayload []byte
	}{
		{
			name:            "basic",
			context:         "harness-payload-signature-v1",
			version:         2,
			flags:           0,
			metadata:        []byte(`{"test":"metadata"}`),
			encryptedPayload: []byte("encrypted payload data"),
		},
		{
			name:            "empty metadata",
			context:         "harness-payload-signature-v1",
			version:         2,
			flags:           0,
			metadata:        []byte{},
			encryptedPayload: []byte("encrypted payload"),
		},
		{
			name:            "empty payload",
			context:         "harness-payload-signature-v1",
			version:         2,
			flags:           0,
			metadata:        []byte(`{"test":"metadata"}`),
			encryptedPayload: []byte{},
		},
		{
			name:            "large payload",
			context:         "harness-payload-signature-v1",
			version:         2,
			flags:           0,
			metadata:        []byte(`{"test":"metadata"}`),
			encryptedPayload: make([]byte, 10000),
		},
		{
			name:            "different version",
			context:         "harness-payload-signature-v1",
			version:         3,
			flags:           0,
			metadata:        []byte(`{"test":"metadata"}`),
			encryptedPayload: []byte("payload"),
		},
		{
			name:            "non-zero flags",
			context:         "harness-payload-signature-v1",
			version:         2,
			flags:           0xFF,
			metadata:        []byte(`{"test":"metadata"}`),
			encryptedPayload: []byte("payload"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			transcript, err := BuildEOTranscript(tt.context, tt.version, tt.flags, pkEO, pkT, pkH, tt.metadata, tt.encryptedPayload)
			if err != nil {
				t.Fatalf("BuildEOTranscript() error = %v", err)
			}

			// Verify transcript structure
			pos := 0

			// 1. Context (length-prefixed)
			if len(transcript) < pos+4 {
				t.Fatal("transcript too short for context length")
			}
			contextLen := int(binary.BigEndian.Uint32(transcript[pos : pos+4]))
			pos += 4
			if len(transcript) < pos+contextLen {
				t.Fatal("transcript too short for context")
			}
			contextBytes := transcript[pos : pos+contextLen]
			if string(contextBytes) != tt.context {
				t.Errorf("context = %q, want %q", string(contextBytes), tt.context)
			}
			pos += contextLen

			// 2. Version (4 bytes)
			if len(transcript) < pos+4 {
				t.Fatal("transcript too short for version")
			}
			version := binary.BigEndian.Uint32(transcript[pos : pos+4])
			if version != tt.version {
				t.Errorf("version = %d, want %d", version, tt.version)
			}
			pos += 4

			// 3. Flags (4 bytes)
			if len(transcript) < pos+4 {
				t.Fatal("transcript too short for flags")
			}
			flags := binary.BigEndian.Uint32(transcript[pos : pos+4])
			if flags != tt.flags {
				t.Errorf("flags = %d, want %d", flags, tt.flags)
			}
			pos += 4

			// 4. H(pk_EO) (32 bytes)
			if len(transcript) < pos+32 {
				t.Fatal("transcript too short for H(pk_EO)")
			}
			hashEO := transcript[pos : pos+32]
			expectedHashEO := HashPublicKey(pkEO)
			if !equalBytes(hashEO, expectedHashEO[:]) {
				t.Errorf("H(pk_EO) = %x, want %x", hashEO, expectedHashEO[:])
			}
			pos += 32

			// 5. H(pk_T) (32 bytes)
			if len(transcript) < pos+32 {
				t.Fatal("transcript too short for H(pk_T)")
			}
			hashT := transcript[pos : pos+32]
			expectedHashT := HashPublicKey(pkT)
			if !equalBytes(hashT, expectedHashT[:]) {
				t.Errorf("H(pk_T) = %x, want %x", hashT, expectedHashT[:])
			}
			pos += 32

			// 6. H(pk_H) (32 bytes)
			if len(transcript) < pos+32 {
				t.Fatal("transcript too short for H(pk_H)")
			}
			hashH := transcript[pos : pos+32]
			expectedHashH := HashPublicKey(pkH)
			if !equalBytes(hashH, expectedHashH[:]) {
				t.Errorf("H(pk_H) = %x, want %x", hashH, expectedHashH[:])
			}
			pos += 32

			// 7. Metadata (length-prefixed)
			if len(transcript) < pos+4 {
				t.Fatal("transcript too short for metadata length")
			}
			metadataLen := int(binary.BigEndian.Uint32(transcript[pos : pos+4]))
			pos += 4
			if len(transcript) < pos+metadataLen {
				t.Fatal("transcript too short for metadata")
			}
			metadata := transcript[pos : pos+metadataLen]
			if !equalBytes(metadata, tt.metadata) {
				t.Errorf("metadata = %x, want %x", metadata, tt.metadata)
			}
			pos += metadataLen

			// 8. Encrypted payload (length-prefixed)
			if len(transcript) < pos+4 {
				t.Fatal("transcript too short for encrypted payload length")
			}
			payloadLen := int(binary.BigEndian.Uint32(transcript[pos : pos+4]))
			pos += 4
			if len(transcript) < pos+payloadLen {
				t.Fatal("transcript too short for encrypted payload")
			}
			payload := transcript[pos : pos+payloadLen]
			if !equalBytes(payload, tt.encryptedPayload) {
				t.Errorf("encryptedPayload = %x, want %x", payload, tt.encryptedPayload)
			}
			pos += payloadLen

			// Verify we consumed all data
			if pos != len(transcript) {
				t.Errorf("transcript length = %d, consumed %d bytes", len(transcript), pos)
			}
		})
	}
}

func TestBuildEOTranscript_InvalidKeys(t *testing.T) {
	// Generate valid keys
	pkEO, _, _ := ed25519.GenerateKey(rand.Reader)
	pkT, _, _ := ed25519.GenerateKey(rand.Reader)
	pkH, _, _ := ed25519.GenerateKey(rand.Reader)

	tests := []struct {
		name string
		pkEO ed25519.PublicKey
		pkT  ed25519.PublicKey
		pkH  ed25519.PublicKey
	}{
		{"invalid EO key size", []byte("too short"), pkT, pkH},
		{"invalid Target key size", pkEO, []byte("too short"), pkH},
		{"invalid Harness key size", pkEO, pkT, []byte("too short")},
		{"all invalid", []byte("short"), []byte("short"), []byte("short")},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := BuildEOTranscript("harness-payload-signature-v1", 2, 0, tt.pkEO, tt.pkT, tt.pkH, []byte("metadata"), []byte("payload"))
			if err == nil {
				t.Error("BuildEOTranscript() error = nil, want error")
			}
		})
	}
}

func TestBuildTargetTranscript(t *testing.T) {
	// Generate test keys
	pkEO, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate EO key: %v", err)
	}
	pkT, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate Target key: %v", err)
	}
	pkH, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate Harness key: %v", err)
	}

	tests := []struct {
		name            string
		context         string
		version         uint32
		flags           uint32
		encryptedPayload []byte
		encryptedArgs   []byte
		expiration      int64
	}{
		{
			name:            "basic",
			context:         "harness-client-signature-v1",
			version:         2,
			flags:           0,
			encryptedPayload: []byte("encrypted payload"),
			encryptedArgs:   []byte(`{"arg":"value"}`),
			expiration:      1234567890,
		},
		{
			name:            "empty payload",
			context:         "harness-client-signature-v1",
			version:         2,
			flags:           0,
			encryptedPayload: []byte{},
			encryptedArgs:   []byte(`{}`),
			expiration:      1234567890,
		},
		{
			name:            "empty args",
			context:         "harness-client-signature-v1",
			version:         2,
			flags:           0,
			encryptedPayload: []byte("payload"),
			encryptedArgs:   []byte{},
			expiration:      1234567890,
		},
		{
			name:            "large args",
			context:         "harness-client-signature-v1",
			version:         2,
			flags:           0,
			encryptedPayload: []byte("payload"),
			encryptedArgs:   make([]byte, 5000),
			expiration:      1234567890,
		},
		{
			name:            "zero expiration",
			context:         "harness-client-signature-v1",
			version:         2,
			flags:           0,
			encryptedPayload: []byte("payload"),
			encryptedArgs:   []byte(`{}`),
			expiration:      0,
		},
		{
			name:            "future expiration",
			context:         "harness-client-signature-v1",
			version:         2,
			flags:           0,
			encryptedPayload: []byte("payload"),
			encryptedArgs:   []byte(`{}`),
			expiration:      9999999999,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			transcript, err := BuildTargetTranscript(tt.context, tt.version, tt.flags, pkEO, pkT, pkH, tt.encryptedPayload, tt.encryptedArgs, tt.expiration)
			if err != nil {
				t.Fatalf("BuildTargetTranscript() error = %v", err)
			}

			// Verify transcript structure
			pos := 0

			// 1. Context (length-prefixed)
			if len(transcript) < pos+4 {
				t.Fatal("transcript too short for context length")
			}
			contextLen := int(binary.BigEndian.Uint32(transcript[pos : pos+4]))
			pos += 4
			if len(transcript) < pos+contextLen {
				t.Fatal("transcript too short for context")
			}
			contextBytes := transcript[pos : pos+contextLen]
			if string(contextBytes) != tt.context {
				t.Errorf("context = %q, want %q", string(contextBytes), tt.context)
			}
			pos += contextLen

			// 2. Version (4 bytes)
			if len(transcript) < pos+4 {
				t.Fatal("transcript too short for version")
			}
			version := binary.BigEndian.Uint32(transcript[pos : pos+4])
			if version != tt.version {
				t.Errorf("version = %d, want %d", version, tt.version)
			}
			pos += 4

			// 3. Flags (4 bytes)
			if len(transcript) < pos+4 {
				t.Fatal("transcript too short for flags")
			}
			flags := binary.BigEndian.Uint32(transcript[pos : pos+4])
			if flags != tt.flags {
				t.Errorf("flags = %d, want %d", flags, tt.flags)
			}
			pos += 4

			// 4-6. Identity hashes (32 bytes each)
			for i, expectedHash := range []ed25519.PublicKey{pkEO, pkT, pkH} {
				if len(transcript) < pos+32 {
					t.Fatalf("transcript too short for identity hash %d", i)
				}
				hash := transcript[pos : pos+32]
				expected := HashPublicKey(expectedHash)
				if !equalBytes(hash, expected[:]) {
					t.Errorf("identity hash %d = %x, want %x", i, hash, expected[:])
				}
				pos += 32
			}

			// 7. Encrypted payload (length-prefixed)
			if len(transcript) < pos+4 {
				t.Fatal("transcript too short for encrypted payload length")
			}
			payloadLen := int(binary.BigEndian.Uint32(transcript[pos : pos+4]))
			pos += 4
			if len(transcript) < pos+payloadLen {
				t.Fatal("transcript too short for encrypted payload")
			}
			payload := transcript[pos : pos+payloadLen]
			if !equalBytes(payload, tt.encryptedPayload) {
				t.Errorf("encryptedPayload = %x, want %x", payload, tt.encryptedPayload)
			}
			pos += payloadLen

			// 8. Encrypted args (length-prefixed)
			if len(transcript) < pos+4 {
				t.Fatal("transcript too short for encrypted args length")
			}
			argsLen := int(binary.BigEndian.Uint32(transcript[pos : pos+4]))
			pos += 4
			if len(transcript) < pos+argsLen {
				t.Fatal("transcript too short for encrypted args")
			}
			args := transcript[pos : pos+argsLen]
			if !equalBytes(args, tt.encryptedArgs) {
				t.Errorf("encryptedArgs = %x, want %x", args, tt.encryptedArgs)
			}
			pos += argsLen

			// 9. Expiration (8 bytes, uint64)
			if len(transcript) < pos+8 {
				t.Fatal("transcript too short for expiration")
			}
			expiration := int64(binary.BigEndian.Uint64(transcript[pos : pos+8]))
			if expiration != tt.expiration {
				t.Errorf("expiration = %d, want %d", expiration, tt.expiration)
			}
			pos += 8

			// Verify we consumed all data
			if pos != len(transcript) {
				t.Errorf("transcript length = %d, consumed %d bytes", len(transcript), pos)
			}
		})
	}
}

func TestBuildTargetTranscript_InvalidKeys(t *testing.T) {
	// Generate valid keys
	pkEO, _, _ := ed25519.GenerateKey(rand.Reader)
	pkT, _, _ := ed25519.GenerateKey(rand.Reader)
	pkH, _, _ := ed25519.GenerateKey(rand.Reader)

	tests := []struct {
		name string
		pkEO ed25519.PublicKey
		pkT  ed25519.PublicKey
		pkH  ed25519.PublicKey
	}{
		{"invalid EO key size", []byte("too short"), pkT, pkH},
		{"invalid Target key size", pkEO, []byte("too short"), pkH},
		{"invalid Harness key size", pkEO, pkT, []byte("too short")},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := BuildTargetTranscript("harness-client-signature-v1", 2, 0, tt.pkEO, tt.pkT, tt.pkH, []byte("payload"), []byte("args"), 1234567890)
			if err == nil {
				t.Error("BuildTargetTranscript() error = nil, want error")
			}
		})
	}
}

func TestVerifyIdentityHashes(t *testing.T) {
	// Generate test keys
	pkEO, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate EO key: %v", err)
	}
	pkT, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate Target key: %v", err)
	}
	pkH, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate Harness key: %v", err)
	}

	// Build a valid transcript
	transcript, err := BuildEOTranscript("harness-payload-signature-v1", 2, 0, pkEO, pkT, pkH, []byte("metadata"), []byte("payload"))
	if err != nil {
		t.Fatalf("failed to build transcript: %v", err)
	}

	// Verify with correct keys should succeed
	err = VerifyIdentityHashes(transcript, pkEO, pkT, pkH)
	if err != nil {
		t.Errorf("VerifyIdentityHashes() with correct keys error = %v, want nil", err)
	}

	// Verify with wrong keys should fail
	wrongKey, _, _ := ed25519.GenerateKey(rand.Reader)
	err = VerifyIdentityHashes(transcript, wrongKey, pkT, pkH)
	if err == nil {
		t.Error("VerifyIdentityHashes() with wrong EO key error = nil, want error")
	}

	err = VerifyIdentityHashes(transcript, pkEO, wrongKey, pkH)
	if err == nil {
		t.Error("VerifyIdentityHashes() with wrong Target key error = nil, want error")
	}

	err = VerifyIdentityHashes(transcript, pkEO, pkT, wrongKey)
	if err == nil {
		t.Error("VerifyIdentityHashes() with wrong Harness key error = nil, want error")
	}
}

func TestVerifyIdentityHashes_InvalidTranscript(t *testing.T) {
	// Generate test keys
	pkEO, _, _ := ed25519.GenerateKey(rand.Reader)
	pkT, _, _ := ed25519.GenerateKey(rand.Reader)
	pkH, _, _ := ed25519.GenerateKey(rand.Reader)

	tests := []struct {
		name      string
		transcript []byte
	}{
		{"empty transcript", []byte{}},
		{"too short for context length", []byte{0, 0, 0}},
		{"too short for version/flags", []byte{0, 0, 0, 5, 'h', 'e', 'l', 'l', 'o'}},
		{"too short for first hash", []byte{0, 0, 0, 5, 'h', 'e', 'l', 'l', 'o', 0, 0, 0, 2, 0, 0, 0, 0}},
		{"too short for second hash", make([]byte, 4+5+8+32)}, // context+version+flags+first hash
		{"too short for third hash", make([]byte, 4+5+8+32+32)}, // context+version+flags+first two hashes
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := VerifyIdentityHashes(tt.transcript, pkEO, pkT, pkH)
			if err == nil {
				t.Error("VerifyIdentityHashes() error = nil, want error")
			}
		})
	}
}

