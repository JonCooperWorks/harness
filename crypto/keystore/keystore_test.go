package keystore

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"testing"
)

// MockKeystore is an in-memory implementation of Keystore for testing.
// It implements the full Keystore interface using memory-based key storage.
type MockKeystore struct {
	keyID      KeyID
	privateKey ed25519.PrivateKey
}

// NewMockKeystore creates a new in-memory keystore for testing.
func NewMockKeystore(keyID KeyID) (*MockKeystore, error) {
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	return &MockKeystore{
		keyID:      keyID,
		privateKey: privateKey,
	}, nil
}

// NewMockKeystoreWithKey creates a mock keystore with a specific private key.
func NewMockKeystoreWithKey(keyID KeyID, privateKey ed25519.PrivateKey) *MockKeystore {
	return &MockKeystore{
		keyID:      keyID,
		privateKey: privateKey,
	}
}

func (m *MockKeystore) KeyID() KeyID {
	return m.keyID
}

func (m *MockKeystore) PublicKey() (ed25519.PublicKey, error) {
	return m.privateKey.Public().(ed25519.PublicKey), nil
}

func (m *MockKeystore) PublicKeyX25519() ([32]byte, error) {
	x25519Priv, err := Ed25519ToX25519PrivateKey(m.privateKey)
	if err != nil {
		return [32]byte{}, err
	}
	// Compute X25519 public key from private key using scalar base multiplication
	return ScalarBaseMult(x25519Priv)
}

// Sign creates an Ed25519 signature over the message with domain separation.
// The signing process computes SHA-256(context || msg) then signs the digest.
// This matches the real keystore implementation exactly.
func (m *MockKeystore) Sign(msg, context Context) ([]byte, error) {
	// Compute digest with domain separation: SHA-256(context || msg)
	h := sha256.New()
	h.Write(context)
	h.Write(msg)
	digest := h.Sum(nil)

	// Ed25519.Sign returns a 64-byte signature
	signature := ed25519.Sign(m.privateKey, digest)
	return signature, nil
}

// Verify checks an Ed25519 signature against the provided public key.
// The verification process computes SHA-256(context || msg) then verifies.
// This matches the real keystore implementation exactly.
func (m *MockKeystore) Verify(pubKey ed25519.PublicKey, msg, sig, context Context) error {
	// Compute digest with domain separation: SHA-256(context || msg)
	h := sha256.New()
	h.Write(context)
	h.Write(msg)
	digest := h.Sum(nil)

	if !ed25519.Verify(pubKey, digest, sig) {
		return errors.New("signature verification failed")
	}
	return nil
}

// EncryptFor encrypts plaintext for a recipient using hybrid encryption.
// Wire format: [ephemeral_x25519_public_key:32][nonce:12][ciphertext+tag]
// This matches the real keystore implementation exactly.
func (m *MockKeystore) EncryptFor(recipientPub [32]byte, plaintext []byte, context Context) ([]byte, KeyID, error) {
	// Generate ephemeral Ed25519 key pair
	ephemeralPublic, ephemeralPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, m.keyID, fmt.Errorf("failed to generate ephemeral key: %w", err)
	}

	// Convert Ed25519 keys to X25519 for key exchange
	ephemeralX25519Private, err := Ed25519ToX25519PrivateKey(ephemeralPrivate)
	if err != nil {
		return nil, m.keyID, fmt.Errorf("failed to convert ephemeral private key to X25519: %w", err)
	}

	// Compute shared secret using X25519
	sharedSecret, err := ScalarMult(ephemeralX25519Private, recipientPub)
	if err != nil {
		return nil, m.keyID, fmt.Errorf("failed to compute shared secret: %w", err)
	}

	// Derive AES key from shared secret using HKDF with context
	aesKey, err := DeriveKeyFromSecret(sharedSecret[:], context)
	if err != nil {
		return nil, m.keyID, fmt.Errorf("failed to derive key: %w", err)
	}

	// Encrypt with AES-GCM
	nonce := make([]byte, 12) // GCM standard nonce size
	if _, err := rand.Read(nonce); err != nil {
		return nil, m.keyID, fmt.Errorf("failed to generate nonce: %w", err)
	}

	block, err := aes.NewCipher(aesKey[:])
	if err != nil {
		return nil, m.keyID, fmt.Errorf("failed to create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, m.keyID, fmt.Errorf("failed to create GCM: %w", err)
	}

	ciphertext := gcm.Seal(nil, nonce, plaintext, nil)

	// Encode ephemeral X25519 public key (32 bytes)
	ephemeralX25519PubBytes, err := Ed25519ToX25519PublicKey(ephemeralPublic)
	if err != nil {
		return nil, m.keyID, fmt.Errorf("failed to convert ephemeral public key to X25519: %w", err)
	}

	// Build result: [ephemeral_x25519_public_key:32][nonce:12][ciphertext+tag]
	result := make([]byte, 0, 32+12+len(ciphertext))
	result = append(result, ephemeralX25519PubBytes...)
	result = append(result, nonce...)
	result = append(result, ciphertext...)

	return result, m.keyID, nil
}

// Decrypt decrypts ciphertext that was encrypted to this keystore's key.
// This matches the real keystore implementation exactly.
func (m *MockKeystore) Decrypt(ciphertext []byte, context Context) ([]byte, KeyID, error) {
	if len(ciphertext) < 32+12+16 { // Need at least ephemeral key (32) + nonce (12) + tag (16)
		return nil, m.keyID, errors.New("encrypted blob too short")
	}

	// Extract ephemeral X25519 public key (32 bytes)
	var ephemeralX25519PubKey [32]byte
	copy(ephemeralX25519PubKey[:], ciphertext[:32])

	// Convert our private key to X25519
	x25519PrivateKey, err := Ed25519ToX25519PrivateKey(m.privateKey)
	if err != nil {
		return nil, m.keyID, fmt.Errorf("failed to convert private key to X25519: %w", err)
	}

	// Compute shared secret using X25519
	sharedSecret, err := ScalarMult(x25519PrivateKey, ephemeralX25519PubKey)
	if err != nil {
		return nil, m.keyID, fmt.Errorf("failed to compute shared secret: %w", err)
	}

	// Derive AES key from shared secret using HKDF with context
	aesKey, err := DeriveKeyFromSecret(sharedSecret[:], context)
	if err != nil {
		return nil, m.keyID, fmt.Errorf("failed to derive key: %w", err)
	}

	// Extract nonce and ciphertext
	encryptedData := ciphertext[32:]
	if len(encryptedData) < 12+16 { // Need at least nonce (12) + tag (16)
		return nil, m.keyID, errors.New("encrypted data too short")
	}

	nonce := encryptedData[:12]
	data := encryptedData[12:]

	block, err := aes.NewCipher(aesKey[:])
	if err != nil {
		return nil, m.keyID, fmt.Errorf("failed to create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, m.keyID, fmt.Errorf("failed to create GCM: %w", err)
	}

	// Decrypt and verify authentication tag
	plaintext, err := gcm.Open(nil, nonce, data, nil)
	if err != nil {
		return nil, m.keyID, fmt.Errorf("failed to decrypt: %w", err)
	}

	return plaintext, m.keyID, nil
}

// TestKeyIDWiredCorrectly verifies that KeyID returns the correct identifier.
func TestKeyIDWiredCorrectly(t *testing.T) {
	testCases := []struct {
		name  string
		keyID KeyID
	}{
		{"simple-key", KeyID("simple-key")},
		{"exploit-owner-key", KeyID("exploit-owner-key")},
		{"target-client-key", KeyID("target-client-key")},
		{"harness-pentester-key", KeyID("harness-pentester-key")},
		{"key-with-special-chars-123_abc", KeyID("key-with-special-chars-123_abc")},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ks, err := NewMockKeystore(tc.keyID)
			if err != nil {
				t.Fatalf("failed to create mock keystore: %v", err)
			}

			if got := ks.KeyID(); got != tc.keyID {
				t.Errorf("KeyID() = %q, want %q", got, tc.keyID)
			}
		})
	}
}

// TestSignVerifyRoundtrip tests that Sign + Verify works correctly.
func TestSignVerifyRoundtrip(t *testing.T) {
	ks, err := NewMockKeystore("test-key")
	if err != nil {
		t.Fatalf("failed to create mock keystore: %v", err)
	}

	pubKey, err := ks.PublicKey()
	if err != nil {
		t.Fatalf("failed to get public key: %v", err)
	}

	testCases := []struct {
		name    string
		msg     []byte
		context Context
	}{
		{"simple-message", []byte("hello world"), Context("test-context")},
		{"empty-message", []byte{}, Context("empty-msg-context")},
		{"binary-message", []byte{0x00, 0xFF, 0x80, 0x7F}, Context("binary-context")},
		{"payload-signature", []byte("encrypted payload hash"), Context("harness:payload-signature")},
		{"client-signature", []byte("client approval data"), Context("harness:client-signature")},
		{"long-message", bytes.Repeat([]byte("a"), 10000), Context("long-msg-context")},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Sign the message
			sig, err := ks.Sign(tc.msg, tc.context)
			if err != nil {
				t.Fatalf("Sign() failed: %v", err)
			}

			// Verify should succeed with correct public key
			if err := ks.Verify(pubKey, tc.msg, sig, tc.context); err != nil {
				t.Errorf("Verify() failed for valid signature: %v", err)
			}
		})
	}
}

// TestVerifyFailsForTamperedData tests that Verify fails when data is tampered.
func TestVerifyFailsForTamperedData(t *testing.T) {
	ks, err := NewMockKeystore("test-key")
	if err != nil {
		t.Fatalf("failed to create mock keystore: %v", err)
	}

	pubKey, err := ks.PublicKey()
	if err != nil {
		t.Fatalf("failed to get public key: %v", err)
	}

	msg := []byte("original message")
	context := Context("test-context")

	sig, err := ks.Sign(msg, context)
	if err != nil {
		t.Fatalf("Sign() failed: %v", err)
	}

	// Test: tampered message should fail verification
	t.Run("tampered-message", func(t *testing.T) {
		tamperedMsg := []byte("tampered message")
		if err := ks.Verify(pubKey, tamperedMsg, sig, context); err == nil {
			t.Error("Verify() should fail for tampered message, but it succeeded")
		}
	})

	// Test: wrong context should fail verification
	t.Run("wrong-context", func(t *testing.T) {
		wrongContext := Context("wrong-context")
		if err := ks.Verify(pubKey, msg, sig, wrongContext); err == nil {
			t.Error("Verify() should fail for wrong context, but it succeeded")
		}
	})

	// Test: tampered signature should fail verification
	t.Run("tampered-signature", func(t *testing.T) {
		tamperedSig := make([]byte, len(sig))
		copy(tamperedSig, sig)
		tamperedSig[0] ^= 0xFF // Flip bits in first byte
		if err := ks.Verify(pubKey, msg, tamperedSig, context); err == nil {
			t.Error("Verify() should fail for tampered signature, but it succeeded")
		}
	})
}

// TestVerifyFailsForWrongPublicKey tests that Verify fails when using wrong public key.
func TestVerifyFailsForWrongPublicKey(t *testing.T) {
	ks1, err := NewMockKeystore("key-1")
	if err != nil {
		t.Fatalf("failed to create mock keystore 1: %v", err)
	}

	ks2, err := NewMockKeystore("key-2")
	if err != nil {
		t.Fatalf("failed to create mock keystore 2: %v", err)
	}

	// Get public key from second keystore
	wrongPubKey, err := ks2.PublicKey()
	if err != nil {
		t.Fatalf("failed to get public key from ks2: %v", err)
	}

	msg := []byte("test message")
	context := Context("test-context")

	// Sign with first keystore
	sig, err := ks1.Sign(msg, context)
	if err != nil {
		t.Fatalf("Sign() failed: %v", err)
	}

	// Verify with wrong public key should fail
	// This tests that EO signature vs Client signature verification is explicit
	if err := ks1.Verify(wrongPubKey, msg, sig, context); err == nil {
		t.Error("Verify() should fail for wrong public key, but it succeeded")
	}
}

// TestEncryptDecryptRoundtrip tests that EncryptFor + Decrypt roundtrip works.
func TestEncryptDecryptRoundtrip(t *testing.T) {
	// Create sender and recipient keystores
	sender, err := NewMockKeystore("sender-key")
	if err != nil {
		t.Fatalf("failed to create sender keystore: %v", err)
	}

	recipient, err := NewMockKeystore("recipient-key")
	if err != nil {
		t.Fatalf("failed to create recipient keystore: %v", err)
	}

	recipientPubX, err := recipient.PublicKeyX25519()
	if err != nil {
		t.Fatalf("failed to get recipient X25519 public key: %v", err)
	}

	testCases := []struct {
		name      string
		plaintext []byte
		context   Context
	}{
		{"simple-text", []byte("hello world"), Context("harness:symmetric-key")},
		{"empty-plaintext", []byte{}, Context("harness:args")},
		{"binary-data", []byte{0x00, 0xFF, 0x80, 0x7F, 0x01, 0x02}, Context("harness:envelope")},
		{"json-args", []byte(`{"host":"example.com","port":443}`), Context("harness:args")},
		{"large-payload", bytes.Repeat([]byte("x"), 100000), Context("harness:payload")},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Encrypt
			ciphertext, senderKeyID, err := sender.EncryptFor(recipientPubX, tc.plaintext, tc.context)
			if err != nil {
				t.Fatalf("EncryptFor() failed: %v", err)
			}

			// Verify sender key ID is returned
			if senderKeyID != sender.KeyID() {
				t.Errorf("EncryptFor() returned wrong senderKeyID: got %q, want %q", senderKeyID, sender.KeyID())
			}

			// Decrypt
			decrypted, receiverKeyID, err := recipient.Decrypt(ciphertext, tc.context)
			if err != nil {
				t.Fatalf("Decrypt() failed: %v", err)
			}

			// Verify receiver key ID is returned
			if receiverKeyID != recipient.KeyID() {
				t.Errorf("Decrypt() returned wrong receiverKeyID: got %q, want %q", receiverKeyID, recipient.KeyID())
			}

			// Verify decrypted matches original (accounting for mock implementation)
			if !bytes.Equal(decrypted, tc.plaintext) {
				t.Errorf("Decrypt() returned wrong plaintext:\ngot:  %v\nwant: %v", decrypted, tc.plaintext)
			}
		})
	}
}

// TestContextDomainSeparation tests that different contexts produce different results.
func TestContextDomainSeparation(t *testing.T) {
	ks, err := NewMockKeystore("test-key")
	if err != nil {
		t.Fatalf("failed to create mock keystore: %v", err)
	}

	pubKey, err := ks.PublicKey()
	if err != nil {
		t.Fatalf("failed to get public key: %v", err)
	}

	msg := []byte("same message")
	context1 := Context("harness:payload-signature")
	context2 := Context("harness:client-signature")

	// Sign with context1
	sig1, err := ks.Sign(msg, context1)
	if err != nil {
		t.Fatalf("Sign() with context1 failed: %v", err)
	}

	// Sign with context2
	sig2, err := ks.Sign(msg, context2)
	if err != nil {
		t.Fatalf("Sign() with context2 failed: %v", err)
	}

	// Signatures should be different (different contexts)
	if bytes.Equal(sig1, sig2) {
		t.Error("Signatures should be different for different contexts")
	}

	// Verify sig1 with context1 should succeed
	if err := ks.Verify(pubKey, msg, sig1, context1); err != nil {
		t.Errorf("Verify() failed for sig1 with context1: %v", err)
	}

	// Verify sig1 with context2 should fail (wrong context)
	if err := ks.Verify(pubKey, msg, sig1, context2); err == nil {
		t.Error("Verify() should fail for sig1 with wrong context2")
	}

	// Verify sig2 with context2 should succeed
	if err := ks.Verify(pubKey, msg, sig2, context2); err != nil {
		t.Errorf("Verify() failed for sig2 with context2: %v", err)
	}

	// Verify sig2 with context1 should fail (wrong context)
	if err := ks.Verify(pubKey, msg, sig2, context1); err == nil {
		t.Error("Verify() should fail for sig2 with wrong context1")
	}
}

// TestPublicKeyConsistency tests that PublicKey returns consistent results.
func TestPublicKeyConsistency(t *testing.T) {
	ks, err := NewMockKeystore("test-key")
	if err != nil {
		t.Fatalf("failed to create mock keystore: %v", err)
	}

	// Get public key multiple times
	pub1, err := ks.PublicKey()
	if err != nil {
		t.Fatalf("PublicKey() call 1 failed: %v", err)
	}

	pub2, err := ks.PublicKey()
	if err != nil {
		t.Fatalf("PublicKey() call 2 failed: %v", err)
	}

	pub3, err := ks.PublicKey()
	if err != nil {
		t.Fatalf("PublicKey() call 3 failed: %v", err)
	}

	// All should be equal
	if !bytes.Equal(pub1, pub2) || !bytes.Equal(pub2, pub3) {
		t.Error("PublicKey() should return consistent results")
	}

	// Should be correct size for Ed25519
	if len(pub1) != ed25519.PublicKeySize {
		t.Errorf("PublicKey() returned wrong size: got %d, want %d", len(pub1), ed25519.PublicKeySize)
	}
}

// TestEd25519ToX25519KeyConversion tests the key conversion functions.
func TestEd25519ToX25519KeyConversion(t *testing.T) {
	// Generate a test key pair
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key pair: %v", err)
	}

	// Test private key conversion
	t.Run("private-key-conversion", func(t *testing.T) {
		x25519Priv, err := Ed25519ToX25519PrivateKey(privateKey)
		if err != nil {
			t.Fatalf("Ed25519ToX25519PrivateKey() failed: %v", err)
		}
		if len(x25519Priv) != 32 {
			t.Errorf("X25519 private key wrong size: got %d, want 32", len(x25519Priv))
		}
	})

	// Test public key conversion
	t.Run("public-key-conversion", func(t *testing.T) {
		x25519Pub, err := Ed25519ToX25519PublicKey(publicKey)
		if err != nil {
			t.Fatalf("Ed25519ToX25519PublicKey() failed: %v", err)
		}
		if len(x25519Pub) != 32 {
			t.Errorf("X25519 public key wrong size: got %d, want 32", len(x25519Pub))
		}
	})

	// Test invalid key sizes
	t.Run("invalid-private-key-size", func(t *testing.T) {
		_, err := Ed25519ToX25519PrivateKey([]byte("too short"))
		if err != ErrInvalidKeySize {
			t.Errorf("expected ErrInvalidKeySize, got %v", err)
		}
	})

	t.Run("invalid-public-key-size", func(t *testing.T) {
		_, err := Ed25519ToX25519PublicKey([]byte("too short"))
		if err != ErrInvalidKeySize {
			t.Errorf("expected ErrInvalidKeySize, got %v", err)
		}
	})
}
