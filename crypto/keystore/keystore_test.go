package keystore

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/rand"
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

func (m *MockKeystore) SignDirect(msg []byte) ([]byte, error) {
	signature := ed25519.Sign(m.privateKey, msg)
	return signature, nil
}

func (m *MockKeystore) VerifyDirect(pubKey ed25519.PublicKey, msg, sig []byte) error {
	if !ed25519.Verify(pubKey, msg, sig) {
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
