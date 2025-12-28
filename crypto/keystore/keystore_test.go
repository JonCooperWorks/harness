package keystore

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"testing"
)

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
