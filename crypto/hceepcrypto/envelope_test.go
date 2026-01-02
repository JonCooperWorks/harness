package hceepcrypto

import (
	"bytes"
	"testing"

	"github.com/joncooperworks/harness/crypto/keystore"
)

func TestNewEnvelopeCipher(t *testing.T) {
	mockKS, err := keystore.NewMockKeystore("test-key")
	if err != nil {
		t.Fatalf("failed to create mock keystore: %v", err)
	}

	cipher := NewEnvelopeCipher(mockKS)
	if cipher == nil {
		t.Fatal("NewEnvelopeCipher() returned nil")
	}

	// Verify Keystore() returns the original keystore
	if cipher.Keystore() != mockKS {
		t.Error("Keystore() did not return the original keystore")
	}
}

func TestEnvelopeCipher_EncryptToPeer(t *testing.T) {
	// Create sender and recipient keystores
	sender, err := keystore.NewMockKeystore("sender-key")
	if err != nil {
		t.Fatalf("failed to create sender keystore: %v", err)
	}

	recipient, err := keystore.NewMockKeystore("recipient-key")
	if err != nil {
		t.Fatalf("failed to create recipient keystore: %v", err)
	}

	recipientPubX, err := recipient.PublicKeyX25519()
	if err != nil {
		t.Fatalf("failed to get recipient X25519 public key: %v", err)
	}

	// Create cipher from sender keystore
	cipher := NewEnvelopeCipher(sender)

	tests := []struct {
		name      string
		plaintext []byte
		context   Context
	}{
		{"simple text", []byte("hello world"), ContextSymmetricKey},
		{"empty plaintext", []byte{}, ContextArgs},
		{"binary data", []byte{0x00, 0xFF, 0x80, 0x7F}, ContextEnvelope},
		{"larger payload", bytes.Repeat([]byte("x"), 1000), ContextSymmetricKey},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ciphertext, err := cipher.EncryptToPeer(recipientPubX, tt.context, tt.plaintext)
			if err != nil {
				t.Fatalf("EncryptToPeer() error = %v", err)
			}

			// Verify ciphertext is not empty
			if len(ciphertext) == 0 {
				t.Error("EncryptToPeer() returned empty ciphertext")
			}

			// Verify ciphertext is different from plaintext
			if bytes.Equal(ciphertext, tt.plaintext) {
				t.Error("EncryptToPeer() returned ciphertext equal to plaintext")
			}

			// Verify ciphertext has minimum size (ephemeral key 32 + nonce 12 + tag 16)
			if len(ciphertext) < 32+12+16 {
				t.Errorf("EncryptToPeer() returned ciphertext too short: %d bytes", len(ciphertext))
			}
		})
	}
}

func TestEnvelopeCipher_DecryptFromPeer(t *testing.T) {
	// Create sender and recipient keystores
	sender, err := keystore.NewMockKeystore("sender-key")
	if err != nil {
		t.Fatalf("failed to create sender keystore: %v", err)
	}

	recipient, err := keystore.NewMockKeystore("recipient-key")
	if err != nil {
		t.Fatalf("failed to create recipient keystore: %v", err)
	}

	recipientPubX, err := recipient.PublicKeyX25519()
	if err != nil {
		t.Fatalf("failed to get recipient X25519 public key: %v", err)
	}

	// Create ciphers
	senderCipher := NewEnvelopeCipher(sender)
	recipientCipher := NewEnvelopeCipher(recipient)

	tests := []struct {
		name      string
		plaintext []byte
		context   Context
	}{
		{"simple text", []byte("hello world"), ContextSymmetricKey},
		{"empty plaintext", []byte{}, ContextArgs},
		{"binary data", []byte{0x00, 0xFF, 0x80, 0x7F}, ContextEnvelope},
		{"json args", []byte(`{"arg":"value"}`), ContextArgs},
		{"larger payload", bytes.Repeat([]byte("x"), 5000), ContextSymmetricKey},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Encrypt
			ciphertext, err := senderCipher.EncryptToPeer(recipientPubX, tt.context, tt.plaintext)
			if err != nil {
				t.Fatalf("EncryptToPeer() error = %v", err)
			}

			// Decrypt
			decrypted, err := recipientCipher.DecryptFromPeer(tt.context, ciphertext)
			if err != nil {
				t.Fatalf("DecryptFromPeer() error = %v", err)
			}

			// Verify decrypted matches original
			if !bytes.Equal(decrypted, tt.plaintext) {
				t.Errorf("DecryptFromPeer() = %v, want %v", decrypted, tt.plaintext)
			}
		})
	}
}

func TestEnvelopeCipher_EncryptDecryptRoundtrip(t *testing.T) {
	// Create sender and recipient keystores
	sender, err := keystore.NewMockKeystore("sender-key")
	if err != nil {
		t.Fatalf("failed to create sender keystore: %v", err)
	}

	recipient, err := keystore.NewMockKeystore("recipient-key")
	if err != nil {
		t.Fatalf("failed to create recipient keystore: %v", err)
	}

	recipientPubX, err := recipient.PublicKeyX25519()
	if err != nil {
		t.Fatalf("failed to get recipient X25519 public key: %v", err)
	}

	// Create ciphers
	senderCipher := NewEnvelopeCipher(sender)
	recipientCipher := NewEnvelopeCipher(recipient)

	plaintext := []byte("test message for roundtrip")
	context := ContextSymmetricKey

	// Encrypt
	ciphertext, err := senderCipher.EncryptToPeer(recipientPubX, context, plaintext)
	if err != nil {
		t.Fatalf("EncryptToPeer() error = %v", err)
	}

	// Decrypt
	decrypted, err := recipientCipher.DecryptFromPeer(context, ciphertext)
	if err != nil {
		t.Fatalf("DecryptFromPeer() error = %v", err)
	}

	// Verify roundtrip
	if !bytes.Equal(decrypted, plaintext) {
		t.Errorf("roundtrip failed: got %v, want %v", decrypted, plaintext)
	}

	// Verify ciphertext is different each time (due to ephemeral keys)
	ciphertext2, err := senderCipher.EncryptToPeer(recipientPubX, context, plaintext)
	if err != nil {
		t.Fatalf("EncryptToPeer() second call error = %v", err)
	}
	if bytes.Equal(ciphertext, ciphertext2) {
		t.Error("EncryptToPeer() returned same ciphertext for same plaintext (should use different ephemeral keys)")
	}

	// But both should decrypt to the same plaintext
	decrypted2, err := recipientCipher.DecryptFromPeer(context, ciphertext2)
	if err != nil {
		t.Fatalf("DecryptFromPeer() second call error = %v", err)
	}
	if !bytes.Equal(decrypted2, plaintext) {
		t.Errorf("second decryption failed: got %v, want %v", decrypted2, plaintext)
	}
}

func TestEnvelopeCipher_Keystore(t *testing.T) {
	mockKS, err := keystore.NewMockKeystore("test-key")
	if err != nil {
		t.Fatalf("failed to create mock keystore: %v", err)
	}

	cipher := NewEnvelopeCipher(mockKS)

	// Verify Keystore() returns the same keystore
	ks := cipher.Keystore()
	if ks != mockKS {
		t.Error("Keystore() did not return the original keystore")
	}

	// Verify we can call methods on the returned keystore
	keyID := ks.KeyID()
	if keyID != "test-key" {
		t.Errorf("keystore.KeyID() = %q, want %q", keyID, "test-key")
	}
}

func TestEnvelopeCipher_WrongContext(t *testing.T) {
	// Create sender and recipient keystores
	sender, err := keystore.NewMockKeystore("sender-key")
	if err != nil {
		t.Fatalf("failed to create sender keystore: %v", err)
	}

	recipient, err := keystore.NewMockKeystore("recipient-key")
	if err != nil {
		t.Fatalf("failed to create recipient keystore: %v", err)
	}

	recipientPubX, err := recipient.PublicKeyX25519()
	if err != nil {
		t.Fatalf("failed to get recipient X25519 public key: %v", err)
	}

	// Create ciphers
	senderCipher := NewEnvelopeCipher(sender)
	recipientCipher := NewEnvelopeCipher(recipient)

	plaintext := []byte("test message")
	encryptContext := ContextSymmetricKey
	decryptContext := ContextArgs // Wrong context

	// Encrypt with one context
	ciphertext, err := senderCipher.EncryptToPeer(recipientPubX, encryptContext, plaintext)
	if err != nil {
		t.Fatalf("EncryptToPeer() error = %v", err)
	}

	// Try to decrypt with wrong context - should fail
	_, err = recipientCipher.DecryptFromPeer(decryptContext, ciphertext)
	if err == nil {
		t.Error("DecryptFromPeer() with wrong context should have failed")
	}
}

func TestEnvelopeCipher_WrongRecipient(t *testing.T) {
	// Create three keystores: sender, correct recipient, wrong recipient
	sender, err := keystore.NewMockKeystore("sender-key")
	if err != nil {
		t.Fatalf("failed to create sender keystore: %v", err)
	}

	recipient, err := keystore.NewMockKeystore("recipient-key")
	if err != nil {
		t.Fatalf("failed to create recipient keystore: %v", err)
	}

	wrongRecipient, err := keystore.NewMockKeystore("wrong-recipient-key")
	if err != nil {
		t.Fatalf("failed to create wrong recipient keystore: %v", err)
	}

	recipientPubX, err := recipient.PublicKeyX25519()
	if err != nil {
		t.Fatalf("failed to get recipient X25519 public key: %v", err)
	}

	// Create ciphers
	senderCipher := NewEnvelopeCipher(sender)
	wrongRecipientCipher := NewEnvelopeCipher(wrongRecipient)

	plaintext := []byte("test message")
	context := ContextSymmetricKey

	// Encrypt for correct recipient
	ciphertext, err := senderCipher.EncryptToPeer(recipientPubX, context, plaintext)
	if err != nil {
		t.Fatalf("EncryptToPeer() error = %v", err)
	}

	// Try to decrypt with wrong recipient - should fail
	_, err = wrongRecipientCipher.DecryptFromPeer(context, ciphertext)
	if err == nil {
		t.Error("DecryptFromPeer() with wrong recipient should have failed")
	}
}
