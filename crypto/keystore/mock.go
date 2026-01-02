package keystore

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
)

// MockKeystore is an in-memory implementation of Keystore for testing.
// It implements the full Keystore interface using memory-based key storage.
// This is exported so it can be used by tests in other packages.
type MockKeystore struct {
	keyID      KeyID
	privateKey ed25519.PrivateKey
}

// NewMockKeystore creates a new in-memory keystore for testing.
// This is exported so it can be used by tests in other packages.
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

	// Use context as AAD for domain separation (RFC compliance)
	ciphertext := gcm.Seal(nil, nonce, plaintext, context)

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

	// Decrypt and verify authentication tag (context as AAD for domain separation)
	plaintext, err := gcm.Open(nil, nonce, data, context)
	if err != nil {
		return nil, m.keyID, fmt.Errorf("failed to decrypt: %w", err)
	}

	return plaintext, m.keyID, nil
}
