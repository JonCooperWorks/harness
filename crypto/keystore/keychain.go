//go:build darwin
// +build darwin

package keystore

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"

	"github.com/99designs/keyring"
)

func init() {
	RegisterKeystore("darwin", NewKeychainKeyManager)
}

// KeychainKeyManager implements KeyManager for macOS using Keychain.
// It provides key management operations (SetPrivateKey, ListKeys) and
// can create bound Keystore instances for cryptographic operations.
type KeychainKeyManager struct {
	ring keyring.Keyring
}

// NewKeychainKeyManager creates a new macOS Keychain key manager.
// Uses HARNESS_KEYCHAIN environment variable if set, otherwise uses default login keychain.
// Set HARNESS_KEYCHAIN="harness-keys" to use custom keychain, or "" for default login keychain.
func NewKeychainKeyManager() (KeyManager, error) {
	keychainName := os.Getenv("HARNESS_KEYCHAIN")
	// If not set, default to empty (login keychain) to avoid double password prompts
	// Set HARNESS_KEYCHAIN="harness-keys" to use the custom keychain

	ring, err := keyring.Open(keyring.Config{
		ServiceName:              "harness",
		KeychainName:             keychainName, // Empty = default login keychain, "harness-keys" = custom keychain
		KeychainPasswordFunc:     nil,          // Use default keychain
		KeychainTrustApplication: true,
		// Use login keychain by default (unlocked when logged in, fewer prompts)
		// Only prompt if using a custom keychain that requires unlocking
	})
	if err != nil {
		return nil, fmt.Errorf("failed to open keychain: %w", err)
	}

	return &KeychainKeyManager{ring: ring}, nil
}

// SetPrivateKey stores an Ed25519 private key in macOS Keychain.
func (k *KeychainKeyManager) SetPrivateKey(id KeyID, privateKey ed25519.PrivateKey) error {
	// Encode private key to PEM format (PKCS8)
	privateKeyBytes, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return fmt.Errorf("failed to marshal private key: %w", err)
	}

	privateKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: privateKeyBytes,
	})

	// Store in keychain
	err = k.ring.Set(keyring.Item{
		Key:  string(id),
		Data: privateKeyPEM,
	})
	if err != nil {
		return fmt.Errorf("failed to store key in keychain: %w", err)
	}

	return nil
}

// ListKeys returns all key IDs stored in macOS Keychain.
func (k *KeychainKeyManager) ListKeys() ([]KeyID, error) {
	keys, err := k.ring.Keys()
	if err != nil {
		return nil, fmt.Errorf("failed to list keys from keychain: %w", err)
	}
	result := make([]KeyID, len(keys))
	for i, key := range keys {
		result[i] = KeyID(key)
	}
	return result, nil
}

// ForKey creates a Keystore bound to the specified key ID.
// The returned Keystore can be used for cryptographic operations with that key.
func (k *KeychainKeyManager) ForKey(id KeyID) (Keystore, error) {
	// Verify the key exists by trying to retrieve it
	_, err := k.getPrivateKey(id)
	if err != nil {
		return nil, fmt.Errorf("key %s not found in keychain: %w", id, err)
	}

	return &keychainKeystore{
		ring:  k.ring,
		keyID: id,
	}, nil
}

// getPrivateKey retrieves an Ed25519 private key from macOS Keychain (internal helper).
func (k *KeychainKeyManager) getPrivateKey(keyID KeyID) (ed25519.PrivateKey, error) {
	item, err := k.ring.Get(string(keyID))
	if err != nil {
		return nil, fmt.Errorf("failed to get key from keychain: %w", err)
	}

	// Parse PEM format
	block, _ := pem.Decode(item.Data)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}

	// Try PKCS8 format
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err == nil {
		if ed25519Key, ok := key.(ed25519.PrivateKey); ok {
			return ed25519Key, nil
		}
		return nil, fmt.Errorf("key is not Ed25519")
	}

	// Try raw Ed25519 private key (64 bytes)
	if len(block.Bytes) == ed25519.PrivateKeySize {
		return ed25519.PrivateKey(block.Bytes), nil
	}

	return nil, fmt.Errorf("failed to parse private key: unsupported format")
}

// keychainKeystore implements Keystore for macOS, bound to a specific key.
type keychainKeystore struct {
	ring  keyring.Keyring
	keyID KeyID
}

// KeyID returns the stable identifier for this keystore's key.
func (k *keychainKeystore) KeyID() KeyID {
	return k.keyID
}

// PublicKey returns the Ed25519 public key for this keystore's key.
func (k *keychainKeystore) PublicKey() (ed25519.PublicKey, error) {
	privateKey, err := k.getPrivateKey()
	if err != nil {
		return nil, err
	}
	return privateKey.Public().(ed25519.PublicKey), nil
}

// PublicKeyX25519 returns the X25519 public key derived from this keystore's Ed25519 key.
func (k *keychainKeystore) PublicKeyX25519() ([32]byte, error) {
	privateKey, err := k.getPrivateKey()
	if err != nil {
		return [32]byte{}, err
	}

	// Convert Ed25519 private key to X25519
	x25519PrivateKey, err := Ed25519ToX25519PrivateKey(privateKey)
	if err != nil {
		return [32]byte{}, fmt.Errorf("failed to convert private key to X25519: %w", err)
	}

	// Compute X25519 public key from private key
	x25519Pub, err := ScalarBaseMult(x25519PrivateKey)
	if err != nil {
		return [32]byte{}, fmt.Errorf("failed to compute X25519 public key: %w", err)
	}

	return x25519Pub, nil
}

// Sign creates an Ed25519 signature over the message with domain separation.
// The signing process computes SHA-256(context || msg) then signs the digest.
func (k *keychainKeystore) Sign(msg, context Context) ([]byte, error) {
	privateKey, err := k.getPrivateKey()
	if err != nil {
		return nil, err
	}

	// Compute digest with domain separation: SHA-256(context || msg)
	h := sha256.New()
	h.Write(context)
	h.Write(msg)
	digest := h.Sum(nil)

	// Ed25519.Sign returns a 64-byte signature
	signature := ed25519.Sign(privateKey, digest)
	return signature, nil
}

// Verify checks an Ed25519 signature against the provided public key.
// The verification process computes SHA-256(context || msg) then verifies.
func (k *keychainKeystore) Verify(pubKey ed25519.PublicKey, msg, sig, context Context) error {
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
func (k *keychainKeystore) EncryptFor(recipientPub [32]byte, plaintext []byte, context Context) ([]byte, KeyID, error) {
	// Generate ephemeral Ed25519 key pair
	ephemeralPublic, ephemeralPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, k.keyID, fmt.Errorf("failed to generate ephemeral key: %w", err)
	}

	// Convert Ed25519 keys to X25519 for key exchange
	ephemeralX25519Private, err := Ed25519ToX25519PrivateKey(ephemeralPrivate)
	if err != nil {
		return nil, k.keyID, fmt.Errorf("failed to convert ephemeral private key to X25519: %w", err)
	}

	// Compute shared secret using X25519
	sharedSecret, err := ScalarMult(ephemeralX25519Private, recipientPub)
	if err != nil {
		return nil, k.keyID, fmt.Errorf("failed to compute shared secret: %w", err)
	}

	// Derive AES key from shared secret using HKDF with context
	aesKey, err := DeriveKeyFromSecret(sharedSecret[:], context)
	if err != nil {
		return nil, k.keyID, fmt.Errorf("failed to derive key: %w", err)
	}

	// Encrypt with AES-GCM
	nonce := make([]byte, 12) // GCM standard nonce size
	if _, err := rand.Read(nonce); err != nil {
		return nil, k.keyID, fmt.Errorf("failed to generate nonce: %w", err)
	}

	block, err := aes.NewCipher(aesKey[:])
	if err != nil {
		return nil, k.keyID, fmt.Errorf("failed to create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, k.keyID, fmt.Errorf("failed to create GCM: %w", err)
	}

	ciphertext := gcm.Seal(nil, nonce, plaintext, nil)

	// Encode ephemeral X25519 public key (32 bytes)
	ephemeralX25519PubBytes, err := Ed25519ToX25519PublicKey(ephemeralPublic)
	if err != nil {
		return nil, k.keyID, fmt.Errorf("failed to convert ephemeral public key to X25519: %w", err)
	}

	// Build result: [ephemeral_x25519_public_key:32][nonce:12][ciphertext+tag]
	result := make([]byte, 0, 32+12+len(ciphertext))
	result = append(result, ephemeralX25519PubBytes...)
	result = append(result, nonce...)
	result = append(result, ciphertext...)

	return result, k.keyID, nil
}

// Decrypt decrypts ciphertext that was encrypted to this keystore's key.
func (k *keychainKeystore) Decrypt(ciphertext []byte, context Context) ([]byte, KeyID, error) {
	if len(ciphertext) < 32+12+16 { // Need at least ephemeral key (32) + nonce (12) + tag (16)
		return nil, k.keyID, errors.New("encrypted blob too short")
	}

	// Extract ephemeral X25519 public key (32 bytes)
	var ephemeralX25519PubKey [32]byte
	copy(ephemeralX25519PubKey[:], ciphertext[:32])

	// Get our private key and convert to X25519
	privateKey, err := k.getPrivateKey()
	if err != nil {
		return nil, k.keyID, err
	}

	x25519PrivateKey, err := Ed25519ToX25519PrivateKey(privateKey)
	if err != nil {
		return nil, k.keyID, fmt.Errorf("failed to convert private key to X25519: %w", err)
	}

	// Compute shared secret using X25519
	sharedSecret, err := ScalarMult(x25519PrivateKey, ephemeralX25519PubKey)
	if err != nil {
		return nil, k.keyID, fmt.Errorf("failed to compute shared secret: %w", err)
	}

	// Derive AES key from shared secret using HKDF with context
	aesKey, err := DeriveKeyFromSecret(sharedSecret[:], context)
	if err != nil {
		return nil, k.keyID, fmt.Errorf("failed to derive key: %w", err)
	}

	// Extract nonce and ciphertext
	encryptedData := ciphertext[32:]
	if len(encryptedData) < 12+16 { // Need at least nonce (12) + tag (16)
		return nil, k.keyID, errors.New("encrypted data too short")
	}

	nonce := encryptedData[:12]
	data := encryptedData[12:]

	block, err := aes.NewCipher(aesKey[:])
	if err != nil {
		return nil, k.keyID, fmt.Errorf("failed to create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, k.keyID, fmt.Errorf("failed to create GCM: %w", err)
	}

	// Decrypt and verify authentication tag
	plaintext, err := gcm.Open(nil, nonce, data, nil)
	if err != nil {
		return nil, k.keyID, fmt.Errorf("failed to decrypt: %w", err)
	}

	return plaintext, k.keyID, nil
}

// getPrivateKey retrieves the Ed25519 private key for this keystore's key.
func (k *keychainKeystore) getPrivateKey() (ed25519.PrivateKey, error) {
	item, err := k.ring.Get(string(k.keyID))
	if err != nil {
		return nil, fmt.Errorf("failed to get key from keychain: %w", err)
	}

	// Parse PEM format
	block, _ := pem.Decode(item.Data)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}

	// Try PKCS8 format
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err == nil {
		if ed25519Key, ok := key.(ed25519.PrivateKey); ok {
			return ed25519Key, nil
		}
		return nil, fmt.Errorf("key is not Ed25519")
	}

	// Try raw Ed25519 private key (64 bytes)
	if len(block.Bytes) == ed25519.PrivateKeySize {
		return ed25519.PrivateKey(block.Bytes), nil
	}

	return nil, fmt.Errorf("failed to parse private key: unsupported format")
}
