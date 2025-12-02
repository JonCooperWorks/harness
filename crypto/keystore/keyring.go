//go:build linux
// +build linux

package keystore

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"math/big"

	"github.com/99designs/keyring"
)

// KeyringKeystore implements Keystore for Linux using libsecret/keyring
type KeyringKeystore struct {
	ring keyring.Keyring
}

// NewKeyringKeystore creates a new Linux keyring keystore
func NewKeyringKeystore() (Keystore, error) {
	ring, err := keyring.Open(keyring.Config{
		ServiceName: "harness",
	})
	if err != nil {
		return nil, fmt.Errorf("failed to open keyring: %w", err)
	}

	return &KeyringKeystore{ring: ring}, nil
}

// GetPrivateKey retrieves an ECDSA private key from Linux keyring
func (k *KeyringKeystore) GetPrivateKey(keyID string) (*ecdsa.PrivateKey, error) {
	item, err := k.ring.Get(keyID)
	if err != nil {
		return nil, fmt.Errorf("failed to get key from keyring: %w", err)
	}

	// Parse PEM format
	block, _ := pem.Decode(item.Data)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}

	// Try PKCS8 format
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err == nil {
		if ecdsaKey, ok := key.(*ecdsa.PrivateKey); ok {
			return ecdsaKey, nil
		}
		return nil, fmt.Errorf("key is not ECDSA")
	}

	// Try EC private key format
	ecKey, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key: %w", err)
	}

	return ecKey, nil
}

// SetPrivateKey stores an ECDSA private key in Linux keyring
func (k *KeyringKeystore) SetPrivateKey(keyID string, privateKey *ecdsa.PrivateKey) error {
	// Encode private key to PEM format (PKCS8)
	privateKeyBytes, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return fmt.Errorf("failed to marshal private key: %w", err)
	}

	privateKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: privateKeyBytes,
	})

	// Store in keyring
	err = k.ring.Set(keyring.Item{
		Key:  keyID,
		Data: privateKeyPEM,
	})
	if err != nil {
		return fmt.Errorf("failed to store key in keyring: %w", err)
	}

	return nil
}

// GetPublicKey retrieves the public key associated with a key ID
func (k *KeyringKeystore) GetPublicKey(keyID string) (*ecdsa.PublicKey, error) {
	privateKey, err := k.GetPrivateKey(keyID)
	if err != nil {
		return nil, err
	}
	return &privateKey.PublicKey, nil
}

// Sign signs the provided data hash using the private key associated with keyID
func (k *KeyringKeystore) Sign(keyID string, hash []byte) ([]byte, error) {
	privateKey, err := k.GetPrivateKey(keyID)
	if err != nil {
		return nil, err
	}

	r, s, err := ecdsa.Sign(rand.Reader, privateKey, hash)
	if err != nil {
		return nil, fmt.Errorf("failed to sign: %w", err)
	}

	signature, err := asn1.Marshal(struct {
		R, S *big.Int
	}{R: r, S: s})
	if err != nil {
		return nil, fmt.Errorf("failed to marshal signature: %w", err)
	}

	return signature, nil
}

// DecryptSymmetricKey decrypts a symmetric key encrypted via ECDH
func (k *KeyringKeystore) DecryptSymmetricKey(keyID string, encryptedKey []byte) ([]byte, error) {
	if len(encryptedKey) < 65 {
		return nil, fmt.Errorf("encrypted key too short")
	}

	privateKey, err := k.GetPrivateKey(keyID)
	if err != nil {
		return nil, err
	}

	// Extract ephemeral public key (uncompressed format: 0x04 || x || y)
	pubKeyBytes := encryptedKey[:65]
	x := new(big.Int).SetBytes(pubKeyBytes[1:33])
	y := new(big.Int).SetBytes(pubKeyBytes[33:65])

	// Create public key from point
	ephemeralPubKey := &ecdsa.PublicKey{
		Curve: privateKey.Curve,
		X:     x,
		Y:     y,
	}

	// Compute shared secret using ECDH
	sharedX, _ := ephemeralPubKey.Curve.ScalarMult(ephemeralPubKey.X, ephemeralPubKey.Y, privateKey.D.Bytes())
	sharedSecret := sharedX.Bytes()

	// Derive AES key from shared secret using SHA256
	aesKey := sha256.Sum256(sharedSecret)

	// Decrypt the symmetric key
	encryptedSymmetricKey := encryptedKey[65:]
	if len(encryptedSymmetricKey) < 12+16 {
		return nil, fmt.Errorf("encrypted symmetric key too short")
	}

	// Extract nonce (first 12 bytes)
	nonce := encryptedSymmetricKey[:12]
	ciphertext := encryptedSymmetricKey[12:]

	block, err := aes.NewCipher(aesKey[:])
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	// Create GCM mode
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	// Decrypt and verify authentication tag
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt symmetric key: %w", err)
	}

	return plaintext, nil
}

// ListKeys returns all key IDs stored in Linux keyring
func (k *KeyringKeystore) ListKeys() ([]string, error) {
	keys, err := k.ring.Keys()
	if err != nil {
		return nil, fmt.Errorf("failed to list keys from keyring: %w", err)
	}
	return keys, nil
}
