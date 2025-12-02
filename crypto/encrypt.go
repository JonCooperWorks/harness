// Package crypto provides cryptographic operations for encrypting, signing, and decrypting plugins.
// It implements a dual-authorization model where plugins are encrypted with a pentester's public key
// and signed by both a principal (who encrypts) and a client (who approves execution arguments).
package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"github.com/joncooperworks/harness/crypto/keystore"
	"golang.org/x/crypto/curve25519"
)

// EncryptPluginRequest contains all the information needed to encrypt a plugin.
//
// The encryption process uses ECDH key exchange to encrypt a symmetric AES-256-GCM key
// with the pentester's public key, then encrypts the plugin data with that symmetric key.
// The principal signs the encrypted payload hash to provide cryptographic proof of approval.
type EncryptPluginRequest struct {
	// PluginData is the raw plugin binary data (e.g., WASM file).
	// The data is read from this io.Reader, making it suitable for streaming from S3, Lambda, etc.
	PluginData io.Reader
	// PluginType is the type identifier (e.g., "wasm", "python").
	// This must match a registered plugin loader type.
	PluginType string
	// PluginName is the name of the plugin.
	// If empty, the name may be extracted from plugin data by loading it separately.
	// Note: To extract the name, you'll need to load the plugin separately using the plugin package.
	PluginName string
	// HarnessPubKey is the pentester's public key for encrypting the symmetric key.
	// The symmetric key is encrypted using X25519 key exchange with this public key.
	HarnessPubKey ed25519.PublicKey
	// PrincipalKeystore is the keystore containing the principal's private key.
	// The principal's key is used to sign the encrypted payload hash.
	PrincipalKeystore keystore.Keystore
	// PrincipalKeyID is the key ID in the keystore for the principal's private key.
	// This key is used to sign the encrypted payload to prove principal approval.
	PrincipalKeyID string
}

// EncryptPluginResult contains the encrypted plugin data and metadata.
//
// The EncryptedData field contains the complete encrypted file format:
// [magic:4][version:1][flags:1][file_length:4][principal_sig_len:4][principal_sig][metadata_length:4][metadata][encrypted_symmetric_key][encrypted_plugin_data]
// Note: file_length is set to 0 initially and will be updated by SignEncryptedPlugin
type EncryptPluginResult struct {
	// EncryptedData is the complete encrypted file format:
	// [magic:4][version:1][flags:1][file_length:4][principal_sig_len:4][principal_sig][metadata_length:4][metadata][encrypted_symmetric_key][encrypted_plugin_data]
	EncryptedData []byte
	// PluginName is the name extracted from the plugin or provided in the request.
	PluginName string
}

// EncryptPlugin encrypts a plugin and signs it with the principal's key.
//
// This function implements the principal's role in the dual-authorization model:
//  1. Reads the plugin data from the provided io.Reader
//  2. Generates a random AES-256 symmetric key
//  3. Encrypts the plugin data with AES-256-GCM using the symmetric key
//  4. Encrypts the symmetric key using ECDH key exchange with the pentester's public key
//  5. Signs the encrypted payload hash with the principal's private key
//
// The function works with io.Reader, making it suitable for Lambda/S3 use cases where
// plugin data may be streamed rather than loaded entirely into memory.
//
// The returned EncryptedData can be further signed by a client using SignEncryptedPlugin
// to create an approved execution package.
func EncryptPlugin(req *EncryptPluginRequest) (*EncryptPluginResult, error) {
	if req == nil {
		return nil, errors.New("request cannot be nil")
	}
	if req.PluginData == nil {
		return nil, errors.New("plugin data reader cannot be nil")
	}
	if req.HarnessPubKey == nil {
		return nil, errors.New("harness public key cannot be nil")
	}
	if req.PrincipalKeystore == nil {
		return nil, errors.New("principal keystore cannot be nil")
	}
	if req.PrincipalKeyID == "" {
		return nil, errors.New("principal key ID cannot be empty")
	}

	// Read all plugin data
	pluginData, err := io.ReadAll(req.PluginData)
	if err != nil {
		return nil, fmt.Errorf("failed to read plugin data: %w", err)
	}

	// Use provided plugin name, or empty string if not provided
	pluginName := req.PluginName

	// Create payload
	payload := Payload{
		Type: PluginTypeString(req.PluginType),
		Name: pluginName,
		Data: pluginData,
	}

	// Marshal payload
	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal payload: %w", err)
	}

	// Generate symmetric key for AES encryption
	symmetricKey := make([]byte, 32) // AES-256
	if _, err := rand.Read(symmetricKey); err != nil {
		return nil, fmt.Errorf("failed to generate symmetric key: %w", err)
	}

	// Encrypt plugin data with AES
	encryptedPluginData, err := encryptAES(payloadJSON, symmetricKey)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt plugin data: %w", err)
	}

	// Encrypt symmetric key using ECDH with harness's public key
	encryptedSymmetricKey, err := encryptSymmetricKey(symmetricKey, req.HarnessPubKey)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt symmetric key: %w", err)
	}

	// Create metadata
	metadata := map[string]interface{}{
		"symmetric_key_len": len(encryptedSymmetricKey),
		"plugin_data_len":   len(encryptedPluginData),
		"algorithm":         "Ed25519+X25519+AES-256-GCM",
	}
	metadataJSON, err := json.Marshal(metadata)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal metadata: %w", err)
	}

	// Build encrypted payload: [metadata_length:4][metadata][encrypted_symmetric_key][encrypted_plugin_data]
	// This is what the principal signature will sign
	var encryptedPayload []byte
	metadataLenBuf := make([]byte, 4)
	binary.BigEndian.PutUint32(metadataLenBuf, uint32(len(metadataJSON)))
	encryptedPayload = append(encryptedPayload, metadataLenBuf...)
	encryptedPayload = append(encryptedPayload, metadataJSON...)
	encryptedPayload = append(encryptedPayload, encryptedSymmetricKey...)
	encryptedPayload = append(encryptedPayload, encryptedPluginData...)

	// Sign encrypted payload hash with principal key
	encryptedPayloadHash := sha256.Sum256(encryptedPayload)
	principalSignature, err := req.PrincipalKeystore.Sign(req.PrincipalKeyID, encryptedPayloadHash[:])
	if err != nil {
		return nil, fmt.Errorf("failed to sign encrypted payload: %w", err)
	}

	// Build encrypted file structure with header and principal signature:
	// [magic:4][version:1][flags:1][file_length:4][principal_sig_len:4][principal_sig][metadata_length:4][metadata][encrypted_symmetric_key][encrypted_plugin_data]
	var output []byte

	// Write magic bytes "HARN" (0x48 0x41 0x52 0x4E)
	output = append(output, []byte("HARN")...)

	// Write version (1 byte, version 1)
	output = append(output, byte(1))

	// Write flags (1 byte, currently 0 - reserved for future use)
	output = append(output, byte(0))

	// Write file length placeholder (4 bytes, will be updated by SignEncryptedPlugin)
	fileLengthBuf := make([]byte, 4)
	binary.BigEndian.PutUint32(fileLengthBuf, 0) // Placeholder
	output = append(output, fileLengthBuf...)

	// Write principal signature length
	principalSigLenBuf := make([]byte, 4)
	binary.BigEndian.PutUint32(principalSigLenBuf, uint32(len(principalSignature)))
	output = append(output, principalSigLenBuf...)

	// Write principal signature
	output = append(output, principalSignature...)

	// Write encrypted payload (already constructed above)
	output = append(output, encryptedPayload...)

	return &EncryptPluginResult{
		EncryptedData: output,
		PluginName:    pluginName,
	}, nil
}

// encryptSymmetricKey encrypts the symmetric key using X25519
func encryptSymmetricKey(symmetricKey []byte, publicKey ed25519.PublicKey) ([]byte, error) {
	if len(publicKey) != ed25519.PublicKeySize {
		return nil, errors.New("invalid public key size")
	}

	// Generate ephemeral Ed25519 key pair
	ephemeralPublic, ephemeralPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate ephemeral key: %w", err)
	}

	// Convert Ed25519 keys to X25519 for key exchange
	ephemeralX25519Private, err := keystore.Ed25519ToX25519PrivateKey(ephemeralPrivate)
	if err != nil {
		return nil, fmt.Errorf("failed to convert ephemeral private key to X25519: %w", err)
	}

	harnessX25519Public, err := keystore.Ed25519ToX25519PublicKey(publicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to convert harness public key to X25519: %w", err)
	}

	// Compute shared secret using X25519
	var sharedSecret [32]byte
	curve25519.ScalarMult(&sharedSecret, (*[32]byte)(ephemeralX25519Private), (*[32]byte)(harnessX25519Public))

	// Derive AES key from shared secret using HKDF
	aesKey, err := deriveKey(sharedSecret[:], "harness-symmetric-key-v1")
	if err != nil {
		return nil, fmt.Errorf("failed to derive key: %w", err)
	}

	// Encrypt symmetric key with AES-GCM
	nonce := make([]byte, 12) // GCM standard nonce size
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	block, err := aes.NewCipher(aesKey[:])
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	// Encrypt with GCM
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	ciphertext := gcm.Seal(nil, nonce, symmetricKey, nil)

	// Build result: [ephemeral_x25519_public_key:32][nonce:12][ciphertext+tag]
	result := make([]byte, 0, 32+12+len(ciphertext))

	// Encode ephemeral X25519 public key (32 bytes)
	ephemeralX25519PubBytes, err := keystore.Ed25519ToX25519PublicKey(ephemeralPublic)
	if err != nil {
		return nil, fmt.Errorf("failed to convert ephemeral public key to X25519: %w", err)
	}
	result = append(result, ephemeralX25519PubBytes...)

	// Append nonce
	result = append(result, nonce...)

	// Append ciphertext (includes authentication tag)
	result = append(result, ciphertext...)

	return result, nil
}

// encryptAES encrypts data using AES-256-GCM
func encryptAES(plaintext, key []byte) ([]byte, error) {
	if len(key) != 32 {
		return nil, errors.New("key must be 32 bytes for AES-256")
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	// Create GCM mode
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	// Generate nonce (12 bytes is standard for GCM)
	nonce := make([]byte, 12)
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	// Encrypt and authenticate (ciphertext includes authentication tag)
	ciphertext := gcm.Seal(nil, nonce, plaintext, nil)

	// Prepend nonce
	result := append(nonce, ciphertext...)

	return result, nil
}
