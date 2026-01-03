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
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"github.com/joncooperworks/harness/crypto/hceepcrypto"
	"github.com/joncooperworks/harness/crypto/keystore"
)

// EncryptPluginRequest contains all the information needed to encrypt a plugin.
//
// The encryption process uses ECDH key exchange to encrypt a symmetric AES-256-GCM key
// with the pentester's public key, then encrypts the plugin data with that symmetric key.
// The principal signs the encrypted payload hash to provide cryptographic proof of approval.
// The inner envelope is then encrypted to the target's public key (onion encryption).
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
	// TargetPubKey is the target's public key for onion encryption.
	// The inner envelope is encrypted to this key using X25519 key exchange.
	// Only the target can decrypt the envelope before signing.
	TargetPubKey ed25519.PublicKey
	// PrincipalKeystore is a Keystore bound to the principal's (exploit owner's) key.
	// The keystore is used to sign the encrypted payload hash, proving EO approval.
	// Use keystore.NewKeystoreForKey(keyID) to create a bound keystore.
	PrincipalKeystore keystore.Keystore
}

// EncryptHashes contains all SHA256 hashes calculated during encryption.
type EncryptHashes struct {
	// ExploitOwnerSignatureHash is the SHA256 hash of the exploit owner's signature.
	ExploitOwnerSignatureHash string
	// ExploitOwnerPublicKeyHash is the SHA256 hash of the exploit owner's public key.
	ExploitOwnerPublicKeyHash string
	// HarnessPublicKeyHash is the SHA256 hash of the harness (pentester's) public key.
	HarnessPublicKeyHash string
}

// EncryptPluginResult contains the encrypted plugin data and metadata.
//
// The EncryptedData field contains the encrypted envelope (E), which is the inner envelope
// encrypted to the target's public key:
// [ephemeral_x25519_public_key:32][nonce:12][ciphertext+tag]
// Where ciphertext contains: [magic:4][version:1][flags:1][file_length:4][principal_sig_len:4][principal_sig][metadata_length:4][metadata][encrypted_symmetric_key][encrypted_plugin_data]
// Note: file_length is set to 0 initially and will be updated by SignEncryptedPlugin
type EncryptPluginResult struct {
	// EncryptedData is the encrypted envelope (E), encrypted to target's public key:
	// [ephemeral_x25519_public_key:32][nonce:12][ciphertext+tag]
	// The inner envelope (E_inner) is encrypted using X25519 + AES-256-GCM.
	EncryptedData []byte
	// PluginName is the name extracted from the plugin or provided in the request.
	PluginName string
	// PrincipalSignature is the exploit owner's signature.
	// This is extracted from the inner envelope before encryption.
	PrincipalSignature []byte
	// Hashes contains all SHA256 hashes calculated during encryption.
	Hashes EncryptHashes
}

// EncryptPlugin encrypts a plugin and signs it with the principal's key, then encrypts
// the inner envelope to the target's public key (onion encryption).
//
// This function implements the principal's role in the dual-authorization model:
//  1. Reads the plugin data from the provided io.Reader
//  2. Generates a random AES-256 symmetric key
//  3. Encrypts the plugin data with AES-256-GCM using the symmetric key
//  4. Encrypts the symmetric key using ECDH key exchange with the pentester's public key
//  5. Signs the encrypted payload hash with the principal's private key (using EO signature context)
//  6. Encrypts the inner envelope to the target's public key (onion encryption)
//
// The function works with io.Reader, making it suitable for Lambda/S3 use cases where
// plugin data may be streamed rather than loaded entirely into memory.
//
// The returned EncryptedData is the encrypted envelope (E), which must be decrypted by
// the target before signing using SignEncryptedPlugin to create an approved execution package.
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
	if req.TargetPubKey == nil {
		return nil, errors.New("target public key cannot be nil")
	}
	if req.PrincipalKeystore == nil {
		return nil, errors.New("principal keystore cannot be nil")
	}

	// Create EnvelopeCipher for exploit owner using the bound keystore
	enc := hceepcrypto.NewEnvelopeCipher(req.PrincipalKeystore)

	// Convert harness public key to X25519
	harnessPubX, err := keystore.Ed25519ToX25519PublicKey(req.HarnessPubKey)
	if err != nil {
		return nil, fmt.Errorf("failed to convert harness public key to X25519: %w", err)
	}
	var harnessPubX32 [32]byte
	copy(harnessPubX32[:], harnessPubX)

	// Convert target public key to X25519
	targetPubX, err := keystore.Ed25519ToX25519PublicKey(req.TargetPubKey)
	if err != nil {
		return nil, fmt.Errorf("failed to convert target public key to X25519: %w", err)
	}
	var targetPubX32 [32]byte
	copy(targetPubX32[:], targetPubX)

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

	// Create AAD for payload encryption (RFC section 5.1 step 2)
	// AAD includes plugin type and name to prevent ciphertext substitution attacks
	payloadAAD := struct {
		Type string `json:"type"`
		Name string `json:"name"`
	}{Type: req.PluginType, Name: pluginName}
	payloadAADBytes, err := json.Marshal(payloadAAD)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal payload AAD: %w", err)
	}

	// Encrypt plugin data with AES using AAD
	encryptedPluginData, err := encryptAES(payloadJSON, symmetricKey, payloadAADBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt plugin data: %w", err)
	}

	// Encrypt symmetric key using EnvelopeCipher
	encryptedSymmetricKey, err := enc.EncryptToPeer(harnessPubX32, hceepcrypto.ContextSymmetricKey, symmetricKey)
	// Zeroize symmetric key immediately after use (defense-in-depth)
	zeroize(symmetricKey)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt symmetric key: %w", err)
	}

	// Create metadata (includes plugin type/name for AAD reconstruction during decryption)
	metadata := map[string]interface{}{
		"symmetric_key_len": len(encryptedSymmetricKey),
		"plugin_data_len":   len(encryptedPluginData),
		"algorithm":         "Ed25519+X25519+AES-256-GCM",
		"plugin_type":       req.PluginType,
		"plugin_name":       pluginName,
	}
	metadataJSON, err := json.Marshal(metadata)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal metadata: %w", err)
	}

	// Build encrypted payload: [metadata_length:4][metadata][encrypted_symmetric_key][encrypted_plugin_data]
	var encryptedPayload []byte
	metadataLenBuf := make([]byte, 4)
	binary.BigEndian.PutUint32(metadataLenBuf, uint32(len(metadataJSON)))
	encryptedPayload = append(encryptedPayload, metadataLenBuf...)
	encryptedPayload = append(encryptedPayload, metadataJSON...)
	encryptedPayload = append(encryptedPayload, encryptedSymmetricKey...)
	encryptedPayload = append(encryptedPayload, encryptedPluginData...)

	// Build encrypted file structure with header:
	// [magic:4][version:1][flags:1][file_length:4][principal_sig_len:4][principal_sig][metadata_length:4][metadata][encrypted_symmetric_key][encrypted_plugin_data]
	var output []byte

	// Write magic bytes "HARN" (0x48 0x41 0x52 0x4E)
	output = append(output, []byte("HARN")...)

	// Write version (1 byte, version 2 - includes version/flags in signature)
	version := byte(2)
	output = append(output, version)

	// Write flags (1 byte, currently 0 - reserved for future use)
	flags := byte(0)
	output = append(output, flags)

	// Write file length placeholder (4 bytes, will be updated by SignEncryptedPlugin)
	fileLengthBuf := make([]byte, 4)
	binary.BigEndian.PutUint32(fileLengthBuf, 0) // Placeholder
	output = append(output, fileLengthBuf...)

	// Get principal (EO) public key for identity hash
	principalPubKey, err := req.PrincipalKeystore.PublicKey()
	if err != nil {
		return nil, fmt.Errorf("failed to get principal public key: %w", err)
	}

	// Build canonical EO signature transcript (HCEEP v0.3)
	// Includes context string, version, flags, identity hashes, metadata, and encrypted payload
	eoTranscript, err := BuildEOTranscript(
		string(hceepcrypto.ContextPayloadSignature),
		uint32(version),
		uint32(flags),
		principalPubKey,
		req.TargetPubKey,
		req.HarnessPubKey,
		metadataJSON,
		encryptedPayload,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to build EO transcript: %w", err)
	}

	// Sign the canonical transcript directly (HCEEP v0.3 uses direct signing, not hash-then-sign)
	principalSignature, err := req.PrincipalKeystore.SignDirect(eoTranscript)
	if err != nil {
		return nil, fmt.Errorf("failed to sign encrypted payload: %w", err)
	}

	// Write principal signature length
	principalSigLenBuf := make([]byte, 4)
	binary.BigEndian.PutUint32(principalSigLenBuf, uint32(len(principalSignature)))
	output = append(output, principalSigLenBuf...)

	// Write principal signature
	output = append(output, principalSignature...)

	// Write encrypted payload (already constructed above)
	output = append(output, encryptedPayload...)

	// This is the inner envelope (E_inner)
	innerEnvelope := output

	// Extract principal signature for logging (before encryption)
	// Format: [magic:4][version:1][flags:1][file_length:4][principal_sig_len:4][principal_sig]...
	const headerSize = 4 + 1 + 1 + 4 // magic + version + flags + file_length
	if len(innerEnvelope) < headerSize+4 {
		return nil, errors.New("inner envelope too short for signature extraction")
	}
	principalSigLen := int(binary.BigEndian.Uint32(innerEnvelope[headerSize : headerSize+4]))
	if len(innerEnvelope) < headerSize+4+principalSigLen {
		return nil, errors.New("inner envelope too short for signature")
	}
	principalSig := make([]byte, principalSigLen)
	copy(principalSig, innerEnvelope[headerSize+4:headerSize+4+principalSigLen])

	// Encrypt inner envelope to target's public key (onion encryption)
	encryptedEnvelope, err := enc.EncryptToPeer(targetPubX32, hceepcrypto.ContextEnvelope, innerEnvelope)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt envelope to target: %w", err)
	}

	// Calculate hashes (using raw Ed25519 bytes for consistency with transcript identity hashes)
	exploitSigHash := sha256.Sum256(principalSig)
	exploitSigHashHex := hex.EncodeToString(exploitSigHash[:])

	// Use raw Ed25519 public key bytes (32 bytes) - matches HashPublicKey in transcript.go
	exploitPubKeyHash := sha256.Sum256(principalPubKey)
	exploitPubKeyHashHex := hex.EncodeToString(exploitPubKeyHash[:])

	harnessPubKeyHash := sha256.Sum256(req.HarnessPubKey)
	harnessPubKeyHashHex := hex.EncodeToString(harnessPubKeyHash[:])

	return &EncryptPluginResult{
		EncryptedData:      encryptedEnvelope,
		PluginName:         pluginName,
		PrincipalSignature: principalSig,
		Hashes: EncryptHashes{
			ExploitOwnerSignatureHash: exploitSigHashHex,
			ExploitOwnerPublicKeyHash: exploitPubKeyHashHex,
			HarnessPublicKeyHash:      harnessPubKeyHashHex,
		},
	}, nil
}

// encryptAES encrypts data using AES-256-GCM with Associated Authenticated Data (AAD).
// The AAD provides domain separation and prevents ciphertext substitution attacks.
// Per RFC section 5.1 step 2, metadata should be used as AAD for payload encryption.
func encryptAES(plaintext, key, aad []byte) ([]byte, error) {
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

	// Encrypt and authenticate with AAD (ciphertext includes authentication tag)
	// AAD is authenticated but not encrypted - used for domain separation
	ciphertext := gcm.Seal(nil, nonce, plaintext, aad)

	// Prepend nonce
	result := append(nonce, ciphertext...)

	return result, nil
}
