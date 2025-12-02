package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/joncooperworks/harness/crypto/keystore"
)

	// SignEncryptedPluginRequest contains all the information needed to sign an encrypted plugin.
//
// This request implements the client's role in the dual-authorization model:
// signing execution arguments and expiration to approve exploit execution.
type SignEncryptedPluginRequest struct {
	// EncryptedData is the encrypted plugin data (from EncryptPlugin).
	// Format: [magic:4][version:1][flags:1][file_length:4][principal_sig_len:4][principal_sig][metadata_length:4][metadata][encrypted_symmetric_key][encrypted_plugin_data]
	// The data is read from this io.Reader, making it suitable for streaming from S3, Lambda, etc.
	EncryptedData io.Reader
	// ArgsJSON is the JSON arguments to sign and encrypt.
	// These arguments are encrypted with the pentester's public key before signing,
	// ensuring only the pentester can read them.
	ArgsJSON []byte
	// ClientKeystore is the keystore containing the client's private key.
	// The client's key is used to sign the encrypted payload hash, expiration, and arguments.
	ClientKeystore keystore.Keystore
	// ClientKeyID is the key ID in the keystore for the client's private key.
	// This key is used to sign the approval of execution arguments and expiration.
	ClientKeyID string
	// PentesterPubKey is the pentester's public key for encrypting arguments.
	// Arguments are encrypted using ECDH key exchange with this public key.
	PentesterPubKey *ecdsa.PublicKey
	// Expiration is when the signature expires.
	// Defaults to 72 hours from now if nil.
	// The expiration is included in the signature, preventing execution after expiry.
	Expiration *time.Time
}

// SignEncryptedPluginResult contains the signed and approved plugin data.
//
// The ApprovedData field contains the complete approved file format:
// [magic:4][version:1][flags:1][file_length:4][principal_sig_len:4][principal_sig][metadata_length:4][metadata][encrypted_symmetric_key][encrypted_plugin_data][client_sig_len:4][client_sig][expiration:8][args_len:4][encrypted_args]
type SignEncryptedPluginResult struct {
	// ApprovedData is the complete approved file format:
	// [magic:4][version:1][flags:1][file_length:4][principal_sig_len:4][principal_sig][metadata_length:4][metadata][encrypted_symmetric_key][encrypted_plugin_data][client_sig_len:4][client_sig][expiration:8][args_len:4][encrypted_args]
	ApprovedData []byte
	// ExpirationTime is when the signature expires.
	// Execution will fail if attempted after this time.
	ExpirationTime time.Time
}

// SignEncryptedPlugin signs an encrypted plugin with client arguments.
//
// This function implements the client's role in the dual-authorization model:
//  1. Reads the encrypted plugin data from EncryptPlugin
//  2. Encrypts execution arguments with the pentester's public key (ECDH + AES-256-GCM)
//  3. Calculates expiration timestamp (defaults to 72 hours if not provided)
//  4. Signs the encrypted payload hash, expiration, and encrypted arguments with the client's private key
//  5. Appends the signature, expiration, and encrypted arguments to create an approved package
//
// The function works with io.Reader, making it suitable for Lambda/S3 use cases where
// encrypted data may be streamed rather than loaded entirely into memory.
//
// The returned ApprovedData can be executed using PresidentialOrder.VerifyAndDecrypt.
func SignEncryptedPlugin(req *SignEncryptedPluginRequest) (*SignEncryptedPluginResult, error) {
	if req == nil {
		return nil, errors.New("request cannot be nil")
	}
	if req.EncryptedData == nil {
		return nil, errors.New("encrypted data reader cannot be nil")
	}
	if len(req.ArgsJSON) == 0 {
		return nil, errors.New("args JSON cannot be empty")
	}
	if req.ClientKeystore == nil {
		return nil, errors.New("client keystore cannot be nil")
	}
	if req.ClientKeyID == "" {
		return nil, errors.New("client key ID cannot be empty")
	}
	if req.PentesterPubKey == nil {
		return nil, errors.New("pentester public key cannot be nil")
	}

	// Read all encrypted data
	encryptedData, err := io.ReadAll(req.EncryptedData)
	if err != nil {
		return nil, fmt.Errorf("failed to read encrypted data: %w", err)
	}

	// Validate args JSON
	var args json.RawMessage
	if err := json.Unmarshal(req.ArgsJSON, &args); err != nil {
		return nil, fmt.Errorf("invalid JSON in args: %w", err)
	}

	// Encrypt arguments with pentester's public key
	encryptedArgs, err := encryptArgs(req.ArgsJSON, req.PentesterPubKey)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt arguments: %w", err)
	}

	// Calculate expiration timestamp (Unix timestamp in seconds)
	var expirationTime time.Time
	if req.Expiration != nil {
		expirationTime = *req.Expiration
	} else {
		expirationTime = time.Now().Add(72 * time.Hour) // Default 72 hours
	}
	expirationUnix := expirationTime.Unix()

	// Validate magic bytes and version
	const headerSize = 4 + 1 + 1 + 4 // magic + version + flags + file_length
	if len(encryptedData) < headerSize {
		return nil, errors.New("encrypted data too short for header")
	}
	if string(encryptedData[0:4]) != "HARN" {
		return nil, errors.New("invalid magic bytes: not a harness file")
	}
	if encryptedData[4] != 1 {
		return nil, fmt.Errorf("unsupported file format version: %d (expected 1)", encryptedData[4])
	}

	// Extract encrypted payload for hashing (everything after principal signature)
	// Encrypted payload = [metadata_length:4][metadata][encrypted_symmetric_key][encrypted_plugin_data]
	// Skip header (10 bytes) + principal_sig_len (4 bytes) + principal_sig (variable)
	if len(encryptedData) < headerSize+4 {
		return nil, errors.New("encrypted data too short")
	}
	principalSigLen := int(binary.BigEndian.Uint32(encryptedData[headerSize : headerSize+4]))
	if len(encryptedData) < headerSize+4+principalSigLen {
		return nil, errors.New("encrypted data too short for principal signature")
	}
	encryptedPayload := encryptedData[headerSize+4+principalSigLen:]

	// Hash the encrypted payload to include in signature
	encryptedPayloadHash := sha256.Sum256(encryptedPayload)

	// Sign encrypted payload hash + expiration + encrypted arguments together using keystore
	// Create data to sign: encrypted_payload_hash (32 bytes) + expiration (8 bytes) + encrypted_args
	dataToSign := make([]byte, 32+8+len(encryptedArgs))
	copy(dataToSign[0:32], encryptedPayloadHash[:])
	binary.BigEndian.PutUint64(dataToSign[32:40], uint64(expirationUnix))
	copy(dataToSign[40:], encryptedArgs)

	hash := sha256.Sum256(dataToSign)
	signature, err := req.ClientKeystore.Sign(req.ClientKeyID, hash[:])
	if err != nil {
		return nil, fmt.Errorf("failed to sign payload and arguments: %w", err)
	}

	// Build final approved file structure:
	// [magic:4][version:1][flags:1][file_length:4][principal_sig_len:4][principal_sig][metadata_length:4][metadata][encrypted_symmetric_key][encrypted_plugin_data][client_sig_len:4][client_sig][expiration:8][args_len:4][encrypted_args]
	var output []byte

	// Write header (magic, version, flags) and encrypted payload (already in correct format)
	output = append(output, encryptedData...)

	// Write client signature length
	sigLenBuf := make([]byte, 4)
	binary.BigEndian.PutUint32(sigLenBuf, uint32(len(signature)))
	output = append(output, sigLenBuf...)

	// Write client signature
	output = append(output, signature...)

	// Write expiration timestamp (Unix timestamp, 8 bytes)
	expirationBuf := make([]byte, 8)
	binary.BigEndian.PutUint64(expirationBuf, uint64(expirationUnix))
	output = append(output, expirationBuf...)

	// Write encrypted args length
	argsLenBuf := make([]byte, 4)
	binary.BigEndian.PutUint32(argsLenBuf, uint32(len(encryptedArgs)))
	output = append(output, argsLenBuf...)

	// Write encrypted args
	output = append(output, encryptedArgs...)

	// Update file length field (at offset 6, after magic:4 + version:1 + flags:1)
	fileLengthBuf := make([]byte, 4)
	binary.BigEndian.PutUint32(fileLengthBuf, uint32(len(output)))
	copy(output[6:10], fileLengthBuf)

	return &SignEncryptedPluginResult{
		ApprovedData:   output,
		ExpirationTime: expirationTime,
	}, nil
}

// encryptArgs encrypts arguments using ECDH + AES-256-GCM (same method as encryptSymmetricKey)
func encryptArgs(plaintext []byte, publicKey *ecdsa.PublicKey) ([]byte, error) {
	// Validate public key
	if err := validatePublicKey(publicKey); err != nil {
		return nil, fmt.Errorf("invalid public key: %w", err)
	}

	// Generate ephemeral key pair for ECDH
	ephemeralPrivate, err := ecdsa.GenerateKey(publicKey.Curve, rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate ephemeral key: %w", err)
	}

	// Validate ephemeral public key
	if err := validatePublicKey(&ephemeralPrivate.PublicKey); err != nil {
		return nil, fmt.Errorf("invalid ephemeral public key: %w", err)
	}

	// Compute shared secret using ECDH
	sharedX, _ := publicKey.Curve.ScalarMult(publicKey.X, publicKey.Y, ephemeralPrivate.D.Bytes())
	sharedSecret := sharedX.Bytes()

	// Derive AES key from shared secret using HKDF
	aesKey, err := deriveKey(sharedSecret, "harness-args-v1")
	if err != nil {
		return nil, fmt.Errorf("failed to derive key: %w", err)
	}

	// Encrypt with AES-GCM
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

	ciphertext := gcm.Seal(nil, nonce, plaintext, nil)

	// Build result: [ephemeral_public_key:65][nonce:12][ciphertext+tag]
	result := make([]byte, 0, 65+12+len(ciphertext))

	// Encode ephemeral public key (uncompressed: 0x04 || x || y)
	ephemeralPubBytes := make([]byte, 65)
	ephemeralPubBytes[0] = 0x04
	copy(ephemeralPubBytes[1:33], ephemeralPrivate.PublicKey.X.Bytes())
	copy(ephemeralPubBytes[33:65], ephemeralPrivate.PublicKey.Y.Bytes())
	result = append(result, ephemeralPubBytes...)

	// Append nonce
	result = append(result, nonce...)

	// Append ciphertext (includes authentication tag)
	result = append(result, ciphertext...)

	return result, nil
}

