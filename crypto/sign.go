package crypto

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/joncooperworks/harness/crypto/hceepcrypto"
	"github.com/joncooperworks/harness/crypto/keystore"
)

// SignEncryptedPluginRequest contains all the information needed to sign an encrypted plugin.
//
// This request implements the client's role in the dual-authorization model:
// decrypting the envelope, verifying the exploit owner signature, then signing execution arguments and expiration to approve exploit execution.
type SignEncryptedPluginRequest struct {
	// EncryptedData is the encrypted envelope (E) from EncryptPlugin.
	// Format: [ephemeral_x25519_public_key:32][nonce:12][ciphertext+tag]
	// Where ciphertext contains the inner envelope encrypted to target's public key.
	// The data is read from this io.Reader, making it suitable for streaming from S3, Lambda, etc.
	EncryptedData io.Reader
	// ArgsJSON is the JSON arguments to sign and encrypt.
	// These arguments are encrypted with the pentester's public key before signing,
	// ensuring only the pentester can read them.
	ArgsJSON []byte
	// ClientKeystore is the keystore containing the client's (target's) private key.
	// The client's key is used to:
	//   - Decrypt the envelope (E) to get the inner envelope (E_inner)
	//   - Sign the encrypted payload hash, expiration, and arguments
	ClientKeystore keystore.Keystore
	// ClientKeyID is the key ID in the keystore for the client's (target's) private key.
	// This key is used to decrypt the envelope and sign the approval of execution arguments and expiration.
	ClientKeyID keystore.KeyID
	// PrincipalPubKey is the exploit owner's (principal's) public key for verifying the payload signature.
	// The exploit owner signature is verified before the target signs, ensuring cryptographic chain-of-custody.
	PrincipalPubKey ed25519.PublicKey
	// PentesterPubKey is the pentester's public key for encrypting arguments.
	// Arguments are encrypted using X25519 key exchange with this public key.
	PentesterPubKey ed25519.PublicKey
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

// SignEncryptedPlugin decrypts the encrypted envelope, verifies the exploit owner signature, and signs it with client arguments.
//
// This function implements the client's role in the dual-authorization model:
//  1. Reads the encrypted envelope (E) from EncryptPlugin
//  2. Decrypts the envelope using the target's private key to get the inner envelope (E_inner)
//  3. Verifies the exploit owner (principal) signature on the encrypted payload hash (ensures chain-of-custody)
//  4. Encrypts execution arguments with the pentester's public key (ECDH + AES-256-GCM)
//  5. Calculates expiration timestamp (defaults to 72 hours if not provided)
//  6. Signs the encrypted payload hash, expiration, and encrypted arguments with the client's private key
//  7. Appends the signature, expiration, and encrypted arguments to create an approved package
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
	if req.PrincipalPubKey == nil {
		return nil, errors.New("principal public key cannot be nil")
	}
	if req.PentesterPubKey == nil {
		return nil, errors.New("pentester public key cannot be nil")
	}

	// Create EnvelopeCipher for target
	enc := hceepcrypto.NewEnvelopeCipher(req.ClientKeystore, req.ClientKeyID)

	// Convert pentester public key to X25519
	pentesterPubX, err := keystore.Ed25519ToX25519PublicKey(req.PentesterPubKey)
	if err != nil {
		return nil, fmt.Errorf("failed to convert pentester public key to X25519: %w", err)
	}
	var pentesterPubX32 [32]byte
	copy(pentesterPubX32[:], pentesterPubX)

	// Read all encrypted envelope data
	encryptedEnvelope, err := io.ReadAll(req.EncryptedData)
	if err != nil {
		return nil, fmt.Errorf("failed to read encrypted envelope: %w", err)
	}

	// Decrypt the envelope using target's private key
	innerEnvelope, err := enc.DecryptFromPeer(hceepcrypto.ContextEnvelope, encryptedEnvelope)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt envelope: %w", err)
	}

	// Now we have the inner envelope (E_inner), proceed with signing
	encryptedData := innerEnvelope

	// Validate args JSON
	var args json.RawMessage
	if err := json.Unmarshal(req.ArgsJSON, &args); err != nil {
		return nil, fmt.Errorf("invalid JSON in args: %w", err)
	}

	// Encrypt arguments with pentester's public key
	encryptedArgs, err := enc.EncryptToPeer(pentesterPubX32, hceepcrypto.ContextArgs, req.ArgsJSON)
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

	// Extract principal signature and encrypted payload
	// Skip header (10 bytes) + principal_sig_len (4 bytes) + principal_sig (variable)
	if len(encryptedData) < headerSize+4 {
		return nil, errors.New("encrypted data too short")
	}
	principalSigLen := int(binary.BigEndian.Uint32(encryptedData[headerSize : headerSize+4]))
	if principalSigLen != 64 {
		return nil, fmt.Errorf("invalid principal signature length: %d (expected 64 bytes for Ed25519)", principalSigLen)
	}
	if len(encryptedData) < headerSize+4+principalSigLen {
		return nil, errors.New("encrypted data too short for principal signature")
	}
	principalSignature := encryptedData[headerSize+4 : headerSize+4+principalSigLen]
	
	// Extract encrypted payload for hashing and verification
	// Encrypted payload = [metadata_length:4][metadata][encrypted_symmetric_key][encrypted_plugin_data]
	encryptedPayload := encryptedData[headerSize+4+principalSigLen:]

	// Hash the encrypted payload for signature verification
	encryptedPayloadHash := sha256.Sum256(encryptedPayload)

	// Verify principal (exploit owner) signature BEFORE signing (ensures chain-of-custody)
	if !ed25519.Verify(req.PrincipalPubKey, encryptedPayloadHash[:], principalSignature) {
		return nil, errors.New("principal signature verification failed: payload not signed by expected exploit owner")
	}

	// Sign encrypted payload hash + expiration + encrypted arguments together using keystore
	// Create data to sign: encrypted_payload_hash (32 bytes) + expiration (8 bytes) + encrypted_args
	dataToSign := make([]byte, 32+8+len(encryptedArgs))
	copy(dataToSign[0:32], encryptedPayloadHash[:])
	binary.BigEndian.PutUint64(dataToSign[32:40], uint64(expirationUnix))
	copy(dataToSign[40:], encryptedArgs)

	hash := sha256.Sum256(dataToSign)
	signature, err := req.ClientKeystore.SignDigest(req.ClientKeyID, hash[:])
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
