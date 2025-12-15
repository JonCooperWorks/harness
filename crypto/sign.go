package crypto

import (
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
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
	// ClientKeystore is a Keystore bound to the client's (target's) key.
	// The keystore is used to:
	//   - Decrypt the envelope (E) to get the inner envelope (E_inner)
	//   - Sign the encrypted payload hash, expiration, and arguments
	// Use keystore.NewKeystoreForKey(keyID) to create a bound keystore.
	ClientKeystore keystore.Keystore
	// PrincipalPubKey is the exploit owner's (principal's) public key for verifying the payload signature.
	// The exploit owner signature is verified before the target signs, ensuring cryptographic chain-of-custody.
	PrincipalPubKey ed25519.PublicKey
	// HarnessPubKey is the harness's (pentester's) public key for identity binding in signatures.
	// Required for HCEEP v0.3 canonical transcript signing with identity hashes.
	HarnessPubKey ed25519.PublicKey
	// PentesterPubKey is the pentester's public key for encrypting arguments.
	// Arguments are encrypted using X25519 key exchange with this public key.
	PentesterPubKey ed25519.PublicKey
	// Expiration is when the signature expires.
	// Defaults to 72 hours from now if nil.
	// The expiration is included in the signature, preventing execution after expiry.
	Expiration *time.Time
}

// SignHashes contains all SHA256 hashes calculated during signing.
type SignHashes struct {
	// EncryptedPayloadHash is the SHA256 hash of the encrypted payload.
	EncryptedPayloadHash string
	// TargetPublicKeyHash is the SHA256 hash of the target's public key.
	TargetPublicKeyHash string
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
	// Hashes contains all SHA256 hashes calculated during signing.
	Hashes SignHashes
}

// SignEncryptedPlugin decrypts the encrypted envelope, verifies the exploit owner signature, and signs it with client arguments.
//
// This function implements the client's role in the dual-authorization model:
//  1. Reads the encrypted envelope (E) from EncryptPlugin
//  2. Decrypts the envelope using the target's private key to get the inner envelope (E_inner)
//  3. Verifies the exploit owner (principal) signature on the encrypted payload using ContextPayloadSignature (ensures chain-of-custody)
//  4. Encrypts execution arguments with the pentester's public key (ECDH + AES-256-GCM)
//  5. Calculates expiration timestamp (defaults to 72 hours if not provided)
//  6. Signs the encrypted payload, expiration, and encrypted arguments with the client's private key using ContextClientSignature
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
	if req.PrincipalPubKey == nil {
		return nil, errors.New("principal public key cannot be nil")
	}
	if req.PentesterPubKey == nil {
		return nil, errors.New("pentester public key cannot be nil")
	}
	if req.HarnessPubKey == nil {
		return nil, errors.New("harness public key cannot be nil")
	}

	// Create EnvelopeCipher for target using the bound keystore
	enc := hceepcrypto.NewEnvelopeCipher(req.ClientKeystore)

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
	
	// Enforce max size limit for encrypted args (DoS protection)
	if len(encryptedArgs) > MaxEncryptedArgsSize {
		return nil, fmt.Errorf("encrypted args size %d exceeds maximum %d", len(encryptedArgs), MaxEncryptedArgsSize)
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
	version := encryptedData[4]
	flags := encryptedData[5]
	if version != 1 && version != 2 {
		return nil, fmt.Errorf("unsupported file format version: %d (expected 1 or 2)", version)
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

	// Extract metadata from encrypted payload for EO transcript reconstruction
	if len(encryptedPayload) < 4 {
		return nil, errors.New("encrypted payload too short for metadata length")
	}
	metadataLen := int(binary.BigEndian.Uint32(encryptedPayload[0:4]))
	if len(encryptedPayload) < 4+metadataLen {
		return nil, errors.New("encrypted payload too short for metadata")
	}
	metadata := encryptedPayload[4 : 4+metadataLen]

	// Get target public key for identity hash
	targetPubKey, err := req.ClientKeystore.PublicKey()
	if err != nil {
		return nil, fmt.Errorf("failed to get target public key: %w", err)
	}

	// Rebuild canonical EO signature transcript for verification (HCEEP v0.3)
	eoTranscript, err := BuildEOTranscript(
		string(hceepcrypto.ContextPayloadSignature),
		uint32(version),
		uint32(flags),
		req.PrincipalPubKey,
		targetPubKey,
		req.HarnessPubKey,
		metadata,
		encryptedPayload,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to build EO transcript for verification: %w", err)
	}

	// Verify principal (exploit owner) signature BEFORE signing (ensures chain-of-custody)
	// HCEEP v0.3 uses direct transcript signing with identity binding
	if err := req.ClientKeystore.VerifyDirect(req.PrincipalPubKey, eoTranscript, principalSignature); err != nil {
		return nil, errors.New("principal signature verification failed: payload not signed by expected exploit owner")
	}

	// Build canonical Target signature transcript (HCEEP v0.3)
	// Includes context string, version, flags, identity hashes, encrypted payload, encrypted args, and expiration
	targetTranscript, err := BuildTargetTranscript(
		string(hceepcrypto.ContextClientSignature),
		uint32(version),
		uint32(flags),
		req.PrincipalPubKey,
		targetPubKey,
		req.HarnessPubKey,
		encryptedPayload,
		encryptedArgs,
		expirationUnix,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to build Target transcript: %w", err)
	}

	// Sign the canonical transcript directly (HCEEP v0.3 uses direct signing, not hash-then-sign)
	signature, err := req.ClientKeystore.SignDirect(targetTranscript)
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
	expirationBuf2 := make([]byte, 8)
	binary.BigEndian.PutUint64(expirationBuf2, uint64(expirationUnix))
	output = append(output, expirationBuf2...)

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

	// Calculate hashes
	encryptedPayloadHash := sha256.Sum256(encryptedPayload)
	encryptedPayloadHashHex := hex.EncodeToString(encryptedPayloadHash[:])

	targetPubKeyBytes, err := x509.MarshalPKIXPublicKey(targetPubKey)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal target public key: %w", err)
	}
	targetPubKeyHash := sha256.Sum256(targetPubKeyBytes)
	targetPubKeyHashHex := hex.EncodeToString(targetPubKeyHash[:])

	return &SignEncryptedPluginResult{
		ApprovedData:   output,
		ExpirationTime: expirationTime,
		Hashes: SignHashes{
			EncryptedPayloadHash: encryptedPayloadHashHex,
			TargetPublicKeyHash:  targetPubKeyHashHex,
		},
	}, nil
}
