package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/hkdf"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"time"

	"github.com/joncooperworks/harness/crypto/keystore"
)

// DecryptedResult contains both the decrypted payload and the execution arguments.
//
// This is returned by PresidentialOrder.VerifyAndDecrypt after successfully
// verifying all signatures and decrypting the plugin data.
type DecryptedResult struct {
	// Payload is the decrypted plugin payload containing the plugin type, name, and binary data.
	Payload *Payload
	// Args are the JSON execution arguments extracted from the approved file.
	// These were encrypted with the pentester's public key and signed by the client.
	Args []byte
	// ClientSignature is the client's signature from the approved file.
	// This signature covers the encrypted payload hash, expiration, and encrypted arguments.
	ClientSignature []byte
	// PrincipalSignature is the principal's signature from the approved file.
	// This signature covers the encrypted payload hash.
	PrincipalSignature []byte
}

// PresidentialOrder is an interface for verifying signatures and decrypting payloads.
//
// Implementations of this interface handle the pentester's role in the dual-authorization
// model: verifying both principal and client signatures, checking expiration, and
// decrypting the plugin data and execution arguments.
//
// The VerifyAndDecrypt method performs all verification and decryption operations,
// ensuring that execution only proceeds if:
//  1. The principal signature is valid (proves principal approved the encrypted payload)
//  2. The client signature is valid (proves client approved the arguments and expiration)
//  3. The expiration has not passed
//  4. All cryptographic operations succeed
type PresidentialOrder interface {
	// VerifyAndDecrypt verifies signatures and decrypts the payload.
	//
	// The ciphertextAndMetadata must be in the approved file format:
	// [magic:4][version:1][flags:1][file_length:4][principal_sig_len:4][principal_sig][metadata_length:4][metadata][encrypted_symmetric_key][encrypted_plugin_data][client_sig_len:4][client_sig][expiration:8][args_len:4][encrypted_args]
	//
	// Returns an error if any signature verification fails, expiration has passed,
	// or decryption fails.
	VerifyAndDecrypt(ciphertextAndMetadata []byte) (*DecryptedResult, error)
}

// PresidentialOrderImpl implements the PresidentialOrder interface
type PresidentialOrderImpl struct {
	privateKey      *ecdsa.PrivateKey // Pentester's private key (for decryption) - DEPRECATED: use keystore instead
	clientPubKey    *ecdsa.PublicKey  // Client's public key (for verifying argument signature)
	principalPubKey *ecdsa.PublicKey  // Principal's public key (for verifying payload signature)
	keystore        keystore.Keystore
	keystoreKeyID   string
}

// NewPresidentialOrderFromKeys creates a new PresidentialOrder from provided keys.
//
// DEPRECATED: Use NewPresidentialOrderFromKeystoreWithPrincipal instead.
// Private keys should be stored in OS keystores, not loaded into memory.
//
// This function creates a PresidentialOrder using an in-memory private key.
// The privateKey is the pentester's private key for decryption.
// The clientPubKey is the client's public key for verifying argument signatures.
func NewPresidentialOrderFromKeys(privateKey *ecdsa.PrivateKey, clientPubKey *ecdsa.PublicKey) (PresidentialOrder, error) {
	if privateKey == nil {
		return nil, errors.New("private key cannot be nil")
	}
	if clientPubKey == nil {
		return nil, errors.New("client public key cannot be nil")
	}
	return &PresidentialOrderImpl{
		privateKey:   privateKey,
		clientPubKey: clientPubKey,
	}, nil
}

// NewPresidentialOrderFromKeystore creates a new PresidentialOrder loading the private key from OS keystore.
//
// DEPRECATED: Use NewPresidentialOrderFromKeystoreWithPrincipal instead.
// Principal signature verification is required for security.
//
// This function creates a PresidentialOrder using a private key stored in the OS keystore.
// The keystoreKeyID identifies the pentester's private key in the keystore.
// The clientPubKey is the client's public key for verifying argument signatures.
//
// Note: This function does not include principal signature verification.
// Use NewPresidentialOrderFromKeystoreWithPrincipal for full security.
func NewPresidentialOrderFromKeystore(keystoreKeyID string, clientPubKey *ecdsa.PublicKey) (PresidentialOrder, error) {
	return NewPresidentialOrderFromKeystoreWithPrincipal(keystoreKeyID, clientPubKey, nil)
}

// NewPresidentialOrderFromKeystoreWithPrincipal creates a new PresidentialOrder with principal public key.
//
// This is the recommended way to create a PresidentialOrder. It uses a private key
// stored in the OS keystore (never loaded into memory) and includes both client and
// principal signature verification for full dual-authorization security.
//
// The keystoreKeyID identifies the pentester's private key in the OS keystore.
// The clientPubKey is the client's public key for verifying argument signatures.
// The principalPubKey is the principal's public key for verifying payload signatures.
//
// The private key never leaves secure storage - all decryption operations happen
// through the keystore interface, allowing hardware-backed or cloud-based key storage.
func NewPresidentialOrderFromKeystoreWithPrincipal(keystoreKeyID string, clientPubKey *ecdsa.PublicKey, principalPubKey *ecdsa.PublicKey) (PresidentialOrder, error) {
	if keystoreKeyID == "" {
		return nil, errors.New("keystore key ID cannot be empty")
	}
	if clientPubKey == nil {
		return nil, errors.New("client public key cannot be nil")
	}
	if principalPubKey == nil {
		return nil, errors.New("principal public key cannot be nil")
	}

	ks, err := keystore.NewKeystore()
	if err != nil {
		return nil, fmt.Errorf("failed to create keystore: %w", err)
	}

	// Don't extract private key - use keystore operations directly
	// This allows keys to remain in secure storage (HSM, cloud KMS, Secure Enclave, TPM)
	return &PresidentialOrderImpl{
		clientPubKey:    clientPubKey,
		principalPubKey: principalPubKey,
		keystore:        ks,
		keystoreKeyID:   keystoreKeyID,
	}, nil
}

// NewPresidentialOrderFromFile creates a new PresidentialOrder loading the private key from a file.
//
// DEPRECATED: Use NewPresidentialOrderFromKeystoreWithPrincipal instead.
// Private keys should be stored in OS keystores, not in files.
//
// This function creates a PresidentialOrder using a private key loaded from a file.
// The privateKeyPath is the path to a PEM-encoded private key file.
// The clientPubKey is the client's public key for verifying argument signatures.
//
// Security Warning: Loading private keys from files exposes them to the filesystem
// and process memory. Use OS keystore integration instead.
func NewPresidentialOrderFromFile(privateKeyPath string, clientPubKey *ecdsa.PublicKey) (PresidentialOrder, error) {
	if privateKeyPath == "" {
		return nil, errors.New("private key path cannot be empty")
	}
	if clientPubKey == nil {
		return nil, errors.New("client public key cannot be nil")
	}

	keyData, err := os.ReadFile(privateKeyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read private key file: %w", err)
	}

	privateKey, err := parsePrivateKey(keyData)
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key: %w", err)
	}

	return &PresidentialOrderImpl{
		privateKey:   privateKey,
		clientPubKey: clientPubKey,
	}, nil
}

// VerifyAndDecrypt verifies signatures and decrypts the payload.
//
// This method implements the pentester's role in the dual-authorization model:
//  1. Verifies the principal signature on the encrypted payload hash (before decryption)
//  2. Verifies the client signature on encrypted payload hash + expiration + arguments
//  3. Checks that the expiration has not passed
//  4. Decrypts the symmetric key using ECDH with the pentester's private key (from keystore)
//  5. Decrypts the plugin data using AES-256-GCM
//  6. Decrypts the execution arguments using ECDH
//
// File format: [magic:4][version:1][flags:1][file_length:4][principal_sig_len:4][principal_sig][metadata_len:4][metadata][encrypted_symmetric_key][encrypted_plugin_data][client_sig_len:4][client_sig][expiration:8][args_len:4][encrypted_args]
//
// Principal signature signs: SHA256([metadata_len:4][metadata][encrypted_symmetric_key][encrypted_plugin_data])
//
// Client signature signs: SHA256(SHA256(encrypted_payload) || expiration || encrypted_args)
//
// Returns an error if any verification fails, expiration has passed, or decryption fails.
func (po *PresidentialOrderImpl) VerifyAndDecrypt(fileData []byte) (*DecryptedResult, error) {
	const (
		headerSize      = 4 + 1 + 1 + 4                                // magic + version + flags + file_length
		minFileSize     = headerSize + 4 + 50 + 4 + 4 + 4 + 60 + 8 + 4 // header + principal_sig_len + min_sig + metadata_len + min_metadata + client_sig_len + min_sig + expiration + args_len
		maxMetadataSize = 10000
	)

	if len(fileData) < minFileSize {
		return nil, errors.New("file too short")
	}

	pos := 0

	// Read and validate magic bytes
	if len(fileData) < 4 {
		return nil, errors.New("file too short for magic bytes")
	}
	if string(fileData[pos:pos+4]) != "HARN" {
		return nil, errors.New("invalid magic bytes: not a harness file")
	}
	pos += 4

	// Read version (must be 1)
	if fileData[pos] != 1 {
		return nil, fmt.Errorf("unsupported file format version: %d (expected 1)", fileData[pos])
	}
	pos++

	// Read flags (reserved for future use)
	flags := fileData[pos]
	pos++

	// Read file length
	if pos+4 > len(fileData) {
		return nil, errors.New("file too short for file length")
	}
	fileLength := binary.BigEndian.Uint32(fileData[pos : pos+4])
	if fileLength != 0 && fileLength != uint32(len(fileData)) {
		return nil, fmt.Errorf("file length mismatch: header says %d bytes, but file has %d bytes", fileLength, len(fileData))
	}
	pos += 4

	_ = flags // Reserved for future use

	// Read principal signature length
	if pos+4 > len(fileData) {
		return nil, errors.New("file too short for principal signature length")
	}
	principalSigLen := int(binary.BigEndian.Uint32(fileData[pos : pos+4]))
	if principalSigLen < 50 || principalSigLen > 120 {
		return nil, fmt.Errorf("invalid principal signature length: %d (expected 50-120 bytes)", principalSigLen)
	}
	pos += 4

	// Read principal signature
	if pos+principalSigLen > len(fileData) {
		return nil, errors.New("file too short for principal signature")
	}
	principalSignature := fileData[pos : pos+principalSigLen]
	pos += principalSigLen

	// Read metadata length
	if pos+4 > len(fileData) {
		return nil, errors.New("file too short for metadata length")
	}
	metadataLen := int(binary.BigEndian.Uint32(fileData[pos : pos+4]))
	if metadataLen > maxMetadataSize {
		return nil, fmt.Errorf("metadata length %d exceeds maximum allowed size %d", metadataLen, maxMetadataSize)
	}
	if metadataLen < 0 {
		return nil, fmt.Errorf("invalid metadata length: %d", metadataLen)
	}
	pos += 4

	// Read metadata
	if pos+metadataLen > len(fileData) {
		return nil, errors.New("file too short for metadata")
	}
	metadata := fileData[pos : pos+metadataLen]
	pos += metadataLen

	// Parse metadata to get encrypted symmetric key length
	var metadataStruct struct {
		SymmetricKeyLen int    `json:"symmetric_key_len"`
		PluginDataLen   int    `json:"plugin_data_len"`
		Algorithm       string `json:"algorithm"`
	}
	if err := json.Unmarshal(metadata, &metadataStruct); err != nil {
		return nil, fmt.Errorf("failed to unmarshal metadata: %w", err)
	}

	// Calculate encrypted payload hash for principal signature verification
	// Encrypted payload = [metadata_len:4][metadata][encrypted_symmetric_key][encrypted_plugin_data]
	encryptedPayloadStart := pos - 4 - metadataLen // Start at metadata_len
	encryptedPayloadEnd := pos + metadataStruct.SymmetricKeyLen + metadataStruct.PluginDataLen
	if encryptedPayloadEnd > len(fileData) {
		return nil, errors.New("file too short for encrypted payload")
	}
	encryptedPayload := fileData[encryptedPayloadStart:encryptedPayloadEnd]
	encryptedPayloadHash := sha256.Sum256(encryptedPayload)

	// Verify principal signature BEFORE decryption (signs encrypted payload hash)
	var principalSig struct {
		R, S *big.Int
	}
	if _, err := asn1.Unmarshal(principalSignature, &principalSig); err != nil {
		return nil, fmt.Errorf("failed to unmarshal principal signature: %w", err)
	}
	if !ecdsa.Verify(po.principalPubKey, encryptedPayloadHash[:], principalSig.R, principalSig.S) {
		return nil, errors.New("principal signature verification failed (signature must cover encrypted payload hash)")
	}

	// Read encrypted symmetric key
	if pos+metadataStruct.SymmetricKeyLen > len(fileData) {
		return nil, errors.New("file too short for encrypted symmetric key")
	}
	encryptedSymmetricKey := fileData[pos : pos+metadataStruct.SymmetricKeyLen]
	pos += metadataStruct.SymmetricKeyLen

	// Read encrypted plugin data
	if pos+metadataStruct.PluginDataLen > len(fileData) {
		return nil, errors.New("file too short for encrypted plugin data")
	}
	encryptedPluginData := fileData[pos : pos+metadataStruct.PluginDataLen]
	pos += metadataStruct.PluginDataLen

	// Read client signature length
	if pos+4 > len(fileData) {
		return nil, errors.New("file too short for client signature length")
	}
	clientSigLen := int(binary.BigEndian.Uint32(fileData[pos : pos+4]))
	if clientSigLen < 60 || clientSigLen > 80 {
		return nil, fmt.Errorf("invalid client signature length: %d (expected 60-80 bytes)", clientSigLen)
	}
	pos += 4

	// Read client signature
	if pos+clientSigLen > len(fileData) {
		return nil, errors.New("file too short for client signature")
	}
	clientSignature := fileData[pos : pos+clientSigLen]
	pos += clientSigLen

	// Read expiration
	if pos+8 > len(fileData) {
		return nil, errors.New("file too short for expiration")
	}
	expirationUnix := int64(binary.BigEndian.Uint64(fileData[pos : pos+8]))
	expirationTime := time.Unix(expirationUnix, 0)
	pos += 8

	// Verify expiration has not passed
	if time.Now().After(expirationTime) {
		return nil, fmt.Errorf("payload has expired: expiration was %s, current time is %s", expirationTime.Format(time.RFC3339), time.Now().Format(time.RFC3339))
	}

	// Read encrypted args length
	if pos+4 > len(fileData) {
		return nil, errors.New("file too short for encrypted args length")
	}
	encryptedArgsLen := int(binary.BigEndian.Uint32(fileData[pos : pos+4]))
	pos += 4

	// Read encrypted args
	if pos+encryptedArgsLen > len(fileData) {
		return nil, errors.New("file too short for encrypted args")
	}
	encryptedArgs := fileData[pos : pos+encryptedArgsLen]
	pos += encryptedArgsLen

	// Verify we consumed all data
	if pos != len(fileData) {
		return nil, fmt.Errorf("file format error: expected %d bytes total, but file has %d bytes", pos, len(fileData))
	}

	// Verify client signature: Signature covers encrypted_payload_hash (32 bytes) + expiration (8 bytes) + encrypted_args
	// Note: encryptedPayloadHash is computed from [metadata_len:4][metadata][encrypted_symmetric_key][encrypted_plugin_data]
	dataToVerify := make([]byte, 32+8+len(encryptedArgs))
	copy(dataToVerify[0:32], encryptedPayloadHash[:])
	binary.BigEndian.PutUint64(dataToVerify[32:40], uint64(expirationUnix))
	copy(dataToVerify[40:], encryptedArgs)

	dataHash := sha256.Sum256(dataToVerify)
	var clientSig struct {
		R, S *big.Int
	}
	if _, err := asn1.Unmarshal(clientSignature, &clientSig); err != nil {
		return nil, fmt.Errorf("failed to unmarshal client signature: %w", err)
	}
	if !ecdsa.Verify(po.clientPubKey, dataHash[:], clientSig.R, clientSig.S) {
		return nil, errors.New("client signature verification failed (signature must cover encrypted payload hash, expiration, and arguments)")
	}

	// Decrypt symmetric key using pentester's private key (ECDH)
	var symmetricKey []byte
	var err error
	if po.keystore != nil && po.keystoreKeyID != "" {
		// Use keystore for decryption (keys never leave secure storage)
		symmetricKey, err = po.keystore.DecryptWithContext(po.keystoreKeyID, encryptedSymmetricKey, "harness-symmetric-key-v1")
		if err != nil {
			return nil, fmt.Errorf("failed to decrypt symmetric key via keystore: %w", err)
		}
	} else if po.privateKey != nil {
		// Fallback to in-memory private key (deprecated)
		symmetricKey, err = po.decryptSymmetricKey(encryptedSymmetricKey)
		if err != nil {
			return nil, fmt.Errorf("failed to decrypt symmetric key: %w", err)
		}
	} else {
		return nil, errors.New("no keystore or private key available for decryption")
	}

	// Decrypt plugin data using AES
	pluginData, err := decryptAES(encryptedPluginData, symmetricKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt plugin data: %w", err)
	}

	// Deserialize Payload
	var payload Payload
	if err := json.Unmarshal(pluginData, &payload); err != nil {
		return nil, fmt.Errorf("failed to unmarshal payload: %w", err)
	}

	// Decrypt arguments using pentester's private key (from keystore)
	var decryptedArgs []byte
	if po.keystore != nil && po.keystoreKeyID != "" {
		// Use keystore for decryption (keys never leave secure storage)
		decryptedArgs, err = po.decryptArgs(encryptedArgs)
		if err != nil {
			return nil, fmt.Errorf("failed to decrypt arguments: %w", err)
		}
	} else if po.privateKey != nil {
		// Fallback to in-memory private key (deprecated)
		decryptedArgs, err = po.decryptArgsWithKey(encryptedArgs, po.privateKey)
		if err != nil {
			return nil, fmt.Errorf("failed to decrypt arguments: %w", err)
		}
	} else {
		return nil, errors.New("no keystore or private key available for argument decryption")
	}

	return &DecryptedResult{
		Payload:            &payload,
		Args:               decryptedArgs,
		ClientSignature:    clientSignature,
		PrincipalSignature: principalSignature,
	}, nil
}

// decryptArgs decrypts arguments using keystore (keys never leave secure storage)
// The encrypted args format is: [ephemeral_public_key:65][nonce:12][ciphertext+tag]
// Uses context "harness-args-v1" for key derivation (different from symmetric keys)
func (po *PresidentialOrderImpl) decryptArgs(encryptedArgs []byte) ([]byte, error) {
	if len(encryptedArgs) < 65+12+16 { // Need at least ephemeral key + nonce + tag
		return nil, errors.New("encrypted args too short")
	}

	// Use keystore to decrypt with args-specific context
	// DecryptWithContext expects format: [ephemeral_public_key:65][nonce:12][ciphertext+tag]
	// which matches our encryptedArgs format
	return po.keystore.DecryptWithContext(po.keystoreKeyID, encryptedArgs, "harness-args-v1")
}

// decryptArgsWithKey decrypts arguments using in-memory private key (deprecated)
func (po *PresidentialOrderImpl) decryptArgsWithKey(encryptedArgs []byte, privateKey *ecdsa.PrivateKey) ([]byte, error) {
	if len(encryptedArgs) < 65+12+16 { // Need at least ephemeral key + nonce + tag
		return nil, errors.New("encrypted args too short")
	}

	// Extract ephemeral public key (uncompressed format: 0x04 || x || y)
	ephemeralPubKeyBytes := encryptedArgs[:65]
	x := new(big.Int).SetBytes(ephemeralPubKeyBytes[1:33])
	y := new(big.Int).SetBytes(ephemeralPubKeyBytes[33:65])

	// Create ephemeral public key from point
	ephemeralPubKey := &ecdsa.PublicKey{
		Curve: privateKey.Curve,
		X:     x,
		Y:     y,
	}

	// Validate ephemeral public key
	if err := validatePublicKey(ephemeralPubKey); err != nil {
		return nil, fmt.Errorf("invalid ephemeral public key: %w", err)
	}

	// Compute shared secret using ECDH
	sharedX, _ := ephemeralPubKey.Curve.ScalarMult(ephemeralPubKey.X, ephemeralPubKey.Y, privateKey.D.Bytes())
	sharedSecret := sharedX.Bytes()

	// Derive AES key from shared secret using HKDF
	aesKey, err := deriveKey(sharedSecret, "harness-args-v1")
	if err != nil {
		return nil, fmt.Errorf("failed to derive key: %w", err)
	}

	// Extract nonce and ciphertext
	encryptedData := encryptedArgs[65:]
	if len(encryptedData) < 12+16 { // Need at least nonce (12) + tag (16)
		return nil, errors.New("encrypted args data too short")
	}

	nonce := encryptedData[:12]
	ciphertext := encryptedData[12:]

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
		return nil, fmt.Errorf("failed to decrypt args: %w", err)
	}

	return plaintext, nil
}

// decryptSymmetricKey decrypts the symmetric key using ECDSA key exchange
func (po *PresidentialOrderImpl) decryptSymmetricKey(encryptedKey []byte) ([]byte, error) {
	// For ECDSA key exchange, we use ECDH (Elliptic Curve Diffie-Hellman)
	// The encrypted key contains the public key point and the encrypted symmetric key

	if len(encryptedKey) < 65 { // 1 byte prefix + 32 bytes x + 32 bytes y
		return nil, errors.New("encrypted key too short")
	}

	// Extract public key point (uncompressed format: 0x04 || x || y)
	pubKeyBytes := encryptedKey[:65]
	x := new(big.Int).SetBytes(pubKeyBytes[1:33])
	y := new(big.Int).SetBytes(pubKeyBytes[33:65])

	// Create public key from point
	pubKey := &ecdsa.PublicKey{
		Curve: po.privateKey.Curve,
		X:     x,
		Y:     y,
	}

	// Validate ephemeral public key
	if err := validatePublicKey(pubKey); err != nil {
		return nil, fmt.Errorf("invalid ephemeral public key: %w", err)
	}

	// Compute shared secret using ECDH
	sharedX, _ := pubKey.Curve.ScalarMult(pubKey.X, pubKey.Y, po.privateKey.D.Bytes())
	sharedSecret := sharedX.Bytes()

	// Derive AES key from shared secret using HKDF
	aesKey, err := deriveKey(sharedSecret, "harness-symmetric-key-v1")
	if err != nil {
		return nil, fmt.Errorf("failed to derive key: %w", err)
	}

	// Decrypt the symmetric key
	encryptedSymmetricKey := encryptedKey[65:]
	if len(encryptedSymmetricKey) < 12+16 { // Need at least nonce (12) + tag (16)
		return nil, errors.New("encrypted symmetric key too short")
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

// decryptAES decrypts data using AES-256-GCM
func decryptAES(ciphertext, key []byte) ([]byte, error) {
	if len(ciphertext) < 12+16 { // Need at least nonce (12) + tag (16)
		return nil, errors.New("ciphertext too short")
	}

	if len(key) != 32 {
		return nil, errors.New("key must be 32 bytes for AES-256")
	}

	// Extract nonce (first 12 bytes)
	nonce := ciphertext[:12]
	data := ciphertext[12:]

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	// Create GCM mode
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	// Decrypt and verify authentication tag
	plaintext, err := gcm.Open(nil, nonce, data, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt data: %w", err)
	}

	return plaintext, nil
}

// parsePrivateKey parses a private key from various formats
func parsePrivateKey(keyData []byte) (*ecdsa.PrivateKey, error) {
	// Try PEM format first
	block, _ := pem.Decode(keyData)
	if block != nil {
		keyData = block.Bytes
	}

	// Try PKCS8 format
	key, err := x509.ParsePKCS8PrivateKey(keyData)
	if err == nil {
		if ecdsaKey, ok := key.(*ecdsa.PrivateKey); ok {
			return ecdsaKey, nil
		}
		return nil, errors.New("key is not ECDSA")
	}

	// Try EC private key format
	ecKey, err := x509.ParseECPrivateKey(keyData)
	if err == nil {
		return ecKey, nil
	}

	return nil, errors.New("failed to parse private key: unsupported format")
}

// validatePublicKey validates that a public key point is on the curve and not at infinity
func validatePublicKey(pubKey *ecdsa.PublicKey) error {
	if pubKey == nil {
		return errors.New("public key cannot be nil")
	}
	if pubKey.Curve == nil {
		return errors.New("public key curve cannot be nil")
	}
	// Check if point is at infinity (both coordinates are zero or invalid)
	if pubKey.X == nil || pubKey.Y == nil {
		return errors.New("public key point coordinates cannot be nil")
	}
	// Check if point is on the curve
	if !pubKey.Curve.IsOnCurve(pubKey.X, pubKey.Y) {
		return errors.New("public key point is not on the curve")
	}
	return nil
}

// padSharedSecret pads a shared secret to exactly 32 bytes for consistent key derivation
func padSharedSecret(secret []byte) []byte {
	const keySize = 32
	if len(secret) >= keySize {
		// If already >= 32 bytes, take the last 32 bytes (rightmost)
		return secret[len(secret)-keySize:]
	}
	// Pad with zeros on the left
	padded := make([]byte, keySize)
	copy(padded[keySize-len(secret):], secret)
	return padded
}

// deriveKey derives a 32-byte AES key using HKDF-SHA256
func deriveKey(sharedSecret []byte, context string) ([32]byte, error) {
	paddedSecret := padSharedSecret(sharedSecret)
	keyBytes, err := hkdf.Key(sha256.New, paddedSecret, nil, context, 32)
	if err != nil {
		var key [32]byte
		return key, fmt.Errorf("failed to derive key: %w", err)
	}
	var key [32]byte
	copy(key[:], keyBytes)
	return key, nil
}
