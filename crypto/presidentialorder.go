package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/joncooperworks/harness/crypto/hceepcrypto"
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
	// This signature covers the encrypted payload, expiration, and encrypted arguments.
	ClientSignature []byte
	// PrincipalSignature is the principal's signature from the approved file.
	// This signature covers the encrypted payload.
	PrincipalSignature []byte
}

// VerifyHashes contains all SHA256 hashes calculated during verification.
type VerifyHashes struct {
	// EncryptedPayloadHash is the SHA256 hash of the encrypted payload.
	EncryptedPayloadHash string
	// ExploitOwnerSignatureHash is the SHA256 hash of the exploit owner's signature.
	ExploitOwnerSignatureHash string
	// ExploitOwnerPublicKeyHash is the SHA256 hash of the exploit owner's public key.
	ExploitOwnerPublicKeyHash string
	// TargetSignatureHash is the SHA256 hash of the target's signature.
	TargetSignatureHash string
	// TargetPublicKeyHash is the SHA256 hash of the target's public key.
	TargetPublicKeyHash string
	// HarnessPublicKeyHash is the SHA256 hash of the harness (pentester's) public key.
	HarnessPublicKeyHash string
}

// VerifyAndDecryptResult contains the decrypted result and all calculated hashes.
type VerifyAndDecryptResult struct {
	// DecryptedResult contains the decrypted payload and signatures.
	*DecryptedResult
	// Hashes contains all SHA256 hashes calculated during verification.
	Hashes VerifyHashes
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

// Max size limits for encrypted blobs (DoS protection)
const (
	MaxEncryptedSymmetricKeySize = 1024              // Reasonable for X25519+AES-GCM envelope
	MaxEncryptedPluginDataSize   = 100 * 1024 * 1024 // 100MB
	MaxEncryptedArgsSize         = 1 * 1024 * 1024   // 1MB
)

// PresidentialOrderImpl implements the PresidentialOrder interface
type PresidentialOrderImpl struct {
	clientPubKey    ed25519.PublicKey // Client's public key (for verifying argument signature)
	principalPubKey ed25519.PublicKey // Principal's public key (for verifying payload signature)
	keystore        keystore.Keystore // Bound keystore for the harness/pentester key
}

// NewPresidentialOrderFromKeystore creates a new PresidentialOrder with the specified keystore and public keys.
//
// This is the recommended way to create a PresidentialOrder. It uses a bound Keystore
// (private key stored in OS keystore, never loaded into memory) and includes both client and
// principal signature verification for full dual-authorization security.
//
// The harnessKeystore is a bound keystore for the pentester's key (use keystore.NewKeystoreForKey).
// The clientPubKey is the client's public key for verifying argument signatures.
// The principalPubKey is the principal's (EO's) public key for verifying payload signatures.
//
// The private key never leaves secure storage - all decryption operations happen
// through the keystore interface, allowing hardware-backed or cloud-based key storage.
func NewPresidentialOrderFromKeystore(harnessKeystore keystore.Keystore, clientPubKey ed25519.PublicKey, principalPubKey ed25519.PublicKey) (PresidentialOrder, error) {
	if harnessKeystore == nil {
		return nil, errors.New("harness keystore cannot be nil")
	}
	if len(clientPubKey) == 0 {
		return nil, errors.New("client public key cannot be empty")
	}
	if len(principalPubKey) == 0 {
		return nil, errors.New("principal public key cannot be empty")
	}

	return &PresidentialOrderImpl{
		clientPubKey:    clientPubKey,
		principalPubKey: principalPubKey,
		keystore:        harnessKeystore,
	}, nil
}

// VerifyAndDecryptWithHashes verifies signatures, decrypts the payload, and returns hashes.
//
// This is a convenience wrapper around PresidentialOrder.VerifyAndDecrypt that also
// calculates and returns all relevant SHA256 hashes for audit logging.
func VerifyAndDecryptWithHashes(po PresidentialOrder, fileData []byte, harnessPubKey ed25519.PublicKey, targetPubKey ed25519.PublicKey, exploitPubKey ed25519.PublicKey) (*VerifyAndDecryptResult, error) {
	result, err := po.VerifyAndDecrypt(fileData)
	if err != nil {
		return nil, err
	}

	// Calculate hash of target signature
	targetSigHash := sha256.Sum256(result.ClientSignature)
	targetSigHashHex := hex.EncodeToString(targetSigHash[:])

	// Calculate hash of target public key
	targetPubKeyBytes, err := x509.MarshalPKIXPublicKey(targetPubKey)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal target public key: %w", err)
	}
	targetPubKeyHash := sha256.Sum256(targetPubKeyBytes)
	targetPubKeyHashHex := hex.EncodeToString(targetPubKeyHash[:])

	// Calculate hash of harness public key
	harnessPubKeyBytes, err := x509.MarshalPKIXPublicKey(harnessPubKey)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal harness public key: %w", err)
	}
	harnessPubKeyHash := sha256.Sum256(harnessPubKeyBytes)
	harnessPubKeyHashHex := hex.EncodeToString(harnessPubKeyHash[:])

	// Calculate hash of exploit owner signature
	exploitSigHash := sha256.Sum256(result.PrincipalSignature)
	exploitSigHashHex := hex.EncodeToString(exploitSigHash[:])

	// Calculate hash of exploit owner public key
	exploitPubKeyBytes, err := x509.MarshalPKIXPublicKey(exploitPubKey)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal exploit owner public key: %w", err)
	}
	exploitPubKeyHash := sha256.Sum256(exploitPubKeyBytes)
	exploitPubKeyHashHex := hex.EncodeToString(exploitPubKeyHash[:])

	// Calculate encrypted payload hash deterministically by parsing offsets
	// This matches the exact calculation used in VerifyAndDecrypt
	const headerSize = 4 + 1 + 1 + 4 // magic + version + flags + file_length
	if len(fileData) < headerSize+4 {
		return nil, errors.New("file too short")
	}
	principalSigLen := int(binary.BigEndian.Uint32(fileData[headerSize : headerSize+4]))
	if len(fileData) < headerSize+4+principalSigLen+4 {
		return nil, errors.New("file too short")
	}
	pos := headerSize + 4 + principalSigLen // Position after principal signature

	// Read metadata length
	if pos+4 > len(fileData) {
		return nil, errors.New("file too short for metadata length")
	}
	metadataLen := int(binary.BigEndian.Uint32(fileData[pos : pos+4]))
	if metadataLen > 10000 {
		return nil, fmt.Errorf("metadata length %d exceeds maximum allowed size %d", metadataLen, 10000)
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

	// Parse metadata to get encrypted symmetric key length and plugin data length
	var metadataStruct struct {
		SymmetricKeyLen int    `json:"symmetric_key_len"`
		PluginDataLen   int    `json:"plugin_data_len"`
		Algorithm       string `json:"algorithm"`
	}
	if err := json.Unmarshal(metadata, &metadataStruct); err != nil {
		return nil, fmt.Errorf("failed to unmarshal metadata: %w", err)
	}

	// Calculate encrypted payload deterministically
	// Encrypted payload = [metadata_len:4][metadata][encrypted_symmetric_key][encrypted_plugin_data]
	encryptedPayloadStart := pos - 4 - metadataLen // Start at metadata_len
	encryptedPayloadEnd := pos + metadataStruct.SymmetricKeyLen + metadataStruct.PluginDataLen
	if encryptedPayloadEnd > len(fileData) {
		return nil, errors.New("file too short for encrypted payload")
	}
	encryptedPayload := fileData[encryptedPayloadStart:encryptedPayloadEnd]
	encryptedPayloadHash := sha256.Sum256(encryptedPayload)
	encryptedPayloadHashHex := hex.EncodeToString(encryptedPayloadHash[:])

	return &VerifyAndDecryptResult{
		DecryptedResult: result,
		Hashes: VerifyHashes{
			EncryptedPayloadHash:      encryptedPayloadHashHex,
			ExploitOwnerSignatureHash: exploitSigHashHex,
			ExploitOwnerPublicKeyHash: exploitPubKeyHashHex,
			TargetSignatureHash:       targetSigHashHex,
			TargetPublicKeyHash:       targetPubKeyHashHex,
			HarnessPublicKeyHash:      harnessPubKeyHashHex,
		},
	}, nil
}

// VerifyAndDecrypt verifies signatures and decrypts the payload.
//
// This method implements the pentester's role in the dual-authorization model:
//  1. Verifies the principal signature on the encrypted payload using ContextPayloadSignature (before decryption)
//  2. Verifies the client signature on encrypted payload + expiration + arguments using ContextClientSignature
//  3. Checks that the expiration has not passed
//  4. Decrypts the symmetric key using ECDH with the pentester's private key (from keystore)
//  5. Decrypts the plugin data using AES-256-GCM
//  6. Decrypts the execution arguments using ECDH
//
// File format: [magic:4][version:1][flags:1][file_length:4][principal_sig_len:4][principal_sig][metadata_len:4][metadata][encrypted_symmetric_key][encrypted_plugin_data][client_sig_len:4][client_sig][expiration:8][args_len:4][encrypted_args]
//
// Principal signature signs: encrypted_payload = [metadata_len:4][metadata][encrypted_symmetric_key][encrypted_plugin_data]
// (using ContextPayloadSignature for domain separation)
//
// Client signature signs: encrypted_payload || expiration || encrypted_args
// (using ContextClientSignature for domain separation)
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

	// Read version (supports 1 and 2)
	version := fileData[pos]
	if version != 1 && version != 2 {
		return nil, fmt.Errorf("unsupported file format version: %d (expected 1 or 2)", version)
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
	if principalSigLen != 64 {
		return nil, fmt.Errorf("invalid principal signature length: %d (expected 64 bytes for Ed25519)", principalSigLen)
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

	// Enforce max size limits (DoS protection)
	if metadataStruct.SymmetricKeyLen > MaxEncryptedSymmetricKeySize {
		return nil, fmt.Errorf("encrypted symmetric key size %d exceeds maximum %d", metadataStruct.SymmetricKeyLen, MaxEncryptedSymmetricKeySize)
	}
	if metadataStruct.PluginDataLen > MaxEncryptedPluginDataSize {
		return nil, fmt.Errorf("encrypted plugin data size %d exceeds maximum %d", metadataStruct.PluginDataLen, MaxEncryptedPluginDataSize)
	}
	if metadataStruct.SymmetricKeyLen < 0 {
		return nil, fmt.Errorf("invalid encrypted symmetric key size: %d", metadataStruct.SymmetricKeyLen)
	}
	if metadataStruct.PluginDataLen < 0 {
		return nil, fmt.Errorf("invalid encrypted plugin data size: %d", metadataStruct.PluginDataLen)
	}

	// Calculate encrypted payload for signature verification
	// Encrypted payload = [metadata_len:4][metadata][encrypted_symmetric_key][encrypted_plugin_data]
	encryptedPayloadStart := pos - 4 - metadataLen // Start at metadata_len
	encryptedPayloadEnd := pos + metadataStruct.SymmetricKeyLen + metadataStruct.PluginDataLen
	if encryptedPayloadEnd > len(fileData) {
		return nil, errors.New("file too short for encrypted payload")
	}
	encryptedPayload := fileData[encryptedPayloadStart:encryptedPayloadEnd]

	// Verify principal signature BEFORE decryption
	// EO signatures use ContextPayloadSignature for domain separation
	// Version 1: ContextPayloadSignature || encrypted_payload
	// Version 2: ContextPayloadSignature || version || flags || encrypted_payload
	var principalDataToVerify []byte
	if version == 2 {
		principalDataToVerify = append(principalDataToVerify, version)
		principalDataToVerify = append(principalDataToVerify, flags)
		principalDataToVerify = append(principalDataToVerify, encryptedPayload...)
	} else {
		principalDataToVerify = encryptedPayload
	}
	if err := po.keystore.Verify(po.principalPubKey, principalDataToVerify, principalSignature, hceepcrypto.ContextPayloadSignature); err != nil {
		return nil, errors.New("principal signature verification failed (signature must cover encrypted payload with ContextPayloadSignature)")
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
	if clientSigLen != 64 {
		return nil, fmt.Errorf("invalid client signature length: %d (expected 64 bytes for Ed25519)", clientSigLen)
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

	// Enforce max size limit for encrypted args (DoS protection)
	if encryptedArgsLen > MaxEncryptedArgsSize {
		return nil, fmt.Errorf("encrypted args size %d exceeds maximum %d", encryptedArgsLen, MaxEncryptedArgsSize)
	}
	if encryptedArgsLen < 0 {
		return nil, fmt.Errorf("invalid encrypted args size: %d", encryptedArgsLen)
	}

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

	// Verify client signature: Signature covers encrypted_payload + expiration (8 bytes) + encrypted_args
	// Client signatures use ContextClientSignature for domain separation
	// Version 1: ContextClientSignature || encrypted_payload || expiration || encrypted_args
	// Version 2: ContextClientSignature || version || flags || encrypted_payload || expiration || encrypted_args
	var dataToVerify []byte
	if version == 2 {
		dataToVerify = append(dataToVerify, version)
		dataToVerify = append(dataToVerify, flags)
	}
	dataToVerify = append(dataToVerify, encryptedPayload...)
	expirationBuf := make([]byte, 8)
	binary.BigEndian.PutUint64(expirationBuf, uint64(expirationUnix))
	dataToVerify = append(dataToVerify, expirationBuf...)
	dataToVerify = append(dataToVerify, encryptedArgs...)

	if err := po.keystore.Verify(po.clientPubKey, dataToVerify, clientSignature, hceepcrypto.ContextClientSignature); err != nil {
		return nil, errors.New("client signature verification failed (signature must cover encrypted payload, expiration, and arguments with ContextClientSignature)")
	}

	// Create EnvelopeCipher for harness using the bound keystore
	enc := hceepcrypto.NewEnvelopeCipher(po.keystore)

	// Decrypt symmetric key using EnvelopeCipher
	symmetricKey, err := enc.DecryptFromPeer(hceepcrypto.ContextSymmetricKey, encryptedSymmetricKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt symmetric key: %w", err)
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

	// Decrypt arguments using EnvelopeCipher
	decryptedArgs, err := enc.DecryptFromPeer(hceepcrypto.ContextArgs, encryptedArgs)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt arguments: %w", err)
	}

	// Populate Args in the Payload for use during plugin loading
	payload.Args = decryptedArgs

	return &DecryptedResult{
		Payload:            &payload,
		Args:               decryptedArgs,
		ClientSignature:    clientSignature,
		PrincipalSignature: principalSignature,
	}, nil
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
