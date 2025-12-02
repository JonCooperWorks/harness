package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
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

// DecryptedResult contains both the decrypted payload and the execution arguments
type DecryptedResult struct {
	Payload *Payload
	Args    []byte // JSON arguments extracted from the file
}

// PresidentialOrder interface for verifying signatures and decrypting payloads
type PresidentialOrder interface {
	VerifyAndDecrypt(ciphertextAndMetadata []byte) (*DecryptedResult, error)
}

// PresidentialOrderImpl implements the PresidentialOrder interface
type PresidentialOrderImpl struct {
	privateKey    *ecdsa.PrivateKey // Pentester's private key (for decryption) - DEPRECATED: use keystore instead
	clientPubKey  *ecdsa.PublicKey  // Client's public key (for verifying argument signature)
	keystore      keystore.Keystore
	keystoreKeyID string
}

// NewPresidentialOrderFromKeys creates a new PresidentialOrder from provided keys
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

// NewPresidentialOrderFromKeystore creates a new PresidentialOrder loading the private key from OS keystore
func NewPresidentialOrderFromKeystore(keystoreKeyID string, clientPubKey *ecdsa.PublicKey) (PresidentialOrder, error) {
	if keystoreKeyID == "" {
		return nil, errors.New("keystore key ID cannot be empty")
	}
	if clientPubKey == nil {
		return nil, errors.New("client public key cannot be nil")
	}

	ks, err := keystore.NewKeystore()
	if err != nil {
		return nil, fmt.Errorf("failed to create keystore: %w", err)
	}

	// Don't extract private key - use keystore operations directly
	// This allows keys to remain in secure storage (HSM, cloud KMS, Secure Enclave, TPM)
	return &PresidentialOrderImpl{
		clientPubKey:  clientPubKey,
		keystore:      ks,
		keystoreKeyID: keystoreKeyID,
	}, nil
}

// NewPresidentialOrderFromFile creates a new PresidentialOrder loading the private key from a file
// DEPRECATED: Use NewPresidentialOrderFromKeystore instead (private keys should only be in keystore)
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

// VerifyAndDecrypt verifies the client signature on arguments and decrypts the payload
// File format: [encrypted_payload][client_sig_len:4][client_sig][expiration:8][args_len:4][args_json]
// Encrypted payload format: [metadata_length:4][metadata][encrypted_symmetric_key][encrypted_plugin_data]
func (po *PresidentialOrderImpl) VerifyAndDecrypt(fileData []byte) (*DecryptedResult, error) {
	if len(fileData) < 12 {
		return nil, errors.New("file too short")
	}

	// Parse from the end: read client signature, expiration, and args
	// File format (as written by sign command):
	// [encrypted_payload][client_sig_len:4][client_sig][expiration:8][args_len:4][args_json]
	//
	// Working backwards from the end:
	// - args_json is the last N bytes (where N = args_len)
	// - args_len is 4 bytes before args_json starts
	// - expiration is 8 bytes before args_len
	// - signature ends right before expiration
	// - sig_len is 4 bytes before signature starts

	if len(fileData) < 20 {
		return nil, errors.New("file too short")
	}

	// Step 1: Read args_len from the last 4 bytes
	// But wait - args_len tells us how long args_json is, and args_json comes AFTER args_len
	// So: args_json is at the end, args_len is 4 bytes before args_json starts
	// We need to find where args_len is by trying different positions

	// Try reading args_len from positions near the end
	// The args_len field tells us the length of args_json that follows it
	var argsLenPos int
	var fileArgsJSON []byte

	foundArgsLen := false
	// Try positions from the end (checking reasonable args_json lengths)
	for offset := 4; offset < len(fileData) && offset < 1024*1024+4; offset++ {
		argsLenPos = len(fileData) - offset
		if argsLenPos < 0 {
			break
		}

		// Read potential args_len
		if argsLenPos+4 > len(fileData) {
			continue
		}
		candidateArgsLen := int(binary.BigEndian.Uint32(fileData[argsLenPos : argsLenPos+4]))

		// Check if args_json would fit (starts right after args_len, ends at file end)
		argsStart := argsLenPos + 4
		expectedArgsEnd := argsStart + candidateArgsLen
		if expectedArgsEnd == len(fileData) {
			// Validate it looks like JSON
			if candidateArgsLen > 0 && argsStart < len(fileData) {
				argsJSON := fileData[argsStart : argsStart+candidateArgsLen]
				if len(argsJSON) > 0 && (argsJSON[0] == '{' || argsJSON[0] == '[') {
					fileArgsJSON = argsJSON
					foundArgsLen = true
					break
				}
			} else if candidateArgsLen == 0 {
				// Empty args_json is valid
				fileArgsJSON = []byte{}
				foundArgsLen = true
				break
			}
		}
	}

	if !foundArgsLen {
		return nil, errors.New("could not find valid args_len")
	}

	if !foundArgsLen {
		return nil, errors.New("could not find valid args_len")
	}

	// Step 2: Read expiration (8 bytes before args_len)
	expirationPos := argsLenPos - 8
	if expirationPos < 0 {
		return nil, errors.New("file too short for expiration")
	}
	expirationUnix := int64(binary.BigEndian.Uint64(fileData[expirationPos : expirationPos+8]))
	expirationTime := time.Unix(expirationUnix, 0)

	// Verify expiration has not passed
	if time.Now().After(expirationTime) {
		return nil, fmt.Errorf("payload has expired: expiration was %s, current time is %s", expirationTime.Format(time.RFC3339), time.Now().Format(time.RFC3339))
	}

	// Now we need to find the signature. The signature is before expiration.
	// Structure: [encrypted_payload][client_sig_len:4][client_sig][expiration:8][args_len:4][args_json]
	// The signature ends at expirationPos, so we need to find where it starts.
	// ECDSA P-256 signatures are typically 70-72 bytes in ASN.1 DER format.

	// Read backwards from expirationPos to find the signature length
	// We'll check positions where sig_len could be (4 bytes before where sig would start)
	// Signature lengths are typically 60-80 bytes for ECDSA P-256
	foundSigLen := false
	var clientSigLen int
	var sigLenPos int

	// Try reading signature length from positions before expirationPos
	// We need at least 4 bytes for sig_len, so start from expirationPos - 4 - 80 (max sig len)
	minPos := expirationPos - 4 - 80
	if minPos < 0 {
		minPos = 0
	}

	// Check positions backwards from expirationPos
	for pos := expirationPos - 4 - 60; pos >= minPos && pos >= 0; pos-- {
		// Read potential signature length
		if pos+4 > expirationPos {
			continue
		}
		sigLenCandidate := int(binary.BigEndian.Uint32(fileData[pos : pos+4]))

		// Check if it's a reasonable signature length
		if sigLenCandidate >= 60 && sigLenCandidate <= 80 {
			// Check if signature would end exactly at expirationPos
			sigStart := pos + 4
			sigEnd := sigStart + sigLenCandidate
			if sigEnd == expirationPos {
				clientSigLen = sigLenCandidate
				sigLenPos = pos
				foundSigLen = true
				break
			}
		}
	}

	if !foundSigLen {
		return nil, errors.New("could not find valid signature length")
	}

	// Read client signature
	sigPos := sigLenPos + 4
	// Signature should end at expirationPos (8 bytes before args_len)
	if sigPos+clientSigLen != expirationPos {
		return nil, fmt.Errorf("signature position mismatch: expected sig to end at %d, but expiration starts at %d", sigPos+clientSigLen, expirationPos)
	}
	clientSignature := fileData[sigPos : sigPos+clientSigLen]
	offset := sigLenPos

	// Verify client signature on expiration + arguments
	// Signature covers: expiration (8 bytes) + args_json
	dataToVerify := make([]byte, 8+len(fileArgsJSON))
	binary.BigEndian.PutUint64(dataToVerify[0:8], uint64(expirationUnix))
	copy(dataToVerify[8:], fileArgsJSON)

	dataHash := sha256.Sum256(dataToVerify)
	var sig struct {
		R, S *big.Int
	}
	if _, err := asn1.Unmarshal(clientSignature, &sig); err != nil {
		return nil, fmt.Errorf("failed to unmarshal client signature: %w", err)
	}
	if !ecdsa.Verify(po.clientPubKey, dataHash[:], sig.R, sig.S) {
		return nil, errors.New("client signature verification failed")
	}

	// Now parse encrypted payload (everything before client signature)
	encryptedPayload := fileData[:offset]
	if len(encryptedPayload) < 4 {
		return nil, errors.New("encrypted payload too short")
	}

	// Parse encrypted payload: [metadata_length:4][metadata][encrypted_symmetric_key][encrypted_plugin_data]
	payloadOffset := 0

	// Read metadata length
	metadataLen := int(binary.BigEndian.Uint32(encryptedPayload[payloadOffset : payloadOffset+4]))
	payloadOffset += 4

	if len(encryptedPayload) < payloadOffset+metadataLen {
		return nil, errors.New("invalid metadata length")
	}

	// Read metadata
	metadata := encryptedPayload[payloadOffset : payloadOffset+metadataLen]
	payloadOffset += metadataLen

	// Parse metadata to get encrypted symmetric key length
	var metadataStruct struct {
		SymmetricKeyLen int    `json:"symmetric_key_len"`
		PluginDataLen   int    `json:"plugin_data_len"`
		Algorithm       string `json:"algorithm"`
	}
	if err := json.Unmarshal(metadata, &metadataStruct); err != nil {
		return nil, fmt.Errorf("failed to unmarshal metadata: %w", err)
	}

	// Remaining data is encrypted symmetric key + encrypted plugin data
	encryptedData := encryptedPayload[payloadOffset:]
	if len(encryptedData) < metadataStruct.SymmetricKeyLen+metadataStruct.PluginDataLen {
		return nil, errors.New("encrypted data too short")
	}

	// Extract encrypted symmetric key
	encryptedSymmetricKey := encryptedData[:metadataStruct.SymmetricKeyLen]
	encryptedPluginData := encryptedData[metadataStruct.SymmetricKeyLen : metadataStruct.SymmetricKeyLen+metadataStruct.PluginDataLen]

	// Decrypt symmetric key using pentester's private key (ECDH)
	var symmetricKey []byte
	var err error
	if po.keystore != nil && po.keystoreKeyID != "" {
		// Use keystore for decryption (keys never leave secure storage)
		symmetricKey, err = po.keystore.DecryptSymmetricKey(po.keystoreKeyID, encryptedSymmetricKey)
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

	return &DecryptedResult{
		Payload: &payload,
		Args:    fileArgsJSON,
	}, nil
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

	// Compute shared secret using ECDH
	sharedX, _ := pubKey.Curve.ScalarMult(pubKey.X, pubKey.Y, po.privateKey.D.Bytes())
	sharedSecret := sharedX.Bytes()

	// Derive AES key from shared secret using SHA256
	aesKey := sha256.Sum256(sharedSecret)

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
