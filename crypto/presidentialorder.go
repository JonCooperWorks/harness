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

	"github.com/joncooperworks/harness/crypto/keystore"
)

// PresidentialOrder interface for verifying signatures and decrypting payloads
type PresidentialOrder interface {
	VerifyAndDecrypt(ciphertextAndMetadata []byte, argsJSON []byte) (*Payload, error)
}

// PresidentialOrderImpl implements the PresidentialOrder interface
type PresidentialOrderImpl struct {
	privateKey      *ecdsa.PrivateKey // Pentester's private key (for decryption)
	clientPubKey    *ecdsa.PublicKey  // Client's public key (for verifying argument signature)
	keystore        keystore.Keystore
	keystoreKeyID   string
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

	privateKey, err := ks.GetPrivateKey(keystoreKeyID)
	if err != nil {
		return nil, fmt.Errorf("failed to get private key from keystore: %w", err)
	}

	return &PresidentialOrderImpl{
		privateKey:    privateKey,
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
// File format: [encrypted_payload][client_sig_len:4][client_sig][args_len:4][args_json]
// Encrypted payload format: [metadata_length:4][metadata][encrypted_symmetric_key][encrypted_plugin_data]
func (po *PresidentialOrderImpl) VerifyAndDecrypt(fileData []byte, argsJSON []byte) (*Payload, error) {
	if len(fileData) < 12 {
		return nil, errors.New("file too short")
	}

	// Parse from the end: read client signature and args
	// File format: [encrypted_payload][client_sig_len:4][client_sig][args_len:4][args_json]
	argsJSONBytes := []byte(argsJSON)
	argsLen := len(argsJSONBytes)
	
	// Find args in the file (should be at the end)
	if len(fileData) < argsLen+4 {
		return nil, errors.New("file too short")
	}
	
	// Args start position (args_json starts here)
	argsStart := len(fileData) - argsLen
	
	// Verify args match
	fileArgsJSON := fileData[argsStart : argsStart+argsLen]
	if string(fileArgsJSON) != string(argsJSONBytes) {
		return nil, fmt.Errorf("provided args do not match file args: file has %q, provided %q", string(fileArgsJSON), string(argsJSONBytes))
	}
	
	// Read args_len (4 bytes before args_json)
	argsLenPos := argsStart - 4
	if argsLenPos < 0 {
		return nil, errors.New("file too short for args_len")
	}
	argsLenFromFile := int(binary.BigEndian.Uint32(fileData[argsLenPos : argsLenPos+4]))
	if argsLenFromFile != argsLen {
		return nil, fmt.Errorf("args length mismatch: file has %d bytes, provided %d bytes", argsLenFromFile, argsLen)
	}
	
	// Now we need to find the signature. The signature is before args_len.
	// We know the structure is: [payload][sig_len:4][sig][args_len:4][args]
	// So sig ends at argsLenPos, and sig_len is 4 bytes before sig starts.
	// But we don't know sig length yet. Let's try reading backwards to find a reasonable sig_len value.
	// ECDSA P-256 signatures are typically 70-72 bytes in ASN.1 DER format.
	
	// Try to find sig_len by looking for reasonable values (60-80 bytes)
	// Start from argsLenPos and work backwards
	foundSigLen := false
	var clientSigLen int
	var sigLenPos int
	for offset := 4; offset < argsLenPos && offset < 200; offset += 1 {
		pos := argsLenPos - offset - 4
		if pos < 0 {
			break
		}
		sigLenCandidate := int(binary.BigEndian.Uint32(fileData[pos : pos+4]))
		if sigLenCandidate >= 60 && sigLenCandidate <= 80 {
			// Check if sig + sig_len + args_len + args would match
			sigStart := pos + 4
			sigEnd := sigStart + sigLenCandidate
			if sigEnd == argsLenPos {
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
	if sigPos+clientSigLen != argsLenPos {
		return nil, fmt.Errorf("signature position mismatch: expected sig to end at %d, but args_len starts at %d", sigPos+clientSigLen, argsLenPos)
	}
	clientSignature := fileData[sigPos : sigPos+clientSigLen]
	offset := sigLenPos

	// Verify client signature on arguments
	argsHash := sha256.Sum256(argsJSON)
	var sig struct {
		R, S *big.Int
	}
	if _, err := asn1.Unmarshal(clientSignature, &sig); err != nil {
		return nil, fmt.Errorf("failed to unmarshal client signature: %w", err)
	}
	if !ecdsa.Verify(po.clientPubKey, argsHash[:], sig.R, sig.S) {
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
	symmetricKey, err := po.decryptSymmetricKey(encryptedSymmetricKey)
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

	return &payload, nil
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

