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
	VerifyAndDecrypt(ciphertextAndMetadata []byte) (*Payload, error)
}

// PresidentialOrderImpl implements the PresidentialOrder interface
type PresidentialOrderImpl struct {
	privateKey        *ecdsa.PrivateKey
	presidentPubKey   *ecdsa.PublicKey
	keystore          keystore.Keystore
	keystoreKeyID     string
}

// NewPresidentialOrderFromKeys creates a new PresidentialOrder from provided keys
func NewPresidentialOrderFromKeys(privateKey *ecdsa.PrivateKey, presidentPubKey *ecdsa.PublicKey) (PresidentialOrder, error) {
	if privateKey == nil {
		return nil, errors.New("private key cannot be nil")
	}
	if presidentPubKey == nil {
		return nil, errors.New("president public key cannot be nil")
	}
	return &PresidentialOrderImpl{
		privateKey:      privateKey,
		presidentPubKey: presidentPubKey,
	}, nil
}

// NewPresidentialOrderFromKeystore creates a new PresidentialOrder loading the private key from OS keystore
func NewPresidentialOrderFromKeystore(keystoreKeyID string, presidentPubKey *ecdsa.PublicKey) (PresidentialOrder, error) {
	if keystoreKeyID == "" {
		return nil, errors.New("keystore key ID cannot be empty")
	}
	if presidentPubKey == nil {
		return nil, errors.New("president public key cannot be nil")
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
		privateKey:      privateKey,
		presidentPubKey: presidentPubKey,
		keystore:        ks,
		keystoreKeyID:   keystoreKeyID,
	}, nil
}

// NewPresidentialOrderFromFile creates a new PresidentialOrder loading the private key from a file
func NewPresidentialOrderFromFile(privateKeyPath string, presidentPubKey *ecdsa.PublicKey) (PresidentialOrder, error) {
	if privateKeyPath == "" {
		return nil, errors.New("private key path cannot be empty")
	}
	if presidentPubKey == nil {
		return nil, errors.New("president public key cannot be nil")
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
		privateKey:      privateKey,
		presidentPubKey: presidentPubKey,
	}, nil
}

// VerifyAndDecrypt verifies the signature and decrypts the payload
func (po *PresidentialOrderImpl) VerifyAndDecrypt(ciphertextAndMetadata []byte) (*Payload, error) {
	// Parse the encrypted payload structure:
	// [signature_length:4][signature][metadata_length:4][metadata][encrypted_symmetric_key][encrypted_plugin_data]
	
	if len(ciphertextAndMetadata) < 8 {
		return nil, errors.New("ciphertext too short")
	}

	offset := 0
	
	// Read signature length
	sigLen := int(binary.BigEndian.Uint32(ciphertextAndMetadata[offset:offset+4]))
	offset += 4
	
	if len(ciphertextAndMetadata) < offset+sigLen {
		return nil, errors.New("invalid signature length")
	}
	
	// Read signature
	signature := ciphertextAndMetadata[offset:offset+sigLen]
	offset += sigLen
	
	// Read metadata length
	metadataLen := int(binary.BigEndian.Uint32(ciphertextAndMetadata[offset:offset+4]))
	offset += 4
	
	if len(ciphertextAndMetadata) < offset+metadataLen {
		return nil, errors.New("invalid metadata length")
	}
	
	// Read metadata
	metadata := ciphertextAndMetadata[offset:offset+metadataLen]
	offset += metadataLen
	
	// Remaining data is encrypted symmetric key + encrypted plugin data
	encryptedData := ciphertextAndMetadata[offset:]
	
	// Verify signature over metadata + encrypted data
	hash := sha256.Sum256(append(metadata, encryptedData...))
	
	var sig struct {
		R, S *big.Int
	}
	_, err := asn1.Unmarshal(signature, &sig)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal signature: %w", err)
	}
	
	if !ecdsa.Verify(po.presidentPubKey, hash[:], sig.R, sig.S) {
		return nil, errors.New("signature verification failed")
	}
	
	// Parse metadata to get encrypted symmetric key length
	var metadataStruct struct {
		SymmetricKeyLen int    `json:"symmetric_key_len"`
		PluginDataLen   int    `json:"plugin_data_len"`
		Algorithm       string `json:"algorithm"`
	}
	if err := json.Unmarshal(metadata, &metadataStruct); err != nil {
		return nil, fmt.Errorf("failed to unmarshal metadata: %w", err)
	}
	
	if len(encryptedData) < metadataStruct.SymmetricKeyLen+metadataStruct.PluginDataLen {
		return nil, errors.New("encrypted data too short")
	}
	
	// Extract encrypted symmetric key
	encryptedSymmetricKey := encryptedData[:metadataStruct.SymmetricKeyLen]
	encryptedPluginData := encryptedData[metadataStruct.SymmetricKeyLen : metadataStruct.SymmetricKeyLen+metadataStruct.PluginDataLen]
	
	// Decrypt symmetric key using ECDSA key exchange
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

