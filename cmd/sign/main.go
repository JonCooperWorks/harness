package main

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/joncooperworks/harness/crypto"
	"github.com/joncooperworks/harness/crypto/keystore"
)

func main() {
	var (
		encryptedFile       = flag.String("file", "", "Path to encrypted plugin file (from encrypt command)")
		clientKeyID         = flag.String("client-keystore-key", "", "Key ID in OS keystore for client's private key (required)")
		pentesterPubKeyFile = flag.String("pentester-key", "", "Path to pentester's public key file (required, for encrypting arguments)")
		argsJSON            = flag.String("args", "", "JSON arguments to sign (required)")
		expirationDur       = flag.Duration("expiration", 72*time.Hour, "Expiration duration from now (default: 72h = 3 days)")
		outputPath          = flag.String("output", "", "Path to save approved plugin (defaults to input file with .approved suffix)")
	)
	flag.Parse()

	if *encryptedFile == "" {
		fmt.Fprintf(os.Stderr, "Error: -file is required\n")
		os.Exit(1)
	}

	if *clientKeyID == "" {
		fmt.Fprintf(os.Stderr, "Error: -client-keystore-key is required (private keys must be stored in OS keystore)\n")
		os.Exit(1)
	}

	if *pentesterPubKeyFile == "" {
		fmt.Fprintf(os.Stderr, "Error: -pentester-key is required (pentester's public key for encrypting arguments)\n")
		os.Exit(1)
	}

	if *argsJSON == "" {
		fmt.Fprintf(os.Stderr, "Error: -args is required (client must sign execution arguments)\n")
		os.Exit(1)
	}

	if *outputPath == "" {
		*outputPath = *encryptedFile + ".approved"
	}

	// Load keystore (keys never leave secure storage)
	ks, err := keystore.NewKeystore()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error creating keystore: %v\n", err)
		os.Exit(1)
	}

	// Load pentester's public key for encrypting arguments
	pentesterPubKey, err := loadPublicKey(*pentesterPubKeyFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading pentester's public key: %v\n", err)
		os.Exit(1)
	}

	// Open encrypted file
	encryptedFileHandle, err := os.Open(*encryptedFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error opening encrypted file: %v\n", err)
		os.Exit(1)
	}
	defer encryptedFileHandle.Close()

	// Calculate expiration timestamp
	expirationTime := time.Now().Add(*expirationDur)

	// Sign encrypted plugin using library function
	signReq := &crypto.SignEncryptedPluginRequest{
		EncryptedData:   encryptedFileHandle,
		ArgsJSON:        []byte(*argsJSON),
		ClientKeystore:  ks,
		ClientKeyID:     *clientKeyID,
		PentesterPubKey: pentesterPubKey,
		Expiration:      &expirationTime,
	}

	result, err := crypto.SignEncryptedPlugin(signReq)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error signing encrypted plugin: %v\n", err)
		os.Exit(1)
	}

	// Extract encrypted payload hash for logging
	// Format: [version:1][principal_sig_len:4][principal_sig][metadata_length:4][metadata][encrypted_symmetric_key][encrypted_plugin_data][client_sig_len:4][client_sig][expiration:8][args_len:4][encrypted_args]
	if len(result.ApprovedData) < 1+4 {
		fmt.Fprintf(os.Stderr, "Error: approved data too short\n")
		os.Exit(1)
	}
	principalSigLen := int(binary.BigEndian.Uint32(result.ApprovedData[1:5]))
	if len(result.ApprovedData) < 1+4+principalSigLen+4 {
		fmt.Fprintf(os.Stderr, "Error: approved data too short\n")
		os.Exit(1)
	}
	encryptedPayloadStart := 1 + 4 + principalSigLen
	// Find end of encrypted payload (before client signature)
	// We need to read metadata to find the exact end
	metadataLen := int(binary.BigEndian.Uint32(result.ApprovedData[encryptedPayloadStart : encryptedPayloadStart+4]))
	if len(result.ApprovedData) < encryptedPayloadStart+4+metadataLen {
		fmt.Fprintf(os.Stderr, "Error: approved data too short for metadata\n")
		os.Exit(1)
	}
	metadataStart := encryptedPayloadStart + 4
	metadataEnd := metadataStart + metadataLen
	var metadataStruct struct {
		SymmetricKeyLen int `json:"symmetric_key_len"`
		PluginDataLen   int `json:"plugin_data_len"`
	}
	if err := json.Unmarshal(result.ApprovedData[metadataStart:metadataEnd], &metadataStruct); err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing metadata: %v\n", err)
		os.Exit(1)
	}
	encryptedPayloadEnd := metadataEnd + metadataStruct.SymmetricKeyLen + metadataStruct.PluginDataLen
	encryptedPayload := result.ApprovedData[encryptedPayloadStart:encryptedPayloadEnd]
	encryptedPayloadHash := sha256.Sum256(encryptedPayload)
	encryptedPayloadHashHex := hex.EncodeToString(encryptedPayloadHash[:])

	// Get client public key for logging
	clientPubKey, err := ks.GetPublicKey(*clientKeyID)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error getting client public key: %v\n", err)
		os.Exit(1)
	}
	pubKeyBytes, err := x509.MarshalPKIXPublicKey(clientPubKey)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error marshaling public key: %v\n", err)
		os.Exit(1)
	}
	pubKeyHash := sha256.Sum256(pubKeyBytes)
	pubKeyHashHex := hex.EncodeToString(pubKeyHash[:])

	// Log signing details
	fmt.Fprintf(os.Stderr, "[SIGNING LOG] %s\n", time.Now().Format(time.RFC3339))
	fmt.Fprintf(os.Stderr, "[SIGNING LOG] Encrypted Payload Hash (SHA256): %s\n", encryptedPayloadHashHex)
	fmt.Fprintf(os.Stderr, "[SIGNING LOG] Client Public Key Hash (SHA256): %s\n", pubKeyHashHex)

	output := result.ApprovedData

	// Write to file
	if err := os.WriteFile(*outputPath, output, 0644); err != nil {
		fmt.Fprintf(os.Stderr, "Error writing approved file: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Arguments signed successfully:\n")
	fmt.Printf("  Input: %s\n", *encryptedFile)
	fmt.Printf("  Output: %s\n", *outputPath)
	fmt.Printf("  Expiration: %s (%s)\n", result.ExpirationTime.Format(time.RFC3339), result.ExpirationTime.Format(time.RFC1123))
}

// loadPublicKey loads an ECDSA public key from a file
func loadPublicKey(path string) (*ecdsa.PublicKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read public key file: %w", err)
	}

	// Try PEM format first
	block, _ := pem.Decode(data)
	if block != nil {
		data = block.Bytes
	}

	// Parse public key
	pubKey, err := x509.ParsePKIXPublicKey(data)
	if err != nil {
		return nil, fmt.Errorf("failed to parse public key: %w", err)
	}

	ecdsaPubKey, ok := pubKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("public key is not ECDSA")
	}

	return ecdsaPubKey, nil
}
