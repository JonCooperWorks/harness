package main

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/joncooperworks/harness/crypto/keystore"
)

func main() {
	var (
		encryptedFile = flag.String("file", "", "Path to encrypted plugin file (from encrypt command)")
		clientKeyID   = flag.String("client-keystore-key", "", "Key ID in OS keystore for client's private key (required)")
		argsJSON      = flag.String("args", "", "JSON arguments to sign (required)")
		expirationDur = flag.Duration("expiration", 72*time.Hour, "Expiration duration from now (default: 72h = 3 days)")
		outputPath    = flag.String("output", "", "Path to save approved plugin (defaults to input file with .approved suffix)")
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

	// Validate args JSON
	var args json.RawMessage
	if err := json.Unmarshal([]byte(*argsJSON), &args); err != nil {
		fmt.Fprintf(os.Stderr, "Error: invalid JSON in -args: %v\n", err)
		os.Exit(1)
	}

	// Load encrypted file (format: [principal_sig_len:4][principal_sig][metadata_length:4][metadata][encrypted_symmetric_key][encrypted_plugin_data])
	encryptedData, err := os.ReadFile(*encryptedFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading encrypted file: %v\n", err)
		os.Exit(1)
	}

	// Calculate expiration timestamp (Unix timestamp in seconds)
	expirationTime := time.Now().Add(*expirationDur)
	expirationUnix := expirationTime.Unix()

	// Hash the encrypted payload to include in signature
	encryptedPayloadHash := sha256.Sum256(encryptedData)
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

	// Sign encrypted payload hash + expiration + arguments together using keystore (key never leaves secure storage)
	argsBytes := []byte(*argsJSON)
	// Create data to sign: encrypted_payload_hash (32 bytes) + expiration (8 bytes) + args_json
	dataToSign := make([]byte, 32+8+len(argsBytes))
	copy(dataToSign[0:32], encryptedPayloadHash[:])
	binary.BigEndian.PutUint64(dataToSign[32:40], uint64(expirationUnix))
	copy(dataToSign[40:], argsBytes)

	hash := sha256.Sum256(dataToSign)
	signature, err := ks.Sign(*clientKeyID, hash[:])
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error signing payload and arguments: %v\n", err)
		os.Exit(1)
	}

	// Build final approved file structure:
	// [version:1][principal_sig_len:4][principal_sig][metadata_length:4][metadata][encrypted_symmetric_key][encrypted_plugin_data][client_sig_len:4][client_sig][expiration:8][args_len:4][args_json]
	var output []byte

	// Write version (1 byte, version 1)
	output = append(output, byte(1))

	// Write encrypted payload (already in correct format)
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

	// Write args length
	argsLenBuf := make([]byte, 4)
	binary.BigEndian.PutUint32(argsLenBuf, uint32(len(argsBytes)))
	output = append(output, argsLenBuf...)

	// Write args JSON
	output = append(output, argsBytes...)

	// Write to file
	if err := os.WriteFile(*outputPath, output, 0644); err != nil {
		fmt.Fprintf(os.Stderr, "Error writing approved file: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Arguments signed successfully:\n")
	fmt.Printf("  Input: %s\n", *encryptedFile)
	fmt.Printf("  Output: %s\n", *outputPath)
	fmt.Printf("  Expiration: %s (%s)\n", expirationTime.Format(time.RFC3339), expirationTime.Format(time.RFC1123))
}
