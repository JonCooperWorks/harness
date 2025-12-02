package main

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
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
		encryptedFile      = flag.String("file", "", "Path to approved plugin file (with client signature)")
		keystoreKeyID      = flag.String("keystore-key", "", "Key ID in OS keystore for pentester's private key (required)")
		clientPubKeyFile   = flag.String("client-key", "", "Path to client's public key file (required)")
		principalPubKeyFile = flag.String("principal-key", "", "Path to principal's public key file (required, for verifying payload signature)")
	)
	flag.Parse()

	if *encryptedFile == "" {
		fmt.Fprintf(os.Stderr, "Error: -file is required\n")
		os.Exit(1)
	}

	if *keystoreKeyID == "" {
		fmt.Fprintf(os.Stderr, "Error: -keystore-key is required (pentester's private key must be stored in OS keystore)\n")
		os.Exit(1)
	}

	if *clientPubKeyFile == "" {
		fmt.Fprintf(os.Stderr, "Error: -client-key is required (client's public key for verifying argument signature)\n")
		os.Exit(1)
	}

	if *principalPubKeyFile == "" {
		fmt.Fprintf(os.Stderr, "Error: -principal-key is required (principal's public key for verifying payload signature)\n")
		os.Exit(1)
	}

	// Load client's public key
	clientPubKey, err := loadPublicKey(*clientPubKeyFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading client's public key: %v\n", err)
		os.Exit(1)
	}

	// Load principal's public key (required)
	principalPubKey, err := loadPublicKey(*principalPubKeyFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading principal's public key: %v\n", err)
		os.Exit(1)
	}

	// Get pentester's public key from keystore for logging
	ks, err := keystore.NewKeystore()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error creating keystore: %v\n", err)
		os.Exit(1)
	}
	pentesterPubKey, err := ks.GetPublicKey(*keystoreKeyID)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error getting pentester's public key: %v\n", err)
		os.Exit(1)
	}

	// Create PresidentialOrder from keystore (pentester's private key + client's public key + principal's public key)
	po, err := crypto.NewPresidentialOrderFromKeystoreWithPrincipal(*keystoreKeyID, clientPubKey, principalPubKey)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error creating PresidentialOrder from keystore: %v\n", err)
		os.Exit(1)
	}

	// Load approved file (contains encrypted payload + client signature + args)
	fileData, err := os.ReadFile(*encryptedFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading approved file: %v\n", err)
		os.Exit(1)
	}

	// Verify client signature on arguments and decrypt
	// VerifyAndDecrypt handles all parsing deterministically
	result, err := po.VerifyAndDecrypt(fileData)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error verifying and decrypting: %v\n", err)
		os.Exit(1)
	}

	// Calculate hash of client signature
	signatureHash := sha256.Sum256(result.ClientSignature)
	signatureHashHex := hex.EncodeToString(signatureHash[:])

	// Calculate hash of client public key
	clientPubKeyBytes, err := x509.MarshalPKIXPublicKey(clientPubKey)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error marshaling client public key: %v\n", err)
		os.Exit(1)
	}
	clientPubKeyHash := sha256.Sum256(clientPubKeyBytes)
	clientPubKeyHashHex := hex.EncodeToString(clientPubKeyHash[:])

	// Calculate hash of pentester public key
	pentesterPubKeyBytes, err := x509.MarshalPKIXPublicKey(pentesterPubKey)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error marshaling pentester public key: %v\n", err)
		os.Exit(1)
	}
	pentesterPubKeyHash := sha256.Sum256(pentesterPubKeyBytes)
	pentesterPubKeyHashHex := hex.EncodeToString(pentesterPubKeyHash[:])

	// Calculate hash of principal signature
	principalSigHash := sha256.Sum256(result.PrincipalSignature)
	principalSigHashHex := hex.EncodeToString(principalSigHash[:])

	// Calculate hash of principal public key
	principalPubKeyBytes, err := x509.MarshalPKIXPublicKey(principalPubKey)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error marshaling principal public key: %v\n", err)
		os.Exit(1)
	}
	principalPubKeyHash := sha256.Sum256(principalPubKeyBytes)
	principalPubKeyHashHex := hex.EncodeToString(principalPubKeyHash[:])

	// Calculate encrypted payload hash for logging
	// Extract encrypted payload: skip version(1) + principal_sig_len(4) + principal_sig, then read metadata_len(4) + metadata + encrypted data
	if len(fileData) < 1+4 {
		fmt.Fprintf(os.Stderr, "Error: file too short\n")
		os.Exit(1)
	}
	principalSigLen := int(binary.BigEndian.Uint32(fileData[1:5]))
	if len(fileData) < 1+4+principalSigLen+4 {
		fmt.Fprintf(os.Stderr, "Error: file too short\n")
		os.Exit(1)
	}
	encryptedPayloadStart := 1 + 4 + principalSigLen
	encryptedPayloadEnd := len(fileData) - 4 - 60 - 8 - 4 // Approximate: client_sig_len - min_sig - expiration - args_len
	if encryptedPayloadEnd <= encryptedPayloadStart {
		encryptedPayloadEnd = len(fileData)
	}
	encryptedPayload := fileData[encryptedPayloadStart:encryptedPayloadEnd]
	encryptedPayloadHash := sha256.Sum256(encryptedPayload)
	encryptedPayloadHashHex := hex.EncodeToString(encryptedPayloadHash[:])

	// Log verification details
	fmt.Fprintf(os.Stderr, "[VERIFICATION LOG] %s\n", time.Now().Format(time.RFC3339))
	fmt.Fprintf(os.Stderr, "[VERIFICATION LOG] Encrypted Payload Hash (SHA256): %s\n", encryptedPayloadHashHex)
	fmt.Fprintf(os.Stderr, "[VERIFICATION LOG] Principal Signature Hash (SHA256): %s\n", principalSigHashHex)
	fmt.Fprintf(os.Stderr, "[VERIFICATION LOG] Principal Public Key Hash (SHA256): %s\n", principalPubKeyHashHex)
	fmt.Fprintf(os.Stderr, "[VERIFICATION LOG] Client Signature Hash (SHA256): %s\n", signatureHashHex)
	fmt.Fprintf(os.Stderr, "[VERIFICATION LOG] Client Public Key Hash (SHA256): %s\n", clientPubKeyHashHex)
	fmt.Fprintf(os.Stderr, "[VERIFICATION LOG] Pentester Public Key Hash (SHA256): %s\n", pentesterPubKeyHashHex)

	fmt.Printf("✓ Client signature on arguments verified successfully\n")
	fmt.Printf("✓ Plugin decrypted successfully\n")
	fmt.Printf("\nPlugin details:\n")
	fmt.Printf("  Type: %s\n", result.Payload.Type.String())
	fmt.Printf("  Name: %s\n", result.Payload.Name)
	fmt.Printf("  Data size: %d bytes\n", len(result.Payload.Data))

	if result.Payload.Type.String() == "wasm" {
		fmt.Printf("  Note: WASM plugin ready to execute\n")
	} else {
		fmt.Printf("  Warning: Unknown plugin type\n")
	}
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
