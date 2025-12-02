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
		encryptedFile     = flag.String("file", "", "Path to approved plugin file (with target signature)")
		harnessKeystoreKey = flag.String("harness-keystore-key", "", "Key ID in OS keystore for harness (pentester) private key (required, for decryption)")
		targetPubKeyFile  = flag.String("target-key", "", "Path to target's public key file (required, for verifying argument signature)")
		exploitPubKeyFile = flag.String("exploit-key", "", "Path to exploit owner's public key file (required, for verifying payload signature)")
	)
	flag.Parse()

	if *encryptedFile == "" {
		fmt.Fprintf(os.Stderr, "Error: -file is required\n")
		os.Exit(1)
	}

	if *harnessKeystoreKey == "" {
		fmt.Fprintf(os.Stderr, "Error: -harness-keystore-key is required (harness private key must be stored in OS keystore)\n")
		os.Exit(1)
	}

	if *targetPubKeyFile == "" {
		fmt.Fprintf(os.Stderr, "Error: -target-key is required (target's public key for verifying argument signature)\n")
		os.Exit(1)
	}

	if *exploitPubKeyFile == "" {
		fmt.Fprintf(os.Stderr, "Error: -exploit-key is required (exploit owner's public key for verifying payload signature)\n")
		os.Exit(1)
	}

	// Load target's public key
	targetPubKey, err := loadPublicKey(*targetPubKeyFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading target's public key: %v\n", err)
		os.Exit(1)
	}

	// Load exploit owner's public key (required)
	exploitPubKey, err := loadPublicKey(*exploitPubKeyFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading exploit owner's public key: %v\n", err)
		os.Exit(1)
	}

	// Get harness public key from keystore for logging
	ks, err := keystore.NewKeystore()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error creating keystore: %v\n", err)
		os.Exit(1)
	}
	harnessPubKey, err := ks.GetPublicKey(*harnessKeystoreKey)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error getting harness public key: %v\n", err)
		os.Exit(1)
	}

	// Create PresidentialOrder from keystore (harness private key + target's public key + exploit owner's public key)
	po, err := crypto.NewPresidentialOrderFromKeystoreWithPrincipal(*harnessKeystoreKey, targetPubKey, exploitPubKey)
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

	// Calculate hash of target signature
	targetSigHash := sha256.Sum256(result.ClientSignature)
	targetSigHashHex := hex.EncodeToString(targetSigHash[:])

	// Calculate hash of target public key
	targetPubKeyBytes, err := x509.MarshalPKIXPublicKey(targetPubKey)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error marshaling target public key: %v\n", err)
		os.Exit(1)
	}
	targetPubKeyHash := sha256.Sum256(targetPubKeyBytes)
	targetPubKeyHashHex := hex.EncodeToString(targetPubKeyHash[:])

	// Calculate hash of harness public key
	harnessPubKeyBytes, err := x509.MarshalPKIXPublicKey(harnessPubKey)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error marshaling harness public key: %v\n", err)
		os.Exit(1)
	}
	harnessPubKeyHash := sha256.Sum256(harnessPubKeyBytes)
	harnessPubKeyHashHex := hex.EncodeToString(harnessPubKeyHash[:])

	// Calculate hash of exploit owner signature
	exploitSigHash := sha256.Sum256(result.PrincipalSignature)
	exploitSigHashHex := hex.EncodeToString(exploitSigHash[:])

	// Calculate hash of exploit owner public key
	exploitPubKeyBytes, err := x509.MarshalPKIXPublicKey(exploitPubKey)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error marshaling exploit owner public key: %v\n", err)
		os.Exit(1)
	}
	exploitPubKeyHash := sha256.Sum256(exploitPubKeyBytes)
	exploitPubKeyHashHex := hex.EncodeToString(exploitPubKeyHash[:])

	// Calculate encrypted payload hash for logging
	// Extract encrypted payload: skip header(10) + principal_sig_len(4) + principal_sig, then read metadata_len(4) + metadata + encrypted data
	const headerSize = 4 + 1 + 1 + 4 // magic + version + flags + file_length
	if len(fileData) < headerSize+4 {
		fmt.Fprintf(os.Stderr, "Error: file too short\n")
		os.Exit(1)
	}
	principalSigLen := int(binary.BigEndian.Uint32(fileData[headerSize : headerSize+4]))
	if len(fileData) < headerSize+4+principalSigLen+4 {
		fmt.Fprintf(os.Stderr, "Error: file too short\n")
		os.Exit(1)
	}
	encryptedPayloadStart := headerSize + 4 + principalSigLen
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
	fmt.Fprintf(os.Stderr, "[VERIFICATION LOG] Exploit Owner Signature Hash (SHA256): %s\n", exploitSigHashHex)
	fmt.Fprintf(os.Stderr, "[VERIFICATION LOG] Exploit Owner Public Key Hash (SHA256): %s\n", exploitPubKeyHashHex)
	fmt.Fprintf(os.Stderr, "[VERIFICATION LOG] Target Signature Hash (SHA256): %s\n", targetSigHashHex)
	fmt.Fprintf(os.Stderr, "[VERIFICATION LOG] Target Public Key Hash (SHA256): %s\n", targetPubKeyHashHex)
	fmt.Fprintf(os.Stderr, "[VERIFICATION LOG] Harness Public Key Hash (SHA256): %s\n", harnessPubKeyHashHex)

	fmt.Printf("✓ Target signature on arguments verified successfully\n")
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
