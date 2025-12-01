package main

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"os"

	"github.com/joncooperworks/harness/crypto"
)

func main() {
	var (
		encryptedFile      = flag.String("file", "", "Path to encrypted plugin file")
		privateKeyFile     = flag.String("key", "", "Path to private key file (optional if using keystore)")
		keystoreKeyID      = flag.String("keystore-key", "", "Key ID in OS keystore (optional if using key file)")
		presidentPubKeyFile = flag.String("president-key", "", "Path to president's public key file")
	)
	flag.Parse()

	if *encryptedFile == "" {
		fmt.Fprintf(os.Stderr, "Error: -file is required\n")
		os.Exit(1)
	}

	if *presidentPubKeyFile == "" {
		fmt.Fprintf(os.Stderr, "Error: -president-key is required\n")
		os.Exit(1)
	}

	if *privateKeyFile == "" && *keystoreKeyID == "" {
		fmt.Fprintf(os.Stderr, "Error: -keystore-key is required (private keys should be stored in OS keystore, not files)\n")
		fmt.Fprintf(os.Stderr, "  Use -key only for migration purposes\n")
		os.Exit(1)
	}

	// Load president's public key
	presidentPubKey, err := loadPublicKey(*presidentPubKeyFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading president's public key: %v\n", err)
		os.Exit(1)
	}

	// Create PresidentialOrder
	var po crypto.PresidentialOrder
	if *keystoreKeyID != "" {
		po, err = crypto.NewPresidentialOrderFromKeystore(*keystoreKeyID, presidentPubKey)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error creating PresidentialOrder from keystore: %v\n", err)
			os.Exit(1)
		}
	} else {
		po, err = crypto.NewPresidentialOrderFromFile(*privateKeyFile, presidentPubKey)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error creating PresidentialOrder: %v\n", err)
			os.Exit(1)
		}
	}

	// Load encrypted file
	encryptedData, err := os.ReadFile(*encryptedFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading encrypted file: %v\n", err)
		os.Exit(1)
	}

	// Verify and decrypt
	payload, err := po.VerifyAndDecrypt(encryptedData)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error verifying and decrypting: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("✓ Signature verified successfully\n")
	fmt.Printf("✓ Plugin decrypted successfully\n")
	fmt.Printf("\nPlugin details:\n")
	fmt.Printf("  Type: %v\n", payload.Type)
	fmt.Printf("  Name: %s\n", payload.Name)
	fmt.Printf("  Data size: %d bytes\n", len(payload.Data))
	
	if payload.Type == crypto.WASM {
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

