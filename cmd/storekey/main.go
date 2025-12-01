package main

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"os"

	"github.com/joncooperworks/harness/crypto/keystore"
)

func main() {
	var (
		privateKeyPath = flag.String("key", "", "Path to private key PEM file to import")
		keystoreKeyID  = flag.String("keystore-key", "", "Key ID to store private key in OS keystore (required)")
	)
	flag.Parse()

	if *privateKeyPath == "" {
		fmt.Fprintf(os.Stderr, "Error: -key is required\n")
		os.Exit(1)
	}

	if *keystoreKeyID == "" {
		fmt.Fprintf(os.Stderr, "Error: -keystore-key is required\n")
		os.Exit(1)
	}

	// Load private key from file
	privateKey, err := loadPrivateKey(*privateKeyPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading private key: %v\n", err)
		os.Exit(1)
	}

	// Store private key in keystore
	ks, err := keystore.NewKeystore()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error creating keystore: %v\n", err)
		os.Exit(1)
	}

	if err := ks.SetPrivateKey(*keystoreKeyID, privateKey); err != nil {
		fmt.Fprintf(os.Stderr, "Error storing key in keystore: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Private key imported successfully:\n")
	fmt.Printf("  Source: %s\n", *privateKeyPath)
	fmt.Printf("  Keystore ID: %s\n", *keystoreKeyID)
	fmt.Printf("  Note: You can now delete the PEM file for security\n")
}

// loadPrivateKey loads an ECDSA private key from a file
func loadPrivateKey(path string) (*ecdsa.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read private key file: %w", err)
	}

	// Try PEM format first
	block, _ := pem.Decode(data)
	if block != nil {
		data = block.Bytes
	}

	// Try PKCS8 format
	key, err := x509.ParsePKCS8PrivateKey(data)
	if err == nil {
		if ecdsaKey, ok := key.(*ecdsa.PrivateKey); ok {
			return ecdsaKey, nil
		}
		return nil, fmt.Errorf("key is not ECDSA")
	}

	// Try EC private key format
	ecKey, err := x509.ParseECPrivateKey(data)
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key: %w", err)
	}

	return ecKey, nil
}

