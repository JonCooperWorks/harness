package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"os"

	"github.com/joncooperworks/harness/crypto/keystore"
)

func main() {
	var (
		publicKeyPath = flag.String("public", "public.pem", "Path to save public key")
		keystoreKeyID = flag.String("keystore-key", "", "Key ID to store private key in OS keystore (required)")
		importKeyPath = flag.String("import", "", "Path to existing private key PEM file to import (optional)")
	)
	flag.Parse()

	if *keystoreKeyID == "" {
		fmt.Fprintf(os.Stderr, "Error: -keystore-key is required\n")
		os.Exit(1)
	}

	var privateKey *ecdsa.PrivateKey
	var err error

	if *importKeyPath != "" {
		// Import existing private key from file
		privateKey, err = loadPrivateKey(*importKeyPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error loading private key: %v\n", err)
			os.Exit(1)
		}
	} else {
		// Generate new ECDSA key pair
		privateKey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error generating key: %v\n", err)
			os.Exit(1)
		}
	}

	// Store private key directly in keystore (never write to disk)
	ks, err := keystore.NewKeystore()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error creating keystore: %v\n", err)
		os.Exit(1)
	}

	if err := ks.SetPrivateKey(*keystoreKeyID, privateKey); err != nil {
		fmt.Fprintf(os.Stderr, "Error storing key in keystore: %v\n", err)
		os.Exit(1)
	}

	// Encode and write public key only
	publicKeyBytes, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error marshaling public key: %v\n", err)
		os.Exit(1)
	}

	publicKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicKeyBytes,
	})

	if err := os.WriteFile(*publicKeyPath, publicKeyPEM, 0644); err != nil {
		fmt.Fprintf(os.Stderr, "Error writing public key: %v\n", err)
		os.Exit(1)
	}

	if *importKeyPath != "" {
		fmt.Printf("Private key imported successfully:\n")
		fmt.Printf("  Source: %s\n", *importKeyPath)
		fmt.Printf("  Private key stored in keystore with ID: %s\n", *keystoreKeyID)
		fmt.Printf("  Public key written to: %s\n", *publicKeyPath)
		fmt.Printf("  Note: You can now delete the PEM file for security\n")
	} else {
		fmt.Printf("Key pair generated successfully:\n")
		fmt.Printf("  Private key stored in keystore with ID: %s\n", *keystoreKeyID)
		fmt.Printf("  Public key written to: %s\n", *publicKeyPath)
	}
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
