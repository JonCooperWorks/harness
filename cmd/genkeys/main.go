package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"log/slog"
	"os"

	"github.com/joncooperworks/harness/crypto/keystore"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stderr, nil))

	var (
		publicKeyPath = flag.String("public", "public.pem", "Path to save public key")
		keystoreKeyID = flag.String("keystore-key", "", "Key ID to store private key in OS keystore (required)")
		importKeyPath = flag.String("import", "", "Path to existing private key PEM file to import (optional)")
	)
	flag.Parse()

	if *keystoreKeyID == "" {
		logger.Error("missing required flag", "flag", "keystore-key")
		os.Exit(1)
	}

	var privateKey ed25519.PrivateKey
	var err error

	if *importKeyPath != "" {
		// Import existing private key from file
		privateKey, err = loadPrivateKey(*importKeyPath)
		if err != nil {
			logger.Error("failed to load private key", "error", err, "file", *importKeyPath)
			os.Exit(1)
		}
	} else {
		// Generate new Ed25519 key pair
		_, privateKey, err = ed25519.GenerateKey(rand.Reader)
		if err != nil {
			logger.Error("failed to generate key", "error", err)
			os.Exit(1)
		}
	}

	// Store private key directly in keystore (never write to disk)
	ks, err := keystore.NewKeystore()
	if err != nil {
		logger.Error("failed to create keystore", "error", err)
		os.Exit(1)
	}

	if err := ks.SetPrivateKey(keystore.KeyID(*keystoreKeyID), privateKey); err != nil {
		logger.Error("failed to store key in keystore", "error", err, "key_id", *keystoreKeyID)
		os.Exit(1)
	}

	// Encode and write public key only
	publicKey := privateKey.Public().(ed25519.PublicKey)
	publicKeyBytes, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		logger.Error("failed to marshal public key", "error", err)
		os.Exit(1)
	}

	publicKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicKeyBytes,
	})

	if err := os.WriteFile(*publicKeyPath, publicKeyPEM, 0644); err != nil {
		logger.Error("failed to write public key", "error", err, "path", *publicKeyPath)
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

// loadPrivateKey loads an Ed25519 private key from a file
func loadPrivateKey(path string) (ed25519.PrivateKey, error) {
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
		if ed25519Key, ok := key.(ed25519.PrivateKey); ok {
			return ed25519Key, nil
		}
		return nil, fmt.Errorf("key is not Ed25519")
	}

	// Try raw Ed25519 private key (64 bytes)
	if len(data) == ed25519.PrivateKeySize {
		return ed25519.PrivateKey(data), nil
	}

	return nil, fmt.Errorf("failed to parse private key: unsupported format")
}
