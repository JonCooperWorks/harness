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
	)
	flag.Parse()

	if *keystoreKeyID == "" {
		fmt.Fprintf(os.Stderr, "Error: -keystore-key is required\n")
		os.Exit(1)
	}

	// Generate ECDSA key pair
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error generating key: %v\n", err)
		os.Exit(1)
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

	fmt.Printf("Key pair generated successfully:\n")
	fmt.Printf("  Private key stored in keystore with ID: %s\n", *keystoreKeyID)
	fmt.Printf("  Public key written to: %s\n", *publicKeyPath)
}


