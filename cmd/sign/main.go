package main

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"time"

	"github.com/joncooperworks/harness/crypto"
	"github.com/joncooperworks/harness/crypto/keystore"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stderr, nil))

	var (
		encryptedFile     = flag.String("file", "", "Path to encrypted plugin file (from encrypt command)")
		targetKeystoreKey = flag.String("target-keystore-key", "", "Key ID in OS keystore for target's private key (required, for signing execution arguments)")
		exploitPubKeyFile = flag.String("exploit-key", "", "Path to exploit owner's public key file (required, for verifying payload signature)")
		harnessPubKeyFile = flag.String("harness-key", "", "Path to harness (pentester) public key file (required, for encrypting arguments)")
		argsJSON          = flag.String("args", "", "JSON execution arguments to sign (required)")
		expirationDur     = flag.Duration("expiration", 72*time.Hour, "Expiration duration from now (default: 72h = 3 days)")
		outputPath        = flag.String("output", "", "Path to save approved plugin (defaults to input file with .approved suffix)")
	)
	flag.Parse()

	if *encryptedFile == "" {
		logger.Error("missing required flag", "flag", "file")
		os.Exit(1)
	}

	if *targetKeystoreKey == "" {
		logger.Error("missing required flag", "flag", "target-keystore-key", "message", "target's private key for signing execution arguments")
		os.Exit(1)
	}

	if *exploitPubKeyFile == "" {
		logger.Error("missing required flag", "flag", "exploit-key", "message", "exploit owner's public key for verifying payload signature")
		os.Exit(1)
	}

	if *harnessPubKeyFile == "" {
		logger.Error("missing required flag", "flag", "harness-key", "message", "harness public key for encrypting arguments")
		os.Exit(1)
	}

	if *argsJSON == "" {
		logger.Error("missing required flag", "flag", "args", "message", "target must sign execution arguments")
		os.Exit(1)
	}

	if *outputPath == "" {
		*outputPath = *encryptedFile + ".approved"
	}

	// Create bound keystore for target's key (keys never leave secure storage)
	// The keystore is bound to the specific key ID for cryptographic operations
	targetKs, err := keystore.NewKeystoreForKey(keystore.KeyID(*targetKeystoreKey))
	if err != nil {
		logger.Error("failed to create keystore for target", "error", err, "key_id", *targetKeystoreKey)
		os.Exit(1)
	}

	// Load exploit owner public key for verifying payload signature
	exploitPubKey, err := loadPublicKey(*exploitPubKeyFile)
	if err != nil {
		logger.Error("failed to load exploit owner public key", "error", err, "file", *exploitPubKeyFile)
		os.Exit(1)
	}

	// Load harness public key for encrypting arguments
	harnessPubKey, err := loadPublicKey(*harnessPubKeyFile)
	if err != nil {
		logger.Error("failed to load harness public key", "error", err, "file", *harnessPubKeyFile)
		os.Exit(1)
	}

	// Open encrypted file
	encryptedFileHandle, err := os.Open(*encryptedFile)
	if err != nil {
		logger.Error("failed to open encrypted file", "error", err, "file", *encryptedFile)
		os.Exit(1)
	}
	defer encryptedFileHandle.Close()

	// Calculate expiration timestamp
	expirationTime := time.Now().Add(*expirationDur)

	// Sign encrypted plugin using library function
	signReq := &crypto.SignEncryptedPluginRequest{
		EncryptedData:   encryptedFileHandle,
		ArgsJSON:        []byte(*argsJSON),
		ClientKeystore:  targetKs,
		PrincipalPubKey: exploitPubKey,
		HarnessPubKey:   harnessPubKey,
		PentesterPubKey: harnessPubKey,
		Expiration:      &expirationTime,
	}

	result, err := crypto.SignEncryptedPlugin(signReq)
	if err != nil {
		logger.Error("failed to sign encrypted plugin", "error", err)
		os.Exit(1)
	}

	// Log signing details using hashes from result
	logger.Info("signing log",
		"timestamp", time.Now().Format(time.RFC3339),
		"encrypted_payload_hash_sha256", result.Hashes.EncryptedPayloadHash,
		"target_public_key_hash_sha256", result.Hashes.TargetPublicKeyHash,
	)

	output := result.ApprovedData

	// Write to file
	if err := os.WriteFile(*outputPath, output, 0644); err != nil {
		logger.Error("failed to write approved file", "error", err, "path", *outputPath)
		os.Exit(1)
	}

	fmt.Printf("Arguments signed successfully:\n")
	fmt.Printf("  Input: %s\n", *encryptedFile)
	fmt.Printf("  Output: %s\n", *outputPath)
	fmt.Printf("  Expiration: %s (%s)\n", result.ExpirationTime.Format(time.RFC3339), result.ExpirationTime.Format(time.RFC1123))
}

// loadPublicKey loads an Ed25519 public key from a file
func loadPublicKey(path string) (ed25519.PublicKey, error) {
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

	ed25519PubKey, ok := pubKey.(ed25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf("public key is not Ed25519")
	}

	return ed25519PubKey, nil
}
