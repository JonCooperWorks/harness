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
		encryptedFile      = flag.String("file", "", "Path to approved plugin file (with target signature)")
		harnessKeystoreKey = flag.String("harness-keystore-key", "", "Key ID in OS keystore for harness (pentester) private key (required, for decryption)")
		targetPubKeyFile   = flag.String("target-key", "", "Path to target's public key file (required, for verifying argument signature)")
		exploitPubKeyFile  = flag.String("exploit-key", "", "Path to exploit owner's public key file (required, for verifying payload signature)")
	)
	flag.Parse()

	if *encryptedFile == "" {
		logger.Error("missing required flag", "flag", "file")
		os.Exit(1)
	}

	if *harnessKeystoreKey == "" {
		logger.Error("missing required flag", "flag", "harness-keystore-key", "message", "harness private key must be stored in OS keystore")
		os.Exit(1)
	}

	if *targetPubKeyFile == "" {
		logger.Error("missing required flag", "flag", "target-key", "message", "target's public key for verifying argument signature")
		os.Exit(1)
	}

	if *exploitPubKeyFile == "" {
		logger.Error("missing required flag", "flag", "exploit-key", "message", "exploit owner's public key for verifying payload signature")
		os.Exit(1)
	}

	// Load target's public key
	targetPubKey, err := loadPublicKey(*targetPubKeyFile)
	if err != nil {
		logger.Error("failed to load target's public key", "error", err, "file", *targetPubKeyFile)
		os.Exit(1)
	}

	// Load exploit owner's public key (required)
	exploitPubKey, err := loadPublicKey(*exploitPubKeyFile)
	if err != nil {
		logger.Error("failed to load exploit owner's public key", "error", err, "file", *exploitPubKeyFile)
		os.Exit(1)
	}

	// Create bound keystore for harness (pentester) key
	// The keystore is bound to the specific key ID for cryptographic operations
	harnessKs, err := keystore.NewKeystoreForKey(keystore.KeyID(*harnessKeystoreKey))
	if err != nil {
		logger.Error("failed to create keystore for harness", "error", err, "key_id", *harnessKeystoreKey)
		os.Exit(1)
	}

	// Get harness public key for logging
	harnessPubKey, err := harnessKs.PublicKey()
	if err != nil {
		logger.Error("failed to get harness public key", "error", err, "key_id", *harnessKeystoreKey)
		os.Exit(1)
	}

	// Create PresidentialOrder from bound keystore (harness private key + target's public key + exploit owner's public key + harness public key)
	po, err := crypto.NewPresidentialOrderFromKeystore(harnessKs, targetPubKey, exploitPubKey, harnessPubKey)
	if err != nil {
		logger.Error("failed to create PresidentialOrder from keystore", "error", err)
		os.Exit(1)
	}

	// Load approved file (contains encrypted payload + client signature + args)
	fileData, err := os.ReadFile(*encryptedFile)
	if err != nil {
		logger.Error("failed to read approved file", "error", err, "file", *encryptedFile)
		os.Exit(1)
	}


	// Verify and decrypt with hash calculation
	verifyResult, err := crypto.VerifyAndDecryptWithHashes(po, fileData, harnessPubKey, targetPubKey, exploitPubKey)
	if err != nil {
		logger.Error("failed to verify and decrypt", "error", err)
		os.Exit(1)
	}

	// Log verification details using hashes from result
	logger.Info("verification log",
		"timestamp", time.Now().Format(time.RFC3339),
		"encrypted_payload_hash_sha256", verifyResult.Hashes.EncryptedPayloadHash,
		"exploit_owner_signature_hash_sha256", verifyResult.Hashes.ExploitOwnerSignatureHash,
		"exploit_owner_public_key_hash_sha256", verifyResult.Hashes.ExploitOwnerPublicKeyHash,
		"target_signature_hash_sha256", verifyResult.Hashes.TargetSignatureHash,
		"target_public_key_hash_sha256", verifyResult.Hashes.TargetPublicKeyHash,
		"harness_public_key_hash_sha256", verifyResult.Hashes.HarnessPublicKeyHash,
	)

	result := verifyResult.DecryptedResult

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
