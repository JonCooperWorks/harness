package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
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

	// Create PresidentialOrder from bound keystore (harness private key + target's public key + exploit owner's public key)
	po, err := crypto.NewPresidentialOrderFromKeystore(harnessKs, targetPubKey, exploitPubKey)
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

	// Verify client signature on arguments and decrypt
	// VerifyAndDecrypt handles all parsing deterministically
	result, err := po.VerifyAndDecrypt(fileData)
	if err != nil {
		logger.Error("failed to verify and decrypt", "error", err)
		os.Exit(1)
	}

	// Calculate hash of target signature
	targetSigHash := sha256.Sum256(result.ClientSignature)
	targetSigHashHex := hex.EncodeToString(targetSigHash[:])

	// Calculate hash of target public key
	targetPubKeyBytes, err := x509.MarshalPKIXPublicKey(targetPubKey)
	if err != nil {
		logger.Error("failed to marshal target public key", "error", err)
		os.Exit(1)
	}
	targetPubKeyHash := sha256.Sum256(targetPubKeyBytes)
	targetPubKeyHashHex := hex.EncodeToString(targetPubKeyHash[:])

	// Calculate hash of harness public key
	harnessPubKeyBytes, err := x509.MarshalPKIXPublicKey(harnessPubKey)
	if err != nil {
		logger.Error("failed to marshal harness public key", "error", err)
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
		logger.Error("failed to marshal exploit owner public key", "error", err)
		os.Exit(1)
	}
	exploitPubKeyHash := sha256.Sum256(exploitPubKeyBytes)
	exploitPubKeyHashHex := hex.EncodeToString(exploitPubKeyHash[:])

	// Calculate encrypted payload hash for logging
	// Extract encrypted payload: skip header(10) + principal_sig_len(4) + principal_sig, then read metadata_len(4) + metadata + encrypted data
	const headerSize = 4 + 1 + 1 + 4 // magic + version + flags + file_length
	if len(fileData) < headerSize+4 {
		logger.Error("file too short", "size", len(fileData), "min_size", headerSize+4)
		os.Exit(1)
	}
	principalSigLen := int(binary.BigEndian.Uint32(fileData[headerSize : headerSize+4]))
	if len(fileData) < headerSize+4+principalSigLen+4 {
		logger.Error("file too short", "size", len(fileData), "min_size", headerSize+4+principalSigLen+4)
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
	logger.Info("verification log",
		"timestamp", time.Now().Format(time.RFC3339),
		"encrypted_payload_hash_sha256", encryptedPayloadHashHex,
		"exploit_owner_signature_hash_sha256", exploitSigHashHex,
		"exploit_owner_public_key_hash_sha256", exploitPubKeyHashHex,
		"target_signature_hash_sha256", targetSigHashHex,
		"target_public_key_hash_sha256", targetPubKeyHashHex,
		"harness_public_key_hash_sha256", harnessPubKeyHashHex,
	)

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
