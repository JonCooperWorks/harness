package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
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

	// Load keystore (keys never leave secure storage)
	ks, err := keystore.NewKeystore()
	if err != nil {
		logger.Error("failed to create keystore", "error", err)
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
		ClientKeystore:  ks,
		ClientKeyID:     *targetKeystoreKey,
		PrincipalPubKey: exploitPubKey,
		PentesterPubKey: harnessPubKey,
		Expiration:      &expirationTime,
	}

	result, err := crypto.SignEncryptedPlugin(signReq)
	if err != nil {
		logger.Error("failed to sign encrypted plugin", "error", err)
		os.Exit(1)
	}

	// Extract encrypted payload hash for logging
	// Format: [magic:4][version:1][flags:1][file_length:4][principal_sig_len:4][principal_sig][metadata_length:4][metadata][encrypted_symmetric_key][encrypted_plugin_data][client_sig_len:4][client_sig][expiration:8][args_len:4][encrypted_args]
	const headerSize = 4 + 1 + 1 + 4 // magic + version + flags + file_length
	if len(result.ApprovedData) < headerSize+4 {
		logger.Error("approved data too short", "size", len(result.ApprovedData), "min_size", headerSize+4)
		os.Exit(1)
	}
	principalSigLen := int(binary.BigEndian.Uint32(result.ApprovedData[headerSize : headerSize+4]))
	if len(result.ApprovedData) < headerSize+4+principalSigLen+4 {
		logger.Error("approved data too short", "size", len(result.ApprovedData), "min_size", headerSize+4+principalSigLen+4)
		os.Exit(1)
	}
	encryptedPayloadStart := headerSize + 4 + principalSigLen
	// Find end of encrypted payload (before client signature)
	// We need to read metadata to find the exact end
	metadataLen := int(binary.BigEndian.Uint32(result.ApprovedData[encryptedPayloadStart : encryptedPayloadStart+4]))
	if len(result.ApprovedData) < encryptedPayloadStart+4+metadataLen {
		logger.Error("approved data too short for metadata", "size", len(result.ApprovedData), "min_size", encryptedPayloadStart+4+metadataLen)
		os.Exit(1)
	}
	metadataStart := encryptedPayloadStart + 4
	metadataEnd := metadataStart + metadataLen
	var metadataStruct struct {
		SymmetricKeyLen int `json:"symmetric_key_len"`
		PluginDataLen   int `json:"plugin_data_len"`
	}
	if err := json.Unmarshal(result.ApprovedData[metadataStart:metadataEnd], &metadataStruct); err != nil {
		logger.Error("failed to parse metadata", "error", err)
		os.Exit(1)
	}
	encryptedPayloadEnd := metadataEnd + metadataStruct.SymmetricKeyLen + metadataStruct.PluginDataLen
	encryptedPayload := result.ApprovedData[encryptedPayloadStart:encryptedPayloadEnd]
	encryptedPayloadHash := sha256.Sum256(encryptedPayload)
	encryptedPayloadHashHex := hex.EncodeToString(encryptedPayloadHash[:])

	// Get target public key for logging
	targetPubKey, err := ks.GetPublicKey(*targetKeystoreKey)
	if err != nil {
		logger.Error("failed to get target public key", "error", err, "key_id", *targetKeystoreKey)
		os.Exit(1)
	}
	targetPubKeyBytes, err := x509.MarshalPKIXPublicKey(targetPubKey)
	if err != nil {
		logger.Error("failed to marshal target public key", "error", err)
		os.Exit(1)
	}
	targetPubKeyHash := sha256.Sum256(targetPubKeyBytes)
	targetPubKeyHashHex := hex.EncodeToString(targetPubKeyHash[:])

	// Log signing details
	logger.Info("signing log",
		"timestamp", time.Now().Format(time.RFC3339),
		"encrypted_payload_hash_sha256", encryptedPayloadHashHex,
		"target_public_key_hash_sha256", targetPubKeyHashHex,
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
