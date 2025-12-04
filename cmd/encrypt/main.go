package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"time"

	"github.com/joncooperworks/harness/crypto"
	"github.com/joncooperworks/harness/crypto/keystore"
	"github.com/joncooperworks/harness/plugin"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stderr, nil))

	var (
		pluginFile         = flag.String("plugin", "", "Path to plugin file to encrypt")
		pluginType         = flag.String("type", "wasm", "Plugin type: wasm")
		harnessPubKeyPath  = flag.String("harness-key", "", "Path to harness (pentester) public key file (required, for encrypting exploit)")
		targetPubKeyPath   = flag.String("target-key", "", "Path to target public key file (required, for onion encryption of envelope)")
		exploitKeystoreKey = flag.String("exploit-keystore-key", "", "Key ID in OS keystore for exploit owner's private key (required, for signing encrypted payload)")
		outputPath         = flag.String("output", "plugin.encrypted", "Path to save encrypted plugin")
	)
	flag.Parse()

	if *pluginFile == "" {
		logger.Error("missing required flag", "flag", "plugin")
		os.Exit(1)
	}

	if *harnessPubKeyPath == "" {
		logger.Error("missing required flag", "flag", "harness-key", "message", "harness public key for encrypting exploit")
		os.Exit(1)
	}

	if *targetPubKeyPath == "" {
		logger.Error("missing required flag", "flag", "target-key", "message", "target public key for onion encryption of envelope")
		os.Exit(1)
	}

	if *exploitKeystoreKey == "" {
		logger.Error("missing required flag", "flag", "exploit-keystore-key", "message", "exploit owner's private key for signing encrypted payload")
		os.Exit(1)
	}

	// Load pentester's public key (for encryption - this is the harness key)
	// The exploit is encrypted with the pentester's public key so they can decrypt and execute
	harnessPubKey, err := loadPublicKey(*harnessPubKeyPath)
	if err != nil {
		logger.Error("failed to load pentester's public key", "error", err, "file", *harnessPubKeyPath)
		os.Exit(1)
	}

	// Load target's public key (for onion encryption)
	// The inner envelope is encrypted to the target's public key so only they can decrypt it
	targetPubKey, err := loadPublicKey(*targetPubKeyPath)
	if err != nil {
		logger.Error("failed to load target's public key", "error", err, "file", *targetPubKeyPath)
		os.Exit(1)
	}

	// Load keystore for exploit owner signature
	ks, err := keystore.NewKeystore()
	if err != nil {
		logger.Error("failed to create keystore", "error", err)
		os.Exit(1)
	}

	// Read plugin file to extract name
	pluginData, err := os.ReadFile(*pluginFile)
	if err != nil {
		logger.Error("failed to read plugin file", "error", err, "file", *pluginFile)
		os.Exit(1)
	}

	// Load plugin to get its name
	tempPayload := &crypto.Payload{
		Type: crypto.PluginTypeString(*pluginType),
		Name: "", // Temporary - plugin will provide its own name
		Data: pluginData,
	}
	plg, err := plugin.LoadPlugin(tempPayload)
	if err != nil {
		logger.Error("failed to load plugin", "error", err)
		os.Exit(1)
	}
	pluginName := plg.Name()
	// Note: Plugin interface doesn't have Close(), but implementations may have cleanup
	// For WASM plugins, resources are managed by the plugin loader

	// Get exploit owner public key for logging
	exploitPubKey, err := ks.PublicEd25519(keystore.KeyID(*exploitKeystoreKey))
	if err != nil {
		logger.Error("failed to get exploit owner public key", "error", err, "key_id", *exploitKeystoreKey)
		os.Exit(1)
	}

	// Encrypt plugin using library function
	encryptReq := &crypto.EncryptPluginRequest{
		PluginData:        bytes.NewReader(pluginData),
		PluginType:        *pluginType,
		PluginName:        pluginName,
		HarnessPubKey:     harnessPubKey,
		TargetPubKey:      targetPubKey,
		PrincipalKeystore: ks,
		PrincipalKeyID:    keystore.KeyID(*exploitKeystoreKey),
	}

	result, err := crypto.EncryptPlugin(encryptReq)
	if err != nil {
		logger.Error("failed to encrypt plugin", "error", err)
		os.Exit(1)
	}

	// Calculate hash of exploit owner signature for logging
	// The signature is extracted from the inner envelope before encryption
	if len(result.PrincipalSignature) == 0 {
		logger.Error("principal signature not available for logging")
		os.Exit(1)
	}
	exploitSigHash := sha256.Sum256(result.PrincipalSignature)
	exploitSigHashHex := hex.EncodeToString(exploitSigHash[:])

	// Calculate hash of exploit owner public key for logging
	exploitPubKeyBytes, err := x509.MarshalPKIXPublicKey(exploitPubKey)
	if err != nil {
		logger.Error("failed to marshal exploit owner public key", "error", err)
		os.Exit(1)
	}
	exploitPubKeyHash := sha256.Sum256(exploitPubKeyBytes)
	exploitPubKeyHashHex := hex.EncodeToString(exploitPubKeyHash[:])

	// Calculate hash of harness public key for logging
	harnessPubKeyBytes, err := x509.MarshalPKIXPublicKey(harnessPubKey)
	if err != nil {
		logger.Error("failed to marshal harness public key", "error", err)
		os.Exit(1)
	}
	harnessPubKeyHash := sha256.Sum256(harnessPubKeyBytes)
	harnessPubKeyHashHex := hex.EncodeToString(harnessPubKeyHash[:])

	// Log encryption details
	logger.Info("encryption log",
		"timestamp", time.Now().Format(time.RFC3339),
		"exploit_owner_signature_hash_sha256", exploitSigHashHex,
		"exploit_owner_public_key_hash_sha256", exploitPubKeyHashHex,
		"harness_public_key_hash_sha256", harnessPubKeyHashHex,
	)

	output := result.EncryptedData

	// Write to file
	if err := os.WriteFile(*outputPath, output, 0644); err != nil {
		logger.Error("failed to write encrypted file", "error", err, "path", *outputPath)
		os.Exit(1)
	}

	fmt.Printf("Plugin encrypted successfully:\n")
	fmt.Printf("  Input: %s\n", *pluginFile)
	fmt.Printf("  Output: %s\n", *outputPath)
	fmt.Printf("  Type: %s\n", *pluginType)
	fmt.Printf("  Name: %s\n", result.PluginName)
	fmt.Printf("\nNext step: Sign the encrypted file with ./bin/sign\n")
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
