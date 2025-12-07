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
	"path/filepath"
	"strings"
	"time"

	"github.com/joncooperworks/harness/crypto"
	"github.com/joncooperworks/harness/crypto/keystore"
	"github.com/joncooperworks/harness/plugin"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stderr, nil))

	var (
		pluginFile         = flag.String("plugin", "", "Path to plugin file to store")
		pluginType         = flag.String("type", "wasm", "Plugin type: wasm, python, etc.")
		harnessPubKeyPath  = flag.String("harness-key", "", "Path to harness (pentester) public key file (required, for encrypting exploit)")
		exploitKeystoreKey = flag.String("exploit-keystore-key", "", "Key ID in OS keystore for exploit owner's private key (required, for signing and self-encryption)")
		outputPath         = flag.String("output", "", "Path to save stored plugin (defaults to input filename with .stored extension)")
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

	if *exploitKeystoreKey == "" {
		logger.Error("missing required flag", "flag", "exploit-keystore-key", "message", "exploit owner's private key for signing and self-encryption")
		os.Exit(1)
	}

	// Load harness public key (for encryption - this is the harness key)
	// The exploit is encrypted with the harness's public key so they can decrypt and execute
	harnessPubKey, err := loadPublicKey(*harnessPubKeyPath)
	if err != nil {
		logger.Error("failed to load harness public key", "error", err, "file", *harnessPubKeyPath)
		os.Exit(1)
	}

	// Create bound keystore for exploit owner
	// The keystore is bound to the specific key ID for cryptographic operations
	exploitKs, err := keystore.NewKeystoreForKey(keystore.KeyID(*exploitKeystoreKey))
	if err != nil {
		logger.Error("failed to create keystore for exploit owner", "error", err, "key_id", *exploitKeystoreKey)
		os.Exit(1)
	}

	// Get exploit owner's public key (used as the "target" key for self-encryption)
	exploitPubKey, err := exploitKs.PublicKey()
	if err != nil {
		logger.Error("failed to get exploit owner public key", "error", err, "key_id", *exploitKeystoreKey)
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

	// Encrypt plugin using library function
	// Use exploit owner's public key as the "target" key for self-encryption
	encryptReq := &crypto.EncryptPluginRequest{
		PluginData:        bytes.NewReader(pluginData),
		PluginType:        *pluginType,
		PluginName:        pluginName,
		HarnessPubKey:     harnessPubKey,
		TargetPubKey:      exploitPubKey, // Self-encryption: encrypt to exploit owner's key
		PrincipalKeystore: exploitKs,
	}

	result, err := crypto.EncryptPlugin(encryptReq)
	if err != nil {
		logger.Error("failed to store plugin", "error", err)
		os.Exit(1)
	}

	// Calculate hash of exploit owner signature for logging
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

	// Log storage details
	logger.Info("storage log",
		"timestamp", time.Now().Format(time.RFC3339),
		"exploit_owner_signature_hash_sha256", exploitSigHashHex,
		"exploit_owner_public_key_hash_sha256", exploitPubKeyHashHex,
		"harness_public_key_hash_sha256", harnessPubKeyHashHex,
	)

	// Determine output path
	output := *outputPath
	if output == "" {
		// Default to input filename with .stored extension
		base := filepath.Base(*pluginFile)
		ext := filepath.Ext(base)
		if ext != "" {
			output = strings.TrimSuffix(base, ext) + ext + ".stored"
		} else {
			output = base + ".stored"
		}
	}

	// Write to file
	if err := os.WriteFile(output, result.EncryptedData, 0644); err != nil {
		logger.Error("failed to write stored file", "error", err, "path", output)
		os.Exit(1)
	}

	fmt.Printf("Plugin stored successfully:\n")
	fmt.Printf("  Input: %s\n", *pluginFile)
	fmt.Printf("  Output: %s\n", output)
	fmt.Printf("  Type: %s\n", *pluginType)
	fmt.Printf("  Name: %s\n", result.PluginName)
	fmt.Printf("\nThe plugin is encrypted to your key. You can decrypt it with your exploit-keystore-key.\n")
	fmt.Printf("To encrypt for a target, use: ./bin/encrypt -plugin %s ...\n", output)
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

