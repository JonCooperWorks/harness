package main

import (
	"bytes"
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
	"github.com/joncooperworks/harness/crypto/hceepcrypto"
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

	// Create bound keystore for exploit owner signature
	// The keystore is bound to the specific key ID for cryptographic operations
	exploitKs, err := keystore.NewKeystoreForKey(keystore.KeyID(*exploitKeystoreKey))
	if err != nil {
		logger.Error("failed to create keystore for exploit owner", "error", err, "key_id", *exploitKeystoreKey)
		os.Exit(1)
	}

	// Read plugin file
	fileData, err := os.ReadFile(*pluginFile)
	if err != nil {
		logger.Error("failed to read plugin file", "error", err, "file", *pluginFile)
		os.Exit(1)
	}

	// Try to detect if this is a stored file by attempting to decrypt with exploit owner keystore
	var pluginData []byte
	var pluginName string
	var result *crypto.EncryptPluginResult

	enc := hceepcrypto.NewEnvelopeCipher(exploitKs)
	innerEnvelope, decryptErr := enc.DecryptFromPeer(hceepcrypto.ContextEnvelope, fileData)

	if decryptErr == nil {
		// Successfully decrypted - this is a stored file
		// Re-encrypt the inner envelope to the target's public key
		targetPubX, err := keystore.Ed25519ToX25519PublicKey(targetPubKey)
		if err != nil {
			logger.Error("failed to convert target public key to X25519", "error", err)
			os.Exit(1)
		}
		var targetPubX32 [32]byte
		copy(targetPubX32[:], targetPubX)

		// Re-encrypt inner envelope to target
		encryptedEnvelope, err := enc.EncryptToPeer(targetPubX32, hceepcrypto.ContextEnvelope, innerEnvelope)
		if err != nil {
			logger.Error("failed to re-encrypt envelope to target", "error", err)
			os.Exit(1)
		}

		// Extract principal signature from inner envelope
		// Format: [magic:4][version:1][flags:1][file_length:4][principal_sig_len:4][principal_sig]...
		const headerSize = 4 + 1 + 1 + 4 // magic + version + flags + file_length
		if len(innerEnvelope) < headerSize+4 {
			logger.Error("inner envelope too short")
			os.Exit(1)
		}

		// Extract principal signature
		principalSigLen := int(binary.BigEndian.Uint32(innerEnvelope[headerSize : headerSize+4]))
		if len(innerEnvelope) < headerSize+4+principalSigLen {
			logger.Error("inner envelope too short for principal signature")
			os.Exit(1)
		}
		principalSignature := make([]byte, principalSigLen)
		copy(principalSignature, innerEnvelope[headerSize+4:headerSize+4+principalSigLen])

		// We can't extract the plugin name without decrypting the payload (which requires harness private key)
		// So we'll use a placeholder - the actual name will be available after target signs
		pluginName = "stored-plugin"

		// Get principal public key for hash calculation
		principalPubKey, err := exploitKs.PublicKey()
		if err != nil {
			logger.Error("failed to get principal public key", "error", err)
			os.Exit(1)
		}

		// Calculate hashes for stored file re-encryption
		exploitSigHash := sha256.Sum256(principalSignature)
		exploitSigHashHex := hex.EncodeToString(exploitSigHash[:])

		exploitPubKeyBytes, err := x509.MarshalPKIXPublicKey(principalPubKey)
		if err != nil {
			logger.Error("failed to marshal exploit owner public key", "error", err)
			os.Exit(1)
		}
		exploitPubKeyHash := sha256.Sum256(exploitPubKeyBytes)
		exploitPubKeyHashHex := hex.EncodeToString(exploitPubKeyHash[:])

		harnessPubKeyBytes, err := x509.MarshalPKIXPublicKey(harnessPubKey)
		if err != nil {
			logger.Error("failed to marshal harness public key", "error", err)
			os.Exit(1)
		}
		harnessPubKeyHash := sha256.Sum256(harnessPubKeyBytes)
		harnessPubKeyHashHex := hex.EncodeToString(harnessPubKeyHash[:])

		result = &crypto.EncryptPluginResult{
			EncryptedData:      encryptedEnvelope,
			PluginName:         pluginName,
			PrincipalSignature: principalSignature,
			Hashes: crypto.EncryptHashes{
				ExploitOwnerSignatureHash: exploitSigHashHex,
				ExploitOwnerPublicKeyHash: exploitPubKeyHashHex,
				HarnessPublicKeyHash:      harnessPubKeyHashHex,
			},
		}

		logger.Info("detected stored file", "file", *pluginFile, "re_encrypted_to", "target")
	} else {
		// Not a stored file - treat as raw binary
		pluginData = fileData

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
		pluginName = plg.Name()

		// Encrypt plugin using library function
		encryptReq := &crypto.EncryptPluginRequest{
			PluginData:        bytes.NewReader(pluginData),
			PluginType:        *pluginType,
			PluginName:        pluginName,
			HarnessPubKey:     harnessPubKey,
			TargetPubKey:      targetPubKey,
			PrincipalKeystore: exploitKs,
		}

		result, err = crypto.EncryptPlugin(encryptReq)
		if err != nil {
			logger.Error("failed to encrypt plugin", "error", err)
			os.Exit(1)
		}
	}

	// Log encryption details using hashes from result
	logger.Info("encryption log",
		"timestamp", time.Now().Format(time.RFC3339),
		"exploit_owner_signature_hash_sha256", result.Hashes.ExploitOwnerSignatureHash,
		"exploit_owner_public_key_hash_sha256", result.Hashes.ExploitOwnerPublicKeyHash,
		"harness_public_key_hash_sha256", result.Hashes.HarnessPublicKeyHash,
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
