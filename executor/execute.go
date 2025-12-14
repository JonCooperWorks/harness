// Package executor provides plugin execution functionality.
// It coordinates between the crypto and plugin packages to execute plugins
// and return structured results with hashes.
package executor

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/joncooperworks/harness/crypto"
	"github.com/joncooperworks/harness/crypto/keystore"
	"github.com/joncooperworks/harness/plugin"
)

// ExecutePluginRequest contains all the information needed to execute a plugin.
//
// This request implements the harness/pentester's role in the dual-authorization model:
// verifying signatures, decrypting the payload, and executing the plugin.
type ExecutePluginRequest struct {
	// EncryptedData is the approved file data containing the encrypted payload,
	// signatures, expiration, and encrypted arguments.
	// Format: [magic:4][version:1][flags:1][file_length:4][principal_sig_len:4][principal_sig][metadata_length:4][metadata][encrypted_symmetric_key][encrypted_plugin_data][client_sig_len:4][client_sig][expiration:8][args_len:4][encrypted_args]
	EncryptedData []byte
	// HarnessKeystore is a Keystore bound to the harness (pentester's) key.
	// The keystore is used to decrypt the symmetric key and arguments.
	// Use keystore.NewKeystoreForKey(keyID) to create a bound keystore.
	HarnessKeystore keystore.Keystore
	// TargetPubKey is the target's public key for verifying argument signatures.
	// The target signs the encrypted payload, expiration, and arguments.
	TargetPubKey ed25519.PublicKey
	// ExploitPubKey is the exploit owner's (principal's) public key for verifying payload signatures.
	// The exploit owner signs the encrypted payload before encryption.
	ExploitPubKey ed25519.PublicKey
}

// ExecutionHashes contains all SHA256 hashes calculated during plugin execution.
//
// These hashes provide cryptographic proof of what was executed and can be used
// for audit logging, chain-of-custody tracking, and verification.
type ExecutionHashes struct {
	// EncryptedPayloadHash is the SHA256 hash of the encrypted payload.
	// The encrypted payload is: [metadata_length:4][metadata][encrypted_symmetric_key][encrypted_plugin_data]
	EncryptedPayloadHash string
	// ExploitBinaryHash is the SHA256 hash of the decrypted exploit binary (plugin data).
	ExploitBinaryHash string
	// ExploitOwnerSignatureHash is the SHA256 hash of the exploit owner's signature.
	ExploitOwnerSignatureHash string
	// ExploitOwnerPublicKeyHash is the SHA256 hash of the exploit owner's public key.
	ExploitOwnerPublicKeyHash string
	// TargetSignatureHash is the SHA256 hash of the target's signature on the arguments.
	TargetSignatureHash string
	// TargetPublicKeyHash is the SHA256 hash of the target's public key.
	TargetPublicKeyHash string
	// HarnessPublicKeyHash is the SHA256 hash of the harness (pentester's) public key.
	HarnessPublicKeyHash string
}

// ExecutePluginResult contains the execution result and all calculated hashes.
//
// This is returned by ExecutePlugin after successfully verifying signatures,
// decrypting the payload, and executing the plugin.
type ExecutePluginResult struct {
	// Hashes contains all SHA256 hashes calculated during execution.
	Hashes ExecutionHashes
	// PluginResult is the result returned by the plugin's Execute() method.
	// This is typically a JSON-serializable value.
	PluginResult interface{}
	// PluginType is the plugin type identifier (e.g., "wasm", "python").
	PluginType string
	// PluginName is the name of the plugin.
	PluginName string
}

// ExecutePlugin verifies signatures, decrypts the payload, and executes the plugin.
//
// This function implements the harness/pentester's role in the dual-authorization model:
//  1. Creates a PresidentialOrder from the harness keystore and public keys
//  2. Verifies both principal and client signatures
//  3. Checks expiration
//  4. Decrypts the plugin data and execution arguments
//  5. Calculates all relevant hashes for audit logging
//  6. Loads and executes the plugin
//  7. Returns the execution result along with all calculated hashes
//
// This function does not perform any logging - it is a pure library function
// that returns structured data. Logging should be handled by the caller (e.g., CLI).
func ExecutePlugin(ctx context.Context, req *ExecutePluginRequest) (*ExecutePluginResult, error) {
	if req == nil {
		return nil, errors.New("request cannot be nil")
	}
	if len(req.EncryptedData) == 0 {
		return nil, errors.New("encrypted data cannot be empty")
	}
	if req.HarnessKeystore == nil {
		return nil, errors.New("harness keystore cannot be nil")
	}
	if req.TargetPubKey == nil {
		return nil, errors.New("target public key cannot be nil")
	}
	if req.ExploitPubKey == nil {
		return nil, errors.New("exploit public key cannot be nil")
	}

	// Create PresidentialOrder from bound keystore
	po, err := crypto.NewPresidentialOrderFromKeystore(req.HarnessKeystore, req.TargetPubKey, req.ExploitPubKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create PresidentialOrder: %w", err)
	}

	// Verify client signature on arguments and decrypt
	result, err := po.VerifyAndDecrypt(req.EncryptedData)
	if err != nil {
		return nil, fmt.Errorf("failed to verify and decrypt: %w", err)
	}

	// Get harness public key for hash calculation
	harnessPubKey, err := req.HarnessKeystore.PublicKey()
	if err != nil {
		return nil, fmt.Errorf("failed to get harness public key: %w", err)
	}

	// Calculate hash of decrypted exploit binary
	exploitHash := sha256.Sum256(result.Payload.Data)
	exploitHashHex := hex.EncodeToString(exploitHash[:])

	// Calculate hash of target signature
	targetSigHash := sha256.Sum256(result.ClientSignature)
	targetSigHashHex := hex.EncodeToString(targetSigHash[:])

	// Calculate hash of target public key
	targetPubKeyBytes, err := x509.MarshalPKIXPublicKey(req.TargetPubKey)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal target public key: %w", err)
	}
	targetPubKeyHash := sha256.Sum256(targetPubKeyBytes)
	targetPubKeyHashHex := hex.EncodeToString(targetPubKeyHash[:])

	// Calculate hash of harness public key
	harnessPubKeyBytes, err := x509.MarshalPKIXPublicKey(harnessPubKey)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal harness public key: %w", err)
	}
	harnessPubKeyHash := sha256.Sum256(harnessPubKeyBytes)
	harnessPubKeyHashHex := hex.EncodeToString(harnessPubKeyHash[:])

	// Calculate hash of exploit owner signature
	exploitSigHash := sha256.Sum256(result.PrincipalSignature)
	exploitSigHashHex := hex.EncodeToString(exploitSigHash[:])

	// Calculate hash of exploit owner public key
	exploitPubKeyBytes, err := x509.MarshalPKIXPublicKey(req.ExploitPubKey)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal exploit owner public key: %w", err)
	}
	exploitPubKeyHash := sha256.Sum256(exploitPubKeyBytes)
	exploitPubKeyHashHex := hex.EncodeToString(exploitPubKeyHash[:])

	// Calculate encrypted payload hash
	// Extract encrypted payload: skip header(10) + principal_sig_len(4) + principal_sig, then read metadata_len(4) + metadata + encrypted data
	const headerSize = 4 + 1 + 1 + 4 // magic + version + flags + file_length
	if len(req.EncryptedData) < headerSize+4 {
		return nil, errors.New("file too short")
	}
	principalSigLen := int(binary.BigEndian.Uint32(req.EncryptedData[headerSize : headerSize+4]))
	if len(req.EncryptedData) < headerSize+4+principalSigLen+4 {
		return nil, errors.New("file too short")
	}
	encryptedPayloadStart := headerSize + 4 + principalSigLen
	encryptedPayloadEnd := len(req.EncryptedData) - 4 - 60 - 8 - 4 // Approximate: client_sig_len - min_sig - expiration - args_len
	if encryptedPayloadEnd <= encryptedPayloadStart {
		encryptedPayloadEnd = len(req.EncryptedData)
	}
	encryptedPayload := req.EncryptedData[encryptedPayloadStart:encryptedPayloadEnd]
	encryptedPayloadHash := sha256.Sum256(encryptedPayload)
	encryptedPayloadHashHex := hex.EncodeToString(encryptedPayloadHash[:])

	// Load plugin
	plg, err := plugin.LoadPlugin(result.Payload)
	if err != nil {
		return nil, fmt.Errorf("failed to load plugin: %w", err)
	}

	// Parse arguments from the package (extracted from the file)
	var args json.RawMessage
	if err := json.Unmarshal(result.Args, &args); err != nil {
		return nil, fmt.Errorf("failed to parse arguments JSON: %w", err)
	}

	// Execute plugin
	execResult, err := plg.Execute(ctx, args)
	if err != nil {
		return nil, fmt.Errorf("failed to execute plugin: %w", err)
	}

	// Build result with all hashes
	return &ExecutePluginResult{
		Hashes: ExecutionHashes{
			EncryptedPayloadHash:        encryptedPayloadHashHex,
			ExploitBinaryHash:            exploitHashHex,
			ExploitOwnerSignatureHash:    exploitSigHashHex,
			ExploitOwnerPublicKeyHash:   exploitPubKeyHashHex,
			TargetSignatureHash:          targetSigHashHex,
			TargetPublicKeyHash:         targetPubKeyHashHex,
			HarnessPublicKeyHash:        harnessPubKeyHashHex,
		},
		PluginResult: execResult,
		PluginType:   result.Payload.Type.String(),
		PluginName:   result.Payload.Name,
	}, nil
}

