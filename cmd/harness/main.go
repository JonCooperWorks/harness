package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/joncooperworks/harness/crypto"
	"github.com/joncooperworks/harness/crypto/keystore"
	"github.com/joncooperworks/harness/plugin"
)

func main() {
	var (
		encryptedFile       = flag.String("file", "", "Path to approved plugin file (with signature)")
		keystoreKeyID       = flag.String("keystore-key", "", "Key ID in OS keystore for private key (required)")
		signaturePubKeyFile = flag.String("signature-key", "", "Path to public key file for verifying signature (required)")
		principalPubKeyFile = flag.String("principal-key", "", "Path to principal's public key file (required, for verifying payload signature)")
	)
	flag.Parse()

	if *encryptedFile == "" {
		fmt.Fprintf(os.Stderr, "Error: -file is required\n")
		os.Exit(1)
	}

	if *keystoreKeyID == "" {
		fmt.Fprintf(os.Stderr, "Error: -keystore-key is required (private key must be stored in OS keystore)\n")
		os.Exit(1)
	}

	if *signaturePubKeyFile == "" {
		fmt.Fprintf(os.Stderr, "Error: -signature-key is required (public key for verifying signature)\n")
		os.Exit(1)
	}

	if *principalPubKeyFile == "" {
		fmt.Fprintf(os.Stderr, "Error: -principal-key is required (principal's public key for verifying payload signature)\n")
		os.Exit(1)
	}

	// Load public key for signature verification
	signaturePubKey, err := loadPublicKey(*signaturePubKeyFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading signature public key: %v\n", err)
		os.Exit(1)
	}

	// Load principal's public key (required)
	principalPubKey, err := loadPublicKey(*principalPubKeyFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading principal's public key: %v\n", err)
		os.Exit(1)
	}

	// Get pentester's public key from keystore for logging
	ks, err := keystore.NewKeystore()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error creating keystore: %v\n", err)
		os.Exit(1)
	}
	pentesterPubKey, err := ks.GetPublicKey(*keystoreKeyID)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error getting pentester's public key: %v\n", err)
		os.Exit(1)
	}

	// Create PresidentialOrder from keystore
	po, err := crypto.NewPresidentialOrderFromKeystoreWithPrincipal(*keystoreKeyID, signaturePubKey, principalPubKey)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error creating PresidentialOrder from keystore: %v\n", err)
		os.Exit(1)
	}

	// Load approved file (contains encrypted payload + client signature + args)
	fileData, err := os.ReadFile(*encryptedFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading approved file: %v\n", err)
		os.Exit(1)
	}

	// Extract encrypted payload for logging (parse backwards to find signature position)
	// File format: [version:1][encrypted_payload][client_sig_len:4][client_sig][expiration:8][args_len:4][args_json]
	if len(fileData) < 21 {
		fmt.Fprintf(os.Stderr, "Error: file too short\n")
		os.Exit(1)
	}

	// Find args_len by parsing backwards
	var argsLenPos int
	foundArgsLen := false
	for offset := 4; offset < len(fileData) && offset < 1024*1024+4; offset++ {
		argsLenPos = len(fileData) - offset
		if argsLenPos < 0 {
			break
		}
		if argsLenPos+4 > len(fileData) {
			continue
		}
		candidateArgsLen := int(binary.BigEndian.Uint32(fileData[argsLenPos : argsLenPos+4]))
		argsStart := argsLenPos + 4
		expectedArgsEnd := argsStart + candidateArgsLen
		if expectedArgsEnd == len(fileData) {
			if candidateArgsLen > 0 && argsStart < len(fileData) {
				argsJSON := fileData[argsStart : argsStart+candidateArgsLen]
				if len(argsJSON) > 0 && (argsJSON[0] == '{' || argsJSON[0] == '[') {
					foundArgsLen = true
					break
				}
			} else if candidateArgsLen == 0 {
				foundArgsLen = true
				break
			}
		}
	}

	if !foundArgsLen {
		fmt.Fprintf(os.Stderr, "Error: could not find valid args_len\n")
		os.Exit(1)
	}

	// Find signature position (8 bytes before args_len is expiration, signature ends at expiration)
	expirationPos := argsLenPos - 8
	if expirationPos < 0 {
		fmt.Fprintf(os.Stderr, "Error: file too short for expiration\n")
		os.Exit(1)
	}

	// Find signature length (4 bytes before signature start)
	var sigLenPos int
	foundSigLen := false
	minPos := expirationPos - 4 - 80
	if minPos < 0 {
		minPos = 0
	}
	for pos := expirationPos - 4 - 60; pos >= minPos && pos >= 0; pos-- {
		if pos+4 > expirationPos {
			continue
		}
		sigLenCandidate := int(binary.BigEndian.Uint32(fileData[pos : pos+4]))
		if sigLenCandidate >= 60 && sigLenCandidate <= 80 {
			sigStart := pos + 4
			sigEnd := sigStart + sigLenCandidate
			if sigEnd == expirationPos {
				sigLenPos = pos
				foundSigLen = true
				break
			}
		}
	}

	if !foundSigLen {
		fmt.Fprintf(os.Stderr, "Error: could not find valid signature length\n")
		os.Exit(1)
	}

	// Extract encrypted payload (after version byte, before signature)
	encryptedPayloadStart := 1 // Skip version byte
	encryptedPayload := fileData[encryptedPayloadStart:sigLenPos]
	encryptedPayloadHash := sha256.Sum256(encryptedPayload)
	encryptedPayloadHashHex := hex.EncodeToString(encryptedPayloadHash[:])

	// Verify client signature on arguments and decrypt
	result, err := po.VerifyAndDecrypt(fileData)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error verifying and decrypting: %v\n", err)
		os.Exit(1)
	}

	// Calculate hash of decrypted exploit binary for logging
	exploitHash := sha256.Sum256(result.Payload.Data)
	exploitHashHex := hex.EncodeToString(exploitHash[:])

	// Calculate hash of client signature
	signatureHash := sha256.Sum256(result.ClientSignature)
	signatureHashHex := hex.EncodeToString(signatureHash[:])

	// Calculate hash of client public key
	clientPubKeyBytes, err := x509.MarshalPKIXPublicKey(signaturePubKey)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error marshaling client public key: %v\n", err)
		os.Exit(1)
	}
	clientPubKeyHash := sha256.Sum256(clientPubKeyBytes)
	clientPubKeyHashHex := hex.EncodeToString(clientPubKeyHash[:])

	// Calculate hash of pentester public key
	pentesterPubKeyBytes, err := x509.MarshalPKIXPublicKey(pentesterPubKey)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error marshaling pentester public key: %v\n", err)
		os.Exit(1)
	}
	pentesterPubKeyHash := sha256.Sum256(pentesterPubKeyBytes)
	pentesterPubKeyHashHex := hex.EncodeToString(pentesterPubKeyHash[:])

	// Calculate hash of principal signature
	principalSigHash := sha256.Sum256(result.PrincipalSignature)
	principalSigHashHex := hex.EncodeToString(principalSigHash[:])

	// Calculate hash of principal public key
	principalPubKeyBytes, err := x509.MarshalPKIXPublicKey(principalPubKey)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error marshaling principal public key: %v\n", err)
		os.Exit(1)
	}
	principalPubKeyHash := sha256.Sum256(principalPubKeyBytes)
	principalPubKeyHashHex := hex.EncodeToString(principalPubKeyHash[:])

	// Log execution details
	fmt.Fprintf(os.Stderr, "[EXECUTION LOG] %s\n", time.Now().Format(time.RFC3339))
	fmt.Fprintf(os.Stderr, "[EXECUTION LOG] Encrypted Payload Hash (SHA256): %s\n", encryptedPayloadHashHex)
	fmt.Fprintf(os.Stderr, "[EXECUTION LOG] Plugin Type: %s\n", result.Payload.Type.String())
	fmt.Fprintf(os.Stderr, "[EXECUTION LOG] Plugin Name: %s\n", result.Payload.Name)
	fmt.Fprintf(os.Stderr, "[EXECUTION LOG] Exploit Binary Hash (SHA256): %s\n", exploitHashHex)
	fmt.Fprintf(os.Stderr, "[EXECUTION LOG] Principal Signature Hash (SHA256): %s\n", principalSigHashHex)
	fmt.Fprintf(os.Stderr, "[EXECUTION LOG] Principal Public Key Hash (SHA256): %s\n", principalPubKeyHashHex)
	fmt.Fprintf(os.Stderr, "[EXECUTION LOG] Client Signature Hash (SHA256): %s\n", signatureHashHex)
	fmt.Fprintf(os.Stderr, "[EXECUTION LOG] Client Public Key Hash (SHA256): %s\n", clientPubKeyHashHex)
	fmt.Fprintf(os.Stderr, "[EXECUTION LOG] Pentester Public Key Hash (SHA256): %s\n", pentesterPubKeyHashHex)

	// Load plugin
	plg, err := plugin.LoadPlugin(result.Payload)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading plugin: %v\n", err)
		os.Exit(1)
	}

	// Use arguments from the package (extracted from the file)
	var args json.RawMessage
	if err := json.Unmarshal(result.Args, &args); err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing arguments JSON: %v\n", err)
		os.Exit(1)
	}

	// Execute plugin
	ctx := context.Background()
	execResult, err := plg.Execute(ctx, args)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error executing plugin: %v\n", err)
		os.Exit(1)
	}

	// Print result
	resultJSON, err := json.MarshalIndent(execResult, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error marshaling result: %v\n", err)
		os.Exit(1)
	}

	fmt.Println(string(resultJSON))
}

// loadPublicKey loads an ECDSA public key from a file
func loadPublicKey(path string) (*ecdsa.PublicKey, error) {
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

	ecdsaPubKey, ok := pubKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("public key is not ECDSA")
	}

	return ecdsaPubKey, nil
}
