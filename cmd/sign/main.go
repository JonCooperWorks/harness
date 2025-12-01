package main

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/asn1"
	"encoding/binary"
	"encoding/json"
	"flag"
	"fmt"
	"math/big"
	"os"

	"github.com/joncooperworks/harness/crypto/keystore"
)

func main() {
	var (
		encryptedFile  = flag.String("file", "", "Path to encrypted plugin file (from encrypt command)")
		presidentKeyID = flag.String("president-keystore-key", "", "Key ID in OS keystore for president's private key (required)")
		outputPath     = flag.String("output", "", "Path to save signed plugin (defaults to input file with .signed suffix)")
	)
	flag.Parse()

	if *encryptedFile == "" {
		fmt.Fprintf(os.Stderr, "Error: -file is required (use ./bin/encrypt first to create encrypted file)\n")
		os.Exit(1)
	}

	if *presidentKeyID == "" {
		fmt.Fprintf(os.Stderr, "Error: -president-keystore-key is required (private keys must be stored in OS keystore)\n")
		os.Exit(1)
	}

	if *outputPath == "" {
		*outputPath = *encryptedFile + ".signed"
	}

	// Load president's private key from keystore
	ks, err := keystore.NewKeystore()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error creating keystore: %v\n", err)
		os.Exit(1)
	}
	presidentKey, err := ks.GetPrivateKey(*presidentKeyID)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading president's private key from keystore: %v\n", err)
		os.Exit(1)
	}

	// Load encrypted file
	encryptedData, err := os.ReadFile(*encryptedFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading encrypted file: %v\n", err)
		os.Exit(1)
	}

	// Parse encrypted file structure (without signature):
	// [metadata_length:4][metadata][encrypted_symmetric_key][encrypted_plugin_data]
	if len(encryptedData) < 4 {
		fmt.Fprintf(os.Stderr, "Error: encrypted file too short\n")
		os.Exit(1)
	}

	offset := 0

	// Read metadata length
	metadataLen := int(binary.BigEndian.Uint32(encryptedData[offset : offset+4]))
	offset += 4

	if len(encryptedData) < offset+metadataLen {
		fmt.Fprintf(os.Stderr, "Error: invalid metadata length\n")
		os.Exit(1)
	}

	// Read metadata
	metadataJSON := encryptedData[offset : offset+metadataLen]
	offset += metadataLen

	// Parse metadata to get lengths
	var metadataStruct struct {
		SymmetricKeyLen int    `json:"symmetric_key_len"`
		PluginDataLen   int    `json:"plugin_data_len"`
		Algorithm       string `json:"algorithm"`
	}
	if err := json.Unmarshal(metadataJSON, &metadataStruct); err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing metadata: %v\n", err)
		os.Exit(1)
	}

	// Verify we have enough data
	if len(encryptedData) < offset+metadataStruct.SymmetricKeyLen+metadataStruct.PluginDataLen {
		fmt.Fprintf(os.Stderr, "Error: encrypted file incomplete\n")
		os.Exit(1)
	}

	// Extract encrypted symmetric key and plugin data
	encryptedSymmetricKey := encryptedData[offset : offset+metadataStruct.SymmetricKeyLen]
	offset += metadataStruct.SymmetricKeyLen
	encryptedPluginData := encryptedData[offset : offset+metadataStruct.PluginDataLen]

	// Create data to sign: metadata + encrypted data
	dataToSign := append(metadataJSON, encryptedSymmetricKey...)
	dataToSign = append(dataToSign, encryptedPluginData...)

	// Sign the data with president's private key
	hash := sha256.Sum256(dataToSign)
	r, s, err := ecdsa.Sign(rand.Reader, presidentKey, hash[:])
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error signing data: %v\n", err)
		os.Exit(1)
	}

	// Encode signature
	signature, err := asn1.Marshal(struct {
		R, S *big.Int
	}{R: r, S: s})
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error encoding signature: %v\n", err)
		os.Exit(1)
	}

	// Build final encrypted file structure:
	// [signature_length:4][signature][metadata_length:4][metadata][encrypted_symmetric_key][encrypted_plugin_data]
	var output []byte

	// Write signature length
	sigLenBuf := make([]byte, 4)
	binary.BigEndian.PutUint32(sigLenBuf, uint32(len(signature)))
	output = append(output, sigLenBuf...)

	// Write signature
	output = append(output, signature...)

	// Write metadata length
	metadataLenBuf := make([]byte, 4)
	binary.BigEndian.PutUint32(metadataLenBuf, uint32(len(metadataJSON)))
	output = append(output, metadataLenBuf...)

	// Write metadata
	output = append(output, metadataJSON...)

	// Write encrypted symmetric key
	output = append(output, encryptedSymmetricKey...)

	// Write encrypted plugin data
	output = append(output, encryptedPluginData...)

	// Write to file
	if err := os.WriteFile(*outputPath, output, 0644); err != nil {
		fmt.Fprintf(os.Stderr, "Error writing encrypted file: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Plugin signed successfully:\n")
	fmt.Printf("  Input: %s\n", *encryptedFile)
	fmt.Printf("  Output: %s\n", *outputPath)
}
