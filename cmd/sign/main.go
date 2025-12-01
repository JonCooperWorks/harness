package main

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"math/big"
	"os"

	"github.com/joncooperworks/harness/crypto/keystore"
)

func main() {
	var (
		encryptedFile      = flag.String("file", "", "Path to encrypted plugin file (from encrypt command)")
		presidentKeyPath   = flag.String("president-key", "", "Path to president's private key file (optional if using keystore)")
		presidentKeyID     = flag.String("president-keystore-key", "", "Key ID in OS keystore for president's private key (optional if using key file)")
		outputPath         = flag.String("output", "", "Path to save signed plugin (defaults to input file with .signed suffix)")
	)
	flag.Parse()

	if *encryptedFile == "" {
		fmt.Fprintf(os.Stderr, "Error: -file is required (use ./bin/encrypt first to create encrypted file)\n")
		os.Exit(1)
	}

	if *presidentKeyPath == "" && *presidentKeyID == "" {
		fmt.Fprintf(os.Stderr, "Error: either -president-key or -president-keystore-key must be provided\n")
		os.Exit(1)
	}

	if *outputPath == "" {
		*outputPath = *encryptedFile + ".signed"
	}

	// Load president's private key (for signing)
	var presidentKey *ecdsa.PrivateKey
	var err error
	if *presidentKeyID != "" {
		ks, err := keystore.NewKeystore()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error creating keystore: %v\n", err)
			os.Exit(1)
		}
		presidentKey, err = ks.GetPrivateKey(*presidentKeyID)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error loading president's private key from keystore: %v\n", err)
			os.Exit(1)
		}
	} else {
		presidentKey, err = loadPrivateKey(*presidentKeyPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error loading president's private key: %v\n", err)
			os.Exit(1)
		}
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
	metadataLen := int(binary.BigEndian.Uint32(encryptedData[offset:offset+4]))
	offset += 4

	if len(encryptedData) < offset+metadataLen {
		fmt.Fprintf(os.Stderr, "Error: invalid metadata length\n")
		os.Exit(1)
	}

	// Read metadata
	metadataJSON := encryptedData[offset:offset+metadataLen]
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
	encryptedSymmetricKey := encryptedData[offset:offset+metadataStruct.SymmetricKeyLen]
	offset += metadataStruct.SymmetricKeyLen
	encryptedPluginData := encryptedData[offset:offset+metadataStruct.PluginDataLen]

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

// loadPrivateKey loads an ECDSA private key from a file
func loadPrivateKey(path string) (*ecdsa.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read private key file: %w", err)
	}

	// Try PEM format first
	block, _ := pem.Decode(data)
	if block != nil {
		data = block.Bytes
	}

	// Try PKCS8 format
	key, err := x509.ParsePKCS8PrivateKey(data)
	if err == nil {
		if ecdsaKey, ok := key.(*ecdsa.PrivateKey); ok {
			return ecdsaKey, nil
		}
		return nil, fmt.Errorf("key is not ECDSA")
	}

	// Try EC private key format
	ecKey, err := x509.ParseECPrivateKey(data)
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key: %w", err)
	}

	return ecKey, nil
}


