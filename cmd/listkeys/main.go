package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/joncooperworks/harness/crypto/keystore"
)

func main() {
	flag.Parse()

	ks, err := keystore.NewKeystore()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error creating keystore: %v\n", err)
		os.Exit(1)
	}

	keys, err := ks.ListKeys()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error listing keys: %v\n", err)
		os.Exit(1)
	}

	if len(keys) == 0 {
		fmt.Println("No keys found in keystore")
		return
	}

	fmt.Printf("Keys in keystore (%d):\n", len(keys))
	for _, keyID := range keys {
		fmt.Printf("  - %s\n", keyID)
	}
}

