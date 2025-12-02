package main

import (
	"flag"
	"fmt"
	"log/slog"
	"os"

	"github.com/joncooperworks/harness/crypto/keystore"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stderr, nil))

	flag.Parse()

	ks, err := keystore.NewKeystore()
	if err != nil {
		logger.Error("failed to create keystore", "error", err)
		os.Exit(1)
	}

	keys, err := ks.ListKeys()
	if err != nil {
		logger.Error("failed to list keys", "error", err)
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
