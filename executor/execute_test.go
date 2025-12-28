package executor

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"strings"
	"testing"

	"github.com/joncooperworks/harness/crypto/keystore"
)

func TestExecutePlugin_NilRequest(t *testing.T) {
	_, err := ExecutePlugin(context.Background(), nil)
	if err == nil {
		t.Error("ExecutePlugin() with nil request error = nil, want error")
		return
	}
	if !strings.Contains(err.Error(), "cannot be nil") {
		t.Errorf("ExecutePlugin() error = %v, want error containing 'cannot be nil'", err)
	}
}

func TestExecutePlugin_EmptyEncryptedData(t *testing.T) {
	harnessKS, _ := keystore.NewMockKeystore("harness-key")
	targetPub, _, _ := ed25519.GenerateKey(rand.Reader)
	exploitPub, _, _ := ed25519.GenerateKey(rand.Reader)

	req := &ExecutePluginRequest{
		EncryptedData:   []byte{},
		HarnessKeystore: harnessKS,
		TargetPubKey:    targetPub,
		ExploitPubKey:   exploitPub,
	}

	_, err := ExecutePlugin(context.Background(), req)
	if err == nil {
		t.Error("ExecutePlugin() with empty encrypted data error = nil, want error")
		return
	}
	if !strings.Contains(err.Error(), "cannot be empty") {
		t.Errorf("ExecutePlugin() error = %v, want error containing 'cannot be empty'", err)
	}
}

func TestExecutePlugin_InvalidKeys(t *testing.T) {
	harnessKS, _ := keystore.NewMockKeystore("harness-key")
	targetPub, _, _ := ed25519.GenerateKey(rand.Reader)
	exploitPub, _, _ := ed25519.GenerateKey(rand.Reader)

	tests := []struct {
		name           string
		harnessKS      keystore.Keystore
		targetPub      ed25519.PublicKey
		exploitPub     ed25519.PublicKey
		encryptedData  []byte
		errMsg         string
	}{
		{
			name:          "nil harness keystore",
			harnessKS:     nil,
			targetPub:     targetPub,
			exploitPub:    exploitPub,
			encryptedData: []byte("some data"),
			errMsg:        "harness keystore cannot be nil",
		},
		{
			name:          "nil target public key",
			harnessKS:     harnessKS,
			targetPub:     nil,
			exploitPub:    exploitPub,
			encryptedData: []byte("some data"),
			errMsg:        "target public key cannot be nil",
		},
		{
			name:          "nil exploit public key",
			harnessKS:     harnessKS,
			targetPub:     targetPub,
			exploitPub:    nil,
			encryptedData: []byte("some data"),
			errMsg:        "exploit public key cannot be nil",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := &ExecutePluginRequest{
				EncryptedData:   tt.encryptedData,
				HarnessKeystore: tt.harnessKS,
				TargetPubKey:    tt.targetPub,
				ExploitPubKey:   tt.exploitPub,
			}

			_, err := ExecutePlugin(context.Background(), req)
			if err == nil {
				t.Error("ExecutePlugin() error = nil, want error")
				return
			}
			if !strings.Contains(err.Error(), tt.errMsg) {
				t.Errorf("ExecutePlugin() error = %v, want error containing %q", err, tt.errMsg)
			}
		})
	}
}

