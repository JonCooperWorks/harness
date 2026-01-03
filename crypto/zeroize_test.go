package crypto

import (
	"testing"
)

func TestZeroize(t *testing.T) {
	t.Run("zeroizes non-empty slice", func(t *testing.T) {
		data := []byte{0x01, 0x02, 0x03, 0x04, 0x05}
		zeroize(data)

		for i, b := range data {
			if b != 0 {
				t.Errorf("byte at index %d should be 0, got %d", i, b)
			}
		}
	})

	t.Run("handles empty slice", func(t *testing.T) {
		data := []byte{}
		zeroize(data) // Should not panic

		if len(data) != 0 {
			t.Error("empty slice should remain empty")
		}
	})

	t.Run("handles nil slice", func(t *testing.T) {
		var data []byte
		zeroize(data) // Should not panic
	})

	t.Run("zeroizes 32-byte key", func(t *testing.T) {
		key := make([]byte, 32)
		for i := range key {
			key[i] = byte(i + 1)
		}

		zeroize(key)

		for i, b := range key {
			if b != 0 {
				t.Errorf("byte at index %d should be 0, got %d", i, b)
			}
		}
	})
}
