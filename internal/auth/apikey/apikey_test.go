package apikey

import (
	"strings"
	"testing"
)

func TestGenerateKey(t *testing.T) {
	tests := []struct {
		name    string
		wantErr bool
	}{
		{
			name:    "generate key successfully",
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key, hash, err := GenerateKey()
			if (err != nil) != tt.wantErr {
				t.Errorf("GenerateKey() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr {
				// Check key format
				if !strings.HasPrefix(key, KeyPrefix) {
					t.Errorf("GenerateKey() key = %v, should start with %v", key, KeyPrefix)
				}

				// Check key length (prefix + hex encoded 32 bytes = prefix + 64 chars)
				expectedLen := len(KeyPrefix) + KeyLength*2
				if len(key) != expectedLen {
					t.Errorf("GenerateKey() key length = %v, want %v", len(key), expectedLen)
				}

				// Check hash is not empty
				if hash == "" {
					t.Error("GenerateKey() returned empty hash")
				}

				// Hash should be 64 characters (SHA256 hex encoded)
				if len(hash) != 64 {
					t.Errorf("GenerateKey() hash length = %v, want 64", len(hash))
				}
			}
		})
	}
}

func TestGenerateKeyUniqueness(t *testing.T) {
	keys := make(map[string]bool)
	hashes := make(map[string]bool)

	// Generate 100 keys and check uniqueness
	for i := 0; i < 100; i++ {
		key, hash, err := GenerateKey()
		if err != nil {
			t.Errorf("GenerateKey() error = %v", err)
			continue
		}

		if keys[key] {
			t.Errorf("GenerateKey() produced duplicate key: %v", key)
		}
		if hashes[hash] {
			t.Errorf("GenerateKey() produced duplicate hash: %v", hash)
		}

		keys[key] = true
		hashes[hash] = true
	}
}

func TestHashKey(t *testing.T) {
	tests := []struct {
		name string
		key  string
	}{
		{
			name: "standard key",
			key:  "sk_live_0123456789abcdef",
		},
		{
			name: "empty key",
			key:  "",
		},
		{
			name: "long key",
			key:  "sk_live_" + strings.Repeat("a", 100),
		},
		{
			name: "unicode key",
			key:  "sk_live_unicode测试",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hash := HashKey(tt.key)

			// Hash should be 64 characters (SHA256 hex encoded)
			if len(hash) != 64 {
				t.Errorf("HashKey() hash length = %v, want 64", len(hash))
			}

			// Same input should produce same hash
			hash2 := HashKey(tt.key)
			if hash != hash2 {
				t.Errorf("HashKey() not deterministic: %v != %v", hash, hash2)
			}

			// Different input should produce different hash
			if tt.key != "" {
				differentHash := HashKey(tt.key + "x")
				if hash == differentHash {
					t.Error("HashKey() produced same hash for different inputs")
				}
			}
		})
	}
}

func TestHashKeyConsistency(t *testing.T) {
	key := "sk_live_testkey12345678901234567890"

	// Generate hash multiple times
	hash1 := HashKey(key)
	hash2 := HashKey(key)

	if hash1 != hash2 {
		t.Errorf("HashKey() inconsistent: %v != %v", hash1, hash2)
	}
}

func TestGenerateKeyPrefix(t *testing.T) {
	// Test multiple times for uniqueness
	prefixes := make(map[string]bool)

	for i := 0; i < 100; i++ {
		prefix := GenerateKeyPrefix()

		// Should start with KeyPrefix
		if !strings.HasPrefix(prefix, KeyPrefix) {
			t.Errorf("GenerateKeyPrefix() = %v, should start with %v", prefix, KeyPrefix)
		}

		// Check uniqueness
		if prefixes[prefix] {
			t.Errorf("GenerateKeyPrefix() produced duplicate prefix: %v", prefix)
		}
		prefixes[prefix] = true

		// Length should be prefix + 8 chars (UUID prefix)
		expectedLen := len(KeyPrefix) + 8
		if len(prefix) != expectedLen {
			t.Errorf("GenerateKeyPrefix() length = %v, want %v", len(prefix), expectedLen)
		}
	}
}

func TestConstants(t *testing.T) {
	// Test KeyPrefix constant
	if KeyPrefix != "sk_live_" {
		t.Errorf("KeyPrefix = %v, want sk_live_", KeyPrefix)
	}

	// Test KeyLength constant
	if KeyLength != 32 {
		t.Errorf("KeyLength = %v, want 32", KeyLength)
	}
}

func TestGenerateKeyAndHashMatch(t *testing.T) {
	// Generate a key
	key, hash, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}

	// Hash the key manually
	manualHash := HashKey(key)

	// Both hashes should match
	if hash != manualHash {
		t.Errorf("GenerateKey hash = %v, HashKey = %v, should match", hash, manualHash)
	}
}

func TestHashKeyFormat(t *testing.T) {
	key := "sk_live_testkey"
	hash := HashKey(key)

	// Hash should only contain hex characters
	for _, c := range hash {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			t.Errorf("HashKey() hash contains non-hex character: %c", c)
		}
	}
}

func TestGenerateKeyFormat(t *testing.T) {
	key, _, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}

	// After prefix, should only contain hex characters
	afterPrefix := key[len(KeyPrefix):]
	for _, c := range afterPrefix {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			t.Errorf("GenerateKey() key contains non-hex character after prefix: %c", c)
		}
	}
}
