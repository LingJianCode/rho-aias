package password

import (
	"testing"
)

func TestHashPassword(t *testing.T) {
	tests := []struct {
		name     string
		password string
		wantErr  bool
	}{
		{
			name:     "simple password",
			password: "password123",
			wantErr:  false,
		},
		{
			name:     "complex password",
			password: "P@ssw0rd!#$%^&*()",
			wantErr:  false,
		},
		{
			name:     "empty password",
			password: "",
			wantErr:  false, // bcrypt allows empty passwords
		},
		{
			name:     "long password",
			password: "this_is_a_very_long_password_that_should_still_work_fine_1234567890",
			wantErr:  false,
		},
		{
			name:     "unicode password",
			password: "密码测试123",
			wantErr:  false,
		},
		{
			name:     "password with spaces",
			password: "password with spaces",
			wantErr:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hash, err := HashPassword(tt.password)
			if (err != nil) != tt.wantErr {
				t.Errorf("HashPassword() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr {
				if hash == "" {
					t.Error("HashPassword() returned empty hash")
				}
				if hash == tt.password {
					t.Error("HashPassword() returned unhashed password")
				}
			}
		})
	}
}

func TestCheckPassword(t *testing.T) {
	// Pre-generate hashes for testing
	password := "testPassword123"
	hash, _ := HashPassword(password)

	tests := []struct {
		name     string
		password string
		hash     string
		want     bool
	}{
		{
			name:     "correct password",
			password: password,
			hash:     hash,
			want:     true,
		},
		{
			name:     "incorrect password",
			password: "wrongPassword",
			hash:     hash,
			want:     false,
		},
		{
			name:     "empty password with valid hash",
			password: "",
			hash:     hash,
			want:     false,
		},
		{
			name:     "password with empty hash",
			password: password,
			hash:     "",
			want:     false,
		},
		{
			name:     "case sensitive password",
			password: "TESTPASSWORD123",
			hash:     hash,
			want:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := CheckPassword(tt.password, tt.hash); got != tt.want {
				t.Errorf("CheckPassword() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestHashPasswordAndCheck(t *testing.T) {
	passwords := []string{
		"simple",
		"with spaces",
		"P@ssw0rd!#$",
		"unicode密码",
		"12345678",
		"verylongpassword" + string(make([]byte, 50)),
	}

	for i, password := range passwords {
		t.Run("password_"+string(rune('A'+i)), func(t *testing.T) {
			hash, err := HashPassword(password)
			if err != nil {
				t.Errorf("HashPassword() error = %v", err)
				return
			}

			if !CheckPassword(password, hash) {
				t.Errorf("CheckPassword() failed for password %q", password)
			}

			if CheckPassword("wrong"+password, hash) {
				t.Errorf("CheckPassword() succeeded for wrong password %q", "wrong"+password)
			}
		})
	}
}

func TestMustHashPassword(t *testing.T) {
	tests := []struct {
		name     string
		password string
		panic    bool
	}{
		{
			name:     "valid password",
			password: "password123",
			panic:    false,
		},
		{
			name:     "empty password",
			password: "",
			panic:    false, // bcrypt allows empty passwords
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					if !tt.panic {
						t.Errorf("MustHashPassword() panicked unexpectedly: %v", r)
					}
				} else if tt.panic {
					t.Error("MustHashPassword() expected panic but didn't")
				}
			}()

			hash := MustHashPassword(tt.password)
			if hash == "" {
				t.Error("MustHashPassword() returned empty hash")
			}
			if hash == tt.password {
				t.Error("MustHashPassword() returned unhashed password")
			}
		})
	}
}

func TestHashUniqueness(t *testing.T) {
	password := "samePassword123"

	hash1, _ := HashPassword(password)
	hash2, _ := HashPassword(password)

	// Same password should produce different hashes (due to salt)
	if hash1 == hash2 {
		t.Error("HashPassword() produced same hash for same password twice")
	}

	// But both should validate
	if !CheckPassword(password, hash1) {
		t.Error("CheckPassword() failed for hash1")
	}
	if !CheckPassword(password, hash2) {
		t.Error("CheckPassword() failed for hash2")
	}
}

func TestDefaultCost(t *testing.T) {
	if DefaultCost < 4 || DefaultCost > 31 {
		t.Errorf("DefaultCost = %v, should be between 4 and 31", DefaultCost)
	}
}
