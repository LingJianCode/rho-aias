package kernel

import (
	"testing"
)

func TestVersionString(t *testing.T) {
	tests := []struct {
		v    Version
		want string
	}{
		{Version{5, 15, 0}, "5.15.0"},
		{Version{4, 18, 0}, "4.18.0"},
		{Version{6, 1, 25}, "6.1.25"},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			if got := tt.v.String(); got != tt.want {
				t.Errorf("Version.String() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestVersionCompare(t *testing.T) {
	tests := []struct {
		v1, v2 Version
		want   int
	}{
		// Equal versions
		{Version{5, 15, 0}, Version{5, 15, 0}, 0},
		{Version{4, 18, 0}, Version{4, 18, 0}, 0},

		// Major version differences
		{Version{5, 0, 0}, Version{4, 18, 0}, 1},
		{Version{4, 18, 0}, Version{5, 0, 0}, -1},

		// Minor version differences
		{Version{5, 15, 0}, Version{5, 14, 0}, 1},
		{Version{5, 14, 0}, Version{5, 15, 0}, -1},

		// Patch version differences
		{Version{5, 15, 1}, Version{5, 15, 0}, 1},
		{Version{5, 15, 0}, Version{5, 15, 1}, -1},

		// Complex comparisons
		{Version{6, 1, 25}, Version{5, 15, 0}, 1},
		{Version{4, 19, 100}, Version{5, 0, 0}, -1},

		// Edge cases for Issue #34
		{Version{0, 0, 0}, Version{0, 0, 0}, 0},
		{Version{0, 0, 0}, Version{1, 0, 0}, -1},
		{Version{999, 999, 999}, Version{999, 999, 998}, 1},
		{Version{999, 999, 998}, Version{999, 999, 999}, -1},
	}

	for _, tt := range tests {
		name := tt.v1.String() + "_vs_" + tt.v2.String()
		t.Run(name, func(t *testing.T) {
			if got := tt.v1.Compare(tt.v2); got != tt.want {
				t.Errorf("Version.Compare(%v, %v) = %v, want %v", tt.v1, tt.v2, got, tt.want)
			}
		})
	}
}

func TestVersionAtLeast(t *testing.T) {
	tests := []struct {
		v, min Version
		want   bool
	}{
		{Version{5, 15, 0}, Version{4, 18, 0}, true},
		{Version{4, 18, 0}, Version{4, 18, 0}, true},
		{Version{4, 18, 1}, Version{4, 18, 0}, true},
		{Version{4, 17, 0}, Version{4, 18, 0}, false},
		{Version{3, 10, 0}, Version{4, 18, 0}, false},
		// Edge cases for Issue #34
		{Version{0, 0, 0}, Version{4, 18, 0}, false},
		{Version{999, 999, 999}, Version{4, 18, 0}, true},
		{Version{4, 18, 0}, Version{4, 18, 0}, true},  // boundary
		{Version{4, 17, 999}, Version{4, 18, 0}, false}, // just below boundary
	}

	for _, tt := range tests {
		name := tt.v.String() + "_atLeast_" + tt.min.String()
		t.Run(name, func(t *testing.T) {
			if got := tt.v.AtLeast(tt.min); got != tt.want {
				t.Errorf("Version.AtLeast(%v) = %v, want %v", tt.min, got, tt.want)
			}
		})
	}
}

func TestParseKernelVersion(t *testing.T) {
	tests := []struct {
		name    string
		content string
		want    Version
		wantErr bool
	}{
		{
			name:    "standard Ubuntu format",
			content: "Linux version 5.15.0-91-generic (buildd@lcy02-amd64-082) (gcc (Ubuntu 11.4.0-1ubuntu1~22.04) 11.4.0, GNU ld (GNU Binutils for Ubuntu) 2.38) #101-Ubuntu SMP Tue Nov 14 13:30:08 UTC 2023",
			want:    Version{5, 15, 0},
			wantErr: false,
		},
		{
			name:    "CentOS format",
			content: "Linux version 4.18.0-348.el8.x86_64 (mockbuild@kbuilder.bsys.centos.org) (gcc version 8.5.0 20210514 (Red Hat 8.5.0-4) (GCC)) #1 SMP Tue Nov 9 14:10:40 UTC 2021",
			want:    Version{4, 18, 0},
			wantErr: false,
		},
		{
			name:    "Debian format",
			content: "Linux version 6.1.0-17-amd64 (debian-kernel@lists.debian.org) (gcc-12 (Debian 12.2.0-14) 12.2.0, GNU ld (GNU Binutils for Debian) 2.40) #1 SMP PREEMPT_DYNAMIC Debian 6.1.69-1 (2024-01-08) x86_64",
			want:    Version{6, 1, 0},
			wantErr: false,
		},
		{
			name:    "simple version",
			content: "Linux version 5.10.0 (root@localhost) #1 SMP",
			want:    Version{5, 10, 0},
			wantErr: false,
		},
		{
			name:    "kernel 5.x",
			content: "Linux version 5.4.0-150-generic",
			want:    Version{5, 4, 0},
			wantErr: false,
		},
		{
			name:    "kernel 6.x",
			content: "Linux version 6.5.0-15-generic (gcc-13 (Ubuntu 13.2.0-4ubuntu3) 13.2.0)",
			want:    Version{6, 5, 0},
			wantErr: false,
		},
		{
			name:    "invalid content",
			content: "invalid content without version",
			want:    Version{},
			wantErr: true,
		},
		{
			name:    "empty content",
			content: "",
			want:    Version{},
			wantErr: true,
		},
		// Edge cases for Issue #34
		{
			name:    "kernel version 0.0.0",
			content: "Linux version 0.0.0 (test@localhost) #1 SMP",
			want:    Version{0, 0, 0},
			wantErr: false,
		},
		{
			name:    "very large version numbers 999.999.999",
			content: "Linux version 999.999.999-test (test@localhost) #1 SMP",
			want:    Version{999, 999, 999},
			wantErr: false,
		},
		{
			name:    "large minor version 5.999.1",
			content: "Linux version 5.999.1-test (test@localhost) #1 SMP",
			want:    Version{5, 999, 1},
			wantErr: false,
		},
		{
			name:    "large patch version 5.15.9999",
			content: "Linux version 5.15.9999-test (test@localhost) #1 SMP",
			want:    Version{5, 15, 9999},
			wantErr: false,
		},
		{
			name:    "minimum version boundary 4.18.0",
			content: "Linux version 4.18.0 (test@localhost) #1 SMP",
			want:    Version{4, 18, 0},
			wantErr: false,
		},
		{
			name:    "just below minimum 4.17.999",
			content: "Linux version 4.17.999 (test@localhost) #1 SMP",
			want:    Version{4, 17, 999},
			wantErr: false,
		},
		{
			name:    "version with zero minor and patch 5.0.0",
			content: "Linux version 5.0.0 (test@localhost) #1 SMP",
			want:    Version{5, 0, 0},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseKernelVersion(tt.content)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseKernelVersion() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && got != tt.want {
				t.Errorf("ParseKernelVersion() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestMinVersion(t *testing.T) {
	// Test that the minimum version is correctly set
	if MinVersion.Major != 4 || MinVersion.Minor != 18 || MinVersion.Patch != 0 {
		t.Errorf("MinVersion = %v, want 4.18.0", MinVersion)
	}
}

func TestRecommendedVersion(t *testing.T) {
	// Test that the recommended version is correctly set
	if RecommendedVersion.Major != 5 || RecommendedVersion.Minor != 1 || RecommendedVersion.Patch != 0 {
		t.Errorf("RecommendedVersion = %v, want 5.1.0", RecommendedVersion)
	}
}

func TestCheckAndValidate(t *testing.T) {
	// This test runs on the actual system, so we just verify it doesn't panic
	// and returns a meaningful result
	result, err := CheckAndValidate()

	// Get the actual kernel version for logging purposes
	version, verr := GetKernelVersion()
	if verr != nil {
		t.Logf("Could not get kernel version: %v", verr)
		return
	}

	t.Logf("Current kernel version: %s", version)

	// If the test system has kernel < 4.18, the check should fail
	// Most modern CI systems should have kernel >= 4.18
	if version.AtLeast(MinVersion) {
		if err != nil {
			t.Errorf("CheckAndValidate() should pass for kernel %s >= %s, but got error: %v",
				version, MinVersion, err)
		}
		// Verify result is returned correctly
		if result.CurrentVersion != version {
			t.Errorf("CheckAndValidate() result.CurrentVersion = %v, want %v", result.CurrentVersion, version)
		}
	} else {
		if err == nil {
			t.Errorf("CheckAndValidate() should fail for kernel %s < %s",
				version, MinVersion)
		}
		t.Logf("Expected error for old kernel: %v", err)
	}
}
