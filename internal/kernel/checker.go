// Package kernel provides kernel version checking functionality
// to ensure the system meets the minimum requirements for eBPF/XDP operations.
package kernel

import (
	"fmt"
	"os"
	"regexp"
	"runtime"
	"strconv"
	"strings"
)

// Version represents a kernel version with major, minor, and patch components.
type Version struct {
	Major int
	Minor int
	Patch int
}

// String returns the string representation of the kernel version.
func (v Version) String() string {
	return fmt.Sprintf("%d.%d.%d", v.Major, v.Minor, v.Patch)
}

// Compare compares two kernel versions.
// Returns -1 if v < other, 0 if v == other, 1 if v > other.
func (v Version) Compare(other Version) int {
	if v.Major != other.Major {
		if v.Major < other.Major {
			return -1
		}
		return 1
	}
	if v.Minor != other.Minor {
		if v.Minor < other.Minor {
			return -1
		}
		return 1
	}
	if v.Patch != other.Patch {
		if v.Patch < other.Patch {
			return -1
		}
		return 1
	}
	return 0
}

// AtLeast checks if the version is at least the specified minimum version.
func (v Version) AtLeast(min Version) bool {
	return v.Compare(min) >= 0
}

const (
	// MinKernelVersion is the minimum kernel version required for eBPF/XDP.
	// Linux 4.18+ is required for XDP and ringbuf support.
	MinKernelMajor = 4
	MinKernelMinor = 18
	MinKernelPatch = 0

	// RecommendedKernelVersion is the recommended kernel version for best stability.
	// Linux 5.1+ has more stable ringbuf support.
	RecommendedKernelMajor = 5
	RecommendedKernelMinor = 1
	RecommendedKernelPatch = 0
)

var (
	// MinVersion is the minimum required kernel version.
	MinVersion = Version{Major: MinKernelMajor, Minor: MinKernelMinor, Patch: MinKernelPatch}

	// RecommendedVersion is the recommended kernel version.
	RecommendedVersion = Version{Major: RecommendedKernelMajor, Minor: RecommendedKernelMinor, Patch: RecommendedKernelPatch}
)

// kernelVersionRegex matches kernel version strings like "5.15.0-91-generic".
var kernelVersionRegex = regexp.MustCompile(`^(\d+)\.(\d+)\.(\d+)`)

// GetKernelVersion reads and parses the kernel version from /proc/version.
// Returns an error if running on non-Linux systems.
func GetKernelVersion() (Version, error) {
	// Check if running on Linux
	if runtime.GOOS != "linux" {
		return Version{}, fmt.Errorf(
			"unsupported operating system: %s.\n"+
				"This application requires Linux (kernel 4.18+) for eBPF/XDP support.\n"+
				"macOS, Windows, and other operating systems are not supported.",
			runtime.GOOS)
	}

	data, err := os.ReadFile("/proc/version")
	if err != nil {
		return Version{}, fmt.Errorf("failed to read /proc/version: %w", err)
	}

	return ParseKernelVersion(string(data))
}

// ParseKernelVersion parses kernel version from the content of /proc/version.
// Example input: "Linux version 5.15.0-91-generic (buildd@lcy02-amd64-082) ..."
func ParseKernelVersion(content string) (Version, error) {
	// Extract version string (typically appears after "Linux version")
	parts := strings.Fields(content)
	for i, part := range parts {
		if part == "version" && i+1 < len(parts) {
			versionStr := parts[i+1]
			return parseVersionString(versionStr)
		}
	}

	// Fallback: try to find version pattern anywhere in the content
	matches := kernelVersionRegex.FindStringSubmatch(content)
	if matches != nil {
		return parseVersionMatches(matches)
	}

	return Version{}, fmt.Errorf("could not parse kernel version from content: %q (expected format: 'Linux version X.Y.Z')", content)
}

// parseVersionString parses a version string like "5.15.0-91-generic".
func parseVersionString(s string) (Version, error) {
	matches := kernelVersionRegex.FindStringSubmatch(s)
	if matches == nil {
		return Version{}, fmt.Errorf("invalid version string %q: expected format 'X.Y.Z' (e.g., '5.15.0')", s)
	}
	return parseVersionMatches(matches)
}

// parseVersionMatches converts regex matches to a Version struct.
func parseVersionMatches(matches []string) (Version, error) {
	if len(matches) < 4 {
		return Version{}, fmt.Errorf("invalid version matches: expected 4 elements (full match + 3 version parts), got %d: %v", len(matches), matches)
	}

	major, err := strconv.Atoi(matches[1])
	if err != nil {
		return Version{}, fmt.Errorf("invalid major version %q: %w", matches[1], err)
	}

	minor, err := strconv.Atoi(matches[2])
	if err != nil {
		return Version{}, fmt.Errorf("invalid minor version %q: %w", matches[2], err)
	}

	patch, err := strconv.Atoi(matches[3])
	if err != nil {
		return Version{}, fmt.Errorf("invalid patch version %q: %w", matches[3], err)
	}

	return Version{
		Major: major,
		Minor: minor,
		Patch: patch,
	}, nil
}

// CheckResult contains the result of a kernel version check.
type CheckResult struct {
	CurrentVersion    Version
	MinimumVersion    Version
	RecommendedVersion Version
	MeetsMinimum      bool
	MeetsRecommended  bool
}

// Check performs a kernel version check against the minimum and recommended versions.
func Check() (CheckResult, error) {
	current, err := GetKernelVersion()
	if err != nil {
		return CheckResult{}, err
	}

	return CheckResult{
		CurrentVersion:     current,
		MinimumVersion:     MinVersion,
		RecommendedVersion: RecommendedVersion,
		MeetsMinimum:       current.AtLeast(MinVersion),
		MeetsRecommended:   current.AtLeast(RecommendedVersion),
	}, nil
}

// CheckAndValidate checks the kernel version and returns an error if it doesn't meet requirements.
// The error message includes helpful information about the current and required versions.
// Returns CheckResult so callers can reuse the version information.
func CheckAndValidate() (CheckResult, error) {
	result, err := Check()
	if err != nil {
		return CheckResult{}, fmt.Errorf("failed to check kernel version: %w", err)
	}

	if !result.MeetsMinimum {
		return result, fmt.Errorf(
			"kernel version %s does not meet minimum requirements.\n"+
				"  Current:    %s\n"+
				"  Minimum:    %s (required for eBPF/XDP support)\n"+
				"  Recommended: %s (for best stability)\n"+
				"\n"+
				"Please upgrade your kernel to at least version %s to run this application.\n"+
				"eBPF/XDP features require Linux 4.18+ for ringbuf and XDP support.",
			result.CurrentVersion,
			result.CurrentVersion,
			result.MinimumVersion,
			result.RecommendedVersion,
			result.MinimumVersion,
		)
	}

	return result, nil
}
