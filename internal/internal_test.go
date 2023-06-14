package internal

import (
	"testing"
)

func TestParsePlatformAndSegment(t *testing.T) {
	tests := []struct {
		in           string
		wantPlatform []byte
		wantSegment  []byte
	}{
		{"CBL-Mariner 1.0", []byte("CBL-Mariner"), []byte("1.0")},
		{"Oracle Linux 5", []byte("Oracle Linux"), []byte("5")},
		{"Photon OS 1.0", []byte("Photon OS"), []byte("1.0")},
		{"Red Hat", []byte("Red Hat"), []byte("")},
		{"Red Hat CPE", []byte("Red Hat CPE"), []byte("")},
		{"SUSE Linux Enterprise 11.2", []byte("SUSE Linux Enterprise"), []byte("11.2")},
		{"alma 9", []byte("alma"), []byte("9")},
		{"alpine 3.15", []byte("alpine"), []byte("3.15")},
		{"alpine edge", []byte("alpine"), []byte("edge")},
		{"amazon linux 2023", []byte("amazon linux"), []byte("2023")},
		{"archlinux", []byte("archlinux"), []byte("")},
		{"cargo::GitHub Security Advisory Rust", []byte("cargo::GitHub Security Advisory Rust"), []byte("")},
		{"chainguard", []byte("chainguard"), []byte("")},
		{"composer::GitHub Security Advisory Composer", []byte("composer::GitHub Security Advisory Composer"), []byte("")},
		{"composer::PHP Security Advisories Database", []byte("composer::PHP Security Advisories Database"), []byte("")},
		{"conan::GitLab Advisory Database Community", []byte("conan::GitLab Advisory Database Community"), []byte("")},
		{"debian 12", []byte("debian"), []byte("12")},
		{"erlang::GitHub Security Advisory Erlang", []byte("erlang::GitHub Security Advisory Erlang"), []byte("")},
		{"go::GitHub Security Advisory Go", []byte("go::GitHub Security Advisory Go"), []byte("")},
		{"go::The Go Vulnerability Database", []byte("go::The Go Vulnerability Database"), []byte("")},
		{"maven::GitHub Security Advisory Maven", []byte("maven::GitHub Security Advisory Maven"), []byte("")},
		{"maven::GitLab Advisory Database Community", []byte("maven::GitLab Advisory Database Community"), []byte("")},
		{"npm::GitHub Security Advisory Npm", []byte("npm::GitHub Security Advisory Npm"), []byte("")},
		{"npm::Node.js Ecosystem Security Working Group", []byte("npm::Node.js Ecosystem Security Working Group"), []byte("")},
		{"nuget::GitHub Security Advisory Nuget", []byte("nuget::GitHub Security Advisory Nuget"), []byte("")},
		{"openSUSE Leap 42.3", []byte("openSUSE Leap"), []byte("42.3")},
		{"pip::GitHub Security Advisory Pip", []byte("pip::GitHub Security Advisory Pip"), []byte("")},
		{"pip::Open Source Vulnerability", []byte("pip::Open Source Vulnerability"), []byte("")},
		{"pub::GitHub Security Advisory Pub", []byte("pub::GitHub Security Advisory Pub"), []byte("")},
		{"rocky 9", []byte("rocky"), []byte("9")},
		{"rubygems::GitHub Security Advisory Rubygems", []byte("rubygems::GitHub Security Advisory Rubygems"), []byte("")},
		{"rubygems::Ruby Advisory Database", []byte("rubygems::Ruby Advisory Database"), []byte("")},
		{"ubuntu 12.04", []byte("ubuntu"), []byte("12.04")},
		{"ubuntu 12.04-ESM", []byte("ubuntu"), []byte("12.04-ESM")},
		{"ubuntu 16.04-ESM", []byte("ubuntu"), []byte("16.04-ESM")},
		{"ubuntu 23.04", []byte("ubuntu"), []byte("23.04")},
		{"wolfi", []byte("wolfi"), []byte("")},
	}
	for _, tt := range tests {
		gotPlatform, gotSegment := parsePlatformAndSegment(tt.in)
		if string(gotPlatform) != string(tt.wantPlatform) {
			t.Errorf("parsePlatformAndSegment(%s) gotPlatform = %s, want %s", tt.in, gotPlatform, tt.wantPlatform)
		}
		if string(gotSegment) != string(tt.wantSegment) {
			t.Errorf("parsePlatformAndSegment(%s) gotSegment = %s, want %s", tt.in, gotSegment, tt.wantSegment)
		}
	}
}
