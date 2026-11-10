//go:build windows

package testpki

import "github.com/hostinger/hcdn-connector/internal/winacl"

// The temp directory DACL is inherited; the credentials check needs owner-only.
func restrict(p string) error { return winacl.Restrict(p) }
