//go:build !windows

package testpki

func restrict(string) error { return nil }
