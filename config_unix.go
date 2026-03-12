//go:build !windows

package main

import (
	"os"
	"syscall"
)

// fileOwnerUID returns the UID of the file owner on Unix systems.
// This is a variable so tests can override it (tests run as non-root).
var fileOwnerUID = fileOwnerUIDImpl

func fileOwnerUIDImpl(info os.FileInfo) (uint32, bool) {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, false
	}
	return stat.Uid, true
}
