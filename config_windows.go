//go:build windows

package main

import "os"

// fileOwnerUID is a no-op on Windows — ownership checks are not applicable.
// This is a variable to match the Unix signature (tests can override it).
var fileOwnerUID = func(info os.FileInfo) (uint32, bool) {
	return 0, false
}
