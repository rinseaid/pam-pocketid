//go:build !linux

package main

// requestParentDeathSignal is a no-op on non-Linux systems.
// The polling loop's parent-alive check provides the fallback.
func requestParentDeathSignal() {}
