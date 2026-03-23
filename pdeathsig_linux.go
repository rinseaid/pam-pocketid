package main

import "syscall"

// requestParentDeathSignal asks the kernel to send SIGTERM to this process
// when the parent process dies. This allows pam-pocketid to exit cleanly
// when sudo is killed (e.g., from another terminal via `kill`), since the
// PAM child is not in the terminal's foreground process group and does not
// receive SIGINT from Ctrl+C directly.
//
// Note: Ctrl+C during the polling phase is not reliably detectable because:
// - SIGINT goes to sudo's process group, not to pam-pocketid
// - pam_exec does not give the child a controlling terminal (/dev/tty)
// - sudo does not exit on SIGINT (it waits for PAM to finish)
// - The stdin pipe from pam_exec may close unpredictably
//
// The PPID polling fallback in pamclient.go handles the case where sudo
// is killed externally.
func requestParentDeathSignal() {
	syscall.RawSyscall(syscall.SYS_PRCTL, syscall.PR_SET_PDEATHSIG, uintptr(syscall.SIGTERM), 0)
}
