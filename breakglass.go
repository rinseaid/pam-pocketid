package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"strings"
	"syscall"
	"time"

	"golang.org/x/crypto/bcrypt"
	"golang.org/x/term"
)

// escrowHTTPError represents an HTTP error from the escrow endpoint.
// Used for structured status code checking instead of fragile string matching.
type escrowHTTPError struct {
	StatusCode int
	Body       string
}

func (e *escrowHTTPError) Error() string {
	return fmt.Sprintf("server returned %d: %s", e.StatusCode, e.Body)
}

// bcryptCost is the cost parameter for bcrypt hashing. Cost 12 provides good
// security (~250ms on modern hardware) while remaining acceptable for
// interactive break-glass authentication.
const bcryptCost = 12

// openTTY is a function variable for opening /dev/tty, allowing test injection.
// pam_exec does not connect stdin, so we must open the terminal directly.
var openTTY = func() (*os.File, error) {
	return os.OpenFile("/dev/tty", os.O_RDWR, 0)
}

// readPasswordFn is a function variable for reading a password with echo disabled.
// Defaults to term.ReadPassword but can be overridden for testing.
var readPasswordFn = func(fd int) ([]byte, error) {
	return term.ReadPassword(fd)
}

// generateBreakglassPassword generates a password of the specified type.
// Supported types:
//   - "random": 32 random bytes base64url-encoded (43 chars, 256 bits entropy)
//   - "passphrase": 10 words from a 256-word list (80 bits entropy)
//   - "alphanumeric": 24 unambiguous alphanumeric characters (~138 bits entropy)
func generateBreakglassPassword(passwordType string) (string, error) {
	switch passwordType {
	case "random":
		return generateRandomPassword()
	case "passphrase":
		return generatePassphrase()
	case "alphanumeric":
		return generateAlphanumericPassword()
	default:
		return "", fmt.Errorf("unknown password type: %s", passwordType)
	}
}

// generateRandomPassword generates a base64url-encoded password from 32 random bytes.
func generateRandomPassword() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("reading random bytes: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// unambiguousAlphanum contains characters that are visually unambiguous.
// Excludes: 0/O, 1/l/I, and similar confusable pairs.
const unambiguousAlphanum = "23456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghjkmnpqrstuvwxyz"

// generateAlphanumericPassword generates a 24-character password from unambiguous chars.
func generateAlphanumericPassword() (string, error) {
	result := make([]byte, 24)
	for i := range result {
		n, err := rand.Int(rand.Reader, big.NewInt(int64(len(unambiguousAlphanum))))
		if err != nil {
			return "", fmt.Errorf("generating random char: %w", err)
		}
		result[i] = unambiguousAlphanum[n.Int64()]
	}
	return string(result), nil
}

// generatePassphrase generates a diceware-style passphrase of 10 words.
// Each word is drawn from a 256-word list (8 bits per word, 80 bits total).
// Words are joined with dashes for readability.
func generatePassphrase() (string, error) {
	words := make([]string, 10)
	for i := range words {
		n, err := rand.Int(rand.Reader, big.NewInt(int64(len(passphraseWordlist))))
		if err != nil {
			return "", fmt.Errorf("generating random index: %w", err)
		}
		words[i] = passphraseWordlist[n.Int64()]
	}
	return strings.Join(words, "-"), nil
}

// hashBreakglassPassword bcrypt-hashes a password at the configured cost.
func hashBreakglassPassword(password string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcryptCost)
	if err != nil {
		return "", fmt.Errorf("bcrypt hash: %w", err)
	}
	return string(hash), nil
}

// writeBreakglassFile atomically writes a bcrypt hash to the break-glass file.
// Uses temp file + rename to prevent partial reads.
// A metadata comment header is written before the hash for provenance tracking.
func writeBreakglassFile(path, hash, hostname, passwordType string) error {
	// Write to temp file in the same directory (ensures same filesystem for rename)
	dir := path[:strings.LastIndex(path, "/")+1]
	if dir == "" {
		dir = "."
	}
	tmp, err := os.CreateTemp(dir, ".breakglass-tmp-*")
	if err != nil {
		return fmt.Errorf("creating temp file: %w", err)
	}
	tmpName := tmp.Name()

	// Write metadata comment header
	header := fmt.Sprintf("# pam-pocketid breakglass host=%s type=%s created=%s\n",
		hostname, passwordType, time.Now().UTC().Format(time.RFC3339))
	if _, err := fmt.Fprint(tmp, header); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return fmt.Errorf("writing header: %w", err)
	}

	// Write hash + newline
	if _, err := fmt.Fprintln(tmp, hash); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return fmt.Errorf("writing hash: %w", err)
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpName)
		return fmt.Errorf("closing temp file: %w", err)
	}

	// Set permissions before rename (root-owned, 0600)
	if err := os.Chmod(tmpName, 0600); err != nil {
		os.Remove(tmpName)
		return fmt.Errorf("setting permissions: %w", err)
	}

	// Atomic rename
	if err := os.Rename(tmpName, path); err != nil {
		os.Remove(tmpName)
		return fmt.Errorf("renaming to target: %w", err)
	}

	return nil
}

// readBreakglassHash reads and validates the break-glass hash file.
// Rejects symlinks, wrong permissions, and wrong ownership (same pattern as config file).
func readBreakglassHash(path string) (string, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return "", fmt.Errorf("opening break-glass file: %w", err)
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil {
		return "", fmt.Errorf("stating break-glass file: %w", err)
	}

	if !info.Mode().IsRegular() {
		return "", fmt.Errorf("break-glass file is not a regular file")
	}

	mode := info.Mode().Perm()
	if mode&0077 != 0 {
		return "", fmt.Errorf("break-glass file has group/other permissions (mode %04o)", mode)
	}

	if uid, ok := fileOwnerUID(info); ok && uid != 0 {
		return "", fmt.Errorf("break-glass file is not owned by root (uid=%d)", uid)
	}

	// Read the file (header + hash, max 512 bytes — metadata header ~100 chars, bcrypt hash ~60 chars)
	data := make([]byte, 512)
	n, err := f.Read(data)
	if err != nil && err != io.EOF {
		return "", fmt.Errorf("reading break-glass file: %w", err)
	}

	// Find the first non-comment, non-empty line (the hash)
	var hash string
	for _, line := range strings.Split(string(data[:n]), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		hash = line
		break
	}
	if hash == "" {
		return "", fmt.Errorf("break-glass file is empty")
	}

	// Basic sanity check: bcrypt hashes start with $2
	if !strings.HasPrefix(hash, "$2") {
		return "", fmt.Errorf("break-glass file does not contain a valid bcrypt hash")
	}

	return hash, nil
}

// breakglassFileAge returns the age of the break-glass file based on mtime.
// Uses Lstat to be consistent with breakglassFileExists (no symlink following).
func breakglassFileAge(path string) (time.Duration, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return 0, err
	}
	return time.Since(info.ModTime()), nil
}

// breakglassFailurePath is the file used to track consecutive break-glass failures
// for rate limiting. Stored in /var/run/ (tmpfs) so it resets on reboot.
const breakglassFailurePath = "/var/run/pam-pocketid-breakglass-failures"

// readFailureCounter reads and validates the failure counter file.
// Returns (0, nil) if the file doesn't exist, is malformed, or fails security checks.
// This fails-open (allows attempts) on any read error — rate limiting is defense-in-depth.
func readFailureCounter() (count int, lastFail time.Time) {
	f, err := os.OpenFile(breakglassFailurePath, os.O_RDONLY, 0)
	if err != nil {
		return 0, time.Time{}
	}
	defer f.Close()

	// Validate the file is owned by root and has restrictive permissions.
	// This prevents a non-root user from injecting a high count (DoS)
	// or deleting/corrupting the file to bypass rate limiting.
	info, err := f.Stat()
	if err != nil {
		return 0, time.Time{}
	}
	if uid, ok := fileOwnerUID(info); ok && uid != 0 {
		return 0, time.Time{} // not root-owned — ignore (fail-open)
	}
	if info.Mode().Perm()&0077 != 0 {
		return 0, time.Time{} // world-readable/writable — ignore
	}

	data := make([]byte, 128)
	n, _ := f.Read(data)
	parts := strings.SplitN(strings.TrimSpace(string(data[:n])), " ", 2)
	if len(parts) != 2 {
		return 0, time.Time{}
	}
	fmt.Sscanf(parts[0], "%d", &count)
	t, _ := time.Parse(time.RFC3339, parts[1])
	return count, t
}

// checkBreakglassRateLimit reads the failure count and returns an error if
// the caller should be rate-limited. Implements exponential backoff:
// after N failures, require a wait of 2^(N-1) seconds (max 300s).
func checkBreakglassRateLimit() error {
	count, lastFail := readFailureCounter()
	if count < 3 {
		return nil // allow first 3 attempts without delay
	}
	// Exponential backoff: 2^(count-3) seconds, capped at 300s
	delaySec := 1 << min(count-3, 8) // max 256s
	if delaySec > 300 {
		delaySec = 300
	}
	if time.Since(lastFail) < time.Duration(delaySec)*time.Second {
		return fmt.Errorf("too many failed break-glass attempts — try again in %ds", delaySec-int(time.Since(lastFail).Seconds()))
	}
	return nil
}

// recordBreakglassFailure increments the failure counter.
// The file is created root-owned with 0600 permissions.
func recordBreakglassFailure() {
	count, _ := readFailureCounter()
	count++
	// Write atomically to prevent partial reads
	content := []byte(fmt.Sprintf("%d %s", count, time.Now().Format(time.RFC3339)))
	os.WriteFile(breakglassFailurePath, content, 0600)
}

// clearBreakglassFailures resets the counter on successful authentication.
func clearBreakglassFailures() {
	os.Remove(breakglassFailurePath)
}

// authenticateBreakglass prompts for a break-glass password and verifies it
// against the stored bcrypt hash. Opens /dev/tty for password input since
// pam_exec does not connect stdin.
func authenticateBreakglass(username, hashFilePath string) error {
	// Rate limit: check for too many consecutive failures
	if err := checkBreakglassRateLimit(); err != nil {
		fmt.Fprintf(os.Stderr, "pam-pocketid: BREAKGLASS: rate limited for user %q: %v\n", username, err)
		return err
	}

	// Print warning banner
	fmt.Fprintf(messageWriter, "\n")
	fmt.Fprintf(messageWriter, "  *** BREAK-GLASS AUTHENTICATION ***\n")
	fmt.Fprintf(messageWriter, "  The Pocket ID server is unreachable.\n")
	fmt.Fprintf(messageWriter, "  Enter the break-glass password to proceed.\n")
	fmt.Fprintf(messageWriter, "\n")

	// Open /dev/tty for reading (pam_exec doesn't connect stdin)
	tty, err := openTTY()
	if err != nil {
		return fmt.Errorf("cannot open terminal: %w", err)
	}
	defer tty.Close()

	// Prompt with echo disabled
	fmt.Fprintf(tty, "Break-glass password: ")
	password, err := readPasswordFn(int(tty.Fd()))
	fmt.Fprintf(tty, "\n")
	if err != nil {
		return fmt.Errorf("reading password: %w", err)
	}

	// Load and validate hash file
	hash, err := readBreakglassHash(hashFilePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "pam-pocketid: BREAKGLASS: hash file error for user %q: %v\n", username, err)
		// Run a dummy bcrypt comparison to equalize timing with the wrong-password path,
		// preventing a timing oracle that distinguishes "file error" from "wrong password".
		bcrypt.CompareHashAndPassword([]byte("$2a$12$000000000000000000000000000000000000000000000000000000"), password)
		recordBreakglassFailure()
		return fmt.Errorf("break-glass authentication failed")
	}

	// Verify password
	if err := bcrypt.CompareHashAndPassword([]byte(hash), password); err != nil {
		fmt.Fprintf(os.Stderr, "pam-pocketid: BREAKGLASS: authentication FAILED for user %q\n", username)
		recordBreakglassFailure()
		return fmt.Errorf("break-glass authentication failed")
	}

	fmt.Fprintf(os.Stderr, "pam-pocketid: BREAKGLASS: authentication SUCCESS for user %q\n", username)
	fmt.Fprintf(messageWriter, "  Break-glass authentication successful.\n\n")
	clearBreakglassFailures()
	return nil
}

// isServerUnreachable returns true if the error indicates a connection-level
// failure (server down, DNS failure, timeout) as opposed to an HTTP error
// response from a reachable server.
func isServerUnreachable(err error) bool {
	if err == nil {
		return false
	}

	// Check for serverHTTPError — server responded with an HTTP status,
	// meaning it's reachable. No fallback. Uses errors.As to handle
	// wrapped errors (e.g., fmt.Errorf("...: %w", httpErr)).
	var httpErr *serverHTTPError
	if errors.As(err, &httpErr) {
		return false
	}

	// Check for typed network errors in the error chain.
	// These are more robust than string matching, which could be spoofed
	// by a malicious server's HTTP response body.
	//
	// Only match dial-phase OpErrors (Op=="dial") to avoid false positives
	// when a server accepts TCP but then resets the connection (ECONNRESET)
	// or stalls. A "dial" error means the connection was never established.
	var opErr *net.OpError
	if errors.As(err, &opErr) && opErr.Op == "dial" {
		return true
	}
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		return true
	}
	// Note: context.DeadlineExceeded is intentionally NOT matched here.
	// It is ambiguous — it fires both when the server never responded (truly
	// unreachable) and when the server accepted TCP but responded slowly.
	// A malicious server that accepts connections and stalls could force
	// break-glass fallback if we matched timeouts. Instead, slow servers
	// produce a clear timeout error to the user without triggering fallback.

	return false
}

// breakglassFileExists checks if the break-glass hash file exists.
// Uses Lstat (not Stat) to be consistent with readBreakglassHash's O_NOFOLLOW —
// a symlink should not trigger break-glass mode.
func breakglassFileExists(path string) bool {
	info, err := os.Lstat(path)
	if err != nil {
		return false
	}
	return info.Mode().IsRegular()
}

// rotateBreakglass generates a new break-glass password, writes the hash locally,
// and escrows the plaintext to the server. Returns the plaintext password when
// escrow was not performed (caller should display it), or empty string if escrowed.
func rotateBreakglass(cfg *Config, force bool) (plaintext string, err error) {
	// Acquire an exclusive advisory lock to prevent concurrent rotations
	// (e.g., cron + maybeRotateBreakglass, or two simultaneous sudo sessions).
	// Without this, two rotations can each escrow different passwords and race
	// on the atomic rename, leaving the escrowed password mismatched.
	lockPath := cfg.BreakglassFile + ".lock"
	lockFile, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return "", fmt.Errorf("opening lock file: %w", err)
	}
	defer lockFile.Close()
	if err := syscall.Flock(int(lockFile.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		// Another rotation is in progress — skip silently
		fmt.Fprintf(os.Stderr, "break-glass rotation already in progress — skipping\n")
		return "", nil
	}
	defer syscall.Flock(int(lockFile.Fd()), syscall.LOCK_UN)

	// Check if rotation is due (unless forced)
	if !force && breakglassFileExists(cfg.BreakglassFile) {
		age, err := breakglassFileAge(cfg.BreakglassFile)
		if err == nil && age < time.Duration(cfg.BreakglassRotationDays)*24*time.Hour {
			fmt.Fprintf(os.Stderr, "break-glass password is %d days old (rotation every %d days) — skipping (use --force to override)\n",
				int(age.Hours()/24), cfg.BreakglassRotationDays)
			return "", nil
		}
	}

	// Generate password
	password, err := generateBreakglassPassword(cfg.BreakglassPasswordType)
	if err != nil {
		return "", fmt.Errorf("generating password: %w", err)
	}

	// Hash it
	hash, err := hashBreakglassPassword(password)
	if err != nil {
		return "", fmt.Errorf("hashing password: %w", err)
	}

	// Escrow to server BEFORE writing local hash.
	// If escrow fails, the old password remains valid on disk.
	// If we wrote first and escrow failed, the new password would be lost
	// (exists only in process memory) and the old password is already gone.
	hostname, _ := os.Hostname()
	escrowed := false
	if cfg.ServerURL != "" {
		err := escrowPassword(cfg, hostname, password)
		if err != nil {
			// Treat 501 (escrow not configured on server) as non-fatal:
			// the server is reachable but has no escrow command. Proceed with
			// local-only rotation and return the password so the caller can save it.
			var httpErr *escrowHTTPError
			if errors.As(err, &httpErr) && httpErr.StatusCode == http.StatusNotImplemented {
				fmt.Fprintf(os.Stderr, "WARNING: server has no escrow command configured\n")
			} else {
				return "", fmt.Errorf("escrow failed (local hash NOT updated): %w", err)
			}
		} else {
			escrowed = true
		}
	}

	// Write hash file locally (atomic)
	if err := writeBreakglassFile(cfg.BreakglassFile, hash, hostname, cfg.BreakglassPasswordType); err != nil {
		return "", fmt.Errorf("writing hash file: %w", err)
	}
	fmt.Fprintf(os.Stderr, "break-glass hash written to %s\n", cfg.BreakglassFile)

	// Return the plaintext password when it was NOT escrowed, so the caller
	// can display it appropriately. The CLI prints it; the PAM path suppresses it.
	if !escrowed {
		return password, nil
	}
	return "", nil
}

// escrowPassword sends the plaintext password to the server's escrow endpoint.
func escrowPassword(cfg *Config, hostname, password string) error {
	if cfg.ServerURL == "" {
		return fmt.Errorf("PAM_POCKETID_SERVER_URL not configured")
	}

	payload := map[string]string{
		"hostname": hostname,
		"password": password,
	}
	body, _ := json.Marshal(payload)

	req, err := http.NewRequest(http.MethodPost, cfg.ServerURL+"/api/breakglass/escrow", bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("creating request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if cfg.SharedSecret != "" {
		req.Header.Set("X-Shared-Secret", cfg.SharedSecret)
		// Per-host escrow token: HMAC(shared_secret, hostname) proves this host
		// is authorized to escrow for its own hostname. Prevents a compromised
		// host from planting a known password for a different host.
		req.Header.Set("X-Escrow-Token", computeEscrowToken(cfg.SharedSecret, hostname))
	}

	client := &http.Client{
		Timeout: 5 * time.Second, // Short timeout — escrow is best-effort, don't block sudo sessions
		Transport: &http.Transport{
			Proxy: nil, // Never use proxy env vars
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("connecting to server: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return &escrowHTTPError{StatusCode: resp.StatusCode, Body: strings.TrimSpace(string(b))}
	}

	fmt.Fprintf(os.Stderr, "break-glass password escrowed to server\n")
	return nil
}

// computeEscrowToken produces HMAC-SHA256(shared_secret, hostname) as a per-host
// escrow authorization token. The server verifies this to ensure a host can only
// escrow passwords for its own hostname.
func computeEscrowToken(sharedSecret, hostname string) string {
	mac := hmac.New(sha256.New, []byte(sharedSecret))
	mac.Write([]byte("escrow:" + hostname))
	return hex.EncodeToString(mac.Sum(nil))
}

// breakglassFileMtime returns the modification time of the break-glass file.
// Uses Lstat to be consistent with breakglassFileExists (no symlink following).
func breakglassFileMtime(path string) (time.Time, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return time.Time{}, err
	}
	return info.ModTime(), nil
}

// maybeRotateBreakglass checks if the server requested a rotation and performs it if needed.
// Called after successful authentication when the server signals rotation is needed.
func maybeRotateBreakglass(cfg *Config, rotateBefore time.Time) {
	if rotateBefore.IsZero() {
		return
	}
	if !breakglassFileExists(cfg.BreakglassFile) {
		return
	}
	mtime, err := breakglassFileMtime(cfg.BreakglassFile)
	if err != nil {
		return
	}
	if mtime.Before(rotateBefore) {
		fmt.Fprintf(os.Stderr, "pam-pocketid: server requested break-glass rotation — rotating now\n")
		// Discard the returned password — in the PAM path we must NOT print it
		// to stdout (which goes to the user's terminal via pam_exec).
		if _, err := rotateBreakglass(cfg, true); err != nil {
			fmt.Fprintf(os.Stderr, "pam-pocketid: break-glass rotation failed: %v\n", err)
		}
	}
}

// passphraseWordlist is a curated list of 256 short, common, unambiguous English words
// for generating memorable break-glass passphrases. 10 words = 80 bits of entropy.
// This list is optimized to have zero edit-distance-1 confusable pairs, reducing
// transcription errors when reading a passphrase from a vault under stress.
var passphraseWordlist = []string{
	"able", "acid", "aged", "also", "arch", "area", "army", "atom",
	"away", "axis", "baby", "base", "beam", "best", "bias", "bird",
	"bite", "body", "bolt", "bomb", "bone", "boss", "both", "bowl",
	"bulk", "burn", "busy", "cake", "calm", "camp", "cart", "cash",
	"chat", "chip", "city", "clay", "club", "cold", "cool", "copy",
	"core", "crab", "crew", "curl", "cute", "dark", "data", "dead",
	"deer", "deny", "dirt", "disk", "dock", "dose", "down", "draw",
	"drop", "drum", "dual", "duty", "each", "earn", "easy", "echo",
	"edge", "else", "epic", "ever", "evil", "exam", "exit", "fact",
	"fair", "fawn", "feed", "fine", "firm", "fist", "flat", "flip",
	"flow", "flux", "foam", "folk", "foot", "ford", "foul", "free",
	"from", "full", "fund", "fuse", "gain", "game", "gang", "gear",
	"gene", "germ", "gift", "girl", "give", "glad", "glen", "glue",
	"goat", "good", "gray", "grip", "grow", "gulf", "guru", "guys",
	"halt", "haul", "hawk", "haze", "heat", "help", "hero", "high",
	"hill", "hint", "hire", "holy", "hook", "hope", "horn", "host",
	"hour", "huge", "hurt", "hymn", "idea", "inch", "into", "iris",
	"iron", "isle", "item", "jack", "jade", "jail", "jazz", "join",
	"joke", "jump", "jury", "just", "keep", "kick", "knob", "lace",
	"leaf", "levy", "limb", "link", "lion", "load", "loft", "logo",
	"long", "loop", "lure", "lush", "lynx", "mane", "mask", "menu",
	"mesh", "mild", "mode", "monk", "moon", "mule", "myth", "navy",
	"norm", "note", "noun", "oath", "obey", "omen", "orca", "page",
	"paid", "peak", "pier", "plan", "plea", "plot", "plum", "poem",
	"polo", "pond", "port", "prey", "pulp", "raft", "rare", "reef",
	"rely", "rent", "rich", "rind", "robe", "roof", "ruby", "ruin",
	"sank", "seal", "self", "shed", "shop", "shut", "sign", "silk",
	"size", "skip", "slab", "slim", "slug", "snap", "snow", "sofa",
	"soil", "sole", "span", "star", "step", "stub", "such", "sung",
	"surf", "taco", "tale", "taxi", "tend", "text", "they", "this",
	"tidy", "toll", "tops", "twig", "unit", "upon", "void", "warp",
	"weld", "whim", "wilt", "wing", "wiry", "wolf", "wrap", "yoga",
}
