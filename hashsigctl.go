//go:build windows && amd64

package main

// hashsigctl — Hash and Authenticode signature verification (read-only).
// Single-file, standard-library-only build:
//
//   go build -trimpath -ldflags "-s -w" -o hashsigctl.exe hashsigctl.go
//
// Log: ./hashsigctl_backup/hashsigctl.log  [cmd] [ts] [exit code]

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"debug/pe"
	"encoding/asn1"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"
)

// ============================================================================
// Colors
// ============================================================================

const (
	clrReset  = "\x1b[0m"
	clrBold   = "\x1b[1m"
	clrRed    = "\x1b[31m"
	clrGreen  = "\x1b[32m"
	clrYellow = "\x1b[33m"
	clrCyan   = "\x1b[36m"
	clrGray   = "\x1b[90m"
)

var (
	useColor      = false
	dryRun        = false
	noColorFlag   = false
	outputCleanup func()
)

func c(code, s string) string {
	if !useColor {
		return s
	}
	return code + s + clrReset
}

// ============================================================================
// Console detection
// ============================================================================

const (
	STD_INPUT_HANDLE  = ^uint32(9)
	STD_OUTPUT_HANDLE = ^uint32(11)
)

var (
	kernel32 = syscall.NewLazyDLL("kernel32.dll")
	wintrust = syscall.NewLazyDLL("wintrust.dll")
	crypt32  = syscall.NewLazyDLL("crypt32.dll")

	pGetStdHandle   = kernel32.NewProc("GetStdHandle")
	pGetConsoleMode = kernel32.NewProc("GetConsoleMode")

	pWinVerifyTrust = wintrust.NewProc("WinVerifyTrust")

	pCryptQueryObject = crypt32.NewProc("CryptQueryObject")
	pCertGetNameStringW = crypt32.NewProc("CertGetNameStringW")
	pCertFreeCertificateContext = crypt32.NewProc("CertFreeCertificateContext")
	pCertCloseStore = crypt32.NewProc("CertCloseStore")
)

func isConsole(which uint32) bool {
	h, _, _ := pGetStdHandle.Call(uintptr(which))
	if h == 0 {
		return false
	}
	var mode uint32
	r, _, _ := pGetConsoleMode.Call(h, uintptr(unsafe.Pointer(&mode)))
	return r != 0
}

func stdoutIsTTY() bool { return isConsole(STD_OUTPUT_HANDLE) }

// ============================================================================
// Bug collector
// ============================================================================

type bugEntry struct {
	At    time.Time
	Level string
	Msg   string
}

type bugCollector struct {
	mu      sync.Mutex
	entries []bugEntry
	enabled bool
}

var bugs = &bugCollector{}

func (b *bugCollector) Add(level, format string, args ...any) {
	if !b.enabled {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	b.entries = append(b.entries, bugEntry{At: time.Now(), Level: level, Msg: fmt.Sprintf(format, args...)})
}

func (b *bugCollector) Flush() {
	b.mu.Lock()
	defer b.mu.Unlock()
	if !b.enabled {
		return
	}
	if len(b.entries) == 0 {
		fmt.Fprintln(os.Stderr, "[hashsigctl] -b/--bugs enabled: no errors or warnings captured this run.")
		return
	}
	fmt.Fprintf(os.Stderr, "\n--- hashsigctl bugs report (%d entries) ---\n", len(b.entries))
	for _, e := range b.entries {
		fmt.Fprintf(os.Stderr, "[%s] %s %s\n", e.At.Format("15:04:05.000"), e.Level, e.Msg)
	}
	fmt.Fprintln(os.Stderr, "--- end of bugs report ---")
}

// ============================================================================
// WinTrust structures
// ============================================================================

// GUID represents a Windows GUID. We only need the VERIFY_V2 action id, so
// we hardcode its bytes and never need string parsing.
type GUID struct {
	Data1 uint32
	Data2 uint16
	Data3 uint16
	Data4 [8]byte
}

// WINTRUST_ACTION_GENERIC_VERIFY_V2 = {00AAC56B-CD44-11d0-8CC2-00C04FC295EE}
var winTrustActionVerifyV2 = GUID{
	Data1: 0x00AAC56B,
	Data2: 0xCD44,
	Data3: 0x11D0,
	Data4: [8]byte{0x8C, 0xC2, 0x00, 0xC0, 0x4F, 0xC2, 0x95, 0xEE},
}

const (
	WTD_UI_NONE              = 2
	WTD_REVOKE_NONE          = 0
	WTD_CHOICE_FILE          = 1
	WTD_STATEACTION_VERIFY   = 1
	WTD_STATEACTION_CLOSE    = 2
	WTD_SAFER_FLAG           = 0x100
	WTD_REVOCATION_CHECK_NONE = 0x10

	WTD_PROV_FLAGS_MASK = 0x0000FFFF

	TRUST_E_NOSIGNATURE       = 0x800B0100
	TRUST_E_SUBJECT_FORM_UNKNOWN = 0x800B0003
	TRUST_E_PROVIDER_UNKNOWN  = 0x800B0001
	TRUST_E_EXPLICIT_DISTRUST = 0x800B0111
	TRUST_E_SUBJECT_NOT_TRUSTED = 0x800B0004
	TRUST_E_BAD_DIGEST        = 0x80096010
	CERT_E_UNTRUSTEDROOT      = 0x800B0109
	CERT_E_CHAINING           = 0x800B010A
	CERT_E_EXPIRED            = 0x800B0101
)

// WINTRUST_FILE_INFO is the "file" variant of the union inside WINTRUST_DATA.
type WINTRUST_FILE_INFO struct {
	CbStruct       uint32
	PcwszFilePath  *uint16
	HFile          syscall.Handle
	PgKnownSubject *GUID
}

// WINTRUST_DATA is the same layout for 32-bit and 64-bit Windows; the only
// difference is pointer size, which Go handles automatically.
type WINTRUST_DATA struct {
	CbStruct          uint32
	PolicyCallbackData uintptr
	SIPClientData     uintptr
	DwUIChoice        uint32
	FdwRevocationChecks uint32
	DwUnionChoice     uint32
	PFile             uintptr // *WINTRUST_FILE_INFO when DwUnionChoice == WTD_CHOICE_FILE
	DwStateAction     uint32
	HWVTStateData     syscall.Handle
	PwszURLReference  *uint16
	DwProvFlags       uint32
	DwUIContext       uint32
}

// ============================================================================
// WinTrust verification
// ============================================================================

type sigResult struct {
	Status     string   `json:"status"` // valid | invalid | unsigned | error
	Reason     string   `json:"reason,omitempty"`
	Signer     string   `json:"signer,omitempty"`
	Issuer     string   `json:"issuer,omitempty"`
	ChainNotes []string `json:"chainNotes,omitempty"`
}

// verifyAuthenticode calls WinVerifyTrust with the standard Authenticode
// action id. It reports success (nil error), TRUST_E_NOSIGNATURE when the
// file is unsigned, and any other trust error otherwise.
func verifyAuthenticode(path string) (sigResult, error) {
	pathPtr, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return sigResult{Status: "error", Reason: err.Error()}, err
	}

	fileInfo := WINTRUST_FILE_INFO{
		CbStruct:      uint32(unsafe.Sizeof(WINTRUST_FILE_INFO{})),
		PcwszFilePath: pathPtr,
	}
	data := WINTRUST_DATA{
		CbStruct:            uint32(unsafe.Sizeof(WINTRUST_DATA{})),
		DwUIChoice:          WTD_UI_NONE,
		FdwRevocationChecks: WTD_REVOKE_NONE,
		DwUnionChoice:       WTD_CHOICE_FILE,
		PFile:               uintptr(unsafe.Pointer(&fileInfo)),
		DwStateAction:       WTD_STATEACTION_VERIFY,
		DwProvFlags:         WTD_SAFER_FLAG,
	}

	ret, _, _ := pWinVerifyTrust.Call(
		uintptr(0),
		uintptr(unsafe.Pointer(&winTrustActionVerifyV2)),
		uintptr(unsafe.Pointer(&data)),
	)

	// Always close the state, even on failure, so we don't leak handles.
	defer func() {
		data.DwStateAction = WTD_STATEACTION_CLOSE
		pWinVerifyTrust.Call(
			uintptr(0),
			uintptr(unsafe.Pointer(&winTrustActionVerifyV2)),
			uintptr(unsafe.Pointer(&data)),
		)
	}()

	code := uint32(ret)
	switch code {
	case 0:
		return sigResult{Status: "valid"}, nil
	case TRUST_E_NOSIGNATURE:
		return sigResult{Status: "unsigned", Reason: "no Authenticode signature"}, nil
	case TRUST_E_BAD_DIGEST:
		return sigResult{Status: "invalid", Reason: "digest mismatch (file has been modified)"}, nil
	case TRUST_E_EXPLICIT_DISTRUST:
		return sigResult{Status: "invalid", Reason: "signature is explicitly distrusted"}, nil
	case TRUST_E_SUBJECT_NOT_TRUSTED:
		return sigResult{Status: "invalid", Reason: "subject is not trusted"}, nil
	case CERT_E_UNTRUSTEDROOT:
		return sigResult{Status: "invalid", Reason: "certificate chain ends at an untrusted root"}, nil
	case CERT_E_CHAINING:
		return sigResult{Status: "invalid", Reason: "certificate chain could not be built"}, nil
	case CERT_E_EXPIRED:
		return sigResult{Status: "invalid", Reason: "certificate has expired"}, nil
	case TRUST_E_SUBJECT_FORM_UNKNOWN, TRUST_E_PROVIDER_UNKNOWN:
		return sigResult{Status: "error", Reason: "WinVerifyTrust cannot determine the subject form"}, nil
	}
	return sigResult{
		Status: "invalid",
		Reason: fmt.Sprintf("WinVerifyTrust returned 0x%08X", code),
	}, nil
}

// extractSigner attempts to pull the signer's display name and issuer out of
// the file's embedded PKCS#7 signature. It uses CryptQueryObject to locate the
// certificate and CertGetNameStringW to render the subject/issuer into a
// string. Any failure is non-fatal: the caller still has the trust verdict
// from verifyAuthenticode.
func extractSigner(path string) (signer, issuer string, notes []string) {
	pathPtr, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return "", "", nil
	}

	const (
		CERT_QUERY_OBJECT_FILE = 1
		CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED = 1 << 10
		CERT_QUERY_FORMAT_FLAG_BINARY = 1 << 1
	)

	var encodingType, contentType, formatType uint32
	var store syscall.Handle
	var msg syscall.Handle
	var certContext uintptr

	r, _, _ := pCryptQueryObject.Call(
		uintptr(CERT_QUERY_OBJECT_FILE),
		uintptr(unsafe.Pointer(pathPtr)),
		uintptr(CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED),
		uintptr(CERT_QUERY_FORMAT_FLAG_BINARY),
		0,
		uintptr(unsafe.Pointer(&encodingType)),
		uintptr(unsafe.Pointer(&contentType)),
		uintptr(unsafe.Pointer(&formatType)),
		uintptr(unsafe.Pointer(&store)),
		uintptr(unsafe.Pointer(&msg)),
		uintptr(unsafe.Pointer(&certContext)),
	)
	if r == 0 {
		return "", "", nil
	}

	if store != 0 {
		defer pCertCloseStore.Call(uintptr(store), 0)
	}
	if certContext != 0 {
		defer pCertFreeCertificateContext.Call(certContext)
	}

	if certContext == 0 {
		return "", "", []string{"no signer certificate context"}
	}

	// CERT_NAME_SIMPLE_DISPLAY_TYPE == 4
	signer = certNameString(certContext, 4)
	issuer = certNameString(certContext, 4) // same type but applied to Issuer
	// CertGetNameStringW with CERT_NAME_ISSUER_FLAG (0x1) reads the issuer.
	issuer = certNameStringFlags(certContext, 4, 0x1)

	return signer, issuer, nil
}

func certNameString(certCtx uintptr, nameType uint32) string {
	return certNameStringFlags(certCtx, nameType, 0)
}

func certNameStringFlags(certCtx uintptr, nameType, flags uint32) string {
	// First call with size 0 to discover the required length.
	n, _, _ := pCertGetNameStringW.Call(
		certCtx,
		uintptr(nameType),
		uintptr(flags),
		0,
		0,
		0,
	)
	if n <= 1 {
		return ""
	}
	buf := make([]uint16, n)
	r, _, _ := pCertGetNameStringW.Call(
		certCtx,
		uintptr(nameType),
		uintptr(flags),
		0,
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(n),
	)
	if r == 0 {
		return ""
	}
	return syscall.UTF16ToString(buf)
}

// ============================================================================
// Hash computation
// ============================================================================

type hashResult struct {
	MD5    string `json:"md5"`
	SHA1   string `json:"sha1"`
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
}

func hashFile(path string) (hashResult, error) {
	f, err := os.Open(path)
	if err != nil {
		return hashResult{}, err
	}
	defer f.Close()

	hMD5 := md5.New()
	hSHA1 := sha1.New()
	hSHA256 := sha256.New()

	mw := io.MultiWriter(hMD5, hSHA1, hSHA256)
	n, err := io.Copy(mw, f)
	if err != nil {
		return hashResult{}, err
	}

	return hashResult{
		MD5:    hex.EncodeToString(hMD5.Sum(nil)),
		SHA1:   hex.EncodeToString(hSHA1.Sum(nil)),
		SHA256: hex.EncodeToString(hSHA256.Sum(nil)),
		Size:   n,
	}, nil
}

// ============================================================================
// File classification
// ============================================================================

// isPE returns true when the file starts with 'MZ' and has a plausible PE
// header. It is cheap and is only used to decide whether to run Authenticode
// verification, which is fairly expensive.
func isPE(path string) bool {
	f, err := pe.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()
	return true
}

// ============================================================================
// Entry type used for reporting
// ============================================================================

type reportEntry struct {
	Path   string      `json:"path"`
	Hashes *hashResult `json:"hashes,omitempty"`
	Sig    *sigResult  `json:"signature,omitempty"`
	Error  string      `json:"error,omitempty"`
}

// ============================================================================
// Display-width helpers
// ============================================================================

func dispWidth(s string) int {
	w := 0
	for _, r := range s {
		if isWideRune(r) {
			w += 2
		} else {
			w++
		}
	}
	return w
}

func isWideRune(r rune) bool {
	return (r >= 0x1100 && r <= 0x115F) ||
		(r >= 0x2E80 && r <= 0x303E) ||
		(r >= 0x3041 && r <= 0x33FF) ||
		(r >= 0x3400 && r <= 0x4DBF) ||
		(r >= 0x4E00 && r <= 0x9FFF) ||
		(r >= 0xA000 && r <= 0xA4CF) ||
		(r >= 0xAC00 && r <= 0xD7A3) ||
		(r >= 0xF900 && r <= 0xFAFF) ||
		(r >= 0xFE10 && r <= 0xFE19) ||
		(r >= 0xFE30 && r <= 0xFE6F) ||
		(r >= 0xFF00 && r <= 0xFF60) ||
		(r >= 0xFFE0 && r <= 0xFFE6)
}

func padRight(s string, width int) string {
	w := dispWidth(s)
	if w >= width {
		return s
	}
	return s + strings.Repeat(" ", width-w)
}

// ============================================================================
// Paths and log
// ============================================================================

const (
	backupDirName = "hashsigctl_backup"
	logFileName   = "hashsigctl.log"
)

func exeDir() string {
	if e, err := os.Executable(); err == nil {
		return filepath.Dir(e)
	}
	if w, err := os.Getwd(); err == nil {
		return w
	}
	return "."
}

func logRoot() string { return filepath.Join(exeDir(), backupDirName) }
func logPath() string { return filepath.Join(logRoot(), logFileName) }

func readLogLines() ([]string, error) {
	data, err := os.ReadFile(logPath())
	if err != nil {
		return nil, err
	}
	var out []string
	for _, l := range strings.Split(string(data), "\n") {
		if strings.TrimSpace(l) != "" {
			out = append(out, l)
		}
	}
	return out, nil
}

func appendLogLine(cmd string, code int) {
	_ = os.MkdirAll(logRoot(), 0755)
	f, err := os.OpenFile(logPath(), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		bugs.Add("ERR", "open log: %v", err)
		return
	}
	defer f.Close()
	ts := time.Now().Format("2006-01-02 15:04:05")
	_, _ = fmt.Fprintf(f, "[%s] [%s] [%d]\n", cmd, ts, code)
}

func buildCmdLine(argv []string) string {
	if len(argv) == 0 {
		return ""
	}
	exe, err := os.Executable()
	if err != nil || exe == "" {
		exe = argv[0]
	}
	parts := make([]string, 0, len(argv))
	parts = append(parts, syscall.EscapeArg(exe))
	for _, a := range argv[1:] {
		parts = append(parts, syscall.EscapeArg(a))
	}
	return strings.Join(parts, " ")
}

// ============================================================================
// History / rollback
// ============================================================================

func cmdHistory() int {
	lines, err := readLogLines()
	if err != nil {
		fmt.Fprintf(os.Stderr, "read log %s: %v\n", logPath(), err)
		return 4
	}
	if len(lines) == 0 {
		fmt.Fprintln(os.Stderr, "log is empty")
		return 0
	}
	for i := len(lines) - 1; i >= 0; i-- {
		n := len(lines) - i
		fmt.Printf("[%d] %s\n", n, lines[i])
	}
	fmt.Fprintf(os.Stderr, "\n%d entrie(s). Log: %s\n", len(lines), logPath())
	return 0
}

func cmdRollback() int {
	fmt.Fprintln(os.Stderr, "hashsigctl is read-only: there are no operations to roll back")
	fmt.Fprintln(os.Stderr, "  hashsigctl only reads files, computes hashes, and verifies signatures.")
	fmt.Fprintln(os.Stderr, "  Its history is for audit only; use --history to view it.")
	return 0
}

// ============================================================================
// Output
// ============================================================================

func printHash(e *reportEntry) {
	fmt.Printf("%s %s\n", c(clrCyan, "File:  "), e.Path)
	if e.Error != "" {
		fmt.Printf("%s %s\n", c(clrRed, "Error:"), e.Error)
		return
	}
	fmt.Printf("%s %s\n", c(clrCyan, "Size:  "), humanBytes(uint64(e.Hashes.Size)))
	fmt.Printf("%s %s\n", c(clrCyan, "MD5:   "), e.Hashes.MD5)
	fmt.Printf("%s %s\n", c(clrCyan, "SHA1:  "), e.Hashes.SHA1)
	fmt.Printf("%s %s\n", c(clrCyan, "SHA256:"), e.Hashes.SHA256)

	if e.Sig != nil {
		s := e.Sig
		fmt.Println()
		fmt.Println(c(clrBold+clrCyan, "Signature"))
		switch s.Status {
		case "valid":
			fmt.Printf("  %s %s\n", c(clrCyan, "Status:"), c(clrGreen, "Valid"))
		case "unsigned":
			fmt.Printf("  %s %s\n", c(clrCyan, "Status:"), c(clrGray, "No signature"))
		case "invalid":
			fmt.Printf("  %s %s\n", c(clrCyan, "Status:"), c(clrRed, "Invalid"))
		default:
			fmt.Printf("  %s %s\n", c(clrCyan, "Status:"), c(clrYellow, "Error"))
		}
		if s.Reason != "" {
			fmt.Printf("  %s %s\n", c(clrCyan, "Reason:"), c(clrGray, s.Reason))
		}
		if s.Signer != "" {
			fmt.Printf("  %s %s\n", c(clrCyan, "Signer:"), s.Signer)
		}
		if s.Issuer != "" {
			fmt.Printf("  %s %s\n", c(clrCyan, "Issuer:"), s.Issuer)
		}
	}
}

func printHashJSON(e *reportEntry) {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(e); err != nil {
		bugs.Add("ERR", "json encode: %v", err)
	}
}

func humanBytes(b uint64) string {
	const u = 1024
	if b < u {
		return fmt.Sprintf("%dB", b)
	}
	div, exp := uint64(u), 0
	for n := b / u; n >= u; n /= u {
		div *= u
		exp++
	}
	return fmt.Sprintf("%.1f%c", float64(b)/float64(div), "KMGTPE"[exp])
}

// ============================================================================
// Commands
// ============================================================================

func cmdHash(paths []string, jsonOut bool) int {
	var entries []*reportEntry
	okCount, failCount := 0, 0

	for _, p := range paths {
		e := &reportEntry{Path: p}
		h, err := hashFile(p)
		if err != nil {
			e.Error = err.Error()
			failCount++
			entries = append(entries, e)
			continue
		}
		e.Hashes = &h

		if isPE(p) {
			sig, err := verifyAuthenticode(p)
			if err == nil {
				signer, issuer, notes := extractSigner(p)
				sig.Signer = signer
				sig.Issuer = issuer
				sig.ChainNotes = notes
			}
			e.Sig = &sig
		}

		okCount++
		entries = append(entries, e)
	}

	if jsonOut {
		for _, e := range entries {
			printHashJSON(e)
		}
	} else {
		for i, e := range entries {
			if i > 0 {
				fmt.Println()
			}
			printHash(e)
		}
	}

	if failCount == 0 {
		return 0
	}
	if okCount == 0 {
		return 2
	}
	return 1
}

// ============================================================================
// Directory scanning
// ============================================================================

func collectFiles(args []string, recursive bool) ([]string, error) {
	var files []string
	for _, p := range args {
		fi, err := os.Stat(p)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", p, err)
		}
		if !fi.IsDir() {
			files = append(files, p)
			continue
		}
		if recursive {
			err := filepath.Walk(p, func(path string, info os.FileInfo, err error) error {
				if err != nil {
					return nil
				}
				if info.IsDir() {
					return nil
				}
				files = append(files, path)
				return nil
			})
			if err != nil {
				return nil, err
			}
		} else {
			entries, err := os.ReadDir(p)
			if err != nil {
				return nil, err
			}
			for _, e := range entries {
				if e.IsDir() {
					continue
				}
				files = append(files, filepath.Join(p, e.Name()))
			}
		}
	}
	sort.Strings(files)
	return files, nil
}

// ============================================================================
// Help
// ============================================================================

func printHelp() {
	header := "hashsigctl v1.0.0 (Windows)"
	fmt.Println(c(clrBold+clrCyan, header))
	fmt.Println("Hash and Authenticode signature verification (read-only)")
	fmt.Println()
	fmt.Print(`USAGE
  hashsigctl hash <file|dir>...
  hashsigctl sig  <file|dir>...          (signature only)
  hashsigctl <file|dir>...               (hash + sig if PE)
  hashsigctl --history
  hashsigctl --rollback                  (always a no-op: read-only)

HASH
  For each file, prints MD5, SHA1, SHA256 and the file size.
  Directories are expanded one level; add --recursive to walk deeper.

SIGNATURE
  For .exe / .dll / .sys files, calls WinVerifyTrust to check the
  Authenticode signature, then extracts the signer and issuer names from
  the embedded PKCS#7 certificate.
  Non-PE files are skipped silently when mixed with PE files.

OPTIONS
  --json           JSON output (one object per file)
  --recursive      Walk directories recursively
  --hash-only      Skip signature verification
  --sig-only       Only verify signatures (skip hash computation)

GLOBAL
  -o, --out <path> Redirect stdout to a file
  --dry-run        Print the plan without reading any file
  --no-color       Disable ANSI colors (also honors NO_COLOR)
  -b, --bugs       Print collected errors/warnings on exit
  -h, --help       Show this help
  --version        Show version

HISTORY
  Every invocation (except -h/--help/--version/--history/--rollback/--dry-run)
  appends one line to ./hashsigctl_backup/hashsigctl.log:
    [command line] [timestamp] [exit code]
  --history prints it, numbered from newest (1) to oldest.

READ-ONLY BY DESIGN
  hashsigctl never writes to the files it inspects, never modifies the
  registry, and never changes any system state. The only file it writes
  is its own audit log.

EXIT CODES
  0 success | 1 partial failure | 2 total failure or bad args
  3 permission denied | 4 not found | 5 I/O error
`)
}

// ============================================================================
// Global flag consumption
// ============================================================================

func consumeGlobalFlags(args []string) (rest []string, outPath string, err error) {
	rest = make([]string, 0, len(args))
	i := 0
	for i < len(args) {
		a := args[i]
		switch {
		case a == "-b" || a == "--bugs":
			bugs.enabled = true
			i++
		case a == "--dry-run":
			dryRun = true
			i++
		case a == "--no-color":
			noColorFlag = true
			i++
		case a == "-o" || a == "--out":
			if i+1 >= len(args) {
				return nil, "", fmt.Errorf("%s requires a path", a)
			}
			outPath = args[i+1]
			i += 2
		case strings.HasPrefix(a, "--out="):
			outPath = strings.TrimPrefix(a, "--out=")
			i++
		case strings.HasPrefix(a, "-o="):
			outPath = strings.TrimPrefix(a, "-o=")
			i++
		default:
			rest = append(rest, a)
			i++
		}
	}
	return rest, outPath, nil
}

func setupOutput(path string) error {
	if path == "" {
		return nil
	}
	dir := filepath.Dir(path)
	if dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return fmt.Errorf("create dir %s: %w", dir, err)
		}
	}
	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("create %s: %w", path, err)
	}
	orig := os.Stdout
	os.Stdout = f
	useColor = false
	outputCleanup = func() {
		_ = f.Sync()
		_ = f.Close()
		os.Stdout = orig
	}
	return nil
}

// ============================================================================
// Command dispatch
// ============================================================================

type hashOpts struct {
	jsonOut   bool
	recursive bool
	hashOnly  bool
	sigOnly   bool
}

func parseHashOpts(args []string) (*hashOpts, []string, error) {
	opts := &hashOpts{}
	var positional []string
	i := 0
	for i < len(args) {
		a := args[i]
		switch a {
		case "--json":
			opts.jsonOut = true
			i++
		case "--recursive", "-r":
			opts.recursive = true
			i++
		case "--hash-only":
			opts.hashOnly = true
			i++
		case "--sig-only":
			opts.sigOnly = true
			i++
		default:
			if strings.HasPrefix(a, "-") {
				return nil, nil, fmt.Errorf("unknown option %s", a)
			}
			positional = append(positional, a)
			i++
		}
	}
	if opts.hashOnly && opts.sigOnly {
		return nil, nil, fmt.Errorf("--hash-only and --sig-only are mutually exclusive")
	}
	return opts, positional, nil
}

func cmdHashOrSig(paths []string, opts *hashOpts) int {
	if len(paths) == 0 {
		fmt.Fprintln(os.Stderr, "hashsigctl: no files given")
		return 2
	}

	files, err := collectFiles(paths, opts.recursive)
	if err != nil {
		fmt.Fprintf(os.Stderr, "hashsigctl: %v\n", err)
		return 5
	}
	if len(files) == 0 {
		fmt.Fprintln(os.Stderr, "hashsigctl: no files matched")
		return 0
	}

	if dryRun {
		fmt.Printf("[dry-run] would process %d file(s):\n", len(files))
		for _, f := range files {
			fmt.Printf("  %s\n", f)
		}
		return 0
	}

	var entries []*reportEntry
	okCount, failCount := 0, 0

	for _, p := range files {
		e := &reportEntry{Path: p}

		if !opts.sigOnly {
			h, err := hashFile(p)
			if err != nil {
				e.Error = err.Error()
				failCount++
				entries = append(entries, e)
				continue
			}
			e.Hashes = &h
		}

		if !opts.hashOnly && isPE(p) {
			sig, err := verifyAuthenticode(p)
			if err == nil {
				signer, issuer, notes := extractSigner(p)
				sig.Signer = signer
				sig.Issuer = issuer
				sig.ChainNotes = notes
			}
			e.Sig = &sig
		}

		okCount++
		entries = append(entries, e)
	}

	if opts.jsonOut {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(entries); err != nil {
			bugs.Add("ERR", "json encode: %v", err)
		}
	} else {
		for i, e := range entries {
			if i > 0 {
				fmt.Println()
			}
			if e.Error != "" {
				fmt.Printf("%s %s\n", c(clrRed, "Error:"), e.Error)
				continue
			}
			if e.Hashes != nil {
				fmt.Printf("%s %s\n", c(clrCyan, "File:  "), e.Path)
				fmt.Printf("%s %s\n", c(clrCyan, "Size:  "), humanBytes(uint64(e.Hashes.Size)))
				fmt.Printf("%s %s\n", c(clrCyan, "MD5:   "), e.Hashes.MD5)
				fmt.Printf("%s %s\n", c(clrCyan, "SHA1:  "), e.Hashes.SHA1)
				fmt.Printf("%s %s\n", c(clrCyan, "SHA256:"), e.Hashes.SHA256)
			}
			if e.Sig != nil {
				s := e.Sig
				fmt.Println()
				fmt.Println(c(clrBold+clrCyan, "Signature"))
				switch s.Status {
				case "valid":
					fmt.Printf("  %s %s\n", c(clrCyan, "Status:"), c(clrGreen, "Valid"))
				case "unsigned":
					fmt.Printf("  %s %s\n", c(clrCyan, "Status:"), c(clrGray, "No signature"))
				case "invalid":
					fmt.Printf("  %s %s\n", c(clrCyan, "Status:"), c(clrRed, "Invalid"))
				default:
					fmt.Printf("  %s %s\n", c(clrCyan, "Status:"), c(clrYellow, "Error"))
				}
				if s.Reason != "" {
					fmt.Printf("  %s %s\n", c(clrCyan, "Reason:"), c(clrGray, s.Reason))
				}
				if s.Signer != "" {
					fmt.Printf("  %s %s\n", c(clrCyan, "Signer:"), s.Signer)
				}
				if s.Issuer != "" {
					fmt.Printf("  %s %s\n", c(clrCyan, "Issuer:"), s.Issuer)
				}
			}
		}
	}

	if failCount == 0 {
		return 0
	}
	if okCount == 0 {
		return 2
	}
	return 1
}

// ============================================================================
// main
// ============================================================================

func main() {
	args, outPath, err := consumeGlobalFlags(os.Args[1:])
	if err != nil {
		fmt.Fprintf(os.Stderr, "hashsigctl: %v\n", err)
		bugs.Flush()
		os.Exit(2)
	}

	if noColorFlag || os.Getenv("NO_COLOR") != "" {
		useColor = false
	} else if stdoutIsTTY() {
		useColor = true
	}

	if has(args, "--version") {
		fmt.Println("hashsigctl v1.0.0")
		finalExit(0, false)
	}
	if len(args) == 0 || has(args, "-h", "--help") {
		printHelp()
		finalExit(0, false)
	}
	if has(args, "--history") {
		finalExit(cmdHistory(), false)
	}
	if has(args, "--rollback") {
		finalExit(cmdRollback(), false)
	}

	if outPath != "" {
		if err := setupOutput(outPath); err != nil {
			fmt.Fprintf(os.Stderr, "hashsigctl: %v\n", err)
			bugs.Flush()
			os.Exit(2)
		}
	}

	// Subcommands: hash / sig. Anything else is treated as a path for the
	// default action.
	cmd := ""
	rest := args
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		switch args[0] {
		case "hash", "sig":
			cmd = args[0]
			rest = args[1:]
		}
	}

	opts, positional, err := parseHashOpts(rest)
	if err != nil {
		fmt.Fprintf(os.Stderr, "hashsigctl: %v\n", err)
		bugs.Flush()
		os.Exit(2)
	}

	switch cmd {
	case "hash":
		opts.sigOnly = false
		opts.hashOnly = true
		if len(positional) == 0 {
			fmt.Fprintln(os.Stderr, "hashsigctl: hash requires at least one file or directory")
			finalExit(2, true)
		}
		finalExit(cmdHashOrSig(positional, opts), true)
	case "sig":
		opts.sigOnly = true
		opts.hashOnly = false
		if len(positional) == 0 {
			fmt.Fprintln(os.Stderr, "hashsigctl: sig requires at least one file or directory")
			finalExit(2, true)
		}
		finalExit(cmdHashOrSig(positional, opts), true)
	default:
		if len(positional) == 0 {
			fmt.Fprintln(os.Stderr, "hashsigctl: no files given (use -h for help)")
			finalExit(2, true)
		}
		finalExit(cmdHashOrSig(positional, opts), true)
	}
}

func has(args []string, flags ...string) bool {
	for _, a := range args {
		for _, f := range flags {
			if a == f {
				return true
			}
		}
	}
	return false
}

func finalExit(code int, logIt bool) {
	if logIt && !dryRun && shouldLogRun() {
		appendLogLine(buildCmdLine(os.Args), code)
	}
	bugs.Flush()
	if outputCleanup != nil {
		outputCleanup()
		outputCleanup = nil
	}
	os.Exit(code)
}

func shouldLogRun() bool {
	for _, a := range os.Args[1:] {
		switch a {
		case "-h", "--help", "--version", "--history", "--rollback", "--dry-run":
			return false
		}
	}
	return true
}

// Suppress unused-import warnings for helpers we keep around.
var (
	_ = asn1.Marshal
	_ = runtime.GOARCH
	_ = strconv.Itoa
)