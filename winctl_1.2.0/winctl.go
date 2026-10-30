//go:build windows && amd64

// winctl v1.2.0 — Windows administrator toolkit.
// Single binary, standard library only, Windows amd64 only.
//
// Unified layout:
//   ./backup/winctl_logs.log              shared audit log (all modules)
//   ./backup/<module>/ops/<line>.json     per-operation manifests
//   ./backup/<module>/files/              per-operation backups
//   ./backup/batch/scripts/<ts>.wctl      executed batch script copies
//   ./backup/box/volumes/<name>/<ts>.tar.gz   box volume snapshots
//   %LOCALAPPDATA%\winctl\box\<name>\     box runtime state
//
// Every module (net, open, pe, proc, reg, svc, sys, task, acl, bkp,
// disk, doc, evt, fs, hash, batch, box) shares the same logging, backup
// and dispatch scaffolding defined in this file.
//
// batch is a script runner: it dispatches each line to one of the other
// 16 modules as a child winctl process, so every child keeps its own
// backups, manifests and audit lines.  v1.2 added chunked result
// printing so very long scripts don't dump everything at once.
//
// box is a container-like runner for Windows: Job Object resource limits
// (reused from proc), junction-point volume mounts, user-mode health
// probes, and restart policies.  No namespaces, no overlayfs — pure
// Windows primitives.
//
// Performance notes (unchanged public behaviour):
//   * open info / preview read at most the first 64 MB of a file.
//   * open decrypt loads at most 256 MB; larger files are refused.
//   * sys_pumpOutput reads 64 KB at a time instead of byte-by-byte.
//   * hash computes SHA-256 only by default; --all adds MD5 and SHA1.
//   * fs cat / grep / head / tail stream stdin/stdout instead of
//     reading whole files into memory.
//   * batch flushes its step report in 20-line chunks.

package main

import (
	"archive/tar"
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"crypto/md5"
	"crypto/rc4"
	"crypto/sha1"
	"crypto/sha256"
	"debug/pe"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"math"
	"math/rand"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unicode/utf8"
	"unsafe")

// ============================================================================
// Version
// ============================================================================

const Version = "1.2.0"

// ============================================================================
// Shared constants
// ============================================================================

const (
	backupDirName = "backup"
	globalLogName = "winctl_logs.log"

	clrReset  = "\x1b[0m"
	clrBold   = "\x1b[1m"
	clrRed    = "\x1b[31m"
	clrGreen  = "\x1b[32m"
	clrYellow = "\x1b[33m"
	clrCyan   = "\x1b[36m"
	clrGray   = "\x1b[90m"

	STD_INPUT_HANDLE  = ^uint32(9)
	STD_OUTPUT_HANDLE = ^uint32(11)

	HKCU = uintptr(0xFFFFFFFF80000001)
	HKLM = uintptr(0xFFFFFFFF80000002)
	HKCR = uintptr(0xFFFFFFFF80000000)
	HKU  = uintptr(0xFFFFFFFF80000003)
	HKCC = uintptr(0xFFFFFFFF80000005)

	KEY_QUERY_VALUE        = 0x0001
	KEY_SET_VALUE          = 0x0002
	KEY_CREATE_SUB_KEY     = 0x0004
	KEY_ENUMERATE_SUB_KEYS = 0x0008
	KEY_WOW64_32KEY        = 0x0200
	KEY_WOW64_64KEY        = 0x0100
	KEY_READ               = 0x20019
	KEY_WRITE              = 0x20006
	KEY_ALL_ACCESS         = 0xF003F

	REG_NONE                       = 0
	REG_SZ                         = 1
	REG_EXPAND_SZ                  = 2
	REG_BINARY                     = 3
	REG_DWORD                      = 4
	REG_DWORD_BIG_ENDIAN           = 5
	REG_LINK                       = 6
	REG_MULTI_SZ                   = 7
	REG_RESOURCE_LIST              = 8
	REG_FULL_RESOURCE_DESCRIPTOR   = 9
	REG_RESOURCE_REQUIREMENTS_LIST = 10
	REG_QWORD                      = 11

	ERROR_FILE_NOT_FOUND = syscall.Errno(2)
	ERROR_ACCESS_DENIED  = syscall.Errno(5)
	ERROR_INVALID_HANDLE = syscall.Errno(6)
	ERROR_NO_MORE_ITEMS  = syscall.Errno(259)
	ERROR_MORE_DATA      = syscall.Errno(234)
	ERROR_NO_MORE_FILES  = syscall.Errno(18)
)

// ============================================================================
// Shared runtime state
// ============================================================================

var (
	useColor      = false
	dryRun        = false
	noColorFlag   = false
	outputCleanup func()

	kernel32 = syscall.NewLazyDLL("kernel32.dll")
	advapi32 = syscall.NewLazyDLL("advapi32.dll")

	pGetStdHandle   = kernel32.NewProc("GetStdHandle")
	pGetConsoleMode = kernel32.NewProc("GetConsoleMode")
	pCloseHandle    = kernel32.NewProc("CloseHandle")

	pRegOpenKeyExW    = advapi32.NewProc("RegOpenKeyExW")
	pRegCloseKey      = advapi32.NewProc("RegCloseKey")
	pRegEnumKeyExW    = advapi32.NewProc("RegEnumKeyExW")
	pRegEnumValueW    = advapi32.NewProc("RegEnumValueW")
	pRegQueryValueExW = advapi32.NewProc("RegQueryValueExW")
	pRegSetValueExW   = advapi32.NewProc("RegSetValueExW")
	pRegCreateKeyExW  = advapi32.NewProc("RegCreateKeyExW")
	pRegDeleteKeyW    = advapi32.NewProc("RegDeleteKeyW")
	pRegDeleteTreeW   = advapi32.NewProc("RegDeleteTreeW")
	pRegDeleteValueW  = advapi32.NewProc("RegDeleteValueW")

	// Buffers reused across hot paths (registry enum, adapter parse).
	bytePool   = sync.Pool{New: func() any { b := make([]byte, 0, 64*1024); return &b }}
	uint16Pool = sync.Pool{New: func() any { b := make([]uint16, 0, 1024); return &b }}
)

// ============================================================================
// Bug collector (-b/--bugs)
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
		fmt.Fprintln(os.Stderr, "[winctl] -b/--bugs enabled: no errors or warnings captured this run.")
		return
	}
	fmt.Fprintf(os.Stderr, "\n--- winctl bugs report (%d entries) ---\n", len(b.entries))
	for _, e := range b.entries {
		fmt.Fprintf(os.Stderr, "[%s] %s %s\n", e.At.Format("15:04:05.000"), e.Level, e.Msg)
	}
	fmt.Fprintln(os.Stderr, "--- end of bugs report ---")
}

// ============================================================================
// Colour / TTY / formatting helpers
// ============================================================================

func c(code, s string) string {
	if !useColor {
		return s
	}
	return code + s + clrReset
}

func isConsole(which uint32) bool {
	h, _, _ := pGetStdHandle.Call(uintptr(which))
	if h == 0 {
		return false
	}
	var mode uint32
	r, _, _ := pGetConsoleMode.Call(h, uintptr(unsafe.Pointer(&mode)))
	return r != 0
}

func stdinIsTTY() bool  { return isConsole(STD_INPUT_HANDLE) }
func stdoutIsTTY() bool { return isConsole(STD_OUTPUT_HANDLE) }

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

func confirm(prompt string) bool {
	if !stdinIsTTY() {
		fmt.Fprintf(os.Stderr, "%s\n  non-interactive stdin: use -f or -y to skip confirmation\n", prompt)
		return false
	}
	fmt.Fprintf(os.Stderr, "%s [y/N] ", prompt)
	var line string
	fmt.Scanln(&line)
	line = strings.ToLower(strings.TrimSpace(line))
	return line == "y" || line == "yes"
}

func machineName(m uint16) string {
	switch m {
	case 0x014C:
		return "i386"
	case 0x8664:
		return "AMD64"
	case 0x01C0:
		return "ARM"
	case 0x01C4:
		return "ARMv7"
	case 0xAA64:
		return "ARM64"
	case 0x0200:
		return "IA64"
	}
	return fmt.Sprintf("0x%04X", m)
}

// ============================================================================
// Global flags / output redirection
// ============================================================================

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

func consumeGlobalFlags(args []string) ([]string, string, error) {
	rest := make([]string, 0, len(args))
	outPath := ""
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

func initColor() {
	if noColorFlag || os.Getenv("NO_COLOR") != "" {
		useColor = false
	} else if stdoutIsTTY() {
		useColor = true
	}
}

func stripFlags(args []string, flags ...string) []string {
	out := make([]string, 0, len(args))
	for _, a := range args {
		keep := true
		for _, f := range flags {
			if a == f {
				keep = false
				break
			}
		}
		if keep {
			out = append(out, a)
		}
	}
	return out
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

func finalExit(code int) {
	bugs.Flush()
	if outputCleanup != nil {
		outputCleanup()
		outputCleanup = nil
	}
	auditClose()
	os.Exit(code)
}

// ============================================================================
// Unified backup root and audit log
// ============================================================================

func exeDir() string {
	if e, err := os.Executable(); err == nil {
		return filepath.Dir(e)
	}
	if w, err := os.Getwd(); err == nil {
		return w
	}
	return "."
}

func backupRoot() string      { return filepath.Join(exeDir(), backupDirName) }
func moduleRoot(m string) string     { return filepath.Join(backupRoot(), m) }
func moduleOpsDir(m string) string   { return filepath.Join(moduleRoot(m), "ops") }
func moduleFilesDir(m string) string { return filepath.Join(moduleRoot(m), "files") }
func globalLogPath() string   { return filepath.Join(backupRoot(), globalLogName) }

// logLineRe matches one line of the shared log:
//
//	[module] [cmd line] [YYYY-MM-DD HH:MM:SS] [exit code]
var logLineRe = regexp.MustCompile(`^\[([a-z]+)\] \[(.*)\] \[(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\] \[(-?\d+)\]$`)

type auditState struct {
	mu     sync.Mutex
	file   *os.File
	writer *bufio.Writer
	count  int
	inited bool
}

var audit auditState

func auditCount() int {
	audit.mu.Lock()
	defer audit.mu.Unlock()
	return audit.count
}

func auditInit() error {
	audit.mu.Lock()
	defer audit.mu.Unlock()
	if audit.inited {
		return nil
	}
	if err := os.MkdirAll(backupRoot(), 0755); err != nil {
		return err
	}
	f, err := os.OpenFile(globalLogPath(), os.O_CREATE|os.O_RDWR|os.O_APPEND, 0644)
	if err != nil {
		return err
	}
	if st, e := f.Stat(); e == nil && st.Size() > 0 {
		if _, e2 := f.Seek(0, 0); e2 == nil {
			sc := bufio.NewScanner(f)
			sc.Buffer(make([]byte, 64*1024), 4*1024*1024)
			for sc.Scan() {
				audit.count++
			}
			_, _ = f.Seek(0, 2)
		}
	}
	audit.file = f
	audit.writer = bufio.NewWriterSize(f, 32*1024)
	audit.inited = true
	return nil
}

func auditLog(module, cmdLine string, exitCode int) int {
	audit.mu.Lock()
	defer audit.mu.Unlock()
	if !audit.inited {
		return -1
	}
	ts := time.Now().Format("2006-01-02 15:04:05")
	fmt.Fprintf(audit.writer, "[%s] [%s] [%s] [%d]\n", module, cmdLine, ts, exitCode)
	_ = audit.writer.Flush()
	idx := audit.count
	audit.count++
	return idx
}

func auditClose() {
	audit.mu.Lock()
	defer audit.mu.Unlock()
	if audit.writer != nil {
		_ = audit.writer.Flush()
	}
	if audit.file != nil {
		_ = audit.file.Close()
	}
	audit.file = nil
	audit.writer = nil
	audit.inited = false
}

func auditReadLines() ([]string, error) {
	data, err := os.ReadFile(globalLogPath())
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

func auditParseLine(line string) (module, cmd string, code int, ok bool) {
	m := logLineRe.FindStringSubmatch(line)
	if m == nil {
		return "", "", 0, false
	}
	n, _ := strconv.Atoi(m[4])
	return m[1], m[2], n, true
}

func moduleManifestExists(module string, idx int) bool {
	_, err := os.Stat(filepath.Join(moduleOpsDir(module), fmt.Sprintf("%d.json", idx)))
	return err == nil
}

func moduleSaveManifest(module string, idx int, v any) error {
	dir := moduleOpsDir(module)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, fmt.Sprintf("%d.json", idx)), data, 0644)
}

func moduleLoadManifest(module string, idx int, v any) error {
	data, err := os.ReadFile(filepath.Join(moduleOpsDir(module), fmt.Sprintf("%d.json", idx)))
	if err != nil {
		return err
	}
	return json.Unmarshal(data, v)
}

func moduleTailOps(module string, n int) ([]int, error) {
	lines, err := auditReadLines()
	if err != nil {
		return nil, err
	}
	var out []int
	for i := len(lines) - 1; i >= 0 && len(out) < n; i-- {
		m, cmd, _, ok := auditParseLine(lines[i])
		if !ok || m != module {
			continue
		}
		if isHistorySelf(cmd) {
			continue
		}
		if !moduleManifestExists(module, i) {
			continue
		}
		out = append(out, i)
	}
	return out, nil
}

func isHistorySelf(cmd string) bool {
	return strings.Contains(cmd, "--history") || strings.Contains(cmd, "--rollback") ||
		strings.Contains(cmd, " -h") || strings.HasSuffix(cmd, "-h") ||
		strings.Contains(cmd, "--help") || strings.Contains(cmd, "--version")
}

// ============================================================================
// Registry wrappers (shared)
// ============================================================================

type RegKey uintptr

type RegValue struct {
	Name string
	Type uint32
	Data []byte
}

func regOpenKey(root uintptr, subKey string, samDesired uint32) (RegKey, error) {
	var subPtr *uint16
	if subKey != "" {
		var err error
		subPtr, err = syscall.UTF16PtrFromString(subKey)
		if err != nil {
			return 0, err
		}
	}
	var subPtrU uintptr
	if subPtr != nil {
		subPtrU = uintptr(unsafe.Pointer(subPtr))
	}
	var phk uintptr
	r, _, _ := pRegOpenKeyExW.Call(root, subPtrU, 0,
		uintptr(samDesired), uintptr(unsafe.Pointer(&phk)))
	if r != 0 {
		return 0, syscall.Errno(r)
	}
	return RegKey(phk), nil
}

func regCloseKey(k RegKey) {
	if k != 0 {
		pRegCloseKey.Call(uintptr(k))
	}
}

func regEnumKeys(k RegKey) ([]string, error) {
	var out []string
	var idx uint32
	buf := make([]uint16, 1024)
	for {
		size := uint32(len(buf))
		r, _, _ := pRegEnumKeyExW.Call(
			uintptr(k), uintptr(idx),
			uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&size)),
			0, 0, 0, 0)
		if r == uintptr(ERROR_NO_MORE_ITEMS) {
			break
		}
		if r != 0 {
			return out, syscall.Errno(r)
		}
		out = append(out, syscall.UTF16ToString(buf[:size]))
		idx++
	}
	return out, nil
}

func regEnumValues(k RegKey) ([]RegValue, error) {
	var out []RegValue
	var idx uint32
	nameBuf := make([]uint16, 1024)
	dataBuf := make([]byte, 65536)
	for {
		nameSize := uint32(len(nameBuf))
		dataSize := uint32(len(dataBuf))
		var typ uint32
		r, _, _ := pRegEnumValueW.Call(
			uintptr(k), uintptr(idx),
			uintptr(unsafe.Pointer(&nameBuf[0])), uintptr(unsafe.Pointer(&nameSize)),
			0, uintptr(unsafe.Pointer(&typ)),
			uintptr(unsafe.Pointer(&dataBuf[0])), uintptr(unsafe.Pointer(&dataSize)))
		if r == uintptr(ERROR_NO_MORE_ITEMS) {
			break
		}
		if r == uintptr(ERROR_MORE_DATA) {
			dataBuf = make([]byte, int(dataSize)+1024)
			nameSize = uint32(len(nameBuf))
			r, _, _ = pRegEnumValueW.Call(
				uintptr(k), uintptr(idx),
				uintptr(unsafe.Pointer(&nameBuf[0])), uintptr(unsafe.Pointer(&nameSize)),
				0, uintptr(unsafe.Pointer(&typ)),
				uintptr(unsafe.Pointer(&dataBuf[0])), uintptr(unsafe.Pointer(&dataSize)))
		}
		if r != 0 {
			return out, syscall.Errno(r)
		}
		out = append(out, RegValue{
			Name: syscall.UTF16ToString(nameBuf[:nameSize]),
			Type: typ,
			Data: append([]byte(nil), dataBuf[:dataSize]...),
		})
		idx++
	}
	return out, nil
}

func regQueryValue(k RegKey, name string) (*RegValue, error) {
	var namePtr *uint16
	if name != "" {
		var err error
		namePtr, err = syscall.UTF16PtrFromString(name)
		if err != nil {
			return nil, err
		}
	}
	var nameU uintptr
	if namePtr != nil {
		nameU = uintptr(unsafe.Pointer(namePtr))
	}
	var typ uint32
	var size uint32
	r, _, _ := pRegQueryValueExW.Call(uintptr(k), nameU, 0,
		uintptr(unsafe.Pointer(&typ)), 0, uintptr(unsafe.Pointer(&size)))
	if r != 0 {
		return nil, syscall.Errno(r)
	}
	buf := make([]byte, size)
	r, _, _ = pRegQueryValueExW.Call(uintptr(k), nameU, 0,
		uintptr(unsafe.Pointer(&typ)),
		uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&size)))
	if r != 0 {
		return nil, syscall.Errno(r)
	}
	return &RegValue{Name: name, Type: typ, Data: buf[:size]}, nil
}

func regSetValue(k RegKey, name string, typ uint32, data []byte) error {
	var namePtr *uint16
	if name != "" {
		var err error
		namePtr, err = syscall.UTF16PtrFromString(name)
		if err != nil {
			return err
		}
	}
	var nameU uintptr
	if namePtr != nil {
		nameU = uintptr(unsafe.Pointer(namePtr))
	}
	var dataU uintptr
	if len(data) > 0 {
		dataU = uintptr(unsafe.Pointer(&data[0]))
	}
	r, _, _ := pRegSetValueExW.Call(uintptr(k), nameU, 0,
		uintptr(typ), dataU, uintptr(len(data)))
	if r != 0 {
		return syscall.Errno(r)
	}
	return nil
}

func regDeleteTree(root uintptr, subKey string) error {
	subPtr, err := syscall.UTF16PtrFromString(subKey)
	if err != nil {
		return err
	}
	r, _, _ := pRegDeleteTreeW.Call(root, uintptr(unsafe.Pointer(subPtr)))
	if r != 0 {
		return syscall.Errno(r)
	}
	return nil
}

func regDeleteValue(k RegKey, name string) error {
	var namePtr *uint16
	if name != "" {
		var err error
		namePtr, err = syscall.UTF16PtrFromString(name)
		if err != nil {
			return err
		}
	}
	var nameU uintptr
	if namePtr != nil {
		nameU = uintptr(unsafe.Pointer(namePtr))
	}
	r, _, _ := pRegDeleteValueW.Call(uintptr(k), nameU)
	if r != 0 {
		return syscall.Errno(r)
	}
	return nil
}

// ============================================================================
// UTF-16 helpers (shared)
// ============================================================================

func utf16Decode(u []uint16) []rune {
	var out []rune
	for i := 0; i < len(u); i++ {
		if u[i] >= 0xD800 && u[i] <= 0xDBFF && i+1 < len(u) && u[i+1] >= 0xDC00 && u[i+1] <= 0xDFFF {
			hi := rune(u[i] - 0xD800)
			lo := rune(u[i+1] - 0xDC00)
			out = append(out, (hi<<10)+lo+0x10000)
			i++
		} else {
			out = append(out, rune(u[i]))
		}
	}
	return out
}

func utf16Encode(s string) []uint16 {
	var out []uint16
	for _, r := range s {
		if r > 0xFFFF {
			r -= 0x10000
			out = append(out, uint16(0xD800+(r>>10)), uint16(0xDC00+(r&0x3FF)))
		} else {
			out = append(out, uint16(r))
		}
	}
	return out
}

func utf16At(p *uint16, maxCodeUnits int) string {
	if p == nil || maxCodeUnits <= 0 {
		return ""
	}
	s := unsafe.Slice(p, maxCodeUnits)
	for i, v := range s {
		if v == 0 {
			return syscall.UTF16ToString(s[:i])
		}
	}
	return syscall.UTF16ToString(s)
}

func decodeRegString(b []byte) string {
	if len(b) < 2 {
		return ""
	}
	u := make([]uint16, len(b)/2)
	for i := 0; i < len(u); i++ {
		u[i] = uint16(b[i*2]) | uint16(b[i*2+1])<<8
	}
	for i, v := range u {
		if v == 0 {
			u = u[:i]
			break
		}
	}
	return string(utf16Decode(u))
}

func encodeRegString(s string) []byte {
	u := utf16Encode(s)
	u = append(u, 0)
	out := make([]byte, len(u)*2)
	for i, v := range u {
		out[i*2] = byte(v)
		out[i*2+1] = byte(v >> 8)
	}
	return out
}

func decodeMultiString(data []byte) []string {
	if len(data) < 2 {
		return nil
	}
	u := make([]uint16, len(data)/2)
	for i := 0; i < len(u); i++ {
		u[i] = uint16(data[i*2]) | uint16(data[i*2+1])<<8
	}
	var out []string
	start := 0
	for i := 0; i < len(u); i++ {
		if u[i] == 0 {
			if i == start {
				break
			}
			out = append(out, string(utf16Decode(u[start:i])))
			start = i + 1
		}
	}
	return out
}

func encodeMultiString(items []string) []byte {
	var out []byte
	for _, s := range items {
		u := utf16Encode(s)
		for _, v := range u {
			out = append(out, byte(v), byte(v>>8))
		}
		out = append(out, 0, 0)
	}
	if len(out) == 0 {
		out = append(out, 0, 0)
	}
	return out
}

// ============================================================================
// main dispatch
// ============================================================================

func main() {
	args := os.Args[1:]
	if len(args) == 0 {
		printTopHelp()
		os.Exit(2)
	}
	tool := args[0]
	os.Args = append([]string{os.Args[0]}, args[1:]...)

	if err := auditInit(); err != nil {
		fmt.Fprintf(os.Stderr, "winctl: cannot open audit log: %v\n", err)
	}
	defer auditClose()

	switch tool {
	case "net":
		net_main()
	case "open":
		open_main()
	case "pe":
		pe_main()
	case "proc":
		proc_main()
	case "reg":
		reg_main()
	case "svc":
		svc_main()
	case "sys":
		sys_main()
	case "task":
		task_main()
	case "acl":
		acl_main()
	case "bkp":
		bkp_main()
	case "disk":
		disk_main()
	case "doc":
		doc_main()
	case "evt":
		evt_main()
	case "fs":
		fs_main()
	case "hash":
		hash_main()
	case "batch":
		batch_main()
	case "box":
		box_main()
	default:
		fmt.Fprintf(os.Stderr, "winctl: unknown subcommand %q\n", tool)
		printTopHelp()
		os.Exit(2)
	}
}

func printTopHelp() {
	fmt.Printf("winctl v%s (Windows amd64)\n\n", Version)
	fmt.Println("Subcommands:")
	fmt.Println("  net    network conn / dns / adapters / hosts / proxy")
	fmt.Println("  open   file identify / preview / decrypt attempt")
	fmt.Println("  pe     PE dependency diagnostic")
	fmt.Println("  proc   process list / monitor / limit")
	fmt.Println("  reg    registry manager")
	fmt.Println("  svc    service manager")
	fmt.Println("  sys    system repair (DISM / SFC / chkdsk)")
	fmt.Println("  task   scheduled tasks + startup entries")
	fmt.Println("  acl    file ACL / owner / DACL")
	fmt.Println("  bkp    unified backup / restore")
	fmt.Println("  disk   disk and volume viewer")
	fmt.Println("  doc    environment diagnostics")
	fmt.Println("  evt    event log query")
	fmt.Println("  fs     file and text basics with rollback")
	fmt.Println("  hash   hash + Authenticode verification")
	fmt.Println("  batch  script runner for the other 15 modules")
	fmt.Println("  box    container-like runner (job + volumes + probes)")
	fmt.Println()
	fmt.Println("All logs:   ./backup/winctl_logs.log")
	fmt.Println("All backups: ./backup/<module>/")
}

// ============================================================================
// net — network connections / DNS / adapters / hosts / proxy
// ============================================================================

var (
	net_iphlpapi = syscall.NewLazyDLL("net_iphlpapi.dll")

	net_pGetExtendedTcpTable  = net_iphlpapi.NewProc("GetExtendedTcpTable")
	net_pGetExtendedUdpTable  = net_iphlpapi.NewProc("GetExtendedUdpTable")
	net_pGetAdaptersAddresses = net_iphlpapi.NewProc("GetAdaptersAddresses")

	net_pOpenProcess                = kernel32.NewProc("OpenProcess")
	net_pQueryFullProcessImageNameW = kernel32.NewProc("QueryFullProcessImageNameW")
)

const (
	net_AF_UNSPEC = 0
	net_AF_INET   = 2
	net_AF_INET6  = 23

	net_TCP_TABLE_OWNER_PID_ALL = 5
	net_UDP_TABLE_OWNER_PID     = 1

	net_MIB_TCP_STATE_CLOSED     = 1
	net_MIB_TCP_STATE_LISTEN     = 2
	net_MIB_TCP_STATE_SYN_SENT   = 3
	net_MIB_TCP_STATE_SYN_RCVD   = 4
	net_MIB_TCP_STATE_ESTAB      = 5
	net_MIB_TCP_STATE_FIN_WAIT1  = 6
	net_MIB_TCP_STATE_FIN_WAIT2  = 7
	net_MIB_TCP_STATE_CLOSE_WAIT = 8
	net_MIB_TCP_STATE_CLOSING    = 9
	net_MIB_TCP_STATE_LAST_ACK   = 10
	net_MIB_TCP_STATE_TIME_WAIT  = 11
	net_MIB_TCP_STATE_DELETE_TCB = 12

	net_PROCESS_QUERY_LIMITED = 0x1000

	net_IfOperStatusUp            = 1
	net_IF_TYPE_ETHERNET_CSMACD   = 6
	net_IF_TYPE_IEEE80211         = 71
	net_IF_TYPE_SOFTWARE_LOOPBACK = 24
	net_IF_TYPE_TUNNEL            = 131
	net_GAA_FLAG_INCLUDE_PREFIX   = 0x0010
)

type net_ConnRow struct {
	Proto    string
	Local    string
	Remote   string
	State    uint32
	Pid      uint32
	ProcName string
}

type net_MIB_TCPROW_OWNER_PID struct {
	State, LocalAddr, LocalPort, RemoteAddr, RemotePort, OwningPid uint32
}
type net_MIB_TCP6ROW_OWNER_PID struct {
	ucLocalAddr     [16]byte
	dwLocalScopeId  uint32
	dwLocalPort     uint32
	ucRemoteAddr    [16]byte
	dwRemoteScopeId uint32
	dwRemotePort    uint32
	dwState         uint32
	dwOwningPid     uint32
}
type net_MIB_UDPROW_OWNER_PID struct {
	LocalAddr, LocalPort, OwningPid uint32
}
type net_MIB_UDP6ROW_OWNER_PID struct {
	ucLocalAddr    [16]byte
	dwLocalScopeId uint32
	dwLocalPort    uint32
	dwOwningPid    uint32
}

type net_SOCKET_ADDRESS struct {
	lpSockaddr      *syscall.RawSockaddrAny
	iSockaddrLength int32
}

type net_IP_ADAPTER_UNICAST_ADDRESS_LH struct {
	Length  uint32
	Flags   uint32
	Next    *net_IP_ADAPTER_UNICAST_ADDRESS_LH
	Address net_SOCKET_ADDRESS
}

type net_IP_ADAPTER_DNS_SERVER_ADDRESS_XP struct {
	Length, Reserved uint32
	Next             *net_IP_ADAPTER_DNS_SERVER_ADDRESS_XP
	Address          net_SOCKET_ADDRESS
}

type net_IP_ADAPTER_ADDRESSES_LH struct {
	Length, IfIndex                  uint32
	Next                             *net_IP_ADAPTER_ADDRESSES_LH
	AdapterName                      *byte
	FirstUnicastAddress              *net_IP_ADAPTER_UNICAST_ADDRESS_LH
	FirstAnycastAddress              *net_IP_ADAPTER_UNICAST_ADDRESS_LH
	FirstMulticastAddress            *net_IP_ADAPTER_UNICAST_ADDRESS_LH
	FirstDnsServerAddress            *net_IP_ADAPTER_DNS_SERVER_ADDRESS_XP
	DnsSuffix                        *uint16
	Description                      *uint16
	FriendlyName                     *uint16
	PhysicalAddress                  [8]byte
	PhysicalAddressLength            uint32
	Flags, Mtu, IfType, OperStatus   uint32
	Ipv6IfIndex                      uint32
	ZoneIndices                      [16]uint32
	FirstPrefix                      uintptr
}

const net_proxyKeyPath = `Software\Microsoft\Windows\CurrentVersion\Internet Settings`

func net_regCreateKey(root uintptr, subKey string, samDesired uint32) (RegKey, error) {
	subPtr, err := syscall.UTF16PtrFromString(subKey)
	if err != nil {
		return 0, err
	}
	var phk uintptr
	var disp uint32
	r, _, _ := pRegCreateKeyExW.Call(root,
		uintptr(unsafe.Pointer(subPtr)), 0, 0, 0,
		uintptr(samDesired), 0,
		uintptr(unsafe.Pointer(&phk)),
		uintptr(unsafe.Pointer(&disp)))
	if r != 0 {
		return 0, syscall.Errno(r)
	}
	return RegKey(phk), nil
}

func net_ntohs(x uint32) uint16 { return uint16(x&0xFF)<<8 | uint16((x>>8)&0xFF) }

func net_ipv4FromUint32(a uint32) string {
	return fmt.Sprintf("%d.%d.%d.%d", byte(a), byte(a>>8), byte(a>>16), byte(a>>24))
}

func net_formatIPv6(b []byte) string {
	if len(b) < 16 {
		return ""
	}
	var parts [8]uint16
	for i := 0; i < 8; i++ {
		parts[i] = binary.BigEndian.Uint16(b[i*2:])
	}
	bestStart, bestLen := -1, 0
	curStart, curLen := -1, 0
	for i := 0; i < 8; i++ {
		if parts[i] == 0 {
			if curStart < 0 {
				curStart, curLen = i, 0
			}
			curLen++
			if curLen > bestLen {
				bestStart, bestLen = curStart, curLen
			}
		} else {
			curStart, curLen = -1, 0
		}
	}
	var b2 strings.Builder
	if bestLen >= 2 {
		for i := 0; i < bestStart; i++ {
			fmt.Fprintf(&b2, "%x", parts[i])
			if i < bestStart-1 {
				b2.WriteString(":")
			}
		}
		b2.WriteString("::")
		for i := bestStart + bestLen; i < 8; i++ {
			fmt.Fprintf(&b2, "%x", parts[i])
			if i < 7 {
				b2.WriteString(":")
			}
		}
	} else {
		for i := 0; i < 8; i++ {
			fmt.Fprintf(&b2, "%x", parts[i])
			if i < 7 {
				b2.WriteString(":")
			}
		}
	}
	return b2.String()
}

func net_sockaddrToIP(sa *syscall.RawSockaddrAny) (string, int, bool) {
	if sa == nil {
		return "", 0, false
	}
	switch int(sa.Addr.Family) {
	case net_AF_INET:
		in4 := (*syscall.RawSockaddrInet4)(unsafe.Pointer(sa))
		return fmt.Sprintf("%d.%d.%d.%d", in4.Addr[0], in4.Addr[1], in4.Addr[2], in4.Addr[3]), net_AF_INET, true
	case net_AF_INET6:
		in6 := (*syscall.RawSockaddrInet6)(unsafe.Pointer(sa))
		return net_formatIPv6(in6.Addr[:]), net_AF_INET6, true
	}
	return "", int(sa.Addr.Family), false
}

func net_callTableFn(fn *syscall.LazyProc, family, tableClass uint32) ([]byte, error) {
	var buf []byte
	for attempt := 0; attempt < 3; attempt++ {
		size := uint32(len(buf))
		var p uintptr
		if size > 0 {
			p = uintptr(unsafe.Pointer(&buf[0]))
		}
		r, _, _ := fn.Call(p, uintptr(unsafe.Pointer(&size)), 0,
			uintptr(family), uintptr(tableClass), 0)
		if r == 0 && size > 0 {
			return buf[:size], nil
		}
		if size == 0 {
			if r == 0 {
				return nil, nil
			}
			return nil, syscall.Errno(r)
		}
		buf = make([]byte, int(size)+4096)
	}
	return nil, fmt.Errorf("buffer size discovery failed after retries")
}

func net_queryTcp4() ([]net_ConnRow, error) {
	buf, err := net_callTableFn(net_pGetExtendedTcpTable, net_AF_INET, net_TCP_TABLE_OWNER_PID_ALL)
	if err != nil || len(buf) < 4 {
		return nil, err
	}
	num := *(*uint32)(unsafe.Pointer(&buf[0]))
	out := make([]net_ConnRow, 0, num)
	rowSize := int(unsafe.Sizeof(net_MIB_TCPROW_OWNER_PID{}))
	for i := uint32(0); i < num; i++ {
		off := 4 + int(i)*rowSize
		if off+rowSize > len(buf) {
			break
		}
		row := (*net_MIB_TCPROW_OWNER_PID)(unsafe.Pointer(&buf[off]))
		local := net_ipv4FromUint32(row.LocalAddr) + ":" + strconv.Itoa(int(net_ntohs(row.LocalPort)))
		remote := "*:*"
		if row.RemoteAddr != 0 || row.RemotePort != 0 {
			remote = net_ipv4FromUint32(row.RemoteAddr) + ":" + strconv.Itoa(int(net_ntohs(row.RemotePort)))
		}
		out = append(out, net_ConnRow{"tcp4", local, remote, row.State, row.OwningPid, ""})
	}
	return out, nil
}

func net_queryTcp6() ([]net_ConnRow, error) {
	buf, err := net_callTableFn(net_pGetExtendedTcpTable, net_AF_INET6, net_TCP_TABLE_OWNER_PID_ALL)
	if err != nil || len(buf) < 4 {
		return nil, err
	}
	num := *(*uint32)(unsafe.Pointer(&buf[0]))
	out := make([]net_ConnRow, 0, num)
	rowSize := int(unsafe.Sizeof(net_MIB_TCP6ROW_OWNER_PID{}))
	for i := uint32(0); i < num; i++ {
		off := 4 + int(i)*rowSize
		if off+rowSize > len(buf) {
			break
		}
		row := (*net_MIB_TCP6ROW_OWNER_PID)(unsafe.Pointer(&buf[off]))
		local := "[" + net_formatIPv6(row.ucLocalAddr[:]) + "]:" + strconv.Itoa(int(net_ntohs(row.dwLocalPort)))
		remote := "[::]:*"
		if row.ucRemoteAddr != [16]byte{} {
			remote = "[" + net_formatIPv6(row.ucRemoteAddr[:]) + "]:" + strconv.Itoa(int(net_ntohs(row.dwRemotePort)))
		}
		out = append(out, net_ConnRow{"tcp6", local, remote, row.dwState, row.dwOwningPid, ""})
	}
	return out, nil
}

func net_queryUdp4() ([]net_ConnRow, error) {
	buf, err := net_callTableFn(net_pGetExtendedUdpTable, net_AF_INET, net_UDP_TABLE_OWNER_PID)
	if err != nil || len(buf) < 4 {
		return nil, err
	}
	num := *(*uint32)(unsafe.Pointer(&buf[0]))
	out := make([]net_ConnRow, 0, num)
	rowSize := int(unsafe.Sizeof(net_MIB_UDPROW_OWNER_PID{}))
	for i := uint32(0); i < num; i++ {
		off := 4 + int(i)*rowSize
		if off+rowSize > len(buf) {
			break
		}
		row := (*net_MIB_UDPROW_OWNER_PID)(unsafe.Pointer(&buf[off]))
		local := net_ipv4FromUint32(row.LocalAddr) + ":" + strconv.Itoa(int(net_ntohs(row.LocalPort)))
		out = append(out, net_ConnRow{"udp4", local, "*:*", 0, row.OwningPid, ""})
	}
	return out, nil
}

func net_queryUdp6() ([]net_ConnRow, error) {
	buf, err := net_callTableFn(net_pGetExtendedUdpTable, net_AF_INET6, net_UDP_TABLE_OWNER_PID)
	if err != nil || len(buf) < 4 {
		return nil, err
	}
	num := *(*uint32)(unsafe.Pointer(&buf[0]))
	out := make([]net_ConnRow, 0, num)
	rowSize := int(unsafe.Sizeof(net_MIB_UDP6ROW_OWNER_PID{}))
	for i := uint32(0); i < num; i++ {
		off := 4 + int(i)*rowSize
		if off+rowSize > len(buf) {
			break
		}
		row := (*net_MIB_UDP6ROW_OWNER_PID)(unsafe.Pointer(&buf[off]))
		local := "[" + net_formatIPv6(row.ucLocalAddr[:]) + "]:" + strconv.Itoa(int(net_ntohs(row.dwLocalPort)))
		out = append(out, net_ConnRow{"udp6", local, "*:*", 0, row.dwOwningPid, ""})
	}
	return out, nil
}

type net_AdapterInfo struct {
	IfIndex     uint32
	Name        string
	Description string
	Mac         string
	IfType      uint32
	OperStatus  uint32
	IPv4s       []string
	IPv6s       []string
	DNS         []string
}

func net_queryAdapters() ([]net_AdapterInfo, error) {
	flags := uint32(net_GAA_FLAG_INCLUDE_PREFIX)
	family := uint32(net_AF_UNSPEC)
	var buf []byte
	for attempt := 0; attempt < 3; attempt++ {
		size := uint32(len(buf))
		var p uintptr
		if size > 0 {
			p = uintptr(unsafe.Pointer(&buf[0]))
		}
		r, _, _ := net_pGetAdaptersAddresses.Call(uintptr(family), uintptr(flags), 0, p,
			uintptr(unsafe.Pointer(&size)))
		if r == 0 && size > 0 {
			return net_parseAdapters(buf[:size])
		}
		if size == 0 {
			if r == 0 {
				return nil, nil
			}
			return nil, syscall.Errno(r)
		}
		buf = make([]byte, int(size)+16384)
	}
	return nil, fmt.Errorf("GetAdaptersAddresses: buffer size discovery failed")
}

func net_parseAdapters(buf []byte) ([]net_AdapterInfo, error) {
	if len(buf) == 0 {
		return nil, nil
	}
	var out []net_AdapterInfo
	cur := (*net_IP_ADAPTER_ADDRESSES_LH)(unsafe.Pointer(&buf[0]))
	for cur != nil {
		info := net_AdapterInfo{IfIndex: cur.IfIndex, IfType: cur.IfType, OperStatus: cur.OperStatus}
		info.Description = utf16At(cur.Description, 512)
		info.Name = utf16At(cur.FriendlyName, 512)
		if info.Name == "" {
			info.Name = info.Description
		}
		if cur.PhysicalAddressLength > 0 && cur.PhysicalAddressLength <= 8 {
			parts := make([]string, cur.PhysicalAddressLength)
			for i := uint32(0); i < cur.PhysicalAddressLength; i++ {
				parts[i] = fmt.Sprintf("%02x", cur.PhysicalAddress[i])
			}
			info.Mac = strings.Join(parts, "-")
		}
		for ua := cur.FirstUnicastAddress; ua != nil; ua = ua.Next {
			if ip, fam, ok := net_sockaddrToIP(ua.Address.lpSockaddr); ok {
				if fam == net_AF_INET {
					info.IPv4s = append(info.IPv4s, ip)
				} else if fam == net_AF_INET6 {
					info.IPv6s = append(info.IPv6s, ip)
				}
			}
		}
		for da := cur.FirstDnsServerAddress; da != nil; da = da.Next {
			if ip, _, ok := net_sockaddrToIP(da.Address.lpSockaddr); ok {
				info.DNS = append(info.DNS, ip)
			}
		}
		out = append(out, info)
		cur = cur.Next
	}
	sort.Slice(out, func(i, j int) bool { return out[i].IfIndex < out[j].IfIndex })
	return out, nil
}

type net_ProxyState struct {
	Enable   bool
	Server   string
	Override string
	Exists   bool
}

func net_readProxyState() net_ProxyState {
	var st net_ProxyState
	k, err := regOpenKey(HKCU, net_proxyKeyPath, KEY_READ)
	if err != nil {
		return st
	}
	defer regCloseKey(k)
	gotAny := false
	if v, err := regQueryValue(k, "ProxyEnable"); err == nil {
		if v.Type == REG_DWORD && len(v.Data) >= 4 {
			st.Enable = binary.LittleEndian.Uint32(v.Data) != 0
			gotAny = true
		}
	}
	if v, err := regQueryValue(k, "ProxyServer"); err == nil {
		if v.Type == REG_SZ || v.Type == REG_EXPAND_SZ {
			st.Server = decodeRegString(v.Data)
			gotAny = true
		}
	}
	if v, err := regQueryValue(k, "ProxyOverride"); err == nil {
		if v.Type == REG_SZ || v.Type == REG_EXPAND_SZ {
			st.Override = decodeRegString(v.Data)
			gotAny = true
		}
	}
	st.Exists = gotAny
	return st
}

func net_writeProxyState(st net_ProxyState) error {
	k, err := net_regCreateKey(HKCU, net_proxyKeyPath, KEY_WRITE)
	if err != nil {
		return err
	}
	defer regCloseKey(k)
	enData := make([]byte, 4)
	if st.Enable {
		binary.LittleEndian.PutUint32(enData, 1)
	}
	if err := regSetValue(k, "ProxyEnable", REG_DWORD, enData); err != nil {
		return err
	}
	if st.Server == "" {
		_ = regDeleteValue(k, "ProxyServer")
	} else if err := regSetValue(k, "ProxyServer", REG_SZ, encodeRegString(st.Server)); err != nil {
		return err
	}
	if st.Override == "" {
		_ = regDeleteValue(k, "ProxyOverride")
	} else if err := regSetValue(k, "ProxyOverride", REG_SZ, encodeRegString(st.Override)); err != nil {
		return err
	}
	return nil
}

func net_hostsPath() string {
	root := os.Getenv("SystemRoot")
	if root == "" {
		root = `C:\Windows`
	}
	return filepath.Join(root, `System32\drivers\etc\hosts`)
}

func net_applyHostsAdd(ip string, hostnames []string) error {
	data, err := os.ReadFile(net_hostsPath())
	if err != nil {
		return err
	}
	hostSet := make(map[string]bool, len(hostnames))
	for _, h := range hostnames {
		hostSet[strings.ToLower(h)] = true
	}
	var out []string
	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(make([]byte, 64*1024), 4*1024*1024)
	for scanner.Scan() {
		line := scanner.Text()
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			out = append(out, line)
			continue
		}
		fields := strings.Fields(trimmed)
		if len(fields) < 2 {
			out = append(out, line)
			continue
		}
		var kept []string
		for _, h := range fields[1:] {
			if !hostSet[strings.ToLower(h)] {
				kept = append(kept, h)
			}
		}
		if len(kept) == len(fields)-1 {
			out = append(out, line)
		} else if len(kept) > 0 {
			out = append(out, fields[0]+" "+strings.Join(kept, " "))
		}
	}
	out = append(out, ip+" "+strings.Join(hostnames, " "))
	body := strings.Join(out, "\r\n") + "\r\n"
	return os.WriteFile(net_hostsPath(), []byte(body), 0644)
}

func net_applyHostsRemove(hostnames []string) error {
	data, err := os.ReadFile(net_hostsPath())
	if err != nil {
		return err
	}
	hostSet := make(map[string]bool, len(hostnames))
	for _, h := range hostnames {
		hostSet[strings.ToLower(h)] = true
	}
	var out []string
	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(make([]byte, 64*1024), 4*1024*1024)
	for scanner.Scan() {
		line := scanner.Text()
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			out = append(out, line)
			continue
		}
		fields := strings.Fields(trimmed)
		if len(fields) < 2 {
			out = append(out, line)
			continue
		}
		var kept []string
		for _, h := range fields[1:] {
			if !hostSet[strings.ToLower(h)] {
				kept = append(kept, h)
			}
		}
		if len(kept) == len(fields)-1 {
			out = append(out, line)
		} else if len(kept) > 0 {
			out = append(out, fields[0]+" "+strings.Join(kept, " "))
		}
	}
	body := strings.Join(out, "\r\n")
	if body != "" && !strings.HasSuffix(body, "\r\n") {
		body += "\r\n"
	}
	return os.WriteFile(net_hostsPath(), []byte(body), 0644)
}

type net_proxySnap struct {
	Enable   bool   `json:"enable"`
	Server   string `json:"server,omitempty"`
	Override string `json:"override,omitempty"`
	Exists   bool   `json:"exists"`
}

type net_opRecord struct {
	Op            string         `json:"op"`
	TS            string         `json:"ts"`
	Cmd           string         `json:"cmd"`
	Code          int            `json:"code"`
	BackupFile    string         `json:"backupFile,omitempty"`
	BackupGzipped bool           `json:"backupGzipped,omitempty"`
	OldProxy      *net_proxySnap `json:"oldProxy,omitempty"`
	NewProxy      *net_proxySnap `json:"newProxy,omitempty"`
	HostsIP       string         `json:"hostsIP,omitempty"`
	HostsNames    []string       `json:"hostsNames,omitempty"`
	HostsRemove   []string       `json:"hostsRemove,omitempty"`
}

func net_saveOp(idx int, rec *net_opRecord) {
	if err := moduleSaveManifest("net", idx, rec); err != nil {
		bugs.Add("ERR", "save op %d: %v", idx, err)
	}
}

func net_loadOp(idx int) (*net_opRecord, error) {
	var rec net_opRecord
	if err := moduleLoadManifest("net", idx, &rec); err != nil {
		return nil, err
	}
	return &rec, nil
}

const net_smallHostsThreshold = 8192

func net_backupHosts(logIdx int) (string, bool, error) {
	data, err := os.ReadFile(net_hostsPath())
	if err != nil {
		return "", false, err
	}
	filesDir := moduleFilesDir("net")
	base := fmt.Sprintf("%d_hosts", logIdx)
	if len(data) < net_smallHostsThreshold {
		rel := base + ".hosts"
		full := filepath.Join(filesDir, rel)
		if err := os.MkdirAll(filesDir, 0755); err != nil {
			return "", false, err
		}
		if err := os.WriteFile(full, data, 0644); err != nil {
			return "", false, err
		}
		return rel, false, nil
	}
	rel := base + ".hosts.gz"
	full := filepath.Join(filesDir, rel)
	if err := os.MkdirAll(filesDir, 0755); err != nil {
		return "", false, err
	}
	f, err := os.Create(full)
	if err != nil {
		return "", false, err
	}
	gz, err := gzip.NewWriterLevel(f, gzip.BestCompression)
	if err != nil {
		f.Close()
		return "", false, err
	}
	if _, err := gz.Write(data); err != nil {
		gz.Close()
		f.Close()
		return "", false, err
	}
	if err := gz.Close(); err != nil {
		f.Close()
		return "", false, err
	}
	return rel, true, f.Close()
}

func net_restoreHosts(relPath string, gzipped bool) error {
	src := filepath.Join(moduleFilesDir("net"), relPath)
	var data []byte
	var err error
	if gzipped {
		f, ferr := os.Open(src)
		if ferr != nil {
			return ferr
		}
		defer f.Close()
		gz, gerr := gzip.NewReader(f)
		if gerr != nil {
			return gerr
		}
		defer gz.Close()
		data, err = io.ReadAll(gz)
	} else {
		data, err = os.ReadFile(src)
	}
	if err != nil {
		return err
	}
	return os.WriteFile(net_hostsPath(), data, 0644)
}

func net_tcpStateName(s uint32) string {
	switch s {
	case net_MIB_TCP_STATE_CLOSED:
		return "CLOSED"
	case net_MIB_TCP_STATE_LISTEN:
		return "LISTEN"
	case net_MIB_TCP_STATE_SYN_SENT:
		return "SYN_SENT"
	case net_MIB_TCP_STATE_SYN_RCVD:
		return "SYN_RCVD"
	case net_MIB_TCP_STATE_ESTAB:
		return "ESTABLISHED"
	case net_MIB_TCP_STATE_FIN_WAIT1:
		return "FIN_WAIT1"
	case net_MIB_TCP_STATE_FIN_WAIT2:
		return "FIN_WAIT2"
	case net_MIB_TCP_STATE_CLOSE_WAIT:
		return "CLOSE_WAIT"
	case net_MIB_TCP_STATE_CLOSING:
		return "CLOSING"
	case net_MIB_TCP_STATE_LAST_ACK:
		return "LAST_ACK"
	case net_MIB_TCP_STATE_TIME_WAIT:
		return "TIME_WAIT"
	case net_MIB_TCP_STATE_DELETE_TCB:
		return "DELETE_TCB"
	}
	return fmt.Sprintf("STATE_%d", s)
}

func net_tcpStateColor(s uint32) string {
	switch s {
	case net_MIB_TCP_STATE_ESTAB:
		return clrGreen
	case net_MIB_TCP_STATE_LISTEN:
		return clrCyan
	case net_MIB_TCP_STATE_TIME_WAIT, net_MIB_TCP_STATE_CLOSE_WAIT:
		return clrYellow
	}
	return clrGray
}

func net_processNameForPid(pid uint32) string {
	if pid == 0 {
		return ""
	}
	h, _, _ := net_pOpenProcess.Call(uintptr(net_PROCESS_QUERY_LIMITED), 0, uintptr(pid))
	if h == 0 {
		return ""
	}
	defer pCloseHandle.Call(h)
	buf := make([]uint16, 1024)
	size := uint32(len(buf))
	r, _, _ := net_pQueryFullProcessImageNameW.Call(h, 0,
		uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&size)))
	if r == 0 {
		return ""
	}
	return filepath.Base(syscall.UTF16ToString(buf[:size]))
}

func net_cmdConn(args []string) int {
	protoFilter := "all"
	stateFilter := ""
	portFilter := -1
	pidFilter := uint32(0xFFFFFFFF)
	showProcess, jsonOut := false, false
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "-t", "--type":
			if i+1 >= len(args) {
				fmt.Fprintln(os.Stderr, "conn: -t requires tcp|udp|all")
				return 2
			}
			protoFilter = strings.ToLower(args[i+1])
			switch protoFilter {
			case "all", "tcp", "udp", "tcp4", "tcp6", "udp4", "udp6":
			default:
				fmt.Fprintf(os.Stderr, "conn: invalid type %q (use tcp|udp|all)\n", protoFilter)
				return 2
			}
			i++
		case "-s", "--state":
			if i+1 >= len(args) {
				return 2
			}
			stateFilter = strings.ToUpper(args[i+1])
			i++
		case "--port":
			if i+1 >= len(args) {
				return 2
			}
			v, err := strconv.Atoi(args[i+1])
			if err != nil || v < 0 || v > 65535 {
				fmt.Fprintf(os.Stderr, "conn: invalid port %q\n", args[i+1])
				return 2
			}
			portFilter = v
			i++
		case "--pid":
			if i+1 >= len(args) {
				return 2
			}
			v, err := strconv.ParseUint(args[i+1], 10, 32)
			if err != nil {
				return 2
			}
			pidFilter = uint32(v)
			i++
		case "--process":
			showProcess = true
		case "--json":
			jsonOut = true
		default:
			if strings.HasPrefix(args[i], "-") {
				fmt.Fprintf(os.Stderr, "conn: unknown option %s\n", args[i])
				return 2
			}
		}
	}

	var rows []net_ConnRow
	add := func(src []net_ConnRow, err error) {
		if err != nil {
			bugs.Add("WARN", "query: %v", err)
			return
		}
		rows = append(rows, src...)
	}
	if protoFilter == "all" || protoFilter == "tcp" || protoFilter == "tcp4" {
		add(net_queryTcp4())
	}
	if protoFilter == "all" || protoFilter == "tcp" || protoFilter == "tcp6" {
		add(net_queryTcp6())
	}
	if protoFilter == "all" || protoFilter == "udp" || protoFilter == "udp4" {
		add(net_queryUdp4())
	}
	if protoFilter == "all" || protoFilter == "udp" || protoFilter == "udp6" {
		add(net_queryUdp6())
	}

	filtered := make([]net_ConnRow, 0, len(rows))
	for _, r := range rows {
		if stateFilter != "" && strings.HasPrefix(r.Proto, "tcp") {
			if net_tcpStateName(r.State) != stateFilter {
				continue
			}
		}
		if portFilter >= 0 {
			idx := strings.LastIndex(r.Local, ":")
			if idx < 0 {
				continue
			}
			p, _ := strconv.Atoi(r.Local[idx+1:])
			if p != portFilter {
				continue
			}
		}
		if pidFilter != 0xFFFFFFFF && r.Pid != pidFilter {
			continue
		}
		if showProcess && r.ProcName == "" {
			r.ProcName = net_processNameForPid(r.Pid)
		}
		filtered = append(filtered, r)
	}
	sort.Slice(filtered, func(i, j int) bool {
		if filtered[i].Proto != filtered[j].Proto {
			return filtered[i].Proto < filtered[j].Proto
		}
		return filtered[i].Local < filtered[j].Local
	})

	if jsonOut {
		out := make([]map[string]any, len(filtered))
		for i, r := range filtered {
			m := map[string]any{"proto": r.Proto, "local": r.Local, "remote": r.Remote, "pid": r.Pid}
			if strings.HasPrefix(r.Proto, "tcp") {
				m["state"] = net_tcpStateName(r.State)
			}
			if r.ProcName != "" {
				m["process"] = r.ProcName
			}
			out[i] = m
		}
		b, _ := json.MarshalIndent(out, "", "  ")
		fmt.Println(string(b))
		return 0
	}

	protoW := dispWidth("PROTO")
	localW := dispWidth("LOCAL")
	remoteW := dispWidth("REMOTE")
	stateW := dispWidth("STATE")
	pidW := dispWidth("PID")
	for _, r := range filtered {
		if w := dispWidth(r.Proto); w > protoW {
			protoW = w
		}
		if w := dispWidth(r.Local); w > localW {
			localW = w
		}
		if w := dispWidth(r.Remote); w > remoteW {
			remoteW = w
		}
		st := ""
		if strings.HasPrefix(r.Proto, "tcp") {
			st = net_tcpStateName(r.State)
		}
		if w := dispWidth(st); w > stateW {
			stateW = w
		}
		pidStr := strconv.FormatUint(uint64(r.Pid), 10)
		if w := dispWidth(pidStr); w > pidW {
			pidW = w
		}
	}
	header := padRight("PROTO", protoW) + "  " +
		padRight("LOCAL", localW) + "  " +
		padRight("REMOTE", remoteW) + "  " +
		padRight("STATE", stateW) + "  " +
		padRight("PID", pidW)
	if showProcess {
		header += "  PROCESS"
	}
	fmt.Println(c(clrBold+clrCyan, header))
	for _, r := range filtered {
		st := ""
		stColor := clrGray
		if strings.HasPrefix(r.Proto, "tcp") {
			st = net_tcpStateName(r.State)
			stColor = net_tcpStateColor(r.State)
		}
		line := padRight(r.Proto, protoW) + "  " +
			padRight(r.Local, localW) + "  " +
			padRight(r.Remote, remoteW) + "  " +
			c(stColor, padRight(st, stateW)) + "  " +
			c(clrGray, padRight(strconv.FormatUint(uint64(r.Pid), 10), pidW))
		if showProcess {
			line += "  " + c(clrCyan, r.ProcName)
		}
		fmt.Println(line)
	}
	fmt.Fprintf(os.Stderr, "\n%d connection(s)\n", len(filtered))
	return 0
}

func net_adapterTypeName(t uint32) string {
	switch t {
	case net_IF_TYPE_ETHERNET_CSMACD:
		return "ethernet"
	case net_IF_TYPE_IEEE80211:
		return "wifi"
	case net_IF_TYPE_SOFTWARE_LOOPBACK:
		return "loopback"
	case net_IF_TYPE_TUNNEL:
		return "tunnel"
	}
	return fmt.Sprintf("iftype-%d", t)
}

func net_cmdAdapters(args []string) int {
	jsonOut, upOnly := false, false
	for _, a := range args {
		switch a {
		case "--json":
			jsonOut = true
		case "--up":
			upOnly = true
		default:
			if strings.HasPrefix(a, "-") {
				fmt.Fprintf(os.Stderr, "adapters: unknown option %s\n", a)
				return 2
			}
		}
	}
	adapters, err := net_queryAdapters()
	if err != nil {
		fmt.Fprintf(os.Stderr, "netctl: %v\n", err)
		return 5
	}
	if upOnly {
		var f []net_AdapterInfo
		for _, a := range adapters {
			if a.OperStatus == net_IfOperStatusUp {
				f = append(f, a)
			}
		}
		adapters = f
	}
	if jsonOut {
		out := make([]map[string]any, len(adapters))
		for i, a := range adapters {
			o := map[string]any{
				"ifIndex": a.IfIndex, "name": a.Name, "description": a.Description,
				"mac": a.Mac, "type": net_adapterTypeName(a.IfType),
				"up": a.OperStatus == net_IfOperStatusUp,
			}
			if len(a.IPv4s) > 0 {
				o["ipv4"] = a.IPv4s
			}
			if len(a.IPv6s) > 0 {
				o["ipv6"] = a.IPv6s
			}
			if len(a.DNS) > 0 {
				o["dns"] = a.DNS
			}
			out[i] = o
		}
		b, _ := json.MarshalIndent(out, "", "  ")
		fmt.Println(string(b))
		return 0
	}
	idxW := dispWidth("IDX")
	nameW := dispWidth("NAME")
	typeW := dispWidth("TYPE")
	statusW := dispWidth("STATUS")
	for _, a := range adapters {
		if w := dispWidth(strconv.FormatUint(uint64(a.IfIndex), 10)); w > idxW {
			idxW = w
		}
		if w := dispWidth(a.Name); w > nameW {
			nameW = w
		}
		if w := dispWidth(net_adapterTypeName(a.IfType)); w > typeW {
			typeW = w
		}
		st := "down"
		if a.OperStatus == net_IfOperStatusUp {
			st = "up"
		}
		if w := dispWidth(st); w > statusW {
			statusW = w
		}
	}
	header := padRight("IDX", idxW) + "  " +
		padRight("NAME", nameW) + "  " +
		padRight("TYPE", typeW) + "  " +
		padRight("STATUS", statusW) + "  " +
		"MAC              IPV4                    DNS"
	fmt.Println(c(clrBold+clrCyan, header))
	for _, a := range adapters {
		st := "down"
		stColor := clrGray
		if a.OperStatus == net_IfOperStatusUp {
			st, stColor = "up", clrGreen
		}
		line := padRight(strconv.FormatUint(uint64(a.IfIndex), 10), idxW) + "  " +
			padRight(a.Name, nameW) + "  " +
			padRight(net_adapterTypeName(a.IfType), typeW) + "  " +
			c(stColor, padRight(st, statusW)) + "  " +
			padRight(a.Mac, 16) + " " +
			padRight(strings.Join(a.IPv4s, ","), 23) + " " +
			c(clrGray, strings.Join(a.DNS, ","))
		fmt.Println(line)
	}
	fmt.Fprintf(os.Stderr, "\n%d adapter(s)\n", len(adapters))
	return 0
}

func net_cmdDns(args []string) int {
	jsonOut := false
	adapterFilter := ""
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--json":
			jsonOut = true
		case "--adapter":
			if i+1 >= len(args) {
				return 2
			}
			adapterFilter = args[i+1]
			i++
		default:
			if strings.HasPrefix(args[i], "-") {
				fmt.Fprintf(os.Stderr, "dns: unknown option %s\n", args[i])
				return 2
			}
		}
	}
	adapters, err := net_queryAdapters()
	if err != nil {
		fmt.Fprintf(os.Stderr, "netctl: %v\n", err)
		return 5
	}
	type dnsEntry struct {
		Name    string   `json:"name"`
		IfIndex uint32   `json:"ifIndex"`
		DNS     []string `json:"dns"`
	}
	var entries []dnsEntry
	for _, a := range adapters {
		if adapterFilter != "" && !strings.EqualFold(a.Name, adapterFilter) {
			continue
		}
		if len(a.DNS) == 0 {
			continue
		}
		entries = append(entries, dnsEntry{a.Name, a.IfIndex, a.DNS})
	}
	if jsonOut {
		b, _ := json.MarshalIndent(entries, "", "  ")
		fmt.Println(string(b))
		return 0
	}
	if len(entries) == 0 {
		fmt.Fprintln(os.Stderr, "no DNS servers configured on matching adapters")
		return 0
	}
	nameW := dispWidth("ADAPTER")
	idxW := dispWidth("IDX")
	for _, e := range entries {
		if w := dispWidth(e.Name); w > nameW {
			nameW = w
		}
		if w := dispWidth(strconv.FormatUint(uint64(e.IfIndex), 10)); w > idxW {
			idxW = w
		}
	}
	fmt.Println(c(clrBold+clrCyan, padRight("ADAPTER", nameW)+"  "+padRight("IDX", idxW)+"  SERVERS"))
	for _, e := range entries {
		fmt.Println(padRight(e.Name, nameW) + "  " +
			padRight(strconv.FormatUint(uint64(e.IfIndex), 10), idxW) + "  " +
			c(clrCyan, strings.Join(e.DNS, ", ")))
	}
	fmt.Fprintf(os.Stderr, "\n%d adapter(s) with DNS configured\n", len(entries))
	return 0
}

var net_hostRe = regexp.MustCompile(`^[A-Za-z0-9._\-]+$`)

func net_validIP(s string) bool {
	if s == "" || len(s) > 45 {
		return false
	}
	if strings.Count(s, ".") == 3 && !strings.Contains(s, ":") {
		parts := strings.Split(s, ".")
		if len(parts) != 4 {
			return false
		}
		for _, p := range parts {
			if p == "" || len(p) > 3 {
				return false
			}
			n, err := strconv.Atoi(p)
			if err != nil || n < 0 || n > 255 {
				return false
			}
		}
		return true
	}
	if !strings.Contains(s, ":") {
		return false
	}
	for _, r := range s {
		if (r >= '0' && r <= '9') || (r >= 'a' && r <= 'f') || (r >= 'A' && r <= 'F') || r == ':' || r == '.' {
			continue
		}
		return false
	}
	return true
}

func net_cmdHosts(args []string) int {
	sub := "show"
	var rest []string
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		sub = args[0]
		rest = args[1:]
	} else {
		rest = args
	}
	switch sub {
	case "show":
		data, err := os.ReadFile(net_hostsPath())
		if err != nil {
			fmt.Fprintf(os.Stderr, "netctl: %v\n", err)
			return 5
		}
		lines := strings.Split(string(data), "\n")
		fmt.Println(c(clrBold+clrCyan, net_hostsPath()))
		for i, line := range lines {
			if line == "" {
				continue
			}
			trimmed := strings.TrimSpace(line)
			color := ""
			switch {
			case strings.HasPrefix(trimmed, "#"):
				color = clrGray
			case len(strings.Fields(trimmed)) >= 2:
				color = clrCyan
			}
			if color != "" {
				fmt.Printf("%4d  %s\n", i+1, c(color, line))
			} else {
				fmt.Printf("%4d  %s\n", i+1, line)
			}
		}
		return 0

	case "add":
		if len(rest) < 2 {
			fmt.Fprintln(os.Stderr, "usage: winctl net hosts add <ip> <hostname...> [-f]")
			return 2
		}
		force := false
		var pos []string
		for _, a := range rest {
			if a == "-f" || a == "--force" {
				force = true
				continue
			}
			pos = append(pos, a)
		}
		if len(pos) < 2 {
			return 2
		}
		ip := pos[0]
		if !net_validIP(ip) {
			fmt.Fprintf(os.Stderr, "hosts add: invalid IP %q\n", ip)
			return 2
		}
		hostnames := pos[1:]
		for _, h := range hostnames {
			if !net_hostRe.MatchString(h) {
				fmt.Fprintf(os.Stderr, "hosts add: invalid hostname %q\n", h)
				return 2
			}
		}
		if dryRun {
			fmt.Printf("[dry-run] hosts add %s %s\n", ip, strings.Join(hostnames, " "))
			return 0
		}
		if !force && !confirm(fmt.Sprintf("add to hosts: %s -> %s?", strings.Join(hostnames, " "), ip)) {
			return 1
		}
		idx := auditLog("net", buildCmdLine(os.Args), 0)
		backupRel, backupGz, err := net_backupHosts(idx)
		if err != nil {
			fmt.Fprintf(os.Stderr, "netctl: backup failed, aborting: %v\n", err)
			return 5
		}
		if err := net_applyHostsAdd(ip, hostnames); err != nil {
			fmt.Fprintf(os.Stderr, "netctl: %v\n", err)
			return 5
		}
		net_saveOp(idx, &net_opRecord{
			Op: "hosts-add", TS: time.Now().Format("2006-01-02 15:04:05"),
			Cmd: buildCmdLine(os.Args), BackupFile: backupRel, BackupGzipped: backupGz,
			HostsIP: ip, HostsNames: hostnames,
		})
		fmt.Printf("%s hosts: %s -> %s\n", c(clrGreen, "added"), strings.Join(hostnames, " "), ip)
		return 0

	case "remove", "rm":
		force := false
		var hostnames []string
		for _, a := range rest {
			if a == "-f" || a == "--force" {
				force = true
				continue
			}
			hostnames = append(hostnames, a)
		}
		if len(hostnames) == 0 {
			fmt.Fprintln(os.Stderr, "usage: winctl net hosts remove <hostname...> [-f]")
			return 2
		}
		if dryRun {
			fmt.Printf("[dry-run] hosts remove %s\n", strings.Join(hostnames, " "))
			return 0
		}
		if !force && !confirm(fmt.Sprintf("remove from hosts: %s?", strings.Join(hostnames, " "))) {
			return 1
		}
		idx := auditLog("net", buildCmdLine(os.Args), 0)
		backupRel, backupGz, err := net_backupHosts(idx)
		if err != nil {
			fmt.Fprintf(os.Stderr, "netctl: backup failed, aborting: %v\n", err)
			return 5
		}
		if err := net_applyHostsRemove(hostnames); err != nil {
			fmt.Fprintf(os.Stderr, "netctl: %v\n", err)
			return 5
		}
		net_saveOp(idx, &net_opRecord{
			Op: "hosts-remove", TS: time.Now().Format("2006-01-02 15:04:05"),
			Cmd: buildCmdLine(os.Args), BackupFile: backupRel, BackupGzipped: backupGz,
			HostsRemove: hostnames,
		})
		fmt.Printf("%s hosts: %s\n", c(clrYellow, "removed"), strings.Join(hostnames, " "))
		return 0

	case "restore":
		return net_hostsManualRestore()
	}
	fmt.Fprintf(os.Stderr, "hosts: unknown subcommand %q (show|add|remove|restore)\n", sub)
	return 2
}

func net_hostsManualRestore() int {
	idxs, err := moduleTailOps("net", 1000)
	if err != nil {
		fmt.Fprintf(os.Stderr, "netctl: %v\n", err)
		return 4
	}
	for _, i := range idxs {
		rec, err := net_loadOp(i)
		if err != nil {
			continue
		}
		if rec.Op != "hosts-add" && rec.Op != "hosts-remove" {
			continue
		}
		if rec.BackupFile == "" {
			continue
		}
		if err := net_restoreHosts(rec.BackupFile, rec.BackupGzipped); err != nil {
			fmt.Fprintf(os.Stderr, "netctl: restore: %v\n", err)
			return 5
		}
		fmt.Fprintf(os.Stderr, "restored hosts from op #%d\n", i)
		return 0
	}
	fmt.Fprintln(os.Stderr, "no hosts backup found in log")
	return 4
}

func net_printProxy(st net_ProxyState) {
	fmt.Printf("%s %v\n", c(clrCyan, "Enable:  "), st.Enable)
	if st.Server != "" {
		fmt.Printf("%s %s\n", c(clrCyan, "Server:  "), st.Server)
	}
	if st.Override != "" {
		fmt.Printf("%s %s\n", c(clrCyan, "Bypass:  "), st.Override)
	}
	if st.Server == "" && st.Override == "" && !st.Enable {
		fmt.Println(c(clrGray, "(no proxy configured)"))
	}
}

func net_cmdProxy(args []string) int {
	sub := "show"
	var rest []string
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		sub = args[0]
		rest = args[1:]
	} else {
		rest = args
	}
	switch sub {
	case "show":
		net_printProxy(net_readProxyState())
		return 0

	case "set":
		var server, bypass string
		force := false
		var pos []string
		for i := 0; i < len(rest); i++ {
			switch rest[i] {
			case "--bypass":
				if i+1 >= len(rest) {
					return 2
				}
				bypass = rest[i+1]
				i++
			case "-f", "--force":
				force = true
			default:
				pos = append(pos, rest[i])
			}
		}
		if len(pos) == 0 {
			fmt.Fprintln(os.Stderr, "usage: winctl net proxy set <server> [--bypass <list>] [-f]")
			return 2
		}
		server = pos[0]
		if dryRun {
			fmt.Printf("[dry-run] proxy set %s (bypass=%q)\n", server, bypass)
			return 0
		}
		old := net_readProxyState()
		if !force {
			fmt.Fprintf(os.Stderr, "old: enable=%v server=%q bypass=%q\n", old.Enable, old.Server, old.Override)
			if !confirm(fmt.Sprintf("set proxy to %q?", server)) {
				return 1
			}
		}
		idx := auditLog("net", buildCmdLine(os.Args), 0)
		newState := net_ProxyState{Enable: true, Server: server, Override: bypass, Exists: true}
		if err := net_writeProxyState(newState); err != nil {
			fmt.Fprintf(os.Stderr, "netctl: set proxy: %v\n", err)
			return 5
		}
		net_saveOp(idx, &net_opRecord{
			Op: "proxy-set", TS: time.Now().Format("2006-01-02 15:04:05"),
			Cmd:      buildCmdLine(os.Args),
			OldProxy: &net_proxySnap{Enable: old.Enable, Server: old.Server, Override: old.Override, Exists: old.Exists},
			NewProxy: &net_proxySnap{Enable: true, Server: server, Override: bypass, Exists: true},
		})
		fmt.Printf("%s proxy = %s\n", c(clrGreen, "set"), server)
		return 0

	case "unset":
		force := false
		for _, a := range rest {
			if a == "-f" || a == "--force" {
				force = true
			} else if strings.HasPrefix(a, "-") {
				fmt.Fprintf(os.Stderr, "proxy unset: unknown option %s\n", a)
				return 2
			}
		}
		if dryRun {
			fmt.Println("[dry-run] proxy unset")
			return 0
		}
		old := net_readProxyState()
		if !force {
			fmt.Fprintf(os.Stderr, "old: enable=%v server=%q bypass=%q\n", old.Enable, old.Server, old.Override)
			if !confirm("disable system proxy?") {
				return 1
			}
		}
		idx := auditLog("net", buildCmdLine(os.Args), 0)
		if err := net_writeProxyState(net_ProxyState{Enable: false}); err != nil {
			fmt.Fprintf(os.Stderr, "netctl: unset proxy: %v\n", err)
			return 5
		}
		net_saveOp(idx, &net_opRecord{
			Op: "proxy-unset", TS: time.Now().Format("2006-01-02 15:04:05"),
			Cmd:      buildCmdLine(os.Args),
			OldProxy: &net_proxySnap{Enable: old.Enable, Server: old.Server, Override: old.Override, Exists: old.Exists},
			NewProxy: &net_proxySnap{Enable: false},
		})
		fmt.Printf("%s proxy disabled\n", c(clrYellow, "unset"))
		return 0

	case "restore":
		return net_proxyManualRestore()
	}
	fmt.Fprintf(os.Stderr, "proxy: unknown subcommand %q (show|set|unset|restore)\n", sub)
	return 2
}

func net_proxyManualRestore() int {
	idxs, err := moduleTailOps("net", 1000)
	if err != nil {
		return 4
	}
	for _, i := range idxs {
		rec, err := net_loadOp(i)
		if err != nil {
			continue
		}
		if rec.Op != "proxy-set" && rec.Op != "proxy-unset" {
			continue
		}
		if rec.OldProxy == nil {
			continue
		}
		if !rec.OldProxy.Exists {
			k, err := regOpenKey(HKCU, net_proxyKeyPath, KEY_WRITE)
			if err == nil {
				_ = regDeleteValue(k, "ProxyEnable")
				_ = regDeleteValue(k, "ProxyServer")
				_ = regDeleteValue(k, "ProxyOverride")
				regCloseKey(k)
			}
			fmt.Fprintf(os.Stderr, "restored proxy from op #%d (removed)\n", i)
			return 0
		}
		st := net_ProxyState{Enable: rec.OldProxy.Enable, Server: rec.OldProxy.Server, Override: rec.OldProxy.Override, Exists: rec.OldProxy.Exists}
		if err := net_writeProxyState(st); err != nil {
			fmt.Fprintf(os.Stderr, "netctl: restore: %v\n", err)
			return 5
		}
		fmt.Fprintf(os.Stderr, "restored proxy from op #%d\n", i)
		return 0
	}
	fmt.Fprintln(os.Stderr, "no proxy backup found in log")
	return 4
}

func net_cmdHistory() int {
	lines, err := auditReadLines()
	if err != nil {
		fmt.Fprintf(os.Stderr, "read log: %v\n", err)
		return 4
	}
	if len(lines) == 0 {
		fmt.Fprintln(os.Stderr, "log is empty")
		return 0
	}
	count := 0
	for i := len(lines) - 1; i >= 0; i-- {
		m, cmd, _, ok := auditParseLine(lines[i])
		if !ok || m != "net" {
			continue
		}
		if isHistorySelf(cmd) || !moduleManifestExists("net", i) {
			continue
		}
		desc := ""
		if rec, e := net_loadOp(i); e == nil {
			desc = net_summarizeOp(rec)
		}
		count++
		fmt.Printf("[%d] %s %s\n", count, lines[i], c(clrGray, desc))
	}
	if count == 0 {
		fmt.Fprintln(os.Stderr, "no rollback-able net operations in log")
	}
	return 0
}

func net_summarizeOp(rec *net_opRecord) string {
	switch rec.Op {
	case "hosts-add":
		return "-> restore hosts (" + strings.Join(rec.HostsNames, ",") + " removed)"
	case "hosts-remove":
		return "-> restore hosts"
	case "proxy-set":
		if rec.OldProxy != nil && rec.OldProxy.Exists {
			return "-> restore proxy to " + rec.OldProxy.Server
		}
		return "-> disable proxy"
	case "proxy-unset":
		if rec.OldProxy != nil && rec.OldProxy.Exists {
			return "-> restore proxy to " + rec.OldProxy.Server
		}
		return "-> (no prior proxy to restore)"
	}
	return ""
}

func net_cmdRollback(args []string) int {
	n := 1
	for i := 0; i < len(args); i++ {
		if args[i] == "-n" || args[i] == "--last" {
			if i+1 >= len(args) {
				return 2
			}
			v, err := strconv.Atoi(args[i+1])
			if err != nil || v <= 0 {
				return 2
			}
			n = v
			i++
		} else if strings.HasPrefix(args[i], "-") {
			fmt.Fprintf(os.Stderr, "rollback: unknown option %s\n", args[i])
			return 2
		}
	}
	idxs, err := moduleTailOps("net", n)
	if err != nil || len(idxs) == 0 {
		fmt.Fprintln(os.Stderr, "no rollback-able net operations found")
		return 4
	}
	if dryRun {
		for k, i := range idxs {
			if rec, err := net_loadOp(i); err == nil {
				fmt.Printf("[dry-run] step %d: %s %s\n", k+1, rec.Op, net_summarizeOp(rec))
			}
		}
		return 0
	}
	okCount, failCount := 0, 0
	for k, i := range idxs {
		rec, err := net_loadOp(i)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[rollback] step %d: %v\n", k+1, err)
			failCount++
			continue
		}
		if err := net_rollbackOne(rec); err != nil {
			fmt.Fprintf(os.Stderr, "[rollback] step %d: %v\n", k+1, err)
			failCount++
			continue
		}
		fmt.Fprintf(os.Stderr, "[rollback] step %d: %s ok\n", k+1, rec.Op)
		okCount++
	}
	if failCount == 0 {
		return 0
	}
	if okCount == 0 {
		return 2
	}
	return 1
}

func net_rollbackOne(rec *net_opRecord) error {
	switch rec.Op {
	case "hosts-add", "hosts-remove":
		if rec.BackupFile == "" {
			return fmt.Errorf("no hosts backup recorded")
		}
		return net_restoreHosts(rec.BackupFile, rec.BackupGzipped)
	case "proxy-set", "proxy-unset":
		if rec.OldProxy == nil {
			return fmt.Errorf("no old proxy recorded")
		}
		if !rec.OldProxy.Exists {
			k, err := regOpenKey(HKCU, net_proxyKeyPath, KEY_WRITE)
			if err != nil {
				return nil
			}
			defer regCloseKey(k)
			_ = regDeleteValue(k, "ProxyEnable")
			_ = regDeleteValue(k, "ProxyServer")
			_ = regDeleteValue(k, "ProxyOverride")
			return nil
		}
		return net_writeProxyState(net_ProxyState{
			Enable: rec.OldProxy.Enable, Server: rec.OldProxy.Server,
			Override: rec.OldProxy.Override, Exists: rec.OldProxy.Exists,
		})
	}
	return fmt.Errorf("unknown op %q", rec.Op)
}

func net_printHelp() {
	fmt.Printf("%s v%s (Windows)\n\n", c(clrBold+clrCyan, "winctl net"), Version)
	fmt.Print(`USAGE
  winctl net conn [OPTIONS]
  winctl net dns [OPTIONS]
  winctl net adapters [OPTIONS]
  winctl net hosts [show|add|remove|restore]
  winctl net proxy [show|set|unset|restore]
  winctl net --history
  winctl net --rollback [-n N]

CONN
  -t, --type tcp|udp|all     protocol filter (default all)
  -s, --state LISTEN         TCP state filter
  --port N                   local port filter
  --pid N                    owning PID filter
  --process                  resolve PID to process name
  --json                     JSON output

DNS
  --adapter NAME             only this adapter
  --json                     JSON output

ADAPTERS
  --up                       only adapters that are up
  --json                     JSON output

HOSTS
  hosts show                 print the file with line numbers
  hosts add <ip> <name...>   replace any existing mapping and append
  hosts remove <name...>     strip <name...> from every line
  hosts restore              restore the most recent hosts backup

PROXY
  proxy show                 display current settings
  proxy set <server>         enable the proxy
    --bypass <list>          set ProxyOverride
  proxy unset                disable the proxy
  proxy restore              restore the most recent proxy backup

GLOBAL
  -o, --out <path>           write stdout to a file
  --dry-run                  preview only
  --no-color                 disable ANSI colors (also honors NO_COLOR)
  -b, --bugs                 print collected errors/warnings on exit
  -h, --help                 show this help
  --version                  show version

All logs go to ./backup/winctl_logs.log
All backups go to ./backup/net/{ops,files}/
`)
}

func net_main() {
	args, outPath, err := consumeGlobalFlags(os.Args[1:])
	if err != nil {
		fmt.Fprintf(os.Stderr, "winctl net: %v\n", err)
		finalExit(2)
	}
	initColor()
	if outPath != "" {
		if err := setupOutput(outPath); err != nil {
			fmt.Fprintf(os.Stderr, "winctl net: %v\n", err)
			finalExit(2)
		}
	}

	if has(args, "--version") {
		fmt.Printf("winctl net v%s\n", Version)
		finalExit(0)
	}
	if len(args) == 0 || has(args, "-h", "--help") {
		net_printHelp()
		finalExit(0)
	}

	var code int
	switch {
	case has(args, "--history"):
		code = net_cmdHistory()
	case has(args, "--rollback"):
		code = net_cmdRollback(stripFlags(args, "--rollback"))
	default:
		cmdIdx := -1
		for i, a := range args {
			if !strings.HasPrefix(a, "-") {
				cmdIdx = i
				break
			}
		}
		if cmdIdx < 0 {
			fmt.Fprintln(os.Stderr, "winctl net: missing command, use -h for help")
			code = 2
			break
		}
		cmd := args[cmdIdx]
		rest := append([]string{}, args[:cmdIdx]...)
		rest = append(rest, args[cmdIdx+1:]...)
		switch cmd {
		case "conn", "connections":
			code = net_cmdConn(rest)
		case "dns":
			code = net_cmdDns(rest)
		case "adapters", "if":
			code = net_cmdAdapters(rest)
		case "hosts":
			code = net_cmdHosts(rest)
		case "proxy":
			code = net_cmdProxy(rest)
		default:
			fmt.Fprintf(os.Stderr, "winctl net: unknown command %q\n", cmd)
			code = 2
		}
	}
	if !dryRun && shouldLogRun() {
		auditLog("net", buildCmdLine(os.Args), code)
	}
	finalExit(code)
}
// ============================================================================
// open — file type identification + read-only preview + decrypt attempt
// ============================================================================
//
// Read-only module: it never writes to the inspected file, the registry,
// or any other state. --rollback is therefore always a no-op.
//
// Performance:
//   info / preview read at most open_maxAnalyzeBytes (64 MB) from the head.
//   decrypt loads at most open_maxDecryptBytes (256 MB) into memory.
//   Anything larger prints a Note: line and works on the head sample only.

type open_MagicSig struct {
	Offset   int
	Bytes    []byte
	Ext      string
	Desc     string
	Category string
}

var open_magicSigs = []open_MagicSig{
	// images
	{0, []byte{0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A}, "PNG", "PNG image", "image"},
	{0, []byte{0xFF, 0xD8, 0xFF}, "JPEG", "JPEG image", "image"},
	{0, []byte{0x47, 0x49, 0x46, 0x38}, "GIF", "GIF image", "image"},
	{0, []byte{0x42, 0x4D}, "BMP", "Windows bitmap", "image"},
	{0, []byte{0x49, 0x49, 0x2A, 0x00}, "TIFF", "TIFF image (LE)", "image"},
	{0, []byte{0x4D, 0x4D, 0x00, 0x2A}, "TIFF", "TIFF image (BE)", "image"},
	{0, []byte{0x00, 0x00, 0x01, 0x00}, "ICO", "Windows icon", "image"},
	{0, []byte{0x52, 0x49, 0x46, 0x46}, "RIFF", "RIFF container", "media"},
	// archives
	{0, []byte{0x50, 0x4B, 0x03, 0x04}, "ZIP", "ZIP archive", "archive"},
	{0, []byte{0x50, 0x4B, 0x05, 0x06}, "ZIP", "Empty ZIP archive", "archive"},
	{0, []byte{0x52, 0x61, 0x72, 0x21, 0x1A, 0x07}, "RAR", "RAR archive", "archive"},
	{0, []byte{0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C}, "7Z", "7-Zip archive", "archive"},
	{0, []byte{0x1F, 0x8B}, "GZ", "gzip compressed data", "archive"},
	{0, []byte{0x42, 0x5A, 0x68}, "BZ2", "bzip2 compressed data", "archive"},
	{0, []byte{0xFD, 0x37, 0x7A, 0x58, 0x5A, 0x00}, "XZ", "xz compressed data", "archive"},
	{0, []byte{0x28, 0xB5, 0x2F, 0xFD}, "ZST", "zstd compressed data", "archive"},
	{0, []byte{0x04, 0x22, 0x4D, 0x18}, "LZ4", "lz4 compressed data", "archive"},
	// documents
	{0, []byte{0x25, 0x50, 0x44, 0x46}, "PDF", "PDF document", "document"},
	{0, []byte{0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1}, "OLE", "OLE compound file", "document"},
	// executables
	{0, []byte{0x4D, 0x5A}, "PE", "DOS / Windows PE executable", "executable"},
	{0, []byte{0x7F, 0x45, 0x4C, 0x46}, "ELF", "ELF executable", "executable"},
	{0, []byte{0xCA, 0xFE, 0xBA, 0xBE}, "CLASS", "Java class / Mach-O fat", "executable"},
	{0, []byte{0xFE, 0xED, 0xFA, 0xCE}, "MACHO", "Mach-O 32-bit", "executable"},
	{0, []byte{0xFE, 0xED, 0xFA, 0xCF}, "MACHO", "Mach-O 64-bit", "executable"},
	// structured data
	{0, []byte("SQLite format 3\x00"), "SQLITE", "SQLite 3 database", "database"},
	{0, []byte{0x53, 0x51, 0x4C, 0x69}, "SQLITE", "SQLite database", "database"},
	{0, []byte{0x7B, 0x5C, 0x72, 0x74, 0x66}, "RTF", "RTF document", "document"},
	// media
	{0, []byte{0x30, 0x26, 0xB2, 0x75}, "WMV", "Windows Media Video", "media"},
	{0, []byte{0x00, 0x00, 0x00, 0x18, 0x66, 0x74, 0x79, 0x70}, "MP4", "MP4 video", "media"},
	{0, []byte{0x66, 0x74, 0x79, 0x70, 0x69, 0x73}, "MP4", "MP4 video", "media"},
	{0, []byte{0x66, 0x4C, 0x61, 0x43}, "FLAC", "FLAC audio", "media"},
	{0, []byte{0x4F, 0x67, 0x67, 0x53}, "OGG", "Ogg container", "media"},
	{0, []byte{0x49, 0x44, 0x33}, "MP3", "MP3 with ID3 tag", "media"},
	{0, []byte{0xFF, 0xFB}, "MP3", "MP3 audio", "media"},
}

type open_PESection struct {
	Name            string
	VirtualSize     uint32
	VirtualAddr     uint32
	RawSize         uint32
	RawPtr          uint32
	Characteristics uint32
}

type open_PEInfo struct {
	Valid            bool
	Machine          uint16
	NumberOfSections uint16
	Timestamp        uint32
	Characteristics  uint16
	OptionalMagic    uint16
	EntryPoint       uint32
	ImageBase        uint64
	Subsystem        uint16
	Sections         []open_PESection
}

type open_FileType struct {
	Ext          string
	Description  string
	Category     string
	ByMagic      bool
	ByExtension  bool
	Encrypted    bool
	Text         bool
	EntropyValue float64
	Size         int64
	PE           *open_PEInfo
}

var open_extMap = map[string]open_FileType{
	"txt":  {Ext: "TXT", Description: "Plain text", Category: "text"},
	"log":  {Ext: "LOG", Description: "Log file", Category: "text"},
	"md":   {Ext: "MD", Description: "Markdown", Category: "text"},
	"json": {Ext: "JSON", Description: "JSON document", Category: "text"},
	"xml":  {Ext: "XML", Description: "XML document", Category: "text"},
	"yaml": {Ext: "YAML", Description: "YAML document", Category: "text"},
	"yml":  {Ext: "YAML", Description: "YAML document", Category: "text"},
	"ini":  {Ext: "INI", Description: "INI config", Category: "text"},
	"cfg":  {Ext: "CFG", Description: "Config file", Category: "text"},
	"conf": {Ext: "CONF", Description: "Config file", Category: "text"},
	"csv":  {Ext: "CSV", Description: "CSV data", Category: "text"},
	"html": {Ext: "HTML", Description: "HTML document", Category: "text"},
	"htm":  {Ext: "HTML", Description: "HTML document", Category: "text"},
	"css":  {Ext: "CSS", Description: "CSS stylesheet", Category: "text"},
	"js":   {Ext: "JS", Description: "JavaScript", Category: "text"},
	"ts":   {Ext: "TS", Description: "TypeScript", Category: "text"},
	"go":   {Ext: "GO", Description: "Go source", Category: "text"},
	"py":   {Ext: "PY", Description: "Python source", Category: "text"},
	"rs":   {Ext: "RS", Description: "Rust source", Category: "text"},
	"c":    {Ext: "C", Description: "C source", Category: "text"},
	"h":    {Ext: "H", Description: "C header", Category: "text"},
	"cpp":  {Ext: "CPP", Description: "C++ source", Category: "text"},
	"hpp":  {Ext: "HPP", Description: "C++ header", Category: "text"},
	"java": {Ext: "JAVA", Description: "Java source", Category: "text"},
	"bat":  {Ext: "BAT", Description: "Batch script", Category: "text"},
	"cmd":  {Ext: "CMD", Description: "Batch script", Category: "text"},
	"ps1":  {Ext: "PS1", Description: "PowerShell script", Category: "text"},
	"sh":   {Ext: "SH", Description: "Shell script", Category: "text"},
	"png":  {Ext: "PNG", Description: "PNG image", Category: "image"},
	"jpg":  {Ext: "JPEG", Description: "JPEG image", Category: "image"},
	"jpeg": {Ext: "JPEG", Description: "JPEG image", Category: "image"},
	"gif":  {Ext: "GIF", Description: "GIF image", Category: "image"},
	"bmp":  {Ext: "BMP", Description: "Windows bitmap", Category: "image"},
	"ico":  {Ext: "ICO", Description: "Windows icon", Category: "image"},
	"zip":  {Ext: "ZIP", Description: "ZIP archive", Category: "archive"},
	"rar":  {Ext: "RAR", Description: "RAR archive", Category: "archive"},
	"7z":   {Ext: "7Z", Description: "7-Zip archive", Category: "archive"},
	"gz":   {Ext: "GZ", Description: "gzip compressed data", Category: "archive"},
	"tar":  {Ext: "TAR", Description: "tar archive", Category: "archive"},
	"bz2":  {Ext: "BZ2", Description: "bzip2 compressed data", Category: "archive"},
	"xz":   {Ext: "XZ", Description: "xz compressed data", Category: "archive"},
	"exe":  {Ext: "PE", Description: "Windows PE executable", Category: "executable"},
	"dll":  {Ext: "PE", Description: "Windows PE dynamic library", Category: "executable"},
	"sys":  {Ext: "PE", Description: "Windows PE driver", Category: "executable"},
	"obj":  {Ext: "PE", Description: "COFF object file", Category: "executable"},
	"lib":  {Ext: "PE", Description: "COFF import library", Category: "executable"},
	"msi":  {Ext: "MSI", Description: "Windows installer package", Category: "executable"},
	"pdf":  {Ext: "PDF", Description: "PDF document", Category: "document"},
	"doc":  {Ext: "OLE", Description: "Word document", Category: "document"},
	"xls":  {Ext: "OLE", Description: "Excel workbook", Category: "document"},
	"ppt":  {Ext: "OLE", Description: "PowerPoint presentation", Category: "document"},
	"mp3":  {Ext: "MP3", Description: "MP3 audio", Category: "media"},
	"mp4":  {Ext: "MP4", Description: "MP4 video", Category: "media"},
	"wav":  {Ext: "WAV", Description: "WAV audio", Category: "media"},
	"avi":  {Ext: "AVI", Description: "AVI video", Category: "media"},
	"flac": {Ext: "FLAC", Description: "FLAC audio", Category: "media"},
	"ogg":  {Ext: "OGG", Description: "Ogg media", Category: "media"},
	"class": {Ext: "CLASS", Description: "Java class", Category: "executable"},
	"jar":  {Ext: "ZIP", Description: "Java archive", Category: "archive"},
	"sqlite": {Ext: "SQLITE", Description: "SQLite database", Category: "database"},
	"db":   {Ext: "SQLITE", Description: "Database file", Category: "database"},
}

const open_maxAnalyzeBytes = 64 * 1024 * 1024
const open_maxDecryptBytes = 256 * 1024 * 1024

func open_readHead(path string, maxBytes int64) ([]byte, int64, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, 0, err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return nil, 0, err
	}
	total := fi.Size()
	readN := total
	if maxBytes > 0 && readN > maxBytes {
		readN = maxBytes
	}
	buf := make([]byte, readN)
	if readN > 0 {
		if _, err := io.ReadFull(f, buf); err != nil && err != io.ErrUnexpectedEOF {
			return nil, 0, err
		}
	}
	return buf, total, nil
}

func open_detectByMagic(data []byte) *open_MagicSig {
	for _, sig := range open_magicSigs {
		end := sig.Offset + len(sig.Bytes)
		if end > len(data) {
			continue
		}
		if bytes.Equal(data[sig.Offset:end], sig.Bytes) {
			s := sig
			return &s
		}
	}
	if len(data) >= 262 && bytes.Equal(data[257:262], []byte("ustar")) {
		return &open_MagicSig{Ext: "TAR", Desc: "tar archive", Category: "archive"}
	}
	if len(data) >= 32774 && bytes.Equal(data[32769:32774], []byte("CD001")) {
		return &open_MagicSig{Ext: "ISO", Desc: "ISO 9660 image", Category: "archive"}
	}
	return nil
}

func open_entropyOf(data []byte) float64 {
	if len(data) == 0 {
		return 0
	}
	var counts [256]int
	for _, b := range data {
		counts[b]++
	}
	var e float64
	n := float64(len(data))
	for _, cnt := range counts {
		if cnt == 0 {
			continue
		}
		p := float64(cnt) / n
		e -= p * math.Log2(p)
	}
	return e
}

func open_printableRatio(data []byte) float64 {
	if len(data) == 0 {
		return 0
	}
	var n int
	for _, b := range data {
		if (b >= 0x20 && b < 0x7F) || b == '\n' || b == '\r' || b == '\t' {
			n++
		}
	}
	return float64(n) / float64(len(data))
}

func open_looksText(data []byte) bool {
	if len(data) == 0 {
		return false
	}
	sample := data
	if len(sample) > 64*1024 {
		sample = sample[:64*1024]
	}
	if bytes.IndexByte(sample, 0) >= 0 {
		return false
	}
	if len(sample) >= 16 && utf8.Valid(sample) {
		return true
	}
	ratio := open_printableRatio(sample)
	if ratio < 0.90 {
		return false
	}
	return utf8.Valid(sample) || ratio > 0.95
}

func open_parsePE(data []byte) *open_PEInfo {
	if len(data) < 64 || data[0] != 'M' || data[1] != 'Z' {
		return nil
	}
	eLfanew := binary.LittleEndian.Uint32(data[0x3C:])
	if eLfanew == 0 || int(eLfanew)+24+2 > len(data) {
		return nil
	}
	if data[eLfanew] != 'P' || data[eLfanew+1] != 'E' || data[eLfanew+2] != 0 || data[eLfanew+3] != 0 {
		return nil
	}
	pe := &open_PEInfo{Valid: true}
	coff := data[eLfanew+4:]
	if len(coff) < 20 {
		return nil
	}
	pe.Machine = binary.LittleEndian.Uint16(coff[0:])
	pe.NumberOfSections = binary.LittleEndian.Uint16(coff[2:])
	pe.Timestamp = binary.LittleEndian.Uint32(coff[4:])
	pe.Characteristics = binary.LittleEndian.Uint16(coff[18:])
	optSize := binary.LittleEndian.Uint16(coff[16:])

	optStart := int(eLfanew) + 24
	if optStart+2 > len(data) {
		return pe
	}
	pe.OptionalMagic = binary.LittleEndian.Uint16(data[optStart:])
	if pe.OptionalMagic == 0x10B && optStart+70 <= len(data) {
		pe.EntryPoint = binary.LittleEndian.Uint32(data[optStart+16:])
		pe.ImageBase = uint64(binary.LittleEndian.Uint32(data[optStart+28:]))
		pe.Subsystem = binary.LittleEndian.Uint16(data[optStart+68:])
	} else if pe.OptionalMagic == 0x20B && optStart+70 <= len(data) {
		pe.EntryPoint = binary.LittleEndian.Uint32(data[optStart+16:])
		pe.ImageBase = binary.LittleEndian.Uint64(data[optStart+24:])
		pe.Subsystem = binary.LittleEndian.Uint16(data[optStart+68:])
	}

	sectionStart := int(eLfanew) + 24 + int(optSize)
	for i := 0; i < int(pe.NumberOfSections); i++ {
		off := sectionStart + i*40
		if off+40 > len(data) {
			break
		}
		name := strings.TrimRight(string(data[off:off+8]), "\x00")
		pe.Sections = append(pe.Sections, open_PESection{
			Name:            name,
			VirtualSize:     binary.LittleEndian.Uint32(data[off+8:]),
			VirtualAddr:     binary.LittleEndian.Uint32(data[off+12:]),
			RawSize:         binary.LittleEndian.Uint32(data[off+16:]),
			RawPtr:          binary.LittleEndian.Uint32(data[off+20:]),
			Characteristics: binary.LittleEndian.Uint32(data[off+36:]),
		})
	}
	return pe
}

func open_peMachineName(m uint16) string { return machineName(m) }

func open_peSubsystemName(s uint16) string {
	switch s {
	case 1:
		return "Native"
	case 2:
		return "Windows GUI"
	case 3:
		return "Windows CUI"
	case 7:
		return "POSIX CUI"
	case 9:
		return "Windows CE"
	case 10:
		return "EFI Application"
	case 11:
		return "EFI Boot Driver"
	case 12:
		return "EFI Runtime Driver"
	case 13:
		return "EFI ROM"
	case 14:
		return "Xbox"
	case 16:
		return "Windows Boot Application"
	}
	return fmt.Sprintf("0x%04X", s)
}

func open_imageDimensions(data []byte, ext string) (int, int, bool) {
	switch ext {
	case "PNG":
		if len(data) >= 24 {
			return int(binary.BigEndian.Uint32(data[16:])), int(binary.BigEndian.Uint32(data[20:])), true
		}
	case "GIF":
		if len(data) >= 10 {
			return int(binary.LittleEndian.Uint16(data[6:])), int(binary.LittleEndian.Uint16(data[8:])), true
		}
	case "BMP":
		if len(data) >= 26 {
			w := int(int32(binary.LittleEndian.Uint32(data[18:])))
			h := int(int32(binary.LittleEndian.Uint32(data[22:])))
			if w < 0 {
				w = -w
			}
			if h < 0 {
				h = -h
			}
			return w, h, true
		}
	case "JPEG":
		i := 2
		for i+9 < len(data) {
			if data[i] != 0xFF {
				i++
				continue
			}
			marker := data[i+1]
			if marker == 0xC0 || marker == 0xC1 || marker == 0xC2 ||
				marker == 0xC3 || marker == 0xC5 || marker == 0xC6 ||
				marker == 0xC7 || marker == 0xC9 || marker == 0xCA ||
				marker == 0xCB || marker == 0xCD || marker == 0xCE || marker == 0xCF {
				if i+9 <= len(data) {
					h := int(binary.BigEndian.Uint16(data[i+5:]))
					w := int(binary.BigEndian.Uint16(data[i+7:]))
					return w, h, true
				}
			}
			if i+4 > len(data) {
				break
			}
			segLen := int(binary.BigEndian.Uint16(data[i+2:]))
			if segLen < 2 {
				break
			}
			i += 2 + segLen
		}
	}
	return 0, 0, false
}

func open_detectFile(path string, data []byte) *open_FileType {
	ft := &open_FileType{Size: int64(len(data))}
	ext := strings.ToLower(strings.TrimPrefix(filepath.Ext(path), "."))
	if t, ok := open_extMap[ext]; ok {
		ft.Ext, ft.Description, ft.Category = t.Ext, t.Description, t.Category
		ft.ByExtension = true
	}
	if sig := open_detectByMagic(data); sig != nil {
		ft.Ext, ft.Description, ft.Category = sig.Ext, sig.Desc, sig.Category
		ft.ByMagic = true
	}
	ft.EntropyValue = open_entropyOf(data)
	if ft.Category == "" {
		if open_looksText(data) {
			ft.Ext, ft.Description, ft.Category, ft.Text = "TXT", "Likely plain text (no magic, no known extension)", "text", true
		} else {
			ft.Ext, ft.Description, ft.Category = "BIN", "Unknown binary", "binary"
		}
	}
	if ft.Category == "text" {
		ft.Text = true
	}
	if ft.Category == "executable" && ft.Ext == "PE" {
		ft.PE = open_parsePE(data)
		if ft.PE == nil {
			ft.Description = "DOS MZ executable (no PE header)"
		}
	}
	if ft.EntropyValue > 7.5 && ft.Category != "archive" && ft.Category != "image" && ft.Category != "media" {
		ft.Encrypted = true
	}
	return ft
}

func open_previewText(data []byte, maxLines int) {
	allLines := bytes.Split(data, []byte("\n"))
	total := len(allLines)
	lines := allLines
	if maxLines >= 0 && len(lines) > maxLines {
		lines = lines[:maxLines]
	}
	for i, line := range lines {
		line = bytes.TrimSuffix(line, []byte("\r"))
		fmt.Printf("%s %s\n", c(clrGray, fmt.Sprintf("%4d |", i+1)), string(line))
	}
	if len(lines) < total {
		fmt.Println(c(clrGray, "  ..."))
	}
}

func open_hexDump(data []byte, startOffset int64, maxBytes int) {
	if len(data) > maxBytes {
		data = data[:maxBytes]
	}
	for i := 0; i < len(data); i += 16 {
		fmt.Printf("%s  ", c(clrGray, fmt.Sprintf("%08x", startOffset+int64(i))))
		for j := 0; j < 16; j++ {
			if i+j < len(data) {
				col := clrCyan
				if j >= 8 {
					col = clrYellow
				}
				fmt.Print(c(col, fmt.Sprintf("%02x ", data[i+j])))
			} else {
				fmt.Print("   ")
			}
			if j == 7 {
				fmt.Print(" ")
			}
		}
		fmt.Print(" ")
		fmt.Print(c(clrGray, "|"))
		for j := 0; j < 16; j++ {
			if i+j >= len(data) {
				break
			}
			b := data[i+j]
			if b >= 0x20 && b < 0x7F {
				fmt.Print(c(clrGreen, string(rune(b))))
			} else {
				fmt.Print(c(clrGray, "."))
			}
		}
		fmt.Println(c(clrGray, "|"))
	}
}

// ---------- decryption ----------

var open_weakPasswords = []string{
	"password", "Password", "PASSWORD", "password123", "Password123",
	"Password1", "P@ssw0rd", "123456", "1234567", "12345678", "123456789",
	"0123456789", "1234567890", "1234567890123456",
	"qwerty", "qwertyuiop", "qwerty123",
	"abc123", "abcd1234", "abcdefgh", "abcdefghijklmnop",
	"admin", "administrator", "root", "toor", "guest",
	"test", "testing", "demo",
	"key", "secret", "aeskey", "deskey", "rc4key",
	"00000000", "0000000000000000", "11111111", "1111111111111111",
	"aaaaaaaa", "aaaaaaaaaaaaaaaa",
	"changeme", "default", "master", "letmein", "welcome",
	"monkey", "dragon", "sunshine", "iloveyou", "trustno1",
}

type open_KeyCandidate struct {
	Bytes []byte
	Desc  string
}

type open_IVCandidate struct {
	Bytes []byte
	Desc  string
}

type open_DecryptAttempt struct {
	Algorithm, Mode, Padding string
	Key                      []byte
	KeyDesc                  string
	IV                       []byte
	IVDesc                   string
}

type open_decryptOpts struct {
	key      []byte
	keyDesc  string
	iv       []byte
	ivDesc   string
	password string
	alg      string
	mode     string
	dictFile string
	noScan   bool
	noDict   bool
	maxTries int
}

func open_deriveKey(input []byte, size int) []byte {
	if len(input) == size {
		return append([]byte(nil), input...)
	}
	if len(input) > size {
		return append([]byte(nil), input[:size]...)
	}
	h := sha256.Sum256(input)
	if size <= 32 {
		return append([]byte(nil), h[:size]...)
	}
	out := make([]byte, 0, size)
	for len(out) < size {
		out = append(out, h[:]...)
		h = sha256.Sum256(h[:])
	}
	return out[:size]
}

func open_decodeHexStrict(s string) ([]byte, bool) {
	clean := strings.NewReplacer(" ", "", ":", "", "-", "").Replace(s)
	if clean == "" || len(clean)%2 != 0 {
		return nil, false
	}
	b, err := hex.DecodeString(clean)
	if err != nil {
		return nil, false
	}
	return b, true
}

func open_scanHardcodedKeys(data []byte, limit int) []open_KeyCandidate {
	var keys []open_KeyCandidate
	seen := map[string]bool{}
	sample := data
	if len(sample) > 4*1024*1024 {
		sample = sample[:4*1024*1024]
	}
	re := regexp.MustCompile(`[A-Za-z0-9+/=._!@#$%^&*\-]{16,64}`)
	for _, m := range re.FindAll(sample, limit*4) {
		if len(m) < 16 {
			continue
		}
		for _, size := range []int{32, 24, 16} {
			if len(m) >= size {
				k := m[:size]
				key := string(k)
				if seen[key] {
					continue
				}
				seen[key] = true
				keys = append(keys, open_KeyCandidate{Bytes: k, Desc: fmt.Sprintf("scan(len=%d):%q", size, k)})
				if len(keys) >= limit {
					return keys
				}
			}
		}
	}
	return keys
}

func open_loadDictFile(path string) []string {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var out []string
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		out = append(out, line)
	}
	return out
}

func open_pkcs7Unpad(data []byte, blockSize int) ([]byte, error) {
	if len(data) == 0 || len(data)%blockSize != 0 {
		return nil, fmt.Errorf("bad length")
	}
	pad := int(data[len(data)-1])
	if pad == 0 || pad > blockSize || pad > len(data) {
		return nil, fmt.Errorf("bad padding")
	}
	for i := len(data) - pad; i < len(data); i++ {
		if int(data[i]) != pad {
			return nil, fmt.Errorf("bad padding")
		}
	}
	return data[:len(data)-pad], nil
}

func open_zeroUnpad(data []byte) []byte {
	i := len(data)
	for i > 0 && data[i-1] == 0 {
		i--
	}
	return data[:i]
}

func open_decryptAESCBC(ct, key, iv []byte, usePKCS7 bool) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	if len(iv) != aes.BlockSize || len(ct) == 0 || len(ct)%aes.BlockSize != 0 {
		return nil, fmt.Errorf("bad length")
	}
	plain := make([]byte, len(ct))
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(plain, ct)
	if usePKCS7 {
		return open_pkcs7Unpad(plain, aes.BlockSize)
	}
	return open_zeroUnpad(plain), nil
}

func open_decryptAESECB(ct, key []byte, usePKCS7 bool) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	if len(ct) == 0 || len(ct)%aes.BlockSize != 0 {
		return nil, fmt.Errorf("bad length")
	}
	plain := make([]byte, len(ct))
	for i := 0; i < len(ct); i += aes.BlockSize {
		block.Decrypt(plain[i:i+aes.BlockSize], ct[i:i+aes.BlockSize])
	}
	if usePKCS7 {
		return open_pkcs7Unpad(plain, aes.BlockSize)
	}
	return open_zeroUnpad(plain), nil
}

func open_decryptAESCTR(ct, key, iv []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	if len(iv) != aes.BlockSize {
		return nil, fmt.Errorf("bad IV length")
	}
	plain := make([]byte, len(ct))
	cipher.NewCTR(block, iv).XORKeyStream(plain, ct)
	return plain, nil
}

func open_decryptDESCBC(ct, key, iv []byte, usePKCS7 bool) ([]byte, error) {
	block, err := des.NewCipher(key)
	if err != nil {
		return nil, err
	}
	if len(iv) != des.BlockSize || len(ct) == 0 || len(ct)%des.BlockSize != 0 {
		return nil, fmt.Errorf("bad length")
	}
	plain := make([]byte, len(ct))
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(plain, ct)
	if usePKCS7 {
		return open_pkcs7Unpad(plain, des.BlockSize)
	}
	return open_zeroUnpad(plain), nil
}

func open_decryptDESECB(ct, key []byte, usePKCS7 bool) ([]byte, error) {
	block, err := des.NewCipher(key)
	if err != nil {
		return nil, err
	}
	if len(ct) == 0 || len(ct)%des.BlockSize != 0 {
		return nil, fmt.Errorf("bad length")
	}
	plain := make([]byte, len(ct))
	for i := 0; i < len(ct); i += des.BlockSize {
		block.Decrypt(plain[i:i+des.BlockSize], ct[i:i+des.BlockSize])
	}
	if usePKCS7 {
		return open_pkcs7Unpad(plain, des.BlockSize)
	}
	return open_zeroUnpad(plain), nil
}

func open_decryptRC4(ct, key []byte) ([]byte, error) {
	cp, err := rc4.NewCipher(key)
	if err != nil {
		return nil, err
	}
	plain := make([]byte, len(ct))
	cp.XORKeyStream(plain, ct)
	return plain, nil
}

func open_runAttempt(data []byte, at open_DecryptAttempt) ([]byte, error) {
	switch at.Algorithm {
	case "aes":
		switch at.Mode {
		case "cbc":
			return open_decryptAESCBC(data, at.Key, at.IV, at.Padding == "pkcs7")
		case "ecb":
			return open_decryptAESECB(data, at.Key, at.Padding == "pkcs7")
		case "ctr":
			return open_decryptAESCTR(data, at.Key, at.IV)
		}
	case "des":
		switch at.Mode {
		case "cbc":
			return open_decryptDESCBC(data, at.Key, at.IV, at.Padding == "pkcs7")
		case "ecb":
			return open_decryptDESECB(data, at.Key, at.Padding == "pkcs7")
		}
	case "rc4":
		return open_decryptRC4(data, at.Key)
	}
	return nil, fmt.Errorf("unsupported %s/%s", at.Algorithm, at.Mode)
}

func open_looksDecrypted(plain []byte) bool {
	if len(plain) == 0 {
		return false
	}
	if open_detectByMagic(plain) != nil {
		return true
	}
	if open_looksText(plain) {
		return true
	}
	if bytes.IndexByte(plain, 0) < 0 && open_printableRatio(plain) > 0.80 && utf8.Valid(plain) {
		return true
	}
	return false
}

func open_collectAttempts(data []byte, opts *open_decryptOpts) []open_DecryptAttempt {
	var keys []open_KeyCandidate
	seen := map[string]bool{}
	addKey := func(b []byte, desc string) {
		k := string(b)
		if seen[k] {
			return
		}
		seen[k] = true
		keys = append(keys, open_KeyCandidate{Bytes: b, Desc: desc})
	}
	if opts.key != nil {
		addKey(opts.key, opts.keyDesc)
	}
	if opts.password != "" {
		addKey(open_deriveKey([]byte(opts.password), 32), "password:"+opts.password)
	}
	if !opts.noDict {
		for _, pw := range open_weakPasswords {
			addKey(open_deriveKey([]byte(pw), 32), "dict:"+pw)
		}
	}
	if !opts.noDict && opts.dictFile != "" {
		for _, pw := range open_loadDictFile(opts.dictFile) {
			addKey(open_deriveKey([]byte(pw), 32), "dict-file:"+pw)
		}
	}
	if !opts.noScan {
		for _, kc := range open_scanHardcodedKeys(data, 30) {
			addKey(kc.Bytes, kc.Desc)
		}
	}
	if len(keys) == 0 {
		return nil
	}

	type algMode struct{ alg, mode string }
	var combos []algMode
	if opts.alg != "" {
		switch strings.ToLower(opts.alg) {
		case "aes":
			if opts.mode != "" {
				m := strings.ToLower(opts.mode)
				if m != "cbc" && m != "ecb" && m != "ctr" {
					return nil
				}
				combos = append(combos, algMode{"aes", m})
			} else {
				combos = append(combos, algMode{"aes", "cbc"}, algMode{"aes", "ecb"})
			}
		case "des":
			if opts.mode != "" {
				m := strings.ToLower(opts.mode)
				if m != "cbc" && m != "ecb" {
					return nil
				}
				combos = append(combos, algMode{"des", m})
			} else {
				combos = append(combos, algMode{"des", "cbc"}, algMode{"des", "ecb"})
			}
		case "rc4":
			combos = append(combos, algMode{"rc4", ""})
		default:
			return nil
		}
	} else {
		combos = []algMode{
			{"aes", "cbc"}, {"aes", "ecb"},
			{"des", "cbc"}, {"des", "ecb"},
			{"rc4", ""},
		}
	}

	var ivs []open_IVCandidate
	if opts.iv != nil {
		ivs = append(ivs, open_IVCandidate{Bytes: opts.iv, Desc: opts.ivDesc})
	} else {
		ivs = append(ivs,
			open_IVCandidate{Bytes: make([]byte, 16), Desc: "zeros(16)"},
			open_IVCandidate{Bytes: make([]byte, 8), Desc: "zeros(8)"},
		)
		seq := make([]byte, 16)
		for i := range seq {
			seq[i] = byte(i)
		}
		ivs = append(ivs, open_IVCandidate{Bytes: seq, Desc: "seq(0..15)"})
	}

	maxTries := opts.maxTries
	var attempts []open_DecryptAttempt
	full := func() bool { return maxTries > 0 && len(attempts) >= maxTries }

	for _, kc := range keys {
		if full() {
			return attempts
		}
		for _, am := range combos {
			if full() {
				return attempts
			}
			switch am.alg {
			case "aes":
				for _, size := range []int{32, 24, 16} {
					if full() {
						return attempts
					}
					k := open_deriveKey(kc.Bytes, size)
					if am.mode == "cbc" || am.mode == "ctr" {
						for _, iv := range ivs {
							if len(iv.Bytes) != 16 {
								continue
							}
							for _, pad := range []string{"pkcs7", "zero"} {
								if full() {
									return attempts
								}
								attempts = append(attempts, open_DecryptAttempt{
									Algorithm: "aes", Mode: am.mode, Padding: pad,
									Key: k, KeyDesc: fmt.Sprintf("%s (AES-%d)", kc.Desc, size*8),
									IV: iv.Bytes, IVDesc: iv.Desc,
								})
							}
						}
					} else {
						for _, pad := range []string{"pkcs7", "zero"} {
							if full() {
								return attempts
							}
							attempts = append(attempts, open_DecryptAttempt{
								Algorithm: "aes", Mode: am.mode, Padding: pad,
								Key: k, KeyDesc: fmt.Sprintf("%s (AES-%d)", kc.Desc, size*8),
							})
						}
					}
				}
			case "des":
				k := open_deriveKey(kc.Bytes, 8)
				if am.mode == "cbc" {
					for _, iv := range ivs {
						if len(iv.Bytes) != 8 {
							continue
						}
						for _, pad := range []string{"pkcs7", "zero"} {
							if full() {
								return attempts
							}
							attempts = append(attempts, open_DecryptAttempt{
								Algorithm: "des", Mode: "cbc", Padding: pad,
								Key: k, KeyDesc: kc.Desc + " (DES)",
								IV: iv.Bytes, IVDesc: iv.Desc,
							})
						}
					}
				} else {
					for _, pad := range []string{"pkcs7", "zero"} {
						if full() {
							return attempts
						}
						attempts = append(attempts, open_DecryptAttempt{
							Algorithm: "des", Mode: "ecb", Padding: pad,
							Key: k, KeyDesc: kc.Desc + " (DES)",
						})
					}
				}
			case "rc4":
				if full() {
					return attempts
				}
				attempts = append(attempts, open_DecryptAttempt{
					Algorithm: "rc4", Key: open_deriveKey(kc.Bytes, 32),
					KeyDesc: kc.Desc + " (RC4)",
				})
				if len(kc.Bytes) >= 5 && len(kc.Bytes) <= 64 {
					if full() {
						return attempts
					}
					attempts = append(attempts, open_DecryptAttempt{
						Algorithm: "rc4", Key: append([]byte(nil), kc.Bytes...),
						KeyDesc: kc.Desc + " (RC4 raw)",
					})
				}
			}
		}
	}
	return attempts
}

// ---------- open commands ----------

func open_printPEInfo(pe *open_PEInfo) {
	fmt.Println(c(clrBold+clrCyan, "\nPE header"))
	fmt.Printf("  Machine:     %s\n", open_peMachineName(pe.Machine))
	fmt.Printf("  Subsystem:   %s\n", open_peSubsystemName(pe.Subsystem))
	fmt.Printf("  Sections:    %d\n", pe.NumberOfSections)
	fmt.Printf("  EntryPoint:  0x%X\n", pe.EntryPoint)
	fmt.Printf("  ImageBase:   0x%X\n", pe.ImageBase)
	fmt.Printf("  Timestamp:   %s\n", time.Unix(int64(pe.Timestamp), 0).UTC().Format(time.RFC3339))
	if len(pe.Sections) > 0 {
		fmt.Println(c(clrBold+clrCyan, "\nSections"))
		fmt.Printf("  %-10s %-10s %-10s %-10s %-10s %s\n",
			"NAME", "VIRTADDR", "VIRTSIZE", "RAWPTR", "RAWSIZE", "FLAGS")
		for _, s := range pe.Sections {
			fmt.Printf("  %-10s 0x%-8X 0x%-8X 0x%-8X 0x%-8X 0x%08X\n",
				s.Name, s.VirtualAddr, s.VirtualSize, s.RawPtr, s.RawSize, s.Characteristics)
		}
	}
}

func open_printFileInfo(path string, ft *open_FileType) {
	fmt.Printf("%s %s\n", c(clrCyan, "File:    "), path)
	fmt.Printf("%s %d bytes\n", c(clrCyan, "Size:    "), ft.Size)
	fmt.Printf("%s %s\n", c(clrCyan, "Type:    "), c(clrGreen, ft.Ext+" - "+ft.Description))
	fmt.Printf("%s %s\n", c(clrCyan, "Category:"), ft.Category)
	if ft.ByMagic {
		fmt.Printf("%s yes\n", c(clrCyan, "Magic:   "))
	}
	if ft.ByExtension {
		fmt.Printf("%s yes\n", c(clrCyan, "Ext:     "))
	}
	fmt.Printf("%s %.4f (0=uniform, 8=random)\n", c(clrCyan, "Entropy: "), ft.EntropyValue)
	if ft.Encrypted {
		fmt.Printf("%s %s\n", c(clrRed, "Encrypted:"), "likely (high entropy, no known archive/image magic)")
	}
	if ft.PE != nil && ft.PE.Valid {
		open_printPEInfo(ft.PE)
	}
}

func open_cmdInfo(path string) int {
	data, size, err := open_readHead(path, open_maxAnalyzeBytes)
	if err != nil {
		fmt.Fprintf(os.Stderr, "winctl open: %v\n", err)
		return 4
	}
	ft := open_detectFile(path, data)
	ft.Size = size
	open_printFileInfo(path, ft)
	if int64(len(data)) < size {
		fmt.Printf("%s analyzed %d of %d bytes (head sample)\n",
			c(clrYellow, "Note:  "), len(data), size)
	}
	return 0
}

func open_cmdPreview(path string, lines, maxBytes int, showEntropy bool) int {
	data, size, err := open_readHead(path, open_maxAnalyzeBytes)
	if err != nil {
		fmt.Fprintf(os.Stderr, "winctl open: %v\n", err)
		return 4
	}
	ft := open_detectFile(path, data)
	ft.Size = size
	open_printFileInfo(path, ft)
	_ = showEntropy

	fmt.Println()
	switch ft.Category {
	case "text":
		fmt.Println(c(clrBold+clrCyan, "Text preview"))
		open_previewText(data, lines)
	case "image":
		if w, h, ok := open_imageDimensions(data, ft.Ext); ok {
			fmt.Printf("%s %dx%d\n", c(clrCyan, "Dimensions:"), w, h)
		}
		fmt.Println(c(clrBold+clrCyan, "\nHex preview"))
		open_hexDump(data, 0, maxBytes)
	case "executable":
		if ft.PE != nil && ft.PE.Valid {
			fmt.Println(c(clrBold+clrCyan, "\nHex preview (first 256 bytes)"))
			open_hexDump(data, 0, 256)
		} else {
			fmt.Println(c(clrBold+clrCyan, "Hex preview"))
			open_hexDump(data, 0, maxBytes)
		}
	case "archive":
		fmt.Println(c(clrBold+clrCyan, "\nHex preview (archive members not listed)"))
		open_hexDump(data, 0, maxBytes)
	default:
		fmt.Println(c(clrBold+clrCyan, "Hex preview"))
		open_hexDump(data, 0, maxBytes)
	}
	if ft.Encrypted {
		fmt.Println(c(clrYellow, "\nHint: high entropy suggests this file may be encrypted."))
		fmt.Printf("%s winctl open decrypt %s\n", c(clrGray, "      try:"), path)
	}
	if int64(len(data)) < size {
		fmt.Printf("%s previewed %d of %d bytes\n",
			c(clrGray, "Note: "), len(data), size)
	}
	return 0
}

func open_cmdDecrypt(path string, args []string) int {
	opts := &open_decryptOpts{maxTries: 2000}
	i := 0
	for i < len(args) {
		a := args[i]
		switch a {
		case "-k", "--key":
			if i+1 >= len(args) {
				return 2
			}
			opts.key = []byte(args[i+1])
			opts.keyDesc = "user:" + args[i+1]
			i += 2
		case "--key-hex":
			if i+1 >= len(args) {
				return 2
			}
			b, ok := open_decodeHexStrict(args[i+1])
			if !ok {
				fmt.Fprintf(os.Stderr, "decrypt: invalid hex key %q\n", args[i+1])
				return 2
			}
			opts.key, opts.keyDesc = b, "user-hex:"+args[i+1]
			i += 2
		case "-i", "--iv":
			if i+1 >= len(args) {
				return 2
			}
			opts.iv, opts.ivDesc = []byte(args[i+1]), "user-iv"
			i += 2
		case "--iv-hex":
			if i+1 >= len(args) {
				return 2
			}
			b, ok := open_decodeHexStrict(args[i+1])
			if !ok {
				fmt.Fprintf(os.Stderr, "decrypt: invalid hex IV %q\n", args[i+1])
				return 2
			}
			opts.iv, opts.ivDesc = b, "user-iv-hex:"+args[i+1]
			i += 2
		case "-p", "--password":
			if i+1 >= len(args) {
				return 2
			}
			opts.password = args[i+1]
			i += 2
		case "-a", "--algorithm":
			if i+1 >= len(args) {
				return 2
			}
			opts.alg = strings.ToLower(args[i+1])
			i += 2
		case "-m", "--mode":
			if i+1 >= len(args) {
				return 2
			}
			opts.mode = strings.ToLower(args[i+1])
			i += 2
		case "-d", "--dict":
			if i+1 >= len(args) {
				return 2
			}
			opts.dictFile = args[i+1]
			i += 2
		case "--no-scan":
			opts.noScan = true
			i++
		case "--no-dict":
			opts.noDict = true
			i++
		case "--max-tries":
			if i+1 >= len(args) {
				return 2
			}
			v, err := strconv.Atoi(args[i+1])
			if err != nil || v <= 0 {
				return 2
			}
			opts.maxTries = v
			i += 2
		default:
			if strings.HasPrefix(a, "-") {
				fmt.Fprintf(os.Stderr, "decrypt: unknown option %s\n", a)
				return 2
			}
			return 2
		}
	}
	if opts.alg == "rc4" && opts.mode != "" {
		fmt.Fprintln(os.Stderr, "decrypt: rc4 does not take a mode")
		return 2
	}
	if opts.alg == "des" && opts.mode == "ctr" {
		fmt.Fprintln(os.Stderr, "decrypt: DES does not support ctr mode")
		return 2
	}

	data, size, err := open_readHead(path, open_maxDecryptBytes)
	if err != nil {
		fmt.Fprintf(os.Stderr, "winctl open: %v\n", err)
		return 4
	}
	if size > int64(len(data)) {
		fmt.Fprintf(os.Stderr, "winctl open: file is %d bytes, decrypt is capped at %d bytes\n",
			size, open_maxDecryptBytes)
		fmt.Fprintf(os.Stderr, "  split the file first, or use a dedicated tool\n")
		return 5
	}
	analyze := data
	if len(analyze) > 16*1024*1024 {
		analyze = analyze[:16*1024*1024]
	}
	attempts := open_collectAttempts(analyze, opts)
	if len(attempts) == 0 {
		fmt.Fprintln(os.Stderr, "winctl open: no decryption candidates (check your key / algorithm)")
		return 2
	}
	if dryRun {
		fmt.Printf("[dry-run] %d attempt(s) would be tried\n", len(attempts))
		for i := 0; i < len(attempts) && i < 20; i++ {
			at := attempts[i]
			fmt.Printf("  %-8s %-6s %-8s key=%s iv=%s\n",
				at.Algorithm, at.Mode, at.Padding, at.KeyDesc, at.IVDesc)
		}
		if len(attempts) > 20 {
			fmt.Printf("  ... and %d more\n", len(attempts)-20)
		}
		return 0
	}
	tried := 0
	for _, at := range attempts {
		plain, err := open_runAttempt(analyze, at)
		tried++
		if err != nil {
			continue
		}
		if !open_looksDecrypted(plain) {
			continue
		}
		fullPlain := plain
		if len(data) > len(analyze) {
			if fp, err := open_runAttempt(data, at); err == nil {
				fullPlain = fp
			}
		}
		fmt.Println(c(clrBold+clrGreen, "=== decryption succeeded ==="))
		fmt.Printf("  Algorithm: %s\n", strings.ToUpper(at.Algorithm))
		if at.Mode != "" {
			fmt.Printf("  Mode:      %s\n", strings.ToUpper(at.Mode))
		}
		if at.Padding != "" {
			fmt.Printf("  Padding:   %s\n", at.Padding)
		}
		fmt.Printf("  Key:       %s\n", at.KeyDesc)
		if at.IVDesc != "" {
			fmt.Printf("  IV:        %s\n", at.IVDesc)
		}
		fmt.Printf("  Tried:     %d candidate(s) before success\n", tried)
		fmt.Printf("  Plaintext: %d bytes\n\n", len(fullPlain))
		pft := open_detectFile(path+".decrypted", fullPlain)
		if pft.ByMagic || pft.Category == "text" {
			fmt.Printf("  Detected plaintext type: %s (%s)\n\n", pft.Ext, pft.Description)
		}
		if pft.Category == "text" {
			open_previewText(fullPlain, 0x7FFFFFFF)
		} else {
			open_hexDump(fullPlain, 0, 4096)
		}
		return 0
	}
	fmt.Fprintf(os.Stderr, "winctl open: no decryption candidate produced recognizable plaintext\n")
	fmt.Fprintf(os.Stderr, "  tried %d candidate(s)\n", tried)
	ft := open_detectFile(path, data)
	fmt.Fprintf(os.Stderr, "  file type: %s - %s\n", ft.Ext, ft.Description)
	if ft.EntropyValue > 7.5 {
		fmt.Fprintf(os.Stderr, "  entropy: %.4f (likely encrypted or compressed)\n", ft.EntropyValue)
	}
	return 1
}

func open_cmdHistory() int {
	lines, err := auditReadLines()
	if err != nil {
		fmt.Fprintf(os.Stderr, "read log %s: %v\n", globalLogPath(), err)
		return 4
	}
	if len(lines) == 0 {
		fmt.Fprintln(os.Stderr, "log is empty")
		return 0
	}
	count := 0
	for i := len(lines) - 1; i >= 0; i-- {
		m, cmd, _, ok := auditParseLine(lines[i])
		if !ok || m != "open" {
			continue
		}
		if isHistorySelf(cmd) {
			continue
		}
		count++
		fmt.Printf("[%d] %s\n", count, lines[i])
	}
	if count == 0 {
		fmt.Fprintln(os.Stderr, "no open history entries in log")
	}
	return 0
}

func open_cmdRollback() int {
	fmt.Fprintln(os.Stderr, "winctl open is read-only: there are no operations to roll back")
	fmt.Fprintln(os.Stderr, "  It only reads files and (optionally) attempts decryption in memory;")
	fmt.Fprintln(os.Stderr, "  it never writes to the source file or to the registry.")
	fmt.Fprintln(os.Stderr, "  Its history is for audit only; use --history to view it.")
	return 0
}

func open_printHelp() {
	fmt.Printf("%s v%s (Windows)\n\n", c(clrBold+clrCyan, "winctl open"), Version)
	fmt.Print(`USAGE
  winctl open <file>                     identify + preview
  winctl open info <file>                identify only
  winctl open preview <file> [OPTIONS]   preview
  winctl open decrypt <file> [OPTIONS]   try to decrypt
  winctl open --history
  winctl open --rollback                 (always a no-op: read-only)

PREVIEW
  --lines <N>       text preview line count (default 40)
  --bytes <N>       binary preview byte count (default 4096)
  --entropy         print Shannon entropy of the file

DECRYPT
  -k, --key <val>       user key (literal)
  --key-hex <hex>       user key given as hex
  -i, --iv <val>        user IV (literal)
  --iv-hex <hex>        user IV given as hex
  -p, --password <pw>   password (SHA-256 derived key)
  -a, --algorithm <a>   aes | des | rc4 (default: try all)
  -m, --mode <m>        cbc | ecb | ctr
  -d, --dict <file>     extra password dictionary
  --no-scan             disable hardcoded-key scanning inside the file
  --no-dict             disable the built-in weak password list
  --max-tries <N>       cap the number of candidate combinations (default 2000)

LIMITS
  info / preview analyze at most 64 MB from the head of the file.
  decrypt loads at most 256 MB into memory.
  Larger inputs print a Note: line and analyze the head sample only.

GLOBAL
  -o, --out <path>      write stdout to a file
  --dry-run             print the plan without touching the file
  --no-color            disable ANSI colors (also honors NO_COLOR)
  -b, --bugs            print collected errors/warnings on exit
  -h, --help            show this help
  --version             show version

All logs go to ./backup/winctl_logs.log
`)
}

func open_main() {
	args, outPath, err := consumeGlobalFlags(os.Args[1:])
	if err != nil {
		fmt.Fprintf(os.Stderr, "winctl open: %v\n", err)
		finalExit(2)
	}
	initColor()
	if outPath != "" {
		if err := setupOutput(outPath); err != nil {
			fmt.Fprintf(os.Stderr, "winctl open: %v\n", err)
			finalExit(2)
		}
	}

	if has(args, "--version") {
		fmt.Printf("winctl open v%s\n", Version)
		finalExit(0)
	}
	if len(args) == 0 || has(args, "-h", "--help") {
		open_printHelp()
		finalExit(0)
	}
	if has(args, "--history") {
		code := open_cmdHistory()
		finalExit(code)
	}
	if has(args, "--rollback") {
		code := open_cmdRollback()
		finalExit(code)
	}

	code := open_dispatch(args)
	if !dryRun && shouldLogRun() {
		auditLog("open", buildCmdLine(os.Args), code)
	}
	finalExit(code)
}

func open_dispatch(args []string) int {
	cmd := ""
	rest := args
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		switch args[0] {
		case "info", "preview", "decrypt":
			cmd = args[0]
			rest = args[1:]
		}
	}

	if cmd == "" {
		var path string
		var extra []string
		for _, a := range args {
			if path == "" && !strings.HasPrefix(a, "-") {
				path = a
			} else {
				extra = append(extra, a)
			}
		}
		if path == "" {
			fmt.Fprintln(os.Stderr, "winctl open: missing file (use -h for help)")
			return 2
		}
		return open_runDefault(path, extra)
	}

	switch cmd {
	case "info":
		if len(rest) == 0 {
			fmt.Fprintln(os.Stderr, "winctl open: info requires a file")
			return 2
		}
		return open_cmdInfo(rest[0])
	case "preview":
		return open_runPreview(rest)
	case "decrypt":
		if len(rest) == 0 {
			fmt.Fprintln(os.Stderr, "winctl open: decrypt requires a file")
			return 2
		}
		return open_cmdDecrypt(rest[0], rest[1:])
	}
	fmt.Fprintf(os.Stderr, "winctl open: unknown command %q\n", cmd)
	return 2
}

func open_runDefault(path string, extra []string) int {
	lines, maxBytes := 40, 4096
	showEntropy := false
	i := 0
	for i < len(extra) {
		switch extra[i] {
		case "--lines":
			if i+1 < len(extra) {
				if v, err := strconv.Atoi(extra[i+1]); err == nil && v > 0 {
					lines = v
				}
				i += 2
				continue
			}
			i++
		case "--bytes":
			if i+1 < len(extra) {
				if v, err := strconv.Atoi(extra[i+1]); err == nil && v > 0 {
					maxBytes = v
				}
				i += 2
				continue
			}
			i++
		case "--entropy":
			showEntropy = true
			i++
		default:
			fmt.Fprintf(os.Stderr, "winctl open: unknown option %q\n", extra[i])
			return 2
		}
	}
	return open_cmdPreview(path, lines, maxBytes, showEntropy)
}

func open_runPreview(args []string) int {
	var path string
	var extra []string
	for _, a := range args {
		if path == "" && !strings.HasPrefix(a, "-") {
			path = a
		} else {
			extra = append(extra, a)
		}
	}
	if path == "" {
		fmt.Fprintln(os.Stderr, "winctl open: preview requires a file")
		return 2
	}
	return open_runDefault(path, extra)
}
// ============================================================================
// pe — PE dependency diagnostic (read-only)
// ============================================================================

type pe_SectionInfo struct {
	Name            string `json:"name"`
	VirtualSize     uint32 `json:"virtualSize"`
	VirtualAddress  uint32 `json:"virtualAddress"`
	RawSize         uint32 `json:"rawSize"`
	RawOffset       uint32 `json:"rawOffset"`
	Characteristics uint32 `json:"characteristics"`
}

type pe_PEInfo struct {
	Path            string
	Machine         uint16
	Bits            string
	Is64            bool
	KnownBits       bool
	IsDLL           bool
	Subsystem       uint16
	SubsystemName   string
	EntryPoint      uint32
	ImageBase       uint64
	TimeStamp       uint32
	Characteristics uint16
	Sections        []pe_SectionInfo
	Imports         []string
	ImportSymbols   map[string][]string
	Exports         map[string]uint32
	Forwarders      map[string]string
}

func pe_machineIs64(m uint16) bool { return m == 0x8664 || m == 0xAA64 }
func pe_machineIsKnown(m uint16) bool {
	switch m {
	case 0x014C, 0x8664, 0x01C0, 0x01C4, 0xAA64, 0x0200:
		return true
	}
	return false
}

func pe_subsystemName(s uint16) string {
	switch s {
	case 1:
		return "Native"
	case 2:
		return "Windows GUI"
	case 3:
		return "Windows CUI"
	case 7:
		return "POSIX CUI"
	case 9:
		return "Windows CE"
	case 10:
		return "EFI Application"
	case 11:
		return "EFI Boot Driver"
	case 12:
		return "EFI Runtime Driver"
	case 13:
		return "EFI ROM"
	case 14:
		return "Xbox"
	case 16:
		return "Windows Boot Application"
	}
	return fmt.Sprintf("0x%04X", s)
}

func pe_rvaToFileOffset(f *pe.File, rva uint32) int {
	for _, sec := range f.Sections {
		if sec.VirtualAddress <= rva && rva < sec.VirtualAddress+sec.VirtualSize {
			return int(sec.Offset + (rva - sec.VirtualAddress))
		}
	}
	return -1
}

func pe_parseExports(f *pe.File, data []byte) (map[string]uint32, map[string]string, error) {
	var dd pe.DataDirectory
	switch o := f.OptionalHeader.(type) {
	case *pe.OptionalHeader32:
		dd = o.DataDirectory[0]
	case *pe.OptionalHeader64:
		dd = o.DataDirectory[0]
	default:
		return nil, nil, nil
	}
	if dd.VirtualAddress == 0 || dd.Size < 40 {
		return nil, nil, nil
	}
	dirOff := pe_rvaToFileOffset(f, dd.VirtualAddress)
	if dirOff < 0 || dirOff+40 > len(data) {
		return nil, nil, fmt.Errorf("export directory out of range")
	}
	exp := data[dirOff : dirOff+40]
	numFuncs := binary.LittleEndian.Uint32(exp[20:])
	numNames := binary.LittleEndian.Uint32(exp[24:])
	addrFuncsRVA := binary.LittleEndian.Uint32(exp[28:])
	addrNamesRVA := binary.LittleEndian.Uint32(exp[32:])
	addrOrdsRVA := binary.LittleEndian.Uint32(exp[36:])
	funcsOff := pe_rvaToFileOffset(f, addrFuncsRVA)
	namesOff := pe_rvaToFileOffset(f, addrNamesRVA)
	ordsOff := pe_rvaToFileOffset(f, addrOrdsRVA)
	if funcsOff < 0 || namesOff < 0 || ordsOff < 0 {
		return nil, nil, fmt.Errorf("export table out of range")
	}
	exports := make(map[string]uint32)
	forwarders := make(map[string]string)
	dirStart := dd.VirtualAddress
	dirEnd := dd.VirtualAddress + dd.Size

	for i := uint32(0); i < numNames; i++ {
		nameRVAoff := namesOff + int(i)*4
		if nameRVAoff+4 > len(data) {
			break
		}
		nameRVA := binary.LittleEndian.Uint32(data[nameRVAoff:])
		ordOff := ordsOff + int(i)*2
		if ordOff+2 > len(data) {
			break
		}
		ord := binary.LittleEndian.Uint16(data[ordOff:])
		if uint32(ord) >= numFuncs {
			continue
		}
		funcOff := funcsOff + int(ord)*4
		if funcOff+4 > len(data) {
			continue
		}
		funcRVA := binary.LittleEndian.Uint32(data[funcOff:])
		nameOff := pe_rvaToFileOffset(f, nameRVA)
		if nameOff < 0 {
			continue
		}
		end := nameOff
		for end < len(data) && data[end] != 0 {
			end++
		}
		name := string(data[nameOff:end])

		if funcRVA >= dirStart && funcRVA < dirEnd {
			strOff := pe_rvaToFileOffset(f, funcRVA)
			if strOff >= 0 && strOff < len(data) {
				endS := strOff
				for endS < len(data) && data[endS] != 0 {
					endS++
				}
				if endS > strOff {
					forwarders[name] = string(data[strOff:endS])
					exports[name] = 0
					continue
				}
			}
			forwarders[name] = "?"
			exports[name] = 0
			continue
		}
		exports[name] = funcRVA
	}
	return exports, forwarders, nil
}

func pe_parsePE(path string) (*pe_PEInfo, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	f, err := pe.NewFile(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	defer f.Close()

	info := &pe_PEInfo{
		Path:            path,
		Machine:         f.FileHeader.Machine,
		TimeStamp:       f.FileHeader.TimeDateStamp,
		Characteristics: f.FileHeader.Characteristics,
		IsDLL:           f.FileHeader.Characteristics&0x2000 != 0,
		ImportSymbols:   map[string][]string{},
	}
	info.KnownBits = pe_machineIsKnown(info.Machine)
	info.Is64 = pe_machineIs64(info.Machine)
	if info.Is64 {
		info.Bits = "64-bit"
	} else if info.KnownBits {
		info.Bits = "32-bit"
	} else {
		info.Bits = "unknown"
	}

	switch o := f.OptionalHeader.(type) {
	case *pe.OptionalHeader32:
		info.EntryPoint = o.AddressOfEntryPoint
		info.ImageBase = uint64(o.ImageBase)
		info.Subsystem = o.Subsystem
	case *pe.OptionalHeader64:
		info.EntryPoint = o.AddressOfEntryPoint
		info.ImageBase = o.ImageBase
		info.Subsystem = o.Subsystem
	}
	info.SubsystemName = pe_subsystemName(info.Subsystem)

	for _, s := range f.Sections {
		info.Sections = append(info.Sections, pe_SectionInfo{
			Name:            s.Name,
			VirtualSize:     s.VirtualSize,
			VirtualAddress:  s.VirtualAddress,
			RawSize:         s.Size,
			RawOffset:       s.Offset,
			Characteristics: s.Characteristics,
		})
	}

	if libs, err := f.ImportedLibraries(); err == nil {
		info.Imports = append(info.Imports, libs...)
		sort.Strings(info.Imports)
	} else {
		bugs.Add("WARN", "%s imported libraries: %v", path, err)
	}
	if syms, err := f.ImportedSymbols(); err == nil {
		for _, s := range syms {
			idx := strings.Index(s, ":")
			if idx < 0 {
				continue
			}
			dll := strings.ToLower(s[:idx])
			info.ImportSymbols[dll] = append(info.ImportSymbols[dll], s[idx+1:])
		}
	} else {
		bugs.Add("WARN", "%s imported symbols: %v", path, err)
	}
	if info.IsDLL {
		exp, fw, err := pe_parseExports(f, data)
		if err != nil {
			bugs.Add("WARN", "%s exports: %v", path, err)
		} else {
			info.Exports = exp
			info.Forwarders = fw
		}
	}
	return info, nil
}

func pe_buildSearchPaths(exe *pe_PEInfo, extra []string) []string {
	var paths []string
	add := func(p string) {
		if p == "" {
			return
		}
		p = filepath.Clean(p)
		for _, existing := range paths {
			if strings.EqualFold(existing, p) {
				return
			}
		}
		paths = append(paths, p)
	}
	add(filepath.Dir(exe.Path))
	winDir := os.Getenv("SystemRoot")
	if winDir == "" {
		winDir = `C:\Windows`
	}
	if exe.Is64 {
		add(filepath.Join(winDir, "System32"))
	} else {
		if pe_dirExists(filepath.Join(winDir, "SysWOW64")) {
			add(filepath.Join(winDir, "SysWOW64"))
		} else {
			add(filepath.Join(winDir, "System32"))
		}
	}
	add(winDir)
	for _, p := range extra {
		add(p)
	}
	for _, p := range strings.Split(os.Getenv("PATH"), ";") {
		add(strings.TrimSpace(p))
	}
	return paths
}

func pe_dirExists(p string) bool {
	fi, err := os.Stat(p)
	return err == nil && fi.IsDir()
}

func pe_findDLL(name string, searchPaths []string) (string, error) {
	for _, dir := range searchPaths {
		full := filepath.Join(dir, name)
		if fi, err := os.Stat(full); err == nil && !fi.IsDir() {
			return full, nil
		}
	}
	return "", fmt.Errorf("not found")
}

func pe_isAPISet(name string) bool {
	lower := strings.ToLower(name)
	return strings.HasPrefix(lower, "api-ms-win-") ||
		strings.HasPrefix(lower, "ext-ms-") ||
		strings.HasPrefix(lower, "api-ms-onecore-")
}

type pe_DepStatus struct {
	DLL        string `json:"dll"`
	Status     string `json:"status"`
	Path       string `json:"path,omitempty"`
	ActualBits string `json:"actualBits,omitempty"`
}

type pe_ExeReport struct {
	Path       string         `json:"path"`
	Bits       string         `json:"bits"`
	Machine    string         `json:"machine"`
	IsDLL      bool           `json:"isDll"`
	Subsystem  string         `json:"subsystem"`
	Imports    int            `json:"imports"`
	Deps       []pe_DepStatus `json:"dependencies"`
	Missing    int            `json:"missing"`
	Mismatch   int            `json:"mismatch"`
	ReadErrMsg string         `json:"error,omitempty"`
}

func pe_checkExe(path string, libPaths []string) (*pe_PEInfo, []pe_DepStatus, error) {
	info, err := pe_parsePE(path)
	if err != nil {
		return nil, nil, err
	}
	if len(info.Imports) == 0 {
		return info, nil, nil
	}
	searchPaths := pe_buildSearchPaths(info, libPaths)
	var deps []pe_DepStatus
	for _, dll := range info.Imports {
		ds := pe_DepStatus{DLL: dll}
		if pe_isAPISet(dll) {
			ds.Status = "apiset"
			deps = append(deps, ds)
			continue
		}
		full, ferr := pe_findDLL(dll, searchPaths)
		if ferr != nil {
			ds.Status = "missing"
			deps = append(deps, ds)
			continue
		}
		ds.Path = full
		dllInfo, derr := pe_parsePE(full)
		if derr != nil {
			ds.Status = "unreadable"
			deps = append(deps, ds)
			continue
		}
		ds.ActualBits = dllInfo.Bits
		if dllInfo.KnownBits && info.KnownBits && dllInfo.Is64 != info.Is64 {
			ds.Status = "bitmismatch"
			deps = append(deps, ds)
			continue
		}
		ds.Status = "ok"
		deps = append(deps, ds)
	}
	return info, deps, nil
}

func pe_printHeader(info *pe_PEInfo) {
	fmt.Printf("%s %s\n", c(clrCyan, "File:      "), info.Path)
	fmt.Printf("%s %s (%s)\n", c(clrCyan, "Machine:   "), machineName(info.Machine), info.Bits)
	kind := "EXE"
	if info.IsDLL {
		kind = "DLL"
	}
	fmt.Printf("%s %s\n", c(clrCyan, "Kind:      "), kind)
	fmt.Printf("%s %s (0x%X)\n", c(clrCyan, "Subsystem: "), info.SubsystemName, info.Subsystem)
	fmt.Printf("%s 0x%X\n", c(clrCyan, "EntryPoint:"), info.EntryPoint)
	fmt.Printf("%s 0x%X\n", c(clrCyan, "ImageBase: "), info.ImageBase)
	fmt.Printf("%s %s\n", c(clrCyan, "Timestamp: "),
		time.Unix(int64(info.TimeStamp), 0).UTC().Format("2006-01-02 15:04:05 UTC"))
}

func pe_printSections(info *pe_PEInfo) {
	if len(info.Sections) == 0 {
		return
	}
	fmt.Println(c(clrBold+clrCyan, "\nSections"))
	fmt.Printf("  %-10s %-12s %-12s %-12s %-12s %s\n",
		"NAME", "VADDR", "VSIZE", "RAWOFF", "RAWSIZE", "FLAGS")
	for _, s := range info.Sections {
		fmt.Printf("  %-10s 0x%-10X 0x%-10X 0x%-10X 0x%-10X 0x%08X\n",
			s.Name, s.VirtualAddress, s.VirtualSize, s.RawOffset, s.RawSize, s.Characteristics)
	}
}

func pe_printImports(info *pe_PEInfo) {
	if len(info.Imports) == 0 {
		fmt.Println(c(clrGray, "\n(no imports)"))
		return
	}
	fmt.Println(c(clrBold+clrCyan, "\nImports (DLLs)"))
	for _, dll := range info.Imports {
		count := len(info.ImportSymbols[strings.ToLower(dll)])
		fmt.Printf("  %s (%d function%s)\n", c(clrCyan, dll), count, pe_plural(count))
	}
}

func pe_printExports(info *pe_PEInfo) {
	if len(info.Exports) == 0 && len(info.Forwarders) == 0 {
		fmt.Println(c(clrGray, "\n(no exports)"))
		return
	}
	names := make([]string, 0, len(info.Exports))
	for n := range info.Exports {
		names = append(names, n)
	}
	sort.Strings(names)
	fmt.Println(c(clrBold+clrCyan, "\nExports"))
	for _, name := range names {
		if tgt, ok := info.Forwarders[name]; ok {
			fmt.Printf("  %s -> %s\n", c(clrCyan, name), c(clrGray, "[forwarder] "+tgt))
			continue
		}
		fmt.Printf("  %s 0x%X\n", c(clrCyan, name), info.Exports[name])
	}
}

func pe_printDeps(deps []pe_DepStatus) {
	if len(deps) == 0 {
		fmt.Println(c(clrGray, "\n(no dependencies)"))
		return
	}
	dllW := dispWidth("DLL")
	bitsW := dispWidth("BITS")
	for _, d := range deps {
		if w := dispWidth(d.DLL); w > dllW {
			dllW = w
		}
		if w := dispWidth(d.ActualBits); w > bitsW {
			bitsW = w
		}
	}
	fmt.Println(c(clrBold+clrCyan, "\nDependencies"))
	header := padRight("DLL", dllW) + "  " +
		padRight("STATUS", 12) + "  " +
		padRight("BITS", bitsW) + "  RESOLVED PATH"
	fmt.Println(c(clrBold+clrCyan, header))
	for _, d := range deps {
		statusColor := clrGray
		switch d.Status {
		case "ok":
			statusColor = clrGreen
		case "missing":
			statusColor = clrRed
		case "bitmismatch", "unreadable":
			statusColor = clrYellow
		}
		fmt.Println(padRight(d.DLL, dllW) + "  " +
			c(statusColor, padRight(d.Status, 12)) + "  " +
			padRight(d.ActualBits, bitsW) + "  " +
			c(clrGray, d.Path))
	}
}

func pe_plural(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}

type pe_jsonInfo struct {
	Path       string            `json:"path"`
	Machine    string            `json:"machine"`
	Bits       string            `json:"bits"`
	Kind       string            `json:"kind"`
	Subsystem  string            `json:"subsystem"`
	EntryPoint uint32            `json:"entryPoint"`
	ImageBase  uint64            `json:"imageBase"`
	TimeStamp  uint32            `json:"timestamp"`
	Sections   []pe_SectionInfo  `json:"sections"`
	Imports    []string          `json:"imports"`
	Exports    map[string]uint32 `json:"exports,omitempty"`
	Forwarders map[string]string `json:"forwarders,omitempty"`
}

func pe_printJSON(v any) {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		bugs.Add("ERR", "json encode: %v", err)
	}
}

func pe_infoToJSON(info *pe_PEInfo) pe_jsonInfo {
	kind := "EXE"
	if info.IsDLL {
		kind = "DLL"
	}
	return pe_jsonInfo{
		Path:       info.Path,
		Machine:    machineName(info.Machine),
		Bits:       info.Bits,
		Kind:       kind,
		Subsystem:  info.SubsystemName,
		EntryPoint: info.EntryPoint,
		ImageBase:  info.ImageBase,
		TimeStamp:  info.TimeStamp,
		Sections:   info.Sections,
		Imports:    info.Imports,
		Exports:    info.Exports,
		Forwarders: info.Forwarders,
	}
}

type pe_cmdOpts struct {
	libPaths    []string
	jsonOut     bool
	recursive   bool
	summaryOnly bool
	failMissing bool
	noCheck     bool
}

func pe_reportExitCode(deps []pe_DepStatus, failMissing bool) int {
	missing, mismatch := 0, 0
	for _, d := range deps {
		if d.Status == "missing" {
			missing++
		}
		if d.Status == "bitmismatch" {
			mismatch++
		}
	}
	if failMissing && (missing > 0 || mismatch > 0) {
		return 1
	}
	return 0
}

func pe_cmdInfo(path string, opts *pe_cmdOpts) int {
	info, deps, err := pe_checkExe(path, opts.libPaths)
	if err != nil {
		fmt.Fprintf(os.Stderr, "winctl pe: %v\n", err)
		return 5
	}
	if opts.jsonOut {
		out := pe_infoToJSON(info)
		if opts.noCheck {
			pe_printJSON(out)
		} else {
			pe_printJSON(struct {
				pe_jsonInfo
				Dependencies []pe_DepStatus `json:"dependencies"`
			}{out, deps})
		}
		return pe_reportExitCode(deps, opts.failMissing)
	}
	pe_printHeader(info)
	pe_printSections(info)
	pe_printImports(info)
	if info.IsDLL {
		pe_printExports(info)
	}
	if !opts.noCheck {
		pe_printDeps(deps)
	}
	return pe_reportExitCode(deps, opts.failMissing)
}

func pe_cmdDeps(path string, opts *pe_cmdOpts) int {
	info, deps, err := pe_checkExe(path, opts.libPaths)
	if err != nil {
		fmt.Fprintf(os.Stderr, "winctl pe: %v\n", err)
		return 5
	}
	if opts.jsonOut {
		pe_printJSON(struct {
			Path         string         `json:"path"`
			Bits         string         `json:"bits"`
			Dependencies []pe_DepStatus `json:"dependencies"`
		}{info.Path, info.Bits, deps})
		return pe_reportExitCode(deps, opts.failMissing)
	}
	fmt.Printf("%s %s (%s)\n", c(clrCyan, "File:"), info.Path, info.Bits)
	pe_printDeps(deps)
	return pe_reportExitCode(deps, opts.failMissing)
}

func pe_cmdSections(path string, opts *pe_cmdOpts) int {
	info, err := pe_parsePE(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "winctl pe: %v\n", err)
		return 5
	}
	if opts.jsonOut {
		pe_printJSON(info.Sections)
		return 0
	}
	pe_printHeader(info)
	pe_printSections(info)
	return 0
}

func pe_cmdExports(path string, opts *pe_cmdOpts) int {
	info, err := pe_parsePE(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "winctl pe: %v\n", err)
		return 5
	}
	if opts.jsonOut {
		pe_printJSON(map[string]any{
			"path": info.Path, "exports": info.Exports, "forwarders": info.Forwarders,
		})
		return 0
	}
	pe_printHeader(info)
	pe_printExports(info)
	return 0
}

func pe_cmdImports(path string, opts *pe_cmdOpts) int {
	info, err := pe_parsePE(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "winctl pe: %v\n", err)
		return 5
	}
	if opts.jsonOut {
		pe_printJSON(map[string]any{
			"path": info.Path, "imports": info.Imports, "symbols": info.ImportSymbols,
		})
		return 0
	}
	pe_printHeader(info)
	pe_printImports(info)
	return 0
}

func pe_relPath(base, full string) string {
	rel, err := filepath.Rel(base, full)
	if err != nil {
		return full
	}
	return rel
}

func pe_scanExitCode(missing, mismatch int, failMissing bool) int {
	if failMissing && (missing > 0 || mismatch > 0) {
		return 1
	}
	return 0
}

func pe_scanDir(dir string, opts *pe_cmdOpts) int {
	if !pe_dirExists(dir) {
		fmt.Fprintf(os.Stderr, "winctl pe: %s is not a directory\n", dir)
		return 4
	}
	var files []string
	if opts.recursive {
		_ = filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
			if err != nil || info.IsDir() {
				return nil
			}
			ext := strings.ToLower(filepath.Ext(path))
			if ext == ".exe" || ext == ".dll" || ext == ".sys" {
				files = append(files, path)
			}
			return nil
		})
	} else {
		entries, err := os.ReadDir(dir)
		if err != nil {
			fmt.Fprintf(os.Stderr, "winctl pe: %v\n", err)
			return 5
		}
		for _, e := range entries {
			if e.IsDir() {
				continue
			}
			ext := strings.ToLower(filepath.Ext(e.Name()))
			if ext == ".exe" || ext == ".dll" || ext == ".sys" {
				files = append(files, filepath.Join(dir, e.Name()))
			}
		}
	}
	if len(files) == 0 {
		fmt.Fprintln(os.Stderr, "no PE files found")
		return 0
	}
	sort.Strings(files)
	if dryRun {
		fmt.Printf("[dry-run] would scan %d PE file(s) in %s\n", len(files), dir)
		return 0
	}
	sawSys := false
	for _, f := range files {
		if strings.EqualFold(filepath.Ext(f), ".sys") {
			sawSys = true
			break
		}
	}
	if sawSys {
		fmt.Fprintln(os.Stderr, "note: .sys drivers import kernel modules (ntoskrnl.exe, hal.dll);")
		fmt.Fprintln(os.Stderr, "      those will be reported as missing here. That is expected.")
	}
	var reports []pe_ExeReport
	totalMissing, totalMismatch, totalFiles := 0, 0, 0
	for _, path := range files {
		info, deps, err := pe_checkExe(path, opts.libPaths)
		if err != nil {
			reports = append(reports, pe_ExeReport{Path: path, ReadErrMsg: err.Error()})
			continue
		}
		rep := pe_ExeReport{
			Path: path, Bits: info.Bits, Machine: machineName(info.Machine),
			IsDLL: info.IsDLL, Subsystem: info.SubsystemName,
			Imports: len(info.Imports), Deps: deps,
		}
		for _, d := range deps {
			if d.Status == "missing" {
				rep.Missing++
			}
			if d.Status == "bitmismatch" {
				rep.Mismatch++
			}
		}
		totalMissing += rep.Missing
		totalMismatch += rep.Mismatch
		totalFiles++
		reports = append(reports, rep)
	}
	if opts.jsonOut {
		pe_printJSON(map[string]any{
			"directory": dir, "files": totalFiles,
			"totalMissing": totalMissing, "totalMismatch": totalMismatch,
			"reports": reports,
		})
		return pe_scanExitCode(totalMissing, totalMismatch, opts.failMissing)
	}
	nameW := dispWidth("FILE")
	bitsW := dispWidth("BITS")
	for _, r := range reports {
		if w := dispWidth(pe_relPath(dir, r.Path)); w > nameW {
			nameW = w
		}
		if w := dispWidth(r.Bits); w > bitsW {
			bitsW = w
		}
	}
	fmt.Println(c(clrBold+clrCyan,
		padRight("FILE", nameW)+"  "+padRight("BITS", bitsW)+"  "+
			padRight("IMPORTS", 7)+"  "+padRight("MISSING", 7)+"  "+
			padRight("MISMATCH", 8)+"  STATUS"))
	for _, r := range reports {
		rel := pe_relPath(dir, r.Path)
		status, statusColor := "ok", clrGreen
		if r.ReadErrMsg != "" {
			status, statusColor = "error", clrRed
		} else if r.Missing > 0 {
			status, statusColor = "missing", clrRed
		} else if r.Mismatch > 0 {
			status, statusColor = "mismatch", clrYellow
		}
		fmt.Println(padRight(rel, nameW)+"  "+
			padRight(r.Bits, bitsW)+"  "+
			padRight(strconv.Itoa(r.Imports), 7)+"  "+
			padRight(strconv.Itoa(r.Missing), 7)+"  "+
			padRight(strconv.Itoa(r.Mismatch), 8)+"  "+
			c(statusColor, status))
	}
	if !opts.summaryOnly {
		printedHeader := false
		for _, r := range reports {
			var problems []pe_DepStatus
			for _, d := range r.Deps {
				if d.Status == "missing" || d.Status == "bitmismatch" {
					problems = append(problems, d)
				}
			}
			if r.ReadErrMsg == "" && len(problems) == 0 {
				continue
			}
			if !printedHeader {
				fmt.Println(c(clrBold+clrCyan, "\nProblems"))
				printedHeader = true
			}
			fmt.Printf("\n  %s\n", c(clrCyan, r.Path))
			if r.ReadErrMsg != "" {
				fmt.Printf("    %s %s\n", c(clrRed, "read error:"), r.ReadErrMsg)
				continue
			}
			for _, d := range problems {
				switch d.Status {
				case "missing":
					fmt.Printf("    %s %s\n", c(clrRed, "missing:"), d.DLL)
				case "bitmismatch":
					fmt.Printf("    %s %s (have %s, want %s)\n",
						c(clrYellow, "bit mismatch:"), d.DLL, d.ActualBits, r.Bits)
				}
			}
		}
	}
	fmt.Fprintf(os.Stderr, "\n%d PE file(s), %d missing dependency(ies), %d bitness mismatch(es)\n",
		totalFiles, totalMissing, totalMismatch)
	return pe_scanExitCode(totalMissing, totalMismatch, opts.failMissing)
}

func pe_parseCmdOpts(args []string) (*pe_cmdOpts, []string, error) {
	opts := &pe_cmdOpts{}
	var rest []string
	i := 0
	for i < len(args) {
		a := args[i]
		switch a {
		case "--lib-path":
			if i+1 >= len(args) {
				return nil, nil, fmt.Errorf("--lib-path requires a directory")
			}
			opts.libPaths = append(opts.libPaths, args[i+1])
			i += 2
		case "--json":
			opts.jsonOut = true
			i++
		case "--recursive":
			opts.recursive = true
			i++
		case "--summary":
			opts.summaryOnly = true
			i++
		case "--fail-on-missing":
			opts.failMissing = true
			i++
		case "--no-check":
			opts.noCheck = true
			i++
		default:
			if strings.HasPrefix(a, "-") {
				return nil, nil, fmt.Errorf("unknown option %s", a)
			}
			rest = append(rest, a)
			i++
		}
	}
	return opts, rest, nil
}

func pe_cmdHistory() int {
	lines, err := auditReadLines()
	if err != nil {
		fmt.Fprintf(os.Stderr, "read log %s: %v\n", globalLogPath(), err)
		return 4
	}
	if len(lines) == 0 {
		fmt.Fprintln(os.Stderr, "log is empty")
		return 0
	}
	count := 0
	for i := len(lines) - 1; i >= 0; i-- {
		m, cmd, _, ok := auditParseLine(lines[i])
		if !ok || m != "pe" {
			continue
		}
		if isHistorySelf(cmd) {
			continue
		}
		count++
		fmt.Printf("[%d] %s\n", count, lines[i])
	}
	if count == 0 {
		fmt.Fprintln(os.Stderr, "no pe history entries in log")
	}
	return 0
}

func pe_cmdRollback() int {
	fmt.Fprintln(os.Stderr, "winctl pe is read-only: there are no operations to roll back")
	fmt.Fprintln(os.Stderr, "  It only reads PE headers and checks DLL search paths.")
	fmt.Fprintln(os.Stderr, "  Its history is for audit only; use --history to view it.")
	return 0
}

func pe_printHelp() {
	fmt.Printf("%s v%s (Windows)\n\n", c(clrBold+clrCyan, "winctl pe"), Version)
	fmt.Print(`USAGE
  winctl pe <file>                       same as "info"
  winctl pe info     <file> [OPTIONS]
  winctl pe deps     <file> [OPTIONS]
  winctl pe imports  <file> [OPTIONS]
  winctl pe exports  <file> [OPTIONS]
  winctl pe sections <file> [OPTIONS]
  winctl pe scan-dir <dir>  [OPTIONS]
  winctl pe --history
  winctl pe --rollback                   (always a no-op: read-only)

OPTIONS
  --lib-path <dir>       extra directory to search for DLLs (repeatable)
  --recursive            scan-dir: recurse into subdirectories
  --json                 JSON output
  --summary              scan-dir: only print the summary table
  --fail-on-missing      return exit code 1 on missing DLLs or bitness mismatch
  --no-check             info: skip the dependency check

GLOBAL
  -o, --out <path>       write stdout to a file
  --dry-run              print the plan without parsing any file
  --no-color             disable ANSI colors (also honors NO_COLOR)
  -b, --bugs             print collected errors/warnings on exit
  -h, --help             show this help
  --version              show version

All logs go to ./backup/winctl_logs.log
`)
}

func pe_main() {
	args, outPath, err := consumeGlobalFlags(os.Args[1:])
	if err != nil {
		fmt.Fprintf(os.Stderr, "winctl pe: %v\n", err)
		finalExit(2)
	}
	initColor()
	if has(args, "--version") {
		fmt.Printf("winctl pe v%s\n", Version)
		finalExit(0)
	}
	if len(args) == 0 || has(args, "-h", "--help") {
		pe_printHelp()
		finalExit(0)
	}
	if outPath != "" {
		if err := setupOutput(outPath); err != nil {
			fmt.Fprintf(os.Stderr, "winctl pe: %v\n", err)
			finalExit(2)
		}
	}
	if has(args, "--history") {
		finalExit(pe_cmdHistory())
	}
	if has(args, "--rollback") {
		finalExit(pe_cmdRollback())
	}

	cmd := ""
	rest := args
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		switch args[0] {
		case "info", "deps", "imports", "exports", "sections", "scan-dir":
			cmd = args[0]
			rest = args[1:]
		}
	}
	opts, positional, err := pe_parseCmdOpts(rest)
	if err != nil {
		fmt.Fprintf(os.Stderr, "winctl pe: %v\n", err)
		finalExit(2)
	}
	if cmd == "" {
		if len(positional) == 0 {
			fmt.Fprintln(os.Stderr, "winctl pe: missing file or directory (use -h for help)")
			finalExit(2)
		}
		cmd = "info"
	}

	var code int
	switch cmd {
	case "info", "deps", "imports", "exports", "sections":
		if len(positional) == 0 {
			fmt.Fprintf(os.Stderr, "winctl pe: %s requires a file\n", cmd)
			finalExit(2)
		}
		path := positional[0]
		if fi, err := os.Stat(path); err == nil && fi.IsDir() {
			fmt.Fprintf(os.Stderr, "winctl pe: %s is a directory (use scan-dir)\n", path)
			finalExit(2)
		}
		if dryRun {
			fmt.Printf("[dry-run] would parse %q (command=%s)\n", path, cmd)
			finalExit(0)
		}
		switch cmd {
		case "info":
			code = pe_cmdInfo(path, opts)
		case "deps":
			code = pe_cmdDeps(path, opts)
		case "imports":
			code = pe_cmdImports(path, opts)
		case "exports":
			code = pe_cmdExports(path, opts)
		case "sections":
			code = pe_cmdSections(path, opts)
		}
	case "scan-dir":
		if len(positional) == 0 {
			fmt.Fprintln(os.Stderr, "winctl pe: scan-dir requires a directory")
			finalExit(2)
		}
		code = pe_scanDir(positional[0], opts)
	default:
		fmt.Fprintf(os.Stderr, "winctl pe: unknown command %q\n", cmd)
		code = 2
	}
	if !dryRun && shouldLogRun() {
		auditLog("pe", buildCmdLine(os.Args), code)
	}
	finalExit(code)
}
// ============================================================================
// proc — process controller (list / monitor / limit / rollback)
// ============================================================================

var (
	proc_user32  = syscall.NewLazyDLL("user32.dll")
	proc_ntdll   = syscall.NewLazyDLL("ntdll.dll")
	proc_shell32 = syscall.NewLazyDLL("shell32.dll")
)

var (
	proc_pCreateToolhelp32Snapshot         = kernel32.NewProc("CreateToolhelp32Snapshot")
	proc_pProcess32FirstW                  = kernel32.NewProc("Process32FirstW")
	proc_pProcess32NextW                   = kernel32.NewProc("Process32NextW")
	proc_pOpenProcess                      = kernel32.NewProc("OpenProcess")
	proc_pTerminateProcess                 = kernel32.NewProc("TerminateProcess")
	proc_pK32GetProcessMemoryInfo          = kernel32.NewProc("K32GetProcessMemoryInfo")
	proc_pGetProcessTimes                  = kernel32.NewProc("GetProcessTimes")
	proc_pGetProcessHandleCount            = kernel32.NewProc("GetProcessHandleCount")
	proc_pGetProcessIoCounters             = kernel32.NewProc("GetProcessIoCounters")
	proc_pGetPriorityClass                 = kernel32.NewProc("GetPriorityClass")
	proc_pSetPriorityClass                 = kernel32.NewProc("SetPriorityClass")
	proc_pQueryFullProcessImageNameW       = kernel32.NewProc("QueryFullProcessImageNameW")
	proc_pCreateJobObjectW                 = kernel32.NewProc("CreateJobObjectW")
	proc_pAssignProcessToJobObject         = kernel32.NewProc("AssignProcessToJobObject")
	proc_pSetInformationJobObject          = kernel32.NewProc("SetInformationJobObject")
	proc_pQueryInformationJobObject        = kernel32.NewProc("QueryInformationJobObject")
	proc_pTerminateJobObject               = kernel32.NewProc("TerminateJobObject")
	proc_pCreateProcessW                   = kernel32.NewProc("CreateProcessW")
	proc_pResumeThread                     = kernel32.NewProc("ResumeThread")
	proc_pWaitForSingleObject              = kernel32.NewProc("WaitForSingleObject")
	proc_pGetExitCodeProcess               = kernel32.NewProc("GetExitCodeProcess")
	proc_pGetActiveProcessorCount          = kernel32.NewProc("GetActiveProcessorCount")
	proc_pGetLogicalProcessorInformationEx = kernel32.NewProc("GetLogicalProcessorInformationEx")
	proc_pGlobalMemoryStatusEx             = kernel32.NewProc("GlobalMemoryStatusEx")
	proc_pGetSystemTimes                   = kernel32.NewProc("GetSystemTimes")
	proc_pGetDiskFreeSpaceExW              = kernel32.NewProc("GetDiskFreeSpaceExW")
	proc_pSetConsoleMode                   = kernel32.NewProc("SetConsoleMode")
	proc_pReadConsoleInputW                = kernel32.NewProc("ReadConsoleInputW")
	proc_pGetTickCount64                   = kernel32.NewProc("GetTickCount64")
	proc_pGetConsoleScreenBufferInfo       = kernel32.NewProc("GetConsoleScreenBufferInfo")
	proc_pGetCurrentProcess                = kernel32.NewProc("GetCurrentProcess")

	proc_pGetGuiResources  = proc_user32.NewProc("GetGuiResources")
	proc_pNtSuspendProcess = proc_ntdll.NewProc("NtSuspendProcess")
	proc_pNtResumeProcess  = proc_ntdll.NewProc("NtResumeProcess")

	proc_pOpenProcessToken    = advapi32.NewProc("OpenProcessToken")
	proc_pGetTokenInformation = advapi32.NewProc("GetTokenInformation")
	proc_pLookupAccountSidW   = advapi32.NewProc("LookupAccountSidW")
	proc_pShellExecuteExW     = proc_shell32.NewProc("ShellExecuteExW")
)

type proc_apiEntry struct {
	name     string
	proc     *syscall.LazyProc
	required bool
}

var proc_apiTable = []proc_apiEntry{
	{"CreateToolhelp32Snapshot", proc_pCreateToolhelp32Snapshot, true},
	{"Process32FirstW", proc_pProcess32FirstW, true},
	{"Process32NextW", proc_pProcess32NextW, true},
	{"OpenProcess", proc_pOpenProcess, true},
	{"CloseHandle", pCloseHandle, true},
	{"TerminateProcess", proc_pTerminateProcess, true},
	{"K32GetProcessMemoryInfo", proc_pK32GetProcessMemoryInfo, true},
	{"GetProcessTimes", proc_pGetProcessTimes, true},
	{"GetProcessHandleCount", proc_pGetProcessHandleCount, true},
	{"GetProcessIoCounters", proc_pGetProcessIoCounters, true},
	{"GetPriorityClass", proc_pGetPriorityClass, true},
	{"SetPriorityClass", proc_pSetPriorityClass, true},
	{"QueryFullProcessImageNameW", proc_pQueryFullProcessImageNameW, true},
	{"CreateJobObjectW", proc_pCreateJobObjectW, true},
	{"AssignProcessToJobObject", proc_pAssignProcessToJobObject, true},
	{"SetInformationJobObject", proc_pSetInformationJobObject, true},
	{"QueryInformationJobObject", proc_pQueryInformationJobObject, true},
	{"TerminateJobObject", proc_pTerminateJobObject, true},
	{"CreateProcessW", proc_pCreateProcessW, true},
	{"ResumeThread", proc_pResumeThread, true},
	{"WaitForSingleObject", proc_pWaitForSingleObject, true},
	{"GetExitCodeProcess", proc_pGetExitCodeProcess, true},
	{"GetActiveProcessorCount", proc_pGetActiveProcessorCount, true},
	{"GetLogicalProcessorInformationEx", proc_pGetLogicalProcessorInformationEx, true},
	{"GlobalMemoryStatusEx", proc_pGlobalMemoryStatusEx, true},
	{"GetSystemTimes", proc_pGetSystemTimes, true},
	{"GetDiskFreeSpaceExW", proc_pGetDiskFreeSpaceExW, true},
	{"GetStdHandle", pGetStdHandle, true},
	{"GetConsoleMode", pGetConsoleMode, true},
	{"SetConsoleMode", proc_pSetConsoleMode, true},
	{"ReadConsoleInputW", proc_pReadConsoleInputW, true},
	{"GetTickCount64", proc_pGetTickCount64, true},
	{"GetConsoleScreenBufferInfo", proc_pGetConsoleScreenBufferInfo, true},
	{"GetCurrentProcess", proc_pGetCurrentProcess, true},
	{"ShellExecuteExW", proc_pShellExecuteExW, true},
	{"GetGuiResources", proc_pGetGuiResources, false},
	{"NtSuspendProcess", proc_pNtSuspendProcess, true},
	{"NtResumeProcess", proc_pNtResumeProcess, true},
	{"OpenProcessToken", proc_pOpenProcessToken, true},
	{"GetTokenInformation", proc_pGetTokenInformation, true},
	{"LookupAccountSidW", proc_pLookupAccountSidW, true},
}

var proc_apiOK = map[string]bool{}

func proc_initAPIs() {
	for _, e := range proc_apiTable {
		proc_apiOK[e.name] = e.proc.Find() == nil
	}
}

func proc_checkRequiredAPIs() {
	var missing []string
	for _, e := range proc_apiTable {
		if e.required && !proc_apiOK[e.name] {
			missing = append(missing, e.name)
		}
	}
	if len(missing) > 0 {
		fmt.Fprintf(os.Stderr, "winctl proc: missing required Windows APIs:\n  %s\n", strings.Join(missing, "\n  "))
		os.Exit(5)
	}
	if !proc_apiOK["GetGuiResources"] {
		bugs.Add("WARN", "user32.dll!GetGuiResources unavailable, gdiobj/userobj skipped")
	}
}

func proc_cpuColor(pct float64) string {
	switch {
	case pct >= 50:
		return clrRed
	case pct >= 20:
		return clrYellow
	case pct > 0.1:
		return clrGreen
	}
	return clrGray
}

func proc_openOutputFile(path string, asJSON bool) (*os.File, string, error) {
	isDir := strings.HasSuffix(path, `\`) || strings.HasSuffix(path, "/")
	if !isDir {
		if st, err := os.Stat(path); err == nil && st.IsDir() {
			isDir = true
		}
	}
	if isDir {
		ext := ".txt"
		if asJSON {
			ext = ".json"
		}
		name := "proc_" + time.Now().Format("20060102_150405.000") + ext
		path = filepath.Join(path, name)
	}
	dir := filepath.Dir(path)
	if dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return nil, path, fmt.Errorf("create directory %s: %w", dir, err)
		}
	}
	f, err := os.Create(path)
	if err != nil {
		return nil, path, err
	}
	return f, path, nil
}

func proc_setupOutput(cmd string, args []string) bool {
	path := ""
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "-o" || a == "--out":
			if i+1 >= len(args) {
				fmt.Fprintf(os.Stderr, "%s requires a path\n", a)
				return false
			}
			path = args[i+1]
			i++
		case strings.HasPrefix(a, "--out="):
			path = strings.TrimPrefix(a, "--out=")
		case strings.HasPrefix(a, "-o="):
			path = strings.TrimPrefix(a, "-o=")
		}
	}
	if path == "" {
		return true
	}
	if has(args, "--watch") {
		fmt.Fprintln(os.Stderr, "-o/--out cannot be used with --watch")
		return false
	}
	f, actualPath, err := proc_openOutputFile(path, has(args, "--json"))
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to open output file: %v\n", err)
		return false
	}
	origStdout := os.Stdout
	os.Stdout = f
	useColor = false
	outputCleanup = func() {
		_ = f.Sync()
		_ = f.Close()
		os.Stdout = origStdout
	}
	fmt.Fprintf(os.Stderr, "output redirected to %s\n", actualPath)
	return true
}

const (
	proc_PROCESS_TERMINATE       = 0x0001
	proc_PROCESS_SET_INFORMATION = 0x0200
	proc_PROCESS_SUSPEND_RESUME  = 0x0800
	proc_PROCESS_QUERY_LIMITED   = 0x1000
	proc_PROCESS_ALL_ACCESS      = 0x1F0FFF
	proc_PROCESS_SET_QUOTA       = 0x0100

	proc_TH32CS_SNAPPROCESS = 0x00000002
	proc_CREATE_SUSPENDED   = 0x00000004
	proc_CREATE_NEW_CONSOLE = 0x00000010
	proc_CREATE_NO_WINDOW   = 0x08000000
	proc_INFINITE           = 0xFFFFFFFF

	proc_ENABLE_PROCESSED_INPUT             = 0x0001
	proc_ENABLE_LINE_INPUT                  = 0x0002
	proc_ENABLE_ECHO_INPUT                  = 0x0004
	proc_ENABLE_WINDOW_INPUT                = 0x0008
	proc_ENABLE_MOUSE_INPUT                 = 0x0010
	proc_ENABLE_EXTENDED_FLAGS              = 0x0080
	proc_ENABLE_VIRTUAL_TERMINAL_PROCESSING = 0x0004

	proc_ALL_PROCESSOR_GROUPS  = 0xFFFF
	proc_RelationProcessorCore = 0

	proc_JOB_OBJECT_LIMIT_JOB_MEMORY        = 0x00000200
	proc_JOB_OBJECT_LIMIT_WORKINGSET        = 0x00000001
	proc_JOB_OBJECT_LIMIT_ACTIVE_PROCESS    = 0x00000008
	proc_JOB_OBJECT_LIMIT_AFFINITY          = 0x00000010
	proc_JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x00002000

	proc_JobObjectExtendedLimitInformation  = 9
	proc_JobObjectCpuRateControlInformation = 15
	proc_JobObjectNetRateControlInformation = 32
	proc_JobObjectIoRateControlInformation  = 33
	proc_JobObjectBasicProcessIdList        = 3

	proc_JOB_CPU_RATE_CONTROL_ENABLE   = 0x1
	proc_JOB_CPU_RATE_CONTROL_HARD_CAP = 0x4
	proc_JOB_NET_RATE_CONTROL_ENABLE   = 0x1
	proc_TOKEN_QUERY                   = 0x0008
	proc_TokenElevation                = 20

	proc_SEE_MASK_NOCLOSEPROCESS = 0x00000040
	proc_SEE_MASK_NOASYNC        = 0x00000100
	proc_SW_SHOWNORMAL           = 1

	proc_VK_BACK   = 0x08
	proc_VK_TAB    = 0x09
	proc_VK_RETURN = 0x0D
	proc_VK_ESCAPE = 0x1B
	proc_VK_SPACE  = 0x20
	proc_VK_UP     = 0x26
	proc_VK_DOWN   = 0x28
	proc_VK_CTRL_C = 0x43
	proc_VK_F2     = 0x71

	proc_LEFT_CTRL_PRESSED = 0x0008
	proc_MOUSE_WHEELED     = 0x0004

	proc_ERROR_CANCELLED       = syscall.Errno(1223)
	proc_ERR_ACCESS_DENIED     = syscall.Errno(5)
	proc_ERR_INVALID_PARAMETER = syscall.Errno(87)
	proc_ERR_NO_MORE_FILES     = syscall.Errno(18)
)

type proc_FILETIME struct{ LowDateTime, HighDateTime uint32 }

type proc_PROCESSENTRY32 struct {
	Size            uint32
	Usage           uint32
	ProcessID       uint32
	DefaultHeapID   uintptr
	ModuleID        uint32
	Threads         uint32
	ParentProcessID uint32
	PriClassBase    int32
	Flags           uint32
	ExeFile         [260]uint16
}

type proc_PROCESS_MEMORY_COUNTERS struct {
	Cb                         uint32
	PageFaultCount             uint32
	PeakWorkingSetSize         uintptr
	WorkingSetSize             uintptr
	QuotaPeakPagedPoolUsage    uintptr
	QuotaPagedPoolUsage        uintptr
	QuotaPeakNonPagedPoolUsage uintptr
	QuotaNonPagedPoolUsage     uintptr
	PagefileUsage              uintptr
	PeakPagefileUsage          uintptr
}

type proc_IO_COUNTERS struct {
	ReadOperationCount, WriteOperationCount, OtherOperationCount uint64
	ReadTransferCount, WriteTransferCount, OtherTransferCount    uint64
}

type proc_MEMORYSTATUSEX struct {
	Length, MemoryLoad                               uint32
	TotalPhys, AvailPhys                             uint64
	TotalPageFile, AvailPageFile                     uint64
	TotalVirtual, AvailVirtual, AvailExtendedVirtual uint64
}

type proc_STARTUPINFOW struct {
	Cb                          uint32
	Reserved                    *uint16
	Desktop                     *uint16
	Title                       *uint16
	X, Y, XSize, YSize          uint32
	XCountChars, YCountChars    uint32
	FillAttribute, Flags        uint32
	ShowWindow                  uint16
	CbReserved2                 uint16
	Reserved2                   *byte
	StdInput, StdOutput, StdErr syscall.Handle
}

type proc_PROCESS_INFORMATION struct {
	Process, Thread     syscall.Handle
	ProcessID, ThreadID uint32
}

type proc_JOBOBJECT_CPU_RATE_CONTROL_INFORMATION struct{ ControlFlags, CpuRate uint32 }
type proc_JOBOBJECT_NET_RATE_CONTROL_INFORMATION struct {
	MaxBandwidth uint64
	ControlFlags uint32
	DscpTag      uint32
}
type proc_JOBOBJECT_IO_RATE_CONTROL_INFORMATION struct {
	MaxIops, MaxBandwidth, ReservationIops int64
	VolumeName                             uintptr
	BaseIoSize, ControlFlags               uint32
}

type proc_COORD struct{ X, Y int16 }
type proc_SMALL_RECT struct{ Left, Top, Right, Bottom int16 }
type proc_CONSOLE_SCREEN_BUFFER_INFO struct {
	Size, CursorPosition proc_COORD
	Attributes           uint16
	Window               proc_SMALL_RECT
	MaximumWindowSize    proc_COORD
}
type proc_INPUT_RECORD struct {
	EventType uint16
	_         uint16
	Event     [16]byte
}
type proc_KEY_EVENT_RECORD struct {
	KeyDown                                      int32
	RepeatCount, VirtualKeyCode, VirtualScanCode uint16
	UnicodeChar                                  uint16
	ControlKeyState                              uint32
}
type proc_MOUSE_EVENT_RECORD struct {
	MousePosX, MousePosY                     int16
	ButtonState, ControlKeyState, EventFlags uint32
}
type proc_TOKEN_ELEVATION struct{ TokenIsElevated uint32 }

type proc_SHELLEXECUTEINFO struct {
	CbSize         uint32
	FMask          uint32
	Hwnd           uintptr
	LpVerb         *uint16
	LpFile         *uint16
	LpParameters   *uint16
	LpDirectory    *uint16
	NnShow         int32
	HInstApp       uintptr
	LpIDList       uintptr
	LpClass        *uint16
	HkeyClass      uintptr
	DwHotKey       uint32
	HIconOrMonitor uintptr
	HProcess       uintptr
}

// ---------- Job limits ----------

type proc_ResourceLimits struct {
	Affinity     *uint64
	CPUCores     *float64
	IOPS         *int64
	IORead       *uint64
	IOWrite      *uint64
	Mem          *uint64
	NetIn        *uint64
	NetOut       *uint64
	OnExit       string
	ProcessCount *uint32
	Timeout      *time.Duration
	WorkingSet   *uint64
}

type proc_runOptions struct {
	workDir  string
	title    string
	priority uint32
	noWindow bool
}

func proc_buildExtendedLimitBuffer(lim *proc_ResourceLimits, isRun bool) []byte {
	const (
		size          = 144
		offLimitFlags = 16
		offMaxWS      = 32
		offActiveProc = 40
		offAffinity   = 48
		offJobMemLim  = 120
	)
	buf := make([]byte, size)
	var limitFlags uint32
	if lim.Mem != nil {
		limitFlags |= proc_JOB_OBJECT_LIMIT_JOB_MEMORY
		binary.LittleEndian.PutUint64(buf[offJobMemLim:], *lim.Mem)
	}
	if lim.WorkingSet != nil {
		limitFlags |= proc_JOB_OBJECT_LIMIT_WORKINGSET
		binary.LittleEndian.PutUint64(buf[offMaxWS:], *lim.WorkingSet)
	}
	if lim.ProcessCount != nil {
		limitFlags |= proc_JOB_OBJECT_LIMIT_ACTIVE_PROCESS
		binary.LittleEndian.PutUint32(buf[offActiveProc:], *lim.ProcessCount)
	}
	if lim.Affinity != nil {
		limitFlags |= proc_JOB_OBJECT_LIMIT_AFFINITY
		binary.LittleEndian.PutUint64(buf[offAffinity:], *lim.Affinity)
	}
	if lim.OnExit == "kill" && isRun {
		limitFlags |= proc_JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
	}
	binary.LittleEndian.PutUint32(buf[offLimitFlags:], limitFlags)
	return buf
}

type proc_cleanupEntry struct {
	job    *proc_jobHandle
	onExit string
}

var (
	proc_cleanups  []proc_cleanupEntry
	proc_cleanupMu sync.Mutex
)

func proc_registerCleanup(j *proc_jobHandle, onExit string) {
	proc_cleanupMu.Lock()
	proc_cleanups = append(proc_cleanups, proc_cleanupEntry{j, onExit})
	proc_cleanupMu.Unlock()
}

func proc_runCleanups() {
	proc_cleanupMu.Lock()
	list := proc_cleanups
	proc_cleanups = nil
	proc_cleanupMu.Unlock()
	for _, e := range list {
		switch e.onExit {
		case "kill":
			proc_pTerminateJobObject.Call(uintptr(e.job.h), 1)
		case "suspend":
			proc_suspendJobProcesses(e.job)
		}
		e.job.close()
	}
}

func proc_suspendJobProcesses(j *proc_jobHandle) {
	var need uint32
	proc_pQueryInformationJobObject.Call(uintptr(j.h), proc_JobObjectBasicProcessIdList, 0, 0, uintptr(unsafe.Pointer(&need)))
	if need == 0 {
		need = 1024
	}
	buf := make([]byte, need+64)
	r, _, _ := proc_pQueryInformationJobObject.Call(uintptr(j.h), proc_JobObjectBasicProcessIdList,
		uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)), uintptr(unsafe.Pointer(&need)))
	if r == 0 {
		return
	}
	count := *(*uint32)(unsafe.Pointer(&buf[4]))
	base := uintptr(8)
	step := unsafe.Sizeof(uintptr(0))
	for i := uint32(0); i < count && base+uintptr(i)*step < uintptr(len(buf)); i++ {
		pid := uint32(*(*uintptr)(unsafe.Pointer(&buf[base+uintptr(i)*step])))
		_ = proc_suspendProcess(pid)
	}
}

func proc_exit(code int) {
	proc_runCleanups()
	bugs.Flush()
	if outputCleanup != nil {
		outputCleanup()
		outputCleanup = nil
	}
	auditClose()
	os.Exit(code)
}

// ---------- Short-option combining ----------

var proc_shortNoArg = map[byte]bool{'a': true, 'e': true, 't': true, 'm': true, 'b': true, 'h': true}
var proc_shortReqArg = map[byte]bool{'k': true, 'x': true, 'p': true, 'n': true, 'o': true}
var proc_shortOptArg = map[byte]bool{'s': true}

func proc_expandShortArgs(args []string) []string {
	out := make([]string, 0, len(args)*2)
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "--" {
			out = append(out, a)
			out = append(out, args[i+1:]...)
			return out
		}
		if len(a) < 2 || a[0] != '-' || a[1] == '-' {
			out = append(out, a)
			continue
		}
		if expanded, ok := proc_tryExpandShort(a[1:]); ok {
			out = append(out, expanded...)
		} else {
			out = append(out, a)
		}
	}
	return out
}

func proc_tryExpandShort(s string) ([]string, bool) {
	var out []string
	j := 0
	for j < len(s) {
		ch := s[j]
		if proc_shortNoArg[ch] {
			out = append(out, "-"+string(ch))
			j++
			continue
		}
		if proc_shortReqArg[ch] {
			out = append(out, "-"+string(ch))
			if rest := s[j+1:]; rest != "" {
				out = append(out, rest)
			}
			return out, true
		}
		if proc_shortOptArg[ch] {
			rest := s[j+1:]
			if rest != "" {
				if _, err := strconv.Atoi(rest); err == nil {
					out = append(out, "-"+string(ch), rest)
					return out, true
				}
			}
			out = append(out, "-"+string(ch))
			j++
			continue
		}
		return nil, false
	}
	return out, true
}

// ---------- Command parsing ----------

var proc_commandAliases = map[string]string{
	"-a": "list", "--all": "list",
	"-t": "total", "--total": "total",
	"-s": "sum", "--sum": "sum",
	"-m": "monitor", "--monitor": "monitor",
	"-k": "kill", "--kill": "kill",
	"-x": "superkill", "--super-kill": "superkill",
	"--suspend":  "suspend",
	"--resume":   "resume",
	"--priority": "priority",
	"--run":      "run",
	"--history":  "history",
	"--rollback": "rollback",
	"-p": "limit", "--pid": "limit",
	"-n": "limit", "--name": "limit",
}

var proc_subcommands = map[string]bool{
	"list": true, "total": true, "sum": true, "monitor": true,
	"kill": true, "superkill": true, "suspend": true, "resume": true,
	"priority": true, "limit": true, "run": true,
	"history": true, "rollback": true, "help": true, "version": true,
}

func proc_removeAt(args []string, i int) []string {
	out := make([]string, 0, len(args)-1)
	out = append(out, args[:i]...)
	out = append(out, args[i+1:]...)
	return out
}

func proc_hasBeforeDoubleDash(args []string, flags ...string) bool {
	for _, a := range args {
		if a == "--" {
			return false
		}
		for _, f := range flags {
			if a == f {
				return true
			}
		}
	}
	return false
}

func proc_parseCommand(args []string) (cmd string, rest []string, ok bool) {
	for i, a := range args {
		if a == "--" {
			break
		}
		if strings.HasPrefix(a, "-") {
			continue
		}
		if proc_subcommands[a] {
			return a, proc_removeAt(args, i), true
		}
		break
	}
	for i, a := range args {
		if a == "--" {
			break
		}
		if alias, isCmd := proc_commandAliases[a]; isCmd {
			if alias == "limit" {
				return "limit", args, true
			}
			return alias, proc_removeAt(args, i), true
		}
	}
	return "", args, false
}

var proc_limitOptionFlags = map[string]bool{
	"--affinity": true, "--cpu": true, "--iops": true, "--io-read": true,
	"--io-write": true, "--mem": true, "--net": true, "--net-in": true,
	"--net-out": true, "--on-proc_exit": true, "--process-count": true,
	"--timeout": true, "--working-set": true,
}

func proc_isQueryCommand(cmd string) bool {
	argv := proc_splitCommandLine(cmd)
	if len(argv) < 2 {
		return true
	}
	c, rest, ok := proc_parseCommand(argv[1:])
	if !ok {
		return true
	}
	switch c {
	case "help", "version", "history", "rollback", "list", "total", "sum", "monitor":
		return true
	case "limit":
		for _, a := range rest {
			if proc_limitOptionFlags[a] {
				return false
			}
		}
		return true
	}
	return false
}

func proc_invertCommand(cmd string) (string, error) {
	argv := proc_splitCommandLine(cmd)
	if len(argv) == 0 {
		return "", fmt.Errorf("empty command")
	}
	exe := argv[0]
	c, rest, ok := proc_parseCommand(argv[1:])
	if !ok {
		return "", fmt.Errorf("cannot parse command: %s", cmd)
	}
	firstPositional := func(args []string) string {
		for _, a := range args {
			if a == "--" {
				return ""
			}
			if !strings.HasPrefix(a, "-") {
				return a
			}
		}
		return ""
	}
	switch c {
	case "suspend":
		t := firstPositional(rest)
		if t == "" {
			return "", fmt.Errorf("suspend requires a target")
		}
		return proc_joinCommandLine([]string{exe, "resume", t}), nil
	case "resume":
		t := firstPositional(rest)
		if t == "" {
			return "", fmt.Errorf("resume requires a target")
		}
		return proc_joinCommandLine([]string{exe, "suspend", t}), nil
	case "kill", "superkill":
		return "", fmt.Errorf("kill has no inverse (process is already gone)")
	case "priority":
		return "", fmt.Errorf("priority has no inverse (original priority was not logged)")
	case "run":
		return "", fmt.Errorf("run has no inverse (child PID was not logged)")
	case "limit":
		return "", fmt.Errorf("limits cannot be removed from a running process")
	}
	return "", fmt.Errorf("no invertible operation found (only suspend/resume are auto-invertible)")
}

func proc_runCommandLine(cmdLine string) (int, error) {
	p, err := syscall.UTF16PtrFromString(cmdLine)
	if err != nil {
		return 5, err
	}
	var si proc_STARTUPINFOW
	si.Cb = uint32(unsafe.Sizeof(si))
	var pi proc_PROCESS_INFORMATION
	r, _, callErr := proc_pCreateProcessW.Call(0, uintptr(unsafe.Pointer(p)), 0, 0, 1, 0, 0, 0,
		uintptr(unsafe.Pointer(&si)), uintptr(unsafe.Pointer(&pi)))
	if r == 0 {
		return 5, callErr
	}
	defer pCloseHandle.Call(uintptr(pi.Thread))
	defer pCloseHandle.Call(uintptr(pi.Process))
	proc_pWaitForSingleObject.Call(uintptr(pi.Process), proc_INFINITE)
	var code uint32
	proc_pGetExitCodeProcess.Call(uintptr(pi.Process), uintptr(unsafe.Pointer(&code)))
	return int(code), nil
}

func proc_splitCommandLine(cmd string) []string {
	var out []string
	var buf strings.Builder
	inQuote := false
	i := 0
	for i < len(cmd) {
		ch := cmd[i]
		if ch == '"' {
			inQuote = !inQuote
			i++
			continue
		}
		if ch == '\\' && inQuote && i+1 < len(cmd) && cmd[i+1] == '"' {
			buf.WriteByte('"')
			i += 2
			continue
		}
		if ch == ' ' && !inQuote {
			if buf.Len() > 0 {
				out = append(out, buf.String())
				buf.Reset()
			}
			i++
			continue
		}
		buf.WriteByte(ch)
		i++
	}
	if buf.Len() > 0 {
		out = append(out, buf.String())
	}
	return out
}

func proc_joinCommandLine(argv []string) string {
	parts := make([]string, len(argv))
	for i, a := range argv {
		parts[i] = syscall.EscapeArg(a)
	}
	return strings.Join(parts, " ")
}

// ---------- History / rollback ----------

func proc_logLines() ([]string, error) {
	lines, err := auditReadLines()
	if err != nil {
		return nil, err
	}
	var out []string
	for _, l := range lines {
		m, cmd, _, ok := auditParseLine(l)
		if !ok || m != "proc" {
			continue
		}
		out = append(out, cmd)
	}
	return out, nil
}

func proc_cmdHistory() {
	cmds, err := proc_logLines()
	if err != nil {
		fmt.Fprintf(os.Stderr, "read operation log: %v\n", err)
		proc_exit(4)
	}
	type entry struct {
		cmd string
		raw string
	}
	var entries []entry
	for i := len(cmds) - 1; i >= 0; i-- {
		cmd := cmds[i]
		if proc_isQueryCommand(cmd) {
			continue
		}
		entries = append(entries, entry{cmd, cmd})
	}
	if len(entries) == 0 {
		fmt.Fprintln(os.Stderr, "operation log has no rollback-able entries")
		proc_exit(0)
	}
	for i, e := range entries {
		fmt.Printf("[%d] %s\n", i+1, e.raw)
	}
	fmt.Fprintf(os.Stderr, "\n%d rollback-able operation(s). Full log: %s\n", len(entries), globalLogPath())
	proc_exit(0)
}

func proc_cmdRollback(args []string) {
	n := 0
	for _, a := range args {
		if a == "--" {
			break
		}
		if strings.HasPrefix(a, "-") {
			continue
		}
		if v, err := strconv.Atoi(a); err == nil {
			n = v
			break
		}
	}
	if n <= 0 {
		fmt.Fprintln(os.Stderr, "usage: winctl proc rollback <N>")
		proc_exit(2)
	}
	cmds, err := proc_logLines()
	if err != nil {
		fmt.Fprintf(os.Stderr, "read operation log: %v\n", err)
		proc_exit(4)
	}
	var all []string
	for _, cmd := range cmds {
		if proc_isQueryCommand(cmd) {
			continue
		}
		all = append(all, cmd)
	}
	if len(all) == 0 {
		fmt.Fprintln(os.Stderr, "operation log has no rollback-able entries")
		proc_exit(4)
	}
	if n > len(all) {
		n = len(all)
	}
	sel := make([]string, n)
	for i := 0; i < n; i++ {
		sel[i] = all[len(all)-1-i]
	}
	okCount, failCount := 0, 0
	for k, cmd := range sel {
		inv, err := proc_invertCommand(cmd)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[rollback] step %d: cannot invert %q: %v\n", k+1, cmd, err)
			failCount++
			continue
		}
		fmt.Fprintf(os.Stderr, "[rollback] step %d: %s\n", k+1, inv)
		code, err := proc_runCommandLine(inv)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[rollback] step %d: exit code = 5 (%v)\n", k+1, err)
			failCount++
			continue
		}
		fmt.Fprintf(os.Stderr, "[rollback] step %d: exit code = %d\n", k+1, code)
		if code == 0 {
			okCount++
		} else {
			failCount++
		}
	}
	if failCount == 0 {
		proc_exit(0)
	}
	if okCount == 0 {
		proc_exit(2)
	}
	proc_exit(1)
}

// ---------- Elevation ----------

func proc_isAdmin() bool {
	h, _, _ := proc_pGetCurrentProcess.Call()
	if h == 0 {
		return false
	}
	var token syscall.Handle
	if r, _, _ := proc_pOpenProcessToken.Call(h, proc_TOKEN_QUERY, uintptr(unsafe.Pointer(&token))); r == 0 {
		return false
	}
	defer pCloseHandle.Call(uintptr(token))
	var elev proc_TOKEN_ELEVATION
	var size uint32
	r, _, _ := proc_pGetTokenInformation.Call(uintptr(token), proc_TokenElevation,
		uintptr(unsafe.Pointer(&elev)), uintptr(unsafe.Sizeof(elev)),
		uintptr(unsafe.Pointer(&size)))
	if r == 0 {
		return false
	}
	return elev.TokenIsElevated != 0
}

func proc_relaunchElevated(originalArgs []string) (int, error) {
	exePath, err := os.Executable()
	if err != nil {
		return 5, fmt.Errorf("locate executable: %w", err)
	}
	paramParts := []string{"proc", "run"}
	for _, a := range originalArgs {
		paramParts = append(paramParts, syscall.EscapeArg(a))
	}
	paramParts = append(paramParts, "--elevated")
	verb, _ := syscall.UTF16PtrFromString("runas")
	filePtr, _ := syscall.UTF16PtrFromString(exePath)
	paramsPtr, _ := syscall.UTF16PtrFromString(strings.Join(paramParts, " "))
	var sei proc_SHELLEXECUTEINFO
	sei.CbSize = uint32(unsafe.Sizeof(sei))
	sei.FMask = proc_SEE_MASK_NOCLOSEPROCESS | proc_SEE_MASK_NOASYNC
	sei.LpVerb = verb
	sei.LpFile = filePtr
	sei.LpParameters = paramsPtr
	sei.NnShow = proc_SW_SHOWNORMAL
	r, _, callErr := proc_pShellExecuteExW.Call(uintptr(unsafe.Pointer(&sei)))
	if r == 0 {
		if errno, ok := callErr.(syscall.Errno); ok && errno == proc_ERROR_CANCELLED {
			return 5, fmt.Errorf("UAC elevation cancelled by user")
		}
		return 5, fmt.Errorf("ShellExecuteExW: %v", callErr)
	}
	if sei.HProcess == 0 {
		return 5, fmt.Errorf("ShellExecuteExW returned no process handle")
	}
	defer pCloseHandle.Call(sei.HProcess)
	proc_pWaitForSingleObject.Call(sei.HProcess, proc_INFINITE)
	var code uint32
	proc_pGetExitCodeProcess.Call(sei.HProcess, uintptr(unsafe.Pointer(&code)))
	return int(code), nil
}

// ---------- Data model ----------

type proc_ProcInfo struct {
	PID        uint32    `json:"pid"`
	PPID       uint32    `json:"ppid"`
	Name       string    `json:"name"`
	Exe        string    `json:"exe,omitempty"`
	CPU        float64   `json:"cpu,omitempty"`
	Mem        uint64    `json:"mem,omitempty"`
	Threads    uint32    `json:"threads,omitempty"`
	Handles    uint32    `json:"handles,omitempty"`
	GdiObj     uint32    `json:"gdiobj,omitempty"`
	UserObj    uint32    `json:"userobj,omitempty"`
	IOReadB    uint64    `json:"io_read_b,omitempty"`
	IOWriteB   uint64    `json:"io_write_b,omitempty"`
	IOReadC    uint64    `json:"io_read_c,omitempty"`
	IOWriteC   uint64    `json:"io_write_c,omitempty"`
	Priority   string    `json:"priority,omitempty"`
	Username   string    `json:"username,omitempty"`
	PageFaults uint64    `json:"page_faults,omitempty"`
	CreateTime time.Time `json:"-"`
}

type proc_SysInfo struct {
	LogicalCPU  int             `json:"logical_cpu"`
	PhysicalCPU int             `json:"physical_cpu"`
	CPUPercent  float64         `json:"cpu_percent"`
	MemTotal    uint64          `json:"mem_total"`
	MemUsed     uint64          `json:"mem_used"`
	MemFree     uint64          `json:"mem_free"`
	Disks       []proc_DiskInfo `json:"disks,omitempty"`
	Uptime      string          `json:"uptime"`
}

type proc_DiskInfo struct {
	Letter  string  `json:"letter"`
	Percent float64 `json:"percent"`
	Free    uint64  `json:"free"`
	Total   uint64  `json:"total"`
}

func proc_ftU64(ft proc_FILETIME) uint64 { return uint64(ft.HighDateTime)<<32 | uint64(ft.LowDateTime) }

func proc_filetimeToTime(ft proc_FILETIME) time.Time {
	v := int64(proc_ftU64(ft))
	if v <= 0 {
		return time.Time{}
	}
	return time.Unix(0, (v-116444736000000000)*100)
}

func proc_utf16At(buf []uint16) string {
	for i, v := range buf {
		if v == 0 {
			return syscall.UTF16ToString(buf[:i])
		}
	}
	return syscall.UTF16ToString(buf)
}

func proc_openProcess(access uint32, pid uint32) (syscall.Handle, error) {
	h, _, err := proc_pOpenProcess.Call(uintptr(access), 0, uintptr(pid))
	if h == 0 {
		return 0, err
	}
	return syscall.Handle(h), nil
}

type proc_procSnapshot struct {
	PID, PPID uint32
	Name      string
	Threads   uint32
}

func proc_listProcesses() ([]proc_procSnapshot, error) {
	h, _, err := proc_pCreateToolhelp32Snapshot.Call(proc_TH32CS_SNAPPROCESS, 0)
	if syscall.Handle(h) == syscall.InvalidHandle {
		return nil, fmt.Errorf("CreateToolhelp32Snapshot: %w", err)
	}
	defer pCloseHandle.Call(h)
	var pe proc_PROCESSENTRY32
	pe.Size = uint32(unsafe.Sizeof(pe))
	if r, _, err := proc_pProcess32FirstW.Call(h, uintptr(unsafe.Pointer(&pe))); r == 0 {
		return nil, fmt.Errorf("Process32First: %w", err)
	}
	out := make([]proc_procSnapshot, 0, 512)
	for {
		out = append(out, proc_procSnapshot{pe.ProcessID, pe.ParentProcessID, proc_utf16At(pe.ExeFile[:]), pe.Threads})
		r, _, err := proc_pProcess32NextW.Call(h, uintptr(unsafe.Pointer(&pe)))
		if r == 0 {
			if errno, ok := err.(syscall.Errno); ok && errno == proc_ERR_NO_MORE_FILES {
				break
			}
			break
		}
	}
	return out, nil
}

func proc_resolveTarget(target string) ([]uint32, error) {
	if pid, err := strconv.ParseUint(target, 10, 32); err == nil {
		return []uint32{uint32(pid)}, nil
	}
	procs, err := proc_listProcesses()
	if err != nil {
		return nil, err
	}
	var pids []uint32
	for _, p := range procs {
		if strings.EqualFold(p.Name, target) {
			pids = append(pids, p.PID)
		}
	}
	if len(pids) == 0 {
		return nil, fmt.Errorf("process %q not found", target)
	}
	return pids, nil
}

func proc_needsOpen(fields map[string]bool) bool {
	for k := range fields {
		if k != "pid" && k != "name" && k != "threads" {
			return true
		}
	}
	return false
}

func proc_collectDetails(snaps []proc_procSnapshot, fields map[string]bool, parallel int) []proc_ProcInfo {
	out := make([]proc_ProcInfo, len(snaps))
	for i, s := range snaps {
		out[i] = proc_ProcInfo{PID: s.PID, PPID: s.PPID, Name: s.Name, Threads: s.Threads}
	}
	if !proc_needsOpen(fields) || len(snaps) == 0 {
		return out
	}
	if parallel < 1 {
		parallel = 1
	}
	if parallel > len(snaps) {
		parallel = len(snaps)
	}
	jobs := make(chan int, len(snaps))
	var wg sync.WaitGroup
	for w := 0; w < parallel; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range jobs {
				pid := snaps[i].PID
				if err := proc_queryProcessDetail(&out[i], pid, fields); err != nil {
					bugs.Add("WARN", "detail pid=%d: %v", pid, err)
				}
			}
		}()
	}
	for i := range snaps {
		jobs <- i
	}
	close(jobs)
	wg.Wait()
	return out
}

func proc_queryProcessDetail(p *proc_ProcInfo, pid uint32, fields map[string]bool) error {
	h, err := proc_openProcess(proc_PROCESS_QUERY_LIMITED, pid)
	if err != nil {
		return err
	}
	defer pCloseHandle.Call(uintptr(h))

	if fields["mem"] || fields["page_faults"] {
		var pmc proc_PROCESS_MEMORY_COUNTERS
		pmc.Cb = uint32(unsafe.Sizeof(pmc))
		if r, _, _ := proc_pK32GetProcessMemoryInfo.Call(uintptr(h), uintptr(unsafe.Pointer(&pmc)), uintptr(pmc.Cb)); r != 0 {
			p.Mem = uint64(pmc.WorkingSetSize)
			p.PageFaults = uint64(pmc.PageFaultCount)
		}
	}
	if fields["handles"] {
		var n uint32
		if r, _, _ := proc_pGetProcessHandleCount.Call(uintptr(h), uintptr(unsafe.Pointer(&n))); r != 0 {
			p.Handles = n
		}
	}
	if proc_apiOK["GetGuiResources"] {
		if fields["gdiobj"] {
			if r, _, _ := proc_pGetGuiResources.Call(uintptr(h), 0); r != 0 {
				p.GdiObj = uint32(r)
			}
		}
		if fields["userobj"] {
			if r, _, _ := proc_pGetGuiResources.Call(uintptr(h), 1); r != 0 {
				p.UserObj = uint32(r)
			}
		}
	}
	if fields["io_read_b"] || fields["io_write_b"] || fields["io_read_c"] || fields["io_write_c"] {
		var ioc proc_IO_COUNTERS
		if r, _, _ := proc_pGetProcessIoCounters.Call(uintptr(h), uintptr(unsafe.Pointer(&ioc))); r != 0 {
			p.IOReadB = ioc.ReadTransferCount
			p.IOWriteB = ioc.WriteTransferCount
			p.IOReadC = ioc.ReadOperationCount
			p.IOWriteC = ioc.WriteOperationCount
		}
	}
	if fields["priority"] {
		if r, _, _ := proc_pGetPriorityClass.Call(uintptr(h)); r != 0 {
			p.Priority = proc_priorityName(uint32(r))
		}
	}
	if fields["create-time"] {
		var ct, e, k, u proc_FILETIME
		if r, _, _ := proc_pGetProcessTimes.Call(uintptr(h),
			uintptr(unsafe.Pointer(&ct)), uintptr(unsafe.Pointer(&e)),
			uintptr(unsafe.Pointer(&k)), uintptr(unsafe.Pointer(&u))); r != 0 {
			p.CreateTime = proc_filetimeToTime(ct)
		}
	}
	if fields["username"] {
		p.Username = proc_usernameByHandle(h)
	}
	if fields["exe"] {
		p.Exe = proc_imagePathByHandle(h)
	}
	return nil
}

func proc_usernameByHandle(h syscall.Handle) string {
	var token syscall.Handle
	if r, _, _ := proc_pOpenProcessToken.Call(uintptr(h), proc_TOKEN_QUERY, uintptr(unsafe.Pointer(&token))); r == 0 {
		return ""
	}
	defer pCloseHandle.Call(uintptr(token))
	var size uint32
	proc_pGetTokenInformation.Call(uintptr(token), 1, 0, 0, uintptr(unsafe.Pointer(&size)))
	if size == 0 {
		return ""
	}
	buf := make([]byte, size)
	if r, _, _ := proc_pGetTokenInformation.Call(uintptr(token), 1,
		uintptr(unsafe.Pointer(&buf[0])), uintptr(size), uintptr(unsafe.Pointer(&size))); r == 0 {
		return ""
	}
	sidPtr := *(*unsafe.Pointer)(unsafe.Pointer(&buf[0]))
	if sidPtr == nil {
		return ""
	}
	var nameBuf, domainBuf [256]uint16
	nameSize, domainSize, sidType := uint32(256), uint32(256), uint32(0)
	r, _, _ := proc_pLookupAccountSidW.Call(0, uintptr(sidPtr),
		uintptr(unsafe.Pointer(&nameBuf[0])), uintptr(unsafe.Pointer(&nameSize)),
		uintptr(unsafe.Pointer(&domainBuf[0])), uintptr(unsafe.Pointer(&domainSize)),
		uintptr(unsafe.Pointer(&sidType)))
	if r == 0 {
		return ""
	}
	return proc_utf16At(nameBuf[:nameSize])
}

func proc_imagePathByHandle(h syscall.Handle) string {
	buf := make([]uint16, 1024)
	size := uint32(len(buf))
	if r, _, _ := proc_pQueryFullProcessImageNameW.Call(uintptr(h), 0,
		uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&size))); r == 0 {
		return ""
	}
	return syscall.UTF16ToString(buf[:size])
}

func proc_processUsername(pid uint32) string {
	h, err := proc_openProcess(proc_PROCESS_QUERY_LIMITED, pid)
	if err != nil {
		return ""
	}
	defer pCloseHandle.Call(uintptr(h))
	return proc_usernameByHandle(h)
}

// ---------- CPU sampling ----------

type proc_cpuPrev struct {
	k, u uint64
	ts   time.Time
}
type proc_cpuSampler struct {
	mu     sync.Mutex
	prev   map[uint32]proc_cpuPrev
	warmed bool
}

var proc_sampler = &proc_cpuSampler{prev: map[uint32]proc_cpuPrev{}}

func (s *proc_cpuSampler) Percent(procs []proc_ProcInfo) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	cur := make(map[uint32]proc_cpuPrev, len(procs))
	for i := range procs {
		k, u, err := proc_procCPUTimes(procs[i].PID)
		if err != nil {
			continue
		}
		cur[procs[i].PID] = proc_cpuPrev{k, u, now}
		if s.warmed {
			if prev, ok := s.prev[procs[i].PID]; ok {
				dk := k - prev.k
				du := u - prev.u
				elapsed := now.Sub(prev.ts).Seconds()
				if elapsed > 0 {
					pct := (float64(dk) + float64(du)) / 1e7 / elapsed * 100
					if pct < 0 {
						pct = 0
					}
					procs[i].CPU = pct
				}
			}
		}
	}
	s.prev = cur
	s.warmed = true
}

func proc_isSamplerWarmed() bool {
	proc_sampler.mu.Lock()
	defer proc_sampler.mu.Unlock()
	return proc_sampler.warmed
}

func proc_percentWithWarmup(procs []proc_ProcInfo) {
	wasWarmed := proc_isSamplerWarmed()
	proc_sampler.Percent(procs)
	if !wasWarmed && len(procs) > 0 {
		time.Sleep(100 * time.Millisecond)
		proc_sampler.Percent(procs)
	}
}

func proc_procCPUTimes(pid uint32) (uint64, uint64, error) {
	h, err := proc_openProcess(proc_PROCESS_QUERY_LIMITED, pid)
	if err != nil {
		return 0, 0, err
	}
	defer pCloseHandle.Call(uintptr(h))
	var ct, e, k, u proc_FILETIME
	if r, _, _ := proc_pGetProcessTimes.Call(uintptr(h),
		uintptr(unsafe.Pointer(&ct)), uintptr(unsafe.Pointer(&e)),
		uintptr(unsafe.Pointer(&k)), uintptr(unsafe.Pointer(&u))); r == 0 {
		return 0, 0, fmt.Errorf("GetProcessTimes")
	}
	return proc_ftU64(k), proc_ftU64(u), nil
}
// ---------- Process control ----------

func proc_suspendProcess(pid uint32) error {
	h, err := proc_openProcess(proc_PROCESS_SUSPEND_RESUME, pid)
	if err != nil {
		return err
	}
	defer pCloseHandle.Call(uintptr(h))
	if r, _, _ := proc_pNtSuspendProcess.Call(uintptr(h)); uint32(r) != 0 {
		return fmt.Errorf("NtSuspendProcess 0x%X", uint32(r))
	}
	return nil
}

func proc_resumeProcess(pid uint32) error {
	h, err := proc_openProcess(proc_PROCESS_SUSPEND_RESUME, pid)
	if err != nil {
		return err
	}
	defer pCloseHandle.Call(uintptr(h))
	if r, _, _ := proc_pNtResumeProcess.Call(uintptr(h)); uint32(r) != 0 {
		return fmt.Errorf("NtResumeProcess 0x%X", uint32(r))
	}
	return nil
}

func proc_priorityName(cl uint32) string {
	switch cl {
	case 0x40:
		return "idle"
	case 0x4000:
		return "below-normal"
	case 0x20:
		return "normal"
	case 0x8000:
		return "above-normal"
	case 0x80:
		return "high"
	case 0x100:
		return "realtime"
	}
	return "unknown"
}

func proc_priorityClass(level string) uint32 {
	switch level {
	case "idle":
		return 0x40
	case "below-normal":
		return 0x4000
	case "normal":
		return 0x20
	case "above-normal":
		return 0x8000
	case "high":
		return 0x80
	case "realtime":
		return 0x100
	}
	return 0
}

func proc_setPriority(pid uint32, level string) error {
	class := proc_priorityClass(level)
	if class == 0 {
		return fmt.Errorf("invalid priority %q", level)
	}
	h, err := proc_openProcess(proc_PROCESS_SET_INFORMATION, pid)
	if err != nil {
		return err
	}
	defer pCloseHandle.Call(uintptr(h))
	if r, _, err := proc_pSetPriorityClass.Call(uintptr(h), uintptr(class)); r == 0 {
		return err
	}
	return nil
}

func proc_killProcess(pid uint32, tree bool) error {
	if tree {
		return proc_killTree(pid)
	}
	h, err := proc_openProcess(proc_PROCESS_TERMINATE, pid)
	if err != nil {
		return err
	}
	defer pCloseHandle.Call(uintptr(h))
	if r, _, err := proc_pTerminateProcess.Call(uintptr(h), 1); r == 0 {
		return err
	}
	return nil
}

func proc_killTree(root uint32) error {
	procs, err := proc_listProcesses()
	if err != nil {
		return err
	}
	children := make(map[uint32][]uint32)
	for _, p := range procs {
		children[p.PPID] = append(children[p.PPID], p.PID)
	}
	var order []uint32
	stack := []uint32{root}
	for len(stack) > 0 {
		pid := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		order = append(order, pid)
		stack = append(stack, children[pid]...)
	}
	for i := len(order) - 1; i >= 0; i-- {
		_ = proc_killProcess(order[i], false)
	}
	return nil
}

func proc_isProtected(pid uint32) bool { return pid == 0 || pid == 4 }

// ---------- Job Object ----------

type proc_jobHandle struct{ h syscall.Handle }

func proc_newJob() (*proc_jobHandle, error) {
	r, _, err := proc_pCreateJobObjectW.Call(0, 0)
	if r == 0 {
		return nil, fmt.Errorf("CreateJobObject: %w", err)
	}
	return &proc_jobHandle{h: syscall.Handle(r)}, nil
}

func (j *proc_jobHandle) close() { pCloseHandle.Call(uintptr(j.h)) }

func (j *proc_jobHandle) assign(h syscall.Handle) error {
	if r, _, err := proc_pAssignProcessToJobObject.Call(uintptr(j.h), uintptr(h)); r == 0 {
		return fmt.Errorf("AssignProcessToJobObject: %w", err)
	}
	return nil
}

func (j *proc_jobHandle) setInfo(class uint32, info unsafe.Pointer, size uint32) error {
	if r, _, err := proc_pSetInformationJobObject.Call(uintptr(j.h), uintptr(class), uintptr(info), uintptr(size)); r == 0 {
		return err
	}
	return nil
}

func (j *proc_jobHandle) setLimits(lim *proc_ResourceLimits, isRun bool) error {
	buf := proc_buildExtendedLimitBuffer(lim, isRun)
	if err := j.setInfo(proc_JobObjectExtendedLimitInformation, unsafe.Pointer(&buf[0]), uint32(len(buf))); err != nil {
		return fmt.Errorf("extended limits: %w", err)
	}
	if lim.CPUCores != nil {
		n := proc_getLogicalCPU()
		rate := uint32(*lim.CPUCores * 100.0 / float64(n))
		if rate < 1 {
			rate = 1
		}
		if rate > 10000 {
			rate = 10000
		}
		ci := proc_JOBOBJECT_CPU_RATE_CONTROL_INFORMATION{
			ControlFlags: proc_JOB_CPU_RATE_CONTROL_ENABLE | proc_JOB_CPU_RATE_CONTROL_HARD_CAP,
			CpuRate:      rate,
		}
		if err := j.setInfo(proc_JobObjectCpuRateControlInformation, unsafe.Pointer(&ci), uint32(unsafe.Sizeof(ci))); err != nil {
			return fmt.Errorf("cpu rate: %w", err)
		}
	}
	if lim.IOPS != nil || lim.IOWrite != nil {
		io := proc_JOBOBJECT_IO_RATE_CONTROL_INFORMATION{}
		if lim.IOPS != nil {
			io.MaxIops = *lim.IOPS
		}
		if lim.IOWrite != nil {
			io.MaxBandwidth = int64(*lim.IOWrite)
		}
		if err := j.setInfo(proc_JobObjectIoRateControlInformation, unsafe.Pointer(&io), uint32(unsafe.Sizeof(io))); err != nil {
			return fmt.Errorf("io rate: %w", err)
		}
		if lim.IORead != nil {
			bugs.Add("WARN", "ioread: Job Object only limits total bandwidth")
		}
	}
	if lim.NetOut != nil {
		ni := proc_JOBOBJECT_NET_RATE_CONTROL_INFORMATION{MaxBandwidth: *lim.NetOut, ControlFlags: proc_JOB_NET_RATE_CONTROL_ENABLE}
		if err := j.setInfo(proc_JobObjectNetRateControlInformation, unsafe.Pointer(&ni), uint32(unsafe.Sizeof(ni))); err != nil {
			return fmt.Errorf("net rate: %w", err)
		}
	}
	if lim.NetIn != nil {
		bugs.Add("WARN", "netin: Job Object does not support inbound rate limits")
	}
	return nil
}

func proc_attachAndLimit(pid uint32, lim *proc_ResourceLimits) error {
	jb, err := proc_newJob()
	if err != nil {
		return err
	}
	const access = uint32(proc_PROCESS_SET_QUOTA | proc_PROCESS_TERMINATE | proc_PROCESS_QUERY_LIMITED)
	h, err := proc_openProcess(access, pid)
	if err != nil {
		jb.close()
		if errors.Is(err, proc_ERR_ACCESS_DENIED) {
			return fmt.Errorf("access denied (pid %d), administrator privileges required", pid)
		}
		if errors.Is(err, proc_ERR_INVALID_PARAMETER) {
			return fmt.Errorf("process not found (pid %d)", pid)
		}
		return fmt.Errorf("OpenProcess(%d): %w", pid, err)
	}
	defer pCloseHandle.Call(uintptr(h))
	if err := jb.assign(h); err != nil {
		jb.close()
		return fmt.Errorf("assign pid %d: %w", pid, err)
	}
	if err := jb.setLimits(lim, false); err != nil {
		jb.close()
		return err
	}
	if lim.Timeout != nil {
		go func() {
			time.Sleep(*lim.Timeout)
			proc_pTerminateJobObject.Call(uintptr(jb.h), 1)
		}()
	}
	onExit := lim.OnExit
	if onExit != "kill" && onExit != "suspend" {
		onExit = "keep"
	}
	proc_registerCleanup(jb, onExit)
	return nil
}

func proc_runWithLimits(cmdLine string, lim *proc_ResourceLimits, opts *proc_runOptions) (int, error) {
	jb, err := proc_newJob()
	if err != nil {
		return 5, err
	}
	defer jb.close()
	var si proc_STARTUPINFOW
	si.Cb = uint32(unsafe.Sizeof(si))
	var titlePtr, cwdPtr *uint16
	if opts != nil && opts.title != "" {
		titlePtr, _ = syscall.UTF16PtrFromString(opts.title)
		si.Title = titlePtr
	}
	if opts != nil && opts.workDir != "" {
		cwdPtr, _ = syscall.UTF16PtrFromString(opts.workDir)
	}
	var pi proc_PROCESS_INFORMATION
	cmdUTF16, err := syscall.UTF16FromString(cmdLine)
	if err != nil {
		return 5, fmt.Errorf("invalid command line: %w", err)
	}
	if len(cmdUTF16) == 0 {
		return 5, fmt.Errorf("empty command line")
	}
	flags := uint32(proc_CREATE_SUSPENDED | proc_CREATE_NEW_CONSOLE)
	if opts != nil && opts.noWindow {
		flags = proc_CREATE_SUSPENDED | proc_CREATE_NO_WINDOW
	}
	if r, _, callErr := proc_pCreateProcessW.Call(0, uintptr(unsafe.Pointer(&cmdUTF16[0])), 0, 0, 0,
		uintptr(flags), 0, uintptr(unsafe.Pointer(cwdPtr)),
		uintptr(unsafe.Pointer(&si)), uintptr(unsafe.Pointer(&pi))); r == 0 {
		return 5, fmt.Errorf("CreateProcess: %w", callErr)
	}
	defer pCloseHandle.Call(uintptr(pi.Thread))
	defer pCloseHandle.Call(uintptr(pi.Process))
	if opts != nil && opts.priority != 0 {
		proc_pSetPriorityClass.Call(uintptr(pi.Process), uintptr(opts.priority))
	}
	if err := jb.assign(pi.Process); err != nil {
		proc_pTerminateProcess.Call(uintptr(pi.Process), 1)
		return 5, err
	}
	if err := jb.setLimits(lim, true); err != nil {
		proc_pTerminateProcess.Call(uintptr(pi.Process), 1)
		return 5, err
	}
	proc_pResumeThread.Call(uintptr(pi.Thread))
	if lim.Timeout != nil {
		go func() {
			time.Sleep(*lim.Timeout)
			proc_pTerminateJobObject.Call(uintptr(jb.h), 1)
		}()
	}
	if lim.OnExit == "kill" {
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, os.Interrupt)
		go func() {
			<-sigCh
			jb.close()
		}()
	}
	proc_pWaitForSingleObject.Call(uintptr(pi.Process), proc_INFINITE)
	var code uint32
	proc_pGetExitCodeProcess.Call(uintptr(pi.Process), uintptr(unsafe.Pointer(&code)))
	return int(code), nil
}

func proc_buildRunCmdLine(parts []string) string {
	out := make([]string, len(parts))
	for i, p := range parts {
		out[i] = syscall.EscapeArg(p)
	}
	return strings.Join(out, " ")
}

// ---------- System totals ----------

func proc_getLogicalCPU() int {
	r, _, _ := proc_pGetActiveProcessorCount.Call(proc_ALL_PROCESSOR_GROUPS)
	if r == 0 {
		return 1
	}
	return int(r)
}

func proc_getPhysicalCPU() int {
	var length uint32
	proc_pGetLogicalProcessorInformationEx.Call(uintptr(proc_RelationProcessorCore), 0, uintptr(unsafe.Pointer(&length)))
	if length == 0 {
		return 0
	}
	buf := make([]byte, length)
	if r, _, _ := proc_pGetLogicalProcessorInformationEx.Call(uintptr(proc_RelationProcessorCore),
		uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&length))); r == 0 {
		return 0
	}
	count := 0
	offset := uint32(0)
	for offset+8 <= length {
		rel := *(*uint32)(unsafe.Pointer(&buf[offset]))
		sz := *(*uint32)(unsafe.Pointer(&buf[offset+4]))
		if sz == 0 {
			break
		}
		if rel == proc_RelationProcessorCore {
			count++
		}
		offset += sz
	}
	return count
}

func proc_getTotalPhys() uint64 {
	var ms proc_MEMORYSTATUSEX
	ms.Length = uint32(unsafe.Sizeof(ms))
	if r, _, _ := proc_pGlobalMemoryStatusEx.Call(uintptr(unsafe.Pointer(&ms))); r == 0 {
		return 0
	}
	return ms.TotalPhys
}

func proc_validateLimits(lim *proc_ResourceLimits) error {
	if lim == nil {
		return nil
	}
	nCPU := proc_getLogicalCPU()
	totalPhys := proc_getTotalPhys()
	if totalPhys == 0 {
		return fmt.Errorf("cannot read system physical memory, refusing to set limits")
	}
	var problems []string
	if lim.CPUCores != nil {
		v := *lim.CPUCores
		switch {
		case v <= 0:
			problems = append(problems, fmt.Sprintf("cpu=%.2f must be greater than 0", v))
		case v > float64(nCPU):
			problems = append(problems, fmt.Sprintf("cpu=%.2f exceeds system logical CPU count %d", v, nCPU))
		}
	}
	if lim.Affinity != nil {
		m := *lim.Affinity
		if m == 0 {
			problems = append(problems, "affinity=0 is invalid")
		} else if nCPU < 64 {
			valid := (uint64(1) << uint(nCPU)) - 1
			if m&^valid != 0 {
				problems = append(problems, fmt.Sprintf("affinity=0x%X contains nonexistent CPU bits (system has %d cores)", m, nCPU))
			}
		}
	}
	if lim.Mem != nil && *lim.Mem > totalPhys {
		problems = append(problems, fmt.Sprintf("mem=%s exceeds system physical memory %s", humanBytes(*lim.Mem), humanBytes(totalPhys)))
	}
	if lim.WorkingSet != nil && *lim.WorkingSet > totalPhys {
		problems = append(problems, fmt.Sprintf("workingset=%s exceeds system physical memory %s", humanBytes(*lim.WorkingSet), humanBytes(totalPhys)))
	}
	if lim.ProcessCount != nil && *lim.ProcessCount == 0 {
		problems = append(problems, "processcount=0 is meaningless: Windows treats 0 as unlimited")
	}
	if lim.Timeout != nil && *lim.Timeout <= 0 {
		problems = append(problems, fmt.Sprintf("timeout=%s must be greater than 0", lim.Timeout.String()))
	}
	if len(problems) == 0 {
		return nil
	}
	return fmt.Errorf("resource limit validation failed:\n  - %s\nuse winctl proc total to view system totals", strings.Join(problems, "\n  - "))
}

func proc_systemTimes() (uint64, uint64, uint64) {
	var i, k, u proc_FILETIME
	if r, _, _ := proc_pGetSystemTimes.Call(uintptr(unsafe.Pointer(&i)),
		uintptr(unsafe.Pointer(&k)), uintptr(unsafe.Pointer(&u))); r == 0 {
		return 0, 0, 0
	}
	return proc_ftU64(i), proc_ftU64(k), proc_ftU64(u)
}

func proc_getTickCount64() uint64 {
	r, _, _ := proc_pGetTickCount64.Call()
	return uint64(r)
}

func proc_diskUsages() []proc_DiskInfo {
	var out []proc_DiskInfo
	for d := 'A'; d <= 'Z'; d++ {
		root := string(d) + ":\\"
		rootPtr, err := syscall.UTF16PtrFromString(root)
		if err != nil {
			continue
		}
		var free, total, _ uint64
		if r, _, _ := proc_pGetDiskFreeSpaceExW.Call(uintptr(unsafe.Pointer(rootPtr)),
			uintptr(unsafe.Pointer(&free)), uintptr(unsafe.Pointer(&total)), 0); r != 0 && total > 0 {
			out = append(out, proc_DiskInfo{
				Letter:  string(d) + ":",
				Percent: (1 - float64(free)/float64(total)) * 100,
				Free:    free,
				Total:   total,
			})
		}
	}
	return out
}

func proc_formatUptime(sec uint64) string {
	return fmt.Sprintf("%dd %dh %dm", sec/86400, (sec%86400)/3600, (sec%3600)/60)
}

func proc_collectSysInfo() proc_SysInfo {
	si := proc_SysInfo{LogicalCPU: proc_getLogicalCPU(), PhysicalCPU: proc_getPhysicalCPU()}
	idle1, kern1, user1 := proc_systemTimes()
	time.Sleep(150 * time.Millisecond)
	idle2, kern2, user2 := proc_systemTimes()
	di := float64(idle2 - idle1)
	dk := float64(kern2 - kern1)
	du := float64(user2 - user1)
	total := dk + du
	if total > 0 {
		si.CPUPercent = (total - di) / total * 100
	}
	var ms proc_MEMORYSTATUSEX
	ms.Length = uint32(unsafe.Sizeof(ms))
	if r, _, _ := proc_pGlobalMemoryStatusEx.Call(uintptr(unsafe.Pointer(&ms))); r != 0 {
		si.MemTotal = ms.TotalPhys
		si.MemUsed = ms.TotalPhys - ms.AvailPhys
		si.MemFree = ms.AvailPhys
	}
	si.Disks = proc_diskUsages()
	si.Uptime = proc_formatUptime(proc_getTickCount64() / 1000)
	return si
}

func proc_printJSON(v any) {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		bugs.Add("ERR", "json encode: %v", err)
	}
}

// ---------- Field/filter helpers ----------

func proc_defaultFields() map[string]bool {
	return map[string]bool{"pid": true, "name": true, "cpu": true, "mem": true, "exe": true}
}

func proc_allFields() map[string]bool {
	fs := map[string]bool{}
	for _, f := range []string{"pid", "name", "exe", "cpu", "mem", "threads", "handles",
		"gdiobj", "userobj", "io_read_b", "io_write_b", "io_read_c", "io_write_c",
		"priority", "username", "page_faults", "create-time"} {
		fs[f] = true
	}
	return fs
}

func proc_parseFields(s string) map[string]bool {
	fs := map[string]bool{}
	for _, f := range strings.Split(s, ",") {
		fs[strings.ToLower(strings.TrimSpace(f))] = true
	}
	return fs
}

func proc_filterSystem(procs []proc_ProcInfo) []proc_ProcInfo {
	var out []proc_ProcInfo
	for _, p := range procs {
		if p.PID == 0 || p.PID == 4 || p.Name == "System" || p.Name == "smss.exe" {
			continue
		}
		user := proc_processUsername(p.PID)
		if user == "SYSTEM" || user == "LOCAL SERVICE" || user == "NETWORK SERVICE" {
			continue
		}
		out = append(out, p)
	}
	return out
}

func proc_applyFilter(procs []proc_ProcInfo, pattern string) []proc_ProcInfo {
	if pattern == "" {
		return procs
	}
	lp := strings.ToLower(pattern)
	var out []proc_ProcInfo
	for _, p := range procs {
		if strings.Contains(strings.ToLower(p.Name), lp) {
			out = append(out, p)
		}
	}
	return out
}

func proc_applyLimit(procs []proc_ProcInfo, n int) []proc_ProcInfo {
	if n <= 0 || len(procs) <= n {
		return procs
	}
	return procs[:n]
}

func proc_applyLimitKey(key, val string, lim *proc_ResourceLimits) error {
	switch key {
	case "affinity":
		v, err := strconv.ParseUint(val, 0, 64)
		if err != nil {
			return err
		}
		lim.Affinity = &v
	case "cpu":
		v, err := strconv.ParseFloat(val, 64)
		if err != nil {
			return err
		}
		lim.CPUCores = &v
	case "iops":
		v, err := strconv.ParseInt(val, 10, 64)
		if err != nil {
			return err
		}
		lim.IOPS = &v
	case "ioread":
		v, err := proc_parseRate(val)
		if err != nil {
			return err
		}
		lim.IORead = &v
	case "iowrite":
		v, err := proc_parseRate(val)
		if err != nil {
			return err
		}
		lim.IOWrite = &v
	case "mem":
		v, err := proc_parseSize(val)
		if err != nil {
			return err
		}
		lim.Mem = &v
	case "netin":
		v, err := proc_parseRate(val)
		if err != nil {
			return err
		}
		lim.NetIn = &v
	case "netout":
		v, err := proc_parseRate(val)
		if err != nil {
			return err
		}
		lim.NetOut = &v
	case "onexit":
		lim.OnExit = strings.ToLower(val)
	case "processcount":
		v, err := strconv.ParseUint(val, 10, 32)
		if err != nil {
			return err
		}
		vv := uint32(v)
		lim.ProcessCount = &vv
	case "timeout":
		d, err := time.ParseDuration(val)
		if err != nil {
			return err
		}
		lim.Timeout = &d
	case "workingset":
		v, err := proc_parseSize(val)
		if err != nil {
			return err
		}
		lim.WorkingSet = &v
	default:
		return fmt.Errorf("unknown key %q", key)
	}
	return nil
}

func proc_consumeLimitOption(args []string, i int, lim *proc_ResourceLimits) (int, bool) {
	if i+1 >= len(args) {
		return 0, false
	}
	flag, val := args[i], args[i+1]
	key := ""
	switch flag {
	case "--affinity":
		key = "affinity"
	case "--cpu":
		key = "cpu"
	case "--iops":
		key = "iops"
	case "--io-read":
		key = "ioread"
	case "--io-write":
		key = "iowrite"
	case "--mem":
		key = "mem"
	case "--net-in":
		key = "netin"
	case "--net-out":
		key = "netout"
	case "--net":
		_ = proc_applyLimitKey("netin", val, lim)
		_ = proc_applyLimitKey("netout", val, lim)
		return 2, true
	case "--on-proc_exit":
		key = "onexit"
	case "--process-count":
		key = "processcount"
	case "--timeout":
		key = "timeout"
	case "--working-set":
		key = "workingset"
	default:
		return 0, false
	}
	_ = proc_applyLimitKey(key, val, lim)
	return 2, true
}

func proc_isEmptyLimits(lim *proc_ResourceLimits) bool {
	if lim == nil {
		return true
	}
	return lim.Affinity == nil && lim.CPUCores == nil && lim.IOPS == nil &&
		lim.IORead == nil && lim.IOWrite == nil && lim.Mem == nil &&
		lim.NetIn == nil && lim.NetOut == nil &&
		(lim.OnExit == "" || lim.OnExit == "keep") &&
		lim.ProcessCount == nil && lim.Timeout == nil && lim.WorkingSet == nil
}

func proc_getOpt(args []string, flags ...string) string {
	for i, a := range args {
		for _, f := range flags {
			if a == f && i+1 < len(args) {
				return args[i+1]
			}
			if strings.HasPrefix(a, f+"=") {
				return strings.TrimPrefix(a, f+"=")
			}
		}
	}
	return ""
}

func proc_getParallel(args []string) int {
	if s := proc_getOpt(args, "--parallel"); s != "" {
		if v, err := strconv.Atoi(s); err == nil && v >= 1 {
			return v
		}
	}
	return 8
}

func proc_orderFor(args []string, sortKey string) bool {
	o := proc_getOpt(args, "--order")
	if o == "asc" {
		return false
	}
	if o == "desc" {
		return true
	}
	if sortKey == "name" {
		return false
	}
	return true
}

// ---------- Query commands ----------

func proc_cmdList(args []string) {
	fields := proc_defaultFields()
	if fs := proc_getOpt(args, "--fields"); fs != "" {
		fields = proc_parseFields(fs)
	}
	if has(args, "--detail") {
		fields = proc_allFields()
	}
	parallel := proc_getParallel(args)
	filterPat := proc_getOpt(args, "--filter")
	limitN := 0
	if s := proc_getOpt(args, "--limit"); s != "" {
		if v, err := strconv.Atoi(s); err == nil {
			limitN = v
		}
	}
	runOnce := func() []proc_ProcInfo {
		snaps, err := proc_listProcesses()
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return nil
		}
		procs := proc_collectDetails(snaps, fields, parallel)
		proc_percentWithWarmup(procs)
		if has(args, "-e", "--exclude-system") {
			procs = proc_filterSystem(procs)
		}
		if filterPat != "" {
			procs = proc_applyFilter(procs, filterPat)
		}
		sk := proc_getOpt(args, "--sort")
		if sk == "" {
			sk = "cpu"
		}
		proc_sortProcs(procs, sk, proc_orderFor(args, sk))
		if limitN > 0 {
			procs = proc_applyLimit(procs, limitN)
		}
		return procs
	}
	procs := runOnce()
	if procs == nil {
		proc_exit(5)
	}
	if has(args, "--watch") {
		proc_watchLoop(args, func() {
			p := runOnce()
			if has(args, "--tree") {
				if has(args, "--json") {
					proc_printJSON(p)
				} else {
					proc_printTree(p)
				}
				return
			}
			proc_printProcs(p, has(args, "--json"))
		})
		return
	}
	if has(args, "--tree") {
		if has(args, "--json") {
			proc_printJSON(procs)
		} else {
			proc_printTree(procs)
		}
		return
	}
	proc_printProcs(procs, has(args, "--json"))
}

func proc_printProcs(procs []proc_ProcInfo, asJSON bool) {
	if asJSON {
		proc_printJSON(procs)
		return
	}
	header := fmt.Sprintf("%-7s %-20s %6s %-9s %s", "PID", "NAME", "CPU%", "MEM", "EXE")
	fmt.Println(c(clrBold+clrCyan, header))
	for _, p := range procs {
		exe := proc_trunc(p.Exe, 64)
		line := c(clrCyan, fmt.Sprintf("%-7d", p.PID)) + " " +
			fmt.Sprintf("%-20s", proc_trunc(p.Name, 20)) + " " +
			c(proc_cpuColor(p.CPU), fmt.Sprintf("%6.1f", p.CPU)) + " " +
			c(clrYellow, fmt.Sprintf("%-9s", humanBytes(p.Mem))) + " " +
			c(clrGray, exe)
		fmt.Println(line)
	}
}

func proc_cmdTotal(args []string) {
	if has(args, "--watch") {
		proc_watchLoop(args, func() {
			s := proc_collectSysInfo()
			proc_printSys(s, has(args, "--json"))
		})
		return
	}
	sys := proc_collectSysInfo()
	proc_printSys(sys, has(args, "--json"))
}

func proc_printSys(s proc_SysInfo, asJSON bool) {
	if asJSON {
		proc_printJSON(s)
		return
	}
	fmt.Println(c(clrBold+clrCyan, "System Resources"))
	fmt.Printf("  %s  %s  %s\n",
		c(clrCyan, "CPU   "),
		c(proc_cpuColor(s.CPUPercent), fmt.Sprintf("%5.1f%%", s.CPUPercent)),
		c(clrGray, fmt.Sprintf("Logical %d / Physical %d", s.LogicalCPU, s.PhysicalCPU)))
	fmt.Printf("  %s  %s / %s  %s\n",
		c(clrCyan, "MEM   "),
		c(clrYellow, humanBytes(s.MemUsed)), humanBytes(s.MemTotal),
		c(clrGray, fmt.Sprintf("Free %s", humanBytes(s.MemFree))))
	fmt.Printf("  %s  %s\n", c(clrCyan, "Uptime"), s.Uptime)
	for _, d := range s.Disks {
		fmt.Printf("  %s  %5.1f%%  %s\n",
			c(clrCyan, d.Letter), d.Percent,
			c(clrGray, fmt.Sprintf("%s / %s", humanBytes(d.Free), humanBytes(d.Total))))
	}
}

func proc_cmdSum(args []string) {
	n := 10
	for _, a := range args {
		if a == "--" {
			break
		}
		if strings.HasPrefix(a, "-") {
			continue
		}
		if v, err := strconv.Atoi(a); err == nil {
			n = v
			break
		}
	}
	parallel := proc_getParallel(args)
	filterPat := proc_getOpt(args, "--filter")
	runOnce := func() []proc_ProcInfo {
		snaps, err := proc_listProcesses()
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return nil
		}
		procs := proc_collectDetails(snaps, proc_allFields(), parallel)
		proc_percentWithWarmup(procs)
		if filterPat != "" {
			procs = proc_applyFilter(procs, filterPat)
		}
		sk := proc_getOpt(args, "--sort")
		if sk == "" {
			sk = "cpu"
		}
		proc_sortProcs(procs, sk, proc_orderFor(args, sk))
		if n > 0 {
			procs = proc_applyLimit(procs, n)
		}
		return procs
	}
	if has(args, "--watch") {
		proc_watchLoop(args, func() {
			p := runOnce()
			proc_printProcs(p, has(args, "--json"))
		})
		return
	}
	procs := runOnce()
	if procs == nil {
		proc_exit(5)
	}
	proc_printProcs(procs, has(args, "--json"))
}

func proc_cmdMonitor(args []string) {
	interval := time.Second
	if s := proc_getOpt(args, "--interval"); s != "" {
		if v, err := strconv.Atoi(s); err == nil {
			interval = time.Duration(v) * time.Millisecond
		}
	}
	if interval < 500*time.Millisecond {
		interval = 500 * time.Millisecond
	}
	fps := 30
	if s := proc_getOpt(args, "--fps"); s != "" {
		if v, err := strconv.Atoi(s); err == nil {
			fps = v
		}
	}
	proc_runTUI(interval, fps, has(args, "--no-mouse"), proc_getParallel(args),
		proc_defaultConfigPath(args), has(args, "--reset-config"))
}

// ---------- Control commands ----------

func proc_cmdKill(args []string, super bool) {
	var target string
	for _, a := range args {
		if a == "--" {
			break
		}
		if strings.HasPrefix(a, "-") {
			continue
		}
		target = a
		break
	}
	if target == "" {
		fmt.Fprintln(os.Stderr, "missing target")
		proc_exit(2)
	}
	pids, err := proc_resolveTarget(target)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		proc_exit(4)
	}
	tree := has(args, "--tree")
	noWarn := has(args, "--no-warn")
	ok := 0
	for _, pid := range pids {
		if proc_isProtected(pid) {
			fmt.Fprintf(os.Stderr, "pid %d is protected by Windows\n", pid)
			continue
		}
		if super && !noWarn {
			fmt.Fprintf(os.Stderr, "about to force-kill pid %d, press Ctrl+C to cancel...\n", pid)
			time.Sleep(time.Second)
		}
		if err := proc_killProcess(pid, tree); err != nil {
			fmt.Fprintf(os.Stderr, "kill %d: %v\n", pid, err)
			bugs.Add("WARN", "kill %d: %v", pid, err)
		} else {
			fmt.Printf("%s pid %d\n", c(clrGreen, "killed"), pid)
			ok++
		}
	}
	if ok == 0 {
		proc_exit(2)
	}
	if ok < len(pids) {
		proc_exit(1)
	}
	proc_exit(0)
}

func proc_cmdSuspendResume(args []string, doResume bool) {
	var target string
	for _, a := range args {
		if a == "--" {
			break
		}
		if strings.HasPrefix(a, "-") {
			continue
		}
		target = a
		break
	}
	if target == "" {
		fmt.Fprintln(os.Stderr, "missing target")
		proc_exit(2)
	}
	pids, err := proc_resolveTarget(target)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		proc_exit(4)
	}
	verb := "suspended"
	if doResume {
		verb = "resumed"
	}
	ok := 0
	for _, pid := range pids {
		var e error
		if doResume {
			e = proc_resumeProcess(pid)
		} else {
			e = proc_suspendProcess(pid)
		}
		if e != nil {
			fmt.Fprintf(os.Stderr, "%d: %v\n", pid, e)
			bugs.Add("WARN", "suspend/resume pid=%d: %v", pid, e)
		} else {
			fmt.Printf("%s pid %d\n", c(clrGreen, verb), pid)
			ok++
		}
	}
	if ok == 0 {
		proc_exit(2)
	}
	proc_exit(0)
}

func proc_cmdPriority(args []string) {
	var pos []string
	for _, a := range args {
		if a == "--" {
			break
		}
		if strings.HasPrefix(a, "-") {
			continue
		}
		pos = append(pos, a)
	}
	if len(pos) < 2 {
		fmt.Fprintln(os.Stderr, "usage: winctl proc priority <pid|name> <level>")
		fmt.Fprintln(os.Stderr, "  level: idle|below-normal|normal|above-normal|high|realtime")
		proc_exit(2)
	}
	target, level := pos[0], pos[1]
	pids, err := proc_resolveTarget(target)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		proc_exit(4)
	}
	ok := 0
	for _, pid := range pids {
		if err := proc_setPriority(pid, level); err != nil {
			fmt.Fprintf(os.Stderr, "priority %d: %v\n", pid, err)
			bugs.Add("WARN", "priority pid=%d: %v", pid, err)
		} else {
			fmt.Printf("%s pid %d = %s\n", c(clrGreen, "priority"), pid, level)
			ok++
		}
	}
	if ok == 0 {
		proc_exit(2)
	}
	proc_exit(0)
}

func proc_cmdLimit(args []string) {
	if has(args, "-p", "--pid", "-n", "--name") {
		proc_cmdLimitMixed(args)
		return
	}
	target := ""
	for _, a := range args {
		if a == "--" {
			break
		}
		if strings.HasPrefix(a, "-") {
			continue
		}
		target = a
		break
	}
	if target == "" {
		fmt.Fprintln(os.Stderr, "usage: winctl proc limit <pid|name> [LIMIT OPTIONS]")
		proc_exit(2)
	}
	rest := make([]string, 0, len(args))
	dropped := false
	for _, a := range args {
		if !dropped && a == target {
			dropped = true
			continue
		}
		rest = append(rest, a)
	}
	proc_cmdLimitMixed(append([]string{"-p", target}, rest...))
}

func proc_cmdLimitMixed(args []string) {
	targets := map[uint32]*proc_ResourceLimits{}
	var order []uint32
	var queries []uint32
	assign := func(pids []uint32, lim *proc_ResourceLimits) {
		for _, pid := range pids {
			if _, ok := targets[pid]; !ok {
				order = append(order, pid)
			}
			targets[pid] = lim
		}
	}
	queryFields := proc_allFields()
	if fs := proc_getOpt(args, "--fields"); fs != "" {
		queryFields = proc_parseFields(fs)
	}
	i := 0
	for i < len(args) {
		a := args[i]
		switch a {
		case "-p", "--pid", "-n", "--name":
			i++
			if i >= len(args) {
				fmt.Fprintln(os.Stderr, "missing target")
				proc_exit(2)
			}
			target := args[i]
			i++
			lim := &proc_ResourceLimits{}
			for i < len(args) {
				consumed, ok := proc_consumeLimitOption(args, i, lim)
				if !ok {
					break
				}
				i += consumed
			}
			pids, err := proc_resolveTarget(target)
			if err != nil {
				fmt.Fprintf(os.Stderr, "%s: %v\n", target, err)
				bugs.Add("WARN", "resolve %s: %v", target, err)
				continue
			}
			if proc_isEmptyLimits(lim) {
				queries = append(queries, pids...)
			} else {
				assign(pids, lim)
			}
		default:
			i++
		}
	}
	ok, total := 0, 0
	for _, pid := range order {
		lim := targets[pid]
		total++
		if err := proc_validateLimits(lim); err != nil {
			fmt.Fprintln(os.Stderr, err)
			bugs.Add("WARN", "validate pid=%d: %v", pid, err)
			continue
		}
		if err := proc_attachAndLimit(pid, lim); err != nil {
			fmt.Fprintf(os.Stderr, "limit %d: %v\n", pid, err)
			bugs.Add("WARN", "limit pid=%d: %v", pid, err)
		} else {
			fmt.Printf("%s pid %d\n", c(clrGreen, "limited"), pid)
			ok++
		}
	}
	asJSON := has(args, "--json")
	qOK := 0
	for _, pid := range queries {
		if err := proc_queryAndPrint(pid, asJSON, queryFields); err != nil {
			fmt.Fprintf(os.Stderr, "query %d: %v\n", pid, err)
			bugs.Add("WARN", "query pid=%d: %v", pid, err)
		} else {
			qOK++
		}
	}
	if len(order) > 0 {
		if ok == 0 {
			proc_exit(2)
		}
		if ok < total {
			proc_exit(1)
		}
		proc_exit(0)
	}
	if len(queries) > 0 {
		if qOK == 0 {
			proc_exit(4)
		}
		proc_exit(0)
	}
	proc_exit(2)
}

func proc_queryAndPrint(pid uint32, asJSON bool, fields map[string]bool) error {
	h, err := proc_openProcess(proc_PROCESS_QUERY_LIMITED, pid)
	if err != nil {
		if errors.Is(err, proc_ERR_INVALID_PARAMETER) {
			return fmt.Errorf("PID %d does not exist or has exited", pid)
		}
		if errors.Is(err, proc_ERR_ACCESS_DENIED) {
			return fmt.Errorf("PID %d permission denied", pid)
		}
		return fmt.Errorf("PID %d OpenProcess: %w", pid, err)
	}
	pCloseHandle.Call(uintptr(h))
	info := proc_ProcInfo{PID: pid}
	if err := proc_queryProcessDetail(&info, pid, fields); err != nil {
		return err
	}
	if snaps, e := proc_listProcesses(); e == nil {
		for _, s := range snaps {
			if s.PID == pid {
				info.Name, info.PPID, info.Threads = s.Name, s.PPID, s.Threads
				break
			}
		}
	}
	if k1, u1, e := proc_procCPUTimes(pid); e == nil {
		time.Sleep(100 * time.Millisecond)
		if k2, u2, e2 := proc_procCPUTimes(pid); e2 == nil {
			pct := (float64(k2-k1) + float64(u2-u1)) / 1e7 / 0.1 * 100
			if pct < 0 {
				pct = 0
			}
			info.CPU = pct
		}
	}
	if asJSON {
		proc_printJSON(info)
		return nil
	}
	proc_printSingleProc(info)
	return nil
}

func proc_printSingleProc(info proc_ProcInfo) {
	fmt.Printf("%s %d\n", c(clrCyan, "PID     "), info.PID)
	fmt.Printf("%s %d\n", c(clrCyan, "PPID    "), info.PPID)
	fmt.Printf("%s %s\n", c(clrCyan, "Name    "), info.Name)
	if info.Exe != "" {
		fmt.Printf("%s %s\n", c(clrCyan, "Exe     "), c(clrGray, info.Exe))
	}
	fmt.Printf("%s %s\n", c(clrCyan, "CPU     "), c(proc_cpuColor(info.CPU), fmt.Sprintf("%.1f%%", info.CPU)))
	fmt.Printf("%s %s\n", c(clrCyan, "Mem     "), c(clrYellow, humanBytes(info.Mem)))
	fmt.Printf("%s %d\n", c(clrCyan, "Threads "), info.Threads)
	if info.Handles > 0 {
		fmt.Printf("%s %d\n", c(clrCyan, "Handles "), info.Handles)
	}
	if info.GdiObj > 0 {
		fmt.Printf("%s %d\n", c(clrCyan, "GDI Obj "), info.GdiObj)
	}
	if info.UserObj > 0 {
		fmt.Printf("%s %d\n", c(clrCyan, "UserObj "), info.UserObj)
	}
	if info.IOReadB > 0 || info.IOWriteB > 0 {
		fmt.Printf("%s %s / %d ops\n", c(clrCyan, "IO Read "), humanBytes(info.IOReadB), info.IOReadC)
		fmt.Printf("%s %s / %d ops\n", c(clrCyan, "IO Write"), humanBytes(info.IOWriteB), info.IOWriteC)
	}
	if info.Priority != "" {
		fmt.Printf("%s %s\n", c(clrCyan, "Priority"), info.Priority)
	}
	if info.Username != "" {
		fmt.Printf("%s %s\n", c(clrCyan, "User    "), info.Username)
	}
	if info.PageFaults > 0 {
		fmt.Printf("%s %d\n", c(clrCyan, "PageFlts"), info.PageFaults)
	}
	if !info.CreateTime.IsZero() {
		fmt.Printf("%s %s\n", c(clrCyan, "Created "), info.CreateTime.Format("2006-01-02 15:04:05"))
	}
}

// ---------- run ----------

func proc_cmdRun(args []string) {
	admin := false
	elevated := false
	filtered := make([]string, 0, len(args))
	for _, a := range args {
		switch a {
		case "--admin":
			admin = true
		case "--elevated":
			elevated = true
		default:
			filtered = append(filtered, a)
		}
	}
	args = filtered
	if admin && !elevated && !proc_isAdmin() {
		fmt.Fprintln(os.Stderr, "requesting administrator privileges (UAC prompt)...")
		code, err := proc_relaunchElevated(args)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%v\n", err)
			bugs.Add("ERR", "elevate: %v", err)
			proc_exit(5)
		}
		proc_exit(code)
	}
	lim := &proc_ResourceLimits{}
	opts := &proc_runOptions{}
	var cmdParts []string
	i := 0
	for i < len(args) {
		if args[i] == "--" {
			cmdParts = args[i+1:]
			break
		}
		if consumed, ok := proc_consumeLimitOption(args, i, lim); ok {
			i += consumed
			continue
		}
		switch args[i] {
		case "--cwd":
			if i+1 >= len(args) {
				proc_exit(2)
			}
			opts.workDir = args[i+1]
			i += 2
			continue
		case "--title":
			if i+1 >= len(args) {
				proc_exit(2)
			}
			opts.title = args[i+1]
			i += 2
			continue
		case "--priority":
			if i+1 >= len(args) {
				proc_exit(2)
			}
			pc := proc_priorityClass(args[i+1])
			if pc == 0 {
				proc_exit(2)
			}
			opts.priority = pc
			i += 2
			continue
		case "--no-window":
			opts.noWindow = true
			i++
			continue
		}
		i++
	}
	if len(cmdParts) == 0 {
		fmt.Fprintln(os.Stderr, "no command after --")
		proc_exit(2)
	}
	if err := proc_validateLimits(lim); err != nil {
		fmt.Fprintln(os.Stderr, err)
		proc_exit(2)
	}
	if lim.OnExit == "suspend" {
		bugs.Add("WARN", "run: on-exit=suspend is unreliable on Ctrl+C, degraded to keep")
	}
	cmdLine := proc_buildRunCmdLine(cmdParts)
	code, err := proc_runWithLimits(cmdLine, lim, opts)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		bugs.Add("ERR", "run: %v", err)
		proc_exit(5)
	}
	proc_exit(code)
}

// ---------- --watch ----------

func proc_watchLoop(args []string, fn func()) {
	d := time.Second
	if s := proc_getOpt(args, "--watch"); s != "" {
		if v, err := time.ParseDuration(s); err == nil {
			d = v
		}
	}
	fmt.Print("\x1b[?25l")
	defer fmt.Print("\x1b[?25h")
	for {
		fmt.Print("\x1b[H\x1b[2J")
		fn()
		fmt.Printf("\n%s\n", c(clrGray, fmt.Sprintf("refresh interval %s, Ctrl+C to exit", d)))
		time.Sleep(d)
	}
}

// ---------- Tree rendering ----------

func proc_printTree(procs []proc_ProcInfo) {
	byParent := make(map[uint32][]proc_ProcInfo)
	pidSet := make(map[uint32]bool, len(procs))
	for _, p := range procs {
		pidSet[p.PID] = true
	}
	var roots []proc_ProcInfo
	for _, p := range procs {
		if pidSet[p.PPID] && p.PPID != p.PID {
			byParent[p.PPID] = append(byParent[p.PPID], p)
		} else {
			roots = append(roots, p)
		}
	}
	var walk func(p proc_ProcInfo, prefix string, last bool, depth int)
	walk = func(p proc_ProcInfo, prefix string, last bool, depth int) {
		if depth == 0 {
			fmt.Printf("%-6d %s\n", p.PID, p.Name)
		} else if last {
			fmt.Printf("%s`-- %-6d %s\n", prefix, p.PID, p.Name)
		} else {
			fmt.Printf("%s|-- %-6d %s\n", prefix, p.PID, p.Name)
		}
		if depth > 32 {
			fmt.Printf("%s    %s\n", prefix, c(clrGray, "..."))
			return
		}
		children := byParent[p.PID]
		childPrefix := prefix
		if depth > 0 {
			if last {
				childPrefix += "    "
			} else {
				childPrefix += "|   "
			}
		}
		for i, ch := range children {
			walk(ch, childPrefix, i == len(children)-1, depth+1)
		}
	}
	for _, r := range roots {
		walk(r, "", true, 0)
	}
}

// ---------- Utilities ----------

func proc_sortProcs(procs []proc_ProcInfo, key string, desc bool) {
	sort.Slice(procs, func(i, j int) bool {
		var a, b float64
		switch key {
		case "mem":
			a, b = float64(procs[i].Mem), float64(procs[j].Mem)
		case "pid":
			a, b = float64(procs[i].PID), float64(procs[j].PID)
		case "name":
			if desc {
				return procs[i].Name > procs[j].Name
			}
			return procs[i].Name < procs[j].Name
		case "create-time":
			return procs[i].CreateTime.After(procs[j].CreateTime) == desc
		case "io_read_b":
			a, b = float64(procs[i].IOReadB), float64(procs[j].IOReadB)
		case "io_write_b":
			a, b = float64(procs[i].IOWriteB), float64(procs[j].IOWriteB)
		case "threads":
			a, b = float64(procs[i].Threads), float64(procs[j].Threads)
		case "handles":
			a, b = float64(procs[i].Handles), float64(procs[j].Handles)
		default:
			a, b = procs[i].CPU, procs[j].CPU
		}
		if desc {
			return a > b
		}
		return a < b
	})
}

func proc_nextSort(k string) string {
	order := []string{"cpu", "mem", "pid", "name"}
	for i, s := range order {
		if s == k {
			return order[(i+1)%len(order)]
		}
	}
	return "cpu"
}

func proc_trunc(s string, n int) string {
	if n <= 0 || len(s) <= n {
		return s
	}
	if n == 1 {
		return s[:1]
	}
	return s[:n-1] + "~"
}

func proc_parseSize(s string) (uint64, error) {
	orig := s
	s = strings.TrimSpace(strings.ToUpper(s))
	mult := uint64(1)
	for _, sfx := range []struct {
		s string
		m uint64
	}{
		{"KB", 1 << 10}, {"MB", 1 << 20}, {"GB", 1 << 30}, {"TB", 1 << 40},
		{"K", 1 << 10}, {"M", 1 << 20}, {"G", 1 << 30}, {"B", 1},
	} {
		if strings.HasSuffix(s, sfx.s) {
			mult = sfx.m
			s = strings.TrimSuffix(s, sfx.s)
			break
		}
	}
	v, err := strconv.ParseUint(strings.TrimSpace(s), 10, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid size %q", orig)
	}
	return v * mult, nil
}

func proc_parseRate(s string) (uint64, error) {
	s = strings.ReplaceAll(s, "/s", "")
	s = strings.ReplaceAll(s, "/S", "")
	orig := s
	low := strings.ToLower(s)
	for _, sfx := range []struct {
		s string
		m uint64
	}{
		{"gbps", 1_000_000_000 / 8}, {"mbps", 1_000_000 / 8},
		{"kbps", 1_000 / 8}, {"bps", 1},
	} {
		if strings.HasSuffix(low, sfx.s) {
			v, err := strconv.ParseUint(strings.TrimSpace(strings.TrimSuffix(low, sfx.s)), 10, 64)
			if err != nil {
				return 0, fmt.Errorf("invalid rate %q", orig)
			}
			return v * sfx.m, nil
		}
	}
	return proc_parseSize(s)
}

// ---------- TUI config ----------

type proc_tuiConfig struct {
	Interval int    `json:"interval"`
	FPS      int    `json:"fps"`
	SortKey  string `json:"sort_key"`
	SortDesc bool   `json:"sort_desc"`
}

func proc_defaultConfigPath(args []string) string {
	if p := proc_getOpt(args, "--config"); p != "" {
		return p
	}
	la := os.Getenv("LOCALAPPDATA")
	if la == "" {
		la = os.Getenv("TEMP")
	}
	return filepath.Join(strings.TrimRight(la, `\`), "procctl", "config.json")
}

func proc_loadTUIConfig(path string) proc_tuiConfig {
	c := proc_tuiConfig{Interval: 1000, FPS: 30, SortKey: "cpu", SortDesc: true}
	if data, err := os.ReadFile(path); err == nil {
		_ = json.Unmarshal(data, &c)
	}
	return c
}

func proc_saveTUIConfig(path string, c proc_tuiConfig) {
	_ = os.MkdirAll(filepath.Dir(path), 0755)
	data, _ := json.MarshalIndent(c, "", "  ")
	_ = os.WriteFile(path, data, 0644)
}

// ---------- TUI ----------

type proc_tui struct {
	view           int
	cursor         int
	marked         map[uint32]bool
	filter         string
	filterMode     bool
	sortKey        string
	sortDesc       bool
	interval       time.Duration
	procs          []proc_ProcInfo
	sys            proc_SysInfo
	detail         *proc_ProcInfo
	width, height  int
	lastDraw       time.Time
	fpsLimit       time.Duration
	noMouse        bool
	quit           bool
	parallel       int
	configPath     string
	lastRefreshDur time.Duration
	forceRefresh   bool
}

func proc_runTUI(interval time.Duration, fps int, noMouse bool, parallel int, configPath string, resetConfig bool) {
	if resetConfig {
		_ = os.Remove(configPath)
	}
	cfg := proc_loadTUIConfig(configPath)
	cfg.Interval = int(interval / time.Millisecond)
	cfg.FPS = fps
	if fps < 15 {
		fps = 15
	}
	if fps > 60 {
		fps = 60
	}
	if parallel < 1 {
		parallel = 8
	}
	t := &proc_tui{marked: map[uint32]bool{}, sortKey: cfg.SortKey, sortDesc: cfg.SortDesc,
		interval: interval, fpsLimit: time.Second / time.Duration(fps),
		noMouse: noMouse, width: 120, height: 30, parallel: parallel, configPath: configPath}
	inH, _, _ := pGetStdHandle.Call(uintptr(STD_INPUT_HANDLE))
	outH, _, _ := pGetStdHandle.Call(uintptr(STD_OUTPUT_HANDLE))
	var oldIn, oldOut uint32
	pGetConsoleMode.Call(inH, uintptr(unsafe.Pointer(&oldIn)))
	pGetConsoleMode.Call(outH, uintptr(unsafe.Pointer(&oldOut)))
	defer func() {
		proc_pSetConsoleMode.Call(inH, uintptr(oldIn))
		proc_pSetConsoleMode.Call(outH, uintptr(oldOut))
		fmt.Print("\x1b[?25h\x1b[?1049l")
	}()
	newIn := oldIn &^ uint32(proc_ENABLE_LINE_INPUT|proc_ENABLE_ECHO_INPUT|proc_ENABLE_PROCESSED_INPUT|proc_ENABLE_MOUSE_INPUT)
	newIn |= proc_ENABLE_EXTENDED_FLAGS | proc_ENABLE_WINDOW_INPUT
	if !noMouse {
		newIn |= proc_ENABLE_MOUSE_INPUT
	}
	proc_pSetConsoleMode.Call(inH, uintptr(newIn))
	proc_pSetConsoleMode.Call(outH, uintptr(oldOut|proc_ENABLE_VIRTUAL_TERMINAL_PROCESSING))
	fmt.Print("\x1b[?1049h\x1b[?25l\x1b[2J")
	proc_updateConsoleSize(syscall.Handle(outH), t)
	inputCh := make(chan proc_INPUT_RECORD, 64)
	go func() {
		var rec proc_INPUT_RECORD
		var n uint32
		for {
			r, _, _ := proc_pReadConsoleInputW.Call(inH, uintptr(unsafe.Pointer(&rec)), 1, uintptr(unsafe.Pointer(&n)))
			if r == 0 {
				close(inputCh)
				return
			}
			if n > 0 {
				inputCh <- rec
			}
		}
	}()
	t.refresh()
	t.draw(syscall.Handle(outH))
	tick := time.NewTicker(t.interval)
	defer tick.Stop()
	for !t.quit {
		select {
		case rec, ok := <-inputCh:
			if !ok {
				t.quit = true
				break
			}
			t.handleInput(rec)
			if t.forceRefresh {
				t.forceRefresh = false
				t.refresh()
				t.draw(syscall.Handle(outH))
			} else if t.filterMode || time.Since(t.lastDraw) >= t.fpsLimit {
				t.draw(syscall.Handle(outH))
			}
		case <-tick.C:
			if t.filterMode {
				t.draw(syscall.Handle(outH))
			} else {
				t.refresh()
				t.draw(syscall.Handle(outH))
			}
		}
	}
	proc_saveTUIConfig(t.configPath, proc_tuiConfig{int(t.interval / time.Millisecond), fps, t.sortKey, t.sortDesc})
}

func proc_updateConsoleSize(h syscall.Handle, t *proc_tui) {
	var info proc_CONSOLE_SCREEN_BUFFER_INFO
	if r, _, _ := proc_pGetConsoleScreenBufferInfo.Call(uintptr(h), uintptr(unsafe.Pointer(&info))); r != 0 {
		t.width = int(info.Window.Right-info.Window.Left) + 1
		t.height = int(info.Window.Bottom-info.Window.Top) + 1
	}
}

func (t *proc_tui) refresh() {
	start := time.Now()
	defer func() { t.lastRefreshDur = time.Since(start) }()
	snaps, err := proc_listProcesses()
	if err != nil {
		return
	}
	fields := map[string]bool{"pid": true, "name": true, "threads": true, "cpu": true, "mem": true}
	t.procs = proc_collectDetails(snaps, fields, t.parallel)
	proc_percentWithWarmup(t.procs)
	if t.filter != "" {
		lf := strings.ToLower(t.filter)
		filtered := t.procs[:0]
		for _, p := range t.procs {
			if strings.Contains(strings.ToLower(p.Name), lf) {
				filtered = append(filtered, p)
			}
		}
		t.procs = filtered
	}
	proc_sortProcs(t.procs, t.sortKey, t.sortDesc)
	if t.view == 1 {
		t.sys = proc_collectSysInfo()
	}
	if t.cursor >= len(t.procs) && len(t.procs) > 0 {
		t.cursor = len(t.procs) - 1
	}
}

func (t *proc_tui) handleInput(rec proc_INPUT_RECORD) {
	switch rec.EventType {
	case 0x0001:
		k := (*proc_KEY_EVENT_RECORD)(unsafe.Pointer(&rec.Event[0]))
		if k.KeyDown == 0 {
			return
		}
		t.handleKey(k)
	case 0x0002:
		if t.noMouse {
			return
		}
		m := (*proc_MOUSE_EVENT_RECORD)(unsafe.Pointer(&rec.Event[0]))
		if m.EventFlags&proc_MOUSE_WHEELED != 0 {
			delta := int16(m.ButtonState >> 16)
			if delta > 0 {
				t.cursor -= 3
			} else {
				t.cursor += 3
			}
			if t.cursor < 0 {
				t.cursor = 0
			}
			if t.cursor >= len(t.procs) {
				t.cursor = len(t.procs) - 1
			}
		} else if m.ButtonState&0x1 != 0 {
			row := int(m.MousePosY) - 3
			if row >= 0 && row < len(t.procs) {
				t.cursor = row
			}
		}
	}
}

func (t *proc_tui) handleKey(k *proc_KEY_EVENT_RECORD) {
	if k.UnicodeChar == 3 || (k.VirtualKeyCode == proc_VK_CTRL_C && k.ControlKeyState&proc_LEFT_CTRL_PRESSED != 0) {
		t.quit = true
		return
	}
	if t.filterMode {
		switch k.VirtualKeyCode {
		case proc_VK_RETURN:
			t.filterMode = false
			t.forceRefresh = true
			return
		case proc_VK_ESCAPE:
			t.filterMode = false
			t.filter = ""
			t.forceRefresh = true
			return
		case proc_VK_BACK:
			if len(t.filter) > 0 {
				t.filter = t.filter[:len(t.filter)-1]
			}
			return
		}
		if k.UnicodeChar >= 32 {
			t.filter += string(rune(k.UnicodeChar))
			return
		}
		if k.UnicodeChar == 0 {
			vk := k.VirtualKeyCode
			if vk >= 0x30 && vk <= 0x39 {
				t.filter += string(rune(vk))
				return
			}
			if vk >= 0x41 && vk <= 0x5A {
				t.filter += string(rune(vk + 32))
				return
			}
		}
		return
	}
	switch k.VirtualKeyCode {
	case proc_VK_UP:
		if t.cursor > 0 {
			t.cursor--
		}
		return
	case proc_VK_DOWN:
		if t.cursor < len(t.procs)-1 {
			t.cursor++
		}
		return
	case proc_VK_SPACE:
		if t.cursor < len(t.procs) {
			pid := t.procs[t.cursor].PID
			if t.marked[pid] {
				delete(t.marked, pid)
			} else {
				t.marked[pid] = true
			}
		}
		return
	case proc_VK_TAB:
		t.view = (t.view + 1) % 2
		t.cursor = 0
		return
	case proc_VK_RETURN:
		if t.view == 0 && t.cursor < len(t.procs) {
			p := t.procs[t.cursor]
			t.detail = &p
		}
		return
	case proc_VK_ESCAPE:
		t.detail = nil
		return
	case proc_VK_F2:
		switch t.interval {
		case 500 * time.Millisecond:
			t.interval = time.Second
		case time.Second:
			t.interval = 2 * time.Second
		case 2 * time.Second:
			t.interval = 5 * time.Second
		default:
			t.interval = 500 * time.Millisecond
		}
		return
	}
	if k.UnicodeChar == 0 {
		return
	}
	switch string(rune(k.UnicodeChar)) {
	case "q":
		t.quit = true
	case "j":
		if t.cursor < len(t.procs)-1 {
			t.cursor++
		}
	case "k":
		if t.cursor > 0 {
			t.cursor--
		}
	case "s":
		t.sortKey = proc_nextSort(t.sortKey)
		t.sortDesc = !t.sortDesc
	case "/":
		t.view = 0
		t.detail = nil
		t.filterMode = true
	case "K":
		t.controlSelected("kill")
	case "X":
		t.controlSelected("superkill")
	case "Z":
		t.controlSelected("suspend")
	case "R":
		t.controlSelected("resume")
	case "P":
		if t.cursor < len(t.procs) {
			ppid := t.procs[t.cursor].PPID
			for i, p := range t.procs {
				if p.PID == ppid {
					t.cursor = i
					break
				}
			}
		}
	}
}

func (t *proc_tui) controlSelected(action string) {
	var pids []uint32
	if len(t.marked) > 0 {
		for pid := range t.marked {
			pids = append(pids, pid)
		}
	} else if t.cursor < len(t.procs) {
		pids = append(pids, t.procs[t.cursor].PID)
	}
	for _, pid := range pids {
		if proc_isProtected(pid) && action != "superkill" {
			continue
		}
		var err error
		switch action {
		case "kill", "superkill":
			err = proc_killProcess(pid, true)
		case "suspend":
			err = proc_suspendProcess(pid)
		case "resume":
			err = proc_resumeProcess(pid)
		}
		if err != nil {
			bugs.Add("WARN", "tui %s pid=%d: %v", action, pid, err)
		}
	}
}

func (t *proc_tui) draw(outH syscall.Handle) {
	t.lastDraw = time.Now()
	proc_updateConsoleSize(outH, t)
	var b strings.Builder
	b.WriteString("\x1b[H")
	if t.detail != nil {
		t.renderDetail(&b)
	} else {
		switch t.view {
		case 1:
			t.renderSystem(&b)
		default:
			t.renderProcesses(&b)
		}
	}
	for i := strings.Count(b.String(), "\n"); i < t.height; i++ {
		b.WriteString("\x1b[K\n")
	}
	fmt.Print(b.String())
}

func (t *proc_tui) nameWidth() int {
	w := t.width - 50
	if w < 12 {
		w = 12
	}
	if w > 44 {
		w = 44
	}
	return w
}

func (t *proc_tui) renderProcesses(b *strings.Builder) {
	arrow := "v"
	if !t.sortDesc {
		arrow = "^"
	}
	pidW, nameW, cpuW, memW, thrW := 6, t.nameWidth(), 6, 9, 5
	header := "  " +
		fmt.Sprintf("%*s", pidW, "PID") + " " +
		fmt.Sprintf("%-*s", nameW, "NAME") + " " +
		fmt.Sprintf("%*s", cpuW, "CPU%") + " " +
		fmt.Sprintf("%-*s", memW, "MEM") + " " +
		fmt.Sprintf("%*s", thrW, "THR")
	b.WriteString(c(clrBold+clrCyan, header) +
		fmt.Sprintf("  sort=%s%s marked=%d", t.sortKey, arrow, len(t.marked)))
	if !t.filterMode && t.filter != "" {
		fmt.Fprintf(b, "  filter=%q(%d)", t.filter, len(t.procs))
	}
	b.WriteString("\n")
	visible := t.height - 4
	if visible < 1 {
		visible = 1
	}
	start := 0
	if t.cursor >= visible {
		start = t.cursor - visible + 1
	}
	end := start + visible
	if end > len(t.procs) {
		end = len(t.procs)
	}
	for i := start; i < end; i++ {
		p := t.procs[i]
		marker := " "
		if t.marked[p.PID] {
			marker = "*"
		}
		pidStr := fmt.Sprintf("%*d", pidW, p.PID)
		nameStr := fmt.Sprintf("%-*s", nameW, proc_trunc(p.Name, nameW))
		cpuStr := fmt.Sprintf("%*.1f", cpuW, p.CPU)
		memStr := fmt.Sprintf("%-*s", memW, humanBytes(p.Mem))
		thrStr := fmt.Sprintf("%*d", thrW, p.Threads)
		line := marker + " " +
			c(clrCyan, pidStr) + " " + nameStr + " " +
			c(proc_cpuColor(p.CPU), cpuStr) + " " +
			c(clrYellow, memStr) + " " + thrStr
		if i == t.cursor {
			line = "\x1b[7m" + line + "\x1b[0m"
		}
		b.WriteString(line + "\x1b[K\n")
	}
	b.WriteString("\x1b[K\n")
	if t.filterMode {
		shown := t.filter
		maxShown := t.width - 60
		if maxShown < 10 {
			maxShown = 10
		}
		if len(shown) > maxShown {
			shown = "..." + shown[len(shown)-maxShown+3:]
		}
		b.WriteString(c(clrBold+clrYellow, fmt.Sprintf("FILTER> %s_", shown)))
		b.WriteString(c(clrGray, "   [enter]apply  [esc]clear  [backspace]del"))
	} else {
		b.WriteString(c(clrGray, "[q]quit [space]mark [K]kill [X]super [Z]suspend [R]resume [s]sort [/]filter [P]parent [F2]interval [tab]view"))
	}
	b.WriteString("\x1b[K\n")
	b.WriteString(c(clrGray, fmt.Sprintf("%d procs | %.1fms", len(t.procs), t.lastRefreshDur.Seconds()*1000)))
}

func (t *proc_tui) renderSystem(b *strings.Builder) {
	b.WriteString(c(clrBold+clrCyan, "System Resources") + "\n\n")
	fmt.Fprintf(b, "  %s  %s  %s\n",
		c(clrCyan, "CPU   "),
		c(proc_cpuColor(t.sys.CPUPercent), fmt.Sprintf("%5.1f%%", t.sys.CPUPercent)),
		c(clrGray, fmt.Sprintf("Logical %d / Physical %d", t.sys.LogicalCPU, t.sys.PhysicalCPU)))
	fmt.Fprintf(b, "  %s  %s / %s  %s\n",
		c(clrCyan, "MEM   "),
		c(clrYellow, humanBytes(t.sys.MemUsed)), humanBytes(t.sys.MemTotal),
		c(clrGray, fmt.Sprintf("Free %s", humanBytes(t.sys.MemFree))))
	fmt.Fprintf(b, "  %s  %s\n", c(clrCyan, "Uptime"), t.sys.Uptime)
	if len(t.sys.Disks) > 0 {
		b.WriteString("\n")
		for _, d := range t.sys.Disks {
			fmt.Fprintf(b, "  %s  %5.1f%%  %s\n",
				c(clrCyan, d.Letter), d.Percent,
				c(clrGray, fmt.Sprintf("%s / %s", humanBytes(d.Free), humanBytes(d.Total))))
		}
	}
}

func (t *proc_tui) renderDetail(b *strings.Builder) {
	p := t.detail
	b.WriteString(c(clrBold+clrCyan, "Process Detail") + "\n\n")
	fmt.Fprintf(b, "PID         %d\nPPID        %d\nName        %s\nExe         %s\n",
		p.PID, p.PPID, p.Name, p.Exe)
	fmt.Fprintf(b, "CPU         %.1f%%\nMem         %s\nThreads     %d\nHandles     %d\n",
		p.CPU, humanBytes(p.Mem), p.Threads, p.Handles)
	fmt.Fprintf(b, "IO Read     %s / %d ops\nIO Write    %s / %d ops\n",
		humanBytes(p.IOReadB), p.IOReadC, humanBytes(p.IOWriteB), p.IOWriteC)
	if p.Priority != "" {
		fmt.Fprintf(b, "Priority    %s\n", p.Priority)
	}
	b.WriteString("\n[esc] back")
}

// ---------- Help ----------

func proc_printHelp() {
	fmt.Printf("%s v%s (Windows)\n\n", c(clrBold+clrCyan, "winctl proc"), Version)
	fmt.Print(`USAGE
  winctl proc <command> [OPTIONS] [ARGS...]

COMMANDS
  list [OPTIONS]                    List processes
  total [OPTIONS]                   System totals
  sum [N] [OPTIONS]                 Top N processes (default 10)
  monitor [OPTIONS]                 Live TUI monitor
  kill <pid|name> [--tree]          Kill process
  superkill <pid|name> [--tree]     Force-kill process
  suspend <pid|name>                Suspend process
  resume <pid|name>                 Resume process
  priority <pid|name> <level>       Set priority
  limit <pid|name> [LIMIT OPTIONS]  Limit one process
  run [OPTIONS] -- <command>        Controlled launch
  history                           Show rollback-able operations
  rollback <N>                      Undo the most recent N operations
  help / version

GLOBAL
  -b, --bugs           print collected errors/warnings on exit
  -o, --out <path>     write output to file
  --no-color           disable color (also honors NO_COLOR)
  -h, --help           show this help
  --version            show version

LIST
  -e, --exclude-system Exclude system processes
  --detail             Show all fields
  --fields <f1,f2>     Custom fields
  --filter <pattern>   Filter by process name
  --limit <N>          Show only first N rows
  --sort <field>       cpu|mem|pid|name|create-time|io_read_b|io_write_b|threads|handles
  --order <asc|desc>   Sort order
  --tree               Process tree
  --json               JSON output
  --parallel <N>       Collection concurrency (default 8)
  --watch[=interval]   Refresh periodically (default 1s)

MONITOR
  --interval[=ms]      Refresh interval (default 1000, min 500)
  --fps[=N]            Frame rate cap (15~60, default 30)
  --parallel[=N]       Collection concurrency
  --no-mouse           Disable mouse
  --config[=path]      Settings file path
  --reset-config       Reset settings
  Keys: q quit  Up/Down select  Space mark  K/X/Z/R control  / filter
        P parent  F2 interval  Tab view  s sort

KILL / SUPERKILL
  --tree               Recursively kill subtree
  --no-warn            Skip warnings

PRIORITY LEVELS
  idle|below-normal|normal|above-normal|high|realtime

LIMIT OPTIONS (limit / run)
  --affinity --cpu --iops --io-read --io-write --mem --net --net-in
  --net-out --on-proc_exit --process-count --timeout --working-set

RUN OPTIONS
  --admin              Re-launch with UAC elevation
  --cwd <dir>          Working directory
  --title <text>       Console title
  --priority <level>   Startup priority
  --no-window          Create child without console window

All logs go to ./backup/winctl_logs.log
`)
}

func proc_main() {
	proc_initAPIs()
	defer func() {
		if r := recover(); r != nil {
			bugs.enabled = true
			bugs.Add("PANIC", "%v", r)
			proc_exit(5)
		}
	}()
	args := proc_expandShortArgs(os.Args[1:])
	var filtered []string
	for _, a := range args {
		if a == "-b" || a == "--bugs" {
			bugs.enabled = true
			continue
		}
		filtered = append(filtered, a)
	}
	args = filtered
	initColor()
	proc_checkRequiredAPIs()

	if proc_hasBeforeDoubleDash(args, "--version") {
		fmt.Printf("winctl proc v%s\n", Version)
		finalExit(0)
	}
	cmd, rest, ok := proc_parseCommand(args)
	if !ok {
		if len(args) == 0 || has(args, "-h", "--help") {
			proc_printHelp()
			finalExit(0)
		}
		fmt.Fprintln(os.Stderr, "unknown command, use -h for help")
		finalExit(2)
	}
	if cmd == "help" || proc_hasBeforeDoubleDash(rest, "-h", "--help") {
		proc_printHelp()
		finalExit(0)
	}
	if cmd == "version" {
		fmt.Printf("winctl proc v%s\n", Version)
		finalExit(0)
	}
	switch cmd {
	case "list", "total", "sum", "limit":
		if !proc_setupOutput(cmd, rest) {
			finalExit(2)
		}
	case "monitor":
		if has(rest, "-o", "--out") {
			fmt.Fprintln(os.Stderr, "-o/--out cannot be used with monitor")
			finalExit(2)
		}
	}
	switch cmd {
	case "list":
		proc_cmdList(rest)
	case "total":
		proc_cmdTotal(rest)
	case "sum":
		proc_cmdSum(rest)
	case "monitor":
		proc_cmdMonitor(rest)
	case "kill":
		proc_cmdKill(rest, false)
	case "superkill":
		proc_cmdKill(rest, true)
	case "suspend":
		proc_cmdSuspendResume(rest, false)
	case "resume":
		proc_cmdSuspendResume(rest, true)
	case "priority":
		proc_cmdPriority(rest)
	case "limit":
		proc_cmdLimit(rest)
	case "run":
		proc_cmdRun(rest)
	case "history":
		proc_cmdHistory()
	case "rollback":
		proc_cmdRollback(rest)
	}
	finalExit(0)
}
// ============================================================================
// reg — registry manager (infrastructure build: export/import/backup only)
// ============================================================================

var reg_wow32Flag = false

func reg_wowFlag() uint32 {
	if reg_wow32Flag {
		return KEY_WOW64_32KEY
	}
	return KEY_WOW64_64KEY
}

func reg_regCreateKey(root uintptr, subKey string, samDesired uint32) (RegKey, bool, error) {
	subPtr, err := syscall.UTF16PtrFromString(subKey)
	if err != nil {
		return 0, false, err
	}
	var phk uintptr
	var disp uint32
	r, _, _ := pRegCreateKeyExW.Call(root,
		uintptr(unsafe.Pointer(subPtr)), 0, 0, 0,
		uintptr(samDesired), 0,
		uintptr(unsafe.Pointer(&phk)),
		uintptr(unsafe.Pointer(&disp)))
	if r != 0 {
		return 0, false, syscall.Errno(r)
	}
	return RegKey(phk), disp == 1, nil
}

type reg_RegPath struct {
	Root     uintptr
	RootName string
	SubKey   string
}

func reg_parseRegPath(s string) (*reg_RegPath, error) {
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, `\\?\`)
	s = strings.ReplaceAll(s, "/", `\`)
	s = strings.TrimSuffix(s, `\`)
	idx := strings.Index(s, `\`)
	var rootName, subKey string
	if idx < 0 {
		rootName, subKey = s, ""
	} else {
		rootName, subKey = s[:idx], s[idx+1:]
	}
	var root uintptr
	switch strings.ToUpper(rootName) {
	case "HKCR", "HKEY_CLASSES_ROOT":
		root, rootName = HKCR, "HKEY_CLASSES_ROOT"
	case "HKCU", "HKEY_CURRENT_USER":
		root, rootName = HKCU, "HKEY_CURRENT_USER"
	case "HKLM", "HKEY_LOCAL_MACHINE":
		root, rootName = HKLM, "HKEY_LOCAL_MACHINE"
	case "HKU", "HKEY_USERS":
		root, rootName = HKU, "HKEY_USERS"
	case "HKCC", "HKEY_CURRENT_CONFIG":
		root, rootName = HKCC, "HKEY_CURRENT_CONFIG"
	default:
		return nil, fmt.Errorf("unknown registry root %q", rootName)
	}
	return &reg_RegPath{Root: root, RootName: rootName, SubKey: subKey}, nil
}

func (p *reg_RegPath) FullName() string {
	if p.SubKey == "" {
		return p.RootName
	}
	return p.RootName + `\` + p.SubKey
}

func reg_typeName(t uint32) string {
	switch t {
	case REG_NONE:
		return "none"
	case REG_SZ:
		return "string"
	case REG_EXPAND_SZ:
		return "expand"
	case REG_BINARY:
		return "binary"
	case REG_DWORD:
		return "dword"
	case REG_DWORD_BIG_ENDIAN:
		return "dword-be"
	case REG_LINK:
		return "link"
	case REG_MULTI_SZ:
		return "multi"
	case REG_QWORD:
		return "qword"
	}
	return fmt.Sprintf("type-%d", t)
}

func reg_hexJoin(b []byte) string {
	parts := make([]string, len(b))
	for i, x := range b {
		parts[i] = fmt.Sprintf("%02x", x)
	}
	return strings.Join(parts, ",")
}

func reg_formatValueDisplay(v RegValue) string {
	switch v.Type {
	case REG_SZ, REG_EXPAND_SZ, REG_LINK:
		return decodeRegString(v.Data)
	case REG_MULTI_SZ:
		return strings.Join(decodeMultiString(v.Data), " | ")
	case REG_DWORD:
		if len(v.Data) >= 4 {
			n := binary.LittleEndian.Uint32(v.Data)
			return fmt.Sprintf("%d (0x%08X)", n, n)
		}
		return fmt.Sprintf("hex:%X", v.Data)
	case REG_QWORD:
		if len(v.Data) >= 8 {
			n := binary.LittleEndian.Uint64(v.Data)
			return fmt.Sprintf("%d (0x%016X)", n, n)
		}
		return fmt.Sprintf("hex:%X", v.Data)
	}
	return fmt.Sprintf("hex:%s", reg_hexJoin(v.Data))
}

var reg_escapeStringReplacer = strings.NewReplacer(`\`, `\\`, `"`, `\"`)

func reg_exportKeyToReg(buf *bytes.Buffer, key RegKey, fullPath string) error {
	buf.WriteString("\r\n[" + fullPath + "]\r\n")
	values, err := regEnumValues(key)
	if err != nil {
		return err
	}
	for _, v := range values {
		reg_writeRegValue(buf, v)
	}
	subKeys, err := regEnumKeys(key)
	if err != nil {
		return err
	}
	for _, sub := range subKeys {
		child, err := regOpenKey(uintptr(key), sub, KEY_READ|reg_wowFlag())
		if err != nil {
			bugs.Add("WARN", "export: skip %s\\%s: %v", fullPath, sub, err)
			continue
		}
		_ = reg_exportKeyToReg(buf, child, fullPath+`\`+sub)
		regCloseKey(child)
	}
	return nil
}

func reg_writeRegValue(buf *bytes.Buffer, v RegValue) {
	name := `@`
	if v.Name != "" {
		name = `"` + reg_escapeStringReplacer.Replace(v.Name) + `"`
	}
	buf.WriteString(name + "=")
	switch v.Type {
	case REG_SZ, REG_LINK:
		buf.WriteString(`"` + reg_escapeStringReplacer.Replace(decodeRegString(v.Data)) + `"` + "\r\n")
	case REG_DWORD:
		if len(v.Data) >= 4 {
			buf.WriteString(fmt.Sprintf("dword:%08x\r\n", binary.LittleEndian.Uint32(v.Data)))
		} else {
			buf.WriteString("hex:" + reg_hexJoin(v.Data) + "\r\n")
		}
	case REG_QWORD:
		if len(v.Data) >= 8 {
			buf.WriteString("hex(b):" + reg_hexJoin(v.Data[:8]) + "\r\n")
		} else {
			buf.WriteString("hex:" + reg_hexJoin(v.Data) + "\r\n")
		}
	case REG_EXPAND_SZ:
		buf.WriteString("hex(2):" + reg_hexJoin(v.Data) + "\r\n")
	case REG_MULTI_SZ:
		buf.WriteString("hex(7):" + reg_hexJoin(v.Data) + "\r\n")
	default:
		buf.WriteString("hex:" + reg_hexJoin(v.Data) + "\r\n")
	}
}

func reg_exportRegString(p *reg_RegPath) (string, error) {
	k, err := regOpenKey(p.Root, p.SubKey, KEY_READ|reg_wowFlag())
	if err != nil {
		return "", err
	}
	defer regCloseKey(k)
	var buf bytes.Buffer
	buf.WriteString("Windows Registry Editor Version 5.00\r\n")
	_ = reg_exportKeyToReg(&buf, k, p.FullName())
	return buf.String(), nil
}

func reg_utf16LEToUTF8(b []byte) string {
	if len(b)%2 != 0 {
		b = b[:len(b)-1]
	}
	u := make([]uint16, len(b)/2)
	for i := 0; i < len(u); i++ {
		u[i] = uint16(b[i*2]) | uint16(b[i*2+1])<<8
	}
	return string(utf16Decode(u))
}

func reg_decodeRegFileContent(content []byte) string {
	if len(content) >= 2 && content[0] == 0xFF && content[1] == 0xFE {
		return reg_utf16LEToUTF8(content[2:])
	}
	if len(content) >= 3 && content[0] == 0xEF && content[1] == 0xBB && content[2] == 0xBF {
		return string(content[3:])
	}
	return string(content)
}

func reg_lineContinues(line string) bool {
	trimmed := strings.TrimRight(line, " \t")
	if !strings.HasSuffix(trimmed, `\`) {
		return false
	}
	if strings.Contains(trimmed, "=hex") {
		return true
	}
	n := 0
	for i := len(trimmed) - 1; i >= 0 && trimmed[i] == '\\'; i-- {
		n++
	}
	return n%2 == 1
}

func reg_importRegContent(content []byte) error {
	text := reg_decodeRegFileContent(content)
	lines := strings.Split(text, "\n")
	var curPath *reg_RegPath
	var curKey RegKey
	defer func() { regCloseKey(curKey) }()
	flushKey := func() {
		regCloseKey(curKey)
		curKey = 0
	}
	var pendingLine string
	for _, raw := range lines {
		line := strings.TrimRight(raw, "\r")
		if pendingLine != "" {
			line = pendingLine + line
			pendingLine = ""
		}
		if reg_lineContinues(line) {
			pendingLine = line[:len(line)-1]
			continue
		}
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, ";") {
			continue
		}
		if strings.HasPrefix(trimmed, "Windows Registry Editor") || strings.HasPrefix(trimmed, "REGEDIT4") {
			continue
		}
		if strings.HasPrefix(trimmed, "[-") && strings.HasSuffix(trimmed, "]") {
			continue
		}
		if strings.HasPrefix(trimmed, "[") && strings.HasSuffix(trimmed, "]") {
			flushKey()
			inner := trimmed[1 : len(trimmed)-1]
			p, err := reg_parseRegPath(inner)
			if err != nil {
				return fmt.Errorf("bad section %q: %w", inner, err)
			}
			curPath = p
			key, _, err := reg_regCreateKey(p.Root, p.SubKey, KEY_WRITE|reg_wowFlag())
			if err != nil {
				return fmt.Errorf("create %s: %w", p.FullName(), err)
			}
			curKey = key
			continue
		}
		if curPath == nil || curKey == 0 {
			continue
		}
		if err := reg_applyRegValueLine(curKey, trimmed); err != nil {
			bugs.Add("WARN", "value line %q: %v", trimmed, err)
		}
	}
	flushKey()
	return nil
}

var reg_regValueLineRe = regexp.MustCompile(`^(@|"(?:[^"\\]|\\.)*")\s*=\s*(.*)$`)

func reg_applyRegValueLine(key RegKey, line string) error {
	m := reg_regValueLineRe.FindStringSubmatch(line)
	if m == nil {
		return fmt.Errorf("not a value line")
	}
	name := ""
	if m[1] != "@" {
		name = reg_unescapeRegString(m[1][1 : len(m[1])-1])
	}
	data := strings.TrimSpace(m[2])
	if data == "-" {
		return regDeleteValue(key, name)
	}
	if strings.HasPrefix(data, `"`) && strings.HasSuffix(data, `"`) && len(data) >= 2 {
		s := reg_unescapeRegString(data[1 : len(data)-1])
		return regSetValue(key, name, REG_SZ, encodeRegString(s))
	}
	if strings.HasPrefix(data, "dword:") {
		v, err := strconv.ParseUint(data[6:], 16, 32)
		if err != nil {
			return err
		}
		b := make([]byte, 4)
		binary.LittleEndian.PutUint32(b, uint32(v))
		return regSetValue(key, name, REG_DWORD, b)
	}
	if strings.HasPrefix(data, "hex(b):") {
		b, err := hexDecodeStr(strings.ReplaceAll(data[7:], ",", ""))
		if err != nil {
			return err
		}
		return regSetValue(key, name, REG_QWORD, b)
	}
	if strings.HasPrefix(data, "hex(2):") {
		b, err := hexDecodeStr(strings.ReplaceAll(data[7:], ",", ""))
		if err != nil {
			return err
		}
		return regSetValue(key, name, REG_EXPAND_SZ, b)
	}
	if strings.HasPrefix(data, "hex(7):") {
		b, err := hexDecodeStr(strings.ReplaceAll(data[7:], ",", ""))
		if err != nil {
			return err
		}
		return regSetValue(key, name, REG_MULTI_SZ, b)
	}
	if strings.HasPrefix(data, "hex:") {
		b, err := hexDecodeStr(strings.ReplaceAll(data[4:], ",", ""))
		if err != nil {
			return err
		}
		return regSetValue(key, name, REG_BINARY, b)
	}
	return fmt.Errorf("unsupported value syntax %q", data)
}

func hexDecodeStr(s string) ([]byte, error) {
	out := make([]byte, len(s)/2)
	for i := 0; i < len(out); i++ {
		hi := hexVal(s[i*2])
		lo := hexVal(s[i*2+1])
		if hi < 0 || lo < 0 {
			return nil, fmt.Errorf("bad hex")
		}
		out[i] = byte(hi<<4 | lo)
	}
	return out, nil
}

func hexVal(c byte) int {
	switch {
	case c >= '0' && c <= '9':
		return int(c - '0')
	case c >= 'a' && c <= 'f':
		return int(c-'a') + 10
	case c >= 'A' && c <= 'F':
		return int(c-'A') + 10
	}
	return -1
}

func reg_unescapeRegString(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+1 < len(s) {
			b.WriteByte(s[i+1])
			i++
			continue
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

type reg_jsonKey struct {
	Name    string         `json:"name"`
	Path    string         `json:"path"`
	Values  []reg_jsonValue `json:"values"`
	SubKeys []string       `json:"subkeys,omitempty"`
}

type reg_jsonValue struct {
	Name string `json:"name"`
	Type string `json:"type"`
	Data string `json:"data"`
}

func reg_exportKeyToJSON(p *reg_RegPath) ([]byte, error) {
	k, err := regOpenKey(p.Root, p.SubKey, KEY_READ|reg_wowFlag())
	if err != nil {
		return nil, err
	}
	defer regCloseKey(k)
	obj, err := reg_buildJSONKey(k, p.FullName())
	if err != nil {
		return nil, err
	}
	return json.MarshalIndent(obj, "", "  ")
}

func reg_buildJSONKey(k RegKey, fullPath string) (*reg_jsonKey, error) {
	name := fullPath
	if i := strings.LastIndex(fullPath, `\`); i >= 0 {
		name = fullPath[i+1:]
	}
	obj := &reg_jsonKey{Name: name, Path: fullPath}
	values, _ := regEnumValues(k)
	for _, v := range values {
		obj.Values = append(obj.Values, reg_jsonValue{
			Name: v.Name, Type: reg_typeName(v.Type), Data: reg_formatValueDisplay(v),
		})
	}
	subs, _ := regEnumKeys(k)
	obj.SubKeys = subs
	return obj, nil
}

const reg_smallRegThreshold = 8192

var reg_sanitizeRe = regexp.MustCompile(`[^A-Za-z0-9._-]`)

func reg_sanitizeForFilename(s string) string {
	s = strings.ReplaceAll(s, `\`, "_")
	s = reg_sanitizeRe.ReplaceAllString(s, "_")
	if len(s) > 80 {
		s = s[:80]
	}
	return s
}

func reg_toUTF16LEBOM(s string) []byte {
	u := utf16Encode(s)
	buf := make([]byte, 2+len(u)*2)
	buf[0] = 0xFF
	buf[1] = 0xFE
	for i, v := range u {
		buf[2+i*2] = byte(v)
		buf[2+i*2+1] = byte(v >> 8)
	}
	return buf
}

func reg_backupKeyToReg(p *reg_RegPath, logIdx int) (string, bool, error) {
	text, err := reg_exportRegString(p)
	if err != nil {
		return "", false, err
	}
	raw := reg_toUTF16LEBOM(text)
	filesDir := moduleFilesDir("reg")
	base := fmt.Sprintf("%d_%s", logIdx, reg_sanitizeForFilename(p.FullName()))
	if len(raw) < reg_smallRegThreshold {
		rel := base + ".reg"
		full := filepath.Join(filesDir, rel)
		if err := os.MkdirAll(filesDir, 0755); err != nil {
			return "", false, err
		}
		if err := os.WriteFile(full, raw, 0644); err != nil {
			return "", false, err
		}
		return rel, false, nil
	}
	rel := base + ".reg.gz"
	full := filepath.Join(filesDir, rel)
	if err := os.MkdirAll(filesDir, 0755); err != nil {
		return "", false, err
	}
	f, err := os.Create(full)
	if err != nil {
		return "", false, err
	}
	gz, err := gzip.NewWriterLevel(f, gzip.BestCompression)
	if err != nil {
		f.Close()
		return "", false, err
	}
	if _, err := gz.Write(raw); err != nil {
		gz.Close()
		f.Close()
		return "", false, err
	}
	if err := gz.Close(); err != nil {
		f.Close()
		return "", false, err
	}
	if err := f.Close(); err != nil {
		return "", false, err
	}
	return rel, true, nil
}

func reg_restoreFromBackup(relPath string, gzipped bool) error {
	full := filepath.Join(moduleFilesDir("reg"), relPath)
	var content []byte
	var err error
	if gzipped {
		f, ferr := os.Open(full)
		if ferr != nil {
			return ferr
		}
		defer f.Close()
		gz, gerr := gzip.NewReader(f)
		if gerr != nil {
			return gerr
		}
		defer gz.Close()
		content, err = io.ReadAll(gz)
	} else {
		content, err = os.ReadFile(full)
	}
	if err != nil {
		return err
	}
	return reg_importRegContent(content)
}

type reg_opRecord struct {
	Op            string `json:"op"`
	TS            string `json:"ts"`
	Cmd           string `json:"cmd"`
	Code          int    `json:"code"`
	Path          string `json:"path"`
	ValueName     string `json:"valueName,omitempty"`
	OldValueType  uint32 `json:"oldValueType,omitempty"`
	OldValueData  []byte `json:"oldValueData,omitempty"`
	ExistsBefore  bool   `json:"existsBefore"`
	BackupFile    string `json:"backupFile,omitempty"`
	BackupGzipped bool   `json:"backupGzipped,omitempty"`
	Tree          bool   `json:"tree,omitempty"`
}

func reg_saveOp(idx int, rec *reg_opRecord) {
	if err := moduleSaveManifest("reg", idx, rec); err != nil {
		bugs.Add("ERR", "save op %d: %v", idx, err)
	}
}

func reg_loadOp(idx int) (*reg_opRecord, error) {
	var rec reg_opRecord
	if err := moduleLoadManifest("reg", idx, &rec); err != nil {
		return nil, err
	}
	return &rec, nil
}

func reg_cmdHistory() int {
	lines, err := auditReadLines()
	if err != nil {
		fmt.Fprintf(os.Stderr, "read log %s: %v\n", globalLogPath(), err)
		return 4
	}
	if len(lines) == 0 {
		fmt.Fprintln(os.Stderr, "log is empty")
		return 0
	}
	count := 0
	for i := len(lines) - 1; i >= 0; i-- {
		m, cmd, _, ok := auditParseLine(lines[i])
		if !ok || m != "reg" {
			continue
		}
		if isHistorySelf(cmd) || !moduleManifestExists("reg", i) {
			continue
		}
		count++
		fmt.Printf("[%d] %s\n", count, lines[i])
	}
	if count == 0 {
		fmt.Fprintln(os.Stderr, "no rollback-able reg operations in log")
	}
	return 0
}

func reg_cmdRollback(args []string) int {
	n := 1
	for i := 0; i < len(args); i++ {
		if args[i] == "-n" || args[i] == "--last" {
			if i+1 >= len(args) {
				return 2
			}
			v, err := strconv.Atoi(args[i+1])
			if err != nil || v <= 0 {
				return 2
			}
			n = v
			i++
		} else if strings.HasPrefix(args[i], "-") {
			fmt.Fprintf(os.Stderr, "rollback: unknown option %s\n", args[i])
			return 2
		}
	}
	idxs, err := moduleTailOps("reg", n)
	if err != nil || len(idxs) == 0 {
		fmt.Fprintln(os.Stderr, "no rollback-able reg operations found")
		return 4
	}
	if dryRun {
		for k, i := range idxs {
			if rec, err := reg_loadOp(i); err == nil {
				fmt.Printf("[dry-run] step %d: %s on %s\n", k+1, rec.Op, rec.Path)
			}
		}
		return 0
	}
	okCount, failCount := 0, 0
	for k, i := range idxs {
		rec, err := reg_loadOp(i)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[rollback] step %d: %v\n", k+1, err)
			failCount++
			continue
		}
		fmt.Fprintf(os.Stderr, "[rollback] step %d: %s on %s\n", k+1, rec.Op, rec.Path)
		if err := reg_rollbackOne(rec); err != nil {
			fmt.Fprintf(os.Stderr, "[rollback] step %d: error: %v\n", k+1, err)
			failCount++
			continue
		}
		fmt.Fprintf(os.Stderr, "[rollback] step %d: ok\n", k+1)
		okCount++
	}
	if failCount == 0 {
		return 0
	}
	if okCount == 0 {
		return 2
	}
	return 1
}

func reg_rollbackOne(rec *reg_opRecord) error {
	if rec.BackupFile != "" {
		return reg_restoreFromBackup(rec.BackupFile, rec.BackupGzipped)
	}
	p, err := reg_parseRegPath(rec.Path)
	if err != nil {
		return fmt.Errorf("parse %q: %w", rec.Path, err)
	}
	if !rec.ExistsBefore {
		k, err := regOpenKey(p.Root, p.SubKey, KEY_WRITE|reg_wowFlag())
		if err != nil {
			return nil
		}
		defer regCloseKey(k)
		_ = regDeleteValue(k, rec.ValueName)
		return nil
	}
	k, _, err := reg_regCreateKey(p.Root, p.SubKey, KEY_WRITE|reg_wowFlag())
	if err != nil {
		return err
	}
	defer regCloseKey(k)
	return regSetValue(k, rec.ValueName, rec.OldValueType, rec.OldValueData)
}

func reg_printHelp() {
	fmt.Printf("%s v%s (Windows)\n\n", c(clrBold+clrCyan, "winctl reg"), Version)
	fmt.Println("Registry manager — infrastructure build")
	fmt.Println()
	fmt.Println("NOTE: subcommands (ls/cat/get/set/del/mkkey/export/find/browse)")
	fmt.Println("      are not compiled into this build. Only the backup,")
	fmt.Println("      .reg/JSON export, and .reg import paths are present.")
	fmt.Println()
	fmt.Print(`USAGE
  winctl reg --history
  winctl reg --rollback [-n N]

GLOBAL
  -b, --bugs       print collected errors/warnings on exit
  -o, --out <p>    write stdout to a file
  --no-color       disable colors
  --wow32          use the 32-bit registry view
  -h, --help       show this help
  --version        show version

All logs go to ./backup/winctl_logs.log
`)
}

func reg_main() {
	args, outPath, err := consumeGlobalFlags(os.Args[1:])
	if err != nil {
		fmt.Fprintf(os.Stderr, "winctl reg: %v\n", err)
		finalExit(2)
	}
	// reg also honours --wow32 which consumeGlobalFlags doesn't know about.
	clean := make([]string, 0, len(args))
	for _, a := range args {
		if a == "--wow32" {
			reg_wow32Flag = true
			continue
		}
		clean = append(clean, a)
	}
	args = clean
	initColor()
	if has(args, "--version") {
		fmt.Printf("winctl reg v%s\n", Version)
		finalExit(0)
	}
	if len(args) == 0 || has(args, "-h", "--help") {
		reg_printHelp()
		finalExit(0)
	}
	if outPath != "" {
		if err := setupOutput(outPath); err != nil {
			fmt.Fprintf(os.Stderr, "winctl reg: %v\n", err)
			finalExit(2)
		}
	}
	var code int
	switch {
	case has(args, "--history"):
		code = reg_cmdHistory()
	case has(args, "--rollback"):
		code = reg_cmdRollback(stripFlags(args, "--rollback"))
	default:
		fmt.Fprintf(os.Stderr, "winctl reg: subcommand %q is not implemented in this build\n", args[0])
		code = 2
	}
	if !dryRun && shouldLogRun() {
		auditLog("reg", buildCmdLine(os.Args), code)
	}
	finalExit(code)
}
// ============================================================================
// svc — Windows service manager
// ============================================================================

var (
	svc_pOpenSCManagerW        = advapi32.NewProc("OpenSCManagerW")
	svc_pCloseServiceHandle    = advapi32.NewProc("CloseServiceHandle")
	svc_pEnumServicesStatusExW = advapi32.NewProc("EnumServicesStatusExW")
	svc_pOpenServiceW          = advapi32.NewProc("OpenServiceW")
	svc_pQueryServiceStatus    = advapi32.NewProc("QueryServiceStatus")
	svc_pQueryServiceConfigW   = advapi32.NewProc("QueryServiceConfigW")
	svc_pChangeServiceConfigW  = advapi32.NewProc("ChangeServiceConfigW")
	svc_pStartServiceW         = advapi32.NewProc("StartServiceW")
	svc_pControlService        = advapi32.NewProc("ControlService")
)

const (
	svc_SC_MANAGER_ALL_ACCESS  = 0xF003F
	svc_SERVICE_ALL_ACCESS     = 0xF01FF
	svc_SERVICE_QUERY_CONFIG   = 0x0001
	svc_SERVICE_CHANGE_CONFIG  = 0x0002
	svc_SERVICE_QUERY_STATUS   = 0x0004
	svc_SERVICE_START          = 0x0010
	svc_SERVICE_STOP           = 0x0020
	svc_SERVICE_PAUSE_CONTINUE = 0x0040
	svc_SERVICE_NO_CHANGE      = 0xFFFFFFFF

	svc_SERVICE_WIN32_OWN_PROCESS   = 0x00000010
	svc_SERVICE_WIN32_SHARE_PROCESS = 0x00000020
	svc_SERVICE_INTERACTIVE_PROCESS = 0x00000100
	svc_SERVICE_KERNEL_DRIVER       = 0x00000001
	svc_SERVICE_FILE_SYSTEM_DRIVER  = 0x00000002

	svc_SERVICE_BOOT_START   = 0x00000000
	svc_SERVICE_SYSTEM_START = 0x00000001
	svc_SERVICE_AUTO_START   = 0x00000002
	svc_SERVICE_DEMAND_START = 0x00000003
	svc_SERVICE_DISABLED     = 0x00000004

	svc_SERVICE_START_TYPE_UNKNOWN = 0xFFFFFFFF

	svc_SERVICE_STOPPED          = 0x00000001
	svc_SERVICE_START_PENDING    = 0x00000002
	svc_SERVICE_STOP_PENDING     = 0x00000003
	svc_SERVICE_RUNNING          = 0x00000004
	svc_SERVICE_CONTINUE_PENDING = 0x00000005
	svc_SERVICE_PAUSE_PENDING    = 0x00000006
	svc_SERVICE_PAUSED           = 0x00000007

	svc_SERVICE_CONTROL_STOP        = 0x00000001
	svc_SERVICE_CONTROL_PAUSE       = 0x00000002
	svc_SERVICE_CONTROL_CONTINUE    = 0x00000003
	svc_SERVICE_CONTROL_INTERROGATE = 0x00000004

	svc_SC_ENUM_PROCESS_INFO = 0
	svc_SERVICE_ACTIVE       = 0x00000001
	svc_SERVICE_INACTIVE     = 0x00000002
	svc_SERVICE_STATE_ALL    = svc_SERVICE_ACTIVE | svc_SERVICE_INACTIVE

	svc_ERROR_SERVICE_ALREADY_RUNNING = syscall.Errno(1056)
	svc_ERROR_SERVICE_NOT_ACTIVE      = syscall.Errno(1062)
	svc_ERROR_SERVICE_DISABLED        = syscall.Errno(1058)
	svc_ERROR_SERVICE_DOES_NOT_EXIST  = syscall.Errno(1060)
)

type svc_SERVICE_STATUS struct {
	ServiceType             uint32
	CurrentState            uint32
	ControlsAccepted        uint32
	Win32ExitCode           uint32
	ServiceSpecificExitCode uint32
	CheckPoint              uint32
	WaitHint                uint32
}

type svc_ENUM_SERVICE_STATUS_PROCESSW struct {
	ServiceName *uint16
	DisplayName *uint16
	ServiceStatusProcess struct {
		ServiceType             uint32
		CurrentState            uint32
		ControlsAccepted        uint32
		Win32ExitCode           uint32
		ServiceSpecificExitCode uint32
		CheckPoint              uint32
		WaitHint                uint32
		ProcessId               uint32
		ServiceFlags            uint32
	}
}

type svc_QUERY_SERVICE_CONFIGW struct {
	ServiceType      uint32
	StartType        uint32
	ErrorControl     uint32
	BinaryPathName   *uint16
	LoadOrderGroup   *uint16
	TagID            uint32
	Dependencies     *uint16
	ServiceStartName *uint16
	DisplayName      *uint16
}

func svc_openSCM() (syscall.Handle, error) {
	h, _, err := svc_pOpenSCManagerW.Call(0, 0, svc_SC_MANAGER_ALL_ACCESS)
	if h == 0 {
		return 0, fmt.Errorf("OpenSCManager: %w", err)
	}
	return syscall.Handle(h), nil
}

func svc_openService(scm syscall.Handle, name string, access uint32) (syscall.Handle, error) {
	p, err := syscall.UTF16PtrFromString(name)
	if err != nil {
		return 0, err
	}
	h, _, callErr := svc_pOpenServiceW.Call(uintptr(scm), uintptr(unsafe.Pointer(p)), uintptr(access))
	if h == 0 {
		return 0, fmt.Errorf("OpenService %q: %w", name, callErr)
	}
	return syscall.Handle(h), nil
}

func svc_closeHandle(h syscall.Handle) { svc_pCloseServiceHandle.Call(uintptr(h)) }

func svc_queryServiceStatus(h syscall.Handle) (*svc_SERVICE_STATUS, error) {
	var st svc_SERVICE_STATUS
	r, _, err := svc_pQueryServiceStatus.Call(uintptr(h), uintptr(unsafe.Pointer(&st)))
	if r == 0 {
		return nil, err
	}
	return &st, nil
}

func svc_queryServiceConfig(h syscall.Handle) (*svc_QUERY_SERVICE_CONFIGW, error) {
	var needed uint32
	svc_pQueryServiceConfigW.Call(uintptr(h), 0, 0, uintptr(unsafe.Pointer(&needed)))
	if needed == 0 {
		return nil, fmt.Errorf("QueryServiceConfig: cannot determine size")
	}
	buf := make([]byte, needed)
	r, _, err := svc_pQueryServiceConfigW.Call(uintptr(h),
		uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)),
		uintptr(unsafe.Pointer(&needed)))
	if r == 0 {
		return nil, err
	}
	return (*svc_QUERY_SERVICE_CONFIGW)(unsafe.Pointer(&buf[0])), nil
}

func svc_changeStartType(h syscall.Handle, startType uint32) error {
	r, _, err := svc_pChangeServiceConfigW.Call(uintptr(h),
		uintptr(svc_SERVICE_NO_CHANGE), uintptr(startType), uintptr(svc_SERVICE_NO_CHANGE),
		0, 0, 0, 0, 0, 0, 0)
	if r == 0 {
		return err
	}
	return nil
}

func svc_startService(h syscall.Handle) error {
	r, _, err := svc_pStartServiceW.Call(uintptr(h), 0, 0)
	if r == 0 {
		if errno, ok := err.(syscall.Errno); ok && errno == svc_ERROR_SERVICE_ALREADY_RUNNING {
			return nil
		}
		return err
	}
	return nil
}

func svc_controlService(h syscall.Handle, code uint32) error {
	var st svc_SERVICE_STATUS
	r, _, err := svc_pControlService.Call(uintptr(h), uintptr(code), uintptr(unsafe.Pointer(&st)))
	if r == 0 {
		return err
	}
	return nil
}

func svc_waitForState(h syscall.Handle, want uint32, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		st, err := svc_queryServiceStatus(h)
		if err != nil {
			return err
		}
		if st.CurrentState == want {
			return nil
		}
		if st.CurrentState == svc_SERVICE_STOPPED && want != svc_SERVICE_STOPPED {
			return fmt.Errorf("service stopped unexpectedly")
		}
		time.Sleep(200 * time.Millisecond)
	}
	return fmt.Errorf("timeout waiting for state 0x%X", want)
}

type svc_ServiceInfo struct {
	Name        string
	DisplayName string
	State       uint32
	StartType   uint32
	BinaryPath  string
	Deps        []string
}

func svc_enumServices(scm syscall.Handle) ([]svc_ServiceInfo, error) {
	var needed, returned, resume uint32
	svc_pEnumServicesStatusExW.Call(uintptr(scm), svc_SC_ENUM_PROCESS_INFO,
		svc_SERVICE_WIN32_OWN_PROCESS|svc_SERVICE_WIN32_SHARE_PROCESS|svc_SERVICE_KERNEL_DRIVER|svc_SERVICE_FILE_SYSTEM_DRIVER,
		svc_SERVICE_STATE_ALL, 0, 0,
		uintptr(unsafe.Pointer(&needed)), uintptr(unsafe.Pointer(&returned)),
		uintptr(unsafe.Pointer(&resume)), 0)
	if needed == 0 {
		return nil, fmt.Errorf("EnumServicesStatusEx: cannot determine size")
	}
	buf := make([]byte, needed+8192)
	r, _, err := svc_pEnumServicesStatusExW.Call(uintptr(scm), svc_SC_ENUM_PROCESS_INFO,
		svc_SERVICE_WIN32_OWN_PROCESS|svc_SERVICE_WIN32_SHARE_PROCESS|svc_SERVICE_KERNEL_DRIVER|svc_SERVICE_FILE_SYSTEM_DRIVER,
		svc_SERVICE_STATE_ALL, uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)),
		uintptr(unsafe.Pointer(&needed)), uintptr(unsafe.Pointer(&returned)),
		uintptr(unsafe.Pointer(&resume)), 0)
	if r == 0 {
		return nil, fmt.Errorf("EnumServicesStatusEx: %w", err)
	}
	entrySize := int(unsafe.Sizeof(svc_ENUM_SERVICE_STATUS_PROCESSW{}))
	out := make([]svc_ServiceInfo, 0, returned)
	for i := uint32(0); i < returned; i++ {
		off := int(i) * entrySize
		if off+entrySize > len(buf) {
			break
		}
		ep := (*svc_ENUM_SERVICE_STATUS_PROCESSW)(unsafe.Pointer(&buf[off]))
		out = append(out, svc_ServiceInfo{
			Name:        syscall.UTF16ToString(unsafe.Slice(ep.ServiceName, 256)),
			DisplayName: syscall.UTF16ToString(unsafe.Slice(ep.DisplayName, 256)),
			State:       ep.ServiceStatusProcess.CurrentState,
			StartType:   svc_SERVICE_START_TYPE_UNKNOWN,
		})
	}
	for i := range out {
		h, err := svc_openService(scm, out[i].Name, svc_SERVICE_QUERY_CONFIG|svc_SERVICE_QUERY_STATUS)
		if err != nil {
			continue
		}
		cfg, err := svc_queryServiceConfig(h)
		if err == nil {
			out[i].StartType = cfg.StartType
			if cfg.BinaryPathName != nil {
				out[i].BinaryPath = syscall.UTF16ToString(unsafe.Slice(cfg.BinaryPathName, 1024))
			}
			out[i].Deps = svc_splitDeps(cfg.Dependencies)
		}
		svc_closeHandle(h)
	}
	return out, nil
}

func svc_splitDeps(p *uint16) []string {
	if p == nil {
		return nil
	}
	var out []string
	cur := p
	for iter := 0; iter < 256; iter++ {
		s := syscall.UTF16ToString(unsafe.Slice(cur, 1024))
		if s == "" {
			break
		}
		out = append(out, s)
		cur = (*uint16)(unsafe.Add(unsafe.Pointer(cur), (len(s)+1)*2))
	}
	return out
}

func svc_stateName(s uint32) string {
	switch s {
	case svc_SERVICE_STOPPED:
		return "stopped"
	case svc_SERVICE_START_PENDING:
		return "start-pending"
	case svc_SERVICE_STOP_PENDING:
		return "stop-pending"
	case svc_SERVICE_RUNNING:
		return "running"
	case svc_SERVICE_CONTINUE_PENDING:
		return "continue-pending"
	case svc_SERVICE_PAUSE_PENDING:
		return "pause-pending"
	case svc_SERVICE_PAUSED:
		return "paused"
	}
	return fmt.Sprintf("0x%X", s)
}

func svc_startTypeName(s uint32) string {
	switch s {
	case svc_SERVICE_BOOT_START:
		return "boot"
	case svc_SERVICE_SYSTEM_START:
		return "system"
	case svc_SERVICE_AUTO_START:
		return "auto"
	case svc_SERVICE_DEMAND_START:
		return "manual"
	case svc_SERVICE_DISABLED:
		return "disabled"
	case svc_SERVICE_START_TYPE_UNKNOWN:
		return "?"
	}
	return fmt.Sprintf("0x%X", s)
}

func svc_stateColor(s uint32) string {
	switch s {
	case svc_SERVICE_RUNNING:
		return clrGreen
	case svc_SERVICE_STOPPED:
		return clrGray
	case svc_SERVICE_PAUSED:
		return clrYellow
	}
	return clrCyan
}

func svc_startTypeColor(s uint32) string {
	switch s {
	case svc_SERVICE_AUTO_START:
		return clrGreen
	case svc_SERVICE_DEMAND_START:
		return clrCyan
	case svc_SERVICE_DISABLED:
		return clrRed
	case svc_SERVICE_START_TYPE_UNKNOWN:
		return clrGray
	}
	return clrYellow
}

type svc_svcSnapshot struct {
	Name      string `json:"name"`
	StartType uint32 `json:"startType"`
	State     uint32 `json:"state"`
}

type svc_opRecord struct {
	Op     string            `json:"op"`
	TS     string            `json:"ts"`
	Cmd    string            `json:"cmd"`
	Code   int               `json:"code"`
	Before []svc_svcSnapshot `json:"before"`
	After  []svc_svcSnapshot `json:"after,omitempty"`
}

func svc_saveOp(idx int, rec *svc_opRecord) {
	if err := moduleSaveManifest("svc", idx, rec); err != nil {
		bugs.Add("ERR", "save op %d: %v", idx, err)
	}
}

func svc_loadOp(idx int) (*svc_opRecord, error) {
	var rec svc_opRecord
	if err := moduleLoadManifest("svc", idx, &rec); err != nil {
		return nil, err
	}
	return &rec, nil
}

func svc_resolveService(scm syscall.Handle, target string) (string, error) {
	if h, err := svc_openService(scm, target, svc_SERVICE_QUERY_STATUS); err == nil {
		svc_closeHandle(h)
		return target, nil
	}
	svcs, err := svc_enumServices(scm)
	if err != nil {
		return "", err
	}
	lower := strings.ToLower(target)
	for _, s := range svcs {
		if strings.ToLower(s.Name) == lower || strings.ToLower(s.DisplayName) == lower {
			return s.Name, nil
		}
	}
	return "", fmt.Errorf("service %q not found", target)
}

func svc_snapshotService(scm syscall.Handle, name string) (svc_svcSnapshot, error) {
	h, err := svc_openService(scm, name, svc_SERVICE_QUERY_CONFIG|svc_SERVICE_QUERY_STATUS)
	if err != nil {
		return svc_svcSnapshot{}, err
	}
	defer svc_closeHandle(h)
	cfg, err := svc_queryServiceConfig(h)
	if err != nil {
		return svc_svcSnapshot{}, err
	}
	st, err := svc_queryServiceStatus(h)
	if err != nil {
		return svc_svcSnapshot{}, err
	}
	return svc_svcSnapshot{Name: name, StartType: cfg.StartType, State: st.CurrentState}, nil
}

func svc_cmdLs(args []string) int {
	stateFilter := ""
	noDeps := false
	jsonOut := false
	var rest []string
	for _, a := range args {
		switch a {
		case "--running":
			stateFilter = "running"
		case "--stopped":
			stateFilter = "stopped"
		case "--no-deps":
			noDeps = true
		case "--json":
			jsonOut = true
		default:
			if strings.HasPrefix(a, "-") {
				fmt.Fprintf(os.Stderr, "ls: unknown option %s\n", a)
				return 2
			}
			rest = append(rest, a)
		}
	}
	scm, err := svc_openSCM()
	if err != nil {
		fmt.Fprintf(os.Stderr, "winctl svc: %v\n", err)
		return 5
	}
	defer svc_closeHandle(scm)
	svcs, err := svc_enumServices(scm)
	if err != nil {
		fmt.Fprintf(os.Stderr, "winctl svc: %v\n", err)
		return 5
	}
	if len(rest) > 0 {
		filtered := make([]svc_ServiceInfo, 0, len(svcs))
		lower := strings.ToLower(rest[0])
		for _, s := range svcs {
			if strings.Contains(strings.ToLower(s.Name), lower) ||
				strings.Contains(strings.ToLower(s.DisplayName), lower) {
				filtered = append(filtered, s)
			}
		}
		svcs = filtered
	}
	if stateFilter != "" {
		filtered := make([]svc_ServiceInfo, 0, len(svcs))
		for _, s := range svcs {
			if stateFilter == "running" && s.State == svc_SERVICE_RUNNING {
				filtered = append(filtered, s)
			}
			if stateFilter == "stopped" && s.State == svc_SERVICE_STOPPED {
				filtered = append(filtered, s)
			}
		}
		svcs = filtered
	}
	sort.Slice(svcs, func(i, j int) bool { return svcs[i].Name < svcs[j].Name })
	if jsonOut {
		out := make([]map[string]any, len(svcs))
		for i, s := range svcs {
			o := map[string]any{
				"name": s.Name, "displayName": s.DisplayName,
				"state": svc_stateName(s.State), "startType": svc_startTypeName(s.StartType),
				"binaryPath": s.BinaryPath,
			}
			if !noDeps && len(s.Deps) > 0 {
				o["dependencies"] = s.Deps
			}
			out[i] = o
		}
		b, _ := json.MarshalIndent(out, "", "  ")
		fmt.Println(string(b))
		return 0
	}
	nameW := dispWidth("NAME")
	dispW := dispWidth("DISPLAY NAME")
	stateW := dispWidth("STATE")
	startW := dispWidth("START")
	for _, s := range svcs {
		if w := dispWidth(s.Name); w > nameW {
			nameW = w
		}
		dn := s.DisplayName
		if dn == "" {
			dn = "—"
		}
		if w := dispWidth(dn); w > dispW {
			dispW = w
		}
		if w := dispWidth(svc_stateName(s.State)); w > stateW {
			stateW = w
		}
		if w := dispWidth(svc_startTypeName(s.StartType)); w > startW {
			startW = w
		}
	}
	header := padRight("NAME", nameW) + " " +
		padRight("DISPLAY NAME", dispW) + " " +
		padRight("STATE", stateW) + " " +
		padRight("START", startW) + " BINARY"
	fmt.Println(c(clrBold+clrCyan, header))
	for _, s := range svcs {
		dn := s.DisplayName
		if dn == "" {
			dn = "—"
		}
		line := padRight(s.Name, nameW) + " " +
			padRight(dn, dispW) + " " +
			c(svc_stateColor(s.State), padRight(svc_stateName(s.State), stateW)) + " " +
			c(svc_startTypeColor(s.StartType), padRight(svc_startTypeName(s.StartType), startW)) + " " +
			c(clrGray, s.BinaryPath)
		if !noDeps && len(s.Deps) > 0 {
			line += c(clrGray, "  deps="+strings.Join(s.Deps, ","))
		}
		fmt.Println(line)
	}
	fmt.Fprintf(os.Stderr, "\n%d service(s)\n", len(svcs))
	return 0
}

func svc_cmdServiceControl(args []string, action string) int {
	force := false
	var targets []string
	for _, a := range args {
		switch a {
		case "-f", "--force":
			force = true
		default:
			if strings.HasPrefix(a, "-") {
				fmt.Fprintf(os.Stderr, "%s: unknown option %s\n", action, a)
				return 2
			}
			targets = append(targets, a)
		}
	}
	if len(targets) == 0 {
		fmt.Fprintf(os.Stderr, "usage: winctl svc %s [-f] <service|displayname>...\n", action)
		return 2
	}
	scm, err := svc_openSCM()
	if err != nil {
		fmt.Fprintf(os.Stderr, "winctl svc: %v\n", err)
		return 5
	}
	defer svc_closeHandle(scm)
	names := make([]string, 0, len(targets))
	snaps := make([]svc_svcSnapshot, 0, len(targets))
	for _, t := range targets {
		name, err := svc_resolveService(scm, t)
		if err != nil {
			fmt.Fprintf(os.Stderr, "winctl svc: %v\n", err)
			return 4
		}
		snap, err := svc_snapshotService(scm, name)
		if err != nil {
			fmt.Fprintf(os.Stderr, "winctl svc: snapshot %s: %v\n", name, err)
			return 5
		}
		names = append(names, name)
		snaps = append(snaps, snap)
	}
	if dryRun {
		for i, n := range names {
			fmt.Printf("[dry-run] %s %s  (state=%s, start=%s)\n",
				action, n, svc_stateName(snaps[i].State), svc_startTypeName(snaps[i].StartType))
		}
		return 0
	}
	if len(names) > 1 && !force {
		fmt.Fprintln(os.Stderr, "about to "+action+" the following services:")
		for i, n := range names {
			fmt.Fprintf(os.Stderr, "  %-32s state=%s\n", n, svc_stateName(snaps[i].State))
		}
		if !confirm("proceed?") {
			return 1
		}
	}
	idx := auditLog("svc", buildCmdLine(os.Args), 0)
	rec := &svc_opRecord{
		Op: action, TS: time.Now().Format("2006-01-02 15:04:05"),
		Cmd: buildCmdLine(os.Args), Before: snaps,
	}
	okCount, failCount := 0, 0
	for _, n := range names {
		h, err := svc_openService(scm, n, svc_SERVICE_ALL_ACCESS)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s: %v\n", n, err)
			failCount++
			continue
		}
		var serr error
		switch action {
		case "start":
			serr = svc_startService(h)
			if serr == nil {
				serr = svc_waitForState(h, svc_SERVICE_RUNNING, 15*time.Second)
			}
		case "stop":
			serr = svc_controlService(h, svc_SERVICE_CONTROL_STOP)
			if serr == nil {
				serr = svc_waitForState(h, svc_SERVICE_STOPPED, 15*time.Second)
			} else if errno, ok := serr.(syscall.Errno); ok && errno == svc_ERROR_SERVICE_NOT_ACTIVE {
				serr = nil
			}
		case "pause":
			serr = svc_controlService(h, svc_SERVICE_CONTROL_PAUSE)
		case "resume", "continue":
			serr = svc_controlService(h, svc_SERVICE_CONTROL_CONTINUE)
		}
		svc_closeHandle(h)
		if serr != nil {
			fmt.Fprintf(os.Stderr, "%s %s: %v\n", action, n, serr)
			bugs.Add("WARN", "%s %s: %v", action, n, serr)
			failCount++
		} else {
			fmt.Printf("%s %s\n", c(clrGreen, action), c(clrCyan, n))
			okCount++
		}
	}
	var after []svc_svcSnapshot
	for _, n := range names {
		if snap, err := svc_snapshotService(scm, n); err == nil {
			after = append(after, snap)
		}
	}
	rec.After = after
	svc_saveOp(idx, rec)
	if failCount == 0 {
		return 0
	}
	if okCount == 0 {
		return 2
	}
	return 1
}

func svc_cmdStartType(args []string) int {
	force := false
	var rest []string
	for _, a := range args {
		switch a {
		case "-f", "--force":
			force = true
		default:
			if strings.HasPrefix(a, "-") {
				fmt.Fprintf(os.Stderr, "start-type: unknown option %s\n", a)
				return 2
			}
			rest = append(rest, a)
		}
	}
	if len(rest) < 2 {
		fmt.Fprintln(os.Stderr, "usage: winctl svc start-type [-f] <service>... <auto|manual|disabled>")
		return 2
	}
	levelStr := rest[len(rest)-1]
	targets := rest[:len(rest)-1]
	var newType uint32
	switch strings.ToLower(levelStr) {
	case "auto", "automatic":
		newType = svc_SERVICE_AUTO_START
	case "manual", "demand":
		newType = svc_SERVICE_DEMAND_START
	case "disabled", "disable":
		newType = svc_SERVICE_DISABLED
	default:
		fmt.Fprintf(os.Stderr, "start-type: invalid level %q (use auto|manual|disabled)\n", levelStr)
		return 2
	}
	scm, err := svc_openSCM()
	if err != nil {
		fmt.Fprintf(os.Stderr, "winctl svc: %v\n", err)
		return 5
	}
	defer svc_closeHandle(scm)
	names := make([]string, 0, len(targets))
	snaps := make([]svc_svcSnapshot, 0, len(targets))
	for _, t := range targets {
		name, err := svc_resolveService(scm, t)
		if err != nil {
			fmt.Fprintf(os.Stderr, "winctl svc: %v\n", err)
			return 4
		}
		snap, err := svc_snapshotService(scm, name)
		if err != nil {
			fmt.Fprintf(os.Stderr, "winctl svc: snapshot %s: %v\n", name, err)
			return 5
		}
		names = append(names, name)
		snaps = append(snaps, snap)
	}
	if dryRun {
		for i, n := range names {
			fmt.Printf("[dry-run] start-type %s %s -> %s\n",
				n, svc_startTypeName(snaps[i].StartType), levelStr)
		}
		return 0
	}
	if len(names) > 1 && !force {
		fmt.Fprintf(os.Stderr, "about to set start type to %q for:\n", levelStr)
		for i, n := range names {
			fmt.Fprintf(os.Stderr, "  %-32s current=%s\n", n, svc_startTypeName(snaps[i].StartType))
		}
		if !confirm("proceed?") {
			return 1
		}
	}
	idx := auditLog("svc", buildCmdLine(os.Args), 0)
	rec := &svc_opRecord{
		Op: "start-type", TS: time.Now().Format("2006-01-02 15:04:05"),
		Cmd: buildCmdLine(os.Args), Before: snaps,
	}
	okCount, failCount := 0, 0
	for _, n := range names {
		h, err := svc_openService(scm, n, svc_SERVICE_CHANGE_CONFIG|svc_SERVICE_QUERY_CONFIG)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s: %v\n", n, err)
			failCount++
			continue
		}
		err = svc_changeStartType(h, newType)
		svc_closeHandle(h)
		if err != nil {
			fmt.Fprintf(os.Stderr, "start-type %s: %v\n", n, err)
			bugs.Add("WARN", "start-type %s: %v", n, err)
			failCount++
		} else {
			fmt.Printf("%s %s -> %s\n", c(clrGreen, "start-type"), c(clrCyan, n),
				c(svc_startTypeColor(newType), levelStr))
			okCount++
		}
	}
	var after []svc_svcSnapshot
	for _, n := range names {
		if snap, err := svc_snapshotService(scm, n); err == nil {
			after = append(after, snap)
		}
	}
	rec.After = after
	svc_saveOp(idx, rec)
	if failCount == 0 {
		return 0
	}
	if okCount == 0 {
		return 2
	}
	return 1
}

func svc_summarizeOp(rec *svc_opRecord) string {
	var names []string
	for _, b := range rec.Before {
		names = append(names, b.Name)
	}
	switch rec.Op {
	case "start":
		return "-> stop " + strings.Join(names, ", ")
	case "stop":
		return "-> start " + strings.Join(names, ", ")
	case "pause":
		return "-> resume " + strings.Join(names, ", ")
	case "resume", "continue":
		return "-> pause " + strings.Join(names, ", ")
	case "start-type":
		var parts []string
		for _, b := range rec.Before {
			parts = append(parts, b.Name+"->"+svc_startTypeName(b.StartType))
		}
		return "-> restore start type: " + strings.Join(parts, ", ")
	}
	return ""
}

func svc_cmdHistory() int {
	lines, err := auditReadLines()
	if err != nil {
		fmt.Fprintf(os.Stderr, "read log %s: %v\n", globalLogPath(), err)
		return 4
	}
	if len(lines) == 0 {
		fmt.Fprintln(os.Stderr, "log is empty")
		return 0
	}
	count := 0
	for i := len(lines) - 1; i >= 0; i-- {
		m, cmd, _, ok := auditParseLine(lines[i])
		if !ok || m != "svc" {
			continue
		}
		if isHistorySelf(cmd) || !moduleManifestExists("svc", i) {
			continue
		}
		desc := ""
		if rec, e := svc_loadOp(i); e == nil {
			desc = svc_summarizeOp(rec)
		}
		count++
		fmt.Printf("[%d] %s %s\n", count, lines[i], c(clrGray, desc))
	}
	if count == 0 {
		fmt.Fprintln(os.Stderr, "no rollback-able svc operations in log")
	}
	return 0
}

func svc_cmdRollback(args []string) int {
	target := ""
	var names []string
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "-n", "--last":
			if i+1 >= len(args) {
				return 2
			}
			target = args[i+1]
			i++
		case "--service":
			if i+1 >= len(args) {
				return 2
			}
			names = append(names, args[i+1])
			i++
		default:
			if strings.HasPrefix(args[i], "-") {
				fmt.Fprintf(os.Stderr, "rollback: unknown option %s\n", args[i])
				return 2
			}
		}
	}
	lines, err := auditReadLines()
	if err != nil {
		fmt.Fprintf(os.Stderr, "read log: %v\n", err)
		return 4
	}
	type targetRec struct {
		idx int
		rec *svc_opRecord
	}
	var targets []targetRec
	if len(names) > 0 {
		want := map[string]bool{}
		for _, n := range names {
			want[strings.ToLower(strings.TrimSpace(n))] = true
		}
		for i := len(lines) - 1; i >= 0; i-- {
			m, _, _, ok := auditParseLine(lines[i])
			if !ok || m != "svc" || !moduleManifestExists("svc", i) {
				continue
			}
			rec, err := svc_loadOp(i)
			if err != nil {
				continue
			}
			match := false
			for _, b := range rec.Before {
				if want[strings.ToLower(b.Name)] {
					match = true
					break
				}
			}
			if match {
				targets = append(targets, targetRec{i, rec})
			}
		}
	} else {
		n := 1
		if target != "" {
			v, err := strconv.Atoi(target)
			if err != nil || v <= 0 {
				return 2
			}
			n = v
		}
		for i := len(lines) - 1; i >= 0 && len(targets) < n; i-- {
			m, _, _, ok := auditParseLine(lines[i])
			if !ok || m != "svc" || !moduleManifestExists("svc", i) {
				continue
			}
			rec, err := svc_loadOp(i)
			if err != nil {
				continue
			}
			targets = append(targets, targetRec{i, rec})
		}
	}
	if len(targets) == 0 {
		fmt.Fprintln(os.Stderr, "no rollback-able svc operations found")
		return 4
	}
	if dryRun {
		for k, t := range targets {
			fmt.Printf("[dry-run] step %d: %s %s\n", k+1, t.rec.Op, svc_summarizeOp(t.rec))
		}
		return 0
	}
	scm, err := svc_openSCM()
	if err != nil {
		fmt.Fprintf(os.Stderr, "winctl svc: %v\n", err)
		return 5
	}
	defer svc_closeHandle(scm)
	okCount, failCount := 0, 0
	for k, t := range targets {
		fmt.Fprintf(os.Stderr, "[rollback] step %d: %s %s\n", k+1, t.rec.Op, svc_summarizeOp(t.rec))
		if err := svc_rollbackOne(scm, t.rec); err != nil {
			fmt.Fprintf(os.Stderr, "[rollback] step %d: error: %v\n", k+1, err)
			failCount++
			continue
		}
		fmt.Fprintf(os.Stderr, "[rollback] step %d: ok\n", k+1)
		okCount++
	}
	if failCount == 0 {
		return 0
	}
	if okCount == 0 {
		return 2
	}
	return 1
}

func svc_rollbackOne(scm syscall.Handle, rec *svc_opRecord) error {
	for i := len(rec.Before) - 1; i >= 0; i-- {
		b := rec.Before[i]
		h, err := svc_openService(scm, b.Name, svc_SERVICE_ALL_ACCESS)
		if err != nil {
			return fmt.Errorf("%s: %w", b.Name, err)
		}
		if b.StartType != svc_SERVICE_START_TYPE_UNKNOWN {
			if err := svc_changeStartType(h, b.StartType); err != nil {
				svc_closeHandle(h)
				return fmt.Errorf("%s start-type: %w", b.Name, err)
			}
		}
		st, err := svc_queryServiceStatus(h)
		if err == nil {
			switch b.State {
			case svc_SERVICE_RUNNING:
				if st.CurrentState != svc_SERVICE_RUNNING {
					_ = svc_startService(h)
					_ = svc_waitForState(h, svc_SERVICE_RUNNING, 15*time.Second)
				}
			case svc_SERVICE_STOPPED:
				if st.CurrentState != svc_SERVICE_STOPPED {
					_ = svc_controlService(h, svc_SERVICE_CONTROL_STOP)
					_ = svc_waitForState(h, svc_SERVICE_STOPPED, 15*time.Second)
				}
			case svc_SERVICE_PAUSED:
				if st.CurrentState == svc_SERVICE_RUNNING {
					_ = svc_controlService(h, svc_SERVICE_CONTROL_PAUSE)
				} else if st.CurrentState == svc_SERVICE_STOPPED {
					_ = svc_startService(h)
					_ = svc_waitForState(h, svc_SERVICE_RUNNING, 15*time.Second)
					_ = svc_controlService(h, svc_SERVICE_CONTROL_PAUSE)
				}
			}
		}
		svc_closeHandle(h)
	}
	return nil
}

func svc_printHelp() {
	fmt.Printf("%s v%s (Windows)\n\n", c(clrBold+clrCyan, "winctl svc"), Version)
	fmt.Print(`USAGE
  winctl svc ls [OPTIONS] [filter]
  winctl svc start     [-f] <service|displayname>...
  winctl svc stop      [-f] <service|displayname>...
  winctl svc pause     [-f] <service|displayname>...
  winctl svc resume    [-f] <service|displayname>...
  winctl svc start-type [-f] <service>... <auto|manual|disabled>
  winctl svc --history
  winctl svc --rollback [-n N] [--service name...]

LIST
  ls <filter>          substring match on name or display name
  ls --running         only running services
  ls --stopped         only stopped services
  ls --no-deps         hide dependency column
  ls --json            JSON output

CONTROL
  -f, --force          skip confirmation when operating on more than one service

GLOBAL
  -o, --out <path>     write stdout to a file
  --dry-run            preview only
  --no-color           disable ANSI colors (also honors NO_COLOR)
  -b, --bugs           print collected errors/warnings on exit
  -h, --help           show this help
  --version            show version

All logs go to ./backup/winctl_logs.log
`)
}

func svc_main() {
	args, outPath, err := consumeGlobalFlags(os.Args[1:])
	if err != nil {
		fmt.Fprintf(os.Stderr, "winctl svc: %v\n", err)
		finalExit(2)
	}
	initColor()
	if has(args, "--version") {
		fmt.Printf("winctl svc v%s\n", Version)
		finalExit(0)
	}
	if len(args) == 0 || has(args, "-h", "--help") {
		svc_printHelp()
		finalExit(0)
	}
	if outPath != "" {
		if err := setupOutput(outPath); err != nil {
			fmt.Fprintf(os.Stderr, "winctl svc: %v\n", err)
			finalExit(2)
		}
	}
	var code int
	switch {
	case has(args, "--history"):
		code = svc_cmdHistory()
	case has(args, "--rollback"):
		code = svc_cmdRollback(stripFlags(args, "--rollback"))
	default:
		cmdIdx := -1
		for i, a := range args {
			if !strings.HasPrefix(a, "-") {
				cmdIdx = i
				break
			}
		}
		if cmdIdx < 0 {
			fmt.Fprintln(os.Stderr, "winctl svc: missing command, use -h for help")
			code = 2
			break
		}
		cmd := args[cmdIdx]
		rest := append([]string{}, args[:cmdIdx]...)
		rest = append(rest, args[cmdIdx+1:]...)
		switch cmd {
		case "ls", "list":
			code = svc_cmdLs(rest)
		case "start":
			code = svc_cmdServiceControl(rest, "start")
		case "stop":
			code = svc_cmdServiceControl(rest, "stop")
		case "pause":
			code = svc_cmdServiceControl(rest, "pause")
		case "resume", "continue":
			code = svc_cmdServiceControl(rest, "resume")
		case "start-type", "starttype":
			code = svc_cmdStartType(rest)
		default:
			fmt.Fprintf(os.Stderr, "winctl svc: unknown command %q\n", cmd)
			code = 2
		}
	}
	if !dryRun && shouldLogRun() {
		auditLog("svc", buildCmdLine(os.Args), code)
	}
	finalExit(code)
}
// ============================================================================
// sys — system repair entry point (DISM / SFC / chkdsk)
// ============================================================================
//
// Layout:
//   ./backup/winctl_logs.log            one line per sysfixctl run
//   ./backup/sys/steps/<ts>.log         full stdout/stderr of every step
//
// Read-only history: sysfixctl cannot undo repairs. --rollback prints the
// last N summary lines from the audit log.

var (
	sys_shell32 = syscall.NewLazyDLL("shell32.dll")

	sys_pGetOEMCP            = kernel32.NewProc("GetOEMCP")
	sys_pGetACP              = kernel32.NewProc("GetACP")
	sys_pMultiByteToWideChar = kernel32.NewProc("MultiByteToWideChar")
	sys_pGetCurrentProcess   = kernel32.NewProc("GetCurrentProcess")
	sys_pWaitForSingleObject = kernel32.NewProc("WaitForSingleObject")
	sys_pGetExitCodeProcess  = kernel32.NewProc("GetExitCodeProcess")

	sys_pOpenProcessToken    = advapi32.NewProc("OpenProcessToken")
	sys_pGetTokenInformation = advapi32.NewProc("GetTokenInformation")

	sys_pShellExecuteExW = sys_shell32.NewProc("ShellExecuteExW")
)

const (
	sys_TOKEN_QUERY    = 0x0008
	sys_TokenElevation = 20
	sys_INFINITE       = 0xFFFFFFFF

	sys_SEE_MASK_NOCLOSEPROCESS = 0x00000040
	sys_SEE_MASK_NOASYNC        = 0x00000100
	sys_SW_SHOWNORMAL           = 1

	sys_ERROR_CANCELLED = syscall.Errno(1223)
)

type sys_TOKEN_ELEVATION struct{ TokenIsElevated uint32 }

type sys_SHELLEXECUTEINFO struct {
	CbSize         uint32
	FMask          uint32
	Hwnd           uintptr
	LpVerb         *uint16
	LpFile         *uint16
	LpParameters   *uint16
	LpDirectory    *uint16
	NShow          int32
	HInstApp       uintptr
	LpIDList       uintptr
	LpClass        *uint16
	HkeyClass      uintptr
	DwHotKey       uint32
	HIconOrMonitor uintptr
	HProcess       uintptr
}

func sys_convertToUTF8(data []byte) []byte {
	if len(data) == 0 {
		return data
	}
	if utf8.Valid(data) {
		return data
	}
	cp, _, _ := sys_pGetOEMCP.Call()
	if cp == 0 {
		cp, _, _ = sys_pGetACP.Call()
	}
	if cp == 0 {
		return data
	}
	n, _, _ := sys_pMultiByteToWideChar.Call(
		cp, 0,
		uintptr(unsafe.Pointer(&data[0])), uintptr(len(data)),
		0, 0,
	)
	if n == 0 {
		return data
	}
	wide := make([]uint16, n)
	sys_pMultiByteToWideChar.Call(
		cp, 0,
		uintptr(unsafe.Pointer(&data[0])), uintptr(len(data)),
		uintptr(unsafe.Pointer(&wide[0])), uintptr(n),
	)
	return []byte(syscall.UTF16ToString(wide))
}

func sys_isAdmin() bool {
	h, _, _ := sys_pGetCurrentProcess.Call()
	if h == 0 {
		return false
	}
	var token syscall.Handle
	r, _, _ := sys_pOpenProcessToken.Call(h, sys_TOKEN_QUERY, uintptr(unsafe.Pointer(&token)))
	if r == 0 {
		return false
	}
	defer pCloseHandle.Call(uintptr(token))
	var elev sys_TOKEN_ELEVATION
	var size uint32
	r, _, _ = sys_pGetTokenInformation.Call(uintptr(token), sys_TokenElevation,
		uintptr(unsafe.Pointer(&elev)), uintptr(unsafe.Sizeof(elev)),
		uintptr(unsafe.Pointer(&size)))
	if r == 0 {
		return false
	}
	return elev.TokenIsElevated != 0
}

func sys_relaunchElevated(args []string) (int, error) {
	exePath, err := os.Executable()
	if err != nil {
		return 5, err
	}
	paramParts := []string{"sys"}
	for _, a := range args {
		paramParts = append(paramParts, syscall.EscapeArg(a))
	}
	paramParts = append(paramParts, "--elevated")
	verb, _ := syscall.UTF16PtrFromString("runas")
	filePtr, _ := syscall.UTF16PtrFromString(exePath)
	paramsPtr, _ := syscall.UTF16PtrFromString(strings.Join(paramParts, " "))
	var sei sys_SHELLEXECUTEINFO
	sei.CbSize = uint32(unsafe.Sizeof(sei))
	sei.FMask = sys_SEE_MASK_NOCLOSEPROCESS | sys_SEE_MASK_NOASYNC
	sei.LpVerb = verb
	sei.LpFile = filePtr
	sei.LpParameters = paramsPtr
	sei.NShow = sys_SW_SHOWNORMAL
	r, _, callErr := sys_pShellExecuteExW.Call(uintptr(unsafe.Pointer(&sei)))
	if r == 0 {
		if errno, ok := callErr.(syscall.Errno); ok && errno == sys_ERROR_CANCELLED {
			return 5, fmt.Errorf("elevation cancelled by user")
		}
		return 5, fmt.Errorf("ShellExecuteExW: %v", callErr)
	}
	if sei.HProcess == 0 {
		return 5, fmt.Errorf("ShellExecuteExW returned no process handle")
	}
	defer pCloseHandle.Call(sei.HProcess)
	sys_pWaitForSingleObject.Call(sei.HProcess, sys_INFINITE)
	var code uint32
	sys_pGetExitCodeProcess.Call(sei.HProcess, uintptr(unsafe.Pointer(&code)))
	return int(code), nil
}

type sys_fixStep struct {
	Key   string
	Flag  string
	Label string
	Exe   string
	Args  []string
	Note  string
}

func (s *sys_fixStep) cmdLine() string {
	parts := append([]string{s.Exe}, s.Args...)
	return strings.Join(parts, " ")
}

func sys_stepDISMCheck() *sys_fixStep {
	return &sys_fixStep{
		Key: "dism-check", Flag: "--dism-check", Label: "DISM /CheckHealth",
		Exe: "dism.exe", Args: []string{"/Online", "/Cleanup-Image", "/CheckHealth"},
		Note: "Quick health check of the component store",
	}
}
func sys_stepDISMScan() *sys_fixStep {
	return &sys_fixStep{
		Key: "dism-scan", Flag: "--dism-scan", Label: "DISM /ScanHealth",
		Exe: "dism.exe", Args: []string{"/Online", "/Cleanup-Image", "/ScanHealth"},
		Note: "Full scan of the component store (may take 10+ min)",
	}
}
func sys_stepDISMRestore() *sys_fixStep {
	return &sys_fixStep{
		Key: "dism-restore", Flag: "--dism-restore", Label: "DISM /RestoreHealth",
		Exe: "dism.exe", Args: []string{"/Online", "/Cleanup-Image", "/RestoreHealth"},
		Note: "Repair the component store (may take 15+ min)",
	}
}
func sys_stepSFC() *sys_fixStep {
	return &sys_fixStep{
		Key: "sfc", Flag: "--sfc", Label: "SFC /scannow",
		Exe: "sfc.exe", Args: []string{"/scannow"},
		Note: "Scan and repair system files (may take 30+ min)",
	}
}
func sys_stepChkdsk(drive string, fix bool) *sys_fixStep {
	drive = strings.ToUpper(strings.TrimSuffix(drive, ":"))
	if len(drive) != 1 || drive[0] < 'A' || drive[0] > 'Z' {
		drive = "C"
	}
	args := []string{drive + ":", "/scan"}
	label := "chkdsk " + drive + ": /scan"
	note := "Online disk scan (read-only; 1-5 min)"
	if fix {
		args = []string{drive + ":", "/f"}
		label = "chkdsk " + drive + ": /f"
		note = "Repair disk errors (requires reboot, scheduled for next boot)"
	}
	return &sys_fixStep{Key: "chkdsk", Flag: "--chkdsk", Label: label, Exe: "chkdsk.exe", Args: args, Note: note}
}

type sys_lockedWriter struct {
	mu sync.Mutex
	w  io.Writer
}

func (lw *sys_lockedWriter) Write(p []byte) (int, error) {
	lw.mu.Lock()
	defer lw.mu.Unlock()
	return lw.w.Write(p)
}

// sys_pumpOutput reads the child process's stdout/stderr in 64 KB chunks
// instead of byte-by-byte. It preserves the original semantics:
//   * '\r' in a TTY screen writes the segment and a carriage return
//     (so progress lines overwrite each other) without touching the log;
//   * '\r' in a non-TTY screen turns into a newline on both screen and log;
//   * '\n' always writes segment + newline to screen and log.
func sys_pumpOutput(r io.Reader, screen io.Writer, log io.Writer, screenIsTTY bool) {
	br := bufio.NewReaderSize(r, 64*1024)
	for {
		line, err := br.ReadBytes('\n')
		if len(line) > 0 {
			start := 0
			for i := 0; i < len(line); i++ {
				if line[i] != '\r' && line[i] != '\n' {
					continue
				}
				seg := sys_convertToUTF8(line[start:i])
				if line[i] == '\r' {
					if screenIsTTY {
						screen.Write(seg)
						screen.Write([]byte("\r"))
					} else {
						screen.Write(seg)
						screen.Write([]byte("\n"))
						if log != nil {
							log.Write(seg)
							log.Write([]byte("\n"))
						}
					}
				} else {
					screen.Write(seg)
					screen.Write([]byte("\n"))
					if log != nil {
						log.Write(seg)
						log.Write([]byte("\n"))
					}
				}
				start = i + 1
			}
			if start < len(line) {
				seg := sys_convertToUTF8(line[start:])
				if len(seg) > 0 {
					screen.Write(seg)
					if log != nil {
						log.Write(seg)
					}
				}
			}
		}
		if err != nil {
			return
		}
	}
}

func sys_runStep(s *sys_fixStep, logFile *os.File, stepNum, totalNum int) int {
	header := fmt.Sprintf("\n--- %d/%d %s ---\n", stepNum, totalNum, s.Label)
	fmt.Print(c(clrBold+clrCyan, header))
	if logFile != nil {
		_, _ = logFile.WriteString(header)
	}
	fmt.Printf("  %s\n", c(clrGray, "cmd:  "+s.cmdLine()))
	fmt.Printf("  %s\n\n", c(clrGray, "note: "+s.Note))
	if logFile != nil {
		_, _ = logFile.WriteString("cmd: " + s.cmdLine() + "\n")
		_, _ = logFile.WriteString("note: " + s.Note + "\n\n")
	}
	cmd := exec.Command(s.Exe, s.Args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		fmt.Fprintf(os.Stderr, "winctl sys: %v\n", err)
		return 5
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		fmt.Fprintf(os.Stderr, "winctl sys: %v\n", err)
		return 5
	}
	if err := cmd.Start(); err != nil {
		fmt.Fprintf(os.Stderr, "winctl sys: start %s: %v\n", s.Exe, err)
		return 5
	}
	screenIsTTY := stdoutIsTTY()
	var lw io.Writer = os.Stderr
	if logFile != nil {
		lw = &sys_lockedWriter{w: logFile}
	}
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); sys_pumpOutput(stdout, os.Stdout, lw, screenIsTTY) }()
	go func() { defer wg.Done(); sys_pumpOutput(stderr, os.Stdout, lw, screenIsTTY) }()
	wg.Wait()
	exitCode := 0
	if err := cmd.Wait(); err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			exitCode = ee.ExitCode()
		} else {
			exitCode = 5
		}
	}
	ts := time.Now().Format("2006-01-02 15:04:05")
	summary := fmt.Sprintf("[%s] [%s] [%d]\n", s.cmdLine(), ts, exitCode)
	if logFile != nil {
		_, _ = logFile.WriteString(summary)
	}
	if exitCode == 0 {
		fmt.Printf("\n%s %s\n", c(clrGreen, "done:"), s.Label)
	} else {
		fmt.Printf("\n%s %s (exit %d)\n", c(clrRed, "failed:"), s.Label, exitCode)
	}
	return exitCode
}

func sys_cmdRun(steps []*sys_fixStep, yes bool) int {
	if len(steps) == 0 {
		fmt.Fprintln(os.Stderr, "winctl sys: no steps selected")
		return 2
	}
	if !sys_isAdmin() {
		fmt.Fprintln(os.Stderr, c(clrBold+clrRed, "error: not running as administrator"))
		fmt.Fprintln(os.Stderr, "  SFC, DISM, and chkdsk require administrator privileges.")
		fmt.Fprintln(os.Stderr, "  Re-run with --elevate to relaunch with a UAC prompt.")
		return 3
	}
	fmt.Println(c(clrBold+clrCyan, "System repair plan"))
	fmt.Println()
	for i, s := range steps {
		fmt.Printf("  %d. %s\n", i+1, c(clrBold, s.Label))
		fmt.Printf("     %s\n", c(clrGray, s.cmdLine()))
		fmt.Printf("     %s\n", c(clrGray, s.Note))
	}
	fmt.Println()
	if dryRun {
		fmt.Println(c(clrYellow, "[dry-run] nothing executed"))
		return 0
	}
	if !yes && !confirm("Proceed with these steps?") {
		return 1
	}
	stepsDir := filepath.Join(moduleRoot("sys"), "steps")
	_ = os.MkdirAll(stepsDir, 0755)
	stepsLog := filepath.Join(stepsDir, time.Now().Format("20060102_150405")+".log")
	logFile, err := os.OpenFile(stepsLog, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		fmt.Fprintf(os.Stderr, "winctl sys: open step log: %v\n", err)
		return 5
	}
	defer logFile.Close()
	header := fmt.Sprintf("\n=== winctl sys session ===\nstarted: %s\nsteps: %d\nadmin: %v\n\n",
		time.Now().Format("2006-01-02 15:04:05"), len(steps), sys_isAdmin())
	_, _ = logFile.WriteString(header)
	succeeded, failed := 0, 0
	for i, s := range steps {
		if code := sys_runStep(s, logFile, i+1, len(steps)); code == 0 {
			succeeded++
		} else {
			failed++
		}
	}
	summary := fmt.Sprintf("\n=== summary: %d ok, %d failed ===\n", succeeded, failed)
	_, _ = logFile.WriteString(summary)
	fmt.Print(c(clrBold+clrCyan, summary))
	fmt.Fprintf(os.Stderr, "step log: %s\n", stepsLog)
	if failed == 0 {
		return 0
	}
	if succeeded == 0 {
		return 2
	}
	return 1
}

func sys_cmdMenu() int {
	fmt.Println()
	fmt.Println(c(clrBold+clrCyan, "================================================================"))
	fmt.Printf("%s\n", c(clrBold+clrCyan, "  winctl sys v"+Version+" - Windows System Repair"))
	fmt.Println(c(clrBold+clrCyan, "================================================================"))
	fmt.Println()
	if !sys_isAdmin() {
		fmt.Println(c(clrYellow, "  Warning: not running as administrator."))
		fmt.Println(c(clrYellow, "  SFC, DISM, and chkdsk require elevation."))
		fmt.Println()
	}
	if !stdinIsTTY() {
		fmt.Fprintln(os.Stderr, c(clrYellow, "note: stdin is not a console; menu choices are unavailable."))
		fmt.Fprintln(os.Stderr, "      use 'winctl sys run --safe|--repair|--all' instead.")
		return 2
	}
	fmt.Println("  [1] Quick check        DISM CheckHealth + ScanHealth + chkdsk /scan")
	fmt.Println("                         (read-only, 15-30 min)")
	fmt.Println("  [2] Repair             DISM RestoreHealth + SFC /scannow")
	fmt.Println("                         (modifies system files, 45-60 min)")
	fmt.Println("  [3] Complete           DISM Check -> Scan -> Restore -> SFC -> chkdsk")
	fmt.Println("                         (full repair, 60-90 min)")
	fmt.Println("  [4] Custom             Pick individual steps")
	fmt.Println("  [0] Cancel")
	fmt.Println()
	var choice string
	fmt.Print(c(clrBold, "  Choose [0-4]: "))
	fmt.Scanln(&choice)
	switch choice {
	case "1":
		return sys_runOrElevate([]*sys_fixStep{sys_stepDISMCheck(), sys_stepDISMScan(), sys_stepChkdsk("C", false)}, true)
	case "2":
		return sys_runOrElevate([]*sys_fixStep{sys_stepDISMRestore(), sys_stepSFC()}, true)
	case "3":
		return sys_runOrElevate([]*sys_fixStep{sys_stepDISMCheck(), sys_stepDISMScan(), sys_stepDISMRestore(), sys_stepSFC(), sys_stepChkdsk("C", false)}, true)
	case "4":
		return sys_cmdCustomMenu()
	case "0", "":
		fmt.Println("Cancelled.")
		return 0
	}
	fmt.Fprintf(os.Stderr, "invalid choice %q\n", choice)
	return 2
}

func sys_cmdCustomMenu() int {
	available := []*sys_fixStep{
		sys_stepDISMCheck(), sys_stepDISMScan(), sys_stepDISMRestore(), sys_stepSFC(), sys_stepChkdsk("C", false),
	}
	fmt.Println()
	for i, s := range available {
		fmt.Printf("  [%d] %-28s %s\n", i+1, s.Label, c(clrGray, s.Note))
	}
	fmt.Println()
	if !stdinIsTTY() {
		fmt.Fprintln(os.Stderr, c(clrYellow, "note: stdin is not a console; custom selection is unavailable."))
		return 2
	}
	fmt.Print(c(clrBold, "  Select steps (comma-separated, e.g. 1,2,4): "))
	var line string
	fmt.Scanln(&line)
	if strings.TrimSpace(line) == "" {
		fmt.Println("Cancelled.")
		return 0
	}
	var selected []*sys_fixStep
	for _, part := range strings.Split(line, ",") {
		part = strings.TrimSpace(part)
		n, err := strconv.Atoi(part)
		if err != nil || n < 1 || n > len(available) {
			fmt.Fprintf(os.Stderr, "invalid choice %q\n", part)
			return 2
		}
		selected = append(selected, available[n-1])
	}
	return sys_runOrElevate(selected, true)
}

func sys_runOrElevate(steps []*sys_fixStep, yes bool) int {
	if sys_isAdmin() {
		return sys_cmdRun(steps, yes)
	}
	args := []string{"run"}
	if yes {
		args = append(args, "-y")
	}
	for _, s := range steps {
		switch s.Key {
		case "dism-check":
			args = append(args, "--dism-check")
		case "dism-scan":
			args = append(args, "--dism-scan")
		case "dism-restore":
			args = append(args, "--dism-restore")
		case "sfc":
			args = append(args, "--sfc")
		case "chkdsk":
			fix := false
			for _, a := range s.Args {
				if a == "/f" {
					fix = true
					break
				}
			}
			if fix {
				args = append(args, "--chkdsk-fix")
			} else {
				args = append(args, "--chkdsk")
				if len(s.Args) > 0 {
					drive := strings.TrimSuffix(s.Args[0], ":")
					if drive != "C" {
						args = append(args, drive)
					}
				}
			}
		}
	}
	fmt.Println(c(clrYellow, "Requesting administrator privileges (UAC prompt)..."))
	code, err := sys_relaunchElevated(args)
	if err != nil {
		fmt.Fprintf(os.Stderr, "winctl sys: %v\n", err)
		return 5
	}
	return code
}

func sys_readMainLog() ([]string, error) {
	lines, err := auditReadLines()
	if err != nil {
		return nil, err
	}
	var out []string
	for _, l := range lines {
		m, _, _, ok := auditParseLine(l)
		if !ok || m != "sys" {
			continue
		}
		out = append(out, l)
	}
	return out, nil
}

func sys_cmdHistory() int {
	lines, err := sys_readMainLog()
	if err != nil {
		fmt.Fprintf(os.Stderr, "read log: %v\n", err)
		return 4
	}
	if len(lines) == 0 {
		fmt.Fprintln(os.Stderr, "no sys history entries in log")
		return 0
	}
	for i := len(lines) - 1; i >= 0; i-- {
		n := len(lines) - i
		fmt.Printf("[%d] %s\n", n, lines[i])
	}
	fmt.Fprintf(os.Stderr, "\n%d entrie(s). Log: %s\n", len(lines), globalLogPath())
	return 0
}

func sys_cmdRollback(args []string) int {
	n := 5
	for i := 0; i < len(args); i++ {
		if args[i] == "-n" || args[i] == "--last" {
			if i+1 >= len(args) {
				return 2
			}
			v, err := strconv.Atoi(args[i+1])
			if err != nil || v <= 0 {
				return 2
			}
			n = v
			i++
		}
	}
	fmt.Fprintln(os.Stderr, c(clrYellow, "note: sys cannot undo repairs."))
	fmt.Fprintln(os.Stderr, c(clrYellow, "      SFC, DISM, and chkdsk modify system files in place."))
	fmt.Fprintln(os.Stderr, c(clrYellow, "      This command only shows the most recent log entries."))
	fmt.Fprintln(os.Stderr)
	lines, err := sys_readMainLog()
	if err != nil {
		fmt.Fprintf(os.Stderr, "read log: %v\n", err)
		return 4
	}
	if len(lines) == 0 {
		fmt.Fprintln(os.Stderr, "no sys history entries in log")
		return 0
	}
	if n > len(lines) {
		n = len(lines)
	}
	for k := 0; k < n; k++ {
		idx := len(lines) - 1 - k
		fmt.Printf("[%d] %s\n", k+1, lines[idx])
	}
	fmt.Fprintf(os.Stderr, "\n%d entrie(s) shown. Log: %s\n", n, globalLogPath())
	return 0
}

func sys_parseRunArgs(args []string) (steps []*sys_fixStep, yes bool, elevate bool, err error) {
	elevate = true
	var keys []string
	chkdskDrive := "C"
	chkdskFix := false
	chkdskSpecified := false
	i := 0
	for i < len(args) {
		a := args[i]
		switch a {
		case "--all":
			keys = append(keys, "dism-check", "dism-scan", "dism-restore", "sfc", "chkdsk")
			i++
		case "--safe":
			keys = append(keys, "dism-check", "dism-scan", "chkdsk")
			i++
		case "--repair":
			keys = append(keys, "dism-restore", "sfc")
			i++
		case "--dism-check":
			keys = append(keys, "dism-check")
			i++
		case "--dism-scan":
			keys = append(keys, "dism-scan")
			i++
		case "--dism-restore":
			keys = append(keys, "dism-restore")
			i++
		case "--sfc":
			keys = append(keys, "sfc")
			i++
		case "--chkdsk":
			keys = append(keys, "chkdsk")
			chkdskSpecified = true
			i++
			if i < len(args) && !strings.HasPrefix(args[i], "-") && len(args[i]) <= 2 {
				chkdskDrive = args[i]
				i++
			}
		case "--chkdsk-fix":
			keys = append(keys, "chkdsk")
			chkdskSpecified = true
			chkdskFix = true
			i++
			if i < len(args) && !strings.HasPrefix(args[i], "-") && len(args[i]) <= 2 {
				chkdskDrive = args[i]
				i++
			}
		case "-y", "--yes":
			yes = true
			i++
		case "--elevate":
			elevate = true
			i++
		case "--no-elevate":
			elevate = false
			i++
		default:
			if strings.HasPrefix(a, "-") {
				return nil, false, false, fmt.Errorf("unknown option %s", a)
			}
			return nil, false, false, fmt.Errorf("unexpected argument %q", a)
		}
	}
	seen := map[string]bool{}
	for _, k := range keys {
		if k == "chkdsk" {
			if seen["chkdsk"] {
				continue
			}
			seen["chkdsk"] = true
			if chkdskSpecified {
				steps = append(steps, sys_stepChkdsk(chkdskDrive, chkdskFix))
			}
			continue
		}
		if seen[k] {
			continue
		}
		seen[k] = true
		switch k {
		case "dism-check":
			steps = append(steps, sys_stepDISMCheck())
		case "dism-scan":
			steps = append(steps, sys_stepDISMScan())
		case "dism-restore":
			steps = append(steps, sys_stepDISMRestore())
		case "sfc":
			steps = append(steps, sys_stepSFC())
		}
	}
	return steps, yes, elevate, nil
}

func sys_printHelp() {
	fmt.Printf("%s v%s (Windows)\n\n", c(clrBold+clrCyan, "winctl sys"), Version)
	fmt.Print(`USAGE
  winctl sys                                 interactive menu
  winctl sys menu                            interactive menu
  winctl sys run [OPTIONS]                   run repair steps
  winctl sys --history
  winctl sys --rollback [-n N]               (read-only: shows last N log entries)

RUN OPTIONS
  --safe                     DISM /CheckHealth + /ScanHealth + chkdsk /scan
  --repair                   DISM /RestoreHealth + SFC /scannow
  --all                      Check -> Scan -> Restore -> SFC -> chkdsk
  --dism-check               DISM /Online /Cleanup-Image /CheckHealth
  --dism-scan                DISM /Online /Cleanup-Image /ScanHealth
  --dism-restore             DISM /Online /Cleanup-Image /RestoreHealth
  --sfc                      SFC /scannow
  --chkdsk [drive]           chkdsk <drive>: /scan (default C)
  --chkdsk-fix [drive]       chkdsk <drive>: /f (requires reboot)
  -y, --yes                  skip the confirmation prompt
  --elevate                  relaunch with UAC (default)
  --no-elevate               do not try to relaunch; fail with exit 3

GLOBAL
  -o, --out <path>           redirect stdout to a file
  --dry-run                  print the plan without executing
  --no-color                 disable ANSI colors (also honors NO_COLOR)
  -b, --bugs                 print collected errors/warnings on exit
  -h, --help                 show this help
  --version                  show version

LAYOUT
  ./backup/winctl_logs.log            one summary line per run
  ./backup/sys/steps/<ts>.log         full stdout/stderr of every step

READ-ONLY HISTORY
  sys cannot undo a repair. --history lists every sysfixctl run in
  reverse chronological order; --rollback only prints the last N lines.

EXIT CODES
  0 success | 1 partial failure | 2 bad args | 3 not elevated
  4 not found | 5 I/O error
`)
}

func sys_main() {
	args, outPath, err := consumeGlobalFlags(os.Args[1:])
	if err != nil {
		fmt.Fprintf(os.Stderr, "winctl sys: %v\n", err)
		finalExit(2)
	}
	initColor()
	if outPath != "" {
		if err := setupOutput(outPath); err != nil {
			fmt.Fprintf(os.Stderr, "winctl sys: %v\n", err)
			finalExit(2)
		}
	}
	if has(args, "--version") {
		fmt.Printf("winctl sys v%s\n", Version)
		finalExit(0)
	}
	if has(args, "--history") {
		code := sys_cmdHistory()
		if !dryRun && shouldLogRun() {
			auditLog("sys", buildCmdLine(os.Args), code)
		}
		finalExit(code)
	}
	if has(args, "--rollback") {
		code := sys_cmdRollback(stripFlags(args, "--rollback"))
		if !dryRun && shouldLogRun() {
			auditLog("sys", buildCmdLine(os.Args), code)
		}
		finalExit(code)
	}
	if has(args, "-h", "--help") {
		sys_printHelp()
		finalExit(0)
	}
	if len(args) == 0 {
		code := sys_cmdMenu()
		if !dryRun && shouldLogRun() {
			auditLog("sys", buildCmdLine(os.Args), code)
		}
		finalExit(code)
	}
	if args[0] == "menu" {
		code := sys_cmdMenu()
		if !dryRun && shouldLogRun() {
			auditLog("sys", buildCmdLine(os.Args), code)
		}
		finalExit(code)
	}
	runArgs := args
	if args[0] == "run" {
		runArgs = args[1:]
	}
	elevated := false
	cleaned := make([]string, 0, len(runArgs))
	for _, a := range runArgs {
		if a == "--elevated" {
			elevated = true
			continue
		}
		cleaned = append(cleaned, a)
	}
	runArgs = cleaned
	steps, yes, elevate, err := sys_parseRunArgs(runArgs)
	if err != nil {
		fmt.Fprintf(os.Stderr, "winctl sys: %v\n", err)
		finalExit(2)
	}
	if len(steps) == 0 {
		fmt.Fprintln(os.Stderr, "winctl sys: no steps selected (use --all, --safe, --repair, or explicit steps)")
		finalExit(2)
	}
	if !sys_isAdmin() {
		if !elevate {
			fmt.Fprintln(os.Stderr, c(clrBold+clrRed, "error: not running as administrator"))
			fmt.Fprintln(os.Stderr, "  SFC, DISM, and chkdsk all require administrator privileges.")
			fmt.Fprintln(os.Stderr, "  Re-run with --elevate to relaunch with a UAC prompt.")
			finalExit(3)
		}
		if !elevated {
			fmt.Println(c(clrYellow, "Requesting administrator privileges (UAC prompt)..."))
			code, err := sys_relaunchElevated(os.Args[1:])
			if err != nil {
				fmt.Fprintf(os.Stderr, "winctl sys: %v\n", err)
				finalExit(5)
			}
			os.Exit(code)
		}
	}
	code := sys_cmdRun(steps, yes)
	if !dryRun && shouldLogRun() {
		auditLog("sys", buildCmdLine(os.Args), code)
	}
	finalExit(code)
}
// ============================================================================
// task — scheduled tasks + startup entries
// ============================================================================

type task_StartupLocation struct {
	Name    string
	Root    uintptr
	RootStr string
	SubKey  string
	Wow32   bool
}

var task_startupLocations = []task_StartupLocation{
	{"HKCU Run", HKCU, "HKCU", `Software\Microsoft\Windows\CurrentVersion\Run`, false},
	{"HKLM Run", HKLM, "HKLM", `Software\Microsoft\Windows\CurrentVersion\Run`, false},
	{"HKLM Wow64 Run", HKLM, "HKLM", `Software\Microsoft\Windows\CurrentVersion\Run`, true},
	{"HKCU RunOnce", HKCU, "HKCU", `Software\Microsoft\Windows\CurrentVersion\RunOnce`, false},
	{"HKLM RunOnce", HKLM, "HKLM", `Software\Microsoft\Windows\CurrentVersion\RunOnce`, false},
	{"HKLM Wow64 RunOnce", HKLM, "HKLM", `Software\Microsoft\Windows\CurrentVersion\RunOnce`, true},
	{"HKLM Winlogon UserInit", HKLM, "HKLM", `SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`, false},
	{"HKLM Winlogon Shell", HKLM, "HKLM", `SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`, false},
}

var task_startupFolders = []struct {
	Name string
	Path string
}{
	{"User Startup Folder", ""},
	{"Common Startup Folder", ""},
}

func task_resolveStartupFolders() {
	if up := os.Getenv("USERPROFILE"); up != "" {
		task_startupFolders[0].Path = filepath.Join(up, `AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup`)
	}
	if pd := os.Getenv("ProgramData"); pd != "" {
		task_startupFolders[1].Path = filepath.Join(pd, `Microsoft\Windows\Start Menu\Programs\Startup`)
	}
}

type task_StartupEntry struct {
	Location string
	Root     string
	SubKey   string
	Name     string
	Command  string
	Type     uint32
	Wow32    bool
	IsFolder bool
	FullPath string
}

func task_regCreateKey(root uintptr, subKey string, samDesired uint32) (RegKey, error) {
	subPtr, err := syscall.UTF16PtrFromString(subKey)
	if err != nil {
		return 0, err
	}
	var phk uintptr
	var disp uint32
	r, _, _ := pRegCreateKeyExW.Call(root,
		uintptr(unsafe.Pointer(subPtr)), 0, 0, 0,
		uintptr(samDesired), 0,
		uintptr(unsafe.Pointer(&phk)),
		uintptr(unsafe.Pointer(&disp)))
	if r != 0 {
		return 0, syscall.Errno(r)
	}
	return RegKey(phk), nil
}

func task_hexJoin(b []byte) string {
	parts := make([]string, len(b))
	for i, x := range b {
		parts[i] = fmt.Sprintf("%02x", x)
	}
	return strings.Join(parts, ",")
}

var task_escapeReplacer = strings.NewReplacer(`\`, `\\`, `"`, `\"`)

func task_escapeString(s string) string { return task_escapeReplacer.Replace(s) }

func task_toUTF16LEBOM(s string) []byte {
	u := utf16Encode(s)
	out := make([]byte, 2+len(u)*2)
	out[0] = 0xFF
	out[1] = 0xFE
	for i, v := range u {
		out[2+i*2] = byte(v)
		out[2+i*2+1] = byte(v >> 8)
	}
	return out
}

func task_exportRegKey(root uintptr, rootStr, subKey string, wow32 bool) (string, error) {
	access := uint32(KEY_READ | KEY_WOW64_64KEY)
	if wow32 {
		access = KEY_READ | KEY_WOW64_32KEY
	}
	k, err := regOpenKey(root, subKey, access)
	if err != nil {
		return "", err
	}
	defer regCloseKey(k)
	var buf bytes.Buffer
	buf.WriteString("Windows Registry Editor Version 5.00\r\n\r\n")
	buf.WriteString("[" + rootStr + `\` + subKey + "]\r\n")
	vals, _ := regEnumValues(k)
	for _, v := range vals {
		buf.WriteString(`"` + task_escapeString(v.Name) + `"=`)
		switch v.Type {
		case REG_SZ:
			buf.WriteString(`"` + task_escapeString(decodeRegString(v.Data)) + `"` + "\r\n")
		case REG_EXPAND_SZ:
			buf.WriteString("hex(2):" + task_hexJoin(v.Data) + "\r\n")
		default:
			buf.WriteString("hex:" + task_hexJoin(v.Data) + "\r\n")
		}
	}
	return buf.String(), nil
}

func task_decodeCP(b []byte, cp uint32) string {
	if len(b) == 0 {
		return ""
	}
	if cp == 0 {
		r, _, _ := sys_pGetACP.Call()
		cp = uint32(r)
	}
	if cp == 0 || cp == 65001 {
		return string(b)
	}
	n, _, _ := sys_pMultiByteToWideChar.Call(uintptr(cp), 0,
		uintptr(unsafe.Pointer(&b[0])), uintptr(len(b)), 0, 0)
	if n == 0 {
		return string(b)
	}
	buf := make([]uint16, n)
	n2, _, _ := sys_pMultiByteToWideChar.Call(uintptr(cp), 0,
		uintptr(unsafe.Pointer(&b[0])), uintptr(len(b)),
		uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)))
	if n2 == 0 {
		return string(b)
	}
	return string(utf16Decode(buf[:n2]))
}

func task_decodeConsoleOutput(b []byte) string {
	if len(b) == 0 {
		return ""
	}
	if len(b) >= 2 && b[0] == 0xFF && b[1] == 0xFE {
		u := make([]uint16, (len(b)-2)/2)
		for i := 0; i < len(u); i++ {
			u[i] = uint16(b[2+i*2]) | uint16(b[2+i*2+1])<<8
		}
		return string(utf16Decode(u))
	}
	if len(b) >= 3 && b[0] == 0xEF && b[1] == 0xBB && b[2] == 0xBF {
		return string(b[3:])
	}
	if len(b) >= 4 && len(b)%2 == 0 {
		oddNulls, oddTotal := 0, 0
		for i := 1; i < len(b); i += 2 {
			oddTotal++
			if b[i] == 0 {
				oddNulls++
			}
		}
		if oddTotal > 0 && oddNulls*2 >= oddTotal {
			u := make([]uint16, len(b)/2)
			for i := 0; i < len(u); i++ {
				u[i] = uint16(b[i*2]) | uint16(b[i*2+1])<<8
			}
			return string(utf16Decode(u))
		}
	}
	if utf8.Valid(b) {
		return string(b)
	}
	return task_decodeCP(b, 0)
}

func task_schtasksPath() string {
	return filepath.Join(os.Getenv("SystemRoot"), "System32", "schtasks.exe")
}

func task_runSchtasks(args ...string) (stdout, stderr string, exitCode int) {
	cmd := exec.Command(task_schtasksPath(), args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	var outBuf, errBuf bytes.Buffer
	cmd.Stdout = &outBuf
	cmd.Stderr = &errBuf
	err := cmd.Run()
	stdout = task_decodeConsoleOutput(outBuf.Bytes())
	stderr = task_decodeConsoleOutput(errBuf.Bytes())
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			exitCode = ee.ExitCode()
		} else {
			exitCode = -1
			if stderr == "" {
				stderr = err.Error()
			}
		}
	}
	return
}

type task_TaskInfo struct {
	Name        string
	Status      string
	NextRunTime string
	TaskToRun   string
}

func task_splitCSV(line string) []string {
	var out []string
	var cur strings.Builder
	inQuote := false
	for i := 0; i < len(line); i++ {
		ch := line[i]
		if ch == '"' {
			if inQuote && i+1 < len(line) && line[i+1] == '"' {
				cur.WriteByte('"')
				i++
				continue
			}
			inQuote = !inQuote
			continue
		}
		if ch == ',' && !inQuote {
			out = append(out, cur.String())
			cur.Reset()
			continue
		}
		cur.WriteByte(ch)
	}
	out = append(out, cur.String())
	return out
}

func task_listTasks() ([]task_TaskInfo, error) {
	stdout, stderr, code := task_runSchtasks("/query", "/fo", "csv", "/nh", "/v")
	if code != 0 && stdout == "" {
		return nil, fmt.Errorf("schtasks query failed: %s", strings.TrimSpace(stderr))
	}
	var tasks []task_TaskInfo
	scanner := bufio.NewScanner(strings.NewReader(stdout))
	scanner.Buffer(make([]byte, 64*1024), 4*1024*1024)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		fields := task_splitCSV(line)
		if len(fields) < 9 {
			continue
		}
		t := task_TaskInfo{Name: fields[1], NextRunTime: fields[2], Status: fields[3], TaskToRun: fields[8]}
		if t.Name == "" || strings.EqualFold(t.Name, "TaskName") || t.Name == "任务名" {
			continue
		}
		tasks = append(tasks, t)
	}
	sort.Slice(tasks, func(i, j int) bool { return tasks[i].Name < tasks[j].Name })
	return tasks, nil
}

func task_exportTaskXML(taskName string) ([]byte, error) {
	cmd := exec.Command(task_schtasksPath(), "/query", "/tn", taskName, "/xml")
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	var errBuf bytes.Buffer
	cmd.Stderr = &errBuf
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("schtasks /query /xml: %s",
			strings.TrimSpace(task_decodeConsoleOutput(errBuf.Bytes())))
	}
	return out, nil
}

func task_listStartupEntries() ([]task_StartupEntry, error) {
	task_resolveStartupFolders()
	var out []task_StartupEntry
	for _, loc := range task_startupLocations {
		access := uint32(KEY_READ | KEY_WOW64_64KEY)
		if loc.Wow32 {
			access = KEY_READ | KEY_WOW64_32KEY
		}
		k, err := regOpenKey(loc.Root, loc.SubKey, access)
		if err != nil {
			continue
		}
		vals, _ := regEnumValues(k)
		regCloseKey(k)
		for _, v := range vals {
			if loc.Name == "HKLM Winlogon UserInit" && v.Name != "UserInit" {
				continue
			}
			if loc.Name == "HKLM Winlogon Shell" && v.Name != "Shell" {
				continue
			}
			cmd := ""
			switch v.Type {
			case REG_SZ, REG_EXPAND_SZ:
				cmd = decodeRegString(v.Data)
			}
			out = append(out, task_StartupEntry{
				Location: loc.Name, Root: loc.RootStr, SubKey: loc.SubKey,
				Name: v.Name, Command: cmd, Type: v.Type, Wow32: loc.Wow32,
			})
		}
	}
	for _, folder := range task_startupFolders {
		if folder.Path == "" {
			continue
		}
		entries, err := os.ReadDir(folder.Path)
		if err != nil {
			continue
		}
		for _, e := range entries {
			if e.IsDir() {
				continue
			}
			out = append(out, task_StartupEntry{
				Location: folder.Name, Name: e.Name(),
				IsFolder: true, FullPath: filepath.Join(folder.Path, e.Name()),
			})
		}
	}
	return out, nil
}

type task_opRecord struct {
	Op              string `json:"op"`
	TS              string `json:"ts"`
	Cmd             string `json:"cmd"`
	Code            int    `json:"code"`
	TaskName        string `json:"taskName,omitempty"`
	BackupFile      string `json:"backupFile,omitempty"`
	BackupGzipped   bool   `json:"backupGzipped,omitempty"`
	ExistedBefore   bool   `json:"existedBefore"`
	StartupLocation string `json:"startupLocation,omitempty"`
	StartupRoot     string `json:"startupRoot,omitempty"`
	StartupSubKey   string `json:"startupSubKey,omitempty"`
	StartupName     string `json:"startupName,omitempty"`
	StartupWow32    bool   `json:"startupWow32,omitempty"`
	WasEnabled      *bool  `json:"wasEnabled,omitempty"`
}

func task_saveOp(idx int, rec *task_opRecord) {
	if err := moduleSaveManifest("task", idx, rec); err != nil {
		bugs.Add("ERR", "save op %d: %v", idx, err)
	}
}

func task_loadOp(idx int) (*task_opRecord, error) {
	var rec task_opRecord
	if err := moduleLoadManifest("task", idx, &rec); err != nil {
		return nil, err
	}
	return &rec, nil
}

const task_smallXMLThreshold = 8192

var task_sanitizeRe = regexp.MustCompile(`[^A-Za-z0-9._-]`)

func task_sanitizeForFilename(s string) string {
	s = strings.ReplaceAll(s, `\`, "_")
	s = task_sanitizeRe.ReplaceAllString(s, "_")
	if len(s) > 80 {
		s = s[:80]
	}
	return s
}

func task_backupTaskXML(taskName string, logIdx int) (string, bool, error) {
	xmlData, err := task_exportTaskXML(taskName)
	if err != nil {
		return "", false, err
	}
	filesDir := moduleFilesDir("task")
	base := fmt.Sprintf("%d_%s", logIdx, task_sanitizeForFilename(taskName))
	if len(xmlData) < task_smallXMLThreshold {
		rel := base + ".xml"
		full := filepath.Join(filesDir, rel)
		if err := os.MkdirAll(filesDir, 0755); err != nil {
			return "", false, err
		}
		if err := os.WriteFile(full, xmlData, 0644); err != nil {
			return "", false, err
		}
		return rel, false, nil
	}
	rel := base + ".xml.gz"
	full := filepath.Join(filesDir, rel)
	if err := os.MkdirAll(filesDir, 0755); err != nil {
		return "", false, err
	}
	f, err := os.Create(full)
	if err != nil {
		return "", false, err
	}
	gz, err := gzip.NewWriterLevel(f, gzip.BestCompression)
	if err != nil {
		f.Close()
		return "", false, err
	}
	if _, err := gz.Write(xmlData); err != nil {
		gz.Close()
		f.Close()
		return "", false, err
	}
	if err := gz.Close(); err != nil {
		f.Close()
		return "", false, err
	}
	return rel, true, f.Close()
}

func task_backupStartupKey(root uintptr, rootStr, subKey string, wow32 bool, logIdx int) (string, bool, error) {
	regText, err := task_exportRegKey(root, rootStr, subKey, wow32)
	if err != nil {
		return "", false, err
	}
	raw := task_toUTF16LEBOM(regText)
	filesDir := moduleFilesDir("task")
	base := fmt.Sprintf("%d_%s_%s", logIdx, rootStr, task_sanitizeForFilename(subKey))
	if len(raw) < task_smallXMLThreshold {
		rel := base + ".reg"
		full := filepath.Join(filesDir, rel)
		if err := os.MkdirAll(filesDir, 0755); err != nil {
			return "", false, err
		}
		if err := os.WriteFile(full, raw, 0644); err != nil {
			return "", false, err
		}
		return rel, false, nil
	}
	rel := base + ".reg.gz"
	full := filepath.Join(filesDir, rel)
	if err := os.MkdirAll(filesDir, 0755); err != nil {
		return "", false, err
	}
	f, err := os.Create(full)
	if err != nil {
		return "", false, err
	}
	gz, err := gzip.NewWriterLevel(f, gzip.BestCompression)
	if err != nil {
		f.Close()
		return "", false, err
	}
	if _, err := gz.Write(raw); err != nil {
		gz.Close()
		f.Close()
		return "", false, err
	}
	if err := gz.Close(); err != nil {
		f.Close()
		return "", false, err
	}
	return rel, true, f.Close()
}

func task_importRegFile(relPath string, gzipped bool) error {
	src := filepath.Join(moduleFilesDir("task"), relPath)
	var tmpPath string
	if gzipped {
		f, err := os.Open(src)
		if err != nil {
			return err
		}
		gz, err := gzip.NewReader(f)
		if err != nil {
			f.Close()
			return err
		}
		data, err := io.ReadAll(gz)
		gz.Close()
		f.Close()
		if err != nil {
			return err
		}
		tmp, err := os.CreateTemp("", "winctl_task_*.reg")
		if err != nil {
			return err
		}
		tmpPath = tmp.Name()
		if _, err := tmp.Write(data); err != nil {
			tmp.Close()
			os.Remove(tmpPath)
			return err
		}
		tmp.Close()
	} else {
		tmpPath = src
	}
	defer func() {
		if gzipped && tmpPath != "" {
			os.Remove(tmpPath)
		}
	}()
	cmd := exec.Command("reg", "import", tmpPath)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	var errBuf bytes.Buffer
	cmd.Stderr = &errBuf
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("reg import: %s", strings.TrimSpace(errBuf.String()))
	}
	return nil
}

func task_restoreTaskFromBackup(rec *task_opRecord) error {
	src := filepath.Join(moduleFilesDir("task"), rec.BackupFile)
	var xmlPath string
	if rec.BackupGzipped {
		f, err := os.Open(src)
		if err != nil {
			return err
		}
		gz, err := gzip.NewReader(f)
		if err != nil {
			f.Close()
			return err
		}
		data, err := io.ReadAll(gz)
		gz.Close()
		f.Close()
		if err != nil {
			return err
		}
		tmp, err := os.CreateTemp("", "winctl_task_restore_*.xml")
		if err != nil {
			return err
		}
		xmlPath = tmp.Name()
		if _, err := tmp.Write(data); err != nil {
			tmp.Close()
			os.Remove(xmlPath)
			return err
		}
		tmp.Close()
		defer os.Remove(xmlPath)
	} else {
		xmlPath = src
	}
	_, _, _ = task_runSchtasks("/delete", "/tn", rec.TaskName, "/f")
	_, stderr, code := task_runSchtasks("/create", "/tn", rec.TaskName, "/xml", xmlPath, "/f")
	if code != 0 {
		return fmt.Errorf("schtasks /create: %s", strings.TrimSpace(stderr))
	}
	return nil
}

func task_deleteStartupValue(rec *task_opRecord) error {
	var root uintptr
	switch rec.StartupRoot {
	case "HKCU":
		root = HKCU
	case "HKLM":
		root = HKLM
	default:
		return fmt.Errorf("unknown root %q", rec.StartupRoot)
	}
	access := uint32(KEY_SET_VALUE | KEY_WOW64_64KEY)
	if rec.StartupWow32 {
		access = KEY_SET_VALUE | KEY_WOW64_32KEY
	}
	k, err := regOpenKey(root, rec.StartupSubKey, access)
	if err != nil {
		if errno, ok := err.(syscall.Errno); ok && errno == ERROR_FILE_NOT_FOUND {
			return nil
		}
		return err
	}
	defer regCloseKey(k)
	return regDeleteValue(k, rec.StartupName)
}

func task_currentTaskEnabled(taskName string) bool {
	stdout, _, code := task_runSchtasks("/query", "/tn", taskName, "/fo", "list", "/v")
	if code != 0 {
		return true
	}
	for _, line := range strings.Split(stdout, "\n") {
		lower := strings.ToLower(line)
		isStatusLine := strings.Contains(lower, "status") || strings.Contains(line, "状态")
		if !isStatusLine {
			continue
		}
		if strings.Contains(lower, "disabled") || strings.Contains(line, "已禁用") {
			return false
		}
		return true
	}
	return true
}

func task_setTaskEnabled(taskName string, enable bool) error {
	verb := "/enable"
	if !enable {
		verb = "/disable"
	}
	_, stderr, code := task_runSchtasks("/change", "/tn", taskName, verb)
	if code != 0 {
		return fmt.Errorf("schtasks /change %s: %s", verb, strings.TrimSpace(stderr))
	}
	return nil
}

func task_actionName(enable bool) string {
	if enable {
		return "enable"
	}
	return "disable"
}
func task_cmdLs(args []string) int {
	filter := ""
	for _, a := range args {
		if strings.HasPrefix(a, "-") {
			fmt.Fprintf(os.Stderr, "ls: unknown option %s\n", a)
			return 2
		}
		filter = a
	}
	tasks, err := task_listTasks()
	if err != nil {
		fmt.Fprintf(os.Stderr, "winctl task: %v\n", err)
		return 5
	}
	if filter != "" {
		lower := strings.ToLower(filter)
		var filtered []task_TaskInfo
		for _, t := range tasks {
			if strings.Contains(strings.ToLower(t.Name), lower) {
				filtered = append(filtered, t)
			}
		}
		tasks = filtered
	}
	nameW := dispWidth("TASK NAME")
	statusW := dispWidth("STATUS")
	nextW := dispWidth("NEXT RUN")
	for _, t := range tasks {
		if w := dispWidth(t.Name); w > nameW {
			nameW = w
		}
		if w := dispWidth(t.Status); w > statusW {
			statusW = w
		}
		if w := dispWidth(t.NextRunTime); w > nextW {
			nextW = w
		}
	}
	header := padRight("TASK NAME", nameW) + "  " +
		padRight("STATUS", statusW) + "  " +
		padRight("NEXT RUN", nextW) + "  TASK TO RUN"
	fmt.Println(c(clrBold+clrCyan, header))
	for _, t := range tasks {
		statusColor := clrGray
		switch t.Status {
		case "Ready":
			statusColor = clrGreen
		case "Running":
			statusColor = clrYellow
		case "Disabled":
			statusColor = clrRed
		}
		fmt.Println(padRight(t.Name, nameW) + "  " +
			c(statusColor, padRight(t.Status, statusW)) + "  " +
			padRight(t.NextRunTime, nextW) + "  " +
			c(clrGray, t.TaskToRun))
	}
	fmt.Fprintf(os.Stderr, "\n%d task(s)\n", len(tasks))
	return 0
}

func task_cmdStartup(args []string) int {
	jsonOut := false
	for _, a := range args {
		if a == "--json" {
			jsonOut = true
		} else if strings.HasPrefix(a, "-") {
			fmt.Fprintf(os.Stderr, "startup: unknown option %s\n", a)
			return 2
		}
	}
	entries, err := task_listStartupEntries()
	if err != nil {
		fmt.Fprintf(os.Stderr, "winctl task: %v\n", err)
		return 5
	}
	if jsonOut {
		out := make([]map[string]string, len(entries))
		for i, e := range entries {
			m := map[string]string{"location": e.Location, "name": e.Name}
			if e.IsFolder {
				m["path"] = e.FullPath
			} else {
				m["command"] = e.Command
			}
			out[i] = m
		}
		b, _ := json.MarshalIndent(out, "", "  ")
		fmt.Println(string(b))
		return 0
	}
	locW := dispWidth("LOCATION")
	nameW := dispWidth("NAME")
	for _, e := range entries {
		if w := dispWidth(e.Location); w > locW {
			locW = w
		}
		if w := dispWidth(e.Name); w > nameW {
			nameW = w
		}
	}
	header := padRight("LOCATION", locW) + "  " + padRight("NAME", nameW) + "  COMMAND / PATH"
	fmt.Println(c(clrBold+clrCyan, header))
	for _, e := range entries {
		target := e.Command
		if e.IsFolder {
			target = e.FullPath
		}
		fmt.Println(padRight(e.Location, locW) + "  " +
			c(clrCyan, padRight(e.Name, nameW)) + "  " + c(clrGray, target))
	}
	fmt.Fprintf(os.Stderr, "\n%d startup entry(ies)\n", len(entries))
	return 0
}

func task_cmdCreate(args []string) int {
	var taskName, xmlFile, cmdRun, schedule, startTime, runAs string
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "-n", "--name":
			if i+1 >= len(args) {
				return 2
			}
			taskName = args[i+1]
			i++
		case "--xml":
			if i+1 >= len(args) {
				return 2
			}
			xmlFile = args[i+1]
			i++
		case "-c", "--command":
			if i+1 >= len(args) {
				return 2
			}
			cmdRun = args[i+1]
			i++
		case "-s", "--schedule":
			if i+1 >= len(args) {
				return 2
			}
			schedule = args[i+1]
			i++
		case "-t", "--start-time":
			if i+1 >= len(args) {
				return 2
			}
			startTime = args[i+1]
			i++
		case "-u", "--run-as":
			if i+1 >= len(args) {
				return 2
			}
			runAs = args[i+1]
			i++
		default:
			if strings.HasPrefix(args[i], "-") {
				fmt.Fprintf(os.Stderr, "create: unknown option %s\n", args[i])
				return 2
			}
		}
	}
	if taskName == "" {
		fmt.Fprintln(os.Stderr, "usage: winctl task create -n <name> (-c <cmd> -s <sched> | --xml <file>) [-t <time>] [-u <user>]")
		return 2
	}
	if xmlFile == "" && (cmdRun == "" || schedule == "") {
		fmt.Fprintln(os.Stderr, "create: -c and -s are required unless --xml is used")
		return 2
	}
	_, _, qcode := task_runSchtasks("/query", "/tn", taskName)
	existsBefore := qcode == 0
	if dryRun {
		fmt.Printf("[dry-run] create task %q (exists=%v)\n", taskName, existsBefore)
		return 0
	}
	idx := auditCount()
	backupRel := ""
	backupGz := false
	if existsBefore {
		var err error
		backupRel, backupGz, err = task_backupTaskXML(taskName, idx)
		if err != nil {
			fmt.Fprintf(os.Stderr, "winctl task: backup failed, aborting: %v\n", err)
			return 5
		}
	}
	var code int
	if xmlFile != "" {
		_, stderr, c := task_runSchtasks("/create", "/tn", taskName, "/xml", xmlFile, "/f")
		if c != 0 {
			fmt.Fprintf(os.Stderr, "winctl task: create from xml: %s\n", strings.TrimSpace(stderr))
			code = 5
		}
	} else {
		sargs := []string{"/create", "/tn", taskName, "/tr", cmdRun, "/sc", schedule}
		if startTime != "" {
			sargs = append(sargs, "/st", startTime)
		}
		if runAs != "" {
			sargs = append(sargs, "/ru", runAs)
		}
		sargs = append(sargs, "/f")
		_, stderr, c := task_runSchtasks(sargs...)
		if c != 0 {
			fmt.Fprintf(os.Stderr, "winctl task: create: %s\n", strings.TrimSpace(stderr))
			code = 5
		}
	}
	task_saveOp(idx, &task_opRecord{
		Op: "create", TS: time.Now().Format("2006-01-02 15:04:05"),
		Cmd: buildCmdLine(os.Args), TaskName: taskName,
		ExistedBefore: existsBefore, BackupFile: backupRel, BackupGzipped: backupGz,
	})
	if code == 0 {
		fmt.Printf("%s task %s\n", c(clrGreen, "created"), c(clrCyan, taskName))
	}
	return code
}

func task_cmdDelete(args []string) int {
	force := false
	var taskName string
	for _, a := range args {
		switch a {
		case "-f", "--force":
			force = true
		default:
			if strings.HasPrefix(a, "-") {
				return 2
			}
			taskName = a
		}
	}
	if taskName == "" {
		fmt.Fprintln(os.Stderr, "usage: winctl task delete <task> [-f]")
		return 2
	}
	_, _, qcode := task_runSchtasks("/query", "/tn", taskName)
	if qcode != 0 {
		fmt.Fprintf(os.Stderr, "winctl task: task %q not found\n", taskName)
		return 4
	}
	if dryRun {
		fmt.Printf("[dry-run] delete task %q\n", taskName)
		return 0
	}
	if !force && !confirm(fmt.Sprintf("delete task %q?", taskName)) {
		return 1
	}
	idx := auditCount()
	backupRel, backupGz, err := task_backupTaskXML(taskName, idx)
	if err != nil {
		fmt.Fprintf(os.Stderr, "winctl task: backup failed, aborting: %v\n", err)
		return 5
	}
	_, stderr, code := task_runSchtasks("/delete", "/tn", taskName, "/f")
	task_saveOp(idx, &task_opRecord{
		Op: "delete", TS: time.Now().Format("2006-01-02 15:04:05"),
		Cmd: buildCmdLine(os.Args), TaskName: taskName, ExistedBefore: true,
		BackupFile: backupRel, BackupGzipped: backupGz,
	})
	if code != 0 {
		fmt.Fprintf(os.Stderr, "winctl task: delete: %s\n", strings.TrimSpace(stderr))
		return 5
	}
	fmt.Printf("%s task %s\n", c(clrYellow, "deleted"), c(clrCyan, taskName))
	return 0
}

func task_cmdEnableDisable(args []string, enable bool) int {
	force := false
	var taskName string
	for _, a := range args {
		switch a {
		case "-f", "--force":
			force = true
		default:
			if strings.HasPrefix(a, "-") {
				return 2
			}
			taskName = a
		}
	}
	if taskName == "" {
		fmt.Fprintf(os.Stderr, "usage: winctl task %s <task> [-f]\n", task_actionName(enable))
		return 2
	}
	_, _, qcode := task_runSchtasks("/query", "/tn", taskName)
	if qcode != 0 {
		fmt.Fprintf(os.Stderr, "winctl task: task %q not found\n", taskName)
		return 4
	}
	if dryRun {
		wasEnabled := task_currentTaskEnabled(taskName)
		fmt.Printf("[dry-run] %s task %q (currently enabled=%v)\n", task_actionName(enable), taskName, wasEnabled)
		return 0
	}
	if !force && !confirm(fmt.Sprintf("%s task %q?", task_actionName(enable), taskName)) {
		return 1
	}
	wasEnabled := task_currentTaskEnabled(taskName)
	idx := auditCount()
	backupRel, backupGz, err := task_backupTaskXML(taskName, idx)
	if err != nil {
		fmt.Fprintf(os.Stderr, "winctl task: backup failed, aborting: %v\n", err)
		return 5
	}
	verb := "/enable"
	if !enable {
		verb = "/disable"
	}
	_, stderr, code := task_runSchtasks("/change", "/tn", taskName, verb)
	we := wasEnabled
	task_saveOp(idx, &task_opRecord{
		Op: task_actionName(enable), TS: time.Now().Format("2006-01-02 15:04:05"),
		Cmd: buildCmdLine(os.Args), TaskName: taskName, ExistedBefore: true,
		BackupFile: backupRel, BackupGzipped: backupGz, WasEnabled: &we,
	})
	if code != 0 {
		fmt.Fprintf(os.Stderr, "winctl task: %s: %s\n", task_actionName(enable), strings.TrimSpace(stderr))
		return 5
	}
	fmt.Printf("%s task %s\n", c(clrGreen, task_actionName(enable)+"d"), c(clrCyan, taskName))
	return 0
}

func task_cmdExport(args []string) int {
	var taskName, outFile string
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "-n", "--name":
			if i+1 >= len(args) {
				return 2
			}
			taskName = args[i+1]
			i++
		case "-o", "--out":
			if i+1 >= len(args) {
				return 2
			}
			outFile = args[i+1]
			i++
		default:
			if strings.HasPrefix(args[i], "-") {
				return 2
			}
			taskName = args[i]
		}
	}
	if taskName == "" {
		fmt.Fprintln(os.Stderr, "usage: winctl task export -n <task> [-o file.xml]")
		return 2
	}
	data, err := task_exportTaskXML(taskName)
	if err != nil {
		fmt.Fprintf(os.Stderr, "winctl task: %v\n", err)
		return 5
	}
	if outFile != "" {
		dir := filepath.Dir(outFile)
		if dir != "" && dir != "." {
			_ = os.MkdirAll(dir, 0755)
		}
		if err := os.WriteFile(outFile, data, 0644); err != nil {
			fmt.Fprintf(os.Stderr, "winctl task: %v\n", err)
			return 5
		}
		fmt.Fprintf(os.Stderr, "exported to %s\n", outFile)
		return 0
	}
	if _, err := os.Stdout.Write(data); err != nil {
		fmt.Fprintf(os.Stderr, "winctl task: write stdout: %v\n", err)
		return 5
	}
	return 0
}

func task_cmdImport(args []string) int {
	var taskName, xmlFile string
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "-n", "--name":
			if i+1 >= len(args) {
				return 2
			}
			taskName = args[i+1]
			i++
		default:
			if strings.HasPrefix(args[i], "-") {
				return 2
			}
			xmlFile = args[i]
		}
	}
	if taskName == "" || xmlFile == "" {
		fmt.Fprintln(os.Stderr, "usage: winctl task import -n <task> <file.xml>")
		return 2
	}
	_, _, qcode := task_runSchtasks("/query", "/tn", taskName)
	existsBefore := qcode == 0
	if dryRun {
		fmt.Printf("[dry-run] import task %q from %s (exists=%v)\n", taskName, xmlFile, existsBefore)
		return 0
	}
	idx := auditCount()
	backupRel := ""
	backupGz := false
	if existsBefore {
		var err error
		backupRel, backupGz, err = task_backupTaskXML(taskName, idx)
		if err != nil {
			fmt.Fprintf(os.Stderr, "winctl task: backup failed, aborting: %v\n", err)
			return 5
		}
	}
	_, stderr, code := task_runSchtasks("/create", "/tn", taskName, "/xml", xmlFile, "/f")
	task_saveOp(idx, &task_opRecord{
		Op: "import", TS: time.Now().Format("2006-01-02 15:04:05"),
		Cmd: buildCmdLine(os.Args), TaskName: taskName,
		ExistedBefore: existsBefore, BackupFile: backupRel, BackupGzipped: backupGz,
	})
	if code != 0 {
		fmt.Fprintf(os.Stderr, "winctl task: import: %s\n", strings.TrimSpace(stderr))
		return 5
	}
	fmt.Printf("%s task %s\n", c(clrGreen, "imported"), c(clrCyan, taskName))
	return 0
}

func task_cmdRun(args []string) int {
	var taskName string
	for _, a := range args {
		if strings.HasPrefix(a, "-") {
			return 2
		}
		taskName = a
	}
	if taskName == "" {
		fmt.Fprintln(os.Stderr, "usage: winctl task run <task>")
		return 2
	}
	if dryRun {
		fmt.Printf("[dry-run] run task %q\n", taskName)
		return 0
	}
	_, stderr, code := task_runSchtasks("/run", "/tn", taskName)
	if code != 0 {
		fmt.Fprintf(os.Stderr, "winctl task: run: %s\n", strings.TrimSpace(stderr))
		return 5
	}
	fmt.Printf("%s task %s\n", c(clrGreen, "started"), c(clrCyan, taskName))
	return 0
}

func task_cmdStartupAdd(args []string) int {
	var locName, name, command string
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "-l", "--location":
			if i+1 >= len(args) {
				return 2
			}
			locName = args[i+1]
			i++
		case "-n", "--name":
			if i+1 >= len(args) {
				return 2
			}
			name = args[i+1]
			i++
		case "-c", "--command":
			if i+1 >= len(args) {
				return 2
			}
			command = args[i+1]
			i++
		default:
			if strings.HasPrefix(args[i], "-") {
				return 2
			}
		}
	}
	if locName == "" || name == "" || command == "" {
		fmt.Fprintln(os.Stderr, "usage: winctl task startup-add -l <location> -n <name> -c <command>")
		return 2
	}
	var loc *task_StartupLocation
	for i := range task_startupLocations {
		if strings.EqualFold(task_startupLocations[i].Name, locName) {
			loc = &task_startupLocations[i]
			break
		}
	}
	if loc == nil {
		fmt.Fprintf(os.Stderr, "startup-add: unknown location %q\n", locName)
		return 2
	}
	access := uint32(KEY_READ | KEY_WOW64_64KEY)
	if loc.Wow32 {
		access = KEY_READ | KEY_WOW64_32KEY
	}
	k, err := regOpenKey(loc.Root, loc.SubKey, access)
	if err != nil {
		fmt.Fprintf(os.Stderr, "winctl task: %v\n", err)
		return 5
	}
	existing, _ := regEnumValues(k)
	regCloseKey(k)
	existsBefore := false
	for _, v := range existing {
		if strings.EqualFold(v.Name, name) {
			existsBefore = true
			break
		}
	}
	if dryRun {
		fmt.Printf("[dry-run] startup-add %s\\%s = %q (exists=%v)\n", loc.Name, name, command, existsBefore)
		return 0
	}
	idx := auditCount()
	backupRel := ""
	backupGz := false
	if existsBefore {
		backupRel, backupGz, err = task_backupStartupKey(loc.Root, loc.RootStr, loc.SubKey, loc.Wow32, idx)
		if err != nil {
			fmt.Fprintf(os.Stderr, "winctl task: backup failed, aborting: %v\n", err)
			return 5
		}
	}
	writeAccess := uint32(KEY_SET_VALUE | KEY_WOW64_64KEY)
	if loc.Wow32 {
		writeAccess = KEY_SET_VALUE | KEY_WOW64_32KEY
	}
	wk, err := task_regCreateKey(loc.Root, loc.SubKey, writeAccess)
	if err != nil {
		fmt.Fprintf(os.Stderr, "winctl task: create key: %v\n", err)
		return 5
	}
	if err := regSetValue(wk, name, REG_SZ, encodeRegString(command)); err != nil {
		regCloseKey(wk)
		fmt.Fprintf(os.Stderr, "winctl task: set value: %v\n", err)
		return 5
	}
	regCloseKey(wk)
	task_saveOp(idx, &task_opRecord{
		Op: "startup-add", TS: time.Now().Format("2006-01-02 15:04:05"),
		Cmd:             buildCmdLine(os.Args),
		StartupLocation: loc.Name, StartupRoot: loc.RootStr, StartupSubKey: loc.SubKey,
		StartupName: name, StartupWow32: loc.Wow32,
		ExistedBefore: existsBefore, BackupFile: backupRel, BackupGzipped: backupGz,
	})
	fmt.Printf("%s startup %s\\%s = %s\n", c(clrGreen, "added"), loc.Name, c(clrCyan, name), command)
	return 0
}

func task_cmdStartupDel(args []string) int {
	force := false
	var locName, name string
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "-f", "--force":
			force = true
		case "-l", "--location":
			if i+1 >= len(args) {
				return 2
			}
			locName = args[i+1]
			i++
		case "-n", "--name":
			if i+1 >= len(args) {
				return 2
			}
			name = args[i+1]
			i++
		default:
			if strings.HasPrefix(args[i], "-") {
				return 2
			}
		}
	}
	if locName == "" || name == "" {
		fmt.Fprintln(os.Stderr, "usage: winctl task startup-del -l <location> -n <name> [-f]")
		return 2
	}
	var loc *task_StartupLocation
	for i := range task_startupLocations {
		if strings.EqualFold(task_startupLocations[i].Name, locName) {
			loc = &task_startupLocations[i]
			break
		}
	}
	if loc == nil {
		fmt.Fprintf(os.Stderr, "startup-del: unknown location %q\n", locName)
		return 2
	}
	access := uint32(KEY_READ | KEY_WOW64_64KEY)
	if loc.Wow32 {
		access = KEY_READ | KEY_WOW64_32KEY
	}
	k, err := regOpenKey(loc.Root, loc.SubKey, access)
	if err != nil {
		fmt.Fprintf(os.Stderr, "winctl task: %v\n", err)
		return 5
	}
	existing, _ := regEnumValues(k)
	regCloseKey(k)
	found := false
	for _, v := range existing {
		if strings.EqualFold(v.Name, name) {
			found = true
			break
		}
	}
	if !found {
		fmt.Fprintf(os.Stderr, "winctl task: %s\\%s not found\n", loc.Name, name)
		return 4
	}
	if dryRun {
		fmt.Printf("[dry-run] startup-del %s\\%s\n", loc.Name, name)
		return 0
	}
	if !force && !confirm(fmt.Sprintf("delete startup entry %s\\%s?", loc.Name, name)) {
		return 1
	}
	idx := auditCount()
	backupRel, backupGz, err := task_backupStartupKey(loc.Root, loc.RootStr, loc.SubKey, loc.Wow32, idx)
	if err != nil {
		fmt.Fprintf(os.Stderr, "winctl task: backup failed, aborting: %v\n", err)
		return 5
	}
	writeAccess := uint32(KEY_SET_VALUE | KEY_WOW64_64KEY)
	if loc.Wow32 {
		writeAccess = KEY_SET_VALUE | KEY_WOW64_32KEY
	}
	wk, err := regOpenKey(loc.Root, loc.SubKey, writeAccess)
	if err != nil {
		fmt.Fprintf(os.Stderr, "winctl task: %v\n", err)
		return 5
	}
	defer regCloseKey(wk)
	if err := regDeleteValue(wk, name); err != nil {
		fmt.Fprintf(os.Stderr, "winctl task: delete value: %v\n", err)
		return 5
	}
	task_saveOp(idx, &task_opRecord{
		Op: "startup-del", TS: time.Now().Format("2006-01-02 15:04:05"),
		Cmd:             buildCmdLine(os.Args),
		StartupLocation: loc.Name, StartupRoot: loc.RootStr, StartupSubKey: loc.SubKey,
		StartupName: name, StartupWow32: loc.Wow32,
		ExistedBefore: true, BackupFile: backupRel, BackupGzipped: backupGz,
	})
	fmt.Printf("%s startup %s\\%s\n", c(clrYellow, "deleted"), loc.Name, c(clrCyan, name))
	return 0
}

func task_summarizeOp(rec *task_opRecord) string {
	switch rec.Op {
	case "create":
		if rec.ExistedBefore {
			return "-> restore previous task XML " + rec.TaskName
		}
		return "-> delete task " + rec.TaskName
	case "delete":
		return "-> restore task XML " + rec.TaskName
	case "enable":
		return "-> disable task " + rec.TaskName
	case "disable":
		return "-> enable task " + rec.TaskName
	case "import":
		if rec.ExistedBefore {
			return "-> restore previous task XML " + rec.TaskName
		}
		return "-> delete task " + rec.TaskName
	case "run":
		return "-> (no inverse: run is not reversible)"
	case "startup-add":
		if rec.ExistedBefore {
			return "-> restore startup key " + rec.StartupLocation
		}
		return "-> delete startup entry " + rec.StartupLocation + `\` + rec.StartupName
	case "startup-del":
		return "-> restore startup key " + rec.StartupLocation
	}
	return ""
}

func task_cmdHistory() int {
	lines, err := auditReadLines()
	if err != nil {
		fmt.Fprintf(os.Stderr, "read log: %v\n", err)
		return 4
	}
	if len(lines) == 0 {
		fmt.Fprintln(os.Stderr, "log is empty")
		return 0
	}
	count := 0
	for i := len(lines) - 1; i >= 0; i-- {
		m, cmd, _, ok := auditParseLine(lines[i])
		if !ok || m != "task" {
			continue
		}
		if isHistorySelf(cmd) || !moduleManifestExists("task", i) {
			continue
		}
		desc := ""
		if rec, e := task_loadOp(i); e == nil {
			desc = task_summarizeOp(rec)
		}
		count++
		fmt.Printf("[%d] %s %s\n", count, lines[i], c(clrGray, desc))
	}
	if count == 0 {
		fmt.Fprintln(os.Stderr, "no rollback-able task operations in log")
	}
	return 0
}

func task_cmdRollback(args []string) int {
	n := 1
	for i := 0; i < len(args); i++ {
		if args[i] == "-n" || args[i] == "--last" {
			if i+1 >= len(args) {
				return 2
			}
			v, err := strconv.Atoi(args[i+1])
			if err != nil || v <= 0 {
				return 2
			}
			n = v
			i++
		} else if strings.HasPrefix(args[i], "-") {
			return 2
		}
	}
	idxs, err := moduleTailOps("task", n)
	if err != nil || len(idxs) == 0 {
		fmt.Fprintln(os.Stderr, "no rollback-able task operations found")
		return 4
	}
	if dryRun {
		for k, i := range idxs {
			if rec, e := task_loadOp(i); e == nil {
				fmt.Printf("[dry-run] step %d: %s %s\n", k+1, rec.Op, task_summarizeOp(rec))
			}
		}
		return 0
	}
	okCount, failCount := 0, 0
	for k, i := range idxs {
		rec, err := task_loadOp(i)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[rollback] step %d: %v\n", k+1, err)
			failCount++
			continue
		}
		fmt.Fprintf(os.Stderr, "[rollback] step %d: %s %s\n", k+1, rec.Op, task_summarizeOp(rec))
		if err := task_rollbackOne(rec); err != nil {
			fmt.Fprintf(os.Stderr, "[rollback] step %d: error: %v\n", k+1, err)
			failCount++
			continue
		}
		fmt.Fprintf(os.Stderr, "[rollback] step %d: ok\n", k+1)
		okCount++
	}
	if failCount == 0 {
		return 0
	}
	if okCount == 0 {
		return 2
	}
	return 1
}

func task_rollbackOne(rec *task_opRecord) error {
	switch rec.Op {
	case "create":
		if rec.ExistedBefore {
			return task_restoreTaskFromBackup(rec)
		}
		_, _, _ = task_runSchtasks("/delete", "/tn", rec.TaskName, "/f")
		return nil
	case "delete":
		return task_restoreTaskFromBackup(rec)
	case "import":
		if rec.ExistedBefore {
			return task_restoreTaskFromBackup(rec)
		}
		_, _, _ = task_runSchtasks("/delete", "/tn", rec.TaskName, "/f")
		return nil
	case "enable":
		if rec.WasEnabled != nil && !*rec.WasEnabled {
			return task_setTaskEnabled(rec.TaskName, false)
		}
		return nil
	case "disable":
		if rec.WasEnabled != nil && *rec.WasEnabled {
			return task_setTaskEnabled(rec.TaskName, true)
		}
		return nil
	case "run":
		return fmt.Errorf("run has no inverse")
	case "startup-add":
		if rec.ExistedBefore {
			return task_importRegFile(rec.BackupFile, rec.BackupGzipped)
		}
		return task_deleteStartupValue(rec)
	case "startup-del":
		return task_importRegFile(rec.BackupFile, rec.BackupGzipped)
	}
	return fmt.Errorf("unknown op %q", rec.Op)
}

func task_printHelp() {
	fmt.Printf("%s v%s (Windows)\n\n", c(clrBold+clrCyan, "winctl task"), Version)
	fmt.Print(`USAGE
  winctl task ls [filter]
  winctl task startup [--json]
  winctl task create -n <name> (-c <cmd> -s <sched> | --xml <file>) [-t <time>] [-u <user>]
  winctl task delete <task> [-f]
  winctl task enable <task> [-f]
  winctl task disable <task> [-f]
  winctl task export -n <task> [-o file.xml]
  winctl task import -n <task> <file.xml>
  winctl task run <task>
  winctl task startup-add -l <location> -n <name> -c <command>
  winctl task startup-del -l <location> -n <name> [-f]
  winctl task --history
  winctl task --rollback [-n N]

GLOBAL
  -o, --out <path>  write stdout to a file
  --dry-run         preview only
  --no-color        disable colors
  -b, --bugs        print collected errors/warnings
  -h, --help        show this help
  --version         show version

All logs go to ./backup/winctl_logs.log
All backups go to ./backup/task/files/
`)
}

func task_main() {
	args, outPath, err := consumeGlobalFlags(os.Args[1:])
	if err != nil {
		fmt.Fprintf(os.Stderr, "winctl task: %v\n", err)
		finalExit(2)
	}
	initColor()
	if has(args, "--version") {
		fmt.Printf("winctl task v%s\n", Version)
		finalExit(0)
	}
	if len(args) == 0 || has(args, "-h", "--help") {
		task_printHelp()
		finalExit(0)
	}
	if outPath != "" {
		if err := setupOutput(outPath); err != nil {
			fmt.Fprintf(os.Stderr, "winctl task: %v\n", err)
			finalExit(2)
		}
	}
	var code int
	switch {
	case has(args, "--history"):
		code = task_cmdHistory()
	case has(args, "--rollback"):
		code = task_cmdRollback(stripFlags(args, "--rollback"))
	default:
		cmdIdx := -1
		for i, a := range args {
			if !strings.HasPrefix(a, "-") {
				cmdIdx = i
				break
			}
		}
		if cmdIdx < 0 {
			fmt.Fprintln(os.Stderr, "winctl task: missing command, use -h for help")
			code = 2
			break
		}
		cmd := args[cmdIdx]
		rest := append([]string{}, args[:cmdIdx]...)
		rest = append(rest, args[cmdIdx+1:]...)
		switch cmd {
		case "ls":
			code = task_cmdLs(rest)
		case "startup":
			code = task_cmdStartup(rest)
		case "create":
			code = task_cmdCreate(rest)
		case "delete":
			code = task_cmdDelete(rest)
		case "enable":
			code = task_cmdEnableDisable(rest, true)
		case "disable":
			code = task_cmdEnableDisable(rest, false)
		case "export":
			code = task_cmdExport(rest)
		case "import":
			code = task_cmdImport(rest)
		case "run":
			code = task_cmdRun(rest)
		case "startup-add":
			code = task_cmdStartupAdd(rest)
		case "startup-del":
			code = task_cmdStartupDel(rest)
		default:
			fmt.Fprintf(os.Stderr, "winctl task: unknown command %q\n", cmd)
			code = 2
		}
	}
	if !dryRun && shouldLogRun() {
		auditLog("task", buildCmdLine(os.Args), code)
	}
	finalExit(code)
}
// ============================================================================
// acl — file ACL / owner / DACL
// ============================================================================

var (
	acl_pGetNamedSecurityInfoW = advapi32.NewProc("GetNamedSecurityInfoW")
	acl_pSetNamedSecurityInfoW = advapi32.NewProc("SetNamedSecurityInfoW")

	acl_pGetSecurityDescriptorOwner = advapi32.NewProc("GetSecurityDescriptorOwner")
	acl_pGetSecurityDescriptorGroup = advapi32.NewProc("GetSecurityDescriptorGroup")
	acl_pGetSecurityDescriptorDacl  = advapi32.NewProc("GetSecurityDescriptorDacl")
	acl_pGetSecurityDescriptorSacl  = advapi32.NewProc("GetSecurityDescriptorSacl")

	acl_pConvertSecurityDescriptorToStringSecurityDescriptorW = advapi32.NewProc("ConvertSecurityDescriptorToStringSecurityDescriptorW")
	acl_pConvertStringSecurityDescriptorToSecurityDescriptorW = advapi32.NewProc("ConvertStringSecurityDescriptorToSecurityDescriptorW")

	acl_pSetEntriesInAclW             = advapi32.NewProc("SetEntriesInAclW")
	acl_pBuildExplicitAccessWithNameW = advapi32.NewProc("BuildExplicitAccessWithNameW")

	acl_pOpenProcessToken      = advapi32.NewProc("OpenProcessToken")
	acl_pAdjustTokenPrivileges = advapi32.NewProc("AdjustTokenPrivileges")
	acl_pLookupPrivilegeValueW = advapi32.NewProc("LookupPrivilegeValueW")

	acl_pLookupAccountNameW     = advapi32.NewProc("LookupAccountNameW")
	acl_pConvertSidToStringSidW = advapi32.NewProc("ConvertSidToStringSidW")

	acl_pGetCurrentProcess = kernel32.NewProc("GetCurrentProcess")
	acl_pLocalFree         = kernel32.NewProc("LocalFree")
)

const (
	acl_SE_FILE_OBJECT = 1

	acl_OWNER_SECURITY_INFORMATION = 0x00000001
	acl_GROUP_SECURITY_INFORMATION = 0x00000002
	acl_DACL_SECURITY_INFORMATION  = 0x00000004
	acl_SACL_SECURITY_INFORMATION  = 0x00000008

	acl_ACCESS_ALLOWED_ACE_TYPE = 0
	acl_ACCESS_DENIED_ACE_TYPE  = 1

	acl_GRANT_ACCESS = 1
	acl_DENY_ACCESS  = 3

	acl_NO_INHERITANCE        = 0x0
	acl_OBJECT_INHERIT_ACE    = 0x1
	acl_CONTAINER_INHERIT_ACE = 0x2

	acl_TOKEN_QUERY             = 0x0008
	acl_TOKEN_ADJUST_PRIVILEGES = 0x0020

	acl_SE_PRIVILEGE_ENABLED = 0x00000002

	acl_SDDL_REVISION_1 = 1

	acl_ERROR_SUCCESS          = 0
	acl_ERROR_NOT_ALL_ASSIGNED = 1300
)

type acl_LUID struct {
	LowPart  uint32
	HighPart int32
}
type acl_LUID_AND_ATTRIBUTES struct {
	Luid       acl_LUID
	Attributes uint32
}
type acl_TOKEN_PRIVILEGES struct {
	PrivilegeCount uint32
	Privileges     [1]acl_LUID_AND_ATTRIBUTES
}
type acl_TRUSTEEW struct {
	pMultipleTrustee         uintptr
	MultipleTrusteeOperation uint32
	TrusteeForm              uint32
	TrusteeType              uint32
	ptstrName                *uint16
}
type acl_EXPLICIT_ACCESSW struct {
	grfAccessPermissions uint32
	grfAccessMode        uint32
	grfInheritance       uint32
	Trustee              acl_TRUSTEEW
}
type acl_ACL struct {
	AclRevision byte
	Sbz1        byte
	AclSize     uint16
	AceCount    uint16
	Sbz2        uint16
}
type acl_SECURITY_DESCRIPTOR struct {
	Revision byte
	Sbz1     byte
	Control  uint16
	Owner    uintptr
	Group    uintptr
	Sacl     uintptr
	Dacl     uintptr
}
type acl_ACEHeader struct {
	AceType  byte
	AceFlags byte
	AceSize  uint16
}
type acl_ACCESS_ALLOWED_ACE struct {
	Header   acl_ACEHeader
	Mask     uint32
	SidStart uint32
}

func acl_sddlFromSecurityDescriptor(sd uintptr, secInfo uint32) (string, error) {
	if sd == 0 {
		return "", fmt.Errorf("nil security descriptor")
	}
	var strPtr *uint16
	var strLen uint32
	r, _, callErr := acl_pConvertSecurityDescriptorToStringSecurityDescriptorW.Call(
		sd, uintptr(acl_SDDL_REVISION_1), uintptr(secInfo),
		uintptr(unsafe.Pointer(&strPtr)), uintptr(unsafe.Pointer(&strLen)))
	if r == 0 {
		return "", fmt.Errorf("ConvertSecurityDescriptorToString: %w", callErr)
	}
	if strPtr == nil {
		return "", fmt.Errorf("ConvertSecurityDescriptorToString returned nil")
	}
	defer acl_pLocalFree.Call(uintptr(unsafe.Pointer(strPtr)))
	return syscall.UTF16ToString(unsafe.Slice(strPtr, strLen)), nil
}

func acl_securityDescriptorFromSDDL(sddl string) (*acl_SECURITY_DESCRIPTOR, uintptr, error) {
	ptr, err := syscall.UTF16PtrFromString(sddl)
	if err != nil {
		return nil, 0, err
	}
	var sd *acl_SECURITY_DESCRIPTOR
	var sdLen uint32
	r, _, callErr := acl_pConvertStringSecurityDescriptorToSecurityDescriptorW.Call(
		uintptr(unsafe.Pointer(ptr)), uintptr(acl_SDDL_REVISION_1),
		uintptr(unsafe.Pointer(&sd)), uintptr(unsafe.Pointer(&sdLen)))
	if r == 0 {
		return nil, 0, fmt.Errorf("ConvertStringSecurityDescriptor: %w", callErr)
	}
	return sd, uintptr(unsafe.Pointer(sd)), nil
}

type acl_secInfoResult struct {
	sdPtr uintptr
	owner uintptr
	group uintptr
	dacl  uintptr
	sacl  uintptr
}

func (r *acl_secInfoResult) free() {
	if r != nil && r.sdPtr != 0 {
		acl_pLocalFree.Call(r.sdPtr)
		r.sdPtr = 0
	}
}

func acl_getSecurityInfo(path string, secInfo uint32) (*acl_secInfoResult, error) {
	pathPtr, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	var sd uintptr
	var owner, group, dacl, sacl uintptr
	r, _, _ := acl_pGetNamedSecurityInfoW.Call(
		uintptr(unsafe.Pointer(pathPtr)), uintptr(acl_SE_FILE_OBJECT), uintptr(secInfo),
		uintptr(unsafe.Pointer(&owner)), uintptr(unsafe.Pointer(&group)),
		uintptr(unsafe.Pointer(&dacl)), uintptr(unsafe.Pointer(&sacl)),
		uintptr(unsafe.Pointer(&sd)))
	if code := uint32(r); code != acl_ERROR_SUCCESS {
		return nil, fmt.Errorf("GetNamedSecurityInfo(%s): %w", path, syscall.Errno(code))
	}
	return &acl_secInfoResult{sdPtr: sd, owner: owner, group: group, dacl: dacl, sacl: sacl}, nil
}

func acl_setSecurityInfoRaw(path string, secInfo uint32, owner, group, dacl, sacl uintptr) error {
	pathPtr, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	r, _, _ := acl_pSetNamedSecurityInfoW.Call(
		uintptr(unsafe.Pointer(pathPtr)), uintptr(acl_SE_FILE_OBJECT), uintptr(secInfo),
		owner, group, dacl, sacl)
	if code := uint32(r); code != acl_ERROR_SUCCESS {
		return fmt.Errorf("SetNamedSecurityInfo(%s): %w", path, syscall.Errno(code))
	}
	return nil
}

func acl_extractComponents(sd *acl_SECURITY_DESCRIPTOR) (owner, group, dacl, sacl uintptr, secInfo uint32) {
	var present, defaulted uint32
	if sd == nil {
		return
	}
	base := uintptr(unsafe.Pointer(sd))
	var p uintptr
	if r, _, _ := acl_pGetSecurityDescriptorOwner.Call(base,
		uintptr(unsafe.Pointer(&p)), uintptr(unsafe.Pointer(&defaulted))); r != 0 && p != 0 {
		owner = p
		secInfo |= acl_OWNER_SECURITY_INFORMATION
	}
	if r, _, _ := acl_pGetSecurityDescriptorGroup.Call(base,
		uintptr(unsafe.Pointer(&p)), uintptr(unsafe.Pointer(&defaulted))); r != 0 && p != 0 {
		group = p
		secInfo |= acl_GROUP_SECURITY_INFORMATION
	}
	if r, _, _ := acl_pGetSecurityDescriptorDacl.Call(base,
		uintptr(unsafe.Pointer(&present)), uintptr(unsafe.Pointer(&p)),
		uintptr(unsafe.Pointer(&defaulted))); r != 0 && present != 0 && p != 0 {
		dacl = p
		secInfo |= acl_DACL_SECURITY_INFORMATION
	}
	if r, _, _ := acl_pGetSecurityDescriptorSacl.Call(base,
		uintptr(unsafe.Pointer(&present)), uintptr(unsafe.Pointer(&p)),
		uintptr(unsafe.Pointer(&defaulted))); r != 0 && present != 0 && p != 0 {
		sacl = p
		secInfo |= acl_SACL_SECURITY_INFORMATION
	}
	return
}

func acl_addACE(path, trustee, access string, deny bool, inheritFlags uint32) error {
	info, err := acl_getSecurityInfo(path, acl_DACL_SECURITY_INFORMATION)
	if err != nil {
		return err
	}
	defer info.free()
	trusteePtr, err := syscall.UTF16PtrFromString(trustee)
	if err != nil {
		return err
	}
	accessMask := acl_parseAccessMask(access)
	accessMode := uint32(acl_GRANT_ACCESS)
	if deny {
		accessMode = acl_DENY_ACCESS
	}
	var ea acl_EXPLICIT_ACCESSW
	acl_pBuildExplicitAccessWithNameW.Call(
		uintptr(unsafe.Pointer(&ea)), uintptr(unsafe.Pointer(trusteePtr)),
		uintptr(accessMask), uintptr(accessMode), uintptr(inheritFlags))
	var newAcl *acl_ACL
	r, _, _ := acl_pSetEntriesInAclW.Call(1,
		uintptr(unsafe.Pointer(&ea)), info.dacl,
		uintptr(unsafe.Pointer(&newAcl)))
	if code := uint32(r); code != acl_ERROR_SUCCESS {
		return fmt.Errorf("SetEntriesInAcl: %w", syscall.Errno(code))
	}
	if newAcl != nil {
		defer acl_pLocalFree.Call(uintptr(unsafe.Pointer(newAcl)))
	}
	return acl_setSecurityInfoRaw(path, acl_DACL_SECURITY_INFORMATION,
		0, 0, uintptr(unsafe.Pointer(newAcl)), 0)
}

func acl_parseAccessMask(s string) uint32 {
	switch strings.ToLower(s) {
	case "read", "r":
		return 0x120089
	case "write", "w":
		return 0x120116
	case "execute", "x":
		return 0x1200A0
	case "full", "f":
		return 0x1F01FF
	}
	if v, err := strconv.ParseUint(s, 0, 32); err == nil {
		return uint32(v)
	}
	return 0x120089
}

func acl_enablePrivilege(name string) (bool, error) {
	h, _, _ := acl_pGetCurrentProcess.Call()
	if h == 0 {
		return false, fmt.Errorf("GetCurrentProcess failed")
	}
	var token syscall.Handle
	r, _, callErr := acl_pOpenProcessToken.Call(h,
		uintptr(acl_TOKEN_QUERY|acl_TOKEN_ADJUST_PRIVILEGES),
		uintptr(unsafe.Pointer(&token)))
	if r == 0 {
		return false, fmt.Errorf("OpenProcessToken: %w", callErr)
	}
	defer pCloseHandle.Call(uintptr(token))
	var luid acl_LUID
	namePtr, err := syscall.UTF16PtrFromString(name)
	if err != nil {
		return false, err
	}
	r, _, callErr = acl_pLookupPrivilegeValueW.Call(0,
		uintptr(unsafe.Pointer(namePtr)), uintptr(unsafe.Pointer(&luid)))
	if r == 0 {
		return false, fmt.Errorf("LookupPrivilegeValue(%s): %w", name, callErr)
	}
	tp := acl_TOKEN_PRIVILEGES{
		PrivilegeCount: 1,
		Privileges: [1]acl_LUID_AND_ATTRIBUTES{
			{Luid: luid, Attributes: acl_SE_PRIVILEGE_ENABLED},
		},
	}
	var prevSize uint32
	r, _, callErr = acl_pAdjustTokenPrivileges.Call(
		uintptr(token), 0, uintptr(unsafe.Pointer(&tp)), 0, 0,
		uintptr(unsafe.Pointer(&prevSize)))
	if r == 0 {
		return false, fmt.Errorf("AdjustTokenPrivileges: %w", callErr)
	}
	if errno, ok := callErr.(syscall.Errno); ok && errno == acl_ERROR_NOT_ALL_ASSIGNED {
		return false, fmt.Errorf("privilege %s not held by current token (run elevated)", name)
	}
	return true, nil
}

func acl_ensurePrivileges() {
	for _, priv := range []string{"SeRestorePrivilege", "SeTakeOwnershipPrivilege", "SeSecurityPrivilege"} {
		if _, err := acl_enablePrivilege(priv); err != nil {
			bugs.Add("WARN", "enable %s: %v", priv, err)
		}
	}
}

const acl_smallThreshold = 8192

var acl_sanitizeRe = regexp.MustCompile(`[^A-Za-z0-9._-]`)

func acl_sanitize(s string) string {
	s = strings.ReplaceAll(s, `\`, "_")
	s = strings.ReplaceAll(s, `:`, "_")
	s = acl_sanitizeRe.ReplaceAllString(s, "_")
	if len(s) > 80 {
		s = s[:80]
	}
	return s
}

func acl_backupSDDL(path string, logIdx int) (string, bool, error) {
	baseInfo := uint32(acl_OWNER_SECURITY_INFORMATION | acl_GROUP_SECURITY_INFORMATION | acl_DACL_SECURITY_INFORMATION)
	info, err := acl_getSecurityInfo(path, baseInfo)
	if err != nil {
		return "", false, err
	}
	defer info.free()
	sddl, err := acl_sddlFromSecurityDescriptor(info.sdPtr, baseInfo)
	if err != nil {
		return "", false, err
	}
	filesDir := moduleFilesDir("acl")
	base := fmt.Sprintf("%d_%s", logIdx, acl_sanitize(path))
	if len(sddl) < acl_smallThreshold {
		rel := base + ".sddl"
		full := filepath.Join(filesDir, rel)
		if err := os.MkdirAll(filesDir, 0755); err != nil {
			return "", false, err
		}
		if err := os.WriteFile(full, []byte(sddl), 0644); err != nil {
			return "", false, err
		}
		return rel, false, nil
	}
	rel := base + ".sddl.gz"
	full := filepath.Join(filesDir, rel)
	if err := os.MkdirAll(filesDir, 0755); err != nil {
		return "", false, err
	}
	f, err := os.Create(full)
	if err != nil {
		return "", false, err
	}
	gz, err := gzip.NewWriterLevel(f, gzip.BestCompression)
	if err != nil {
		f.Close()
		return "", false, err
	}
	if _, err := gz.Write([]byte(sddl)); err != nil {
		gz.Close()
		f.Close()
		return "", false, err
	}
	if err := gz.Close(); err != nil {
		f.Close()
		return "", false, err
	}
	return rel, true, f.Close()
}

func acl_restoreSDDL(relPath string, gzipped bool, path string) error {
	full := filepath.Join(moduleFilesDir("acl"), relPath)
	var data []byte
	var err error
	if gzipped {
		f, ferr := os.Open(full)
		if ferr != nil {
			return ferr
		}
		defer f.Close()
		gz, gerr := gzip.NewReader(f)
		if gerr != nil {
			return gerr
		}
		defer gz.Close()
		data, err = io.ReadAll(gz)
	} else {
		data, err = os.ReadFile(full)
	}
	if err != nil {
		return err
	}
	return acl_applySDDL(string(data), path)
}

func acl_applySDDL(sddl, path string) error {
	sd, sdPtr, err := acl_securityDescriptorFromSDDL(sddl)
	if err != nil {
		return err
	}
	defer acl_pLocalFree.Call(sdPtr)
	owner, group, dacl, sacl, secInfo := acl_extractComponents(sd)
	if secInfo == 0 {
		return fmt.Errorf("SDDL contains no owner, group, DACL or SACL")
	}
	return acl_setSecurityInfoRaw(path, secInfo, owner, group, dacl, sacl)
}

type acl_opRecord struct {
	Op      string `json:"op"`
	TS      string `json:"ts"`
	Cmd     string `json:"cmd"`
	Code    int    `json:"code"`
	Path    string `json:"path"`
	OldSDDL string `json:"oldSddl"`
	NewSDDL string `json:"newSddl"`
	Backup  string `json:"backup,omitempty"`
}

func acl_saveOp(idx int, rec *acl_opRecord) {
	if err := moduleSaveManifest("acl", idx, rec); err != nil {
		bugs.Add("ERR", "save op %d: %v", idx, err)
	}
}

func acl_loadOp(idx int) (*acl_opRecord, error) {
	var rec acl_opRecord
	if err := moduleLoadManifest("acl", idx, &rec); err != nil {
		return nil, err
	}
	return &rec, nil
}

func acl_cmdShow(path string, jsonOut bool) int {
	secInfo := uint32(acl_OWNER_SECURITY_INFORMATION | acl_GROUP_SECURITY_INFORMATION | acl_DACL_SECURITY_INFORMATION)
	info, err := acl_getSecurityInfo(path, secInfo)
	if err != nil {
		fmt.Fprintf(os.Stderr, "winctl acl: %v\n", err)
		return 5
	}
	defer info.free()
	if jsonOut {
		sddl, _ := acl_sddlFromSecurityDescriptor(info.sdPtr, secInfo)
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(map[string]string{"path": path, "sddl": sddl}); err != nil {
			fmt.Fprintf(os.Stderr, "winctl acl: json encode: %v\n", err)
			return 5
		}
		return 0
	}
	fmt.Printf("%s %s\n\n", c(clrCyan, "Path:"), path)
	if sddl, err := acl_sddlFromSecurityDescriptor(info.sdPtr, secInfo); err == nil {
		fmt.Printf("%s\n%s\n", c(clrCyan, "SDDL:"), c(clrGray, sddl))
	}
	if info.dacl != 0 {
		fmt.Println()
		fmt.Println(c(clrBold+clrCyan, "DACL entries"))
		acl_printACEs((*acl_ACL)(unsafe.Pointer(info.dacl)))
	}
	return 0
}

func acl_printACEs(acl *acl_ACL) {
	if acl == nil {
		fmt.Println(c(clrGray, "  (no DACL)"))
		return
	}
	count := int(acl.AceCount)
	if count == 0 {
		fmt.Println(c(clrGray, "  (empty DACL)"))
		return
	}
	base := uintptr(unsafe.Pointer(acl)) + unsafe.Sizeof(*acl)
	for i := 0; i < count; i++ {
		header := (*acl_ACEHeader)(unsafe.Pointer(base))
		if header.AceSize == 0 {
			break
		}
		switch header.AceType {
		case acl_ACCESS_ALLOWED_ACE_TYPE:
			mask := (*acl_ACCESS_ALLOWED_ACE)(unsafe.Pointer(base)).Mask
			fmt.Printf("  %s allow mask=0x%08X flags=0x%X\n", c(clrGreen, "ACE"), mask, header.AceFlags)
		case acl_ACCESS_DENIED_ACE_TYPE:
			mask := (*acl_ACCESS_ALLOWED_ACE)(unsafe.Pointer(base)).Mask
			fmt.Printf("  %s deny  mask=0x%08X flags=0x%X\n", c(clrRed, "ACE"), mask, header.AceFlags)
		default:
			fmt.Printf("  ACE type=%d flags=0x%X size=%d\n", header.AceType, header.AceFlags, header.AceSize)
		}
		base += uintptr(header.AceSize)
	}
}

func acl_cmdSetOwner(path, owner string, yes bool) int {
	if !yes && !confirm(fmt.Sprintf("change owner of %s to %s?", path, owner)) {
		return 1
	}
	idx := auditCount()
	backupRel, _, err := acl_backupSDDL(path, idx)
	if err != nil {
		fmt.Fprintf(os.Stderr, "winctl acl: backup failed, aborting: %v\n", err)
		return 5
	}
	acl_ensurePrivileges()
	ownerSID, err := acl_lookupAccountSID(owner)
	if err != nil {
		fmt.Fprintf(os.Stderr, "winctl acl: resolve owner %q: %v\n", owner, err)
		return 5
	}
	fullInfo := uint32(acl_OWNER_SECURITY_INFORMATION | acl_GROUP_SECURITY_INFORMATION | acl_DACL_SECURITY_INFORMATION)
	info, err := acl_getSecurityInfo(path, fullInfo)
	if err != nil {
		fmt.Fprintf(os.Stderr, "winctl acl: %v\n", err)
		return 5
	}
	oldSDDL, _ := acl_sddlFromSecurityDescriptor(info.sdPtr, fullInfo)
	info.free()
	newSDDL := acl_replaceOwnerInSDDL(oldSDDL, ownerSID)
	if newSDDL == "" {
		fmt.Fprintf(os.Stderr, "winctl acl: could not build new SDDL for owner change\n")
		return 5
	}
	if err := acl_applySDDL(newSDDL, path); err != nil {
		fmt.Fprintf(os.Stderr, "winctl acl: %v\n", err)
		return 5
	}
	acl_saveOp(idx, &acl_opRecord{
		Op: "set-owner", TS: time.Now().Format("2006-01-02 15:04:05"),
		Cmd: buildCmdLine(os.Args), Path: path,
		OldSDDL: oldSDDL, NewSDDL: newSDDL, Backup: backupRel,
	})
	fmt.Printf("%s owner of %s -> %s (%s)\n", c(clrGreen, "changed"), path, owner, ownerSID)
	return 0
}

var acl_ownerRe = regexp.MustCompile(`O:(?:S-[\d-]+|[A-Z]{2,})`)

func acl_replaceOwnerInSDDL(sddl, ownerSID string) string {
	if sddl == "" {
		return "O:" + ownerSID
	}
	if acl_ownerRe.MatchString(sddl) {
		return acl_ownerRe.ReplaceAllString(sddl, "O:"+ownerSID)
	}
	return "O:" + ownerSID + sddl
}

func acl_lookupAccountSID(name string) (string, error) {
	namePtr, err := syscall.UTF16PtrFromString(name)
	if err != nil {
		return "", err
	}
	var sidSize, domainSize uint32
	acl_pLookupAccountNameW.Call(0, uintptr(unsafe.Pointer(namePtr)), 0,
		uintptr(unsafe.Pointer(&sidSize)), 0,
		uintptr(unsafe.Pointer(&domainSize)), 0, 0)
	if sidSize == 0 {
		return "", fmt.Errorf("cannot determine SID size for %q", name)
	}
	sidBuf := make([]byte, sidSize)
	if domainSize == 0 {
		domainSize = 1
	}
	domainBuf := make([]uint16, domainSize)
	var use uint32
	r, _, callErr := acl_pLookupAccountNameW.Call(0,
		uintptr(unsafe.Pointer(namePtr)),
		uintptr(unsafe.Pointer(&sidBuf[0])), uintptr(unsafe.Pointer(&sidSize)),
		uintptr(unsafe.Pointer(&domainBuf[0])), uintptr(unsafe.Pointer(&domainSize)),
		uintptr(unsafe.Pointer(&use)))
	if r == 0 {
		return "", fmt.Errorf("LookupAccountName(%q): %w", name, callErr)
	}
	var sidStrPtr *uint16
	r, _, callErr = acl_pConvertSidToStringSidW.Call(
		uintptr(unsafe.Pointer(&sidBuf[0])), uintptr(unsafe.Pointer(&sidStrPtr)))
	if r == 0 {
		return "", fmt.Errorf("ConvertSidToStringSid: %w", callErr)
	}
	if sidStrPtr == nil {
		return "", fmt.Errorf("ConvertSidToStringSid returned nil")
	}
	defer acl_pLocalFree.Call(uintptr(unsafe.Pointer(sidStrPtr)))
	return syscall.UTF16ToString(unsafe.Slice(sidStrPtr, 256)), nil
}

func acl_cmdAddACE(path, trustee, access string, deny, recursive, yes bool) int {
	if recursive {
		fmt.Fprintf(os.Stderr, "%s --recursive affects only future children;\n         existing children keep their current ACL.\n",
			c(clrYellow, "note:"))
		if !yes && !confirm(fmt.Sprintf("Apply inheritable ACE change to %s?", path)) {
			return 1
		}
	}
	if !yes && !confirm(fmt.Sprintf("add %s ACE for %s on %s?", access, trustee, path)) {
		return 1
	}
	idx := auditCount()
	backupRel, _, err := acl_backupSDDL(path, idx)
	if err != nil {
		fmt.Fprintf(os.Stderr, "winctl acl: backup failed, aborting: %v\n", err)
		return 5
	}
	acl_ensurePrivileges()
	inheritFlags := uint32(acl_NO_INHERITANCE)
	if recursive {
		inheritFlags = acl_OBJECT_INHERIT_ACE | acl_CONTAINER_INHERIT_ACE
	}
	if err := acl_addACE(path, trustee, access, deny, inheritFlags); err != nil {
		fmt.Fprintf(os.Stderr, "winctl acl: %v\n", err)
		return 5
	}
	acl_saveOp(idx, &acl_opRecord{
		Op: "add-ace", TS: time.Now().Format("2006-01-02 15:04:05"),
		Cmd: buildCmdLine(os.Args), Path: path, Backup: backupRel,
	})
	fmt.Printf("%s ACE for %s on %s\n", c(clrGreen, "added"), trustee, path)
	return 0
}

func acl_summarizeOp(rec *acl_opRecord) string {
	switch rec.Op {
	case "set-owner":
		return "-> restore owner on " + rec.Path
	case "add-ace":
		return "-> restore DACL on " + rec.Path
	}
	return ""
}

func acl_cmdHistory() int {
	lines, err := auditReadLines()
	if err != nil {
		fmt.Fprintf(os.Stderr, "read log: %v\n", err)
		return 4
	}
	if len(lines) == 0 {
		fmt.Fprintln(os.Stderr, "log is empty")
		return 0
	}
	count := 0
	for i := len(lines) - 1; i >= 0; i-- {
		m, cmd, _, ok := auditParseLine(lines[i])
		if !ok || m != "acl" {
			continue
		}
		if isHistorySelf(cmd) || !moduleManifestExists("acl", i) {
			continue
		}
		desc := ""
		if rec, e := acl_loadOp(i); e == nil {
			desc = acl_summarizeOp(rec)
		}
		count++
		fmt.Printf("[%d] %s %s\n", count, lines[i], c(clrGray, desc))
	}
	if count == 0 {
		fmt.Fprintln(os.Stderr, "no rollback-able acl operations in log")
	}
	return 0
}

func acl_cmdRollback(args []string) int {
	n := 1
	for i := 0; i < len(args); i++ {
		if args[i] == "-n" || args[i] == "--last" {
			if i+1 >= len(args) {
				return 2
			}
			v, err := strconv.Atoi(args[i+1])
			if err != nil || v <= 0 {
				return 2
			}
			n = v
			i++
		} else if strings.HasPrefix(args[i], "-") {
			return 2
		}
	}
	idxs, err := moduleTailOps("acl", n)
	if err != nil || len(idxs) == 0 {
		fmt.Fprintln(os.Stderr, "no rollback-able acl operations found")
		return 4
	}
	if dryRun {
		for k, i := range idxs {
			if rec, e := acl_loadOp(i); e == nil {
				fmt.Printf("[dry-run] step %d: %s %s\n", k+1, rec.Op, acl_summarizeOp(rec))
			}
		}
		return 0
	}
	acl_ensurePrivileges()
	okCount, failCount := 0, 0
	for k, i := range idxs {
		rec, err := acl_loadOp(i)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[rollback] step %d: %v\n", k+1, err)
			failCount++
			continue
		}
		fmt.Fprintf(os.Stderr, "[rollback] step %d: %s %s\n", k+1, rec.Op, acl_summarizeOp(rec))
		if rec.Backup == "" || rec.Path == "" {
			fmt.Fprintf(os.Stderr, "[rollback] step %d: missing backup or path\n", k+1)
			failCount++
			continue
		}
		if err := acl_restoreSDDL(rec.Backup, strings.HasSuffix(rec.Backup, ".gz"), rec.Path); err != nil {
			fmt.Fprintf(os.Stderr, "[rollback] step %d: error: %v\n", k+1, err)
			failCount++
			continue
		}
		fmt.Fprintf(os.Stderr, "[rollback] step %d: ok\n", k+1)
		okCount++
	}
	if failCount == 0 {
		return 0
	}
	if okCount == 0 {
		return 2
	}
	return 1
}

func acl_printHelp() {
	fmt.Printf("%s v%s (Windows)\n\n", c(clrBold+clrCyan, "winctl acl"), Version)
	fmt.Print(`USAGE
  winctl acl show <path> [--json]
  winctl acl set-owner <path> <user|group> [-y]
  winctl acl add-ace <path> <trustee> <access> [--deny] [--recursive] [-y]
  winctl acl --history
  winctl acl --rollback [-n N]

ADD-ACE
  <access>: read | write | execute | full | <hex mask>
  --deny         create a deny ACE
  --recursive    mark the new ACE as inheritable by future children
                 (does NOT modify existing children)

GLOBAL
  -o, --out <path>  write stdout to a file
  --dry-run         preview only
  --no-color        disable colors
  -b, --bugs        print collected errors/warnings
  -h, --help        show this help
  --version         show version

All logs go to ./backup/winctl_logs.log
All backups go to ./backup/acl/files/
`)
}

func acl_main() {
	args, outPath, err := consumeGlobalFlags(os.Args[1:])
	if err != nil {
		fmt.Fprintf(os.Stderr, "winctl acl: %v\n", err)
		finalExit(2)
	}
	initColor()
	if has(args, "--version") {
		fmt.Printf("winctl acl v%s\n", Version)
		finalExit(0)
	}
	if len(args) == 0 || has(args, "-h", "--help") {
		acl_printHelp()
		finalExit(0)
	}
	if outPath != "" {
		if err := setupOutput(outPath); err != nil {
			fmt.Fprintf(os.Stderr, "winctl acl: %v\n", err)
			finalExit(2)
		}
	}
	var code int
	switch {
	case has(args, "--history"):
		code = acl_cmdHistory()
		auditLog("acl", buildCmdLine(os.Args), code)
		finalExit(code)
	case has(args, "--rollback"):
		code = acl_cmdRollback(stripFlags(args, "--rollback"))
		auditLog("acl", buildCmdLine(os.Args), code)
		finalExit(code)
	}
	cmd := args[0]
	rest := args[1:]
	switch cmd {
	case "show":
		if len(rest) == 0 {
			fmt.Fprintln(os.Stderr, "usage: winctl acl show <path> [--json]")
			finalExit(2)
		}
		path := rest[0]
		jsonOut := has(rest, "--json")
		if dryRun {
			fmt.Printf("[dry-run] would show ACL of %s\n", path)
			finalExit(0)
		}
		code = acl_cmdShow(path, jsonOut)
	case "set-owner":
		if len(rest) < 2 {
			fmt.Fprintln(os.Stderr, "usage: winctl acl set-owner <path> <user|group> [-y]")
			finalExit(2)
		}
		path, owner := rest[0], rest[1]
		yes := has(rest, "-y", "--yes")
		if dryRun {
			fmt.Printf("[dry-run] would change owner of %s to %s\n", path, owner)
			finalExit(0)
		}
		code = acl_cmdSetOwner(path, owner, yes)
	case "add-ace":
		if len(rest) < 3 {
			fmt.Fprintln(os.Stderr, "usage: winctl acl add-ace <path> <trustee> <access> [--deny] [--recursive] [-y]")
			finalExit(2)
		}
		path, trustee, access := rest[0], rest[1], rest[2]
		deny := has(rest, "--deny")
		recursive := has(rest, "--recursive")
		yes := has(rest, "-y", "--yes")
		if dryRun {
			fmt.Printf("[dry-run] would add %s ACE for %s on %s (inheritable=%v)\n", access, trustee, path, recursive)
			finalExit(0)
		}
		code = acl_cmdAddACE(path, trustee, access, deny, recursive, yes)
	default:
		fmt.Fprintf(os.Stderr, "winctl acl: unknown command %q\n", cmd)
		code = 2
	}
	if !dryRun && shouldLogRun() {
		auditLog("acl", buildCmdLine(os.Args), code)
	}
	finalExit(code)
}
// ============================================================================
// bkp — unified backup / restore (files, registry, services, tasks)
// ============================================================================
//
// Layout:
//   ./backup/bkp/snapshots/<id>/         one directory per snapshot
//   ./backup/bkp/archived/<id>/          archived snapshots (small)
//   ./backup/bkp/archived/<id>.tar.gz    archived snapshots (large)
//   ./backup/bkp/ops/<auditIdx>.json     per-operation manifest

type bkp_BackupItem struct {
	Kind       string `json:"kind"` // file | dir | registry | service | task
	Src        string `json:"src"`
	Stored     string `json:"stored"`
	Compressed bool   `json:"compressed,omitempty"`
}

type bkp_BackupManifest struct {
	ID      string           `json:"id"`
	Created time.Time        `json:"created"`
	Command string           `json:"command"`
	Items   []bkp_BackupItem `json:"items"`
}

type bkp_opRecord struct {
	Op             string           `json:"op"`
	TS             string           `json:"ts"`
	Cmd            string           `json:"cmd"`
	Code           int              `json:"code"`
	BackupID       string           `json:"backupId,omitempty"`
	TargetBackupID string           `json:"targetBackupId,omitempty"`
	PreBackupID    string           `json:"preBackupId,omitempty"`
	CleanedBackups []string         `json:"cleanedBackups,omitempty"`
	ArchivedIDs    []string         `json:"archivedIds,omitempty"`
	Items          []bkp_BackupItem `json:"items,omitempty"`
}

const bkp_backupPrefix = "backup"

func bkp_snapshotsRoot() string      { return filepath.Join(moduleRoot("bkp"), "snapshots") }
func bkp_archivedRoot() string       { return filepath.Join(moduleRoot("bkp"), "archived") }
func bkp_backupDir(id string) string { return filepath.Join(bkp_snapshotsRoot(), id) }

func bkp_newBackupID() string {
	base := bkp_backupPrefix + time.Now().Format("20060102_150405")
	if _, err := os.Stat(filepath.Join(bkp_snapshotsRoot(), base)); err == nil {
		base = fmt.Sprintf("%s_%04x", base, rand.Intn(0x10000))
	}
	return base
}

func bkp_writeManifest(dir string, m *bkp_BackupManifest) error {
	data, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, "manifest.json"), data, 0644)
}

func bkp_readManifest(dir string) (*bkp_BackupManifest, error) {
	data, err := os.ReadFile(filepath.Join(dir, "manifest.json"))
	if err != nil {
		return nil, err
	}
	var m bkp_BackupManifest
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, err
	}
	return &m, nil
}

func bkp_saveOp(idx int, rec *bkp_opRecord) {
	if err := moduleSaveManifest("bkp", idx, rec); err != nil {
		bugs.Add("ERR", "save op %d: %v", idx, err)
	}
}

func bkp_loadOp(idx int) (*bkp_opRecord, error) {
	var rec bkp_opRecord
	if err := moduleLoadManifest("bkp", idx, &rec); err != nil {
		return nil, err
	}
	return &rec, nil
}

const bkp_smallThreshold = 8192

func bkp_copyFile(src, dst string) error {
	if err := os.MkdirAll(filepath.Dir(dst), 0755); err != nil {
		return err
	}
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	return out.Close()
}

func bkp_gzipBytes(data []byte, dst string) error {
	if err := os.MkdirAll(filepath.Dir(dst), 0755); err != nil {
		return err
	}
	f, err := os.Create(dst)
	if err != nil {
		return err
	}
	gz, err := gzip.NewWriterLevel(f, gzip.BestCompression)
	if err != nil {
		f.Close()
		return err
	}
	if _, err := gz.Write(data); err != nil {
		gz.Close()
		f.Close()
		return err
	}
	if err := gz.Close(); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

func bkp_gzipFileTo(src, dst string) error {
	data, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	return bkp_gzipBytes(data, dst)
}

func bkp_gunzipTo(src, dst string) error {
	f, err := os.Open(src)
	if err != nil {
		return err
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		return err
	}
	defer gz.Close()
	if err := os.MkdirAll(filepath.Dir(dst), 0755); err != nil {
		return err
	}
	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, gz); err != nil {
		out.Close()
		return err
	}
	return out.Close()
}

func bkp_tarGzDir(srcDir, dst string) error {
	if err := os.MkdirAll(filepath.Dir(dst), 0755); err != nil {
		return err
	}
	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	gz, err := gzip.NewWriterLevel(out, gzip.BestCompression)
	if err != nil {
		out.Close()
		return err
	}
	tw := tar.NewWriter(gz)
	walkErr := filepath.Walk(srcDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if path == srcDir {
			return nil
		}
		rel, err := filepath.Rel(srcDir, path)
		if err != nil {
			return err
		}
		hdr, err := tar.FileInfoHeader(info, "")
		if err != nil {
			return err
		}
		hdr.Name = filepath.ToSlash(rel)
		if err := tw.WriteHeader(hdr); err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		f, err := os.Open(path)
		if err != nil {
			return err
		}
		_, copyErr := io.Copy(tw, f)
		closeErr := f.Close()
		if copyErr != nil {
			return copyErr
		}
		return closeErr
	})
	if walkErr != nil {
		tw.Close()
		gz.Close()
		out.Close()
		return walkErr
	}
	if err := tw.Close(); err != nil {
		gz.Close()
		out.Close()
		return err
	}
	if err := gz.Close(); err != nil {
		out.Close()
		return err
	}
	return out.Close()
}

func bkp_untarGzTo(src, dstDir string) error {
	f, err := os.Open(src)
	if err != nil {
		return err
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		return err
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	if err := os.MkdirAll(dstDir, 0755); err != nil {
		return err
	}
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		dst := filepath.Join(dstDir, filepath.FromSlash(hdr.Name))
		switch hdr.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(dst, 0755); err != nil {
				return err
			}
		case tar.TypeReg:
			if err := os.MkdirAll(filepath.Dir(dst), 0755); err != nil {
				return err
			}
			out, err := os.Create(dst)
			if err != nil {
				return err
			}
			if _, err := io.Copy(out, tr); err != nil {
				out.Close()
				return err
			}
			out.Close()
			if !hdr.ModTime.IsZero() {
				_ = os.Chtimes(dst, time.Now(), hdr.ModTime)
			}
		}
	}
	return nil
}

func bkp_regParsePath(s string) (root uintptr, rootStr, subKey string, err error) {
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, `\\?\`)
	s = strings.ReplaceAll(s, "/", `\`)
	s = strings.TrimSuffix(s, `\`)
	idx := strings.Index(s, `\`)
	if idx < 0 {
		rootStr = s
	} else {
		rootStr = s[:idx]
		subKey = s[idx+1:]
	}
	switch strings.ToUpper(rootStr) {
	case "HKCR", "HKEY_CLASSES_ROOT":
		root, rootStr = 0xFFFFFFFF80000000, "HKEY_CLASSES_ROOT"
	case "HKCU", "HKEY_CURRENT_USER":
		root, rootStr = 0xFFFFFFFF80000001, "HKEY_CURRENT_USER"
	case "HKLM", "HKEY_LOCAL_MACHINE":
		root, rootStr = 0xFFFFFFFF80000002, "HKEY_LOCAL_MACHINE"
	case "HKU", "HKEY_USERS":
		root, rootStr = 0xFFFFFFFF80000003, "HKEY_USERS"
	case "HKCC", "HKEY_CURRENT_CONFIG":
		root, rootStr = 0xFFFFFFFF80000005, "HKEY_CURRENT_CONFIG"
	default:
		err = fmt.Errorf("unknown registry root %q", rootStr)
	}
	return
}

func bkp_exportRegKey(key string, dstPath string) error {
	cmd := exec.Command("reg", "export", key, dstPath, "/y")
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	var errBuf bytes.Buffer
	cmd.Stderr = &errBuf
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("reg export: %s", strings.TrimSpace(errBuf.String()))
	}
	return nil
}

func bkp_importRegFile(path string) error {
	cmd := exec.Command("reg", "import", path)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	var errBuf bytes.Buffer
	cmd.Stderr = &errBuf
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("reg import: %s", strings.TrimSpace(errBuf.String()))
	}
	return nil
}

type bkp_svcSnapshot struct {
	Name        string `json:"name"`
	DisplayName string `json:"displayName"`
	StartType   uint32 `json:"startType"`
	State       uint32 `json:"state"`
	BinaryPath  string `json:"binaryPath"`
}

const (
	bkp_SC_MANAGER_ALL_ACCESS = 0xF003F
	bkp_SERVICE_ALL_ACCESS    = 0xF01FF
	bkp_SERVICE_QUERY_CONFIG  = 0x0001
	bkp_SERVICE_QUERY_STATUS  = 0x0004
	bkp_SERVICE_NO_CHANGE     = 0xFFFFFFFF

	bkp_SERVICE_STOPPED       = 0x00000001
	bkp_SERVICE_RUNNING       = 0x00000004
	bkp_SERVICE_PAUSED        = 0x00000007
	bkp_SERVICE_CONTROL_STOP  = 0x00000001
	bkp_SERVICE_CONTROL_PAUSE = 0x00000002
)

var (
	bkp_pOpenSCManagerW       = advapi32.NewProc("OpenSCManagerW")
	bkp_pCloseServiceHandle   = advapi32.NewProc("CloseServiceHandle")
	bkp_pOpenServiceW         = advapi32.NewProc("OpenServiceW")
	bkp_pQueryServiceStatus   = advapi32.NewProc("QueryServiceStatus")
	bkp_pQueryServiceConfigW  = advapi32.NewProc("QueryServiceConfigW")
	bkp_pChangeServiceConfigW = advapi32.NewProc("ChangeServiceConfigW")
	bkp_pStartServiceW        = advapi32.NewProc("StartServiceW")
	bkp_pControlService       = advapi32.NewProc("ControlService")
)

func bkp_openSCM() (syscall.Handle, error) {
	h, _, err := bkp_pOpenSCManagerW.Call(0, 0, bkp_SC_MANAGER_ALL_ACCESS)
	if h == 0 {
		return 0, fmt.Errorf("OpenSCManager: %w", err)
	}
	return syscall.Handle(h), nil
}

func bkp_openService(scm syscall.Handle, name string, access uint32) (syscall.Handle, error) {
	p, err := syscall.UTF16PtrFromString(name)
	if err != nil {
		return 0, err
	}
	h, _, callErr := bkp_pOpenServiceW.Call(uintptr(scm), uintptr(unsafe.Pointer(p)), uintptr(access))
	if h == 0 {
		return 0, fmt.Errorf("OpenService %q: %w", name, callErr)
	}
	return syscall.Handle(h), nil
}

func bkp_snapshotService(name string) (*bkp_svcSnapshot, error) {
	scm, err := bkp_openSCM()
	if err != nil {
		return nil, err
	}
	defer bkp_pCloseServiceHandle.Call(uintptr(scm))
	h, err := bkp_openService(scm, name, bkp_SERVICE_QUERY_CONFIG|bkp_SERVICE_QUERY_STATUS)
	if err != nil {
		return nil, err
	}
	defer bkp_pCloseServiceHandle.Call(uintptr(h))
	var st struct {
		ServiceType, CurrentState, ControlsAccepted, Win32ExitCode, ServiceSpecificExitCode, CheckPoint, WaitHint uint32
	}
	bkp_pQueryServiceStatus.Call(uintptr(h), uintptr(unsafe.Pointer(&st)))
	var needed uint32
	bkp_pQueryServiceConfigW.Call(uintptr(h), 0, 0, uintptr(unsafe.Pointer(&needed)))
	if needed == 0 {
		return nil, fmt.Errorf("QueryServiceConfig: cannot determine size")
	}
	buf := make([]byte, needed)
	r, _, callErr := bkp_pQueryServiceConfigW.Call(uintptr(h),
		uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)), uintptr(unsafe.Pointer(&needed)))
	if r == 0 {
		return nil, fmt.Errorf("QueryServiceConfig(%s): %w", name, callErr)
	}
	type qsc struct {
		ServiceType, StartType, ErrorControl uint32
		BinaryPathName                       *uint16
		LoadOrderGroup                       *uint16
		TagID                                uint32
		Dependencies                         *uint16
		ServiceStartName                     *uint16
		DisplayName                          *uint16
	}
	cfg := (*qsc)(unsafe.Pointer(&buf[0]))
	snap := &bkp_svcSnapshot{Name: name, StartType: cfg.StartType, State: st.CurrentState}
	if cfg.BinaryPathName != nil {
		snap.BinaryPath = syscall.UTF16ToString(unsafe.Slice(cfg.BinaryPathName, 1024))
	}
	if cfg.DisplayName != nil {
		snap.DisplayName = syscall.UTF16ToString(unsafe.Slice(cfg.DisplayName, 512))
	}
	return snap, nil
}

func bkp_applyServiceSnapshot(snap *bkp_svcSnapshot) error {
	scm, err := bkp_openSCM()
	if err != nil {
		return err
	}
	defer bkp_pCloseServiceHandle.Call(uintptr(scm))
	h, err := bkp_openService(scm, snap.Name, bkp_SERVICE_ALL_ACCESS)
	if err != nil {
		return err
	}
	defer bkp_pCloseServiceHandle.Call(uintptr(h))
	r, _, callErr := bkp_pChangeServiceConfigW.Call(uintptr(h),
		uintptr(bkp_SERVICE_NO_CHANGE), uintptr(snap.StartType), uintptr(bkp_SERVICE_NO_CHANGE),
		0, 0, 0, 0, 0, 0, 0)
	if r == 0 {
		return fmt.Errorf("ChangeServiceConfig: %w", callErr)
	}
	var st struct {
		ServiceType, CurrentState, ControlsAccepted, Win32ExitCode, ServiceSpecificExitCode, CheckPoint, WaitHint uint32
	}
	bkp_pQueryServiceStatus.Call(uintptr(h), uintptr(unsafe.Pointer(&st)))
	switch snap.State {
	case bkp_SERVICE_RUNNING:
		if st.CurrentState != bkp_SERVICE_RUNNING {
			bkp_pStartServiceW.Call(uintptr(h), 0, 0)
		}
	case bkp_SERVICE_STOPPED:
		if st.CurrentState != bkp_SERVICE_STOPPED {
			bkp_pControlService.Call(uintptr(h), uintptr(bkp_SERVICE_CONTROL_STOP), uintptr(unsafe.Pointer(&st)))
		}
	case bkp_SERVICE_PAUSED:
		if st.CurrentState == bkp_SERVICE_RUNNING {
			bkp_pControlService.Call(uintptr(h), uintptr(bkp_SERVICE_CONTROL_PAUSE), uintptr(unsafe.Pointer(&st)))
		}
	}
	return nil
}

func bkp_exportTaskXML(name string) ([]byte, error) {
	cmd := exec.Command(task_schtasksPath(), "/query", "/tn", name, "/xml")
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	var errBuf bytes.Buffer
	cmd.Stderr = &errBuf
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("schtasks /query /xml: %s", strings.TrimSpace(errBuf.String()))
	}
	return out, nil
}

func bkp_importTaskXML(name string, xml []byte) error {
	tmp, err := os.CreateTemp("", "winctl_bkp_task_*.xml")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	if _, err := tmp.Write(xml); err != nil {
		tmp.Close()
		os.Remove(tmpPath)
		return err
	}
	tmp.Close()
	defer os.Remove(tmpPath)
	cmd := exec.Command(task_schtasksPath(), "/create", "/tn", name, "/xml", tmpPath, "/f")
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	var errBuf bytes.Buffer
	cmd.Stderr = &errBuf
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("schtasks /create: %s", strings.TrimSpace(errBuf.String()))
	}
	return nil
}

func bkp_listTaskNames() ([]string, error) {
	cmd := exec.Command(task_schtasksPath(), "/query", "/fo", "csv", "/nh")
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("schtasks /query: %w", err)
	}
	var names []string
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, `"`) {
			continue
		}
		fields := strings.Split(line, `","`)
		if len(fields) < 2 {
			continue
		}
		name := strings.Trim(fields[1], `"`)
		if name == "" || strings.EqualFold(name, "TaskName") {
			continue
		}
		names = append(names, name)
	}
	sort.Strings(names)
	return names, nil
}

func bkp_listServiceNames() ([]string, error) {
	cmd := exec.Command("sc", "query", "state=", "all", "type=", "service")
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("sc query: %w", err)
	}
	var names []string
	scanner := bufio.NewScanner(bytes.NewReader(out))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "SERVICE_NAME:") {
			names = append(names, strings.TrimSpace(strings.TrimPrefix(line, "SERVICE_NAME:")))
		}
	}
	sort.Strings(names)
	return names, nil
}

var bkp_sanitizeRe = regexp.MustCompile(`[^A-Za-z0-9._-]`)

func bkp_sanitize(s string) string {
	s = strings.ReplaceAll(s, `\`, "_")
	s = strings.ReplaceAll(s, `:`, "_")
	s = bkp_sanitizeRe.ReplaceAllString(s, "_")
	if len(s) > 80 {
		s = s[:80]
	}
	return s
}

func bkp_makeBackupDir(id string) (string, error) {
	base := bkp_backupDir(id)
	if err := os.MkdirAll(base, 0755); err != nil {
		return "", err
	}
	return base, nil
}

func bkp_backupOneItem(baseDir string, idx int, it *bkp_BackupItem) error {
	switch it.Kind {
	case "file":
		fi, err := os.Stat(it.Src)
		if err != nil {
			return err
		}
		base := fmt.Sprintf("%d_%s", idx, bkp_sanitize(filepath.Base(it.Src)))
		if fi.Size() < bkp_smallThreshold {
			rel := filepath.Join("files", base)
			if err := bkp_copyFile(it.Src, filepath.Join(baseDir, rel)); err != nil {
				return err
			}
			it.Stored, it.Compressed = rel, false
			return nil
		}
		rel := filepath.Join("files", base+".gz")
		if err := bkp_gzipFileTo(it.Src, filepath.Join(baseDir, rel)); err != nil {
			return err
		}
		it.Stored, it.Compressed = rel, true
		return nil
	case "dir":
		base := fmt.Sprintf("%d_%s", idx, bkp_sanitize(filepath.Base(it.Src)))
		rel := filepath.Join("files", base+".tar.gz")
		if err := bkp_tarGzDir(it.Src, filepath.Join(baseDir, rel)); err != nil {
			return err
		}
		it.Stored, it.Compressed = rel, true
		return nil
	case "registry":
		base := fmt.Sprintf("%d_%s.reg", idx, bkp_sanitize(it.Src))
		tmp := filepath.Join(baseDir, base)
		if err := bkp_exportRegKey(it.Src, tmp); err != nil {
			return err
		}
		fi, err := os.Stat(tmp)
		if err != nil {
			return err
		}
		if fi.Size() < bkp_smallThreshold {
			it.Stored, it.Compressed = filepath.Join("registry", base), false
			dst := filepath.Join(baseDir, it.Stored)
			if err := os.MkdirAll(filepath.Dir(dst), 0755); err != nil {
				return err
			}
			return os.Rename(tmp, dst)
		}
		rel := filepath.Join("registry", base+".gz")
		if err := bkp_gzipFileTo(tmp, filepath.Join(baseDir, rel)); err != nil {
			return err
		}
		os.Remove(tmp)
		it.Stored, it.Compressed = rel, true
		return nil
	case "service":
		snap, err := bkp_snapshotService(it.Src)
		if err != nil {
			return err
		}
		data, _ := json.MarshalIndent(snap, "", "  ")
		base := fmt.Sprintf("%d_%s.json", idx, bkp_sanitize(it.Src))
		rel := filepath.Join("services", base)
		dst := filepath.Join(baseDir, rel)
		if err := os.MkdirAll(filepath.Dir(dst), 0755); err != nil {
			return err
		}
		if len(data) < bkp_smallThreshold {
			if err := os.WriteFile(dst, data, 0644); err != nil {
				return err
			}
			it.Stored, it.Compressed = rel, false
			return nil
		}
		rel = rel + ".gz"
		if err := bkp_gzipBytes(data, filepath.Join(baseDir, rel)); err != nil {
			return err
		}
		it.Stored, it.Compressed = rel, true
		return nil
	case "task":
		data, err := bkp_exportTaskXML(it.Src)
		if err != nil {
			return err
		}
		base := fmt.Sprintf("%d_%s.xml", idx, bkp_sanitize(it.Src))
		rel := filepath.Join("tasks", base)
		dst := filepath.Join(baseDir, rel)
		if err := os.MkdirAll(filepath.Dir(dst), 0755); err != nil {
			return err
		}
		if len(data) < bkp_smallThreshold {
			if err := os.WriteFile(dst, data, 0644); err != nil {
				return err
			}
			it.Stored, it.Compressed = rel, false
			return nil
		}
		rel = rel + ".gz"
		if err := bkp_gzipBytes(data, filepath.Join(baseDir, rel)); err != nil {
			return err
		}
		it.Stored, it.Compressed = rel, true
		return nil
	}
	return fmt.Errorf("unknown item kind %q", it.Kind)
}

func bkp_backupAll(baseDir string, items []bkp_BackupItem) error {
	for i := range items {
		if err := bkp_backupOneItem(baseDir, i, &items[i]); err != nil {
			return err
		}
	}
	return nil
}

func bkp_restoreOneItem(baseDir string, it bkp_BackupItem) error {
	switch it.Kind {
	case "file":
		src := filepath.Join(baseDir, it.Stored)
		if it.Compressed {
			return bkp_gunzipTo(src, it.Src)
		}
		return bkp_copyFile(src, it.Src)
	case "dir":
		return bkp_untarGzTo(filepath.Join(baseDir, it.Stored), it.Src)
	case "registry":
		src := filepath.Join(baseDir, it.Stored)
		if it.Compressed {
			tmp, err := os.CreateTemp("", "winctl_bkp_reg_*.reg")
			if err != nil {
				return err
			}
			tmpPath := tmp.Name()
			tmp.Close()
			defer os.Remove(tmpPath)
			if err := bkp_gunzipTo(src, tmpPath); err != nil {
				return err
			}
			return bkp_importRegFile(tmpPath)
		}
		return bkp_importRegFile(src)
	case "service":
		src := filepath.Join(baseDir, it.Stored)
		var data []byte
		var err error
		if it.Compressed {
			tmp, cerr := os.CreateTemp("", "winctl_bkp_svc_*.json")
			if cerr != nil {
				return cerr
			}
			tmpPath := tmp.Name()
			tmp.Close()
			defer os.Remove(tmpPath)
			if err := bkp_gunzipTo(src, tmpPath); err != nil {
				return err
			}
			data, err = os.ReadFile(tmpPath)
		} else {
			data, err = os.ReadFile(src)
		}
		if err != nil {
			return err
		}
		var snap bkp_svcSnapshot
		if err := json.Unmarshal(data, &snap); err != nil {
			return err
		}
		return bkp_applyServiceSnapshot(&snap)
	case "task":
		src := filepath.Join(baseDir, it.Stored)
		var data []byte
		var err error
		if it.Compressed {
			tmp, cerr := os.CreateTemp("", "winctl_bkp_task_*.xml")
			if cerr != nil {
				return cerr
			}
			tmpPath := tmp.Name()
			tmp.Close()
			defer os.Remove(tmpPath)
			if err := bkp_gunzipTo(src, tmpPath); err != nil {
				return err
			}
			data, err = os.ReadFile(tmpPath)
		} else {
			data, err = os.ReadFile(src)
		}
		if err != nil {
			return err
		}
		return bkp_importTaskXML(it.Src, data)
	}
	return fmt.Errorf("unknown item kind %q", it.Kind)
}

func bkp_preBackupForRestore(target *bkp_BackupManifest) (string, error) {
	preID := bkp_newBackupID()
	base, err := bkp_makeBackupDir(preID)
	if err != nil {
		return preID, err
	}
	items := make([]bkp_BackupItem, len(target.Items))
	for i, it := range target.Items {
		items[i] = bkp_BackupItem{Kind: it.Kind, Src: it.Src}
	}
	if err := bkp_backupAll(base, items); err != nil {
		return preID, err
	}
	pm := &bkp_BackupManifest{
		ID: preID, Created: time.Now(),
		Command: "pre-restore backup for " + target.ID, Items: items,
	}
	if err := bkp_writeManifest(base, pm); err != nil {
		return preID, err
	}
	return preID, nil
}
func bkp_cmdBackup(args []string) int {
	var items []bkp_BackupItem
	allServices, allTasks := false, false
	i := 0
	for i < len(args) {
		a := args[i]
		switch a {
		case "--file":
			if i+1 >= len(args) {
				return 2
			}
			items = append(items, bkp_BackupItem{Kind: "file", Src: args[i+1]})
			i += 2
		case "--dir":
			if i+1 >= len(args) {
				return 2
			}
			items = append(items, bkp_BackupItem{Kind: "dir", Src: args[i+1]})
			i += 2
		case "--reg":
			if i+1 >= len(args) {
				return 2
			}
			items = append(items, bkp_BackupItem{Kind: "registry", Src: args[i+1]})
			i += 2
		case "--svc":
			if i+1 >= len(args) {
				return 2
			}
			items = append(items, bkp_BackupItem{Kind: "service", Src: args[i+1]})
			i += 2
		case "--task":
			if i+1 >= len(args) {
				return 2
			}
			items = append(items, bkp_BackupItem{Kind: "task", Src: args[i+1]})
			i += 2
		case "--all-services":
			allServices = true
			i++
		case "--all-tasks":
			allTasks = true
			i++
		default:
			if strings.HasPrefix(a, "-") {
				fmt.Fprintf(os.Stderr, "backup: unknown option %s\n", a)
				return 2
			}
			return 2
		}
	}
	if allServices {
		fmt.Fprintln(os.Stderr, "enumerating services...")
		names, err := bkp_listServiceNames()
		if err != nil {
			fmt.Fprintf(os.Stderr, "backup: enumerate services: %v\n", err)
			return 5
		}
		for _, n := range names {
			items = append(items, bkp_BackupItem{Kind: "service", Src: n})
		}
	}
	if allTasks {
		fmt.Fprintln(os.Stderr, "enumerating scheduled tasks...")
		names, err := bkp_listTaskNames()
		if err != nil {
			fmt.Fprintf(os.Stderr, "backup: enumerate tasks: %v\n", err)
			return 5
		}
		for _, n := range names {
			items = append(items, bkp_BackupItem{Kind: "task", Src: n})
		}
	}
	if len(items) == 0 {
		fmt.Fprintln(os.Stderr, "backup: nothing to back up (use --file, --dir, --reg, --svc, --task, --all-services or --all-tasks)")
		return 2
	}
	var valid []bkp_BackupItem
	for _, it := range items {
		switch it.Kind {
		case "file", "dir":
			if _, err := os.Stat(it.Src); err != nil {
				fmt.Fprintf(os.Stderr, "backup: skip %q: %v\n", it.Src, err)
				continue
			}
		case "registry":
			if _, _, _, err := bkp_regParsePath(it.Src); err != nil {
				fmt.Fprintf(os.Stderr, "backup: skip %q: %v\n", it.Src, err)
				continue
			}
		}
		valid = append(valid, it)
	}
	if len(valid) == 0 {
		fmt.Fprintln(os.Stderr, "backup: no valid items")
		return 4
	}
	if dryRun {
		fmt.Printf("[dry-run] would back up %d item(s):\n", len(valid))
		for _, it := range valid {
			fmt.Printf("  %-8s %s\n", it.Kind, it.Src)
		}
		return 0
	}
	id := bkp_newBackupID()
	base, err := bkp_makeBackupDir(id)
	if err != nil {
		fmt.Fprintf(os.Stderr, "backup: create dir: %v\n", err)
		return 5
	}
	idx := auditCount()
	succeeded := 0
	var successful []bkp_BackupItem
	for i := range valid {
		it := valid[i]
		if err := bkp_backupOneItem(base, i, &it); err != nil {
			fmt.Fprintf(os.Stderr, "backup: %s %q: %v\n", it.Kind, it.Src, err)
			continue
		}
		succeeded++
		successful = append(successful, it)
		fmt.Printf("%s %-8s %s -> %s\n", c(clrGreen, "saved"), it.Kind, it.Src, c(clrGray, it.Stored))
	}
	if succeeded == 0 {
		fmt.Fprintf(os.Stderr, "backup: all %d item(s) failed\n", len(valid))
		_ = os.RemoveAll(base)
		return 2
	}
	m := &bkp_BackupManifest{ID: id, Created: time.Now(), Command: buildCmdLine(os.Args), Items: successful}
	if err := bkp_writeManifest(base, m); err != nil {
		fmt.Fprintf(os.Stderr, "backup: write manifest: %v\n", err)
		return 5
	}
	bkp_saveOp(idx, &bkp_opRecord{
		Op: "backup", TS: time.Now().Format("2006-01-02 15:04:05"),
		Cmd: buildCmdLine(os.Args), BackupID: id, Items: successful,
	})
	fmt.Printf("\n%s %s %s\n", c(clrBold+clrGreen, "backup created:"), c(clrCyan, id), c(clrGray, "at "+base))
	if succeeded < len(valid) {
		fmt.Fprintf(os.Stderr, "%d item(s) succeeded, %d failed\n", succeeded, len(valid)-succeeded)
		return 1
	}
	return 0
}

func bkp_cmdList(args []string) int {
	jsonOut := false
	for _, a := range args {
		switch a {
		case "--json":
			jsonOut = true
		default:
			if strings.HasPrefix(a, "-") {
				fmt.Fprintf(os.Stderr, "list: unknown option %s\n", a)
				return 2
			}
		}
	}
	entries, err := os.ReadDir(bkp_snapshotsRoot())
	if err != nil {
		if os.IsNotExist(err) {
			fmt.Fprintln(os.Stderr, "no backups yet")
			return 0
		}
		fmt.Fprintf(os.Stderr, "list: %v\n", err)
		return 5
	}
	type row struct {
		ID      string    `json:"id"`
		Created time.Time `json:"created"`
		Items   int       `json:"items"`
		Size    int64     `json:"size"`
		Path    string    `json:"path"`
	}
	var rows []row
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		dir := filepath.Join(bkp_snapshotsRoot(), e.Name())
		m, err := bkp_readManifest(dir)
		if err != nil {
			continue
		}
		var size int64
		filepath.Walk(dir, func(p string, info os.FileInfo, err error) error {
			if err == nil && !info.IsDir() {
				size += info.Size()
			}
			return nil
		})
		rows = append(rows, row{ID: m.ID, Created: m.Created, Items: len(m.Items), Size: size, Path: dir})
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].Created.After(rows[j].Created) })
	if jsonOut {
		b, _ := json.MarshalIndent(rows, "", "  ")
		fmt.Println(string(b))
		return 0
	}
	if len(rows) == 0 {
		fmt.Fprintln(os.Stderr, "no backups yet")
		return 0
	}
	idW := len("ID")
	for _, r := range rows {
		if len(r.ID) > idW {
			idW = len(r.ID)
		}
	}
	fmt.Println(c(clrBold+clrCyan,
		padRight("ID", idW)+"  "+padRight("CREATED", 19)+"  "+
			padRight("ITEMS", 5)+"  "+padRight("SIZE", 10)+"  PATH"))
	for _, r := range rows {
		fmt.Println(padRight(r.ID, idW)+"  "+
			padRight(r.Created.Local().Format("2006-01-02 15:04:05"), 19)+"  "+
			padRight(strconv.Itoa(r.Items), 5)+"  "+
			padRight(humanBytes(uint64(r.Size)), 10)+"  "+
			c(clrGray, r.Path))
	}
	fmt.Fprintf(os.Stderr, "\n%d backup(s) in %s\n", len(rows), bkp_snapshotsRoot())
	return 0
}

func bkp_cmdRestore(args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "usage: winctl bkp restore <backup-id> [-f]")
		return 2
	}
	id := args[0]
	force := false
	for _, a := range args[1:] {
		switch a {
		case "-f", "--force":
			force = true
		default:
			return 2
		}
	}
	dir := bkp_backupDir(id)
	m, err := bkp_readManifest(dir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "restore: read manifest: %v\n", err)
		return 4
	}
	if !force {
		fmt.Fprintf(os.Stderr, "about to restore backup %s (%d item(s)):\n", id, len(m.Items))
		for _, it := range m.Items {
			fmt.Fprintf(os.Stderr, "  %-8s %s\n", it.Kind, it.Src)
		}
		fmt.Fprintln(os.Stderr, "a pre-restore backup of the current state will be created first.")
		if !confirm("proceed?") {
			return 1
		}
	}
	if dryRun {
		fmt.Printf("[dry-run] would restore %d item(s) from %s\n", len(m.Items), dir)
		return 0
	}
	for _, it := range m.Items {
		stored := filepath.Join(dir, it.Stored)
		if _, err := os.Stat(stored); err != nil {
			fmt.Fprintf(os.Stderr, "restore: warning: stored file %q is missing (%v)\n", it.Stored, err)
		}
	}
	preID, err := bkp_preBackupForRestore(m)
	if err != nil {
		_ = os.RemoveAll(bkp_backupDir(preID))
		fmt.Fprintf(os.Stderr, "restore: pre-backup: %v\n", err)
		return 5
	}
	fmt.Printf("%s %s\n", c(clrCyan, "pre-backup:"), preID)
	idx := auditCount()
	succeeded, failed := 0, 0
	for _, it := range m.Items {
		if err := bkp_restoreOneItem(dir, it); err != nil {
			fmt.Fprintf(os.Stderr, "restore: %s %s: %v\n", it.Kind, it.Src, err)
			failed++
			continue
		}
		fmt.Printf("%s %-8s %s\n", c(clrGreen, "restored"), it.Kind, it.Src)
		succeeded++
	}
	bkp_saveOp(idx, &bkp_opRecord{
		Op: "restore", TS: time.Now().Format("2006-01-02 15:04:05"),
		Cmd: buildCmdLine(os.Args), TargetBackupID: id, PreBackupID: preID, Items: m.Items,
	})
	if failed == 0 {
		return 0
	}
	if succeeded == 0 {
		return 2
	}
	return 1
}

func bkp_copyDirRecursive(src, dst string) error {
	if err := os.MkdirAll(dst, 0755); err != nil {
		return err
	}
	return filepath.Walk(src, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}
		if rel == "." {
			return nil
		}
		target := filepath.Join(dst, rel)
		if info.IsDir() {
			return os.MkdirAll(target, info.Mode())
		}
		return bkp_copyFile(path, target)
	})
}

type bkp_cleanCandidate struct {
	id      string
	dir     string
	created time.Time
	size    int64
}

func bkp_cmdClean(args []string) int {
	keep := 5
	olderThanDays := 0
	force := false
	purge := false
	i := 0
	for i < len(args) {
		a := args[i]
		switch a {
		case "--keep":
			if i+1 >= len(args) {
				return 2
			}
			v, err := strconv.Atoi(args[i+1])
			if err != nil || v < 0 {
				return 2
			}
			keep = v
			i += 2
		case "--older-than":
			if i+1 >= len(args) {
				return 2
			}
			v, err := strconv.Atoi(args[i+1])
			if err != nil || v <= 0 {
				return 2
			}
			olderThanDays = v
			i += 2
		case "-f", "--force":
			force = true
			i++
		case "--purge":
			purge = true
			i++
		default:
			return 2
		}
	}
	entries, err := os.ReadDir(bkp_snapshotsRoot())
	if err != nil {
		if os.IsNotExist(err) {
			fmt.Fprintln(os.Stderr, "no backups")
			return 0
		}
		fmt.Fprintf(os.Stderr, "clean: %v\n", err)
		return 5
	}
	var all []bkp_cleanCandidate
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		dir := filepath.Join(bkp_snapshotsRoot(), e.Name())
		m, err := bkp_readManifest(dir)
		if err != nil {
			continue
		}
		var size int64
		filepath.Walk(dir, func(p string, info os.FileInfo, err error) error {
			if err == nil && !info.IsDir() {
				size += info.Size()
			}
			return nil
		})
		all = append(all, bkp_cleanCandidate{m.ID, dir, m.Created, size})
	}
	if len(all) == 0 {
		fmt.Fprintln(os.Stderr, "no backups")
		return 0
	}
	sort.Slice(all, func(i, j int) bool { return all[i].created.After(all[j].created) })
	var toClean []bkp_cleanCandidate
	if olderThanDays > 0 {
		cutoff := time.Now().Add(-time.Duration(olderThanDays) * 24 * time.Hour)
		for _, cand := range all {
			if cand.created.Before(cutoff) {
				toClean = append(toClean, cand)
			}
		}
	} else {
		if keep >= len(all) {
			fmt.Fprintf(os.Stderr, "nothing to clean (have %d, keep %d)\n", len(all), keep)
			return 0
		}
		toClean = all[keep:]
	}
	if len(toClean) == 0 {
		fmt.Fprintln(os.Stderr, "nothing to clean")
		return 0
	}
	if !force && !dryRun {
		fmt.Fprintf(os.Stderr, "about to remove %d backup(s):\n", len(toClean))
		for _, cand := range toClean {
			fmt.Fprintf(os.Stderr, "  %s  %s  %s\n", cand.id,
				cand.created.Local().Format("2006-01-02 15:04:05"), humanBytes(uint64(cand.size)))
		}
		if !confirm("proceed?") {
			return 1
		}
	}
	if dryRun {
		fmt.Printf("[dry-run] would remove %d backup(s)\n", len(toClean))
		return 0
	}
	idx := auditCount()
	rec := &bkp_opRecord{Op: "clean", TS: time.Now().Format("2006-01-02 15:04:05"), Cmd: buildCmdLine(os.Args)}
	okCount, failCount := 0, 0
	for _, cand := range toClean {
		if purge {
			if err := os.RemoveAll(cand.dir); err != nil {
				fmt.Fprintf(os.Stderr, "clean: remove %s: %v\n", cand.id, err)
				failCount++
				continue
			}
			fmt.Printf("%s %s\n", c(clrYellow, "purged"), cand.id)
			rec.CleanedBackups = append(rec.CleanedBackups, cand.id)
			okCount++
			continue
		}
		if err := os.MkdirAll(bkp_archivedRoot(), 0755); err != nil {
			fmt.Fprintf(os.Stderr, "clean: create archive dir: %v\n", err)
			failCount++
			continue
		}
		if cand.size < bkp_smallThreshold {
			dst := filepath.Join(bkp_archivedRoot(), cand.id)
			if err := os.Rename(cand.dir, dst); err != nil {
				if copyErr := bkp_copyDirRecursive(cand.dir, dst); copyErr != nil {
					fmt.Fprintf(os.Stderr, "clean: archive %s: rename: %v; copy: %v\n", cand.id, err, copyErr)
					failCount++
					continue
				}
				_ = os.RemoveAll(cand.dir)
			}
		} else {
			dst := filepath.Join(bkp_archivedRoot(), cand.id+".tar.gz")
			if err := bkp_tarGzDir(cand.dir, dst); err != nil {
				fmt.Fprintf(os.Stderr, "clean: archive %s: %v\n", cand.id, err)
				failCount++
				continue
			}
			os.RemoveAll(cand.dir)
		}
		fmt.Printf("%s %s\n", c(clrYellow, "archived"), cand.id)
		rec.CleanedBackups = append(rec.CleanedBackups, cand.id)
		rec.ArchivedIDs = append(rec.ArchivedIDs, cand.id)
		okCount++
	}
	bkp_saveOp(idx, rec)
	if failCount == 0 {
		return 0
	}
	if okCount == 0 {
		return 2
	}
	return 1
}

func bkp_summarizeOp(rec *bkp_opRecord) string {
	switch rec.Op {
	case "backup":
		return "-> remove backup " + rec.BackupID
	case "restore":
		return "-> restore pre-backup " + rec.PreBackupID
	case "clean":
		return "-> restore " + strconv.Itoa(len(rec.ArchivedIDs)) + " archived backup(s)"
	}
	return ""
}

func bkp_cmdHistory() int {
	lines, err := auditReadLines()
	if err != nil {
		fmt.Fprintf(os.Stderr, "read log: %v\n", err)
		return 4
	}
	if len(lines) == 0 {
		fmt.Fprintln(os.Stderr, "log is empty")
		return 0
	}
	count := 0
	for i := len(lines) - 1; i >= 0; i-- {
		m, cmd, _, ok := auditParseLine(lines[i])
		if !ok || m != "bkp" {
			continue
		}
		if isHistorySelf(cmd) || !moduleManifestExists("bkp", i) {
			continue
		}
		desc := ""
		if rec, e := bkp_loadOp(i); e == nil {
			desc = bkp_summarizeOp(rec)
		}
		count++
		fmt.Printf("[%d] %s %s\n", count, lines[i], c(clrGray, desc))
	}
	if count == 0 {
		fmt.Fprintln(os.Stderr, "no rollback-able bkp operations in log")
	}
	return 0
}

func bkp_cmdRollback(args []string) int {
	n := 1
	for i := 0; i < len(args); i++ {
		if args[i] == "-n" || args[i] == "--last" {
			if i+1 >= len(args) {
				return 2
			}
			v, err := strconv.Atoi(args[i+1])
			if err != nil || v <= 0 {
				return 2
			}
			n = v
			i++
		} else if strings.HasPrefix(args[i], "-") {
			return 2
		}
	}
	idxs, err := moduleTailOps("bkp", n)
	if err != nil || len(idxs) == 0 {
		fmt.Fprintln(os.Stderr, "no rollback-able bkp operations found")
		return 4
	}
	if dryRun {
		for k, i := range idxs {
			if rec, e := bkp_loadOp(i); e == nil {
				fmt.Printf("[dry-run] step %d: %s %s\n", k+1, rec.Op, bkp_summarizeOp(rec))
			}
		}
		return 0
	}
	okCount, failCount := 0, 0
	for k, i := range idxs {
		rec, err := bkp_loadOp(i)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[rollback] step %d: %v\n", k+1, err)
			failCount++
			continue
		}
		fmt.Fprintf(os.Stderr, "[rollback] step %d: %s %s\n", k+1, rec.Op, bkp_summarizeOp(rec))
		if err := bkp_rollbackOne(rec); err != nil {
			fmt.Fprintf(os.Stderr, "[rollback] step %d: error: %v\n", k+1, err)
			failCount++
			continue
		}
		fmt.Fprintf(os.Stderr, "[rollback] step %d: ok\n", k+1)
		okCount++
	}
	if failCount == 0 {
		return 0
	}
	if okCount == 0 {
		return 2
	}
	return 1
}

func bkp_rollbackOne(rec *bkp_opRecord) error {
	switch rec.Op {
	case "backup":
		if rec.BackupID == "" {
			return fmt.Errorf("no backup id recorded")
		}
		return os.RemoveAll(bkp_backupDir(rec.BackupID))
	case "restore":
		if rec.PreBackupID == "" {
			return fmt.Errorf("no pre-backup id recorded")
		}
		dir := bkp_backupDir(rec.PreBackupID)
		m, err := bkp_readManifest(dir)
		if err != nil {
			return fmt.Errorf("read pre-backup: %w", err)
		}
		for _, it := range m.Items {
			if err := bkp_restoreOneItem(dir, it); err != nil {
				return fmt.Errorf("restore %s %s: %w", it.Kind, it.Src, err)
			}
		}
		return nil
	case "clean":
		okCount, failCount := 0, 0
		var firstErr error
		for _, id := range rec.ArchivedIDs {
			smallPath := filepath.Join(bkp_archivedRoot(), id)
			largePath := filepath.Join(bkp_archivedRoot(), id+".tar.gz")
			destDir := bkp_backupDir(id)
			if fi, err := os.Stat(smallPath); err == nil && fi.IsDir() {
				if err := os.Rename(smallPath, destDir); err != nil {
					if copyErr := bkp_copyDirRecursive(smallPath, destDir); copyErr != nil {
						if firstErr == nil {
							firstErr = fmt.Errorf("rename %s: %v; copy: %v", id, err, copyErr)
						}
						failCount++
						continue
					}
					_ = os.RemoveAll(smallPath)
				}
				okCount++
				continue
			}
			if _, err := os.Stat(largePath); err == nil {
				if err := bkp_untarGzTo(largePath, destDir); err != nil {
					if firstErr == nil {
						firstErr = err
					}
					failCount++
					continue
				}
				_ = os.Remove(largePath)
				okCount++
				continue
			}
			if firstErr == nil {
				firstErr = fmt.Errorf("archived backup %s not found", id)
			}
			failCount++
		}
		if okCount == 0 && firstErr != nil {
			return firstErr
		}
		return nil
	}
	return fmt.Errorf("unknown op %q", rec.Op)
}

func bkp_printHelp() {
	fmt.Printf("%s v%s (Windows)\n\n", c(clrBold+clrCyan, "winctl bkp"), Version)
	fmt.Print(`USAGE
  winctl bkp backup [OPTIONS]
  winctl bkp list [--json]
  winctl bkp restore <backup-id> [-f]
  winctl bkp clean [--keep N | --older-than DAYS] [--purge] [-f]
  winctl bkp --history
  winctl bkp --rollback [-n N]

BACKUP
  --file <path>        back up a single file
  --dir  <path>        back up a directory tree (tar + gzip -9)
  --reg  <key>         back up a registry key subtree (reg export)
  --svc  <name>        snapshot a service's start type and state
  --task <name>        back up a scheduled task's XML
  --all-services       snapshot every service
  --all-tasks          back up every scheduled task

RESTORE
  Restores a backup ID. A pre-restore backup is created first, so the
  restore itself is reversible with --rollback.

CLEAN
  --keep N             keep the newest N backups, archive the rest
  --older-than DAYS    archive backups older than DAYS
  --purge              delete without archiving (cannot be recovered)

LAYOUT
  ./backup/winctl_logs.log                shared audit log
  ./backup/bkp/snapshots/<id>/            live snapshots
  ./backup/bkp/archived/<id>/             archived (small)
  ./backup/bkp/archived/<id>.tar.gz       archived (large)
  ./backup/bkp/ops/<auditIdx>.json        per-operation manifest

GLOBAL
  -o, --out <path>  write stdout to a file
  --dry-run         preview only
  --no-color        disable colors
  -b, --bugs        print collected errors/warnings
  -h, --help        show this help
  --version         show version

EXIT CODES
  0 success | 1 partial failure | 2 bad args | 3 permission denied
  4 not found | 5 I/O error
`)
}

func bkp_main() {
	args, outPath, err := consumeGlobalFlags(os.Args[1:])
	if err != nil {
		fmt.Fprintf(os.Stderr, "winctl bkp: %v\n", err)
		finalExit(2)
	}
	initColor()
	if has(args, "--version") {
		fmt.Printf("winctl bkp v%s\n", Version)
		finalExit(0)
	}
	if len(args) == 0 || has(args, "-h", "--help") {
		bkp_printHelp()
		finalExit(0)
	}
	if outPath != "" {
		if err := setupOutput(outPath); err != nil {
			fmt.Fprintf(os.Stderr, "winctl bkp: %v\n", err)
			finalExit(2)
		}
	}
	var code int
	switch {
	case has(args, "--history"):
		code = bkp_cmdHistory()
	case has(args, "--rollback"):
		code = bkp_cmdRollback(stripFlags(args, "--rollback"))
	default:
		cmdIdx := -1
		for i, a := range args {
			if !strings.HasPrefix(a, "-") {
				cmdIdx = i
				break
			}
		}
		if cmdIdx < 0 {
			fmt.Fprintln(os.Stderr, "winctl bkp: missing command, use -h for help")
			code = 2
			break
		}
		cmd := args[cmdIdx]
		rest := append([]string{}, args[:cmdIdx]...)
		rest = append(rest, args[cmdIdx+1:]...)
		switch cmd {
		case "backup", "b":
			code = bkp_cmdBackup(rest)
		case "list", "ls":
			code = bkp_cmdList(rest)
		case "restore", "r":
			code = bkp_cmdRestore(rest)
		case "clean", "c":
			code = bkp_cmdClean(rest)
		default:
			fmt.Fprintf(os.Stderr, "winctl bkp: unknown command %q\n", cmd)
			code = 2
		}
	}
	if !dryRun && shouldLogRun() {
		auditLog("bkp", buildCmdLine(os.Args), code)
	}
	finalExit(code)
}
// ============================================================================
// disk — disk and volume read-only viewer
// ============================================================================

var (
	disk_pCreateFileW                      = kernel32.NewProc("CreateFileW")
	disk_pDeviceIoControl                  = kernel32.NewProc("DeviceIoControl")
	disk_pGetDriveTypeW                    = kernel32.NewProc("GetDriveTypeW")
	disk_pGetVolumeInformationW            = kernel32.NewProc("GetVolumeInformationW")
	disk_pGetDiskFreeSpaceExW              = kernel32.NewProc("GetDiskFreeSpaceExW")
	disk_pFindFirstVolumeW                 = kernel32.NewProc("FindFirstVolumeW")
	disk_pFindNextVolumeW                  = kernel32.NewProc("FindNextVolumeW")
	disk_pFindVolumeClose                  = kernel32.NewProc("FindVolumeClose")
	disk_pGetVolumePathNamesForVolumeNameW = kernel32.NewProc("GetVolumePathNamesForVolumeNameW")
)

type disk_STORAGE_PROPERTY_QUERY struct {
	PropertyId uint32
	QueryType  uint32
	Additional [1]byte
}
type disk_STORAGE_DEVICE_DESCRIPTOR struct {
	Version               uint32
	Size                  uint32
	DeviceType            byte
	DeviceTypeModifier    byte
	RemovableMedia        byte
	CommandQueueing       byte
	VendorIdOffset        uint32
	ProductIdOffset       uint32
	ProductRevisionOffset uint32
	SerialNumberOffset    uint32
	BusType               uint32
	RawPropertiesLength   uint32
	RawDeviceProperties   [1]byte
}
type disk_DEVICE_TRIM_DESCRIPTOR struct {
	Version     uint32
	Size        uint32
	TrimEnabled byte
}
type disk_DISK_GEOMETRY struct {
	Cylinders         int64
	MediaType         uint32
	TracksPerCylinder uint32
	SectorsPerTrack   uint32
	BytesPerSector    uint32
}
type disk_DISK_GEOMETRY_EX struct {
	Geometry disk_DISK_GEOMETRY
	DiskSize int64
	Data     [1]byte
}
type disk_PARTITION_INFORMATION_EX struct {
	PartitionStyle     uint32
	StartingOffset     int64
	PartitionLength    int64
	PartitionNumber    uint32
	RewritePartition   byte
	IsServicePartition byte
	Union              [112]byte
}

type disk_PartitionInfo struct {
	Number uint32 `json:"number"`
	Offset int64  `json:"offset"`
	Length int64  `json:"length"`
	Style  string `json:"style"`
}
type disk_DiskInfo struct {
	Index      uint32              `json:"index"`
	Size       int64               `json:"size"`
	Vendor     string              `json:"vendor,omitempty"`
	Product    string              `json:"product,omitempty"`
	Revision   string              `json:"revision,omitempty"`
	Serial     string              `json:"serial,omitempty"`
	BusType    string              `json:"busType"`
	Removable  bool                `json:"removable"`
	Trim       bool                `json:"trim"`
	Partitions []disk_PartitionInfo `json:"partitions"`
	Error      string              `json:"error,omitempty"`
}
type disk_VolumeInfo struct {
	VolumeID     string `json:"volumeId"`
	DriveLetters string `json:"driveLetters,omitempty"`
	Label        string `json:"label,omitempty"`
	FileSystem   string `json:"fileSystem,omitempty"`
	TotalBytes   uint64 `json:"totalBytes"`
	FreeBytes    uint64 `json:"freeBytes"`
	DriveType    string `json:"driveType"`
}

const (
	disk_GENERIC_READ     = 0x80000000
	disk_FILE_SHARE_READ  = 0x00000001
	disk_FILE_SHARE_WRITE = 0x00000002
	disk_OPEN_EXISTING    = 3

	disk_IOCTL_STORAGE_QUERY_PROPERTY     = 0x2D1400
	disk_IOCTL_DISK_GET_DRIVE_LAYOUT_EX   = 0x70050
	disk_IOCTL_DISK_GET_DRIVE_GEOMETRY_EX = 0x700A0

	disk_StorageDeviceProperty     = 0
	disk_StorageDeviceTrimProperty = 8
	disk_PropertyStandardQuery     = 0
)

func disk_win32UTF16Ptr(s string) *uint16 {
	p, _ := syscall.UTF16PtrFromString(s)
	return p
}

func disk_openDevice(path string) (syscall.Handle, error) {
	p := disk_win32UTF16Ptr(path)
	h, _, err := disk_pCreateFileW.Call(
		uintptr(unsafe.Pointer(p)),
		uintptr(disk_GENERIC_READ),
		uintptr(disk_FILE_SHARE_READ|disk_FILE_SHARE_WRITE),
		0, uintptr(disk_OPEN_EXISTING), 0, 0)
	if syscall.Handle(h) == syscall.InvalidHandle {
		return 0, err
	}
	return syscall.Handle(h), nil
}

func disk_deviceIoControl(h syscall.Handle, code uint32, inBuf []byte, outBuf []byte) (uint32, error) {
	var inPtr, outPtr uintptr
	if len(inBuf) > 0 {
		inPtr = uintptr(unsafe.Pointer(&inBuf[0]))
	}
	if len(outBuf) > 0 {
		outPtr = uintptr(unsafe.Pointer(&outBuf[0]))
	}
	var returned uint32
	r, _, err := disk_pDeviceIoControl.Call(
		uintptr(h), uintptr(code),
		inPtr, uintptr(len(inBuf)),
		outPtr, uintptr(len(outBuf)),
		uintptr(unsafe.Pointer(&returned)), 0)
	if r == 0 {
		return 0, err
	}
	return returned, nil
}

func disk_storageQueryBytes(q *disk_STORAGE_PROPERTY_QUERY) []byte {
	size := int(unsafe.Sizeof(*q))
	return unsafe.Slice((*byte)(unsafe.Pointer(q)), size)
}

func disk_busTypeName(t uint32) string {
	names := map[uint32]string{
		0: "unknown", 1: "SCSI", 2: "ATAPI", 3: "ATA", 4: "1394", 5: "SSA",
		6: "Fibre", 7: "USB", 8: "RAID", 9: "iSCSI", 10: "SAS", 11: "SATA",
		12: "SD", 13: "MMC", 14: "Virtual", 15: "FileBackedVirtual",
		16: "StorageSpaces", 17: "NVMe", 18: "SCM", 19: "UFS",
	}
	if n, ok := names[t]; ok {
		return n
	}
	return fmt.Sprintf("bus-%d", t)
}

func disk_driveTypeName(t uint32) string {
	switch t {
	case 0:
		return "unknown"
	case 1:
		return "no-root"
	case 2:
		return "removable"
	case 3:
		return "fixed"
	case 4:
		return "remote"
	case 5:
		return "cdrom"
	case 6:
		return "ramdisk"
	}
	return fmt.Sprintf("type-%d", t)
}

func disk_cStringAt(buf []byte, offset uint32) string {
	if offset == 0 || int(offset) >= len(buf) {
		return ""
	}
	end := int(offset)
	for end < len(buf) && buf[end] != 0 {
		end++
	}
	return strings.TrimSpace(string(buf[offset:end]))
}

func disk_queryDiskInfo(index uint32) disk_DiskInfo {
	di := disk_DiskInfo{Index: index}
	path := fmt.Sprintf(`\\.\PhysicalDrive%d`, index)
	h, err := disk_openDevice(path)
	if err != nil {
		di.Error = err.Error()
		return di
	}
	defer pCloseHandle.Call(uintptr(h))

	query := disk_STORAGE_PROPERTY_QUERY{PropertyId: disk_StorageDeviceProperty, QueryType: disk_PropertyStandardQuery}
	buf := make([]byte, 1024)
	if n, err := disk_deviceIoControl(h, disk_IOCTL_STORAGE_QUERY_PROPERTY,
		disk_storageQueryBytes(&query), buf); err == nil && n > 0 {
		desc := (*disk_STORAGE_DEVICE_DESCRIPTOR)(unsafe.Pointer(&buf[0]))
		di.Vendor = disk_cStringAt(buf, desc.VendorIdOffset)
		di.Product = disk_cStringAt(buf, desc.ProductIdOffset)
		di.Revision = disk_cStringAt(buf, desc.ProductRevisionOffset)
		di.Serial = disk_cStringAt(buf, desc.SerialNumberOffset)
		di.BusType = disk_busTypeName(desc.BusType)
		di.Removable = desc.RemovableMedia != 0
	}

	query.PropertyId = disk_StorageDeviceTrimProperty
	buf2 := make([]byte, 32)
	if n, err := disk_deviceIoControl(h, disk_IOCTL_STORAGE_QUERY_PROPERTY,
		disk_storageQueryBytes(&query), buf2); err == nil &&
		n >= uint32(unsafe.Sizeof(disk_DEVICE_TRIM_DESCRIPTOR{})) {
		trim := (*disk_DEVICE_TRIM_DESCRIPTOR)(unsafe.Pointer(&buf2[0]))
		di.Trim = trim.TrimEnabled != 0
	}

	geomBuf := make([]byte, 256)
	if n, err := disk_deviceIoControl(h, disk_IOCTL_DISK_GET_DRIVE_GEOMETRY_EX, nil, geomBuf); err == nil && n >= 40 {
		geom := (*disk_DISK_GEOMETRY_EX)(unsafe.Pointer(&geomBuf[0]))
		di.Size = geom.DiskSize
	}

	layoutBuf := make([]byte, 1024*1024)
	if n, err := disk_deviceIoControl(h, disk_IOCTL_DISK_GET_DRIVE_LAYOUT_EX, nil, layoutBuf); err == nil && n >= 8 {
		style := *(*uint32)(unsafe.Pointer(&layoutBuf[0]))
		count := *(*uint32)(unsafe.Pointer(&layoutBuf[4]))
		styleName := "MBR"
		if style == 1 {
			styleName = "GPT"
		}
		off := 48
		entrySize := int(unsafe.Sizeof(disk_PARTITION_INFORMATION_EX{}))
		for i := uint32(0); i < count && off+entrySize <= len(layoutBuf); i++ {
			part := (*disk_PARTITION_INFORMATION_EX)(unsafe.Pointer(&layoutBuf[off]))
			if part.PartitionLength > 0 {
				di.Partitions = append(di.Partitions, disk_PartitionInfo{
					Number: part.PartitionNumber, Offset: part.StartingOffset,
					Length: part.PartitionLength, Style: styleName,
				})
			}
			off += entrySize
		}
	}
	return di
}

func disk_listVolumes() []disk_VolumeInfo {
	var out []disk_VolumeInfo
	buf := make([]uint16, 512)
	h, _, err := disk_pFindFirstVolumeW.Call(uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)))
	if syscall.Handle(h) == syscall.InvalidHandle {
		bugs.Add("WARN", "FindFirstVolume: %v", err)
		return out
	}
	defer disk_pFindVolumeClose.Call(h)
	for {
		volID := strings.TrimSuffix(syscall.UTF16ToString(buf), `\`)
		vi := disk_VolumeInfo{VolumeID: volID}
		disk_queryVolumeInfo(&vi)
		out = append(out, vi)
		buf = make([]uint16, 512)
		r, _, nextErr := disk_pFindNextVolumeW.Call(h,
			uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)))
		if r == 0 {
			if errno, ok := nextErr.(syscall.Errno); ok && errno != ERROR_NO_MORE_FILES {
				bugs.Add("WARN", "FindNextVolume: %v", errno)
			}
			break
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].DriveLetters < out[j].DriveLetters })
	return out
}

func disk_queryVolumeInfo(vi *disk_VolumeInfo) {
	volName := vi.VolumeID + `\`
	pathBuf := make([]uint16, 1024)
	var pathLen uint32
	disk_pGetVolumePathNamesForVolumeNameW.Call(
		uintptr(unsafe.Pointer(disk_win32UTF16Ptr(volName))),
		uintptr(unsafe.Pointer(&pathBuf[0])),
		uintptr(len(pathBuf)), uintptr(unsafe.Pointer(&pathLen)))
	var letters []string
	start := 0
	for i := 0; i < len(pathBuf); i++ {
		if pathBuf[i] == 0 {
			if i == start {
				break
			}
			s := syscall.UTF16ToString(pathBuf[start:i])
			if s != "" {
				letters = append(letters, strings.TrimRight(s, `\`))
			}
			start = i + 1
		}
	}
	vi.DriveLetters = strings.Join(letters, ",")
	root := volName
	if len(letters) > 0 {
		root = letters[0] + `\`
	}
	labelBuf := make([]uint16, 256)
	fsBuf := make([]uint16, 256)
	var serial, maxComp, fsFlags uint32
	if r, _, _ := disk_pGetVolumeInformationW.Call(
		uintptr(unsafe.Pointer(disk_win32UTF16Ptr(root))),
		uintptr(unsafe.Pointer(&labelBuf[0])), uintptr(len(labelBuf)),
		uintptr(unsafe.Pointer(&serial)), uintptr(unsafe.Pointer(&maxComp)),
		uintptr(unsafe.Pointer(&fsFlags)),
		uintptr(unsafe.Pointer(&fsBuf[0])), uintptr(len(fsBuf))); r != 0 {
		vi.Label = syscall.UTF16ToString(labelBuf)
		vi.FileSystem = syscall.UTF16ToString(fsBuf)
	}
	if len(letters) > 0 {
		var free, total, avail uint64
		if r, _, _ := disk_pGetDiskFreeSpaceExW.Call(
			uintptr(unsafe.Pointer(disk_win32UTF16Ptr(letters[0]+`\`))),
			uintptr(unsafe.Pointer(&free)), uintptr(unsafe.Pointer(&total)),
			uintptr(unsafe.Pointer(&avail))); r != 0 {
			vi.TotalBytes = total
			vi.FreeBytes = free
		}
	}
	if len(letters) > 0 {
		dt, _, _ := disk_pGetDriveTypeW.Call(uintptr(unsafe.Pointer(disk_win32UTF16Ptr(letters[0] + `\`))))
		vi.DriveType = disk_driveTypeName(uint32(dt))
	}
}

func disk_printDisks(disks []disk_DiskInfo) {
	fmt.Println(c(clrBold+clrCyan, "Physical disks"))
	fmt.Println()
	for _, d := range disks {
		if d.Error != "" {
			fmt.Printf("  %s %s\n", c(clrRed, fmt.Sprintf("Disk %d:", d.Index)), d.Error)
			continue
		}
		fmt.Printf("  %s\n", c(clrBold+clrCyan, fmt.Sprintf("Disk %d", d.Index)))
		fmt.Printf("    %s %s\n", c(clrCyan, "Size:     "), humanBytes(uint64(d.Size)))
		if d.Vendor != "" || d.Product != "" {
			fmt.Printf("    %s %s %s\n", c(clrCyan, "Model:    "), d.Vendor, d.Product)
		}
		if d.Revision != "" {
			fmt.Printf("    %s %s\n", c(clrCyan, "Revision: "), d.Revision)
		}
		if d.Serial != "" {
			fmt.Printf("    %s %s\n", c(clrCyan, "Serial:   "), d.Serial)
		}
		fmt.Printf("    %s %s\n", c(clrCyan, "Bus:      "), d.BusType)
		fmt.Printf("    %s %v\n", c(clrCyan, "Removable:"), d.Removable)
		fmt.Printf("    %s %v\n", c(clrCyan, "TRIM:     "), d.Trim)
		if len(d.Partitions) > 0 {
			fmt.Printf("    %s %d\n", c(clrCyan, "Partitions:"), len(d.Partitions))
			for _, p := range d.Partitions {
				fmt.Printf("      #%d  %s  offset=%s\n", p.Number,
					humanBytes(uint64(p.Length)), humanBytes(uint64(p.Offset)))
			}
		}
		fmt.Println()
	}
}

func disk_printVolumes(vols []disk_VolumeInfo) {
	fmt.Println(c(clrBold+clrCyan, "Volumes"))
	fmt.Println()
	volW := dispWidth("VOLUME")
	letterW := dispWidth("LETTERS")
	for _, v := range vols {
		if w := dispWidth(v.VolumeID); w > volW {
			volW = w
		}
		if w := dispWidth(v.DriveLetters); w > letterW {
			letterW = w
		}
	}
	header := padRight("VOLUME", volW) + "  " +
		padRight("LETTERS", letterW) + "  " +
		padRight("LABEL", 20) + "  " +
		padRight("FS", 8) + "  " +
		padRight("TYPE", 10) + "  " +
		padRight("TOTAL", 10) + "  " +
		padRight("FREE", 10) + "  USED%"
	fmt.Println(c(clrBold+clrCyan, header))
	for _, v := range vols {
		usedPct := 0.0
		if v.TotalBytes > 0 {
			usedPct = (1 - float64(v.FreeBytes)/float64(v.TotalBytes)) * 100
		}
		fmt.Println(padRight(v.VolumeID, volW)+"  "+
			padRight(v.DriveLetters, letterW)+"  "+
			padRight(v.Label, 20)+"  "+
			padRight(v.FileSystem, 8)+"  "+
			padRight(v.DriveType, 10)+"  "+
			padRight(humanBytes(v.TotalBytes), 10)+"  "+
			padRight(humanBytes(v.FreeBytes), 10)+"  "+
			fmt.Sprintf("%5.1f%%", usedPct))
	}
}

func disk_cmdHistory() int {
	lines, err := auditReadLines()
	if err != nil {
		fmt.Fprintf(os.Stderr, "read log: %v\n", err)
		return 4
	}
	if len(lines) == 0 {
		fmt.Fprintln(os.Stderr, "log is empty")
		return 0
	}
	count := 0
	for i := len(lines) - 1; i >= 0; i-- {
		m, _, _, ok := auditParseLine(lines[i])
		if !ok || m != "disk" {
			continue
		}
		count++
		fmt.Printf("[%d] %s\n", count, lines[i])
	}
	if count == 0 {
		fmt.Fprintln(os.Stderr, "no disk history entries in log")
	}
	return 0
}

func disk_cmdRollback() int {
	fmt.Fprintln(os.Stderr, "winctl disk is read-only: there are no operations to roll back")
	fmt.Fprintln(os.Stderr, "  It only reads disk and volume metadata.")
	fmt.Fprintln(os.Stderr, "  Its history is for audit only; use --history to view it.")
	return 0
}

func disk_printHelp() {
	fmt.Printf("%s v%s (Windows)\n\n", c(clrBold+clrCyan, "winctl disk"), Version)
	fmt.Print(`USAGE
  winctl disk                 list disks and volumes
  winctl disk disks           disks only
  winctl disk volumes         volumes only
  winctl disk --json          JSON output
  winctl disk --history
  winctl disk --rollback      (always a no-op: read-only)

OPTIONS
  --json           machine-readable JSON output
  -o, --out <path> redirect stdout to a file
  --dry-run        print the plan without touching any device
  --no-color       disable ANSI colors (also honors NO_COLOR)
  -b, --bugs       print collected errors/warnings on exit
  -h, --help       show this help
  --version        show version

READ-ONLY BY DESIGN
  winctl disk never writes to any disk or volume.

All logs go to ./backup/winctl_logs.log
`)
}

func disk_main() {
	args, outPath, err := consumeGlobalFlags(os.Args[1:])
	if err != nil {
		fmt.Fprintf(os.Stderr, "winctl disk: %v\n", err)
		finalExit(2)
	}
	initColor()
	if has(args, "--version") {
		fmt.Printf("winctl disk v%s\n", Version)
		finalExit(0)
	}
	if len(args) == 0 {
		// default: list everything
	} else if has(args, "-h", "--help") {
		disk_printHelp()
		finalExit(0)
	} else if has(args, "--history") {
		code := disk_cmdHistory()
		auditLog("disk", buildCmdLine(os.Args), code)
		finalExit(code)
	} else if has(args, "--rollback") {
		code := disk_cmdRollback()
		auditLog("disk", buildCmdLine(os.Args), code)
		finalExit(code)
	} else if has(args, "disks") || has(args, "volumes") || has(args, "--json") {
		// handled below
	} else {
		fmt.Fprintf(os.Stderr, "winctl disk: unexpected argument %q (use -h for help)\n", args[0])
		finalExit(2)
	}
	if outPath != "" {
		if err := setupOutput(outPath); err != nil {
			fmt.Fprintf(os.Stderr, "winctl disk: %v\n", err)
			finalExit(2)
		}
	}
	if dryRun {
		fmt.Println("[dry-run] would enumerate physical disks and volumes")
		finalExit(0)
	}
	showDisks, showVolumes, jsonOut := true, true, false
	for _, a := range args {
		switch a {
		case "disks":
			showVolumes = false
		case "volumes":
			showDisks = false
		case "--json":
			jsonOut = true
		}
	}
	var disks []disk_DiskInfo
	var vols []disk_VolumeInfo
	if showDisks {
		for i := uint32(0); i < 32; i++ {
			di := disk_queryDiskInfo(i)
			if di.Error != "" {
				low := strings.ToLower(di.Error)
				if strings.Contains(low, "not found") ||
					strings.Contains(low, "system cannot find") ||
					strings.Contains(low, "找不到") {
					break
				}
				bugs.Add("WARN", "disk %d: %v", i, di.Error)
				continue
			}
			disks = append(disks, di)
		}
	}
	if showVolumes {
		vols = disk_listVolumes()
	}
	if jsonOut {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(map[string]any{"disks": disks, "volumes": vols})
	} else {
		if showDisks && len(disks) > 0 {
			disk_printDisks(disks)
		}
		if showVolumes && len(vols) > 0 {
			disk_printVolumes(vols)
		}
	}
	if !dryRun && shouldLogRun() {
		auditLog("disk", buildCmdLine(os.Args), 0)
	}
	finalExit(0)
}
// ============================================================================
// doc — environment diagnostics (read-only)
// ============================================================================

var (
	doc_ntdll = syscall.NewLazyDLL("ntdll.dll")

	doc_pRtlGetVersion       = doc_ntdll.NewProc("RtlGetVersion")
	doc_pGetNativeSystemInfo = kernel32.NewProc("GetNativeSystemInfo")
	doc_pGetACP              = kernel32.NewProc("GetACP")
	doc_pGetOEMCP            = kernel32.NewProc("GetOEMCP")
	doc_pGetConsoleOutputCP  = kernel32.NewProc("GetConsoleOutputCP")
	doc_pGetCurrentProcess   = kernel32.NewProc("GetCurrentProcess")

	doc_pOpenProcessToken    = advapi32.NewProc("OpenProcessToken")
	doc_pGetTokenInformation = advapi32.NewProc("GetTokenInformation")
)

type doc_OSVERSIONINFOW struct {
	OSVersionInfoSize uint32
	MajorVersion      uint32
	MinorVersion      uint32
	BuildNumber       uint32
	PlatformID        uint32
	CSDVersion        [128]uint16
}

type doc_SYSTEM_INFO struct {
	ProcessorArchitecture     uint16
	Reserved                  uint16
	PageSize                  uint32
	MinimumApplicationAddress uintptr
	MaximumApplicationAddress uintptr
	ActiveProcessorMask       uintptr
	NumberOfProcessors        uint32
	ProcessorType             uint32
	AllocationGranularity     uint32
	ProcessorLevel            uint16
	ProcessorRevision         uint16
}

type doc_TOKEN_ELEVATION struct{ TokenIsElevated uint32 }

const (
	doc_PROCESSOR_ARCHITECTURE_INTEL = 0
	doc_PROCESSOR_ARCHITECTURE_ARM   = 5
	doc_PROCESSOR_ARCHITECTURE_IA64  = 6
	doc_PROCESSOR_ARCHITECTURE_AMD64 = 9
	doc_PROCESSOR_ARCHITECTURE_ARM64 = 12

	doc_TOKEN_QUERY    = 0x0008
	doc_TokenElevation = 20
)

var doc_reportMode = false

func doc_archName(a uint16) string {
	switch a {
	case doc_PROCESSOR_ARCHITECTURE_INTEL:
		return "x86"
	case doc_PROCESSOR_ARCHITECTURE_ARM:
		return "ARM"
	case doc_PROCESSOR_ARCHITECTURE_IA64:
		return "IA64"
	case doc_PROCESSOR_ARCHITECTURE_AMD64:
		return "x64"
	case doc_PROCESSOR_ARCHITECTURE_ARM64:
		return "ARM64"
	}
	return fmt.Sprintf("0x%X", a)
}

func doc_regReadDWORD(root uintptr, subKey, name string) (uint32, bool) {
	subPtr, err := syscall.UTF16PtrFromString(subKey)
	if err != nil {
		return 0, false
	}
	var hKey uintptr
	r, _, _ := pRegOpenKeyExW.Call(root, uintptr(unsafe.Pointer(subPtr)), 0,
		uintptr(KEY_READ|KEY_WOW64_64KEY), uintptr(unsafe.Pointer(&hKey)))
	if r != 0 {
		return 0, false
	}
	defer pRegCloseKey.Call(hKey)
	namePtr, err := syscall.UTF16PtrFromString(name)
	if err != nil {
		return 0, false
	}
	var typ, size uint32
	buf := make([]byte, 4)
	size = 4
	r, _, _ = pRegQueryValueExW.Call(hKey, uintptr(unsafe.Pointer(namePtr)), 0,
		uintptr(unsafe.Pointer(&typ)), uintptr(unsafe.Pointer(&buf[0])),
		uintptr(unsafe.Pointer(&size)))
	if r != 0 || typ != REG_DWORD || size < 4 {
		return 0, false
	}
	return binary.LittleEndian.Uint32(buf), true
}

type doc_CheckResult struct {
	Category string `json:"category"`
	Name     string `json:"name"`
	Status   string `json:"status"`
	Value    string `json:"value"`
	Detail   string `json:"detail,omitempty"`
}

func doc_osVersionInfo() (name, version string, build uint32, ok bool) {
	var vi doc_OSVERSIONINFOW
	vi.OSVersionInfoSize = uint32(unsafe.Sizeof(vi))
	r, _, _ := doc_pRtlGetVersion.Call(uintptr(unsafe.Pointer(&vi)))
	if r != 0 {
		return "unknown", "unknown", 0, false
	}
	build = vi.BuildNumber
	version = fmt.Sprintf("%d.%d.%d", vi.MajorVersion, vi.MinorVersion, vi.BuildNumber)
	switch {
	case vi.MajorVersion == 10 && build >= 26100:
		name = "Windows 11 24H2 / Server 2025"
	case vi.MajorVersion == 10 && build >= 22631:
		name = "Windows 11 23H2"
	case vi.MajorVersion == 10 && build >= 22621:
		name = "Windows 11 22H2"
	case vi.MajorVersion == 10 && build >= 22000:
		name = "Windows 11 21H2"
	case vi.MajorVersion == 10 && build >= 19045:
		name = "Windows 10 22H2"
	case vi.MajorVersion == 10 && build >= 19044:
		name = "Windows 10 21H2"
	case vi.MajorVersion == 10 && build >= 19041:
		name = "Windows 10 2004"
	case vi.MajorVersion == 10 && build >= 17763:
		name = "Windows 10 1809 / Server 2019"
	case vi.MajorVersion == 10:
		name = "Windows 10"
	case vi.MajorVersion == 6 && vi.MinorVersion == 3:
		name = "Windows 8.1 / Server 2012 R2"
	case vi.MajorVersion == 6 && vi.MinorVersion == 2:
		name = "Windows 8 / Server 2012"
	case vi.MajorVersion == 6 && vi.MinorVersion == 1:
		name = "Windows 7 / Server 2008 R2"
	case vi.MajorVersion == 6 && vi.MinorVersion == 0:
		name = "Windows Vista / Server 2008"
	default:
		name = version
	}
	return
}

func doc_systemInfo() (string, uint32) {
	var si doc_SYSTEM_INFO
	doc_pGetNativeSystemInfo.Call(uintptr(unsafe.Pointer(&si)))
	return doc_archName(si.ProcessorArchitecture), si.NumberOfProcessors
}

func doc_isAdmin() bool {
	h, _, _ := doc_pGetCurrentProcess.Call()
	if h == 0 {
		return false
	}
	var token syscall.Handle
	r, _, _ := doc_pOpenProcessToken.Call(h, doc_TOKEN_QUERY, uintptr(unsafe.Pointer(&token)))
	if r == 0 {
		return false
	}
	defer pCloseHandle.Call(uintptr(token))
	var elev doc_TOKEN_ELEVATION
	var size uint32
	r, _, _ = doc_pGetTokenInformation.Call(uintptr(token), doc_TokenElevation,
		uintptr(unsafe.Pointer(&elev)), uintptr(unsafe.Sizeof(elev)),
		uintptr(unsafe.Pointer(&size)))
	if r == 0 {
		return false
	}
	return elev.TokenIsElevated != 0
}

func doc_cpName(cp uint32) string {
	if cp == 0 {
		return "unknown"
	}
	names := map[uint32]string{
		65001: "utf-8", 936: "gbk", 950: "big5", 932: "shift-jis",
		949: "euc-kr", 1252: "windows-1252", 1251: "windows-1251",
		1250: "windows-1250", 437: "cp437", 850: "cp850", 852: "cp852", 866: "cp866",
	}
	if n, ok := names[cp]; ok {
		return n
	}
	return fmt.Sprintf("cp%d", cp)
}

func doc_titleCase(s string) string {
	if s == "" {
		return s
	}
	r := []rune(s)
	if r[0] >= 'a' && r[0] <= 'z' {
		r[0] -= 'a' - 'A'
	}
	return string(r)
}

// doc_backupDirNames — every module's backup directory. 1.2.0 adds "box".
var doc_backupDirNames = []string{
	"net", "open", "pe", "proc", "reg", "svc", "sys", "task", "acl", "bkp",
	"disk", "doc", "evt", "fs", "hash", "batch", "box",
}

var doc_expectedTools = []string{
	"winctl.exe",
}

func doc_isDirWritable(dir string) (bool, string) {
	probe := dir
	if fi, err := os.Stat(dir); err != nil {
		probe = filepath.Dir(dir)
	} else if !fi.IsDir() {
		return false, "exists but is not a directory"
	}
	f, err := os.CreateTemp(probe, ".winctl_probe_*")
	if err != nil {
		return false, err.Error()
	}
	name := f.Name()
	f.Close()
	_ = os.Remove(name)
	return true, ""
}

type doc_toolInfo struct {
	Name    string
	Path    string
	Exists  bool
	ValidPE bool
	Machine string
	Bits    string
	Size    int64
	Error   string
}

func doc_checkTool(dir, name string) doc_toolInfo {
	t := doc_toolInfo{Name: name, Path: filepath.Join(dir, name)}
	fi, err := os.Stat(t.Path)
	if err != nil {
		return t
	}
	t.Exists = true
	t.Size = fi.Size()
	if fi.IsDir() {
		t.Error = "is a directory"
		return t
	}
	f, err := pe.Open(t.Path)
	if err != nil {
		t.Error = err.Error()
		return t
	}
	defer f.Close()
	t.ValidPE = true
	t.Machine = machineName(f.FileHeader.Machine)
	switch f.FileHeader.Machine {
	case 0x8664, 0xAA64, 0x0200:
		t.Bits = "64-bit"
	case 0x014C, 0x01C4:
		t.Bits = "32-bit"
	default:
		t.Bits = "unknown"
	}
	return t
}

func doc_runChecks() []doc_CheckResult {
	var results []doc_CheckResult
	exe := exeDir()

	winName, winVer, winBuild, winOK := doc_osVersionInfo()
	if winOK {
		results = append(results, doc_CheckResult{
			Category: "system", Name: "Windows", Status: "ok",
			Value: fmt.Sprintf("%s (%s, build %d)", winName, winVer, winBuild),
		})
	} else {
		results = append(results, doc_CheckResult{
			Category: "system", Name: "Windows", Status: "error", Value: "RtlGetVersion failed",
		})
	}

	sysArch, cpus := doc_systemInfo()
	results = append(results, doc_CheckResult{
		Category: "system", Name: "System arch", Status: "ok",
		Value: fmt.Sprintf("%s, %d logical CPU(s)", sysArch, cpus),
	})

	ptrSize := int(unsafe.Sizeof(uintptr(0)))
	if ptrSize != 8 {
		results = append(results, doc_CheckResult{
			Category: "system", Name: "Process arch", Status: "warn",
			Value: fmt.Sprintf("%s (%d-bit pointer)", runtime.GOARCH, ptrSize*8),
			Detail: "this binary is supposed to be 64-bit; something is wrong with the build",
		})
	} else {
		results = append(results, doc_CheckResult{
			Category: "system", Name: "Process arch", Status: "ok",
			Value: fmt.Sprintf("%s (64-bit, %d-byte pointers)", runtime.GOARCH, ptrSize),
		})
	}

	if doc_isAdmin() {
		results = append(results, doc_CheckResult{
			Category: "security", Name: "Admin rights", Status: "ok", Value: "yes (elevated)",
		})
	} else {
		results = append(results, doc_CheckResult{
			Category: "security", Name: "Admin rights", Status: "info",
			Value: "no (running as standard user)",
			Detail: "operations that touch HKLM, services, or system tasks will need elevation",
		})
	}

	acpRaw, _, _ := doc_pGetACP.Call()
	oemRaw, _, _ := doc_pGetOEMCP.Call()
	outCPRaw, _, _ := doc_pGetConsoleOutputCP.Call()
	acp, oem, outCP := uint32(acpRaw), uint32(oemRaw), uint32(outCPRaw)
	results = append(results, doc_CheckResult{
		Category: "encoding", Name: "Console output CP", Status: "ok",
		Value: fmt.Sprintf("%d (%s)", outCP, doc_cpName(outCP)),
	})
	results = append(results, doc_CheckResult{
		Category: "encoding", Name: "ANSI code page", Status: "ok",
		Value: fmt.Sprintf("%d (%s)", acp, doc_cpName(acp)),
	})
	results = append(results, doc_CheckResult{
		Category: "encoding", Name: "OEM code page", Status: "ok",
		Value: fmt.Sprintf("%d (%s)", oem, doc_cpName(oem)),
	})

	if v, ok := doc_regReadDWORD(HKLM,
		`SYSTEM\CurrentControlSet\Control\FileSystem`, "LongPathsEnabled"); ok {
		if v != 0 {
			results = append(results, doc_CheckResult{
				Category: "system", Name: "Long paths", Status: "ok",
				Value: "enabled (LongPathsEnabled=1)",
			})
		} else {
			results = append(results, doc_CheckResult{
				Category: "system", Name: "Long paths", Status: "warn",
				Value:  "disabled (LongPathsEnabled=0)",
				Detail: "paths longer than MAX_PATH will fail",
			})
		}
	} else {
		results = append(results, doc_CheckResult{
			Category: "system", Name: "Long paths", Status: "warn",
			Value:  "not configured (LongPathsEnabled missing)",
			Detail: "treat as disabled; paths longer than MAX_PATH will fail",
		})
	}

	for _, m := range doc_backupDirNames {
		dir := filepath.Join(exe, backupDirName, m)
		writable, why := doc_isDirWritable(dir)
		if writable {
			results = append(results, doc_CheckResult{
				Category: "backup", Name: "backup/" + m, Status: "ok", Value: dir,
			})
		} else {
			results = append(results, doc_CheckResult{
				Category: "backup", Name: "backup/" + m, Status: "error", Value: dir, Detail: why,
			})
		}
	}

	curExe := strings.ToLower(filepath.Base(doc_exePath()))
	for _, name := range doc_expectedTools {
		if strings.ToLower(name) == curExe {
			continue
		}
		t := doc_checkTool(exe, name)
		switch {
		case !t.Exists:
			results = append(results, doc_CheckResult{
				Category: "tools", Name: t.Name, Status: "warn", Value: "missing", Detail: t.Path,
			})
		case t.Error != "":
			results = append(results, doc_CheckResult{
				Category: "tools", Name: t.Name, Status: "error",
				Value: fmt.Sprintf("%d bytes", t.Size), Detail: t.Error,
			})
		case t.Bits != "64-bit":
			results = append(results, doc_CheckResult{
				Category: "tools", Name: t.Name, Status: "error",
				Value: fmt.Sprintf("%s (%s), %s", t.Bits, t.Machine, humanBytes(uint64(t.Size))),
				Detail: "expected a 64-bit executable",
			})
		default:
			results = append(results, doc_CheckResult{
				Category: "tools", Name: t.Name, Status: "ok",
				Value: fmt.Sprintf("64-bit, %s", humanBytes(uint64(t.Size))),
			})
		}
	}
	return results
}

func doc_exePath() string {
	if e, err := os.Executable(); err == nil {
		return e
	}
	return "winctl.exe"
}

func doc_statusLabel(s string) string {
	switch s {
	case "ok":
		return "ok"
	case "warn":
		return "WARN"
	case "error":
		return "FAIL"
	case "info":
		return "info"
	}
	return s
}
func doc_statusColor(s string) string {
	switch s {
	case "ok":
		return clrGreen
	case "warn":
		return clrYellow
	case "error":
		return clrBold + clrRed
	case "info":
		return clrCyan
	}
	return clrGray
}

func doc_printInteractive(results []doc_CheckResult) {
	fmt.Println()
	fmt.Println(c(clrBold+clrCyan, "════════════════════════════════════════════════════════════════"))
	fmt.Printf("%s\n", c(clrBold+clrCyan, "  winctl doc v"+Version+" — Windows Environment Diagnostics"))
	fmt.Printf("  %s\n", c(clrGray, "Generated: "+time.Now().Format("2006-01-02 15:04:05")))
	fmt.Println(c(clrBold+clrCyan, "════════════════════════════════════════════════════════════════"))
	groups := map[string][]doc_CheckResult{}
	var order []string
	for _, r := range results {
		if _, ok := groups[r.Category]; !ok {
			order = append(order, r.Category)
		}
		groups[r.Category] = append(groups[r.Category], r)
	}
	for _, cat := range order {
		fmt.Println()
		fmt.Println(c(clrBold+clrCyan, "["+doc_titleCase(cat)+"]"))
		for _, r := range groups[cat] {
			label := doc_statusLabel(r.Status)
			labelPad := padRight(label, 4)
			valueStr := r.Value
			if valueStr == "" {
				valueStr = "-"
			}
			nameW := 22
			if len(r.Name) > nameW {
				nameW = len(r.Name)
			}
			fmt.Printf("  %s  %s  %s\n",
				c(doc_statusColor(r.Status), labelPad), padRight(r.Name, nameW), valueStr)
			if r.Detail != "" {
				fmt.Printf("  %s  %s  %s\n", "    ", strings.Repeat(" ", nameW), c(clrGray, r.Detail))
			}
		}
	}
	warns, errors := 0, 0
	for _, r := range results {
		switch r.Status {
		case "warn":
			warns++
		case "error":
			errors++
		}
	}
	fmt.Println()
	fmt.Println(c(clrBold+clrCyan, "────────────────────────────────────────────────────────────────"))
	summary := fmt.Sprintf("  %d check(s), %d warning(s), %d error(s)", len(results), warns, errors)
	switch {
	case errors > 0:
		fmt.Println(c(clrBold+clrRed, summary))
	case warns > 0:
		fmt.Println(c(clrYellow, summary))
	default:
		fmt.Println(c(clrGreen, summary))
	}
	fmt.Println(c(clrBold+clrCyan, "────────────────────────────────────────────────────────────────"))
}

func doc_printReport(results []doc_CheckResult) {
	fmt.Printf("===============================================================\n")
	fmt.Printf("winctl doc v%s - Windows Environment Diagnostics\n", Version)
	fmt.Printf("Generated: %s\n", time.Now().Format("2006-01-02 15:04:05"))
	fmt.Printf("===============================================================\n")
	groups := map[string][]doc_CheckResult{}
	var order []string
	for _, r := range results {
		if _, ok := groups[r.Category]; !ok {
			order = append(order, r.Category)
		}
		groups[r.Category] = append(groups[r.Category], r)
	}
	for _, cat := range order {
		fmt.Println()
		fmt.Println("[" + doc_titleCase(cat) + "]")
		for _, r := range groups[cat] {
			fmt.Printf("  %-22s %-5s %s\n", r.Name, "["+doc_statusLabel(r.Status)+"]", r.Value)
			if r.Detail != "" {
				fmt.Printf("  %-22s       %s\n", "", r.Detail)
			}
		}
	}
	warns, errors := 0, 0
	for _, r := range results {
		switch r.Status {
		case "warn":
			warns++
		case "error":
			errors++
		}
	}
	fmt.Println()
	fmt.Println("----------------------------------------------------------------")
	fmt.Printf("Summary: %d check(s), %d warning(s), %d error(s)\n", len(results), warns, errors)
	fmt.Println("----------------------------------------------------------------")
}

func doc_printJSON(results []doc_CheckResult) {
	b, _ := json.MarshalIndent(results, "", "  ")
	fmt.Println(string(b))
}

func doc_cmdHistory() int {
	lines, err := auditReadLines()
	if err != nil {
		fmt.Fprintf(os.Stderr, "read log: %v\n", err)
		return 4
	}
	if len(lines) == 0 {
		fmt.Fprintln(os.Stderr, "log is empty")
		return 0
	}
	count := 0
	for i := len(lines) - 1; i >= 0; i-- {
		m, _, _, ok := auditParseLine(lines[i])
		if !ok || m != "doc" {
			continue
		}
		count++
		fmt.Printf("[%d] %s\n", count, lines[i])
	}
	if count == 0 {
		fmt.Fprintln(os.Stderr, "no doc history entries in log")
	}
	return 0
}

func doc_cmdRollback() int {
	fmt.Fprintln(os.Stderr, "winctl doc is read-only: there are no operations to roll back")
	fmt.Fprintln(os.Stderr, "  It only inspects the environment and prints a report.")
	fmt.Fprintln(os.Stderr, "  Its history is for audit only; use --history to view it.")
	return 0
}

func doc_printHelp() {
	fmt.Printf("%s v%s (Windows)\n\n", c(clrBold+clrCyan, "winctl doc"), Version)
	fmt.Print(`USAGE
  winctl doc                 run diagnostics, coloured output
  winctl doc --report        plain text (easy to copy)
  winctl doc --json          JSON output
  winctl doc --history
  winctl doc --rollback      (always a no-op: read-only)

WHAT IS CHECKED
  [System]   Windows version / build, system arch, process arch, long paths
  [Security] whether the current token is elevated
  [Encoding] console/ANSI/OEM code pages
  [Backup]   every module's ./backup/<module>/ dir is writable
             (1.2.0 adds box to the list)
  [Tools]    winctl.exe is a 64-bit PE

GLOBAL
  -o, --out <path>  write stdout to a file
  --dry-run         print the plan without running any checks
  --no-color        disable ANSI colors (also honors NO_COLOR)
  -b, --bugs        print collected errors/warnings on exit
  -h, --help        show this help
  --version         show version

EXIT CODES
  0 all checks passed (or only warnings)
  1 at least one error was reported
  2 bad args

All logs go to ./backup/winctl_logs.log
`)
}

func doc_main() {
	args, outPath, err := consumeGlobalFlags(os.Args[1:])
	if err != nil {
		fmt.Fprintf(os.Stderr, "winctl doc: %v\n", err)
		finalExit(2)
	}
	for i, a := range args {
		if a == "--report" {
			doc_reportMode = true
			args = append(args[:i], args[i+1:]...)
			break
		}
	}
	initColor()
	if doc_reportMode {
		useColor = false
	}
	if has(args, "--version") {
		fmt.Printf("winctl doc v%s\n", Version)
		finalExit(0)
	}
	if len(args) == 0 {
		// default: run checks
	} else if has(args, "-h", "--help") {
		doc_printHelp()
		finalExit(0)
	} else if has(args, "--history") {
		code := doc_cmdHistory()
		auditLog("doc", buildCmdLine(os.Args), code)
		finalExit(code)
	} else if has(args, "--rollback") {
		code := doc_cmdRollback()
		auditLog("doc", buildCmdLine(os.Args), code)
		finalExit(code)
	} else if has(args, "--json") {
		// handled below
	} else {
		fmt.Fprintf(os.Stderr, "winctl doc: unexpected argument %q (use -h for help)\n", args[0])
		finalExit(2)
	}
	if outPath != "" {
		if err := setupOutput(outPath); err != nil {
			fmt.Fprintf(os.Stderr, "winctl doc: %v\n", err)
			finalExit(2)
		}
	}
	if dryRun {
		fmt.Printf("[dry-run] would run %d backup-dir probes\n", len(doc_backupDirNames))
		fmt.Printf("[dry-run] would query OS version, encoding, long paths, and admin rights\n")
		finalExit(0)
	}
	results := doc_runChecks()
	if doc_reportMode {
		doc_printReport(results)
	} else if has(args, "--json") {
		doc_printJSON(results)
	} else {
		doc_printInteractive(results)
	}
	exitCode := 0
	for _, r := range results {
		if r.Status == "error" {
			exitCode = 1
			break
		}
	}
	if !dryRun && shouldLogRun() {
		auditLog("doc", buildCmdLine(os.Args), exitCode)
	}
	finalExit(exitCode)
}
// ============================================================================
// evt — event log query (read-only)
// ============================================================================

var (
	evt_wevtapi = syscall.NewLazyDLL("wevtapi.dll")

	evt_pEvtQuery         = evt_wevtapi.NewProc("EvtQuery")
	evt_pEvtNext          = evt_wevtapi.NewProc("EvtNext")
	evt_pEvtRender        = evt_wevtapi.NewProc("EvtRender")
	evt_pEvtFormatMessage = evt_wevtapi.NewProc("EvtFormatMessage")
	evt_pEvtClose         = evt_wevtapi.NewProc("EvtClose")
)

const (
	evt_EvtQueryChannelPath       = 0x1
	evt_EvtQueryForwardDirection  = 0x100
	evt_EvtQueryReverseDirection  = 0x200
	evt_EvtRenderEventXml         = 1
	evt_EvtFormatMessageEvent     = 1
	evt_ERROR_INSUFFICIENT_BUFFER = syscall.Errno(122)
)

func evt_initAPIs() error {
	for name, proc := range map[string]*syscall.LazyProc{
		"EvtQuery": evt_pEvtQuery, "EvtNext": evt_pEvtNext,
		"EvtRender": evt_pEvtRender, "EvtFormatMessage": evt_pEvtFormatMessage,
		"EvtClose": evt_pEvtClose,
	} {
		if err := proc.Find(); err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
	}
	return nil
}

func evt_evtQuery(path, query string, flags uint32) (uintptr, error) {
	var pathPtr, queryPtr *uint16
	var err error
	if path != "" {
		pathPtr, err = syscall.UTF16PtrFromString(path)
		if err != nil {
			return 0, err
		}
	}
	if query != "" {
		queryPtr, err = syscall.UTF16PtrFromString(query)
		if err != nil {
			return 0, err
		}
	}
	var pathU, queryU uintptr
	if pathPtr != nil {
		pathU = uintptr(unsafe.Pointer(pathPtr))
	}
	if queryPtr != nil {
		queryU = uintptr(unsafe.Pointer(queryPtr))
	}
	r, _, callErr := evt_pEvtQuery.Call(0, pathU, queryU, uintptr(flags))
	if r == 0 {
		if callErr != nil {
			return 0, callErr
		}
		return 0, fmt.Errorf("EvtQuery failed")
	}
	return r, nil
}

func evt_evtNextBatch(resultSet uintptr, batch uint32) ([]uintptr, bool, error) {
	if batch == 0 {
		batch = 32
	}
	hbuf := make([]uintptr, batch)
	var returned uint32
	r, _, callErr := evt_pEvtNext.Call(resultSet, uintptr(batch),
		uintptr(unsafe.Pointer(&hbuf[0])), 0, 0,
		uintptr(unsafe.Pointer(&returned)))
	if r != 0 {
		return hbuf[:returned], true, nil
	}
	if callErr != nil {
		if errno, ok := callErr.(syscall.Errno); ok && errno == ERROR_NO_MORE_ITEMS {
			return nil, false, nil
		}
		return nil, false, callErr
	}
	return nil, false, fmt.Errorf("EvtNext failed")
}

func evt_evtRenderXML(evt uintptr) (string, error) {
	var needed, propCount uint32
	evt_pEvtRender.Call(0, evt, uintptr(evt_EvtRenderEventXml),
		0, 0, uintptr(unsafe.Pointer(&needed)), uintptr(unsafe.Pointer(&propCount)))
	if needed == 0 {
		return "", fmt.Errorf("EvtRender: zero size")
	}
	for attempt := 0; attempt < 3; attempt++ {
		units := int((needed + 1) / 2)
		buf := make([]uint16, units)
		size := uint32(units * 2)
		used := size
		r, _, callErr := evt_pEvtRender.Call(0, evt, uintptr(evt_EvtRenderEventXml),
			uintptr(size), uintptr(unsafe.Pointer(&buf[0])),
			uintptr(unsafe.Pointer(&used)), uintptr(unsafe.Pointer(&propCount)))
		if r != 0 {
			chars := used / 2
			if chars > uint32(len(buf)) {
				chars = uint32(len(buf))
			}
			return syscall.UTF16ToString(buf[:chars]), nil
		}
		if used > size {
			needed = used
			continue
		}
		if callErr != nil {
			return "", callErr
		}
		return "", fmt.Errorf("EvtRender failed")
	}
	return "", fmt.Errorf("EvtRender: buffer size discovery failed after retries")
}

func evt_evtFormatMessage(evt uintptr) string {
	var needed uint32
	evt_pEvtFormatMessage.Call(0, evt, 0, 0, 0,
		uintptr(evt_EvtFormatMessageEvent), 0, 0, uintptr(unsafe.Pointer(&needed)))
	if needed == 0 {
		return ""
	}
	for attempt := 0; attempt < 3; attempt++ {
		buf := make([]uint16, needed)
		size := uint32(len(buf))
		used := size
		r, _, _ := evt_pEvtFormatMessage.Call(0, evt, 0, 0, 0,
			uintptr(evt_EvtFormatMessageEvent), uintptr(size),
			uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&used)))
		if r != 0 {
			if used > uint32(len(buf)) {
				used = uint32(len(buf))
			}
			return syscall.UTF16ToString(buf[:used])
		}
		if used > size {
			needed = used
			continue
		}
		if used > 0 && used <= uint32(len(buf)) {
			return syscall.UTF16ToString(buf[:used])
		}
		return ""
	}
	return ""
}

func evt_evtClose(h uintptr) {
	if h != 0 {
		evt_pEvtClose.Call(h)
	}
}

type evt_xmlEvent struct {
	XMLName   xml.Name         `xml:"Event"`
	System    evt_xmlSystem    `xml:"System"`
	EventData evt_xmlEventData `xml:"EventData"`
}
type evt_xmlSystem struct {
	Provider    evt_xmlProvider    `xml:"Provider"`
	EventID     uint32             `xml:"EventID"`
	Level       uint8              `xml:"Level"`
	TimeCreated evt_xmlTimeCreated `xml:"TimeCreated"`
	Channel     string             `xml:"Channel"`
	Computer    string             `xml:"Computer"`
}
type evt_xmlProvider struct {
	Name string `xml:"Name,attr"`
	Guid string `xml:"Guid,attr"`
}
type evt_xmlTimeCreated struct {
	SystemTime string `xml:"SystemTime,attr"`
}
type evt_xmlEventData struct {
	Data []evt_xmlDataField `xml:"Data"`
}
type evt_xmlDataField struct {
	Name  string `xml:"Name,attr"`
	Value string `xml:",chardata"`
}

type evt_EventDataField struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type evt_EventRecord struct {
	Time     time.Time
	Level    uint8
	EventID  uint32
	Source   string
	Channel  string
	Computer string
	Message  string
	Data     []evt_EventDataField
}

func evt_parseEvtTime(s string) time.Time {
	if s == "" {
		return time.Time{}
	}
	if strings.HasSuffix(s, "Z") {
		s = s[:len(s)-1]
	}
	if idx := strings.Index(s, "."); idx >= 0 {
		frac := s[idx+1:]
		for len(frac) < 9 {
			frac += "0"
		}
		if len(frac) > 9 {
			frac = frac[:9]
		}
		s = s[:idx] + "." + frac
	} else {
		s += ".000000000"
	}
	t, err := time.ParseInLocation("2006-01-02T15:04:05.000000000", s, time.UTC)
	if err != nil {
		return time.Time{}
	}
	return t
}

var evt_relTimeRe = regexp.MustCompile(`^(\d+)([smhdw])$`)

func evt_parseTimeArg(s string) (time.Time, error) {
	s = strings.TrimSpace(strings.ToLower(s))
	switch s {
	case "now":
		return time.Now(), nil
	case "today":
		now := time.Now()
		return time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.Local), nil
	case "yesterday":
		now := time.Now()
		return time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.Local).Add(-24 * time.Hour), nil
	}
	if m := evt_relTimeRe.FindStringSubmatch(s); m != nil {
		n, _ := strconv.Atoi(m[1])
		var d time.Duration
		switch m[2] {
		case "s":
			d = time.Duration(n) * time.Second
		case "m":
			d = time.Duration(n) * time.Minute
		case "h":
			d = time.Duration(n) * time.Hour
		case "d":
			d = time.Duration(n) * 24 * time.Hour
		case "w":
			d = time.Duration(n) * 7 * 24 * time.Hour
		}
		return time.Now().Add(-d), nil
	}
	for _, layout := range []string{
		"2006-01-02T15:04:05", "2006-01-02T15:04",
		"2006-01-02 15:04:05", "2006-01-02 15:04", "2006-01-02",
		"2006/01/02 15:04:05", "2006/01/02",
	} {
		if t, err := time.ParseInLocation(layout, s, time.Local); err == nil {
			return t, nil
		}
	}
	return time.Time{}, fmt.Errorf("unrecognized time %q", s)
}

func evt_xpathQuote(s string) string {
	if strings.Contains(s, `'`) && !strings.Contains(s, `"`) {
		return `"` + s + `"`
	}
	if strings.Contains(s, `'`) && strings.Contains(s, `"`) {
		return `'` + strings.ReplaceAll(s, `'`, "") + `'`
	}
	return `'` + s + `'`
}

func evt_levelNumber(s string) (int, bool) {
	switch strings.ToLower(s) {
	case "critical":
		return 1, true
	case "error":
		return 2, true
	case "warning", "warn":
		return 3, true
	case "info", "information":
		return 4, true
	case "verbose":
		return 5, true
	}
	if n, err := strconv.Atoi(s); err == nil && n >= 0 && n <= 5 {
		return n, true
	}
	return 0, false
}

type evt_queryOpts struct {
	channels []string
	levels   []int
	eventID  uint32
	provider string
	since    time.Time
	until    time.Time
	max      uint32
	newest   bool
	jsonOut  bool
}

func evt_buildXPath(opts *evt_queryOpts) string {
	var conds []string
	if len(opts.levels) > 0 {
		var parts []string
		for _, l := range opts.levels {
			parts = append(parts, fmt.Sprintf("Level=%d", l))
		}
		conds = append(conds, "("+strings.Join(parts, " or ")+")")
	}
	if opts.eventID != 0 {
		conds = append(conds, fmt.Sprintf("EventID=%d", opts.eventID))
	}
	if opts.provider != "" {
		conds = append(conds, "Provider[@Name="+evt_xpathQuote(opts.provider)+"]")
	}
	if !opts.since.IsZero() {
		ts := opts.since.UTC().Format("2006-01-02T15:04:05.000Z")
		conds = append(conds, fmt.Sprintf("TimeCreated[@SystemTime>=%s]", evt_xpathQuote(ts)))
	}
	if !opts.until.IsZero() {
		ts := opts.until.UTC().Format("2006-01-02T15:04:05.000Z")
		conds = append(conds, fmt.Sprintf("TimeCreated[@SystemTime<=%s]", evt_xpathQuote(ts)))
	}
	if len(conds) == 0 {
		return "*"
	}
	return "*[System[" + strings.Join(conds, " and ") + "]]"
}

func evt_parseEvent(evt uintptr) (evt_EventRecord, error) {
	xmlStr, err := evt_evtRenderXML(evt)
	if err != nil {
		return evt_EventRecord{}, err
	}
	var ev evt_xmlEvent
	if err := xml.Unmarshal([]byte(xmlStr), &ev); err != nil {
		return evt_EventRecord{}, fmt.Errorf("parse XML: %w", err)
	}
	rec := evt_EventRecord{
		Time:     evt_parseEvtTime(ev.System.TimeCreated.SystemTime),
		Level:    ev.System.Level,
		EventID:  ev.System.EventID,
		Source:   ev.System.Provider.Name,
		Channel:  ev.System.Channel,
		Computer: ev.System.Computer,
		Message:  evt_evtFormatMessage(evt),
	}
	for _, d := range ev.EventData.Data {
		rec.Data = append(rec.Data, evt_EventDataField{Name: d.Name, Value: d.Value})
	}
	return rec, nil
}

func evt_queryChannel(channel, xpath string, maxTotal uint32, newestFirst bool, collected *[]evt_EventRecord) error {
	flags := uint32(evt_EvtQueryChannelPath)
	if newestFirst {
		flags |= evt_EvtQueryReverseDirection
	} else {
		flags |= evt_EvtQueryForwardDirection
	}
	resultSet, err := evt_evtQuery(channel, xpath, flags)
	if err != nil {
		return fmt.Errorf("%s: %w", channel, err)
	}
	defer evt_evtClose(resultSet)
	for {
		if maxTotal > 0 && uint32(len(*collected)) >= maxTotal {
			return nil
		}
		batch := uint32(32)
		if maxTotal > 0 {
			remaining := maxTotal - uint32(len(*collected))
			if remaining < batch {
				batch = remaining
			}
		}
		handles, more, err := evt_evtNextBatch(resultSet, batch)
		if err != nil {
			return fmt.Errorf("%s: %w", channel, err)
		}
		if !more {
			return nil
		}
		for _, h := range handles {
			rec, perr := evt_parseEvent(h)
			evt_evtClose(h)
			if perr != nil {
				bugs.Add("WARN", "%s: %v", channel, perr)
				continue
			}
			*collected = append(*collected, rec)
			if maxTotal > 0 && uint32(len(*collected)) >= maxTotal {
				return nil
			}
		}
	}
}

func evt_runQuery(opts *evt_queryOpts) ([]evt_EventRecord, error) {
	xpath := evt_buildXPath(opts)
	if dryRun {
		fmt.Fprintf(os.Stderr, "[dry-run] XPath: %s\n", xpath)
		for _, ch := range opts.channels {
			fmt.Fprintf(os.Stderr, "[dry-run] query channel %q\n", ch)
		}
		return nil, nil
	}
	var collected []evt_EventRecord
	hadSuccess := false
	var lastErr error
	for _, ch := range opts.channels {
		if err := evt_queryChannel(ch, xpath, opts.max, opts.newest, &collected); err != nil {
			lastErr = err
			bugs.Add("WARN", "%v", err)
			if errno, ok := err.(syscall.Errno); ok && errno == syscall.Errno(5) {
				fmt.Fprintf(os.Stderr, "winctl evt: %s: access denied (try running as administrator)\n", ch)
			} else {
				fmt.Fprintf(os.Stderr, "winctl evt: %v\n", err)
			}
			continue
		}
		hadSuccess = true
		if opts.max > 0 && uint32(len(collected)) >= opts.max {
			break
		}
	}
	if !hadSuccess && lastErr != nil {
		return nil, lastErr
	}
	return collected, nil
}

func evt_levelName(l uint8) string {
	switch l {
	case 1:
		return "Critical"
	case 2:
		return "Error"
	case 3:
		return "Warning"
	case 4:
		return "Info"
	case 5:
		return "Verbose"
	}
	return fmt.Sprintf("L%d", l)
}

func evt_levelColor(l uint8) string {
	switch l {
	case 1:
		return clrBold + clrRed
	case 2:
		return clrRed
	case 3:
		return clrYellow
	case 4:
		return clrGreen
	}
	return clrGray
}

func evt_effectiveMessage(rec *evt_EventRecord) string {
	if rec.Message != "" {
		return rec.Message
	}
	if len(rec.Data) == 0 {
		return ""
	}
	var parts []string
	for _, d := range rec.Data {
		if d.Name != "" {
			parts = append(parts, d.Name+"="+d.Value)
		} else {
			parts = append(parts, d.Value)
		}
	}
	return strings.Join(parts, "; ")
}

func evt_oneLine(s string) string {
	if s == "" {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '\r':
			if i+1 < len(s) && s[i+1] == '\n' {
				i++
			}
			b.WriteByte(' ')
		case '\n', '\t':
			b.WriteByte(' ')
		default:
			b.WriteByte(s[i])
		}
	}
	return b.String()
}

func evt_printEventsText(records []evt_EventRecord) {
	if len(records) == 0 {
		return
	}
	timeW := len("2024-01-01 00:00:00")
	levelW := len("Critical")
	eidW := len("EVENTID")
	srcW := len("SOURCE")
	chW := len("CHANNEL")
	for _, r := range records {
		if w := len(evt_levelName(r.Level)); w > levelW {
			levelW = w
		}
		eidStr := strconv.FormatUint(uint64(r.EventID), 10)
		if w := len(eidStr); w > eidW {
			eidW = w
		}
		if w := dispWidth(r.Source); w > srcW {
			srcW = w
		}
		if w := dispWidth(r.Channel); w > chW {
			chW = w
		}
	}
	header := padRight("TIME", timeW) + "  " +
		padRight("LEVEL", levelW) + "  " +
		padRight("EVENTID", eidW) + "  " +
		padRight("SOURCE", srcW) + "  " +
		padRight("CHANNEL", chW) + "  MESSAGE"
	fmt.Println(c(clrBold+clrCyan, header))
	for _, r := range records {
		ts := r.Time.Local().Format("2006-01-02 15:04:05")
		fmt.Println(padRight(ts, timeW) + "  " +
			c(evt_levelColor(r.Level), padRight(evt_levelName(r.Level), levelW)) + "  " +
			padRight(strconv.FormatUint(uint64(r.EventID), 10), eidW) + "  " +
			padRight(r.Source, srcW) + "  " +
			padRight(r.Channel, chW) + "  " +
			evt_oneLine(evt_effectiveMessage(&r)))
	}
}

type evt_jsonEvent struct {
	Time      string               `json:"time"`
	Level     string               `json:"level"`
	EventID   uint32               `json:"eventId"`
	Source    string               `json:"source"`
	Channel   string               `json:"channel"`
	Computer  string               `json:"computer"`
	Message   string               `json:"message"`
	EventData []evt_EventDataField `json:"eventData,omitempty"`
}

func evt_printEventsJSON(records []evt_EventRecord) {
	out := make([]evt_jsonEvent, len(records))
	for i, r := range records {
		out[i] = evt_jsonEvent{
			Time:      r.Time.UTC().Format(time.RFC3339Nano),
			Level:     evt_levelName(r.Level),
			EventID:   r.EventID,
			Source:    r.Source,
			Channel:   r.Channel,
			Computer:  r.Computer,
			Message:   evt_effectiveMessage(&r),
			EventData: r.Data,
		}
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(out); err != nil {
		bugs.Add("ERR", "json encode: %v", err)
	}
}

func evt_cmdHistory() int {
	lines, err := auditReadLines()
	if err != nil {
		fmt.Fprintf(os.Stderr, "read log: %v\n", err)
		return 4
	}
	if len(lines) == 0 {
		fmt.Fprintln(os.Stderr, "log is empty")
		return 0
	}
	count := 0
	for i := len(lines) - 1; i >= 0; i-- {
		m, _, _, ok := auditParseLine(lines[i])
		if !ok || m != "evt" {
			continue
		}
		count++
		fmt.Printf("[%d] %s\n", count, lines[i])
	}
	if count == 0 {
		fmt.Fprintln(os.Stderr, "no evt history entries in log")
	}
	return 0
}

func evt_cmdRollback() int {
	fmt.Fprintln(os.Stderr, "winctl evt is read-only: there are no operations to roll back")
	fmt.Fprintln(os.Stderr, "  It only reads event logs and exports them.")
	fmt.Fprintln(os.Stderr, "  Its history is for audit only; use --history to view it.")
	return 0
}

var evt_defaultChannels = []string{"System", "Application"}

var evt_channelAliases = map[string]string{
	"system": "System", "application": "Application",
	"security": "Security", "setup": "Setup",
}

func evt_parseQueryArgs(args []string) (*evt_queryOpts, error) {
	opts := &evt_queryOpts{max: 100, newest: true}
	var channelsRaw []string
	var levelsRaw []string
	i := 0
	for i < len(args) {
		a := args[i]
		switch a {
		case "-c", "--channel":
			if i+1 >= len(args) {
				return nil, fmt.Errorf("%s requires a name", a)
			}
			channelsRaw = append(channelsRaw, args[i+1])
			i += 2
		case "-l", "--level":
			if i+1 >= len(args) {
				return nil, fmt.Errorf("%s requires a level", a)
			}
			levelsRaw = append(levelsRaw, args[i+1])
			i += 2
		case "-e", "--event-id":
			if i+1 >= len(args) {
				return nil, fmt.Errorf("%s requires a number", a)
			}
			v, err := strconv.ParseUint(args[i+1], 10, 32)
			if err != nil {
				return nil, fmt.Errorf("invalid event id %q", args[i+1])
			}
			opts.eventID = uint32(v)
			i += 2
		case "-p", "--provider":
			if i+1 >= len(args) {
				return nil, fmt.Errorf("%s requires a name", a)
			}
			opts.provider = args[i+1]
			i += 2
		case "--since":
			if i+1 >= len(args) {
				return nil, fmt.Errorf("--since requires a time")
			}
			t, err := evt_parseTimeArg(args[i+1])
			if err != nil {
				return nil, err
			}
			opts.since = t
			i += 2
		case "--until":
			if i+1 >= len(args) {
				return nil, fmt.Errorf("--until requires a time")
			}
			t, err := evt_parseTimeArg(args[i+1])
			if err != nil {
				return nil, err
			}
			opts.until = t
			i += 2
		case "--last":
			if i+1 >= len(args) {
				return nil, fmt.Errorf("--last requires a duration")
			}
			t, err := evt_parseTimeArg(args[i+1])
			if err != nil {
				return nil, err
			}
			opts.since = t
			i += 2
		case "-n", "--max":
			if i+1 >= len(args) {
				return nil, fmt.Errorf("%s requires a number", a)
			}
			v, err := strconv.ParseUint(args[i+1], 10, 32)
			if err != nil {
				return nil, fmt.Errorf("invalid max %q", args[i+1])
			}
			opts.max = uint32(v)
			i += 2
		case "--newest":
			opts.newest = true
			i++
		case "--oldest":
			opts.newest = false
			i++
		case "--json":
			opts.jsonOut = true
			i++
		default:
			if strings.HasPrefix(a, "-") {
				return nil, fmt.Errorf("unknown option %s", a)
			}
			return nil, fmt.Errorf("unexpected argument %q (use -h for help)", a)
		}
	}
	if len(channelsRaw) == 0 {
		opts.channels = append(opts.channels, evt_defaultChannels...)
	} else {
		for _, cr := range channelsRaw {
			for _, rawPart := range strings.Split(cr, ",") {
				trimmed := strings.TrimSpace(rawPart)
				if trimmed == "" {
					continue
				}
				lower := strings.ToLower(trimmed)
				if lower == "all" {
					opts.channels = append(opts.channels, "System", "Application", "Security")
					continue
				}
				if canonical, ok := evt_channelAliases[lower]; ok {
					opts.channels = append(opts.channels, canonical)
					continue
				}
				opts.channels = append(opts.channels, trimmed)
			}
		}
	}
	seenCh := map[string]bool{}
	deduped := opts.channels[:0]
	for _, ch := range opts.channels {
		key := strings.ToLower(ch)
		if seenCh[key] {
			continue
		}
		seenCh[key] = true
		deduped = append(deduped, ch)
	}
	opts.channels = deduped
	for _, lr := range levelsRaw {
		for _, part := range strings.Split(lr, ",") {
			part = strings.ToLower(strings.TrimSpace(part))
			if part == "" {
				continue
			}
			if n, ok := evt_levelNumber(part); ok {
				opts.levels = append(opts.levels, n)
			} else {
				return nil, fmt.Errorf("invalid level %q", part)
			}
		}
	}
	return opts, nil
}

func evt_printHelp() {
	fmt.Printf("%s v%s (Windows)\n\n", c(clrBold+clrCyan, "winctl evt"), Version)
	fmt.Print(`USAGE
  winctl evt query [OPTIONS]          (query is the default; may be omitted)
  winctl evt [OPTIONS]
  winctl evt --history
  winctl evt --rollback               (always a no-op: read-only)

QUERY OPTIONS
  -c, --channel <name>      event log channel. May be repeated. Default: system, application
  -l, --level <level>       critical | error | warning | info | verbose | <0-5>
  -e, --event-id <N>        only events with this event ID
  -p, --provider <name>     only events with this provider
  --since <time>            at or after <time> (1h, 30m, 7d, 2024-01-01, now, today, yesterday)
  --until <time>            at or before <time>
  --last <duration>         alias for --since
  -n, --max <N>             stop after N events (default 100; 0 = all)
  --newest                  newest first (default)
  --oldest                  oldest first
  --json                    JSON output
  -o, --out <path>          write output to a file

GLOBAL
  --dry-run                 print the XPath query without opening the event log
  --no-color                disable colors
  -b, --bugs                print collected errors/warnings
  -h, --help                show this help
  --version                 show version

All logs go to ./backup/winctl_logs.log
`)
}

func evt_main() {
	if err := evt_initAPIs(); err != nil {
		fmt.Fprintf(os.Stderr, "winctl evt: %v\n", err)
		os.Exit(5)
	}
	args, outPath, err := consumeGlobalFlags(os.Args[1:])
	if err != nil {
		fmt.Fprintf(os.Stderr, "winctl evt: %v\n", err)
		finalExit(2)
	}
	initColor()
	if has(args, "--version") {
		fmt.Printf("winctl evt v%s\n", Version)
		finalExit(0)
	}
	if len(args) == 0 || has(args, "-h", "--help") {
		evt_printHelp()
		finalExit(0)
	}
	if has(args, "--history") {
		code := evt_cmdHistory()
		auditLog("evt", buildCmdLine(os.Args), code)
		finalExit(code)
	}
	if has(args, "--rollback") {
		code := evt_cmdRollback()
		auditLog("evt", buildCmdLine(os.Args), code)
		finalExit(code)
	}
	if len(args) > 0 && args[0] == "query" {
		args = args[1:]
	}
	opts, err := evt_parseQueryArgs(args)
	if err != nil {
		fmt.Fprintf(os.Stderr, "winctl evt: %v\n", err)
		finalExit(2)
	}
	if outPath != "" {
		if err := setupOutput(outPath); err != nil {
			fmt.Fprintf(os.Stderr, "winctl evt: %v\n", err)
			finalExit(2)
		}
	}
	records, err := evt_runQuery(opts)
	code := 0
	if err != nil {
		code = 5
	}
	if !dryRun {
		if opts.jsonOut {
			evt_printEventsJSON(records)
		} else {
			evt_printEventsText(records)
		}
		if len(records) == 0 && err == nil {
			fmt.Fprintln(os.Stderr, "no events matched")
		} else if len(records) > 0 {
			fmt.Fprintf(os.Stderr, "\n%d event(s)\n", len(records))
		}
	}
	if !dryRun && shouldLogRun() {
		auditLog("evt", buildCmdLine(os.Args), code)
	}
	finalExit(code)
}
// ============================================================================
// fs — file and text basics with per-op backup + rollback
// ============================================================================
//
// Performance notes (behaviour unchanged):
//   cat, grep, head and tail stream stdin/stdout through bufio instead of
//   loading whole files into memory. head stops reading after N lines;
//   tail keeps a ring buffer of N lines. wc still reads whole input because
//   word counting needs the whole byte stream.

var fs_expandEnabled = true

const (
	fs_smallFileThreshold = 8192
)

var fs_compressedExt = map[string]bool{
	".gz": true, ".tgz": true, ".zip": true, ".rar": true, ".7z": true, ".bz2": true,
	".xz": true, ".zst": true, ".jpg": true, ".jpeg": true, ".png": true, ".gif": true,
	".webp": true, ".heic": true, ".mp3": true, ".mp4": true, ".avi": true, ".mkv": true,
	".mov": true, ".flac": true, ".m4a": true, ".pdf": true, ".docx": true, ".xlsx": true,
	".pptx": true, ".jar": true, ".apk": true, ".exe": true, ".dll": true, ".bin": true,
	".iso": true, ".cab": true, ".msi": true, ".woff2": true, ".br": true,
}

type fs_opRecord struct {
	Op   string          `json:"op"`
	TS   string          `json:"ts"`
	Cmd  string          `json:"cmd"`
	Code int             `json:"code"`
	Data json.RawMessage `json:"data"`
}

func fs_mustJSON(v any) json.RawMessage {
	b, err := json.Marshal(v)
	if err != nil {
		return json.RawMessage(`null`)
	}
	return b
}

func fs_saveOp(idx int, rec *fs_opRecord) {
	if err := moduleSaveManifest("fs", idx, rec); err != nil {
		bugs.Add("ERR", "save op %d: %v", idx, err)
	}
}

func fs_loadOp(idx int) (*fs_opRecord, error) {
	var rec fs_opRecord
	if err := moduleLoadManifest("fs", idx, &rec); err != nil {
		return nil, err
	}
	return &rec, nil
}

func fs_copyFile(src, dst string) error {
	if err := os.MkdirAll(filepath.Dir(dst), 0755); err != nil {
		return err
	}
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	return out.Close()
}

func fs_gzipFile(src, dst string) error {
	if err := os.MkdirAll(filepath.Dir(dst), 0755); err != nil {
		return err
	}
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	gz, err := gzip.NewWriterLevel(out, gzip.BestCompression)
	if err != nil {
		out.Close()
		return err
	}
	if _, err := io.Copy(gz, in); err != nil {
		gz.Close()
		out.Close()
		return err
	}
	if err := gz.Close(); err != nil {
		out.Close()
		return err
	}
	return out.Close()
}

func fs_tarGz(src, dst string) error {
	if err := os.MkdirAll(filepath.Dir(dst), 0755); err != nil {
		return err
	}
	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	gz, err := gzip.NewWriterLevel(out, gzip.BestCompression)
	if err != nil {
		out.Close()
		return err
	}
	tw := tar.NewWriter(gz)
	base := filepath.Dir(src)
	walkErr := filepath.Walk(src, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(base, path)
		if err != nil {
			return err
		}
		hdr, err := tar.FileInfoHeader(info, "")
		if err != nil {
			return err
		}
		hdr.Name = filepath.ToSlash(rel)
		if err := tw.WriteHeader(hdr); err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		f, err := os.Open(path)
		if err != nil {
			return err
		}
		_, copyErr := io.Copy(tw, f)
		closeErr := f.Close()
		if copyErr != nil {
			return copyErr
		}
		return closeErr
	})
	if walkErr != nil {
		tw.Close()
		gz.Close()
		out.Close()
		return walkErr
	}
	if err := tw.Close(); err != nil {
		gz.Close()
		out.Close()
		return err
	}
	if err := gz.Close(); err != nil {
		out.Close()
		return err
	}
	return out.Close()
}

func fs_gunzipFile(src, dst string) error {
	if err := os.MkdirAll(filepath.Dir(dst), 0755); err != nil {
		return err
	}
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	gz, err := gzip.NewReader(in)
	if err != nil {
		return err
	}
	defer gz.Close()
	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, gz); err != nil {
		out.Close()
		return err
	}
	return out.Close()
}

func fs_untarGz(src, baseDir string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	gz, err := gzip.NewReader(in)
	if err != nil {
		return err
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		clean := filepath.Clean(filepath.FromSlash(hdr.Name))
		if clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) || filepath.IsAbs(clean) {
			return fmt.Errorf("fs_untarGz: refusing path %q (escapes target directory)", hdr.Name)
		}
		dst := filepath.Join(baseDir, clean)
		relCheck, relErr := filepath.Rel(baseDir, dst)
		if relErr != nil || relCheck == ".." || strings.HasPrefix(relCheck, ".."+string(filepath.Separator)) {
			return fmt.Errorf("fs_untarGz: refusing path %q (escapes target directory)", hdr.Name)
		}
		switch hdr.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(dst, 0755); err != nil {
				return err
			}
		case tar.TypeReg:
			if err := os.MkdirAll(filepath.Dir(dst), 0755); err != nil {
				return err
			}
			f, err := os.Create(dst)
			if err != nil {
				return err
			}
			if _, err := io.Copy(f, tr); err != nil {
				f.Close()
				return err
			}
			f.Close()
			mt := hdr.ModTime
			if !mt.IsZero() {
				_ = os.Chtimes(dst, time.Now(), mt)
			}
		}
	}
	return nil
}

func fs_backupPath(src, idx string, seq int) (rel string, compressed bool, err error) {
	info, err := os.Stat(src)
	if err != nil {
		return "", false, err
	}
	base := filepath.Base(src)
	if base == "" || base == "." || base == string(filepath.Separator) {
		base = "root"
	}
	filesDir := moduleFilesDir("fs")
	if info.IsDir() {
		rel = filepath.Join(idx, fmt.Sprintf("%d_%s.tar.gz", seq, base))
		if err = fs_tarGz(src, filepath.Join(filesDir, rel)); err != nil {
			return "", false, err
		}
		return rel, true, nil
	}
	ext := strings.ToLower(filepath.Ext(src))
	if fs_compressedExt[ext] || info.Size() < fs_smallFileThreshold {
		rel = filepath.Join(idx, fmt.Sprintf("%d_%s", seq, base))
		if err = fs_copyFile(src, filepath.Join(filesDir, rel)); err != nil {
			return "", false, err
		}
		return rel, false, nil
	}
	rel = filepath.Join(idx, fmt.Sprintf("%d_%s.gz", seq, base))
	if err = fs_gzipFile(src, filepath.Join(filesDir, rel)); err != nil {
		return "", false, err
	}
	return rel, true, nil
}

func fs_restoreFile(backupRel string, compressed bool, dst string) error {
	src := filepath.Join(moduleFilesDir("fs"), backupRel)
	if strings.HasSuffix(backupRel, ".tar.gz") {
		return fs_untarGz(src, filepath.Dir(dst))
	}
	if compressed || strings.HasSuffix(backupRel, ".gz") {
		return fs_gunzipFile(src, dst)
	}
	return fs_copyFile(src, dst)
}

func fs_exists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

func fs_copyDir(src, dst string) error {
	return filepath.Walk(src, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}
		target := filepath.Join(dst, rel)
		if info.IsDir() {
			return os.MkdirAll(target, info.Mode())
		}
		if err := os.MkdirAll(filepath.Dir(target), 0755); err != nil {
			return err
		}
		return fs_copyFile(path, target)
	})
}

// ---------- pattern expansion ----------

func fs_expandPatterns(args []string) []string {
	out := make([]string, 0, len(args))
	for _, a := range args {
		out = append(out, fs_expandPattern(a)...)
	}
	return out
}

func fs_expandPattern(s string) []string {
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '{':
			return fs_expandBrace(s, i)
		case '[':
			return fs_expandBracket(s, i)
		case '}', ']':
			return []string{s}
		}
	}
	return []string{s}
}

func fs_expandBrace(s string, start int) []string {
	depth := 0
	end := -1
	for i := start; i < len(s); i++ {
		if s[i] == '{' {
			depth++
		}
		if s[i] == '}' {
			depth--
			if depth == 0 {
				end = i
				break
			}
		}
	}
	if end < 0 {
		return []string{s}
	}
	prefix := s[:start]
	body := s[start+1 : end]
	suffix := s[end+1:]
	if strings.TrimSpace(body) == "" {
		return []string{s}
	}
	parts := fs_parseBraceBody(body)
	if len(parts) == 0 {
		return []string{s}
	}
	var out []string
	for _, p := range parts {
		out = append(out, fs_expandPattern(prefix+p+suffix)...)
	}
	return out
}

func fs_expandBracket(s string, start int) []string {
	endRel := strings.IndexByte(s[start:], ']')
	if endRel < 0 {
		return []string{s}
	}
	end := start + endRel
	prefix := s[:start]
	body := s[start+1 : end]
	suffix := s[end+1:]
	if strings.Contains(body, "..") || (strings.Contains(body, "-") && len(body) >= 3) {
		parts := fs_expandRangeBody(body)
		if len(parts) > 0 {
			var out []string
			for _, p := range parts {
				out = append(out, fs_expandPattern(prefix+p+suffix)...)
			}
			return out
		}
	}
	if body != "" && !strings.ContainsAny(body, "[]{},.") {
		var out []string
		for _, ch := range body {
			out = append(out, fs_expandPattern(prefix+string(ch)+suffix)...)
		}
		return out
	}
	return []string{s}
}

func fs_parseBraceBody(body string) []string {
	if strings.Contains(body, "..") && !strings.Contains(body, ",") {
		return fs_expandRangeBody(body)
	}
	return fs_splitTopLevelComma(body)
}

func fs_splitTopLevelComma(s string) []string {
	var out []string
	depth := 0
	start := 0
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '{':
			depth++
		case '}':
			depth--
		case ',':
			if depth == 0 {
				out = append(out, s[start:i])
				start = i + 1
			}
		}
	}
	out = append(out, s[start:])
	return out
}

func fs_expandRangeBody(body string) []string {
	sep := ".."
	if !strings.Contains(body, "..") {
		sep = "-"
	}
	parts := strings.Split(body, sep)
	if len(parts) < 2 || len(parts) > 3 {
		return nil
	}
	step := 1
	if len(parts) == 3 {
		v, err := strconv.Atoi(parts[2])
		if err != nil || v == 0 {
			return nil
		}
		step = v
	}
	startN, err1 := strconv.Atoi(parts[0])
	endN, err2 := strconv.Atoi(parts[1])
	if err1 == nil && err2 == nil {
		var out []string
		if step > 0 {
			for i := startN; i <= endN; i += step {
				out = append(out, strconv.Itoa(i))
			}
		} else {
			for i := startN; i >= endN; i += step {
				out = append(out, strconv.Itoa(i))
			}
		}
		return out
	}
	if len(parts[0]) == 1 && len(parts[1]) == 1 {
		a, b := parts[0][0], parts[1][0]
		var out []string
		if step > 0 {
			for ch := a; ch <= b; ch += byte(step) {
				out = append(out, string(ch))
			}
		} else {
			for ch := a; ch >= b; ch += byte(step) {
				out = append(out, string(ch))
			}
		}
		return out
	}
	return nil
}

// ---------- fs manifest payloads ----------

type fs_cpData struct {
	Src        string
	Dst        string
	DstExisted bool
	DstBackup  string
	Compressed bool
	Recursive  bool
}

type fs_mvData struct {
	Src           string
	Dst           string
	DstExisted    bool
	DstBackup     string
	DstCompressed bool
}

type fs_rmItem struct {
	Path       string
	Backup     string
	Compressed bool
	IsDir      bool
	Existed    bool
}
type fs_rmData struct{ Items []fs_rmItem }

type fs_repItem struct {
	Path       string
	Backup     string
	Compressed bool
	Count      int
}
type fs_replaceMulti struct{ Items []fs_repItem }

type fs_mkdirItem struct {
	Path    string
	Existed bool
}
type fs_mkdirData struct{ Items []fs_mkdirItem }

type fs_touchItem struct {
	Path      string
	Existed   bool
	OrigMtime string
}
type fs_touchData struct{ Items []fs_touchItem }

func fs_rollbackRecord(rec *fs_opRecord) error {
	switch rec.Op {
	case "cp":
		return fs_rollbackCp(rec.Data)
	case "mv":
		return fs_rollbackMv(rec.Data)
	case "rm":
		return fs_rollbackRm(rec.Data)
	case "replace":
		return fs_rollbackReplace(rec.Data)
	case "mkdir":
		return fs_rollbackMkdir(rec.Data)
	case "touch":
		return fs_rollbackTouch(rec.Data)
	}
	return fmt.Errorf("unknown op %q", rec.Op)
}

func fs_rollbackCp(data json.RawMessage) error {
	var d fs_cpData
	if err := json.Unmarshal(data, &d); err != nil {
		return err
	}
	if d.DstExisted {
		return fs_restoreFile(d.DstBackup, d.Compressed, d.Dst)
	}
	if fs_exists(d.Dst) {
		fmt.Fprintf(os.Stderr, "[rollback cp] warning: deleting %s (created by the original cp)\n", d.Dst)
		return os.RemoveAll(d.Dst)
	}
	return nil
}

func fs_rollbackMv(data json.RawMessage) error {
	var d fs_mvData
	if err := json.Unmarshal(data, &d); err != nil {
		return err
	}
	if fs_exists(d.Dst) {
		if err := os.MkdirAll(filepath.Dir(d.Src), 0755); err != nil {
			return err
		}
		if fs_exists(d.Src) {
			_ = os.RemoveAll(d.Src)
		}
		if err := os.Rename(d.Dst, d.Src); err != nil {
			info, serr := os.Stat(d.Dst)
			if serr != nil {
				return err
			}
			if info.IsDir() {
				if err := fs_copyDir(d.Dst, d.Src); err != nil {
					return err
				}
			} else {
				if err := fs_copyFile(d.Dst, d.Src); err != nil {
					return err
				}
			}
			_ = os.RemoveAll(d.Dst)
		}
	}
	if d.DstExisted {
		return fs_restoreFile(d.DstBackup, d.DstCompressed, d.Dst)
	}
	return nil
}

func fs_rollbackRm(data json.RawMessage) error {
	var d fs_rmData
	if err := json.Unmarshal(data, &d); err != nil {
		return err
	}
	for i := len(d.Items) - 1; i >= 0; i-- {
		it := d.Items[i]
		if !it.Existed || it.Backup == "" {
			continue
		}
		if err := fs_restoreFile(it.Backup, it.Compressed, it.Path); err != nil {
			return fmt.Errorf("restore %s: %w", it.Path, err)
		}
	}
	return nil
}

func fs_rollbackReplace(data json.RawMessage) error {
	var d fs_replaceMulti
	if err := json.Unmarshal(data, &d); err != nil {
		return err
	}
	for i := len(d.Items) - 1; i >= 0; i-- {
		it := d.Items[i]
		if it.Backup == "" {
			continue
		}
		if err := fs_restoreFile(it.Backup, it.Compressed, it.Path); err != nil {
			return fmt.Errorf("restore %s: %w", it.Path, err)
		}
	}
	return nil
}

func fs_rollbackMkdir(data json.RawMessage) error {
	var d fs_mkdirData
	if err := json.Unmarshal(data, &d); err != nil {
		return err
	}
	for i := len(d.Items) - 1; i >= 0; i-- {
		it := d.Items[i]
		if it.Existed {
			continue
		}
		if err := os.Remove(it.Path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("rmdir %s: %w", it.Path, err)
		}
	}
	return nil
}

func fs_rollbackTouch(data json.RawMessage) error {
	var d fs_touchData
	if err := json.Unmarshal(data, &d); err != nil {
		return err
	}
	for i := len(d.Items) - 1; i >= 0; i-- {
		it := d.Items[i]
		if !it.Existed {
			_ = os.Remove(it.Path)
			continue
		}
		if it.OrigMtime == "" {
			continue
		}
		t, err := time.Parse(time.RFC3339Nano, it.OrigMtime)
		if err != nil {
			continue
		}
		_ = os.Chtimes(it.Path, t, t)
	}
	return nil
}

// ---------- fs helpers ----------

func fs_getOpt(args []string, flags ...string) string {
	for i, a := range args {
		for _, f := range flags {
			if a == f && i+1 < len(args) {
				return args[i+1]
			}
			if strings.HasPrefix(a, f+"=") {
				return strings.TrimPrefix(a, f+"=")
			}
		}
	}
	return ""
}

func fs_removeOpt(args []string, flags ...string) []string {
	out := make([]string, 0, len(args))
	skip := false
	for _, a := range args {
		if skip {
			skip = false
			continue
		}
		isFlag, isFlagEq := false, false
		for _, f := range flags {
			if a == f {
				isFlag = true
				break
			}
			if strings.HasPrefix(a, f+"=") {
				isFlagEq = true
				break
			}
		}
		if isFlag {
			skip = true
			continue
		}
		if isFlagEq {
			continue
		}
		out = append(out, a)
	}
	return out
}

func fs_removeFlag(args []string, flag string) []string {
	out := make([]string, 0, len(args))
	for _, a := range args {
		if a != flag {
			out = append(out, a)
		}
	}
	return out
}

func fs_readFileOrStdin(path string) ([]byte, error) {
	if path == "-" {
		return io.ReadAll(os.Stdin)
	}
	return os.ReadFile(path)
}

func fs_readLines(path string) ([]string, error) {
	data, err := fs_readFileOrStdin(path)
	if err != nil {
		return nil, err
	}
	s := strings.Split(string(data), "\n")
	if len(s) > 0 && s[len(s)-1] == "" {
		s = s[:len(s)-1]
	}
	return s, nil
}

func fs_resolveInputs(files []string, name string) ([]string, bool) {
	if len(files) > 0 {
		return files, true
	}
	if stdinIsTTY() {
		fmt.Fprintf(os.Stderr, "%s: missing operand\n", name)
		return nil, false
	}
	return []string{"-"}, true
}

// fs_openOrStdin returns a reader for path and a closer.
// For path == "-" it returns os.Stdin and a no-op closer.
// This lets cat/grep/head/tail stream large files instead of loading them
// entirely into memory.
func fs_openOrStdin(path string) (io.Reader, func(), error) {
	if path == "-" {
		return os.Stdin, func() {}, nil
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, nil, err
	}
	return f, func() { f.Close() }, nil
}

// ---------- fs commands ----------

func fs_printLsEntry(path string, info os.FileInfo, long, showPath bool) {
	name := filepath.Base(path)
	if showPath {
		name = path
	}
	color := clrGray
	if info.IsDir() {
		color = clrCyan
	} else if info.Mode()&0111 != 0 {
		color = clrGreen
	}
	if long {
		fmt.Printf("%s %10d %s %s\n", info.Mode().String(), info.Size(),
			info.ModTime().Format("2006-01-02 15:04:05"), c(color, name))
	} else {
		fmt.Println(c(color, name))
	}
}

func fs_cmdLs(args []string) int {
	long, all := false, false
	var paths []string
	endOpts := false
	for _, a := range args {
		if endOpts {
			paths = append(paths, a)
			continue
		}
		if a == "--" {
			endOpts = true
			continue
		}
		if strings.HasPrefix(a, "--") {
			switch a {
			case "--long":
				long = true
			case "--all":
				all = true
			default:
				fmt.Fprintf(os.Stderr, "ls: unknown option %s\n", a)
				return 2
			}
			continue
		}
		if strings.HasPrefix(a, "-") && len(a) > 1 {
			for _, ch := range a[1:] {
				switch ch {
				case 'l':
					long = true
				case 'a':
					all = true
				default:
					fmt.Fprintf(os.Stderr, "ls: unknown option -%c\n", ch)
					return 2
				}
			}
			continue
		}
		paths = append(paths, a)
	}
	if len(paths) == 0 {
		paths = []string{"."}
	}
	multi := len(paths) > 1
	first := true
	for _, p := range paths {
		info, err := os.Stat(p)
		if err != nil {
			fmt.Fprintf(os.Stderr, "ls: %v\n", err)
			return 4
		}
		if !info.IsDir() {
			fs_printLsEntry(p, info, long, true)
			continue
		}
		entries, err := os.ReadDir(p)
		if err != nil {
			fmt.Fprintf(os.Stderr, "ls: %v\n", err)
			return 4
		}
		if multi {
			if !first {
				fmt.Println()
			}
			fmt.Printf("%s:\n", p)
			first = false
		}
		sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
		for _, e := range entries {
			name := e.Name()
			if !all && strings.HasPrefix(name, ".") {
				continue
			}
			fi, err := e.Info()
			if err != nil {
				continue
			}
			fs_printLsEntry(filepath.Join(p, name), fi, long, false)
		}
	}
	return 0
}

// fs_cmdCat streams stdin/stdout. Large files no longer load entirely
// into memory; only one io.Copy buffer per file is used.
func fs_cmdCat(args []string) int {
	var files []string
	endOpts := false
	for _, a := range args {
		if endOpts {
			files = append(files, a)
			continue
		}
		if a == "--" {
			endOpts = true
			continue
		}
		if strings.HasPrefix(a, "-") && a != "-" {
			fmt.Fprintf(os.Stderr, "cat: unknown option %s\n", a)
			return 2
		}
		files = append(files, a)
	}
	var ok bool
	if files, ok = fs_resolveInputs(files, "cat"); !ok {
		return 2
	}
	for _, f := range files {
		r, closeFn, err := fs_openOrStdin(f)
		if err != nil {
			fmt.Fprintf(os.Stderr, "cat: %v\n", err)
			return 4
		}
		_, copyErr := io.Copy(os.Stdout, r)
		closeFn()
		if copyErr != nil {
			fmt.Fprintf(os.Stderr, "cat: %v\n", copyErr)
			return 5
		}
	}
	return 0
}

func fs_cmdCp(args []string) int {
	force, recursive := false, false
	var rest []string
	endOpts := false
	for _, a := range args {
		if endOpts {
			rest = append(rest, a)
			continue
		}
		if a == "--" {
			endOpts = true
			continue
		}
		if strings.HasPrefix(a, "--") {
			switch a {
			case "--force":
				force = true
			case "--recursive":
				recursive = true
			default:
				fmt.Fprintf(os.Stderr, "cp: unknown option %s\n", a)
				return 2
			}
			continue
		}
		if strings.HasPrefix(a, "-") && len(a) > 1 {
			for _, ch := range a[1:] {
				switch ch {
				case 'f':
					force = true
				case 'r', 'R':
					recursive = true
				default:
					fmt.Fprintf(os.Stderr, "cp: unknown option -%c\n", ch)
					return 2
				}
			}
			continue
		}
		rest = append(rest, a)
	}
	if len(rest) != 2 {
		fmt.Fprintln(os.Stderr, "usage: winctl fs cp [-f] [-r] <src> <dst>")
		return 2
	}
	return fs_doCp(rest[0], rest[1], force, recursive)
}

func fs_doCp(src, dst string, force, recursive bool) int {
	sinfo, err := os.Stat(src)
	if err != nil {
		fmt.Fprintf(os.Stderr, "cp: %v\n", err)
		return 4
	}
	if dinfo, derr := os.Stat(dst); derr == nil && dinfo.IsDir() {
		dst = filepath.Join(dst, filepath.Base(src))
	}
	if sinfo.IsDir() {
		if !recursive {
			fmt.Fprintln(os.Stderr, "cp: source is a directory (use -r)")
			return 2
		}
		return fs_doCpDir(src, dst, force)
	}
	if fs_exists(dst) && !force {
		if !confirm(fmt.Sprintf("overwrite %s?", dst)) {
			return 1
		}
	}
	if dryRun {
		fmt.Printf("[dry-run] cp %s %s\n", src, dst)
		return 0
	}
	idx := auditCount()
	dstExisted := fs_exists(dst)
	var backup string
	var compressed bool
	if dstExisted {
		backup, compressed, err = fs_backupPath(dst, fmt.Sprintf("%d", idx), 0)
		if err != nil {
			fmt.Fprintf(os.Stderr, "cp: backup %s: %v\n", dst, err)
			return 5
		}
	}
	data := fs_cpData{Src: src, Dst: dst, DstExisted: dstExisted, DstBackup: backup, Compressed: compressed}
	rec := &fs_opRecord{Op: "cp", TS: time.Now().Format("2006-01-02 15:04:05"),
		Cmd: buildCmdLine(os.Args), Data: fs_mustJSON(data)}
	if err := fs_copyFile(src, dst); err != nil {
		fs_saveOp(idx, rec)
		fmt.Fprintf(os.Stderr, "cp: %v\n", err)
		return 5
	}
	fs_saveOp(idx, rec)
	fmt.Printf("%s -> %s\n", c(clrCyan, src), c(clrGreen, dst))
	return 0
}

func fs_doCpDir(src, dst string, force bool) int {
	if fs_exists(dst) && !force {
		if !confirm(fmt.Sprintf("overwrite directory %s?", dst)) {
			return 1
		}
	}
	if dryRun {
		fmt.Printf("[dry-run] cp -r %s %s\n", src, dst)
		return 0
	}
	idx := auditCount()
	dstExisted := fs_exists(dst)
	var backup string
	var compressed bool
	var err error
	if dstExisted {
		backup, compressed, err = fs_backupPath(dst, fmt.Sprintf("%d", idx), 0)
		if err != nil {
			fmt.Fprintf(os.Stderr, "cp: backup %s: %v\n", dst, err)
			return 5
		}
	}
	data := fs_cpData{Src: src, Dst: dst, DstExisted: dstExisted, DstBackup: backup, Compressed: compressed, Recursive: true}
	rec := &fs_opRecord{Op: "cp", TS: time.Now().Format("2006-01-02 15:04:05"),
		Cmd: buildCmdLine(os.Args), Data: fs_mustJSON(data)}
	if err := fs_copyDir(src, dst); err != nil {
		fs_saveOp(idx, rec)
		fmt.Fprintf(os.Stderr, "cp: %v\n", err)
		return 5
	}
	fs_saveOp(idx, rec)
	fmt.Printf("%s -> %s %s\n", c(clrCyan, src), c(clrGreen, dst), c(clrGray, "(recursive)"))
	return 0
}

func fs_doMv(src, dst string, force bool) int {
	sinfo, err := os.Stat(src)
	if err != nil {
		fmt.Fprintf(os.Stderr, "mv: %v\n", err)
		return 4
	}
	if dinfo, derr := os.Stat(dst); derr == nil && dinfo.IsDir() {
		dst = filepath.Join(dst, filepath.Base(src))
	}
	dstExisted := fs_exists(dst)
	if dstExisted && !force {
		if !confirm(fmt.Sprintf("overwrite %s?", dst)) {
			return 1
		}
	}
	if dryRun {
		fmt.Printf("[dry-run] mv %s %s\n", src, dst)
		return 0
	}
	idx := auditCount()
	var backup string
	var compressed bool
	if dstExisted {
		backup, compressed, err = fs_backupPath(dst, fmt.Sprintf("%d", idx), 0)
		if err != nil {
			fmt.Fprintf(os.Stderr, "mv: backup %s: %v\n", dst, err)
			return 5
		}
	}
	data := fs_mvData{Src: src, Dst: dst, DstExisted: dstExisted, DstBackup: backup, DstCompressed: compressed}
	rec := &fs_opRecord{Op: "mv", TS: time.Now().Format("2006-01-02 15:04:05"),
		Cmd: buildCmdLine(os.Args), Data: fs_mustJSON(data)}
	sidecar := ""
	if dstExisted {
		sidecar = dst + ".winctl_mv_bak"
		_ = os.RemoveAll(sidecar)
		if err := os.Rename(dst, sidecar); err != nil {
			fmt.Fprintf(os.Stderr, "mv: cannot set aside %s: %v\n", dst, err)
			return 5
		}
	}
	err = os.Rename(src, dst)
	if err != nil {
		if sinfo.IsDir() {
			err = fs_copyDir(src, dst)
		} else {
			err = fs_copyFile(src, dst)
		}
		if err == nil {
			_ = os.RemoveAll(src)
		}
	}
	if err != nil {
		if sidecar != "" {
			_ = os.RemoveAll(dst)
			if rerr := os.Rename(sidecar, dst); rerr != nil {
				fmt.Fprintf(os.Stderr, "mv: warning: could not restore %s from %s: %v\n", dst, sidecar, rerr)
			}
		}
		fs_saveOp(idx, rec)
		fmt.Fprintf(os.Stderr, "mv: %v\n", err)
		return 5
	}
	if sidecar != "" {
		_ = os.RemoveAll(sidecar)
	}
	fs_saveOp(idx, rec)
	fmt.Printf("%s -> %s\n", c(clrCyan, src), c(clrGreen, dst))
	return 0
}

func fs_cmdMv(args []string) int {
	force := false
	var rest []string
	endOpts := false
	for _, a := range args {
		if endOpts {
			rest = append(rest, a)
			continue
		}
		if a == "--" {
			endOpts = true
			continue
		}
		if strings.HasPrefix(a, "--") {
			switch a {
			case "--force":
				force = true
			default:
				fmt.Fprintf(os.Stderr, "mv: unknown option %s\n", a)
				return 2
			}
			continue
		}
		if strings.HasPrefix(a, "-") && len(a) > 1 {
			for _, ch := range a[1:] {
				switch ch {
				case 'f':
					force = true
				default:
					fmt.Fprintf(os.Stderr, "mv: unknown option -%c\n", ch)
					return 2
				}
			}
			continue
		}
		rest = append(rest, a)
	}
	if len(rest) != 2 {
		fmt.Fprintln(os.Stderr, "usage: winctl fs mv [-f] <src> <dst>")
		return 2
	}
	return fs_doMv(rest[0], rest[1], force)
}

func fs_cmdRm(args []string) int {
	force, recursive := false, false
	localDry := false
	expand := fs_expandEnabled
	var paths []string
	endOpts := false
	for _, a := range args {
		if endOpts {
			paths = append(paths, a)
			continue
		}
		if a == "--" {
			endOpts = true
			continue
		}
		if strings.HasPrefix(a, "--") {
			switch a {
			case "--force":
				force = true
			case "--recursive":
				recursive = true
			case "--expand":
				expand = true
			case "--no-expand":
				expand = false
			case "--dry-run":
				localDry = true
			default:
				fmt.Fprintf(os.Stderr, "rm: unknown option %s\n", a)
				return 2
			}
			continue
		}
		if strings.HasPrefix(a, "-") && len(a) > 1 {
			for _, ch := range a[1:] {
				switch ch {
				case 'f':
					force = true
				case 'r', 'R':
					recursive = true
				case 'e':
					expand = true
				case 'n':
					localDry = true
				default:
					fmt.Fprintf(os.Stderr, "rm: unknown option -%c\n", ch)
					return 2
				}
			}
			continue
		}
		paths = append(paths, a)
	}
	if expand {
		paths = fs_expandPatterns(paths)
	}
	if len(paths) == 0 {
		fmt.Fprintln(os.Stderr, "rm: missing operand")
		return 2
	}
	if localDry || dryRun {
		for _, p := range paths {
			fmt.Printf("[dry-run] rm %s\n", p)
		}
		return 0
	}
	if !force {
		for _, p := range paths {
			if !fs_exists(p) {
				fmt.Fprintf(os.Stderr, "rm: %s: no such file\n", p)
				return 4
			}
			if !confirm(fmt.Sprintf("remove %s?", p)) {
				return 1
			}
		}
	}
	idx := auditCount()
	rec := &fs_opRecord{Op: "rm", TS: time.Now().Format("2006-01-02 15:04:05"),
		Cmd: buildCmdLine(os.Args)}
	var items []fs_rmItem
	exitCode := 0
	for _, p := range paths {
		if !fs_exists(p) {
			continue
		}
		linfo, lerr := os.Lstat(p)
		if lerr != nil {
			fmt.Fprintf(os.Stderr, "rm: %v\n", lerr)
			exitCode = 5
			continue
		}
		isLink := linfo.Mode()&os.ModeSymlink != 0
		isRealDir := linfo.IsDir()
		needsRecursive := isRealDir
		if isLink && !isRealDir {
			if tinfo, terr := os.Stat(p); terr == nil && tinfo.IsDir() {
				needsRecursive = true
			}
		}
		if needsRecursive && !recursive {
			fmt.Fprintf(os.Stderr, "rm: %s is a directory (use -r)\n", p)
			exitCode = 2
			continue
		}
		seq := len(items)
		backup, compressed, err := fs_backupPath(p, fmt.Sprintf("%d", idx), seq)
		if err != nil {
			fmt.Fprintf(os.Stderr, "rm: backup %s: %v\n", p, err)
			exitCode = 5
			continue
		}
		items = append(items, fs_rmItem{Path: p, Backup: backup, Compressed: compressed,
			IsDir: isRealDir, Existed: true})
		var derr error
		if isRealDir {
			derr = os.RemoveAll(p)
		} else {
			derr = os.Remove(p)
		}
		if derr != nil {
			fmt.Fprintf(os.Stderr, "rm: %v\n", derr)
			exitCode = 5
		} else {
			fmt.Printf("removed %s\n", c(clrYellow, p))
		}
	}
	if len(items) > 0 {
		rec.Data = fs_mustJSON(fs_rmData{Items: items})
		fs_saveOp(idx, rec)
	}
	return exitCode
}

func fs_cmdMkdir(args []string) int {
	parents := false
	expand := fs_expandEnabled
	var paths []string
	endOpts := false
	for _, a := range args {
		if endOpts {
			paths = append(paths, a)
			continue
		}
		if a == "--" {
			endOpts = true
			continue
		}
		if strings.HasPrefix(a, "--") {
			switch a {
			case "--parents":
				parents = true
			case "--expand":
				expand = true
			case "--no-expand":
				expand = false
			default:
				fmt.Fprintf(os.Stderr, "mkdir: unknown option %s\n", a)
				return 2
			}
			continue
		}
		if strings.HasPrefix(a, "-") && len(a) > 1 {
			for _, ch := range a[1:] {
				switch ch {
				case 'p':
					parents = true
				case 'e':
					expand = true
				default:
					fmt.Fprintf(os.Stderr, "mkdir: unknown option -%c\n", ch)
					return 2
				}
			}
			continue
		}
		paths = append(paths, a)
	}
	if expand {
		paths = fs_expandPatterns(paths)
	}
	if len(paths) == 0 {
		fmt.Fprintln(os.Stderr, "mkdir: missing operand")
		return 2
	}
	if dryRun {
		for _, p := range paths {
			fmt.Printf("[dry-run] mkdir %s\n", p)
		}
		return 0
	}
	idx := auditCount()
	var items []fs_mkdirItem
	exitCode := 0
	for _, p := range paths {
		items = append(items, fs_mkdirItem{Path: p, Existed: fs_exists(p)})
		var err error
		if parents {
			err = os.MkdirAll(p, 0755)
		} else {
			err = os.Mkdir(p, 0755)
		}
		if err != nil {
			fmt.Fprintf(os.Stderr, "mkdir: %v\n", err)
			exitCode = 5
		} else {
			fmt.Printf("created %s\n", c(clrGreen, p))
		}
	}
	rec := &fs_opRecord{Op: "mkdir", TS: time.Now().Format("2006-01-02 15:04:05"),
		Cmd: buildCmdLine(os.Args), Data: fs_mustJSON(fs_mkdirData{Items: items})}
	fs_saveOp(idx, rec)
	return exitCode
}

func fs_cmdTouch(args []string) int {
	expand := fs_expandEnabled
	var paths []string
	endOpts := false
	for _, a := range args {
		if endOpts {
			paths = append(paths, a)
			continue
		}
		if a == "--" {
			endOpts = true
			continue
		}
		if strings.HasPrefix(a, "--") {
			switch a {
			case "--expand":
				expand = true
			case "--no-expand":
				expand = false
			default:
				fmt.Fprintf(os.Stderr, "touch: unknown option %s\n", a)
				return 2
			}
			continue
		}
		if strings.HasPrefix(a, "-") && len(a) > 1 && a != "-" {
			for _, ch := range a[1:] {
				switch ch {
				case 'e':
					expand = true
				default:
					fmt.Fprintf(os.Stderr, "touch: unknown option -%c\n", ch)
					return 2
				}
			}
			continue
		}
		paths = append(paths, a)
	}
	if expand {
		paths = fs_expandPatterns(paths)
	}
	if len(paths) == 0 {
		fmt.Fprintln(os.Stderr, "touch: missing operand")
		return 2
	}
	if dryRun {
		for _, p := range paths {
			fmt.Printf("[dry-run] touch %s\n", p)
		}
		return 0
	}
	idx := auditCount()
	var items []fs_touchItem
	exitCode := 0
	now := time.Now()
	for _, p := range paths {
		it := fs_touchItem{Path: p}
		if info, err := os.Stat(p); err == nil {
			it.Existed = true
			it.OrigMtime = info.ModTime().Format(time.RFC3339Nano)
			if err := os.Chtimes(p, now, now); err != nil {
				fmt.Fprintf(os.Stderr, "touch: %s: %v\n", p, err)
				exitCode = 5
			}
		} else {
			f, err := os.Create(p)
			if err != nil {
				fmt.Fprintf(os.Stderr, "touch: %v\n", err)
				exitCode = 5
			} else {
				f.Close()
			}
		}
		items = append(items, it)
	}
	rec := &fs_opRecord{Op: "touch", TS: now.Format("2006-01-02 15:04:05"),
		Cmd: buildCmdLine(os.Args), Data: fs_mustJSON(fs_touchData{Items: items})}
	fs_saveOp(idx, rec)
	if exitCode == 0 {
		for _, p := range paths {
			fmt.Printf("touched %s\n", c(clrCyan, p))
		}
	}
	return exitCode
}

func fs_cmdStat(args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "usage: winctl fs stat <path...>")
		return 2
	}
	for i, p := range args {
		info, err := os.Stat(p)
		if err != nil {
			fmt.Fprintf(os.Stderr, "stat: %v\n", err)
			return 4
		}
		if i > 0 {
			fmt.Println()
		}
		fmt.Printf("%s %s\n", c(clrCyan, "File:  "), p)
		fmt.Printf("%s %d bytes\n", c(clrCyan, "Size:  "), info.Size())
		fmt.Printf("%s %s\n", c(clrCyan, "Mode:  "), info.Mode().String())
		fmt.Printf("%s %s\n", c(clrCyan, "Mtime: "), info.ModTime().Format("2006-01-02 15:04:05.000"))
		if info.IsDir() {
			fmt.Printf("%s directory\n", c(clrCyan, "Type:  "))
		} else {
			fmt.Printf("%s file\n", c(clrCyan, "Type:  "))
		}
	}
	return 0
}

func fs_cmdFind(args []string) int {
	root := "."
	namePat := ""
	typeFilter := ""
	var extras []string
	i := 0
	for i < len(args) {
		a := args[i]
		switch a {
		case "-name":
			if i+1 >= len(args) {
				fmt.Fprintln(os.Stderr, "find: -name requires a pattern")
				return 2
			}
			namePat = args[i+1]
			i += 2
			continue
		case "-type":
			if i+1 >= len(args) {
				fmt.Fprintln(os.Stderr, "find: -type requires f or d")
				return 2
			}
			typeFilter = args[i+1]
			i += 2
			continue
		}
		if strings.HasPrefix(a, "-") {
			fmt.Fprintf(os.Stderr, "find: unknown option %s\n", a)
			return 2
		}
		extras = append(extras, a)
		i++
	}
	if len(extras) > 0 {
		root = extras[0]
	}
	var re *regexp.Regexp
	if namePat != "" {
		pat := regexp.QuoteMeta(namePat)
		pat = strings.ReplaceAll(pat, `\*`, `.*`)
		pat = strings.ReplaceAll(pat, `\?`, `.`)
		re, _ = regexp.Compile("^" + pat + "$")
	}
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil || path == root {
			return nil
		}
		if re != nil && !re.MatchString(info.Name()) {
			return nil
		}
		switch typeFilter {
		case "f":
			if info.IsDir() {
				return nil
			}
		case "d":
			if !info.IsDir() {
				return nil
			}
		}
		color := clrGray
		if info.IsDir() {
			color = clrCyan
		}
		fmt.Println(c(color, path))
		return nil
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "find: %v\n", err)
		return 5
	}
	return 0
}
// fs_cmdGrep streams stdin/file through bufio.Scanner instead of
// reading the entire file into memory first.
func fs_cmdGrep(args []string) int {
	icase, showNum, invert, fixed := false, false, false, false
	var rest []string
	endOpts := false
	for _, a := range args {
		if endOpts {
			rest = append(rest, a)
			continue
		}
		if a == "--" {
			endOpts = true
			continue
		}
		if strings.HasPrefix(a, "--") {
			switch a {
			case "--ignore-case":
				icase = true
			case "--line-number":
				showNum = true
			case "--invert-match":
				invert = true
			case "--fixed-string":
				fixed = true
			default:
				fmt.Fprintf(os.Stderr, "grep: unknown option %s\n", a)
				return 2
			}
			continue
		}
		if strings.HasPrefix(a, "-") && len(a) > 1 && a != "-" {
			for _, ch := range a[1:] {
				switch ch {
				case 'i':
					icase = true
				case 'n':
					showNum = true
				case 'v':
					invert = true
				case 'F':
					fixed = true
				default:
					fmt.Fprintf(os.Stderr, "grep: unknown option -%c\n", ch)
					return 2
				}
			}
			continue
		}
		rest = append(rest, a)
	}
	if len(rest) < 1 {
		fmt.Fprintln(os.Stderr, "usage: winctl fs grep [-i] [-n] [-v] [-F] <pattern> [file...]")
		return 2
	}
	pat := rest[0]
	files := rest[1:]
	var ok bool
	if files, ok = fs_resolveInputs(files, "grep"); !ok {
		return 2
	}
	var matcher func(string) bool
	if fixed {
		if icase {
			lp := strings.ToLower(pat)
			matcher = func(s string) bool { return strings.Contains(strings.ToLower(s), lp) }
		} else {
			matcher = func(s string) bool { return strings.Contains(s, pat) }
		}
	} else {
		expr := pat
		if icase {
			expr = "(?i)" + expr
		}
		re, err := regexp.Compile(expr)
		if err != nil {
			lit := regexp.QuoteMeta(pat)
			if icase {
				lit = "(?i)" + lit
			}
			re = regexp.MustCompile(lit)
		}
		matcher = re.MatchString
	}
	multi := len(files) > 1
	matched := 0
	for _, f := range files {
		if f != "-" {
			if info, err := os.Stat(f); err == nil && info.IsDir() {
				fmt.Fprintf(os.Stderr, "grep: %s: is a directory (skipped)\n", f)
				continue
			}
		}
		r, closeFn, err := fs_openOrStdin(f)
		if err != nil {
			fmt.Fprintf(os.Stderr, "grep: %v\n", err)
			continue
		}
		scanner := bufio.NewScanner(r)
		scanner.Buffer(make([]byte, 64*1024), 4*1024*1024)
		lineNum := 0
		for scanner.Scan() {
			lineNum++
			line := scanner.Text()
			m := matcher(line)
			if m == invert {
				continue
			}
			matched++
			prefix := ""
			if multi {
				if f == "-" {
					prefix += "(stdin):"
				} else {
					prefix += f + ":"
				}
			}
			if showNum {
				prefix += fmt.Sprintf("%d:", lineNum)
			}
			fmt.Println(c(clrGray, prefix) + line)
		}
		if serr := scanner.Err(); serr != nil {
			fmt.Fprintf(os.Stderr, "grep: %v\n", serr)
		}
		closeFn()
	}
	if matched == 0 {
		return 1
	}
	return 0
}

// fs_cmdHead uses bufio.Scanner and stops reading as soon as N lines
// have been printed. Large files are not fully loaded.
func fs_cmdHead(args []string) int {
	n := 10
	var files []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "-n" || a == "--lines" {
			if i+1 >= len(args) {
				return 2
			}
			v, err := strconv.Atoi(args[i+1])
			if err != nil {
				return 2
			}
			n = v
			i++
			continue
		}
		if strings.HasPrefix(a, "-") && len(a) > 1 && a != "-" && a[1] >= '0' && a[1] <= '9' {
			if v, err := strconv.Atoi(a[1:]); err == nil {
				n = v
				continue
			}
		}
		files = append(files, a)
	}
	var ok bool
	if files, ok = fs_resolveInputs(files, "head"); !ok {
		return 2
	}
	for _, f := range files {
		r, closeFn, err := fs_openOrStdin(f)
		if err != nil {
			fmt.Fprintf(os.Stderr, "head: %v\n", err)
			return 4
		}
		scanner := bufio.NewScanner(r)
		scanner.Buffer(make([]byte, 64*1024), 4*1024*1024)
		count := 0
		for count < n && scanner.Scan() {
			fmt.Println(scanner.Text())
			count++
		}
		if serr := scanner.Err(); serr != nil {
			fmt.Fprintf(os.Stderr, "head: %v\n", serr)
		}
		closeFn()
	}
	return 0
}

// fs_cmdTail keeps a ring buffer of the last N lines while streaming,
// so large files are not loaded into memory.
func fs_cmdTail(args []string) int {
	n := 10
	var files []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "-n" || a == "--lines" {
			if i+1 >= len(args) {
				return 2
			}
			v, err := strconv.Atoi(args[i+1])
			if err != nil {
				return 2
			}
			n = v
			i++
			continue
		}
		if strings.HasPrefix(a, "-") && len(a) > 1 && a != "-" && a[1] >= '0' && a[1] <= '9' {
			if v, err := strconv.Atoi(a[1:]); err == nil {
				n = v
				continue
			}
		}
		files = append(files, a)
	}
	var ok bool
	if files, ok = fs_resolveInputs(files, "tail"); !ok {
		return 2
	}
	if n <= 0 {
		return 0
	}
	for _, f := range files {
		r, closeFn, err := fs_openOrStdin(f)
		if err != nil {
			fmt.Fprintf(os.Stderr, "tail: %v\n", err)
			return 4
		}
		scanner := bufio.NewScanner(r)
		scanner.Buffer(make([]byte, 64*1024), 4*1024*1024)
		ring := make([]string, n)
		count := 0
		for scanner.Scan() {
			ring[count%n] = scanner.Text()
			count++
		}
		if serr := scanner.Err(); serr != nil {
			fmt.Fprintf(os.Stderr, "tail: %v\n", serr)
		}
		closeFn()
		start := 0
		if count > n {
			start = count - n
		}
		for i := 0; i < n && start+i < count; i++ {
			fmt.Println(ring[(start+i)%n])
		}
	}
	return 0
}

func fs_cmdWc(args []string) int {
	showL, showW, showC := false, false, false
	var files []string
	for _, a := range args {
		if strings.HasPrefix(a, "-") && len(a) > 1 && a != "-" {
			for _, ch := range a[1:] {
				switch ch {
				case 'l':
					showL = true
				case 'w':
					showW = true
				case 'c':
					showC = true
				default:
					fmt.Fprintf(os.Stderr, "wc: unknown option -%c\n", ch)
					return 2
				}
			}
			continue
		}
		files = append(files, a)
	}
	var ok bool
	if files, ok = fs_resolveInputs(files, "wc"); !ok {
		return 2
	}
	if !showL && !showW && !showC {
		showL, showW, showC = true, true, true
	}
	for _, f := range files {
		data, err := fs_readFileOrStdin(f)
		if err != nil {
			fmt.Fprintf(os.Stderr, "wc: %v\n", err)
			return 4
		}
		lines := strings.Count(string(data), "\n")
		if len(data) > 0 && data[len(data)-1] != '\n' {
			lines++
		}
		words := len(strings.Fields(string(data)))
		var parts []string
		if showL {
			parts = append(parts, fmt.Sprintf("%8d", lines))
		}
		if showW {
			parts = append(parts, fmt.Sprintf("%8d", words))
		}
		if showC {
			parts = append(parts, fmt.Sprintf("%8d", len(data)))
		}
		label := f
		if f == "-" {
			label = "(stdin)"
		}
		fmt.Printf("%s %s\n", strings.Join(parts, " "), c(clrGray, label))
	}
	return 0
}

func fs_cmdReplace(args []string) int {
	if len(args) < 3 {
		fmt.Fprintln(os.Stderr, "usage: winctl fs replace <old> <new> <file...>")
		return 2
	}
	oldStr, newStr := args[0], args[1]
	files := args[2:]
	if dryRun {
		for _, f := range files {
			data, err := os.ReadFile(f)
			if err != nil {
				fmt.Fprintf(os.Stderr, "replace: %v\n", err)
				continue
			}
			count := strings.Count(string(data), oldStr)
			if count == 0 {
				fmt.Printf("no match in %s\n", f)
				continue
			}
			fmt.Printf("[dry-run] replace %q -> %q in %s (%d occurrences)\n", oldStr, newStr, f, count)
		}
		return 0
	}
	idx := auditCount()
	var items []fs_repItem
	exitCode := 0
	for seq, f := range files {
		data, err := os.ReadFile(f)
		if err != nil {
			fmt.Fprintf(os.Stderr, "replace: %v\n", err)
			exitCode = 4
			continue
		}
		count := strings.Count(string(data), oldStr)
		if count == 0 {
			fmt.Printf("no match in %s\n", f)
			continue
		}
		backup, compressed, err := fs_backupPath(f, fmt.Sprintf("%d", idx), seq)
		if err != nil {
			fmt.Fprintf(os.Stderr, "replace: backup %s: %v\n", f, err)
			exitCode = 5
			continue
		}
		newData := strings.ReplaceAll(string(data), oldStr, newStr)
		if err := os.WriteFile(f, []byte(newData), 0644); err != nil {
			fmt.Fprintf(os.Stderr, "replace: %v\n", err)
			exitCode = 5
			continue
		}
		items = append(items, fs_repItem{Path: f, Backup: backup, Compressed: compressed, Count: count})
		fmt.Printf("%s: replaced %d\n", c(clrCyan, f), count)
	}
	if len(items) == 0 {
		return exitCode
	}
	rec := &fs_opRecord{
		Op: "replace", TS: time.Now().Format("2006-01-02 15:04:05"),
		Cmd: buildCmdLine(os.Args), Data: fs_mustJSON(fs_replaceMulti{Items: items}),
	}
	fs_saveOp(idx, rec)
	return exitCode
}

var fs_dispatchDepth int32

func fs_dispatch(args []string) int {
	if atomic.AddInt32(&fs_dispatchDepth, 1) > 8 {
		atomic.AddInt32(&fs_dispatchDepth, -1)
		fmt.Fprintln(os.Stderr, "winctl fs: xargs recursion depth exceeded (8 levels)")
		return 2
	}
	defer atomic.AddInt32(&fs_dispatchDepth, -1)
	cmdIdx := -1
	for i, a := range args {
		if !strings.HasPrefix(a, "-") {
			cmdIdx = i
			break
		}
	}
	if cmdIdx < 0 {
		fmt.Fprintln(os.Stderr, "winctl fs: missing command, use -h for help")
		return 2
	}
	cmd := args[cmdIdx]
	rest := append([]string{}, args[:cmdIdx]...)
	rest = append(rest, args[cmdIdx+1:]...)
	switch cmd {
	case "ls":
		return fs_cmdLs(rest)
	case "cat":
		return fs_cmdCat(rest)
	case "cp":
		return fs_cmdCp(rest)
	case "mv":
		return fs_cmdMv(rest)
	case "rm":
		return fs_cmdRm(rest)
	case "mkdir":
		return fs_cmdMkdir(rest)
	case "touch":
		return fs_cmdTouch(rest)
	case "stat":
		return fs_cmdStat(rest)
	case "find":
		return fs_cmdFind(rest)
	case "grep":
		return fs_cmdGrep(rest)
	case "head":
		return fs_cmdHead(rest)
	case "tail":
		return fs_cmdTail(rest)
	case "wc":
		return fs_cmdWc(rest)
	case "replace":
		return fs_cmdReplace(rest)
	}
	fmt.Fprintf(os.Stderr, "winctl fs: unknown command %q\n", cmd)
	return 2
}

// ---------- fs history / rollback ----------

func fs_summarizeOp(rec *fs_opRecord) string {
	switch rec.Op {
	case "cp":
		var d fs_cpData
		_ = json.Unmarshal(rec.Data, &d)
		if d.DstExisted {
			return "-> restore " + d.Dst
		}
		return "-> delete " + d.Dst
	case "mv":
		var d fs_mvData
		_ = json.Unmarshal(rec.Data, &d)
		return "-> move " + d.Dst + " back to " + d.Src
	case "rm":
		var d fs_rmData
		_ = json.Unmarshal(rec.Data, &d)
		var names []string
		for _, it := range d.Items {
			names = append(names, filepath.Base(it.Path))
		}
		return "-> restore " + strings.Join(names, ", ")
	case "replace":
		var d fs_replaceMulti
		_ = json.Unmarshal(rec.Data, &d)
		var names []string
		for _, it := range d.Items {
			if it.Backup != "" {
				names = append(names, filepath.Base(it.Path))
			}
		}
		return "-> restore " + strings.Join(names, ", ")
	case "mkdir":
		var d fs_mkdirData
		_ = json.Unmarshal(rec.Data, &d)
		var names []string
		for _, it := range d.Items {
			if !it.Existed {
				names = append(names, filepath.Base(it.Path))
			}
		}
		return "-> rmdir " + strings.Join(names, ", ")
	case "touch":
		return "-> restore mtime"
	}
	return ""
}

func fs_cmdHistory() int {
	lines, err := auditReadLines()
	if err != nil {
		fmt.Fprintf(os.Stderr, "read log: %v\n", err)
		return 4
	}
	if len(lines) == 0 {
		fmt.Fprintln(os.Stderr, "log is empty")
		return 0
	}
	count := 0
	for i := len(lines) - 1; i >= 0; i-- {
		m, cmd, _, ok := auditParseLine(lines[i])
		if !ok || m != "fs" {
			continue
		}
		if isHistorySelf(cmd) || !moduleManifestExists("fs", i) {
			continue
		}
		desc := ""
		if rec, e := fs_loadOp(i); e == nil {
			desc = fs_summarizeOp(rec)
		}
		count++
		fmt.Printf("[%d] %s %s\n", count, lines[i], c(clrGray, desc))
	}
	if count == 0 {
		fmt.Fprintln(os.Stderr, "no rollback-able fs operations in log")
	}
	return 0
}

func fs_cmdRollback(args []string) int {
	n := 1
	for i := 0; i < len(args); i++ {
		if args[i] == "-n" || args[i] == "--last" {
			if i+1 >= len(args) {
				return 2
			}
			v, err := strconv.Atoi(args[i+1])
			if err != nil || v <= 0 {
				return 2
			}
			n = v
			i++
		} else if strings.HasPrefix(args[i], "-") {
			return 2
		}
	}
	idxs, err := moduleTailOps("fs", n)
	if err != nil || len(idxs) == 0 {
		fmt.Fprintln(os.Stderr, "no rollback-able fs operations found")
		return 4
	}
	if dryRun {
		for k, i := range idxs {
			if rec, e := fs_loadOp(i); e == nil {
				fmt.Printf("[dry-run] step %d: %s %s\n", k+1, rec.Op, fs_summarizeOp(rec))
			}
		}
		return 0
	}
	okCount, failCount := 0, 0
	for k, i := range idxs {
		rec, err := fs_loadOp(i)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[rollback] step %d: %v\n", k+1, err)
			failCount++
			continue
		}
		fmt.Fprintf(os.Stderr, "[rollback] step %d: %s %s\n", k+1, rec.Op, fs_summarizeOp(rec))
		if err := fs_rollbackRecord(rec); err != nil {
			fmt.Fprintf(os.Stderr, "[rollback] step %d: error: %v\n", k+1, err)
			failCount++
			continue
		}
		fmt.Fprintf(os.Stderr, "[rollback] step %d: ok\n", k+1)
		okCount++
	}
	if failCount == 0 {
		return 0
	}
	if okCount == 0 {
		return 2
	}
	return 1
}

// ---------- pipeline ----------

func fs_splitPipeline(args []string) [][]string {
	var stages [][]string
	var cur []string
	for _, a := range args {
		if a == "::" || a == ":::" {
			stages = append(stages, cur)
			cur = nil
			continue
		}
		cur = append(cur, a)
	}
	stages = append(stages, cur)
	return stages
}

func fs_runPipeline(stages [][]string) int {
	oldStdin, oldStdout := os.Stdin, os.Stdout
	var lastTmp string
	defer func() {
		os.Stdin = oldStdin
		os.Stdout = oldStdout
		if lastTmp != "" {
			os.Remove(lastTmp)
		}
	}()
	for i, stage := range stages {
		last := i == len(stages)-1
		savedColor := useColor
		if !last {
			useColor = false
		}
		var stdinFile *os.File
		if lastTmp != "" {
			f, err := os.Open(lastTmp)
			if err != nil {
				useColor = savedColor
				fmt.Fprintf(os.Stderr, "winctl fs: open pipe: %v\n", err)
				return 5
			}
			stdinFile = f
			os.Stdin = f
		}
		var stdoutFile *os.File
		var outTmp string
		if !last {
			f, err := os.CreateTemp("", "winctl_fs_pipe_*")
			if err != nil {
				if stdinFile != nil {
					stdinFile.Close()
					os.Stdin = oldStdin
				}
				useColor = savedColor
				fmt.Fprintf(os.Stderr, "winctl fs: create pipe: %v\n", err)
				return 5
			}
			stdoutFile = f
			outTmp = f.Name()
			os.Stdout = f
		}
		code := fs_dispatch(stage)
		if stdoutFile != nil {
			stdoutFile.Close()
			os.Stdout = oldStdout
		}
		if stdinFile != nil {
			stdinFile.Close()
			os.Stdin = oldStdin
			os.Remove(lastTmp)
		}
		lastTmp = outTmp
		useColor = savedColor
		if code != 0 {
			return code
		}
	}
	return 0
}

func fs_stageHasControlFlag(stage []string) bool {
	return has(stage, "--history", "--rollback", "-h", "--help", "--version")
}

func fs_printHelp() {
	fmt.Printf("%s v%s (Windows)\n\n", c(clrBold+clrCyan, "winctl fs"), Version)
	fmt.Print(`USAGE
  winctl fs <command> [OPTIONS] [ARGS...]
  winctl fs <cmd1> :: <cmd2> :: ...
  winctl fs --history
  winctl fs --rollback [-n N]

COMMANDS
  ls [-l] [-a] [path...]               list directory
  cat <file...>                        concatenate (use - for stdin)
  cp [-f] [-r] <src> <dst>             copy (backs up destination)
  mv [-f] <src> <dst>                  move (backs up overwritten destination)
  rm [-f] [-r] [-n] <path...>          remove (backs up everything removed)
  mkdir [-p] <path...>                 create directories (patterns expanded)
  touch <path...>                      create or update mtime (patterns expanded)
  stat <path...>                       show file info
  find [path] [-name pat] [-type f|d]  find files/dirs
  grep [-i] [-n] [-v] [-F] pat [file]  search lines
  head [-n N] [file...]                first N lines (default 10)
  tail [-n N] [file...]                last N lines (default 10)
  wc [-l] [-w] [-c] [file...]          count lines/words/bytes
  replace <old> <new> <file...>        replace literal text
  xargs [opts] <command> [args...]     feed stdin to <command>

PATTERN EXPANSION
  mkdir, touch, and rm expand {..} and [..] in path arguments:
    hello{1..3} -> hello1 hello2 hello3
    hello{a,b}  -> helloa hellob
    hello[1..3] -> hello1 hello2 hello3
  Disable with --no-expand.

PIPELINE
  winctl fs <cmd1> :: <cmd2> :: ...     pipe stdout of each stage into stdin
  of the next. ":::" is also accepted (safer inside PowerShell).

GLOBAL
  --dry-run              preview only: no changes, no backups, no log
  --no-expand            disable {..} and [..] expansion
  -o, --out <path>       redirect stdout to a file
  --no-color             disable colors (also honors NO_COLOR)
  -b, --bugs             print collected errors/warnings on exit
  --history              list rollback-able operations
  --rollback <N>         undo the most recent N rollback-able operations
  -h, --help             show this help
  --version              show version

BACKUP AND ROLLBACK
  Every modifying command backs up affected files into
    ./backup/fs/files/<logIndex>/<seq>_<name>[.gz | .tar.gz]
  --rollback executes the inverse of each stored operation.

PERFORMANCE
  cat, grep, head and tail stream input instead of loading whole files.
  head stops after N lines; tail keeps a ring buffer of N lines.

EXIT CODES
  0 success | 1 partial failure | 2 bad args | 3 permission denied
  4 not found | 5 I/O error
`)
}

func fs_main() {
	rawArgs := os.Args[1:]
	args, outPath, err := consumeGlobalFlags(rawArgs)
	if err != nil {
		fmt.Fprintf(os.Stderr, "winctl fs: %v\n", err)
		finalExit(2)
	}
	initColor()
	if has(args, "--version") {
		fmt.Printf("winctl fs v%s\n", Version)
		finalExit(0)
	}
	if len(args) == 0 || has(args, "-h", "--help") {
		fs_printHelp()
		finalExit(0)
	}
	if has(args, "--no-expand") {
		fs_expandEnabled = false
		args = fs_removeFlag(args, "--no-expand")
	}
	if outPath != "" {
		if err := setupOutput(outPath); err != nil {
			fmt.Fprintf(os.Stderr, "winctl fs: %v\n", err)
			finalExit(2)
		}
	}
	var code int
	switch {
	case has(args, "--history"):
		code = fs_cmdHistory()
		if !dryRun {
			auditLog("fs", buildCmdLine(os.Args), code)
		}
		finalExit(code)
	case has(args, "--rollback"):
		code = fs_cmdRollback(stripFlags(args, "--rollback"))
		if !dryRun {
			auditLog("fs", buildCmdLine(os.Args), code)
		}
		finalExit(code)
	}
	stages := fs_splitPipeline(args)
	if len(stages) > 1 {
		bad := false
		for i, s := range stages {
			if fs_stageHasControlFlag(s) {
				fmt.Fprintf(os.Stderr, "winctl fs: --history/--rollback/--help/--version not allowed in a pipeline (stage %d)\n", i+1)
				bad = true
			}
		}
		if bad {
			code = 2
		} else {
			code = fs_runPipeline(stages)
		}
	} else {
		code = fs_dispatch(args)
	}
	if !dryRun && shouldLogRun() {
		auditLog("fs", buildCmdLine(os.Args), code)
	}
	finalExit(code)
}

// ============================================================================
// hash — hash + Authenticode signature verification (read-only)
// ============================================================================
//
// Performance notes (behaviour unchanged for default users):
//   By default only SHA-256 is computed, in one pass over the file.
//   --all adds MD5 and SHA-1 for compatibility with older checksum
//   lists, at the cost of one extra pass per additional algorithm.

var (
	hash_wintrust = syscall.NewLazyDLL("wintrust.dll")
	hash_crypt32  = syscall.NewLazyDLL("crypt32.dll")

	hash_pWinVerifyTrust = hash_wintrust.NewProc("WinVerifyTrust")

	hash_pCryptQueryObject           = hash_crypt32.NewProc("CryptQueryObject")
	hash_pCertGetNameStringW         = hash_crypt32.NewProc("CertGetNameStringW")
	hash_pCertFreeCertificateContext = hash_crypt32.NewProc("CertFreeCertificateContext")
	hash_pCertCloseStore             = hash_crypt32.NewProc("CertCloseStore")
	hash_pCryptMsgClose              = hash_crypt32.NewProc("CryptMsgClose")
)

type hash_GUID struct {
	Data1 uint32
	Data2 uint16
	Data3 uint16
	Data4 [8]byte
}

var hash_winTrustActionVerifyV2 = hash_GUID{
	Data1: 0x00AAC56B, Data2: 0xCD44, Data3: 0x11D0,
	Data4: [8]byte{0x8C, 0xC2, 0x00, 0xC0, 0x4F, 0xC2, 0x95, 0xEE},
}

const (
	hash_WTD_UI_NONE               = 2
	hash_WTD_REVOKE_NONE           = 0
	hash_WTD_CHOICE_FILE           = 1
	hash_WTD_STATEACTION_VERIFY    = 1
	hash_WTD_STATEACTION_CLOSE     = 2
	hash_WTD_SAFER_FLAG            = 0x100
	hash_WTD_REVOCATION_CHECK_NONE = 0x10

	hash_TRUST_E_NOSIGNATURE          = 0x800B0100
	hash_TRUST_E_SUBJECT_FORM_UNKNOWN = 0x800B0003
	hash_TRUST_E_PROVIDER_UNKNOWN     = 0x800B0001
	hash_TRUST_E_EXPLICIT_DISTRUST    = 0x800B0111
	hash_TRUST_E_SUBJECT_NOT_TRUSTED  = 0x800B0004
	hash_TRUST_E_BAD_DIGEST           = 0x80096010
	hash_CERT_E_UNTRUSTEDROOT         = 0x800B0109
	hash_CERT_E_CHAINING              = 0x800B010A
	hash_CERT_E_EXPIRED               = 0x800B0101
)

type hash_WINTRUST_FILE_INFO struct {
	CbStruct       uint32
	PcwszFilePath  *uint16
	HFile          syscall.Handle
	PgKnownSubject *hash_GUID
}

type hash_WINTRUST_DATA struct {
	CbStruct            uint32
	PolicyCallbackData  uintptr
	SIPClientData       uintptr
	DwUIChoice          uint32
	FdwRevocationChecks uint32
	DwUnionChoice       uint32
	PFile               uintptr
	DwStateAction       uint32
	HWVTStateData       syscall.Handle
	PwszURLReference    *uint16
	DwProvFlags         uint32
	DwUIContext         uint32
	PSignatureSettings  uintptr
}

type hash_sigResult struct {
	Status     string   `json:"status"`
	Reason     string   `json:"reason,omitempty"`
	Signer     string   `json:"signer,omitempty"`
	Issuer     string   `json:"issuer,omitempty"`
	ChainNotes []string `json:"chainNotes,omitempty"`
}

func hash_verifyAuthenticode(path string) (hash_sigResult, error) {
	pathPtr, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return hash_sigResult{Status: "error", Reason: err.Error()}, err
	}
	fileInfo := hash_WINTRUST_FILE_INFO{
		CbStruct:      uint32(unsafe.Sizeof(hash_WINTRUST_FILE_INFO{})),
		PcwszFilePath: pathPtr,
	}
	data := hash_WINTRUST_DATA{
		CbStruct:            uint32(unsafe.Sizeof(hash_WINTRUST_DATA{})),
		DwUIChoice:          hash_WTD_UI_NONE,
		FdwRevocationChecks: hash_WTD_REVOKE_NONE,
		DwUnionChoice:       hash_WTD_CHOICE_FILE,
		PFile:               uintptr(unsafe.Pointer(&fileInfo)),
		DwStateAction:       hash_WTD_STATEACTION_VERIFY,
		DwProvFlags:         hash_WTD_SAFER_FLAG,
	}
	ret, _, _ := hash_pWinVerifyTrust.Call(0,
		uintptr(unsafe.Pointer(&hash_winTrustActionVerifyV2)),
		uintptr(unsafe.Pointer(&data)))
	defer func() {
		data.DwStateAction = hash_WTD_STATEACTION_CLOSE
		hash_pWinVerifyTrust.Call(0,
			uintptr(unsafe.Pointer(&hash_winTrustActionVerifyV2)),
			uintptr(unsafe.Pointer(&data)))
	}()
	code := uint32(ret)
	switch code {
	case 0:
		return hash_sigResult{Status: "valid"}, nil
	case hash_TRUST_E_NOSIGNATURE:
		return hash_sigResult{Status: "unsigned", Reason: "no Authenticode signature"}, nil
	case hash_TRUST_E_BAD_DIGEST:
		return hash_sigResult{Status: "invalid", Reason: "digest mismatch (file has been modified)"}, nil
	case hash_TRUST_E_EXPLICIT_DISTRUST:
		return hash_sigResult{Status: "invalid", Reason: "signature is explicitly distrusted"}, nil
	case hash_TRUST_E_SUBJECT_NOT_TRUSTED:
		return hash_sigResult{Status: "invalid", Reason: "subject is not trusted"}, nil
	case hash_CERT_E_UNTRUSTEDROOT:
		return hash_sigResult{Status: "invalid", Reason: "certificate chain ends at an untrusted root"}, nil
	case hash_CERT_E_CHAINING:
		return hash_sigResult{Status: "invalid", Reason: "certificate chain could not be built"}, nil
	case hash_CERT_E_EXPIRED:
		return hash_sigResult{Status: "invalid", Reason: "certificate has expired"}, nil
	case hash_TRUST_E_SUBJECT_FORM_UNKNOWN, hash_TRUST_E_PROVIDER_UNKNOWN:
		return hash_sigResult{Status: "error", Reason: "WinVerifyTrust cannot determine the subject form"}, nil
	}
	return hash_sigResult{
		Status: "invalid", Reason: fmt.Sprintf("WinVerifyTrust returned 0x%08X", code),
	}, nil
}

func hash_certNameStringFlags(certCtx uintptr, nameType, flags uint32) string {
	n, _, _ := hash_pCertGetNameStringW.Call(certCtx, uintptr(nameType), uintptr(flags), 0, 0, 0)
	if n <= 1 {
		return ""
	}
	buf := make([]uint16, n)
	r, _, _ := hash_pCertGetNameStringW.Call(certCtx, uintptr(nameType), uintptr(flags), 0,
		uintptr(unsafe.Pointer(&buf[0])), uintptr(n))
	if r == 0 {
		return ""
	}
	return syscall.UTF16ToString(buf)
}

func hash_extractSigner(path string) (signer, issuer string, notes []string) {
	pathPtr, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return "", "", nil
	}
	const (
		CERT_QUERY_OBJECT_FILE                     = 1
		CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED = 1 << 10
		CERT_QUERY_FORMAT_FLAG_BINARY              = 1 << 1
	)
	var encodingType, contentType, formatType uint32
	var store, msg syscall.Handle
	var certContext uintptr
	r, _, _ := hash_pCryptQueryObject.Call(
		uintptr(CERT_QUERY_OBJECT_FILE),
		uintptr(unsafe.Pointer(pathPtr)),
		uintptr(CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED),
		uintptr(CERT_QUERY_FORMAT_FLAG_BINARY), 0,
		uintptr(unsafe.Pointer(&encodingType)), uintptr(unsafe.Pointer(&contentType)),
		uintptr(unsafe.Pointer(&formatType)), uintptr(unsafe.Pointer(&store)),
		uintptr(unsafe.Pointer(&msg)), uintptr(unsafe.Pointer(&certContext)))
	if r == 0 {
		return "", "", nil
	}
	if store != 0 {
		defer hash_pCertCloseStore.Call(uintptr(store), 0)
	}
	if msg != 0 {
		defer hash_pCryptMsgClose.Call(uintptr(msg))
	}
	if certContext != 0 {
		defer hash_pCertFreeCertificateContext.Call(certContext)
	}
	if certContext == 0 {
		return "", "", []string{"no signer certificate context"}
	}
	signer = hash_certNameStringFlags(certContext, 4, 0)
	issuer = hash_certNameStringFlags(certContext, 4, 0x1)
	return signer, issuer, nil
}

// hash_hashResult: MD5 and SHA1 are only populated when --all is given.
// omitempty keeps the default JSON output to {"sha256": "...", "size": N}.
type hash_hashResult struct {
	MD5    string `json:"md5,omitempty"`
	SHA1   string `json:"sha1,omitempty"`
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
}

// hash_hashFileWith computes SHA-256 always, and MD5/SHA1 only when
// allHashes is true. Default is SHA-256 only (one pass over the file
// instead of three).
func hash_hashFileWith(path string, allHashes bool) (hash_hashResult, error) {
	f, err := os.Open(path)
	if err != nil {
		return hash_hashResult{}, err
	}
	defer f.Close()
	hSHA256 := sha256.New()
	if !allHashes {
		n, err := io.Copy(hSHA256, f)
		if err != nil {
			return hash_hashResult{}, err
		}
		return hash_hashResult{
			SHA256: hex.EncodeToString(hSHA256.Sum(nil)),
			Size:   n,
		}, nil
	}
	hMD5 := md5.New()
	hSHA1 := sha1.New()
	n, err := io.Copy(io.MultiWriter(hMD5, hSHA1, hSHA256), f)
	if err != nil {
		return hash_hashResult{}, err
	}
	return hash_hashResult{
		MD5:    hex.EncodeToString(hMD5.Sum(nil)),
		SHA1:   hex.EncodeToString(hSHA1.Sum(nil)),
		SHA256: hex.EncodeToString(hSHA256.Sum(nil)),
		Size:   n,
	}, nil
}

func hash_isPE(path string) bool {
	f, err := pe.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()
	return true
}

type hash_reportEntry struct {
	Path   string           `json:"path"`
	Hashes *hash_hashResult `json:"hashes,omitempty"`
	Sig    *hash_sigResult  `json:"signature,omitempty"`
	Error  string           `json:"error,omitempty"`
}

func hash_collectFiles(args []string, recursive bool) ([]string, error) {
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
				if err != nil || info.IsDir() {
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

type hash_hashOpts struct {
	jsonOut   bool
	recursive bool
	hashOnly  bool
	sigOnly   bool
	allHashes bool
}

func hash_parseHashOpts(args []string) (*hash_hashOpts, []string, error) {
	opts := &hash_hashOpts{}
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
		case "--all":
			opts.allHashes = true
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

func hash_cmdHashOrSig(paths []string, opts *hash_hashOpts) int {
	if len(paths) == 0 {
		fmt.Fprintln(os.Stderr, "winctl hash: no files given")
		return 2
	}
	files, err := hash_collectFiles(paths, opts.recursive)
	if err != nil {
		fmt.Fprintf(os.Stderr, "winctl hash: %v\n", err)
		return 5
	}
	if len(files) == 0 {
		fmt.Fprintln(os.Stderr, "winctl hash: no files matched")
		return 0
	}
	if dryRun {
		fmt.Printf("[dry-run] would process %d file(s):\n", len(files))
		for _, f := range files {
			fmt.Printf("  %s\n", f)
		}
		return 0
	}
	var entries []*hash_reportEntry
	okCount, failCount := 0, 0
	for _, p := range files {
		e := &hash_reportEntry{Path: p}
		if !opts.sigOnly {
			h, err := hash_hashFileWith(p, opts.allHashes)
			if err != nil {
				e.Error = err.Error()
				failCount++
				entries = append(entries, e)
				continue
			}
			e.Hashes = &h
		}
		if !opts.hashOnly && hash_isPE(p) {
			sig, err := hash_verifyAuthenticode(p)
			if err == nil {
				signer, issuer, notes := hash_extractSigner(p)
				sig.Signer, sig.Issuer, sig.ChainNotes = signer, issuer, notes
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
				if e.Hashes.MD5 != "" {
					fmt.Printf("%s %s\n", c(clrCyan, "MD5:   "), e.Hashes.MD5)
				}
				if e.Hashes.SHA1 != "" {
					fmt.Printf("%s %s\n", c(clrCyan, "SHA1:  "), e.Hashes.SHA1)
				}
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

func hash_cmdHistory() int {
	lines, err := auditReadLines()
	if err != nil {
		fmt.Fprintf(os.Stderr, "read log: %v\n", err)
		return 4
	}
	if len(lines) == 0 {
		fmt.Fprintln(os.Stderr, "log is empty")
		return 0
	}
	count := 0
	for i := len(lines) - 1; i >= 0; i-- {
		m, _, _, ok := auditParseLine(lines[i])
		if !ok || m != "hash" {
			continue
		}
		count++
		fmt.Printf("[%d] %s\n", count, lines[i])
	}
	if count == 0 {
		fmt.Fprintln(os.Stderr, "no hash history entries in log")
	}
	return 0
}

func hash_cmdRollback() int {
	fmt.Fprintln(os.Stderr, "winctl hash is read-only: there are no operations to roll back")
	fmt.Fprintln(os.Stderr, "  It only reads files, computes hashes, and verifies signatures.")
	fmt.Fprintln(os.Stderr, "  Its history is for audit only; use --history to view it.")
	return 0
}

func hash_printHelp() {
	fmt.Printf("%s v%s (Windows)\n\n", c(clrBold+clrCyan, "winctl hash"), Version)
	fmt.Print(`USAGE
  winctl hash hash <file|dir>...
  winctl hash sig  <file|dir>...        (signature only)
  winctl hash <file|dir>...             (hash + sig if PE)
  winctl hash --history
  winctl hash --rollback                (always a no-op: read-only)

OPTIONS
  --json           JSON output
  --recursive, -r  walk directories recursively
  --hash-only      skip signature verification
  --sig-only       only verify signatures
  --all            also compute MD5 and SHA1 (default: SHA-256 only)

GLOBAL
  -o, --out <path> redirect stdout to a file
  --dry-run        print the plan without reading any file
  --no-color       disable ANSI colors (also honors NO_COLOR)
  -b, --bugs       print collected errors/warnings
  -h, --help       show this help
  --version        show version

NOTES
  By default only SHA-256 is computed, in a single pass over the file.
  Use --all when you need MD5 and SHA1 for compatibility with older
  checksum lists; that costs one extra pass per algorithm.

All logs go to ./backup/winctl_logs.log
`)
}

func hash_main() {
	args, outPath, err := consumeGlobalFlags(os.Args[1:])
	if err != nil {
		fmt.Fprintf(os.Stderr, "winctl hash: %v\n", err)
		finalExit(2)
	}
	initColor()
	if has(args, "--version") {
		fmt.Printf("winctl hash v%s\n", Version)
		finalExit(0)
	}
	if len(args) == 0 || has(args, "-h", "--help") {
		hash_printHelp()
		finalExit(0)
	}
	if has(args, "--history") {
		code := hash_cmdHistory()
		auditLog("hash", buildCmdLine(os.Args), code)
		finalExit(code)
	}
	if has(args, "--rollback") {
		code := hash_cmdRollback()
		auditLog("hash", buildCmdLine(os.Args), code)
		finalExit(code)
	}
	if outPath != "" {
		if err := setupOutput(outPath); err != nil {
			fmt.Fprintf(os.Stderr, "winctl hash: %v\n", err)
			finalExit(2)
		}
	}
	cmd := ""
	rest := args
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		switch args[0] {
		case "hash", "sig":
			cmd = args[0]
			rest = args[1:]
		}
	}
	opts, positional, err := hash_parseHashOpts(rest)
	if err != nil {
		fmt.Fprintf(os.Stderr, "winctl hash: %v\n", err)
		finalExit(2)
	}
	var code int
	switch cmd {
	case "hash":
		opts.sigOnly = false
		opts.hashOnly = true
		if len(positional) == 0 {
			fmt.Fprintln(os.Stderr, "winctl hash: hash requires at least one file or directory")
			finalExit(2)
		}
		code = hash_cmdHashOrSig(positional, opts)
	case "sig":
		opts.sigOnly = true
		opts.hashOnly = false
		if len(positional) == 0 {
			fmt.Fprintln(os.Stderr, "winctl hash: sig requires at least one file or directory")
			finalExit(2)
		}
		code = hash_cmdHashOrSig(positional, opts)
	default:
		if len(positional) == 0 {
			fmt.Fprintln(os.Stderr, "winctl hash: no files given (use -h for help)")
			finalExit(2)
		}
		code = hash_cmdHashOrSig(positional, opts)
	}
	if !dryRun && shouldLogRun() {
		auditLog("hash", buildCmdLine(os.Args), code)
	}
	finalExit(code)
}
// ============================================================================
// batch — run a script of winctl commands, optionally in parallel
// ============================================================================
//
// Batch itself is read-only on the system. It dispatches every line to one
// of the existing 16 modules as a child winctl process, so all their
// backups, manifests and audit lines are produced exactly as if you had
// typed the commands by hand.
//
// Layout:
//   ./backup/winctl_logs.log              one line per batch run
//   ./backup/batch/ops/<idx>.json         per-run manifest (steps + exit codes)
//   ./backup/batch/scripts/<ts>.wctl      copy of the executed script
//
// Script syntax (.wctl), one command per line:
//
//   # comment
//   !set NAME=VALUE            define a variable visible to later lines
//   !dry-run                   propagate --dry-run to every child command
//   !no-dry-run                stop propagating --dry-run
//   !stop-on-error             stop the run on first non-zero exit (default)
//   !continue-on-error         keep going on failure
//   !quiet                     suppress child stdout
//   !verbose                   show child stdout (default)
//   !timeout 120s              per-command timeout (default 120s)
//   !parallel N                begin a parallel block of up to N jobs
//     ...
//   !end                       close the parallel block
//   !check                     mark this script as read-only
//   <module> [args...]         a winctl command, e.g. "proc list --json"
//
// Variables $NAME / ${NAME} are expanded from !set and the environment.
// Quoting: double and single quotes are both honoured.
//
// v1.2 changes:
//   * step report is flushed in 20-line chunks so very long scripts don't
//     dump everything at once;
//   * each block's start is announced on stderr, giving live feedback even
//     when the final summary is chunked.
//
// Rollback semantics:
//   batch --rollback walks the recorded steps in reverse and, for each step
//   whose module supports manifest rollback (net, reg, svc, task, acl, bkp,
//   fs, box), it runs "winctl <module> --rollback -n 1". This assumes the
//   batch run is exclusive (no other winctl operations between run and
//   rollback), which is the normal case. Read-only modules (open, pe, disk,
//   doc, evt, hash) and proc/sys (which have no manifest rollback) are
//   skipped.

type batch_Options struct {
	DryRun      bool
	StopOnError bool
	Parallel    int
	Quiet       bool
	Timeout     time.Duration
	OutDir      string
	ExePath     string
}

func batch_defaultOptions() *batch_Options {
	exe, err := os.Executable()
	if err != nil || exe == "" {
		exe = "winctl.exe"
	}
	return &batch_Options{
		StopOnError: true,
		Parallel:    4,
		Quiet:       false,
		Timeout:     120 * time.Second,
		ExePath:     exe,
	}
}

type batch_Line struct {
	LineNum int
	Raw     string
	Module  string
	Args    []string
}

type batch_Block struct {
	Parallel bool
	Lines    []batch_Line
}

type batch_Script struct {
	Path        string
	Blocks      []batch_Block
	Vars        map[string]string
	DryRun      *bool
	StopOnError *bool
	Quiet       *bool
	Timeout     *time.Duration
	CheckOnly   bool
}

type batch_StepResult struct {
	Line     int      `json:"line"`
	Module   string   `json:"module"`
	Args     []string `json:"args,omitempty"`
	Cmd      string   `json:"cmd"`
	ExitCode int      `json:"exitCode"`
	Elapsed  string   `json:"elapsed"`
	Error    string   `json:"error,omitempty"`
	Skipped  bool     `json:"skipped,omitempty"`
	Output   string   `json:"output,omitempty"`
}

type batch_opRecord struct {
	Op     string             `json:"op"`
	TS     string             `json:"ts"`
	Cmd    string             `json:"cmd"`
	Script string             `json:"script"`
	Code   int                `json:"code"`
	Steps  []batch_StepResult `json:"steps"`
}

var batch_readOnlyModules = map[string]bool{
	"open": true, "pe": true, "disk": true, "doc": true, "evt": true, "hash": true,
}

var batch_mutatingModules = map[string]bool{
	"net": true, "proc": true, "reg": true, "svc": true, "sys": true,
	"task": true, "acl": true, "bkp": true, "fs": true, "box": true,
}

// Modules whose "--rollback -n 1" undoes the most recent operation.
var batch_rollbackableModules = map[string]bool{
	"net": true, "reg": true, "svc": true, "task": true,
	"acl": true, "bkp": true, "fs": true, "box": true,
}

func batch_isKnownModule(m string) bool {
	return batch_readOnlyModules[m] || batch_mutatingModules[m] || m == "batch"
}

func batch_expandVars(s string, vars map[string]string) string {
	if !strings.Contains(s, "$") {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	i := 0
	for i < len(s) {
		if s[i] != '$' {
			b.WriteByte(s[i])
			i++
			continue
		}
		if i+1 < len(s) && s[i+1] == '{' {
			j := strings.IndexByte(s[i+2:], '}')
			if j < 0 {
				b.WriteByte(s[i])
				i++
				continue
			}
			name := s[i+2 : i+2+j]
			if v, ok := vars[name]; ok {
				b.WriteString(v)
			} else if v := os.Getenv(name); v != "" {
				b.WriteString(v)
			}
			i += 2 + j + 1
			continue
		}
		j := i + 1
		for j < len(s) {
			c := s[j]
			if !((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_') {
				break
			}
			j++
		}
		if j == i+1 {
			b.WriteByte(s[i])
			i++
			continue
		}
		name := s[i+1 : j]
		if v, ok := vars[name]; ok {
			b.WriteString(v)
		} else if v := os.Getenv(name); v != "" {
			b.WriteString(v)
		}
		i = j
	}
	return b.String()
}

func batch_splitArgs(s string) []string {
	var out []string
	var cur strings.Builder
	inDQ, inSQ := false, false
	for i := 0; i < len(s); i++ {
		c := s[i]
		if inDQ {
			if c == '\\' && i+1 < len(s) && (s[i+1] == '"' || s[i+1] == '\\') {
				cur.WriteByte(s[i+1])
				i++
				continue
			}
			if c == '"' {
				inDQ = false
				continue
			}
			cur.WriteByte(c)
			continue
		}
		if inSQ {
			if c == '\'' {
				inSQ = false
				continue
			}
			cur.WriteByte(c)
			continue
		}
		switch c {
		case '"':
			inDQ = true
		case '\'':
			inSQ = true
		case ' ', '\t':
			if cur.Len() > 0 {
				out = append(out, cur.String())
				cur.Reset()
			}
		default:
			cur.WriteByte(c)
		}
	}
	if cur.Len() > 0 {
		out = append(out, cur.String())
	}
	return out
}

func batch_joinArgs(exe string, args []string) string {
	parts := make([]string, 0, len(args)+1)
	parts = append(parts, syscall.EscapeArg(exe))
	for _, a := range args {
		parts = append(parts, syscall.EscapeArg(a))
	}
	return strings.Join(parts, " ")
}

func batch_parseScript(path string) (*batch_Script, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	sc := &batch_Script{Path: path, Vars: map[string]string{}}
	lines := strings.Split(string(data), "\n")
	var curBlock *batch_Block
	inParallel := false

	flush := func() {
		if curBlock != nil && len(curBlock.Lines) > 0 {
			sc.Blocks = append(sc.Blocks, *curBlock)
		}
		curBlock = nil
	}

	for i, raw := range lines {
		line := strings.TrimRight(raw, "\r")
		stripped := strings.TrimSpace(line)
		if stripped == "" || strings.HasPrefix(stripped, "#") {
			continue
		}
		ln := i + 1
		if strings.HasPrefix(stripped, "!") {
			parts := strings.Fields(stripped[1:])
			if len(parts) == 0 {
				return nil, fmt.Errorf("line %d: empty control command", ln)
			}
			ctrl := strings.ToLower(parts[0])
			arg := strings.TrimSpace(strings.TrimPrefix(stripped, "!"+parts[0]))
			switch ctrl {
			case "set":
				if arg == "" {
					return nil, fmt.Errorf("line %d: !set requires NAME=VALUE", ln)
				}
				eq := strings.IndexByte(arg, '=')
				if eq <= 0 {
					return nil, fmt.Errorf("line %d: !set expects NAME=VALUE, got %q", ln, arg)
				}
				name := strings.TrimSpace(arg[:eq])
				val := batch_expandVars(strings.TrimSpace(arg[eq+1:]), sc.Vars)
				sc.Vars[name] = val
			case "dry-run":
				v := true
				sc.DryRun = &v
			case "no-dry-run":
				v := false
				sc.DryRun = &v
			case "stop-on-error":
				v := true
				sc.StopOnError = &v
			case "continue-on-error":
				v := false
				sc.StopOnError = &v
			case "quiet":
				v := true
				sc.Quiet = &v
			case "verbose":
				v := false
				sc.Quiet = &v
			case "check":
				sc.CheckOnly = true
			case "timeout":
				if arg == "" {
					return nil, fmt.Errorf("line %d: !timeout requires a duration", ln)
				}
				d, err := time.ParseDuration(arg)
				if err != nil {
					return nil, fmt.Errorf("line %d: bad !timeout %q: %v", ln, arg, err)
				}
				sc.Timeout = &d
			case "parallel":
				if inParallel {
					return nil, fmt.Errorf("line %d: nested !parallel is not allowed", ln)
				}
				if arg == "" {
					return nil, fmt.Errorf("line %d: !parallel requires a number", ln)
				}
				n, err := strconv.Atoi(arg)
				if err != nil || n < 1 || n > 64 {
					return nil, fmt.Errorf("line %d: !parallel N must be 1..64", ln)
				}
				flush()
				inParallel = true
				curBlock = &batch_Block{Parallel: true}
			case "end":
				if !inParallel {
					return nil, fmt.Errorf("line %d: !end without !parallel", ln)
				}
				flush()
				inParallel = false
			default:
				return nil, fmt.Errorf("line %d: unknown control %q", ln, ctrl)
			}
			continue
		}
		expanded := batch_expandVars(stripped, sc.Vars)
		fields := batch_splitArgs(expanded)
		if len(fields) == 0 {
			continue
		}
		module := fields[0]
		if !batch_isKnownModule(module) {
			return nil, fmt.Errorf("line %d: unknown module %q", ln, module)
		}
		if curBlock == nil {
			curBlock = &batch_Block{Parallel: inParallel}
		}
		curBlock.Lines = append(curBlock.Lines, batch_Line{
			LineNum: ln, Raw: expanded, Module: module, Args: fields[1:],
		})
	}
	if inParallel {
		return nil, fmt.Errorf("unterminated !parallel block (missing !end)")
	}
	flush()
	if len(sc.Blocks) == 0 {
		return nil, fmt.Errorf("script %s has no commands", path)
	}
	return sc, nil
}

func batch_execStep(line batch_Line, opts *batch_Options, scriptDry bool) batch_StepResult {
	res := batch_StepResult{
		Line:   line.LineNum,
		Module: line.Module,
		Args:   append([]string(nil), line.Args...),
	}
	args := append([]string{line.Module}, line.Args...)
	if scriptDry && !has(args, "--dry-run") {
		args = append(args, "--dry-run")
	}
	if opts.OutDir != "" {
		for i := 0; i < len(args); i++ {
			switch {
			case (args[i] == "-o" || args[i] == "--out") && i+1 < len(args):
				if !filepath.IsAbs(args[i+1]) {
					args[i+1] = filepath.Join(opts.OutDir, args[i+1])
				}
				i++
			case strings.HasPrefix(args[i], "--out="):
				v := strings.TrimPrefix(args[i], "--out=")
				if !filepath.IsAbs(v) {
					args[i] = "--out=" + filepath.Join(opts.OutDir, v)
				}
			case strings.HasPrefix(args[i], "-o="):
				v := strings.TrimPrefix(args[i], "-o=")
				if !filepath.IsAbs(v) {
					args[i] = "-o=" + filepath.Join(opts.OutDir, v)
				}
			}
		}
	}
	res.Cmd = batch_joinArgs(opts.ExePath, args)
	start := time.Now()
	cmd := exec.Command(opts.ExePath, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	var outBuf bytes.Buffer
	if opts.Quiet {
		cmd.Stdout = &outBuf
		cmd.Stderr = &outBuf
	} else {
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
	}
	if err := cmd.Start(); err != nil {
		res.ExitCode = 5
		res.Error = err.Error()
		res.Elapsed = time.Since(start).Round(time.Millisecond).String()
		return res
	}
	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = 120 * time.Second
	}
	done := make(chan struct{})
	go func() {
		select {
		case <-time.After(timeout):
			if cmd.Process != nil {
				_ = cmd.Process.Kill()
			}
		case <-done:
		}
	}()
	runErr := cmd.Wait()
	close(done)
	res.Elapsed = time.Since(start).Round(time.Millisecond).String()
	if runErr != nil {
		if ee, ok := runErr.(*exec.ExitError); ok {
			res.ExitCode = ee.ExitCode()
		} else {
			res.ExitCode = 5
			res.Error = runErr.Error()
		}
	}
	if opts.Quiet && outBuf.Len() > 0 {
		out := strings.TrimSpace(outBuf.String())
		if len(out) > 4000 {
			out = out[:4000] + "...(truncated)"
		}
		res.Output = out
	}
	return res
}

func batch_executeScript(sc *batch_Script, opts *batch_Options) (*batch_opRecord, int) {
	rec := &batch_opRecord{
		Op:     "run",
		TS:     time.Now().Format("2006-01-02 15:04:05"),
		Cmd:    buildCmdLine(os.Args),
		Script: sc.Path,
	}
	dry := opts.DryRun
	if sc.DryRun != nil {
		dry = *sc.DryRun
	}
	stop := opts.StopOnError
	if sc.StopOnError != nil {
		stop = *sc.StopOnError
	}
	quiet := opts.Quiet
	if sc.Quiet != nil {
		quiet = *sc.Quiet
	}
	to := opts.Timeout
	if sc.Timeout != nil {
		to = *sc.Timeout
	}
	local := *opts
	local.DryRun = dry
	local.StopOnError = stop
	local.Quiet = quiet
	local.Timeout = to

	for bi, blk := range sc.Blocks {
		// v1.2: announce block start on stderr so the user gets live
		// feedback even when the final per-step report is chunked.
		tag := "seq"
		if blk.Parallel {
			tag = "par"
		}
		fmt.Fprintf(os.Stderr, "%s %s block %d/%d (%d cmd)\n",
			c(clrGray, "batch:"), tag, bi+1, len(sc.Blocks), len(blk.Lines))

		if blk.Parallel {
			par := local.Parallel
			if par < 1 {
				par = 1
			}
			sem := make(chan struct{}, par)
			results := make([]batch_StepResult, len(blk.Lines))
			var wg sync.WaitGroup
			for i, ln := range blk.Lines {
				if sc.CheckOnly && !batch_readOnlyModules[ln.Module] {
					results[i] = batch_StepResult{
						Line: ln.LineNum, Module: ln.Module, Args: ln.Args,
						Cmd:     batch_joinArgs(local.ExePath, append([]string{ln.Module}, ln.Args...)),
						Skipped: true, Error: "check mode: mutating module skipped",
					}
					continue
				}
				wg.Add(1)
				go func(i int, ln batch_Line) {
					defer wg.Done()
					sem <- struct{}{}
					defer func() { <-sem }()
					results[i] = batch_execStep(ln, &local, dry)
				}(i, ln)
			}
			wg.Wait()
			stopNow := false
			for _, r := range results {
				rec.Steps = append(rec.Steps, r)
				if !r.Skipped && r.ExitCode != 0 && stop {
					stopNow = true
				}
			}
			if stopNow {
				break
			}
			continue
		}
		stopNow := false
		for _, ln := range blk.Lines {
			if sc.CheckOnly && !batch_readOnlyModules[ln.Module] {
				rec.Steps = append(rec.Steps, batch_StepResult{
					Line: ln.LineNum, Module: ln.Module, Args: ln.Args,
					Cmd:     batch_joinArgs(local.ExePath, append([]string{ln.Module}, ln.Args...)),
					Skipped: true, Error: "check mode: mutating module skipped",
				})
				continue
			}
			r := batch_execStep(ln, &local, dry)
			rec.Steps = append(rec.Steps, r)
			if r.ExitCode != 0 && stop {
				stopNow = true
				break
			}
		}
		if stopNow {
			break
		}
	}

	okCount, failCount := 0, 0
	for _, s := range rec.Steps {
		if s.Skipped {
			continue
		}
		if s.ExitCode == 0 {
			okCount++
		} else {
			failCount++
		}
	}
	code := 0
	if failCount > 0 {
		if okCount == 0 {
			code = 2
		} else {
			code = 1
		}
	}
	rec.Code = code
	return rec, code
}

func batch_saveOp(idx int, rec *batch_opRecord) {
	if err := moduleSaveManifest("batch", idx, rec); err != nil {
		bugs.Add("ERR", "save op %d: %v", idx, err)
	}
}

func batch_loadOp(idx int) (*batch_opRecord, error) {
	var rec batch_opRecord
	if err := moduleLoadManifest("batch", idx, &rec); err != nil {
		return nil, err
	}
	return &rec, nil
}

func batch_saveScriptCopy(path string) {
	data, err := os.ReadFile(path)
	if err != nil {
		return
	}
	dir := filepath.Join(moduleRoot("batch"), "scripts")
	if err := os.MkdirAll(dir, 0755); err != nil {
		return
	}
	dst := filepath.Join(dir, time.Now().Format("20060102_150405")+"_"+filepath.Base(path))
	_ = os.WriteFile(dst, data, 0644)
}

func batch_printPlan(sc *batch_Script, opts *batch_Options) {
	dry := opts.DryRun
	if sc.DryRun != nil {
		dry = *sc.DryRun
	}
	fmt.Printf("%s %s\n", c(clrCyan, "Script:"), sc.Path)
	fmt.Printf("%s %d block(s), %d command(s)\n", c(clrCyan, "Plan:  "), len(sc.Blocks), batch_countLines(sc))
	if sc.CheckOnly {
		fmt.Printf("%s read-only check mode\n", c(clrYellow, "Mode:  "))
	}
	if dry {
		fmt.Printf("%s propagated to every child command\n", c(clrYellow, "Dry-run:"))
	}
	if len(sc.Vars) > 0 {
		fmt.Println(c(clrCyan, "Variables:"))
		names := make([]string, 0, len(sc.Vars))
		for k := range sc.Vars {
			names = append(names, k)
		}
		sort.Strings(names)
		for _, k := range names {
			fmt.Printf("  %s = %q\n", k, sc.Vars[k])
		}
	}
	for bi, blk := range sc.Blocks {
		tag := "seq"
		if blk.Parallel {
			tag = "par"
		}
		fmt.Printf("\n%s block %d (%d line(s))\n",
			c(clrBold+clrCyan, tag), bi+1, len(blk.Lines))
		for _, ln := range blk.Lines {
			fmt.Printf("  [%3d] %s\n", ln.LineNum, ln.Raw)
		}
	}
}

func batch_countLines(sc *batch_Script) int {
	n := 0
	for _, b := range sc.Blocks {
		n += len(b.Lines)
	}
	return n
}

func batch_cmdRun(args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "usage: winctl batch run <script.wctl> [OPTIONS]")
		return 2
	}
	scriptPath := ""
	opts := batch_defaultOptions()
	opts.DryRun = dryRun
	yes := false
	i := 0
	for i < len(args) {
		a := args[i]
		switch a {
		case "--parallel":
			if i+1 >= len(args) {
				return 2
			}
			v, err := strconv.Atoi(args[i+1])
			if err != nil || v < 1 || v > 64 {
				return 2
			}
			opts.Parallel = v
			i += 2
		case "--timeout":
			if i+1 >= len(args) {
				return 2
			}
			d, err := time.ParseDuration(args[i+1])
			if err != nil {
				return 2
			}
			opts.Timeout = d
			i += 2
		case "--out-dir":
			if i+1 >= len(args) {
				return 2
			}
			opts.OutDir = args[i+1]
			if err := os.MkdirAll(opts.OutDir, 0755); err != nil {
				fmt.Fprintf(os.Stderr, "winctl batch: mkdir %s: %v\n", opts.OutDir, err)
				return 5
			}
			i += 2
		case "--stop-on-error":
			opts.StopOnError = true
			i++
		case "--continue-on-error":
			opts.StopOnError = false
			i++
		case "--quiet":
			opts.Quiet = true
			i++
		case "--verbose":
			opts.Quiet = false
			i++
		case "-y", "--yes":
			yes = true
			i++
		case "--check":
			i++
		default:
			if strings.HasPrefix(a, "-") {
				fmt.Fprintf(os.Stderr, "batch run: unknown option %s\n", a)
				return 2
			}
			if scriptPath == "" {
				scriptPath = a
			}
			i++
		}
	}
	if scriptPath == "" {
		fmt.Fprintln(os.Stderr, "usage: winctl batch run <script.wctl> [OPTIONS]")
		return 2
	}
	sc, err := batch_parseScript(scriptPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "winctl batch: %v\n", err)
		return 2
	}
	if has(args, "--check") {
		sc.CheckOnly = true
	}
	batch_printPlan(sc, opts)
	if dryRun {
		fmt.Fprintln(os.Stderr, c(clrYellow, "[dry-run] nothing executed"))
		return 0
	}
	if !yes && !confirm("run this batch?") {
		return 1
	}
	batch_saveScriptCopy(scriptPath)
	idx := auditLog("batch", buildCmdLine(os.Args), 0)
	rec, code := batch_executeScript(sc, opts)
	rec.Code = code
	batch_saveOp(idx, rec)

	// --- v1.2: chunked result report, 20 lines per flush ---
	fmt.Println()
	ok, fail, skip := 0, 0, 0
	const batchReportChunk = 20
	chunk := make([]string, 0, batchReportChunk)

	flushChunk := func() {
		if len(chunk) == 0 {
			return
		}
		for _, l := range chunk {
			fmt.Println(l)
		}
		chunk = chunk[:0]
		// Give stderr a chance to drain so live progress stays readable.
		time.Sleep(2 * time.Millisecond)
	}

	for _, s := range rec.Steps {
		switch {
		case s.Skipped:
			skip++
			chunk = append(chunk, fmt.Sprintf("  %s [%3d] %-7s %s %s",
				c(clrGray, "skip"), s.Line, s.Module, s.Cmd,
				c(clrGray, "("+s.Error+")")))
		case s.ExitCode == 0:
			ok++
			chunk = append(chunk, fmt.Sprintf("  %s [%3d] %-7s %s %s",
				c(clrGreen, "ok  "), s.Line, s.Module, s.Cmd,
				c(clrGray, s.Elapsed)))
		default:
			fail++
			reason := s.Error
			if reason == "" {
				reason = fmt.Sprintf("exit %d", s.ExitCode)
			}
			chunk = append(chunk, fmt.Sprintf("  %s [%3d] %-7s %s %s %s",
				c(clrRed, "FAIL"), s.Line, s.Module, s.Cmd,
				c(clrGray, s.Elapsed), c(clrRed, reason)))
		}
		if len(chunk) >= batchReportChunk {
			flushChunk()
		}
	}
	flushChunk()

	fmt.Printf("\n%s %d ok, %d failed, %d skipped\n",
		c(clrBold+clrCyan, "Summary:"), ok, fail, skip)
	return code
}

func batch_cmdShow(args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "usage: winctl batch show <script.wctl>")
		return 2
	}
	sc, err := batch_parseScript(args[0])
	if err != nil {
		fmt.Fprintf(os.Stderr, "winctl batch: %v\n", err)
		return 2
	}
	batch_printPlan(sc, batch_defaultOptions())
	return 0
}

func batch_cmdCheck(args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "usage: winctl batch check <script.wctl>")
		return 2
	}
	sc, err := batch_parseScript(args[0])
	if err != nil {
		fmt.Fprintf(os.Stderr, "winctl batch: %v\n", err)
		return 2
	}
	sc.CheckOnly = true
	mutating := 0
	for _, blk := range sc.Blocks {
		for _, ln := range blk.Lines {
			if !batch_readOnlyModules[ln.Module] {
				mutating++
				fmt.Fprintf(os.Stderr, "line %d: %s is a mutating module (rejected in check mode)\n",
					ln.LineNum, ln.Module)
			}
		}
	}
	if mutating > 0 {
		return 1
	}
	fmt.Printf("%s %s is valid and read-only (%d command(s))\n",
		c(clrGreen, "OK:"), args[0], batch_countLines(sc))
	return 0
}

func batch_cmdHistory() int {
	lines, err := auditReadLines()
	if err != nil {
		fmt.Fprintf(os.Stderr, "read log: %v\n", err)
		return 4
	}
	if len(lines) == 0 {
		fmt.Fprintln(os.Stderr, "log is empty")
		return 0
	}
	count := 0
	for i := len(lines) - 1; i >= 0; i-- {
		m, cmd, _, ok := auditParseLine(lines[i])
		if !ok || m != "batch" {
			continue
		}
		if isHistorySelf(cmd) || !moduleManifestExists("batch", i) {
			continue
		}
		count++
		desc := ""
		if rec, e := batch_loadOp(i); e == nil {
			okc, failc := 0, 0
			for _, s := range rec.Steps {
				if s.Skipped {
					continue
				}
				if s.ExitCode == 0 {
					okc++
				} else {
					failc++
				}
			}
			desc = fmt.Sprintf("-> %d ok, %d failed", okc, failc)
		}
		fmt.Printf("[%d] %s %s\n", count, lines[i], c(clrGray, desc))
	}
	if count == 0 {
		fmt.Fprintln(os.Stderr, "no rollback-able batch operations in log")
	}
	return 0
}

func batch_cmdRollback(args []string) int {
	n := 1
	for i := 0; i < len(args); i++ {
		if args[i] == "-n" || args[i] == "--last" {
			if i+1 >= len(args) {
				return 2
			}
			v, err := strconv.Atoi(args[i+1])
			if err != nil || v <= 0 {
				return 2
			}
			n = v
			i++
		} else if strings.HasPrefix(args[i], "-") {
			return 2
		}
	}
	idxs, err := moduleTailOps("batch", n)
	if err != nil || len(idxs) == 0 {
		fmt.Fprintln(os.Stderr, "no rollback-able batch operations found")
		return 4
	}
	if dryRun {
		for k, i := range idxs {
			if rec, e := batch_loadOp(i); e == nil {
				fmt.Printf("[dry-run] step %d: batch %s (%d command(s))\n",
					k+1, rec.Script, len(rec.Steps))
			}
		}
		return 0
	}
	exe, _ := os.Executable()
	if exe == "" {
		exe = "winctl.exe"
	}
	okCount, failCount := 0, 0
	for k, i := range idxs {
		rec, err := batch_loadOp(i)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[rollback] batch %d: %v\n", k+1, err)
			failCount++
			continue
		}
		fmt.Fprintf(os.Stderr, "[rollback] batch %d: %s (%d step(s))\n", k+1, rec.Script, len(rec.Steps))
		for si := len(rec.Steps) - 1; si >= 0; si-- {
			s := rec.Steps[si]
			if s.Skipped || s.ExitCode != 0 || !batch_rollbackableModules[s.Module] {
				continue
			}
			fmt.Fprintf(os.Stderr, "  step %d/%d: %s --rollback -n 1\n", si+1, len(rec.Steps), s.Module)
			cmd := exec.Command(exe, s.Module, "--rollback", "-n", "1")
			cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
			cmd.Stdout = os.Stderr
			cmd.Stderr = os.Stderr
			if err := cmd.Run(); err != nil {
				fmt.Fprintf(os.Stderr, "  step %d/%d: rollback failed: %v\n", si+1, len(rec.Steps), err)
				failCount++
				continue
			}
			okCount++
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

func batch_printHelp() {
	fmt.Printf("%s v%s (Windows)\n\n", c(clrBold+clrCyan, "winctl batch"), Version)
	fmt.Print(`USAGE
  winctl batch run <script.wctl> [OPTIONS]
  winctl batch show <script.wctl>
  winctl batch check <script.wctl>
  winctl batch --history
  winctl batch --rollback [-n N]

RUN OPTIONS
  --parallel N          max concurrent jobs in !parallel blocks (1..64, default 4)
  --timeout D           per-command timeout (default 120s)
  --out-dir DIR         prepend DIR to every relative -o / --out path
  --stop-on-error       stop on first failure (default)
  --continue-on-error   keep going on failure
  --quiet               suppress child stdout, keep a short summary
  --verbose             show child stdout (default)
  -y, --yes             skip the confirmation prompt
  --check               reject any command from a mutating module

SCRIPT SYNTAX
  # comment
  !set NAME=VALUE
  !dry-run | !no-dry-run
  !stop-on-error | !continue-on-error
  !quiet | !verbose
  !timeout 120s
  !parallel N
    <module> [args...]
  !end
  !check
  <module> [args...]

MODULES
  net open pe proc reg svc sys task acl bkp disk doc evt fs hash batch box

LIVE OUTPUT (v1.2)
  Each block's start is printed to stderr, and the per-step summary is
  flushed in 20-line chunks, so very long scripts do not dump everything
  at once.

ROLLBACK
  For each recorded step whose module supports manifest rollback
  (net reg svc task acl bkp fs box), batch --rollback runs:
      winctl <module> --rollback -n 1
  Read-only modules and proc/sys are skipped. The rollback assumes the
  batch run is exclusive (no other winctl operations in between).

GLOBAL
  -o, --out <path>      write stdout to a file
  --dry-run             print the plan without running any child
  --no-color            disable colors
  -b, --bugs            print collected errors/warnings
  -h, --help            show this help
  --version             show version

All logs go to ./backup/winctl_logs.log
All backups go to ./backup/batch/{ops,scripts}/
`)
}

func batch_main() {
	args, outPath, err := consumeGlobalFlags(os.Args[1:])
	if err != nil {
		fmt.Fprintf(os.Stderr, "winctl batch: %v\n", err)
		finalExit(2)
	}
	initColor()
	if has(args, "--version") {
		fmt.Printf("winctl batch v%s\n", Version)
		finalExit(0)
	}
	if len(args) == 0 || has(args, "-h", "--help") {
		batch_printHelp()
		finalExit(0)
	}
	if has(args, "--history") {
		code := batch_cmdHistory()
		auditLog("batch", buildCmdLine(os.Args), code)
		finalExit(code)
	}
	if has(args, "--rollback") {
		code := batch_cmdRollback(stripFlags(args, "--rollback"))
		auditLog("batch", buildCmdLine(os.Args), code)
		finalExit(code)
	}
	if outPath != "" {
		if err := setupOutput(outPath); err != nil {
			fmt.Fprintf(os.Stderr, "winctl batch: %v\n", err)
			finalExit(2)
		}
	}
	cmd := args[0]
	rest := args[1:]
	var code int
	switch cmd {
	case "run":
		code = batch_cmdRun(rest)
		// batch_cmdRun already wrote the audit line with its own idx
	case "show":
		code = batch_cmdShow(rest)
	case "check":
		code = batch_cmdCheck(rest)
	default:
		fmt.Fprintf(os.Stderr, "winctl batch: unknown command %q\n", cmd)
		code = 2
	}
	finalExit(code)
}

// ============================================================================
// box — container-like runner (job + volumes + probes)
// ============================================================================
//
// Box reuses proc's Job Object plumbing for resource limits, and adds:
//   * junction-point volume mounts (IO_REPARSE_TAG_MOUNT_POINT, no elevation)
//   * read-only volumes via icacls deny-write (saved and restored)
//   * user-mode health / readiness probes (exec / tcp / http)
//   * restart policies (no | on-failure | always | unless-stopped)
//   * named volumes under %LOCALAPPDATA%\winctl\box\volumes\
//   * snapshots via bkp's tar.gz helpers
//
// It deliberately does NOT provide namespaces, overlayfs, or network
// isolation: this is a Job Object wrapper, not a container runtime.
//
// Layout:
//   ./backup/winctl_logs.log                 shared audit log
//   ./backup/box/ops/<auditIdx>.json         per-instance manifest
//   ./backup/box/volumes/<name>/<ts>.tar.gz  volume snapshots
//   %LOCALAPPDATA%\winctl\box\<name>\        state.json, logs, private root

const box_stateVersion = "1.2.0"

// ---------------------------------------------------------------------------
// Data model
// ---------------------------------------------------------------------------

type box_Probe struct {
	Kind string `json:"kind"` // exec | tcp | http
	Arg  string `json:"arg"`
}

type box_Volume struct {
	Source   string `json:"source"`
	Dest     string `json:"dest"`
	Mode     string `json:"mode"` // ro | rw
	IsNamed  bool   `json:"isNamed,omitempty"`
	Junction string `json:"junction,omitempty"`
}

type box_Restart struct {
	At     time.Time `json:"at"`
	Reason string    `json:"reason"`
}

type box_RunSpec struct {
	Name     string   `json:"name"`
	CmdLine  string   `json:"cmdLine"`
	CmdArgs  []string `json:"cmdArgs"`
	Cwd      string   `json:"cwd,omitempty"`
	Env      []string `json:"env,omitempty"`
	Title    string   `json:"title,omitempty"`
	Priority uint32   `json:"priority,omitempty"`
	NoWindow bool     `json:"noWindow,omitempty"`
	Detach   bool     `json:"detach,omitempty"`
	JsonOut  bool     `json:"jsonOut,omitempty"`

	Limits proc_ResourceLimits `json:"limits"`

	Volumes        []box_Volume `json:"volumes,omitempty"`
	VolumeRoot     string       `json:"volumeRoot,omitempty"`
	SnapshotOnStop bool         `json:"snapshotOnStop,omitempty"`
	BackupOnStart  bool         `json:"backupOnStart,omitempty"`

	HealthProbe       *box_Probe    `json:"healthProbe,omitempty"`
	ReadyProbe        *box_Probe    `json:"readyProbe,omitempty"`
	HealthInterval    time.Duration `json:"healthInterval,omitempty"`
	HealthTimeout     time.Duration `json:"healthTimeout,omitempty"`
	HealthRetries     int           `json:"healthRetries,omitempty"`
	HealthStartPeriod time.Duration `json:"healthStartPeriod,omitempty"`

	RestartPolicy     string        `json:"restartPolicy,omitempty"`
	RestartMax        int           `json:"restartMax,omitempty"`
	RestartBackoff    time.Duration `json:"restartBackoff,omitempty"`
	RestartBackoffMax time.Duration `json:"restartBackoffMax,omitempty"`
}

type box_InstanceState struct {
	Name      string        `json:"name"`
	Status    string        `json:"status"` // running | stopped | exiting | exited
	Pid       uint32        `json:"pid"`
	Created   time.Time     `json:"created"`
	Updated   time.Time     `json:"updated"`
	ExitedAt  *time.Time    `json:"exitedAt,omitempty"`
	ExitCode  *int          `json:"exitCode,omitempty"`
	Spec      *box_RunSpec  `json:"spec"`
	LogPath   string        `json:"logPath"`
	Junctions []string      `json:"junctions,omitempty"`
	Restarts  []box_Restart `json:"restarts,omitempty"`
	Snapshots []string      `json:"snapshots,omitempty"`
}

type box_volSetup struct {
	Volume   *box_Volume
	Junction string
	HostPath string
	ROBak    string // icacls /save file, empty if not ro
}

// ---------------------------------------------------------------------------
// State paths
// ---------------------------------------------------------------------------

func box_localAppData() string {
	if v := os.Getenv("LOCALAPPDATA"); v != "" {
		return v
	}
	if v := os.Getenv("TEMP"); v != "" {
		return v
	}
	return os.TempDir()
}

func box_stateRoot() string        { return filepath.Join(box_localAppData(), "winctl", "box") }
func box_stateDir(name string) string { return filepath.Join(box_stateRoot(), name) }
func box_statePath(name string) string {
	return filepath.Join(box_stateDir(name), "state.json")
}
func box_logPath(name string) string       { return filepath.Join(box_stateDir(name), "box.log") }
func box_privateRoot(name string) string   { return filepath.Join(box_stateDir(name), "root") }
func box_namedVolumePath(name string) string {
	return filepath.Join(box_stateRoot(), "volumes", name)
}

// ---------------------------------------------------------------------------
// State persistence
// ---------------------------------------------------------------------------

func box_loadState(name string) (*box_InstanceState, error) {
	data, err := os.ReadFile(box_statePath(name))
	if err != nil {
		return nil, err
	}
	var st box_InstanceState
	if err := json.Unmarshal(data, &st); err != nil {
		return nil, fmt.Errorf("parse state.json: %w", err)
	}
	return &st, nil
}

func box_saveState(st *box_InstanceState) error {
	if err := os.MkdirAll(box_stateDir(st.Name), 0755); err != nil {
		return err
	}
	st.Updated = time.Now()
	data, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	tmp := box_statePath(st.Name) + ".tmp"
	if err := os.WriteFile(tmp, data, 0644); err != nil {
		return err
	}
	return os.Rename(tmp, box_statePath(st.Name))
}

func box_listStates() ([]*box_InstanceState, error) {
	entries, err := os.ReadDir(box_stateRoot())
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var out []*box_InstanceState
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		if e.Name() == "volumes" {
			continue
		}
		st, err := box_loadState(e.Name())
		if err != nil {
			continue
		}
		out = append(out, st)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

func box_deleteStateDir(name string) error { return os.RemoveAll(box_stateDir(name)) }

// ---------------------------------------------------------------------------
// Volume parsing:  --volume <src>:<dst>[:ro|rw]
//
// Drive letters contain ':', so we skip a leading "X:" when locating the
// separator. A bare source with no path separator becomes a named volume.
// ---------------------------------------------------------------------------

func box_isDriveLetter(s string, i int) bool {
	if i+1 >= len(s) || s[i+1] != ':' {
		return false
	}
	c := s[i]
	return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')
}

func box_parseVolumeFlag(s string) (*box_Volume, error) {
	start := 0
	if box_isDriveLetter(s, 0) {
		start = 2
	}
	idx := strings.IndexByte(s[start:], ':')
	if idx < 0 {
		return nil, fmt.Errorf("volume %q: expected <src>:<dst>", s)
	}
	idx += start
	src := s[:idx]
	rest := s[idx+1:]

	mode := "rw"
	if strings.HasSuffix(rest, ":ro") {
		mode = "ro"
		rest = rest[:len(rest)-3]
	} else if strings.HasSuffix(rest, ":rw") {
		mode = "rw"
		rest = rest[:len(rest)-3]
	}
	dst := rest
	if src == "" || dst == "" {
		return nil, fmt.Errorf("volume %q: empty source or destination", s)
	}
	v := &box_Volume{Source: src, Dest: dst, Mode: mode}
	if !strings.ContainsAny(src, `/\`) && !strings.Contains(src, ":") {
		v.IsNamed = true
	}
	return v, nil
}

// ---------------------------------------------------------------------------
// Junctions (mklink /J does not require elevation; rmdir does not follow)
// ---------------------------------------------------------------------------

func box_createJunction(link, target string) error {
	if _, err := os.Lstat(link); err == nil {
		actual, eerr := filepath.EvalSymlinks(link)
		if eerr == nil && strings.EqualFold(actual, target) {
			return nil
		}
		return fmt.Errorf("junction path %s already exists", link)
	}
	if err := os.MkdirAll(filepath.Dir(link), 0755); err != nil {
		return err
	}
	if err := os.MkdirAll(target, 0755); err != nil {
		return err
	}
	cmd := exec.Command("cmd", "/c", "mklink", "/J", link, target)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	var buf bytes.Buffer
	cmd.Stdout = &buf
	cmd.Stderr = &buf
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("mklink /J %s -> %s: %s", link, target, strings.TrimSpace(buf.String()))
	}
	return nil
}

func box_removeJunction(link string) error {
	if _, err := os.Lstat(link); err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	cmd := exec.Command("cmd", "/c", "rmdir", link)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	var buf bytes.Buffer
	cmd.Stdout = &buf
	cmd.Stderr = &buf
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("rmdir %s: %s", link, strings.TrimSpace(buf.String()))
	}
	return nil
}

// ---------------------------------------------------------------------------
// Read-only volumes via icacls deny-write, restored on teardown
// ---------------------------------------------------------------------------

func box_setRO(hostPath string) (string, error) {
	bak, err := os.CreateTemp("", "winctl_box_acl_*.txt")
	if err != nil {
		return "", err
	}
	bakPath := bak.Name()
	bak.Close()

	save := exec.Command("icacls", hostPath, "/save", bakPath, "/t", "/c", "/q")
	save.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	var buf bytes.Buffer
	save.Stdout = &buf
	save.Stderr = &buf
	if err := save.Run(); err != nil {
		os.Remove(bakPath)
		return "", fmt.Errorf("icacls /save %s: %s", hostPath, strings.TrimSpace(buf.String()))
	}

	deny := exec.Command("icacls", hostPath, "/deny", "*S-1-1-0:(OI)(CI)(W)", "/t", "/c", "/q")
	deny.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	buf.Reset()
	deny.Stdout = &buf
	deny.Stderr = &buf
	if err := deny.Run(); err != nil {
		os.Remove(bakPath)
		return "", fmt.Errorf("icacls /deny %s: %s", hostPath, strings.TrimSpace(buf.String()))
	}
	return bakPath, nil
}

func box_restoreACL(hostPath, bakPath string) error {
	if bakPath == "" {
		return nil
	}
	cmd := exec.Command("icacls", hostPath, "/restore", bakPath, "/t", "/c", "/q")
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	var buf bytes.Buffer
	cmd.Stdout = &buf
	cmd.Stderr = &buf
	err := cmd.Run()
	os.Remove(bakPath)
	if err != nil {
		return fmt.Errorf("icacls /restore %s: %s", hostPath, strings.TrimSpace(buf.String()))
	}
	return nil
}

// ---------------------------------------------------------------------------
// Volume setup / teardown
// ---------------------------------------------------------------------------

func box_setupVolumes(spec *box_RunSpec) ([]*box_volSetup, error) {
	var created []*box_volSetup
	teardown := func() {
		for i := len(created) - 1; i >= 0; i-- {
			v := created[i]
			if v.ROBak != "" {
				_ = box_restoreACL(v.HostPath, v.ROBak)
			}
			if v.Junction != "" {
				_ = box_removeJunction(v.Junction)
			}
		}
	}
	for i := range spec.Volumes {
		v := &spec.Volumes[i]
		hostPath := v.Source
		if v.IsNamed {
			hostPath = box_namedVolumePath(v.Source)
			if err := os.MkdirAll(hostPath, 0755); err != nil {
				teardown()
				return nil, fmt.Errorf("named volume %s: %w", v.Source, err)
			}
		} else {
			if _, err := os.Stat(hostPath); err != nil {
				teardown()
				return nil, fmt.Errorf("volume source %s: %w", hostPath, err)
			}
		}
		dst := v.Dest
		if !filepath.IsAbs(dst) {
			dst = filepath.Join(spec.VolumeRoot, dst)
		}
		if err := box_createJunction(dst, hostPath); err != nil {
			teardown()
			return nil, err
		}
		setup := &box_volSetup{Volume: v, Junction: dst, HostPath: hostPath}
		if v.Mode == "ro" {
			bak, err := box_setRO(hostPath)
			if err != nil {
				fmt.Fprintf(os.Stderr, "box: warning: ro on %s not enforced: %v\n", hostPath, err)
			} else {
				setup.ROBak = bak
			}
		}
		created = append(created, setup)
	}
	return created, nil
}

func box_teardownVolumes(setups []*box_volSetup) {
	for i := len(setups) - 1; i >= 0; i-- {
		v := setups[i]
		if v.ROBak != "" {
			_ = box_restoreACL(v.HostPath, v.ROBak)
		}
		if v.Junction != "" {
			_ = box_removeJunction(v.Junction)
		}
	}
}

// ---------------------------------------------------------------------------
// Probes
// ---------------------------------------------------------------------------

func box_runProbe(ctx context.Context, p *box_Probe, timeout time.Duration) error {
	cctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	switch p.Kind {
	case "exec":
		cmd := exec.CommandContext(cctx, "cmd", "/c", p.Arg)
		cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
		return cmd.Run()
	case "tcp":
		port, err := strconv.Atoi(p.Arg)
		if err != nil {
			return fmt.Errorf("bad tcp port %q", p.Arg)
		}
		var d net.Dialer
		conn, err := d.DialContext(cctx, "tcp", fmt.Sprintf("127.0.0.1:%d", port))
		if err != nil {
			return err
		}
		conn.Close()
		return nil
	case "http":
		req, err := http.NewRequestWithContext(cctx, http.MethodGet, p.Arg, nil)
		if err != nil {
			return err
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		if resp.StatusCode >= 200 && resp.StatusCode < 400 {
			return nil
		}
		return fmt.Errorf("http status %d", resp.StatusCode)
	}
	return fmt.Errorf("unknown probe kind %q", p.Kind)
}

func box_probeLoop(
	ctx context.Context,
	job *proc_jobHandle,
	probe *box_Probe,
	interval, timeout, startPeriod time.Duration,
	retries int,
) error {
	if interval <= 0 {
		interval = 10 * time.Second
	}
	if timeout <= 0 {
		timeout = 3 * time.Second
	}
	if retries <= 0 {
		retries = 3
	}
	if startPeriod > 0 {
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(startPeriod):
		}
	}
	consecutiveFailures := 0
	tick := time.NewTicker(interval)
	defer tick.Stop()
	for {
		err := box_runProbe(ctx, probe, timeout)
		if err == nil {
			consecutiveFailures = 0
		} else {
			consecutiveFailures++
			fmt.Fprintf(os.Stderr, "box: probe %s=%s failed (%d/%d): %v\n",
				probe.Kind, probe.Arg, consecutiveFailures, retries, err)
			if consecutiveFailures >= retries {
				if job != nil {
					proc_pTerminateJobObject.Call(uintptr(job.h), 1)
				}
				return fmt.Errorf("probe %s failed %d times: %w", probe.Kind, retries, err)
			}
		}
		select {
		case <-ctx.Done():
			return nil
		case <-tick.C:
		}
	}
}

// ---------------------------------------------------------------------------
// Command line building
// ---------------------------------------------------------------------------

func box_buildCmdLine(args []string) string {
	parts := make([]string, len(args))
	for i, a := range args {
		parts[i] = syscall.EscapeArg(a)
	}
	return strings.Join(parts, " ")
}

func box_buildEnvBlock(extra []string) []uint16 {
	env := os.Environ()
	env = append(env, extra...)
	var buf []uint16
	for _, s := range env {
		u := utf16Encode(s)
		buf = append(buf, u...)
		buf = append(buf, 0)
	}
	if len(buf) == 0 {
		buf = append(buf, 0)
	} else {
		buf = append(buf, 0)
	}
	return buf
}

// ---------------------------------------------------------------------------
// Spawn + supervise
// ---------------------------------------------------------------------------

func box_spawnOnce(spec *box_RunSpec, job *proc_jobHandle, logFile *os.File) (int, error) {
	var si proc_STARTUPINFOW
	si.Cb = uint32(unsafe.Sizeof(si))
	var titlePtr, cwdPtr *uint16
	if spec.Title != "" {
		titlePtr, _ = syscall.UTF16PtrFromString(spec.Title)
		si.Title = titlePtr
	}
	if spec.Cwd != "" {
		cwdPtr, _ = syscall.UTF16PtrFromString(spec.Cwd)
	}

	var envBlock []uint16
	if len(spec.Env) > 0 {
		envBlock = box_buildEnvBlock(spec.Env)
	}
	var envPtr uintptr
	if len(envBlock) > 0 {
		envPtr = uintptr(unsafe.Pointer(&envBlock[0]))
	}

	cmdLine := box_buildCmdLine(spec.CmdArgs)
	cmdUTF16, err := syscall.UTF16FromString(cmdLine)
	if err != nil || len(cmdUTF16) == 0 {
		return 5, fmt.Errorf("invalid command line")
	}

	flags := uint32(proc_CREATE_SUSPENDED | proc_CREATE_NEW_CONSOLE)
	if spec.NoWindow {
		flags = proc_CREATE_SUSPENDED | proc_CREATE_NO_WINDOW
	}

	var pi proc_PROCESS_INFORMATION
	r, _, callErr := proc_pCreateProcessW.Call(
		0,
		uintptr(unsafe.Pointer(&cmdUTF16[0])),
		0, 0, 0,
		uintptr(flags),
		envPtr,
		uintptr(unsafe.Pointer(cwdPtr)),
		uintptr(unsafe.Pointer(&si)),
		uintptr(unsafe.Pointer(&pi)),
	)
	if r == 0 {
		return 5, fmt.Errorf("CreateProcess: %w", callErr)
	}
	defer pCloseHandle.Call(uintptr(pi.Thread))
	defer pCloseHandle.Call(uintptr(pi.Process))

	if spec.Priority != 0 {
		proc_pSetPriorityClass.Call(uintptr(pi.Process), uintptr(spec.Priority))
	}
	if err := job.assign(pi.Process); err != nil {
		proc_pTerminateProcess.Call(uintptr(pi.Process), 1)
		return 5, err
	}
	if err := job.setLimits(&spec.Limits, true); err != nil {
		proc_pTerminateProcess.Call(uintptr(pi.Process), 1)
		return 5, err
	}

	probeCtx, probeCancel := context.WithCancel(context.Background())
	defer probeCancel()
	probeErrCh := make(chan error, 1)

	if spec.HealthProbe != nil {
		go func() {
			err := box_probeLoop(probeCtx, job, spec.HealthProbe,
				spec.HealthInterval, spec.HealthTimeout,
				spec.HealthStartPeriod, spec.HealthRetries)
			if err != nil {
				probeErrCh <- err
			}
		}()
	}

	proc_pResumeThread.Call(uintptr(pi.Thread))

	if logFile != nil {
		fmt.Fprintf(logFile, "box: spawned %s as pid %d\n", cmdLine, pi.ProcessID)
	}

	waitCh := make(chan struct{})
	var exitCode uint32
	go func() {
		proc_pWaitForSingleObject.Call(uintptr(pi.Process), proc_INFINITE)
		proc_pGetExitCodeProcess.Call(uintptr(pi.Process), uintptr(unsafe.Pointer(&exitCode)))
		close(waitCh)
	}()

	select {
	case <-waitCh:
		return int(exitCode), nil
	case err := <-probeErrCh:
		proc_pTerminateJobObject.Call(uintptr(job.h), 1)
		<-waitCh
		return 6, err
	}
}

func box_runOnce(spec *box_RunSpec) (int, error) {
	if spec.VolumeRoot == "" {
		spec.VolumeRoot = box_privateRoot(spec.Name)
	}
	if err := os.MkdirAll(spec.VolumeRoot, 0755); err != nil {
		return 5, fmt.Errorf("create volume root: %w", err)
	}

	setups, err := box_setupVolumes(spec)
	if err != nil {
		return 5, err
	}
	defer box_teardownVolumes(setups)

	job, err := proc_newJob()
	if err != nil {
		return 5, err
	}
	defer job.close()

	st := &box_InstanceState{
		Name:      spec.Name,
		Status:    "running",
		Created:   time.Now(),
		Spec:      spec,
		LogPath:   box_logPath(spec.Name),
		Junctions: make([]string, 0, len(setups)),
	}
	for _, s := range setups {
		st.Junctions = append(st.Junctions, s.Junction)
	}
	if err := box_saveState(st); err != nil {
		bugs.Add("WARN", "save state: %v", err)
	}

	logFile, _ := os.OpenFile(st.LogPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)

	code, err := box_spawnOnce(spec, job, logFile)

	if logFile != nil {
		fmt.Fprintf(logFile, "box: exited code=%d err=%v\n", code, err)
		logFile.Close()
	}

	now := time.Now()
	st.Status = "exited"
	st.ExitedAt = &now
	st.ExitCode = &code
	st.Pid = 0
	_ = box_saveState(st)

	return code, err
}

func box_runLoop(spec *box_RunSpec) (int, error) {
	backoff := spec.RestartBackoff
	if backoff == 0 {
		backoff = time.Second
	}
	maxBackoff := spec.RestartBackoffMax
	if maxBackoff == 0 {
		maxBackoff = 60 * time.Second
	}
	restarts := 0
	var lastCode int
	var lastErr error
	for {
		lastCode, lastErr = box_runOnce(spec)

		if spec.RestartPolicy == "" || spec.RestartPolicy == "no" {
			return lastCode, lastErr
		}
		if spec.RestartPolicy == "on-failure" && lastCode == 0 && lastErr == nil {
			return lastCode, lastErr
		}
		if st, err := box_loadState(spec.Name); err == nil && st.Status == "stopping" {
			return lastCode, lastErr
		}
		restarts++
		if spec.RestartMax > 0 && restarts >= spec.RestartMax {
			fmt.Fprintf(os.Stderr, "box: restart budget exhausted (%d)\n", restarts)
			return 7, fmt.Errorf("restart budget exhausted")
		}
		fmt.Fprintf(os.Stderr, "box: restart #%d in %s (reason: code=%d err=%v)\n",
			restarts, backoff, lastCode, lastErr)
		time.Sleep(backoff)
		backoff *= 2
		if backoff > maxBackoff {
			backoff = maxBackoff
		}
	}
}

// ---------------------------------------------------------------------------
// Argument parsing for "box run"
// ---------------------------------------------------------------------------

func box_parseRunArgs(args []string) (*box_RunSpec, error) {
	spec := &box_RunSpec{
		HealthInterval:    10 * time.Second,
		HealthTimeout:     3 * time.Second,
		HealthRetries:     3,
		RestartBackoff:    time.Second,
		RestartBackoffMax: 60 * time.Second,
		RestartPolicy:     "no",
	}
	i := 0
	var cmdParts []string
	for i < len(args) {
		if args[i] == "--" {
			cmdParts = args[i+1:]
			break
		}
		a := args[i]
		next := func() (string, error) {
			if i+1 >= len(args) {
				return "", fmt.Errorf("%s requires a value", a)
			}
			return args[i+1], nil
		}
		switch a {
		case "--name":
			v, err := next()
			if err != nil {
				return nil, err
			}
			spec.Name = v
			i += 2
		case "--cwd":
			v, err := next()
			if err != nil {
				return nil, err
			}
			spec.Cwd = v
			i += 2
		case "--env":
			v, err := next()
			if err != nil {
				return nil, err
			}
			spec.Env = append(spec.Env, v)
			i += 2
		case "--title":
			v, err := next()
			if err != nil {
				return nil, err
			}
			spec.Title = v
			i += 2
		case "--priority":
			v, err := next()
			if err != nil {
				return nil, err
			}
			pc := proc_priorityClass(v)
			if pc == 0 {
				return nil, fmt.Errorf("invalid priority %q", v)
			}
			spec.Priority = pc
			i += 2
		case "--no-window":
			spec.NoWindow = true
			i++
		case "--detach", "-d":
			spec.Detach = true
			i++
		case "--json":
			spec.JsonOut = true
			i++
		case "--volume":
			v, err := next()
			if err != nil {
				return nil, err
			}
			vol, err := box_parseVolumeFlag(v)
			if err != nil {
				return nil, err
			}
			spec.Volumes = append(spec.Volumes, *vol)
			i += 2
		case "--volume-snapshot":
			spec.SnapshotOnStop = true
			i++
		case "--volume-backup":
			spec.BackupOnStart = true
			i++
		case "--volume-root":
			v, err := next()
			if err != nil {
				return nil, err
			}
			spec.VolumeRoot = v
			i += 2
		case "--health-exec":
			v, err := next()
			if err != nil {
				return nil, err
			}
			spec.HealthProbe = &box_Probe{Kind: "exec", Arg: v}
			i += 2
		case "--health-tcp":
			v, err := next()
			if err != nil {
				return nil, err
			}
			spec.HealthProbe = &box_Probe{Kind: "tcp", Arg: v}
			i += 2
		case "--health-http":
			v, err := next()
			if err != nil {
				return nil, err
			}
			spec.HealthProbe = &box_Probe{Kind: "http", Arg: v}
			i += 2
		case "--health-interval":
			v, err := next()
			if err != nil {
				return nil, err
			}
			d, err := time.ParseDuration(v)
			if err != nil || d < time.Second {
				return nil, fmt.Errorf("health-interval: invalid %q", v)
			}
			spec.HealthInterval = d
			i += 2
		case "--health-timeout":
			v, err := next()
			if err != nil {
				return nil, err
			}
			d, err := time.ParseDuration(v)
			if err != nil || d <= 0 {
				return nil, fmt.Errorf("health-timeout: invalid %q", v)
			}
			spec.HealthTimeout = d
			i += 2
		case "--health-retries":
			v, err := next()
			if err != nil {
				return nil, err
			}
			n, err := strconv.Atoi(v)
			if err != nil || n < 1 {
				return nil, fmt.Errorf("health-retries: invalid %q", v)
			}
			spec.HealthRetries = n
			i += 2
		case "--health-start-period":
			v, err := next()
			if err != nil {
				return nil, err
			}
			d, err := time.ParseDuration(v)
			if err != nil {
				return nil, fmt.Errorf("health-start-period: invalid %q", v)
			}
			spec.HealthStartPeriod = d
			i += 2
		case "--readiness-exec":
			v, err := next()
			if err != nil {
				return nil, err
			}
			spec.ReadyProbe = &box_Probe{Kind: "exec", Arg: v}
			i += 2
		case "--readiness-tcp":
			v, err := next()
			if err != nil {
				return nil, err
			}
			spec.ReadyProbe = &box_Probe{Kind: "tcp", Arg: v}
			i += 2
		case "--readiness-http":
			v, err := next()
			if err != nil {
				return nil, err
			}
			spec.ReadyProbe = &box_Probe{Kind: "http", Arg: v}
			i += 2
		case "--restart":
			v, err := next()
			if err != nil {
				return nil, err
			}
			switch v {
			case "no", "on-failure", "always", "unless-stopped":
				spec.RestartPolicy = v
			default:
				return nil, fmt.Errorf("restart: invalid %q", v)
			}
			i += 2
		case "--restart-max":
			v, err := next()
			if err != nil {
				return nil, err
			}
			n, err := strconv.Atoi(v)
			if err != nil || n < 0 {
				return nil, fmt.Errorf("restart-max: invalid %q", v)
			}
			spec.RestartMax = n
			i += 2
		case "--restart-backoff":
			v, err := next()
			if err != nil {
				return nil, err
			}
			d, err := time.ParseDuration(v)
			if err != nil || d <= 0 {
				return nil, fmt.Errorf("restart-backoff: invalid %q", v)
			}
			spec.RestartBackoff = d
			i += 2
		case "--restart-backoff-max":
			v, err := next()
			if err != nil {
				return nil, err
			}
			d, err := time.ParseDuration(v)
			if err != nil || d <= 0 {
				return nil, fmt.Errorf("restart-backoff-max: invalid %q", v)
			}
			spec.RestartBackoffMax = d
			i += 2
		default:
			if consumed, ok := proc_consumeLimitOption(args, i, &spec.Limits); ok {
				i += consumed
				continue
			}
			return nil, fmt.Errorf("unknown option %s", a)
		}
	}
	if len(cmdParts) == 0 {
		return nil, fmt.Errorf("no command given (use -- <cmd> [args...])")
	}
	spec.CmdArgs = cmdParts
	spec.CmdLine = box_buildCmdLine(cmdParts)
	if spec.Name == "" {
		base := filepath.Base(cmdParts[0])
		if base == "" || base == "." {
			base = "box"
		}
		spec.Name = fmt.Sprintf("%s_%s", base, time.Now().Format("20060102_150405"))
	}
	if spec.Detach {
		return nil, fmt.Errorf("--detach is not implemented in v1.2 (use proc run --admin for background launches)")
	}
	if err := proc_validateLimits(&spec.Limits); err != nil {
		return nil, err
	}
	return spec, nil
}

// ---------------------------------------------------------------------------
// Audit records
// ---------------------------------------------------------------------------

type box_opRecord struct {
	Op        string       `json:"op"`
	TS        string       `json:"ts"`
	Cmd       string       `json:"cmd"`
	Name      string       `json:"name"`
	Code      int          `json:"code"`
	Spec      *box_RunSpec `json:"spec,omitempty"`
	Junctions []string     `json:"junctions,omitempty"`
	Snapshots []string     `json:"snapshots,omitempty"`
	Note      string       `json:"note,omitempty"`
}

func box_saveOp(idx int, rec *box_opRecord) {
	if err := moduleSaveManifest("box", idx, rec); err != nil {
		bugs.Add("ERR", "save op %d: %v", idx, err)
	}
}

func box_loadOp(idx int) (*box_opRecord, error) {
	var rec box_opRecord
	if err := moduleLoadManifest("box", idx, &rec); err != nil {
		return nil, err
	}
	return &rec, nil
}

// ---------------------------------------------------------------------------
// Snapshot helpers
// ---------------------------------------------------------------------------

func box_snapshotVolume(volName string) (string, error) {
	src := box_namedVolumePath(volName)
	if _, err := os.Stat(src); err != nil {
		return "", err
	}
	dir := filepath.Join(moduleRoot("box"), "volumes", volName)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return "", err
	}
	dst := filepath.Join(dir, time.Now().Format("20060102_150405")+".tar.gz")
	if err := bkp_tarGzDir(src, dst); err != nil {
		return "", err
	}
	return dst, nil
}

// ---------------------------------------------------------------------------
// Commands
// ---------------------------------------------------------------------------

func box_cmdRun(args []string) int {
	spec, err := box_parseRunArgs(args)
	if err != nil {
		fmt.Fprintf(os.Stderr, "box: %v\n", err)
		return 2
	}
	if dryRun {
		fmt.Printf("[dry-run] box %s: %s\n", spec.Name, spec.CmdLine)
		for _, v := range spec.Volumes {
			fmt.Printf("[dry-run]   volume %s:%s (%s)\n", v.Source, v.Dest, v.Mode)
		}
		if spec.HealthProbe != nil {
			fmt.Printf("[dry-run]   health=%s:%s interval=%s\n",
				spec.HealthProbe.Kind, spec.HealthProbe.Arg, spec.HealthInterval)
		}
		if spec.RestartPolicy != "no" {
			fmt.Printf("[dry-run]   restart=%s max=%d\n", spec.RestartPolicy, spec.RestartMax)
		}
		return 0
	}

	if spec.BackupOnStart {
		for _, v := range spec.Volumes {
			if !v.IsNamed {
				continue
			}
			if snap, err := box_snapshotVolume(v.Source); err == nil {
				fmt.Printf("box: initial snapshot of volume %s -> %s\n", v.Source, snap)
			}
		}
	}

	idx := auditLog("box", buildCmdLine(os.Args), 0)
	code, runErr := box_runLoop(spec)

	rec := &box_opRecord{
		Op:   "run",
		TS:   time.Now().Format("2006-01-02 15:04:05"),
		Cmd:  buildCmdLine(os.Args),
		Name: spec.Name,
		Code: code,
		Spec: spec,
	}
	if runErr != nil {
		rec.Note = runErr.Error()
	}
	if spec.SnapshotOnStop {
		for _, v := range spec.Volumes {
			if !v.IsNamed {
				continue
			}
			if snap, err := box_snapshotVolume(v.Source); err == nil {
				rec.Snapshots = append(rec.Snapshots, snap)
				fmt.Fprintf(os.Stderr, "box: volume snapshot %s -> %s\n", v.Source, snap)
			}
		}
	}
	box_saveOp(idx, rec)

	if spec.JsonOut {
		st, _ := box_loadState(spec.Name)
		if st != nil {
			data, _ := json.MarshalIndent(st, "", "  ")
			fmt.Println(string(data))
		}
	}
	if runErr != nil {
		fmt.Fprintf(os.Stderr, "box: %v\n", runErr)
	}
	return code
}

func box_cmdLs(args []string) int {
	all, jsonOut := false, false
	for _, a := range args {
		switch a {
		case "--all":
			all = true
		case "--json":
			jsonOut = true
		default:
			if strings.HasPrefix(a, "-") {
				fmt.Fprintf(os.Stderr, "box ls: unknown option %s\n", a)
				return 2
			}
		}
	}
	states, err := box_listStates()
	if err != nil {
		fmt.Fprintf(os.Stderr, "box ls: %v\n", err)
		return 5
	}
	if !all {
		var filtered []*box_InstanceState
		for _, s := range states {
			if s.Status == "running" || s.ExitedAt != nil && time.Since(*s.ExitedAt) < 24*time.Hour {
				filtered = append(filtered, s)
			}
		}
		states = filtered
	}
	if jsonOut {
		data, _ := json.MarshalIndent(states, "", "  ")
		fmt.Println(string(data))
		return 0
	}
	if len(states) == 0 {
		fmt.Fprintln(os.Stderr, "no box instances")
		return 0
	}
	nameW := len("NAME")
	statusW := len("STATUS")
	for _, s := range states {
		if w := dispWidth(s.Name); w > nameW {
			nameW = w
		}
		if w := dispWidth(s.Status); w > statusW {
			statusW = w
		}
	}
	fmt.Println(c(clrBold+clrCyan,
		padRight("NAME", nameW)+"  "+padRight("STATUS", statusW)+"  "+
			padRight("PID", 8)+"  CREATED"))
	for _, s := range states {
		statusColor := clrGray
		switch s.Status {
		case "running":
			statusColor = clrGreen
		case "exited":
			statusColor = clrYellow
		case "stopping":
			statusColor = clrRed
		}
		fmt.Println(
			padRight(s.Name, nameW) + "  " +
				c(statusColor, padRight(s.Status, statusW)) + "  " +
				padRight(strconv.FormatUint(uint64(s.Pid), 10), 8) + "  " +
				c(clrGray, s.Created.Format("2006-01-02 15:04:05")))
	}
	return 0
}

func box_cmdInspect(args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "usage: winctl box inspect <name> [--json]")
		return 2
	}
	name := args[0]
	jsonOut := has(args, "--json")
	st, err := box_loadState(name)
	if err != nil {
		fmt.Fprintf(os.Stderr, "box inspect: %v\n", err)
		return 4
	}
	if jsonOut {
		data, _ := json.MarshalIndent(st, "", "  ")
		fmt.Println(string(data))
		return 0
	}
	fmt.Printf("%s %s\n", c(clrCyan, "Name:    "), st.Name)
	fmt.Printf("%s %s\n", c(clrCyan, "Status:  "), st.Status)
	if st.Pid > 0 {
		fmt.Printf("%s %d\n", c(clrCyan, "PID:     "), st.Pid)
	}
	fmt.Printf("%s %s\n", c(clrCyan, "Created: "), st.Created.Format("2006-01-02 15:04:05"))
	if st.ExitedAt != nil {
		fmt.Printf("%s %s (code=%d)\n",
			c(clrCyan, "Exited:  "), st.ExitedAt.Format("2006-01-02 15:04:05"), *st.ExitCode)
	}
	fmt.Printf("%s %s\n", c(clrCyan, "Log:     "), st.LogPath)

	if st.Spec != nil {
		fmt.Println()
		fmt.Println(c(clrBold+clrCyan, "Command"))
		fmt.Printf("  %s\n", st.Spec.CmdLine)
		if st.Spec.Cwd != "" {
			fmt.Printf("  cwd: %s\n", st.Spec.Cwd)
		}
		if len(st.Spec.Env) > 0 {
			fmt.Printf("  env: %v\n", st.Spec.Env)
		}
		if len(st.Spec.Volumes) > 0 {
			fmt.Println()
			fmt.Println(c(clrBold+clrCyan, "Volumes"))
			for _, v := range st.Spec.Volumes {
				kind := "bind"
				if v.IsNamed {
					kind = "named"
				}
				fmt.Printf("  %-12s %s -> %s [%s]\n", kind, v.Source, v.Dest, v.Mode)
			}
		}
		if st.Spec.HealthProbe != nil {
			fmt.Println()
			fmt.Println(c(clrBold+clrCyan, "Health probe"))
			fmt.Printf("  %s: %s (interval=%s timeout=%s retries=%d)\n",
				st.Spec.HealthProbe.Kind, st.Spec.HealthProbe.Arg,
				st.Spec.HealthInterval, st.Spec.HealthTimeout, st.Spec.HealthRetries)
		}
		if st.Spec.RestartPolicy != "no" {
			fmt.Println()
			fmt.Println(c(clrBold+clrCyan, "Restart"))
			fmt.Printf("  policy=%s max=%d backoff=%s\n",
				st.Spec.RestartPolicy, st.Spec.RestartMax, st.Spec.RestartBackoff)
		}
	}
	if len(st.Restarts) > 0 {
		fmt.Println()
		fmt.Println(c(clrBold+clrCyan, "Restart history"))
		for _, r := range st.Restarts {
			fmt.Printf("  %s  %s\n", r.At.Format("2006-01-02 15:04:05"), r.Reason)
		}
	}
	if len(st.Snapshots) > 0 {
		fmt.Println()
		fmt.Println(c(clrBold+clrCyan, "Snapshots"))
		for _, s := range st.Snapshots {
			fmt.Printf("  %s\n", s)
		}
	}
	return 0
}

func box_cmdLogs(args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "usage: winctl box logs <name> [-f] [--tail N]")
		return 2
	}
	name := args[0]
	tail := 200
	follow := false
	for i := 1; i < len(args); i++ {
		switch args[i] {
		case "-f", "--follow":
			follow = true
		case "--tail":
			if i+1 >= len(args) {
				return 2
			}
			n, err := strconv.Atoi(args[i+1])
			if err != nil || n < 1 {
				return 2
			}
			tail = n
			i++
		}
	}
	st, err := box_loadState(name)
	if err != nil {
		fmt.Fprintf(os.Stderr, "box logs: %v\n", err)
		return 4
	}
	f, err := os.Open(st.LogPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "box logs: %v\n", err)
		return 5
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 64*1024), 4*1024*1024)
	ring := make([]string, tail)
	count := 0
	for scanner.Scan() {
		ring[count%tail] = scanner.Text()
		count++
	}
	start := 0
	if count > tail {
		start = count - tail
	}
	for i := 0; i < tail && start+i < count; i++ {
		fmt.Println(ring[(start+i)%tail])
	}
	if !follow {
		return 0
	}
	pos, _ := f.Seek(0, io.SeekEnd)
	for {
		time.Sleep(200 * time.Millisecond)
		st, _ := f.Stat()
		if st.Size() <= pos {
			continue
		}
		_, _ = f.Seek(pos, io.SeekStart)
		data, _ := io.ReadAll(f)
		os.Stdout.Write(data)
		pos = st.Size()
	}
}

func box_cmdExec(args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "usage: winctl box exec <name> -- <command> [args...]")
		return 2
	}
	name := args[0]
	rest := args[1:]
	dash := -1
	for i, a := range rest {
		if a == "--" {
			dash = i
			break
		}
	}
	if dash < 0 || dash+1 >= len(rest) {
		fmt.Fprintln(os.Stderr, "box exec: missing command after --")
		return 2
	}
	cmdArgs := rest[dash+1:]

	st, err := box_loadState(name)
	if err != nil {
		fmt.Fprintf(os.Stderr, "box exec: %v\n", err)
		return 4
	}
	if st.Status != "running" {
		fmt.Fprintf(os.Stderr, "box exec: instance is %s, not running\n", st.Status)
		return 4
	}

	job, err := proc_newJob()
	if err != nil {
		fmt.Fprintf(os.Stderr, "box exec: %v\n", err)
		return 5
	}
	defer job.close()

	cmdLine := box_buildCmdLine(cmdArgs)
	spec := &box_RunSpec{CmdArgs: cmdArgs, CmdLine: cmdLine}
	code, err := box_spawnOnce(spec, job, nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "box exec: %v\n", err)
	}
	return code
}

func box_cmdStop(args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "usage: winctl box stop <name> [-t SECONDS]")
		return 2
	}
	name := args[0]
	grace := 10 * time.Second
	for i := 1; i < len(args); i++ {
		if args[i] == "-t" && i+1 < len(args) {
			n, err := strconv.Atoi(args[i+1])
			if err != nil || n < 0 {
				return 2
			}
			grace = time.Duration(n) * time.Second
			i++
		}
	}
	st, err := box_loadState(name)
	if err != nil {
		fmt.Fprintf(os.Stderr, "box stop: %v\n", err)
		return 4
	}
	if st.Status != "running" {
		fmt.Fprintf(os.Stderr, "box stop: %s is %s\n", name, st.Status)
		return 1
	}

	st.Status = "stopping"
	_ = box_saveState(st)

	idx := auditLog("box", buildCmdLine(os.Args), 0)

	tk := exec.Command("taskkill", "/PID", strconv.FormatUint(uint64(st.Pid), 10), "/T")
	tk.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	_ = tk.Run()

	deadline := time.Now().Add(grace)
	for time.Now().Before(deadline) {
		h, _, _ := proc_pOpenProcess.Call(uintptr(proc_PROCESS_QUERY_LIMITED), 0, uintptr(st.Pid))
		if h == 0 {
			break
		}
		pCloseHandle.Call(h)
		time.Sleep(200 * time.Millisecond)
	}

	tkf := exec.Command("taskkill", "/PID",
		strconv.FormatUint(uint64(st.Pid), 10), "/T", "/F")
	tkf.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	_ = tkf.Run()

	now := time.Now()
	st.Status = "exited"
	st.ExitedAt = &now
	st.ExitCode = new(int)
	st.Pid = 0
	_ = box_saveState(st)

	box_saveOp(idx, &box_opRecord{
		Op:   "stop",
		TS:   time.Now().Format("2006-01-02 15:04:05"),
		Cmd:  buildCmdLine(os.Args),
		Name: name,
	})
	fmt.Printf("box: stopped %s\n", name)
	return 0
}

func box_cmdRm(args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "usage: winctl box rm <name> [-f] [--volumes]")
		return 2
	}
	name := args[0]
	force := has(args, "-f", "--force")
	removeVols := has(args, "--volumes")

	st, err := box_loadState(name)
	if err != nil {
		fmt.Fprintf(os.Stderr, "box rm: %v\n", err)
		return 4
	}
	if st.Status == "running" && !force {
		fmt.Fprintf(os.Stderr, "box rm: %s is running (use -f to stop first)\n", name)
		return 1
	}
	if st.Status == "running" && force {
		_ = box_cmdStop([]string{name})
	}
	idx := auditLog("box", buildCmdLine(os.Args), 0)
	if err := box_deleteStateDir(name); err != nil {
		fmt.Fprintf(os.Stderr, "box rm: %v\n", err)
		return 5
	}
	if removeVols && st.Spec != nil {
		for _, v := range st.Spec.Volumes {
			if !v.IsNamed {
				continue
			}
			_ = os.RemoveAll(box_namedVolumePath(v.Source))
		}
	}
	box_saveOp(idx, &box_opRecord{
		Op:   "rm",
		TS:   time.Now().Format("2006-01-02 15:04:05"),
		Cmd:  buildCmdLine(os.Args),
		Name: name,
	})
	fmt.Printf("box: removed %s\n", name)
	return 0
}

func box_cmdHistory() int {
	lines, err := auditReadLines()
	if err != nil {
		fmt.Fprintf(os.Stderr, "read log: %v\n", err)
		return 4
	}
	count := 0
	for i := len(lines) - 1; i >= 0; i-- {
		m, cmd, _, ok := auditParseLine(lines[i])
		if !ok || m != "box" {
			continue
		}
		if isHistorySelf(cmd) || !moduleManifestExists("box", i) {
			continue
		}
		count++
		desc := ""
		if rec, e := box_loadOp(i); e == nil {
			if rec.Op == "run" {
				desc = fmt.Sprintf("-> %d junction(s), %d snapshot(s)",
					len(rec.Junctions), len(rec.Snapshots))
			}
		}
		fmt.Printf("[%d] %s %s\n", count, lines[i], c(clrGray, desc))
	}
	if count == 0 {
		fmt.Fprintln(os.Stderr, "no box history entries")
	}
	return 0
}

func box_cmdRollback(args []string) int {
	n := 1
	for i := 0; i < len(args); i++ {
		if args[i] == "-n" || args[i] == "--last" {
			if i+1 >= len(args) {
				return 2
			}
			v, err := strconv.Atoi(args[i+1])
			if err != nil || v <= 0 {
				return 2
			}
			n = v
			i++
		}
	}
	idxs, err := moduleTailOps("box", n)
	if err != nil || len(idxs) == 0 {
		fmt.Fprintln(os.Stderr, "no rollback-able box operations")
		return 4
	}
	if dryRun {
		for k, i := range idxs {
			if rec, e := box_loadOp(i); e == nil {
				fmt.Printf("[dry-run] step %d: %s %s\n", k+1, rec.Op, rec.Name)
			}
		}
		return 0
	}
	okCount, failCount := 0, 0
	for k, i := range idxs {
		rec, err := box_loadOp(i)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[rollback] step %d: %v\n", k+1, err)
			failCount++
			continue
		}
		switch rec.Op {
		case "run":
			for _, j := range rec.Junctions {
				_ = box_removeJunction(j)
			}
			for _, s := range rec.Snapshots {
				fmt.Fprintf(os.Stderr, "[rollback] snapshot %s (manual restore)\n", s)
			}
			fmt.Fprintf(os.Stderr, "[rollback] step %d: %s cleaned\n", k+1, rec.Name)
			okCount++
		case "stop":
			okCount++
		case "rm":
			fmt.Fprintf(os.Stderr, "[rollback] step %d: rm has no inverse\n", k+1)
			failCount++
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

func box_printHelp() {
	fmt.Printf("%s v%s (Windows)\n\n", c(clrBold+clrCyan, "winctl box"), Version)
	fmt.Print(`USAGE
  winctl box run   [OPTIONS] -- <command> [args...]
  winctl box ls    [--all] [--json]
  winctl box inspect <name> [--json]
  winctl box logs  <name> [-f] [--tail N]
  winctl box exec  <name> -- <command> [args...]
  winctl box stop  <name> [-t SECONDS]
  winctl box rm    <name> [-f] [--volumes]
  winctl box --history
  winctl box --rollback [-n N]

RUN OPTIONS
  --name <name>              instance name (default: derived from exe + timestamp)
  --cwd <dir>                working directory for the child
  --env KEY=VALUE            extra environment variable (repeatable)
  --title <text>             console title for the child
  --priority <level>         idle|below-normal|normal|above-normal|high|realtime
  --no-window                create the child without a console window
  --json                     print the instance record as JSON on exit

RESOURCE LIMITS (Job Object, same as "winctl proc run")
  --cpu --mem --working-set --affinity --process-count
  --iops --io-write --io-read --net --net-out --net-in --timeout
  --on-exit kill|suspend|keep

VOLUME
  --volume <src>:<dst>[:ro|rw]     bind-mount a host path into the box (repeatable)
  --volume <name>:<dst>            use a named volume under %LOCALAPPDATA%\winctl\box\volumes\
  --volume-snapshot                snapshot every rw volume on stop
  --volume-backup                  create an initial backup before the first start
  --volume-root <dir>              override the private root

HEALTH
  --health-exec <cmd>        liveness probe: run a command, exit 0 = healthy
  --health-tcp <port>        liveness probe: TCP connect to 127.0.0.1:<port>
  --health-http <url>        liveness probe: GET <url>, 2xx/3xx = healthy
  --health-interval <dur>    probe interval (default 10s, min 1s)
  --health-timeout <dur>     per-probe timeout (default 3s)
  --health-retries <N>       consecutive failures before unhealthy (default 3)
  --health-start-period <dur>  grace period before probes count (default 0)
  --readiness-exec <cmd>     readiness probe (same forms)
  --readiness-tcp <port>
  --readiness-http <url>

RESTART
  --restart <policy>         no | on-failure | always | unless-stopped (default no)
  --restart-max <N>          max restarts before giving up (default 0 = unlimited)
  --restart-backoff <dur>    base backoff, doubles each restart (default 1s)
  --restart-backoff-max <dur>  backoff ceiling (default 60s)

GLOBAL
  -o, --out <path>           write stdout to a file
  --dry-run                  print the plan without creating any job or junction
  --no-color                 disable ANSI colors (also honors NO_COLOR)
  -b, --bugs                 print collected errors/warnings on exit
  -h, --help                 show this help
  --version                  show version

LAYOUT
  ./backup/winctl_logs.log                 shared audit log
  ./backup/box/ops/<auditIdx>.json         per-instance manifest
  ./backup/box/volumes/<name>/<ts>.tar.gz  volume snapshots
  %LOCALAPPDATA%\winctl\box\<name>\        state.json, logs, private root

LIMITATIONS
  No overlayfs, no PID namespace, no network namespace. Junction targets are
  global: two boxes mapping the same target will collide. IO read and net-in
  limits are accepted for symmetry but only warned about, because the Job
  Object API does not enforce them.

EXIT CODES
  0 success | 1 partial failure | 2 bad args | 3 not elevated
  4 not found | 5 I/O error | 6 probe failed past retries
  7 restart budget exhausted | 8 job limit rejected by validation

All logs go to ./backup/winctl_logs.log
`)
}

func box_main() {
	args, outPath, err := consumeGlobalFlags(os.Args[1:])
	if err != nil {
		fmt.Fprintf(os.Stderr, "winctl box: %v\n", err)
		finalExit(2)
	}
	initColor()
	if has(args, "--version") {
		fmt.Printf("winctl box v%s\n", Version)
		finalExit(0)
	}
	if len(args) == 0 || has(args, "-h", "--help") {
		box_printHelp()
		finalExit(0)
	}
	if has(args, "--history") {
		code := box_cmdHistory()
		auditLog("box", buildCmdLine(os.Args), code)
		finalExit(code)
	}
	if has(args, "--rollback") {
		code := box_cmdRollback(stripFlags(args, "--rollback"))
		auditLog("box", buildCmdLine(os.Args), code)
		finalExit(code)
	}
	if outPath != "" {
		if err := setupOutput(outPath); err != nil {
			fmt.Fprintf(os.Stderr, "winctl box: %v\n", err)
			finalExit(2)
		}
	}
	cmd := args[0]
	rest := args[1:]
	var code int
	switch cmd {
	case "run":
		code = box_cmdRun(rest)
	case "ls", "ps":
		code = box_cmdLs(rest)
	case "inspect":
		code = box_cmdInspect(rest)
	case "logs":
		code = box_cmdLogs(rest)
	case "exec":
		code = box_cmdExec(rest)
	case "stop":
		code = box_cmdStop(rest)
	case "rm":
		code = box_cmdRm(rest)
	default:
		fmt.Fprintf(os.Stderr, "winctl box: unknown command %q\n", cmd)
		code = 2
	}
	if !dryRun && shouldLogRun() {
		auditLog("box", buildCmdLine(os.Args), code)
	}
	finalExit(code)
}
