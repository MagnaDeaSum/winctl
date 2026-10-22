//go:build windows && amd64

package main

// backupctl — Unified backup and restore for files, registry keys, service
// configurations, and scheduled task XML. Single-file, standard-library-only:
//
//   go build -trimpath -ldflags "-s -w" -o backupctl.exe backupctl.go
//
// Layout (all relative to the executable directory):
//   ./backup<YYYYMMDD_HHMMSS>/        one directory per backup
//   ./backup_archived/<id>/           cleaned backups (moved here)
//   ./backup_archived/<id>.tar.gz     cleaned backups (large, tar+gzip)
//   ./backupctl_backup/backupctl.log  audit log
//   ./backupctl_backup/ops/<n>.json   per-operation manifests

import (
	"archive/tar"
	"bufio"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
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
	kernel32        = syscall.NewLazyDLL("kernel32.dll")
	pGetStdHandle   = kernel32.NewProc("GetStdHandle")
	pGetConsoleMode = kernel32.NewProc("GetConsoleMode")
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

func stdinIsTTY() bool  { return isConsole(STD_INPUT_HANDLE) }
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
		fmt.Fprintln(os.Stderr, "[backupctl] -b/--bugs enabled: no errors or warnings captured this run.")
		return
	}
	fmt.Fprintf(os.Stderr, "\n--- backupctl bugs report (%d entries) ---\n", len(b.entries))
	for _, e := range b.entries {
		fmt.Fprintf(os.Stderr, "[%s] %s %s\n", e.At.Format("15:04:05.000"), e.Level, e.Msg)
	}
	fmt.Fprintln(os.Stderr, "--- end of bugs report ---")
}

// ============================================================================
// Win32 / Advapi32 bindings
// ============================================================================

var (
	advapi32 = syscall.NewLazyDLL("advapi32.dll")

	pOpenSCManagerW       = advapi32.NewProc("OpenSCManagerW")
	pCloseServiceHandle   = advapi32.NewProc("CloseServiceHandle")
	pOpenServiceW         = advapi32.NewProc("OpenServiceW")
	pQueryServiceStatus   = advapi32.NewProc("QueryServiceStatus")
	pQueryServiceConfigW  = advapi32.NewProc("QueryServiceConfigW")
	pChangeServiceConfigW = advapi32.NewProc("ChangeServiceConfigW")
	pStartServiceW        = advapi32.NewProc("StartServiceW")
	pControlService       = advapi32.NewProc("ControlService")

	pRegOpenKeyExW = advapi32.NewProc("RegOpenKeyExW")
	pRegCloseKey   = advapi32.NewProc("RegCloseKey")
)

const (
	SC_MANAGER_ALL_ACCESS = 0xF003F
	SERVICE_ALL_ACCESS    = 0xF01FF
	SERVICE_QUERY_CONFIG  = 0x0001
	SERVICE_CHANGE_CONFIG = 0x0002
	SERVICE_QUERY_STATUS  = 0x0004
	SERVICE_NO_CHANGE     = 0xFFFFFFFF

	SERVICE_STOPPED          = 0x00000001
	SERVICE_START_PENDING    = 0x00000002
	SERVICE_STOP_PENDING     = 0x00000003
	SERVICE_RUNNING          = 0x00000004
	SERVICE_CONTINUE_PENDING = 0x00000005
	SERVICE_PAUSE_PENDING    = 0x00000006
	SERVICE_PAUSED           = 0x00000007

	SERVICE_CONTROL_STOP     = 0x00000001
	SERVICE_CONTROL_PAUSE    = 0x00000002
	SERVICE_CONTROL_CONTINUE = 0x00000003

	SERVICE_BOOT_START   = 0x00000000
	SERVICE_SYSTEM_START = 0x00000001
	SERVICE_AUTO_START   = 0x00000002
	SERVICE_DEMAND_START = 0x00000003
	SERVICE_DISABLED     = 0x00000004

	ERROR_SERVICE_ALREADY_RUNNING = syscall.Errno(1056)
	ERROR_SERVICE_NOT_ACTIVE      = syscall.Errno(1062)
	ERROR_SERVICE_DISABLED        = syscall.Errno(1058)
	ERROR_FILE_NOT_FOUND          = syscall.Errno(2)
	ERROR_ACCESS_DENIED           = syscall.Errno(5)

	KEY_READ        = 0x20019
	KEY_WOW64_64KEY = 0x0100
	KEY_WOW64_32KEY = 0x0200
)

// ============================================================================
// Paths
// ============================================================================

const (
	logDirName    = "backupctl_backup"
	logFileName   = "backupctl.log"
	opsDirName    = "ops"
	archivedName  = "backup_archived"
	backupPrefix  = "backup"
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

// logRoot is where the audit log lives.
func logRoot() string { return filepath.Join(exeDir(), logDirName) }
func logPath() string { return filepath.Join(logRoot(), logFileName) }
func opsDir() string  { return filepath.Join(logRoot(), opsDirName) }

// backupRoot is the parent directory of all backups. Each backup lives in
// a sibling directory under this root named "backup<timestamp>".
func backupRoot() string { return exeDir() }

// backupDir returns the absolute path of one backup by its id.
func backupDir(id string) string { return filepath.Join(backupRoot(), id) }

// archivedRoot holds backups that were cleaned.
func archivedRoot() string { return filepath.Join(exeDir(), archivedName) }

func countLogLines() int {
	f, err := os.Open(logPath())
	if err != nil {
		return 0
	}
	defer f.Close()
	var n int
	for {
		var line [1]byte
		_, err := f.Read(line[:])
		if err != nil {
			break
		}
		if line[0] == '\n' {
			n++
		}
	}
	return n
}

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
// Operation manifest
// ============================================================================

type opRecord struct {
	Op             string       `json:"op"`
	TS             string       `json:"ts"`
	Cmd            string       `json:"cmd"`
	Code           int          `json:"code"`
	BackupID       string       `json:"backupId,omitempty"`
	TargetBackupID string       `json:"targetBackupId,omitempty"`
	PreBackupID    string       `json:"preBackupId,omitempty"`
	CleanedBackups []string     `json:"cleanedBackups,omitempty"`
	ArchivedIDs    []string     `json:"archivedIds,omitempty"`
	Items          []BackupItem `json:"items,omitempty"`
}

func saveOpRecord(idx int, rec *opRecord) {
	_ = os.MkdirAll(opsDir(), 0755)
	p := filepath.Join(opsDir(), fmt.Sprintf("%d.json", idx))
	data, err := json.MarshalIndent(rec, "", "  ")
	if err != nil {
		bugs.Add("ERR", "marshal op: %v", err)
		return
	}
	if err := os.WriteFile(p, data, 0644); err != nil {
		bugs.Add("ERR", "write op %s: %v", p, err)
	}
}

func loadOpRecord(idx int) (*opRecord, error) {
	data, err := os.ReadFile(filepath.Join(opsDir(), fmt.Sprintf("%d.json", idx)))
	if err != nil {
		return nil, err
	}
	var rec opRecord
	if err := json.Unmarshal(data, &rec); err != nil {
		return nil, err
	}
	return &rec, nil
}

func manifestExists(idx int) bool {
	_, err := os.Stat(filepath.Join(opsDir(), fmt.Sprintf("%d.json", idx)))
	return err == nil
}

func beginWriteOp() int {
	_ = os.MkdirAll(logRoot(), 0755)
	_ = os.MkdirAll(opsDir(), 0755)
	return countLogLines()
}

// ============================================================================
// Backup types and manifest
// ============================================================================

type BackupItem struct {
	Kind       string `json:"kind"` // file | dir | registry | service | task
	Src        string `json:"src"`
	Stored     string `json:"stored"`
	Compressed bool   `json:"compressed,omitempty"`
}

type BackupManifest struct {
	ID      string       `json:"id"`
	Created time.Time    `json:"created"`
	Command string       `json:"command"`
	Items   []BackupItem `json:"items"`
}

// newBackupID returns a directory name of the form backupYYYYMMDD_HHMMSS,
// with a short random suffix if a directory with that name already exists.
func newBackupID() string {
	base := backupPrefix + time.Now().Format("20060102_150405")
	if _, err := os.Stat(filepath.Join(backupRoot(), base)); err == nil {
		base = fmt.Sprintf("%s_%04x", base, rand.Intn(0x10000))
	}
	return base
}

func writeManifest(dir string, m *BackupManifest) error {
	data, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, "manifest.json"), data, 0644)
}

func readManifest(dir string) (*BackupManifest, error) {
	data, err := os.ReadFile(filepath.Join(dir, "manifest.json"))
	if err != nil {
		return nil, err
	}
	var m BackupManifest
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, err
	}
	return &m, nil
}

func backupExists(id string) bool {
	_, err := os.Stat(filepath.Join(backupDir(id), "manifest.json"))
	return err == nil
}

// isBackupDirName reports whether name looks like a backup directory name
// that this tool would create (backupYYYYMMDD_HHMMSS or with _suffix).
func isBackupDirName(name string) bool {
	if !strings.HasPrefix(name, backupPrefix) {
		return false
	}
	if name == archivedName {
		return false
	}
	rest := strings.TrimPrefix(name, backupPrefix)
	// Expect at least YYYYMMDD_HHMMSS = 15 chars.
	return len(rest) >= 15 && rest[8] == '_'
}

// ============================================================================
// Compression helpers
// ============================================================================

const smallThreshold = 8192

func copyFile(src, dst string) error {
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

func gzipBytes(data []byte, dst string) error {
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

func gzipFileTo(src, dst string) error {
	data, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	return gzipBytes(data, dst)
}

func gunzipTo(src, dst string) error {
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

func tarGzDir(srcDir, dst string) error {
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
		defer f.Close()
		_, err = io.Copy(tw, f)
		return err
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

func untarGzTo(src, dstDir string) error {
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
			f, err := os.Create(dst)
			if err != nil {
				return err
			}
			if _, err := io.Copy(f, tr); err != nil {
				f.Close()
				return err
			}
			f.Close()
			if !hdr.ModTime.IsZero() {
				_ = os.Chtimes(dst, time.Now(), hdr.ModTime)
			}
		}
	}
	return nil
}

// ============================================================================
// Registry export / import
// ============================================================================

func regParsePath(s string) (root uintptr, rootStr, subKey string, err error) {
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
		root = 0xFFFFFFFF80000000
		rootStr = "HKEY_CLASSES_ROOT"
	case "HKCU", "HKEY_CURRENT_USER":
		root = 0xFFFFFFFF80000001
		rootStr = "HKEY_CURRENT_USER"
	case "HKLM", "HKEY_LOCAL_MACHINE":
		root = 0xFFFFFFFF80000002
		rootStr = "HKEY_LOCAL_MACHINE"
	case "HKU", "HKEY_USERS":
		root = 0xFFFFFFFF80000003
		rootStr = "HKEY_USERS"
	case "HKCC", "HKEY_CURRENT_CONFIG":
		root = 0xFFFFFFFF80000005
		rootStr = "HKEY_CURRENT_CONFIG"
	default:
		err = fmt.Errorf("unknown registry root %q", rootStr)
	}
	return
}

func exportRegKey(key string, dstPath string) error {
	cmd := exec.Command("reg", "export", key, dstPath, "/y")
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	var errBuf bytes.Buffer
	cmd.Stderr = &errBuf
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("reg export: %s", strings.TrimSpace(errBuf.String()))
	}
	return nil
}

func importRegFile(path string) error {
	cmd := exec.Command("reg", "import", path)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	var errBuf bytes.Buffer
	cmd.Stderr = &errBuf
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("reg import: %s", strings.TrimSpace(errBuf.String()))
	}
	return nil
}

// ============================================================================
// Service helpers
// ============================================================================

type svcSnapshot struct {
	Name        string `json:"name"`
	DisplayName string `json:"displayName"`
	StartType   uint32 `json:"startType"`
	State       uint32 `json:"state"`
	BinaryPath  string `json:"binaryPath"`
}

func openSCM() (syscall.Handle, error) {
	h, _, err := pOpenSCManagerW.Call(0, 0, SC_MANAGER_ALL_ACCESS)
	if h == 0 {
		return 0, fmt.Errorf("OpenSCManager: %w", err)
	}
	return syscall.Handle(h), nil
}

func openService(scm syscall.Handle, name string, access uint32) (syscall.Handle, error) {
	p, err := syscall.UTF16PtrFromString(name)
	if err != nil {
		return 0, err
	}
	h, _, callErr := pOpenServiceW.Call(uintptr(scm), uintptr(unsafe.Pointer(p)), uintptr(access))
	if h == 0 {
		return 0, fmt.Errorf("OpenService %q: %w", name, callErr)
	}
	return syscall.Handle(h), nil
}

func snapshotService(name string) (*svcSnapshot, error) {
	scm, err := openSCM()
	if err != nil {
		return nil, err
	}
	defer pCloseServiceHandle.Call(uintptr(scm))

	h, err := openService(scm, name, SERVICE_QUERY_CONFIG|SERVICE_QUERY_STATUS)
	if err != nil {
		return nil, err
	}
	defer pCloseServiceHandle.Call(uintptr(h))

	var st struct {
		ServiceType             uint32
		CurrentState            uint32
		ControlsAccepted        uint32
		Win32ExitCode           uint32
		ServiceSpecificExitCode uint32
		CheckPoint              uint32
		WaitHint                uint32
	}
	pQueryServiceStatus.Call(uintptr(h), uintptr(unsafe.Pointer(&st)))

	var needed uint32
	pQueryServiceConfigW.Call(uintptr(h), 0, 0, uintptr(unsafe.Pointer(&needed)))
	if needed == 0 {
		return nil, fmt.Errorf("QueryServiceConfig: cannot determine size")
	}
	buf := make([]byte, needed)
	pQueryServiceConfigW.Call(uintptr(h),
		uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)),
		uintptr(unsafe.Pointer(&needed)))

	type qsc struct {
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
	cfg := (*qsc)(unsafe.Pointer(&buf[0]))
	snap := &svcSnapshot{
		Name:      name,
		StartType: cfg.StartType,
		State:     st.CurrentState,
	}
	if cfg.BinaryPathName != nil {
		snap.BinaryPath = syscall.UTF16ToString(unsafe.Slice(cfg.BinaryPathName, 1024))
	}
	if cfg.DisplayName != nil {
		snap.DisplayName = syscall.UTF16ToString(unsafe.Slice(cfg.DisplayName, 512))
	}
	return snap, nil
}

func applyServiceSnapshot(snap *svcSnapshot) error {
	scm, err := openSCM()
	if err != nil {
		return err
	}
	defer pCloseServiceHandle.Call(uintptr(scm))

	h, err := openService(scm, snap.Name, SERVICE_ALL_ACCESS)
	if err != nil {
		return err
	}
	defer pCloseServiceHandle.Call(uintptr(h))

	r, _, callErr := pChangeServiceConfigW.Call(uintptr(h),
		uintptr(SERVICE_NO_CHANGE), uintptr(snap.StartType), uintptr(SERVICE_NO_CHANGE),
		0, 0, 0, 0, 0, 0, 0)
	if r == 0 {
		return fmt.Errorf("ChangeServiceConfig: %w", callErr)
	}

	var st struct {
		ServiceType             uint32
		CurrentState            uint32
		ControlsAccepted        uint32
		Win32ExitCode           uint32
		ServiceSpecificExitCode uint32
		CheckPoint              uint32
		WaitHint                uint32
	}
	pQueryServiceStatus.Call(uintptr(h), uintptr(unsafe.Pointer(&st)))

	switch snap.State {
	case SERVICE_RUNNING:
		if st.CurrentState != SERVICE_RUNNING {
			pStartServiceW.Call(uintptr(h), 0, 0)
		}
	case SERVICE_STOPPED:
		if st.CurrentState != SERVICE_STOPPED {
			pControlService.Call(uintptr(h), uintptr(SERVICE_CONTROL_STOP), uintptr(unsafe.Pointer(&st)))
		}
	case SERVICE_PAUSED:
		if st.CurrentState == SERVICE_RUNNING {
			pControlService.Call(uintptr(h), uintptr(SERVICE_CONTROL_PAUSE), uintptr(unsafe.Pointer(&st)))
		}
	}
	return nil
}

// ============================================================================
// Scheduled task helpers
// ============================================================================

func schtasksPath() string {
	return filepath.Join(os.Getenv("SystemRoot"), "System32", "schtasks.exe")
}

func exportTaskXML(name string) ([]byte, error) {
	cmd := exec.Command(schtasksPath(), "/query", "/tn", name, "/xml")
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	var errBuf bytes.Buffer
	cmd.Stderr = &errBuf
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("schtasks /query /xml: %s", strings.TrimSpace(errBuf.String()))
	}
	return out, nil
}

func importTaskXML(name string, xml []byte) error {
	tmp, err := os.CreateTemp("", "backupctl_task_*.xml")
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

	cmd := exec.Command(schtasksPath(), "/create", "/tn", name, "/xml", tmpPath, "/f")
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	var errBuf bytes.Buffer
	cmd.Stderr = &errBuf
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("schtasks /create: %s", strings.TrimSpace(errBuf.String()))
	}
	return nil
}

func listTaskNames() ([]string, error) {
	cmd := exec.Command(schtasksPath(), "/query", "/fo", "csv", "/nh")
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

func listServiceNames() ([]string, error) {
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

// ============================================================================
// Backup core
// ============================================================================

var sanitizeRe = regexp.MustCompile(`[^A-Za-z0-9._-]`)

func sanitize(s string) string {
	s = strings.ReplaceAll(s, `\`, "_")
	s = strings.ReplaceAll(s, `:`, "_")
	s = sanitizeRe.ReplaceAllString(s, "_")
	if len(s) > 80 {
		s = s[:80]
	}
	return s
}

func makeBackupDir(id string) (string, error) {
	base := backupDir(id)
	if err := os.MkdirAll(base, 0755); err != nil {
		return "", err
	}
	return base, nil
}

func backupOneItem(baseDir string, idx int, it *BackupItem) error {
	switch it.Kind {
	case "file":
		fi, err := os.Stat(it.Src)
		if err != nil {
			return err
		}
		base := fmt.Sprintf("%d_%s", idx, sanitize(filepath.Base(it.Src)))
		if fi.Size() < smallThreshold {
			rel := filepath.Join("files", base)
			if err := copyFile(it.Src, filepath.Join(baseDir, rel)); err != nil {
				return err
			}
			it.Stored = rel
			it.Compressed = false
			return nil
		}
		rel := filepath.Join("files", base+".gz")
		if err := gzipFileTo(it.Src, filepath.Join(baseDir, rel)); err != nil {
			return err
		}
		it.Stored = rel
		it.Compressed = true
		return nil

	case "dir":
		base := fmt.Sprintf("%d_%s", idx, sanitize(filepath.Base(it.Src)))
		rel := filepath.Join("files", base+".tar.gz")
		if err := tarGzDir(it.Src, filepath.Join(baseDir, rel)); err != nil {
			return err
		}
		it.Stored = rel
		it.Compressed = true
		return nil

	case "registry":
		base := fmt.Sprintf("%d_%s.reg", idx, sanitize(it.Src))
		tmp := filepath.Join(baseDir, base)
		if err := exportRegKey(it.Src, tmp); err != nil {
			return err
		}
		fi, err := os.Stat(tmp)
		if err != nil {
			return err
		}
		if fi.Size() < smallThreshold {
			it.Stored = filepath.Join("registry", base)
			it.Compressed = false
			dst := filepath.Join(baseDir, it.Stored)
			if err := os.MkdirAll(filepath.Dir(dst), 0755); err != nil {
				return err
			}
			if err := os.Rename(tmp, dst); err != nil {
				return err
			}
			return nil
		}
		rel := filepath.Join("registry", base+".gz")
		if err := gzipFileTo(tmp, filepath.Join(baseDir, rel)); err != nil {
			return err
		}
		os.Remove(tmp)
		it.Stored = rel
		it.Compressed = true
		return nil

	case "service":
		snap, err := snapshotService(it.Src)
		if err != nil {
			return err
		}
		data, _ := json.MarshalIndent(snap, "", "  ")
		base := fmt.Sprintf("%d_%s.json", idx, sanitize(it.Src))
		rel := filepath.Join("services", base)
		dst := filepath.Join(baseDir, rel)
		if err := os.MkdirAll(filepath.Dir(dst), 0755); err != nil {
			return err
		}
		if len(data) < smallThreshold {
			if err := os.WriteFile(dst, data, 0644); err != nil {
				return err
			}
			it.Stored = rel
			it.Compressed = false
			return nil
		}
		rel = rel + ".gz"
		if err := gzipBytes(data, filepath.Join(baseDir, rel)); err != nil {
			return err
		}
		it.Stored = rel
		it.Compressed = true
		return nil

	case "task":
		data, err := exportTaskXML(it.Src)
		if err != nil {
			return err
		}
		base := fmt.Sprintf("%d_%s.xml", idx, sanitize(it.Src))
		rel := filepath.Join("tasks", base)
		dst := filepath.Join(baseDir, rel)
		if err := os.MkdirAll(filepath.Dir(dst), 0755); err != nil {
			return err
		}
		if len(data) < smallThreshold {
			if err := os.WriteFile(dst, data, 0644); err != nil {
				return err
			}
			it.Stored = rel
			it.Compressed = false
			return nil
		}
		rel = rel + ".gz"
		if err := gzipBytes(data, filepath.Join(baseDir, rel)); err != nil {
			return err
		}
		it.Stored = rel
		it.Compressed = true
		return nil
	}
	return fmt.Errorf("unknown item kind %q", it.Kind)
}

func backupAll(baseDir string, items []BackupItem) error {
	for i := range items {
		if err := backupOneItem(baseDir, i, &items[i]); err != nil {
			return err
		}
	}
	return nil
}

// ============================================================================
// Restore core
// ============================================================================

func restoreOneItem(baseDir string, it BackupItem) error {
	switch it.Kind {
	case "file":
		src := filepath.Join(baseDir, it.Stored)
		if it.Compressed {
			return gunzipTo(src, it.Src)
		}
		return copyFile(src, it.Src)

	case "dir":
		return untarGzTo(filepath.Join(baseDir, it.Stored), it.Src)

	case "registry":
		src := filepath.Join(baseDir, it.Stored)
		if it.Compressed {
			tmp, err := os.CreateTemp("", "backupctl_reg_*.reg")
			if err != nil {
				return err
			}
			tmpPath := tmp.Name()
			tmp.Close()
			defer os.Remove(tmpPath)
			if err := gunzipTo(src, tmpPath); err != nil {
				return err
			}
			return importRegFile(tmpPath)
		}
		return importRegFile(src)

	case "service":
		src := filepath.Join(baseDir, it.Stored)
		var data []byte
		var err error
		if it.Compressed {
			tmp, cerr := os.CreateTemp("", "backupctl_svc_*.json")
			if cerr != nil {
				return cerr
			}
			tmpPath := tmp.Name()
			tmp.Close()
			defer os.Remove(tmpPath)
			if err := gunzipTo(src, tmpPath); err != nil {
				return err
			}
			data, err = os.ReadFile(tmpPath)
		} else {
			data, err = os.ReadFile(src)
		}
		if err != nil {
			return err
		}
		var snap svcSnapshot
		if err := json.Unmarshal(data, &snap); err != nil {
			return err
		}
		return applyServiceSnapshot(&snap)

	case "task":
		src := filepath.Join(baseDir, it.Stored)
		var data []byte
		var err error
		if it.Compressed {
			tmp, cerr := os.CreateTemp("", "backupctl_task_*.xml")
			if cerr != nil {
				return cerr
			}
			tmpPath := tmp.Name()
			tmp.Close()
			defer os.Remove(tmpPath)
			if err := gunzipTo(src, tmpPath); err != nil {
				return err
			}
			data, err = os.ReadFile(tmpPath)
		} else {
			data, err = os.ReadFile(src)
		}
		if err != nil {
			return err
		}
		return importTaskXML(it.Src, data)
	}
	return fmt.Errorf("unknown item kind %q", it.Kind)
}

func preBackupForRestore(target *BackupManifest) (string, error) {
	preID := newBackupID()
	base, err := makeBackupDir(preID)
	if err != nil {
		return preID, err
	}
	items := make([]BackupItem, len(target.Items))
	for i, it := range target.Items {
		items[i] = BackupItem{Kind: it.Kind, Src: it.Src}
	}
	if err := backupAll(base, items); err != nil {
		return preID, err
	}
	pm := &BackupManifest{
		ID:      preID,
		Created: time.Now(),
		Command: "pre-restore backup for " + target.ID,
		Items:   items,
	}
	if err := writeManifest(base, pm); err != nil {
		return preID, err
	}
	return preID, nil
}

// ============================================================================
// Confirmation
// ============================================================================

func confirm(prompt string) bool {
	if !stdinIsTTY() {
		fmt.Fprintf(os.Stderr, "%s\n  non-interactive stdin: use -f to skip confirmation\n", prompt)
		return false
	}
	fmt.Fprintf(os.Stderr, "%s [y/N] ", prompt)
	var line string
	fmt.Scanln(&line)
	line = strings.ToLower(strings.TrimSpace(line))
	return line == "y" || line == "yes"
}

// ============================================================================
// Backup command
// ============================================================================

func cmdBackup(args []string) int {
	var items []BackupItem
	allServices := false
	allTasks := false

	i := 0
	for i < len(args) {
		a := args[i]
		switch a {
		case "--file":
			if i+1 >= len(args) {
				fmt.Fprintln(os.Stderr, "backup: --file requires a path")
				return 2
			}
			items = append(items, BackupItem{Kind: "file", Src: args[i+1]})
			i += 2
		case "--dir":
			if i+1 >= len(args) {
				fmt.Fprintln(os.Stderr, "backup: --dir requires a path")
				return 2
			}
			items = append(items, BackupItem{Kind: "dir", Src: args[i+1]})
			i += 2
		case "--reg":
			if i+1 >= len(args) {
				fmt.Fprintln(os.Stderr, "backup: --reg requires a key")
				return 2
			}
			items = append(items, BackupItem{Kind: "registry", Src: args[i+1]})
			i += 2
		case "--svc":
			if i+1 >= len(args) {
				fmt.Fprintln(os.Stderr, "backup: --svc requires a name")
				return 2
			}
			items = append(items, BackupItem{Kind: "service", Src: args[i+1]})
			i += 2
		case "--task":
			if i+1 >= len(args) {
				fmt.Fprintln(os.Stderr, "backup: --task requires a name")
				return 2
			}
			items = append(items, BackupItem{Kind: "task", Src: args[i+1]})
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
			fmt.Fprintf(os.Stderr, "backup: unexpected argument %q\n", a)
			return 2
		}
	}

	if allServices {
		names, err := listServiceNames()
		if err != nil {
			fmt.Fprintf(os.Stderr, "backup: enumerate services: %v\n", err)
			return 5
		}
		for _, n := range names {
			items = append(items, BackupItem{Kind: "service", Src: n})
		}
	}
	if allTasks {
		names, err := listTaskNames()
		if err != nil {
			fmt.Fprintf(os.Stderr, "backup: enumerate tasks: %v\n", err)
			return 5
		}
		for _, n := range names {
			items = append(items, BackupItem{Kind: "task", Src: n})
		}
	}

	if len(items) == 0 {
		fmt.Fprintln(os.Stderr, "backup: nothing to back up (use --file, --dir, --reg, --svc, --task, --all-services or --all-tasks)")
		return 2
	}

	var valid []BackupItem
	for _, it := range items {
		switch it.Kind {
		case "file", "dir":
			if _, err := os.Stat(it.Src); err != nil {
				fmt.Fprintf(os.Stderr, "backup: skip %q: %v\n", it.Src, err)
				continue
			}
		case "registry":
			if _, _, _, err := regParsePath(it.Src); err != nil {
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
		fmt.Printf("[dry-run] target directory: %s\n",
			filepath.Join(backupRoot(), backupPrefix+"<YYYYMMDD_HHMMSS>"))
		return 0
	}

	id := newBackupID()
	base, err := makeBackupDir(id)
	if err != nil {
		fmt.Fprintf(os.Stderr, "backup: create dir: %v\n", err)
		return 5
	}

	opIdx := beginWriteOp()
	rec := &opRecord{
		Op:       "backup",
		TS:       time.Now().Format("2006-01-02 15:04:05"),
		Cmd:      buildCmdLine(os.Args),
		BackupID: id,
		Items:    valid,
	}

	succeeded := 0
	for i := range valid {
		if err := backupOneItem(base, i, &valid[i]); err != nil {
			fmt.Fprintf(os.Stderr, "backup: %s %q: %v\n", valid[i].Kind, valid[i].Src, err)
			bugs.Add("WARN", "backup item %q: %v", valid[i].Src, err)
			valid[i].Stored = ""
			continue
		}
		succeeded++
		fmt.Printf("%s %-8s %s -> %s\n",
			c(clrGreen, "saved"), valid[i].Kind, valid[i].Src, c(clrGray, valid[i].Stored))
	}

	if succeeded == 0 {
		fmt.Fprintf(os.Stderr, "backup: all %d item(s) failed\n", len(valid))
		return 2
	}

	m := &BackupManifest{
		ID:      id,
		Created: time.Now(),
		Command: buildCmdLine(os.Args),
		Items:   valid,
	}
	if err := writeManifest(base, m); err != nil {
		fmt.Fprintf(os.Stderr, "backup: write manifest: %v\n", err)
		return 5
	}
	rec.Items = valid
	saveOpRecord(opIdx, rec)
	fmt.Printf("\n%s %s %s\n",
		c(clrBold+clrGreen, "backup created:"),
		c(clrCyan, id),
		c(clrGray, "at "+base))
	if succeeded < len(valid) {
		fmt.Fprintf(os.Stderr, "%d item(s) succeeded, %d failed\n", succeeded, len(valid)-succeeded)
		return 1
	}
	return 0
}

// ============================================================================
// List command
// ============================================================================

func cmdList(args []string) int {
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

	entries, err := os.ReadDir(backupRoot())
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
		name := e.Name()
		if !isBackupDirName(name) {
			continue
		}
		dir := filepath.Join(backupRoot(), name)
		m, err := readManifest(dir)
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
		padRight("ID", idW)+"  "+
			padRight("CREATED", 19)+"  "+
			padRight("ITEMS", 5)+"  "+
			padRight("SIZE", 10)+"  PATH"))
	for _, r := range rows {
		fmt.Println(padRight(r.ID, idW)+"  "+
			padRight(r.Created.Local().Format("2006-01-02 15:04:05"), 19)+"  "+
			padRight(strconv.Itoa(r.Items), 5)+"  "+
			padRight(humanBytes(uint64(r.Size)), 10)+"  "+
			c(clrGray, r.Path))
	}
	fmt.Fprintf(os.Stderr, "\n%d backup(s) in %s\n", len(rows), backupRoot())
	return 0
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
// Restore command
// ============================================================================

func cmdRestore(args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "usage: backupctl restore <backup-id> [-f]")
		return 2
	}

	id := args[0]
	force := false
	for _, a := range args[1:] {
		switch a {
		case "-f", "--force":
			force = true
		default:
			fmt.Fprintf(os.Stderr, "restore: unknown option %s\n", a)
			return 2
		}
	}

	dir := backupDir(id)
	m, err := readManifest(dir)
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
		fmt.Printf("[dry-run] would first snapshot current state to a new backup\n")
		for _, it := range m.Items {
			fmt.Printf("[dry-run]   restore %-8s %s\n", it.Kind, it.Src)
		}
		return 0
	}

	preID, err := preBackupForRestore(m)
	if err != nil {
		fmt.Fprintf(os.Stderr, "restore: pre-backup: %v\n", err)
		return 5
	}
	fmt.Printf("%s %s\n", c(clrCyan, "pre-backup:"), preID)

	opIdx := beginWriteOp()
	rec := &opRecord{
		Op:             "restore",
		TS:             time.Now().Format("2006-01-02 15:04:05"),
		Cmd:            buildCmdLine(os.Args),
		TargetBackupID: id,
		PreBackupID:    preID,
		Items:          m.Items,
	}

	succeeded, failed := 0, 0
	for _, it := range m.Items {
		if err := restoreOneItem(dir, it); err != nil {
			fmt.Fprintf(os.Stderr, "restore: %s %s: %v\n", it.Kind, it.Src, err)
			bugs.Add("WARN", "restore %s %s: %v", it.Kind, it.Src, err)
			failed++
			continue
		}
		fmt.Printf("%s %-8s %s\n", c(clrGreen, "restored"), it.Kind, it.Src)
		succeeded++
	}
	saveOpRecord(opIdx, rec)

	if failed == 0 {
		return 0
	}
	if succeeded == 0 {
		return 2
	}
	return 1
}

// ============================================================================
// Clean command
// ============================================================================

type cleanCandidate struct {
	id      string
	dir     string
	created time.Time
	size    int64
}

func cmdClean(args []string) int {
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
				fmt.Fprintln(os.Stderr, "clean: --keep requires a number")
				return 2
			}
			v, err := strconv.Atoi(args[i+1])
			if err != nil || v < 0 {
				fmt.Fprintf(os.Stderr, "clean: invalid --keep %q\n", args[i+1])
				return 2
			}
			keep = v
			i += 2
		case "--older-than":
			if i+1 >= len(args) {
				fmt.Fprintln(os.Stderr, "clean: --older-than requires a day count")
				return 2
			}
			v, err := strconv.Atoi(args[i+1])
			if err != nil || v <= 0 {
				fmt.Fprintf(os.Stderr, "clean: invalid --older-than %q\n", args[i+1])
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
			if strings.HasPrefix(a, "-") {
				fmt.Fprintf(os.Stderr, "clean: unknown option %s\n", a)
				return 2
			}
			fmt.Fprintf(os.Stderr, "clean: unexpected argument %q\n", a)
			return 2
		}
	}

	entries, err := os.ReadDir(backupRoot())
	if err != nil {
		if os.IsNotExist(err) {
			fmt.Fprintln(os.Stderr, "no backups")
			return 0
		}
		fmt.Fprintf(os.Stderr, "clean: %v\n", err)
		return 5
	}

	var all []cleanCandidate
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		name := e.Name()
		if !isBackupDirName(name) {
			continue
		}
		dir := filepath.Join(backupRoot(), name)
		m, err := readManifest(dir)
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
		all = append(all, cleanCandidate{m.ID, dir, m.Created, size})
	}
	if len(all) == 0 {
		fmt.Fprintln(os.Stderr, "no backups")
		return 0
	}
	sort.Slice(all, func(i, j int) bool { return all[i].created.After(all[j].created) })

	var toClean []cleanCandidate
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
				cand.created.Local().Format("2006-01-02 15:04:05"),
				humanBytes(uint64(cand.size)))
		}
		if !confirm("proceed?") {
			return 1
		}
	}

	if dryRun {
		fmt.Printf("[dry-run] would remove %d backup(s):\n", len(toClean))
		for _, cand := range toClean {
			if purge {
				fmt.Printf("[dry-run]   purge %s\n", cand.id)
			} else {
				fmt.Printf("[dry-run]   archive %s (then remove)\n", cand.id)
			}
		}
		return 0
	}

	opIdx := beginWriteOp()
	rec := &opRecord{
		Op:  "clean",
		TS:  time.Now().Format("2006-01-02 15:04:05"),
		Cmd: buildCmdLine(os.Args),
	}

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

		if err := os.MkdirAll(archivedRoot(), 0755); err != nil {
			fmt.Fprintf(os.Stderr, "clean: create archive dir: %v\n", err)
			failCount++
			continue
		}
		if cand.size < smallThreshold {
			dst := filepath.Join(archivedRoot(), cand.id)
			if err := os.Rename(cand.dir, dst); err != nil {
				fmt.Fprintf(os.Stderr, "clean: archive %s: %v\n", cand.id, err)
				failCount++
				continue
			}
		} else {
			dst := filepath.Join(archivedRoot(), cand.id+".tar.gz")
			if err := tarGzDir(cand.dir, dst); err != nil {
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

	saveOpRecord(opIdx, rec)
	if failCount == 0 {
		return 0
	}
	if okCount == 0 {
		return 2
	}
	return 1
}

// ============================================================================
// History / rollback
// ============================================================================

func isHistorySelf(cmd string) bool {
	return strings.Contains(cmd, "--history") || strings.Contains(cmd, "--rollback") ||
		strings.Contains(cmd, "-h") || strings.Contains(cmd, "--help") ||
		strings.Contains(cmd, "--version")
}

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
	type entry struct {
		idx  int
		line string
	}
	var entries []entry
	for i := len(lines) - 1; i >= 0; i-- {
		if !manifestExists(i) {
			continue
		}
		cmd, _ := parseLogLine(lines[i])
		if isHistorySelf(cmd) {
			continue
		}
		entries = append(entries, entry{i, lines[i]})
	}
	if len(entries) == 0 {
		fmt.Fprintln(os.Stderr, "no rollback-able operations in log")
		return 0
	}
	for k, e := range entries {
		desc := ""
		if rec, err := loadOpRecord(e.idx); err == nil {
			desc = summarizeOp(rec)
		}
		fmt.Printf("[%d] %s %s\n", k+1, e.line, c(clrGray, desc))
	}
	fmt.Fprintf(os.Stderr, "\n%d rollback-able operation(s). Log: %s\n", len(entries), logPath())
	return 0
}

var logRe = regexp.MustCompile(`^\[(.*)\] \[(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\] \[(-?\d+)\]$`)

func parseLogLine(line string) (cmd string, ok bool) {
	m := logRe.FindStringSubmatch(line)
	if m == nil {
		return "", false
	}
	return m[1], true
}

func summarizeOp(rec *opRecord) string {
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

func cmdRollback(args []string) int {
	n := 1
	for i := 0; i < len(args); i++ {
		if args[i] == "-n" || args[i] == "--last" {
			if i+1 >= len(args) {
				fmt.Fprintln(os.Stderr, "rollback: -n requires a number")
				return 2
			}
			v, err := strconv.Atoi(args[i+1])
			if err != nil || v <= 0 {
				fmt.Fprintln(os.Stderr, "rollback: -n expects a positive number")
				return 2
			}
			n = v
			i++
		} else if strings.HasPrefix(args[i], "-") {
			fmt.Fprintf(os.Stderr, "rollback: unknown option %s\n", args[i])
			return 2
		}
	}

	lines, err := readLogLines()
	if err != nil {
		fmt.Fprintf(os.Stderr, "read log: %v\n", err)
		return 4
	}
	var targets []int
	for i := len(lines) - 1; i >= 0 && len(targets) < n; i-- {
		if !manifestExists(i) {
			continue
		}
		cmd, _ := parseLogLine(lines[i])
		if isHistorySelf(cmd) {
			continue
		}
		targets = append(targets, i)
	}
	if len(targets) == 0 {
		fmt.Fprintln(os.Stderr, "no rollback-able operations found")
		return 4
	}

	if dryRun {
		for k, idx := range targets {
			rec, err := loadOpRecord(idx)
			if err != nil {
				fmt.Printf("[dry-run] step %d: load manifest %d: %v\n", k+1, idx, err)
				continue
			}
			fmt.Printf("[dry-run] step %d: %s %s\n", k+1, rec.Op, summarizeOp(rec))
		}
		return 0
	}

	okCount, failCount := 0, 0
	for k, idx := range targets {
		rec, err := loadOpRecord(idx)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[rollback] step %d: load manifest %d: %v\n", k+1, idx, err)
			failCount++
			continue
		}
		fmt.Fprintf(os.Stderr, "[rollback] step %d: %s %s\n", k+1, rec.Op, summarizeOp(rec))
		if err := rollbackOne(rec); err != nil {
			fmt.Fprintf(os.Stderr, "[rollback] step %d: error: %v\n", k+1, err)
			bugs.Add("ERR", "rollback %d: %v", idx, err)
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

func rollbackOne(rec *opRecord) error {
	switch rec.Op {
	case "backup":
		if rec.BackupID == "" {
			return fmt.Errorf("no backup id recorded")
		}
		return os.RemoveAll(backupDir(rec.BackupID))

	case "restore":
		if rec.PreBackupID == "" {
			return fmt.Errorf("no pre-backup id recorded")
		}
		dir := backupDir(rec.PreBackupID)
		m, err := readManifest(dir)
		if err != nil {
			return fmt.Errorf("read pre-backup: %w", err)
		}
		for _, it := range m.Items {
			if err := restoreOneItem(dir, it); err != nil {
				return fmt.Errorf("restore %s %s: %w", it.Kind, it.Src, err)
			}
		}
		return nil

	case "clean":
		okCount, failCount := 0, 0
		var firstErr error
		for _, id := range rec.ArchivedIDs {
			smallPath := filepath.Join(archivedRoot(), id)
			largePath := filepath.Join(archivedRoot(), id+".tar.gz")
			destDir := backupDir(id)
			if fi, err := os.Stat(smallPath); err == nil && fi.IsDir() {
				if err := os.Rename(smallPath, destDir); err != nil {
					if firstErr == nil {
						firstErr = err
					}
					failCount++
					continue
				}
				okCount++
				continue
			}
			if _, err := os.Stat(largePath); err == nil {
				if err := untarGzTo(largePath, destDir); err != nil {
					if firstErr == nil {
						firstErr = err
					}
					failCount++
					continue
				}
				os.Remove(largePath)
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

// ============================================================================
// Display helpers
// ============================================================================

func padRight(s string, width int) string {
	w := 0
	for _, r := range s {
		if isWideRune(r) {
			w += 2
		} else {
			w++
		}
	}
	if w >= width {
		return s
	}
	return s + strings.Repeat(" ", width-w)
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

// ============================================================================
// Help
// ============================================================================

func printHelp() {
	header := "backupctl v1.0.0 (Windows)"
	fmt.Println(c(clrBold+clrCyan, header))
	fmt.Println("Unified backup and restore for files, registry, services, and scheduled tasks")
	fmt.Println()
	fmt.Print(`USAGE
  backupctl backup [OPTIONS]
  backupctl list [--json]
  backupctl restore <backup-id> [-f]
  backupctl clean [--keep N | --older-than DAYS] [--purge] [-f]
  backupctl --history
  backupctl --rollback [-n N]

LAYOUT
  Every backup is a directory named backup<timestamp> next to the
  executable:

    <exe-dir>/
      backup20260101_120000/
        manifest.json
        files/   registry/   services/   tasks/
      backup_archived/         (cleaned backups live here)
      backupctl_backup/        (audit log and op manifests)
        backupctl.log
        ops/<logIndex>.json

BACKUP
  Items can be mixed in any combination:
    --file <path>        back up a single file
    --dir  <path>        back up a directory tree (tar + gzip -9)
    --reg  <key>         back up a registry key subtree (reg export)
    --svc  <name>        snapshot a service's start type and state
    --task <name>        back up a scheduled task's XML
    --all-services       snapshot every service
    --all-tasks          back up every scheduled task

  Compression policy for files and directories:
    < 8 KiB  or already compressed: copied as-is
    >= 8 KiB: gzip -9
    directories: tar + gzip -9

  Each backup includes manifest.json describing every item, so it can be
  restored item-by-item.

LIST
  Prints every backup directory under <exe-dir>, newest first:
    ID  CREATED  ITEMS  SIZE  PATH
  --json emits the same data as JSON.

RESTORE
  Restores one backup by ID. Before touching anything, a pre-restore backup
  of the current state is created so the operation is reversible with
  --rollback. -f skips the confirmation prompt.

CLEAN
  Removes old backups. Two selection modes:
    --keep N           keep the newest N backups, archive the rest
    --older-than DAYS  archive backups older than DAYS

  Without --purge, cleaned backups are moved to <exe-dir>\backup_archived\
  and gzip-compressed if large. This is what --rollback undoes.
  With --purge, backups are deleted outright and cannot be recovered.

HISTORY / ROLLBACK
  Every invocation (except -h/--help/--version/--history/--rollback/--dry-run)
  appends one line to ./backupctl_backup/backupctl.log:
    [command line] [timestamp] [exit code]
  Operations that change state also write a manifest to
  ./backupctl_backup/ops/<logIndex>.json.

  --history lists rollback-able operations, numbered from newest (1).

  --rollback undoes the most recent operation:
    backup   -> delete the created backup directory
    restore  -> restore the pre-backup of the previous state
    clean    -> move archived backups back into the live backup directory

GLOBAL
  -o, --out <path>     Redirect stdout to a file
  --dry-run            Preview only: prints the plan, does nothing, no log
  --no-color           Disable ANSI colors (also honors NO_COLOR)
  -b, --bugs           Print collected errors/warnings on exit
  -h, --help           Show this help
  --version            Show version

EXIT CODES
  0 success | 1 partial failure | 2 bad args | 3 permission denied
  4 not found | 5 I/O error
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
// main
// ============================================================================

func main() {
	args, outPath, err := consumeGlobalFlags(os.Args[1:])
	if err != nil {
		fmt.Fprintf(os.Stderr, "backupctl: %v\n", err)
		bugs.Flush()
		os.Exit(2)
	}

	if noColorFlag || os.Getenv("NO_COLOR") != "" {
		useColor = false
	} else if stdoutIsTTY() {
		useColor = true
	}

	if has(args, "--version") {
		fmt.Println("backupctl v1.0.0")
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
		finalExit(cmdRollback(stripFlags(args, "--rollback")), false)
	}

	if outPath != "" {
		if err := setupOutput(outPath); err != nil {
			fmt.Fprintf(os.Stderr, "backupctl: %v\n", err)
			bugs.Flush()
			os.Exit(2)
		}
	}

	cmdIdx := -1
	for i, a := range args {
		if !strings.HasPrefix(a, "-") {
			cmdIdx = i
			break
		}
	}
	if cmdIdx < 0 {
		fmt.Fprintln(os.Stderr, "backupctl: missing command, use -h for help")
		finalExit(2, true)
	}
	cmd := args[cmdIdx]
	rest := append([]string{}, args[:cmdIdx]...)
	rest = append(rest, args[cmdIdx+1:]...)

	var code int
	switch cmd {
	case "backup", "b":
		code = cmdBackup(rest)
	case "list", "ls":
		code = cmdList(rest)
	case "restore", "r":
		code = cmdRestore(rest)
	case "clean", "c":
		code = cmdClean(rest)
	default:
		fmt.Fprintf(os.Stderr, "backupctl: unknown command %q\n", cmd)
		code = 2
	}
	finalExit(code, true)
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