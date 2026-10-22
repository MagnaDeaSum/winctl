//go:build windows && amd64

package main

// aclctl — File permission manager (DACL / ACE / owner / SDDL).
// Single-file, standard-library-only build:
//
//   go build -trimpath -ldflags "-s -w" -o aclctl.exe aclctl.go
//
// Log: ./aclctl_backup/aclctl.log  [cmd] [ts] [exit code]

import (
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
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
	advapi32 = syscall.NewLazyDLL("advapi32.dll")

	pGetStdHandle   = kernel32.NewProc("GetStdHandle")
	pGetConsoleMode = kernel32.NewProc("GetConsoleMode")

	pGetNamedSecurityInfoW = advapi32.NewProc("GetNamedSecurityInfoW")
	pSetNamedSecurityInfoW = advapi32.NewProc("SetNamedSecurityInfoW")

	pGetSecurityDescriptorOwner = advapi32.NewProc("GetSecurityDescriptorOwner")
	pGetSecurityDescriptorGroup = advapi32.NewProc("GetSecurityDescriptorGroup")
	pGetSecurityDescriptorDacl  = advapi32.NewProc("GetSecurityDescriptorDacl")
	pGetSecurityDescriptorSacl  = advapi32.NewProc("GetSecurityDescriptorSacl")

	pConvertSecurityDescriptorToStringSecurityDescriptorW = advapi32.NewProc("ConvertSecurityDescriptorToStringSecurityDescriptorW")
	pConvertStringSecurityDescriptorToSecurityDescriptorW = advapi32.NewProc("ConvertStringSecurityDescriptorToSecurityDescriptorW")

	pSetEntriesInAclW             = advapi32.NewProc("SetEntriesInAclW")
	pBuildExplicitAccessWithNameW = advapi32.NewProc("BuildExplicitAccessWithNameW")

	pOpenProcessToken      = advapi32.NewProc("OpenProcessToken")
	pAdjustTokenPrivileges = advapi32.NewProc("AdjustTokenPrivileges")
	pLookupPrivilegeValueW = advapi32.NewProc("LookupPrivilegeValueW")

	pLookupAccountNameW     = advapi32.NewProc("LookupAccountNameW")
	pConvertSidToStringSidW = advapi32.NewProc("ConvertSidToStringSidW")

	pGetCurrentProcess = kernel32.NewProc("GetCurrentProcess")
	pCloseHandle       = kernel32.NewProc("CloseHandle")
	pLocalFree         = kernel32.NewProc("LocalFree")
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
func stdinIsTTY() bool  { return isConsole(STD_INPUT_HANDLE) }

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
		fmt.Fprintln(os.Stderr, "[aclctl] -b/--bugs enabled: no errors or warnings captured this run.")
		return
	}
	fmt.Fprintf(os.Stderr, "\n--- aclctl bugs report (%d entries) ---\n", len(b.entries))
	for _, e := range b.entries {
		fmt.Fprintf(os.Stderr, "[%s] %s %s\n", e.At.Format("15:04:05.000"), e.Level, e.Msg)
	}
	fmt.Fprintln(os.Stderr, "--- end of bugs report ---")
}

// ============================================================================
// Windows security constants
// ============================================================================

const (
	SE_FILE_OBJECT = 1

	OWNER_SECURITY_INFORMATION = 0x00000001
	GROUP_SECURITY_INFORMATION = 0x00000002
	DACL_SECURITY_INFORMATION  = 0x00000004
	SACL_SECURITY_INFORMATION  = 0x00000008

	ACCESS_ALLOWED_ACE_TYPE = 0
	ACCESS_DENIED_ACE_TYPE  = 1

	GRANT_ACCESS = 1
	DENY_ACCESS  = 3

	NO_INHERITANCE        = 0x0
	OBJECT_INHERIT_ACE    = 0x1
	CONTAINER_INHERIT_ACE = 0x2

	TOKEN_QUERY             = 0x0008
	TOKEN_ADJUST_PRIVILEGES = 0x0020

	SE_PRIVILEGE_ENABLED = 0x00000002

	SDDL_REVISION_1 = 1

	ERROR_SUCCESS          = 0
	ERROR_NOT_ALL_ASSIGNED = 1300
)

// ============================================================================
// Structures
// ============================================================================

type LUID struct {
	LowPart  uint32
	HighPart int32
}

type LUID_AND_ATTRIBUTES struct {
	Luid       LUID
	Attributes uint32
}

type TOKEN_PRIVILEGES struct {
	PrivilegeCount uint32
	Privileges     [1]LUID_AND_ATTRIBUTES
}

type TRUSTEEW struct {
	pMultipleTrustee         uintptr
	MultipleTrusteeOperation uint32
	TrusteeForm              uint32
	TrusteeType              uint32
	ptstrName                *uint16
}

type EXPLICIT_ACCESSW struct {
	grfAccessPermissions uint32
	grfAccessMode        uint32
	grfInheritance       uint32
	Trustee              TRUSTEEW
}

type ACL struct {
	AclRevision byte
	Sbz1        byte
	AclSize     uint16
	AceCount    uint16
	Sbz2        uint16
}

type SECURITY_DESCRIPTOR struct {
	Revision byte
	Sbz1     byte
	Control  uint16
	Owner    uintptr
	Group    uintptr
	Sacl     uintptr
	Dacl     uintptr
}

type ACEHeader struct {
	AceType  byte
	AceFlags byte
	AceSize  uint16
}

type ACCESS_ALLOWED_ACE struct {
	Header   ACEHeader
	Mask     uint32
	SidStart uint32
}

// ============================================================================
// SDDL conversion
// ============================================================================

// sddlFromSecurityDescriptor takes an SD pointer (self-relative or absolute,
// ConvertSecurityDescriptorToStringSecurityDescriptorW handles both).
func sddlFromSecurityDescriptor(sd uintptr, secInfo uint32) (string, error) {
	if sd == 0 {
		return "", fmt.Errorf("nil security descriptor")
	}

	var strPtr *uint16
	var strLen uint32
	r, _, callErr := pConvertSecurityDescriptorToStringSecurityDescriptorW.Call(
		sd,
		uintptr(SDDL_REVISION_1),
		uintptr(secInfo),
		uintptr(unsafe.Pointer(&strPtr)),
		uintptr(unsafe.Pointer(&strLen)),
	)
	if r == 0 {
		return "", fmt.Errorf("ConvertSecurityDescriptorToString: %w", callErr)
	}
	if strPtr == nil {
		return "", fmt.Errorf("ConvertSecurityDescriptorToString returned nil")
	}
	defer pLocalFree.Call(uintptr(unsafe.Pointer(strPtr)))

	return syscall.UTF16ToString(unsafe.Slice(strPtr, strLen)), nil
}

func securityDescriptorFromSDDL(sddl string) (*SECURITY_DESCRIPTOR, uintptr, error) {
	ptr, err := syscall.UTF16PtrFromString(sddl)
	if err != nil {
		return nil, 0, err
	}

	var sd *SECURITY_DESCRIPTOR
	var sdLen uint32
	r, _, callErr := pConvertStringSecurityDescriptorToSecurityDescriptorW.Call(
		uintptr(unsafe.Pointer(ptr)),
		uintptr(SDDL_REVISION_1),
		uintptr(unsafe.Pointer(&sd)),
		uintptr(unsafe.Pointer(&sdLen)),
	)
	if r == 0 {
		return nil, 0, fmt.Errorf("ConvertStringSecurityDescriptor: %w", callErr)
	}
	return sd, uintptr(unsafe.Pointer(sd)), nil
}

// ============================================================================
// Get / set security info
// ============================================================================

// secInfoResult holds a security descriptor pointer and the four absolute
// component pointers. The absolute pointers can be passed straight to
// SetNamedSecurityInfoW; the sdPtr must be released with LocalFree.
type secInfoResult struct {
	sdPtr uintptr
	owner uintptr
	group uintptr
	dacl  uintptr
	sacl  uintptr
}

func (r *secInfoResult) free() {
	if r != nil && r.sdPtr != 0 {
		pLocalFree.Call(r.sdPtr)
		r.sdPtr = 0
	}
}

// getSecurityInfo fetches the SD and the four absolute component pointers.
func getSecurityInfo(path string, secInfo uint32) (*secInfoResult, error) {
	pathPtr, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}

	var sd uintptr
	var owner, group, dacl, sacl uintptr
	r, _, _ := pGetNamedSecurityInfoW.Call(
		uintptr(unsafe.Pointer(pathPtr)),
		uintptr(SE_FILE_OBJECT),
		uintptr(secInfo),
		uintptr(unsafe.Pointer(&owner)),
		uintptr(unsafe.Pointer(&group)),
		uintptr(unsafe.Pointer(&dacl)),
		uintptr(unsafe.Pointer(&sacl)),
		uintptr(unsafe.Pointer(&sd)),
	)
	if code := uint32(r); code != ERROR_SUCCESS {
		return nil, fmt.Errorf("GetNamedSecurityInfo(%s): %w", path, syscall.Errno(code))
	}
	return &secInfoResult{
		sdPtr: sd,
		owner: owner,
		group: group,
		dacl:  dacl,
		sacl:  sacl,
	}, nil
}

// setSecurityInfoRaw is the real worker: it takes the four absolute pointers
// and calls SetNamedSecurityInfoW. A pointer of 0 means "do not change".
func setSecurityInfoRaw(path string, secInfo uint32, owner, group, dacl, sacl uintptr) error {
	pathPtr, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	r, _, _ := pSetNamedSecurityInfoW.Call(
		uintptr(unsafe.Pointer(pathPtr)),
		uintptr(SE_FILE_OBJECT),
		uintptr(secInfo),
		owner, group, dacl, sacl,
	)
	if code := uint32(r); code != ERROR_SUCCESS {
		return fmt.Errorf("SetNamedSecurityInfo(%s): %w", path, syscall.Errno(code))
	}
	return nil
}

// extractComponents pulls absolute pointers out of a self-relative SD.
// This is the correct way to use an SD that came from
// ConvertStringSecurityDescriptorToSecurityDescriptorW.
func extractComponents(sd *SECURITY_DESCRIPTOR) (owner, group, dacl, sacl uintptr, secInfo uint32) {
	var present, defaulted uint32
	if sd == nil {
		return
	}
	base := uintptr(unsafe.Pointer(sd))

	var p uintptr
	if r, _, _ := pGetSecurityDescriptorOwner.Call(base,
		uintptr(unsafe.Pointer(&p)),
		uintptr(unsafe.Pointer(&defaulted))); r != 0 && p != 0 {
		owner = p
		secInfo |= OWNER_SECURITY_INFORMATION
	}
	if r, _, _ := pGetSecurityDescriptorGroup.Call(base,
		uintptr(unsafe.Pointer(&p)),
		uintptr(unsafe.Pointer(&defaulted))); r != 0 && p != 0 {
		group = p
		secInfo |= GROUP_SECURITY_INFORMATION
	}
	if r, _, _ := pGetSecurityDescriptorDacl.Call(base,
		uintptr(unsafe.Pointer(&present)),
		uintptr(unsafe.Pointer(&p)),
		uintptr(unsafe.Pointer(&defaulted))); r != 0 && present != 0 && p != 0 {
		dacl = p
		secInfo |= DACL_SECURITY_INFORMATION
	}
	if r, _, _ := pGetSecurityDescriptorSacl.Call(base,
		uintptr(unsafe.Pointer(&present)),
		uintptr(unsafe.Pointer(&p)),
		uintptr(unsafe.Pointer(&defaulted))); r != 0 && present != 0 && p != 0 {
		sacl = p
		secInfo |= SACL_SECURITY_INFORMATION
	}
	return
}

// ============================================================================
// ACL manipulation
// ============================================================================

func addACE(path, trustee, access string, deny bool, inheritFlags uint32) error {
	info, err := getSecurityInfo(path, DACL_SECURITY_INFORMATION)
	if err != nil {
		return err
	}
	defer info.free()

	trusteePtr, err := syscall.UTF16PtrFromString(trustee)
	if err != nil {
		return err
	}

	accessMask := parseAccessMask(access)
	accessMode := uint32(GRANT_ACCESS)
	if deny {
		accessMode = DENY_ACCESS
	}

	var ea EXPLICIT_ACCESSW
	pBuildExplicitAccessWithNameW.Call(
		uintptr(unsafe.Pointer(&ea)),
		uintptr(unsafe.Pointer(trusteePtr)),
		uintptr(accessMask),
		uintptr(accessMode),
		uintptr(inheritFlags),
	)

	var newAcl *ACL
	r, _, _ := pSetEntriesInAclW.Call(
		1,
		uintptr(unsafe.Pointer(&ea)),
		info.dacl,
		uintptr(unsafe.Pointer(&newAcl)),
	)
	if code := uint32(r); code != ERROR_SUCCESS {
		return fmt.Errorf("SetEntriesInAcl: %w", syscall.Errno(code))
	}
	if newAcl != nil {
		defer pLocalFree.Call(uintptr(unsafe.Pointer(newAcl)))
	}

	return setSecurityInfoRaw(path, DACL_SECURITY_INFORMATION,
		0, 0, uintptr(unsafe.Pointer(newAcl)), 0)
}

func parseAccessMask(s string) uint32 {
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

// ============================================================================
// Privilege management
// ============================================================================

func enablePrivilege(name string) (bool, error) {
	h, _, _ := pGetCurrentProcess.Call()
	if h == 0 {
		return false, fmt.Errorf("GetCurrentProcess failed")
	}

	var token syscall.Handle
	r, _, callErr := pOpenProcessToken.Call(h,
		uintptr(TOKEN_QUERY|TOKEN_ADJUST_PRIVILEGES),
		uintptr(unsafe.Pointer(&token)))
	if r == 0 {
		return false, fmt.Errorf("OpenProcessToken: %w", callErr)
	}
	defer pCloseHandle.Call(uintptr(token))

	var luid LUID
	namePtr, err := syscall.UTF16PtrFromString(name)
	if err != nil {
		return false, err
	}
	r, _, callErr = pLookupPrivilegeValueW.Call(0,
		uintptr(unsafe.Pointer(namePtr)),
		uintptr(unsafe.Pointer(&luid)))
	if r == 0 {
		return false, fmt.Errorf("LookupPrivilegeValue(%s): %w", name, callErr)
	}

	tp := TOKEN_PRIVILEGES{
		PrivilegeCount: 1,
		Privileges: [1]LUID_AND_ATTRIBUTES{
			{Luid: luid, Attributes: SE_PRIVILEGE_ENABLED},
		},
	}

	var prevSize uint32
	r, _, callErr = pAdjustTokenPrivileges.Call(
		uintptr(token),
		0,
		uintptr(unsafe.Pointer(&tp)),
		0,
		0,
		uintptr(unsafe.Pointer(&prevSize)),
	)
	if r == 0 {
		return false, fmt.Errorf("AdjustTokenPrivileges: %w", callErr)
	}
	if errno, ok := callErr.(syscall.Errno); ok && errno == ERROR_NOT_ALL_ASSIGNED {
		return false, fmt.Errorf("privilege %s not held by current token (run elevated)", name)
	}
	return true, nil
}

func ensurePrivileges() {
	for _, priv := range []string{"SeRestorePrivilege", "SeTakeOwnershipPrivilege", "SeSecurityPrivilege"} {
		if _, err := enablePrivilege(priv); err != nil {
			bugs.Add("WARN", "enable %s: %v", priv, err)
		}
	}
}

// ============================================================================
// Display helpers
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
	backupDirName = "aclctl_backup"
	logFileName   = "aclctl.log"
	opsDirName    = "ops"
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
func opsDir() string  { return filepath.Join(logRoot(), opsDirName) }

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
// Operation records
// ============================================================================

type opRecord struct {
	Op      string `json:"op"`
	TS      string `json:"ts"`
	Cmd     string `json:"cmd"`
	Code    int    `json:"code"`
	Path    string `json:"path"`
	OldSDDL string `json:"oldSddl"`
	NewSDDL string `json:"newSddl"`
	Backup  string `json:"backup,omitempty"`
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
// SDDL backup / restore
// ============================================================================

const smallThreshold = 8192

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

func backupSDDL(path string, logIdx int) (string, bool, error) {
	baseInfo := uint32(OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION)

	info, err := getSecurityInfo(path, baseInfo)
	if err != nil {
		return "", false, err
	}
	defer info.free()

	sddl, err := sddlFromSecurityDescriptor(info.sdPtr, baseInfo)
	if err != nil {
		return "", false, err
	}

	base := fmt.Sprintf("%d_%s", logIdx, sanitize(path))
	if len(sddl) < smallThreshold {
		rel := base + ".sddl"
		full := filepath.Join(logRoot(), rel)
		if err := os.MkdirAll(filepath.Dir(full), 0755); err != nil {
			return "", false, err
		}
		if err := os.WriteFile(full, []byte(sddl), 0644); err != nil {
			return "", false, err
		}
		return rel, false, nil
	}

	rel := base + ".sddl.gz"
	full := filepath.Join(logRoot(), rel)
	if err := os.MkdirAll(filepath.Dir(full), 0755); err != nil {
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

func restoreSDDL(relPath string, gzipped bool, path string) error {
	full := filepath.Join(logRoot(), relPath)
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
	return applySDDL(string(data), path)
}

// applySDDL parses an SDDL string into a self-relative SD, extracts absolute
// component pointers, and calls SetNamedSecurityInfoW.
func applySDDL(sddl, path string) error {
	sd, sdPtr, err := securityDescriptorFromSDDL(sddl)
	if err != nil {
		return err
	}
	defer pLocalFree.Call(sdPtr)

	owner, group, dacl, sacl, secInfo := extractComponents(sd)
	if secInfo == 0 {
		return fmt.Errorf("SDDL contains no owner, group, DACL or SACL")
	}
	return setSecurityInfoRaw(path, secInfo, owner, group, dacl, sacl)
}

// ============================================================================
// Confirmation
// ============================================================================

func confirm(prompt string) bool {
	if !stdinIsTTY() {
		fmt.Fprintf(os.Stderr, "%s\n  non-interactive stdin: use -y to skip confirmation\n", prompt)
		return false
	}
	fmt.Fprintf(os.Stderr, "%s [y/N] ", prompt)
	var line string
	fmt.Scanln(&line)
	line = strings.ToLower(strings.TrimSpace(line))
	return line == "y" || line == "yes"
}

// ============================================================================
// show command
// ============================================================================

func cmdShow(path string, jsonOut bool) int {
	secInfo := uint32(OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION)

	info, err := getSecurityInfo(path, secInfo)
	if err != nil {
		fmt.Fprintf(os.Stderr, "aclctl: %v\n", err)
		return 5
	}
	defer info.free()

	if jsonOut {
		sddl, _ := sddlFromSecurityDescriptor(info.sdPtr, secInfo)
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(map[string]string{
			"path": path,
			"sddl": sddl,
		})
		return 0
	}

	fmt.Printf("%s %s\n\n", c(clrCyan, "Path:"), path)

	if sddl, err := sddlFromSecurityDescriptor(info.sdPtr, secInfo); err == nil {
		fmt.Printf("%s\n%s\n", c(clrCyan, "SDDL:"), c(clrGray, sddl))
	}

	if info.dacl != 0 {
		fmt.Println()
		fmt.Println(c(clrBold+clrCyan, "DACL entries"))
		printACEs((*ACL)(unsafe.Pointer(info.dacl)))
	}
	return 0
}

func printACEs(acl *ACL) {
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
		header := (*ACEHeader)(unsafe.Pointer(base))
		if header.AceSize == 0 {
			break
		}
		switch header.AceType {
		case ACCESS_ALLOWED_ACE_TYPE:
			mask := (*ACCESS_ALLOWED_ACE)(unsafe.Pointer(base)).Mask
			fmt.Printf("  %s allow mask=0x%08X flags=0x%X\n",
				c(clrGreen, "ACE"), mask, header.AceFlags)
		case ACCESS_DENIED_ACE_TYPE:
			mask := (*ACCESS_ALLOWED_ACE)(unsafe.Pointer(base)).Mask
			fmt.Printf("  %s deny  mask=0x%08X flags=0x%X\n",
				c(clrRed, "ACE"), mask, header.AceFlags)
		default:
			fmt.Printf("  ACE type=%d flags=0x%X size=%d\n",
				header.AceType, header.AceFlags, header.AceSize)
		}
		base += uintptr(header.AceSize)
	}
}

// ============================================================================
// set-owner command
// ============================================================================

func cmdSetOwner(path, owner string, yes bool) int {
	if !yes && !confirm(fmt.Sprintf("change owner of %s to %s?", path, owner)) {
		return 1
	}

	idx := beginWriteOp()
	backupRel, _, err := backupSDDL(path, idx)
	if err != nil {
		fmt.Fprintf(os.Stderr, "aclctl: backup failed, aborting: %v\n", err)
		return 5
	}

	ensurePrivileges()

	ownerSID, err := lookupAccountSID(owner)
	if err != nil {
		fmt.Fprintf(os.Stderr, "aclctl: resolve owner %q: %v\n", owner, err)
		return 5
	}

	fullInfo := uint32(OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION)
	info, err := getSecurityInfo(path, fullInfo)
	if err != nil {
		fmt.Fprintf(os.Stderr, "aclctl: %v\n", err)
		return 5
	}
	oldSDDL, _ := sddlFromSecurityDescriptor(info.sdPtr, fullInfo)
	info.free()

	newSDDL := replaceOwnerInSDDL(oldSDDL, ownerSID)
	if newSDDL == "" {
		fmt.Fprintf(os.Stderr, "aclctl: could not build new SDDL for owner change\n")
		return 5
	}

	if err := applySDDL(newSDDL, path); err != nil {
		fmt.Fprintf(os.Stderr, "aclctl: %v\n", err)
		return 5
	}

	rec := &opRecord{
		Op:      "set-owner",
		TS:      time.Now().Format("2006-01-02 15:04:05"),
		Cmd:     buildCmdLine(os.Args),
		Path:    path,
		OldSDDL: oldSDDL,
		NewSDDL: newSDDL,
		Backup:  backupRel,
	}
	saveOpRecord(idx, rec)

	fmt.Printf("%s owner of %s -> %s (%s)\n",
		c(clrGreen, "changed"), path, owner, ownerSID)
	return 0
}

func replaceOwnerInSDDL(sddl, ownerSID string) string {
	if sddl == "" {
		return "O:" + ownerSID
	}
	re := regexp.MustCompile(`O:[^GDS]*`)
	if re.MatchString(sddl) {
		return re.ReplaceAllString(sddl, "O:"+ownerSID)
	}
	return "O:" + ownerSID + sddl
}

func lookupAccountSID(name string) (string, error) {
	namePtr, err := syscall.UTF16PtrFromString(name)
	if err != nil {
		return "", err
	}

	var sidSize, domainSize uint32
	pLookupAccountNameW.Call(0, uintptr(unsafe.Pointer(namePtr)), 0,
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

	r, _, callErr := pLookupAccountNameW.Call(0,
		uintptr(unsafe.Pointer(namePtr)),
		uintptr(unsafe.Pointer(&sidBuf[0])),
		uintptr(unsafe.Pointer(&sidSize)),
		uintptr(unsafe.Pointer(&domainBuf[0])),
		uintptr(unsafe.Pointer(&domainSize)),
		uintptr(unsafe.Pointer(&use)),
	)
	if r == 0 {
		return "", fmt.Errorf("LookupAccountName(%q): %w", name, callErr)
	}

	var sidStrPtr *uint16
	r, _, callErr = pConvertSidToStringSidW.Call(
		uintptr(unsafe.Pointer(&sidBuf[0])),
		uintptr(unsafe.Pointer(&sidStrPtr)),
	)
	if r == 0 {
		return "", fmt.Errorf("ConvertSidToStringSid: %w", callErr)
	}
	if sidStrPtr == nil {
		return "", fmt.Errorf("ConvertSidToStringSid returned nil")
	}
	defer pLocalFree.Call(uintptr(unsafe.Pointer(sidStrPtr)))

	return syscall.UTF16ToString(unsafe.Slice(sidStrPtr, 256)), nil
}

// ============================================================================
// add-ace command
// ============================================================================

func cmdAddACE(path, trustee, access string, deny, recursive, yes bool) int {
	if recursive {
		fmt.Fprintf(os.Stderr, "%s recursive ACL changes require --recursive and a second confirmation.\n",
			c(clrYellow, "warning:"))
		if !yes && !confirm(fmt.Sprintf("Apply ACE change to %s AND all children?", path)) {
			return 1
		}
	}

	if !yes && !confirm(fmt.Sprintf("add %s ACE for %s on %s?", access, trustee, path)) {
		return 1
	}

	idx := beginWriteOp()
	backupRel, _, err := backupSDDL(path, idx)
	if err != nil {
		fmt.Fprintf(os.Stderr, "aclctl: backup failed, aborting: %v\n", err)
		return 5
	}

	ensurePrivileges()

	inheritFlags := uint32(NO_INHERITANCE)
	if recursive {
		inheritFlags = OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE
	}

	if err := addACE(path, trustee, access, deny, inheritFlags); err != nil {
		fmt.Fprintf(os.Stderr, "aclctl: %v\n", err)
		return 5
	}

	rec := &opRecord{
		Op:     "add-ace",
		TS:     time.Now().Format("2006-01-02 15:04:05"),
		Cmd:    buildCmdLine(os.Args),
		Path:   path,
		Backup: backupRel,
	}
	saveOpRecord(idx, rec)

	fmt.Printf("%s ACE for %s on %s\n", c(clrGreen, "added"), trustee, path)
	return 0
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
	case "set-owner":
		return "-> restore owner on " + rec.Path
	case "add-ace":
		return "-> restore DACL on " + rec.Path
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

	ensurePrivileges()

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
	if rec.Backup == "" {
		return fmt.Errorf("no SDDL backup recorded")
	}
	if rec.Path == "" {
		return fmt.Errorf("no target path recorded")
	}
	return restoreSDDL(rec.Backup, strings.HasSuffix(rec.Backup, ".gz"), rec.Path)
}

// ============================================================================
// Help
// ============================================================================

func printHelp() {
	header := "aclctl v1.0.0 (Windows)"
	fmt.Println(c(clrBold+clrCyan, header))
	fmt.Println("File permission manager - view / modify DACL, ACE, owner, SDDL")
	fmt.Println()
	fmt.Print(`USAGE
  aclctl show <path> [--json]           show DACL / owner SDDL
  aclctl set-owner <path> <user|group> [-y]
  aclctl add-ace <path> <trustee> <access> [--deny] [--recursive] [-y]
  aclctl --history
  aclctl --rollback [-n N]

SHOW
  Prints the DACL and owner in SDDL form, plus a best-effort ACE listing.
  SACL is not requested by default, because reading it requires
  SeSecurityPrivilege.
  --json emits a single object: {"path": "...", "sddl": "..."}.

SET-OWNER
  Changes the owner of <path> to the given user or group.
  The current SDDL is backed up before the change; --rollback restores it.
  Requires SeRestorePrivilege / SeTakeOwnershipPrivilege; the tool tries to
  enable them automatically if the process token holds them.

ADD-ACE
  Adds or replaces an ACE for <trustee> on <path>.
    <access> can be: read | write | execute | full | <hex mask>
    --deny         create a deny ACE instead of allow
    --recursive    apply the ACE to the object and all children
                   (requires a second confirmation; uses inheritance flags)

  A full SDDL backup is taken before the change.

GLOBAL
  -o, --out <path>  Redirect stdout to a file
  --dry-run         Preview only: no changes, no backups, no log
  --no-color        Disable ANSI colors (also honors NO_COLOR)
  -b, --bugs        Print collected errors/warnings on exit
  -h, --help        Show this help
  --version         Show version

HISTORY / ROLLBACK
  Every invocation (except -h/--help/--version/--history/--rollback/--dry-run)
  appends one line to ./aclctl_backup/aclctl.log:
    [command line] [timestamp] [exit code]

  Operations that modify ACLs also write a manifest to
  ./aclctl_backup/ops/<logIndex>.json and a .sddl (or .sddl.gz) backup.

  --history lists rollback-able operations, numbered from newest (1).
  --rollback restores the SDDL backup of the most recent operation.

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
		fmt.Fprintf(os.Stderr, "aclctl: %v\n", err)
		bugs.Flush()
		os.Exit(2)
	}

	if noColorFlag || os.Getenv("NO_COLOR") != "" {
		useColor = false
	} else if stdoutIsTTY() {
		useColor = true
	}

	if has(args, "--version") {
		fmt.Println("aclctl v1.0.0")
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
		finalExit(cmdRollback(stripFlag(args, "--rollback")), false)
	}

	if outPath != "" {
		if err := setupOutput(outPath); err != nil {
			fmt.Fprintf(os.Stderr, "aclctl: %v\n", err)
			bugs.Flush()
			os.Exit(2)
		}
	}

	cmd := args[0]
	rest := args[1:]

	switch cmd {
	case "show":
		if len(rest) == 0 {
			fmt.Fprintln(os.Stderr, "usage: aclctl show <path> [--json]")
			finalExit(2, true)
		}
		path := rest[0]
		jsonOut := has(rest, "--json")
		if dryRun {
			fmt.Printf("[dry-run] would show ACL of %s\n", path)
			finalExit(0, false)
		}
		finalExit(cmdShow(path, jsonOut), true)

	case "set-owner":
		if len(rest) < 2 {
			fmt.Fprintln(os.Stderr, "usage: aclctl set-owner <path> <user|group> [-y]")
			finalExit(2, true)
		}
		path, owner := rest[0], rest[1]
		yes := has(rest, "-y", "--yes")
		if dryRun {
			fmt.Printf("[dry-run] would change owner of %s to %s\n", path, owner)
			finalExit(0, false)
		}
		finalExit(cmdSetOwner(path, owner, yes), true)

	case "add-ace":
		if len(rest) < 3 {
			fmt.Fprintln(os.Stderr, "usage: aclctl add-ace <path> <trustee> <access> [--deny] [--recursive] [-y]")
			finalExit(2, true)
		}
		path, trustee, access := rest[0], rest[1], rest[2]
		deny := has(rest, "--deny")
		recursive := has(rest, "--recursive")
		yes := has(rest, "-y", "--yes")
		if dryRun {
			fmt.Printf("[dry-run] would add %s ACE for %s on %s (recursive=%v)\n",
				access, trustee, path, recursive)
			finalExit(0, false)
		}
		finalExit(cmdAddACE(path, trustee, access, deny, recursive, yes), true)

	default:
		fmt.Fprintf(os.Stderr, "aclctl: unknown command %q\n", cmd)
		finalExit(2, true)
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

func stripFlag(args []string, flag string) []string {
	out := make([]string, 0, len(args))
	for _, a := range args {
		if a != flag {
			out = append(out, a)
		}
	}
	return out
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