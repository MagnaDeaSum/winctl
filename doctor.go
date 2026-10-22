//go:build windows && amd64

package main

// doctor — Environment diagnostics (read-only).
// Single-file, standard-library-only build:
//
//   go build -trimpath -ldflags "-s -w" -o doctor.exe doctor.go
//
// Log: ./doctor_backup/doctor.log  [cmd] [ts] [exit code]

import (
	"debug/pe"
	"encoding/binary"
	"encoding/json"
	"fmt"
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
	reportMode    = false
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
	ntdll    = syscall.NewLazyDLL("ntdll.dll")
	advapi32 = syscall.NewLazyDLL("advapi32.dll")

	pGetStdHandle   = kernel32.NewProc("GetStdHandle")
	pGetConsoleMode = kernel32.NewProc("GetConsoleMode")

	pRtlGetVersion          = ntdll.NewProc("RtlGetVersion")
	pGetNativeSystemInfo    = kernel32.NewProc("GetNativeSystemInfo")
	pGetACP                = kernel32.NewProc("GetACP")
	pGetOEMCP              = kernel32.NewProc("GetOEMCP")
	pGetConsoleOutputCP    = kernel32.NewProc("GetConsoleOutputCP")
	pGetCurrentProcess     = kernel32.NewProc("GetCurrentProcess")

	pOpenProcessToken    = advapi32.NewProc("OpenProcessToken")
	pGetTokenInformation = advapi32.NewProc("GetTokenInformation")

	pRegOpenKeyExW    = advapi32.NewProc("RegOpenKeyExW")
	pRegCloseKey      = advapi32.NewProc("RegCloseKey")
	pRegQueryValueExW = advapi32.NewProc("RegQueryValueExW")
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
		fmt.Fprintln(os.Stderr, "[doctor] -b/--bugs enabled: no errors or warnings captured this run.")
		return
	}
	fmt.Fprintf(os.Stderr, "\n--- doctor bugs report (%d entries) ---\n", len(b.entries))
	for _, e := range b.entries {
		fmt.Fprintf(os.Stderr, "[%s] %s %s\n", e.At.Format("15:04:05.000"), e.Level, e.Msg)
	}
	fmt.Fprintln(os.Stderr, "--- end of bugs report ---")
}

// ============================================================================
// Windows structures
// ============================================================================

type OSVERSIONINFOW struct {
	OSVersionInfoSize uint32
	MajorVersion      uint32
	MinorVersion      uint32
	BuildNumber       uint32
	PlatformID        uint32
	CSDVersion        [128]uint16
}

type SYSTEM_INFO struct {
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

type TOKEN_ELEVATION struct{ TokenIsElevated uint32 }

const (
	PROCESSOR_ARCHITECTURE_INTEL = 0
	PROCESSOR_ARCHITECTURE_ARM   = 5
	PROCESSOR_ARCHITECTURE_IA64  = 6
	PROCESSOR_ARCHITECTURE_AMD64 = 9
	PROCESSOR_ARCHITECTURE_ARM64 = 12

	TOKEN_QUERY    = 0x0008
	TokenElevation = 20

	HKEY_LOCAL_MACHINE = uintptr(0xFFFFFFFF80000002)
	KEY_READ           = 0x20019
	KEY_WOW64_64KEY    = 0x0100
	REG_DWORD          = 4
)

func archName(a uint16) string {
	switch a {
	case PROCESSOR_ARCHITECTURE_INTEL:
		return "x86"
	case PROCESSOR_ARCHITECTURE_ARM:
		return "ARM"
	case PROCESSOR_ARCHITECTURE_IA64:
		return "IA64"
	case PROCESSOR_ARCHITECTURE_AMD64:
		return "x64"
	case PROCESSOR_ARCHITECTURE_ARM64:
		return "ARM64"
	}
	return fmt.Sprintf("0x%X", a)
}

// ============================================================================
// Registry helpers
// ============================================================================

func regReadDWORD(root uintptr, subKey, name string) (uint32, bool) {
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
		uintptr(unsafe.Pointer(&typ)),
		uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&size)))
	if r != 0 || typ != REG_DWORD || size < 4 {
		return 0, false
	}
	return binary.LittleEndian.Uint32(buf), true
}

// ============================================================================
// Checks
// ============================================================================

type CheckResult struct {
	Category string `json:"category"`
	Name     string `json:"name"`
	Status   string `json:"status"` // ok | warn | error | info
	Value    string `json:"value"`
	Detail   string `json:"detail,omitempty"`
}

// ----------------------------------------------------------------------------
// OS version
// ----------------------------------------------------------------------------

func osVersionInfo() (name, version string, build uint32, ok bool) {
	var vi OSVERSIONINFOW
	vi.OSVersionInfoSize = uint32(unsafe.Sizeof(vi))
	r, _, _ := pRtlGetVersion.Call(uintptr(unsafe.Pointer(&vi)))
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
	case vi.MajorVersion == 10 && build >= 19043:
		name = "Windows 10 21H1"
	case vi.MajorVersion == 10 && build >= 19042:
		name = "Windows 10 20H2"
	case vi.MajorVersion == 10 && build >= 19041:
		name = "Windows 10 2004"
	case vi.MajorVersion == 10 && build >= 17763:
		name = "Windows 10 1809 / Server 2019"
	case vi.MajorVersion == 10 && build >= 17134:
		name = "Windows 10 1803"
	case vi.MajorVersion == 10 && build >= 16299:
		name = "Windows 10 1709"
	case vi.MajorVersion == 10 && build >= 14393:
		name = "Windows 10 1607 / Server 2016"
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
	return name, version, build, true
}

func systemInfo() (string, uint32) {
	var si SYSTEM_INFO
	pGetNativeSystemInfo.Call(uintptr(unsafe.Pointer(&si)))
	return archName(si.ProcessorArchitecture), si.NumberOfProcessors
}

func isAdmin() bool {
	h, _, _ := pGetCurrentProcess.Call()
	if h == 0 {
		return false
	}
	var token syscall.Handle
	r, _, _ := pOpenProcessToken.Call(h, TOKEN_QUERY, uintptr(unsafe.Pointer(&token)))
	if r == 0 {
		return false
	}
	defer syscall.CloseHandle(token)
	var elev TOKEN_ELEVATION
	var size uint32
	r, _, _ = pGetTokenInformation.Call(uintptr(token), TokenElevation,
		uintptr(unsafe.Pointer(&elev)), uintptr(unsafe.Sizeof(elev)),
		uintptr(unsafe.Pointer(&size)))
	if r == 0 {
		return false
	}
	return elev.TokenIsElevated != 0
}

func cpName(cp uint32) string {
	switch cp {
	case 0:
		return "ansi"
	case 65001:
		return "utf-8"
	case 936:
		return "gbk"
	case 950:
		return "big5"
	case 932:
		return "shift-jis"
	case 949:
		return "euc-kr"
	case 1252:
		return "windows-1252"
	case 1251:
		return "windows-1251"
	case 1250:
		return "windows-1250"
	case 1253:
		return "windows-1253"
	case 1254:
		return "windows-1254"
	case 1255:
		return "windows-1255"
	case 1256:
		return "windows-1256"
	case 1257:
		return "windows-1257"
	case 1258:
		return "windows-1258"
	case 437:
		return "cp437"
	case 850:
		return "cp850"
	case 852:
		return "cp852"
	case 866:
		return "cp866"
	}
	return fmt.Sprintf("cp%d", cp)
}

// ----------------------------------------------------------------------------
// Exe-relative paths
// ----------------------------------------------------------------------------

func exeDir() string {
	if e, err := os.Executable(); err == nil {
		return filepath.Dir(e)
	}
	if w, err := os.Getwd(); err == nil {
		return w
	}
	return "."
}

func exePath() string {
	if e, err := os.Executable(); err == nil {
		return e
	}
	return "doctor.exe"
}

// ----------------------------------------------------------------------------
// Backup directory writability
// ----------------------------------------------------------------------------

// backupDirNames is every tool's log directory. They all live next to the
// executable.
var backupDirNames = []string{
	"procctl_backup",
	"fsctl_backup",
	"svcctl_backup",
	"taskctl_backup",
	"netctl_backup",
	"evtctl_backup",
	"openerctl_backup",
	"pectl_backup",
	"backupctl_backup",
	"doctor_backup",
}

// isDirWritable tries to create and delete a test file inside dir. If dir
// does not exist yet, it checks dir's parent directory instead, because that
// is what we would need in order to create it.
func isDirWritable(dir string) (bool, string) {
	probe := dir
	if fi, err := os.Stat(dir); err != nil {
		// Does not exist: probe the parent, since that is what we would need
		// to write to in order to create it.
		probe = filepath.Dir(dir)
	} else if !fi.IsDir() {
		return false, "exists but is not a directory"
	}
	f, err := os.CreateTemp(probe, ".doctor_probe_*")
	if err != nil {
		return false, err.Error()
	}
	name := f.Name()
	f.Close()
	_ = os.Remove(name)
	return true, ""
}

// ----------------------------------------------------------------------------
// Tool integrity
// ----------------------------------------------------------------------------

var expectedTools = []string{
	"procctl.exe",
	"fsctl.exe",
	"svcctl.exe",
	"taskctl.exe",
	"netctl.exe",
	"evtctl.exe",
	"openerctl.exe",
	"pectl.exe",
	"backupctl.exe",
}

type toolInfo struct {
	Name    string
	Path    string
	Exists  bool
	ValidPE bool
	Machine string
	Bits    string
	Size    int64
	Error   string
}

func checkTool(dir, name string) toolInfo {
	t := toolInfo{
		Name: name,
		Path: filepath.Join(dir, name),
	}
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
	case 0x8664:
		t.Bits = "64-bit"
	case 0xAA64:
		t.Bits = "64-bit"
	case 0x014C:
		t.Bits = "32-bit"
	case 0x01C4:
		t.Bits = "32-bit"
	case 0x0200:
		t.Bits = "64-bit"
	default:
		t.Bits = "unknown"
	}
	return t
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

// ----------------------------------------------------------------------------
// Run all checks
// ----------------------------------------------------------------------------

func runChecks() []CheckResult {
	var results []CheckResult
	exe := exeDir()

	// --- System ---
	winName, winVer, winBuild, winOK := osVersionInfo()
	if winOK {
		results = append(results, CheckResult{
			Category: "system", Name: "Windows",
			Status: "ok",
			Value:  fmt.Sprintf("%s (%s, build %d)", winName, winVer, winBuild),
		})
	} else {
		results = append(results, CheckResult{
			Category: "system", Name: "Windows",
			Status: "error", Value: "RtlGetVersion failed",
		})
	}

	sysArch, cpus := systemInfo()
	results = append(results, CheckResult{
		Category: "system", Name: "System arch",
		Status: "ok", Value: fmt.Sprintf("%s, %d logical CPU(s)", sysArch, cpus),
	})

	// The build tag ensures amd64, and unsafe.Sizeof(uintptr) confirms it.
	ptrSize := int(unsafe.Sizeof(uintptr(0)))
	processArch := runtime.GOARCH
	if ptrSize != 8 {
		results = append(results, CheckResult{
			Category: "system", Name: "Process arch",
			Status: "warn",
			Value:  fmt.Sprintf("%s (%d-bit pointer)", processArch, ptrSize*8),
			Detail: "this binary is supposed to be 64-bit; something is wrong with the build",
		})
	} else {
		results = append(results, CheckResult{
			Category: "system", Name: "Process arch",
			Status: "ok",
			Value:  fmt.Sprintf("%s (64-bit, %d-byte pointers)", processArch, ptrSize),
		})
	}

	// --- Security ---
	if isAdmin() {
		results = append(results, CheckResult{
			Category: "security", Name: "Admin rights",
			Status: "ok", Value: "yes (elevated)",
		})
	} else {
		results = append(results, CheckResult{
			Category: "security", Name: "Admin rights",
			Status: "info",
			Value:  "no (running as standard user)",
			Detail: "operations that touch HKLM, services, or system tasks will need elevation",
		})
	}

	// --- Encoding ---
	acpRaw, _, _ := pGetACP.Call()
	acp := uint32(acpRaw)
	oemRaw, _, _ := pGetOEMCP.Call()
	oem := uint32(oemRaw)
	outCPRaw, _, _ := pGetConsoleOutputCP.Call()
	outCP := uint32(outCPRaw)

	results = append(results, CheckResult{
		Category: "encoding", Name: "Console output CP",
		Status: "ok", Value: fmt.Sprintf("%d (%s)", outCP, cpName(outCP)),
	})
	results = append(results, CheckResult{
		Category: "encoding", Name: "ANSI code page",
		Status: "ok", Value: fmt.Sprintf("%d (%s)", acp, cpName(acp)),
	})
	results = append(results, CheckResult{
		Category: "encoding", Name: "OEM code page",
		Status: "ok", Value: fmt.Sprintf("%d (%s)", oem, cpName(oem)),
	})
	if outCP != 65001 && outCP != acp {
		results = append(results, CheckResult{
			Category: "encoding", Name: "Encoding note",
			Status: "info",
			Value:  "console output CP differs from ACP",
			Detail: "some tools may need chcp 65001 before printing non-ASCII",
		})
	}

	// --- Long paths ---
	if v, ok := regReadDWORD(HKEY_LOCAL_MACHINE,
		`SYSTEM\CurrentControlSet\Control\FileSystem`, "LongPathsEnabled"); ok {
		if v != 0 {
			results = append(results, CheckResult{
				Category: "system", Name: "Long paths",
				Status: "ok", Value: "enabled (LongPathsEnabled=1)",
			})
		} else {
			results = append(results, CheckResult{
				Category: "system", Name: "Long paths",
				Status: "warn", Value: "disabled (LongPathsEnabled=0)",
				Detail: "paths longer than MAX_PATH will fail; enable with: reg add HKLM\\SYSTEM\\CurrentControlSet\\Control\\FileSystem /v LongPathsEnabled /t REG_DWORD /d 1 /f",
			})
		}
	} else {
		results = append(results, CheckResult{
			Category: "system", Name: "Long paths",
			Status: "warn", Value: "not configured (LongPathsEnabled missing)",
			Detail: "treat as disabled; paths longer than MAX_PATH will fail",
		})
	}

	// --- Backup directories ---
	for _, name := range backupDirNames {
		dir := filepath.Join(exe, name)
		writable, why := isDirWritable(dir)
		if writable {
			results = append(results, CheckResult{
				Category: "backup", Name: name,
				Status: "ok", Value: dir,
			})
		} else {
			results = append(results, CheckResult{
				Category: "backup", Name: name,
				Status: "error", Value: dir,
				Detail: why,
			})
		}
	}

	// --- Tools ---
	curExe := strings.ToLower(filepath.Base(exePath()))
	for _, name := range expectedTools {
		if strings.ToLower(name) == curExe {
			continue
		}
		t := checkTool(exe, name)
		switch {
		case !t.Exists:
			results = append(results, CheckResult{
				Category: "tools", Name: t.Name,
				Status: "warn", Value: "missing",
				Detail: t.Path,
			})
		case t.Error != "":
			results = append(results, CheckResult{
				Category: "tools", Name: t.Name,
				Status: "error",
				Value:  fmt.Sprintf("%d bytes", t.Size),
				Detail: t.Error,
			})
		case !t.ValidPE:
			results = append(results, CheckResult{
				Category: "tools", Name: t.Name,
				Status: "error",
				Value:  "not a valid PE",
				Detail: t.Path,
			})
		case t.Bits != "64-bit":
			results = append(results, CheckResult{
				Category: "tools", Name: t.Name,
				Status: "error",
				Value:  fmt.Sprintf("%s (%s), %s", t.Bits, t.Machine, humanBytes(uint64(t.Size))),
				Detail: "expected a 64-bit executable",
			})
		default:
			results = append(results, CheckResult{
				Category: "tools", Name: t.Name,
				Status: "ok",
				Value:  fmt.Sprintf("64-bit, %s", humanBytes(uint64(t.Size))),
			})
		}
	}

	return results
}

// ============================================================================
// Output
// ============================================================================

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

func statusLabel(status string) string {
	switch status {
	case "ok":
		return "ok"
	case "warn":
		return "WARN"
	case "error":
		return "FAIL"
	case "info":
		return "info"
	}
	return status
}

func statusColor(status string) string {
	switch status {
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

func printInteractive(results []CheckResult) {
	fmt.Println()
	fmt.Println(c(clrBold+clrCyan, "════════════════════════════════════════════════════════════════"))
	fmt.Println(c(clrBold+clrCyan, "  doctor v1.0.0 — Windows Environment Diagnostics"))
	fmt.Printf("  %s\n", c(clrGray, "Generated: "+time.Now().Format("2006-01-02 15:04:05")))
	fmt.Println(c(clrBold+clrCyan, "════════════════════════════════════════════════════════════════"))

	groups := map[string][]CheckResult{}
	var order []string
	for _, r := range results {
		if _, ok := groups[r.Category]; !ok {
			order = append(order, r.Category)
		}
		groups[r.Category] = append(groups[r.Category], r)
	}

	for _, cat := range order {
		fmt.Println()
		fmt.Println(c(clrBold+clrCyan, "["+strings.Title(cat)+"]"))
		for _, r := range groups[cat] {
			label := statusLabel(r.Status)
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
				c(statusColor(r.Status), labelPad),
				padRight(r.Name, nameW),
				valueStr)
			if r.Detail != "" {
				fmt.Printf("  %s  %s  %s\n",
					"    ",
					strings.Repeat(" ", nameW),
					c(clrGray, r.Detail))
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
	summary := fmt.Sprintf("  %d check(s), %d warning(s), %d error(s)",
		len(results), warns, errors)
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

func printReport(results []CheckResult) {
	fmt.Println("================================================================")
	fmt.Println("doctor v1.0.0 - Windows Environment Diagnostics")
	fmt.Println("Generated: " + time.Now().Format("2006-01-02 15:04:05"))
	fmt.Println("================================================================")

	groups := map[string][]CheckResult{}
	var order []string
	for _, r := range results {
		if _, ok := groups[r.Category]; !ok {
			order = append(order, r.Category)
		}
		groups[r.Category] = append(groups[r.Category], r)
	}

	for _, cat := range order {
		fmt.Println()
		fmt.Println("[" + strings.Title(cat) + "]")
		for _, r := range groups[cat] {
			fmt.Printf("  %-22s %-5s %s\n", r.Name, "["+statusLabel(r.Status)+"]", r.Value)
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
	fmt.Printf("Summary: %d check(s), %d warning(s), %d error(s)\n",
		len(results), warns, errors)
	fmt.Println("----------------------------------------------------------------")
}

func printJSON(results []CheckResult) {
	b, _ := json.MarshalIndent(results, "", "  ")
	fmt.Println(string(b))
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
// Logging
// ============================================================================

const (
	backupDirName = "doctor_backup"
	logFileName   = "doctor.log"
)

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
// --history / --rollback
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
	fmt.Fprintln(os.Stderr, "doctor is read-only: there are no operations to roll back")
	fmt.Fprintln(os.Stderr, "  doctor only inspects the environment and prints a report.")
	fmt.Fprintln(os.Stderr, "  Its history is for audit only; use --history to view it.")
	return 0
}

// ============================================================================
// Help
// ============================================================================

func printHelp() {
	header := "doctor v1.0.0 (Windows)"
	fmt.Println(c(clrBold+clrCyan, header))
	fmt.Println("Windows environment diagnostics (read-only)")
	fmt.Println()
	fmt.Print(`USAGE
  doctor                     run diagnostics, colored output
  doctor --report            run diagnostics, plain text (easy to copy)
  doctor --json              run diagnostics, JSON output
  doctor --history
  doctor --rollback          (always a no-op: doctor is read-only)

WHAT IS CHECKED
  [System]
    Windows          version, edition, build (from RtlGetVersion)
    System arch      native architecture, logical CPU count
    Process arch     architecture of the running doctor.exe
    Long paths       HKLM\SYSTEM\CurrentControlSet\Control\FileSystem\
                       LongPathsEnabled

  [Security]
    Admin rights     whether the current token is elevated

  [Encoding]
    Console output CP, ANSI code page, OEM code page, with names

  [Backup]
    For each sibling tool's log directory (procctl_backup, fsctl_backup,
    svcctl_backup, taskctl_backup, netctl_backup, evtctl_backup,
    openerctl_backup, pectl_backup, backupctl_backup, doctor_backup):
      exists, is a directory, and is writable
    If a directory does not exist yet, its parent directory is probed
    instead, because that is what would need to be writable to create it.

  [Tools]
    Every expected sibling executable next to doctor.exe:
      procctl.exe fsctl.exe svcctl.exe taskctl.exe netctl.exe
      evtctl.exe openerctl.exe pectl.exe backupctl.exe
    For each file that exists: PE header parses, machine type is 64-bit,
    file size. Missing files are reported as warnings.

GLOBAL
  -o, --out <path>     Redirect stdout to a file
  --dry-run            Print the plan without running any checks
  --no-color           Disable ANSI colors (also honors NO_COLOR)
  -b, --bugs           Print collected errors/warnings on exit
  -h, --help           Show this help
  --version            Show version

HISTORY
  Every invocation (except -h/--help/--version/--history/--rollback/--dry-run)
  appends one line to ./doctor_backup/doctor.log:
    [command line] [timestamp] [exit code]
  --history prints it, numbered from newest (1) to oldest.

READ-ONLY BY DESIGN
  doctor never modifies the system. The only write it performs is the
  writability probe (a temp file created and immediately deleted inside
  each backup directory, or in the executable's directory when the
  backup directory does not exist yet).

EXIT CODES
  0 all checks passed (or only warnings)
  1 at least one error was reported
  2 bad args
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
		case a == "--report":
			reportMode = true
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
		fmt.Fprintf(os.Stderr, "doctor: %v\n", err)
		bugs.Flush()
		os.Exit(2)
	}

	if noColorFlag || os.Getenv("NO_COLOR") != "" || reportMode {
		useColor = false
	} else if stdoutIsTTY() {
		useColor = true
	}

	if has(args, "--version") {
		fmt.Println("doctor v1.0.0")
		finalExit(0, false)
	}
	if len(args) == 0 {
		// default action: run checks
	} else if has(args, "-h", "--help") {
		printHelp()
		finalExit(0, false)
	} else if has(args, "--history") {
		finalExit(cmdHistory(), false)
	} else if has(args, "--rollback") {
		finalExit(cmdRollback(), false)
	} else {
		// Unknown positional argument: doctor has no subcommands
		fmt.Fprintf(os.Stderr, "doctor: unexpected argument %q (use -h for help)\n", args[0])
		finalExit(2, true)
	}

	if outPath != "" {
		if err := setupOutput(outPath); err != nil {
			fmt.Fprintf(os.Stderr, "doctor: %v\n", err)
			bugs.Flush()
			os.Exit(2)
		}
	}

	if dryRun {
		fmt.Printf("[dry-run] would run %d backup-dir probes\n", len(backupDirNames))
		fmt.Printf("[dry-run] would check %d sibling executables\n", len(expectedTools))
		fmt.Printf("[dry-run] would query OS version, encoding, long paths, and admin rights\n")
		finalExit(0, false)
	}

	results := runChecks()

	if reportMode {
		printReport(results)
	} else if has(args, "--json") || hasReportJSON(args) {
		printJSON(results)
	} else {
		printInteractive(results)
	}

	// Exit code: 1 if any errors, otherwise 0. Warnings do not fail the run.
	exitCode := 0
	for _, r := range results {
		if r.Status == "error" {
			exitCode = 1
			break
		}
	}
	finalExit(exitCode, true)
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

func hasReportJSON(args []string) bool {
	for _, a := range args {
		if a == "--json" {
			return true
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

// Suppress unused-import warnings for helpers that are useful across the
// codebase but not always referenced.
var (
	_ = sort.Strings
	_ = strconv.Itoa
)