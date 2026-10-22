//go:build windows && amd64

package main

// svcctl — Windows service manager with rollback.
// Single-file, standard-library-only build:
//
//   go build -trimpath -ldflags "-s -w" -o svcctl.exe svcctl.go

import (
	"encoding/json"
	"fmt"
	"os"
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
		fmt.Fprintln(os.Stderr, "[svcctl] -b/--bugs enabled: no errors or warnings captured this run.")
		return
	}
	fmt.Fprintf(os.Stderr, "\n--- svcctl bugs report (%d entries) ---\n", len(b.entries))
	for _, e := range b.entries {
		fmt.Fprintf(os.Stderr, "[%s] %s %s\n", e.At.Format("15:04:05.000"), e.Level, e.Msg)
	}
	fmt.Fprintln(os.Stderr, "--- end of bugs report ---")
}

// ============================================================================
// Windows SCM API bindings
// ============================================================================

var (
	advapi32 = syscall.NewLazyDLL("advapi32.dll")

	pOpenSCManagerW        = advapi32.NewProc("OpenSCManagerW")
	pCloseServiceHandle    = advapi32.NewProc("CloseServiceHandle")
	pEnumServicesStatusExW = advapi32.NewProc("EnumServicesStatusExW")
	pOpenServiceW          = advapi32.NewProc("OpenServiceW")
	pQueryServiceStatus    = advapi32.NewProc("QueryServiceStatus")
	pQueryServiceConfigW   = advapi32.NewProc("QueryServiceConfigW")
	pChangeServiceConfigW  = advapi32.NewProc("ChangeServiceConfigW")
	pStartServiceW         = advapi32.NewProc("StartServiceW")
	pControlService        = advapi32.NewProc("ControlService")
)

const (
	SC_MANAGER_ALL_ACCESS  = 0xF003F
	SERVICE_ALL_ACCESS     = 0xF01FF
	SERVICE_QUERY_CONFIG   = 0x0001
	SERVICE_CHANGE_CONFIG  = 0x0002
	SERVICE_QUERY_STATUS   = 0x0004
	SERVICE_START          = 0x0010
	SERVICE_STOP           = 0x0020
	SERVICE_PAUSE_CONTINUE = 0x0040
	SERVICE_NO_CHANGE      = 0xFFFFFFFF

	SERVICE_WIN32_OWN_PROCESS   = 0x00000010
	SERVICE_WIN32_SHARE_PROCESS = 0x00000020
	SERVICE_INTERACTIVE_PROCESS = 0x00000100
	SERVICE_KERNEL_DRIVER       = 0x00000001
	SERVICE_FILE_SYSTEM_DRIVER  = 0x00000002

	SERVICE_BOOT_START   = 0x00000000
	SERVICE_SYSTEM_START = 0x00000001
	SERVICE_AUTO_START   = 0x00000002
	SERVICE_DEMAND_START = 0x00000003
	SERVICE_DISABLED     = 0x00000004

	SERVICE_STOPPED          = 0x00000001
	SERVICE_START_PENDING    = 0x00000002
	SERVICE_STOP_PENDING     = 0x00000003
	SERVICE_RUNNING          = 0x00000004
	SERVICE_CONTINUE_PENDING = 0x00000005
	SERVICE_PAUSE_PENDING    = 0x00000006
	SERVICE_PAUSED           = 0x00000007

	SERVICE_CONTROL_STOP        = 0x00000001
	SERVICE_CONTROL_PAUSE       = 0x00000002
	SERVICE_CONTROL_CONTINUE    = 0x00000003
	SERVICE_CONTROL_INTERROGATE = 0x00000004

	SC_ENUM_PROCESS_INFO = 0
	SERVICE_ACTIVE       = 0x00000001
	SERVICE_INACTIVE     = 0x00000002
	SERVICE_STATE_ALL    = SERVICE_ACTIVE | SERVICE_INACTIVE

	ERROR_SERVICE_ALREADY_RUNNING = syscall.Errno(1056)
	ERROR_SERVICE_NOT_ACTIVE      = syscall.Errno(1062)
	ERROR_SERVICE_DISABLED        = syscall.Errno(1058)
	ERROR_SERVICE_DOES_NOT_EXIST  = syscall.Errno(1060)
)

type SERVICE_STATUS struct {
	ServiceType             uint32
	CurrentState            uint32
	ControlsAccepted        uint32
	Win32ExitCode           uint32
	ServiceSpecificExitCode uint32
	CheckPoint              uint32
	WaitHint                uint32
}

type ENUM_SERVICE_STATUS_PROCESSW struct {
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

type QUERY_SERVICE_CONFIGW struct {
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

func closeHandle(h syscall.Handle) {
	pCloseServiceHandle.Call(uintptr(h))
}

func queryServiceStatus(h syscall.Handle) (*SERVICE_STATUS, error) {
	var st SERVICE_STATUS
	r, _, err := pQueryServiceStatus.Call(uintptr(h), uintptr(unsafe.Pointer(&st)))
	if r == 0 {
		return nil, err
	}
	return &st, nil
}

func queryServiceConfig(h syscall.Handle) (*QUERY_SERVICE_CONFIGW, error) {
	var needed uint32
	pQueryServiceConfigW.Call(uintptr(h), 0, 0, uintptr(unsafe.Pointer(&needed)))
	if needed == 0 {
		return nil, fmt.Errorf("QueryServiceConfig: cannot determine size")
	}
	buf := make([]byte, needed)
	r, _, err := pQueryServiceConfigW.Call(uintptr(h),
		uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)),
		uintptr(unsafe.Pointer(&needed)))
	if r == 0 {
		return nil, err
	}
	cfg := (*QUERY_SERVICE_CONFIGW)(unsafe.Pointer(&buf[0]))
	return cfg, nil
}

func changeStartType(h syscall.Handle, startType uint32) error {
	r, _, err := pChangeServiceConfigW.Call(uintptr(h),
		uintptr(SERVICE_NO_CHANGE), uintptr(startType), uintptr(SERVICE_NO_CHANGE),
		0, 0, 0, 0, 0, 0, 0)
	if r == 0 {
		return err
	}
	return nil
}

func startService(h syscall.Handle) error {
	r, _, err := pStartServiceW.Call(uintptr(h), 0, 0)
	if r == 0 {
		if errno, ok := err.(syscall.Errno); ok && errno == ERROR_SERVICE_ALREADY_RUNNING {
			return nil
		}
		return err
	}
	return nil
}

func controlService(h syscall.Handle, code uint32) error {
	var st SERVICE_STATUS
	r, _, err := pControlService.Call(uintptr(h), uintptr(code), uintptr(unsafe.Pointer(&st)))
	if r == 0 {
		return err
	}
	return nil
}

func waitForState(h syscall.Handle, want uint32, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		st, err := queryServiceStatus(h)
		if err != nil {
			return err
		}
		if st.CurrentState == want {
			return nil
		}
		if st.CurrentState == SERVICE_STOPPED && want != SERVICE_STOPPED {
			return fmt.Errorf("service stopped unexpectedly")
		}
		time.Sleep(200 * time.Millisecond)
	}
	return fmt.Errorf("timeout waiting for state 0x%X", want)
}

// ============================================================================
// Service enumeration
// ============================================================================

type ServiceInfo struct {
	Name        string
	DisplayName string
	State       uint32
	StartType   uint32
	BinaryPath  string
	Deps        []string
}

func enumServices(scm syscall.Handle) ([]ServiceInfo, error) {
	var needed, returned, resume uint32

	pEnumServicesStatusExW.Call(uintptr(scm), SC_ENUM_PROCESS_INFO,
		SERVICE_WIN32_OWN_PROCESS|SERVICE_WIN32_SHARE_PROCESS|SERVICE_KERNEL_DRIVER|SERVICE_FILE_SYSTEM_DRIVER,
		SERVICE_STATE_ALL, 0, 0,
		uintptr(unsafe.Pointer(&needed)), uintptr(unsafe.Pointer(&returned)),
		uintptr(unsafe.Pointer(&resume)), 0)

	if needed == 0 {
		return nil, fmt.Errorf("EnumServicesStatusEx: cannot determine size")
	}

	buf := make([]byte, needed+8192)
	r, _, err := pEnumServicesStatusExW.Call(uintptr(scm), SC_ENUM_PROCESS_INFO,
		SERVICE_WIN32_OWN_PROCESS|SERVICE_WIN32_SHARE_PROCESS|SERVICE_KERNEL_DRIVER|SERVICE_FILE_SYSTEM_DRIVER,
		SERVICE_STATE_ALL, uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)),
		uintptr(unsafe.Pointer(&needed)), uintptr(unsafe.Pointer(&returned)),
		uintptr(unsafe.Pointer(&resume)), 0)

	if r == 0 {
		return nil, fmt.Errorf("EnumServicesStatusEx: %w", err)
	}

	entrySize := int(unsafe.Sizeof(ENUM_SERVICE_STATUS_PROCESSW{}))
	out := make([]ServiceInfo, 0, returned)
	for i := uint32(0); i < returned; i++ {
		off := int(i) * entrySize
		ep := (*ENUM_SERVICE_STATUS_PROCESSW)(unsafe.Pointer(&buf[off]))
		out = append(out, ServiceInfo{
			Name:        syscall.UTF16ToString(unsafe.Slice(ep.ServiceName, 256)),
			DisplayName: syscall.UTF16ToString(unsafe.Slice(ep.DisplayName, 256)),
			State:       ep.ServiceStatusProcess.CurrentState,
		})
	}

	for i := range out {
		h, err := openService(scm, out[i].Name, SERVICE_QUERY_CONFIG|SERVICE_QUERY_STATUS)
		if err != nil {
			continue
		}
		cfg, err := queryServiceConfig(h)
		if err == nil {
			out[i].StartType = cfg.StartType
			if cfg.BinaryPathName != nil {
				out[i].BinaryPath = syscall.UTF16ToString(unsafe.Slice(cfg.BinaryPathName, 1024))
			}
			out[i].Deps = splitDeps(cfg.Dependencies)
		}
		closeHandle(h)
	}
	return out, nil
}

func splitDeps(p *uint16) []string {
	if p == nil {
		return nil
	}
	var out []string
	cur := p
	for {
		s := syscall.UTF16ToString(unsafe.Slice(cur, 1024))
		if s == "" {
			break
		}
		out = append(out, s)
		cur = (*uint16)(unsafe.Add(unsafe.Pointer(cur), (len(s)+1)*2))
	}
	return out
}

// ============================================================================
// Human-readable names
// ============================================================================

func stateName(s uint32) string {
	switch s {
	case SERVICE_STOPPED:
		return "stopped"
	case SERVICE_START_PENDING:
		return "start-pending"
	case SERVICE_STOP_PENDING:
		return "stop-pending"
	case SERVICE_RUNNING:
		return "running"
	case SERVICE_CONTINUE_PENDING:
		return "continue-pending"
	case SERVICE_PAUSE_PENDING:
		return "pause-pending"
	case SERVICE_PAUSED:
		return "paused"
	}
	return fmt.Sprintf("0x%X", s)
}

func startTypeName(s uint32) string {
	switch s {
	case SERVICE_BOOT_START:
		return "boot"
	case SERVICE_SYSTEM_START:
		return "system"
	case SERVICE_AUTO_START:
		return "auto"
	case SERVICE_DEMAND_START:
		return "manual"
	case SERVICE_DISABLED:
		return "disabled"
	}
	return fmt.Sprintf("0x%X", s)
}

func stateColor(s uint32) string {
	switch s {
	case SERVICE_RUNNING:
		return clrGreen
	case SERVICE_STOPPED:
		return clrGray
	case SERVICE_PAUSED:
		return clrYellow
	}
	return clrCyan
}

func startTypeColor(s uint32) string {
	switch s {
	case SERVICE_AUTO_START:
		return clrGreen
	case SERVICE_DEMAND_START:
		return clrCyan
	case SERVICE_DISABLED:
		return clrRed
	}
	return clrYellow
}

// ============================================================================
// Display-width helpers (CJK-aware, ANSI-safe when applied before color)
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
// Paths, log
// ============================================================================

const (
	backupDirName = "svcctl_backup"
	logFileName   = "svcctl.log"
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

func backupRoot() string { return filepath.Join(exeDir(), backupDirName) }
func logPath() string    { return filepath.Join(backupRoot(), logFileName) }
func opsDir() string     { return filepath.Join(backupRoot(), opsDirName) }

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
	_ = os.MkdirAll(backupRoot(), 0755)
	f, err := os.OpenFile(logPath(), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		bugs.Add("ERR", "open log: %v", err)
		return
	}
	defer f.Close()
	ts := time.Now().Format("2006-01-02 15:04:05")
	_, _ = fmt.Fprintf(f, "[%s] [%s] [%d]\n", cmd, ts, code)
}

var logRe = regexp.MustCompile(`^\[(.*)\] \[(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\] \[(-?\d+)\]$`)

func parseLogLine(line string) (cmd string, ok bool) {
	m := logRe.FindStringSubmatch(line)
	if m == nil {
		return "", false
	}
	return m[1], true
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
// State manifests
// ============================================================================

type svcSnapshot struct {
	Name      string `json:"name"`
	StartType uint32 `json:"startType"`
	State     uint32 `json:"state"`
}

type opRecord struct {
	Op     string        `json:"op"`
	TS     string        `json:"ts"`
	Cmd    string        `json:"cmd"`
	Code   int           `json:"code"`
	Before []svcSnapshot `json:"before"`
	After  []svcSnapshot `json:"after,omitempty"`
}

func mustJSON(v any) []byte {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return []byte("null")
	}
	return b
}

func saveOpRecord(idx int, rec *opRecord) {
	_ = os.MkdirAll(opsDir(), 0755)
	p := filepath.Join(opsDir(), fmt.Sprintf("%d.json", idx))
	if err := os.WriteFile(p, mustJSON(rec), 0644); err != nil {
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
	_ = os.MkdirAll(backupRoot(), 0755)
	_ = os.MkdirAll(opsDir(), 0755)
	return countLogLines()
}

// ============================================================================
// Resolve / snapshot
// ============================================================================

func resolveService(scm syscall.Handle, target string) (string, error) {
	if h, err := openService(scm, target, SERVICE_QUERY_STATUS); err == nil {
		closeHandle(h)
		return target, nil
	}
	svcs, err := enumServices(scm)
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

func snapshotService(scm syscall.Handle, name string) (svcSnapshot, error) {
	h, err := openService(scm, name, SERVICE_QUERY_CONFIG|SERVICE_QUERY_STATUS)
	if err != nil {
		return svcSnapshot{}, err
	}
	defer closeHandle(h)

	cfg, err := queryServiceConfig(h)
	if err != nil {
		return svcSnapshot{}, err
	}
	st, err := queryServiceStatus(h)
	if err != nil {
		return svcSnapshot{}, err
	}
	return svcSnapshot{
		Name:      name,
		StartType: cfg.StartType,
		State:     st.CurrentState,
	}, nil
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
// ls
// ============================================================================

func cmdLs(args []string) int {
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

	scm, err := openSCM()
	if err != nil {
		fmt.Fprintf(os.Stderr, "svcctl: %v\n", err)
		return 5
	}
	defer closeHandle(scm)

	svcs, err := enumServices(scm)
	if err != nil {
		fmt.Fprintf(os.Stderr, "svcctl: %v\n", err)
		return 5
	}

	if len(rest) > 0 {
		filtered := make([]ServiceInfo, 0, len(svcs))
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
		filtered := make([]ServiceInfo, 0, len(svcs))
		for _, s := range svcs {
			if stateFilter == "running" && s.State == SERVICE_RUNNING {
				filtered = append(filtered, s)
			}
			if stateFilter == "stopped" && s.State == SERVICE_STOPPED {
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
				"name":        s.Name,
				"displayName": s.DisplayName,
				"state":       stateName(s.State),
				"startType":   startTypeName(s.StartType),
				"binaryPath":  s.BinaryPath,
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

	// Dynamic column widths: never truncate, pad only to align.
	nameW := dispWidth("NAME")
	dispW := dispWidth("DISPLAY NAME")
	stateW := dispWidth("STATE")
	startW := dispWidth("START")
	for _, s := range svcs {
		if w := dispWidth(s.Name); w > nameW {
			nameW = w
		}
		if w := dispWidth(s.DisplayName); w > dispW {
			dispW = w
		}
		if w := dispWidth(stateName(s.State)); w > stateW {
			stateW = w
		}
		if w := dispWidth(startTypeName(s.StartType)); w > startW {
			startW = w
		}
	}

	header := padRight("NAME", nameW) + " " +
		padRight("DISPLAY NAME", dispW) + " " +
		padRight("STATE", stateW) + " " +
		padRight("START", startW) + " " +
		"BINARY"
	fmt.Println(c(clrBold+clrCyan, header))

	for _, s := range svcs {
		line := padRight(s.Name, nameW) + " " +
			padRight(s.DisplayName, dispW) + " " +
			c(stateColor(s.State), padRight(stateName(s.State), stateW)) + " " +
			c(startTypeColor(s.StartType), padRight(startTypeName(s.StartType), startW)) + " " +
			c(clrGray, s.BinaryPath)
		if !noDeps && len(s.Deps) > 0 {
			line += c(clrGray, "  deps="+strings.Join(s.Deps, ","))
		}
		fmt.Println(line)
	}
	fmt.Fprintf(os.Stderr, "\n%d service(s)\n", len(svcs))
	return 0
}

// ============================================================================
// start / stop / pause / resume
// ============================================================================

func cmdServiceControl(args []string, action string) int {
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
		fmt.Fprintf(os.Stderr, "usage: svcctl %s [-f] <service|displayname>...\n", action)
		return 2
	}

	scm, err := openSCM()
	if err != nil {
		fmt.Fprintf(os.Stderr, "svcctl: %v\n", err)
		return 5
	}
	defer closeHandle(scm)

	names := make([]string, 0, len(targets))
	snaps := make([]svcSnapshot, 0, len(targets))
	for _, t := range targets {
		name, err := resolveService(scm, t)
		if err != nil {
			fmt.Fprintf(os.Stderr, "svcctl: %v\n", err)
			return 4
		}
		snap, err := snapshotService(scm, name)
		if err != nil {
			fmt.Fprintf(os.Stderr, "svcctl: snapshot %s: %v\n", name, err)
			return 5
		}
		names = append(names, name)
		snaps = append(snaps, snap)
	}

	// dry-run: print plan, no changes, no confirmation, no log, no backup.
	if dryRun {
		for i, n := range names {
			fmt.Printf("[dry-run] %s %s  (state=%s, start=%s)\n",
				action, n, stateName(snaps[i].State), startTypeName(snaps[i].StartType))
		}
		return 0
	}

	if len(names) > 1 && !force {
		fmt.Fprintln(os.Stderr, "about to "+action+" the following services:")
		for i, n := range names {
			fmt.Fprintf(os.Stderr, "  %-32s state=%s\n", n, stateName(snaps[i].State))
		}
		if !confirm("proceed?") {
			return 1
		}
	}

	idx := beginWriteOp()
	rec := &opRecord{
		Op:     action,
		TS:     time.Now().Format("2006-01-02 15:04:05"),
		Cmd:    buildCmdLine(os.Args),
		Before: snaps,
	}
	okCount, failCount := 0, 0
	for _, n := range names {
		h, err := openService(scm, n, SERVICE_ALL_ACCESS)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s: %v\n", n, err)
			failCount++
			continue
		}
		var serr error
		switch action {
		case "start":
			serr = startService(h)
			if serr == nil {
				serr = waitForState(h, SERVICE_RUNNING, 15*time.Second)
			}
		case "stop":
			serr = controlService(h, SERVICE_CONTROL_STOP)
			if serr == nil {
				serr = waitForState(h, SERVICE_STOPPED, 15*time.Second)
			} else if errno, ok := serr.(syscall.Errno); ok && errno == ERROR_SERVICE_NOT_ACTIVE {
				// already stopped: idempotent success
				serr = nil
			}
		case "pause":
			serr = controlService(h, SERVICE_CONTROL_PAUSE)
		case "resume", "continue":
			serr = controlService(h, SERVICE_CONTROL_CONTINUE)
		}
		closeHandle(h)
		if serr != nil {
			fmt.Fprintf(os.Stderr, "%s %s: %v\n", action, n, serr)
			bugs.Add("WARN", "%s %s: %v", action, n, serr)
			failCount++
		} else {
			fmt.Printf("%s %s\n", c(clrGreen, action), c(clrCyan, n))
			okCount++
		}
	}
	rec.After = snaps
	saveOpRecord(idx, rec)

	if failCount == 0 {
		return 0
	}
	if okCount == 0 {
		return 2
	}
	return 1
}

// ============================================================================
// start-type
// ============================================================================

func cmdStartType(args []string) int {
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
		fmt.Fprintln(os.Stderr, "usage: svcctl start-type [-f] <service>... <auto|manual|disabled>")
		return 2
	}
	levelStr := rest[len(rest)-1]
	targets := rest[:len(rest)-1]

	var newType uint32
	switch strings.ToLower(levelStr) {
	case "auto", "automatic":
		newType = SERVICE_AUTO_START
	case "manual", "demand":
		newType = SERVICE_DEMAND_START
	case "disabled", "disable":
		newType = SERVICE_DISABLED
	default:
		fmt.Fprintf(os.Stderr, "start-type: invalid level %q (use auto|manual|disabled)\n", levelStr)
		return 2
	}

	scm, err := openSCM()
	if err != nil {
		fmt.Fprintf(os.Stderr, "svcctl: %v\n", err)
		return 5
	}
	defer closeHandle(scm)

	names := make([]string, 0, len(targets))
	snaps := make([]svcSnapshot, 0, len(targets))
	for _, t := range targets {
		name, err := resolveService(scm, t)
		if err != nil {
			fmt.Fprintf(os.Stderr, "svcctl: %v\n", err)
			return 4
		}
		snap, err := snapshotService(scm, name)
		if err != nil {
			fmt.Fprintf(os.Stderr, "svcctl: snapshot %s: %v\n", name, err)
			return 5
		}
		names = append(names, name)
		snaps = append(snaps, snap)
	}

	if dryRun {
		for i, n := range names {
			fmt.Printf("[dry-run] start-type %s %s -> %s\n",
				n, startTypeName(snaps[i].StartType), levelStr)
		}
		return 0
	}

	if len(names) > 1 && !force {
		fmt.Fprintf(os.Stderr, "about to set start type to %q for:\n", levelStr)
		for i, n := range names {
			fmt.Fprintf(os.Stderr, "  %-32s current=%s\n", n, startTypeName(snaps[i].StartType))
		}
		if !confirm("proceed?") {
			return 1
		}
	}

	idx := beginWriteOp()
	rec := &opRecord{
		Op:     "start-type",
		TS:     time.Now().Format("2006-01-02 15:04:05"),
		Cmd:    buildCmdLine(os.Args),
		Before: snaps,
	}
	okCount, failCount := 0, 0
	for _, n := range names {
		h, err := openService(scm, n, SERVICE_CHANGE_CONFIG|SERVICE_QUERY_CONFIG)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s: %v\n", n, err)
			failCount++
			continue
		}
		err = changeStartType(h, newType)
		closeHandle(h)
		if err != nil {
			fmt.Fprintf(os.Stderr, "start-type %s: %v\n", n, err)
			bugs.Add("WARN", "start-type %s: %v", n, err)
			failCount++
		} else {
			fmt.Printf("%s %s -> %s\n", c(clrGreen, "start-type"), c(clrCyan, n), c(startTypeColor(newType), levelStr))
			okCount++
		}
	}
	saveOpRecord(idx, rec)

	if failCount == 0 {
		return 0
	}
	if okCount == 0 {
		return 2
	}
	return 1
}

// ============================================================================
// History
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
		cmd, ok := parseLogLine(lines[i])
		if !ok || isHistorySelf(cmd) {
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

func summarizeOp(rec *opRecord) string {
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
			parts = append(parts, b.Name+"->"+startTypeName(b.StartType))
		}
		return "-> restore start type: " + strings.Join(parts, ", ")
	}
	return ""
}

// ============================================================================
// Rollback
// ============================================================================

func cmdRollback(args []string) int {
	target := ""
	var names []string
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "-n", "--last":
			if i+1 >= len(args) {
				fmt.Fprintln(os.Stderr, "rollback: -n requires a number")
				return 2
			}
			target = args[i+1]
			i++
		case "--service":
			if i+1 >= len(args) {
				fmt.Fprintln(os.Stderr, "rollback: --service requires a name")
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

	lines, err := readLogLines()
	if err != nil {
		fmt.Fprintf(os.Stderr, "read log: %v\n", err)
		return 4
	}

	type targetRec struct {
		idx int
		rec *opRecord
	}
	var targets []targetRec

	if len(names) > 0 {
		want := map[string]bool{}
		for _, n := range names {
			want[strings.ToLower(n)] = true
		}
		for i := len(lines) - 1; i >= 0; i-- {
			if !manifestExists(i) {
				continue
			}
			rec, err := loadOpRecord(i)
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
				fmt.Fprintln(os.Stderr, "rollback: -n expects a positive number")
				return 2
			}
			n = v
		}
		for i := len(lines) - 1; i >= 0 && len(targets) < n; i-- {
			if !manifestExists(i) {
				continue
			}
			rec, err := loadOpRecord(i)
			if err != nil {
				continue
			}
			targets = append(targets, targetRec{i, rec})
		}
	}

	if len(targets) == 0 {
		fmt.Fprintln(os.Stderr, "no rollback-able operations found")
		return 4
	}

	// dry-run: print plan without touching anything.
	if dryRun {
		for k, t := range targets {
			fmt.Printf("[dry-run] step %d: %s %s\n", k+1, t.rec.Op, summarizeOp(t.rec))
		}
		return 0
	}

	scm, err := openSCM()
	if err != nil {
		fmt.Fprintf(os.Stderr, "svcctl: %v\n", err)
		return 5
	}
	defer closeHandle(scm)

	okCount, failCount := 0, 0
	for k, t := range targets {
		fmt.Fprintf(os.Stderr, "[rollback] step %d: %s %s\n", k+1, t.rec.Op, summarizeOp(t.rec))
		if err := rollbackOne(scm, t.rec); err != nil {
			fmt.Fprintf(os.Stderr, "[rollback] step %d: error: %v\n", k+1, err)
			bugs.Add("ERR", "rollback %d: %v", t.idx, err)
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

func rollbackOne(scm syscall.Handle, rec *opRecord) error {
	for i := len(rec.Before) - 1; i >= 0; i-- {
		b := rec.Before[i]
		h, err := openService(scm, b.Name, SERVICE_ALL_ACCESS)
		if err != nil {
			return fmt.Errorf("%s: %w", b.Name, err)
		}

		if err := changeStartType(h, b.StartType); err != nil {
			closeHandle(h)
			return fmt.Errorf("%s start-type: %w", b.Name, err)
		}

		st, err := queryServiceStatus(h)
		if err == nil {
			switch b.State {
			case SERVICE_RUNNING:
				if st.CurrentState != SERVICE_RUNNING {
					_ = startService(h)
					_ = waitForState(h, SERVICE_RUNNING, 15*time.Second)
				}
			case SERVICE_STOPPED:
				if st.CurrentState != SERVICE_STOPPED {
					_ = controlService(h, SERVICE_CONTROL_STOP)
					_ = waitForState(h, SERVICE_STOPPED, 15*time.Second)
				}
			case SERVICE_PAUSED:
				if st.CurrentState == SERVICE_RUNNING {
					_ = controlService(h, SERVICE_CONTROL_PAUSE)
				} else if st.CurrentState == SERVICE_STOPPED {
					_ = startService(h)
					_ = waitForState(h, SERVICE_RUNNING, 15*time.Second)
					_ = controlService(h, SERVICE_CONTROL_PAUSE)
				}
			}
		}
		closeHandle(h)
	}
	return nil
}

// ============================================================================
// Help
// ============================================================================

func printHelp() {
	header := "svcctl v1.0.0 (Windows)"
	fmt.Println(c(clrBold+clrCyan, header))
	fmt.Println("Windows service manager - list / control / configure / rollback")
	fmt.Println()
	fmt.Print(`USAGE
  svcctl ls [OPTIONS] [filter]
  svcctl start     [-f] <service|displayname>...
  svcctl stop      [-f] <service|displayname>...
  svcctl pause     [-f] <service|displayname>...
  svcctl resume    [-f] <service|displayname>...
  svcctl start-type [-f] <service>... <auto|manual|disabled>
  svcctl --history
  svcctl --rollback [-n N] [--service name...]

LIST
  ls                   List all services
  ls <filter>          Substring match on name or display name
  ls --running         Only running services
  ls --stopped         Only stopped services
  ls --no-deps         Hide dependency column
  ls --json            JSON output

  Columns: NAME  DISPLAY NAME  STATE  START  BINARY  DEPS
  No field is truncated. Column widths expand to fit the widest row, and
  CJK / fullwidth characters are counted as 2 terminal cells so that
  Chinese display names stay aligned.

CONTROL
  start   <svc>        Start service (waits for running state)
  stop    <svc>        Stop service (waits for stopped state; stopping an
                       already-stopped service is treated as success)
  pause   <svc>        Pause service
  resume  <svc>        Resume / continue service

  <svc> is the service name (e.g. wuauserv) or, if not found, a
  case-insensitive display name (e.g. "Windows Update").

  -f, --force          Skip the confirmation prompt when operating on
                       more than one service.

START TYPE
  start-type <svc>... <level>
      level: auto | manual | disabled

GLOBAL
  -o, --out <path>     Write stdout to <path> instead of the console.
                       Works with every subcommand, including --history,
                       --rollback and --dry-run:
                         svcctl -o services.txt ls
                         svcctl ls -o services.json --json
                         svcctl --history -o history.txt
                         svcctl --dry-run -o plan.txt start Fax
                       The file is truncated if it exists. Parent
                       directories are created. Colors are disabled while
                       redirecting. stderr is not redirected, so errors
                       and warnings stay on the console.
  --dry-run            Preview only: prints the plan for each target and
                       returns without changing anything, without prompting,
                       without writing backups, and without logging.
                       Works before or after the subcommand:
                         svcctl --dry-run start Fax
                         svcctl start --dry-run Fax
                         svcctl --dry-run -f start-type Fax WMPNetworkSvc disabled
                         svcctl --dry-run --rollback -n 2
  --no-color           Disable ANSI colors (also honors NO_COLOR env var)
  -b, --bugs           Print collected errors/warnings on exit
  -h, --help           Show this help
  --version            Show version

HISTORY / ROLLBACK
  --history
      Lists rollback-able operations in reverse chronological order.
      [1] is the most recent operation.

  --rollback
      Undo the most recent operation (equivalent to -n 1).

  --rollback -n N
      Undo the most recent N operations.

  --rollback --service <name>...
      Undo every logged operation that touched any of these services,
      newest first.

  Rollback restores, for each service in the record's "before" snapshot:
    1. the original start type (auto / manual / disabled)
    2. the original running state (running / stopped / paused)
  Start type is restored first, so a service that was previously
  disabled can still be started if its "before" state was running.

LOG
  Every invocation (except -h / --help / --version / --history / --dry-run)
  appends one line to:
    ./svcctl_backup/svcctl.log
  Format:
    [command line] [timestamp] [exit code]

  Per-operation snapshots are stored as JSON in:
    ./svcctl_backup/ops/<logIndex>.json

EXIT CODES
  0 success | 1 partial failure | 2 total failure or bad args
  3 permission denied | 4 service not found | 5 Windows API / I/O error
`)
}

// ============================================================================
// Global flag consumption
// ============================================================================

// consumeGlobalFlags strips flags that apply to the whole invocation, so
// subcommand parsers never see them. This lets --dry-run / --no-color / -b /
// -o appear anywhere on the command line, including after the subcommand.
// outPath is returned separately because -o/--out takes an argument and must
// be applied after color initialization.
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

// setupOutput redirects os.Stdout to a file. Colors are disabled while the
// redirection is active, because ANSI escapes in a text file are noise.
// The original stdout is restored by the returned cleanup function.
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
		fmt.Fprintf(os.Stderr, "svcctl: %v\n", err)
		bugs.Flush()
		os.Exit(2)
	}

	if noColorFlag || os.Getenv("NO_COLOR") != "" {
		useColor = false
	} else if stdoutIsTTY() {
		useColor = true
	}

	// -o is applied after color init so that the redirect can safely clear
	// useColor. The cleanup is not deferred; finalExit() handles it so that
	// every exit path (including --version and --help) flushes the file.
	if outPath != "" {
		if err := setupOutput(outPath); err != nil {
			fmt.Fprintf(os.Stderr, "svcctl: %v\n", err)
			bugs.Flush()
			os.Exit(2)
		}
	}

	if has(args, "--version") {
		fmt.Println("svcctl v1.0.0")
		finalExit(0)
	}
	if len(args) == 0 || has(args, "-h", "--help") {
		printHelp()
		finalExit(0)
	}

	var code int
	switch {
	case has(args, "--history"):
		code = cmdHistory()
	case has(args, "--rollback"):
		code = cmdRollback(stripFlags(args, "--rollback"))
	default:
		cmdIdx := -1
		for i, a := range args {
			if !strings.HasPrefix(a, "-") {
				cmdIdx = i
				break
			}
		}
		if cmdIdx < 0 {
			fmt.Fprintln(os.Stderr, "svcctl: missing command, use -h for help")
			code = 2
			break
		}
		cmd := args[cmdIdx]
		rest := append([]string{}, args[:cmdIdx]...)
		rest = append(rest, args[cmdIdx+1:]...)

		switch cmd {
		case "ls", "list":
			code = cmdLs(rest)
		case "start":
			code = cmdServiceControl(rest, "start")
		case "stop":
			code = cmdServiceControl(rest, "stop")
		case "pause":
			code = cmdServiceControl(rest, "pause")
		case "resume", "continue":
			code = cmdServiceControl(rest, "resume")
		case "start-type", "starttype":
			code = cmdStartType(rest)
		default:
			fmt.Fprintf(os.Stderr, "svcctl: unknown command %q\n", cmd)
			code = 2
		}
	}

	finalExit(code)
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

func finalExit(code int) {
	if !dryRun && shouldLogRun() {
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
		case "-h", "--help", "--version", "--history", "--dry-run":
			return false
		}
	}
	return true
}