//go:build windows && amd64

package main

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/signal"
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
	outputCleanup func()
)

// ============================================================================
// DLL handles
// ============================================================================

var (
	kernel32 = syscall.NewLazyDLL("kernel32.dll")
	user32   = syscall.NewLazyDLL("user32.dll")
	ntdll    = syscall.NewLazyDLL("ntdll.dll")
	advapi32 = syscall.NewLazyDLL("advapi32.dll")
	shell32  = syscall.NewLazyDLL("shell32.dll")
)

var (
	pCreateToolhelp32Snapshot         = kernel32.NewProc("CreateToolhelp32Snapshot")
	pProcess32FirstW                  = kernel32.NewProc("Process32FirstW")
	pProcess32NextW                   = kernel32.NewProc("Process32NextW")
	pOpenProcess                      = kernel32.NewProc("OpenProcess")
	pCloseHandle                      = kernel32.NewProc("CloseHandle")
	pTerminateProcess                 = kernel32.NewProc("TerminateProcess")
	pK32GetProcessMemoryInfo          = kernel32.NewProc("K32GetProcessMemoryInfo")
	pGetProcessTimes                  = kernel32.NewProc("GetProcessTimes")
	pGetProcessHandleCount            = kernel32.NewProc("GetProcessHandleCount")
	pGetProcessIoCounters             = kernel32.NewProc("GetProcessIoCounters")
	pGetPriorityClass                 = kernel32.NewProc("GetPriorityClass")
	pSetPriorityClass                 = kernel32.NewProc("SetPriorityClass")
	pQueryFullProcessImageNameW       = kernel32.NewProc("QueryFullProcessImageNameW")
	pCreateJobObjectW                 = kernel32.NewProc("CreateJobObjectW")
	pAssignProcessToJobObject         = kernel32.NewProc("AssignProcessToJobObject")
	pSetInformationJobObject          = kernel32.NewProc("SetInformationJobObject")
	pQueryInformationJobObject        = kernel32.NewProc("QueryInformationJobObject")
	pTerminateJobObject               = kernel32.NewProc("TerminateJobObject")
	pCreateProcessW                   = kernel32.NewProc("CreateProcessW")
	pResumeThread                     = kernel32.NewProc("ResumeThread")
	pWaitForSingleObject              = kernel32.NewProc("WaitForSingleObject")
	pGetExitCodeProcess               = kernel32.NewProc("GetExitCodeProcess")
	pGetActiveProcessorCount          = kernel32.NewProc("GetActiveProcessorCount")
	pGetLogicalProcessorInformationEx = kernel32.NewProc("GetLogicalProcessorInformationEx")
	pGlobalMemoryStatusEx             = kernel32.NewProc("GlobalMemoryStatusEx")
	pGetSystemTimes                   = kernel32.NewProc("GetSystemTimes")
	pGetDiskFreeSpaceExW              = kernel32.NewProc("GetDiskFreeSpaceExW")
	pGetStdHandle                     = kernel32.NewProc("GetStdHandle")
	pGetConsoleMode                   = kernel32.NewProc("GetConsoleMode")
	pSetConsoleMode                   = kernel32.NewProc("SetConsoleMode")
	pReadConsoleInputW                = kernel32.NewProc("ReadConsoleInputW")
	pGetTickCount64                   = kernel32.NewProc("GetTickCount64")
	pGetConsoleScreenBufferInfo       = kernel32.NewProc("GetConsoleScreenBufferInfo")
	pGetCurrentProcess                = kernel32.NewProc("GetCurrentProcess")

	pGetGuiResources = user32.NewProc("GetGuiResources")

	pNtSuspendProcess = ntdll.NewProc("NtSuspendProcess")
	pNtResumeProcess  = ntdll.NewProc("NtResumeProcess")

	pOpenProcessToken    = advapi32.NewProc("OpenProcessToken")
	pGetTokenInformation = advapi32.NewProc("GetTokenInformation")
	pLookupAccountSidW   = advapi32.NewProc("LookupAccountSidW")

	pShellExecuteExW = shell32.NewProc("ShellExecuteExW")
)

type apiEntry struct {
	name     string
	proc     *syscall.LazyProc
	required bool
}

var apiTable = []apiEntry{
	{"CreateToolhelp32Snapshot", pCreateToolhelp32Snapshot, true},
	{"Process32FirstW", pProcess32FirstW, true},
	{"Process32NextW", pProcess32NextW, true},
	{"OpenProcess", pOpenProcess, true},
	{"CloseHandle", pCloseHandle, true},
	{"TerminateProcess", pTerminateProcess, true},
	{"K32GetProcessMemoryInfo", pK32GetProcessMemoryInfo, true},
	{"GetProcessTimes", pGetProcessTimes, true},
	{"GetProcessHandleCount", pGetProcessHandleCount, true},
	{"GetProcessIoCounters", pGetProcessIoCounters, true},
	{"GetPriorityClass", pGetPriorityClass, true},
	{"SetPriorityClass", pSetPriorityClass, true},
	{"QueryFullProcessImageNameW", pQueryFullProcessImageNameW, true},
	{"CreateJobObjectW", pCreateJobObjectW, true},
	{"AssignProcessToJobObject", pAssignProcessToJobObject, true},
	{"SetInformationJobObject", pSetInformationJobObject, true},
	{"QueryInformationJobObject", pQueryInformationJobObject, true},
	{"TerminateJobObject", pTerminateJobObject, true},
	{"CreateProcessW", pCreateProcessW, true},
	{"ResumeThread", pResumeThread, true},
	{"WaitForSingleObject", pWaitForSingleObject, true},
	{"GetExitCodeProcess", pGetExitCodeProcess, true},
	{"GetActiveProcessorCount", pGetActiveProcessorCount, true},
	{"GetLogicalProcessorInformationEx", pGetLogicalProcessorInformationEx, true},
	{"GlobalMemoryStatusEx", pGlobalMemoryStatusEx, true},
	{"GetSystemTimes", pGetSystemTimes, true},
	{"GetDiskFreeSpaceExW", pGetDiskFreeSpaceExW, true},
	{"GetStdHandle", pGetStdHandle, true},
	{"GetConsoleMode", pGetConsoleMode, true},
	{"SetConsoleMode", pSetConsoleMode, true},
	{"ReadConsoleInputW", pReadConsoleInputW, true},
	{"GetTickCount64", pGetTickCount64, true},
	{"GetConsoleScreenBufferInfo", pGetConsoleScreenBufferInfo, true},
	{"GetCurrentProcess", pGetCurrentProcess, true},
	{"ShellExecuteExW", pShellExecuteExW, true},
	{"GetGuiResources", pGetGuiResources, false},
	{"NtSuspendProcess", pNtSuspendProcess, true},
	{"NtResumeProcess", pNtResumeProcess, true},
	{"OpenProcessToken", pOpenProcessToken, true},
	{"GetTokenInformation", pGetTokenInformation, true},
	{"LookupAccountSidW", pLookupAccountSidW, true},
}

var apiOK = map[string]bool{}

func initAPIs() {
	for _, e := range apiTable {
		apiOK[e.name] = e.proc.Find() == nil
	}
}

func checkRequiredAPIs() {
	var missing []string
	for _, e := range apiTable {
		if e.required && !apiOK[e.name] {
			missing = append(missing, e.name)
		}
	}
	if len(missing) > 0 {
		fmt.Fprintf(os.Stderr, "procctl: missing required Windows APIs:\n  %s\n", strings.Join(missing, "\n  "))
		os.Exit(5)
	}
	if !apiOK["GetGuiResources"] {
		bugs.Add("WARN", "user32.dll!GetGuiResources unavailable, gdiobj/userobj skipped")
	}
}

// ============================================================================
// Color init + output redirection
// ============================================================================

func initColor(args []string) {
	if has(args, "--no-color") || os.Getenv("NO_COLOR") != "" {
		useColor = false
		return
	}
	outH, _, _ := pGetStdHandle.Call(uintptr(STD_OUTPUT_HANDLE))
	var mode uint32
	if r, _, _ := pGetConsoleMode.Call(outH, uintptr(unsafe.Pointer(&mode))); r != 0 {
		useColor = true
	}
}

func c(code, s string) string {
	if !useColor {
		return s
	}
	return code + s + clrReset
}

func cpuColor(pct float64) string {
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

// setupOutput redirects stdout when -o/--out is given. Only list/total/sum/limit
// call this; monitor refuses -o/--out elsewhere.
func setupOutput(cmd string, args []string) bool {
	path := getOpt(args, "-o", "--out")
	if path == "" {
		return true
	}
	if has(args, "--watch") {
		fmt.Fprintln(os.Stderr, "-o/--out cannot be used with --watch")
		return false
	}
	f, actualPath, err := openOutputFile(path, has(args, "--json"))
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

func openOutputFile(path string, asJSON bool) (*os.File, string, error) {
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
		name := "procctl_" + time.Now().Format("20060102_150405.000") + ext
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

// ============================================================================
// Constants
// ============================================================================

const (
	PROCESS_TERMINATE       = 0x0001
	PROCESS_SET_INFORMATION = 0x0200
	PROCESS_SUSPEND_RESUME  = 0x0800
	PROCESS_QUERY_LIMITED   = 0x1000
	PROCESS_ALL_ACCESS      = 0x1F0FFF

	TH32CS_SNAPPROCESS = 0x00000002
	CREATE_SUSPENDED   = 0x00000004
	CREATE_NEW_CONSOLE = 0x00000010
	CREATE_NO_WINDOW   = 0x08000000
	INFINITE           = 0xFFFFFFFF

	STD_INPUT_HANDLE  = ^uint32(9)
	STD_OUTPUT_HANDLE = ^uint32(11)

	ENABLE_PROCESSED_INPUT             = 0x0001
	ENABLE_LINE_INPUT                  = 0x0002
	ENABLE_ECHO_INPUT                  = 0x0004
	ENABLE_WINDOW_INPUT                = 0x0008
	ENABLE_MOUSE_INPUT                 = 0x0010
	ENABLE_EXTENDED_FLAGS              = 0x0080
	ENABLE_VIRTUAL_TERMINAL_PROCESSING = 0x0004

	ALL_PROCESSOR_GROUPS  = 0xFFFF
	RelationProcessorCore = 0

	JOB_OBJECT_LIMIT_JOB_MEMORY        = 0x00000200
	JOB_OBJECT_LIMIT_WORKINGSET        = 0x00000001
	JOB_OBJECT_LIMIT_ACTIVE_PROCESS    = 0x00000008
	JOB_OBJECT_LIMIT_AFFINITY          = 0x00000010
	JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x00002000

	JobObjectExtendedLimitInformation  = 9
	JobObjectCpuRateControlInformation = 15
	JobObjectNetRateControlInformation = 32
	JobObjectIoRateControlInformation  = 33
	JobObjectBasicProcessIdList        = 3

	JOB_CPU_RATE_CONTROL_ENABLE   = 0x1
	JOB_CPU_RATE_CONTROL_HARD_CAP = 0x4
	JOB_NET_RATE_CONTROL_ENABLE   = 0x1
	TOKEN_QUERY                   = 0x0008
	TokenElevation                = 20

	SEE_MASK_NOCLOSEPROCESS = 0x00000040
	SEE_MASK_NOASYNC        = 0x00000100
	SW_SHOWNORMAL           = 1

	VK_BACK   = 0x08
	VK_TAB    = 0x09
	VK_RETURN = 0x0D
	VK_ESCAPE = 0x1B
	VK_SPACE  = 0x20
	VK_UP     = 0x26
	VK_DOWN   = 0x28
	VK_CTRL_C = 0x43
	VK_F2     = 0x71

	LEFT_CTRL_PRESSED = 0x0008
	MOUSE_WHEELED     = 0x0004

	ERROR_CANCELLED       = syscall.Errno(1223)
	ERR_ACCESS_DENIED     = syscall.Errno(5)
	ERR_INVALID_PARAMETER = syscall.Errno(87)
	ERR_NO_MORE_FILES     = syscall.Errno(18)
)

// ============================================================================
// Structures
// ============================================================================

type FILETIME struct{ LowDateTime, HighDateTime uint32 }

type PROCESSENTRY32 struct {
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

type PROCESS_MEMORY_COUNTERS struct {
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

type IO_COUNTERS struct {
	ReadOperationCount, WriteOperationCount, OtherOperationCount uint64
	ReadTransferCount, WriteTransferCount, OtherTransferCount    uint64
}

type MEMORYSTATUSEX struct {
	Length, MemoryLoad                               uint32
	TotalPhys, AvailPhys                             uint64
	TotalPageFile, AvailPageFile                     uint64
	TotalVirtual, AvailVirtual, AvailExtendedVirtual uint64
}

type STARTUPINFOW struct {
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

type PROCESS_INFORMATION struct {
	Process, Thread     syscall.Handle
	ProcessID, ThreadID uint32
}

type JOBOBJECT_CPU_RATE_CONTROL_INFORMATION struct{ ControlFlags, CpuRate uint32 }

type JOBOBJECT_NET_RATE_CONTROL_INFORMATION struct {
	MaxBandwidth uint64
	ControlFlags uint32
	DscpTag      uint32
}

type JOBOBJECT_IO_RATE_CONTROL_INFORMATION struct {
	MaxIops, MaxBandwidth, ReservationIops int64
	VolumeName                             uintptr
	BaseIoSize, ControlFlags               uint32
}

type COORD struct{ X, Y int16 }
type SMALL_RECT struct{ Left, Top, Right, Bottom int16 }

type CONSOLE_SCREEN_BUFFER_INFO struct {
	Size, CursorPosition COORD
	Attributes           uint16
	Window               SMALL_RECT
	MaximumWindowSize    COORD
}

type INPUT_RECORD struct {
	EventType uint16
	_         uint16
	Event     [16]byte
}

type KEY_EVENT_RECORD struct {
	KeyDown                                      int32
	RepeatCount, VirtualKeyCode, VirtualScanCode uint16
	UnicodeChar                                  uint16
	ControlKeyState                              uint32
}

type MOUSE_EVENT_RECORD struct {
	MousePosX, MousePosY                     int16
	ButtonState, ControlKeyState, EventFlags uint32
}

type TOKEN_ELEVATION struct{ TokenIsElevated uint32 }

type SHELLEXECUTEINFO struct {
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

// ============================================================================
// JOBOBJECT_EXTENDED_LIMIT_INFORMATION byte buffer (amd64 only)
// ============================================================================

func buildExtendedLimitBuffer(lim *ResourceLimits, isRun bool) []byte {
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
		limitFlags |= JOB_OBJECT_LIMIT_JOB_MEMORY
		binary.LittleEndian.PutUint64(buf[offJobMemLim:], *lim.Mem)
	}
	if lim.WorkingSet != nil {
		limitFlags |= JOB_OBJECT_LIMIT_WORKINGSET
		binary.LittleEndian.PutUint64(buf[offMaxWS:], *lim.WorkingSet)
	}
	if lim.ProcessCount != nil {
		limitFlags |= JOB_OBJECT_LIMIT_ACTIVE_PROCESS
		binary.LittleEndian.PutUint32(buf[offActiveProc:], *lim.ProcessCount)
	}
	if lim.Affinity != nil {
		limitFlags |= JOB_OBJECT_LIMIT_AFFINITY
		binary.LittleEndian.PutUint64(buf[offAffinity:], *lim.Affinity)
	}
	if lim.OnExit == "kill" && isRun {
		limitFlags |= JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
	}
	binary.LittleEndian.PutUint32(buf[offLimitFlags:], limitFlags)
	return buf
}

// ============================================================================
// -b / --bugs
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
		fmt.Fprintln(os.Stderr, "[procctl] -b/--bugs enabled: no errors or warnings captured this run.")
		return
	}
	fmt.Fprintf(os.Stderr, "\n--- procctl bugs report (%d entries) ---\n", len(b.entries))
	for _, e := range b.entries {
		fmt.Fprintf(os.Stderr, "[%s] %s %s\n", e.At.Format("15:04:05.000"), e.Level, e.Msg)
	}
	fmt.Fprintln(os.Stderr, "--- end of bugs report ---")
}

// ============================================================================
// Job cleanup
// ============================================================================

type cleanupEntry struct {
	job    *jobHandle
	onExit string
}

var (
	cleanups  []cleanupEntry
	cleanupMu sync.Mutex
)

func registerCleanup(j *jobHandle, onExit string) {
	cleanupMu.Lock()
	cleanups = append(cleanups, cleanupEntry{j, onExit})
	cleanupMu.Unlock()
}

func runCleanups() {
	cleanupMu.Lock()
	list := cleanups
	cleanups = nil
	cleanupMu.Unlock()
	for _, e := range list {
		switch e.onExit {
		case "kill":
			pTerminateJobObject.Call(uintptr(e.job.h), 1)
		case "suspend":
			suspendJobProcesses(e.job)
		}
		e.job.close()
	}
}

func suspendJobProcesses(j *jobHandle) {
	var need uint32
	pQueryInformationJobObject.Call(uintptr(j.h), JobObjectBasicProcessIdList, 0, 0, uintptr(unsafe.Pointer(&need)))
	if need == 0 {
		need = 1024
	}
	buf := make([]byte, need+64)
	r, _, _ := pQueryInformationJobObject.Call(uintptr(j.h), JobObjectBasicProcessIdList,
		uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)), uintptr(unsafe.Pointer(&need)))
	if r == 0 {
		return
	}
	count := *(*uint32)(unsafe.Pointer(&buf[4]))
	base := uintptr(8)
	step := unsafe.Sizeof(uintptr(0))
	for i := uint32(0); i < count && base+uintptr(i)*step < uintptr(len(buf)); i++ {
		pid := uint32(*(*uintptr)(unsafe.Pointer(&buf[base+uintptr(i)*step])))
		_ = suspendProcess(pid)
	}
}

func exit(code int) {
	runCleanups()
	appendOpLog(buildCmdLine(os.Args), code)
	bugs.Flush()
	if outputCleanup != nil {
		outputCleanup()
		outputCleanup = nil
	}
	os.Exit(code)
}

// ============================================================================
// Operation log: ./procctl_backup/procctl.log
// Format: [full command line] [timestamp] [numeric exit code]
// ============================================================================

const (
	opLogDirName  = "procctl_backup"
	opLogFileName = "procctl.log"
)

func exeDir() string {
	if exe, err := os.Executable(); err == nil {
		return filepath.Dir(exe)
	}
	if wd, err := os.Getwd(); err == nil {
		return wd
	}
	return "."
}

func opLogPath() string {
	return filepath.Join(exeDir(), opLogDirName, opLogFileName)
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

func appendOpLog(cmdLine string, code int) {
	path := opLogPath()
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		bugs.Add("WARN", "create log dir %s: %v", filepath.Dir(path), err)
		return
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		bugs.Add("WARN", "open log %s: %v", path, err)
		return
	}
	defer f.Close()
	ts := time.Now().Format("2006-01-02 15:04:05")
	if _, err := fmt.Fprintf(f, "[%s] [%s] [%d]\n", cmdLine, ts, code); err != nil {
		bugs.Add("WARN", "write log %s: %v", path, err)
	}
}

func readOpLog() ([]string, error) {
	data, err := os.ReadFile(opLogPath())
	if err != nil {
		return nil, err
	}
	var lines []string
	for _, l := range strings.Split(string(data), "\n") {
		if strings.TrimSpace(l) != "" {
			lines = append(lines, l)
		}
	}
	return lines, nil
}

var opLogRe = regexp.MustCompile(`^\[(.*)\] \[(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\] \[(-?\d+)\]$`)

func parseLogCommand(line string) (string, bool) {
	if strings.HasPrefix(line, "【") {
		rest := strings.TrimPrefix(line, "【")
		idx := strings.Index(rest, "】 【")
		if idx < 0 {
			return "", false
		}
		return rest[:idx], true
	}
	m := opLogRe.FindStringSubmatch(line)
	if m == nil {
		return "", false
	}
	return m[1], true
}

func splitCommandLine(cmd string) []string {
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

func joinCommandLine(argv []string) string {
	parts := make([]string, len(argv))
	for i, a := range argv {
		parts[i] = syscall.EscapeArg(a)
	}
	return strings.Join(parts, " ")
}

// ============================================================================
// Command parsing (subcommand + legacy flag aliases)
// ============================================================================

// commandAliases maps legacy flags to their canonical subcommands. Bare -p/-n
// are special: they return the raw argument list so cmdLimitMixed can parse
// multiple targets.
var commandAliases = map[string]string{
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

var subcommands = map[string]bool{
	"list": true, "total": true, "sum": true, "monitor": true,
	"kill": true, "superkill": true, "suspend": true, "resume": true,
	"priority": true, "limit": true, "run": true,
	"history": true, "rollback": true, "help": true, "version": true,
}

func removeAt(args []string, i int) []string {
	out := make([]string, 0, len(args)-1)
	out = append(out, args[:i]...)
	out = append(out, args[i+1:]...)
	return out
}

// hasBeforeDoubleDash reports whether any of flags appears before a literal
// "--". This prevents "procctl run -- cmd --help" from being mistaken for a
// help request.
func hasBeforeDoubleDash(args []string, flags ...string) bool {
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

// parseCommand resolves both "procctl <subcmd> ..." and the legacy
// "procctl -a ..." style into a canonical command name and the remaining
// argument list. The special limit subcommand keeps the raw arguments so
// cmdLimitMixed can still process multiple -p/-n targets.
func parseCommand(args []string) (cmd string, rest []string, ok bool) {
	for i, a := range args {
		if a == "--" {
			break
		}
		if alias, isCmd := commandAliases[a]; isCmd {
			if alias == "limit" {
				return "limit", args, true
			}
			return alias, removeAt(args, i), true
		}
	}
	for i, a := range args {
		if a == "--" {
			break
		}
		if strings.HasPrefix(a, "-") {
			continue
		}
		if subcommands[a] {
			return a, removeAt(args, i), true
		}
		break
	}
	return "", args, false
}

var limitOptionFlags = map[string]bool{
	"--affinity": true, "--cpu": true, "--iops": true, "--io-read": true,
	"--io-write": true, "--mem": true, "--net": true, "--net-in": true,
	"--net-out": true, "--on-exit": true, "--process-count": true,
	"--timeout": true, "--working-set": true,
}

// isQueryCommand reports whether the logged command has no side effects.
func isQueryCommand(cmd string) bool {
	argv := splitCommandLine(cmd)
	if len(argv) < 2 {
		return true
	}
	c, rest, ok := parseCommand(argv[1:])
	if !ok {
		return true
	}
	switch c {
	case "help", "version", "history", "rollback", "list", "total", "sum", "monitor":
		return true
	case "limit":
		for _, a := range rest {
			if limitOptionFlags[a] {
				return false
			}
		}
		return true
	}
	return false
}

// invertCommand returns the inverse command line for an operation. Only
// suspend/resume are auto-invertible.
func invertCommand(cmd string) (string, error) {
	argv := splitCommandLine(cmd)
	if len(argv) == 0 {
		return "", fmt.Errorf("empty command")
	}
	exe := argv[0]
	c, rest, ok := parseCommand(argv[1:])
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
		return joinCommandLine([]string{exe, "resume", t}), nil
	case "resume":
		t := firstPositional(rest)
		if t == "" {
			return "", fmt.Errorf("resume requires a target")
		}
		return joinCommandLine([]string{exe, "suspend", t}), nil
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

func runCommandLine(cmdLine string) (int, error) {
	p, err := syscall.UTF16PtrFromString(cmdLine)
	if err != nil {
		return 5, err
	}
	var si STARTUPINFOW
	si.Cb = uint32(unsafe.Sizeof(si))
	var pi PROCESS_INFORMATION
	r, _, callErr := pCreateProcessW.Call(0, uintptr(unsafe.Pointer(p)), 0, 0, 1, 0, 0, 0,
		uintptr(unsafe.Pointer(&si)), uintptr(unsafe.Pointer(&pi)))
	if r == 0 {
		return 5, callErr
	}
	defer pCloseHandle.Call(uintptr(pi.Thread))
	defer pCloseHandle.Call(uintptr(pi.Process))
	pWaitForSingleObject.Call(uintptr(pi.Process), INFINITE)
	var code uint32
	pGetExitCodeProcess.Call(uintptr(pi.Process), uintptr(unsafe.Pointer(&code)))
	return int(code), nil
}

// ============================================================================
// History / rollback
// ============================================================================

func cmdHistory() {
	lines, err := readOpLog()
	if err != nil {
		fmt.Fprintf(os.Stderr, "read operation log %s: %v\n", opLogPath(), err)
		exit(4)
	}
	type entry struct {
		cmd string
		raw string
	}
	var entries []entry
	for i := len(lines) - 1; i >= 0; i-- {
		cmd, ok := parseLogCommand(lines[i])
		if !ok {
			continue
		}
		if isQueryCommand(cmd) {
			continue
		}
		entries = append(entries, entry{cmd: cmd, raw: lines[i]})
	}
	if len(entries) == 0 {
		fmt.Fprintln(os.Stderr, "operation log has no rollback-able entries")
		exit(0)
	}
	for i, e := range entries {
		fmt.Printf("[%d] %s\n", i+1, e.raw)
	}
	fmt.Fprintf(os.Stderr, "\n%d rollback-able operation(s). Full log: %s\n", len(entries), opLogPath())
	exit(0)
}

func cmdRollback(args []string) {
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
		fmt.Fprintln(os.Stderr, "usage: procctl rollback <N>")
		exit(2)
	}
	lines, err := readOpLog()
	if err != nil {
		fmt.Fprintf(os.Stderr, "read operation log %s: %v\n", opLogPath(), err)
		exit(4)
	}
	var cmds []string
	for _, l := range lines {
		cmd, ok := parseLogCommand(l)
		if !ok {
			continue
		}
		if isQueryCommand(cmd) {
			continue
		}
		cmds = append(cmds, cmd)
	}
	if len(cmds) == 0 {
		fmt.Fprintln(os.Stderr, "operation log has no rollback-able entries")
		exit(4)
	}
	if n > len(cmds) {
		n = len(cmds)
	}
	sel := make([]string, n)
	for i := 0; i < n; i++ {
		sel[i] = cmds[len(cmds)-1-i]
	}
	okCount, failCount := 0, 0
	for k, cmd := range sel {
		inv, err := invertCommand(cmd)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[rollback] step %d: cannot invert %q: %v\n", k+1, cmd, err)
			bugs.Add("ERR", "rollback step %d cannot invert %q: %v", k+1, cmd, err)
			failCount++
			continue
		}
		fmt.Fprintf(os.Stderr, "[rollback] step %d: %s\n", k+1, inv)
		code, err := runCommandLine(inv)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[rollback] step %d: exit code = 5 (%v)\n", k+1, err)
			bugs.Add("ERR", "rollback step %d: %v", k+1, err)
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
		exit(0)
	}
	if okCount == 0 {
		exit(2)
	}
	exit(1)
}

// ============================================================================
// Elevation helpers
// ============================================================================

func isAdmin() bool {
	h, _, _ := pGetCurrentProcess.Call()
	if h == 0 {
		return false
	}
	var token syscall.Handle
	if r, _, _ := pOpenProcessToken.Call(h, TOKEN_QUERY, uintptr(unsafe.Pointer(&token))); r == 0 {
		return false
	}
	defer pCloseHandle.Call(uintptr(token))
	var elev TOKEN_ELEVATION
	var size uint32
	r, _, _ := pGetTokenInformation.Call(uintptr(token), TokenElevation,
		uintptr(unsafe.Pointer(&elev)), uintptr(unsafe.Sizeof(elev)),
		uintptr(unsafe.Pointer(&size)))
	if r == 0 {
		return false
	}
	return elev.TokenIsElevated != 0
}

func relaunchElevated(originalArgs []string) (int, error) {
	exePath, err := os.Executable()
	if err != nil {
		return 5, fmt.Errorf("locate executable: %w", err)
	}
	// The caller has already stripped the "run" subcommand / "--run" flag,
	// so we prepend it again for the elevated instance.
	paramParts := []string{"run"}
	for _, a := range originalArgs {
		paramParts = append(paramParts, syscall.EscapeArg(a))
	}
	paramParts = append(paramParts, "--elevated")

	verb, _ := syscall.UTF16PtrFromString("runas")
	filePtr, _ := syscall.UTF16PtrFromString(exePath)
	paramsPtr, _ := syscall.UTF16PtrFromString(strings.Join(paramParts, " "))

	var sei SHELLEXECUTEINFO
	sei.CbSize = uint32(unsafe.Sizeof(sei))
	sei.FMask = SEE_MASK_NOCLOSEPROCESS | SEE_MASK_NOASYNC
	sei.LpVerb = verb
	sei.LpFile = filePtr
	sei.LpParameters = paramsPtr
	sei.NShow = SW_SHOWNORMAL

	r, _, callErr := pShellExecuteExW.Call(uintptr(unsafe.Pointer(&sei)))
	if r == 0 {
		if errno, ok := callErr.(syscall.Errno); ok && errno == ERROR_CANCELLED {
			return 5, fmt.Errorf("UAC elevation cancelled by user")
		}
		return 5, fmt.Errorf("ShellExecuteExW: %v", callErr)
	}
	if sei.HProcess == 0 {
		return 5, fmt.Errorf("ShellExecuteExW returned no process handle")
	}
	defer pCloseHandle.Call(sei.HProcess)
	pWaitForSingleObject.Call(sei.HProcess, INFINITE)
	var code uint32
	pGetExitCodeProcess.Call(sei.HProcess, uintptr(unsafe.Pointer(&code)))
	return int(code), nil
}

// ============================================================================
// Data model
// ============================================================================

type ProcInfo struct {
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

type SysInfo struct {
	LogicalCPU  int        `json:"logical_cpu"`
	PhysicalCPU int        `json:"physical_cpu"`
	CPUPercent  float64    `json:"cpu_percent"`
	MemTotal    uint64     `json:"mem_total"`
	MemUsed     uint64     `json:"mem_used"`
	MemFree     uint64     `json:"mem_free"`
	Disks       []DiskInfo `json:"disks,omitempty"`
	Uptime      string     `json:"uptime"`
}

type DiskInfo struct {
	Letter  string  `json:"letter"`
	Percent float64 `json:"percent"`
	Free    uint64  `json:"free"`
	Total   uint64  `json:"total"`
}

type ResourceLimits struct {
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

type runOptions struct {
	workDir  string
	title    string
	priority uint32
	noWindow bool
}

// ============================================================================
// Short option combining
// ============================================================================

var shortNoArg = map[byte]bool{'a': true, 'e': true, 't': true, 'm': true, 'b': true, 'h': true}
var shortReqArg = map[byte]bool{'k': true, 'x': true, 'p': true, 'n': true, 'o': true}
var shortOptArg = map[byte]bool{'s': true}

func expandShortArgs(args []string) []string {
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
		if expanded, ok := tryExpandShort(a[1:]); ok {
			out = append(out, expanded...)
		} else {
			out = append(out, a)
		}
	}
	return out
}

func tryExpandShort(s string) ([]string, bool) {
	var out []string
	j := 0
	for j < len(s) {
		ch := s[j]
		if shortNoArg[ch] {
			out = append(out, "-"+string(ch))
			j++
			continue
		}
		if shortReqArg[ch] {
			out = append(out, "-"+string(ch))
			if rest := s[j+1:]; rest != "" {
				out = append(out, rest)
			}
			return out, true
		}
		if shortOptArg[ch] {
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

// ============================================================================
// Utilities
// ============================================================================

func ftU64(ft FILETIME) uint64 { return uint64(ft.HighDateTime)<<32 | uint64(ft.LowDateTime) }

func filetimeToTime(ft FILETIME) time.Time {
	v := int64(ftU64(ft))
	if v <= 0 {
		return time.Time{}
	}
	return time.Unix(0, (v-116444736000000000)*100)
}

func utf16At(buf []uint16) string {
	for i, v := range buf {
		if v == 0 {
			return syscall.UTF16ToString(buf[:i])
		}
	}
	return syscall.UTF16ToString(buf)
}

func openProcess(access uint32, pid uint32) (syscall.Handle, error) {
	h, _, err := pOpenProcess.Call(uintptr(access), 0, uintptr(pid))
	if h == 0 {
		return 0, err
	}
	return syscall.Handle(h), nil
}

// ============================================================================
// Process enumeration
// ============================================================================

type procSnapshot struct {
	PID, PPID uint32
	Name      string
	Threads   uint32
}

func listProcesses() ([]procSnapshot, error) {
	h, _, err := pCreateToolhelp32Snapshot.Call(TH32CS_SNAPPROCESS, 0)
	if syscall.Handle(h) == syscall.InvalidHandle {
		bugs.Add("ERR", "CreateToolhelp32Snapshot: %v", err)
		return nil, fmt.Errorf("CreateToolhelp32Snapshot: %w", err)
	}
	defer pCloseHandle.Call(h)
	var pe PROCESSENTRY32
	pe.Size = uint32(unsafe.Sizeof(pe))
	if r, _, err := pProcess32FirstW.Call(h, uintptr(unsafe.Pointer(&pe))); r == 0 {
		bugs.Add("ERR", "Process32First: %v", err)
		return nil, fmt.Errorf("Process32First: %w", err)
	}
	out := make([]procSnapshot, 0, 512)
	for {
		out = append(out, procSnapshot{pe.ProcessID, pe.ParentProcessID, utf16At(pe.ExeFile[:]), pe.Threads})
		r, _, err := pProcess32NextW.Call(h, uintptr(unsafe.Pointer(&pe)))
		if r == 0 {
			if errno, ok := err.(syscall.Errno); ok && errno == ERR_NO_MORE_FILES {
				break
			}
			bugs.Add("ERR", "Process32Next: %v", err)
			break
		}
	}
	return out, nil
}

func resolveTarget(target string) ([]uint32, error) {
	if pid, err := strconv.ParseUint(target, 10, 32); err == nil {
		return []uint32{uint32(pid)}, nil
	}
	procs, err := listProcesses()
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

// ============================================================================
// Extended fields
// ============================================================================

func collectDetails(snaps []procSnapshot, fields map[string]bool, parallel int) []ProcInfo {
	out := make([]ProcInfo, len(snaps))
	for i, s := range snaps {
		out[i] = ProcInfo{PID: s.PID, PPID: s.PPID, Name: s.Name, Threads: s.Threads}
	}
	if !needsOpen(fields) || len(snaps) == 0 {
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
				if err := queryProcessDetail(&out[i], pid, fields); err != nil {
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

func needsOpen(fields map[string]bool) bool {
	for k := range fields {
		if k != "pid" && k != "name" && k != "threads" {
			return true
		}
	}
	return false
}

func queryProcessDetail(p *ProcInfo, pid uint32, fields map[string]bool) error {
	h, err := openProcess(PROCESS_QUERY_LIMITED, pid)
	if err != nil {
		return err
	}
	defer pCloseHandle.Call(uintptr(h))

	if fields["mem"] || fields["page_faults"] {
		var pmc PROCESS_MEMORY_COUNTERS
		pmc.Cb = uint32(unsafe.Sizeof(pmc))
		if r, _, _ := pK32GetProcessMemoryInfo.Call(uintptr(h), uintptr(unsafe.Pointer(&pmc)), uintptr(pmc.Cb)); r != 0 {
			p.Mem = uint64(pmc.WorkingSetSize)
			p.PageFaults = uint64(pmc.PageFaultCount)
		}
	}
	if fields["handles"] {
		var n uint32
		if r, _, _ := pGetProcessHandleCount.Call(uintptr(h), uintptr(unsafe.Pointer(&n))); r != 0 {
			p.Handles = n
		}
	}
	if apiOK["GetGuiResources"] {
		if fields["gdiobj"] {
			if r, _, _ := pGetGuiResources.Call(uintptr(h), 0); r != 0 {
				p.GdiObj = uint32(r)
			}
		}
		if fields["userobj"] {
			if r, _, _ := pGetGuiResources.Call(uintptr(h), 1); r != 0 {
				p.UserObj = uint32(r)
			}
		}
	}
	if fields["io_read_b"] || fields["io_write_b"] || fields["io_read_c"] || fields["io_write_c"] {
		var ioc IO_COUNTERS
		if r, _, _ := pGetProcessIoCounters.Call(uintptr(h), uintptr(unsafe.Pointer(&ioc))); r != 0 {
			p.IOReadB = ioc.ReadTransferCount
			p.IOWriteB = ioc.WriteTransferCount
			p.IOReadC = ioc.ReadOperationCount
			p.IOWriteC = ioc.WriteOperationCount
		}
	}
	if fields["priority"] {
		if r, _, _ := pGetPriorityClass.Call(uintptr(h)); r != 0 {
			p.Priority = priorityName(uint32(r))
		}
	}
	if fields["create-time"] {
		var ct, e, k, u FILETIME
		if r, _, _ := pGetProcessTimes.Call(uintptr(h),
			uintptr(unsafe.Pointer(&ct)), uintptr(unsafe.Pointer(&e)),
			uintptr(unsafe.Pointer(&k)), uintptr(unsafe.Pointer(&u))); r != 0 {
			p.CreateTime = filetimeToTime(ct)
		}
	}
	if fields["username"] {
		p.Username = usernameByHandle(h)
	}
	if fields["exe"] {
		p.Exe = imagePathByHandle(h)
	}
	return nil
}

func usernameByHandle(h syscall.Handle) string {
	var token syscall.Handle
	if r, _, _ := pOpenProcessToken.Call(uintptr(h), TOKEN_QUERY, uintptr(unsafe.Pointer(&token))); r == 0 {
		return ""
	}
	defer pCloseHandle.Call(uintptr(token))
	var size uint32
	pGetTokenInformation.Call(uintptr(token), 1, 0, 0, uintptr(unsafe.Pointer(&size)))
	if size == 0 {
		return ""
	}
	buf := make([]byte, size)
	if r, _, _ := pGetTokenInformation.Call(uintptr(token), 1,
		uintptr(unsafe.Pointer(&buf[0])), uintptr(size), uintptr(unsafe.Pointer(&size))); r == 0 {
		return ""
	}
	sidPtr := *(*unsafe.Pointer)(unsafe.Pointer(&buf[0]))
	if sidPtr == nil {
		return ""
	}
	var nameBuf, domainBuf [256]uint16
	nameSize, domainSize, sidType := uint32(256), uint32(256), uint32(0)
	r, _, _ := pLookupAccountSidW.Call(0, uintptr(sidPtr),
		uintptr(unsafe.Pointer(&nameBuf[0])), uintptr(unsafe.Pointer(&nameSize)),
		uintptr(unsafe.Pointer(&domainBuf[0])), uintptr(unsafe.Pointer(&domainSize)),
		uintptr(unsafe.Pointer(&sidType)))
	if r == 0 {
		return ""
	}
	return utf16At(nameBuf[:nameSize])
}

func imagePathByHandle(h syscall.Handle) string {
	buf := make([]uint16, 1024)
	size := uint32(len(buf))
	if r, _, _ := pQueryFullProcessImageNameW.Call(uintptr(h), 0,
		uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&size))); r == 0 {
		return ""
	}
	return syscall.UTF16ToString(buf[:size])
}

func processUsername(pid uint32) string {
	h, err := openProcess(PROCESS_QUERY_LIMITED, pid)
	if err != nil {
		return ""
	}
	defer pCloseHandle.Call(uintptr(h))
	return usernameByHandle(h)
}

// ============================================================================
// CPU sampling
// ============================================================================

type cpuPrev struct {
	k, u uint64
	ts   time.Time
}
type cpuSampler struct {
	mu     sync.Mutex
	prev   map[uint32]cpuPrev
	warmed bool
}

var sampler = &cpuSampler{prev: map[uint32]cpuPrev{}}

func (s *cpuSampler) Percent(procs []ProcInfo) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	cur := make(map[uint32]cpuPrev, len(procs))
	for i := range procs {
		k, u, err := procCPUTimes(procs[i].PID)
		if err != nil {
			continue
		}
		cur[procs[i].PID] = cpuPrev{k, u, now}
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

func isSamplerWarmed() bool {
	sampler.mu.Lock()
	defer sampler.mu.Unlock()
	return sampler.warmed
}

func percentWithWarmup(procs []ProcInfo) {
	wasWarmed := isSamplerWarmed()
	sampler.Percent(procs)
	if !wasWarmed && len(procs) > 0 {
		time.Sleep(100 * time.Millisecond)
		sampler.Percent(procs)
	}
}

func procCPUTimes(pid uint32) (uint64, uint64, error) {
	h, err := openProcess(PROCESS_QUERY_LIMITED, pid)
	if err != nil {
		return 0, 0, err
	}
	defer pCloseHandle.Call(uintptr(h))
	var ct, e, k, u FILETIME
	if r, _, _ := pGetProcessTimes.Call(uintptr(h),
		uintptr(unsafe.Pointer(&ct)), uintptr(unsafe.Pointer(&e)),
		uintptr(unsafe.Pointer(&k)), uintptr(unsafe.Pointer(&u))); r == 0 {
		return 0, 0, fmt.Errorf("GetProcessTimes")
	}
	return ftU64(k), ftU64(u), nil
}

// ============================================================================
// Process control
// ============================================================================

func suspendProcess(pid uint32) error {
	h, err := openProcess(PROCESS_SUSPEND_RESUME, pid)
	if err != nil {
		return err
	}
	defer pCloseHandle.Call(uintptr(h))
	if r, _, _ := pNtSuspendProcess.Call(uintptr(h)); uint32(r) != 0 {
		return fmt.Errorf("NtSuspendProcess 0x%X", uint32(r))
	}
	return nil
}

func resumeProcess(pid uint32) error {
	h, err := openProcess(PROCESS_SUSPEND_RESUME, pid)
	if err != nil {
		return err
	}
	defer pCloseHandle.Call(uintptr(h))
	if r, _, _ := pNtResumeProcess.Call(uintptr(h)); uint32(r) != 0 {
		return fmt.Errorf("NtResumeProcess 0x%X", uint32(r))
	}
	return nil
}

func priorityName(cl uint32) string {
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

func priorityClass(level string) uint32 {
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

func setPriority(pid uint32, level string) error {
	class := priorityClass(level)
	if class == 0 {
		return fmt.Errorf("invalid priority %q", level)
	}
	h, err := openProcess(PROCESS_SET_INFORMATION, pid)
	if err != nil {
		return err
	}
	defer pCloseHandle.Call(uintptr(h))
	if r, _, err := pSetPriorityClass.Call(uintptr(h), uintptr(class)); r == 0 {
		return err
	}
	return nil
}

func killProcess(pid uint32, tree bool) error {
	if tree {
		return killTree(pid)
	}
	h, err := openProcess(PROCESS_TERMINATE, pid)
	if err != nil {
		return err
	}
	defer pCloseHandle.Call(uintptr(h))
	if r, _, err := pTerminateProcess.Call(uintptr(h), 1); r == 0 {
		return err
	}
	return nil
}

func killTree(root uint32) error {
	procs, err := listProcesses()
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
		if err := killProcess(order[i], false); err != nil {
			bugs.Add("WARN", "killTree pid=%d: %v", order[i], err)
		}
	}
	return nil
}

func isProtected(pid uint32) bool { return pid == 0 || pid == 4 }

// ============================================================================
// Job Object
// ============================================================================

type jobHandle struct{ h syscall.Handle }

func newJob() (*jobHandle, error) {
	r, _, err := pCreateJobObjectW.Call(0, 0)
	if r == 0 {
		return nil, fmt.Errorf("CreateJobObject: %w", err)
	}
	return &jobHandle{h: syscall.Handle(r)}, nil
}

func (j *jobHandle) close() { pCloseHandle.Call(uintptr(j.h)) }

func (j *jobHandle) assign(h syscall.Handle) error {
	if r, _, err := pAssignProcessToJobObject.Call(uintptr(j.h), uintptr(h)); r == 0 {
		return fmt.Errorf("AssignProcessToJobObject: %w", err)
	}
	return nil
}

func (j *jobHandle) setInfo(class uint32, info unsafe.Pointer, size uint32) error {
	if r, _, err := pSetInformationJobObject.Call(uintptr(j.h), uintptr(class), uintptr(info), uintptr(size)); r == 0 {
		return err
	}
	return nil
}

func (j *jobHandle) setLimits(lim *ResourceLimits, isRun bool) error {
	buf := buildExtendedLimitBuffer(lim, isRun)
	if err := j.setInfo(JobObjectExtendedLimitInformation, unsafe.Pointer(&buf[0]), uint32(len(buf))); err != nil {
		return fmt.Errorf("extended limits: %w", err)
	}
	if lim.CPUCores != nil {
		n := getLogicalCPU()
		rate := uint32(*lim.CPUCores * 100.0 / float64(n))
		if rate < 1 {
			rate = 1
		}
		if rate > 10000 {
			rate = 10000
		}
		ci := JOBOBJECT_CPU_RATE_CONTROL_INFORMATION{
			ControlFlags: JOB_CPU_RATE_CONTROL_ENABLE | JOB_CPU_RATE_CONTROL_HARD_CAP,
			CpuRate:      rate,
		}
		if err := j.setInfo(JobObjectCpuRateControlInformation, unsafe.Pointer(&ci), uint32(unsafe.Sizeof(ci))); err != nil {
			return fmt.Errorf("cpu rate: %w", err)
		}
	}
	if lim.IOPS != nil || lim.IOWrite != nil {
		io := JOBOBJECT_IO_RATE_CONTROL_INFORMATION{}
		if lim.IOPS != nil {
			io.MaxIops = *lim.IOPS
		}
		if lim.IOWrite != nil {
			io.MaxBandwidth = int64(*lim.IOWrite)
		}
		if err := j.setInfo(JobObjectIoRateControlInformation, unsafe.Pointer(&io), uint32(unsafe.Sizeof(io))); err != nil {
			return fmt.Errorf("io rate: %w", err)
		}
		if lim.IORead != nil {
			bugs.Add("WARN", "ioread: Job Object only limits total bandwidth")
		}
	}
	if lim.NetOut != nil {
		ni := JOBOBJECT_NET_RATE_CONTROL_INFORMATION{MaxBandwidth: *lim.NetOut, ControlFlags: JOB_NET_RATE_CONTROL_ENABLE}
		if err := j.setInfo(JobObjectNetRateControlInformation, unsafe.Pointer(&ni), uint32(unsafe.Sizeof(ni))); err != nil {
			return fmt.Errorf("net rate: %w", err)
		}
	}
	if lim.NetIn != nil {
		bugs.Add("WARN", "netin: Job Object does not support inbound rate limits")
	}
	return nil
}

func attachAndLimit(pid uint32, lim *ResourceLimits) error {
	jb, err := newJob()
	if err != nil {
		return err
	}
	h, err := openProcess(PROCESS_ALL_ACCESS, pid)
	if err != nil {
		jb.close()
		if errors.Is(err, ERR_ACCESS_DENIED) {
			return fmt.Errorf("access denied (pid %d), administrator privileges required", pid)
		}
		if errors.Is(err, ERR_INVALID_PARAMETER) {
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
			pTerminateJobObject.Call(uintptr(jb.h), 1)
		}()
	}
	onExit := lim.OnExit
	if onExit != "kill" && onExit != "suspend" {
		onExit = "keep"
	}
	registerCleanup(jb, onExit)
	return nil
}

func runWithLimits(cmdLine string, lim *ResourceLimits, opts *runOptions) (int, error) {
	jb, err := newJob()
	if err != nil {
		return 5, err
	}
	defer jb.close()
	var si STARTUPINFOW
	si.Cb = uint32(unsafe.Sizeof(si))
	var titlePtr, cwdPtr *uint16
	if opts != nil && opts.title != "" {
		titlePtr, _ = syscall.UTF16PtrFromString(opts.title)
		si.Title = titlePtr
	}
	if opts != nil && opts.workDir != "" {
		cwdPtr, _ = syscall.UTF16PtrFromString(opts.workDir)
	}
	var pi PROCESS_INFORMATION
	cmdUTF16, _ := syscall.UTF16FromString(cmdLine)
	flags := uint32(CREATE_SUSPENDED | CREATE_NEW_CONSOLE)
	if opts != nil && opts.noWindow {
		flags = CREATE_SUSPENDED | CREATE_NO_WINDOW
	}
	if r, _, err := pCreateProcessW.Call(0, uintptr(unsafe.Pointer(&cmdUTF16[0])), 0, 0, 0,
		uintptr(flags), 0, uintptr(unsafe.Pointer(cwdPtr)),
		uintptr(unsafe.Pointer(&si)), uintptr(unsafe.Pointer(&pi))); r == 0 {
		return 5, fmt.Errorf("CreateProcess: %w", err)
	}
	defer pCloseHandle.Call(uintptr(pi.Thread))
	defer pCloseHandle.Call(uintptr(pi.Process))
	if opts != nil && opts.priority != 0 {
		pSetPriorityClass.Call(uintptr(pi.Process), uintptr(opts.priority))
	}
	if err := jb.assign(pi.Process); err != nil {
		pTerminateProcess.Call(uintptr(pi.Process), 1)
		return 5, err
	}
	if err := jb.setLimits(lim, true); err != nil {
		pTerminateProcess.Call(uintptr(pi.Process), 1)
		return 5, err
	}
	pResumeThread.Call(uintptr(pi.Thread))
	if lim.Timeout != nil {
		go func() {
			time.Sleep(*lim.Timeout)
			pTerminateJobObject.Call(uintptr(jb.h), 1)
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
	pWaitForSingleObject.Call(uintptr(pi.Process), INFINITE)
	var code uint32
	pGetExitCodeProcess.Call(uintptr(pi.Process), uintptr(unsafe.Pointer(&code)))
	return int(code), nil
}

func buildRunCmdLine(parts []string) string {
	out := make([]string, len(parts))
	for i, p := range parts {
		out[i] = syscall.EscapeArg(p)
	}
	return strings.Join(out, " ")
}

// ============================================================================
// System totals and validation
// ============================================================================

func getLogicalCPU() int {
	r, _, _ := pGetActiveProcessorCount.Call(ALL_PROCESSOR_GROUPS)
	if r == 0 {
		return 1
	}
	return int(r)
}

func getPhysicalCPU() int {
	var length uint32
	pGetLogicalProcessorInformationEx.Call(uintptr(RelationProcessorCore), 0, uintptr(unsafe.Pointer(&length)))
	if length == 0 {
		return 0
	}
	buf := make([]byte, length)
	if r, _, _ := pGetLogicalProcessorInformationEx.Call(uintptr(RelationProcessorCore),
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
		if rel == RelationProcessorCore {
			count++
		}
		offset += sz
	}
	return count
}

func getTotalPhys() uint64 {
	var ms MEMORYSTATUSEX
	ms.Length = uint32(unsafe.Sizeof(ms))
	if r, _, _ := pGlobalMemoryStatusEx.Call(uintptr(unsafe.Pointer(&ms))); r == 0 {
		return 0
	}
	return ms.TotalPhys
}

func validateLimits(lim *ResourceLimits) error {
	if lim == nil {
		return nil
	}
	nCPU := getLogicalCPU()
	totalPhys := getTotalPhys()
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
	return fmt.Errorf("resource limit validation failed:\n  - %s\nuse procctl total to view system totals",
		strings.Join(problems, "\n  - "))
}

// ============================================================================
// System information
// ============================================================================

func collectSysInfo() SysInfo {
	si := SysInfo{LogicalCPU: getLogicalCPU(), PhysicalCPU: getPhysicalCPU()}
	idle1, kern1, user1 := systemTimes()
	time.Sleep(150 * time.Millisecond)
	idle2, kern2, user2 := systemTimes()
	di := float64(idle2 - idle1)
	dk := float64(kern2 - kern1)
	du := float64(user2 - user1)
	total := dk + du
	if total > 0 {
		si.CPUPercent = (total - di) / total * 100
	}
	var ms MEMORYSTATUSEX
	ms.Length = uint32(unsafe.Sizeof(ms))
	if r, _, _ := pGlobalMemoryStatusEx.Call(uintptr(unsafe.Pointer(&ms))); r != 0 {
		si.MemTotal = ms.TotalPhys
		si.MemUsed = ms.TotalPhys - ms.AvailPhys
		si.MemFree = ms.AvailPhys
	}
	si.Disks = diskUsages()
	si.Uptime = formatUptime(getTickCount64() / 1000)
	return si
}

func systemTimes() (uint64, uint64, uint64) {
	var i, k, u FILETIME
	if r, _, _ := pGetSystemTimes.Call(uintptr(unsafe.Pointer(&i)),
		uintptr(unsafe.Pointer(&k)), uintptr(unsafe.Pointer(&u))); r == 0 {
		return 0, 0, 0
	}
	return ftU64(i), ftU64(k), ftU64(u)
}

func getTickCount64() uint64 {
	r, _, _ := pGetTickCount64.Call()
	return uint64(r)
}

func diskUsages() []DiskInfo {
	var out []DiskInfo
	for d := 'A'; d <= 'Z'; d++ {
		root := string(d) + ":\\"
		rootPtr, err := syscall.UTF16PtrFromString(root)
		if err != nil {
			continue
		}
		var free, total, _ uint64
		if r, _, _ := pGetDiskFreeSpaceExW.Call(uintptr(unsafe.Pointer(rootPtr)),
			uintptr(unsafe.Pointer(&free)), uintptr(unsafe.Pointer(&total)), 0); r != 0 && total > 0 {
			out = append(out, DiskInfo{
				Letter:  string(d) + ":",
				Percent: (1 - float64(free)/float64(total)) * 100,
				Free:    free,
				Total:   total,
			})
		}
	}
	return out
}

func formatUptime(sec uint64) string {
	return fmt.Sprintf("%dd %dh %dm", sec/86400, (sec%86400)/3600, (sec%3600)/60)
}

func printJSON(v any) {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		bugs.Add("ERR", "json encode: %v", err)
	}
}

// ============================================================================
// TUI config
// ============================================================================

type tuiConfig struct {
	Interval int    `json:"interval"`
	FPS      int    `json:"fps"`
	SortKey  string `json:"sort_key"`
	SortDesc bool   `json:"sort_desc"`
}

func defaultConfigPath(args []string) string {
	if p := getOpt(args, "--config"); p != "" {
		return p
	}
	la := os.Getenv("LOCALAPPDATA")
	if la == "" {
		la = os.Getenv("TEMP")
	}
	return filepath.Join(strings.TrimRight(la, `\`), "procctl", "config.json")
}

func loadTUIConfig(path string) tuiConfig {
	c := tuiConfig{Interval: 1000, FPS: 30, SortKey: "cpu", SortDesc: true}
	if data, err := os.ReadFile(path); err == nil {
		_ = json.Unmarshal(data, &c)
	}
	return c
}

func saveTUIConfig(path string, c tuiConfig) {
	_ = os.MkdirAll(filepath.Dir(path), 0755)
	data, _ := json.MarshalIndent(c, "", "  ")
	_ = os.WriteFile(path, data, 0644)
}

// ============================================================================
// TUI
// ============================================================================

type tui struct {
	view           int
	cursor         int
	marked         map[uint32]bool
	filter         string
	filterMode     bool
	sortKey        string
	sortDesc       bool
	interval       time.Duration
	procs          []ProcInfo
	sys            SysInfo
	detail         *ProcInfo
	width          int
	height         int
	lastDraw       time.Time
	fpsLimit       time.Duration
	noMouse        bool
	quit           bool
	parallel       int
	configPath     string
	lastRefreshDur time.Duration
	forceRefresh   bool
}

func runTUI(interval time.Duration, fps int, noMouse bool, parallel int, configPath string, resetConfig bool) {
	if resetConfig {
		_ = os.Remove(configPath)
	}
	cfg := loadTUIConfig(configPath)
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
	t := &tui{marked: map[uint32]bool{}, sortKey: cfg.SortKey, sortDesc: cfg.SortDesc,
		interval: interval, fpsLimit: time.Second / time.Duration(fps),
		noMouse: noMouse, width: 120, height: 30, parallel: parallel, configPath: configPath}
	inH, _, _ := pGetStdHandle.Call(uintptr(STD_INPUT_HANDLE))
	outH, _, _ := pGetStdHandle.Call(uintptr(STD_OUTPUT_HANDLE))
	var oldIn, oldOut uint32
	pGetConsoleMode.Call(inH, uintptr(unsafe.Pointer(&oldIn)))
	pGetConsoleMode.Call(outH, uintptr(unsafe.Pointer(&oldOut)))
	defer func() {
		pSetConsoleMode.Call(inH, uintptr(oldIn))
		pSetConsoleMode.Call(outH, uintptr(oldOut))
		fmt.Print("\x1b[?25h\x1b[?1049l")
	}()
	newIn := oldIn &^ uint32(ENABLE_LINE_INPUT|ENABLE_ECHO_INPUT|ENABLE_PROCESSED_INPUT|ENABLE_MOUSE_INPUT)
	newIn |= ENABLE_EXTENDED_FLAGS | ENABLE_WINDOW_INPUT
	if !noMouse {
		newIn |= ENABLE_MOUSE_INPUT
	}
	pSetConsoleMode.Call(inH, uintptr(newIn))
	pSetConsoleMode.Call(outH, uintptr(oldOut|ENABLE_VIRTUAL_TERMINAL_PROCESSING))
	fmt.Print("\x1b[?1049h\x1b[?25l\x1b[2J")
	updateConsoleSize(syscall.Handle(outH), t)
	inputCh := make(chan INPUT_RECORD, 64)
	go func() {
		var rec INPUT_RECORD
		var n uint32
		for {
			r, _, _ := pReadConsoleInputW.Call(inH, uintptr(unsafe.Pointer(&rec)), 1, uintptr(unsafe.Pointer(&n)))
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
	saveTUIConfig(t.configPath, tuiConfig{int(t.interval / time.Millisecond), fps, t.sortKey, t.sortDesc})
}

func updateConsoleSize(h syscall.Handle, t *tui) {
	var info CONSOLE_SCREEN_BUFFER_INFO
	if r, _, _ := pGetConsoleScreenBufferInfo.Call(uintptr(h), uintptr(unsafe.Pointer(&info))); r != 0 {
		t.width = int(info.Window.Right-info.Window.Left) + 1
		t.height = int(info.Window.Bottom-info.Window.Top) + 1
	}
}

func (t *tui) refresh() {
	start := time.Now()
	defer func() { t.lastRefreshDur = time.Since(start) }()
	snaps, err := listProcesses()
	if err != nil {
		bugs.Add("ERR", "tui list: %v", err)
		return
	}
	fields := map[string]bool{"pid": true, "name": true, "threads": true, "cpu": true, "mem": true}
	t.procs = collectDetails(snaps, fields, t.parallel)
	percentWithWarmup(t.procs)
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
	sortProcs(t.procs, t.sortKey, t.sortDesc)
	if t.view == 1 {
		t.sys = collectSysInfo()
	}
	if t.cursor >= len(t.procs) && len(t.procs) > 0 {
		t.cursor = len(t.procs) - 1
	}
}

func (t *tui) handleInput(rec INPUT_RECORD) {
	switch rec.EventType {
	case 0x0001:
		k := (*KEY_EVENT_RECORD)(unsafe.Pointer(&rec.Event[0]))
		if k.KeyDown == 0 {
			return
		}
		t.handleKey(k)
	case 0x0002:
		if t.noMouse {
			return
		}
		m := (*MOUSE_EVENT_RECORD)(unsafe.Pointer(&rec.Event[0]))
		if m.EventFlags&MOUSE_WHEELED != 0 {
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

func (t *tui) handleKey(k *KEY_EVENT_RECORD) {
	if k.UnicodeChar == 3 || (k.VirtualKeyCode == VK_CTRL_C && k.ControlKeyState&LEFT_CTRL_PRESSED != 0) {
		t.quit = true
		return
	}
	if t.filterMode {
		switch k.VirtualKeyCode {
		case VK_RETURN:
			t.filterMode = false
			t.forceRefresh = true
			return
		case VK_ESCAPE:
			t.filterMode = false
			t.filter = ""
			t.forceRefresh = true
			return
		case VK_BACK:
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
	case VK_UP:
		if t.cursor > 0 {
			t.cursor--
		}
		return
	case VK_DOWN:
		if t.cursor < len(t.procs)-1 {
			t.cursor++
		}
		return
	case VK_SPACE:
		if t.cursor < len(t.procs) {
			pid := t.procs[t.cursor].PID
			if t.marked[pid] {
				delete(t.marked, pid)
			} else {
				t.marked[pid] = true
			}
		}
		return
	case VK_TAB:
		t.view = (t.view + 1) % 2
		t.cursor = 0
		return
	case VK_RETURN:
		if t.view == 0 && t.cursor < len(t.procs) {
			p := t.procs[t.cursor]
			t.detail = &p
		}
		return
	case VK_ESCAPE:
		t.detail = nil
		return
	case VK_F2:
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
		t.sortKey = nextSort(t.sortKey)
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

func (t *tui) controlSelected(action string) {
	var pids []uint32
	if len(t.marked) > 0 {
		for pid := range t.marked {
			pids = append(pids, pid)
		}
	} else if t.cursor < len(t.procs) {
		pids = append(pids, t.procs[t.cursor].PID)
	}
	for _, pid := range pids {
		if isProtected(pid) && action != "superkill" {
			continue
		}
		var err error
		switch action {
		case "kill", "superkill":
			err = killProcess(pid, true)
		case "suspend":
			err = suspendProcess(pid)
		case "resume":
			err = resumeProcess(pid)
		}
		if err != nil {
			bugs.Add("WARN", "tui %s pid=%d: %v", action, pid, err)
		}
	}
}

func (t *tui) draw(outH syscall.Handle) {
	t.lastDraw = time.Now()
	updateConsoleSize(outH, t)
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

func (t *tui) nameWidth() int {
	w := t.width - 50
	if w < 12 {
		w = 12
	}
	if w > 44 {
		w = 44
	}
	return w
}

func (t *tui) renderProcesses(b *strings.Builder) {
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
		nameStr := fmt.Sprintf("%-*s", nameW, trunc(p.Name, nameW))
		cpuStr := fmt.Sprintf("%*.1f", cpuW, p.CPU)
		memStr := fmt.Sprintf("%-*s", memW, humanBytes(p.Mem))
		thrStr := fmt.Sprintf("%*d", thrW, p.Threads)
		line := marker + " " +
			c(clrCyan, pidStr) + " " +
			nameStr + " " +
			c(cpuColor(p.CPU), cpuStr) + " " +
			c(clrYellow, memStr) + " " +
			thrStr
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

func (t *tui) renderSystem(b *strings.Builder) {
	b.WriteString(c(clrBold+clrCyan, "System Resources") + "\n\n")
	fmt.Fprintf(b, "  %s  %s  %s\n",
		c(clrCyan, "CPU   "),
		c(cpuColor(t.sys.CPUPercent), fmt.Sprintf("%5.1f%%", t.sys.CPUPercent)),
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
				c(clrCyan, d.Letter),
				d.Percent,
				c(clrGray, fmt.Sprintf("%s / %s", humanBytes(d.Free), humanBytes(d.Total))))
		}
	}
}

func (t *tui) renderDetail(b *strings.Builder) {
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

// ============================================================================
// Utilities
// ============================================================================

func sortProcs(procs []ProcInfo, key string, desc bool) {
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

func nextSort(k string) string {
	order := []string{"cpu", "mem", "pid", "name"}
	for i, s := range order {
		if s == k {
			return order[(i+1)%len(order)]
		}
	}
	return "cpu"
}

func trunc(s string, n int) string {
	if n <= 0 || len(s) <= n {
		return s
	}
	if n == 1 {
		return s[:1]
	}
	return s[:n-1] + "~"
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

func parseSize(s string) (uint64, error) {
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

func parseRate(s string) (uint64, error) {
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
	return parseSize(s)
}

// ============================================================================
// Fields and filters
// ============================================================================

func defaultFields() map[string]bool {
	return map[string]bool{"pid": true, "name": true, "cpu": true, "mem": true, "exe": true}
}

func allFields() map[string]bool {
	fs := map[string]bool{}
	for _, f := range []string{"pid", "name", "exe", "cpu", "mem", "threads", "handles",
		"gdiobj", "userobj", "io_read_b", "io_write_b", "io_read_c", "io_write_c",
		"priority", "username", "page_faults", "create-time"} {
		fs[f] = true
	}
	return fs
}

func parseFields(s string) map[string]bool {
	fs := map[string]bool{}
	for _, f := range strings.Split(s, ",") {
		fs[strings.ToLower(strings.TrimSpace(f))] = true
	}
	return fs
}

func filterSystem(procs []ProcInfo) []ProcInfo {
	var out []ProcInfo
	for _, p := range procs {
		if p.PID == 0 || p.PID == 4 || p.Name == "System" || p.Name == "smss.exe" {
			continue
		}
		user := processUsername(p.PID)
		if user == "SYSTEM" || user == "LOCAL SERVICE" || user == "NETWORK SERVICE" {
			continue
		}
		out = append(out, p)
	}
	return out
}

func applyFilter(procs []ProcInfo, pattern string) []ProcInfo {
	if pattern == "" {
		return procs
	}
	lp := strings.ToLower(pattern)
	var out []ProcInfo
	for _, p := range procs {
		if strings.Contains(strings.ToLower(p.Name), lp) {
			out = append(out, p)
		}
	}
	return out
}

func applyLimit(procs []ProcInfo, n int) []ProcInfo {
	if n <= 0 || len(procs) <= n {
		return procs
	}
	return procs[:n]
}

// ============================================================================
// Limit parsing
// ============================================================================

func applyLimitKey(key, val string, lim *ResourceLimits) error {
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
		v, err := parseRate(val)
		if err != nil {
			return err
		}
		lim.IORead = &v
	case "iowrite":
		v, err := parseRate(val)
		if err != nil {
			return err
		}
		lim.IOWrite = &v
	case "mem":
		v, err := parseSize(val)
		if err != nil {
			return err
		}
		lim.Mem = &v
	case "netin":
		v, err := parseRate(val)
		if err != nil {
			return err
		}
		lim.NetIn = &v
	case "netout":
		v, err := parseRate(val)
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
		v, err := parseSize(val)
		if err != nil {
			return err
		}
		lim.WorkingSet = &v
	default:
		return fmt.Errorf("unknown key %q", key)
	}
	return nil
}

func consumeLimitOption(args []string, i int, lim *ResourceLimits) (int, bool) {
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
		_ = applyLimitKey("netin", val, lim)
		_ = applyLimitKey("netout", val, lim)
		return 2, true
	case "--on-exit":
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
	_ = applyLimitKey(key, val, lim)
	return 2, true
}

func isEmptyLimits(lim *ResourceLimits) bool {
	if lim == nil {
		return true
	}
	return lim.Affinity == nil && lim.CPUCores == nil && lim.IOPS == nil &&
		lim.IORead == nil && lim.IOWrite == nil && lim.Mem == nil &&
		lim.NetIn == nil && lim.NetOut == nil &&
		(lim.OnExit == "" || lim.OnExit == "keep") &&
		lim.ProcessCount == nil && lim.Timeout == nil && lim.WorkingSet == nil
}

func queryAndPrint(pid uint32, asJSON bool, fields map[string]bool) error {
	h, err := openProcess(PROCESS_QUERY_LIMITED, pid)
	if err != nil {
		if errors.Is(err, ERR_INVALID_PARAMETER) {
			return fmt.Errorf("PID %d does not exist or has exited (PID may have been reused; re-check with procctl list)", pid)
		}
		if errors.Is(err, ERR_ACCESS_DENIED) {
			return fmt.Errorf("PID %d permission denied (process may be running with higher privileges)", pid)
		}
		return fmt.Errorf("PID %d OpenProcess: %w", pid, err)
	}
	pCloseHandle.Call(uintptr(h))

	info := ProcInfo{PID: pid}
	if err := queryProcessDetail(&info, pid, fields); err != nil {
		return err
	}
	if snaps, e := listProcesses(); e == nil {
		for _, s := range snaps {
			if s.PID == pid {
				info.Name = s.Name
				info.PPID = s.PPID
				info.Threads = s.Threads
				break
			}
		}
	}
	if k1, u1, e := procCPUTimes(pid); e == nil {
		time.Sleep(100 * time.Millisecond)
		if k2, u2, e2 := procCPUTimes(pid); e2 == nil {
			pct := (float64(k2-k1) + float64(u2-u1)) / 1e7 / 0.1 * 100
			if pct < 0 {
				pct = 0
			}
			info.CPU = pct
		}
	}

	if asJSON {
		printJSON(info)
		return nil
	}
	printSingleProc(info)
	return nil
}

func printSingleProc(info ProcInfo) {
	fmt.Printf("%s %d\n", c(clrCyan, "PID     "), info.PID)
	fmt.Printf("%s %d\n", c(clrCyan, "PPID    "), info.PPID)
	fmt.Printf("%s %s\n", c(clrCyan, "Name    "), info.Name)
	if info.Exe != "" {
		fmt.Printf("%s %s\n", c(clrCyan, "Exe     "), c(clrGray, info.Exe))
	}
	fmt.Printf("%s %s\n", c(clrCyan, "CPU     "), c(cpuColor(info.CPU), fmt.Sprintf("%.1f%%", info.CPU)))
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

// ============================================================================
// Flag helpers
// ============================================================================

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

func getOpt(args []string, flags ...string) string {
	for i, a := range args {
		for _, f := range flags {
			if a == f && i+1 < len(args) {
				return args[i+1]
			}
		}
	}
	return ""
}

func getParallel(args []string) int {
	if s := getOpt(args, "--parallel"); s != "" {
		if v, err := strconv.Atoi(s); err == nil && v >= 1 {
			return v
		}
	}
	return 8
}

func orderFor(args []string, sortKey string) bool {
	o := getOpt(args, "--order")
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

// ============================================================================
// Query commands
// ============================================================================

func cmdList(args []string) {
	fields := defaultFields()
	if fs := getOpt(args, "--fields"); fs != "" {
		fields = parseFields(fs)
	}
	if has(args, "--detail") {
		fields = allFields()
	}
	parallel := getParallel(args)
	filterPat := getOpt(args, "--filter")
	limitN := 0
	if s := getOpt(args, "--limit"); s != "" {
		if v, err := strconv.Atoi(s); err == nil {
			limitN = v
		}
	}

	runOnce := func() []ProcInfo {
		snaps, err := listProcesses()
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return nil
		}
		procs := collectDetails(snaps, fields, parallel)
		percentWithWarmup(procs)
		if has(args, "-e", "--exclude-system") {
			procs = filterSystem(procs)
		}
		if filterPat != "" {
			procs = applyFilter(procs, filterPat)
		}
		sk := getOpt(args, "--sort")
		if sk == "" {
			sk = "cpu"
		}
		sortProcs(procs, sk, orderFor(args, sk))
		if limitN > 0 {
			procs = applyLimit(procs, limitN)
		}
		return procs
	}

	procs := runOnce()
	if procs == nil {
		exit(5)
	}
	if has(args, "--watch") {
		watchLoop(args, func() {
			p := runOnce()
			if has(args, "--tree") {
				if has(args, "--json") {
					printJSON(p)
				} else {
					printTree(p)
				}
				return
			}
			printProcs(p, has(args, "--json"))
		})
		return
	}
	if has(args, "--tree") {
		if has(args, "--json") {
			printJSON(procs)
		} else {
			printTree(procs)
		}
		return
	}
	printProcs(procs, has(args, "--json"))
}

func printProcs(procs []ProcInfo, asJSON bool) {
	if asJSON {
		printJSON(procs)
		return
	}
	header := fmt.Sprintf("%-7s %-20s %6s %-9s %s", "PID", "NAME", "CPU%", "MEM", "EXE")
	fmt.Println(c(clrBold+clrCyan, header))
	for _, p := range procs {
		exe := trunc(p.Exe, 64)
		line := c(clrCyan, fmt.Sprintf("%-7d", p.PID)) + " " +
			fmt.Sprintf("%-20s", trunc(p.Name, 20)) + " " +
			c(cpuColor(p.CPU), fmt.Sprintf("%6.1f", p.CPU)) + " " +
			c(clrYellow, fmt.Sprintf("%-9s", humanBytes(p.Mem))) + " " +
			c(clrGray, exe)
		fmt.Println(line)
	}
}

func cmdTotal(args []string) {
	if has(args, "--watch") {
		watchLoop(args, func() {
			s := collectSysInfo()
			printSys(s, has(args, "--json"))
		})
		return
	}
	sys := collectSysInfo()
	printSys(sys, has(args, "--json"))
}

func printSys(s SysInfo, asJSON bool) {
	if asJSON {
		printJSON(s)
		return
	}
	fmt.Println(c(clrBold+clrCyan, "System Resources"))
	fmt.Printf("  %s  %s  %s\n",
		c(clrCyan, "CPU   "),
		c(cpuColor(s.CPUPercent), fmt.Sprintf("%5.1f%%", s.CPUPercent)),
		c(clrGray, fmt.Sprintf("Logical %d / Physical %d", s.LogicalCPU, s.PhysicalCPU)))
	fmt.Printf("  %s  %s / %s  %s\n",
		c(clrCyan, "MEM   "),
		c(clrYellow, humanBytes(s.MemUsed)), humanBytes(s.MemTotal),
		c(clrGray, fmt.Sprintf("Free %s", humanBytes(s.MemFree))))
	fmt.Printf("  %s  %s\n", c(clrCyan, "Uptime"), s.Uptime)
	for _, d := range s.Disks {
		fmt.Printf("  %s  %5.1f%%  %s\n",
			c(clrCyan, d.Letter),
			d.Percent,
			c(clrGray, fmt.Sprintf("%s / %s", humanBytes(d.Free), humanBytes(d.Total))))
	}
}

func cmdSum(args []string) {
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
	parallel := getParallel(args)
	filterPat := getOpt(args, "--filter")

	runOnce := func() []ProcInfo {
		snaps, err := listProcesses()
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return nil
		}
		procs := collectDetails(snaps, allFields(), parallel)
		percentWithWarmup(procs)
		if filterPat != "" {
			procs = applyFilter(procs, filterPat)
		}
		sk := getOpt(args, "--sort")
		if sk == "" {
			sk = "cpu"
		}
		sortProcs(procs, sk, orderFor(args, sk))
		if n > 0 {
			procs = applyLimit(procs, n)
		}
		return procs
	}

	if has(args, "--watch") {
		watchLoop(args, func() {
			p := runOnce()
			printProcs(p, has(args, "--json"))
		})
		return
	}
	procs := runOnce()
	if procs == nil {
		exit(5)
	}
	printProcs(procs, has(args, "--json"))
}

func cmdMonitor(args []string) {
	interval := time.Second
	if s := getOpt(args, "--interval"); s != "" {
		if v, err := strconv.Atoi(s); err == nil {
			interval = time.Duration(v) * time.Millisecond
		}
	}
	if interval < 500*time.Millisecond {
		interval = 500 * time.Millisecond
	}
	fps := 30
	if s := getOpt(args, "--fps"); s != "" {
		if v, err := strconv.Atoi(s); err == nil {
			fps = v
		}
	}
	runTUI(interval, fps, has(args, "--no-mouse"), getParallel(args),
		defaultConfigPath(args), has(args, "--reset-config"))
}

// ============================================================================
// Control commands
// ============================================================================

func cmdKill(args []string, super bool) {
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
		exit(2)
	}
	pids, err := resolveTarget(target)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		exit(4)
	}
	tree := has(args, "--tree")
	noWarn := has(args, "--no-warn")
	ok := 0
	for _, pid := range pids {
		if isProtected(pid) {
			fmt.Fprintf(os.Stderr, "pid %d is protected by Windows\n", pid)
			continue
		}
		if super && !noWarn {
			fmt.Fprintf(os.Stderr, "about to force-kill pid %d, press Ctrl+C to cancel...\n", pid)
			time.Sleep(time.Second)
		}
		if err := killProcess(pid, tree); err != nil {
			fmt.Fprintf(os.Stderr, "kill %d: %v\n", pid, err)
			bugs.Add("WARN", "kill %d: %v", pid, err)
		} else {
			fmt.Printf("%s pid %d\n", c(clrGreen, "killed"), pid)
			ok++
		}
	}
	if ok == 0 {
		exit(2)
	}
	if ok < len(pids) {
		exit(1)
	}
	exit(0)
}

func cmdSuspendResume(args []string, doResume bool) {
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
		exit(2)
	}
	pids, err := resolveTarget(target)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		exit(4)
	}
	verb := "suspended"
	if doResume {
		verb = "resumed"
	}
	ok := 0
	for _, pid := range pids {
		var e error
		if doResume {
			e = resumeProcess(pid)
		} else {
			e = suspendProcess(pid)
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
		exit(2)
	}
	exit(0)
}

func cmdPriority(args []string) {
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
		fmt.Fprintln(os.Stderr, "usage: procctl priority <pid|name> <level>")
		fmt.Fprintln(os.Stderr, "  level: idle|below-normal|normal|above-normal|high|realtime")
		exit(2)
	}
	target, level := pos[0], pos[1]
	pids, err := resolveTarget(target)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		exit(4)
	}
	ok := 0
	for _, pid := range pids {
		if err := setPriority(pid, level); err != nil {
			fmt.Fprintf(os.Stderr, "priority %d: %v\n", pid, err)
			bugs.Add("WARN", "priority pid=%d: %v", pid, err)
		} else {
			fmt.Printf("%s pid %d = %s\n", c(clrGreen, "priority"), pid, level)
			ok++
		}
	}
	if ok == 0 {
		exit(2)
	}
	exit(0)
}

// ============================================================================
// limit: new single-target entry + legacy -p/-n via cmdLimitMixed
// ============================================================================

func cmdLimit(args []string) {
	if has(args, "-p", "--pid", "-n", "--name") {
		cmdLimitMixed(args)
		return
	}
	// New style: limit <pid|name> [LIMIT OPTIONS] [QUERY OPTIONS]
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
		fmt.Fprintln(os.Stderr, "usage: procctl limit <pid|name> [LIMIT OPTIONS]")
		exit(2)
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
	cmdLimitMixed(append([]string{"-p", target}, rest...))
}

func cmdLimitMixed(args []string) {
	targets := map[uint32]*ResourceLimits{}
	var order []uint32
	var queries []uint32
	assign := func(pids []uint32, lim *ResourceLimits) {
		for _, pid := range pids {
			if _, ok := targets[pid]; !ok {
				order = append(order, pid)
			}
			targets[pid] = lim
		}
	}
	queryFields := allFields()
	if fs := getOpt(args, "--fields"); fs != "" {
		queryFields = parseFields(fs)
	}
	i := 0
	for i < len(args) {
		a := args[i]
		switch a {
		case "-p", "--pid", "-n", "--name":
			i++
			if i >= len(args) {
				fmt.Fprintln(os.Stderr, "missing target")
				exit(2)
			}
			target := args[i]
			i++
			lim := &ResourceLimits{}
			for i < len(args) {
				consumed, ok := consumeLimitOption(args, i, lim)
				if !ok {
					break
				}
				i += consumed
			}
			pids, err := resolveTarget(target)
			if err != nil {
				fmt.Fprintf(os.Stderr, "%s: %v\n", target, err)
				bugs.Add("WARN", "resolve %s: %v", target, err)
				continue
			}
			if isEmptyLimits(lim) {
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
		if err := validateLimits(lim); err != nil {
			fmt.Fprintln(os.Stderr, err)
			bugs.Add("WARN", "validate pid=%d: %v", pid, err)
			continue
		}
		if err := attachAndLimit(pid, lim); err != nil {
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
		if err := queryAndPrint(pid, asJSON, queryFields); err != nil {
			fmt.Fprintf(os.Stderr, "query %d: %v\n", pid, err)
			bugs.Add("WARN", "query pid=%d: %v", pid, err)
		} else {
			qOK++
		}
	}

	if len(order) > 0 {
		if ok == 0 {
			exit(2)
		}
		if ok < total {
			exit(1)
		}
		exit(0)
	}
	if len(queries) > 0 {
		if qOK == 0 {
			exit(4)
		}
		exit(0)
	}
	exit(2)
}

// ============================================================================
// run
// ============================================================================

func cmdRun(args []string) {
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

	if admin && !elevated && !isAdmin() {
		fmt.Fprintln(os.Stderr, "requesting administrator privileges (UAC prompt)...")
		code, err := relaunchElevated(args)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%v\n", err)
			bugs.Add("ERR", "elevate: %v", err)
			exit(5)
		}
		exit(code)
	}

	lim := &ResourceLimits{}
	opts := &runOptions{}
	var cmdParts []string
	i := 0
	for i < len(args) {
		if args[i] == "--" {
			cmdParts = args[i+1:]
			break
		}
		if consumed, ok := consumeLimitOption(args, i, lim); ok {
			i += consumed
			continue
		}
		switch args[i] {
		case "--cwd":
			if i+1 >= len(args) {
				fmt.Fprintln(os.Stderr, "--cwd expects a directory")
				exit(2)
			}
			opts.workDir = args[i+1]
			i += 2
			continue
		case "--title":
			if i+1 >= len(args) {
				fmt.Fprintln(os.Stderr, "--title expects a string")
				exit(2)
			}
			opts.title = args[i+1]
			i += 2
			continue
		case "--priority":
			if i+1 >= len(args) {
				fmt.Fprintln(os.Stderr, "--priority expects a level: idle|below-normal|normal|above-normal|high|realtime")
				exit(2)
			}
			pc := priorityClass(args[i+1])
			if pc == 0 {
				fmt.Fprintf(os.Stderr, "invalid priority %q (valid: idle|below-normal|normal|above-normal|high|realtime)\n", args[i+1])
				exit(2)
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
		exit(2)
	}
	if err := validateLimits(lim); err != nil {
		fmt.Fprintln(os.Stderr, err)
		exit(2)
	}
	if lim.OnExit == "suspend" {
		bugs.Add("WARN", "run: on-exit=suspend is unreliable on Ctrl+C, degraded to keep")
	}
	cmdLine := buildRunCmdLine(cmdParts)
	code, err := runWithLimits(cmdLine, lim, opts)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		bugs.Add("ERR", "run: %v", err)
		exit(5)
	}
	exit(code)
}

// ============================================================================
// --watch
// ============================================================================

func watchLoop(args []string, fn func()) {
	d := time.Second
	if s := getOpt(args, "--watch"); s != "" {
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

// ============================================================================
// Tree rendering
// ============================================================================

func printTree(procs []ProcInfo) {
	byParent := make(map[uint32][]ProcInfo)
	pidSet := make(map[uint32]bool, len(procs))
	for _, p := range procs {
		pidSet[p.PID] = true
	}
	var roots []ProcInfo
	for _, p := range procs {
		if pidSet[p.PPID] && p.PPID != p.PID {
			byParent[p.PPID] = append(byParent[p.PPID], p)
		} else {
			roots = append(roots, p)
		}
	}
	var walk func(p ProcInfo, prefix string, last bool, depth int)
	walk = func(p ProcInfo, prefix string, last bool, depth int) {
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

// ============================================================================
// Help
// ============================================================================

func printHelp() {
	header := "procctl v1.0.0 (Windows)"
	fmt.Println(c(clrBold+clrCyan, header))
	fmt.Println("Windows process controller - query / monitor / limit / rollback")
	fmt.Println()
	fmt.Print(`USAGE
  procctl <command> [OPTIONS] [ARGS...]

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
  limit <pid|name> [LIMIT OPTIONS]  Limit one process (query if no limits)
  run [OPTIONS] -- <command>        Controlled launch
  history                           Show rollback-able operations
  rollback <N>                      Undo the most recent N operations
  help / version

GLOBAL OPTIONS
  -b, --bugs           Print collected errors/warnings on exit
  -o, --out <path>     Write output to file (list/total/sum/limit)
  --no-color           Disable color (also honors NO_COLOR env var)
  -h, --help           Show this help
  --version            Show version

LIST
  -e, --exclude-system Exclude system processes
  --detail             Show all fields
  --fields <f1,f2>     Custom fields
  --filter <pattern>   Filter by process name (case-insensitive)
  --limit <N>          Show only first N rows
  --sort <field>       cpu|mem|pid|name|create-time|io_read_b|io_write_b|threads|handles
  --order <asc|desc>   Sort order (name defaults asc, others desc)
  --tree               Process tree
  --json               JSON output
  --parallel <N>       Collection concurrency (default 8)
  --watch <interval>   Refresh -a/-t/-s periodically

MONITOR
  --interval <ms>      Refresh interval (default 1000, min 500)
  --fps <N>            Frame rate cap (15~60, default 30)
  --parallel <N>       Collection concurrency
  --no-mouse           Disable mouse
  --config <path>      Settings file path
  --reset-config       Reset settings
  Keys: q quit  Up/Down select  Space mark  K/X/Z/R control  / filter  P parent  F2 interval  Tab view  s sort

KILL / SUPERKILL
  --tree               Recursively kill subtree
  --no-warn            Skip warnings

PRIORITY LEVELS
  idle|below-normal|normal|above-normal|high|realtime

LIMIT OPTIONS (limit / run)
  --affinity --cpu --iops --io-read --io-write --mem --net --net-in
  --net-out --on-exit --process-count --timeout --working-set

RUN OPTIONS
  --admin              Re-launch procctl with UAC elevation, then run
                       the target with the requested limits. Example:
                         procctl --run --admin --mem 1G -- taskmgr.exe
  --cwd <dir>          Working directory for the child process
  --title <text>       Console window title
  --priority <level>   Startup priority
  --no-window          Create the child without a console window
  (any LIMIT OPTION above may also be used)

PRIORITY LEVELS
  idle | below-normal | normal | above-normal | high | realtime

LEGACY FLAGS (still accepted, mapped to subcommands)
  -a/--all -> list, -t/--total -> total, -s/--sum -> sum,
  -m/--monitor -> monitor, -k/--kill -> kill, -x/--super-kill -> superkill,
  --suspend / --resume / --priority, --run, -p/--pid / -n/--name -> limit,
  --history, --rollback

OPERATION LOG
  Every invocation appends one line to ./procctl_backup/procctl.log:
    [full command line] [timestamp] [numeric exit code]
  Help/version/list/total/sum/monitor and bare limit queries are logged but
  excluded from history/rollback (they have no side effects).
  history prints rollback-able operations in reverse order (1 = most recent).
  rollback <N> undoes the most recent N operations by executing their
  inverse command; non-invertible operations are reported as errors.

EXIT CODES
  0 success | 1 partial failure | 2 total failure/bad args | 3 permission denied
  4 process not found | 5 Windows API error
`)
}

// ============================================================================
// Entry
// ============================================================================

func main() {
	initAPIs()
	defer func() {
		if r := recover(); r != nil {
			bugs.enabled = true
			bugs.Add("PANIC", "%v", r)
			exit(5)
		}
	}()

	args := expandShortArgs(os.Args[1:])

	var filtered []string
	for _, a := range args {
		if a == "-b" || a == "--bugs" {
			bugs.enabled = true
			continue
		}
		filtered = append(filtered, a)
	}
	args = filtered

	initColor(args)
	checkRequiredAPIs()

	if hasBeforeDoubleDash(args, "--version") {
		fmt.Println("procctl v1.0.0")
		exit(0)
	}

	cmd, rest, ok := parseCommand(args)
	if !ok {
		if len(args) == 0 || has(args, "-h", "--help") {
			printHelp()
			exit(0)
		}
		fmt.Fprintln(os.Stderr, "unknown command, use -h for help")
		exit(2)
	}

	if cmd == "help" || hasBeforeDoubleDash(rest, "-h", "--help") {
		printHelp()
		exit(0)
	}
	if cmd == "version" {
		fmt.Println("procctl v1.0.0")
		exit(0)
	}

	switch cmd {
	case "list", "total", "sum", "limit":
		if !setupOutput(cmd, rest) {
			exit(2)
		}
	case "monitor":
		if has(rest, "-o", "--out") {
			fmt.Fprintln(os.Stderr, "-o/--out cannot be used with monitor")
			exit(2)
		}
	}

	switch cmd {
	case "list":
		cmdList(rest)
	case "total":
		cmdTotal(rest)
	case "sum":
		cmdSum(rest)
	case "monitor":
		cmdMonitor(rest)
	case "kill":
		cmdKill(rest, false)
	case "superkill":
		cmdKill(rest, true)
	case "suspend":
		cmdSuspendResume(rest, false)
	case "resume":
		cmdSuspendResume(rest, true)
	case "priority":
		cmdPriority(rest)
	case "limit":
		cmdLimit(rest)
	case "run":
		cmdRun(rest)
	case "history":
		cmdHistory()
	case "rollback":
		cmdRollback(rest)
	}
	exit(0)
}