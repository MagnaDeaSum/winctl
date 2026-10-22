//go:build windows && amd64

package main

// taskctl — Windows scheduled task and startup entry manager with rollback.
// Single-file, standard-library-only build:
//
//   go build -trimpath -ldflags "-s -w" -o taskctl.exe taskctl.go

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
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
	"unicode/utf8"
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
	pMultiByteToWideChar = kernel32.NewProc("MultiByteToWideChar")
	pGetACP              = kernel32.NewProc("GetACP")
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
		fmt.Fprintln(os.Stderr, "[taskctl] -b/--bugs enabled: no errors or warnings captured this run.")
		return
	}
	fmt.Fprintf(os.Stderr, "\n--- taskctl bugs report (%d entries) ---\n", len(b.entries))
	for _, e := range b.entries {
		fmt.Fprintf(os.Stderr, "[%s] %s %s\n", e.At.Format("15:04:05.000"), e.Level, e.Msg)
	}
	fmt.Fprintln(os.Stderr, "--- end of bugs report ---")
}

// ============================================================================
// Registry bindings (for startup entries)
// ============================================================================

var (
	advapi32 = syscall.NewLazyDLL("advapi32.dll")

	pRegOpenKeyExW   = advapi32.NewProc("RegOpenKeyExW")
	pRegCloseKey     = advapi32.NewProc("RegCloseKey")
	pRegEnumValueW   = advapi32.NewProc("RegEnumValueW")
	pRegSetValueExW  = advapi32.NewProc("RegSetValueExW")
	pRegDeleteValueW = advapi32.NewProc("RegDeleteValueW")
	pRegCreateKeyExW = advapi32.NewProc("RegCreateKeyExW")
)

const (
	HKCU = uintptr(0xFFFFFFFF80000001)
	HKLM = uintptr(0xFFFFFFFF80000002)

	KEY_QUERY_VALUE = 0x0001
	KEY_SET_VALUE   = 0x0002
	KEY_WOW64_32KEY = 0x0200
	KEY_WOW64_64KEY = 0x0100
	KEY_READ        = 0x20019
	KEY_WRITE       = 0x20006

	REG_SZ        = 1
	REG_EXPAND_SZ = 2

	ERROR_FILE_NOT_FOUND = syscall.Errno(2)
	ERROR_ACCESS_DENIED  = syscall.Errno(5)
	ERROR_NO_MORE_ITEMS  = syscall.Errno(259)
)

type RegKey uintptr

type RegValue struct {
	Name string
	Type uint32
	Data []byte
}

func regOpenKey(root uintptr, subKey string, samDesired uint32) (RegKey, error) {
	subPtr, err := syscall.UTF16PtrFromString(subKey)
	if err != nil {
		return 0, err
	}
	var phk uintptr
	r, _, _ := pRegOpenKeyExW.Call(root, uintptr(unsafe.Pointer(subPtr)), 0,
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

func regEnumValues(k RegKey) ([]RegValue, error) {
	var out []RegValue
	var idx uint32
	for {
		nameBuf := make([]uint16, 1024)
		nameSize := uint32(len(nameBuf))
		dataBuf := make([]byte, 65536)
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

func regSetValue(k RegKey, name string, typ uint32, data []byte) error {
	namePtr, _ := syscall.UTF16PtrFromString(name)
	var dataU uintptr
	if len(data) > 0 {
		dataU = uintptr(unsafe.Pointer(&data[0]))
	}
	r, _, _ := pRegSetValueExW.Call(uintptr(k), uintptr(unsafe.Pointer(namePtr)), 0,
		uintptr(typ), dataU, uintptr(len(data)))
	if r != 0 {
		return syscall.Errno(r)
	}
	return nil
}

func regDeleteValue(k RegKey, name string) error {
	namePtr, _ := syscall.UTF16PtrFromString(name)
	r, _, _ := pRegDeleteValueW.Call(uintptr(k), uintptr(unsafe.Pointer(namePtr)))
	if r != 0 {
		return syscall.Errno(r)
	}
	return nil
}

func regCreateKey(root uintptr, subKey string, samDesired uint32) (RegKey, error) {
	subPtr, _ := syscall.UTF16PtrFromString(subKey)
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

// ============================================================================
// Startup entry locations
// ============================================================================

type StartupLocation struct {
	Name    string
	Root    uintptr
	RootStr string
	SubKey  string
	Wow32   bool
	Folder  string
}

var startupLocations = []StartupLocation{
	{"HKCU Run", HKCU, "HKCU", `Software\Microsoft\Windows\CurrentVersion\Run`, false, ""},
	{"HKLM Run", HKLM, "HKLM", `Software\Microsoft\Windows\CurrentVersion\Run`, false, ""},
	{"HKLM Wow64 Run", HKLM, "HKLM", `Software\Microsoft\Windows\CurrentVersion\Run`, true, ""},
	{"HKCU RunOnce", HKCU, "HKCU", `Software\Microsoft\Windows\CurrentVersion\RunOnce`, false, ""},
	{"HKLM RunOnce", HKLM, "HKLM", `Software\Microsoft\Windows\CurrentVersion\RunOnce`, false, ""},
	{"HKLM Wow64 RunOnce", HKLM, "HKLM", `Software\Microsoft\Windows\CurrentVersion\RunOnce`, true, ""},
	{"HKLM Winlogon UserInit", HKLM, "HKLM", `SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`, false, ""},
	{"HKLM Winlogon Shell", HKLM, "HKLM", `SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`, false, ""},
}

var startupFolders = []struct {
	Name string
	Path string
}{
	{"User Startup Folder", ""},
	{"Common Startup Folder", ""},
}

func resolveStartupFolders() {
	userProfile := os.Getenv("USERPROFILE")
	if userProfile != "" {
		startupFolders[0].Path = filepath.Join(userProfile,
			`AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup`)
	}
	programData := os.Getenv("ProgramData")
	if programData != "" {
		startupFolders[1].Path = filepath.Join(programData,
			`Microsoft\Windows\Start Menu\Programs\Startup`)
	}
}

type StartupEntry struct {
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

// ============================================================================
// UTF-16 helpers
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

// ============================================================================
// .reg export for a single registry key
// ============================================================================

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

func hexJoin(b []byte) string {
	parts := make([]string, len(b))
	for i, x := range b {
		parts[i] = fmt.Sprintf("%02x", x)
	}
	return strings.Join(parts, ",")
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

func toUTF16LEBOM(s string) []byte {
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

func exportRegKey(root uintptr, rootStr, subKey string, wow32 bool) (string, error) {
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
	fullPath := rootStr + `\` + subKey
	buf.WriteString("[" + fullPath + "]\r\n")

	vals, _ := regEnumValues(k)
	for _, v := range vals {
		buf.WriteString(`"` + v.Name + `"=`)
		switch v.Type {
		case REG_SZ:
			buf.WriteString(`"` + decodeRegString(v.Data) + `"` + "\r\n")
		case REG_EXPAND_SZ:
			buf.WriteString("hex(2):" + hexJoin(v.Data) + "\r\n")
		default:
			buf.WriteString("hex:" + hexJoin(v.Data) + "\r\n")
		}
	}
	return buf.String(), nil
}

// ============================================================================
// Code page decoding for subprocess output
// ============================================================================

// decodeCP converts b from code page cp to a Go string. cp == 0 means "use
// the system ANSI code page". The function relies on MultiByteToWideChar so
// no external tables are needed.
func decodeCP(b []byte, cp uint32) string {
	if len(b) == 0 {
		return ""
	}
	if cp == 0 {
		r, _, _ := pGetACP.Call()
		cp = uint32(r)
	}
	if cp == 0 || cp == 65001 {
		return string(b)
	}
	// First call: get required buffer length.
	n, _, _ := pMultiByteToWideChar.Call(
		uintptr(cp), 0,
		uintptr(unsafe.Pointer(&b[0])), uintptr(len(b)),
		0, 0)
	if n == 0 {
		return string(b)
	}
	buf := make([]uint16, n)
	n2, _, _ := pMultiByteToWideChar.Call(
		uintptr(cp), 0,
		uintptr(unsafe.Pointer(&b[0])), uintptr(len(b)),
		uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)))
	if n2 == 0 {
		return string(b)
	}
	return string(utf16Decode(buf[:n2]))
}

// decodeConsoleOutput decodes schtasks.exe output. It handles UTF-16LE with
// and without BOM, UTF-8 with and without BOM, and the system ANSI code page
// (CP936 on Chinese Windows, CP1252 on English Windows, etc.).
func decodeConsoleOutput(b []byte) string {
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
	// Heuristic for UTF-16LE without BOM: every other byte is zero.
	if len(b) >= 4 && b[1] == 0 && b[3] == 0 {
		u := make([]uint16, len(b)/2)
		for i := 0; i < len(u); i++ {
			u[i] = uint16(b[i*2]) | uint16(b[i*2+1])<<8
		}
		return string(utf16Decode(u))
	}
	if utf8.Valid(b) {
		return string(b)
	}
	return decodeCP(b, 0)
}

// ============================================================================
// schtasks.exe wrapper
// ============================================================================

func schtasksPath() string {
	return filepath.Join(os.Getenv("SystemRoot"), "System32", "schtasks.exe")
}

// runSchtasks runs schtasks and returns text output decoded from the console
// code page. Use exportTaskXML when you need raw XML bytes.
func runSchtasks(args ...string) (stdout, stderr string, exitCode int) {
	cmd := exec.Command(schtasksPath(), args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	var outBuf, errBuf bytes.Buffer
	cmd.Stdout = &outBuf
	cmd.Stderr = &errBuf
	err := cmd.Run()
	stdout = decodeConsoleOutput(outBuf.Bytes())
	stderr = decodeConsoleOutput(errBuf.Bytes())
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			exitCode = ee.ExitCode()
		} else {
			exitCode = -1
		}
	}
	return stdout, stderr, exitCode
}

// ============================================================================
// Task listing
// ============================================================================

type TaskInfo struct {
	Name        string
	Status      string
	NextRunTime string
	TaskToRun   string
}

func listTasks() ([]TaskInfo, error) {
	stdout, stderr, code := runSchtasks("/query", "/fo", "csv", "/nh", "/v")
	if code != 0 && stdout == "" {
		return nil, fmt.Errorf("schtasks query failed: %s", strings.TrimSpace(stderr))
	}

	var tasks []TaskInfo
	scanner := bufio.NewScanner(strings.NewReader(stdout))
	scanner.Buffer(make([]byte, 64*1024), 4*1024*1024)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		fields := splitCSV(line)
		if len(fields) < 9 {
			continue
		}
		t := TaskInfo{
			Name:        fields[1],
			NextRunTime: fields[2],
			Status:      fields[3],
			TaskToRun:   fields[8],
		}
		if t.Name == "" || strings.EqualFold(t.Name, "TaskName") || t.Name == "任务名" {
			continue
		}
		tasks = append(tasks, t)
	}
	sort.Slice(tasks, func(i, j int) bool { return tasks[i].Name < tasks[j].Name })
	return tasks, nil
}

func splitCSV(line string) []string {
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

// ============================================================================
// Task XML export (raw bytes, no transcoding)
// ============================================================================

// exportTaskXML returns the raw bytes produced by
//   schtasks.exe /query /tn <task> /xml
// On Windows 10/11 this is UTF-16LE with BOM and an XML declaration of
// encoding="UTF-16". We must not transcode it, otherwise schtasks /create /xml
// will reject the file on rollback.
func exportTaskXML(taskName string) ([]byte, error) {
	cmd := exec.Command(schtasksPath(), "/query", "/tn", taskName, "/xml")
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	var errBuf bytes.Buffer
	cmd.Stderr = &errBuf
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("schtasks /query /xml: %s",
			strings.TrimSpace(decodeConsoleOutput(errBuf.Bytes())))
	}
	return out, nil
}

// ============================================================================
// Startup entry listing
// ============================================================================

func listStartupEntries() ([]StartupEntry, error) {
	resolveStartupFolders()
	var out []StartupEntry

	for _, loc := range startupLocations {
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
			out = append(out, StartupEntry{
				Location: loc.Name,
				Root:     loc.RootStr,
				SubKey:   loc.SubKey,
				Name:     v.Name,
				Command:  cmd,
				Type:     v.Type,
				Wow32:    loc.Wow32,
			})
		}
	}

	for _, folder := range startupFolders {
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
			out = append(out, StartupEntry{
				Location: folder.Name,
				Name:     e.Name(),
				IsFolder: true,
				FullPath: filepath.Join(folder.Path, e.Name()),
			})
		}
	}
	return out, nil
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
// Paths, log
// ============================================================================

const (
	backupDirName = "taskctl_backup"
	logFileName   = "taskctl.log"
	opsDirName    = "ops"
	filesDirName  = "files"
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
func filesDir() string   { return filepath.Join(backupRoot(), filesDirName) }

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
// Operation records
// ============================================================================

type opRecord struct {
	Op            string `json:"op"`
	TS            string `json:"ts"`
	Cmd           string `json:"cmd"`
	Code          int    `json:"code"`
	TaskName      string `json:"taskName,omitempty"`
	BackupFile    string `json:"backupFile,omitempty"`
	BackupGzipped bool   `json:"backupGzipped,omitempty"`
	ExistedBefore bool   `json:"existedBefore"`

	StartupLocation string `json:"startupLocation,omitempty"`
	StartupRoot     string `json:"startupRoot,omitempty"`
	StartupSubKey   string `json:"startupSubKey,omitempty"`
	StartupName     string `json:"startupName,omitempty"`
	StartupWow32    bool   `json:"startupWow32,omitempty"`
	StartupIsFolder bool   `json:"startupIsFolder,omitempty"`
	StartupFullPath string `json:"startupFullPath,omitempty"`

	WasEnabled *bool `json:"wasEnabled,omitempty"`
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
	_ = os.MkdirAll(backupRoot(), 0755)
	_ = os.MkdirAll(opsDir(), 0755)
	_ = os.MkdirAll(filesDir(), 0755)
	return countLogLines()
}

// ============================================================================
// Backup helpers
// ============================================================================

const smallXMLThreshold = 8192

var sanitizeRe = regexp.MustCompile(`[^A-Za-z0-9._-]`)

func sanitizeForFilename(s string) string {
	s = strings.ReplaceAll(s, `\`, "_")
	s = sanitizeRe.ReplaceAllString(s, "_")
	if len(s) > 80 {
		s = s[:80]
	}
	return s
}

// backupTaskXML writes the raw schtasks XML to disk, gzipping when it exceeds
// the small-file threshold.
func backupTaskXML(taskName string, logIdx int) (string, bool, error) {
	xmlData, err := exportTaskXML(taskName)
	if err != nil {
		return "", false, err
	}
	base := fmt.Sprintf("%d_%s", logIdx, sanitizeForFilename(taskName))
	if len(xmlData) < smallXMLThreshold {
		rel := base + ".xml"
		full := filepath.Join(filesDir(), rel)
		if err := os.MkdirAll(filepath.Dir(full), 0755); err != nil {
			return "", false, err
		}
		if err := os.WriteFile(full, xmlData, 0644); err != nil {
			return "", false, err
		}
		return rel, false, nil
	}
	rel := base + ".xml.gz"
	full := filepath.Join(filesDir(), rel)
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
	if _, err := gz.Write(xmlData); err != nil {
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

func backupStartupKey(root uintptr, rootStr, subKey string, wow32 bool, logIdx int) (string, bool, error) {
	regText, err := exportRegKey(root, rootStr, subKey, wow32)
	if err != nil {
		return "", false, err
	}
	raw := toUTF16LEBOM(regText)
	base := fmt.Sprintf("%d_%s_%s", logIdx, rootStr, sanitizeForFilename(subKey))
	if len(raw) < smallXMLThreshold {
		rel := base + ".reg"
		full := filepath.Join(filesDir(), rel)
		if err := os.MkdirAll(filepath.Dir(full), 0755); err != nil {
			return "", false, err
		}
		if err := os.WriteFile(full, raw, 0644); err != nil {
			return "", false, err
		}
		return rel, false, nil
	}
	rel := base + ".reg.gz"
	full := filepath.Join(filesDir(), rel)
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

func importRegFile(relPath string, gzipped bool) error {
	src := filepath.Join(filesDir(), relPath)
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
		tmp, err := os.CreateTemp("", "taskctl_*.reg")
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
// ls (task listing)
// ============================================================================

func cmdLs(args []string) int {
	filter := ""
	for _, a := range args {
		if strings.HasPrefix(a, "-") {
			fmt.Fprintf(os.Stderr, "ls: unknown option %s\n", a)
			return 2
		}
		filter = a
	}

	tasks, err := listTasks()
	if err != nil {
		fmt.Fprintf(os.Stderr, "taskctl: %v\n", err)
		return 5
	}
	if filter != "" {
		lower := strings.ToLower(filter)
		var filtered []TaskInfo
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
		padRight("NEXT RUN", nextW) + "  " +
		"TASK TO RUN"
	fmt.Println(c(clrBold+clrCyan, header))
	for _, t := range tasks {
		statusColor := clrGray
		switch t.Status {
		case "Ready", "就绪":
			statusColor = clrGreen
		case "Running", "正在运行":
			statusColor = clrYellow
		case "Disabled", "已禁用":
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

// ============================================================================
// startup (listing)
// ============================================================================

func cmdStartup(args []string) int {
	jsonOut := false
	for _, a := range args {
		if a == "--json" {
			jsonOut = true
		} else if strings.HasPrefix(a, "-") {
			fmt.Fprintf(os.Stderr, "startup: unknown option %s\n", a)
			return 2
		}
	}

	entries, err := listStartupEntries()
	if err != nil {
		fmt.Fprintf(os.Stderr, "taskctl: %v\n", err)
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
			c(clrCyan, padRight(e.Name, nameW)) + "  " +
			c(clrGray, target))
	}
	fmt.Fprintf(os.Stderr, "\n%d startup entry(ies)\n", len(entries))
	return 0
}

// ============================================================================
// create
// ============================================================================

func cmdCreate(args []string) int {
	var taskName, xmlFile, cmdRun, schedule, startTime, runAs string
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "-n", "--name":
			if i+1 >= len(args) {
				fmt.Fprintln(os.Stderr, "create: -n requires a name")
				return 2
			}
			taskName = args[i+1]
			i++
		case "--xml":
			if i+1 >= len(args) {
				fmt.Fprintln(os.Stderr, "create: --xml requires a file")
				return 2
			}
			xmlFile = args[i+1]
			i++
		case "-c", "--command":
			if i+1 >= len(args) {
				fmt.Fprintln(os.Stderr, "create: -c requires a command")
				return 2
			}
			cmdRun = args[i+1]
			i++
		case "-s", "--schedule":
			if i+1 >= len(args) {
				fmt.Fprintln(os.Stderr, "create: -s requires a schedule")
				return 2
			}
			schedule = args[i+1]
			i++
		case "-t", "--start-time":
			if i+1 >= len(args) {
				fmt.Fprintln(os.Stderr, "create: -t requires a time")
				return 2
			}
			startTime = args[i+1]
			i++
		case "-u", "--run-as":
			if i+1 >= len(args) {
				fmt.Fprintln(os.Stderr, "create: -u requires a user")
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
		fmt.Fprintln(os.Stderr, "usage: taskctl create -n <name> (-c <cmd> -s <sched> | --xml <file>) [-t <time>] [-u <user>]")
		return 2
	}

	_, _, qcode := runSchtasks("/query", "/tn", taskName)
	existsBefore := qcode == 0

	if dryRun {
		fmt.Printf("[dry-run] create task %q (exists=%v)\n", taskName, existsBefore)
		return 0
	}

	idx := beginWriteOp()
	backupRel := ""
	backupGz := false
	if existsBefore {
		var err error
		backupRel, backupGz, err = backupTaskXML(taskName, idx)
		if err != nil {
			fmt.Fprintf(os.Stderr, "taskctl: backup failed, aborting: %v\n", err)
			return 5
		}
	}

	var code int
	if xmlFile != "" {
		_, stderr, c := runSchtasks("/create", "/tn", taskName, "/xml", xmlFile, "/f")
		if c != 0 {
			fmt.Fprintf(os.Stderr, "taskctl: create from xml: %s\n", strings.TrimSpace(stderr))
			code = 5
		}
	} else {
		if cmdRun == "" || schedule == "" {
			fmt.Fprintln(os.Stderr, "create: -c and -s are required unless --xml is used")
			return 2
		}
		sargs := []string{"/create", "/tn", taskName, "/tr", cmdRun, "/sc", schedule}
		if startTime != "" {
			sargs = append(sargs, "/st", startTime)
		}
		if runAs != "" {
			sargs = append(sargs, "/ru", runAs)
		}
		sargs = append(sargs, "/f")
		_, stderr, c := runSchtasks(sargs...)
		if c != 0 {
			fmt.Fprintf(os.Stderr, "taskctl: create: %s\n", strings.TrimSpace(stderr))
			code = 5
		}
	}

	rec := &opRecord{
		Op:            "create",
		TS:            time.Now().Format("2006-01-02 15:04:05"),
		Cmd:           buildCmdLine(os.Args),
		TaskName:      taskName,
		ExistedBefore: existsBefore,
		BackupFile:    backupRel,
		BackupGzipped: backupGz,
	}
	saveOpRecord(idx, rec)

	if code == 0 {
		fmt.Printf("%s task %s\n", c(clrGreen, "created"), c(clrCyan, taskName))
	}
	return code
}

// ============================================================================
// delete
// ============================================================================

func cmdDelete(args []string) int {
	force := false
	var taskName string
	for _, a := range args {
		switch a {
		case "-f", "--force":
			force = true
		default:
			if strings.HasPrefix(a, "-") {
				fmt.Fprintf(os.Stderr, "delete: unknown option %s\n", a)
				return 2
			}
			taskName = a
		}
	}
	if taskName == "" {
		fmt.Fprintln(os.Stderr, "usage: taskctl delete <task> [-f]")
		return 2
	}

	_, _, qcode := runSchtasks("/query", "/tn", taskName)
	if qcode != 0 {
		fmt.Fprintf(os.Stderr, "taskctl: task %q not found\n", taskName)
		return 4
	}

	if dryRun {
		fmt.Printf("[dry-run] delete task %q\n", taskName)
		return 0
	}

	if !force {
		if !confirm(fmt.Sprintf("delete task %q?", taskName)) {
			return 1
		}
	}

	idx := beginWriteOp()
	backupRel, backupGz, err := backupTaskXML(taskName, idx)
	if err != nil {
		fmt.Fprintf(os.Stderr, "taskctl: backup failed, aborting: %v\n", err)
		return 5
	}

	_, stderr, code := runSchtasks("/delete", "/tn", taskName, "/f")
	rec := &opRecord{
		Op:            "delete",
		TS:            time.Now().Format("2006-01-02 15:04:05"),
		Cmd:           buildCmdLine(os.Args),
		TaskName:      taskName,
		ExistedBefore: true,
		BackupFile:    backupRel,
		BackupGzipped: backupGz,
	}
	saveOpRecord(idx, rec)

	if code != 0 {
		fmt.Fprintf(os.Stderr, "taskctl: delete: %s\n", strings.TrimSpace(stderr))
		return 5
	}
	fmt.Printf("%s task %s\n", c(clrYellow, "deleted"), c(clrCyan, taskName))
	return 0
}

// ============================================================================
// enable / disable
// ============================================================================

func cmdEnableDisable(args []string, enable bool) int {
	force := false
	var taskName string
	for _, a := range args {
		switch a {
		case "-f", "--force":
			force = true
		default:
			if strings.HasPrefix(a, "-") {
				fmt.Fprintf(os.Stderr, "%s: unknown option %s\n", actionName(enable), a)
				return 2
			}
			taskName = a
		}
	}
	if taskName == "" {
		fmt.Fprintf(os.Stderr, "usage: taskctl %s <task> [-f]\n", actionName(enable))
		return 2
	}

	_, _, qcode := runSchtasks("/query", "/tn", taskName)
	if qcode != 0 {
		fmt.Fprintf(os.Stderr, "taskctl: task %q not found\n", taskName)
		return 4
	}

	wasEnabled := currentTaskEnabled(taskName)

	if dryRun {
		fmt.Printf("[dry-run] %s task %q (currently enabled=%v)\n", actionName(enable), taskName, wasEnabled)
		return 0
	}

	if !force && !confirm(fmt.Sprintf("%s task %q?", actionName(enable), taskName)) {
		return 1
	}

	idx := beginWriteOp()
	backupRel, backupGz, err := backupTaskXML(taskName, idx)
	if err != nil {
		fmt.Fprintf(os.Stderr, "taskctl: backup failed, aborting: %v\n", err)
		return 5
	}

	verb := "/enable"
	if !enable {
		verb = "/disable"
	}
	_, stderr, code := runSchtasks("/change", "/tn", taskName, verb)

	rec := &opRecord{
		Op:            actionName(enable),
		TS:            time.Now().Format("2006-01-02 15:04:05"),
		Cmd:           buildCmdLine(os.Args),
		TaskName:      taskName,
		ExistedBefore: true,
		BackupFile:    backupRel,
		BackupGzipped: backupGz,
		WasEnabled:    &wasEnabled,
	}
	saveOpRecord(idx, rec)

	if code != 0 {
		fmt.Fprintf(os.Stderr, "taskctl: %s: %s\n", actionName(enable), strings.TrimSpace(stderr))
		return 5
	}
	fmt.Printf("%s task %s\n", c(clrGreen, actionName(enable)+"d"), c(clrCyan, taskName))
	return 0
}

func actionName(enable bool) string {
	if enable {
		return "enable"
	}
	return "disable"
}

func currentTaskEnabled(taskName string) bool {
	stdout, _, code := runSchtasks("/query", "/tn", taskName, "/fo", "list", "/v")
	if code != 0 {
		return true
	}
	for _, line := range strings.Split(stdout, "\n") {
		lower := strings.ToLower(line)
		if strings.Contains(lower, "status") || strings.Contains(line, "状态") {
			if strings.Contains(lower, "disabled") || strings.Contains(line, "已禁用") {
				return false
			}
			return true
		}
	}
	return true
}

// ============================================================================
// export / import
// ============================================================================

func cmdExport(args []string) int {
	var taskName, outFile string
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "-n", "--name":
			if i+1 >= len(args) {
				fmt.Fprintln(os.Stderr, "export: -n requires a task name")
				return 2
			}
			taskName = args[i+1]
			i++
		case "-o", "--out":
			if i+1 >= len(args) {
				fmt.Fprintln(os.Stderr, "export: -o requires a path")
				return 2
			}
			outFile = args[i+1]
			i++
		default:
			if strings.HasPrefix(args[i], "-") {
				fmt.Fprintf(os.Stderr, "export: unknown option %s\n", args[i])
				return 2
			}
			taskName = args[i]
		}
	}
	if taskName == "" {
		fmt.Fprintln(os.Stderr, "usage: taskctl export -n <task> [-o file.xml]")
		return 2
	}

	data, err := exportTaskXML(taskName)
	if err != nil {
		fmt.Fprintf(os.Stderr, "taskctl: %v\n", err)
		return 5
	}
	if outFile != "" {
		dir := filepath.Dir(outFile)
		if dir != "" && dir != "." {
			_ = os.MkdirAll(dir, 0755)
		}
		if err := os.WriteFile(outFile, data, 0644); err != nil {
			fmt.Fprintf(os.Stderr, "taskctl: %v\n", err)
			return 5
		}
		fmt.Fprintf(os.Stderr, "exported to %s\n", outFile)
		return 0
	}
	os.Stdout.Write(data)
	return 0
}

func cmdImport(args []string) int {
	var taskName, xmlFile string
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "-n", "--name":
			if i+1 >= len(args) {
				fmt.Fprintln(os.Stderr, "import: -n requires a task name")
				return 2
			}
			taskName = args[i+1]
			i++
		default:
			if strings.HasPrefix(args[i], "-") {
				fmt.Fprintf(os.Stderr, "import: unknown option %s\n", args[i])
				return 2
			}
			xmlFile = args[i]
		}
	}
	if taskName == "" || xmlFile == "" {
		fmt.Fprintln(os.Stderr, "usage: taskctl import -n <task> <file.xml>")
		return 2
	}

	_, _, qcode := runSchtasks("/query", "/tn", taskName)
	existsBefore := qcode == 0

	if dryRun {
		fmt.Printf("[dry-run] import task %q from %s (exists=%v)\n", taskName, xmlFile, existsBefore)
		return 0
	}

	idx := beginWriteOp()
	backupRel := ""
	backupGz := false
	if existsBefore {
		var err error
		backupRel, backupGz, err = backupTaskXML(taskName, idx)
		if err != nil {
			fmt.Fprintf(os.Stderr, "taskctl: backup failed, aborting: %v\n", err)
			return 5
		}
	}

	_, stderr, code := runSchtasks("/create", "/tn", taskName, "/xml", xmlFile, "/f")
	rec := &opRecord{
		Op:            "import",
		TS:            time.Now().Format("2006-01-02 15:04:05"),
		Cmd:           buildCmdLine(os.Args),
		TaskName:      taskName,
		ExistedBefore: existsBefore,
		BackupFile:    backupRel,
		BackupGzipped: backupGz,
	}
	saveOpRecord(idx, rec)

	if code != 0 {
		fmt.Fprintf(os.Stderr, "taskctl: import: %s\n", strings.TrimSpace(stderr))
		return 5
	}
	fmt.Printf("%s task %s\n", c(clrGreen, "imported"), c(clrCyan, taskName))
	return 0
}

// ============================================================================
// run
// ============================================================================

func cmdRun(args []string) int {
	var taskName string
	for _, a := range args {
		if strings.HasPrefix(a, "-") {
			fmt.Fprintf(os.Stderr, "run: unknown option %s\n", a)
			return 2
		}
		taskName = a
	}
	if taskName == "" {
		fmt.Fprintln(os.Stderr, "usage: taskctl run <task>")
		return 2
	}
	if dryRun {
		fmt.Printf("[dry-run] run task %q\n", taskName)
		return 0
	}
	_, stderr, code := runSchtasks("/run", "/tn", taskName)
	if code != 0 {
		fmt.Fprintf(os.Stderr, "taskctl: run: %s\n", strings.TrimSpace(stderr))
		return 5
	}
	fmt.Printf("%s task %s\n", c(clrGreen, "started"), c(clrCyan, taskName))
	return 0
}

// ============================================================================
// Startup add / del
// ============================================================================

func cmdStartupAdd(args []string) int {
	var locName, name, command string
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "-l", "--location":
			if i+1 >= len(args) {
				fmt.Fprintln(os.Stderr, "startup-add: -l requires a location")
				return 2
			}
			locName = args[i+1]
			i++
		case "-n", "--name":
			if i+1 >= len(args) {
				fmt.Fprintln(os.Stderr, "startup-add: -n requires a name")
				return 2
			}
			name = args[i+1]
			i++
		case "-c", "--command":
			if i+1 >= len(args) {
				fmt.Fprintln(os.Stderr, "startup-add: -c requires a command")
				return 2
			}
			command = args[i+1]
			i++
		default:
			if strings.HasPrefix(args[i], "-") {
				fmt.Fprintf(os.Stderr, "startup-add: unknown option %s\n", args[i])
				return 2
			}
		}
	}
	if locName == "" || name == "" || command == "" {
		fmt.Fprintln(os.Stderr, "usage: taskctl startup-add -l <HKCU Run|HKLM Run|...> -n <name> -c <command>")
		return 2
	}

	var loc *StartupLocation
	for i := range startupLocations {
		if strings.EqualFold(startupLocations[i].Name, locName) {
			loc = &startupLocations[i]
			break
		}
	}
	if loc == nil {
		fmt.Fprintf(os.Stderr, "startup-add: unknown location %q\n", locName)
		fmt.Fprintln(os.Stderr, "  available:")
		for _, l := range startupLocations {
			fmt.Fprintln(os.Stderr, "    "+l.Name)
		}
		return 2
	}

	access := uint32(KEY_READ | KEY_WOW64_64KEY)
	if loc.Wow32 {
		access = KEY_READ | KEY_WOW64_32KEY
	}
	k, err := regOpenKey(loc.Root, loc.SubKey, access)
	if err != nil {
		fmt.Fprintf(os.Stderr, "taskctl: %v\n", err)
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

	idx := beginWriteOp()
	backupRel := ""
	backupGz := false
	if existsBefore {
		backupRel, backupGz, err = backupStartupKey(loc.Root, loc.RootStr, loc.SubKey, loc.Wow32, idx)
		if err != nil {
			fmt.Fprintf(os.Stderr, "taskctl: backup failed, aborting: %v\n", err)
			return 5
		}
	}

	writeAccess := uint32(KEY_SET_VALUE | KEY_WOW64_64KEY)
	if loc.Wow32 {
		writeAccess = KEY_SET_VALUE | KEY_WOW64_32KEY
	}
	wk, err := regCreateKey(loc.Root, loc.SubKey, writeAccess)
	if err != nil {
		fmt.Fprintf(os.Stderr, "taskctl: create key: %v\n", err)
		return 5
	}
	err = regSetValue(wk, name, REG_SZ, encodeRegString(command))
	regCloseKey(wk)

	rec := &opRecord{
		Op:              "startup-add",
		TS:              time.Now().Format("2006-01-02 15:04:05"),
		Cmd:             buildCmdLine(os.Args),
		StartupLocation: loc.Name,
		StartupRoot:     loc.RootStr,
		StartupSubKey:   loc.SubKey,
		StartupName:     name,
		StartupWow32:    loc.Wow32,
		ExistedBefore:   existsBefore,
		BackupFile:      backupRel,
		BackupGzipped:   backupGz,
	}
	saveOpRecord(idx, rec)

	if err != nil {
		fmt.Fprintf(os.Stderr, "taskctl: set value: %v\n", err)
		return 5
	}
	fmt.Printf("%s startup %s\\%s = %s\n", c(clrGreen, "added"), loc.Name, c(clrCyan, name), command)
	return 0
}

func cmdStartupDel(args []string) int {
	force := false
	var locName, name string
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "-f", "--force":
			force = true
		case "-l", "--location":
			if i+1 >= len(args) {
				fmt.Fprintln(os.Stderr, "startup-del: -l requires a location")
				return 2
			}
			locName = args[i+1]
			i++
		case "-n", "--name":
			if i+1 >= len(args) {
				fmt.Fprintln(os.Stderr, "startup-del: -n requires a name")
				return 2
			}
			name = args[i+1]
			i++
		default:
			if strings.HasPrefix(args[i], "-") {
				fmt.Fprintf(os.Stderr, "startup-del: unknown option %s\n", args[i])
				return 2
			}
		}
	}
	if locName == "" || name == "" {
		fmt.Fprintln(os.Stderr, "usage: taskctl startup-del -l <location> -n <name> [-f]")
		return 2
	}

	var loc *StartupLocation
	for i := range startupLocations {
		if strings.EqualFold(startupLocations[i].Name, locName) {
			loc = &startupLocations[i]
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
		fmt.Fprintf(os.Stderr, "taskctl: %v\n", err)
		return 5
	}
	defer regCloseKey(k)
	existing, _ := regEnumValues(k)
	found := false
	for _, v := range existing {
		if strings.EqualFold(v.Name, name) {
			found = true
			break
		}
	}
	if !found {
		fmt.Fprintf(os.Stderr, "taskctl: %s\\%s not found\n", loc.Name, name)
		return 4
	}

	if dryRun {
		fmt.Printf("[dry-run] startup-del %s\\%s\n", loc.Name, name)
		return 0
	}

	if !force {
		if !confirm(fmt.Sprintf("delete startup entry %s\\%s?", loc.Name, name)) {
			return 1
		}
	}

	idx := beginWriteOp()
	backupRel, backupGz, err := backupStartupKey(loc.Root, loc.RootStr, loc.SubKey, loc.Wow32, idx)
	if err != nil {
		fmt.Fprintf(os.Stderr, "taskctl: backup failed, aborting: %v\n", err)
		return 5
	}

	writeAccess := uint32(KEY_SET_VALUE | KEY_WOW64_64KEY)
	if loc.Wow32 {
		writeAccess = KEY_SET_VALUE | KEY_WOW64_32KEY
	}
	wk, err := regOpenKey(loc.Root, loc.SubKey, writeAccess)
	if err != nil {
		fmt.Fprintf(os.Stderr, "taskctl: %v\n", err)
		return 5
	}
	defer regCloseKey(wk)
	if err := regDeleteValue(wk, name); err != nil {
		fmt.Fprintf(os.Stderr, "taskctl: delete value: %v\n", err)
		return 5
	}

	rec := &opRecord{
		Op:              "startup-del",
		TS:              time.Now().Format("2006-01-02 15:04:05"),
		Cmd:             buildCmdLine(os.Args),
		StartupLocation: loc.Name,
		StartupRoot:     loc.RootStr,
		StartupSubKey:   loc.SubKey,
		StartupName:     name,
		StartupWow32:    loc.Wow32,
		ExistedBefore:   true,
		BackupFile:      backupRel,
		BackupGzipped:   backupGz,
	}
	saveOpRecord(idx, rec)

	fmt.Printf("%s startup %s\\%s\n", c(clrYellow, "deleted"), loc.Name, c(clrCyan, name))
	return 0
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

// ============================================================================
// Rollback
// ============================================================================

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
		cmd, ok := parseLogLine(lines[i])
		if !ok || isHistorySelf(cmd) {
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
	case "create":
		if rec.ExistedBefore {
			return restoreTaskFromBackup(rec)
		}
		return deleteTaskQuiet(rec.TaskName)

	case "delete":
		return restoreTaskFromBackup(rec)

	case "import":
		if rec.ExistedBefore {
			return restoreTaskFromBackup(rec)
		}
		return deleteTaskQuiet(rec.TaskName)

	case "enable":
		if rec.WasEnabled != nil && !*rec.WasEnabled {
			return setTaskEnabled(rec.TaskName, false)
		}
		return nil

	case "disable":
		if rec.WasEnabled != nil && *rec.WasEnabled {
			return setTaskEnabled(rec.TaskName, true)
		}
		return nil

	case "run":
		return fmt.Errorf("run has no inverse")

	case "startup-add":
		if rec.ExistedBefore {
			return importRegFile(rec.BackupFile, rec.BackupGzipped)
		}
		return deleteStartupValue(rec)

	case "startup-del":
		return importRegFile(rec.BackupFile, rec.BackupGzipped)
	}
	return fmt.Errorf("unknown op %q", rec.Op)
}

func restoreTaskFromBackup(rec *opRecord) error {
	src := filepath.Join(filesDir(), rec.BackupFile)
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
		tmp, err := os.CreateTemp("", "taskctl_restore_*.xml")
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

	deleteTaskQuiet(rec.TaskName)
	_, stderr, code := runSchtasks("/create", "/tn", rec.TaskName, "/xml", xmlPath, "/f")
	if code != 0 {
		return fmt.Errorf("schtasks /create: %s", strings.TrimSpace(stderr))
	}
	return nil
}

func deleteTaskQuiet(taskName string) error {
	_, _, _ = runSchtasks("/delete", "/tn", taskName, "/f")
	return nil
}

func setTaskEnabled(taskName string, enable bool) error {
	verb := "/enable"
	if !enable {
		verb = "/disable"
	}
	_, stderr, code := runSchtasks("/change", "/tn", taskName, verb)
	if code != 0 {
		return fmt.Errorf("schtasks /change %s: %s", verb, strings.TrimSpace(stderr))
	}
	return nil
}

func deleteStartupValue(rec *opRecord) error {
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

// ============================================================================
// Help
// ============================================================================

func printHelp() {
	header := "taskctl v1.0.0 (Windows)"
	fmt.Println(c(clrBold+clrCyan, header))
	fmt.Println("Windows scheduled task and startup entry manager - list / create / delete / rollback")
	fmt.Println()
	fmt.Print(`USAGE
  taskctl ls [filter]
  taskctl startup [--json]
  taskctl create -n <name> (-c <cmd> -s <sched> | --xml <file>) [-t <time>] [-u <user>]
  taskctl delete <task> [-f]
  taskctl enable <task> [-f]
  taskctl disable <task> [-f]
  taskctl export -n <task> [-o file.xml]
  taskctl import -n <task> <file.xml>
  taskctl run <task>
  taskctl startup-add -l <location> -n <name> -c <command>
  taskctl startup-del -l <location> -n <name> [-f]
  taskctl --history
  taskctl --rollback [-n N]

TASKS
  ls                   List scheduled tasks (name, status, next run, command)
  ls <filter>          Substring match on task name
  create               Create a task from CLI flags or an XML file.
                       -c <cmd>  command to run
                       -s <sched> schedule type: ONCE|DAILY|WEEKLY|MONTHLY|ONLOGON|ONSTART|ONIDLE
                       -t <time> start time (HH:MM)
                       -u <user> run-as user (default: current user)
                       --xml <file>  create from XML (overrides -c/-s)
  delete <task>        Delete a task. Prompts unless -f.
  enable / disable     Toggle a task. Prompts unless -f.
  export               Export task XML (raw UTF-16LE, as schtasks produced it).
  import               Create/overwrite a task from an XML file.
  run                  Start a task immediately (no inverse; not rollback-able).

STARTUP
  startup              List all startup entries:
                         HKCU/HKLM Run + RunOnce (64-bit + Wow6432Node)
                         Winlogon UserInit / Shell
                         User + Common Startup folders
  startup-add          Add or overwrite a registry Run/RunOnce value.
  startup-del          Delete a registry Run/RunOnce value.

GLOBAL
  -o, --out <path>     Redirect stdout to a file.
  --dry-run            Preview only.
  --no-color           Disable ANSI colors (also honors NO_COLOR env var).
  -b, --bugs           Print collected errors/warnings on exit.
  -h, --help           Show this help.
  --version            Show version.

HISTORY / ROLLBACK
  --history            Reverse-numbered rollback-able operations ([1] = newest).
  --rollback           Undo the most recent operation (same as -n 1).
  --rollback -n N      Undo the most recent N operations.

  Inverse mapping:
    create (new)         -> delete task
    create (overwrote)   -> restore previous XML
    delete               -> restore XML
    enable               -> disable (if it was disabled before)
    disable              -> enable  (if it was enabled before)
    import (overwrote)   -> restore previous XML
    import (new)         -> delete task
    startup-add (new)    -> delete value
    startup-add (over.)  -> import .reg backup
    startup-del          -> import .reg backup

BACKUP AND LOG
  Every invocation (except -h/--help/--version/--history/--dry-run) appends
  one line to ./taskctl_backup/taskctl.log:
    [command line] [timestamp] [exit code]

  Write operations store their snapshot under ./taskctl_backup/files/:
    <logIndex>_<sanitized>.xml        small task XML (< 8 KiB)
    <logIndex>_<sanitized>.xml.gz     large task XML (gzip -9)
    <logIndex>_<root>_<key>.reg       small startup key export
    <logIndex>_<root>_<key>.reg.gz    large startup key export (gzip -9)
  and a manifest under ./taskctl_backup/ops/<logIndex>.json.

  Task XML is kept byte-for-byte as schtasks produced it (UTF-16LE with BOM,
  XML declaration encoding="UTF-16"). It is fed back to schtasks /create /xml
  unchanged on rollback.

EXIT CODES
  0 success | 1 partial failure | 2 bad args | 3 permission denied
  4 not found | 5 Windows API / I/O error
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
		fmt.Fprintf(os.Stderr, "taskctl: %v\n", err)
		bugs.Flush()
		os.Exit(2)
	}

	if noColorFlag || os.Getenv("NO_COLOR") != "" {
		useColor = false
	} else if stdoutIsTTY() {
		useColor = true
	}

	if outPath != "" {
		if err := setupOutput(outPath); err != nil {
			fmt.Fprintf(os.Stderr, "taskctl: %v\n", err)
			bugs.Flush()
			os.Exit(2)
		}
	}

	if has(args, "--version") {
		fmt.Println("taskctl v1.0.0")
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
			fmt.Fprintln(os.Stderr, "taskctl: missing command, use -h for help")
			code = 2
			break
		}
		cmd := args[cmdIdx]
		rest := append([]string{}, args[:cmdIdx]...)
		rest = append(rest, args[cmdIdx+1:]...)

		switch cmd {
		case "ls":
			code = cmdLs(rest)
		case "startup":
			code = cmdStartup(rest)
		case "create":
			code = cmdCreate(rest)
		case "delete":
			code = cmdDelete(rest)
		case "enable":
			code = cmdEnableDisable(rest, true)
		case "disable":
			code = cmdEnableDisable(rest, false)
		case "export":
			code = cmdExport(rest)
		case "import":
			code = cmdImport(rest)
		case "run":
			code = cmdRun(rest)
		case "startup-add":
			code = cmdStartupAdd(rest)
		case "startup-del":
			code = cmdStartupDel(rest)
		default:
			fmt.Fprintf(os.Stderr, "taskctl: unknown command %q\n", cmd)
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