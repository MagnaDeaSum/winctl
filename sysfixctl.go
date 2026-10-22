//go:build windows && amd64

package main

// sysfixctl — System file and image repair entry point.
// Single-file, standard-library-only build:
//
//   go build -trimpath -ldflags "-s -w" -o sysfixctl.exe sysfixctl.go
//
// Log: ./sysfixctl_backup/sysfixctl.log  [cmd] [ts] [exit code]

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
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
	kernel32 = syscall.NewLazyDLL("kernel32.dll")
	advapi32 = syscall.NewLazyDLL("advapi32.dll")
	shell32  = syscall.NewLazyDLL("shell32.dll")

	pGetStdHandle        = kernel32.NewProc("GetStdHandle")
	pGetConsoleMode      = kernel32.NewProc("GetConsoleMode")
	pGetOEMCP            = kernel32.NewProc("GetOEMCP")
	pMultiByteToWideChar = kernel32.NewProc("MultiByteToWideChar")
	pGetCurrentProcess   = kernel32.NewProc("GetCurrentProcess")
	pCloseHandle         = kernel32.NewProc("CloseHandle")
	pWaitForSingleObject = kernel32.NewProc("WaitForSingleObject")
	pGetExitCodeProcess  = kernel32.NewProc("GetExitCodeProcess")

	pOpenProcessToken    = advapi32.NewProc("OpenProcessToken")
	pGetTokenInformation = advapi32.NewProc("GetTokenInformation")

	pShellExecuteExW = shell32.NewProc("ShellExecuteExW")
)

const (
	TOKEN_QUERY    = 0x0008
	TokenElevation = 20
	INFINITE       = 0xFFFFFFFF

	SEE_MASK_NOCLOSEPROCESS = 0x00000040
	SEE_MASK_NOASYNC        = 0x00000100
	SW_SHOWNORMAL           = 1

	ERROR_CANCELLED = syscall.Errno(1223)
)

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
		fmt.Fprintln(os.Stderr, "[sysfixctl] -b/--bugs enabled: no errors or warnings captured this run.")
		return
	}
	fmt.Fprintf(os.Stderr, "\n--- sysfixctl bugs report (%d entries) ---\n", len(b.entries))
	for _, e := range b.entries {
		fmt.Fprintf(os.Stderr, "[%s] %s %s\n", e.At.Format("15:04:05.000"), e.Level, e.Msg)
	}
	fmt.Fprintln(os.Stderr, "--- end of bugs report ---")
}

// ============================================================================
// Encoding
// ============================================================================

func convertToUTF8(data []byte) []byte {
	if len(data) == 0 {
		return data
	}
	if utf8.Valid(data) {
		return data
	}
	cp, _, _ := pGetOEMCP.Call()
	if cp == 0 {
		cp = 437
	}
	n, _, _ := pMultiByteToWideChar.Call(
		cp, 0,
		uintptr(unsafe.Pointer(&data[0])), uintptr(len(data)),
		0, 0,
	)
	if n == 0 {
		return data
	}
	wide := make([]uint16, n)
	pMultiByteToWideChar.Call(
		cp, 0,
		uintptr(unsafe.Pointer(&data[0])), uintptr(len(data)),
		uintptr(unsafe.Pointer(&wide[0])), uintptr(n),
	)
	return []byte(syscall.UTF16ToString(wide))
}

// ============================================================================
// Admin / Elevation
// ============================================================================

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
	defer pCloseHandle.Call(uintptr(token))
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

func relaunchElevated(args []string) (int, error) {
	exePath, err := os.Executable()
	if err != nil {
		return 5, err
	}
	var paramParts []string
	for _, a := range args {
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
			return 5, fmt.Errorf("elevation cancelled by user")
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
// Step catalogue
// ============================================================================

type fixStep struct {
	Key   string
	Flag  string
	Label string
	Exe   string
	Args  []string
	Note  string
}

func (s *fixStep) cmdLine() string {
	parts := append([]string{s.Exe}, s.Args...)
	return strings.Join(parts, " ")
}

func stepDISMCheck() *fixStep {
	return &fixStep{
		Key:   "dism-check",
		Flag:  "--dism-check",
		Label: "DISM /CheckHealth",
		Exe:   "dism.exe",
		Args:  []string{"/Online", "/Cleanup-Image", "/CheckHealth"},
		Note:  "Quick health check of the component store",
	}
}

func stepDISMScan() *fixStep {
	return &fixStep{
		Key:   "dism-scan",
		Flag:  "--dism-scan",
		Label: "DISM /ScanHealth",
		Exe:   "dism.exe",
		Args:  []string{"/Online", "/Cleanup-Image", "/ScanHealth"},
		Note:  "Full scan of the component store (may take 10+ min)",
	}
}

func stepDISMRestore() *fixStep {
	return &fixStep{
		Key:   "dism-restore",
		Flag:  "--dism-restore",
		Label: "DISM /RestoreHealth",
		Exe:   "dism.exe",
		Args:  []string{"/Online", "/Cleanup-Image", "/RestoreHealth"},
		Note:  "Repair the component store (may take 15+ min)",
	}
}

func stepSFC() *fixStep {
	return &fixStep{
		Key:   "sfc",
		Flag:  "--sfc",
		Label: "SFC /scannow",
		Exe:   "sfc.exe",
		Args:  []string{"/scannow"},
		Note:  "Scan and repair system files (may take 30+ min)",
	}
}

func stepChkdsk(drive string, fix bool) *fixStep {
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
	return &fixStep{
		Key:   "chkdsk",
		Flag:  "--chkdsk",
		Label: label,
		Exe:   "chkdsk.exe",
		Args:  args,
		Note:  note,
	}
}

// ============================================================================
// Log
// ============================================================================

const (
	backupDirName = "sysfixctl_backup"
	logFileName   = "sysfixctl.log"
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

var histRe = regexp.MustCompile(`^\[(.*)\] \[(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\] \[(-?\d+)\]$`)

// ============================================================================
// Thread-safe writer
// ============================================================================

type lockedWriter struct {
	mu sync.Mutex
	w  io.Writer
}

func (lw *lockedWriter) Write(p []byte) (int, error) {
	lw.mu.Lock()
	defer lw.mu.Unlock()
	return lw.w.Write(p)
}

// ============================================================================
// Subprocess output pump
// ============================================================================

func pumpOutput(r io.Reader, screen io.Writer, log io.Writer, screenIsTTY bool) {
	br := bufio.NewReaderSize(r, 4096)
	var buf []byte
	for {
		b, err := br.ReadByte()
		if err != nil {
			if len(buf) > 0 {
				screen.Write(convertToUTF8(buf))
			}
			return
		}
		if b == '\r' {
			if screenIsTTY {
				screen.Write(convertToUTF8(buf))
				screen.Write([]byte("\r"))
			}
			buf = buf[:0]
			continue
		}
		if b == '\n' {
			converted := convertToUTF8(buf)
			screen.Write(converted)
			screen.Write([]byte("\n"))
			if log != nil {
				log.Write(converted)
				log.Write([]byte("\n"))
			}
			buf = buf[:0]
			continue
		}
		buf = append(buf, b)
	}
}

// ============================================================================
// Run one step
// ============================================================================

func runStep(s *fixStep, logFile *os.File, stepNum, totalNum int) int {
	header := fmt.Sprintf("\n--- %d/%d %s ---\n", stepNum, totalNum, s.Label)
	fmt.Print(c(clrBold+clrCyan, header))
	logFile.WriteString(header)

	fmt.Printf("  %s\n", c(clrGray, "cmd:  "+s.cmdLine()))
	logFile.WriteString("cmd: " + s.cmdLine() + "\n")
	fmt.Printf("  %s\n\n", c(clrGray, "note: "+s.Note))
	logFile.WriteString("note: " + s.Note + "\n\n")

	cmd := exec.Command(s.Exe, s.Args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		fmt.Fprintf(os.Stderr, "sysfixctl: %v\n", err)
		return 5
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		fmt.Fprintf(os.Stderr, "sysfixctl: %v\n", err)
		return 5
	}

	if err := cmd.Start(); err != nil {
		fmt.Fprintf(os.Stderr, "sysfixctl: start %s: %v\n", s.Exe, err)
		logFile.WriteString("start error: " + err.Error() + "\n")
		appendLogLine(s.cmdLine(), 5)
		return 5
	}

	screenIsTTY := stdoutIsTTY()
	lw := &lockedWriter{w: logFile}
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); pumpOutput(stdout, os.Stdout, lw, screenIsTTY) }()
	go func() { defer wg.Done(); pumpOutput(stderr, os.Stdout, lw, screenIsTTY) }()
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
	lw.Write([]byte(summary))

	if exitCode == 0 {
		fmt.Printf("\n%s %s\n", c(clrGreen, "done:"), s.Label)
	} else {
		fmt.Printf("\n%s %s (exit %d)\n", c(clrRed, "failed:"), s.Label, exitCode)
	}
	return exitCode
}

// ============================================================================
// Confirm
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
// cmdRun
// ============================================================================

func cmdRun(steps []*fixStep, yes bool) int {
	if len(steps) == 0 {
		fmt.Fprintln(os.Stderr, "sysfixctl: no steps selected")
		return 2
	}
	if !isAdmin() {
		fmt.Fprintln(os.Stderr, c(clrBold+clrRed, "error: not running as administrator"))
		fmt.Fprintln(os.Stderr, "  SFC, DISM, and chkdsk all require administrator privileges.")
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

	_ = os.MkdirAll(logRoot(), 0755)
	logFile, err := os.OpenFile(logPath(), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		fmt.Fprintf(os.Stderr, "sysfixctl: open log: %v\n", err)
		return 5
	}
	defer logFile.Close()

	header := fmt.Sprintf("\n=== sysfixctl session ===\nstarted: %s\nsteps: %d\nadmin: %v\n\n",
		time.Now().Format("2006-01-02 15:04:05"), len(steps), isAdmin())
	logFile.WriteString(header)

	succeeded, failed := 0, 0
	for i, s := range steps {
		if code := runStep(s, logFile, i+1, len(steps)); code == 0 {
			succeeded++
		} else {
			failed++
		}
	}

	summary := fmt.Sprintf("\n=== summary: %d ok, %d failed ===\n", succeeded, failed)
	logFile.WriteString(summary)
	fmt.Print(c(clrBold+clrCyan, summary))

	if failed == 0 {
		return 0
	}
	if succeeded == 0 {
		return 2
	}
	return 1
}

// ============================================================================
// Menu
// ============================================================================

func cmdMenu() int {
	fmt.Println()
	fmt.Println(c(clrBold+clrCyan, "================================================================"))
	fmt.Println(c(clrBold+clrCyan, "  sysfixctl v1.0.0 - Windows System Repair"))
	fmt.Println(c(clrBold+clrCyan, "================================================================"))
	fmt.Println()

	if !isAdmin() {
		fmt.Println(c(clrYellow, "  Warning: not running as administrator."))
		fmt.Println(c(clrYellow, "  SFC, DISM, and chkdsk require elevation."))
		fmt.Println()
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
		return runOrElevate([]*fixStep{
			stepDISMCheck(), stepDISMScan(), stepChkdsk("C", false),
		}, true)
	case "2":
		return runOrElevate([]*fixStep{
			stepDISMRestore(), stepSFC(),
		}, true)
	case "3":
		return runOrElevate([]*fixStep{
			stepDISMCheck(), stepDISMScan(), stepDISMRestore(), stepSFC(), stepChkdsk("C", false),
		}, true)
	case "4":
		return cmdCustomMenu()
	case "0", "":
		fmt.Println("Cancelled.")
		return 0
	}
	fmt.Fprintf(os.Stderr, "invalid choice %q\n", choice)
	return 2
}

func cmdCustomMenu() int {
	available := []*fixStep{
		stepDISMCheck(), stepDISMScan(), stepDISMRestore(), stepSFC(), stepChkdsk("C", false),
	}
	fmt.Println()
	for i, s := range available {
		fmt.Printf("  [%d] %-28s %s\n", i+1, s.Label, c(clrGray, s.Note))
	}
	fmt.Println()
	fmt.Print(c(clrBold, "  Select steps (comma-separated, e.g. 1,2,4): "))
	var line string
	fmt.Scanln(&line)
	if strings.TrimSpace(line) == "" {
		fmt.Println("Cancelled.")
		return 0
	}
	var selected []*fixStep
	for _, part := range strings.Split(line, ",") {
		part = strings.TrimSpace(part)
		n, err := strconv.Atoi(part)
		if err != nil || n < 1 || n > len(available) {
			fmt.Fprintf(os.Stderr, "invalid choice %q\n", part)
			return 2
		}
		selected = append(selected, available[n-1])
	}
	return runOrElevate(selected, true)
}

// runOrElevate launches the given steps, trying elevation if needed.
func runOrElevate(steps []*fixStep, yes bool) int {
	if isAdmin() {
		return cmdRun(steps, yes)
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
	code, err := relaunchElevated(args)
	if err != nil {
		fmt.Fprintf(os.Stderr, "sysfixctl: %v\n", err)
		return 5
	}
	return code
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
	var entries []string
	for _, l := range lines {
		if histRe.MatchString(l) {
			entries = append(entries, l)
		}
	}
	if len(entries) == 0 {
		fmt.Fprintln(os.Stderr, "no history entries in log")
		return 0
	}
	for k := len(entries) - 1; k >= 0; k-- {
		n := len(entries) - k
		fmt.Printf("[%d] %s\n", n, entries[k])
	}
	fmt.Fprintf(os.Stderr, "\n%d entrie(s). Log: %s\n", len(entries), logPath())
	return 0
}

func cmdRollback(args []string) int {
	n := 5
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
		}
	}

	fmt.Fprintln(os.Stderr, c(clrYellow, "note: sysfixctl cannot undo repairs."))
	fmt.Fprintln(os.Stderr, c(clrYellow, "      SFC, DISM, and chkdsk modify system files in place."))
	fmt.Fprintln(os.Stderr, c(clrYellow, "      This command only shows the most recent log entries."))
	fmt.Fprintln(os.Stderr)

	lines, err := readLogLines()
	if err != nil {
		fmt.Fprintf(os.Stderr, "read log %s: %v\n", logPath(), err)
		return 4
	}
	var entries []string
	for _, l := range lines {
		if histRe.MatchString(l) {
			entries = append(entries, l)
		}
	}
	if len(entries) == 0 {
		fmt.Fprintln(os.Stderr, "no history entries in log")
		return 0
	}
	if n > len(entries) {
		n = len(entries)
	}
	for k := 0; k < n; k++ {
		idx := len(entries) - 1 - k
		line := entries[idx]
		m := histRe.FindStringSubmatch(line)
		code, _ := strconv.Atoi(m[3])
		fmt.Printf("[%d] %s\n", k+1, line)
		if code != 0 {
			fmt.Printf("      %s\n", c(clrRed, fmt.Sprintf("exit code %d", code)))
		}
	}
	fmt.Fprintf(os.Stderr, "\n%d entrie(s) shown. Log: %s\n", n, logPath())
	return 0
}

// ============================================================================
// Help
// ============================================================================

func printHelp() {
	header := "sysfixctl v1.0.0 (Windows)"
	fmt.Println(c(clrBold+clrCyan, header))
	fmt.Println("Windows system file and image repair entry point")
	fmt.Println()
	fmt.Print(`USAGE
  sysfixctl                                 interactive menu
  sysfixctl menu                            interactive menu
  sysfixctl run [OPTIONS]                   run repair steps
  sysfixctl --history
  sysfixctl --rollback [-n N]               (read-only: shows last N log entries)

RUN OPTIONS
  --safe                     read-only check: DISM /CheckHealth, /ScanHealth,
                             chkdsk /scan
  --repair                   repair: DISM /RestoreHealth + SFC /scannow
  --all                      full sequence: Check -> Scan -> Restore -> SFC -> chkdsk

  --dism-check               DISM /Online /Cleanup-Image /CheckHealth
  --dism-scan                DISM /Online /Cleanup-Image /ScanHealth
  --dism-restore             DISM /Online /Cleanup-Image /RestoreHealth
  --sfc                      SFC /scannow
  --chkdsk [drive]           chkdsk <drive>: /scan (default drive: C)
  --chkdsk-fix               chkdsk <drive>: /f (requires reboot)

  -y, --yes                  skip the confirmation prompt
  --elevate                  relaunch with UAC (default)
  --no-elevate               do not try to relaunch; fail with exit 3

GLOBAL
  -o, --out <path>           Redirect stdout to a file
  --dry-run                  Print the plan without executing
  --no-color                 Disable ANSI colors (also honors NO_COLOR)
  -b, --bugs                 Print collected errors/warnings on exit
  -h, --help                 Show this help
  --version                  Show version

REPAIR STEPS
  DISM /CheckHealth          Quick check: does the component store know
                             about any corruption? (fast)
  DISM /ScanHealth           Full scan: does the component store have
                             corruption? (10+ min)
  DISM /RestoreHealth        Repair the component store from Windows Update
                             or a local source (15+ min)
  SFC /scannow               Verify and repair protected system files
                             (30+ min)
  chkdsk /scan               Online disk check (read-only, 1-5 min)
  chkdsk /f                  Schedule a full disk repair on next boot

  All steps require administrator privileges. sysfixctl relaunches itself
  with a UAC prompt when needed.

LOG
  Every step appends its own line to:
    ./sysfixctl_backup/sysfixctl.log
  in the format:
    [command] [timestamp] [exit code]

  The same file also contains the full stdout/stderr of each step,
  separated by "=== sysfixctl session ===" banners. --history and
  --rollback only show the summary lines.

--rollback
  sysfixctl cannot undo a repair. SFC, DISM, and chkdsk modify system
  files, the component store, and disk metadata in place; there is no
  inverse operation that would be safe to run automatically.
  --rollback therefore prints the most recent N summary lines from
  the log, so you can see what was executed and what exit code each
  step returned.

EXIT CODES
  0 success | 1 partial failure | 2 bad args | 3 not elevated
  4 not found | 5 I/O error
`)
}

// ============================================================================
// Main
// ============================================================================

func main() {
	args := os.Args[1:]

	filtered := make([]string, 0, len(args))
	var outPath string
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "-b" || a == "--bugs":
			bugs.enabled = true
		case a == "--dry-run":
			dryRun = true
		case a == "--no-color":
			noColorFlag = true
		case a == "-o" || a == "--out":
			if i+1 >= len(args) {
				fmt.Fprintf(os.Stderr, "sysfixctl: %s requires a path\n", a)
				os.Exit(2)
			}
			outPath = args[i+1]
			i++
		case strings.HasPrefix(a, "--out="):
			outPath = strings.TrimPrefix(a, "--out=")
		case strings.HasPrefix(a, "-o="):
			outPath = strings.TrimPrefix(a, "-o=")
		default:
			filtered = append(filtered, a)
		}
	}
	args = filtered

	if noColorFlag || os.Getenv("NO_COLOR") != "" {
		useColor = false
	} else if stdoutIsTTY() {
		useColor = true
	}

	if outPath != "" {
		if err := setupOutput(outPath); err != nil {
			fmt.Fprintf(os.Stderr, "sysfixctl: %v\n", err)
			bugs.Flush()
			os.Exit(2)
		}
	}

	if has(args, "--version") {
		fmt.Println("sysfixctl v1.0.0")
		finalExit(0, false)
	}
	if has(args, "--history") {
		finalExit(cmdHistory(), false)
	}
	if has(args, "--rollback") {
		finalExit(cmdRollback(stripFlag(args, "--rollback")), false)
	}
	if has(args, "-h", "--help") {
		printHelp()
		finalExit(0, false)
	}
	if len(args) == 0 {
		finalExit(cmdMenu(), true)
	}
	if args[0] == "menu" {
		finalExit(cmdMenu(), true)
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

	steps, yes, elevate, err := parseRunArgs(runArgs)
	if err != nil {
		fmt.Fprintf(os.Stderr, "sysfixctl: %v\n", err)
		finalExit(2, true)
	}
	if len(steps) == 0 {
		fmt.Fprintln(os.Stderr, "sysfixctl: no steps selected (use --all, --safe, --repair, or explicit steps)")
		finalExit(2, true)
	}

	if !isAdmin() {
		if !elevate {
			fmt.Fprintln(os.Stderr, c(clrBold+clrRed, "error: not running as administrator"))
			fmt.Fprintln(os.Stderr, "  SFC, DISM, and chkdsk all require administrator privileges.")
			fmt.Fprintln(os.Stderr, "  Re-run with --elevate to relaunch with a UAC prompt.")
			finalExit(3, true)
		}
		if !elevated {
			fmt.Println(c(clrYellow, "Requesting administrator privileges (UAC prompt)..."))
			code, err := relaunchElevated(os.Args[1:])
			if err != nil {
				fmt.Fprintf(os.Stderr, "sysfixctl: %v\n", err)
				bugs.Flush()
				os.Exit(5)
			}
			os.Exit(code)
		}
	}

	finalExit(cmdRun(steps, yes), true)
}

// ============================================================================
// Argument parsing
// ============================================================================

func parseRunArgs(args []string) (steps []*fixStep, yes bool, elevate bool, err error) {
	elevate = true
	var keys []string
	chkdskDrive := "C"
	chkdskFix := false

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
			i++
			if i < len(args) && !strings.HasPrefix(args[i], "-") && len(args[i]) <= 2 {
				chkdskDrive = args[i]
				i++
			}
		case "--chkdsk-fix":
			keys = append(keys, "chkdsk")
			chkdskFix = true
			i++
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
		if seen[k] && k != "chkdsk" {
			continue
		}
		seen[k] = true
		switch k {
		case "dism-check":
			steps = append(steps, stepDISMCheck())
		case "dism-scan":
			steps = append(steps, stepDISMScan())
		case "dism-restore":
			steps = append(steps, stepDISMRestore())
		case "sfc":
			steps = append(steps, stepSFC())
		case "chkdsk":
			steps = append(steps, stepChkdsk(chkdskDrive, chkdskFix))
		}
	}
	return steps, yes, elevate, nil
}

// ============================================================================
// Helpers
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

func stripFlag(args []string, flag string) []string {
	out := make([]string, 0, len(args))
	for _, a := range args {
		if a != flag {
			out = append(out, a)
		}
	}
	return out
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