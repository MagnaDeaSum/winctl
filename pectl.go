//go:build windows && amd64

package main

// pectl — PE dependency diagnostic tool (read-only).
// Single-file, standard-library-only build:
//
//   go build -trimpath -ldflags "-s -w" -o pectl.exe pectl.go
//
// Log: ./pectl_backup/pectl.log  [cmd] [ts] [exit code]

import (
	"bytes"
	"debug/pe"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
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
		fmt.Fprintln(os.Stderr, "[pectl] -b/--bugs enabled: no errors or warnings captured this run.")
		return
	}
	fmt.Fprintf(os.Stderr, "\n--- pectl bugs report (%d entries) ---\n", len(b.entries))
	for _, e := range b.entries {
		fmt.Fprintf(os.Stderr, "[%s] %s %s\n", e.At.Format("15:04:05.000"), e.Level, e.Msg)
	}
	fmt.Fprintln(os.Stderr, "--- end of bugs report ---")
}

// ============================================================================
// PE parsing
// ============================================================================

type SectionInfo struct {
	Name            string `json:"name"`
	VirtualSize     uint32 `json:"virtualSize"`
	VirtualAddress  uint32 `json:"virtualAddress"`
	RawSize         uint32 `json:"rawSize"`
	RawOffset       uint32 `json:"rawOffset"`
	Characteristics uint32 `json:"characteristics"`
}

type PEInfo struct {
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
	Sections        []SectionInfo
	Imports         []string
	ImportSymbols   map[string][]string
	Exports         map[string]uint32
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

// machineIs64 reports whether the machine is a known 64-bit target.
func machineIs64(m uint16) bool {
	return m == 0x8664 || m == 0xAA64
}

// machineIsKnown reports whether the machine is one of the CPU types we can
// reliably classify as 32-bit or 64-bit. Unknown machines are never flagged
// as bitness mismatches, to avoid false positives on exotic binaries.
func machineIsKnown(m uint16) bool {
	switch m {
	case 0x014C, 0x8664, 0x01C0, 0x01C4, 0xAA64, 0x0200:
		return true
	}
	return false
}

func subsystemName(s uint16) string {
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

func parsePE(path string) (*PEInfo, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	f, err := pe.NewFile(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	defer f.Close()

	info := &PEInfo{
		Path:            path,
		Machine:         f.FileHeader.Machine,
		TimeStamp:       f.FileHeader.TimeDateStamp,
		Characteristics: f.FileHeader.Characteristics,
		IsDLL:           f.FileHeader.Characteristics&0x2000 != 0,
		ImportSymbols:   map[string][]string{},
	}

	info.KnownBits = machineIsKnown(info.Machine)
	info.Is64 = machineIs64(info.Machine)
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
	info.SubsystemName = subsystemName(info.Subsystem)

	for _, s := range f.Sections {
		info.Sections = append(info.Sections, SectionInfo{
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
		// debug/pe does not expose exported symbols; parse .edata ourselves.
		if exp, err := parseExports(f, data); err != nil {
			bugs.Add("WARN", "%s exports: %v", path, err)
		} else if len(exp) > 0 {
			info.Exports = exp
		}
	}

	return info, nil
}

// parseExports walks the IMAGE_EXPORT_DIRECTORY and returns
// name -> function RVA. Returns (nil, nil) if the binary exports nothing.
func parseExports(f *pe.File, data []byte) (map[string]uint32, error) {
	var dd pe.DataDirectory
	switch o := f.OptionalHeader.(type) {
	case *pe.OptionalHeader32:
		dd = o.DataDirectory[0]
	case *pe.OptionalHeader64:
		dd = o.DataDirectory[0]
	default:
		return nil, nil
	}
	if dd.VirtualAddress == 0 || dd.Size < 40 {
		return nil, nil
	}
	dirOff := rvaToFileOffset(f, dd.VirtualAddress)
	if dirOff < 0 || dirOff+40 > len(data) {
		return nil, fmt.Errorf("export directory out of range")
	}
	exp := data[dirOff : dirOff+40]
	numFuncs := binary.LittleEndian.Uint32(exp[20:])
	numNames := binary.LittleEndian.Uint32(exp[24:])
	addrFuncsRVA := binary.LittleEndian.Uint32(exp[28:])
	addrNamesRVA := binary.LittleEndian.Uint32(exp[32:])
	addrOrdsRVA := binary.LittleEndian.Uint32(exp[36:])

	funcsOff := rvaToFileOffset(f, addrFuncsRVA)
	namesOff := rvaToFileOffset(f, addrNamesRVA)
	ordsOff := rvaToFileOffset(f, addrOrdsRVA)
	if funcsOff < 0 || namesOff < 0 || ordsOff < 0 {
		return nil, fmt.Errorf("export table out of range")
	}

	exports := make(map[string]uint32)
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

		nameOff := rvaToFileOffset(f, nameRVA)
		if nameOff < 0 {
			continue
		}
		end := nameOff
		for end < len(data) && data[end] != 0 {
			end++
		}
		exports[string(data[nameOff:end])] = funcRVA
	}
	return exports, nil
}

func rvaToFileOffset(f *pe.File, rva uint32) int {
	for _, sec := range f.Sections {
		if sec.VirtualAddress <= rva && rva < sec.VirtualAddress+sec.VirtualSize {
			return int(sec.Offset + (rva - sec.VirtualAddress))
		}
	}
	return -1
}

// ============================================================================
// DLL search
// ============================================================================

func buildSearchPaths(exe *PEInfo, extra []string) []string {
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
		if dirExists(filepath.Join(winDir, "SysWOW64")) {
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

func dirExists(p string) bool {
	fi, err := os.Stat(p)
	return err == nil && fi.IsDir()
}

func findDLL(name string, searchPaths []string) (string, error) {
	for _, dir := range searchPaths {
		full := filepath.Join(dir, name)
		if fi, err := os.Stat(full); err == nil && !fi.IsDir() {
			return full, nil
		}
	}
	return "", fmt.Errorf("not found")
}

func isAPISet(name string) bool {
	lower := strings.ToLower(name)
	return strings.HasPrefix(lower, "api-ms-win-") ||
		strings.HasPrefix(lower, "ext-ms-") ||
		strings.HasPrefix(lower, "api-ms-onecore-")
}

// ============================================================================
// Dependency status
// ============================================================================

type DepStatus struct {
	DLL        string `json:"dll"`
	Status     string `json:"status"` // ok | missing | bitmismatch | apiset | unreadable
	Path       string `json:"path,omitempty"`
	ActualBits string `json:"actualBits,omitempty"`
}

type ExeReport struct {
	Path       string      `json:"path"`
	Bits       string      `json:"bits"`
	Machine    string      `json:"machine"`
	IsDLL      bool        `json:"isDll"`
	Subsystem  string      `json:"subsystem"`
	Imports    int         `json:"imports"`
	Deps       []DepStatus `json:"dependencies"`
	Missing    int         `json:"missing"`
	Mismatch   int         `json:"mismatch"`
	ReadErrMsg string      `json:"error,omitempty"`
}

func checkExe(path string, libPaths []string) (*PEInfo, []DepStatus, error) {
	info, err := parsePE(path)
	if err != nil {
		return nil, nil, err
	}

	searchPaths := buildSearchPaths(info, libPaths)
	var deps []DepStatus
	for _, dll := range info.Imports {
		ds := DepStatus{DLL: dll}

		if isAPISet(dll) {
			ds.Status = "apiset"
			deps = append(deps, ds)
			continue
		}

		full, ferr := findDLL(dll, searchPaths)
		if ferr != nil {
			ds.Status = "missing"
			deps = append(deps, ds)
			continue
		}
		ds.Path = full

		dllInfo, derr := parsePE(full)
		if derr != nil {
			ds.Status = "unreadable"
			deps = append(deps, ds)
			continue
		}
		ds.ActualBits = dllInfo.Bits

		// Only flag mismatch when both sides are classifiable and the
		// bitness differs.
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
// Output
// ============================================================================

func printHeader(info *PEInfo) {
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

func printSections(info *PEInfo) {
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

func printImports(info *PEInfo) {
	if len(info.Imports) == 0 {
		fmt.Println(c(clrGray, "\n(no imports)"))
		return
	}
	fmt.Println(c(clrBold+clrCyan, "\nImports (DLLs)"))
	for _, dll := range info.Imports {
		count := len(info.ImportSymbols[strings.ToLower(dll)])
		fmt.Printf("  %s (%d function%s)\n", c(clrCyan, dll), count, plural(count))
	}
}

func printExports(info *PEInfo) {
	if len(info.Exports) == 0 {
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
		fmt.Printf("  %s 0x%X\n", c(clrCyan, name), info.Exports[name])
	}
}

func printDeps(deps []DepStatus) {
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
		case "bitmismatch":
			statusColor = clrYellow
		case "unreadable":
			statusColor = clrYellow
		}
		fmt.Println(padRight(d.DLL, dllW) + "  " +
			c(statusColor, padRight(d.Status, 12)) + "  " +
			padRight(d.ActualBits, bitsW) + "  " +
			c(clrGray, d.Path))
	}
}

func plural(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}

// ============================================================================
// JSON output
// ============================================================================

type jsonInfo struct {
	Path       string            `json:"path"`
	Machine    string            `json:"machine"`
	Bits       string            `json:"bits"`
	Kind       string            `json:"kind"`
	Subsystem  string            `json:"subsystem"`
	EntryPoint uint32            `json:"entryPoint"`
	ImageBase  uint64            `json:"imageBase"`
	TimeStamp  uint32            `json:"timestamp"`
	Sections   []SectionInfo     `json:"sections"`
	Imports    []string          `json:"imports"`
	Exports    map[string]uint32 `json:"exports,omitempty"`
}

func printJSON(v any) {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		bugs.Add("ERR", "json encode: %v", err)
	}
}

func infoToJSON(info *PEInfo) jsonInfo {
	kind := "EXE"
	if info.IsDLL {
		kind = "DLL"
	}
	return jsonInfo{
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
	}
}

// ============================================================================
// Commands
// ============================================================================

type cmdOpts struct {
	libPaths    []string
	jsonOut     bool
	recursive   bool
	summaryOnly bool
	failMissing bool
	noCheck     bool
}

func cmdInfo(path string, opts *cmdOpts) int {
	info, deps, err := checkExe(path, opts.libPaths)
	if err != nil {
		fmt.Fprintf(os.Stderr, "pectl: %v\n", err)
		return 5
	}

	if opts.jsonOut {
		out := infoToJSON(info)
		if opts.noCheck {
			printJSON(out)
		} else {
			printJSON(struct {
				jsonInfo
				Dependencies []DepStatus `json:"dependencies"`
			}{out, deps})
		}
		return reportExitCode(deps, opts.failMissing)
	}

	printHeader(info)
	printSections(info)
	printImports(info)
	if info.IsDLL {
		printExports(info)
	}
	if !opts.noCheck {
		printDeps(deps)
	}
	return reportExitCode(deps, opts.failMissing)
}

func cmdDeps(path string, opts *cmdOpts) int {
	info, deps, err := checkExe(path, opts.libPaths)
	if err != nil {
		fmt.Fprintf(os.Stderr, "pectl: %v\n", err)
		return 5
	}

	if opts.jsonOut {
		printJSON(struct {
			Path         string      `json:"path"`
			Bits         string      `json:"bits"`
			Dependencies []DepStatus `json:"dependencies"`
		}{info.Path, info.Bits, deps})
		return reportExitCode(deps, opts.failMissing)
	}

	fmt.Printf("%s %s (%s)\n", c(clrCyan, "File:"), info.Path, info.Bits)
	printDeps(deps)
	return reportExitCode(deps, opts.failMissing)
}

func cmdSections(path string, opts *cmdOpts) int {
	info, err := parsePE(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "pectl: %v\n", err)
		return 5
	}
	if opts.jsonOut {
		printJSON(info.Sections)
		return 0
	}
	printHeader(info)
	printSections(info)
	return 0
}

func cmdExports(path string, opts *cmdOpts) int {
	info, err := parsePE(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "pectl: %v\n", err)
		return 5
	}
	if opts.jsonOut {
		printJSON(map[string]any{
			"path":    info.Path,
			"exports": info.Exports,
		})
		return 0
	}
	printHeader(info)
	printExports(info)
	return 0
}

func cmdImports(path string, opts *cmdOpts) int {
	info, err := parsePE(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "pectl: %v\n", err)
		return 5
	}
	if opts.jsonOut {
		printJSON(map[string]any{
			"path":    info.Path,
			"imports": info.Imports,
			"symbols": info.ImportSymbols,
		})
		return 0
	}
	printHeader(info)
	printImports(info)
	return 0
}

func reportExitCode(deps []DepStatus, failMissing bool) int {
	missing := 0
	mismatch := 0
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

// ============================================================================
// scan-dir
// ============================================================================

func scanDir(dir string, opts *cmdOpts) int {
	if !dirExists(dir) {
		fmt.Fprintf(os.Stderr, "pectl: %s is not a directory\n", dir)
		return 4
	}

	var files []string
	if opts.recursive {
		err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return nil
			}
			if info.IsDir() {
				return nil
			}
			ext := strings.ToLower(filepath.Ext(path))
			if ext == ".exe" || ext == ".dll" || ext == ".sys" {
				files = append(files, path)
			}
			return nil
		})
		if err != nil {
			bugs.Add("WARN", "walk %s: %v", dir, err)
		}
	} else {
		entries, err := os.ReadDir(dir)
		if err != nil {
			fmt.Fprintf(os.Stderr, "pectl: %v\n", err)
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

	var reports []ExeReport
	totalMissing := 0
	totalMismatch := 0
	totalFiles := 0

	for _, path := range files {
		info, deps, err := checkExe(path, opts.libPaths)
		if err != nil {
			reports = append(reports, ExeReport{
				Path:       path,
				ReadErrMsg: err.Error(),
			})
			continue
		}
		rep := ExeReport{
			Path:      path,
			Bits:      info.Bits,
			Machine:   machineName(info.Machine),
			IsDLL:     info.IsDLL,
			Subsystem: info.SubsystemName,
			Imports:   len(info.Imports),
			Deps:      deps,
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
		printJSON(map[string]any{
			"directory":     dir,
			"files":         totalFiles,
			"totalMissing":  totalMissing,
			"totalMismatch": totalMismatch,
			"reports":       reports,
		})
		return scanExitCode(totalMissing, totalMismatch, opts.failMissing)
	}

	nameW := dispWidth("FILE")
	bitsW := dispWidth("BITS")
	for _, r := range reports {
		rel := relPath(dir, r.Path)
		if w := dispWidth(rel); w > nameW {
			nameW = w
		}
		if w := dispWidth(r.Bits); w > bitsW {
			bitsW = w
		}
	}
	fmt.Println(c(clrBold+clrCyan,
		padRight("FILE", nameW)+"  "+
			padRight("BITS", bitsW)+"  "+
			padRight("IMPORTS", 7)+"  "+
			padRight("MISSING", 7)+"  "+
			padRight("MISMATCH", 8)+"  "+
			"STATUS"))
	for _, r := range reports {
		rel := relPath(dir, r.Path)
		status := "ok"
		statusColor := clrGreen
		if r.ReadErrMsg != "" {
			status = "error"
			statusColor = clrRed
		} else if r.Missing > 0 {
			status = "missing"
			statusColor = clrRed
		} else if r.Mismatch > 0 {
			status = "mismatch"
			statusColor = clrYellow
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
			var problems []DepStatus
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
	return scanExitCode(totalMissing, totalMismatch, opts.failMissing)
}

func relPath(base, full string) string {
	rel, err := filepath.Rel(base, full)
	if err != nil {
		return full
	}
	return rel
}

func scanExitCode(missing, mismatch int, failMissing bool) int {
	if failMissing && (missing > 0 || mismatch > 0) {
		return 1
	}
	return 0
}

// ============================================================================
// Logging
// ============================================================================

const (
	backupDirName = "pectl_backup"
	logFileName   = "pectl.log"
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
	fmt.Fprintln(os.Stderr, "pectl is read-only: there are no operations to roll back")
	fmt.Fprintln(os.Stderr, "  pectl only reads PE headers and checks DLL search paths.")
	fmt.Fprintln(os.Stderr, "  Its history is for audit only; use --history to view it.")
	return 0
}

// ============================================================================
// Help
// ============================================================================

func printHelp() {
	header := "pectl v1.0.0 (Windows)"
	fmt.Println(c(clrBold+clrCyan, header))
	fmt.Println("PE dependency diagnostic tool (read-only) - inspect / check / scan")
	fmt.Println()
	fmt.Print(`USAGE
  pectl <file>                       same as "info" on the file
  pectl info     <file> [OPTIONS]    full PE details + dependency check
  pectl deps     <file> [OPTIONS]    dependency status only
  pectl imports  <file> [OPTIONS]    imported DLLs and functions
  pectl exports  <file> [OPTIONS]    exported symbols (DLLs)
  pectl sections <file> [OPTIONS]    section table
  pectl scan-dir <dir>  [OPTIONS]    scan a directory for PE files
  pectl --history
  pectl --rollback                   (always a no-op: pectl is read-only)

OPTIONS
  --lib-path <dir>       extra directory to search for DLLs (repeatable)
  --recursive            scan-dir: recurse into subdirectories
  --json                 JSON output for any command
  --summary              scan-dir: only print the summary table
  --fail-on-missing      return exit code 1 if any missing DLLs or bitness
                         mismatches were found
  --no-check             info: skip the dependency check

GLOBAL
  -o, --out <path>       Redirect stdout to a file
  --dry-run              Print the plan without parsing any file
  --no-color             Disable ANSI colors (also honors NO_COLOR)
  -b, --bugs             Print collected errors/warnings on exit
  -h, --help             Show this help
  --version              Show version

DLL SEARCH ORDER
  For each imported DLL pectl tries:
    1. directory containing the target PE file
    2. System32 (for 64-bit targets) or SysWOW64 (for 32-bit targets)
    3. %SystemRoot%
    4. --lib-path directories, in order
    5. %PATH% entries
  API set pseudo-DLLs (api-ms-win-*, ext-ms-*) are reported as "apiset"
  and never as missing.

HISTORY
  Every invocation (except -h/--help/--version/--history/--rollback/--dry-run)
  appends one line to ./pectl_backup/pectl.log:
    [command line] [timestamp] [exit code]

  --history prints it, numbered from newest (1) to oldest.

READ-ONLY BY DESIGN
  pectl does not modify the PE file, the registry, or any other state.
  --rollback therefore has nothing to undo.

EXIT CODES
  0 success | 1 --fail-on-missing found problems | 2 bad args
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
// Command-line parsing
// ============================================================================

func parseCmdOpts(args []string) (*cmdOpts, []string, error) {
	opts := &cmdOpts{}
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

// ============================================================================
// main
// ============================================================================

func main() {
	args, outPath, err := consumeGlobalFlags(os.Args[1:])
	if err != nil {
		fmt.Fprintf(os.Stderr, "pectl: %v\n", err)
		bugs.Flush()
		os.Exit(2)
	}

	if noColorFlag || os.Getenv("NO_COLOR") != "" {
		useColor = false
	} else if stdoutIsTTY() {
		useColor = true
	}

	if has(args, "--version") {
		fmt.Println("pectl v1.0.0")
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
			fmt.Fprintf(os.Stderr, "pectl: %v\n", err)
			bugs.Flush()
			os.Exit(2)
		}
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

	opts, positional, err := parseCmdOpts(rest)
	if err != nil {
		fmt.Fprintf(os.Stderr, "pectl: %v\n", err)
		bugs.Flush()
		os.Exit(2)
	}

	if cmd == "" {
		if len(positional) == 0 {
			fmt.Fprintln(os.Stderr, "pectl: missing file or directory (use -h for help)")
			finalExit(2, true)
		}
		cmd = "info"
	}

	switch cmd {
	case "info", "deps", "imports", "exports", "sections":
		if len(positional) == 0 {
			fmt.Fprintf(os.Stderr, "pectl: %s requires a file\n", cmd)
			finalExit(2, true)
		}
		path := positional[0]
		if fi, err := os.Stat(path); err == nil && fi.IsDir() {
			fmt.Fprintf(os.Stderr, "pectl: %s is a directory (use scan-dir)\n", path)
			finalExit(2, true)
		}
		if dryRun {
			fmt.Printf("[dry-run] would parse %q (command=%s)\n", path, cmd)
			finalExit(0, false)
		}
		var code int
		switch cmd {
		case "info":
			code = cmdInfo(path, opts)
		case "deps":
			code = cmdDeps(path, opts)
		case "imports":
			code = cmdImports(path, opts)
		case "exports":
			code = cmdExports(path, opts)
		case "sections":
			code = cmdSections(path, opts)
		}
		finalExit(code, true)
	case "scan-dir":
		if len(positional) == 0 {
			fmt.Fprintln(os.Stderr, "pectl: scan-dir requires a directory")
			finalExit(2, true)
		}
		code := scanDir(positional[0], opts)
		finalExit(code, true)
	}
	fmt.Fprintf(os.Stderr, "pectl: unknown command %q\n", cmd)
	finalExit(2, true)
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