//go:build windows && amd64

package main

// regctl — Windows registry manager with rollback.
// Single-file, standard-library-only build:
//
//   go build -trimpath -ldflags "-s -w" -o regctl.exe regctl.go

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"unicode/utf16"
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
	wow32Flag     = false
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
		fmt.Fprintln(os.Stderr, "[regctl] -b/--bugs enabled: no errors or warnings captured this run.")
		return
	}
	fmt.Fprintf(os.Stderr, "\n--- regctl bugs report (%d entries) ---\n", len(b.entries))
	for _, e := range b.entries {
		fmt.Fprintf(os.Stderr, "[%s] %s %s\n", e.At.Format("15:04:05.000"), e.Level, e.Msg)
	}
	fmt.Fprintln(os.Stderr, "--- end of bugs report ---")
}

// ============================================================================
// Windows registry API bindings
// ============================================================================

var (
	advapi32 = syscall.NewLazyDLL("advapi32.dll")

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
)

// Predefined root keys (sign-extended LONG → ULONG_PTR).
const (
	HKCR = uintptr(0xFFFFFFFF80000000)
	HKCU = uintptr(0xFFFFFFFF80000001)
	HKLM = uintptr(0xFFFFFFFF80000002)
	HKU  = uintptr(0xFFFFFFFF80000003)
	HKCC = uintptr(0xFFFFFFFF80000005)
)

const (
	KEY_QUERY_VALUE        = 0x0001
	KEY_SET_VALUE          = 0x0002
	KEY_CREATE_SUB_KEY     = 0x0004
	KEY_ENUMERATE_SUB_KEYS = 0x0008
	KEY_WOW64_32KEY        = 0x0200
	KEY_WOW64_64KEY        = 0x0100
	KEY_READ               = 0x20019
	KEY_WRITE              = 0x20006
	KEY_ALL_ACCESS         = 0xF003F
)

const (
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
)

const (
	ERROR_FILE_NOT_FOUND = syscall.Errno(2)
	ERROR_ACCESS_DENIED  = syscall.Errno(5)
	ERROR_INVALID_HANDLE = syscall.Errno(6)
	ERROR_NO_MORE_ITEMS  = syscall.Errno(259)
	ERROR_MORE_DATA      = syscall.Errno(234)
)

// ============================================================================
// Registry wrapper
// ============================================================================

type RegKey uintptr

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
	r, _, _ := pRegOpenKeyExW.Call(root, subPtrU, 0, uintptr(samDesired), uintptr(unsafe.Pointer(&phk)))
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
	for {
		buf := make([]uint16, 1024)
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

type RegValue struct {
	Name string
	Type uint32
	Data []byte
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
		if r == uintptr(ERROR_MORE_DATA) {
			dataBuf = make([]byte, dataSize)
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

func regCreateKey(root uintptr, subKey string, samDesired uint32) (RegKey, bool, error) {
	subPtr, err := syscall.UTF16PtrFromString(subKey)
	if err != nil {
		return 0, false, err
	}
	var phk uintptr
	var disp uint32
	r, _, _ := pRegCreateKeyExW.Call(root,
		uintptr(unsafe.Pointer(subPtr)),
		0, 0, 0,
		uintptr(samDesired), 0,
		uintptr(unsafe.Pointer(&phk)),
		uintptr(unsafe.Pointer(&disp)))
	if r != 0 {
		return 0, false, syscall.Errno(r)
	}
	// disp: 1 = REG_CREATED_NEW_KEY, 2 = REG_OPENED_EXISTING_KEY
	return RegKey(phk), disp == 1, nil
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
// Path parsing
// ============================================================================

type RegPath struct {
	Root     uintptr
	RootName string
	SubKey   string
}

func parseRegPath(s string) (*RegPath, error) {
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, `\\?\`)
	s = strings.ReplaceAll(s, "/", `\`)
	s = strings.TrimSuffix(s, `\`)

	idx := strings.Index(s, `\`)
	var rootName, subKey string
	if idx < 0 {
		rootName = s
		subKey = ""
	} else {
		rootName = s[:idx]
		subKey = s[idx+1:]
	}

	var root uintptr
	switch strings.ToUpper(rootName) {
	case "HKCR", "HKEY_CLASSES_ROOT":
		root = HKCR
		rootName = "HKEY_CLASSES_ROOT"
	case "HKCU", "HKEY_CURRENT_USER":
		root = HKCU
		rootName = "HKEY_CURRENT_USER"
	case "HKLM", "HKEY_LOCAL_MACHINE":
		root = HKLM
		rootName = "HKEY_LOCAL_MACHINE"
	case "HKU", "HKEY_USERS":
		root = HKU
		rootName = "HKEY_USERS"
	case "HKCC", "HKEY_CURRENT_CONFIG":
		root = HKCC
		rootName = "HKEY_CURRENT_CONFIG"
	default:
		return nil, fmt.Errorf("unknown registry root %q", rootName)
	}

	return &RegPath{Root: root, RootName: rootName, SubKey: subKey}, nil
}

func (p *RegPath) FullName() string {
	if p.SubKey == "" {
		return p.RootName
	}
	return p.RootName + `\` + p.SubKey
}

// ============================================================================
// Value formatting
// ============================================================================

func typeName(t uint32) string {
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
	case REG_RESOURCE_LIST:
		return "resource-list"
	case REG_FULL_RESOURCE_DESCRIPTOR:
		return "resource-descriptor"
	case REG_RESOURCE_REQUIREMENTS_LIST:
		return "resource-requirements"
	case REG_QWORD:
		return "qword"
	}
	return fmt.Sprintf("type-%d", t)
}

func parseTypeName(s string) (uint32, error) {
	switch strings.ToLower(s) {
	case "string", "sz", "reg_sz":
		return REG_SZ, nil
	case "expand", "expand_sz", "reg_expand_sz":
		return REG_EXPAND_SZ, nil
	case "binary", "reg_binary", "hex":
		return REG_BINARY, nil
	case "dword", "reg_dword":
		return REG_DWORD, nil
	case "qword", "reg_qword":
		return REG_QWORD, nil
	case "multi", "multi_sz", "reg_multi_sz":
		return REG_MULTI_SZ, nil
	}
	return 0, fmt.Errorf("unknown value type %q", s)
}

func decodeString(data []byte) string {
	if len(data) < 2 {
		return ""
	}
	u := make([]uint16, len(data)/2)
	for i := 0; i < len(u); i++ {
		u[i] = uint16(data[i*2]) | uint16(data[i*2+1])<<8
	}
	// Trim at first NUL
	for i, v := range u {
		if v == 0 {
			u = u[:i]
			break
		}
	}
	return string(utf16.Decode(u))
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
			out = append(out, string(utf16.Decode(u[start:i])))
			start = i + 1
		}
	}
	return out
}

func encodeString(s string) []byte {
	u := utf16.Encode([]rune(s + "\x00"))
	out := make([]byte, len(u)*2)
	for i, v := range u {
		out[i*2] = byte(v)
		out[i*2+1] = byte(v >> 8)
	}
	return out
}

func encodeMultiString(items []string) []byte {
	var out []byte
	for _, s := range items {
		u := utf16.Encode([]rune(s))
		for _, v := range u {
			out = append(out, byte(v), byte(v>>8))
		}
		out = append(out, 0, 0)
	}
	if len(out) == 0 || out[len(out)-2] != 0 || out[len(out)-1] != 0 {
		out = append(out, 0, 0)
	}
	return out
}

// formatValueDisplay produces a human-readable string for terminal output.
func formatValueDisplay(v RegValue) string {
	switch v.Type {
	case REG_SZ, REG_EXPAND_SZ, REG_LINK:
		return decodeString(v.Data)
	case REG_MULTI_SZ:
		return strings.Join(decodeMultiString(v.Data), " | ")
	case REG_DWORD:
		if len(v.Data) >= 4 {
			n := binary.LittleEndian.Uint32(v.Data)
			return fmt.Sprintf("%d (0x%08X)", n, n)
		}
		return fmt.Sprintf("hex:%X", v.Data)
	case REG_DWORD_BIG_ENDIAN:
		if len(v.Data) >= 4 {
			n := binary.BigEndian.Uint32(v.Data)
			return fmt.Sprintf("%d (0x%08X)", n, n)
		}
		return fmt.Sprintf("hex:%X", v.Data)
	case REG_QWORD:
		if len(v.Data) >= 8 {
			n := binary.LittleEndian.Uint64(v.Data)
			return fmt.Sprintf("%d (0x%016X)", n, n)
		}
		return fmt.Sprintf("hex:%X", v.Data)
	case REG_BINARY:
		return fmt.Sprintf("hex:%s", hexJoin(v.Data))
	}
	return fmt.Sprintf("hex:%s", hexJoin(v.Data))
}

func hexJoin(b []byte) string {
	parts := make([]string, len(b))
	for i, x := range b {
		parts[i] = fmt.Sprintf("%02x", x)
	}
	return strings.Join(parts, ",")
}

// ============================================================================
// Value parsing (for `set` and .reg import)
// ============================================================================

func parseValueData(typeStr, dataStr string) (uint32, []byte, error) {
	typ, err := parseTypeName(typeStr)
	if err != nil {
		return 0, nil, err
	}
	switch typ {
	case REG_SZ, REG_EXPAND_SZ:
		return typ, encodeString(dataStr), nil
	case REG_MULTI_SZ:
		items := strings.Split(dataStr, "|")
		return typ, encodeMultiString(items), nil
	case REG_DWORD:
		n, err := strconv.ParseUint(strings.TrimSpace(dataStr), 0, 32)
		if err != nil {
			return 0, nil, fmt.Errorf("invalid dword %q", dataStr)
		}
		b := make([]byte, 4)
		binary.LittleEndian.PutUint32(b, uint32(n))
		return typ, b, nil
	case REG_QWORD:
		n, err := strconv.ParseUint(strings.TrimSpace(dataStr), 0, 64)
		if err != nil {
			return 0, nil, fmt.Errorf("invalid qword %q", dataStr)
		}
		b := make([]byte, 8)
		binary.LittleEndian.PutUint64(b, n)
		return typ, b, nil
	case REG_BINARY:
		clean := strings.ReplaceAll(dataStr, " ", "")
		clean = strings.ReplaceAll(clean, ",", "")
		clean = strings.TrimPrefix(clean, "0x")
		if len(clean)%2 != 0 {
			clean = "0" + clean
		}
		b, err := hexDecode(clean)
		if err != nil {
			return 0, nil, fmt.Errorf("invalid binary %q", dataStr)
		}
		return typ, b, nil
	}
	return typ, encodeString(dataStr), nil
}

func hexDecode(s string) ([]byte, error) {
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

// ============================================================================
// .reg export
// ============================================================================

var escapeStringReplacer = strings.NewReplacer(`\`, `\\`, `"`, `\"`)

func exportKeyToReg(buf *bytes.Buffer, key RegKey, fullPath string) error {
	buf.WriteString("\r\n[" + fullPath + "]\r\n")

	values, err := regEnumValues(key)
	if err != nil {
		return err
	}
	for _, v := range values {
		writeRegValue(buf, v)
	}

	subKeys, err := regEnumKeys(key)
	if err != nil {
		return err
	}
	for _, sub := range subKeys {
		child, err := regOpenKey(uintptr(key), sub, KEY_READ|wowFlag())
		if err != nil {
			continue
		}
		_ = exportKeyToReg(buf, child, fullPath+`\`+sub)
		regCloseKey(child)
	}
	return nil
}

func writeRegValue(buf *bytes.Buffer, v RegValue) {
	name := `@`
	if v.Name != "" {
		name = `"` + escapeStringReplacer.Replace(v.Name) + `"`
	}
	buf.WriteString(name + "=")
	switch v.Type {
	case REG_SZ, REG_LINK:
		buf.WriteString(`"` + escapeStringReplacer.Replace(decodeString(v.Data)) + `"` + "\r\n")
	case REG_DWORD:
		if len(v.Data) >= 4 {
			buf.WriteString(fmt.Sprintf("dword:%08x\r\n", binary.LittleEndian.Uint32(v.Data)))
		} else {
			buf.WriteString("hex:" + hexJoin(v.Data) + "\r\n")
		}
	case REG_QWORD:
		if len(v.Data) >= 8 {
			buf.WriteString("hex(b):" + hexJoin(v.Data[:8]) + "\r\n")
		} else {
			buf.WriteString("hex:" + hexJoin(v.Data) + "\r\n")
		}
	case REG_EXPAND_SZ:
		buf.WriteString("hex(2):" + hexJoin(v.Data) + "\r\n")
	case REG_MULTI_SZ:
		buf.WriteString("hex(7):" + hexJoin(v.Data) + "\r\n")
	default:
		buf.WriteString("hex:" + hexJoin(v.Data) + "\r\n")
	}
}

// exportRegString builds the full .reg text for a registry key and its subkeys.
func exportRegString(p *RegPath) (string, error) {
	k, err := regOpenKey(p.Root, p.SubKey, KEY_READ|wowFlag())
	if err != nil {
		return "", err
	}
	defer regCloseKey(k)

	var buf bytes.Buffer
	buf.WriteString("Windows Registry Editor Version 5.00\r\n")
	_ = exportKeyToReg(&buf, k, p.FullName())
	return buf.String(), nil
}

func wowFlag() uint32 {
	if wow32Flag {
		return KEY_WOW64_32KEY
	}
	return KEY_WOW64_64KEY
}

// ============================================================================
// .reg import (parser)
// ============================================================================

func utf16LEToUTF8(b []byte) string {
	if len(b)%2 != 0 {
		b = b[:len(b)-1]
	}
	u := make([]uint16, len(b)/2)
	for i := 0; i < len(u); i++ {
		u[i] = uint16(b[i*2]) | uint16(b[i*2+1])<<8
	}
	return string(utf16.Decode(u))
}

func decodeRegFileContent(content []byte) string {
	if len(content) >= 2 && content[0] == 0xFF && content[1] == 0xFE {
		return utf16LEToUTF8(content[2:])
	}
	if len(content) >= 3 && content[0] == 0xEF && content[1] == 0xBB && content[2] == 0xBF {
		return string(content[3:])
	}
	return string(content)
}

// importRegContent parses .reg text and writes every key/value it describes.
// It creates keys as needed and overwrites existing values.
func importRegContent(content []byte) error {
	text := decodeRegFileContent(content)
	lines := strings.Split(text, "\n")

	var curPath *RegPath
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
		if strings.HasSuffix(line, `\`) && !isValueContinuationTerminator(line) {
			pendingLine = line[:len(line)-1]
			continue
		}
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, ";") {
			continue
		}
		if strings.HasPrefix(trimmed, "Windows Registry Editor") {
			continue
		}
		if strings.HasPrefix(trimmed, "REGEDIT4") {
			continue
		}
		if strings.HasPrefix(trimmed, "[-") && strings.HasSuffix(trimmed, "]") {
			// Delete-key marker; restore usually rewrites, so skip.
			continue
		}
		if strings.HasPrefix(trimmed, "[") && strings.HasSuffix(trimmed, "]") {
			flushKey()
			inner := trimmed[1 : len(trimmed)-1]
			p, err := parseRegPath(inner)
			if err != nil {
				return fmt.Errorf("bad section %q: %w", inner, err)
			}
			curPath = p
			key, _, err := regCreateKey(p.Root, p.SubKey, KEY_WRITE|wowFlag())
			if err != nil {
				return fmt.Errorf("create %s: %w", p.FullName(), err)
			}
			curKey = key
			continue
		}
		if curPath == nil || curKey == 0 {
			continue
		}
		if err := applyRegValueLine(curKey, trimmed); err != nil {
			bugs.Add("WARN", "value line %q: %v", trimmed, err)
		}
	}
	flushKey()
	return nil
}

func isValueContinuationTerminator(line string) bool {
	// A value line ending with `\` inside quotes is a string continuation,
	// not a hex continuation. Our exporter only emits hex continuations, so
	// treat any line that starts with '"' or '@' and ends with `\` as
	// string-embedded (very rare). Conservative: only treat hex: lines as
	// continuable.
	l := strings.TrimSpace(line)
	return !(strings.Contains(l, "=hex"))
}

var regValueLineRe = regexp.MustCompile(`^(@|"(?:[^"\\]|\\.)*")\s*=\s*(.*)$`)

func applyRegValueLine(key RegKey, line string) error {
	m := regValueLineRe.FindStringSubmatch(line)
	if m == nil {
		return fmt.Errorf("not a value line")
	}
	name := ""
	if m[1] != "@" {
		name = unescapeRegString(m[1][1 : len(m[1])-1])
	}
	data := strings.TrimSpace(m[2])

	if data == "-" {
		return regDeleteValue(key, name)
	}

	if strings.HasPrefix(data, `"`) && strings.HasSuffix(data, `"`) && len(data) >= 2 {
		s := unescapeRegString(data[1 : len(data)-1])
		return regSetValue(key, name, REG_SZ, encodeString(s))
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
		b, err := hexDecode(strings.ReplaceAll(data[7:], ",", ""))
		if err != nil {
			return err
		}
		return regSetValue(key, name, REG_QWORD, b)
	}
	if strings.HasPrefix(data, "hex(2):") {
		b, err := hexDecode(strings.ReplaceAll(data[7:], ",", ""))
		if err != nil {
			return err
		}
		return regSetValue(key, name, REG_EXPAND_SZ, b)
	}
	if strings.HasPrefix(data, "hex(7):") {
		b, err := hexDecode(strings.ReplaceAll(data[7:], ",", ""))
		if err != nil {
			return err
		}
		return regSetValue(key, name, REG_MULTI_SZ, b)
	}
	if strings.HasPrefix(data, "hex:") {
		b, err := hexDecode(strings.ReplaceAll(data[4:], ",", ""))
		if err != nil {
			return err
		}
		return regSetValue(key, name, REG_BINARY, b)
	}
	return fmt.Errorf("unsupported value syntax %q", data)
}

func unescapeRegString(s string) string {
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

// ============================================================================
// JSON export
// ============================================================================

type jsonKey struct {
	Name     string       `json:"name"`
	Path     string       `json:"path"`
	Values   []jsonValue  `json:"values"`
	SubKeys  []string     `json:"subkeys,omitempty"`
}

type jsonValue struct {
	Name string `json:"name"`
	Type string `json:"type"`
	Data string `json:"data"`
}

func exportKeyToJSON(p *RegPath) ([]byte, error) {
	k, err := regOpenKey(p.Root, p.SubKey, KEY_READ|wowFlag())
	if err != nil {
		return nil, err
	}
	defer regCloseKey(k)
	obj, err := buildJSONKey(k, p.FullName())
	if err != nil {
		return nil, err
	}
	return json.MarshalIndent(obj, "", "  ")
}

func buildJSONKey(k RegKey, fullPath string) (*jsonKey, error) {
	obj := &jsonKey{
		Name: fullPath[strings.LastIndex(fullPath, `\`)+1:],
		Path: fullPath,
	}
	values, _ := regEnumValues(k)
	for _, v := range values {
		obj.Values = append(obj.Values, jsonValue{
			Name: v.Name,
			Type: typeName(v.Type),
			Data: formatValueDisplay(v),
		})
	}
	subs, _ := regEnumKeys(k)
	obj.SubKeys = subs
	return obj, nil
}

// ============================================================================
// Paths, log
// ============================================================================

const (
	backupDirName = "regctl_backup"
	logFileName   = "regctl.log"
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
	Path          string `json:"path"`
	ValueName     string `json:"valueName,omitempty"`
	OldValueType  uint32 `json:"oldValueType,omitempty"`
	OldValueData  []byte `json:"oldValueData,omitempty"`
	ExistsBefore  bool   `json:"existsBefore"`
	BackupFile    string `json:"backupFile,omitempty"`
	BackupGzipped bool   `json:"backupGzipped,omitempty"`
	Tree          bool   `json:"tree,omitempty"`
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

const smallRegThreshold = 8192

var sanitizeRe = regexp.MustCompile(`[^A-Za-z0-9._-]`)

func sanitizeForFilename(s string) string {
	s = strings.ReplaceAll(s, `\`, "_")
	s = sanitizeRe.ReplaceAllString(s, "_")
	if len(s) > 80 {
		s = s[:80]
	}
	return s
}

func toUTF16LEBOM(s string) []byte {
	u := utf16.Encode([]rune(s))
	buf := make([]byte, 2+len(u)*2)
	buf[0] = 0xFF
	buf[1] = 0xFE
	for i, v := range u {
		buf[2+i*2] = byte(v)
		buf[2+i*2+1] = byte(v >> 8)
	}
	return buf
}

// backupKeyToReg exports the target key (and subkeys) into ./files/<idx>_<name>.reg
// or .reg.gz depending on size. Returns the relative path under filesDir and
// whether the file was gzipped.
func backupKeyToReg(p *RegPath, logIdx int) (string, bool, error) {
	text, err := exportRegString(p)
	if err != nil {
		return "", false, err
	}
	raw := toUTF16LEBOM(text)
	base := fmt.Sprintf("%d_%s", logIdx, sanitizeForFilename(p.FullName()))
	if len(raw) < smallRegThreshold {
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
	if err := f.Close(); err != nil {
		return "", false, err
	}
	return rel, true, nil
}

func restoreFromBackup(relPath string, gzipped bool) error {
	full := filepath.Join(filesDir(), relPath)
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
	return importRegContent(content)
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
// Displays
// ============================================================================

func printValueLine(indent, name string, v RegValue) {
	displayName := name
	if displayName == "" {
		displayName = "(default)"
	}
	fmt.Printf("%s%s %s = %s\n",
		indent,
		c(clrCyan, padRight(displayName, 24)),
		c(clrGray, typeName(v.Type)),
		formatValueDisplay(v))
}

// ============================================================================
// ls
// ============================================================================

func cmdLs(args []string) int {
	jsonOut := false
	showValues := true
	showKeys := true
	var pathStr string
	for _, a := range args {
		switch a {
		case "--json":
			jsonOut = true
		case "--no-values":
			showValues = false
		case "--no-keys":
			showKeys = false
		default:
			if strings.HasPrefix(a, "-") {
				fmt.Fprintf(os.Stderr, "ls: unknown option %s\n", a)
				return 2
			}
			pathStr = a
		}
	}
	if pathStr == "" {
		fmt.Fprintln(os.Stderr, "usage: regctl ls <path> [--json] [--no-values] [--no-keys]")
		return 2
	}

	p, err := parseRegPath(pathStr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "regctl: %v\n", err)
		return 2
	}

	k, err := regOpenKey(p.Root, p.SubKey, KEY_READ|wowFlag())
	if err != nil {
		fmt.Fprintf(os.Stderr, "regctl: %v\n", err)
		return 4
	}
	defer regCloseKey(k)

	if jsonOut {
		obj, err := buildJSONKey(k, p.FullName())
		if err != nil {
			fmt.Fprintf(os.Stderr, "regctl: %v\n", err)
			return 5
		}
		out, _ := json.MarshalIndent(obj, "", "  ")
		fmt.Println(string(out))
		return 0
	}

	fmt.Println(c(clrBold+clrCyan, p.FullName()))

	if showKeys {
		subs, _ := regEnumKeys(k)
		if len(subs) > 0 {
			fmt.Println()
			fmt.Println(c(clrGray, "Subkeys:"))
			for _, s := range subs {
				fmt.Println("  " + c(clrCyan, s))
			}
		}
	}

	if showValues {
		vals, _ := regEnumValues(k)
		if len(vals) > 0 {
			fmt.Println()
			fmt.Println(c(clrGray, "Values:"))
			for _, v := range vals {
				printValueLine("  ", v.Name, v)
			}
		}
	}
	return 0
}

// ============================================================================
// cat / get
// ============================================================================

func cmdCat(args []string) int {
	jsonOut := false
	var pathStr string
	for _, a := range args {
		switch a {
		case "--json":
			jsonOut = true
		default:
			if strings.HasPrefix(a, "-") {
				fmt.Fprintf(os.Stderr, "cat: unknown option %s\n", a)
				return 2
			}
			pathStr = a
		}
	}
	if pathStr == "" {
		fmt.Fprintln(os.Stderr, "usage: regctl cat <path> [--json]")
		return 2
	}
	p, err := parseRegPath(pathStr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "regctl: %v\n", err)
		return 2
	}
	k, err := regOpenKey(p.Root, p.SubKey, KEY_READ|wowFlag())
	if err != nil {
		fmt.Fprintf(os.Stderr, "regctl: %v\n", err)
		return 4
	}
	defer regCloseKey(k)

	vals, _ := regEnumValues(k)
	if jsonOut {
		out := make([]jsonValue, len(vals))
		for i, v := range vals {
			out[i] = jsonValue{Name: v.Name, Type: typeName(v.Type), Data: formatValueDisplay(v)}
		}
		b, _ := json.MarshalIndent(out, "", "  ")
		fmt.Println(string(b))
		return 0
	}
	if len(vals) == 0 {
		fmt.Fprintln(os.Stderr, "(no values)")
		return 0
	}
	for _, v := range vals {
		printValueLine("", v.Name, v)
	}
	return 0
}

func cmdGet(args []string) int {
	jsonOut := false
	var pathStr, valName string
	var rest []string
	for _, a := range args {
		switch a {
		case "--json":
			jsonOut = true
		default:
			if strings.HasPrefix(a, "-") && a != "-" {
				fmt.Fprintf(os.Stderr, "get: unknown option %s\n", a)
				return 2
			}
			rest = append(rest, a)
		}
	}
	if len(rest) < 1 {
		fmt.Fprintln(os.Stderr, "usage: regctl get <path> [value] [--json]")
		return 2
	}
	pathStr = rest[0]
	if len(rest) > 1 {
		valName = rest[1]
		if valName == "@" {
			valName = ""
		}
	}

	p, err := parseRegPath(pathStr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "regctl: %v\n", err)
		return 2
	}
	k, err := regOpenKey(p.Root, p.SubKey, KEY_READ|wowFlag())
	if err != nil {
		fmt.Fprintf(os.Stderr, "regctl: %v\n", err)
		return 4
	}
	defer regCloseKey(k)

	v, err := regQueryValue(k, valName)
	if err != nil {
		fmt.Fprintf(os.Stderr, "regctl: value %q not found: %v\n", valName, err)
		return 4
	}
	if jsonOut {
		out := jsonValue{Name: v.Name, Type: typeName(v.Type), Data: formatValueDisplay(*v)}
		b, _ := json.MarshalIndent(out, "", "  ")
		fmt.Println(string(b))
		return 0
	}
	fmt.Println(formatValueDisplay(*v))
	return 0
}

// ============================================================================
// find
// ============================================================================

func cmdFind(args []string) int {
	pattern := ""
	rootStr := "HKLM\\SOFTWARE"
	searchData := false
	searchKeys := true
	searchValues := true
	maxResults := 100
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--root":
			if i+1 >= len(args) {
				fmt.Fprintln(os.Stderr, "find: --root requires a path")
				return 2
			}
			rootStr = args[i+1]
			i++
		case "--data":
			searchData = true
		case "--keys":
			searchKeys = true
			searchValues = false
		case "--values":
			searchValues = true
			searchKeys = false
		case "--max":
			if i+1 >= len(args) {
				fmt.Fprintln(os.Stderr, "find: --max requires a number")
				return 2
			}
			v, err := strconv.Atoi(args[i+1])
			if err != nil || v <= 0 {
				fmt.Fprintf(os.Stderr, "find: invalid --max %q\n", args[i+1])
				return 2
			}
			maxResults = v
			i++
		default:
			if strings.HasPrefix(args[i], "-") {
				fmt.Fprintf(os.Stderr, "find: unknown option %s\n", args[i])
				return 2
			}
			pattern = args[i]
		}
	}
	if pattern == "" {
		fmt.Fprintln(os.Stderr, "usage: regctl find <pattern> [--root <path>] [--data] [--keys|--values] [--max N]")
		return 2
	}

	rootPath, err := parseRegPath(rootStr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "regctl: %v\n", err)
		return 2
	}

	lower := strings.ToLower(pattern)
	matches := 0
	var walk func(p *RegPath) bool
	walk = func(p *RegPath) bool {
		k, err := regOpenKey(p.Root, p.SubKey, KEY_READ|wowFlag())
		if err != nil {
			return false
		}
		defer regCloseKey(k)

		if searchValues {
			vals, _ := regEnumValues(k)
			for _, v := range vals {
				hit := strings.Contains(strings.ToLower(v.Name), lower)
				if searchData {
					hit = hit || strings.Contains(strings.ToLower(formatValueDisplay(v)), lower)
				}
				if hit {
					fmt.Printf("%s   %s = %s\n",
						c(clrGray, p.FullName()),
						c(clrCyan, v.Name),
						formatValueDisplay(v))
					matches++
					if matches >= maxResults {
						return true
					}
				}
			}
		}

		subs, _ := regEnumKeys(k)
		for _, s := range subs {
			childPath := &RegPath{Root: p.Root, RootName: p.RootName, SubKey: p.SubKey + `\` + s}
			if p.SubKey == "" {
				childPath.SubKey = s
			}
			if searchKeys {
				if strings.Contains(strings.ToLower(s), lower) {
					fmt.Println(c(clrCyan, childPath.FullName()))
					matches++
					if matches >= maxResults {
						return true
					}
				}
			}
			if walk(childPath) {
				return true
			}
		}
		return false
	}
	walk(rootPath)
	fmt.Fprintf(os.Stderr, "\n%d match(es)\n", matches)
	if matches == 0 {
		return 1
	}
	return 0
}

// ============================================================================
// export
// ============================================================================

func cmdExport(args []string) int {
	jsonOut := false
	outFile := ""
	var pathStr string
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--json":
			jsonOut = true
		case "-o", "--out":
			if i+1 >= len(args) {
				fmt.Fprintln(os.Stderr, "export: %s requires a path", args[i])
				return 2
			}
			outFile = args[i+1]
			i++
		default:
			if strings.HasPrefix(args[i], "-") {
				fmt.Fprintf(os.Stderr, "export: unknown option %s\n", args[i])
				return 2
			}
			pathStr = args[i]
		}
	}
	if pathStr == "" {
		fmt.Fprintln(os.Stderr, "usage: regctl export <path> [-o file] [--json]")
		return 2
	}
	p, err := parseRegPath(pathStr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "regctl: %v\n", err)
		return 2
	}

	if jsonOut {
		b, err := exportKeyToJSON(p)
		if err != nil {
			fmt.Fprintf(os.Stderr, "regctl: %v\n", err)
			return 5
		}
		if outFile != "" {
			if err := writeFileEnsuringDir(outFile, b); err != nil {
				fmt.Fprintf(os.Stderr, "regctl: %v\n", err)
				return 5
			}
			fmt.Fprintf(os.Stderr, "exported to %s\n", outFile)
			return 0
		}
		fmt.Println(string(b))
		return 0
	}

	text, err := exportRegString(p)
	if err != nil {
		fmt.Fprintf(os.Stderr, "regctl: %v\n", err)
		return 5
	}
	raw := toUTF16LEBOM(text)
	if outFile != "" {
		if err := writeFileEnsuringDir(outFile, raw); err != nil {
			fmt.Fprintf(os.Stderr, "regctl: %v\n", err)
			return 5
		}
		fmt.Fprintf(os.Stderr, "exported to %s\n", outFile)
		return 0
	}
	os.Stdout.Write(raw)
	return 0
}

func writeFileEnsuringDir(path string, data []byte) error {
	dir := filepath.Dir(path)
	if dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return err
		}
	}
	return os.WriteFile(path, data, 0644)
}

// ============================================================================
// set
// ============================================================================

func cmdSet(args []string) int {
	var rest []string
	for _, a := range args {
		if strings.HasPrefix(a, "-") && a != "-" {
			fmt.Fprintf(os.Stderr, "set: unknown option %s\n", a)
			return 2
		}
		rest = append(rest, a)
	}
	if len(rest) < 4 {
		fmt.Fprintln(os.Stderr, "usage: regctl set <path> <value> <type> <data>")
		fmt.Fprintln(os.Stderr, "  <value> is the value name, or @ for the default value")
		fmt.Fprintln(os.Stderr, "  <type>  is string|expand|dword|qword|binary|multi")
		return 2
	}
	pathStr, valName, typeStr := rest[0], rest[1], rest[2]
	dataStr := strings.Join(rest[3:], " ")
	if valName == "@" {
		valName = ""
	}

	p, err := parseRegPath(pathStr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "regctl: %v\n", err)
		return 2
	}

	typ, data, err := parseValueData(typeStr, dataStr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "regctl: %v\n", err)
		return 2
	}

	// Snapshot before mutating.
	existing, _ := regOpenKey(p.Root, p.SubKey, KEY_READ|wowFlag())
	existsBefore := existing != 0
	var oldVal *RegValue
	if existsBefore {
		oldVal, _ = regQueryValue(existing, valName)
		regCloseKey(existing)
	}

	if dryRun {
		fmt.Printf("[dry-run] set %s\\%s = %s (%s)\n", p.FullName(), valueDisplayName(valName), dataStr, typeName(typ))
		return 0
	}

	// Backup BEFORE mutation. If backup fails, abort.
	idx := beginWriteOp()
	backupRel := ""
	backupGz := false
	if existsBefore {
		backupRel, backupGz, err = backupKeyToReg(p, idx)
		if err != nil {
			fmt.Fprintf(os.Stderr, "regctl: backup failed, aborting: %v\n", err)
			return 5
		}
	}

	key, _, err := regCreateKey(p.Root, p.SubKey, KEY_SET_VALUE|wowFlag())
	if err != nil {
		fmt.Fprintf(os.Stderr, "regctl: create key: %v\n", err)
		return 5
	}
	if err := regSetValue(key, valName, typ, data); err != nil {
		regCloseKey(key)
		fmt.Fprintf(os.Stderr, "regctl: set value: %v\n", err)
		return 5
	}
	regCloseKey(key)

	rec := &opRecord{
		Op:            "set",
		TS:            time.Now().Format("2006-01-02 15:04:05"),
		Cmd:           buildCmdLine(os.Args),
		Path:          p.FullName(),
		ValueName:     valName,
		ExistsBefore:  existsBefore,
		BackupFile:    backupRel,
		BackupGzipped: backupGz,
	}
	if oldVal != nil {
		rec.OldValueType = oldVal.Type
		rec.OldValueData = oldVal.Data
	}
	saveOpRecord(idx, rec)

	fmt.Printf("%s %s\\%s = %s\n", c(clrGreen, "set"), p.FullName(), valueDisplayName(valName), formatValueDisplay(RegValue{Type: typ, Data: data}))
	return 0
}

func valueDisplayName(n string) string {
	if n == "" {
		return "(default)"
	}
	return n
}

// ============================================================================
// del / mkkey / rmkey
// ============================================================================

func cmdDel(args []string) int {
	force := false
	tree := false
	var rest []string
	for _, a := range args {
		switch a {
		case "-f", "--force":
			force = true
		case "--tree":
			tree = true
		default:
			if strings.HasPrefix(a, "-") && a != "-" {
				fmt.Fprintf(os.Stderr, "del: unknown option %s\n", a)
				return 2
			}
			rest = append(rest, a)
		}
	}
	if len(rest) < 1 {
		fmt.Fprintln(os.Stderr, "usage: regctl del <path> [value] [-f] [--tree]")
		return 2
	}
	pathStr := rest[0]
	valName := ""
	hasValueName := false
	if len(rest) > 1 {
		valName = rest[1]
		if valName == "@" {
			valName = ""
		}
		hasValueName = true
	}

	p, err := parseRegPath(pathStr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "regctl: %v\n", err)
		return 2
	}

	existing, err := regOpenKey(p.Root, p.SubKey, KEY_READ|wowFlag())
	existsBefore := err == nil
	if !existsBefore {
		fmt.Fprintf(os.Stderr, "regctl: %s does not exist\n", p.FullName())
		return 4
	}
	defer regCloseKey(existing)

	var oldVal *RegValue
	if hasValueName {
		oldVal, _ = regQueryValue(existing, valName)
		if oldVal == nil {
			fmt.Fprintf(os.Stderr, "regctl: value %q not found\n", valueDisplayName(valName))
			return 4
		}
	}

	if dryRun {
		if hasValueName {
			fmt.Printf("[dry-run] del %s\\%s\n", p.FullName(), valueDisplayName(valName))
		} else {
			fmt.Printf("[dry-run] del%s %s\n", treeOrBlank(tree), p.FullName())
		}
		return 0
	}

	// Second confirmation for delete operations.
	if !force {
		var prompt string
		if hasValueName {
			prompt = fmt.Sprintf("delete value %q from %s?", valueDisplayName(valName), p.FullName())
		} else if tree {
			prompt = fmt.Sprintf("delete key %s AND all subkeys?", p.FullName())
		} else {
			prompt = fmt.Sprintf("delete key %s?", p.FullName())
		}
		if !confirm(prompt) {
			return 1
		}
	}

	idx := beginWriteOp()
	backupRel, backupGz, err := backupKeyToReg(p, idx)
	if err != nil {
		fmt.Fprintf(os.Stderr, "regctl: backup failed, aborting: %v\n", err)
		return 5
	}

	var opName string
	if hasValueName {
		if err := regDeleteValue(existing, valName); err != nil {
			fmt.Fprintf(os.Stderr, "regctl: delete value: %v\n", err)
			return 5
		}
		opName = "del-value"
	} else {
		// Close handle first; RegDeleteTree needs the parent open.
		regCloseKey(existing)
		existing = 0
		var derr error
		if tree {
			derr = regDeleteTree(p.Root, p.SubKey)
		} else {
			// Non-recursive: delete the key (fails if it has subkeys).
			subPtr, _ := syscall.UTF16PtrFromString(p.SubKey)
			r, _, _ := pRegDeleteKeyW.Call(p.Root, uintptr(unsafe.Pointer(subPtr)))
			if r != 0 {
				derr = syscall.Errno(r)
			}
		}
		if derr != nil {
			fmt.Fprintf(os.Stderr, "regctl: delete key: %v (use --tree to recurse)\n", derr)
			return 5
		}
		opName = "del-key"
		if tree {
			opName = "del-tree"
		}
	}

	rec := &opRecord{
		Op:            opName,
		TS:            time.Now().Format("2006-01-02 15:04:05"),
		Cmd:           buildCmdLine(os.Args),
		Path:          p.FullName(),
		ValueName:     valName,
		ExistsBefore:  true,
		BackupFile:    backupRel,
		BackupGzipped: backupGz,
		Tree:          tree,
	}
	if oldVal != nil {
		rec.OldValueType = oldVal.Type
		rec.OldValueData = oldVal.Data
	}
	saveOpRecord(idx, rec)

	if hasValueName {
		fmt.Printf("%s %s\\%s\n", c(clrYellow, "deleted"), p.FullName(), valueDisplayName(valName))
	} else {
		fmt.Printf("%s %s\n", c(clrYellow, "deleted"), p.FullName())
	}
	return 0
}

func treeOrBlank(tree bool) string {
	if tree {
		return " --tree"
	}
	return ""
}

func cmdMkkey(args []string) int {
	var pathStr string
	for _, a := range args {
		if strings.HasPrefix(a, "-") {
			fmt.Fprintf(os.Stderr, "mkkey: unknown option %s\n", a)
			return 2
		}
		pathStr = a
	}
	if pathStr == "" {
		fmt.Fprintln(os.Stderr, "usage: regctl mkkey <path>")
		return 2
	}
	p, err := parseRegPath(pathStr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "regctl: %v\n", err)
		return 2
	}

	existing, err := regOpenKey(p.Root, p.SubKey, KEY_READ|wowFlag())
	existsBefore := err == nil
	if existsBefore {
		regCloseKey(existing)
	}

	if dryRun {
		fmt.Printf("[dry-run] mkkey %s%s\n", p.FullName(), existsSuffix(existsBefore))
		return 0
	}

	idx := beginWriteOp()
	backupRel := ""
	backupGz := false
	if existsBefore {
		backupRel, backupGz, err = backupKeyToReg(p, idx)
		if err != nil {
			fmt.Fprintf(os.Stderr, "regctl: backup failed, aborting: %v\n", err)
			return 5
		}
	}

	key, created, err := regCreateKey(p.Root, p.SubKey, KEY_WRITE|wowFlag())
	if err != nil {
		fmt.Fprintf(os.Stderr, "regctl: %v\n", err)
		return 5
	}
	regCloseKey(key)

	rec := &opRecord{
		Op:            "mkkey",
		TS:            time.Now().Format("2006-01-02 15:04:05"),
		Cmd:           buildCmdLine(os.Args),
		Path:          p.FullName(),
		ExistsBefore:  existsBefore,
		BackupFile:    backupRel,
		BackupGzipped: backupGz,
	}
	saveOpRecord(idx, rec)

	if created {
		fmt.Printf("%s %s\n", c(clrGreen, "created"), p.FullName())
	} else {
		fmt.Printf("%s %s\n", c(clrGray, "already exists"), p.FullName())
	}
	return 0
}

func existsSuffix(exists bool) string {
	if exists {
		return " (already exists)"
	}
	return ""
}

// ============================================================================
// browse
// ============================================================================

var browseTargets = map[string][]string{
	"system": {"HKLM\\SYSTEM"},
	"software": {"HKLM\\SOFTWARE"},
	"hardware": {"HKLM\\HARDWARE"},
	"security": {
		"HKLM\\SECURITY",
		"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies",
		"HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies",
		"HKLM\\SOFTWARE\\Policies",
		"HKCU\\SOFTWARE\\Policies",
	},
	"startup": {
		"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
		"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
		"HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
		"HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
		"HKLM\\Software\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Run",
		"HKLM\\Software\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
	},
	"uninstall": {
		"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall",
		"HKLM\\SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall",
		"HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall",
	},
}

func cmdBrowse(args []string) int {
	var category string
	for _, a := range args {
		if strings.HasPrefix(a, "-") {
			fmt.Fprintf(os.Stderr, "browse: unknown option %s\n", a)
			return 2
		}
		category = a
	}
	if category == "" {
		fmt.Fprintln(os.Stderr, "usage: regctl browse <category>")
		fmt.Fprintln(os.Stderr, "  categories: system | software | startup | security | hardware | uninstall")
		return 2
	}
	category = strings.ToLower(category)
	targets, ok := browseTargets[category]
	if !ok {
		fmt.Fprintf(os.Stderr, "browse: unknown category %q\n", category)
		return 2
	}

	for _, target := range targets {
		p, err := parseRegPath(target)
		if err != nil {
			bugs.Add("WARN", "parse %s: %v", target, err)
			continue
		}
		k, err := regOpenKey(p.Root, p.SubKey, KEY_READ|wowFlag())
		if err != nil {
			fmt.Printf("%s\n  %s\n\n",
				c(clrBold+clrCyan, p.FullName()),
				c(clrGray, "(not accessible: "+err.Error()+")"))
			continue
		}

		if category == "startup" {
			fmt.Println(c(clrBold+clrCyan, p.FullName()))
			vals, _ := regEnumValues(k)
			for _, v := range vals {
				fmt.Printf("  %s = %s\n", c(clrCyan, v.Name), formatValueDisplay(v))
			}
			if len(vals) == 0 {
				fmt.Println(c(clrGray, "  (empty)"))
			}
			fmt.Println()
		} else {
			subs, _ := regEnumKeys(k)
			fmt.Printf("%s  %s\n", c(clrBold+clrCyan, p.FullName()),
				c(clrGray, fmt.Sprintf("(%d subkeys)", len(subs))))
			sort.Strings(subs)
			for _, s := range subs {
				fmt.Println("  " + c(clrCyan, s))
			}
			fmt.Println()
		}
		regCloseKey(k)
	}
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
	case "set":
		return "-> restore " + rec.Path + `\` + valueDisplayName(rec.ValueName)
	case "del-value":
		return "-> restore value " + rec.Path + `\` + valueDisplayName(rec.ValueName)
	case "del-key", "del-tree":
		return "-> restore key " + rec.Path
	case "mkkey":
		return "-> delete key " + rec.Path
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
	p, err := parseRegPath(rec.Path)
	if err != nil {
		return err
	}

	// Strategy:
	//   existsBefore && backupFile != "" → delete key (if exists), import backup
	//   !existsBefore                     → delete key (if exists); no backup to restore
	//
	// For set/del-value/del-key/del-tree, this restores the whole key from
	// the backup, which is the correct inverse.
	// For mkkey with existsBefore=false, deleting the key is the inverse.
	// For mkkey with existsBefore=true, the operation was a no-op, so delete
	// and re-import would be a no-op too, but to be safe we do nothing.

	if rec.Op == "mkkey" && rec.ExistsBefore {
		return nil
	}

	// Delete current key if it exists (ignore not-found).
	if k, err := regOpenKey(p.Root, p.SubKey, KEY_READ|wowFlag()); err == nil {
		regCloseKey(k)
		_ = regDeleteTree(p.Root, p.SubKey)
	}

	if rec.ExistsBefore && rec.BackupFile != "" {
		if err := restoreFromBackup(rec.BackupFile, rec.BackupGzipped); err != nil {
			return fmt.Errorf("restore %s: %w", rec.Path, err)
		}
	}
	return nil
}

// ============================================================================
// Help
// ============================================================================

func printHelp() {
	header := "regctl v1.0.0 (Windows)"
	fmt.Println(c(clrBold+clrCyan, header))
	fmt.Println("Windows registry manager - browse / read / search / export / rollback")
	fmt.Println()
	fmt.Print(`USAGE
  regctl ls <path> [--json] [--no-keys] [--no-values]
  regctl cat <path> [--json]
  regctl get <path> [value] [--json]
  regctl find <pattern> [--root <path>] [--data] [--keys|--values] [--max N]
  regctl export <path> [-o file] [--json]
  regctl set <path> <value> <type> <data>
  regctl del <path> [value] [-f] [--tree]
  regctl mkkey <path>
  regctl browse <category>
  regctl --history
  regctl --rollback [-n N]

PATH
  A path is <root>\<subkey>, e.g.
    HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
    HKEY_CURRENT_USER\Software\Test
  Accepted roots: HKCR/HKEY_CLASSES_ROOT, HKCU/HKEY_CURRENT_USER,
                  HKLM/HKEY_LOCAL_MACHINE, HKU/HKEY_USERS,
                  HKCC/HKEY_CURRENT_CONFIG.
  By default the 64-bit registry view is used. Pass --wow32 to read/write
  the 32-bit view (Wow6432Node).

COMMANDS
  ls <path>            Show subkeys and values under <path>
  cat <path>           Show every value directly under <path>
  get <path> [value]   Get a specific value; omit <value> or use @ for
                       the default value
  find <pattern>       Recursively search by name. --data also matches value
                       data; --max N limits results (default 100).
  export <path>        Write a .reg file (default) or JSON (--json)
  set <path> <value> <type> <data>
                       Set a value. <type> is string|expand|dword|qword|
                       binary|multi. <value> @ means the default value.
                       A backup of the whole target key is written BEFORE
                       the change; if the backup fails, the change is
                       aborted.
  del <path> [value]   Delete a value (when <value> is given) or a key
                       (when only <path> is given). Always prompts for
                       confirmation unless -f is used. --tree recurses.
                       A backup is taken first.
  mkkey <path>         Create a key. Backup taken if the key existed.
  browse <category>    Show a curated view:
      system      HKLM\SYSTEM
      software    HKLM\SOFTWARE
      startup     Run/RunOnce keys (HKCU + HKLM + Wow6432Node)
      security    HKLM\SECURITY + Policies keys
      hardware    HKLM\HARDWARE
      uninstall   Uninstall registry keys (32 + 64 bit)

GLOBAL
  -o, --out <path>     Redirect stdout to a file for any subcommand.
  --dry-run            Preview only: prints the plan for each target, does
                       not change the registry, does not write backups,
                       does not write logs.
  --wow32              Use the 32-bit registry view (Wow6432Node).
  --no-color           Disable ANSI colors (also honors NO_COLOR env var).
  -b, --bugs           Print collected errors/warnings on exit.
  -h, --help           Show this help.
  --version            Show version.

HISTORY / ROLLBACK
  --history
      Lists rollback-able operations in reverse chronological order.
      [1] is the most recent operation.

  --rollback
      Undo the most recent operation (equivalent to -n 1).

  --rollback -n N
      Undo the most recent N operations.

  Each rollback deletes the affected key and re-imports its backup. For
  mkkey operations where the key did not exist before, rollback deletes
  the key. Every step prints its exit code.

BACKUP AND LOG
  Every invocation (except -h / --help / --version / --history / --dry-run)
  appends one line to:
    ./regctl_backup/regctl.log
  Format:
    [command line] [timestamp] [exit code]

  Write operations store their snapshot under:
    ./regctl_backup/files/<logIndex>_<sanitized>.reg         (small keys)
    ./regctl_backup/files/<logIndex>_<sanitized>.reg.gz      (gzip -9 when
                                                              the .reg is >= 8 KiB)
  and a manifest under:
    ./regctl_backup/ops/<logIndex>.json

  The .reg file is UTF-16LE with BOM, so it can be imported directly by
  regedit.exe or by "regctl --rollback".

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
		case a == "--wow32":
			wow32Flag = true
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
		fmt.Fprintf(os.Stderr, "regctl: %v\n", err)
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
			fmt.Fprintf(os.Stderr, "regctl: %v\n", err)
			bugs.Flush()
			os.Exit(2)
		}
	}

	if has(args, "--version") {
		fmt.Println("regctl v1.0.0")
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
			fmt.Fprintln(os.Stderr, "regctl: missing command, use -h for help")
			code = 2
			break
		}
		cmd := args[cmdIdx]
		rest := append([]string{}, args[:cmdIdx]...)
		rest = append(rest, args[cmdIdx+1:]...)

		switch cmd {
		case "ls":
			code = cmdLs(rest)
		case "cat":
			code = cmdCat(rest)
		case "get":
			code = cmdGet(rest)
		case "find":
			code = cmdFind(rest)
		case "export":
			code = cmdExport(rest)
		case "set":
			code = cmdSet(rest)
		case "del", "delete":
			code = cmdDel(rest)
		case "mkkey":
			code = cmdMkkey(rest)
		case "browse":
			code = cmdBrowse(rest)
		default:
			fmt.Fprintf(os.Stderr, "regctl: unknown command %q\n", cmd)
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

// padRight is shared with svcctl-style column output.
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

// bufio is imported for potential future line-based prompts; keep the import
// alive with a no-op reference.
var _ = bufio.NewReader