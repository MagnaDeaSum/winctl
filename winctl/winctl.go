//go:build windows && amd64

package main

import (
	"archive/tar"
	"bufio"
	"bytes"
	"compress/gzip"
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"crypto/md5"
	"crypto/rc4"
	"crypto/sha1"
	"crypto/sha256"
	"debug/pe"
	"encoding/asn1"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"math"
	"math/rand"
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
	"unicode/utf16"
	"unicode/utf8"
	"unsafe"
)

// ==================== shared infrastructure ====================

const (
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

	REG_NONE     = 0
	REG_SZ       = 1
	REG_EXPAND_SZ = 2
	REG_BINARY   = 3
	REG_DWORD    = 4
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

	logRe = regexp.MustCompile(`^\[(.*)\] \[(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\] \[(-?\d+)\]$`)
)

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

func exeDir() string {
	if e, err := os.Executable(); err == nil {
		return filepath.Dir(e)
	}
	if w, err := os.Getwd(); err == nil {
		return w
	}
	return "."
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

func isHistorySelf(cmd string) bool {
	return strings.Contains(cmd, "--history") || strings.Contains(cmd, "--rollback") ||
		strings.Contains(cmd, "-h") || strings.Contains(cmd, "--help") ||
		strings.Contains(cmd, "--version")
}

// ────────── registry wrappers ──────────

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
			// BUGFIX: Add margin to prevent infinite loop caused by API growth between two calls
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

// ==================== main ====================

func main() {
	args := os.Args[1:]
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "winctl: missing subcommand")
		fmt.Fprintln(os.Stderr, "  available: net open pe proc reg svc sys task acl bkp disk doc evt fs hash")
		os.Exit(2)
	}
	tool := args[0]
	os.Args = append([]string{os.Args[0]}, args[1:]...)
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
	default:
		fmt.Fprintf(os.Stderr, "winctl: unknown subcommand %q\n", tool)
		os.Exit(2)
	}
}
// ==================== net ====================
// netctl — Windows network & connection viewer with rollback.
// Single-file, standard-library-only build:
//
//   go build -trimpath -ldflags "-s -w" -o netctl.exe netctl.go

// ============================================================================
// Colors
// ============================================================================

// (shared with the rest of the toolkit)

// ============================================================================
// Console detection
// ============================================================================

var (
	net_pOpenProcess                = kernel32.NewProc("OpenProcess")
	net_pQueryFullProcessImageNameW = kernel32.NewProc("QueryFullProcessImageNameW")
)

// ============================================================================
// Bug collector (-b/--bugs)
// ============================================================================

// (shared)

// ============================================================================
// net_iphlpapi bindings
// ============================================================================

var (
	net_iphlpapi = syscall.NewLazyDLL("net_iphlpapi.dll")

	net_pGetExtendedTcpTable  = net_iphlpapi.NewProc("GetExtendedTcpTable")
	net_pGetExtendedUdpTable  = net_iphlpapi.NewProc("GetExtendedUdpTable")
	net_pGetAdaptersAddresses = net_iphlpapi.NewProc("GetAdaptersAddresses")
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
)

type net_MIB_TCPROW_OWNER_PID struct {
	State      uint32
	LocalAddr  uint32
	LocalPort  uint32
	RemoteAddr uint32
	RemotePort uint32
	OwningPid  uint32
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
	LocalAddr uint32
	LocalPort uint32
	OwningPid uint32
}

type net_MIB_UDP6ROW_OWNER_PID struct {
	ucLocalAddr    [16]byte
	dwLocalScopeId uint32
	dwLocalPort    uint32
	dwOwningPid    uint32
}

// ============================================================================
// Adapter address structures (prefix of net_IP_ADAPTER_ADDRESSES_LH)
// ============================================================================

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
	Length   uint32
	Reserved uint32
	Next     *net_IP_ADAPTER_DNS_SERVER_ADDRESS_XP
	Address  net_SOCKET_ADDRESS
}

type net_IP_ADAPTER_ADDRESSES_LH struct {
	Length                uint32
	IfIndex               uint32
	Next                  *net_IP_ADAPTER_ADDRESSES_LH
	AdapterName           *byte
	FirstUnicastAddress   *net_IP_ADAPTER_UNICAST_ADDRESS_LH
	FirstAnycastAddress   *net_IP_ADAPTER_UNICAST_ADDRESS_LH
	FirstMulticastAddress *net_IP_ADAPTER_UNICAST_ADDRESS_LH
	FirstDnsServerAddress *net_IP_ADAPTER_DNS_SERVER_ADDRESS_XP
	DnsSuffix             *uint16
	Description           *uint16
	FriendlyName          *uint16
	PhysicalAddress       [8]byte
	PhysicalAddressLength uint32
	Flags                 uint32
	Mtu                   uint32
	IfType                uint32
	OperStatus            uint32
	Ipv6IfIndex           uint32
	ZoneIndices           [16]uint32
	FirstPrefix           uintptr
}

const (
	net_IfOperStatusUp            = 1
	net_IF_TYPE_ETHERNET_CSMACD   = 6
	net_IF_TYPE_IEEE80211         = 71
	net_IF_TYPE_SOFTWARE_LOOPBACK = 24
	net_IF_TYPE_TUNNEL            = 131
	net_GAA_FLAG_INCLUDE_PREFIX   = 0x0010
)

// ============================================================================
// Registry bindings (proxy)
// ============================================================================

const net_proxyKeyPath = `Software\Microsoft\Windows\CurrentVersion\Internet Settings`

// net_regCreateKey is the error-checked version of RegCreateKeyExW. The
// original implementation silently discarded the UTF16PtrFromString error,
// which would pass a NULL lpSubKey to the API on invalid input.
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

// ============================================================================
// UTF-16 helpers
// ============================================================================

func net_utf16Decode(u []uint16) []rune {
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

func net_utf16Encode(s string) []uint16 {
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

// net_utf16At reads a NUL-terminated UTF-16 string starting at p. It stops at
// the first NUL or after maxCodeUnits elements, whichever comes first. This
// avoids the unsafe.Slice(ptr, N) pattern that can read past the end of a
// string shorter than N.
func net_utf16At(p *uint16, maxCodeUnits int) string {
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

func net_decodeRegString(b []byte) string {
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
	return string(net_utf16Decode(u))
}

func net_encodeRegString(s string) []byte {
	u := net_utf16Encode(s)
	u = append(u, 0)
	out := make([]byte, len(u)*2)
	for i, v := range u {
		out[i*2] = byte(v)
		out[i*2+1] = byte(v >> 8)
	}
	return out
}

// ============================================================================
// IPv4/IPv6 formatting and sockaddr decoding
// ============================================================================

func net_ntohs(x uint32) uint16 {
	return uint16(x&0xFF)<<8 | uint16((x>>8)&0xFF)
}

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
				curStart = i
				curLen = 0
			}
			curLen++
			if curLen > bestLen {
				bestStart = curStart
				bestLen = curLen
			}
		} else {
			curStart = -1
			curLen = 0
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
		return fmt.Sprintf("%d.%d.%d.%d",
			in4.Addr[0], in4.Addr[1], in4.Addr[2], in4.Addr[3]), net_AF_INET, true
	case net_AF_INET6:
		in6 := (*syscall.RawSockaddrInet6)(unsafe.Pointer(sa))
		return net_formatIPv6(in6.Addr[:]), net_AF_INET6, true
	}
	return "", int(sa.Addr.Family), false
}

// ============================================================================
// Generic buffer-size discovery for net_iphlpapi table APIs
// ============================================================================

// net_callTableFn handles the "first call with size=0 to discover the required
// buffer" pattern. Windows returns different codes (122, 111, 206) depending on
// configuration, so we ignore the code and only require that size was filled in.
// Retries up to 3 times because the table can grow between the two calls.
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

// ============================================================================
// TCP/UDP table queries
// ============================================================================

type net_ConnRow struct {
	Proto    string
	Local    string
	Remote   string
	State    uint32
	Pid      uint32
	ProcName string
}

func net_queryTcp4() ([]net_ConnRow, error) {
	buf, err := net_callTableFn(net_pGetExtendedTcpTable, net_AF_INET, net_TCP_TABLE_OWNER_PID_ALL)
	if err != nil || len(buf) < 4 {
		return nil, err
	}
	num := *(*uint32)(unsafe.Pointer(&buf[0]))
	var out []net_ConnRow
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
		out = append(out, net_ConnRow{
			Proto:  "tcp4",
			Local:  local,
			Remote: remote,
			State:  row.State,
			Pid:    row.OwningPid,
		})
	}
	return out, nil
}

func net_queryTcp6() ([]net_ConnRow, error) {
	buf, err := net_callTableFn(net_pGetExtendedTcpTable, net_AF_INET6, net_TCP_TABLE_OWNER_PID_ALL)
	if err != nil || len(buf) < 4 {
		return nil, err
	}
	num := *(*uint32)(unsafe.Pointer(&buf[0]))
	var out []net_ConnRow
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
		out = append(out, net_ConnRow{
			Proto:  "tcp6",
			Local:  local,
			Remote: remote,
			State:  row.dwState,
			Pid:    row.dwOwningPid,
		})
	}
	return out, nil
}

func net_queryUdp4() ([]net_ConnRow, error) {
	buf, err := net_callTableFn(net_pGetExtendedUdpTable, net_AF_INET, net_UDP_TABLE_OWNER_PID)
	if err != nil || len(buf) < 4 {
		return nil, err
	}
	num := *(*uint32)(unsafe.Pointer(&buf[0]))
	var out []net_ConnRow
	rowSize := int(unsafe.Sizeof(net_MIB_UDPROW_OWNER_PID{}))
	for i := uint32(0); i < num; i++ {
		off := 4 + int(i)*rowSize
		if off+rowSize > len(buf) {
			break
		}
		row := (*net_MIB_UDPROW_OWNER_PID)(unsafe.Pointer(&buf[off]))
		local := net_ipv4FromUint32(row.LocalAddr) + ":" + strconv.Itoa(int(net_ntohs(row.LocalPort)))
		out = append(out, net_ConnRow{
			Proto:  "udp4",
			Local:  local,
			Remote: "*:*",
			Pid:    row.OwningPid,
		})
	}
	return out, nil
}

func net_queryUdp6() ([]net_ConnRow, error) {
	buf, err := net_callTableFn(net_pGetExtendedUdpTable, net_AF_INET6, net_UDP_TABLE_OWNER_PID)
	if err != nil || len(buf) < 4 {
		return nil, err
	}
	num := *(*uint32)(unsafe.Pointer(&buf[0]))
	var out []net_ConnRow
	rowSize := int(unsafe.Sizeof(net_MIB_UDP6ROW_OWNER_PID{}))
	for i := uint32(0); i < num; i++ {
		off := 4 + int(i)*rowSize
		if off+rowSize > len(buf) {
			break
		}
		row := (*net_MIB_UDP6ROW_OWNER_PID)(unsafe.Pointer(&buf[off]))
		local := "[" + net_formatIPv6(row.ucLocalAddr[:]) + "]:" + strconv.Itoa(int(net_ntohs(row.dwLocalPort)))
		out = append(out, net_ConnRow{
			Proto:  "udp6",
			Local:  local,
			Remote: "*:*",
			Pid:    row.dwOwningPid,
		})
	}
	return out, nil
}

// ============================================================================
// Adapters
// ============================================================================

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
	return nil, fmt.Errorf("GetAdaptersAddresses: buffer size discovery failed after retries")
}

func net_parseAdapters(buf []byte) ([]net_AdapterInfo, error) {
	if len(buf) == 0 {
		return nil, nil
	}
	var out []net_AdapterInfo
	cur := (*net_IP_ADAPTER_ADDRESSES_LH)(unsafe.Pointer(&buf[0]))
	for cur != nil {
		info := net_AdapterInfo{
			IfIndex:    cur.IfIndex,
			IfType:     cur.IfType,
			OperStatus: cur.OperStatus,
		}
		// BUGFIX: do not assume the string is at least 512 code units long;
		// read up to the first NUL to avoid reading past the adapter buffer.
		info.Description = net_utf16At(cur.Description, 512)
		info.Name = net_utf16At(cur.FriendlyName, 512)
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

// ============================================================================
// Proxy helpers
// ============================================================================

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
			st.Server = net_decodeRegString(v.Data)
			gotAny = true
		}
	}
	if v, err := regQueryValue(k, "ProxyOverride"); err == nil {
		if v.Type == REG_SZ || v.Type == REG_EXPAND_SZ {
			st.Override = net_decodeRegString(v.Data)
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
	} else {
		if err := regSetValue(k, "ProxyServer", REG_SZ, net_encodeRegString(st.Server)); err != nil {
			return err
		}
	}
	if st.Override == "" {
		_ = regDeleteValue(k, "ProxyOverride")
	} else {
		if err := regSetValue(k, "ProxyOverride", REG_SZ, net_encodeRegString(st.Override)); err != nil {
			return err
		}
	}
	return nil
}

// ============================================================================
// hosts helpers
// ============================================================================

// net_hostsPath resolves %SystemRoot%\System32\drivers\etc\hosts.
//
// BUGFIX: the previous version used os.Getenv("SystemRoot") directly, which
// returns "" in some service contexts and produced a relative path. Fall back
// to C:\Windows when the variable is unset.
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
		// else: all names on this line matched; drop the line entirely
	}
	body := strings.Join(out, "\r\n")
	if body != "" && !strings.HasSuffix(body, "\r\n") {
		body += "\r\n"
	}
	return os.WriteFile(net_hostsPath(), []byte(body), 0644)
}

// ============================================================================
// Paths, log
// ============================================================================

const (
	net_backupDirName = "netctl_backup"
	net_logFileName   = "netctl.log"
	net_opsDirName    = "ops"
	net_filesDirName  = "files"
)

func net_backupRoot() string { return filepath.Join(exeDir(), net_backupDirName) }
func net_logPath() string    { return filepath.Join(net_backupRoot(), net_logFileName) }
func net_opsDir() string     { return filepath.Join(net_backupRoot(), net_opsDirName) }
func net_filesDir() string   { return filepath.Join(net_backupRoot(), net_filesDirName) }

func net_countLogLines() int {
	f, err := os.Open(net_logPath())
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

func net_readLogLines() ([]string, error) {
	data, err := os.ReadFile(net_logPath())
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

func net_appendLogLine(cmd string, code int) {
	_ = os.MkdirAll(net_backupRoot(), 0755)
	f, err := os.OpenFile(net_logPath(), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		bugs.Add("ERR", "open log: %v", err)
		return
	}
	defer f.Close()
	ts := time.Now().Format("2006-01-02 15:04:05")
	_, _ = fmt.Fprintf(f, "[%s] [%s] [%d]\n", cmd, ts, code)
}

func net_parseLogLine(line string) (cmd string, ok bool) {
	m := logRe.FindStringSubmatch(line)
	if m == nil {
		return "", false
	}
	return m[1], true
}

// ============================================================================
// Operation records
// ============================================================================

type net_proxySnap struct {
	Enable   bool   `json:"enable"`
	Server   string `json:"server,omitempty"`
	Override string `json:"override,omitempty"`
	Exists   bool   `json:"exists"`
}

type net_opRecord struct {
	Op            string        `json:"op"`
	TS            string        `json:"ts"`
	Cmd           string        `json:"cmd"`
	Code          int           `json:"code"`
	BackupFile    string        `json:"backupFile,omitempty"`
	BackupGzipped bool          `json:"backupGzipped,omitempty"`
	OldProxy      *net_proxySnap `json:"oldProxy,omitempty"`
	NewProxy      *net_proxySnap `json:"newProxy,omitempty"`
	HostsIP       string        `json:"hostsIP,omitempty"`
	HostsNames    []string      `json:"hostsNames,omitempty"`
	HostsRemove   []string      `json:"hostsRemove,omitempty"`
}

func net_saveOpRecord(idx int, rec *net_opRecord) {
	_ = os.MkdirAll(net_opsDir(), 0755)
	p := filepath.Join(net_opsDir(), fmt.Sprintf("%d.json", idx))
	data, err := json.MarshalIndent(rec, "", "  ")
	if err != nil {
		bugs.Add("ERR", "marshal op: %v", err)
		return
	}
	if err := os.WriteFile(p, data, 0644); err != nil {
		bugs.Add("ERR", "write op %s: %v", p, err)
	}
}

func net_loadOpRecord(idx int) (*net_opRecord, error) {
	data, err := os.ReadFile(filepath.Join(net_opsDir(), fmt.Sprintf("%d.json", idx)))
	if err != nil {
		return nil, err
	}
	var rec net_opRecord
	if err := json.Unmarshal(data, &rec); err != nil {
		return nil, err
	}
	return &rec, nil
}

func net_manifestExists(idx int) bool {
	_, err := os.Stat(filepath.Join(net_opsDir(), fmt.Sprintf("%d.json", idx)))
	return err == nil
}

func net_beginWriteOp() int {
	_ = os.MkdirAll(net_backupRoot(), 0755)
	_ = os.MkdirAll(net_opsDir(), 0755)
	_ = os.MkdirAll(net_filesDir(), 0755)
	return net_countLogLines()
}

// ============================================================================
// hosts backup
// ============================================================================

const net_smallHostsThreshold = 8192

func net_backupHosts(logIdx int) (string, bool, error) {
	data, err := os.ReadFile(net_hostsPath())
	if err != nil {
		return "", false, err
	}
	base := fmt.Sprintf("%d_hosts", logIdx)
	if len(data) < net_smallHostsThreshold {
		rel := base + ".hosts"
		full := filepath.Join(net_filesDir(), rel)
		if err := os.MkdirAll(filepath.Dir(full), 0755); err != nil {
			return "", false, err
		}
		if err := os.WriteFile(full, data, 0644); err != nil {
			return "", false, err
		}
		return rel, false, nil
	}
	rel := base + ".hosts.gz"
	full := filepath.Join(net_filesDir(), rel)
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
	src := filepath.Join(net_filesDir(), relPath)
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
// ============================================================================
// Confirmation
// ============================================================================

// (confirm is shared with the rest of the toolkit)

// ============================================================================
// conn command
// ============================================================================

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
	full := syscall.UTF16ToString(buf[:size])
	return filepath.Base(full)
}

func net_cmdConn(args []string) int {
	protoFilter := "all"
	stateFilter := ""
	portFilter := -1
	pidFilter := uint32(0xFFFFFFFF)
	showProcess := false
	jsonOut := false
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "-t", "--type":
			if i+1 >= len(args) {
				fmt.Fprintln(os.Stderr, "conn: -t requires tcp|udp|all")
				return 2
			}
			protoFilter = strings.ToLower(args[i+1])
			// BUGFIX: reject invalid types instead of silently returning empty.
			switch protoFilter {
			case "all", "tcp", "udp", "tcp4", "tcp6", "udp4", "udp6":
			default:
				fmt.Fprintf(os.Stderr, "conn: invalid type %q (use tcp|udp|all)\n", protoFilter)
				return 2
			}
			i++
		case "-s", "--state":
			if i+1 >= len(args) {
				fmt.Fprintln(os.Stderr, "conn: -s requires a state")
				return 2
			}
			stateFilter = strings.ToUpper(args[i+1])
			i++
		case "--port":
			if i+1 >= len(args) {
				fmt.Fprintln(os.Stderr, "conn: --port requires a number")
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
				fmt.Fprintln(os.Stderr, "conn: --pid requires a number")
				return 2
			}
			v, err := strconv.ParseUint(args[i+1], 10, 32)
			if err != nil {
				fmt.Fprintf(os.Stderr, "conn: invalid pid %q\n", args[i+1])
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

	var filtered []net_ConnRow
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
			m := map[string]any{
				"proto":  r.Proto,
				"local":  r.Local,
				"remote": r.Remote,
				"pid":    r.Pid,
			}
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

// ============================================================================
// adapters command
// ============================================================================

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
	jsonOut := false
	upOnly := false
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
		var filtered []net_AdapterInfo
		for _, a := range adapters {
			if a.OperStatus == net_IfOperStatusUp {
				filtered = append(filtered, a)
			}
		}
		adapters = filtered
	}

	if jsonOut {
		out := make([]map[string]any, len(adapters))
		for i, a := range adapters {
			o := map[string]any{
				"ifIndex":     a.IfIndex,
				"name":        a.Name,
				"description": a.Description,
				"mac":         a.Mac,
				"type":        net_adapterTypeName(a.IfType),
				"up":          a.OperStatus == net_IfOperStatusUp,
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
			st = "up"
			stColor = clrGreen
		}
		ipv4 := strings.Join(a.IPv4s, ",")
		dns := strings.Join(a.DNS, ",")
		line := padRight(strconv.FormatUint(uint64(a.IfIndex), 10), idxW) + "  " +
			padRight(a.Name, nameW) + "  " +
			padRight(net_adapterTypeName(a.IfType), typeW) + "  " +
			c(stColor, padRight(st, statusW)) + "  " +
			padRight(a.Mac, 16) + " " +
			padRight(ipv4, 23) + " " +
			c(clrGray, dns)
		fmt.Println(line)
	}
	fmt.Fprintf(os.Stderr, "\n%d adapter(s)\n", len(adapters))
	return 0
}

// ============================================================================
// dns command
// ============================================================================

func net_cmdDns(args []string) int {
	jsonOut := false
	adapterFilter := ""
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--json":
			jsonOut = true
		case "--adapter":
			if i+1 >= len(args) {
				fmt.Fprintln(os.Stderr, "dns: --adapter requires a name")
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
		entries = append(entries, dnsEntry{Name: a.Name, IfIndex: a.IfIndex, DNS: a.DNS})
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

// ============================================================================
// hosts command
// ============================================================================

// net_validIP returns true for a syntactically valid IPv4 or IPv6 address.
// The previous implementation only checked `^[0-9a-fA-F:.]+$`, which accepted
// garbage like "..." or "1.2.3".
func net_validIP(s string) bool {
	if s == "" || len(s) > 45 {
		return false
	}
	// IPv4: four dotted decimal octets in 0..255
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
	// IPv6: at least one ':', only hex digits, ':', and '.' (for v4-mapped)
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
			fmt.Fprintln(os.Stderr, "usage: netctl hosts add <ip> <hostname...> [-f]")
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
			fmt.Fprintln(os.Stderr, "usage: netctl hosts add <ip> <hostname...> [-f]")
			return 2
		}
		ip := pos[0]
		if !net_validIP(ip) {
			fmt.Fprintf(os.Stderr, "hosts add: invalid IP %q\n", ip)
			return 2
		}
		hostnames := pos[1:]
		// BUGFIX: hostnames may contain underscores on Windows (e.g. machine
		// names with '_'); allow them.
		hostRe := regexp.MustCompile(`^[A-Za-z0-9._\-]+$`)
		for _, h := range hostnames {
			if !hostRe.MatchString(h) {
				fmt.Fprintf(os.Stderr, "hosts add: invalid hostname %q\n", h)
				return 2
			}
		}
		if dryRun {
			fmt.Printf("[dry-run] hosts add %s %s\n", ip, strings.Join(hostnames, " "))
			return 0
		}
		if !force {
			if !confirm(fmt.Sprintf("add to hosts: %s -> %s?", strings.Join(hostnames, " "), ip)) {
				return 1
			}
		}
		idx := net_beginWriteOp()
		backupRel, backupGz, err := net_backupHosts(idx)
		if err != nil {
			fmt.Fprintf(os.Stderr, "netctl: backup failed, aborting: %v\n", err)
			return 5
		}
		if err := net_applyHostsAdd(ip, hostnames); err != nil {
			fmt.Fprintf(os.Stderr, "netctl: %v\n", err)
			return 5
		}
		net_saveOpRecord(idx, &net_opRecord{
			Op:            "hosts-add",
			TS:            time.Now().Format("2006-01-02 15:04:05"),
			Cmd:           buildCmdLine(os.Args),
			BackupFile:    backupRel,
			BackupGzipped: backupGz,
			HostsIP:       ip,
			HostsNames:    hostnames,
		})
		fmt.Printf("%s hosts: %s -> %s\n", c(clrGreen, "added"), strings.Join(hostnames, " "), ip)
		return 0

	case "remove", "rm":
		if len(rest) == 0 {
			fmt.Fprintln(os.Stderr, "usage: netctl hosts remove <hostname...> [-f]")
			return 2
		}
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
			fmt.Fprintln(os.Stderr, "usage: netctl hosts remove <hostname...> [-f]")
			return 2
		}
		if dryRun {
			fmt.Printf("[dry-run] hosts remove %s\n", strings.Join(hostnames, " "))
			return 0
		}
		if !force {
			if !confirm(fmt.Sprintf("remove from hosts: %s?", strings.Join(hostnames, " "))) {
				return 1
			}
		}
		idx := net_beginWriteOp()
		backupRel, backupGz, err := net_backupHosts(idx)
		if err != nil {
			fmt.Fprintf(os.Stderr, "netctl: backup failed, aborting: %v\n", err)
			return 5
		}
		if err := net_applyHostsRemove(hostnames); err != nil {
			fmt.Fprintf(os.Stderr, "netctl: %v\n", err)
			return 5
		}
		net_saveOpRecord(idx, &net_opRecord{
			Op:            "hosts-remove",
			TS:            time.Now().Format("2006-01-02 15:04:05"),
			Cmd:           buildCmdLine(os.Args),
			BackupFile:    backupRel,
			BackupGzipped: backupGz,
			HostsRemove:   hostnames,
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
	lines, err := net_readLogLines()
	if err != nil {
		fmt.Fprintf(os.Stderr, "netctl: %v\n", err)
		return 4
	}
	for i := len(lines) - 1; i >= 0; i-- {
		if !net_manifestExists(i) {
			continue
		}
		rec, err := net_loadOpRecord(i)
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

// ============================================================================
// proxy command
// ============================================================================

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
					fmt.Fprintln(os.Stderr, "proxy set: --bypass requires a value")
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
			fmt.Fprintln(os.Stderr, "usage: netctl proxy set <server> [--bypass <list>] [-f]")
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
		idx := net_beginWriteOp()
		newState := net_ProxyState{Enable: true, Server: server, Override: bypass, Exists: true}
		if err := net_writeProxyState(newState); err != nil {
			fmt.Fprintf(os.Stderr, "netctl: set proxy: %v\n", err)
			return 5
		}
		net_saveOpRecord(idx, &net_opRecord{
			Op:       "proxy-set",
			TS:       time.Now().Format("2006-01-02 15:04:05"),
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
		idx := net_beginWriteOp()
		newState := net_ProxyState{Enable: false}
		if err := net_writeProxyState(newState); err != nil {
			fmt.Fprintf(os.Stderr, "netctl: unset proxy: %v\n", err)
			return 5
		}
		net_saveOpRecord(idx, &net_opRecord{
			Op:       "proxy-unset",
			TS:       time.Now().Format("2006-01-02 15:04:05"),
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
	lines, err := net_readLogLines()
	if err != nil {
		fmt.Fprintf(os.Stderr, "netctl: %v\n", err)
		return 4
	}
	for i := len(lines) - 1; i >= 0; i-- {
		if !net_manifestExists(i) {
			continue
		}
		rec, err := net_loadOpRecord(i)
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
		st := net_ProxyState{
			Enable:   rec.OldProxy.Enable,
			Server:   rec.OldProxy.Server,
			Override: rec.OldProxy.Override,
			Exists:   rec.OldProxy.Exists,
		}
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

// ============================================================================
// History
// ============================================================================

func net_cmdHistory() int {
	lines, err := net_readLogLines()
	if err != nil {
		fmt.Fprintf(os.Stderr, "read log %s: %v\n", net_logPath(), err)
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
		if !net_manifestExists(i) {
			continue
		}
		cmd, ok := net_parseLogLine(lines[i])
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
		if rec, err := net_loadOpRecord(e.idx); err == nil {
			desc = net_summarizeOp(rec)
		}
		fmt.Printf("[%d] %s %s\n", k+1, e.line, c(clrGray, desc))
	}
	fmt.Fprintf(os.Stderr, "\n%d rollback-able operation(s). Log: %s\n", len(entries), net_logPath())
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

// ============================================================================
// Rollback
// ============================================================================

func net_cmdRollback(args []string) int {
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

	lines, err := net_readLogLines()
	if err != nil {
		fmt.Fprintf(os.Stderr, "read log: %v\n", err)
		return 4
	}
	var targets []int
	for i := len(lines) - 1; i >= 0 && len(targets) < n; i-- {
		if !net_manifestExists(i) {
			continue
		}
		cmd, ok := net_parseLogLine(lines[i])
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
			rec, err := net_loadOpRecord(idx)
			if err != nil {
				fmt.Printf("[dry-run] step %d: load manifest %d: %v\n", k+1, idx, err)
				continue
			}
			fmt.Printf("[dry-run] step %d: %s %s\n", k+1, rec.Op, net_summarizeOp(rec))
		}
		return 0
	}

	okCount, failCount := 0, 0
	for k, idx := range targets {
		rec, err := net_loadOpRecord(idx)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[rollback] step %d: load manifest %d: %v\n", k+1, idx, err)
			failCount++
			continue
		}
		fmt.Fprintf(os.Stderr, "[rollback] step %d: %s %s\n", k+1, rec.Op, net_summarizeOp(rec))
		if err := net_rollbackOne(rec); err != nil {
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
		st := net_ProxyState{
			Enable:   rec.OldProxy.Enable,
			Server:   rec.OldProxy.Server,
			Override: rec.OldProxy.Override,
			Exists:   rec.OldProxy.Exists,
		}
		return net_writeProxyState(st)
	}
	return fmt.Errorf("unknown op %q", rec.Op)
}

// ============================================================================
// Help
// ============================================================================

func net_printHelp() {
	header := "netctl v1.0.0 (Windows)"
	fmt.Println(c(clrBold+clrCyan, header))
	fmt.Println("Windows network & connection viewer - conn / dns / adapters / hosts / proxy / rollback")
	fmt.Println()
	fmt.Print(`USAGE
  netctl conn [OPTIONS]
  netctl dns [OPTIONS]
  netctl adapters [OPTIONS]
  netctl hosts [show]
  netctl hosts add <ip> <hostname...> [-f]
  netctl hosts remove <hostname...> [-f]
  netctl hosts restore
  netctl proxy [show]
  netctl proxy set <server> [--bypass <list>] [-f]
  netctl proxy unset [-f]
  netctl proxy restore
  netctl --history
  netctl --rollback [-n N]

CONN
  Lists TCP and UDP endpoints (IPv4 and IPv6).
    -t, --type tcp|udp|all     protocol filter (default all)
    -s, --state LISTEN         TCP state filter (LISTEN, ESTABLISHED, TIME_WAIT, ...)
    --port N                   local port filter
    --pid N                    owning PID filter
    --process                  resolve PID to process name
    --json                     JSON output

DNS
  Shows DNS servers per adapter using GetAdaptersAddresses.
    --adapter NAME             only this adapter
    --json                     JSON output

ADAPTERS
  Shows adapters with MAC, addresses, DNS, link state.
    --up                       only adapters in "up" state
    --json                     JSON output

HOSTS
  Displays or edits %SystemRoot%\System32\drivers\etc\hosts.
    hosts show                 print the file with line numbers
    hosts add <ip> <name...>   remove any existing mapping for <name...>
                               and append <ip> <name...>
    hosts remove <name...>     strip <name...> from every line
    hosts restore              manually restore the most recent hosts backup

  Hostnames may contain letters, digits, '.', '_' and '-'.
  Every hosts add/remove prompts for confirmation unless -f is used.
  Writing to hosts requires administrator privileges.

PROXY
  Reads/writes HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings.
    proxy show                 display current ProxyEnable / ProxyServer / ProxyOverride
    proxy set <server>         enable the proxy and set ProxyServer
      --bypass <list>          set ProxyOverride (semicolon-separated)
    proxy unset                disable the proxy (ProxyEnable=0)
    proxy restore              manually restore the most recent proxy backup

  proxy set/unset prompt for confirmation unless -f is used.

GLOBAL
  -o, --out <path>     Redirect stdout to a file. Both "-o path" and
                       "--out=path" forms are accepted.
  --dry-run            Preview only: prints the plan, does not modify the
                       registry or hosts, does not write backups, does not log.
  --no-color           Disable ANSI colors (also honors NO_COLOR env var).
  -b, --bugs           Print collected errors/warnings on exit.
  -h, --help           Show this help.
  --version            Show version.

HISTORY / ROLLBACK
  --history
      Lists rollback-able operations (hosts add/remove, proxy set/unset) in
      reverse chronological order. [1] is the most recent operation.

  --rollback
      Undo the most recent operation (equivalent to -n 1).

  --rollback -n N
      Undo the most recent N operations.

  Inverse mapping:
    hosts add / remove   -> restore the pre-change hosts file
    proxy set            -> restore the previous ProxyEnable / ProxyServer /
                            ProxyOverride values, or delete them if they did
                            not exist before
    proxy unset          -> restore the previous proxy values

BACKUP AND LOG
  Every invocation (except -h/--help/--version/--history/--dry-run) appends
  one line to ./netctl_backup/netctl.log:
    [command line] [timestamp] [exit code]

  hosts snapshots are stored under ./netctl_backup/files/:
    <logIndex>_hosts           when the file is smaller than 8 KiB
    <logIndex>_hosts.gz        when larger (gzip -9)
  Proxy snapshots are stored inline in
    ./netctl_backup/ops/<logIndex>.json
  because they are only a few registry values.

EXIT CODES
  0 success | 1 partial failure | 2 bad args | 3 permission denied
  4 not found | 5 Windows API / I/O error
`)
}

// ============================================================================
// Global flag consumption
// ============================================================================

func net_consumeGlobalFlags(args []string) (rest []string, outPath string, err error) {
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

func net_setupOutput(path string) error {
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
// net_main
// ============================================================================

func net_main() {
	args, outPath, err := net_consumeGlobalFlags(os.Args[1:])
	if err != nil {
		fmt.Fprintf(os.Stderr, "netctl: %v\n", err)
		bugs.Flush()
		os.Exit(2)
	}

	if noColorFlag || os.Getenv("NO_COLOR") != "" {
		useColor = false
	} else if stdoutIsTTY() {
		useColor = true
	}

	if outPath != "" {
		if err := net_setupOutput(outPath); err != nil {
			fmt.Fprintf(os.Stderr, "netctl: %v\n", err)
			bugs.Flush()
			os.Exit(2)
		}
	}

	if has(args, "--version") {
		fmt.Println("netctl v1.0.0")
		net_finalExit(0)
	}
	if len(args) == 0 || has(args, "-h", "--help") {
		net_printHelp()
		net_finalExit(0)
	}

	var code int
	switch {
	case has(args, "--history"):
		code = net_cmdHistory()
	case has(args, "--rollback"):
		code = net_cmdRollback(net_stripFlags(args, "--rollback"))
	default:
		cmdIdx := -1
		for i, a := range args {
			if !strings.HasPrefix(a, "-") {
				cmdIdx = i
				break
			}
		}
		if cmdIdx < 0 {
			fmt.Fprintln(os.Stderr, "netctl: missing command, use -h for help")
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
			fmt.Fprintf(os.Stderr, "netctl: unknown command %q\n", cmd)
			code = 2
		}
	}

	net_finalExit(code)
}

func net_stripFlags(args []string, flags ...string) []string {
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

func net_finalExit(code int) {
	if !dryRun && net_shouldLogRun() {
		net_appendLogLine(buildCmdLine(os.Args), code)
	}
	bugs.Flush()
	if outputCleanup != nil {
		outputCleanup()
		outputCleanup = nil
	}
	os.Exit(code)
}

func net_shouldLogRun() bool {
	for _, a := range os.Args[1:] {
		switch a {
		case "-h", "--help", "--version", "--history", "--dry-run":
			return false
		}
	}
	return true
}
// ==================== open ====================
// openerctl — File type identification and read-only previewer with simple
// decryption attempts. Single-file, standard-library-only build:
//
//   go build -trimpath -ldflags "-s -w" -o openerctl.exe openerctl.go
//
// Log: ./openerctl_backup/openerctl.log  [cmd] [ts] [exit code]

// ============================================================================
// Colors / Console / Bug collector
// ============================================================================

// (shared with the rest of the toolkit)

// ============================================================================
// Magic signatures
// ============================================================================

type open_MagicSig struct {
	Offset   int
	Bytes    []byte
	Ext      string
	Desc     string
	Category string
}

var open_magicSigs = []open_MagicSig{
	// Images
	{0, []byte{0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A}, "PNG", "PNG image", "image"},
	{0, []byte{0xFF, 0xD8, 0xFF}, "JPEG", "JPEG image", "image"},
	{0, []byte{0x47, 0x49, 0x46, 0x38}, "GIF", "GIF image", "image"},
	{0, []byte{0x42, 0x4D}, "BMP", "Windows bitmap", "image"},
	{0, []byte{0x49, 0x49, 0x2A, 0x00}, "TIFF", "TIFF image (LE)", "image"},
	{0, []byte{0x4D, 0x4D, 0x00, 0x2A}, "TIFF", "TIFF image (BE)", "image"},
	{0, []byte{0x00, 0x00, 0x01, 0x00}, "ICO", "Windows icon", "image"},
	{0, []byte{0x52, 0x49, 0x46, 0x46}, "RIFF", "RIFF container", "media"},
	// Archives / compression
	{0, []byte{0x50, 0x4B, 0x03, 0x04}, "ZIP", "ZIP archive", "archive"},
	{0, []byte{0x50, 0x4B, 0x05, 0x06}, "ZIP", "Empty ZIP archive", "archive"},
	{0, []byte{0x52, 0x61, 0x72, 0x21, 0x1A, 0x07}, "RAR", "RAR archive", "archive"},
	{0, []byte{0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C}, "7Z", "7-Zip archive", "archive"},
	{0, []byte{0x1F, 0x8B}, "GZ", "gzip compressed data", "archive"},
	{0, []byte{0x42, 0x5A, 0x68}, "BZ2", "bzip2 compressed data", "archive"},
	{0, []byte{0xFD, 0x37, 0x7A, 0x58, 0x5A, 0x00}, "XZ", "xz compressed data", "archive"},
	{0, []byte{0x28, 0xB5, 0x2F, 0xFD}, "ZST", "zstd compressed data", "archive"},
	{0, []byte{0x04, 0x22, 0x4D, 0x18}, "LZ4", "lz4 compressed data", "archive"},
	// Documents
	{0, []byte{0x25, 0x50, 0x44, 0x46}, "PDF", "PDF document", "document"},
	{0, []byte{0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1}, "OLE", "OLE compound file", "document"},
	// Executables
	{0, []byte{0x4D, 0x5A}, "PE", "DOS / Windows PE executable", "executable"},
	{0, []byte{0x7F, 0x45, 0x4C, 0x46}, "ELF", "ELF executable", "executable"},
	{0, []byte{0xCA, 0xFE, 0xBA, 0xBE}, "CLASS", "Java class / Mach-O fat", "executable"},
	{0, []byte{0xFE, 0xED, 0xFA, 0xCE}, "MACHO", "Mach-O 32-bit", "executable"},
	{0, []byte{0xFE, 0xED, 0xFA, 0xCF}, "MACHO", "Mach-O 64-bit", "executable"},
	// Databases / structured
	{0, []byte("SQLite format 3\x00"), "SQLITE", "SQLite 3 database", "database"},
	// Misc
	{0, []byte{0x53, 0x51, 0x4C, 0x69}, "SQLITE", "SQLite database", "database"},
	{0, []byte{0x7B, 0x5C, 0x72, 0x74, 0x66}, "RTF", "RTF document", "document"},
	{0, []byte{0x30, 0x26, 0xB2, 0x75}, "WMV", "Windows Media Video", "media"},
	{0, []byte{0x00, 0x00, 0x00, 0x18, 0x66, 0x74, 0x79, 0x70}, "MP4", "MP4 video", "media"},
	{0, []byte{0x66, 0x74, 0x79, 0x70, 0x69, 0x73}, "MP4", "MP4 video", "media"},
	{0, []byte{0x66, 0x4C, 0x61, 0x43}, "FLAC", "FLAC audio", "media"},
	{0, []byte{0x4F, 0x67, 0x67, 0x53}, "OGG", "Ogg container", "media"},
	{0, []byte{0x49, 0x44, 0x33}, "MP3", "MP3 with ID3 tag", "media"},
	{0, []byte{0xFF, 0xFB}, "MP3", "MP3 audio", "media"},
}

// ============================================================================
// File type detection
// ============================================================================

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
	// TAR has "ustar" at offset 257 (bytes 257..261 inclusive).
	// BUGFIX: the previous bound `> 265` was too strict; a TAR shorter than
	// 266 bytes would be missed even though the magic is readable at 262.
	if len(data) >= 262 {
		if bytes.Equal(data[257:262], []byte("ustar")) {
			return &open_MagicSig{Ext: "TAR", Desc: "tar archive", Category: "archive"}
		}
	}
	// ISO 9660 has "CD001" at offset 32769 (sector 16 + 1).
	// BUGFIX: same off-by-one; need len >= 32774, not > 32774.
	if len(data) >= 32774 {
		if bytes.Equal(data[32769:32774], []byte("CD001")) {
			return &open_MagicSig{Ext: "ISO", Desc: "ISO 9660 image", Category: "archive"}
		}
	}
	return nil
}

var open_extMap = map[string]open_FileType{
	"txt":    {Ext: "TXT", Description: "Plain text", Category: "text"},
	"log":    {Ext: "LOG", Description: "Log file", Category: "text"},
	"md":     {Ext: "MD", Description: "Markdown", Category: "text"},
	"json":   {Ext: "JSON", Description: "JSON document", Category: "text"},
	"xml":    {Ext: "XML", Description: "XML document", Category: "text"},
	"yaml":   {Ext: "YAML", Description: "YAML document", Category: "text"},
	"yml":    {Ext: "YAML", Description: "YAML document", Category: "text"},
	"ini":    {Ext: "INI", Description: "INI config", Category: "text"},
	"cfg":    {Ext: "CFG", Description: "Config file", Category: "text"},
	"conf":   {Ext: "CONF", Description: "Config file", Category: "text"},
	"csv":    {Ext: "CSV", Description: "CSV data", Category: "text"},
	"html":   {Ext: "HTML", Description: "HTML document", Category: "text"},
	"htm":    {Ext: "HTML", Description: "HTML document", Category: "text"},
	"css":    {Ext: "CSS", Description: "CSS stylesheet", Category: "text"},
	"js":     {Ext: "JS", Description: "JavaScript", Category: "text"},
	"ts":     {Ext: "TS", Description: "TypeScript", Category: "text"},
	"go":     {Ext: "GO", Description: "Go source", Category: "text"},
	"py":     {Ext: "PY", Description: "Python source", Category: "text"},
	"rs":     {Ext: "RS", Description: "Rust source", Category: "text"},
	"c":      {Ext: "C", Description: "C source", Category: "text"},
	"h":      {Ext: "H", Description: "C header", Category: "text"},
	"cpp":    {Ext: "CPP", Description: "C++ source", Category: "text"},
	"hpp":    {Ext: "HPP", Description: "C++ header", Category: "text"},
	"java":   {Ext: "JAVA", Description: "Java source", Category: "text"},
	"bat":    {Ext: "BAT", Description: "Batch script", Category: "text"},
	"cmd":    {Ext: "CMD", Description: "Batch script", Category: "text"},
	"ps1":    {Ext: "PS1", Description: "PowerShell script", Category: "text"},
	"sh":     {Ext: "SH", Description: "Shell script", Category: "text"},
	"txt~":   {Ext: "TXT", Description: "Plain text", Category: "text"},
	"png":    {Ext: "PNG", Description: "PNG image", Category: "image"},
	"jpg":    {Ext: "JPEG", Description: "JPEG image", Category: "image"},
	"jpeg":   {Ext: "JPEG", Description: "JPEG image", Category: "image"},
	"gif":    {Ext: "GIF", Description: "GIF image", Category: "image"},
	"bmp":    {Ext: "BMP", Description: "Windows bitmap", Category: "image"},
	"ico":    {Ext: "ICO", Description: "Windows icon", Category: "image"},
	"zip":    {Ext: "ZIP", Description: "ZIP archive", Category: "archive"},
	"rar":    {Ext: "RAR", Description: "RAR archive", Category: "archive"},
	"7z":     {Ext: "7Z", Description: "7-Zip archive", Category: "archive"},
	"gz":     {Ext: "GZ", Description: "gzip compressed data", Category: "archive"},
	"tar":    {Ext: "TAR", Description: "tar archive", Category: "archive"},
	"bz2":    {Ext: "BZ2", Description: "bzip2 compressed data", Category: "archive"},
	"xz":     {Ext: "XZ", Description: "xz compressed data", Category: "archive"},
	"exe":    {Ext: "PE", Description: "Windows PE executable", Category: "executable"},
	"dll":    {Ext: "PE", Description: "Windows PE dynamic library", Category: "executable"},
	"sys":    {Ext: "PE", Description: "Windows PE driver", Category: "executable"},
	"obj":    {Ext: "PE", Description: "COFF object file", Category: "executable"},
	"lib":    {Ext: "PE", Description: "COFF import library", Category: "executable"},
	"msi":    {Ext: "MSI", Description: "Windows installer package", Category: "executable"},
	"pdf":    {Ext: "PDF", Description: "PDF document", Category: "document"},
	"doc":    {Ext: "OLE", Description: "Word document", Category: "document"},
	"xls":    {Ext: "OLE", Description: "Excel workbook", Category: "document"},
	"ppt":    {Ext: "OLE", Description: "PowerPoint presentation", Category: "document"},
	"mp3":    {Ext: "MP3", Description: "MP3 audio", Category: "media"},
	"mp4":    {Ext: "MP4", Description: "MP4 video", Category: "media"},
	"wav":    {Ext: "WAV", Description: "WAV audio", Category: "media"},
	"avi":    {Ext: "AVI", Description: "AVI video", Category: "media"},
	"flac":   {Ext: "FLAC", Description: "FLAC audio", Category: "media"},
	"ogg":    {Ext: "OGG", Description: "Ogg media", Category: "media"},
	"class":  {Ext: "CLASS", Description: "Java class", Category: "executable"},
	"jar":    {Ext: "ZIP", Description: "Java archive", Category: "archive"},
	"sqlite": {Ext: "SQLITE", Description: "SQLite database", Category: "database"},
	"db":     {Ext: "SQLITE", Description: "Database file", Category: "database"},
}

func open_detectFile(path string, data []byte) *open_FileType {
	ft := &open_FileType{Size: int64(len(data))}
	ext := strings.ToLower(strings.TrimPrefix(filepath.Ext(path), "."))
	if t, ok := open_extMap[ext]; ok {
		ft.Ext = t.Ext
		ft.Description = t.Description
		ft.Category = t.Category
		ft.ByExtension = true
	}
	if sig := open_detectByMagic(data); sig != nil {
		// Magic wins over extension for the Ext/Description fields, but we
		// remember that the extension also matched.
		ft.Ext = sig.Ext
		ft.Description = sig.Desc
		ft.Category = sig.Category
		ft.ByMagic = true
	}
	ft.EntropyValue = open_entropyOf(data)
	if ft.Category == "" {
		if open_looksText(data) {
			ft.Ext = "TXT"
			ft.Description = "Likely plain text (no magic, no known extension)"
			ft.Category = "text"
			ft.Text = true
		} else {
			ft.Ext = "BIN"
			ft.Description = "Unknown binary"
			ft.Category = "binary"
		}
	}
	if ft.Category == "text" {
		ft.Text = true
	}
	if ft.Category == "executable" && ft.Ext == "PE" {
		ft.PE = open_parsePE(data)
		if ft.PE == nil {
			// DOS-only executable (no PE header)
			ft.Description = "DOS MZ executable (no PE header)"
		}
	}
	// High entropy + not a known compressed/encrypted format = suspicious
	if ft.EntropyValue > 7.5 && ft.Category != "archive" && ft.Category != "image" && ft.Category != "media" {
		ft.Encrypted = true
	}
	return ft
}

// ============================================================================
// Entropy / text detection
// ============================================================================

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


// ============================================================================
// PE parsing
// ============================================================================

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

func open_parsePE(data []byte) *open_PEInfo {
	if len(data) < 64 {
		return nil
	}
	if data[0] != 'M' || data[1] != 'Z' {
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

func open_peMachineName(m uint16) string {
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

// ============================================================================
// Image dimensions
// ============================================================================

func open_imageDimensions(data []byte, ext string) (int, int, bool) {
	switch ext {
	case "PNG":
		if len(data) >= 24 {
			w := int(binary.BigEndian.Uint32(data[16:]))
			h := int(binary.BigEndian.Uint32(data[20:]))
			return w, h, true
		}
	case "GIF":
		if len(data) >= 10 {
			w := int(binary.LittleEndian.Uint16(data[6:]))
			h := int(binary.LittleEndian.Uint16(data[8:]))
			return w, h, true
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
		// Scan for SOF0 (C0) through SOF15 (CF, excluding C4, C8, CC)
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

// ============================================================================
// Preview
// ============================================================================

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
	// BUGFIX: use the already-computed total instead of re-splitting the
	// whole buffer just to count newlines.
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

// ============================================================================
// Decryption — shared types & basic helpers
// ============================================================================

var open_weakPasswords = []string{
	"password", "Password", "PASSWORD",
	"password123", "Password123", "Password1", "P@ssw0rd",
	"123456", "1234567", "12345678", "123456789", "0123456789",
	"1234567890", "1234567890123456",
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
	Algorithm string
	Mode      string
	Padding   string
	Key       []byte
	KeyDesc   string
	IV        []byte
	IVDesc    string
}

type open_decryptOpts struct {
	key      []byte
	keyIsHex bool
	keyDesc  string
	iv       []byte
	ivIsHex  bool
	ivDesc   string
	password string
	alg      string
	mode     string
	dictFile string
	noScan   bool
	noDict   bool
	maxTries int
}

// open_deriveKey normalizes input to a key of exactly `size` bytes.
// If input already matches, it is used as-is. Otherwise it is hashed with
// SHA-256 and truncated/extended, which is what most "user password -> key"
// pipelines do in practice.
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

func open_parseHexOrText(s string, isHex bool) []byte {
	if isHex {
		clean := strings.ReplaceAll(s, " ", "")
		clean = strings.ReplaceAll(clean, ":", "")
		if b, err := hex.DecodeString(clean); err == nil {
			return b
		}
	}
	return []byte(s)
}

func open_scanHardcodedKeys(data []byte, limit int) []open_KeyCandidate {
	var keys []open_KeyCandidate
	// BUGFIX: dedupe by the raw key bytes, not the lowercased form. The
	// previous version treated "ABCDEFGHIJKLMNOP" and "abcdefghijklmnop"
	// as the same candidate and dropped one.
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
				keys = append(keys, open_KeyCandidate{
					Bytes: k,
					Desc:  fmt.Sprintf("scan(len=%d):%q", size, k),
				})
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
	c, err := rc4.NewCipher(key)
	if err != nil {
		return nil, err
	}
	plain := make([]byte, len(ct))
	c.XORKeyStream(plain, ct)
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

// open_decodeHexStrict decodes a hex string (spaces, colons, dashes allowed)
// and returns ok=false when the input is not valid hex. The previous helper
// open_parseHexOrText silently fell back to raw bytes on decode failure,
// which meant a typo in --key-hex produced a valid-looking (but wrong) key.
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

// open_looksText reports whether data is likely human-readable text.
//
// BUGFIX: the previous version required an ASCII-printable byte ratio of
// 0.90 before accepting UTF-8, which meant any Chinese (or other non-ASCII
// UTF-8) text was rejected: every byte of a 3-byte UTF-8 codepoint is >= 0x80
// and was therefore counted as "not printable". We now accept any buffer of
// at least 16 bytes that parses as valid UTF-8 and contains no NUL bytes —
// pure binary data essentially never satisfies both conditions.
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
	// Strong signal: valid UTF-8, long enough to be meaningful.
	if len(sample) >= 16 && utf8.Valid(sample) {
		return true
	}
	// Short buffers or invalid UTF-8: fall back to the old heuristic.
	ratio := open_printableRatio(sample)
	if ratio < 0.90 {
		return false
	}
	return utf8.Valid(sample) || ratio > 0.95
}

// open_looksDecrypted reports whether a decryption output looks like real
// plaintext. BUGFIX: routed through the fixed open_looksText so that
// non-ASCII plaintext (e.g. Chinese) is accepted.
func open_looksDecrypted(plain []byte) bool {
	if len(plain) == 0 {
		return false
	}
	// Strong signal: known magic
	if open_detectByMagic(plain) != nil {
		return true
	}
	// Text check (covers ASCII and non-ASCII UTF-8)
	if open_looksText(plain) {
		return true
	}
	// High printable-ASCII ratio without NULs and valid UTF-8 is also
	// suspicious-ok.
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
		scanned := open_scanHardcodedKeys(data, 30)
		for _, kc := range scanned {
			addKey(kc.Bytes, kc.Desc)
		}
	}
	if len(keys) == 0 {
		return nil
	}

	// Determine which algorithm/mode combinations to try.
	type algMode struct {
		alg, mode string
	}
	var combos []algMode
	if opts.alg != "" {
		alg := strings.ToLower(opts.alg)
		switch alg {
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
				// DES-CTR does not exist.
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

	// Build IV candidates
	var ivs []open_IVCandidate
	if opts.iv != nil {
		ivs = append(ivs, open_IVCandidate{Bytes: opts.iv, Desc: opts.ivDesc})
	} else {
		ivs = append(ivs, open_IVCandidate{Bytes: make([]byte, 16), Desc: "zeros(16)"})
		ivs = append(ivs, open_IVCandidate{Bytes: make([]byte, 8), Desc: "zeros(8)"})
		seq := make([]byte, 16)
		for i := range seq {
			seq[i] = byte(i)
		}
		ivs = append(ivs, open_IVCandidate{Bytes: seq, Desc: "seq(0..15)"})
	}

	// BUGFIX: cap attempts as they are produced. Building every combination
	// before truncating wasted time and memory when a big dictionary is used;
	// with a few thousand passwords the slice would grow to tens of thousands
	// of entries before the old code finally dropped the tail.
	maxTries := opts.maxTries
	var attempts []open_DecryptAttempt
	full := func() bool {
		return maxTries > 0 && len(attempts) >= maxTries
	}

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

// ============================================================================
// Argument parsing helpers
// ============================================================================

// (none beyond what open_cmdDecrypt parses inline)

// ============================================================================
// commands
// ============================================================================

func open_cmdInfo(path string) int {
	data, err := os.ReadFile(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "openerctl: %v\n", err)
		return 4
	}
	ft := open_detectFile(path, data)
	open_printFileInfo(path, ft)
	return 0
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
		fmt.Printf("%s %s\n", c(clrRed, "Encrypted:"),
			"likely (high entropy, no known archive/image magic)")
	}
	if ft.PE != nil && ft.PE.Valid {
		open_printPEInfo(ft.PE)
	}
}

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

func open_cmdPreview(path string, lines, maxBytes int, showEntropy bool) int {
	data, err := os.ReadFile(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "openerctl: %v\n", err)
		return 4
	}
	ft := open_detectFile(path, data)
	open_printFileInfo(path, ft)

	if showEntropy {
		// Already printed above.
	}

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
			// open_printPEInfo already done above.
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
		fmt.Printf("%s openerctl decrypt %s\n", c(clrGray, "      try:"), path)
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
				fmt.Fprintln(os.Stderr, "decrypt: -k requires a value")
				return 2
			}
			opts.key = []byte(args[i+1])
			opts.keyDesc = "user:" + args[i+1]
			i += 2
		case "--key-hex":
			if i+1 >= len(args) {
				fmt.Fprintln(os.Stderr, "decrypt: --key-hex requires a value")
				return 2
			}
			b, ok := open_decodeHexStrict(args[i+1])
			if !ok {
				fmt.Fprintf(os.Stderr, "decrypt: invalid hex key %q\n", args[i+1])
				return 2
			}
			opts.key = b
			opts.keyIsHex = true
			opts.keyDesc = "user-hex:" + args[i+1]
			i += 2
		case "-i", "--iv":
			if i+1 >= len(args) {
				fmt.Fprintln(os.Stderr, "decrypt: -i requires a value")
				return 2
			}
			opts.iv = []byte(args[i+1])
			opts.ivDesc = "user-iv"
			i += 2
		case "--iv-hex":
			if i+1 >= len(args) {
				fmt.Fprintln(os.Stderr, "decrypt: --iv-hex requires a value")
				return 2
			}
			b, ok := open_decodeHexStrict(args[i+1])
			if !ok {
				fmt.Fprintf(os.Stderr, "decrypt: invalid hex IV %q\n", args[i+1])
				return 2
			}
			opts.iv = b
			opts.ivIsHex = true
			opts.ivDesc = "user-iv-hex:" + args[i+1]
			i += 2
		case "-p", "--password":
			if i+1 >= len(args) {
				fmt.Fprintln(os.Stderr, "decrypt: -p requires a value")
				return 2
			}
			opts.password = args[i+1]
			i += 2
		case "-a", "--algorithm":
			if i+1 >= len(args) {
				fmt.Fprintln(os.Stderr, "decrypt: -a requires a value")
				return 2
			}
			opts.alg = strings.ToLower(args[i+1])
			i += 2
		case "-m", "--mode":
			if i+1 >= len(args) {
				fmt.Fprintln(os.Stderr, "decrypt: -m requires a value")
				return 2
			}
			opts.mode = strings.ToLower(args[i+1])
			i += 2
		case "-d", "--dict":
			if i+1 >= len(args) {
				fmt.Fprintln(os.Stderr, "decrypt: -d requires a file")
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
				fmt.Fprintln(os.Stderr, "decrypt: --max-tries requires a number")
				return 2
			}
			v, err := strconv.Atoi(args[i+1])
			if err != nil || v <= 0 {
				fmt.Fprintf(os.Stderr, "decrypt: invalid --max-tries %q\n", args[i+1])
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

	// Cross-validate algorithm and mode.
	if opts.alg == "rc4" && opts.mode != "" {
		fmt.Fprintln(os.Stderr, "decrypt: rc4 does not take a mode")
		return 2
	}
	if opts.alg == "des" && opts.mode == "ctr" {
		fmt.Fprintln(os.Stderr, "decrypt: DES does not support ctr mode")
		return 2
	}

	data, err := os.ReadFile(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "openerctl: %v\n", err)
		return 4
	}

	// Cap analysis to 16MB; we still decrypt the full buffer if successful.
	analyze := data
	if len(analyze) > 16*1024*1024 {
		analyze = analyze[:16*1024*1024]
	}

	attempts := open_collectAttempts(analyze, opts)
	if len(attempts) == 0 {
		fmt.Fprintln(os.Stderr, "openerctl: no decryption candidates (check your key / algorithm)")
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
		// Success. Decrypt the full buffer with the same parameters.
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

		// Best-effort new type detection on the plaintext.
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

	fmt.Fprintf(os.Stderr, "openerctl: no decryption candidate produced recognizable plaintext\n")
	fmt.Fprintf(os.Stderr, "  tried %d candidate(s)\n", tried)
	ft := open_detectFile(path, data)
	fmt.Fprintf(os.Stderr, "  file type: %s - %s\n", ft.Ext, ft.Description)
	if ft.EntropyValue > 7.5 {
		fmt.Fprintf(os.Stderr, "  entropy: %.4f (likely encrypted or compressed)\n", ft.EntropyValue)
	}
	return 1
}

// ============================================================================
// Logging (read-only history)
// ============================================================================

const (
	open_backupDirName = "openerctl_backup"
	open_logFileName   = "openerctl.log"
)

func open_backupRoot() string { return filepath.Join(exeDir(), open_backupDirName) }
func open_logPath() string    { return filepath.Join(open_backupRoot(), open_logFileName) }

func open_readLogLines() ([]string, error) {
	data, err := os.ReadFile(open_logPath())
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

func open_appendLogLine(cmd string, code int) {
	_ = os.MkdirAll(open_backupRoot(), 0755)
	f, err := os.OpenFile(open_logPath(), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		bugs.Add("ERR", "open log: %v", err)
		return
	}
	defer f.Close()
	ts := time.Now().Format("2006-01-02 15:04:05")
	_, _ = fmt.Fprintf(f, "[%s] [%s] [%d]\n", cmd, ts, code)
}

func open_cmdHistory() int {
	lines, err := open_readLogLines()
	if err != nil {
		fmt.Fprintf(os.Stderr, "read log %s: %v\n", open_logPath(), err)
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
	fmt.Fprintf(os.Stderr, "\n%d entrie(s). Log: %s\n", len(lines), open_logPath())
	return 0
}

func open_cmdRollback() int {
	fmt.Fprintln(os.Stderr, "openerctl is read-only: there are no operations to roll back")
	fmt.Fprintln(os.Stderr, "  openerctl only reads files and (optionally) attempts decryption")
	fmt.Fprintln(os.Stderr, "  in memory; it never writes to the source file or the registry.")
	fmt.Fprintln(os.Stderr, "  Its history is for audit only; use --history to view it.")
	return 0
}

// ============================================================================
// Help
// ============================================================================

func open_printHelp() {
	header := "openerctl v1.0.0 (Windows)"
	fmt.Println(c(clrBold+clrCyan, header))
	fmt.Println("File type identification and read-only previewer with simple decryption")
	fmt.Println()
	fmt.Print(`USAGE
  openerctl <file>                       identify + preview
  openerctl info <file>                  identify only
  openerctl preview <file> [OPTIONS]     preview (text / binary / PE)
  openerctl decrypt <file> [OPTIONS]     try to decrypt
  openerctl --history
  openerctl --rollback                   (always a no-op: openerctl is read-only)

PREVIEW OPTIONS
  --lines <N>          text preview line count (default 40)
  --bytes <N>          binary preview byte count (default 4096)
  --entropy            print the Shannon entropy of the file

DECRYPT OPTIONS
  -k, --key <value>        user key (literal or hex without 0x)
  --key-hex <hex>          user key given as hex
  -i, --iv <value>         user IV (literal or hex)
  --iv-hex <hex>           user IV given as hex
  -p, --password <pw>      password; SHA-256 is used to derive the key
  -a, --algorithm <alg>    aes | des | rc4 (default: try all)
  -m, --mode <mode>        cbc | ecb | ctr (default: try cbc+ecb for block
                           ciphers; aes also tries ctr when -a aes -m ctr is
                           explicitly given)
  -d, --dict <file>        extra password dictionary (one per line)
  --no-scan                disable hardcoded-key scanning inside the file
  --no-dict                disable the built-in weak password list
  --max-tries <N>          cap the number of candidate combinations (default 2000)

  Decryption is attempted with:
    - user key / password
    - a built-in weak password list (password, 123456, admin, ...)
    - hardcoded key scanning inside the file (ASCII runs of length 16/24/32)
    - built-in IV guesses: all-zero, sequential 0..15
    - PKCS#7 and zero padding
  The first combination whose output looks like text (ASCII OR UTF-8,
  including Chinese), a known file format, or valid UTF-8 wins.
  Because the input is never written to disk, this is a safe read-only
  operation.

GLOBAL
  -o, --out <path>     Redirect stdout to a file
  --dry-run            Print the plan (attempts) without touching the file.
                       Useful with decrypt to preview the candidate list.
  --no-color           Disable ANSI colors (also honors NO_COLOR env var)
  -b, --bugs           Print collected errors/warnings on exit
  -h, --help           Show this help
  --version            Show version

HISTORY
  Every invocation (except -h/--help/--version/--history/--rollback/--dry-run)
  appends one line to ./openerctl_backup/openerctl.log:
    [command line] [timestamp] [exit code]

  --history prints it, numbered from newest (1) to oldest.

READ-ONLY BY DESIGN
  openerctl does not modify the source file, the registry, or any other
  state. --rollback therefore has nothing to undo.

EXIT CODES
  0 success | 1 no decryption candidate succeeded | 2 bad args
  3 permission denied | 4 not found | 5 I/O error
`)
}

// ============================================================================
// open_main
// ============================================================================

func open_main() {
	args := os.Args[1:]

	if noColorFlag || os.Getenv("NO_COLOR") != "" {
		useColor = false
	} else if stdoutIsTTY() {
		useColor = true
	}
	_ = noColorFlag

	// Global flags may appear anywhere.
	filtered := make([]string, 0, len(args))
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
			useColor = false
			i++
		case a == "-o" || a == "--out":
			if i+1 >= len(args) {
				fmt.Fprintf(os.Stderr, "openerctl: %s requires a path\n", a)
				os.Exit(2)
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
			filtered = append(filtered, a)
			i++
		}
	}
	args = filtered

	if outPath != "" {
		if err := open_setupOutput(outPath); err != nil {
			fmt.Fprintf(os.Stderr, "openerctl: %v\n", err)
			bugs.Flush()
			os.Exit(2)
		}
	}

	if has(args, "--version") {
		fmt.Println("openerctl v1.0.0")
		open_finalExit(0, false)
	}
	if len(args) == 0 || has(args, "-h", "--help") {
		open_printHelp()
		open_finalExit(0, false)
	}
	if has(args, "--history") {
		open_finalExit(open_cmdHistory(), false)
	}
	if has(args, "--rollback") {
		open_finalExit(open_cmdRollback(), false)
	}

	code := open_dispatch(args)
	open_finalExit(code, true)
}

func open_dispatch(args []string) int {
	cmd := ""
	rest := args
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		// Could be a subcommand or a file path
		switch args[0] {
		case "info", "preview", "decrypt":
			cmd = args[0]
			rest = args[1:]
		}
	}

	if cmd == "" {
		// Default action: identify + preview. The first non-flag token is
		// treated as the file path; extra tokens are passed through.
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
			fmt.Fprintln(os.Stderr, "openerctl: missing file (use -h for help)")
			return 2
		}
		return open_runDefault(path, extra)
	}

	switch cmd {
	case "info":
		if len(rest) == 0 {
			fmt.Fprintln(os.Stderr, "openerctl: info requires a file")
			return 2
		}
		return open_cmdInfo(rest[0])
	case "preview":
		return open_runPreview(rest)
	case "decrypt":
		if len(rest) == 0 {
			fmt.Fprintln(os.Stderr, "openerctl: decrypt requires a file")
			return 2
		}
		return open_cmdDecrypt(rest[0], rest[1:])
	}
	fmt.Fprintf(os.Stderr, "openerctl: unknown command %q\n", cmd)
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
			// BUGFIX: do not silently ignore unknown options; a typo in
			// --lines/--bytes/--entropy used to be swallowed.
			fmt.Fprintf(os.Stderr, "openerctl: unknown option %q\n", extra[i])
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
		fmt.Fprintln(os.Stderr, "openerctl: preview requires a file")
		return 2
	}
	return open_runDefault(path, extra)
}

// ============================================================================
// -o/--out
// ============================================================================

func open_setupOutput(path string) error {
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
// Final exit
// ============================================================================

func open_finalExit(code int, logIt bool) {
	if logIt && !dryRun && open_shouldLogRun() {
		open_appendLogLine(buildCmdLine(os.Args), code)
	}
	bugs.Flush()
	if outputCleanup != nil {
		outputCleanup()
		outputCleanup = nil
	}
	os.Exit(code)
}

func open_shouldLogRun() bool {
	for _, a := range os.Args[1:] {
		switch a {
		case "-h", "--help", "--version", "--history", "--rollback", "--dry-run":
			return false
		}
	}
	return true
}
// ==================== pe ====================
// pectl — PE dependency diagnostic tool (read-only).
// Single-file, standard-library-only build:
//
//   go build -trimpath -ldflags "-s -w" -o pectl.exe pectl.go
//
// Log: ./pectl_backup/pectl.log  [cmd] [ts] [exit code]

// ============================================================================
// Colors / Console / Bug collector
// ============================================================================

// (shared with the rest of the toolkit)

// ============================================================================
// PE parsing
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
	// Forwarders maps exported-name -> target "DLL.Func". Exports that
	// forward to another DLL are not real RVAs; keeping them separate makes
	// the output unambiguous.
	Forwarders map[string]string
}

// pe_machineIs64 reports whether the machine is a known 64-bit target.
func pe_machineIs64(m uint16) bool {
	return m == 0x8664 || m == 0xAA64
}

// pe_machineIsKnown reports whether the machine is one of the CPU types we can
// reliably classify as 32-bit or 64-bit. Unknown machines are never flagged
// as bitness mismatches, to avoid false positives on exotic binaries.
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
		// debug/pe does not expose exported symbols; parse .edata ourselves.
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

// pe_parseExports walks the IMAGE_EXPORT_DIRECTORY and returns
// name -> function RVA plus name -> forwarder target.
//
// When a function's RVA falls inside the export directory itself, the DWORD
// at that RVA is an RVA to a NUL-terminated "DLL.Func" string; such an entry
// is a forwarder, not a real code address. The old implementation returned
// the string RVA as if it were code, which was misleading. We now report
// forwarders separately, with a zero code RVA.
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

		// Forwarder: RVA points back into the export directory, and the
		// DWORD there is an RVA to the "DLL.Func" string.
		if funcRVA >= dirStart && funcRVA < dirEnd {
			fwOff := pe_rvaToFileOffset(f, funcRVA)
			if fwOff >= 0 && fwOff+4 <= len(data) {
				// The DWORD at fwOff is itself an RVA to the string.
				_ = fwOff
			}
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
			// Could not resolve the string; still record it as a forwarder.
			forwarders[name] = "?"
			exports[name] = 0
			continue
		}

		exports[name] = funcRVA
	}
	return exports, forwarders, nil
}

func pe_rvaToFileOffset(f *pe.File, rva uint32) int {
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

// ============================================================================
// Dependency status
// ============================================================================

type pe_DepStatus struct {
	DLL        string `json:"dll"`
	Status     string `json:"status"` // ok | missing | bitmismatch | apiset | unreadable
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
// Output
// ============================================================================

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

func pe_plural(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}

// ============================================================================
// JSON output
// ============================================================================

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

// ============================================================================
// Commands
// ============================================================================

type pe_cmdOpts struct {
	libPaths    []string
	jsonOut     bool
	recursive   bool
	summaryOnly bool
	failMissing bool
	noCheck     bool
}

func pe_cmdInfo(path string, opts *pe_cmdOpts) int {
	info, deps, err := pe_checkExe(path, opts.libPaths)
	if err != nil {
		fmt.Fprintf(os.Stderr, "pectl: %v\n", err)
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
		fmt.Fprintf(os.Stderr, "pectl: %v\n", err)
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
		fmt.Fprintf(os.Stderr, "pectl: %v\n", err)
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
		fmt.Fprintf(os.Stderr, "pectl: %v\n", err)
		return 5
	}
	if opts.jsonOut {
		pe_printJSON(map[string]any{
			"path":       info.Path,
			"exports":    info.Exports,
			"forwarders": info.Forwarders,
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
		fmt.Fprintf(os.Stderr, "pectl: %v\n", err)
		return 5
	}
	if opts.jsonOut {
		pe_printJSON(map[string]any{
			"path":    info.Path,
			"imports": info.Imports,
			"symbols": info.ImportSymbols,
		})
		return 0
	}
	pe_printHeader(info)
	pe_printImports(info)
	return 0
}

func pe_reportExitCode(deps []pe_DepStatus, failMissing bool) int {
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

func pe_scanDir(dir string, opts *pe_cmdOpts) int {
	if !pe_dirExists(dir) {
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

	// BUGFIX: driver files import kernel modules (ntoskrnl.exe, hal.dll) that
	// do not live in the user-mode DLL search paths, so they always show up as
	// "missing". Warn once, up front, so the user is not misled.
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
	totalMissing := 0
	totalMismatch := 0
	totalFiles := 0

	for _, path := range files {
		info, deps, err := pe_checkExe(path, opts.libPaths)
		if err != nil {
			reports = append(reports, pe_ExeReport{
				Path:       path,
				ReadErrMsg: err.Error(),
			})
			continue
		}
		rep := pe_ExeReport{
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
		pe_printJSON(map[string]any{
			"directory":     dir,
			"files":         totalFiles,
			"totalMissing":  totalMissing,
			"totalMismatch": totalMismatch,
			"reports":       reports,
		})
		return pe_scanExitCode(totalMissing, totalMismatch, opts.failMissing)
	}

	nameW := dispWidth("FILE")
	bitsW := dispWidth("BITS")
	for _, r := range reports {
		rel := pe_relPath(dir, r.Path)
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
		rel := pe_relPath(dir, r.Path)
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

// ============================================================================
// Logging
// ============================================================================

const (
	pe_backupDirName = "pectl_backup"
	pe_logFileName   = "pectl.log"
)

func pe_backupRoot() string { return filepath.Join(exeDir(), pe_backupDirName) }
func pe_logPath() string    { return filepath.Join(pe_backupRoot(), pe_logFileName) }

func pe_readLogLines() ([]string, error) {
	data, err := os.ReadFile(pe_logPath())
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

func pe_appendLogLine(cmd string, code int) {
	_ = os.MkdirAll(pe_backupRoot(), 0755)
	f, err := os.OpenFile(pe_logPath(), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		bugs.Add("ERR", "open log: %v", err)
		return
	}
	defer f.Close()
	ts := time.Now().Format("2006-01-02 15:04:05")
	_, _ = fmt.Fprintf(f, "[%s] [%s] [%d]\n", cmd, ts, code)
}

func pe_cmdHistory() int {
	lines, err := pe_readLogLines()
	if err != nil {
		fmt.Fprintf(os.Stderr, "read log %s: %v\n", pe_logPath(), err)
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
	fmt.Fprintf(os.Stderr, "\n%d entrie(s). Log: %s\n", len(lines), pe_logPath())
	return 0
}

func pe_cmdRollback() int {
	fmt.Fprintln(os.Stderr, "pectl is read-only: there are no operations to roll back")
	fmt.Fprintln(os.Stderr, "  pectl only reads PE headers and checks DLL search paths.")
	fmt.Fprintln(os.Stderr, "  Its history is for audit only; use --history to view it.")
	return 0
}

// ============================================================================
// Help
// ============================================================================

func pe_printHelp() {
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

EXPORTS
  Exports that forward to another DLL (the RVA points back into the export
  directory and the string there is "DLL.Func") are shown with the target
  name and RVA 0, prefixed with "[forwarder] ". They are never real code
  addresses and would be misleading if reported as such.

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

func pe_consumeGlobalFlags(args []string) (rest []string, outPath string, err error) {
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

func pe_setupOutput(path string) error {
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

// ============================================================================
// pe_main
// ============================================================================

func pe_main() {
	args, outPath, err := pe_consumeGlobalFlags(os.Args[1:])
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
		pe_finalExit(0, false)
	}
	if len(args) == 0 || has(args, "-h", "--help") {
		pe_printHelp()
		pe_finalExit(0, false)
	}

	// BUGFIX: apply -o/--out BEFORE handling --history / --rollback, so that
	// `pectl --history -o foo.txt` writes to foo.txt (not stdout). This is
	// what every other module does.
	if outPath != "" {
		if err := pe_setupOutput(outPath); err != nil {
			fmt.Fprintf(os.Stderr, "pectl: %v\n", err)
			bugs.Flush()
			os.Exit(2)
		}
	}

	if has(args, "--history") {
		pe_finalExit(pe_cmdHistory(), false)
	}
	if has(args, "--rollback") {
		pe_finalExit(pe_cmdRollback(), false)
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
		fmt.Fprintf(os.Stderr, "pectl: %v\n", err)
		bugs.Flush()
		os.Exit(2)
	}

	if cmd == "" {
		if len(positional) == 0 {
			fmt.Fprintln(os.Stderr, "pectl: missing file or directory (use -h for help)")
			pe_finalExit(2, true)
		}
		cmd = "info"
	}

	switch cmd {
	case "info", "deps", "imports", "exports", "sections":
		if len(positional) == 0 {
			fmt.Fprintf(os.Stderr, "pectl: %s requires a file\n", cmd)
			pe_finalExit(2, true)
		}
		path := positional[0]
		if fi, err := os.Stat(path); err == nil && fi.IsDir() {
			fmt.Fprintf(os.Stderr, "pectl: %s is a directory (use scan-dir)\n", path)
			pe_finalExit(2, true)
		}
		if dryRun {
			fmt.Printf("[dry-run] would parse %q (command=%s)\n", path, cmd)
			pe_finalExit(0, false)
		}
		var code int
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
		pe_finalExit(code, true)
	case "scan-dir":
		if len(positional) == 0 {
			fmt.Fprintln(os.Stderr, "pectl: scan-dir requires a directory")
			pe_finalExit(2, true)
		}
		code := pe_scanDir(positional[0], opts)
		pe_finalExit(code, true)
	}
	fmt.Fprintf(os.Stderr, "pectl: unknown command %q\n", cmd)
	pe_finalExit(2, true)
}

func pe_finalExit(code int, logIt bool) {
	if logIt && !dryRun && pe_shouldLogRun() {
		pe_appendLogLine(buildCmdLine(os.Args), code)
	}
	bugs.Flush()
	if outputCleanup != nil {
		outputCleanup()
		outputCleanup = nil
	}
	os.Exit(code)
}

func pe_shouldLogRun() bool {
	for _, a := range os.Args[1:] {
		switch a {
		case "-h", "--help", "--version", "--history", "--rollback", "--dry-run":
			return false
		}
	}
	return true
}
// ==================== proc ====================
// procctl — Windows process controller with query / monitor / limit / rollback.
// Single-file, standard-library-only build:
//
//   go build -trimpath -ldflags "-s -w" -o procctl.exe procctl.go

// ============================================================================
// DLL handles
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

	proc_pGetGuiResources = proc_user32.NewProc("GetGuiResources")

	proc_pNtSuspendProcess = proc_ntdll.NewProc("NtSuspendProcess")
	proc_pNtResumeProcess  = proc_ntdll.NewProc("NtResumeProcess")

	proc_pOpenProcessToken    = advapi32.NewProc("OpenProcessToken")
	proc_pGetTokenInformation = advapi32.NewProc("GetTokenInformation")
	proc_pLookupAccountSidW   = advapi32.NewProc("LookupAccountSidW")

	proc_pShellExecuteExW = proc_shell32.NewProc("ShellExecuteExW")
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
		fmt.Fprintf(os.Stderr, "procctl: missing required Windows APIs:\n  %s\n", strings.Join(missing, "\n  "))
		os.Exit(5)
	}
	if !proc_apiOK["GetGuiResources"] {
		bugs.Add("WARN", "user32.dll!GetGuiResources unavailable, gdiobj/userobj skipped")
	}
}

// ============================================================================
// Color init + output redirection
// ============================================================================

func proc_initColor(args []string) {
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

// proc_setupOutput redirects stdout when -o/--out is given.
//
// BUGFIX: the previous version only understood "-o path" and "--out path";
// "--out=path" and "-o=path" were silently ignored, so `procctl list
// --out=foo.txt` printed to stdout instead of the file. All four forms are
// now recognized.
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

// ============================================================================
// Structures
// ============================================================================

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

// proc_buildExtendedLimitBuffer serializes a subset of
// JOBOBJECT_EXTENDED_LIMIT_INFORMATION. The layout on amd64 is:
//
//   offset  0  PerProcessUserTimeLimit   (8)
//   offset  8  PerJobUserTimeLimit       (8)
//   offset 16  LimitFlags                (4)  ← offLimitFlags
//   offset 20  (padding)
//   offset 24  MinimumWorkingSetSize     (8)
//   offset 32  MaximumWorkingSetSize     (8)  ← offMaxWS
//   offset 40  ActiveProcessLimit        (4)  ← offActiveProc
//   offset 44  (padding)
//   offset 48  Affinity                  (8)  ← offAffinity
//   offset 56  PriorityClass             (4)
//   offset 60  SchedulingClass           (4)
//   offset 64  IoInfo                    (48)
//   offset 112 ProcessMemoryLimit        (8)
//   offset 120 JobMemoryLimit            (8)  ← offJobMemLim
//   offset 128 PeakProcessMemoryUsed     (8)
//   offset 136 PeakJobMemoryUsed         (8)
//   total    144
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

// ============================================================================
// Job cleanup
// ============================================================================

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
	proc_appendOpLog(buildCmdLine(os.Args), code)
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
	proc_opLogDirName  = "procctl_backup"
	proc_opLogFileName = "procctl.log"
)

func proc_opLogPath() string {
	return filepath.Join(exeDir(), proc_opLogDirName, proc_opLogFileName)
}

func proc_appendOpLog(cmdLine string, code int) {
	path := proc_opLogPath()
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

func proc_readOpLog() ([]string, error) {
	data, err := os.ReadFile(proc_opLogPath())
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

var proc_opLogRe = regexp.MustCompile(`^\[(.*)\] \[(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\] \[(-?\d+)\]$`)

func proc_parseLogCommand(line string) (string, bool) {
	if strings.HasPrefix(line, "【") {
		rest := strings.TrimPrefix(line, "【")
		idx := strings.Index(rest, "】 【")
		if idx < 0 {
			return "", false
		}
		return rest[:idx], true
	}
	m := proc_opLogRe.FindStringSubmatch(line)
	if m == nil {
		return "", false
	}
	return m[1], true
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

// ============================================================================
// Command parsing (subcommand + legacy flag aliases)
// ============================================================================

// proc_commandAliases maps legacy flags to their canonical proc_subcommands.
// Bare -p/-n are special: they return the raw argument list so proc_cmdLimitMixed
// can parse multiple targets.
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

// proc_hasBeforeDoubleDash reports whether any of flags appears before a literal
// "--". This prevents "procctl run -- cmd --help" from being mistaken for a
// help request.
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

// proc_parseCommand resolves both "procctl <subcmd> ..." and the legacy
// "procctl -a ..." style into a canonical command name and the remaining
// argument list. The special limit subcommand keeps the raw arguments so
// proc_cmdLimitMixed can still process multiple -p/-n targets.
//
// BUGFIX: the original implementation scanned legacy flag aliases first, so
// `procctl list -p 1234` was misparsed as "limit" because `-p` appeared in
// the argument list. We now scan explicit subcommands first; only when no
// subcommand is present do we fall back to the flag aliases.
func proc_parseCommand(args []string) (cmd string, rest []string, ok bool) {
	// Pass 1: an explicit subcommand wins over any legacy flag alias.
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
	// Pass 2: legacy flag aliases.
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

// proc_isQueryCommand reports whether the logged command has no side effects.
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

// proc_invertCommand returns the inverse command line for an operation. Only
// suspend/resume are auto-invertible.
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

// proc_runCommandLine launches an external process and waits for it to exit.
//
// Note on quoting: cmdLine must already be correctly escaped (syscall.EscapeArg
// for each token). We pass lpApplicationName = NULL to CreateProcessW, which
// makes it parse cmdLine by the standard Windows quoting rules: a quoted token
// at the start is the application, the rest are arguments. proc_joinCommandLine
// produces exactly that format.
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

// ============================================================================
// History / rollback
// ============================================================================

func proc_cmdHistory() {
	lines, err := proc_readOpLog()
	if err != nil {
		fmt.Fprintf(os.Stderr, "read operation log %s: %v\n", proc_opLogPath(), err)
		proc_exit(4)
	}
	type entry struct {
		cmd string
		raw string
	}
	var entries []entry
	for i := len(lines) - 1; i >= 0; i-- {
		cmd, ok := proc_parseLogCommand(lines[i])
		if !ok {
			continue
		}
		if proc_isQueryCommand(cmd) {
			continue
		}
		entries = append(entries, entry{cmd: cmd, raw: lines[i]})
	}
	if len(entries) == 0 {
		fmt.Fprintln(os.Stderr, "operation log has no rollback-able entries")
		proc_exit(0)
	}
	for i, e := range entries {
		fmt.Printf("[%d] %s\n", i+1, e.raw)
	}
	fmt.Fprintf(os.Stderr, "\n%d rollback-able operation(s). Full log: %s\n", len(entries), proc_opLogPath())
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
		fmt.Fprintln(os.Stderr, "usage: procctl rollback <N>")
		proc_exit(2)
	}
	lines, err := proc_readOpLog()
	if err != nil {
		fmt.Fprintf(os.Stderr, "read operation log %s: %v\n", proc_opLogPath(), err)
		proc_exit(4)
	}
	var cmds []string
	for _, l := range lines {
		cmd, ok := proc_parseLogCommand(l)
		if !ok {
			continue
		}
		if proc_isQueryCommand(cmd) {
			continue
		}
		cmds = append(cmds, cmd)
	}
	if len(cmds) == 0 {
		fmt.Fprintln(os.Stderr, "operation log has no rollback-able entries")
		proc_exit(4)
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
		inv, err := proc_invertCommand(cmd)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[rollback] step %d: cannot invert %q: %v\n", k+1, cmd, err)
			bugs.Add("ERR", "rollback step %d cannot invert %q: %v", k+1, cmd, err)
			failCount++
			continue
		}
		fmt.Fprintf(os.Stderr, "[rollback] step %d: %s\n", k+1, inv)
		code, err := proc_runCommandLine(inv)
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
		proc_exit(0)
	}
	if okCount == 0 {
		proc_exit(2)
	}
	proc_exit(1)
}

// ============================================================================
// Elevation helpers
// ============================================================================

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

	var sei proc_SHELLEXECUTEINFO
	sei.CbSize = uint32(unsafe.Sizeof(sei))
	sei.FMask = proc_SEE_MASK_NOCLOSEPROCESS | proc_SEE_MASK_NOASYNC
	sei.LpVerb = verb
	sei.LpFile = filePtr
	sei.LpParameters = paramsPtr
	sei.NShow = proc_SW_SHOWNORMAL

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

// ============================================================================
// Data model
// ============================================================================

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
	LogicalCPU  int            `json:"logical_cpu"`
	PhysicalCPU int            `json:"physical_cpu"`
	CPUPercent  float64        `json:"cpu_percent"`
	MemTotal    uint64         `json:"mem_total"`
	MemUsed     uint64         `json:"mem_used"`
	MemFree     uint64         `json:"mem_free"`
	Disks       []proc_DiskInfo `json:"disks,omitempty"`
	Uptime      string         `json:"uptime"`
}

type proc_DiskInfo struct {
	Letter  string  `json:"letter"`
	Percent float64 `json:"percent"`
	Free    uint64  `json:"free"`
	Total   uint64  `json:"total"`
}

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

// ============================================================================
// Short option combining
// ============================================================================

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

// ============================================================================
// Utilities
// ============================================================================

func proc_ftU64(ft proc_FILETIME) uint64 { return uint64(ft.HighDateTime)<<32 | uint64(ft.LowDateTime) }

func proc_filetimeToTime(ft proc_FILETIME) time.Time {
	v := int64(proc_ftU64(ft))
	if v <= 0 {
		return time.Time{}
	}
	return time.Unix(0, (v-116444736000000000)*100)
}

// proc_utf16At returns the NUL-terminated UTF-16 string at the start of buf.
// The previous version relied on UTF16ToString to stop at NUL, which it does,
// but explicit truncation here keeps the contract obvious and prevents any
// future regression if the buffer is ever passed on to unsafe code.
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

// ============================================================================
// Process enumeration
// ============================================================================

type proc_procSnapshot struct {
	PID, PPID uint32
	Name      string
	Threads   uint32
}

func proc_listProcesses() ([]proc_procSnapshot, error) {
	h, _, err := proc_pCreateToolhelp32Snapshot.Call(proc_TH32CS_SNAPPROCESS, 0)
	if syscall.Handle(h) == syscall.InvalidHandle {
		bugs.Add("ERR", "CreateToolhelp32Snapshot: %v", err)
		return nil, fmt.Errorf("CreateToolhelp32Snapshot: %w", err)
	}
	defer pCloseHandle.Call(h)
	var pe proc_PROCESSENTRY32
	pe.Size = uint32(unsafe.Sizeof(pe))
	if r, _, err := proc_pProcess32FirstW.Call(h, uintptr(unsafe.Pointer(&pe))); r == 0 {
		bugs.Add("ERR", "Process32First: %v", err)
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
			bugs.Add("ERR", "Process32Next: %v", err)
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
// ============================================================================
// Extended fields
// ============================================================================

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

func proc_needsOpen(fields map[string]bool) bool {
	for k := range fields {
		if k != "pid" && k != "name" && k != "threads" {
			return true
		}
	}
	return false
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
	// TokenUser = 1
	proc_pGetTokenInformation.Call(uintptr(token), 1, 0, 0, uintptr(unsafe.Pointer(&size)))
	if size == 0 {
		return ""
	}
	buf := make([]byte, size)
	if r, _, _ := proc_pGetTokenInformation.Call(uintptr(token), 1,
		uintptr(unsafe.Pointer(&buf[0])), uintptr(size), uintptr(unsafe.Pointer(&size))); r == 0 {
		return ""
	}
	// TOKEN_USER starts with SID_AND_ATTRIBUTES { PSID Sid; DWORD Attributes; }
	// so the first pointer-sized word is the SID pointer.
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

// ============================================================================
// CPU sampling
// ============================================================================

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

// ============================================================================
// Process control
// ============================================================================

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
		if err := proc_killProcess(order[i], false); err != nil {
			bugs.Add("WARN", "killTree pid=%d: %v", order[i], err)
		}
	}
	return nil
}

func proc_isProtected(pid uint32) bool { return pid == 0 || pid == 4 }

// ============================================================================
// Job Object
// ============================================================================

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

// proc_attachAndLimit attaches the target process to a new Job Object and
// applies resource limits.
//
// BUGFIX: the previous implementation opened the target with PROCESS_ALL_ACCESS,
// which fails with ERROR_ACCESS_DENIED for most system processes even when
// running as administrator. AssignProcessToJobObject only requires
// PROCESS_SET_QUOTA (to set limits) and PROCESS_TERMINATE (for
// KILL_ON_JOB_CLOSE). We also request PROCESS_QUERY_LIMITED_INFORMATION so
// that the subsequent SetInformationJobObject error messages can show the
// process name.
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
	// BUGFIX: check the error from UTF16FromString. It only fails on NUL
	// bytes inside the string, which can happen if the caller was given a
	// NUL-terminated string from a shell with an embedded byte.
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

// ============================================================================
// System totals and validation
// ============================================================================

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

// proc_validateLimits checks resource limit values against the host system.
//
// BUGFIX: `(uint64(1) << uint(nCPU)) - 1` is undefined when nCPU >= 64
// (Go's spec: shift count >= width of the left operand). Systems with 64+
// logical CPUs are real (e.g. 128-core EPYC). We now skip the affinity-bit
// check for such systems; any 64-bit mask is valid there.
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
	return fmt.Errorf("resource limit validation failed:\n  - %s\nuse procctl total to view system totals",
		strings.Join(problems, "\n  - "))
}

// ============================================================================
// System information
// ============================================================================

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

func proc_printJSON(v any) {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		bugs.Add("ERR", "json encode: %v", err)
	}
}

// ============================================================================
// TUI config
// ============================================================================

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
// ============================================================================
// TUI
// ============================================================================

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
		bugs.Add("ERR", "tui list: %v", err)
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
			c(clrCyan, pidStr) + " " +
			nameStr + " " +
			c(proc_cpuColor(p.CPU), cpuStr) + " " +
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
				c(clrCyan, d.Letter),
				d.Percent,
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

// ============================================================================
// Utilities
// ============================================================================

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

// ============================================================================
// Fields and filters
// ============================================================================

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

// ============================================================================
// Limit parsing
// ============================================================================

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

func proc_queryAndPrint(pid uint32, asJSON bool, fields map[string]bool) error {
	h, err := proc_openProcess(proc_PROCESS_QUERY_LIMITED, pid)
	if err != nil {
		if errors.Is(err, proc_ERR_INVALID_PARAMETER) {
			return fmt.Errorf("PID %d does not exist or has exited (PID may have been reused; re-check with procctl list)", pid)
		}
		if errors.Is(err, proc_ERR_ACCESS_DENIED) {
			return fmt.Errorf("PID %d permission denied (process may be running with higher privileges)", pid)
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
				info.Name = s.Name
				info.PPID = s.PPID
				info.Threads = s.Threads
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

// ============================================================================
// Flag helpers
// ============================================================================

// proc_getOpt returns the value following one of flags in args.
//
// BUGFIX: the previous version only matched the "-x value" and "--x value"
// forms. All the "--x=value" and "-x=value" forms were silently ignored, so
// options like --config=foo, --interval=500, --fps=30, --sort=cpu,
// --order=asc, --limit=5, --filter=notepad, --fields=pid,name,
// --parallel=4, --watch=2s, and --lib-path=path all silently fell back to
// their defaults. We now support both forms.
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

// ============================================================================
// Query commands
// ============================================================================

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
			c(clrCyan, d.Letter),
			d.Percent,
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

// ============================================================================
// Control commands
// ============================================================================

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
		fmt.Fprintln(os.Stderr, "usage: procctl priority <pid|name> <level>")
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

// ============================================================================
// limit: new single-target entry + legacy -p/-n via proc_cmdLimitMixed
// ============================================================================

func proc_cmdLimit(args []string) {
	if has(args, "-p", "--pid", "-n", "--name") {
		proc_cmdLimitMixed(args)
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

// ============================================================================
// run
// ============================================================================

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
				fmt.Fprintln(os.Stderr, "--cwd expects a directory")
				proc_exit(2)
			}
			opts.workDir = args[i+1]
			i += 2
			continue
		case "--title":
			if i+1 >= len(args) {
				fmt.Fprintln(os.Stderr, "--title expects a string")
				proc_exit(2)
			}
			opts.title = args[i+1]
			i += 2
			continue
		case "--priority":
			if i+1 >= len(args) {
				fmt.Fprintln(os.Stderr, "--priority expects a level: idle|below-normal|normal|above-normal|high|realtime")
				proc_exit(2)
			}
			pc := proc_priorityClass(args[i+1])
			if pc == 0 {
				fmt.Fprintf(os.Stderr, "invalid priority %q (valid: idle|below-normal|normal|above-normal|high|realtime)\n", args[i+1])
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

// ============================================================================
// --watch
// ============================================================================

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

// ============================================================================
// Tree rendering
// ============================================================================

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

// ============================================================================
// Help
// ============================================================================

func proc_printHelp() {
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
  -o, --out <path>     Write output to file (list/total/sum/limit).
                       Both "-o path" and "--out=path" (also "-o=path")
                       are accepted.
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
  --watch[=interval]   Refresh list/sum/total periodically; interval is a
                       Go duration such as 2s or 500ms (default 1s)

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
  --admin              Re-launch procctl with UAC elevation, then run
                       the target with the requested limits. Example:
                         procctl run --admin --mem 1G -- taskmgr.exe
  --cwd <dir>          Working directory for the child process
  --title <text>       Console window title
  --priority <level>   Startup priority
  --no-window          Create the child without a console window
  (any LIMIT OPTION above may also be used)

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

	proc_initColor(args)
	proc_checkRequiredAPIs()

	if proc_hasBeforeDoubleDash(args, "--version") {
		fmt.Println("procctl v1.0.0")
		proc_exit(0)
	}

	cmd, rest, ok := proc_parseCommand(args)
	if !ok {
		if len(args) == 0 || has(args, "-h", "--help") {
			proc_printHelp()
			proc_exit(0)
		}
		fmt.Fprintln(os.Stderr, "unknown command, use -h for help")
		proc_exit(2)
	}

	if cmd == "help" || proc_hasBeforeDoubleDash(rest, "-h", "--help") {
		proc_printHelp()
		proc_exit(0)
	}
	if cmd == "version" {
		fmt.Println("procctl v1.0.0")
		proc_exit(0)
	}

	switch cmd {
	case "list", "total", "sum", "limit":
		if !proc_setupOutput(cmd, rest) {
			proc_exit(2)
		}
	case "monitor":
		if has(rest, "-o", "--out") {
			fmt.Fprintln(os.Stderr, "-o/--out cannot be used with monitor")
			proc_exit(2)
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
	proc_exit(0)
}
// ==================== reg ====================
// regctl — Windows registry manager with rollback.
// Single-file, standard-library-only build:
//
//   go build -trimpath -ldflags "-s -w" -o regctl.exe regctl.go

// ============================================================================
// Colors / Console / Bug collector
// ============================================================================

// (shared with the rest of the toolkit)

// ============================================================================
// reg module state
// ============================================================================

var (
	// reg_wow32Flag, when true, makes every registry operation use the
	// 32-bit view (Wow6432Node). It is set by reg_consumeGlobalFlags when
	// the user passes --wow32.
	reg_wow32Flag = false
)

// reg_wowFlag returns the appropriate KEY_WOW64_* flag for the current view.
func reg_wowFlag() uint32 {
	if reg_wow32Flag {
		return KEY_WOW64_32KEY
	}
	return KEY_WOW64_64KEY
}

// ============================================================================
// Windows registry API bindings
// ============================================================================

// pRegOpenKeyExW, pRegCloseKey, pRegEnumKeyExW, pRegEnumValueW,
// pRegQueryValueExW, pRegSetValueExW, pRegCreateKeyExW, pRegDeleteKeyW,
// pRegDeleteTreeW, pRegDeleteValueW, RegKey, RegValue, regOpenKey,
// regCloseKey, regEnumKeys, regEnumValues, regQueryValue, regSetValue,
// regDeleteTree, regDeleteValue, and the HKCU / HKLM / HKCR / HKU / HKCC
// constants are defined in the shared infrastructure section.

// ============================================================================
// reg_regCreateKey — create or open a key, reporting whether it was created
// ============================================================================

// reg_regCreateKey calls RegCreateKeyExW and reports whether the key was
// newly created (REG_CREATED_NEW_KEY) versus merely opened
// (REG_OPENED_EXISTING_KEY).
func reg_regCreateKey(root uintptr, subKey string, samDesired uint32) (RegKey, bool, error) {
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

// ============================================================================
// Path parsing
// ============================================================================

type reg_RegPath struct {
	Root     uintptr
	RootName string
	SubKey   string
}

// reg_parseRegPath normalizes user input like "HKCU\Software\Test" or
// "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft" into a struct with the
// pre-defined HKEY handle and the subkey path.
//
// Accepted roots (case-insensitive):
//
//	HKCR / HKEY_CLASSES_ROOT
//	HKCU / HKEY_CURRENT_USER
//	HKLM / HKEY_LOCAL_MACHINE
//	HKU  / HKEY_USERS
//	HKCC / HKEY_CURRENT_CONFIG
//
// The returned RootName is always the canonical long form, so that
// FullName() prints consistently regardless of which short name the user
// typed.
func reg_parseRegPath(s string) (*reg_RegPath, error) {
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

	return &reg_RegPath{Root: root, RootName: rootName, SubKey: subKey}, nil
}

func (p *reg_RegPath) FullName() string {
	if p.SubKey == "" {
		return p.RootName
	}
	return p.RootName + `\` + p.SubKey
}

// ============================================================================
// Value formatting
// ============================================================================

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

func reg_parseTypeName(s string) (uint32, error) {
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

func reg_decodeString(data []byte) string {
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

func reg_decodeMultiString(data []byte) []string {
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

func reg_encodeString(s string) []byte {
	u := utf16.Encode([]rune(s + "\x00"))
	out := make([]byte, len(u)*2)
	for i, v := range u {
		out[i*2] = byte(v)
		out[i*2+1] = byte(v >> 8)
	}
	return out
}

func reg_encodeMultiString(items []string) []byte {
	var out []byte
	for _, s := range items {
		u := utf16.Encode([]rune(s))
		for _, v := range u {
			out = append(out, byte(v), byte(v>>8))
		}
		out = append(out, 0, 0)
	}
	// Always end with a NUL terminator. A single NUL is the empty-string
	// terminator, which is what an empty REG_MULTI_SZ is supposed to be.
	if len(out) == 0 {
		out = append(out, 0, 0)
	}
	return out
}

// reg_formatValueDisplay produces a human-readable string for terminal output.
func reg_formatValueDisplay(v RegValue) string {
	switch v.Type {
	case REG_SZ, REG_EXPAND_SZ, REG_LINK:
		return reg_decodeString(v.Data)
	case REG_MULTI_SZ:
		return strings.Join(reg_decodeMultiString(v.Data), " | ")
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
		return fmt.Sprintf("hex:%s", reg_hexJoin(v.Data))
	}
	return fmt.Sprintf("hex:%s", reg_hexJoin(v.Data))
}

func reg_hexJoin(b []byte) string {
	parts := make([]string, len(b))
	for i, x := range b {
		parts[i] = fmt.Sprintf("%02x", x)
	}
	return strings.Join(parts, ",")
}

// ============================================================================
// Value parsing (for `set` and .reg import)
// ============================================================================

func reg_parseValueData(typeStr, dataStr string) (uint32, []byte, error) {
	typ, err := reg_parseTypeName(typeStr)
	if err != nil {
		return 0, nil, err
	}
	switch typ {
	case REG_SZ, REG_EXPAND_SZ:
		return typ, reg_encodeString(dataStr), nil
	case REG_MULTI_SZ:
		items := strings.Split(dataStr, "|")
		return typ, reg_encodeMultiString(items), nil
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
		b, err := reg_hexDecode(clean)
		if err != nil {
			return 0, nil, fmt.Errorf("invalid binary %q", dataStr)
		}
		return typ, b, nil
	}
	return typ, reg_encodeString(dataStr), nil
}

func reg_hexDecode(s string) ([]byte, error) {
	out := make([]byte, len(s)/2)
	for i := 0; i < len(out); i++ {
		hi := reg_hexVal(s[i*2])
		lo := reg_hexVal(s[i*2+1])
		if hi < 0 || lo < 0 {
			return nil, fmt.Errorf("bad hex")
		}
		out[i] = byte(hi<<4 | lo)
	}
	return out, nil
}

func reg_hexVal(c byte) int {
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

var reg_escapeStringReplacer = strings.NewReplacer(`\`, `\\`, `"`, `\"`)

// reg_exportKeyToReg writes the key's values and recursively its subkeys to
// buf in the standard Windows .reg text format. Errors from a single subkey
// are logged but do not abort the whole export (Windows often has
// unreadable subkeys even for admin).
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
			// Skip subkeys we cannot open. Record it so -b/--bugs can
			// report the exact key.
			bugs.Add("WARN", "export: skip %s\\%s: %v", fullPath, sub, err)
			continue
		}
		if err := reg_exportKeyToReg(buf, child, fullPath+`\`+sub); err != nil {
			bugs.Add("WARN", "export: subkey %s\\%s: %v", fullPath, sub, err)
		}
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
		buf.WriteString(`"` + reg_escapeStringReplacer.Replace(reg_decodeString(v.Data)) + `"` + "\r\n")
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

// reg_exportRegString builds the full .reg text for a registry key and its subkeys.
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

// ============================================================================
// .reg import (parser)
// ============================================================================

func reg_utf16LEToUTF8(b []byte) string {
	if len(b)%2 != 0 {
		b = b[:len(b)-1]
	}
	u := make([]uint16, len(b)/2)
	for i := 0; i < len(u); i++ {
		u[i] = uint16(b[i*2]) | uint16(b[i*2+1])<<8
	}
	return string(utf16.Decode(u))
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

// reg_lineContinues reports whether the given line ends with a continuation
// marker. Windows .reg files use a trailing backslash for both:
//
//   - hex value continuation:
//       "V"=hex:00,01,\
//           02,03
//
//   - string value continuation (inside quotes):
//       "V"="abc \
//           def"
//
// For a hex value, any trailing backslash means "continue". For a string
// value, only an ODD number of trailing backslashes means "continue",
// because pairs of backslashes are escape sequences representing a single
// literal backslash.
//
// BUGFIX: the previous implementation used
// reg_isValueContinuationTerminator(), which rejected string continuation
// entirely (it only handled lines containing "=hex"). That meant a legal
// .reg file with a multi-line string value would be rejected with
// "unsupported value syntax" during import.
func reg_lineContinues(line string) bool {
	trimmed := strings.TrimRight(line, " \t")
	if !strings.HasSuffix(trimmed, `\`) {
		return false
	}
	if strings.Contains(trimmed, "=hex") {
		return true
	}
	// Count trailing backslashes; only an odd count means "continue".
	n := 0
	for i := len(trimmed) - 1; i >= 0 && trimmed[i] == '\\'; i-- {
		n++
	}
	return n%2 == 1
}

// reg_importRegContent parses .reg text and writes every key/value it describes.
// It creates keys as needed and overwrites existing values.
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
		return regSetValue(key, name, REG_SZ, reg_encodeString(s))
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
		b, err := reg_hexDecode(strings.ReplaceAll(data[7:], ",", ""))
		if err != nil {
			return err
		}
		return regSetValue(key, name, REG_QWORD, b)
	}
	if strings.HasPrefix(data, "hex(2):") {
		b, err := reg_hexDecode(strings.ReplaceAll(data[7:], ",", ""))
		if err != nil {
			return err
		}
		return regSetValue(key, name, REG_EXPAND_SZ, b)
	}
	if strings.HasPrefix(data, "hex(7):") {
		b, err := reg_hexDecode(strings.ReplaceAll(data[7:], ",", ""))
		if err != nil {
			return err
		}
		return regSetValue(key, name, REG_MULTI_SZ, b)
	}
	if strings.HasPrefix(data, "hex:") {
		b, err := reg_hexDecode(strings.ReplaceAll(data[4:], ",", ""))
		if err != nil {
			return err
		}
		return regSetValue(key, name, REG_BINARY, b)
	}
	return fmt.Errorf("unsupported value syntax %q", data)
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

// ============================================================================
// JSON export
// ============================================================================

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
	// When fullPath has no backslash (e.g. just "HKEY_CURRENT_USER"),
	// LastIndex returns -1, and -1+1 = 0, so the Name becomes the full
	// path. That is the desired output for a root-only JSON export.
	name := fullPath
	if i := strings.LastIndex(fullPath, `\`); i >= 0 {
		name = fullPath[i+1:]
	}
	obj := &reg_jsonKey{
		Name: name,
		Path: fullPath,
	}
	values, _ := regEnumValues(k)
	for _, v := range values {
		obj.Values = append(obj.Values, reg_jsonValue{
			Name: v.Name,
			Type: reg_typeName(v.Type),
			Data: reg_formatValueDisplay(v),
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
	reg_backupDirName = "regctl_backup"
	reg_logFileName   = "regctl.log"
	reg_opsDirName    = "ops"
	reg_filesDirName  = "files"
)

func reg_backupRoot() string { return filepath.Join(exeDir(), reg_backupDirName) }
func reg_logPath() string    { return filepath.Join(reg_backupRoot(), reg_logFileName) }
func reg_opsDir() string     { return filepath.Join(reg_backupRoot(), reg_opsDirName) }
func reg_filesDir() string   { return filepath.Join(reg_backupRoot(), reg_filesDirName) }

func reg_countLogLines() int {
	f, err := os.Open(reg_logPath())
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

func reg_readLogLines() ([]string, error) {
	data, err := os.ReadFile(reg_logPath())
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

func reg_appendLogLine(cmd string, code int) {
	_ = os.MkdirAll(reg_backupRoot(), 0755)
	f, err := os.OpenFile(reg_logPath(), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		bugs.Add("ERR", "open log: %v", err)
		return
	}
	defer f.Close()
	ts := time.Now().Format("2006-01-02 15:04:05")
	_, _ = fmt.Fprintf(f, "[%s] [%s] [%d]\n", cmd, ts, code)
}

func reg_parseLogLine(line string) (cmd string, ok bool) {
	m := logRe.FindStringSubmatch(line)
	if m == nil {
		return "", false
	}
	return m[1], true
}

// ============================================================================
// Operation records
// ============================================================================

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

func reg_saveOpRecord(idx int, rec *reg_opRecord) {
	_ = os.MkdirAll(reg_opsDir(), 0755)
	p := filepath.Join(reg_opsDir(), fmt.Sprintf("%d.json", idx))
	data, err := json.MarshalIndent(rec, "", "  ")
	if err != nil {
		bugs.Add("ERR", "marshal op: %v", err)
		return
	}
	if err := os.WriteFile(p, data, 0644); err != nil {
		bugs.Add("ERR", "write op %s: %v", p, err)
	}
}

func reg_loadOpRecord(idx int) (*reg_opRecord, error) {
	data, err := os.ReadFile(filepath.Join(reg_opsDir(), fmt.Sprintf("%d.json", idx)))
	if err != nil {
		return nil, err
	}
	var rec reg_opRecord
	if err := json.Unmarshal(data, &rec); err != nil {
		return nil, err
	}
	return &rec, nil
}

func reg_manifestExists(idx int) bool {
	_, err := os.Stat(filepath.Join(reg_opsDir(), fmt.Sprintf("%d.json", idx)))
	return err == nil
}

func reg_beginWriteOp() int {
	_ = os.MkdirAll(reg_backupRoot(), 0755)
	_ = os.MkdirAll(reg_opsDir(), 0755)
	_ = os.MkdirAll(reg_filesDir(), 0755)
	return reg_countLogLines()
}

// ============================================================================
// Backup helpers
// ============================================================================

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

// reg_toUTF16LEBOM converts a Go string to a UTF-16LE byte slice prefixed
// with the BOM. Windows regedit.exe and reg.exe both accept this format,
// and it is the format that reg_restoreFromBackup expects.
func reg_toUTF16LEBOM(s string) []byte {
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

// reg_backupKeyToReg exports the target key (and subkeys) into
// ./files/<idx>_<name>.reg (or .reg.gz when the result exceeds 8 KiB).
// It returns the relative path under reg_filesDir and whether the file is
// gzipped.
func reg_backupKeyToReg(p *reg_RegPath, logIdx int) (string, bool, error) {
	text, err := reg_exportRegString(p)
	if err != nil {
		return "", false, err
	}
	raw := reg_toUTF16LEBOM(text)
	base := fmt.Sprintf("%d_%s", logIdx, reg_sanitizeForFilename(p.FullName()))
	if len(raw) < reg_smallRegThreshold {
		rel := base + ".reg"
		full := filepath.Join(reg_filesDir(), rel)
		if err := os.MkdirAll(filepath.Dir(full), 0755); err != nil {
			return "", false, err
		}
		if err := os.WriteFile(full, raw, 0644); err != nil {
			return "", false, err
		}
		return rel, false, nil
	}
	rel := base + ".reg.gz"
	full := filepath.Join(reg_filesDir(), rel)
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

func reg_restoreFromBackup(relPath string, gzipped bool) error {
	full := filepath.Join(reg_filesDir(), relPath)
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

// ============================================================================
// Displays
// ============================================================================

func reg_printValueLine(indent, name string, v RegValue) {
	displayName := name
	if displayName == "" {
		displayName = "(default)"
	}
	fmt.Printf("%s%s %s = %s\n",
		indent,
		c(clrCyan, padRight(displayName, 24)),
		c(clrGray, reg_typeName(v.Type)),
		reg_formatValueDisplay(v))
}
// ============================================================================
// Global flag consumption
// ============================================================================

func reg_consumeGlobalFlags(args []string) (rest []string, outPath string, err error) {
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
			reg_wow32Flag = true
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

func reg_setupOutput(path string) error {
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
// History / rollback
// ============================================================================

func reg_cmdHistory() int {
	lines, err := reg_readLogLines()
	if err != nil {
		fmt.Fprintf(os.Stderr, "read log %s: %v\n", reg_logPath(), err)
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
		if !reg_manifestExists(i) {
			continue
		}
		cmd, ok := reg_parseLogLine(lines[i])
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
		fmt.Printf("[%d] %s\n", k+1, e.line)
	}
	fmt.Fprintf(os.Stderr, "\n%d rollback-able operation(s). Log: %s\n", len(entries), reg_logPath())
	return 0
}

func reg_cmdRollback(args []string) int {
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

	lines, err := reg_readLogLines()
	if err != nil {
		fmt.Fprintf(os.Stderr, "read log: %v\n", err)
		return 4
	}
	var targets []int
	for i := len(lines) - 1; i >= 0 && len(targets) < n; i-- {
		if !reg_manifestExists(i) {
			continue
		}
		cmd, ok := reg_parseLogLine(lines[i])
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
			rec, err := reg_loadOpRecord(idx)
			if err != nil {
				fmt.Printf("[dry-run] step %d: load manifest %d: %v\n", k+1, idx, err)
				continue
			}
			fmt.Printf("[dry-run] step %d: %s on %s\n", k+1, rec.Op, rec.Path)
		}
		return 0
	}

	okCount, failCount := 0, 0
	for k, idx := range targets {
		rec, err := reg_loadOpRecord(idx)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[rollback] step %d: load manifest %d: %v\n", k+1, idx, err)
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
		// 原来是新增的：删除回滚
		k, err := regOpenKey(p.Root, p.SubKey, KEY_WRITE|reg_wowFlag())
		if err != nil {
			return nil
		}
		defer regCloseKey(k)
		_ = regDeleteValue(k, rec.ValueName)
		return nil
	}

	// 原来有值：恢复旧值
	k, _, err := reg_regCreateKey(p.Root, p.SubKey, KEY_WRITE|reg_wowFlag())
	if err != nil {
		return err
	}
	defer regCloseKey(k)
	return regSetValue(k, rec.ValueName, rec.OldValueType, rec.OldValueData)
}

// ============================================================================
// reg_main
// ============================================================================

func reg_main() {
	args, outPath, err := reg_consumeGlobalFlags(os.Args[1:])
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

	if has(args, "--version") {
		fmt.Println("regctl v1.0.0")
		reg_finalExit(0, false)
	}
	if len(args) == 0 || has(args, "-h", "--help") {
		fmt.Println(c(clrBold+clrCyan, "regctl v1.0.0 (Windows)"))
		fmt.Println("Registry manager — infrastructure only build")
		fmt.Println()
		fmt.Println("NOTE: subcommands (ls/cat/get/set/del/mkkey/export/find/browse)")
		fmt.Println("      are not compiled into this build. Only the backup,")
		fmt.Println("      .reg/JSON export, and .reg import paths are present.")
		reg_finalExit(0, false)
	}

	if outPath != "" {
		if err := reg_setupOutput(outPath); err != nil {
			fmt.Fprintf(os.Stderr, "regctl: %v\n", err)
			bugs.Flush()
			os.Exit(2)
		}
	}

	var code int
	switch {
	case has(args, "--history"):
		code = reg_cmdHistory()
	case has(args, "--rollback"):
		code = reg_cmdRollback(reg_stripFlags(args, "--rollback"))
	default:
		fmt.Fprintf(os.Stderr, "regctl: subcommand %q is not implemented in this build\n", args[0])
		code = 2
	}
	reg_finalExit(code, true)
}

func reg_stripFlags(args []string, flags ...string) []string {
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

func reg_finalExit(code int, logIt bool) {
	if logIt && !dryRun && reg_shouldLogRun() {
		reg_appendLogLine(buildCmdLine(os.Args), code)
	}
	bugs.Flush()
	if outputCleanup != nil {
		outputCleanup()
		outputCleanup = nil
	}
	os.Exit(code)
}

func reg_shouldLogRun() bool {
	for _, a := range os.Args[1:] {
		switch a {
		case "-h", "--help", "--version", "--history", "--rollback", "--dry-run":
			return false
		}
	}
	return true
}
// ==================== svc ====================
// svcctl — Windows service manager with rollback.
// Single-file, standard-library-only build:
//
//   go build -trimpath -ldflags "-s -w" -o svcctl.exe svcctl.go

// ============================================================================
// Colors / Console / Bug collector
// ============================================================================

// (shared with the rest of the toolkit)

// ============================================================================
// Windows SCM API bindings
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

	// BUGFIX: sentinel value used when QueryServiceConfig fails (e.g. the
	// service is stopped, or the caller lacks read permission). Without
	// this, the zero value 0 was indistinguishable from SERVICE_BOOT_START
	// and every unreadable service showed up as "boot".
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

// svc_ENUM_SERVICE_STATUS_PROCESSW mirrors ENUM_SERVICE_STATUS_PROCESSW.
//
// On amd64: 2 pointers (16 bytes) + SERVICE_STATUS_PROCESS (9 * uint32 = 36
// bytes) = 52 bytes, padded to 56 for the struct's 8-byte alignment. This is
// exactly what Windows returns in the EnumServicesStatusExW buffer.
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

func svc_closeHandle(h syscall.Handle) {
	svc_pCloseServiceHandle.Call(uintptr(h))
}

func svc_queryServiceStatus(h syscall.Handle) (*svc_SERVICE_STATUS, error) {
	var st svc_SERVICE_STATUS
	r, _, err := svc_pQueryServiceStatus.Call(uintptr(h), uintptr(unsafe.Pointer(&st)))
	if r == 0 {
		return nil, err
	}
	return &st, nil
}

// svc_queryServiceConfig returns the service configuration.
//
// The returned cfg's pointer fields point into the local buf allocated by
// this function. Go's escape analysis promotes buf to the heap because cfg
// holds pointers into it, so the caller can safely use cfg for as long as
// it keeps the reference alive. The caller does NOT need to free anything.
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
	cfg := (*svc_QUERY_SERVICE_CONFIGW)(unsafe.Pointer(&buf[0]))
	return cfg, nil
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

// ============================================================================
// Service enumeration
// ============================================================================

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
			Name:      syscall.UTF16ToString(unsafe.Slice(ep.ServiceName, 256)),
			DisplayName: syscall.UTF16ToString(unsafe.Slice(ep.DisplayName, 256)),
			State:     ep.ServiceStatusProcess.CurrentState,
			// BUGFIX: sentinel so svc_startTypeName can show "?" for
			// services whose config we failed to read below.
			StartType: svc_SERVICE_START_TYPE_UNKNOWN,
		})
	}

	for i := range out {
		h, err := svc_openService(scm, out[i].Name, svc_SERVICE_QUERY_CONFIG|svc_SERVICE_QUERY_STATUS)
		if err != nil {
			// Keep StartType as UNKNOWN so the user sees "?" not "boot".
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

// svc_splitDeps decodes the double-NUL-terminated REG_MULTI_SZ-style
// dependency list returned by QueryServiceConfig.
//
// BUGFIX: bound the iteration count so a malformed / truncated dependency
// buffer cannot run off the end of memory.
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

// ============================================================================
// Human-readable names
// ============================================================================

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

// ============================================================================
// Paths, log
// ============================================================================

const (
	svc_backupDirName = "svcctl_backup"
	svc_logFileName   = "svcctl.log"
	svc_opsDirName    = "ops"
)

func svc_backupRoot() string { return filepath.Join(exeDir(), svc_backupDirName) }
func svc_logPath() string    { return filepath.Join(svc_backupRoot(), svc_logFileName) }
func svc_opsDir() string     { return filepath.Join(svc_backupRoot(), svc_opsDirName) }

func svc_countLogLines() int {
	f, err := os.Open(svc_logPath())
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

func svc_readLogLines() ([]string, error) {
	data, err := os.ReadFile(svc_logPath())
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

func svc_appendLogLine(cmd string, code int) {
	_ = os.MkdirAll(svc_backupRoot(), 0755)
	f, err := os.OpenFile(svc_logPath(), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		bugs.Add("ERR", "open log: %v", err)
		return
	}
	defer f.Close()
	ts := time.Now().Format("2006-01-02 15:04:05")
	_, _ = fmt.Fprintf(f, "[%s] [%s] [%d]\n", cmd, ts, code)
}

func svc_parseLogLine(line string) (cmd string, ok bool) {
	m := logRe.FindStringSubmatch(line)
	if m == nil {
		return "", false
	}
	return m[1], true
}

// ============================================================================
// State manifests
// ============================================================================

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

func svc_mustJSON(v any) []byte {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return []byte("null")
	}
	return b
}

func svc_saveOpRecord(idx int, rec *svc_opRecord) {
	_ = os.MkdirAll(svc_opsDir(), 0755)
	p := filepath.Join(svc_opsDir(), fmt.Sprintf("%d.json", idx))
	if err := os.WriteFile(p, svc_mustJSON(rec), 0644); err != nil {
		bugs.Add("ERR", "write op %s: %v", p, err)
	}
}

func svc_loadOpRecord(idx int) (*svc_opRecord, error) {
	data, err := os.ReadFile(filepath.Join(svc_opsDir(), fmt.Sprintf("%d.json", idx)))
	if err != nil {
		return nil, err
	}
	var rec svc_opRecord
	if err := json.Unmarshal(data, &rec); err != nil {
		return nil, err
	}
	return &rec, nil
}

func svc_manifestExists(idx int) bool {
	_, err := os.Stat(filepath.Join(svc_opsDir(), fmt.Sprintf("%d.json", idx)))
	return err == nil
}

func svc_beginWriteOp() int {
	_ = os.MkdirAll(svc_backupRoot(), 0755)
	_ = os.MkdirAll(svc_opsDir(), 0755)
	return svc_countLogLines()
}

// ============================================================================
// Resolve / snapshot
// ============================================================================

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
	return svc_svcSnapshot{
		Name:      name,
		StartType: cfg.StartType,
		State:     st.CurrentState,
	}, nil
}

// ============================================================================
// ls
// ============================================================================

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
		fmt.Fprintf(os.Stderr, "svcctl: %v\n", err)
		return 5
	}
	defer svc_closeHandle(scm)

	svcs, err := svc_enumServices(scm)
	if err != nil {
		fmt.Fprintf(os.Stderr, "svcctl: %v\n", err)
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
				"name":        s.Name,
				"displayName": s.DisplayName,
				"state":       svc_stateName(s.State),
				"startType":   svc_startTypeName(s.StartType),
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
		padRight("START", startW) + " " +
		"BINARY"
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
// ============================================================================
// start / stop / pause / resume
// ============================================================================

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
		fmt.Fprintf(os.Stderr, "usage: svcctl %s [-f] <service|displayname>...\n", action)
		return 2
	}

	scm, err := svc_openSCM()
	if err != nil {
		fmt.Fprintf(os.Stderr, "svcctl: %v\n", err)
		return 5
	}
	defer svc_closeHandle(scm)

	names := make([]string, 0, len(targets))
	snaps := make([]svc_svcSnapshot, 0, len(targets))
	for _, t := range targets {
		name, err := svc_resolveService(scm, t)
		if err != nil {
			fmt.Fprintf(os.Stderr, "svcctl: %v\n", err)
			return 4
		}
		snap, err := svc_snapshotService(scm, name)
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

	idx := svc_beginWriteOp()
	rec := &svc_opRecord{
		Op:     action,
		TS:     time.Now().Format("2006-01-02 15:04:05"),
		Cmd:    buildCmdLine(os.Args),
		Before: snaps,
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
				// already stopped: idempotent success
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

	// BUGFIX: After must reflect the new state, not the old one. The previous
	// implementation assigned rec.After = snaps (which is identical to
	// rec.Before), so the recorded "After" was always stale.
	var after []svc_svcSnapshot
	for _, n := range names {
		if snap, err := svc_snapshotService(scm, n); err == nil {
			after = append(after, snap)
		}
	}
	rec.After = after
	svc_saveOpRecord(idx, rec)

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
		fmt.Fprintln(os.Stderr, "usage: svcctl start-type [-f] <service>... <auto|manual|disabled>")
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
		fmt.Fprintf(os.Stderr, "svcctl: %v\n", err)
		return 5
	}
	defer svc_closeHandle(scm)

	names := make([]string, 0, len(targets))
	snaps := make([]svc_svcSnapshot, 0, len(targets))
	for _, t := range targets {
		name, err := svc_resolveService(scm, t)
		if err != nil {
			fmt.Fprintf(os.Stderr, "svcctl: %v\n", err)
			return 4
		}
		snap, err := svc_snapshotService(scm, name)
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

	idx := svc_beginWriteOp()
	rec := &svc_opRecord{
		Op:     "start-type",
		TS:     time.Now().Format("2006-01-02 15:04:05"),
		Cmd:    buildCmdLine(os.Args),
		Before: snaps,
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
			fmt.Printf("%s %s -> %s\n", c(clrGreen, "start-type"), c(clrCyan, n), c(svc_startTypeColor(newType), levelStr))
			okCount++
		}
	}

	// Record the new state so the JSON manifest is complete.
	var after []svc_svcSnapshot
	for _, n := range names {
		if snap, err := svc_snapshotService(scm, n); err == nil {
			after = append(after, snap)
		}
	}
	rec.After = after
	svc_saveOpRecord(idx, rec)

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

func svc_cmdHistory() int {
	lines, err := svc_readLogLines()
	if err != nil {
		fmt.Fprintf(os.Stderr, "read log %s: %v\n", svc_logPath(), err)
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
		if !svc_manifestExists(i) {
			continue
		}
		cmd, ok := svc_parseLogLine(lines[i])
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
		if rec, err := svc_loadOpRecord(e.idx); err == nil {
			desc = svc_summarizeOp(rec)
		}
		fmt.Printf("[%d] %s %s\n", k+1, e.line, c(clrGray, desc))
	}
	fmt.Fprintf(os.Stderr, "\n%d rollback-able operation(s). Log: %s\n", len(entries), svc_logPath())
	return 0
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

// ============================================================================
// Rollback
// ============================================================================

func svc_cmdRollback(args []string) int {
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

	lines, err := svc_readLogLines()
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
			// BUGFIX: trim whitespace so a value pasted from PowerShell with
			// stray spaces still matches.
			want[strings.ToLower(strings.TrimSpace(n))] = true
		}
		for i := len(lines) - 1; i >= 0; i-- {
			if !svc_manifestExists(i) {
				continue
			}
			rec, err := svc_loadOpRecord(i)
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
			if !svc_manifestExists(i) {
				continue
			}
			rec, err := svc_loadOpRecord(i)
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
			fmt.Printf("[dry-run] step %d: %s %s\n", k+1, t.rec.Op, svc_summarizeOp(t.rec))
		}
		return 0
	}

	scm, err := svc_openSCM()
	if err != nil {
		fmt.Fprintf(os.Stderr, "svcctl: %v\n", err)
		return 5
	}
	defer svc_closeHandle(scm)

	okCount, failCount := 0, 0
	for k, t := range targets {
		fmt.Fprintf(os.Stderr, "[rollback] step %d: %s %s\n", k+1, t.rec.Op, svc_summarizeOp(t.rec))
		if err := svc_rollbackOne(scm, t.rec); err != nil {
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

func svc_rollbackOne(scm syscall.Handle, rec *svc_opRecord) error {
	for i := len(rec.Before) - 1; i >= 0; i-- {
		b := rec.Before[i]
		h, err := svc_openService(scm, b.Name, svc_SERVICE_ALL_ACCESS)
		if err != nil {
			return fmt.Errorf("%s: %w", b.Name, err)
		}

		// BUGFIX: skip start-type restoration when the before snapshot does
		// not have a valid start type (0xFFFFFFFF sentinel). Otherwise
		// ChangeServiceConfig would be called with an invalid value and
		// fail the whole rollback for a service we could not snapshot
		// properly in the first place.
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

// ============================================================================
// Help
// ============================================================================

func svc_printHelp() {
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
  A service whose configuration cannot be read (stopped services,
  permission denied, ...) is shown with START = "?" instead of the
  misleading "boot" that earlier versions produced.

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
                       Note: -o is applied AFTER --version / --help, so
                       "svcctl --version -o x.txt" still prints the version
                       to the console.
  --dry-run            Preview only: prints the plan for each target and
                       returns without changing anything, without prompting,
                       without writing backups, and without logging.
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

// svc_consumeGlobalFlags strips flags that apply to the whole invocation, so
// subcommand parsers never see them. This lets --dry-run / --no-color / -b /
// -o appear anywhere on the command line, including after the subcommand.
// outPath is returned separately because -o/--out takes an argument and must
// be applied after color initialization.
func svc_consumeGlobalFlags(args []string) (rest []string, outPath string, err error) {
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

// svc_setupOutput redirects os.Stdout to a file. Colors are disabled while the
// redirection is active, because ANSI escapes in a text file are noise.
// The original stdout is restored by the cleanup function stored in
// outputCleanup (called from svc_finalExit).
func svc_setupOutput(path string) error {
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
// svc_main
// ============================================================================

func svc_main() {
	args, outPath, err := svc_consumeGlobalFlags(os.Args[1:])
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

	// BUGFIX: handle --version and --help BEFORE applying -o/--out, so that
	// "svcctl --version -o x.txt" still prints the version to the console
	// (this is what every other module in the toolkit does, and it avoids
	// creating a file when the user only wanted to see the version).
	if has(args, "--version") {
		fmt.Println("svcctl v1.0.0")
		svc_finalExit(0)
	}
	if len(args) == 0 || has(args, "-h", "--help") {
		svc_printHelp()
		svc_finalExit(0)
	}

	if outPath != "" {
		if err := svc_setupOutput(outPath); err != nil {
			fmt.Fprintf(os.Stderr, "svcctl: %v\n", err)
			bugs.Flush()
			os.Exit(2)
		}
	}

	var code int
	switch {
	case has(args, "--history"):
		code = svc_cmdHistory()
	case has(args, "--rollback"):
		code = svc_cmdRollback(svc_stripFlags(args, "--rollback"))
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
			fmt.Fprintf(os.Stderr, "svcctl: unknown command %q\n", cmd)
			code = 2
		}
	}

	svc_finalExit(code)
}

func svc_stripFlags(args []string, flags ...string) []string {
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

func svc_finalExit(code int) {
	if !dryRun && svc_shouldLogRun() {
		svc_appendLogLine(buildCmdLine(os.Args), code)
	}
	bugs.Flush()
	if outputCleanup != nil {
		outputCleanup()
		outputCleanup = nil
	}
	os.Exit(code)
}

func svc_shouldLogRun() bool {
	for _, a := range os.Args[1:] {
		switch a {
		case "-h", "--help", "--version", "--history", "--dry-run":
			return false
		}
	}
	return true
}
// ==================== sys ====================
// sysfixctl — System file and image repair entry point.
// Single-file, standard-library-only build:
//
//   go build -trimpath -ldflags "-s -w" -o sysfixctl.exe sysfixctl.go
//
// Log: ./sysfixctl_backup/sysfixctl.log  [cmd] [ts] [exit code]

// ============================================================================
// Colors / Console / Bug collector
// ============================================================================

// (shared with the rest of the toolkit)

// ============================================================================
// Win32 / Advapi32 / Shell32 bindings
// ============================================================================

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

// ============================================================================
// Encoding
// ============================================================================

// sys_convertToUTF8 converts a byte slice produced by a console subprocess
// (DISM, SFC, chkdsk) from the OEM code page to UTF-8.
//
// If GetOEMCP fails, fall back to the ANSI code page (GetACP) rather than
// CP437. CP437 is the DOS US code page and produces mojibake for every
// non-English Windows; GetACP returns the system ANSI code page (936 on
// Simplified Chinese, 1252 on English, ...) which is much more likely to be
// the right one when OEM CP is not available.
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
		// Last-ditch: return the original bytes so the caller sees
		// *something* rather than an empty string.
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

// ============================================================================
// Admin / Elevation
// ============================================================================

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
	var paramParts []string
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

// ============================================================================
// Step catalogue
// ============================================================================

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
		Key:   "dism-check",
		Flag:  "--dism-check",
		Label: "DISM /CheckHealth",
		Exe:   "dism.exe",
		Args:  []string{"/Online", "/Cleanup-Image", "/CheckHealth"},
		Note:  "Quick health check of the component store",
	}
}

func sys_stepDISMScan() *sys_fixStep {
	return &sys_fixStep{
		Key:   "dism-scan",
		Flag:  "--dism-scan",
		Label: "DISM /ScanHealth",
		Exe:   "dism.exe",
		Args:  []string{"/Online", "/Cleanup-Image", "/ScanHealth"},
		Note:  "Full scan of the component store (may take 10+ min)",
	}
}

func sys_stepDISMRestore() *sys_fixStep {
	return &sys_fixStep{
		Key:   "dism-restore",
		Flag:  "--dism-restore",
		Label: "DISM /RestoreHealth",
		Exe:   "dism.exe",
		Args:  []string{"/Online", "/Cleanup-Image", "/RestoreHealth"},
		Note:  "Repair the component store (may take 15+ min)",
	}
}

func sys_stepSFC() *sys_fixStep {
	return &sys_fixStep{
		Key:   "sfc",
		Flag:  "--sfc",
		Label: "SFC /scannow",
		Exe:   "sfc.exe",
		Args:  []string{"/scannow"},
		Note:  "Scan and repair system files (may take 30+ min)",
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
	return &sys_fixStep{
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
	sys_backupDirName = "sysfixctl_backup"
	sys_logFileName   = "sysfixctl.log"
)

func sys_logRoot() string { return filepath.Join(exeDir(), sys_backupDirName) }
func sys_logPath() string { return filepath.Join(sys_logRoot(), sys_logFileName) }

func sys_readLogLines() ([]string, error) {
	data, err := os.ReadFile(sys_logPath())
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

func sys_appendLogLine(cmd string, code int) {
	_ = os.MkdirAll(sys_logRoot(), 0755)
	f, err := os.OpenFile(sys_logPath(), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		bugs.Add("ERR", "open log: %v", err)
		return
	}
	defer f.Close()
	ts := time.Now().Format("2006-01-02 15:04:05")
	_, _ = fmt.Fprintf(f, "[%s] [%s] [%d]\n", cmd, ts, code)
}

var sys_histRe = regexp.MustCompile(`^\[(.*)\] \[(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\] \[(-?\d+)\]$`)

// ============================================================================
// Thread-safe writer
// ============================================================================

type sys_lockedWriter struct {
	mu sync.Mutex
	w  io.Writer
}

func (lw *sys_lockedWriter) Write(p []byte) (int, error) {
	lw.mu.Lock()
	defer lw.mu.Unlock()
	return lw.w.Write(p)
}

// ============================================================================
// Subprocess output pump
// ============================================================================

// sys_pumpOutput reads raw bytes from r, converts them to UTF-8, and writes
// them to both screen and log.
//
// Line endings:
//
//   - \n: write "\n" to both screen and log.
//   - \r: console progress line. On a TTY, write the buffered text followed
//         by "\r" (carriage return, no newline), so the next write
//         overwrites the same terminal line — this is what makes DISM's
//         "10% ... 20% ... 100%" progress bar update in place.
//         On a non-TTY (file redirect, CI), write the buffered text
//         followed by "\n", so the progress lines are preserved. Otherwise
//         all progress output disappeared when -o/out.txt was used.
func sys_pumpOutput(r io.Reader, screen io.Writer, log io.Writer, screenIsTTY bool) {
	br := bufio.NewReaderSize(r, 4096)
	var buf []byte
	for {
		b, err := br.ReadByte()
		if err != nil {
			if len(buf) > 0 {
				converted := sys_convertToUTF8(buf)
				screen.Write(converted)
				if log != nil {
					log.Write(converted)
				}
			}
			return
		}
		if b == '\r' {
			converted := sys_convertToUTF8(buf)
			if screenIsTTY {
				screen.Write(converted)
				screen.Write([]byte("\r"))
			} else {
				// Non-TTY: keep the text, terminate the line with \n.
				screen.Write(converted)
				screen.Write([]byte("\n"))
				if log != nil {
					log.Write(converted)
					log.Write([]byte("\n"))
				}
			}
			buf = buf[:0]
			continue
		}
		if b == '\n' {
			converted := sys_convertToUTF8(buf)
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

func sys_runStep(s *sys_fixStep, logFile *os.File, stepNum, totalNum int) int {
	header := fmt.Sprintf("\n--- %d/%d %s ---\n", stepNum, totalNum, s.Label)
	fmt.Print(c(clrBold+clrCyan, header))
	if _, err := logFile.WriteString(header); err != nil {
		bugs.Add("WARN", "log header: %v", err)
	}

	cmdLine := "cmd: " + s.cmdLine() + "\n"
	note := "note: " + s.Note + "\n\n"
	fmt.Printf("  %s\n", c(clrGray, "cmd:  "+s.cmdLine()))
	fmt.Printf("  %s\n\n", c(clrGray, "note: "+s.Note))
	if _, err := logFile.WriteString(cmdLine); err != nil {
		bugs.Add("WARN", "log cmd: %v", err)
	}
	if _, err := logFile.WriteString(note); err != nil {
		bugs.Add("WARN", "log note: %v", err)
	}

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
		_, _ = logFile.WriteString("start error: " + err.Error() + "\n")
		sys_appendLogLine(s.cmdLine(), 5)
		return 5
	}

	screenIsTTY := stdoutIsTTY()
	lw := &sys_lockedWriter{w: logFile}
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
	if _, err := lw.Write([]byte(summary)); err != nil {
		bugs.Add("WARN", "log summary: %v", err)
	}

	if exitCode == 0 {
		fmt.Printf("\n%s %s\n", c(clrGreen, "done:"), s.Label)
	} else {
		fmt.Printf("\n%s %s (exit %d)\n", c(clrRed, "failed:"), s.Label, exitCode)
	}
	return exitCode
}

// ============================================================================
// sys_cmdRun
// ============================================================================

func sys_cmdRun(steps []*sys_fixStep, yes bool) int {
	if len(steps) == 0 {
		fmt.Fprintln(os.Stderr, "sysfixctl: no steps selected")
		return 2
	}
	if !sys_isAdmin() {
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

	_ = os.MkdirAll(sys_logRoot(), 0755)
	logFile, err := os.OpenFile(sys_logPath(), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		fmt.Fprintf(os.Stderr, "sysfixctl: open log: %v\n", err)
		return 5
	}
	defer logFile.Close()

	header := fmt.Sprintf("\n=== sysfixctl session ===\nstarted: %s\nsteps: %d\nadmin: %v\n\n",
		time.Now().Format("2006-01-02 15:04:05"), len(steps), sys_isAdmin())
	if _, err := logFile.WriteString(header); err != nil {
		bugs.Add("WARN", "log header: %v", err)
	}

	succeeded, failed := 0, 0
	for i, s := range steps {
		if code := sys_runStep(s, logFile, i+1, len(steps)); code == 0 {
			succeeded++
		} else {
			failed++
		}
	}

	summary := fmt.Sprintf("\n=== summary: %d ok, %d failed ===\n", succeeded, failed)
	if _, err := logFile.WriteString(summary); err != nil {
		bugs.Add("WARN", "log summary: %v", err)
	}
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

func sys_cmdMenu() int {
	fmt.Println()
	fmt.Println(c(clrBold+clrCyan, "================================================================"))
	fmt.Println(c(clrBold+clrCyan, "  sysfixctl v1.0.0 - Windows System Repair"))
	fmt.Println(c(clrBold+clrCyan, "================================================================"))
	fmt.Println()

	if !sys_isAdmin() {
		fmt.Println(c(clrYellow, "  Warning: not running as administrator."))
		fmt.Println(c(clrYellow, "  SFC, DISM, and chkdsk require elevation."))
		fmt.Println()
	}
	if !stdinIsTTY() {
		fmt.Fprintln(os.Stderr, c(clrYellow, "note: stdin is not a console; menu choices are unavailable."))
		fmt.Fprintln(os.Stderr, "      use 'sysfixctl run --safe|--repair|--all' instead.")
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
		return sys_runOrElevate([]*sys_fixStep{
			sys_stepDISMCheck(), sys_stepDISMScan(), sys_stepChkdsk("C", false),
		}, true)
	case "2":
		return sys_runOrElevate([]*sys_fixStep{
			sys_stepDISMRestore(), sys_stepSFC(),
		}, true)
	case "3":
		return sys_runOrElevate([]*sys_fixStep{
			sys_stepDISMCheck(), sys_stepDISMScan(), sys_stepDISMRestore(), sys_stepSFC(), sys_stepChkdsk("C", false),
		}, true)
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

// sys_runOrElevate launches the given steps, trying elevation if needed.
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
		fmt.Fprintf(os.Stderr, "sysfixctl: %v\n", err)
		return 5
	}
	return code
}

// ============================================================================
// History / rollback
// ============================================================================

func sys_cmdHistory() int {
	lines, err := sys_readLogLines()
	if err != nil {
		fmt.Fprintf(os.Stderr, "read log %s: %v\n", sys_logPath(), err)
		return 4
	}
	if len(lines) == 0 {
		fmt.Fprintln(os.Stderr, "log is empty")
		return 0
	}
	var entries []string
	for _, l := range lines {
		if sys_histRe.MatchString(l) {
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
	fmt.Fprintf(os.Stderr, "\n%d entrie(s). Log: %s\n", len(entries), sys_logPath())
	return 0
}

func sys_cmdRollback(args []string) int {
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

	lines, err := sys_readLogLines()
	if err != nil {
		fmt.Fprintf(os.Stderr, "read log %s: %v\n", sys_logPath(), err)
		return 4
	}
	var entries []string
	for _, l := range lines {
		if sys_histRe.MatchString(l) {
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
		m := sys_histRe.FindStringSubmatch(line)
		code, _ := strconv.Atoi(m[3])
		fmt.Printf("[%d] %s\n", k+1, line)
		if code != 0 {
			fmt.Printf("      %s\n", c(clrRed, fmt.Sprintf("exit code %d", code)))
		}
	}
	fmt.Fprintf(os.Stderr, "\n%d entrie(s) shown. Log: %s\n", n, sys_logPath())
	return 0
}

// ============================================================================
// Help
// ============================================================================

func sys_printHelp() {
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
  --chkdsk-fix [drive]       chkdsk <drive>: /f (requires reboot)
                             When both --chkdsk and --chkdsk-fix are given,
                             the last one wins.

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

OUTPUT NOTES
  Progress lines from DISM/SFC (carriage-return updates) are preserved
  when stdout is redirected to a file or a pipe: each update becomes its
  own line. On an interactive console they update in place, as expected.

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

func sys_main() {
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
		if err := sys_setupOutput(outPath); err != nil {
			fmt.Fprintf(os.Stderr, "sysfixctl: %v\n", err)
			bugs.Flush()
			os.Exit(2)
		}
	}

	if has(args, "--version") {
		fmt.Println("sysfixctl v1.0.0")
		sys_finalExit(0, false)
	}
	if has(args, "--history") {
		sys_finalExit(sys_cmdHistory(), false)
	}
	if has(args, "--rollback") {
		sys_finalExit(sys_cmdRollback(sys_stripFlag(args, "--rollback")), false)
	}
	if has(args, "-h", "--help") {
		sys_printHelp()
		sys_finalExit(0, false)
	}
	if len(args) == 0 {
		sys_finalExit(sys_cmdMenu(), true)
	}
	if args[0] == "menu" {
		sys_finalExit(sys_cmdMenu(), true)
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
		fmt.Fprintf(os.Stderr, "sysfixctl: %v\n", err)
		sys_finalExit(2, true)
	}
	if len(steps) == 0 {
		fmt.Fprintln(os.Stderr, "sysfixctl: no steps selected (use --all, --safe, --repair, or explicit steps)")
		sys_finalExit(2, true)
	}

	if !sys_isAdmin() {
		if !elevate {
			fmt.Fprintln(os.Stderr, c(clrBold+clrRed, "error: not running as administrator"))
			fmt.Fprintln(os.Stderr, "  SFC, DISM, and chkdsk all require administrator privileges.")
			fmt.Fprintln(os.Stderr, "  Re-run with --elevate to relaunch with a UAC prompt.")
			sys_finalExit(3, true)
		}
		if !elevated {
			fmt.Println(c(clrYellow, "Requesting administrator privileges (UAC prompt)..."))
			code, err := sys_relaunchElevated(os.Args[1:])
			if err != nil {
				fmt.Fprintf(os.Stderr, "sysfixctl: %v\n", err)
				bugs.Flush()
				os.Exit(5)
			}
			os.Exit(code)
		}
	}

	sys_finalExit(sys_cmdRun(steps, yes), true)
}

// ============================================================================
// Argument parsing
// ============================================================================

// sys_parseRunArgs turns the "run" arguments into an ordered list of steps.
//
// BUGFIX: --chkdsk and --chkdsk-fix used to both add "chkdsk" to the key
// list, and the "seen" dedupe map explicitly skipped "chkdsk" so the final
// command list contained two chkdsk steps. The fix records the *last*
// chkdsk variant (and its drive) and emits exactly one step.
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
			// Dedupe chkdsk explicitly; emit at most one chkdsk step.
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

// ============================================================================
// Helpers
// ============================================================================

func sys_stripFlag(args []string, flag string) []string {
	out := make([]string, 0, len(args))
	for _, a := range args {
		if a != flag {
			out = append(out, a)
		}
	}
	return out
}

func sys_setupOutput(path string) error {
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

func sys_finalExit(code int, logIt bool) {
	if logIt && !dryRun && sys_shouldLogRun() {
		sys_appendLogLine(buildCmdLine(os.Args), code)
	}
	bugs.Flush()
	if outputCleanup != nil {
		outputCleanup()
		outputCleanup = nil
	}
	os.Exit(code)
}

func sys_shouldLogRun() bool {
	for _, a := range os.Args[1:] {
		switch a {
		case "-h", "--help", "--version", "--history", "--rollback", "--dry-run":
			return false
		}
	}
	return true
}
// ==================== task ====================
// taskctl — Windows scheduled task and startup entry manager with rollback.
// Single-file, standard-library-only build:
//
//   go build -trimpath -ldflags "-s -w" -o taskctl.exe taskctl.go

// ============================================================================
// Colors / Console / Bug collector
// ============================================================================

// (shared with the rest of the toolkit)

// ============================================================================
// Win32 / Advapi32 bindings
// ============================================================================

var (
	task_pMultiByteToWideChar = kernel32.NewProc("MultiByteToWideChar")
	task_pGetACP              = kernel32.NewProc("GetACP")
)

// ============================================================================
// Registry bindings (for startup entries)
// ============================================================================

// regOpenKey, regEnumValues, regSetValue, regDeleteValue, pRegCreateKeyExW,
// HKCU, HKLM, KEY_READ, KEY_SET_VALUE, KEY_WOW64_32KEY, KEY_WOW64_64KEY,
// REG_SZ, REG_EXPAND_SZ, KEY_READ are all shared with the rest of the
// toolkit.

func task_regCreateKey(root uintptr, subKey string, samDesired uint32) (RegKey, error) {
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

type task_StartupLocation struct {
	Name    string
	Root    uintptr
	RootStr string
	SubKey  string
	Wow32   bool
	Folder  string
}

var task_startupLocations = []task_StartupLocation{
	{"HKCU Run", HKCU, "HKCU", `Software\Microsoft\Windows\CurrentVersion\Run`, false, ""},
	{"HKLM Run", HKLM, "HKLM", `Software\Microsoft\Windows\CurrentVersion\Run`, false, ""},
	{"HKLM Wow64 Run", HKLM, "HKLM", `Software\Microsoft\Windows\CurrentVersion\Run`, true, ""},
	{"HKCU RunOnce", HKCU, "HKCU", `Software\Microsoft\Windows\CurrentVersion\RunOnce`, false, ""},
	{"HKLM RunOnce", HKLM, "HKLM", `Software\Microsoft\Windows\CurrentVersion\RunOnce`, false, ""},
	{"HKLM Wow64 RunOnce", HKLM, "HKLM", `Software\Microsoft\Windows\CurrentVersion\RunOnce`, true, ""},
	{"HKLM Winlogon UserInit", HKLM, "HKLM", `SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`, false, ""},
	{"HKLM Winlogon Shell", HKLM, "HKLM", `SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`, false, ""},
}

var task_startupFolders = []struct {
	Name string
	Path string
}{
	{"User Startup Folder", ""},
	{"Common Startup Folder", ""},
}

func task_resolveStartupFolders() {
	userProfile := os.Getenv("USERPROFILE")
	if userProfile != "" {
		task_startupFolders[0].Path = filepath.Join(userProfile,
			`AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup`)
	}
	programData := os.Getenv("ProgramData")
	if programData != "" {
		task_startupFolders[1].Path = filepath.Join(programData,
			`Microsoft\Windows\Start Menu\Programs\Startup`)
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

// ============================================================================
// UTF-16 helpers
// ============================================================================

func task_utf16Decode(u []uint16) []rune {
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

func task_utf16Encode(s string) []uint16 {
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
// Registry value helpers
// ============================================================================

func task_decodeRegString(b []byte) string {
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
	return string(task_utf16Decode(u))
}

func task_hexJoin(b []byte) string {
	parts := make([]string, len(b))
	for i, x := range b {
		parts[i] = fmt.Sprintf("%02x", x)
	}
	return strings.Join(parts, ",")
}

// task_escapeString applies the .reg string-literal escaping rules: every
// backslash becomes "\\", every double-quote becomes "\"".
//
// BUGFIX: the previous version of task_exportRegKey wrote REG_SZ values as
// `"` + raw string + `"`, without escaping. .reg files treat backslash as
// an escape character, so a path like C:\Program Files\app.exe was
// rewritten as C:Program Filesapp.exe on import. Every REG_SZ that
// contains a backslash or a double quote needs escaping, which is what
// this helper does.
var task_escapeReplacer = strings.NewReplacer(`\`, `\\`, `"`, `\"`)

func task_escapeString(s string) string {
	return task_escapeReplacer.Replace(s)
}

func task_encodeRegString(s string) []byte {
	u := task_utf16Encode(s)
	u = append(u, 0)
	out := make([]byte, len(u)*2)
	for i, v := range u {
		out[i*2] = byte(v)
		out[i*2+1] = byte(v >> 8)
	}
	return out
}

func task_toUTF16LEBOM(s string) []byte {
	u := task_utf16Encode(s)
	out := make([]byte, 2+len(u)*2)
	out[0] = 0xFF
	out[1] = 0xFE
	for i, v := range u {
		out[2+i*2] = byte(v)
		out[2+i*2+1] = byte(v >> 8)
	}
	return out
}

// ============================================================================
// .reg export for a single registry key
// ============================================================================

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
	fullPath := rootStr + `\` + subKey
	buf.WriteString("[" + fullPath + "]\r\n")

	vals, _ := regEnumValues(k)
	for _, v := range vals {
		// Value name also needs escaping (it can theoretically contain
		// a backslash or a quote, although that is unusual in practice).
		buf.WriteString(`"` + task_escapeString(v.Name) + `"=`)
		switch v.Type {
		case REG_SZ:
			// BUGFIX: escape the string content.
			buf.WriteString(`"` + task_escapeString(task_decodeRegString(v.Data)) + `"` + "\r\n")
		case REG_EXPAND_SZ:
			// Keep REG_EXPAND_SZ as hex so we round-trip the exact bytes.
			buf.WriteString("hex(2):" + task_hexJoin(v.Data) + "\r\n")
		default:
			buf.WriteString("hex:" + task_hexJoin(v.Data) + "\r\n")
		}
	}
	return buf.String(), nil
}

// ============================================================================
// Code page decoding for subprocess output
// ============================================================================

// task_decodeCP converts b from code page cp to a Go string. cp == 0 means
// "use the system ANSI code page". The function relies on
// MultiByteToWideChar so no external tables are needed.
func task_decodeCP(b []byte, cp uint32) string {
	if len(b) == 0 {
		return ""
	}
	if cp == 0 {
		r, _, _ := task_pGetACP.Call()
		cp = uint32(r)
	}
	if cp == 0 || cp == 65001 {
		return string(b)
	}
	n, _, _ := task_pMultiByteToWideChar.Call(
		uintptr(cp), 0,
		uintptr(unsafe.Pointer(&b[0])), uintptr(len(b)),
		0, 0)
	if n == 0 {
		return string(b)
	}
	buf := make([]uint16, n)
	n2, _, _ := task_pMultiByteToWideChar.Call(
		uintptr(cp), 0,
		uintptr(unsafe.Pointer(&b[0])), uintptr(len(b)),
		uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)))
	if n2 == 0 {
		return string(b)
	}
	return string(task_utf16Decode(buf[:n2]))
}

// task_decodeConsoleOutput decodes schtasks.exe output. It handles:
//
//   - UTF-16LE with BOM (the format schtasks emits when its stdout is
//     redirected to a pipe on modern Windows)
//   - UTF-8 with BOM
//   - UTF-8 without BOM (valid UTF-8)
//   - UTF-16LE without BOM (via a heuristic on odd-position NUL bytes)
//   - the system ANSI code page (CP936 on Chinese Windows, 1252 on
//     English Windows, ...) as a last resort
//
// BUGFIX: the previous heuristic checked only b[1] == 0 && b[3] == 0,
// which fails for UTF-16LE text whose first two characters are CJK (e.g.
// "中文" encodes as 2D 4E 87 65, with b[1]=0x4E and b[3]=0x65 — both
// non-zero). Such output was decoded as ANSI and came out as mojibake.
// We now look at how many odd-position bytes are NUL; when at least half
// of them are, the data is almost certainly UTF-16LE (Latin, CJK, or a
// mix), because ANSI text never produces that pattern.
func task_decodeConsoleOutput(b []byte) string {
	if len(b) == 0 {
		return ""
	}
	// UTF-16LE with BOM
	if len(b) >= 2 && b[0] == 0xFF && b[1] == 0xFE {
		u := make([]uint16, (len(b)-2)/2)
		for i := 0; i < len(u); i++ {
			u[i] = uint16(b[2+i*2]) | uint16(b[2+i*2+1])<<8
		}
		return string(task_utf16Decode(u))
	}
	// UTF-8 with BOM
	if len(b) >= 3 && b[0] == 0xEF && b[1] == 0xBB && b[2] == 0xBF {
		return string(b[3:])
	}
	// UTF-16LE without BOM: odd-position NUL heuristic.
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
			return string(task_utf16Decode(u))
		}
	}
	// Valid UTF-8 without BOM
	if utf8.Valid(b) {
		return string(b)
	}
	// System ANSI code page
	return task_decodeCP(b, 0)
}

// ============================================================================
// schtasks.exe wrapper
// ============================================================================

func task_schtasksPath() string {
	return filepath.Join(os.Getenv("SystemRoot"), "System32", "schtasks.exe")
}

// task_runSchtasks runs schtasks and returns text output decoded from the
// console code page. Use task_exportTaskXML when you need raw XML bytes.
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
	return stdout, stderr, exitCode
}

// ============================================================================
// Task listing
// ============================================================================

type task_TaskInfo struct {
	Name        string
	Status      string
	NextRunTime string
	TaskToRun   string
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
		t := task_TaskInfo{
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

// ============================================================================
// Task XML export (raw bytes, no transcoding)
// ============================================================================

// task_exportTaskXML returns the raw bytes produced by
//   schtasks.exe /query /tn <task> /xml
//
// On Windows 10/11 this is UTF-16LE with BOM and an XML declaration of
// encoding="UTF-16". We must not transcode it, otherwise
// schtasks /create /xml would reject the file on rollback.
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

// ============================================================================
// Startup entry listing
// ============================================================================

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
			// Winlogon keys hold many values; only UserInit and Shell
			// are startup entries.
			if loc.Name == "HKLM Winlogon UserInit" && v.Name != "UserInit" {
				continue
			}
			if loc.Name == "HKLM Winlogon Shell" && v.Name != "Shell" {
				continue
			}
			cmd := ""
			switch v.Type {
			case REG_SZ, REG_EXPAND_SZ:
				cmd = task_decodeRegString(v.Data)
			}
			out = append(out, task_StartupEntry{
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
// Display-width helpers (shared, reused here for CJK-aligned output)
// ============================================================================

// (padRight and dispWidth are shared with the rest of the toolkit)

// ============================================================================
// Paths, log
// ============================================================================

const (
	task_backupDirName = "taskctl_backup"
	task_logFileName   = "taskctl.log"
	task_opsDirName    = "ops"
	task_filesDirName  = "files"
)

func task_backupRoot() string { return filepath.Join(exeDir(), task_backupDirName) }
func task_logPath() string    { return filepath.Join(task_backupRoot(), task_logFileName) }
func task_opsDir() string     { return filepath.Join(task_backupRoot(), task_opsDirName) }
func task_filesDir() string   { return filepath.Join(task_backupRoot(), task_filesDirName) }

func task_countLogLines() int {
	f, err := os.Open(task_logPath())
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

func task_readLogLines() ([]string, error) {
	data, err := os.ReadFile(task_logPath())
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

func task_appendLogLine(cmd string, code int) {
	_ = os.MkdirAll(task_backupRoot(), 0755)
	f, err := os.OpenFile(task_logPath(), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		bugs.Add("ERR", "open log: %v", err)
		return
	}
	defer f.Close()
	ts := time.Now().Format("2006-01-02 15:04:05")
	_, _ = fmt.Fprintf(f, "[%s] [%s] [%d]\n", cmd, ts, code)
}

func task_parseLogLine(line string) (cmd string, ok bool) {
	m := logRe.FindStringSubmatch(line)
	if m == nil {
		return "", false
	}
	return m[1], true
}

// ============================================================================
// Operation records
// ============================================================================

type task_opRecord struct {
	Op            string `json:"op"`
	TS            string `json:"ts"`
	Cmd           string `json:"cmd"`
	Code          int    `json:"code"`
	TaskName      string `json:"taskName,omitempty"`
	BackupFile    string `json:"backupFile,omitempty"`
	BackupGzipped bool   `json:"backupGzipped,omitempty"`
	ExistedBefore bool   `json:"existedBefore"`

	// BUGFIX: renamed from task_StartupLocation — the old field name
	// carried a module prefix that was meaningless inside a struct whose
	// other fields are already clearly scoped. The JSON tag is unchanged,
	// so existing manifests on disk still deserialize correctly.
	StartupLocation string `json:"startupLocation,omitempty"`
	StartupRoot     string `json:"startupRoot,omitempty"`
	StartupSubKey   string `json:"startupSubKey,omitempty"`
	StartupName     string `json:"startupName,omitempty"`
	StartupWow32    bool   `json:"startupWow32,omitempty"`
	StartupIsFolder bool   `json:"startupIsFolder,omitempty"`
	StartupFullPath string `json:"startupFullPath,omitempty"`

	WasEnabled *bool `json:"wasEnabled,omitempty"`
}

func task_saveOpRecord(idx int, rec *task_opRecord) {
	_ = os.MkdirAll(task_opsDir(), 0755)
	p := filepath.Join(task_opsDir(), fmt.Sprintf("%d.json", idx))
	data, err := json.MarshalIndent(rec, "", "  ")
	if err != nil {
		bugs.Add("ERR", "marshal op: %v", err)
		return
	}
	if err := os.WriteFile(p, data, 0644); err != nil {
		bugs.Add("ERR", "write op %s: %v", p, err)
	}
}

func task_loadOpRecord(idx int) (*task_opRecord, error) {
	data, err := os.ReadFile(filepath.Join(task_opsDir(), fmt.Sprintf("%d.json", idx)))
	if err != nil {
		return nil, err
	}
	var rec task_opRecord
	if err := json.Unmarshal(data, &rec); err != nil {
		return nil, err
	}
	return &rec, nil
}

func task_manifestExists(idx int) bool {
	_, err := os.Stat(filepath.Join(task_opsDir(), fmt.Sprintf("%d.json", idx)))
	return err == nil
}

func task_beginWriteOp() int {
	_ = os.MkdirAll(task_backupRoot(), 0755)
	_ = os.MkdirAll(task_opsDir(), 0755)
	_ = os.MkdirAll(task_filesDir(), 0755)
	return task_countLogLines()
}

// ============================================================================
// Backup helpers
// ============================================================================

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

// task_backupTaskXML writes the raw schtasks XML to disk, gzipping when it
// exceeds the small-file threshold.
func task_backupTaskXML(taskName string, logIdx int) (string, bool, error) {
	xmlData, err := task_exportTaskXML(taskName)
	if err != nil {
		return "", false, err
	}
	base := fmt.Sprintf("%d_%s", logIdx, task_sanitizeForFilename(taskName))
	if len(xmlData) < task_smallXMLThreshold {
		rel := base + ".xml"
		full := filepath.Join(task_filesDir(), rel)
		if err := os.MkdirAll(filepath.Dir(full), 0755); err != nil {
			return "", false, err
		}
		if err := os.WriteFile(full, xmlData, 0644); err != nil {
			return "", false, err
		}
		return rel, false, nil
	}
	rel := base + ".xml.gz"
	full := filepath.Join(task_filesDir(), rel)
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

func task_backupStartupKey(root uintptr, rootStr, subKey string, wow32 bool, logIdx int) (string, bool, error) {
	regText, err := task_exportRegKey(root, rootStr, subKey, wow32)
	if err != nil {
		return "", false, err
	}
	raw := task_toUTF16LEBOM(regText)
	base := fmt.Sprintf("%d_%s_%s", logIdx, rootStr, task_sanitizeForFilename(subKey))
	if len(raw) < task_smallXMLThreshold {
		rel := base + ".reg"
		full := filepath.Join(task_filesDir(), rel)
		if err := os.MkdirAll(filepath.Dir(full), 0755); err != nil {
			return "", false, err
		}
		if err := os.WriteFile(full, raw, 0644); err != nil {
			return "", false, err
		}
		return rel, false, nil
	}
	rel := base + ".reg.gz"
	full := filepath.Join(task_filesDir(), rel)
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

func task_importRegFile(relPath string, gzipped bool) error {
	src := filepath.Join(task_filesDir(), relPath)
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
// ls (task listing)
// ============================================================================

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
		fmt.Fprintf(os.Stderr, "taskctl: %v\n", err)
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
		padRight("NEXT RUN", nextW) + "  " +
		"TASK TO RUN"
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

// ============================================================================
// startup (listing)
// ============================================================================

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

func task_cmdCreate(args []string) int {
	var taskName, xmlFile, task_cmdRun, schedule, startTime, runAs string
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
			task_cmdRun = args[i+1]
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
	if xmlFile == "" && (task_cmdRun == "" || schedule == "") {
		fmt.Fprintln(os.Stderr, "create: -c and -s are required unless --xml is used")
		return 2
	}

	_, _, qcode := task_runSchtasks("/query", "/tn", taskName)
	existsBefore := qcode == 0

	if dryRun {
		fmt.Printf("[dry-run] create task %q (exists=%v)\n", taskName, existsBefore)
		return 0
	}

	idx := task_beginWriteOp()
	backupRel := ""
	backupGz := false
	if existsBefore {
		var err error
		backupRel, backupGz, err = task_backupTaskXML(taskName, idx)
		if err != nil {
			fmt.Fprintf(os.Stderr, "taskctl: backup failed, aborting: %v\n", err)
			return 5
		}
	}

	var code int
	if xmlFile != "" {
		_, stderr, c := task_runSchtasks("/create", "/tn", taskName, "/xml", xmlFile, "/f")
		if c != 0 {
			fmt.Fprintf(os.Stderr, "taskctl: create from xml: %s\n", strings.TrimSpace(stderr))
			code = 5
		}
	} else {
		sargs := []string{"/create", "/tn", taskName, "/tr", task_cmdRun, "/sc", schedule}
		if startTime != "" {
			sargs = append(sargs, "/st", startTime)
		}
		if runAs != "" {
			sargs = append(sargs, "/ru", runAs)
		}
		sargs = append(sargs, "/f")
		_, stderr, c := task_runSchtasks(sargs...)
		if c != 0 {
			fmt.Fprintf(os.Stderr, "taskctl: create: %s\n", strings.TrimSpace(stderr))
			code = 5
		}
	}

	rec := &task_opRecord{
		Op:            "create",
		TS:            time.Now().Format("2006-01-02 15:04:05"),
		Cmd:           buildCmdLine(os.Args),
		TaskName:      taskName,
		ExistedBefore: existsBefore,
		BackupFile:    backupRel,
		BackupGzipped: backupGz,
	}
	task_saveOpRecord(idx, rec)

	if code == 0 {
		fmt.Printf("%s task %s\n", c(clrGreen, "created"), c(clrCyan, taskName))
	}
	return code
}

// ============================================================================
// delete
// ============================================================================

func task_cmdDelete(args []string) int {
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

	_, _, qcode := task_runSchtasks("/query", "/tn", taskName)
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

	idx := task_beginWriteOp()
	backupRel, backupGz, err := task_backupTaskXML(taskName, idx)
	if err != nil {
		fmt.Fprintf(os.Stderr, "taskctl: backup failed, aborting: %v\n", err)
		return 5
	}

	_, stderr, code := task_runSchtasks("/delete", "/tn", taskName, "/f")
	rec := &task_opRecord{
		Op:            "delete",
		TS:            time.Now().Format("2006-01-02 15:04:05"),
		Cmd:           buildCmdLine(os.Args),
		TaskName:      taskName,
		ExistedBefore: true,
		BackupFile:    backupRel,
		BackupGzipped: backupGz,
	}
	task_saveOpRecord(idx, rec)

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

func task_cmdEnableDisable(args []string, enable bool) int {
	force := false
	var taskName string
	for _, a := range args {
		switch a {
		case "-f", "--force":
			force = true
		default:
			if strings.HasPrefix(a, "-") {
				fmt.Fprintf(os.Stderr, "%s: unknown option %s\n", task_actionName(enable), a)
				return 2
			}
			taskName = a
		}
	}
	if taskName == "" {
		fmt.Fprintf(os.Stderr, "usage: taskctl %s <task> [-f]\n", task_actionName(enable))
		return 2
	}

	_, _, qcode := task_runSchtasks("/query", "/tn", taskName)
	if qcode != 0 {
		fmt.Fprintf(os.Stderr, "taskctl: task %q not found\n", taskName)
		return 4
	}

	if dryRun {
		// BUGFIX: check current state only after the dry-run guard, so a
		// dry-run does not spawn schtasks /query unnecessarily.
		wasEnabled := task_currentTaskEnabled(taskName)
		fmt.Printf("[dry-run] %s task %q (currently enabled=%v)\n",
			task_actionName(enable), taskName, wasEnabled)
		return 0
	}

	if !force && !confirm(fmt.Sprintf("%s task %q?", task_actionName(enable), taskName)) {
		return 1
	}

	wasEnabled := task_currentTaskEnabled(taskName)

	idx := task_beginWriteOp()
	backupRel, backupGz, err := task_backupTaskXML(taskName, idx)
	if err != nil {
		fmt.Fprintf(os.Stderr, "taskctl: backup failed, aborting: %v\n", err)
		return 5
	}

	verb := "/enable"
	if !enable {
		verb = "/disable"
	}
	_, stderr, code := task_runSchtasks("/change", "/tn", taskName, verb)

	rec := &task_opRecord{
		Op:            task_actionName(enable),
		TS:            time.Now().Format("2006-01-02 15:04:05"),
		Cmd:           buildCmdLine(os.Args),
		TaskName:      taskName,
		ExistedBefore: true,
		BackupFile:    backupRel,
		BackupGzipped: backupGz,
		WasEnabled:    &wasEnabled,
	}
	task_saveOpRecord(idx, rec)

	if code != 0 {
		fmt.Fprintf(os.Stderr, "taskctl: %s: %s\n", task_actionName(enable), strings.TrimSpace(stderr))
		return 5
	}
	fmt.Printf("%s task %s\n", c(clrGreen, task_actionName(enable)+"d"), c(clrCyan, taskName))
	return 0
}

func task_actionName(enable bool) string {
	if enable {
		return "enable"
	}
	return "disable"
}

// task_currentTaskEnabled reports whether a task is currently enabled.
//
// schtasks /query /fo list /v prints a "Status:" (or localized equivalent)
// line. On English it contains "Ready"/"Running"/"Disabled"; on Simplified
// Chinese it contains "就绪"/"正在运行"/"已禁用". Other locales have their
// own strings, which we cannot enumerate. The caller only uses this value
// to decide whether a subsequent rollback should flip the state, so we
// take the conservative route:
//
//   - if the line matches a known "disabled" token -> false
//   - if the line matches a known "enabled" token   -> true
//   - otherwise (unknown locale)                    -> true
//
// Reporting "enabled" for unknown locales means a rollback of a
// "disable" operation will not flip a task back on unless it was
// definitely disabled before, which is safer than the opposite.
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

// ============================================================================
// export / import
// ============================================================================

func task_cmdExport(args []string) int {
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

	data, err := task_exportTaskXML(taskName)
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
	if _, err := os.Stdout.Write(data); err != nil {
		fmt.Fprintf(os.Stderr, "taskctl: write stdout: %v\n", err)
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

	_, _, qcode := task_runSchtasks("/query", "/tn", taskName)
	existsBefore := qcode == 0

	if dryRun {
		fmt.Printf("[dry-run] import task %q from %s (exists=%v)\n", taskName, xmlFile, existsBefore)
		return 0
	}

	idx := task_beginWriteOp()
	backupRel := ""
	backupGz := false
	if existsBefore {
		var err error
		backupRel, backupGz, err = task_backupTaskXML(taskName, idx)
		if err != nil {
			fmt.Fprintf(os.Stderr, "taskctl: backup failed, aborting: %v\n", err)
			return 5
		}
	}

	_, stderr, code := task_runSchtasks("/create", "/tn", taskName, "/xml", xmlFile, "/f")
	rec := &task_opRecord{
		Op:            "import",
		TS:            time.Now().Format("2006-01-02 15:04:05"),
		Cmd:           buildCmdLine(os.Args),
		TaskName:      taskName,
		ExistedBefore: existsBefore,
		BackupFile:    backupRel,
		BackupGzipped: backupGz,
	}
	task_saveOpRecord(idx, rec)

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

func task_cmdRun(args []string) int {
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
	_, stderr, code := task_runSchtasks("/run", "/tn", taskName)
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

func task_cmdStartupAdd(args []string) int {
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

	var loc *task_StartupLocation
	for i := range task_startupLocations {
		if strings.EqualFold(task_startupLocations[i].Name, locName) {
			loc = &task_startupLocations[i]
			break
		}
	}
	if loc == nil {
		fmt.Fprintf(os.Stderr, "startup-add: unknown location %q\n", locName)
		fmt.Fprintln(os.Stderr, "  available:")
		for _, l := range task_startupLocations {
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

	idx := task_beginWriteOp()
	backupRel := ""
	backupGz := false
	if existsBefore {
		backupRel, backupGz, err = task_backupStartupKey(loc.Root, loc.RootStr, loc.SubKey, loc.Wow32, idx)
		if err != nil {
			fmt.Fprintf(os.Stderr, "taskctl: backup failed, aborting: %v\n", err)
			return 5
		}
	}

	writeAccess := uint32(KEY_SET_VALUE | KEY_WOW64_64KEY)
	if loc.Wow32 {
		writeAccess = KEY_SET_VALUE | KEY_WOW64_32KEY
	}
	wk, err := task_regCreateKey(loc.Root, loc.SubKey, writeAccess)
	if err != nil {
		fmt.Fprintf(os.Stderr, "taskctl: create key: %v\n", err)
		return 5
	}
	// BUGFIX: check regSetValue before saving the op record. Previously the
	// record was written even when the registry write failed, which left a
	// rollback manifest pointing at a change that never happened.
	if err := regSetValue(wk, name, REG_SZ, task_encodeRegString(command)); err != nil {
		regCloseKey(wk)
		fmt.Fprintf(os.Stderr, "taskctl: set value: %v\n", err)
		return 5
	}
	regCloseKey(wk)

	rec := &task_opRecord{
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
	task_saveOpRecord(idx, rec)

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

	idx := task_beginWriteOp()
	backupRel, backupGz, err := task_backupStartupKey(loc.Root, loc.RootStr, loc.SubKey, loc.Wow32, idx)
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

	rec := &task_opRecord{
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
	task_saveOpRecord(idx, rec)

	fmt.Printf("%s startup %s\\%s\n", c(clrYellow, "deleted"), loc.Name, c(clrCyan, name))
	return 0
}

// ============================================================================
// History
// ============================================================================

func task_cmdHistory() int {
	lines, err := task_readLogLines()
	if err != nil {
		fmt.Fprintf(os.Stderr, "read log %s: %v\n", task_logPath(), err)
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
		if !task_manifestExists(i) {
			continue
		}
		cmd, ok := task_parseLogLine(lines[i])
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
		if rec, err := task_loadOpRecord(e.idx); err == nil {
			desc = task_summarizeOp(rec)
		}
		fmt.Printf("[%d] %s %s\n", k+1, e.line, c(clrGray, desc))
	}
	fmt.Fprintf(os.Stderr, "\n%d rollback-able operation(s). Log: %s\n", len(entries), task_logPath())
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

// ============================================================================
// Rollback
// ============================================================================

func task_cmdRollback(args []string) int {
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

	lines, err := task_readLogLines()
	if err != nil {
		fmt.Fprintf(os.Stderr, "read log: %v\n", err)
		return 4
	}
	var targets []int
	for i := len(lines) - 1; i >= 0 && len(targets) < n; i-- {
		if !task_manifestExists(i) {
			continue
		}
		cmd, ok := task_parseLogLine(lines[i])
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
			rec, err := task_loadOpRecord(idx)
			if err != nil {
				fmt.Printf("[dry-run] step %d: load manifest %d: %v\n", k+1, idx, err)
				continue
			}
			fmt.Printf("[dry-run] step %d: %s %s\n", k+1, rec.Op, task_summarizeOp(rec))
		}
		return 0
	}

	okCount, failCount := 0, 0
	for k, idx := range targets {
		rec, err := task_loadOpRecord(idx)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[rollback] step %d: load manifest %d: %v\n", k+1, idx, err)
			failCount++
			continue
		}
		fmt.Fprintf(os.Stderr, "[rollback] step %d: %s %s\n", k+1, rec.Op, task_summarizeOp(rec))
		if err := task_rollbackOne(rec); err != nil {
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

func task_rollbackOne(rec *task_opRecord) error {
	switch rec.Op {
	case "create":
		if rec.ExistedBefore {
			return task_restoreTaskFromBackup(rec)
		}
		return task_deleteTaskQuiet(rec.TaskName)

	case "delete":
		return task_restoreTaskFromBackup(rec)

	case "import":
		if rec.ExistedBefore {
			return task_restoreTaskFromBackup(rec)
		}
		return task_deleteTaskQuiet(rec.TaskName)

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

func task_restoreTaskFromBackup(rec *task_opRecord) error {
	src := filepath.Join(task_filesDir(), rec.BackupFile)
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

	_ = task_deleteTaskQuiet(rec.TaskName)
	_, stderr, code := task_runSchtasks("/create", "/tn", rec.TaskName, "/xml", xmlPath, "/f")
	if code != 0 {
		return fmt.Errorf("schtasks /create: %s", strings.TrimSpace(stderr))
	}
	return nil
}

func task_deleteTaskQuiet(taskName string) error {
	_, _, _ = task_runSchtasks("/delete", "/tn", taskName, "/f")
	return nil
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

// ============================================================================
// Help
// ============================================================================

func task_printHelp() {
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

  Task XML is kept byte-for-byte as schtasks produced it (UTF-16LE with
  BOM, XML declaration encoding="UTF-16"). It is fed back to
  schtasks /create /xml unchanged on rollback.
  Startup key .reg files are UTF-16LE with BOM; string values have their
  backslashes and quotes properly escaped so they round-trip correctly.

EXIT CODES
  0 success | 1 partial failure | 2 bad args | 3 permission denied
  4 not found | 5 Windows API / I/O error
`)
}

// ============================================================================
// Global flag consumption
// ============================================================================

func task_consumeGlobalFlags(args []string) (rest []string, outPath string, err error) {
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

func task_setupOutput(path string) error {
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
// task_main
// ============================================================================

func task_main() {
	args, outPath, err := task_consumeGlobalFlags(os.Args[1:])
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

	// handle --version / --help before applying -o, so that
	// "taskctl --version -o foo.txt" still prints the version to the
	// console. This matches svc / pe behavior.
	if has(args, "--version") {
		fmt.Println("taskctl v1.0.0")
		task_finalExit(0)
	}
	if len(args) == 0 || has(args, "-h", "--help") {
		task_printHelp()
		task_finalExit(0)
	}

	if outPath != "" {
		if err := task_setupOutput(outPath); err != nil {
			fmt.Fprintf(os.Stderr, "taskctl: %v\n", err)
			bugs.Flush()
			os.Exit(2)
		}
	}

	var code int
	switch {
	case has(args, "--history"):
		code = task_cmdHistory()
	case has(args, "--rollback"):
		code = task_cmdRollback(task_stripFlags(args, "--rollback"))
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
			fmt.Fprintf(os.Stderr, "taskctl: unknown command %q\n", cmd)
			code = 2
		}
	}

	task_finalExit(code)
}

func task_stripFlags(args []string, flags ...string) []string {
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

func task_finalExit(code int) {
	if !dryRun && task_shouldLogRun() {
		task_appendLogLine(buildCmdLine(os.Args), code)
	}
	bugs.Flush()
	if outputCleanup != nil {
		outputCleanup()
		outputCleanup = nil
	}
	os.Exit(code)
}

func task_shouldLogRun() bool {
	for _, a := range os.Args[1:] {
		switch a {
		case "-h", "--help", "--version", "--history", "--dry-run":
			return false
		}
	}
	return true
}
// ==================== acl ====================
// aclctl — File permission manager (DACL / ACE / owner / SDDL).
// Single-file, standard-library-only build:
//
//   go build -trimpath -ldflags "-s -w" -o aclctl.exe aclctl.go
//
// Log: ./aclctl_backup/aclctl.log  [cmd] [ts] [exit code]

// ============================================================================
// Colors / Console / Bug collector
// ============================================================================

// (shared with the rest of the toolkit)

// ============================================================================
// Advapi32 / Kernel32 bindings
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

// ============================================================================
// Windows security constants
// ============================================================================

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

// ============================================================================
// Structures
// ============================================================================

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

// ============================================================================
// SDDL conversion
// ============================================================================

// acl_sddlFromSecurityDescriptor takes an SD pointer (self-relative or
// absolute, ConvertSecurityDescriptorToStringSecurityDescriptorW handles
// both) and produces the SDDL text.
func acl_sddlFromSecurityDescriptor(sd uintptr, secInfo uint32) (string, error) {
	if sd == 0 {
		return "", fmt.Errorf("nil security descriptor")
	}

	var strPtr *uint16
	var strLen uint32
	r, _, callErr := acl_pConvertSecurityDescriptorToStringSecurityDescriptorW.Call(
		sd,
		uintptr(acl_SDDL_REVISION_1),
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
		uintptr(unsafe.Pointer(ptr)),
		uintptr(acl_SDDL_REVISION_1),
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

// acl_secInfoResult holds a security descriptor pointer and the four
// absolute component pointers. The absolute pointers can be passed
// straight to SetNamedSecurityInfoW; the sdPtr must be released with
// LocalFree.
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

// acl_getSecurityInfo fetches the SD and the four absolute component
// pointers. The pSidOwner/pSidGroup/pDacl/pSacl parameters returned by
// GetNamedSecurityInfoW are ABSOLUTE pointers (direct addresses of the
// SID/ACL bodies), even though the ppSecurityDescriptor is self-relative.
// We rely on this: the absolute pointers are what SetNamedSecurityInfoW
// expects.
func acl_getSecurityInfo(path string, secInfo uint32) (*acl_secInfoResult, error) {
	pathPtr, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}

	var sd uintptr
	var owner, group, dacl, sacl uintptr
	r, _, _ := acl_pGetNamedSecurityInfoW.Call(
		uintptr(unsafe.Pointer(pathPtr)),
		uintptr(acl_SE_FILE_OBJECT),
		uintptr(secInfo),
		uintptr(unsafe.Pointer(&owner)),
		uintptr(unsafe.Pointer(&group)),
		uintptr(unsafe.Pointer(&dacl)),
		uintptr(unsafe.Pointer(&sacl)),
		uintptr(unsafe.Pointer(&sd)),
	)
	if code := uint32(r); code != acl_ERROR_SUCCESS {
		return nil, fmt.Errorf("GetNamedSecurityInfo(%s): %w", path, syscall.Errno(code))
	}
	return &acl_secInfoResult{
		sdPtr: sd,
		owner: owner,
		group: group,
		dacl:  dacl,
		sacl:  sacl,
	}, nil
}

// acl_setSecurityInfoRaw is the real worker: it takes the four absolute
// pointers and calls SetNamedSecurityInfoW. A pointer of 0 means
// "do not change".
func acl_setSecurityInfoRaw(path string, secInfo uint32, owner, group, dacl, sacl uintptr) error {
	pathPtr, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	r, _, _ := acl_pSetNamedSecurityInfoW.Call(
		uintptr(unsafe.Pointer(pathPtr)),
		uintptr(acl_SE_FILE_OBJECT),
		uintptr(secInfo),
		owner, group, dacl, sacl,
	)
	if code := uint32(r); code != acl_ERROR_SUCCESS {
		return fmt.Errorf("SetNamedSecurityInfo(%s): %w", path, syscall.Errno(code))
	}
	return nil
}

// acl_extractComponents pulls absolute pointers out of a self-relative SD.
// This is the correct way to use an SD that came from
// ConvertStringSecurityDescriptorToSecurityDescriptorW.
func acl_extractComponents(sd *acl_SECURITY_DESCRIPTOR) (owner, group, dacl, sacl uintptr, secInfo uint32) {
	var present, defaulted uint32
	if sd == nil {
		return
	}
	base := uintptr(unsafe.Pointer(sd))

	var p uintptr
	if r, _, _ := acl_pGetSecurityDescriptorOwner.Call(base,
		uintptr(unsafe.Pointer(&p)),
		uintptr(unsafe.Pointer(&defaulted))); r != 0 && p != 0 {
		owner = p
		secInfo |= acl_OWNER_SECURITY_INFORMATION
	}
	if r, _, _ := acl_pGetSecurityDescriptorGroup.Call(base,
		uintptr(unsafe.Pointer(&p)),
		uintptr(unsafe.Pointer(&defaulted))); r != 0 && p != 0 {
		group = p
		secInfo |= acl_GROUP_SECURITY_INFORMATION
	}
	if r, _, _ := acl_pGetSecurityDescriptorDacl.Call(base,
		uintptr(unsafe.Pointer(&present)),
		uintptr(unsafe.Pointer(&p)),
		uintptr(unsafe.Pointer(&defaulted))); r != 0 && present != 0 && p != 0 {
		dacl = p
		secInfo |= acl_DACL_SECURITY_INFORMATION
	}
	if r, _, _ := acl_pGetSecurityDescriptorSacl.Call(base,
		uintptr(unsafe.Pointer(&present)),
		uintptr(unsafe.Pointer(&p)),
		uintptr(unsafe.Pointer(&defaulted))); r != 0 && present != 0 && p != 0 {
		sacl = p
		secInfo |= acl_SACL_SECURITY_INFORMATION
	}
	return
}

// ============================================================================
// ACL manipulation
// ============================================================================

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
		uintptr(unsafe.Pointer(&ea)),
		uintptr(unsafe.Pointer(trusteePtr)),
		uintptr(accessMask),
		uintptr(accessMode),
		uintptr(inheritFlags),
	)

	var newAcl *acl_ACL
	r, _, _ := acl_pSetEntriesInAclW.Call(
		1,
		uintptr(unsafe.Pointer(&ea)),
		info.dacl,
		uintptr(unsafe.Pointer(&newAcl)),
	)
	if code := uint32(r); code != acl_ERROR_SUCCESS {
		return fmt.Errorf("SetEntriesInAcl: %w", syscall.Errno(code))
	}
	if newAcl != nil {
		defer acl_pLocalFree.Call(uintptr(unsafe.Pointer(newAcl)))
	}

	// newAcl is a freshly allocated absolute ACL pointer; SetNamedSecurityInfo
	// copies its contents into the target security descriptor, so it is
	// safe to free newAcl after this call.
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

// ============================================================================
// Privilege management
// ============================================================================

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
		uintptr(unsafe.Pointer(namePtr)),
		uintptr(unsafe.Pointer(&luid)))
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
	// AdjustTokenPrivileges returns TRUE even when some privileges were not
	// assigned; the caller must check GetLastError. Go's syscall package
	// folds the errno into callErr, which we inspect here.
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

// ============================================================================
// Paths and log
// ============================================================================

const (
	acl_backupDirName = "aclctl_backup"
	acl_logFileName   = "aclctl.log"
	acl_opsDirName    = "ops"
)

func acl_logRoot() string { return filepath.Join(exeDir(), acl_backupDirName) }
func acl_logPath() string { return filepath.Join(acl_logRoot(), acl_logFileName) }
func acl_opsDir() string  { return filepath.Join(acl_logRoot(), acl_opsDirName) }

func acl_countLogLines() int {
	f, err := os.Open(acl_logPath())
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

func acl_readLogLines() ([]string, error) {
	data, err := os.ReadFile(acl_logPath())
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

func acl_appendLogLine(cmd string, code int) {
	_ = os.MkdirAll(acl_logRoot(), 0755)
	f, err := os.OpenFile(acl_logPath(), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		bugs.Add("ERR", "open log: %v", err)
		return
	}
	defer f.Close()
	ts := time.Now().Format("2006-01-02 15:04:05")
	_, _ = fmt.Fprintf(f, "[%s] [%s] [%d]\n", cmd, ts, code)
}

// ============================================================================
// Operation records
// ============================================================================

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

func acl_saveOpRecord(idx int, rec *acl_opRecord) {
	_ = os.MkdirAll(acl_opsDir(), 0755)
	p := filepath.Join(acl_opsDir(), fmt.Sprintf("%d.json", idx))
	data, err := json.MarshalIndent(rec, "", "  ")
	if err != nil {
		bugs.Add("ERR", "marshal op: %v", err)
		return
	}
	if err := os.WriteFile(p, data, 0644); err != nil {
		bugs.Add("ERR", "write op %s: %v", p, err)
	}
}

func acl_loadOpRecord(idx int) (*acl_opRecord, error) {
	data, err := os.ReadFile(filepath.Join(acl_opsDir(), fmt.Sprintf("%d.json", idx)))
	if err != nil {
		return nil, err
	}
	var rec acl_opRecord
	if err := json.Unmarshal(data, &rec); err != nil {
		return nil, err
	}
	return &rec, nil
}

func acl_manifestExists(idx int) bool {
	_, err := os.Stat(filepath.Join(acl_opsDir(), fmt.Sprintf("%d.json", idx)))
	return err == nil
}

func acl_beginWriteOp() int {
	_ = os.MkdirAll(acl_logRoot(), 0755)
	_ = os.MkdirAll(acl_opsDir(), 0755)
	return acl_countLogLines()
}

// ============================================================================
// SDDL backup / restore
// ============================================================================

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

	base := fmt.Sprintf("%d_%s", logIdx, acl_sanitize(path))
	if len(sddl) < acl_smallThreshold {
		rel := base + ".sddl"
		full := filepath.Join(acl_logRoot(), rel)
		if err := os.MkdirAll(filepath.Dir(full), 0755); err != nil {
			return "", false, err
		}
		if err := os.WriteFile(full, []byte(sddl), 0644); err != nil {
			return "", false, err
		}
		return rel, false, nil
	}

	rel := base + ".sddl.gz"
	full := filepath.Join(acl_logRoot(), rel)
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

func acl_restoreSDDL(relPath string, gzipped bool, path string) error {
	full := filepath.Join(acl_logRoot(), relPath)
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

// acl_applySDDL parses an SDDL string into a self-relative SD, extracts
// absolute component pointers, and calls SetNamedSecurityInfoW.
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

// ============================================================================
// show command
// ============================================================================

func acl_cmdShow(path string, jsonOut bool) int {
	secInfo := uint32(acl_OWNER_SECURITY_INFORMATION | acl_GROUP_SECURITY_INFORMATION | acl_DACL_SECURITY_INFORMATION)

	info, err := acl_getSecurityInfo(path, secInfo)
	if err != nil {
		fmt.Fprintf(os.Stderr, "aclctl: %v\n", err)
		return 5
	}
	defer info.free()

	if jsonOut {
		sddl, _ := acl_sddlFromSecurityDescriptor(info.sdPtr, secInfo)
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		// BUGFIX: check the encode error; previously a broken pipe would
		// silently produce truncated JSON.
		if err := enc.Encode(map[string]string{
			"path": path,
			"sddl": sddl,
		}); err != nil {
			fmt.Fprintf(os.Stderr, "aclctl: json encode: %v\n", err)
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
			fmt.Printf("  %s allow mask=0x%08X flags=0x%X\n",
				c(clrGreen, "ACE"), mask, header.AceFlags)
		case acl_ACCESS_DENIED_ACE_TYPE:
			mask := (*acl_ACCESS_ALLOWED_ACE)(unsafe.Pointer(base)).Mask
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

func acl_cmdSetOwner(path, owner string, yes bool) int {
	if !yes && !confirm(fmt.Sprintf("change owner of %s to %s?", path, owner)) {
		return 1
	}

	idx := acl_beginWriteOp()
	backupRel, _, err := acl_backupSDDL(path, idx)
	if err != nil {
		fmt.Fprintf(os.Stderr, "aclctl: backup failed, aborting: %v\n", err)
		return 5
	}

	acl_ensurePrivileges()

	ownerSID, err := acl_lookupAccountSID(owner)
	if err != nil {
		fmt.Fprintf(os.Stderr, "aclctl: resolve owner %q: %v\n", owner, err)
		return 5
	}

	fullInfo := uint32(acl_OWNER_SECURITY_INFORMATION | acl_GROUP_SECURITY_INFORMATION | acl_DACL_SECURITY_INFORMATION)
	info, err := acl_getSecurityInfo(path, fullInfo)
	if err != nil {
		fmt.Fprintf(os.Stderr, "aclctl: %v\n", err)
		return 5
	}
	oldSDDL, _ := acl_sddlFromSecurityDescriptor(info.sdPtr, fullInfo)
	info.free()

	newSDDL := acl_replaceOwnerInSDDL(oldSDDL, ownerSID)
	if newSDDL == "" {
		fmt.Fprintf(os.Stderr, "aclctl: could not build new SDDL for owner change\n")
		return 5
	}

	if err := acl_applySDDL(newSDDL, path); err != nil {
		fmt.Fprintf(os.Stderr, "aclctl: %v\n", err)
		return 5
	}

	rec := &acl_opRecord{
		Op:      "set-owner",
		TS:      time.Now().Format("2006-01-02 15:04:05"),
		Cmd:     buildCmdLine(os.Args),
		Path:    path,
		OldSDDL: oldSDDL,
		NewSDDL: newSDDL,
		Backup:  backupRel,
	}
	acl_saveOpRecord(idx, rec)

	fmt.Printf("%s owner of %s -> %s (%s)\n",
		c(clrGreen, "changed"), path, owner, ownerSID)
	return 0
}

// acl_ownerRe matches an owner field in SDDL. An owner is either:
//
//   - an alias: two or more ASCII letters, e.g. SY (LocalSystem), BA
//     (Builtin Administrators), WD (Everyone), ...
//   - a SID: S- followed by digits and dashes, e.g. S-1-5-32-544
//
// BUGFIX: the previous regexp was `O:[^GDS]*`, which is wrong because
// the owner SID itself starts with S. The match stopped immediately after
// "O:" and the replacement produced corrupt SDDL such as
// "O:S-1-5-32-544S-1-5-32-544G:...".
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
	r, _, callErr = acl_pConvertSidToStringSidW.Call(
		uintptr(unsafe.Pointer(&sidBuf[0])),
		uintptr(unsafe.Pointer(&sidStrPtr)),
	)
	if r == 0 {
		return "", fmt.Errorf("ConvertSidToStringSid: %w", callErr)
	}
	if sidStrPtr == nil {
		return "", fmt.Errorf("ConvertSidToStringSid returned nil")
	}
	defer acl_pLocalFree.Call(uintptr(unsafe.Pointer(sidStrPtr)))

	return syscall.UTF16ToString(unsafe.Slice(sidStrPtr, 256)), nil
}

// ============================================================================
// add-ace command
// ============================================================================

func acl_cmdAddACE(path, trustee, access string, deny, recursive, yes bool) int {
	if recursive {
		// NOTE: --recursive here only marks the new ACE as inheritable, so
		// FUTURE children inherit it. It does NOT modify existing children
		// (that would require walking the tree and changing each child's
		// DACL, which is slow and prone to partial-failure states that are
		// hard to roll back).
		fmt.Fprintf(os.Stderr, "%s --recursive affects only future children;\n"+
			"         existing children keep their current ACL.\n",
			c(clrYellow, "note:"))
		if !yes && !confirm(fmt.Sprintf("Apply inheritable ACE change to %s?", path)) {
			return 1
		}
	}

	if !yes && !confirm(fmt.Sprintf("add %s ACE for %s on %s?", access, trustee, path)) {
		return 1
	}

	idx := acl_beginWriteOp()
	backupRel, _, err := acl_backupSDDL(path, idx)
	if err != nil {
		fmt.Fprintf(os.Stderr, "aclctl: backup failed, aborting: %v\n", err)
		return 5
	}

	acl_ensurePrivileges()

	inheritFlags := uint32(acl_NO_INHERITANCE)
	if recursive {
		inheritFlags = acl_OBJECT_INHERIT_ACE | acl_CONTAINER_INHERIT_ACE
	}

	if err := acl_addACE(path, trustee, access, deny, inheritFlags); err != nil {
		fmt.Fprintf(os.Stderr, "aclctl: %v\n", err)
		return 5
	}

	rec := &acl_opRecord{
		Op:     "add-ace",
		TS:     time.Now().Format("2006-01-02 15:04:05"),
		Cmd:    buildCmdLine(os.Args),
		Path:   path,
		Backup: backupRel,
	}
	acl_saveOpRecord(idx, rec)

	fmt.Printf("%s ACE for %s on %s\n", c(clrGreen, "added"), trustee, path)
	return 0
}

// ============================================================================
// History / rollback
// ============================================================================

func acl_cmdHistory() int {
	lines, err := acl_readLogLines()
	if err != nil {
		fmt.Fprintf(os.Stderr, "read log %s: %v\n", acl_logPath(), err)
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
		if !acl_manifestExists(i) {
			continue
		}
		cmd, _ := acl_parseLogLine(lines[i])
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
		if rec, err := acl_loadOpRecord(e.idx); err == nil {
			desc = acl_summarizeOp(rec)
		}
		fmt.Printf("[%d] %s %s\n", k+1, e.line, c(clrGray, desc))
	}
	fmt.Fprintf(os.Stderr, "\n%d rollback-able operation(s). Log: %s\n", len(entries), acl_logPath())
	return 0
}

func acl_parseLogLine(line string) (cmd string, ok bool) {
	m := logRe.FindStringSubmatch(line)
	if m == nil {
		return "", false
	}
	return m[1], true
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

func acl_cmdRollback(args []string) int {
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

	lines, err := acl_readLogLines()
	if err != nil {
		fmt.Fprintf(os.Stderr, "read log: %v\n", err)
		return 4
	}
	var targets []int
	for i := len(lines) - 1; i >= 0 && len(targets) < n; i-- {
		if !acl_manifestExists(i) {
			continue
		}
		cmd, _ := acl_parseLogLine(lines[i])
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
			rec, err := acl_loadOpRecord(idx)
			if err != nil {
				fmt.Printf("[dry-run] step %d: load manifest %d: %v\n", k+1, idx, err)
				continue
			}
			fmt.Printf("[dry-run] step %d: %s %s\n", k+1, rec.Op, acl_summarizeOp(rec))
		}
		return 0
	}

	acl_ensurePrivileges()

	okCount, failCount := 0, 0
	for k, idx := range targets {
		rec, err := acl_loadOpRecord(idx)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[rollback] step %d: load manifest %d: %v\n", k+1, idx, err)
			failCount++
			continue
		}
		fmt.Fprintf(os.Stderr, "[rollback] step %d: %s %s\n", k+1, rec.Op, acl_summarizeOp(rec))
		if err := acl_rollbackOne(rec); err != nil {
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

func acl_rollbackOne(rec *acl_opRecord) error {
	if rec.Backup == "" {
		return fmt.Errorf("no SDDL backup recorded")
	}
	if rec.Path == "" {
		return fmt.Errorf("no target path recorded")
	}
	return acl_restoreSDDL(rec.Backup, strings.HasSuffix(rec.Backup, ".gz"), rec.Path)
}

// ============================================================================
// Help
// ============================================================================

func acl_printHelp() {
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
  Requires SeRestorePrivilege / SeTakeOwnershipPrivilege; the tool tries
  to enable them automatically if the process token holds them.

ADD-ACE
  Adds or replaces an ACE for <trustee> on <path>.
    <access> can be: read | write | execute | full | <hex mask>
    --deny         create a deny ACE instead of allow
    --recursive    mark the new ACE as inheritable by future children
                   (OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE).
                   IMPORTANT: this does NOT modify existing children.
                   Walking the tree and updating every existing child
                   DACL is slow and prone to partial-failure states that
                   are hard to roll back, so aclctl deliberately does not
                   do it.

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

func acl_consumeGlobalFlags(args []string) (rest []string, outPath string, err error) {
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

func acl_setupOutput(path string) error {
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
// acl_main
// ============================================================================

func acl_main() {
	args, outPath, err := acl_consumeGlobalFlags(os.Args[1:])
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
		acl_finalExit(0, false)
	}
	if len(args) == 0 || has(args, "-h", "--help") {
		acl_printHelp()
		acl_finalExit(0, false)
	}
	if has(args, "--history") {
		acl_finalExit(acl_cmdHistory(), false)
	}
	if has(args, "--rollback") {
		acl_finalExit(acl_cmdRollback(acl_stripFlag(args, "--rollback")), false)
	}

	if outPath != "" {
		if err := acl_setupOutput(outPath); err != nil {
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
			acl_finalExit(2, true)
		}
		path := rest[0]
		jsonOut := has(rest, "--json")
		if dryRun {
			fmt.Printf("[dry-run] would show ACL of %s\n", path)
			acl_finalExit(0, false)
		}
		acl_finalExit(acl_cmdShow(path, jsonOut), true)

	case "set-owner":
		if len(rest) < 2 {
			fmt.Fprintln(os.Stderr, "usage: aclctl set-owner <path> <user|group> [-y]")
			acl_finalExit(2, true)
		}
		path, owner := rest[0], rest[1]
		yes := has(rest, "-y", "--yes")
		if dryRun {
			fmt.Printf("[dry-run] would change owner of %s to %s\n", path, owner)
			acl_finalExit(0, false)
		}
		acl_finalExit(acl_cmdSetOwner(path, owner, yes), true)

	case "add-ace":
		if len(rest) < 3 {
			fmt.Fprintln(os.Stderr, "usage: aclctl add-ace <path> <trustee> <access> [--deny] [--recursive] [-y]")
			acl_finalExit(2, true)
		}
		path, trustee, access := rest[0], rest[1], rest[2]
		deny := has(rest, "--deny")
		recursive := has(rest, "--recursive")
		yes := has(rest, "-y", "--yes")
		if dryRun {
			fmt.Printf("[dry-run] would add %s ACE for %s on %s (inheritable=%v)\n",
				access, trustee, path, recursive)
			acl_finalExit(0, false)
		}
		acl_finalExit(acl_cmdAddACE(path, trustee, access, deny, recursive, yes), true)

	default:
		fmt.Fprintf(os.Stderr, "aclctl: unknown command %q\n", cmd)
		acl_finalExit(2, true)
	}
}

func acl_stripFlag(args []string, flag string) []string {
	out := make([]string, 0, len(args))
	for _, a := range args {
		if a != flag {
			out = append(out, a)
		}
	}
	return out
}

func acl_finalExit(code int, logIt bool) {
	if logIt && !dryRun && acl_shouldLogRun() {
		acl_appendLogLine(buildCmdLine(os.Args), code)
	}
	bugs.Flush()
	if outputCleanup != nil {
		outputCleanup()
		outputCleanup = nil
	}
	os.Exit(code)
}

func acl_shouldLogRun() bool {
	for _, a := range os.Args[1:] {
		switch a {
		case "-h", "--help", "--version", "--history", "--rollback", "--dry-run":
			return false
		}
	}
	return true
}
// ==================== bkp ====================
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

// ============================================================================
// Colors / Console / Bug collector
// ============================================================================

// (shared with the rest of the toolkit)

// ============================================================================
// Win32 / Advapi32 bindings
// ============================================================================

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

const (
	bkp_SC_MANAGER_ALL_ACCESS = 0xF003F
	bkp_SERVICE_ALL_ACCESS    = 0xF01FF
	bkp_SERVICE_QUERY_CONFIG  = 0x0001
	bkp_SERVICE_CHANGE_CONFIG = 0x0002
	bkp_SERVICE_QUERY_STATUS  = 0x0004
	bkp_SERVICE_NO_CHANGE     = 0xFFFFFFFF

	bkp_SERVICE_STOPPED          = 0x00000001
	bkp_SERVICE_START_PENDING    = 0x00000002
	bkp_SERVICE_STOP_PENDING     = 0x00000003
	bkp_SERVICE_RUNNING          = 0x00000004
	bkp_SERVICE_CONTINUE_PENDING = 0x00000005
	bkp_SERVICE_PAUSE_PENDING    = 0x00000006
	bkp_SERVICE_PAUSED           = 0x00000007

	bkp_SERVICE_CONTROL_STOP     = 0x00000001
	bkp_SERVICE_CONTROL_PAUSE    = 0x00000002
	bkp_SERVICE_CONTROL_CONTINUE = 0x00000003

	bkp_SERVICE_BOOT_START   = 0x00000000
	bkp_SERVICE_SYSTEM_START = 0x00000001
	bkp_SERVICE_AUTO_START   = 0x00000002
	bkp_SERVICE_DEMAND_START = 0x00000003
	bkp_SERVICE_DISABLED     = 0x00000004

	bkp_ERROR_SERVICE_ALREADY_RUNNING = syscall.Errno(1056)
	bkp_ERROR_SERVICE_NOT_ACTIVE      = syscall.Errno(1062)
	bkp_ERROR_SERVICE_DISABLED        = syscall.Errno(1058)
)

// ============================================================================
// Paths
// ============================================================================

const (
	bkp_logDirName   = "backupctl_backup"
	bkp_logFileName  = "backupctl.log"
	bkp_opsDirName   = "ops"
	bkp_archivedName = "backup_archived"
	bkp_backupPrefix = "backup"
)

func bkp_logRoot() string { return filepath.Join(exeDir(), bkp_logDirName) }
func bkp_logPath() string { return filepath.Join(bkp_logRoot(), bkp_logFileName) }
func bkp_opsDir() string  { return filepath.Join(bkp_logRoot(), bkp_opsDirName) }

func bkp_backupRoot() string { return exeDir() }
func bkp_backupDir(id string) string {
	return filepath.Join(bkp_backupRoot(), id)
}

func bkp_archivedRoot() string { return filepath.Join(exeDir(), bkp_archivedName) }

func bkp_countLogLines() int {
	f, err := os.Open(bkp_logPath())
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

func bkp_readLogLines() ([]string, error) {
	data, err := os.ReadFile(bkp_logPath())
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

func bkp_appendLogLine(cmd string, code int) {
	_ = os.MkdirAll(bkp_logRoot(), 0755)
	f, err := os.OpenFile(bkp_logPath(), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		bugs.Add("ERR", "open log: %v", err)
		return
	}
	defer f.Close()
	ts := time.Now().Format("2006-01-02 15:04:05")
	_, _ = fmt.Fprintf(f, "[%s] [%s] [%d]\n", cmd, ts, code)
}

// ============================================================================
// Operation manifest
// ============================================================================

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

func bkp_saveOpRecord(idx int, rec *bkp_opRecord) {
	_ = os.MkdirAll(bkp_opsDir(), 0755)
	p := filepath.Join(bkp_opsDir(), fmt.Sprintf("%d.json", idx))
	data, err := json.MarshalIndent(rec, "", "  ")
	if err != nil {
		bugs.Add("ERR", "marshal op: %v", err)
		return
	}
	if err := os.WriteFile(p, data, 0644); err != nil {
		bugs.Add("ERR", "write op %s: %v", p, err)
	}
}

func bkp_loadOpRecord(idx int) (*bkp_opRecord, error) {
	data, err := os.ReadFile(filepath.Join(bkp_opsDir(), fmt.Sprintf("%d.json", idx)))
	if err != nil {
		return nil, err
	}
	var rec bkp_opRecord
	if err := json.Unmarshal(data, &rec); err != nil {
		return nil, err
	}
	return &rec, nil
}

func bkp_manifestExists(idx int) bool {
	_, err := os.Stat(filepath.Join(bkp_opsDir(), fmt.Sprintf("%d.json", idx)))
	return err == nil
}

func bkp_beginWriteOp() int {
	_ = os.MkdirAll(bkp_logRoot(), 0755)
	_ = os.MkdirAll(bkp_opsDir(), 0755)
	return bkp_countLogLines()
}

// ============================================================================
// Backup types and manifest
// ============================================================================

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

func bkp_newBackupID() string {
	base := bkp_backupPrefix + time.Now().Format("20060102_150405")
	if _, err := os.Stat(filepath.Join(bkp_backupRoot(), base)); err == nil {
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

func bkp_backupExists(id string) bool {
	_, err := os.Stat(filepath.Join(bkp_backupDir(id), "manifest.json"))
	return err == nil
}

func bkp_isBackupDirName(name string) bool {
	if !strings.HasPrefix(name, bkp_backupPrefix) {
		return false
	}
	if name == bkp_archivedName {
		return false
	}
	rest := strings.TrimPrefix(name, bkp_backupPrefix)
	return len(rest) >= 15 && rest[8] == '_'
}

// ============================================================================
// Compression helpers
// ============================================================================

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

// bkp_tarGzDir tars and gzips srcDir into dst.
//
// BUGFIX: the walk callback used to open each file and immediately
// `defer f.Close()`. defers only run when the callback returns, so for a
// directory with thousands of files the function accumulated thousands of
// pending defers — and hence thousands of open file descriptors — until
// the whole walk completed. The fix closes each file explicitly after
// io.Copy returns.
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
		// Close immediately rather than deferring; see the function-level
		// comment for why.
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

// ============================================================================
// Registry export / import
// ============================================================================

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

// ============================================================================
// Service helpers
// ============================================================================

type bkp_svcSnapshot struct {
	Name        string `json:"name"`
	DisplayName string `json:"displayName"`
	StartType   uint32 `json:"startType"`
	State       uint32 `json:"state"`
	BinaryPath  string `json:"binaryPath"`
}

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

// bkp_snapshotService captures a service's start type and state.
//
// BUGFIX: the second QueryServiceConfigW call used to ignore its return
// value. When the call failed (e.g. the service was deleted between
// OpenService and QueryServiceConfig, or the buffer was too small) the
// subsequent read of cfg.BinaryPathName dereferenced uninitialised
// memory. We now check both calls and return a clear error.
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
		ServiceType             uint32
		CurrentState            uint32
		ControlsAccepted        uint32
		Win32ExitCode           uint32
		ServiceSpecificExitCode uint32
		CheckPoint              uint32
		WaitHint                uint32
	}
	bkp_pQueryServiceStatus.Call(uintptr(h), uintptr(unsafe.Pointer(&st)))

	var needed uint32
	bkp_pQueryServiceConfigW.Call(uintptr(h), 0, 0, uintptr(unsafe.Pointer(&needed)))
	if needed == 0 {
		return nil, fmt.Errorf("QueryServiceConfig: cannot determine size")
	}
	buf := make([]byte, needed)
	r, _, callErr := bkp_pQueryServiceConfigW.Call(uintptr(h),
		uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)),
		uintptr(unsafe.Pointer(&needed)))
	if r == 0 {
		return nil, fmt.Errorf("QueryServiceConfig(%s): %w", name, callErr)
	}

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
	snap := &bkp_svcSnapshot{
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
		ServiceType             uint32
		CurrentState            uint32
		ControlsAccepted        uint32
		Win32ExitCode           uint32
		ServiceSpecificExitCode uint32
		CheckPoint              uint32
		WaitHint                uint32
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

// ============================================================================
// Scheduled task helpers
// ============================================================================

func bkp_schtasksPath() string {
	return filepath.Join(os.Getenv("SystemRoot"), "System32", "schtasks.exe")
}

func bkp_exportTaskXML(name string) ([]byte, error) {
	cmd := exec.Command(bkp_schtasksPath(), "/query", "/tn", name, "/xml")
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

	cmd := exec.Command(bkp_schtasksPath(), "/create", "/tn", name, "/xml", tmpPath, "/f")
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	var errBuf bytes.Buffer
	cmd.Stderr = &errBuf
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("schtasks /create: %s", strings.TrimSpace(errBuf.String()))
	}
	return nil
}

func bkp_listTaskNames() ([]string, error) {
	cmd := exec.Command(bkp_schtasksPath(), "/query", "/fo", "csv", "/nh")
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

// ============================================================================
// Backup core
// ============================================================================

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
			it.Stored = rel
			it.Compressed = false
			return nil
		}
		rel := filepath.Join("files", base+".gz")
		if err := bkp_gzipFileTo(it.Src, filepath.Join(baseDir, rel)); err != nil {
			return err
		}
		it.Stored = rel
		it.Compressed = true
		return nil

	case "dir":
		base := fmt.Sprintf("%d_%s", idx, bkp_sanitize(filepath.Base(it.Src)))
		rel := filepath.Join("files", base+".tar.gz")
		if err := bkp_tarGzDir(it.Src, filepath.Join(baseDir, rel)); err != nil {
			return err
		}
		it.Stored = rel
		it.Compressed = true
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
		if err := bkp_gzipFileTo(tmp, filepath.Join(baseDir, rel)); err != nil {
			return err
		}
		os.Remove(tmp)
		it.Stored = rel
		it.Compressed = true
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
			it.Stored = rel
			it.Compressed = false
			return nil
		}
		rel = rel + ".gz"
		if err := bkp_gzipBytes(data, filepath.Join(baseDir, rel)); err != nil {
			return err
		}
		it.Stored = rel
		it.Compressed = true
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
			it.Stored = rel
			it.Compressed = false
			return nil
		}
		rel = rel + ".gz"
		if err := bkp_gzipBytes(data, filepath.Join(baseDir, rel)); err != nil {
			return err
		}
		it.Stored = rel
		it.Compressed = true
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

// ============================================================================
// Restore core
// ============================================================================

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
			tmp, err := os.CreateTemp("", "backupctl_reg_*.reg")
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
			tmp, cerr := os.CreateTemp("", "backupctl_svc_*.json")
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
			tmp, cerr := os.CreateTemp("", "backupctl_task_*.xml")
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

// bkp_preBackupForRestore snapshots the current state of every item in
// target. The returned manifest is written BEFORE any state is changed,
// so a failed restore can be undone by `--rollback`.
//
// Note: the function returns preID even on error so the caller can
// identify and clean up the half-written backup directory.
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
		ID:      preID,
		Created: time.Now(),
		Command: "pre-restore backup for " + target.ID,
		Items:   items,
	}
	if err := bkp_writeManifest(base, pm); err != nil {
		return preID, err
	}
	return preID, nil
}

// ============================================================================
// Backup command
// ============================================================================

func bkp_cmdBackup(args []string) int {
	var items []bkp_BackupItem
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
			items = append(items, bkp_BackupItem{Kind: "file", Src: args[i+1]})
			i += 2
		case "--dir":
			if i+1 >= len(args) {
				fmt.Fprintln(os.Stderr, "backup: --dir requires a path")
				return 2
			}
			items = append(items, bkp_BackupItem{Kind: "dir", Src: args[i+1]})
			i += 2
		case "--reg":
			if i+1 >= len(args) {
				fmt.Fprintln(os.Stderr, "backup: --reg requires a key")
				return 2
			}
			items = append(items, bkp_BackupItem{Kind: "registry", Src: args[i+1]})
			i += 2
		case "--svc":
			if i+1 >= len(args) {
				fmt.Fprintln(os.Stderr, "backup: --svc requires a name")
				return 2
			}
			items = append(items, bkp_BackupItem{Kind: "service", Src: args[i+1]})
			i += 2
		case "--task":
			if i+1 >= len(args) {
				fmt.Fprintln(os.Stderr, "backup: --task requires a name")
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
			fmt.Fprintf(os.Stderr, "backup: unexpected argument %q\n", a)
			return 2
		}
	}

	// BUGFIX: enumerating thousands of services/tasks in a single
	// `backup` command can take a minute; tell the user what is
	// happening before the silent enumeration begins.
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
		fmt.Printf("[dry-run] target directory: %s\n",
			filepath.Join(bkp_backupRoot(), bkp_backupPrefix+"<YYYYMMDD_HHMMSS>"))
		return 0
	}

	id := bkp_newBackupID()
	base, err := bkp_makeBackupDir(id)
	if err != nil {
		fmt.Fprintf(os.Stderr, "backup: create dir: %v\n", err)
		return 5
	}

	opIdx := bkp_beginWriteOp()
	rec := &bkp_opRecord{
		Op:       "backup",
		TS:       time.Now().Format("2006-01-02 15:04:05"),
		Cmd:      buildCmdLine(os.Args),
		BackupID: id,
		Items:    valid,
	}

	// BUGFIX: only successful items go into the manifest. The old code
	// mutated valid[i] in place and still wrote the whole slice, so a
	// failed item ended up in manifest.json with Stored="" and
	// Compressed=true, which made any later `restore` of that backup
	// fail trying to read an empty path.
	succeeded := 0
	var successful []bkp_BackupItem
	for i := range valid {
		it := valid[i]
		if err := bkp_backupOneItem(base, i, &it); err != nil {
			fmt.Fprintf(os.Stderr, "backup: %s %q: %v\n", it.Kind, it.Src, err)
			bugs.Add("WARN", "backup item %q: %v", it.Src, err)
			continue
		}
		succeeded++
		successful = append(successful, it)
		fmt.Printf("%s %-8s %s -> %s\n",
			c(clrGreen, "saved"), it.Kind, it.Src, c(clrGray, it.Stored))
	}

	if succeeded == 0 {
		fmt.Fprintf(os.Stderr, "backup: all %d item(s) failed\n", len(valid))
		// Clean up the empty backup directory so it does not clutter
		// `backupctl list` with a useless entry.
		_ = os.RemoveAll(base)
		return 2
	}

	m := &bkp_BackupManifest{
		ID:      id,
		Created: time.Now(),
		Command: buildCmdLine(os.Args),
		Items:   successful,
	}
	if err := bkp_writeManifest(base, m); err != nil {
		fmt.Fprintf(os.Stderr, "backup: write manifest: %v\n", err)
		return 5
	}
	rec.Items = successful
	bkp_saveOpRecord(opIdx, rec)
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

	entries, err := os.ReadDir(bkp_backupRoot())
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
		if !bkp_isBackupDirName(name) {
			continue
		}
		dir := filepath.Join(bkp_backupRoot(), name)
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
	fmt.Fprintf(os.Stderr, "\n%d backup(s) in %s\n", len(rows), bkp_backupRoot())
	return 0
}
// ============================================================================
// Restore command
// ============================================================================

func bkp_cmdRestore(args []string) int {
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
		fmt.Printf("[dry-run] would first snapshot current state to a new backup\n")
		for _, it := range m.Items {
			fmt.Printf("[dry-run]   restore %-8s %s\n", it.Kind, it.Src)
		}
		return 0
	}

	// BUGFIX: warn (but do not abort) when a source file is missing. The
	// actual restoreOneItem call will report the error item by item; this
	// pre-check gives the user a single warning up front rather than a
	// long list of partial failures that might look like data loss.
	for _, it := range m.Items {
		stored := filepath.Join(dir, it.Stored)
		if _, err := os.Stat(stored); err != nil {
			fmt.Fprintf(os.Stderr, "restore: warning: stored file %q is missing (%v)\n", it.Stored, err)
		}
	}

	preID, err := bkp_preBackupForRestore(m)
	if err != nil {
		// BUGFIX: clean up the half-written pre-backup directory so a
		// subsequent `list` does not show a broken, un-restorable entry.
		_ = os.RemoveAll(bkp_backupDir(preID))
		fmt.Fprintf(os.Stderr, "restore: pre-backup: %v\n", err)
		return 5
	}
	fmt.Printf("%s %s\n", c(clrCyan, "pre-backup:"), preID)

	opIdx := bkp_beginWriteOp()
	rec := &bkp_opRecord{
		Op:             "restore",
		TS:             time.Now().Format("2006-01-02 15:04:05"),
		Cmd:            buildCmdLine(os.Args),
		TargetBackupID: id,
		PreBackupID:    preID,
		Items:          m.Items,
	}

	succeeded, failed := 0, 0
	for _, it := range m.Items {
		if err := bkp_restoreOneItem(dir, it); err != nil {
			fmt.Fprintf(os.Stderr, "restore: %s %s: %v\n", it.Kind, it.Src, err)
			bugs.Add("WARN", "restore %s %s: %v", it.Kind, it.Src, err)
			failed++
			continue
		}
		fmt.Printf("%s %-8s %s\n", c(clrGreen, "restored"), it.Kind, it.Src)
		succeeded++
	}
	bkp_saveOpRecord(opIdx, rec)

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

	entries, err := os.ReadDir(bkp_backupRoot())
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
		name := e.Name()
		if !bkp_isBackupDirName(name) {
			continue
		}
		dir := filepath.Join(bkp_backupRoot(), name)
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

	opIdx := bkp_beginWriteOp()
	rec := &bkp_opRecord{
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

		if err := os.MkdirAll(bkp_archivedRoot(), 0755); err != nil {
			fmt.Fprintf(os.Stderr, "clean: create archive dir: %v\n", err)
			failCount++
			continue
		}
		if cand.size < bkp_smallThreshold {
			dst := filepath.Join(bkp_archivedRoot(), cand.id)
			// BUGFIX: os.Rename fails with EXDEV (ERROR_NOT_SAME_DEVICE)
			// when src and dst are on different volumes. bkp_archivedRoot
			// lives next to bkp_backupRoot, so this normally cannot
			// happen, but if the executable directory is a symlink or a
			// junction into another volume, EXDEV is real. Fall back to
			// a recursive copy followed by RemoveAll.
			if err := os.Rename(cand.dir, dst); err != nil {
				if copyErr := bkp_copyDirRecursive(cand.dir, dst); copyErr != nil {
					fmt.Fprintf(os.Stderr, "clean: archive %s: rename: %v; copy: %v\n",
						cand.id, err, copyErr)
					failCount++
					continue
				}
				if rmErr := os.RemoveAll(cand.dir); rmErr != nil {
					fmt.Fprintf(os.Stderr, "clean: archive %s: remove src: %v\n", cand.id, rmErr)
					failCount++
					continue
				}
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

	bkp_saveOpRecord(opIdx, rec)
	if failCount == 0 {
		return 0
	}
	if okCount == 0 {
		return 2
	}
	return 1
}

// bkp_copyDirRecursive copies src into dst, creating dst if necessary.
// It is used as a fallback for os.Rename when src and dst are on
// different volumes (EXDEV).
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

// ============================================================================
// History / rollback
// ============================================================================

func bkp_cmdHistory() int {
	lines, err := bkp_readLogLines()
	if err != nil {
		fmt.Fprintf(os.Stderr, "read log %s: %v\n", bkp_logPath(), err)
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
		if !bkp_manifestExists(i) {
			continue
		}
		cmd, _ := bkp_parseLogLine(lines[i])
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
		if rec, err := bkp_loadOpRecord(e.idx); err == nil {
			desc = bkp_summarizeOp(rec)
		}
		fmt.Printf("[%d] %s %s\n", k+1, e.line, c(clrGray, desc))
	}
	fmt.Fprintf(os.Stderr, "\n%d rollback-able operation(s). Log: %s\n", len(entries), bkp_logPath())
	return 0
}

func bkp_parseLogLine(line string) (cmd string, ok bool) {
	m := logRe.FindStringSubmatch(line)
	if m == nil {
		return "", false
	}
	return m[1], true
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

func bkp_cmdRollback(args []string) int {
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

	lines, err := bkp_readLogLines()
	if err != nil {
		fmt.Fprintf(os.Stderr, "read log: %v\n", err)
		return 4
	}
	var targets []int
	for i := len(lines) - 1; i >= 0 && len(targets) < n; i-- {
		if !bkp_manifestExists(i) {
			continue
		}
		cmd, _ := bkp_parseLogLine(lines[i])
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
			rec, err := bkp_loadOpRecord(idx)
			if err != nil {
				fmt.Printf("[dry-run] step %d: load manifest %d: %v\n", k+1, idx, err)
				continue
			}
			fmt.Printf("[dry-run] step %d: %s %s\n", k+1, rec.Op, bkp_summarizeOp(rec))
		}
		return 0
	}

	okCount, failCount := 0, 0
	for k, idx := range targets {
		rec, err := bkp_loadOpRecord(idx)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[rollback] step %d: load manifest %d: %v\n", k+1, idx, err)
			failCount++
			continue
		}
		fmt.Fprintf(os.Stderr, "[rollback] step %d: %s %s\n", k+1, rec.Op, bkp_summarizeOp(rec))
		if err := bkp_rollbackOne(rec); err != nil {
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
				// Mirror the EXDEV fallback from bkp_cmdClean.
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
				if err := os.Remove(largePath); err != nil {
					// Not fatal: the live backup directory is already
					// restored; the tar.gz is just a leftover.
					bugs.Add("WARN", "rollback clean: remove %s: %v", largePath, err)
				}
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
// Help
// ============================================================================

func bkp_printHelp() {
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
  Only items that actually succeeded are written to manifest.json. If
  every item fails, the empty backup directory is removed automatically.

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
  When os.Rename fails because backup/ and backup_archived/ are on
  different volumes (EXDEV), the move is performed as a recursive copy
  followed by RemoveAll of the source.
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

func bkp_consumeGlobalFlags(args []string) (rest []string, outPath string, err error) {
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

func bkp_setupOutput(path string) error {
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
// bkp_main
// ============================================================================

func bkp_main() {
	args, outPath, err := bkp_consumeGlobalFlags(os.Args[1:])
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
		bkp_finalExit(0, false)
	}
	if len(args) == 0 || has(args, "-h", "--help") {
		bkp_printHelp()
		bkp_finalExit(0, false)
	}

	// BUGFIX: apply -o/--out BEFORE handling --history / --rollback, so
	// that `backupctl --history -o foo.txt` writes to foo.txt (the same
	// rule every other module in the toolkit follows).
	if outPath != "" {
		if err := bkp_setupOutput(outPath); err != nil {
			fmt.Fprintf(os.Stderr, "backupctl: %v\n", err)
			bugs.Flush()
			os.Exit(2)
		}
	}

	if has(args, "--history") {
		bkp_finalExit(bkp_cmdHistory(), false)
	}
	if has(args, "--rollback") {
		bkp_finalExit(bkp_cmdRollback(bkp_stripFlags(args, "--rollback")), false)
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
		bkp_finalExit(2, true)
	}
	cmd := args[cmdIdx]
	rest := append([]string{}, args[:cmdIdx]...)
	rest = append(rest, args[cmdIdx+1:]...)

	var code int
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
		fmt.Fprintf(os.Stderr, "backupctl: unknown command %q\n", cmd)
		code = 2
	}
	bkp_finalExit(code, true)
}

func bkp_stripFlags(args []string, flags ...string) []string {
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

func bkp_finalExit(code int, logIt bool) {
	if logIt && !dryRun && bkp_shouldLogRun() {
		bkp_appendLogLine(buildCmdLine(os.Args), code)
	}
	bugs.Flush()
	if outputCleanup != nil {
		outputCleanup()
		outputCleanup = nil
	}
	os.Exit(code)
}

func bkp_shouldLogRun() bool {
	for _, a := range os.Args[1:] {
		switch a {
		case "-h", "--help", "--version", "--history", "--rollback", "--dry-run":
			return false
		}
	}
	return true
}
// ==================== disk ====================
// diskvolctl — Disk and volume read-only viewer.
// Single-file, standard-library-only build:
//
//   go build -trimpath -ldflags "-s -w" -o diskvolctl.exe diskvolctl.go
//
// Log: ./diskvolctl_backup/diskvolctl.log  [cmd] [ts] [exit code]

// ============================================================================
// Win32 bindings
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

// ============================================================================
// Windows structures
// ============================================================================

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

// disk_PARTITION_INFORMATION_EX mirrors PARTITION_INFORMATION_EX.
//
// On amd64:
//
//	PartitionStyle     4  (offset 0)
//	[padding]          4  (offset 4)
//	StartingOffset     8  (offset 8)
//	PartitionLength    8  (offset 16)
//	PartitionNumber    4  (offset 24)
//	RewritePartition   1  (offset 28)
//	IsServicePartition 1  (offset 29)
//	[padding]          2  (offset 30)
//	Union            112  (offset 32)  // sizeof(PARTITION_INFORMATION_GPT)
//	                         total = 144
//
// BUGFIX: the previous code declared Union as [144]byte, which made
// unsafe.Sizeof return 176. Windows actually returns 144 bytes per
// partition; iterating with a 176-byte stride read partition 2 and
// beyond from the wrong offset and produced garbage or missed partitions.
type disk_PARTITION_INFORMATION_EX struct {
	PartitionStyle     uint32
	StartingOffset     int64
	PartitionLength    int64
	PartitionNumber    uint32
	RewritePartition   byte
	IsServicePartition byte
	Union              [112]byte
}

// ============================================================================
// Data model
// ============================================================================

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

// ============================================================================
// Win32 helpers
// ============================================================================

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

	disk_PropertyStandardQuery = 0

	disk_BusTypeUnknown           = 0
	disk_BusTypeScsi              = 1
	disk_BusTypeAtapi             = 2
	disk_BusTypeAta               = 3
	disk_BusType1394              = 4
	disk_BusTypeSsa               = 5
	disk_BusTypeFibre             = 6
	disk_BusTypeUsb               = 7
	disk_BusTypeRAID              = 8
	disk_BusTypeiScsi             = 9
	disk_BusTypeSas               = 10
	disk_BusTypeSata              = 11
	disk_BusTypeSd                = 12
	disk_BusTypeMmc               = 13
	disk_BusTypeVirtual           = 14
	disk_BusTypeFileBackedVirtual = 15
	disk_BusTypeSpaces            = 16
	disk_BusTypeNvme              = 17
	disk_BusTypeSCM               = 18
	disk_BusTypeUfs               = 19
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
		0,
		uintptr(disk_OPEN_EXISTING),
		0,
		0,
	)
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
		uintptr(h),
		uintptr(code),
		inPtr,
		uintptr(len(inBuf)),
		outPtr,
		uintptr(len(outBuf)),
		uintptr(unsafe.Pointer(&returned)),
		0,
	)
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
	switch t {
	case disk_BusTypeUnknown:
		return "unknown"
	case disk_BusTypeScsi:
		return "SCSI"
	case disk_BusTypeAtapi:
		return "ATAPI"
	case disk_BusTypeAta:
		return "ATA"
	case disk_BusType1394:
		return "1394"
	case disk_BusTypeSsa:
		return "SSA"
	case disk_BusTypeFibre:
		return "Fibre"
	case disk_BusTypeUsb:
		return "USB"
	case disk_BusTypeRAID:
		return "RAID"
	case disk_BusTypeiScsi:
		return "iSCSI"
	case disk_BusTypeSas:
		return "SAS"
	case disk_BusTypeSata:
		return "SATA"
	case disk_BusTypeSd:
		return "SD"
	case disk_BusTypeMmc:
		return "MMC"
	case disk_BusTypeVirtual:
		return "Virtual"
	case disk_BusTypeFileBackedVirtual:
		return "FileBackedVirtual"
	case disk_BusTypeSpaces:
		return "StorageSpaces"
	case disk_BusTypeNvme:
		return "NVMe"
	case disk_BusTypeSCM:
		return "SCM"
	case disk_BusTypeUfs:
		return "UFS"
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

// ============================================================================
// Disk enumeration
// ============================================================================

func disk_queryDiskInfo(index uint32) disk_DiskInfo {
	di := disk_DiskInfo{Index: index}

	path := fmt.Sprintf(`\\.\PhysicalDrive%d`, index)
	h, err := disk_openDevice(path)
	if err != nil {
		di.Error = err.Error()
		return di
	}
	defer pCloseHandle.Call(uintptr(h))

	// --- Device descriptor ---
	query := disk_STORAGE_PROPERTY_QUERY{
		PropertyId: disk_StorageDeviceProperty,
		QueryType:  disk_PropertyStandardQuery,
	}
	buf := make([]byte, 1024)
	n, err := disk_deviceIoControl(h, disk_IOCTL_STORAGE_QUERY_PROPERTY,
		disk_storageQueryBytes(&query), buf)
	if err == nil && n > 0 {
		desc := (*disk_STORAGE_DEVICE_DESCRIPTOR)(unsafe.Pointer(&buf[0]))
		di.Vendor = disk_cStringAt(buf, desc.VendorIdOffset)
		di.Product = disk_cStringAt(buf, desc.ProductIdOffset)
		di.Revision = disk_cStringAt(buf, desc.ProductRevisionOffset)
		di.Serial = disk_cStringAt(buf, desc.SerialNumberOffset)
		di.BusType = disk_busTypeName(desc.BusType)
		di.Removable = desc.RemovableMedia != 0
	}

	// --- TRIM descriptor ---
	query.PropertyId = disk_StorageDeviceTrimProperty
	buf2 := make([]byte, 32)
	n, err = disk_deviceIoControl(h, disk_IOCTL_STORAGE_QUERY_PROPERTY,
		disk_storageQueryBytes(&query), buf2)
	if err == nil && n >= uint32(unsafe.Sizeof(disk_DEVICE_TRIM_DESCRIPTOR{})) {
		trim := (*disk_DEVICE_TRIM_DESCRIPTOR)(unsafe.Pointer(&buf2[0]))
		di.Trim = trim.TrimEnabled != 0
	}

	// --- Geometry (EX: includes DiskSize) ---
	// BUGFIX: use a fixed 40-byte minimum (24-byte DISK_GEOMETRY + 8-byte
	// DiskSize + 1 byte Data padded to 8-byte alignment) instead of
	// unsafe.Sizeof on the trailing [1]byte field, which works today but
	// is easy to break if the struct ever changes.
	geomBuf := make([]byte, 256)
	n, err = disk_deviceIoControl(h, disk_IOCTL_DISK_GET_DRIVE_GEOMETRY_EX, nil, geomBuf)
	if err == nil && n >= 40 {
		geom := (*disk_DISK_GEOMETRY_EX)(unsafe.Pointer(&geomBuf[0]))
		di.Size = geom.DiskSize
	}

	// --- Drive layout ---
	layoutBuf := make([]byte, 1024*1024)
	n, err = disk_deviceIoControl(h, disk_IOCTL_DISK_GET_DRIVE_LAYOUT_EX, nil, layoutBuf)
	if err == nil && n >= 8 {
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
					Number: part.PartitionNumber,
					Offset: part.StartingOffset,
					Length: part.PartitionLength,
					Style:  styleName,
				})
			}
			off += entrySize
		}
	}

	return di
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

// ============================================================================
// Volume enumeration
// ============================================================================

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
		volID := syscall.UTF16ToString(buf)
		volID = strings.TrimSuffix(volID, `\`)

		vi := disk_VolumeInfo{VolumeID: volID}
		disk_queryVolumeInfo(&vi)
		out = append(out, vi)

		buf = make([]uint16, 512)
		r, _, nextErr := disk_pFindNextVolumeW.Call(h, uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)))
		if r == 0 {
			// ERROR_NO_MORE_FILES is the normal end of enumeration.
			// Anything else is an actual error we want to report via
			// -b/--bugs. We do not distinguish them here beyond that.
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
		uintptr(len(pathBuf)),
		uintptr(unsafe.Pointer(&pathLen)),
	)
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
	r, _, _ := disk_pGetVolumeInformationW.Call(
		uintptr(unsafe.Pointer(disk_win32UTF16Ptr(root))),
		uintptr(unsafe.Pointer(&labelBuf[0])),
		uintptr(len(labelBuf)),
		uintptr(unsafe.Pointer(&serial)),
		uintptr(unsafe.Pointer(&maxComp)),
		uintptr(unsafe.Pointer(&fsFlags)),
		uintptr(unsafe.Pointer(&fsBuf[0])),
		uintptr(len(fsBuf)),
	)
	if r != 0 {
		vi.Label = syscall.UTF16ToString(labelBuf)
		vi.FileSystem = syscall.UTF16ToString(fsBuf)
	}

	if len(letters) > 0 {
		var free, total, avail uint64
		r, _, _ = disk_pGetDiskFreeSpaceExW.Call(
			uintptr(unsafe.Pointer(disk_win32UTF16Ptr(letters[0]+`\`))),
			uintptr(unsafe.Pointer(&free)),
			uintptr(unsafe.Pointer(&total)),
			uintptr(unsafe.Pointer(&avail)),
		)
		if r != 0 {
			vi.TotalBytes = total
			vi.FreeBytes = free
		}
	}

	if len(letters) > 0 {
		dt, _, _ := disk_pGetDriveTypeW.Call(uintptr(unsafe.Pointer(disk_win32UTF16Ptr(letters[0]+`\`))))
		vi.DriveType = disk_driveTypeName(uint32(dt))
	}
}

// ============================================================================
// Output formatting
// ============================================================================

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
				fmt.Printf("      #%d  %s  offset=%s\n",
					p.Number, humanBytes(uint64(p.Length)), humanBytes(uint64(p.Offset)))
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

// ============================================================================
// Log
// ============================================================================

const (
	disk_backupDirName = "diskvolctl_backup"
	disk_logFileName   = "diskvolctl.log"
)

func disk_logRoot() string { return filepath.Join(exeDir(), disk_backupDirName) }
func disk_logPath() string { return filepath.Join(disk_logRoot(), disk_logFileName) }

func disk_readLogLines() ([]string, error) {
	data, err := os.ReadFile(disk_logPath())
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

func disk_appendLogLine(cmd string, code int) {
	_ = os.MkdirAll(disk_logRoot(), 0755)
	f, err := os.OpenFile(disk_logPath(), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		bugs.Add("ERR", "open log: %v", err)
		return
	}
	defer f.Close()
	ts := time.Now().Format("2006-01-02 15:04:05")
	_, _ = fmt.Fprintf(f, "[%s] [%s] [%d]\n", cmd, ts, code)
}

// ============================================================================
// History / rollback
// ============================================================================

func disk_cmdHistory() int {
	lines, err := disk_readLogLines()
	if err != nil {
		fmt.Fprintf(os.Stderr, "read log %s: %v\n", disk_logPath(), err)
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
	fmt.Fprintf(os.Stderr, "\n%d entrie(s). Log: %s\n", len(lines), disk_logPath())
	return 0
}

func disk_cmdRollback() int {
	fmt.Fprintln(os.Stderr, "diskvolctl is read-only: there are no operations to roll back")
	fmt.Fprintln(os.Stderr, "  diskvolctl only reads disk and volume metadata.")
	fmt.Fprintln(os.Stderr, "  Its history is for audit only; use --history to view it.")
	return 0
}

// ============================================================================
// Help
// ============================================================================

func disk_printHelp() {
	header := "diskvolctl v1.0.0 (Windows)"
	fmt.Println(c(clrBold+clrCyan, header))
	fmt.Println("Disk and volume read-only viewer")
	fmt.Println()
	fmt.Print(`USAGE
  diskvolctl                 list disks and volumes
  diskvolctl disks           disks only
  diskvolctl volumes         volumes only
  diskvolctl --json          JSON output
  diskvolctl --history
  diskvolctl --rollback      (always a no-op: read-only)

OPTIONS
  --json           Machine-readable JSON output
  -o, --out <path> Redirect stdout to a file
  --dry-run        Print the plan without touching any device
  --no-color       Disable ANSI colors (also honors NO_COLOR)
  -b, --bugs       Print collected errors/warnings on exit
  -h, --help       Show this help
  --version        Show version

DISKS
  For each physical drive:
    - Size, vendor, product, revision, serial number
    - Bus type (SATA, NVMe, USB, Virtual, ...)
    - Removable flag
    - TRIM support (DEVICE_TRIM_DESCRIPTOR)
    - Partition count, each partition's offset and length

VOLUMES
  For each volume:
    - Volume ID (\\?\Volume{...}\)
    - Drive letters (C:, D:, ...)
    - Label, file system (NTFS, exFAT, FAT32, ...)
    - Drive type (fixed, removable, cdrom, ...)
    - Total size, free space, used percentage

READ-ONLY BY DESIGN
  diskvolctl never writes to any disk or volume. The only file it writes
  is its own audit log.

EXIT CODES
  0 success | 1 partial failure | 2 bad args | 3 permission denied
  4 not found | 5 I/O error
`)
}

// ============================================================================
// Global flag consumption
// ============================================================================

func disk_consumeGlobalFlags(args []string) (rest []string, outPath string, err error) {
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

func disk_setupOutput(path string) error {
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
// disk_main
// ============================================================================

func disk_main() {
	args, outPath, err := disk_consumeGlobalFlags(os.Args[1:])
	if err != nil {
		fmt.Fprintf(os.Stderr, "diskvolctl: %v\n", err)
		bugs.Flush()
		os.Exit(2)
	}

	if noColorFlag || os.Getenv("NO_COLOR") != "" {
		useColor = false
	} else if stdoutIsTTY() {
		useColor = true
	}

	if has(args, "--version") {
		fmt.Println("diskvolctl v1.0.0")
		disk_finalExit(0, false)
	}
	if len(args) == 0 {
		// default action: list everything
	} else if has(args, "-h", "--help") {
		disk_printHelp()
		disk_finalExit(0, false)
	} else if has(args, "--history") {
		disk_finalExit(disk_cmdHistory(), false)
	} else if has(args, "--rollback") {
		disk_finalExit(disk_cmdRollback(), false)
	} else if has(args, "disks") || has(args, "volumes") || has(args, "--json") {
		// valid: handled below
	} else {
		fmt.Fprintf(os.Stderr, "diskvolctl: unexpected argument %q (use -h for help)\n", args[0])
		disk_finalExit(2, true)
	}

	if outPath != "" {
		if err := disk_setupOutput(outPath); err != nil {
			fmt.Fprintf(os.Stderr, "diskvolctl: %v\n", err)
			bugs.Flush()
			os.Exit(2)
		}
	}

	if dryRun {
		fmt.Println("[dry-run] would enumerate physical disks and volumes")
		disk_finalExit(0, false)
	}

	showDisks := true
	showVolumes := true
	jsonOut := false
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
				// Not-found means we've run past the last drive.
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
		_ = enc.Encode(map[string]any{
			"disks":   disks,
			"volumes": vols,
		})
	} else {
		if showDisks && len(disks) > 0 {
			disk_printDisks(disks)
		}
		if showVolumes && len(vols) > 0 {
			disk_printVolumes(vols)
		}
	}

	disk_finalExit(0, true)
}

func disk_finalExit(code int, logIt bool) {
	if logIt && !dryRun && disk_shouldLogRun() {
		disk_appendLogLine(buildCmdLine(os.Args), code)
	}
	bugs.Flush()
	if outputCleanup != nil {
		outputCleanup()
		outputCleanup = nil
	}
	os.Exit(code)
}

func disk_shouldLogRun() bool {
	for _, a := range os.Args[1:] {
		switch a {
		case "-h", "--help", "--version", "--history", "--rollback", "--dry-run":
			return false
		}
	}
	return true
}

// ==================== doc ====================
// doctor — Environment diagnostics (read-only).
// Single-file, standard-library-only build:
//
//   go build -trimpath -ldflags "-s -w" -o doctor.exe doctor.go
//
// Log: ./doctor_backup/doctor.log  [cmd] [ts] [exit code]

// ============================================================================
// doc module state
// ============================================================================

var (
	doc_reportMode = false
)

// ============================================================================
// Win32 bindings
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

// ============================================================================
// Windows structures
// ============================================================================

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

	doc_HKEY_LOCAL_MACHINE = uintptr(0xFFFFFFFF80000002)
)

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

// ============================================================================
// Registry helpers
// ============================================================================

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

type doc_CheckResult struct {
	Category string `json:"category"`
	Name     string `json:"name"`
	Status   string `json:"status"` // ok | warn | error | info
	Value    string `json:"value"`
	Detail   string `json:"detail,omitempty"`
}

// ----------------------------------------------------------------------------
// OS version
// ----------------------------------------------------------------------------

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
	defer syscall.CloseHandle(token)
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
	// BUGFIX: cp == 0 does not mean "ansi"; it means the API failed or
	// returned 0 (which Windows itself treats as an error). Reporting it
	// as "ansi" was misleading.
	if cp == 0 {
		return "unknown"
	}
	switch cp {
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

// doc_titleCase uppercases the first ASCII letter of s.
//
// BUGFIX: Go 1.18 deprecated strings.Title, and the replacement
// (golang.org/x/text/cases) would add an external dependency that the
// project avoids. This tiny helper is all we need for the category
// headers ("System", "Security", ...).
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

// ----------------------------------------------------------------------------
// Exe-relative paths
// ----------------------------------------------------------------------------

func doc_exePath() string {
	if e, err := os.Executable(); err == nil {
		return e
	}
	return "doctor.exe"
}

// ----------------------------------------------------------------------------
// Backup directory writability
// ----------------------------------------------------------------------------

// doc_backupDirNames is every tool's log directory. They all live next
// to the executable.
//
// BUGFIX: the previous list was missing regctl_backup, sysfixctl_backup,
// aclctl_backup, diskvolctl_backup, and hashsigctl_backup, so `doctor`
// silently skipped them.
var doc_backupDirNames = []string{
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
	"regctl_backup",
	"sysfixctl_backup",
	"aclctl_backup",
	"diskvolctl_backup",
	"hashsigctl_backup",
}

// doc_isDirWritable tries to create and delete a test file inside dir.
// If dir does not exist yet, it checks dir's parent directory instead,
// because that is what we would need in order to create it.
func doc_isDirWritable(dir string) (bool, string) {
	probe := dir
	if fi, err := os.Stat(dir); err != nil {
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

// BUGFIX: the previous list was missing regctl.exe, sysfixctl.exe,
// aclctl.exe, diskvolctl.exe, and hashsigctl.exe.
var doc_expectedTools = []string{
	"procctl.exe",
	"fsctl.exe",
	"svcctl.exe",
	"taskctl.exe",
	"netctl.exe",
	"evtctl.exe",
	"openerctl.exe",
	"pectl.exe",
	"backupctl.exe",
	"regctl.exe",
	"sysfixctl.exe",
	"aclctl.exe",
	"diskvolctl.exe",
	"hashsigctl.exe",
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
	t := doc_toolInfo{
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

// ----------------------------------------------------------------------------
// Run all checks
// ----------------------------------------------------------------------------

func doc_runChecks() []doc_CheckResult {
	var results []doc_CheckResult
	exe := exeDir()

	// --- System ---
	winName, winVer, winBuild, winOK := doc_osVersionInfo()
	if winOK {
		results = append(results, doc_CheckResult{
			Category: "system", Name: "Windows",
			Status: "ok",
			Value:  fmt.Sprintf("%s (%s, build %d)", winName, winVer, winBuild),
		})
	} else {
		results = append(results, doc_CheckResult{
			Category: "system", Name: "Windows",
			Status: "error", Value: "RtlGetVersion failed",
		})
	}

	sysArch, cpus := doc_systemInfo()
	results = append(results, doc_CheckResult{
		Category: "system", Name: "System arch",
		Status: "ok", Value: fmt.Sprintf("%s, %d logical CPU(s)", sysArch, cpus),
	})

	ptrSize := int(unsafe.Sizeof(uintptr(0)))
	processArch := runtime.GOARCH
	if ptrSize != 8 {
		results = append(results, doc_CheckResult{
			Category: "system", Name: "Process arch",
			Status: "warn",
			Value:  fmt.Sprintf("%s (%d-bit pointer)", processArch, ptrSize*8),
			Detail: "this binary is supposed to be 64-bit; something is wrong with the build",
		})
	} else {
		results = append(results, doc_CheckResult{
			Category: "system", Name: "Process arch",
			Status: "ok",
			Value:  fmt.Sprintf("%s (64-bit, %d-byte pointers)", processArch, ptrSize),
		})
	}

	// --- Security ---
	if doc_isAdmin() {
		results = append(results, doc_CheckResult{
			Category: "security", Name: "Admin rights",
			Status: "ok", Value: "yes (elevated)",
		})
	} else {
		results = append(results, doc_CheckResult{
			Category: "security", Name: "Admin rights",
			Status: "info",
			Value:  "no (running as standard user)",
			Detail: "operations that touch HKLM, services, or system tasks will need elevation",
		})
	}

	// --- Encoding ---
	acpRaw, _, _ := doc_pGetACP.Call()
	acp := uint32(acpRaw)
	oemRaw, _, _ := doc_pGetOEMCP.Call()
	oem := uint32(oemRaw)
	outCPRaw, _, _ := doc_pGetConsoleOutputCP.Call()
	outCP := uint32(outCPRaw)

	results = append(results, doc_CheckResult{
		Category: "encoding", Name: "Console output CP",
		Status: "ok", Value: fmt.Sprintf("%d (%s)", outCP, doc_cpName(outCP)),
	})
	results = append(results, doc_CheckResult{
		Category: "encoding", Name: "ANSI code page",
		Status: "ok", Value: fmt.Sprintf("%d (%s)", acp, doc_cpName(acp)),
	})
	results = append(results, doc_CheckResult{
		Category: "encoding", Name: "OEM code page",
		Status: "ok", Value: fmt.Sprintf("%d (%s)", oem, doc_cpName(oem)),
	})
	if outCP != 65001 && outCP != acp {
		results = append(results, doc_CheckResult{
			Category: "encoding", Name: "Encoding note",
			Status: "info",
			Value:  "console output CP differs from ACP",
			Detail: "some tools may need chcp 65001 before printing non-ASCII",
		})
	}

	// --- Long paths ---
	if v, ok := doc_regReadDWORD(doc_HKEY_LOCAL_MACHINE,
		`SYSTEM\CurrentControlSet\Control\FileSystem`, "LongPathsEnabled"); ok {
		if v != 0 {
			results = append(results, doc_CheckResult{
				Category: "system", Name: "Long paths",
				Status: "ok", Value: "enabled (LongPathsEnabled=1)",
			})
		} else {
			results = append(results, doc_CheckResult{
				Category: "system", Name: "Long paths",
				Status: "warn", Value: "disabled (LongPathsEnabled=0)",
				Detail: "paths longer than MAX_PATH will fail; enable with: reg add HKLM\\SYSTEM\\CurrentControlSet\\Control\\FileSystem /v LongPathsEnabled /t REG_DWORD /d 1 /f",
			})
		}
	} else {
		results = append(results, doc_CheckResult{
			Category: "system", Name: "Long paths",
			Status: "warn", Value: "not configured (LongPathsEnabled missing)",
			Detail: "treat as disabled; paths longer than MAX_PATH will fail",
		})
	}

	// --- Backup directories ---
	for _, name := range doc_backupDirNames {
		dir := filepath.Join(exe, name)
		writable, why := doc_isDirWritable(dir)
		if writable {
			results = append(results, doc_CheckResult{
				Category: "backup", Name: name,
				Status: "ok", Value: dir,
			})
		} else {
			results = append(results, doc_CheckResult{
				Category: "backup", Name: name,
				Status: "error", Value: dir,
				Detail: why,
			})
		}
	}

	// --- Tools ---
	curExe := strings.ToLower(filepath.Base(doc_exePath()))
	for _, name := range doc_expectedTools {
		if strings.ToLower(name) == curExe {
			continue
		}
		t := doc_checkTool(exe, name)
		switch {
		case !t.Exists:
			results = append(results, doc_CheckResult{
				Category: "tools", Name: t.Name,
				Status: "warn", Value: "missing",
				Detail: t.Path,
			})
		case t.Error != "":
			results = append(results, doc_CheckResult{
				Category: "tools", Name: t.Name,
				Status: "error",
				Value:  fmt.Sprintf("%d bytes", t.Size),
				Detail: t.Error,
			})
		case !t.ValidPE:
			results = append(results, doc_CheckResult{
				Category: "tools", Name: t.Name,
				Status: "error",
				Value:  "not a valid PE",
				Detail: t.Path,
			})
		case t.Bits != "64-bit":
			results = append(results, doc_CheckResult{
				Category: "tools", Name: t.Name,
				Status: "error",
				Value:  fmt.Sprintf("%s (%s), %s", t.Bits, t.Machine, humanBytes(uint64(t.Size))),
				Detail: "expected a 64-bit executable",
			})
		default:
			results = append(results, doc_CheckResult{
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

func doc_statusLabel(status string) string {
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

func doc_statusColor(status string) string {
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

func doc_printInteractive(results []doc_CheckResult) {
	fmt.Println()
	fmt.Println(c(clrBold+clrCyan, "════════════════════════════════════════════════════════════════"))
	fmt.Println(c(clrBold+clrCyan, "  doctor v1.0.0 — Windows Environment Diagnostics"))
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
				c(doc_statusColor(r.Status), labelPad),
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

func doc_printReport(results []doc_CheckResult) {
	fmt.Println("================================================================")
	fmt.Println("doctor v1.0.0 - Windows Environment Diagnostics")
	fmt.Println("Generated: " + time.Now().Format("2006-01-02 15:04:05"))
	fmt.Println("================================================================")

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
	fmt.Printf("Summary: %d check(s), %d warning(s), %d error(s)\n",
		len(results), warns, errors)
	fmt.Println("----------------------------------------------------------------")
}

func doc_printJSON(results []doc_CheckResult) {
	b, _ := json.MarshalIndent(results, "", "  ")
	fmt.Println(string(b))
}

// ============================================================================
// Logging
// ============================================================================

const (
	doc_backupDirName = "doctor_backup"
	doc_logFileName   = "doctor.log"
)

func doc_logRoot() string { return filepath.Join(exeDir(), doc_backupDirName) }
func doc_logPath() string { return filepath.Join(doc_logRoot(), doc_logFileName) }

func doc_readLogLines() ([]string, error) {
	data, err := os.ReadFile(doc_logPath())
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

func doc_appendLogLine(cmd string, code int) {
	_ = os.MkdirAll(doc_logRoot(), 0755)
	f, err := os.OpenFile(doc_logPath(), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		bugs.Add("ERR", "open log: %v", err)
		return
	}
	defer f.Close()
	ts := time.Now().Format("2006-01-02 15:04:05")
	_, _ = fmt.Fprintf(f, "[%s] [%s] [%d]\n", cmd, ts, code)
}

// ============================================================================
// --history / --rollback
// ============================================================================

func doc_cmdHistory() int {
	lines, err := doc_readLogLines()
	if err != nil {
		fmt.Fprintf(os.Stderr, "read log %s: %v\n", doc_logPath(), err)
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
	fmt.Fprintf(os.Stderr, "\n%d entrie(s). Log: %s\n", len(lines), doc_logPath())
	return 0
}

func doc_cmdRollback() int {
	fmt.Fprintln(os.Stderr, "doctor is read-only: there are no operations to roll back")
	fmt.Fprintln(os.Stderr, "  doctor only inspects the environment and prints a report.")
	fmt.Fprintln(os.Stderr, "  Its history is for audit only; use --history to view it.")
	return 0
}

// ============================================================================
// Help
// ============================================================================

func doc_printHelp() {
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
    For every sibling tool's log directory (procctl_backup, fsctl_backup,
    svcctl_backup, taskctl_backup, netctl_backup, evtctl_backup,
    openerctl_backup, pectl_backup, backupctl_backup, doctor_backup,
    regctl_backup, sysfixctl_backup, aclctl_backup, diskvolctl_backup,
    hashsigctl_backup):
      exists, is a directory, and is writable
    If a directory does not exist yet, its parent directory is probed
    instead, because that is what would need to be writable to create it.

  [Tools]
    Every expected sibling executable next to doctor.exe:
      procctl.exe fsctl.exe svcctl.exe taskctl.exe netctl.exe
      evtctl.exe openerctl.exe pectl.exe backupctl.exe
      regctl.exe sysfixctl.exe aclctl.exe diskvolctl.exe
      hashsigctl.exe
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

func doc_consumeGlobalFlags(args []string) (rest []string, outPath string, err error) {
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
			doc_reportMode = true
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

func doc_setupOutput(path string) error {
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
// doc_main
// ============================================================================

func doc_main() {
	args, outPath, err := doc_consumeGlobalFlags(os.Args[1:])
	if err != nil {
		fmt.Fprintf(os.Stderr, "doctor: %v\n", err)
		bugs.Flush()
		os.Exit(2)
	}

	if noColorFlag || os.Getenv("NO_COLOR") != "" || doc_reportMode {
		useColor = false
	} else if stdoutIsTTY() {
		useColor = true
	}

	if has(args, "--version") {
		fmt.Println("doctor v1.0.0")
		doc_finalExit(0, false)
	}
	if len(args) == 0 {
		// default action: run checks
	} else if has(args, "-h", "--help") {
		doc_printHelp()
		doc_finalExit(0, false)
	} else if has(args, "--history") {
		doc_finalExit(doc_cmdHistory(), false)
	} else if has(args, "--rollback") {
		doc_finalExit(doc_cmdRollback(), false)
	} else if has(args, "--json") {
		// valid: handled below
	} else {
		fmt.Fprintf(os.Stderr, "doctor: unexpected argument %q (use -h for help)\n", args[0])
		doc_finalExit(2, true)
	}

	if outPath != "" {
		if err := doc_setupOutput(outPath); err != nil {
			fmt.Fprintf(os.Stderr, "doctor: %v\n", err)
			bugs.Flush()
			os.Exit(2)
		}
	}

	if dryRun {
		fmt.Printf("[dry-run] would run %d backup-dir probes\n", len(doc_backupDirNames))
		fmt.Printf("[dry-run] would check %d sibling executables\n", len(doc_expectedTools))
		fmt.Printf("[dry-run] would query OS version, encoding, long paths, and admin rights\n")
		doc_finalExit(0, false)
	}

	results := doc_runChecks()

	if doc_reportMode {
		doc_printReport(results)
	} else if has(args, "--json") {
		doc_printJSON(results)
	} else {
		doc_printInteractive(results)
	}

	// Exit code: 1 if any errors, otherwise 0. Warnings do not fail the run.
	exitCode := 0
	for _, r := range results {
		if r.Status == "error" {
			exitCode = 1
			break
		}
	}
	doc_finalExit(exitCode, true)
}

func doc_finalExit(code int, logIt bool) {
	if logIt && !dryRun && doc_shouldLogRun() {
		doc_appendLogLine(buildCmdLine(os.Args), code)
	}
	bugs.Flush()
	if outputCleanup != nil {
		outputCleanup()
		outputCleanup = nil
	}
	os.Exit(code)
}

func doc_shouldLogRun() bool {
	for _, a := range os.Args[1:] {
		switch a {
		case "-h", "--help", "--version", "--history", "--rollback", "--dry-run":
			return false
		}
	}
	return true
}
// ==================== evt ====================
// evtctl — Windows Event Log query tool (read-only).
// Single-file, standard-library-only build:
//
//   go build -trimpath -ldflags "-s -w" -o evtctl.exe evtctl.go
//
// Log: ./evtctl_backup/evtctl.log  [cmd] [ts] [exit code]

// ============================================================================
// Colors / Console / Bug collector
// ============================================================================

// (shared with the rest of the toolkit)

// ============================================================================
// evt_wevtapi.dll bindings
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
	evt_EvtQueryChannelPath      = 0x1
	evt_EvtQueryForwardDirection = 0x100
	evt_EvtQueryReverseDirection = 0x200

	evt_EvtRenderEventXml = 1

	evt_EvtFormatMessageEvent = 1

	evt_ERROR_INSUFFICIENT_BUFFER = syscall.Errno(122)
)

func evt_initAPIs() error {
	for name, proc := range map[string]*syscall.LazyProc{
		"EvtQuery":         evt_pEvtQuery,
		"EvtNext":          evt_pEvtNext,
		"EvtRender":        evt_pEvtRender,
		"EvtFormatMessage": evt_pEvtFormatMessage,
		"EvtClose":         evt_pEvtClose,
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

// evt_evtRenderXML renders an event as XML.
//
// EvtRender's BufferSize / BufferUsed are in BYTES, so a []uint16 buffer
// of (bytes+1)/2 elements is correct. BUGFIX: the previous version used
// needed/2, which lost 1 byte when needed was odd — a rare but real
// possibility for events whose XML length is an odd number of UTF-16 code
// units times 2. That made EvtRender keep returning
// ERROR_INSUFFICIENT_BUFFER and the loop gave up after 3 attempts.
func evt_evtRenderXML(evt uintptr) (string, error) {
	var needed, propCount uint32
	evt_pEvtRender.Call(0, evt, uintptr(evt_EvtRenderEventXml),
		0, 0,
		uintptr(unsafe.Pointer(&needed)), uintptr(unsafe.Pointer(&propCount)))
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

// evt_evtFormatMessage resolves the human-readable message for an event.
//
// EvtFormatMessage's BufferSize / BufferUsed are in CHARACTERS (WCHARs), so
// we allocate that many uint16 elements and pass the same count as
// BufferSize. This is the correct unit, unlike EvtRender which uses bytes.
//
// If the API fails, there are two cases:
//
//   - used > size: the buffer grew between the probe and the call; retry
//     with the new size (up to 3 attempts).
//   - used == 0: no usable output. Return an empty string; the caller
//     (evt_effectiveMessage) falls back to EventData.
//   - 0 < used <= size: partial render (some parameters could not be
//     substituted). The template itself is still useful, so return what
//     was filled in.
func evt_evtFormatMessage(evt uintptr) string {
	var needed uint32
	evt_pEvtFormatMessage.Call(0, evt, 0, 0, 0,
		uintptr(evt_EvtFormatMessageEvent), 0, 0,
		uintptr(unsafe.Pointer(&needed)))
	if needed == 0 {
		return ""
	}

	for attempt := 0; attempt < 3; attempt++ {
		buf := make([]uint16, needed)
		size := uint32(len(buf))
		used := size
		r, _, _ := evt_pEvtFormatMessage.Call(0, evt, 0, 0, 0,
			uintptr(evt_EvtFormatMessageEvent), uintptr(size),
			uintptr(unsafe.Pointer(&buf[0])),
			uintptr(unsafe.Pointer(&used)))
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

// ============================================================================
// XML event parsing
// ============================================================================

type evt_xmlEvent struct {
	XMLName   xml.Name        `xml:"Event"`
	System    evt_xmlSystem   `xml:"System"`
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

// ============================================================================
// Event record
// ============================================================================

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

// ============================================================================
// Time parsing
// ============================================================================

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

// evt_relTimeRe matches relative durations like "1h", "30m", "7d", "2w".
//
// BUGFIX: the previous version compiled this regexp on every call to
// evt_parseTimeArg, which was a minor performance issue for a loop like
// `evtctl --since 1h -c system -c application -c security`. Hoisted to
// package scope.
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
		"2006-01-02T15:04:05",
		"2006-01-02T15:04",
		"2006-01-02 15:04:05",
		"2006-01-02 15:04",
		"2006-01-02",
		"2006/01/02 15:04:05",
		"2006/01/02",
	} {
		if t, err := time.ParseInLocation(layout, s, time.Local); err == nil {
			return t, nil
		}
	}
	return time.Time{}, fmt.Errorf("unrecognized time %q", s)
}

// ============================================================================
// XPath construction
// ============================================================================

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

// ============================================================================
// Query execution
// ============================================================================

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
				fmt.Fprintf(os.Stderr, "evtctl: %s: access denied (try running as administrator)\n", ch)
			} else {
				fmt.Fprintf(os.Stderr, "evtctl: %v\n", err)
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

// ============================================================================
// Output formatting
// ============================================================================

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
	Time      string              `json:"time"`
	Level     string              `json:"level"`
	EventID   uint32              `json:"eventId"`
	Source    string              `json:"source"`
	Channel   string              `json:"channel"`
	Computer  string              `json:"computer"`
	Message   string              `json:"message"`
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

// ============================================================================
// Paths and log
// ============================================================================

const (
	evt_backupDirName = "evtctl_backup"
	evt_logFileName   = "evtctl.log"
)

func evt_backupRoot() string { return filepath.Join(exeDir(), evt_backupDirName) }
func evt_logPath() string    { return filepath.Join(evt_backupRoot(), evt_logFileName) }

func evt_readLogLines() ([]string, error) {
	data, err := os.ReadFile(evt_logPath())
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

func evt_appendLogLine(cmd string, code int) {
	_ = os.MkdirAll(evt_backupRoot(), 0755)
	f, err := os.OpenFile(evt_logPath(), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		bugs.Add("ERR", "open log: %v", err)
		return
	}
	defer f.Close()
	ts := time.Now().Format("2006-01-02 15:04:05")
	_, _ = fmt.Fprintf(f, "[%s] [%s] [%d]\n", cmd, ts, code)
}

// ============================================================================
// --history / --rollback
// ============================================================================

func evt_cmdHistory() int {
	lines, err := evt_readLogLines()
	if err != nil {
		fmt.Fprintf(os.Stderr, "read log %s: %v\n", evt_logPath(), err)
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
	fmt.Fprintf(os.Stderr, "\n%d entrie(s). Log: %s\n", len(lines), evt_logPath())
	return 0
}

func evt_cmdRollback(_ []string) int {
	fmt.Fprintln(os.Stderr, "evtctl is read-only: there are no operations to roll back")
	fmt.Fprintln(os.Stderr, "  evtctl only reads event logs and exports them.")
	fmt.Fprintln(os.Stderr, "  Its history is for audit only; use --history to view it.")
	return 0
}

// ============================================================================
// Help
// ============================================================================

func evt_printHelp() {
	header := "evtctl v1.0.0 (Windows)"
	fmt.Println(c(clrBold+clrCyan, header))
	fmt.Println("Windows Event Log query tool (read-only) - query / filter / export")
	fmt.Println()
	fmt.Print(`USAGE
  evtctl query [OPTIONS]            (query is the default; may be omitted)
  evtctl [OPTIONS]
  evtctl --history
  evtctl --rollback                 (always a no-op: evtctl is read-only)

QUERY OPTIONS
  -c, --channel <name>      Event log channel to query. May be repeated.
                            Defaults to system and application.
                            Available (common):
                              system
                              application
                              security       (requires administrator)
                              setup
                            Use "-c all" to select system, application,
                            and security. Duplicate channels (after
                            case-folding) are silently merged.
  -l, --level <level>       Severity: critical | error | warning | info |
                            verbose | <0-5>. May be repeated or
                            comma-separated. Example: -l error,warning
  -e, --event-id <N>        Only events with this event ID
  -p, --provider <name>     Only events with this provider/source name
  --since <time>            Only events at or after <time>. Accepts:
                              relative: 1h 30m 7d 2w
                              absolute: 2024-01-01 / 2024-01-01T12:00:00
                              shortcuts: now, today, yesterday
  --until <time>            Only events at or before <time>
  --last <duration>         Alias for --since <duration>
  -n, --max <N>             Stop after N events total (default 100; 0 = all)
  --newest                  Newest events first (default)
  --oldest                  Oldest events first
  --json                    JSON output
  -o, --out <path>          Write output to a file

GLOBAL
  --dry-run                 Print the XPath query and the channels that would
                            be queried; do not open the event log; do not
                            write to history.
  --no-color                Disable ANSI colors (also honors NO_COLOR).
  -b, --bugs                Print collected errors/warnings on exit.
  -h, --help                Show this help.
  --version                 Show version.

HISTORY
  Every query invocation (successful or not) appends one line to
    ./evtctl_backup/evtctl.log
  in the format:
    [command line] [timestamp] [exit code]

  --history prints the log, numbered from newest (1) to oldest.

READ-ONLY BY DESIGN
  evtctl does not modify the event log, the registry, or the filesystem
  (apart from the log file above). --rollback therefore has nothing to
  undo and simply reports that fact.

EXIT CODES
  0 success | 1 partial failure | 2 bad args | 3 permission denied
  4 not found | 5 Windows API / I/O error
`)
}

// ============================================================================
// Global flag consumption
// ============================================================================

func evt_consumeGlobalFlags(args []string) (rest []string, outPath string, err error) {
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

func evt_setupOutput(path string) error {
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
// Query argument parsing
// ============================================================================

var evt_defaultChannels = []string{"System", "Application"}

var evt_channelAliases = map[string]string{
	"system":      "System",
	"application": "Application",
	"security":    "Security",
	"setup":       "Setup",
}

// evt_parseQueryArgs turns "query" subcommand arguments into an evt_queryOpts.
//
// BUGFIX: the previous implementation appended the whole "-c" argument
// string `cr` to opts.channels when a channel part was not in the alias
// map. For "-c Foo,Bar" with both parts unknown, that produced TWO entries
// of "Foo,Bar" — a channel name that does not exist — and EvtQuery failed
// with a confusing error. We now append the individual, trimmed channel
// name (`trimmed`) and preserve the user's original case.
//
// Channels are also deduplicated (case-insensitively) at the end so that
// "-c system -c system" queries the channel only once.
func evt_parseQueryArgs(args []string) (*evt_queryOpts, error) {
	opts := &evt_queryOpts{
		max:    100,
		newest: true,
	}

	var channelsRaw []string
	levelsRaw := []string{}

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
				// Unknown channel: pass the user-typed name through
				// unchanged (so custom operational channels keep their
				// case). BUGFIX: this used to append `cr` (the entire
				// "-c" argument) instead of the individual part.
				opts.channels = append(opts.channels, trimmed)
			}
		}
	}

	// Deduplicate channels case-insensitively. Users sometimes run
	// "evtctl -c system -c System" by mistake.
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

// ============================================================================
// evt_main
// ============================================================================

func evt_main() {
	if err := evt_initAPIs(); err != nil {
		fmt.Fprintf(os.Stderr, "evtctl: %v\n", err)
		os.Exit(5)
	}

	args, outPath, err := evt_consumeGlobalFlags(os.Args[1:])
	if err != nil {
		fmt.Fprintf(os.Stderr, "evtctl: %v\n", err)
		bugs.Flush()
		os.Exit(2)
	}

	if noColorFlag || os.Getenv("NO_COLOR") != "" {
		useColor = false
	} else if stdoutIsTTY() {
		useColor = true
	}

	// BUGFIX: route --version and --help through evt_finalExit so that
	// -b/--bugs is flushed consistently, matching every other module.
	if has(args, "--version") {
		fmt.Println("evtctl v1.0.0")
		evt_finalExit(0, false)
	}
	if len(args) == 0 || has(args, "-h", "--help") {
		evt_printHelp()
		evt_finalExit(0, false)
	}
	if has(args, "--history") {
		evt_finalExit(evt_cmdHistory(), false)
	}
	if has(args, "--rollback") {
		evt_finalExit(evt_cmdRollback(nil), false)
	}

	if len(args) > 0 && args[0] == "query" {
		args = args[1:]
	}

	opts, err := evt_parseQueryArgs(args)
	if err != nil {
		fmt.Fprintf(os.Stderr, "evtctl: %v\n", err)
		bugs.Flush()
		os.Exit(2)
	}

	if outPath != "" {
		if err := evt_setupOutput(outPath); err != nil {
			fmt.Fprintf(os.Stderr, "evtctl: %v\n", err)
			bugs.Flush()
			os.Exit(2)
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

	evt_finalExit(code, true)
}

func evt_finalExit(code int, logIt bool) {
	if logIt && !dryRun && evt_shouldLogRun() {
		evt_appendLogLine(buildCmdLine(os.Args), code)
	}
	bugs.Flush()
	if outputCleanup != nil {
		outputCleanup()
		outputCleanup = nil
	}
	os.Exit(code)
}

func evt_shouldLogRun() bool {
	for _, a := range os.Args[1:] {
		switch a {
		case "-h", "--help", "--version", "--history", "--rollback", "--dry-run":
			return false
		}
	}
	return true
}
// ==================== fs ====================
// fsctl — File and text basics for Windows with per-operation backup and
// inverse rollback. Build (single file, no external deps):
//
//   go build -trimpath -ldflags "-s -w" -o fsctl.exe fsctl.go
//
// Log:    ./fsctl_backup/fsctl.log          [cmd] [ts] [code]
// Ops:    ./fsctl_backup/ops/<logIndex>.json
// Files:  ./fsctl_backup/files/<logIndex>/<seq>_<name>[.gz|.tar.gz]

// ============================================================================
// Colors / TTY / Bug collector
// ============================================================================

// (shared with the rest of the toolkit)

var (
	// fs_expandEnabled controls whether mkdir/touch/rm expand {..} and [..]
	// patterns in their path arguments. It can be turned off with
	// --no-expand, which is useful when a literal file name contains
	// braces or brackets.
	fs_expandEnabled = true
)

// ============================================================================
// Paths and log
// ============================================================================

const (
	fs_backupDirName = "fsctl_backup"
	fs_logFileName   = "fsctl.log"
	fs_opsDirName    = "ops"
	fs_filesDirName  = "files"
)

func fs_backupRoot() string { return filepath.Join(exeDir(), fs_backupDirName) }
func fs_logPath() string    { return filepath.Join(fs_backupRoot(), fs_logFileName) }
func fs_opsDir() string     { return filepath.Join(fs_backupRoot(), fs_opsDirName) }
func fs_filesDir() string   { return filepath.Join(fs_backupRoot(), fs_filesDirName) }

func fs_countLogLines() int {
	f, err := os.Open(fs_logPath())
	if err != nil {
		return 0
	}
	defer f.Close()
	s := bufio.NewScanner(f)
	s.Buffer(make([]byte, 64*1024), 4*1024*1024)
	n := 0
	for s.Scan() {
		n++
	}
	return n
}

func fs_readLogLines() ([]string, error) {
	data, err := os.ReadFile(fs_logPath())
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

func fs_appendLogLine(cmd string, code int) {
	_ = os.MkdirAll(fs_backupRoot(), 0755)
	f, err := os.OpenFile(fs_logPath(), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		bugs.Add("ERR", "open log: %v", err)
		return
	}
	defer f.Close()
	ts := time.Now().Format("2006-01-02 15:04:05")
	if _, err := fmt.Fprintf(f, "[%s] [%s] [%d]\n", cmd, ts, code); err != nil {
		bugs.Add("ERR", "write log: %v", err)
	}
}

func fs_parseLogLine(line string) (cmd string, ts string, code int, ok bool) {
	if strings.HasPrefix(line, "【") {
		rest := strings.TrimPrefix(line, "【")
		idx := strings.Index(rest, "】 【")
		if idx < 0 {
			return "", "", 0, false
		}
		return rest[:idx], "", 0, true
	}
	m := logRe.FindStringSubmatch(line)
	if m == nil {
		return "", "", 0, false
	}
	code, _ = strconv.Atoi(m[3])
	return m[1], m[2], code, true
}

// fs_escapeArg quotes a single token per Windows CreateProcess rules.
//
// The implementation mirrors syscall.EscapeArg from the standard library
// but keeps the function local so fsctl does not depend on that helper's
// specifics.
func fs_escapeArg(a string) string {
	if a == "" {
		return `""`
	}
	needsQuote := false
	for _, r := range a {
		if r == ' ' || r == '\t' || r == '"' {
			needsQuote = true
			break
		}
	}
	if !needsQuote {
		return a
	}
	var b strings.Builder
	b.WriteByte('"')
	backslashes := 0
	for _, r := range a {
		switch r {
		case '\\':
			backslashes++
			b.WriteRune(r)
		case '"':
			for i := 0; i < backslashes*2+1; i++ {
				b.WriteByte('\\')
			}
			b.WriteRune(r)
			backslashes = 0
		default:
			backslashes = 0
			b.WriteRune(r)
		}
	}
	for i := 0; i < backslashes*2; i++ {
		b.WriteByte('\\')
	}
	b.WriteByte('"')
	return b.String()
}

// ============================================================================
// Operation manifest
// ============================================================================

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

func fs_saveOpRecord(idx int, rec *fs_opRecord) {
	_ = os.MkdirAll(fs_opsDir(), 0755)
	p := filepath.Join(fs_opsDir(), fmt.Sprintf("%d.json", idx))
	data, err := json.MarshalIndent(rec, "", "  ")
	if err != nil {
		bugs.Add("ERR", "marshal op: %v", err)
		return
	}
	if err := os.WriteFile(p, data, 0644); err != nil {
		bugs.Add("ERR", "write op %s: %v", p, err)
	}
}

func fs_loadOpRecord(idx int) (*fs_opRecord, error) {
	data, err := os.ReadFile(filepath.Join(fs_opsDir(), fmt.Sprintf("%d.json", idx)))
	if err != nil {
		return nil, err
	}
	var rec fs_opRecord
	if err := json.Unmarshal(data, &rec); err != nil {
		return nil, err
	}
	return &rec, nil
}

func fs_manifestExists(idx int) bool {
	_, err := os.Stat(filepath.Join(fs_opsDir(), fmt.Sprintf("%d.json", idx)))
	return err == nil
}

func fs_beginWriteOp() int {
	_ = os.MkdirAll(fs_backupRoot(), 0755)
	_ = os.MkdirAll(fs_opsDir(), 0755)
	_ = os.MkdirAll(fs_filesDir(), 0755)
	return fs_countLogLines()
}

// ============================================================================
// Backup files
// ============================================================================

// fs_compressedExt lists extensions whose content is already compressed.
// For these we copy the file verbatim instead of re-gzipping it, because
// gzip would only add ~30 bytes of framing overhead to already-compressed
// data.
var fs_compressedExt = map[string]bool{
	".gz": true, ".tgz": true, ".zip": true, ".rar": true, ".7z": true, ".bz2": true,
	".xz": true, ".zst": true, ".jpg": true, ".jpeg": true, ".png": true, ".gif": true,
	".webp": true, ".heic": true, ".mp3": true, ".mp4": true, ".avi": true, ".mkv": true,
	".mov": true, ".flac": true, ".m4a": true, ".pdf": true, ".docx": true, ".xlsx": true,
	".pptx": true, ".jar": true, ".apk": true, ".exe": true, ".dll": true, ".bin": true,
	".iso": true, ".cab": true, ".msi": true, ".woff2": true, ".br": true,
}

const fs_smallFileThreshold = 8192

// fs_backupPath copies (or gzips, or tars) src into
// ./fsctl_backup/files/<idx>/<seq>_<basename>[.gz|.tar.gz] and returns the
// relative path (under fs_filesDir) plus whether the stored file is
// compressed.
//
// BUGFIX / NOTES:
//
//   - filepath.Base("C:\\") on Windows returns "\\", which the original
//     guard already converts to "root". Kept.
//   - Symbolic links are NOT dereferenced here; os.Stat on a link returns
//     the target's FileInfo, so a dir symlink would be backed up as the
//     target directory. The callers that care (rm with -r) check the
//     link-ness explicitly before calling this function.
func fs_backupPath(src, idx string, seq int) (rel string, compressed bool, err error) {
	info, err := os.Stat(src)
	if err != nil {
		return "", false, err
	}
	base := filepath.Base(src)
	if base == "" || base == "." || base == string(filepath.Separator) {
		base = "root"
	}
	if info.IsDir() {
		rel = filepath.Join(idx, fmt.Sprintf("%d_%s.tar.gz", seq, base))
		if err = fs_tarGz(src, filepath.Join(fs_filesDir(), rel)); err != nil {
			return "", false, err
		}
		return rel, true, nil
	}
	ext := strings.ToLower(filepath.Ext(src))
	if fs_compressedExt[ext] || info.Size() < fs_smallFileThreshold {
		rel = filepath.Join(idx, fmt.Sprintf("%d_%s", seq, base))
		if err = fs_copyFile(src, filepath.Join(fs_filesDir(), rel)); err != nil {
			return "", false, err
		}
		return rel, false, nil
	}
	rel = filepath.Join(idx, fmt.Sprintf("%d_%s.gz", seq, base))
	if err = fs_gzipFile(src, filepath.Join(fs_filesDir(), rel)); err != nil {
		return "", false, err
	}
	return rel, true, nil
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

// fs_tarGz tars and gzips src into dst.
//
// The tar entry names are relative to filepath.Dir(src), so a tar of
// "C:\temp\mydir" contains "mydir/..." entries, and extracting with
// fs_untarGz back to "C:\temp" restores the tree exactly.
//
// BUGFIX: the walk callback used to call defer f.Close() inside the loop,
// which delayed every file close until the whole walk completed. For a
// directory with thousands of files that meant thousands of simultaneously
// open file descriptors. Each file is now closed immediately after its
// copy.
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

// fs_untarGz extracts src into baseDir.
//
// BUGFIX: reject tar entries whose name would escape baseDir (e.g. a
// crafted "../evil"). The tarballs fsctl creates never contain such
// names, but a user could restore a hand-edited tar and we should not
// write outside the target directory.
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
		// Sanity check the extracted path.
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

func fs_restoreFile(backupRel string, compressed bool, dst string) error {
	src := filepath.Join(fs_filesDir(), backupRel)
	if strings.HasSuffix(backupRel, ".tar.gz") {
		return fs_untarGz(src, filepath.Dir(dst))
	}
	if compressed || strings.HasSuffix(backupRel, ".gz") {
		return fs_gunzipFile(src, dst)
	}
	return fs_copyFile(src, dst)
}

// ============================================================================
// Filesystem helpers
// ============================================================================

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

// ============================================================================
// Pattern expansion
// ============================================================================

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

// ============================================================================
// Manifest payloads
// ============================================================================

type fs_cpData struct {
	Src        string `json:"src"`
	Dst        string `json:"dst"`
	DstExisted bool   `json:"dstExisted"`
	DstBackup  string `json:"dstBackup,omitempty"`
	Compressed bool   `json:"compressed,omitempty"`
	Recursive  bool   `json:"recursive,omitempty"`
}

type fs_mvData struct {
	Src           string `json:"src"`
	Dst           string `json:"dst"`
	DstExisted    bool   `json:"dstExisted"`
	DstBackup     string `json:"dstBackup,omitempty"`
	DstCompressed bool   `json:"dstCompressed,omitempty"`
}

type fs_rmItem struct {
	Path       string `json:"path"`
	Backup     string `json:"backup,omitempty"`
	Compressed bool   `json:"compressed,omitempty"`
	IsDir      bool   `json:"isDir"`
	Existed    bool   `json:"existed"`
}

type fs_rmData struct {
	Items []fs_rmItem `json:"items"`
}

type fs_repItem struct {
	Path       string `json:"path"`
	Backup     string `json:"backup,omitempty"`
	Compressed bool   `json:"compressed,omitempty"`
	Count      int    `json:"count"`
}

type fs_replaceMulti struct {
	Items []fs_repItem `json:"items"`
}

type fs_mkdirItem struct {
	Path    string `json:"path"`
	Existed bool   `json:"existed"`
}

type fs_mkdirData struct {
	Items []fs_mkdirItem `json:"items"`
}

type fs_touchItem struct {
	Path      string `json:"path"`
	Existed   bool   `json:"existed"`
	OrigMtime string `json:"origMtime,omitempty"`
}

type fs_touchData struct {
	Items []fs_touchItem `json:"items"`
}

// ============================================================================
// Rollback dispatch
// ============================================================================

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

// fs_rollbackCp restores the state of dst before the cp.
//
// BUGFIX: when DstExisted is false (dst did not exist before the cp), the
// inverse is to delete whatever is now at dst. The previous version did
// this unconditionally; but if the user created a new file at dst between
// the cp and the rollback, deleting it would silently destroy their work.
// We now print a warning first, so a human can intervene if the file
// looks suspicious.
func fs_rollbackCp(data json.RawMessage) error {
	var d fs_cpData
	if err := json.Unmarshal(data, &d); err != nil {
		return err
	}
	if d.DstExisted {
		return fs_restoreFile(d.DstBackup, d.Compressed, d.Dst)
	}
	if fs_exists(d.Dst) {
		fmt.Fprintf(os.Stderr, "[rollback cp] warning: deleting %s (created by the original cp; may have been modified since)\n", d.Dst)
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

// ============================================================================
// Flag helpers
// ============================================================================

// fs_getOpt returns the value following one of flags in args.
//
// BUGFIX: the previous implementation only understood "-x value" and
// "--x value". Every "--x=value" and "-x=value" was silently ignored, so
// `fsctl ls --out=foo.txt`, `fsctl head --lines=5`, and
// `fsctl xargs --max-args=10 ...` had no effect. We now accept both forms.
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
		isFlag := false
		isFlagEq := false
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

// ============================================================================
// stdin-aware readers
// ============================================================================

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
// ============================================================================
// ls
// ============================================================================

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

// ============================================================================
// cat
// ============================================================================

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
		if f == "-" {
			_, _ = io.Copy(os.Stdout, os.Stdin)
			continue
		}
		data, err := os.ReadFile(f)
		if err != nil {
			fmt.Fprintf(os.Stderr, "cat: %v\n", err)
			return 4
		}
		_, _ = os.Stdout.Write(data)
	}
	return 0
}

// ============================================================================
// cp
// ============================================================================

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
		fmt.Fprintln(os.Stderr, "usage: fsctl cp [-f] [-r] <src> <dst>")
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
	idx := fs_beginWriteOp()
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
	rec := &fs_opRecord{Op: "cp", TS: time.Now().Format("2006-01-02 15:04:05"), Cmd: buildCmdLine(os.Args), Data: fs_mustJSON(data)}
	if err := fs_copyFile(src, dst); err != nil {
		fs_saveOpRecord(idx, rec)
		fmt.Fprintf(os.Stderr, "cp: %v\n", err)
		return 5
	}
	fs_saveOpRecord(idx, rec)
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
	idx := fs_beginWriteOp()
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
	rec := &fs_opRecord{Op: "cp", TS: time.Now().Format("2006-01-02 15:04:05"), Cmd: buildCmdLine(os.Args), Data: fs_mustJSON(data)}
	if err := fs_copyDir(src, dst); err != nil {
		fs_saveOpRecord(idx, rec)
		fmt.Fprintf(os.Stderr, "cp: %v\n", err)
		return 5
	}
	fs_saveOpRecord(idx, rec)
	fmt.Printf("%s -> %s %s\n", c(clrCyan, src), c(clrGreen, dst), c(clrGray, "(recursive)"))
	return 0
}

// ============================================================================
// mv
// ============================================================================

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
		fmt.Fprintln(os.Stderr, "usage: fsctl mv [-f] <src> <dst>")
		return 2
	}
	return fs_doMv(rest[0], rest[1], force)
}

// fs_doMv moves src to dst.
//
// BUGFIX: the previous implementation removed dst (when it existed) BEFORE
// attempting the rename. If both os.Rename and the copy fallback failed,
// dst was gone for good — the user lost the pre-existing destination. We
// now move dst to a sidecar path first, restore it on failure, and only
// delete the sidecar once the actual move has succeeded.
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
	idx := fs_beginWriteOp()
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
	rec := &fs_opRecord{Op: "mv", TS: time.Now().Format("2006-01-02 15:04:05"), Cmd: buildCmdLine(os.Args), Data: fs_mustJSON(data)}

	// Move dst aside so we can restore it if the actual move fails.
	sidecar := ""
	if dstExisted {
		sidecar = dst + ".fsctl_mv_bak"
		_ = os.RemoveAll(sidecar) // stale leftover from a crashed run
		if err := os.Rename(dst, sidecar); err != nil {
			// If even moving dst aside fails, abort before touching src.
			fmt.Fprintf(os.Stderr, "mv: cannot set aside %s: %v\n", dst, err)
			return 5
		}
	}

	err = os.Rename(src, dst)
	if err != nil {
		// EXDEV or cross-volume: fall back to copy + remove.
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
		// Restore dst from sidecar.
		if sidecar != "" {
			_ = os.RemoveAll(dst)
			if rerr := os.Rename(sidecar, dst); rerr != nil {
				fmt.Fprintf(os.Stderr, "mv: warning: could not restore %s from %s: %v\n", dst, sidecar, rerr)
			}
		}
		fs_saveOpRecord(idx, rec)
		fmt.Fprintf(os.Stderr, "mv: %v\n", err)
		return 5
	}

	// Success. Remove the sidecar.
	if sidecar != "" {
		_ = os.RemoveAll(sidecar)
	}

	fs_saveOpRecord(idx, rec)
	fmt.Printf("%s -> %s\n", c(clrCyan, src), c(clrGreen, dst))
	return 0
}

// ============================================================================
// rm
// ============================================================================

// fs_cmdRm removes files and directories, backing them up first.
//
// BUGFIX: the -r check for "is a directory" used os.Stat, which follows
// symbolic links. A link pointing at a directory looked like a directory,
// so `fsctl rm -r link` tarred the *target* of the link into the backup
// (potentially gigabytes of data that would never be used for a rollback,
// because rolling back re-creates the link, not its target). We now use
// os.Lstat; if Lstat reports a non-directory but Stat says directory, the
// entry is a directory symlink and we back it up as a *link*, not as its
// target.
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
	idx := fs_beginWriteOp()
	rec := &fs_opRecord{Op: "rm", TS: time.Now().Format("2006-01-02 15:04:05"), Cmd: buildCmdLine(os.Args)}
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
		// Decide if the entry is a directory for the purposes of -r.
		// Lstat tells us whether the *entry itself* is a directory. If it
		// is a symlink to a directory, Lstat says "not a dir" but Stat
		// says "dir" — in that case the entry is a link we can delete
		// without -r, and the backup should be the link itself.
		isLink := linfo.Mode()&os.ModeSymlink != 0
		isRealDir := linfo.IsDir()
		needsRecursive := isRealDir // a real directory needs -r
		if isLink && !isRealDir {
			// Symlink: check the target for the error message only.
			if tinfo, terr := os.Stat(p); terr == nil && tinfo.IsDir() {
				// Deleting a symlink to a dir does not need -r on Windows
				// (Remove removes the link, not the target), but it is
				// safer to require -r to avoid surprising users.
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
		items = append(items, fs_rmItem{Path: p, Backup: backup, Compressed: compressed, IsDir: isRealDir, Existed: true})
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
		fs_saveOpRecord(idx, rec)
	}
	return exitCode
}

// ============================================================================
// mkdir
// ============================================================================

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
	idx := fs_beginWriteOp()
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
	rec := &fs_opRecord{Op: "mkdir", TS: time.Now().Format("2006-01-02 15:04:05"), Cmd: buildCmdLine(os.Args), Data: fs_mustJSON(fs_mkdirData{Items: items})}
	fs_saveOpRecord(idx, rec)
	return exitCode
}

// ============================================================================
// touch
// ============================================================================

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
	idx := fs_beginWriteOp()
	var items []fs_touchItem
	exitCode := 0
	now := time.Now()
	for _, p := range paths {
		it := fs_touchItem{Path: p}
		if info, err := os.Stat(p); err == nil {
			it.Existed = true
			it.OrigMtime = info.ModTime().Format(time.RFC3339Nano)
			// BUGFIX: surface the actual error instead of swallowing it.
			// touch on a read-only file (or a file owned by another user
			// without WRITE_ATTRIBUTES) fails here, and the user deserves
			// to know why.
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
	rec := &fs_opRecord{Op: "touch", TS: now.Format("2006-01-02 15:04:05"), Cmd: buildCmdLine(os.Args), Data: fs_mustJSON(fs_touchData{Items: items})}
	fs_saveOpRecord(idx, rec)
	if exitCode == 0 {
		for _, p := range paths {
			fmt.Printf("touched %s\n", c(clrCyan, p))
		}
	}
	return exitCode
}

// ============================================================================
// stat
// ============================================================================

func fs_cmdStat(args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "usage: fsctl stat <path...>")
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
// ============================================================================
// find
// ============================================================================

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
		if err != nil {
			return nil
		}
		if path == root {
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

// ============================================================================
// grep
// ============================================================================

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
		fmt.Fprintln(os.Stderr, "usage: fsctl grep [-i] [-n] [-v] [-F] <pattern> [file...]")
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
		data, err := fs_readFileOrStdin(f)
		if err != nil {
			fmt.Fprintf(os.Stderr, "grep: %v\n", err)
			continue
		}
		lines := strings.Split(string(data), "\n")
		for i, line := range lines {
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
				prefix += fmt.Sprintf("%d:", i+1)
			}
			fmt.Println(c(clrGray, prefix) + line)
		}
	}
	if matched == 0 {
		return 1
	}
	return 0
}

// ============================================================================
// head / tail / wc
// ============================================================================

func fs_cmdHead(args []string) int {
	n := 10
	var files []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "-n" || a == "--lines" {
			if i+1 >= len(args) {
				fmt.Fprintln(os.Stderr, "head: -n requires a number")
				return 2
			}
			v, err := strconv.Atoi(args[i+1])
			if err != nil {
				fmt.Fprintf(os.Stderr, "head: %v\n", err)
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
		lines, err := fs_readLines(f)
		if err != nil {
			fmt.Fprintf(os.Stderr, "head: %v\n", err)
			return 4
		}
		limit := n
		if limit > len(lines) {
			limit = len(lines)
		}
		for i := 0; i < limit; i++ {
			fmt.Println(lines[i])
		}
	}
	return 0
}

func fs_cmdTail(args []string) int {
	n := 10
	var files []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "-n" || a == "--lines" {
			if i+1 >= len(args) {
				fmt.Fprintln(os.Stderr, "tail: -n requires a number")
				return 2
			}
			v, err := strconv.Atoi(args[i+1])
			if err != nil {
				fmt.Fprintf(os.Stderr, "tail: %v\n", err)
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
	for _, f := range files {
		lines, err := fs_readLines(f)
		if err != nil {
			fmt.Fprintf(os.Stderr, "tail: %v\n", err)
			return 4
		}
		start := len(lines) - n
		if start < 0 {
			start = 0
		}
		for i := start; i < len(lines); i++ {
			fmt.Println(lines[i])
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
		bytes := len(data)
		var parts []string
		if showL {
			parts = append(parts, fmt.Sprintf("%8d", lines))
		}
		if showW {
			parts = append(parts, fmt.Sprintf("%8d", words))
		}
		if showC {
			parts = append(parts, fmt.Sprintf("%8d", bytes))
		}
		label := f
		if f == "-" {
			label = "(stdin)"
		}
		fmt.Printf("%s %s\n", strings.Join(parts, " "), c(clrGray, label))
	}
	return 0
}

// ============================================================================
// replace
// ============================================================================

// fs_cmdReplace replaces all occurrences of oldStr with newStr in each file.
//
// BUGFIX: the dry-run branch used to return exit code 4 when any file was
// unreadable, which made a dry-run over a mixed directory fail even though
// nothing was actually attempted. Dry-run now only warns about unreadable
// files (they are reported, but do not fail the run). Non-dry-run keeps
// the previous behavior — a genuinely unreadable file is a real error.
func fs_cmdReplace(args []string) int {
	if len(args) < 3 {
		fmt.Fprintln(os.Stderr, "usage: fsctl replace <old> <new> <file...>")
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

	idx := fs_beginWriteOp()
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
		Op:   "replace",
		TS:   time.Now().Format("2006-01-02 15:04:05"),
		Cmd:  buildCmdLine(os.Args),
		Data: fs_mustJSON(fs_replaceMulti{Items: items}),
	}
	fs_saveOpRecord(idx, rec)
	return exitCode
}

// ============================================================================
// xargs
// ============================================================================

// fs_cmdXargs reads newline-separated (or NUL-separated with -0) items from
// stdin and invokes <command> [args...] with them.
//
// Behavior:
//   - If any of the command args contains "{}" (or the explicit -I template),
//     each item replaces the placeholder and the command runs once per item
//     (GNU find -exec style).
//   - Otherwise all items are appended to the command and it runs once.
//     Use -n N to run in batches of N items.
//   - Trailing ";" / "\;" / "+" tokens are treated as terminators and dropped.
func fs_cmdXargs(args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "usage: fsctl ... :: xargs <command> [args...]")
		return 2
	}

	maxArgs := 0
	nullSep := false
	template := ""
	i := 0
	for i < len(args) {
		a := args[i]
		switch a {
		case "-0", "--null":
			nullSep = true
			i++
			continue
		case "-n", "--max-args":
			if i+1 >= len(args) {
				fmt.Fprintln(os.Stderr, "xargs: -n requires a number")
				return 2
			}
			v, err := strconv.Atoi(args[i+1])
			if err != nil || v <= 0 {
				fmt.Fprintf(os.Stderr, "xargs: invalid -n %q\n", args[i+1])
				return 2
			}
			maxArgs = v
			i += 2
			continue
		case "-I", "--replace":
			if i+1 >= len(args) {
				fmt.Fprintln(os.Stderr, "xargs: -I requires a placeholder")
				return 2
			}
			template = args[i+1]
			i += 2
			continue
		}
		break
	}
	cmdArgs := append([]string{}, args[i:]...)

	// Strip trailing terminators and collapse "{}\;".
	cleaned := make([]string, 0, len(cmdArgs))
	for _, a := range cmdArgs {
		if a == ";" || a == `\;` || a == "+" {
			continue
		}
		if strings.HasSuffix(a, `\;`) {
			a = strings.TrimSuffix(a, `\;`)
		}
		if a == "" {
			continue
		}
		cleaned = append(cleaned, a)
	}
	cmdArgs = cleaned
	if len(cmdArgs) == 0 {
		fmt.Fprintln(os.Stderr, "xargs: missing command")
		return 2
	}

	data, err := io.ReadAll(os.Stdin)
	if err != nil {
		fmt.Fprintf(os.Stderr, "xargs: read stdin: %v\n", err)
		return 5
	}
	var items []string
	if nullSep {
		for _, tok := range strings.Split(string(data), "\x00") {
			if tok != "" {
				items = append(items, tok)
			}
		}
	} else {
		for _, line := range strings.Split(string(data), "\n") {
			line = strings.TrimSpace(line)
			if line != "" {
				items = append(items, line)
			}
		}
	}
	if len(items) == 0 {
		return 0
	}

	placeholder := template
	if placeholder == "" {
		for _, a := range cmdArgs {
			if strings.Contains(a, "{}") {
				placeholder = "{}"
				break
			}
		}
	}

	if placeholder != "" {
		failCount := 0
		for _, it := range items {
			full := make([]string, len(cmdArgs))
			for j, a := range cmdArgs {
				full[j] = strings.ReplaceAll(a, placeholder, it)
			}
			if code := fs_dispatch(full); code != 0 {
				failCount++
			}
		}
		if failCount == 0 {
			return 0
		}
		if failCount == len(items) {
			return 2
		}
		return 1
	}

	if maxArgs == 0 {
		maxArgs = len(items)
	}
	failCount := 0
	for start := 0; start < len(items); start += maxArgs {
		end := start + maxArgs
		if end > len(items) {
			end = len(items)
		}
		full := append([]string{}, cmdArgs...)
		full = append(full, items[start:end]...)
		if code := fs_dispatch(full); code != 0 {
			failCount++
		}
	}
	if failCount == 0 {
		return 0
	}
	if failCount*maxArgs >= len(items) {
		return 2
	}
	return 1
}

// ============================================================================
// History
// ============================================================================

func fs_cmdHistory() int {
	lines, err := fs_readLogLines()
	if err != nil {
		fmt.Fprintf(os.Stderr, "read log %s: %v\n", fs_logPath(), err)
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
		if !fs_manifestExists(i) {
			continue
		}
		cmd, _, _, ok := fs_parseLogLine(lines[i])
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
		if rec, err := fs_loadOpRecord(e.idx); err == nil {
			desc = fs_summarizeOp(rec)
		}
		fmt.Printf("[%d] %s %s\n", k+1, e.line, c(clrGray, desc))
	}
	fmt.Fprintf(os.Stderr, "\n%d rollback-able operation(s). Log: %s\n", len(entries), fs_logPath())
	return 0
}

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

// ============================================================================
// Rollback
// ============================================================================

func fs_cmdRollback(args []string) int {
	idx := -1
	for i, a := range args {
		if a == "--rollback" {
			idx = i
			break
		}
	}
	if idx < 0 || idx+1 >= len(args) {
		fmt.Fprintln(os.Stderr, "usage: fsctl --rollback <N>")
		return 2
	}
	n, err := strconv.Atoi(args[idx+1])
	if err != nil || n <= 0 {
		fmt.Fprintln(os.Stderr, "--rollback expects a positive number")
		return 2
	}
	lines, err := fs_readLogLines()
	if err != nil {
		fmt.Fprintf(os.Stderr, "read log: %v\n", err)
		return 4
	}
	var targets []int
	for i := len(lines) - 1; i >= 0 && len(targets) < n; i-- {
		if !fs_manifestExists(i) {
			continue
		}
		cmd, _, _, ok := fs_parseLogLine(lines[i])
		if !ok || isHistorySelf(cmd) {
			continue
		}
		targets = append(targets, i)
	}
	if len(targets) == 0 {
		fmt.Fprintln(os.Stderr, "no rollback-able operations in log")
		return 4
	}
	okCount, failCount := 0, 0
	for k, i := range targets {
		rec, err := fs_loadOpRecord(i)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[rollback] step %d: load manifest %d: %v\n", k+1, i, err)
			failCount++
			continue
		}
		fmt.Fprintf(os.Stderr, "[rollback] step %d: %s %s\n", k+1, rec.Op, fs_summarizeOp(rec))
		if err := fs_rollbackRecord(rec); err != nil {
			fmt.Fprintf(os.Stderr, "[rollback] step %d: error: %v\n", k+1, err)
			bugs.Add("ERR", "rollback %d: %v", i, err)
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

// ============================================================================
// Pipeline
// ============================================================================

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

// fs_runPipeline executes each stage in order, feeding the previous stage's
// stdout into the next stage's stdin via temporary files.
//
// BUGFIX: the previous implementation had the cleanup order inverted in one
// place: on error it returned before closing intermediate files and before
// restoring os.Stdout, relying on the top-level defer to do it. That defer
// did run, but only after the caller (fs_main) had a chance to print
// additional messages to the still-redirected stdout. The current version
// explicitly closes every stage's file handles on every exit path, so that
// fs_main always sees the original stdout.
func fs_runPipeline(stages [][]string) int {
	oldStdin := os.Stdin
	oldStdout := os.Stdout
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
				fmt.Fprintf(os.Stderr, "fsctl: open pipe: %v\n", err)
				return 5
			}
			stdinFile = f
			os.Stdin = f
		}

		var stdoutFile *os.File
		var outTmp string
		if !last {
			f, err := os.CreateTemp("", "fsctl_pipe_*")
			if err != nil {
				if stdinFile != nil {
					stdinFile.Close()
					os.Stdin = oldStdin
				}
				useColor = savedColor
				fmt.Fprintf(os.Stderr, "fsctl: create pipe: %v\n", err)
				return 5
			}
			stdoutFile = f
			outTmp = f.Name()
			os.Stdout = f
		}

		code := fs_dispatch(stage)

		// Close stdout FIRST (flushing), then stdin, then restore globals.
		// This ordering matters if a stage short-circuits: an early return
		// below would otherwise leave os.Stdout pointing at a closed file.
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

// ============================================================================
// Dispatch
// ============================================================================

// fs_dispatchDepth guards against xargs recursion (e.g.
// "fsctl ... :: xargs fsctl ... :: xargs fsctl ..."). Each xargs invocation
// calls fs_dispatch, which can invoke xargs again. A hard cap of 8 levels
// is plenty for any legitimate use and stops runaway self-invocation.
var fs_dispatchDepth int32

func fs_dispatch(args []string) int {
	if atomic.AddInt32(&fs_dispatchDepth, 1) > 8 {
		atomic.AddInt32(&fs_dispatchDepth, -1)
		fmt.Fprintln(os.Stderr, "fsctl: xargs recursion depth exceeded (8 levels)")
		return 2
	}
	defer atomic.AddInt32(&fs_dispatchDepth, -1)

	if has(args, "--history") {
		return fs_cmdHistory()
	}
	if has(args, "--rollback") {
		return fs_cmdRollback(args)
	}

	cmdIdx := -1
	for i, a := range args {
		if !strings.HasPrefix(a, "-") {
			cmdIdx = i
			break
		}
	}
	if cmdIdx < 0 {
		fmt.Fprintln(os.Stderr, "fsctl: missing command, use -h for help")
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
	case "xargs":
		return fs_cmdXargs(rest)
	}
	fmt.Fprintf(os.Stderr, "fsctl: unknown command %q\n", cmd)
	return 2
}

// ============================================================================
// Help
// ============================================================================

func fs_printHelp() {
	header := "fsctl v1.0.0 (Windows)"
	fmt.Println(c(clrBold+clrCyan, header))
	fmt.Println("File and text basics for Windows - GNU-like with rollback")
	fmt.Println()
	fmt.Print(`USAGE
  fsctl <command> [OPTIONS] [ARGS...]
  fsctl <cmd1> :: <cmd2> :: ...
  fsctl --history
  fsctl --rollback <N>

COMMANDS
  ls [-l] [-a] [path...]               List directory
  cat <file...>                        Concatenate to stdout (use - for stdin)
  cp [-f] [-r] <src> <dst>             Copy (backs up destination)
  mv [-f] <src> <dst>                  Move (backs up overwritten destination)
  rm [-f] [-r] [-n] <path...>          Remove (backs up everything removed)
  mkdir [-p] <path...>                 Create directories (patterns expanded)
  touch <path...>                      Create files or update mtime (patterns expanded)
  stat <path...>                       Show file information
  find [path] [-name pat] [-type f|d]  Find files/dirs (glob pattern)
  grep [-i] [-n] [-v] [-F] pat [file]  Search lines (regex; -F = literal string;
                                       skips directories; reads stdin if no file)
  head [-n N] [file...]                First N lines (default 10; -N shorthand)
  tail [-n N] [file...]                Last N lines (default 10; -N shorthand)
  wc [-l] [-w] [-c] [file...]          Count lines/words/bytes
  replace <old> <new> <file...>        Replace literal text in files
  xargs [opts] <command> [args...]     Feed stdin to <command>

XARGS
  Default: each stdin line is appended to <command> and it runs once.
    fsctl find . -name "*.txt" :: xargs wc -l
      -> wc -l a.txt b.txt ...
  With "{}" in <command>: each item replaces "{}" and the command runs once
  per item (GNU find -exec style).
    fsctl find . -name "*.tmp" :: xargs rm -rf {}
      -> rm -rf a.tmp ; rm -rf b.tmp ; ...
  Trailing ";" / "\;" / "+" are treated as terminators and dropped.
  Options:
    -0, --null          Read NUL-separated items
    -n, --max-args N    Run in batches of N items
    -I, --replace T     Use placeholder T (default: auto-detect "{}")
  Recursion depth is capped at 8 levels; deeper xargs nesting aborts with
  an error rather than exhausting the stack.

  Correct usage examples:
    # Filter ls output by name, then delete the matches
    fsctl ls . ::: grep -F hello ::: xargs rm -rf

    # Find and delete by pattern
    fsctl find . -name "hello*" -type d ::: xargs rm -rf

    # Replace {} per item
    fsctl find . -name "*.tmp" ::: xargs rm -rf "{}" ";"

  Common mistakes:
    "xargs grep foo" does NOT filter; it runs grep with every stdin line
    as a filename. To filter use "grep foo" directly.

PATTERN EXPANSION
  mkdir, touch, and rm expand {..} and [..] in path arguments:
    hello{1..3} -> hello1 hello2 hello3
    hello{a,b}  -> helloa hellob
    hello[1..3] -> hello1 hello2 hello3
    hello[a-c]  -> helloa hellob helloc
  Disable with --no-expand. In PowerShell quote the pattern:
    fsctl mkdir 'hello{1..3}'

PIPELINE
  fsctl <cmd1> :: <cmd2> :: ...        Pipe stdout of each stage into stdin
                                       of the next. ":::" is accepted as an
                                       alias (safer inside PowerShell).
  Read commands read from stdin when given "-" or when no file argument is
  present and stdin is not a console. Colors are disabled in non-final stages.

  PowerShell note: "::" is a static-member operator in PowerShell. Use ":::"
  or wrap "::" in quotes:
    fsctl ls . ::: grep foo
    fsctl ls . '::' grep foo

GLOBAL
  --dry-run              Preview only: no changes, no backups, no log
  --no-expand            Disable {..} and [..] expansion
  -o, --out <path>       Redirect stdout to a file (read-only commands).
                         Both "-o path" and "--out=path" (also "-o=path")
                         are accepted.
  --no-color             Disable colors (also honors NO_COLOR env var)
  -b, --bugs             Print collected errors/warnings on exit
  --history              List rollback-able operations, numbered from newest
  --rollback <N>         Undo the most recent N rollback-able operations
  -h, --help             Show this help
  --version              Show version

CONFIRMATION
  rm and overwriting cp/mv prompt y/N. Use -f to skip.
  rm -n is a per-command dry-run alias for --dry-run.

BACKUP AND ROLLBACK
  Every modifying command backs up affected files into
    ./fsctl_backup/files/<logIndex>/<seq>_<name>[.gz | .tar.gz]
  before touching them:
    - files < 8 KiB or pre-compressed formats: copied as-is
    - everything else: gzip -9
    - directories: tar + gzip -9
  --rollback executes the inverse of each stored operation.
  Directory symlinks are backed up as links, never as their targets.

LOG
  Every run appends one line to ./fsctl_backup/fsctl.log:
    [command line] [timestamp] [exit code]
  Help/version and --history are not logged. Numbers in --history always
  match --rollback <N>.

EXIT CODES
  0 success | 1 partial failure | 2 bad args | 3 permission denied
  4 not found | 5 I/O error
`)
}

// ============================================================================
// -o/--out
// ============================================================================

func fs_setupOutput(path string) bool {
	dir := filepath.Dir(path)
	if dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0755); err != nil {
			fmt.Fprintf(os.Stderr, "fsctl: create dir %s: %v\n", dir, err)
			return false
		}
	}
	f, err := os.Create(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "fsctl: create %s: %v\n", path, err)
		return false
	}
	orig := os.Stdout
	os.Stdout = f
	useColor = false
	outputCleanup = func() {
		_ = f.Sync()
		_ = f.Close()
		os.Stdout = orig
	}
	return true
}

// ============================================================================
// fs_main
// ============================================================================

func fs_main() {
	rawArgs := os.Args[1:]

	var args []string
	for _, a := range rawArgs {
		if a == "-b" || a == "--bugs" {
			bugs.enabled = true
			continue
		}
		args = append(args, a)
	}

	if has(args, "--no-color") || os.Getenv("NO_COLOR") != "" {
		useColor = false
	} else if stdoutIsTTY() {
		useColor = true
	}

	if has(args, "--version") {
		fmt.Println("fsctl v1.0.0")
		os.Exit(0)
	}
	if len(args) == 0 || has(args, "-h", "--help") {
		fs_printHelp()
		os.Exit(0)
	}

	dryRun = has(args, "--dry-run")

	if has(args, "--no-expand") {
		fs_expandEnabled = false
		args = fs_removeFlag(args, "--no-expand")
	}

	if p := fs_getOpt(args, "-o", "--out"); p != "" {
		args = fs_removeOpt(args, "-o", "--out")
		if !fs_setupOutput(p) {
			bugs.Flush()
			os.Exit(2)
		}
	}

	stages := fs_splitPipeline(args)

	var code int
	if len(stages) > 1 {
		bad := false
		for i, s := range stages {
			if fs_stageHasControlFlag(s) {
				fmt.Fprintf(os.Stderr, "fsctl: --history/--rollback/--help/--version not allowed in a pipeline (stage %d)\n", i+1)
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

	fs_finalExit(code)
}

func fs_finalExit(code int) {
	if !dryRun && fs_shouldLogRun() {
		fs_appendLogLine(buildCmdLine(os.Args), code)
	}
	bugs.Flush()
	if outputCleanup != nil {
		outputCleanup()
		outputCleanup = nil
	}
	os.Exit(code)
}

func fs_shouldLogRun() bool {
	for _, a := range os.Args[1:] {
		switch a {
		case "-h", "--help", "--version", "--history":
			return false
		}
	}
	return true
}
// ==================== hash ====================
// hashsigctl — Hash and Authenticode signature verification (read-only).
// Single-file, standard-library-only build:
//
//   go build -trimpath -ldflags "-s -w" -o hashsigctl.exe hashsigctl.go
//
// Log: ./hashsigctl_backup/hashsigctl.log  [cmd] [ts] [exit code]

// ============================================================================
// Colors / Console / Bug collector
// ============================================================================

// (shared with the rest of the toolkit)

// ============================================================================
// WinTrust / Crypt32 bindings
// ============================================================================

var (
	hash_wintrust = syscall.NewLazyDLL("wintrust.dll")
	hash_crypt32  = syscall.NewLazyDLL("crypt32.dll")

	hash_pWinVerifyTrust = hash_wintrust.NewProc("WinVerifyTrust")

	hash_pCryptQueryObject             = hash_crypt32.NewProc("CryptQueryObject")
	hash_pCertGetNameStringW           = hash_crypt32.NewProc("CertGetNameStringW")
	hash_pCertFreeCertificateContext   = hash_crypt32.NewProc("CertFreeCertificateContext")
	hash_pCertCloseStore               = hash_crypt32.NewProc("CertCloseStore")
	hash_pCryptMsgClose                = hash_crypt32.NewProc("CryptMsgClose")
)

// ============================================================================
// WinTrust structures
// ============================================================================

// hash_GUID represents a Windows GUID. We only need the VERIFY_V2 action id,
// so we hardcode its bytes and never need string parsing.
type hash_GUID struct {
	Data1 uint32
	Data2 uint16
	Data3 uint16
	Data4 [8]byte
}

// WINTRUST_ACTION_GENERIC_VERIFY_V2 = {00AAC56B-CD44-11d0-8CC2-00C04FC295EE}
var hash_winTrustActionVerifyV2 = hash_GUID{
	Data1: 0x00AAC56B,
	Data2: 0xCD44,
	Data3: 0x11D0,
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

	hash_WTD_PROV_FLAGS_MASK = 0x0000FFFF

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

// hash_WINTRUST_FILE_INFO is the "file" variant of the union inside
// hash_WINTRUST_DATA.
type hash_WINTRUST_FILE_INFO struct {
	CbStruct       uint32
	PcwszFilePath  *uint16
	HFile          syscall.Handle
	PgKnownSubject *hash_GUID
}

// hash_WINTRUST_DATA is the same layout for 32-bit and 64-bit Windows; the
// only difference is pointer size, which Go handles automatically.
//
// BUGFIX: the previous version was missing the trailing
// PSignatureSettings field, so cbStruct was 8 bytes short on amd64
// (64 instead of 72). On Windows 10/11, WinVerifyTrust examines cbStruct
// and refuses to parse the structure when the size is wrong; the call
// returns E_INVALIDARG (0x80070057) instead of a signature verdict, so
// every signed file was reported as "Error".
//
// The trailing pointer is optional and stays NULL; the field is only
// there so that cbStruct matches what WinVerifyTrust expects.
type hash_WINTRUST_DATA struct {
	CbStruct            uint32
	PolicyCallbackData  uintptr
	SIPClientData       uintptr
	DwUIChoice          uint32
	FdwRevocationChecks uint32
	DwUnionChoice       uint32
	PFile               uintptr // *hash_WINTRUST_FILE_INFO when DwUnionChoice == hash_WTD_CHOICE_FILE
	DwStateAction       uint32
	HWVTStateData       syscall.Handle
	PwszURLReference    *uint16
	DwProvFlags         uint32
	DwUIContext         uint32
	PSignatureSettings  uintptr // WINTRUST_SIGNATURE_SETTINGS*, optional
}

// ============================================================================
// WinTrust verification
// ============================================================================

type hash_sigResult struct {
	Status     string   `json:"status"` // valid | invalid | unsigned | error
	Reason     string   `json:"reason,omitempty"`
	Signer     string   `json:"signer,omitempty"`
	Issuer     string   `json:"issuer,omitempty"`
	ChainNotes []string `json:"chainNotes,omitempty"`
}

// hash_verifyAuthenticode calls WinVerifyTrust with the standard Authenticode
// action id. It reports success (nil error), hash_TRUST_E_NOSIGNATURE when the
// file is unsigned, and any other trust error otherwise.
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

	ret, _, _ := hash_pWinVerifyTrust.Call(
		uintptr(0),
		uintptr(unsafe.Pointer(&hash_winTrustActionVerifyV2)),
		uintptr(unsafe.Pointer(&data)),
	)

	// Always close the state, even on failure, so we don't leak handles.
	defer func() {
		data.DwStateAction = hash_WTD_STATEACTION_CLOSE
		hash_pWinVerifyTrust.Call(
			uintptr(0),
			uintptr(unsafe.Pointer(&hash_winTrustActionVerifyV2)),
			uintptr(unsafe.Pointer(&data)),
		)
	}()

	// WinVerifyTrust returns a LONG; the low 32 bits is the HRESULT. On
	// amd64, uintptr is 64 bits wide, so the sign extension makes the
	// uint32 conversion essential.
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
		Status: "invalid",
		Reason: fmt.Sprintf("WinVerifyTrust returned 0x%08X", code),
	}, nil
}

// hash_extractSigner attempts to pull the signer's display name and issuer out
// of the file's embedded PKCS#7 signature. It uses CryptQueryObject to locate
// the certificate and CertGetNameStringW to render the subject/issuer into a
// string. Any failure is non-fatal: the caller still has the trust verdict
// from hash_verifyAuthenticode.
//
// BUGFIXES:
//
//   - The HCRYPTMSG returned by CryptQueryObject is now released with
//     CryptMsgClose; the previous version leaked one handle per signed
//     file inspected.
//   - The signer's issuer is now fetched exactly once, with the
//     CERT_NAME_ISSUER_FLAG flag. The previous version called
//     CertGetNameString twice and threw the first result away.
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
	var store syscall.Handle
	var msg syscall.Handle
	var certContext uintptr

	r, _, _ := hash_pCryptQueryObject.Call(
		uintptr(CERT_QUERY_OBJECT_FILE),
		uintptr(unsafe.Pointer(pathPtr)),
		uintptr(CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED),
		uintptr(CERT_QUERY_FORMAT_FLAG_BINARY),
		0,
		uintptr(unsafe.Pointer(&encodingType)),
		uintptr(unsafe.Pointer(&contentType)),
		uintptr(unsafe.Pointer(&formatType)),
		uintptr(unsafe.Pointer(&store)),
		uintptr(unsafe.Pointer(&msg)),
		uintptr(unsafe.Pointer(&certContext)),
	)
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

	// CERT_NAME_SIMPLE_DISPLAY_TYPE == 4.
	// The signer's subject is read without CERT_NAME_ISSUER_FLAG.
	signer = hash_certNameString(certContext, 4)
	// The issuer is read with CERT_NAME_ISSUER_FLAG (0x1).
	issuer = hash_certNameStringFlags(certContext, 4, 0x1)

	return signer, issuer, nil
}

func hash_certNameString(certCtx uintptr, nameType uint32) string {
	return hash_certNameStringFlags(certCtx, nameType, 0)
}

func hash_certNameStringFlags(certCtx uintptr, nameType, flags uint32) string {
	// First call with size 0 to discover the required length.
	n, _, _ := hash_pCertGetNameStringW.Call(
		certCtx,
		uintptr(nameType),
		uintptr(flags),
		0,
		0,
		0,
	)
	if n <= 1 {
		return ""
	}
	buf := make([]uint16, n)
	r, _, _ := hash_pCertGetNameStringW.Call(
		certCtx,
		uintptr(nameType),
		uintptr(flags),
		0,
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(n),
	)
	if r == 0 {
		return ""
	}
	return syscall.UTF16ToString(buf)
}

// ============================================================================
// Hash computation
// ============================================================================

type hash_hashResult struct {
	MD5    string `json:"md5"`
	SHA1   string `json:"sha1"`
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
}

func hash_hashFile(path string) (hash_hashResult, error) {
	f, err := os.Open(path)
	if err != nil {
		return hash_hashResult{}, err
	}
	defer f.Close()

	hMD5 := md5.New()
	hSHA1 := sha1.New()
	hSHA256 := sha256.New()

	mw := io.MultiWriter(hMD5, hSHA1, hSHA256)
	n, err := io.Copy(mw, f)
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

// ============================================================================
// File classification
// ============================================================================

// hash_isPE returns true when the file starts with 'MZ' and has a plausible PE
// header. It is cheap and is only used to decide whether to run Authenticode
// verification, which is fairly expensive.
func hash_isPE(path string) bool {
	f, err := pe.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()
	return true
}

// ============================================================================
// Entry type used for reporting
// ============================================================================

type hash_reportEntry struct {
	Path   string          `json:"path"`
	Hashes *hash_hashResult `json:"hashes,omitempty"`
	Sig    *hash_sigResult  `json:"signature,omitempty"`
	Error  string          `json:"error,omitempty"`
}

// ============================================================================
// Paths and log
// ============================================================================

const (
	hash_backupDirName = "hashsigctl_backup"
	hash_logFileName   = "hashsigctl.log"
)

func hash_logRoot() string { return filepath.Join(exeDir(), hash_backupDirName) }
func hash_logPath() string { return filepath.Join(hash_logRoot(), hash_logFileName) }

func hash_readLogLines() ([]string, error) {
	data, err := os.ReadFile(hash_logPath())
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

func hash_appendLogLine(cmd string, code int) {
	_ = os.MkdirAll(hash_logRoot(), 0755)
	f, err := os.OpenFile(hash_logPath(), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		bugs.Add("ERR", "open log: %v", err)
		return
	}
	defer f.Close()
	ts := time.Now().Format("2006-01-02 15:04:05")
	_, _ = fmt.Fprintf(f, "[%s] [%s] [%d]\n", cmd, ts, code)
}

// ============================================================================
// History / rollback
// ============================================================================

func hash_cmdHistory() int {
	lines, err := hash_readLogLines()
	if err != nil {
		fmt.Fprintf(os.Stderr, "read log %s: %v\n", hash_logPath(), err)
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
	fmt.Fprintf(os.Stderr, "\n%d entrie(s). Log: %s\n", len(lines), hash_logPath())
	return 0
}

func hash_cmdRollback() int {
	fmt.Fprintln(os.Stderr, "hashsigctl is read-only: there are no operations to roll back")
	fmt.Fprintln(os.Stderr, "  hashsigctl only reads files, computes hashes, and verifies signatures.")
	fmt.Fprintln(os.Stderr, "  Its history is for audit only; use --history to view it.")
	return 0
}

// ============================================================================
// Output
// ============================================================================

func hash_printHash(e *hash_reportEntry) {
	fmt.Printf("%s %s\n", c(clrCyan, "File:  "), e.Path)
	if e.Error != "" {
		fmt.Printf("%s %s\n", c(clrRed, "Error:"), e.Error)
		return
	}
	fmt.Printf("%s %s\n", c(clrCyan, "Size:  "), humanBytes(uint64(e.Hashes.Size)))
	fmt.Printf("%s %s\n", c(clrCyan, "MD5:   "), e.Hashes.MD5)
	fmt.Printf("%s %s\n", c(clrCyan, "SHA1:  "), e.Hashes.SHA1)
	fmt.Printf("%s %s\n", c(clrCyan, "SHA256:"), e.Hashes.SHA256)

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

func hash_printHashJSON(e *hash_reportEntry) {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(e); err != nil {
		bugs.Add("ERR", "json encode: %v", err)
	}
}

// ============================================================================
// Directory scanning
// ============================================================================

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
				if err != nil {
					return nil
				}
				if info.IsDir() {
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

// ============================================================================
// Help
// ============================================================================

func hash_printHelp() {
	header := "hashsigctl v1.0.0 (Windows)"
	fmt.Println(c(clrBold+clrCyan, header))
	fmt.Println("Hash and Authenticode signature verification (read-only)")
	fmt.Println()
	fmt.Print(`USAGE
  hashsigctl hash <file|dir>...
  hashsigctl sig  <file|dir>...          (signature only)
  hashsigctl <file|dir>...               (hash + sig if PE)
  hashsigctl --history
  hashsigctl --rollback                  (always a no-op: read-only)

HASH
  For each file, prints MD5, SHA1, SHA256 and the file size.
  Directories are expanded one level; add --recursive to walk deeper.

SIGNATURE
  For .exe / .dll / .sys files, calls WinVerifyTrust to check the
  Authenticode signature, then extracts the signer and issuer names from
  the embedded PKCS#7 certificate.
  Non-PE files are skipped silently when mixed with PE files.

OPTIONS
  --json           JSON output (one object per file)
  --recursive      Walk directories recursively
  --hash-only      Skip signature verification
  --sig-only       Only verify signatures (skip hash computation)

GLOBAL
  -o, --out <path> Redirect stdout to a file
  --dry-run        Print the plan without reading any file
  --no-color       Disable ANSI colors (also honors NO_COLOR)
  -b, --bugs       Print collected errors/warnings on exit
  -h, --help       Show this help
  --version        Show version

HISTORY
  Every invocation (except -h/--help/--version/--history/--rollback/--dry-run)
  appends one line to ./hashsigctl_backup/hashsigctl.log:
    [command line] [timestamp] [exit code]
  --history prints it, numbered from newest (1) to oldest.

READ-ONLY BY DESIGN
  hashsigctl never writes to the files it inspects, never modifies the
  registry, and never changes any system state. The only file it writes
  is its own audit log.

EXIT CODES
  0 success | 1 partial failure | 2 total failure or bad args
  3 permission denied | 4 not found | 5 I/O error
`)
}

// ============================================================================
// Global flag consumption
// ============================================================================

func hash_consumeGlobalFlags(args []string) (rest []string, outPath string, err error) {
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

func hash_setupOutput(path string) error {
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
// Command dispatch
// ============================================================================

type hash_hashOpts struct {
	jsonOut   bool
	recursive bool
	hashOnly  bool
	sigOnly   bool
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
		fmt.Fprintln(os.Stderr, "hashsigctl: no files given")
		return 2
	}

	files, err := hash_collectFiles(paths, opts.recursive)
	if err != nil {
		fmt.Fprintf(os.Stderr, "hashsigctl: %v\n", err)
		return 5
	}
	if len(files) == 0 {
		fmt.Fprintln(os.Stderr, "hashsigctl: no files matched")
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
			h, err := hash_hashFile(p)
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
				sig.Signer = signer
				sig.Issuer = issuer
				sig.ChainNotes = notes
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
				fmt.Printf("%s %s\n", c(clrCyan, "MD5:   "), e.Hashes.MD5)
				fmt.Printf("%s %s\n", c(clrCyan, "SHA1:  "), e.Hashes.SHA1)
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

// ============================================================================
// hash_main
// ============================================================================

func hash_main() {
	args, outPath, err := hash_consumeGlobalFlags(os.Args[1:])
	if err != nil {
		fmt.Fprintf(os.Stderr, "hashsigctl: %v\n", err)
		bugs.Flush()
		os.Exit(2)
	}

	if noColorFlag || os.Getenv("NO_COLOR") != "" {
		useColor = false
	} else if stdoutIsTTY() {
		useColor = true
	}

	if has(args, "--version") {
		fmt.Println("hashsigctl v1.0.0")
		hash_finalExit(0, false)
	}
	if len(args) == 0 || has(args, "-h", "--help") {
		hash_printHelp()
		hash_finalExit(0, false)
	}
	if has(args, "--history") {
		hash_finalExit(hash_cmdHistory(), false)
	}
	if has(args, "--rollback") {
		hash_finalExit(hash_cmdRollback(), false)
	}

	if outPath != "" {
		if err := hash_setupOutput(outPath); err != nil {
			fmt.Fprintf(os.Stderr, "hashsigctl: %v\n", err)
			bugs.Flush()
			os.Exit(2)
		}
	}

	// Subcommands: hash / sig. Anything else is treated as a path for the
	// default action.
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
		fmt.Fprintf(os.Stderr, "hashsigctl: %v\n", err)
		bugs.Flush()
		os.Exit(2)
	}

	switch cmd {
	case "hash":
		opts.sigOnly = false
		opts.hashOnly = true
		if len(positional) == 0 {
			fmt.Fprintln(os.Stderr, "hashsigctl: hash requires at least one file or directory")
			hash_finalExit(2, true)
		}
		hash_finalExit(hash_cmdHashOrSig(positional, opts), true)
	case "sig":
		opts.sigOnly = true
		opts.hashOnly = false
		if len(positional) == 0 {
			fmt.Fprintln(os.Stderr, "hashsigctl: sig requires at least one file or directory")
			hash_finalExit(2, true)
		}
		hash_finalExit(hash_cmdHashOrSig(positional, opts), true)
	default:
		if len(positional) == 0 {
			fmt.Fprintln(os.Stderr, "hashsigctl: no files given (use -h for help)")
			hash_finalExit(2, true)
		}
		hash_finalExit(hash_cmdHashOrSig(positional, opts), true)
	}
}

func hash_finalExit(code int, logIt bool) {
	if logIt && !dryRun && hash_shouldLogRun() {
		hash_appendLogLine(buildCmdLine(os.Args), code)
	}
	bugs.Flush()
	if outputCleanup != nil {
		outputCleanup()
		outputCleanup = nil
	}
	os.Exit(code)
}

func hash_shouldLogRun() bool {
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
	_ = asn1.Marshal
	_ = runtime.GOARCH
	_ = strconv.Itoa
)