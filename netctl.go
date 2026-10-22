//go:build windows && amd64

package main

// netctl — Windows network & connection viewer with rollback.
// Single-file, standard-library-only build:
//
//   go build -trimpath -ldflags "-s -w" -o netctl.exe netctl.go

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

	pOpenProcess                = kernel32.NewProc("OpenProcess")
	pCloseHandle                = kernel32.NewProc("CloseHandle")
	pQueryFullProcessImageNameW = kernel32.NewProc("QueryFullProcessImageNameW")
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
		fmt.Fprintln(os.Stderr, "[netctl] -b/--bugs enabled: no errors or warnings captured this run.")
		return
	}
	fmt.Fprintf(os.Stderr, "\n--- netctl bugs report (%d entries) ---\n", len(b.entries))
	for _, e := range b.entries {
		fmt.Fprintf(os.Stderr, "[%s] %s %s\n", e.At.Format("15:04:05.000"), e.Level, e.Msg)
	}
	fmt.Fprintln(os.Stderr, "--- end of bugs report ---")
}

// ============================================================================
// iphlpapi bindings
// ============================================================================

var (
	iphlpapi = syscall.NewLazyDLL("iphlpapi.dll")

	pGetExtendedTcpTable  = iphlpapi.NewProc("GetExtendedTcpTable")
	pGetExtendedUdpTable  = iphlpapi.NewProc("GetExtendedUdpTable")
	pGetAdaptersAddresses = iphlpapi.NewProc("GetAdaptersAddresses")
)

const (
	AF_UNSPEC = 0
	AF_INET   = 2
	AF_INET6  = 23

	TCP_TABLE_OWNER_PID_ALL = 5
	UDP_TABLE_OWNER_PID     = 1

	MIB_TCP_STATE_CLOSED     = 1
	MIB_TCP_STATE_LISTEN     = 2
	MIB_TCP_STATE_SYN_SENT   = 3
	MIB_TCP_STATE_SYN_RCVD   = 4
	MIB_TCP_STATE_ESTAB      = 5
	MIB_TCP_STATE_FIN_WAIT1  = 6
	MIB_TCP_STATE_FIN_WAIT2  = 7
	MIB_TCP_STATE_CLOSE_WAIT = 8
	MIB_TCP_STATE_CLOSING    = 9
	MIB_TCP_STATE_LAST_ACK   = 10
	MIB_TCP_STATE_TIME_WAIT  = 11
	MIB_TCP_STATE_DELETE_TCB = 12

	PROCESS_QUERY_LIMITED = 0x1000
)

type MIB_TCPROW_OWNER_PID struct {
	State      uint32
	LocalAddr  uint32
	LocalPort  uint32
	RemoteAddr uint32
	RemotePort uint32
	OwningPid  uint32
}

type MIB_TCP6ROW_OWNER_PID struct {
	ucLocalAddr     [16]byte
	dwLocalScopeId  uint32
	dwLocalPort     uint32
	ucRemoteAddr    [16]byte
	dwRemoteScopeId uint32
	dwRemotePort    uint32
	dwState         uint32
	dwOwningPid     uint32
}

type MIB_UDPROW_OWNER_PID struct {
	LocalAddr uint32
	LocalPort uint32
	OwningPid uint32
}

type MIB_UDP6ROW_OWNER_PID struct {
	ucLocalAddr    [16]byte
	dwLocalScopeId uint32
	dwLocalPort    uint32
	dwOwningPid    uint32
}

// ============================================================================
// Adapter address structures (prefix of IP_ADAPTER_ADDRESSES_LH)
// ============================================================================

type SOCKET_ADDRESS struct {
	lpSockaddr      *syscall.RawSockaddrAny
	iSockaddrLength int32
}

type IP_ADAPTER_UNICAST_ADDRESS_LH struct {
	Length  uint32
	Flags   uint32
	Next    *IP_ADAPTER_UNICAST_ADDRESS_LH
	Address SOCKET_ADDRESS
}

type IP_ADAPTER_DNS_SERVER_ADDRESS_XP struct {
	Length   uint32
	Reserved uint32
	Next     *IP_ADAPTER_DNS_SERVER_ADDRESS_XP
	Address  SOCKET_ADDRESS
}

type IP_ADAPTER_ADDRESSES_LH struct {
	Length                uint32
	IfIndex               uint32
	Next                  *IP_ADAPTER_ADDRESSES_LH
	AdapterName           *byte
	FirstUnicastAddress   *IP_ADAPTER_UNICAST_ADDRESS_LH
	FirstAnycastAddress   *IP_ADAPTER_UNICAST_ADDRESS_LH
	FirstMulticastAddress *IP_ADAPTER_UNICAST_ADDRESS_LH
	FirstDnsServerAddress *IP_ADAPTER_DNS_SERVER_ADDRESS_XP
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
	IfOperStatusUp            = 1
	IF_TYPE_ETHERNET_CSMACD   = 6
	IF_TYPE_IEEE80211         = 71
	IF_TYPE_SOFTWARE_LOOPBACK = 24
	IF_TYPE_TUNNEL            = 131
	GAA_FLAG_INCLUDE_PREFIX   = 0x0010
)

// ============================================================================
// Registry bindings (proxy)
// ============================================================================

var (
	advapi32 = syscall.NewLazyDLL("advapi32.dll")

	pRegOpenKeyExW    = advapi32.NewProc("RegOpenKeyExW")
	pRegCloseKey      = advapi32.NewProc("RegCloseKey")
	pRegSetValueExW   = advapi32.NewProc("RegSetValueExW")
	pRegDeleteValueW  = advapi32.NewProc("RegDeleteValueW")
	pRegCreateKeyExW  = advapi32.NewProc("RegCreateKeyExW")
	pRegQueryValueExW = advapi32.NewProc("RegQueryValueExW")
)

const (
	HKCU = uintptr(0xFFFFFFFF80000001)
	HKLM = uintptr(0xFFFFFFFF80000002)

	KEY_QUERY_VALUE = 0x0001
	KEY_SET_VALUE   = 0x0002
	KEY_READ        = 0x20019
	KEY_WRITE       = 0x20006

	REG_SZ        = 1
	REG_EXPAND_SZ = 2
	REG_DWORD     = 4

	ERROR_FILE_NOT_FOUND = syscall.Errno(2)
	ERROR_ACCESS_DENIED  = syscall.Errno(5)
	ERROR_NO_MORE_ITEMS  = syscall.Errno(259)

	proxyKeyPath = `Software\Microsoft\Windows\CurrentVersion\Internet Settings`
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

func regQueryValue(k RegKey, name string) (*RegValue, error) {
	namePtr, _ := syscall.UTF16PtrFromString(name)
	var typ uint32
	var size uint32
	r, _, _ := pRegQueryValueExW.Call(uintptr(k), uintptr(unsafe.Pointer(namePtr)), 0,
		uintptr(unsafe.Pointer(&typ)), 0, uintptr(unsafe.Pointer(&size)))
	if r != 0 {
		return nil, syscall.Errno(r)
	}
	buf := make([]byte, size)
	r, _, _ = pRegQueryValueExW.Call(uintptr(k), uintptr(unsafe.Pointer(namePtr)), 0,
		uintptr(unsafe.Pointer(&typ)),
		uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&size)))
	if r != 0 {
		return nil, syscall.Errno(r)
	}
	return &RegValue{Name: name, Type: typ, Data: buf[:size]}, nil
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

// ============================================================================
// IPv4/IPv6 formatting and sockaddr decoding
// ============================================================================

func ntohs(x uint32) uint16 {
	return uint16(x&0xFF)<<8 | uint16((x>>8)&0xFF)
}

func ipv4FromUint32(a uint32) string {
	return fmt.Sprintf("%d.%d.%d.%d", byte(a), byte(a>>8), byte(a>>16), byte(a>>24))
}

func formatIPv6(b []byte) string {
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

func sockaddrToIP(sa *syscall.RawSockaddrAny) (string, int, bool) {
	if sa == nil {
		return "", 0, false
	}
	switch int(sa.Addr.Family) {
	case AF_INET:
		in4 := (*syscall.RawSockaddrInet4)(unsafe.Pointer(sa))
		return fmt.Sprintf("%d.%d.%d.%d",
			in4.Addr[0], in4.Addr[1], in4.Addr[2], in4.Addr[3]), AF_INET, true
	case AF_INET6:
		in6 := (*syscall.RawSockaddrInet6)(unsafe.Pointer(sa))
		return formatIPv6(in6.Addr[:]), AF_INET6, true
	}
	return "", int(sa.Addr.Family), false
}

// ============================================================================
// Generic buffer-size discovery for iphlpapi table APIs
// ============================================================================

// callTableFn is a generic wrapper that handles the "first call with size=0 to
// discover the required buffer" pattern. Windows is inconsistent about which
// error code it returns when the buffer is too small (122, 111, or 206 in some
// configurations), so instead of checking the code we only require that size
// is filled in. This also handles the case where the table grows between the
// two calls.
func callTableFn(fn *syscall.LazyProc, family, tableClass uint32) ([]byte, error) {
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
			// API reported nothing to return.
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

type ConnRow struct {
	Proto    string
	Local    string
	Remote   string
	State    uint32
	Pid      uint32
	ProcName string
}

func queryTcp4() ([]ConnRow, error) {
	buf, err := callTableFn(pGetExtendedTcpTable, AF_INET, TCP_TABLE_OWNER_PID_ALL)
	if err != nil || len(buf) < 4 {
		return nil, err
	}
	num := *(*uint32)(unsafe.Pointer(&buf[0]))
	var out []ConnRow
	rowSize := int(unsafe.Sizeof(MIB_TCPROW_OWNER_PID{}))
	for i := uint32(0); i < num; i++ {
		off := 4 + int(i)*rowSize
		if off+rowSize > len(buf) {
			break
		}
		row := (*MIB_TCPROW_OWNER_PID)(unsafe.Pointer(&buf[off]))
		local := ipv4FromUint32(row.LocalAddr) + ":" + strconv.Itoa(int(ntohs(row.LocalPort)))
		remote := "*:*"
		if row.RemoteAddr != 0 || row.RemotePort != 0 {
			remote = ipv4FromUint32(row.RemoteAddr) + ":" + strconv.Itoa(int(ntohs(row.RemotePort)))
		}
		out = append(out, ConnRow{
			Proto:  "tcp4",
			Local:  local,
			Remote: remote,
			State:  row.State,
			Pid:    row.OwningPid,
		})
	}
	return out, nil
}

func queryTcp6() ([]ConnRow, error) {
	buf, err := callTableFn(pGetExtendedTcpTable, AF_INET6, TCP_TABLE_OWNER_PID_ALL)
	if err != nil || len(buf) < 4 {
		return nil, err
	}
	num := *(*uint32)(unsafe.Pointer(&buf[0]))
	var out []ConnRow
	rowSize := int(unsafe.Sizeof(MIB_TCP6ROW_OWNER_PID{}))
	for i := uint32(0); i < num; i++ {
		off := 4 + int(i)*rowSize
		if off+rowSize > len(buf) {
			break
		}
		row := (*MIB_TCP6ROW_OWNER_PID)(unsafe.Pointer(&buf[off]))
		local := "[" + formatIPv6(row.ucLocalAddr[:]) + "]:" + strconv.Itoa(int(ntohs(row.dwLocalPort)))
		remote := "[::]:*"
		if row.ucRemoteAddr != [16]byte{} {
			remote = "[" + formatIPv6(row.ucRemoteAddr[:]) + "]:" + strconv.Itoa(int(ntohs(row.dwRemotePort)))
		}
		out = append(out, ConnRow{
			Proto:  "tcp6",
			Local:  local,
			Remote: remote,
			State:  row.dwState,
			Pid:    row.dwOwningPid,
		})
	}
	return out, nil
}

func queryUdp4() ([]ConnRow, error) {
	buf, err := callTableFn(pGetExtendedUdpTable, AF_INET, UDP_TABLE_OWNER_PID)
	if err != nil || len(buf) < 4 {
		return nil, err
	}
	num := *(*uint32)(unsafe.Pointer(&buf[0]))
	var out []ConnRow
	rowSize := int(unsafe.Sizeof(MIB_UDPROW_OWNER_PID{}))
	for i := uint32(0); i < num; i++ {
		off := 4 + int(i)*rowSize
		if off+rowSize > len(buf) {
			break
		}
		row := (*MIB_UDPROW_OWNER_PID)(unsafe.Pointer(&buf[off]))
		local := ipv4FromUint32(row.LocalAddr) + ":" + strconv.Itoa(int(ntohs(row.LocalPort)))
		out = append(out, ConnRow{
			Proto:  "udp4",
			Local:  local,
			Remote: "*:*",
			Pid:    row.OwningPid,
		})
	}
	return out, nil
}

func queryUdp6() ([]ConnRow, error) {
	buf, err := callTableFn(pGetExtendedUdpTable, AF_INET6, UDP_TABLE_OWNER_PID)
	if err != nil || len(buf) < 4 {
		return nil, err
	}
	num := *(*uint32)(unsafe.Pointer(&buf[0]))
	var out []ConnRow
	rowSize := int(unsafe.Sizeof(MIB_UDP6ROW_OWNER_PID{}))
	for i := uint32(0); i < num; i++ {
		off := 4 + int(i)*rowSize
		if off+rowSize > len(buf) {
			break
		}
		row := (*MIB_UDP6ROW_OWNER_PID)(unsafe.Pointer(&buf[off]))
		local := "[" + formatIPv6(row.ucLocalAddr[:]) + "]:" + strconv.Itoa(int(ntohs(row.dwLocalPort)))
		out = append(out, ConnRow{
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

type AdapterInfo struct {
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

// queryAdapters calls GetAdaptersAddresses with a buffer-size discovery loop.
// As with callTableFn, we do not assume a specific error code on the first
// call; we just require that size was filled in and retry with a larger buffer
// up to 3 times.
func queryAdapters() ([]AdapterInfo, error) {
	flags := uint32(GAA_FLAG_INCLUDE_PREFIX)
	family := uint32(AF_UNSPEC)

	var buf []byte
	for attempt := 0; attempt < 3; attempt++ {
		size := uint32(len(buf))
		var p uintptr
		if size > 0 {
			p = uintptr(unsafe.Pointer(&buf[0]))
		}
		r, _, _ := pGetAdaptersAddresses.Call(uintptr(family), uintptr(flags), 0, p,
			uintptr(unsafe.Pointer(&size)))
		if r == 0 && size > 0 {
			return parseAdapters(buf[:size])
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

func parseAdapters(buf []byte) ([]AdapterInfo, error) {
	if len(buf) == 0 {
		return nil, nil
	}
	var out []AdapterInfo
	cur := (*IP_ADAPTER_ADDRESSES_LH)(unsafe.Pointer(&buf[0]))
	for cur != nil {
		info := AdapterInfo{
			IfIndex:    cur.IfIndex,
			IfType:     cur.IfType,
			OperStatus: cur.OperStatus,
		}
		if cur.Description != nil {
			info.Description = syscall.UTF16ToString(unsafe.Slice(cur.Description, 512))
		}
		if cur.FriendlyName != nil {
			info.Name = syscall.UTF16ToString(unsafe.Slice(cur.FriendlyName, 512))
		}
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
			if ip, fam, ok := sockaddrToIP(ua.Address.lpSockaddr); ok {
				if fam == AF_INET {
					info.IPv4s = append(info.IPv4s, ip)
				} else if fam == AF_INET6 {
					info.IPv6s = append(info.IPv6s, ip)
				}
			}
		}

		for da := cur.FirstDnsServerAddress; da != nil; da = da.Next {
			if ip, _, ok := sockaddrToIP(da.Address.lpSockaddr); ok {
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

type ProxyState struct {
	Enable   bool
	Server   string
	Override string
	Exists   bool
}

func readProxyState() ProxyState {
	var st ProxyState
	k, err := regOpenKey(HKCU, proxyKeyPath, KEY_READ)
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
			st.Server = decodeRegString(v.Data)
			gotAny = true
		}
	}
	if v, err := regQueryValue(k, "ProxyOverride"); err == nil {
		if v.Type == REG_SZ || v.Type == REG_EXPAND_SZ {
			st.Override = decodeRegString(v.Data)
			gotAny = true
		}
	}
	st.Exists = gotAny
	return st
}

func writeProxyState(st ProxyState) error {
	k, err := regCreateKey(HKCU, proxyKeyPath, KEY_WRITE)
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
		if err := regSetValue(k, "ProxyServer", REG_SZ, encodeRegString(st.Server)); err != nil {
			return err
		}
	}
	if st.Override == "" {
		_ = regDeleteValue(k, "ProxyOverride")
	} else {
		if err := regSetValue(k, "ProxyOverride", REG_SZ, encodeRegString(st.Override)); err != nil {
			return err
		}
	}
	return nil
}

// ============================================================================
// hosts helpers
// ============================================================================

func hostsPath() string {
	return filepath.Join(os.Getenv("SystemRoot"), `System32\drivers\etc\hosts`)
}

func applyHostsAdd(ip string, hostnames []string) error {
	data, err := os.ReadFile(hostsPath())
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
	return os.WriteFile(hostsPath(), []byte(body), 0644)
}

func applyHostsRemove(hostnames []string) error {
	data, err := os.ReadFile(hostsPath())
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
	body := strings.Join(out, "\r\n")
	if body != "" && !strings.HasSuffix(body, "\r\n") {
		body += "\r\n"
	}
	return os.WriteFile(hostsPath(), []byte(body), 0644)
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
	backupDirName = "netctl_backup"
	logFileName   = "netctl.log"
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

type proxySnap struct {
	Enable   bool   `json:"enable"`
	Server   string `json:"server,omitempty"`
	Override string `json:"override,omitempty"`
	Exists   bool   `json:"exists"`
}

type opRecord struct {
	Op            string     `json:"op"`
	TS            string     `json:"ts"`
	Cmd           string     `json:"cmd"`
	Code          int        `json:"code"`
	BackupFile    string     `json:"backupFile,omitempty"`
	BackupGzipped bool       `json:"backupGzipped,omitempty"`
	OldProxy      *proxySnap `json:"oldProxy,omitempty"`
	NewProxy      *proxySnap `json:"newProxy,omitempty"`
	HostsIP       string     `json:"hostsIP,omitempty"`
	HostsNames    []string   `json:"hostsNames,omitempty"`
	HostsRemove   []string   `json:"hostsRemove,omitempty"`
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
// hosts backup
// ============================================================================

const smallHostsThreshold = 8192

func backupHosts(logIdx int) (string, bool, error) {
	data, err := os.ReadFile(hostsPath())
	if err != nil {
		return "", false, err
	}
	base := fmt.Sprintf("%d_hosts", logIdx)
	if len(data) < smallHostsThreshold {
		rel := base + ".hosts"
		full := filepath.Join(filesDir(), rel)
		if err := os.MkdirAll(filepath.Dir(full), 0755); err != nil {
			return "", false, err
		}
		if err := os.WriteFile(full, data, 0644); err != nil {
			return "", false, err
		}
		return rel, false, nil
	}
	rel := base + ".hosts.gz"
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

func restoreHosts(relPath string, gzipped bool) error {
	src := filepath.Join(filesDir(), relPath)
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
	return os.WriteFile(hostsPath(), data, 0644)
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
// conn command
// ============================================================================

func tcpStateName(s uint32) string {
	switch s {
	case MIB_TCP_STATE_CLOSED:
		return "CLOSED"
	case MIB_TCP_STATE_LISTEN:
		return "LISTEN"
	case MIB_TCP_STATE_SYN_SENT:
		return "SYN_SENT"
	case MIB_TCP_STATE_SYN_RCVD:
		return "SYN_RCVD"
	case MIB_TCP_STATE_ESTAB:
		return "ESTABLISHED"
	case MIB_TCP_STATE_FIN_WAIT1:
		return "FIN_WAIT1"
	case MIB_TCP_STATE_FIN_WAIT2:
		return "FIN_WAIT2"
	case MIB_TCP_STATE_CLOSE_WAIT:
		return "CLOSE_WAIT"
	case MIB_TCP_STATE_CLOSING:
		return "CLOSING"
	case MIB_TCP_STATE_LAST_ACK:
		return "LAST_ACK"
	case MIB_TCP_STATE_TIME_WAIT:
		return "TIME_WAIT"
	case MIB_TCP_STATE_DELETE_TCB:
		return "DELETE_TCB"
	}
	return fmt.Sprintf("STATE_%d", s)
}

func tcpStateColor(s uint32) string {
	switch s {
	case MIB_TCP_STATE_ESTAB:
		return clrGreen
	case MIB_TCP_STATE_LISTEN:
		return clrCyan
	case MIB_TCP_STATE_TIME_WAIT, MIB_TCP_STATE_CLOSE_WAIT:
		return clrYellow
	}
	return clrGray
}

func processNameForPid(pid uint32) string {
	if pid == 0 {
		return ""
	}
	h, _, _ := pOpenProcess.Call(uintptr(PROCESS_QUERY_LIMITED), 0, uintptr(pid))
	if h == 0 {
		return ""
	}
	defer pCloseHandle.Call(h)
	buf := make([]uint16, 1024)
	size := uint32(len(buf))
	r, _, _ := pQueryFullProcessImageNameW.Call(h, 0,
		uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&size)))
	if r == 0 {
		return ""
	}
	full := syscall.UTF16ToString(buf[:size])
	return filepath.Base(full)
}

func cmdConn(args []string) int {
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

	var rows []ConnRow
	add := func(src []ConnRow, err error) {
		if err != nil {
			bugs.Add("WARN", "query: %v", err)
			return
		}
		rows = append(rows, src...)
	}
	if protoFilter == "all" || protoFilter == "tcp" || protoFilter == "tcp4" {
		add(queryTcp4())
	}
	if protoFilter == "all" || protoFilter == "tcp" || protoFilter == "tcp6" {
		add(queryTcp6())
	}
	if protoFilter == "all" || protoFilter == "udp" || protoFilter == "udp4" {
		add(queryUdp4())
	}
	if protoFilter == "all" || protoFilter == "udp" || protoFilter == "udp6" {
		add(queryUdp6())
	}

	var filtered []ConnRow
	for _, r := range rows {
		if stateFilter != "" && strings.HasPrefix(r.Proto, "tcp") {
			if tcpStateName(r.State) != stateFilter {
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
			r.ProcName = processNameForPid(r.Pid)
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
				m["state"] = tcpStateName(r.State)
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
			st = tcpStateName(r.State)
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
			st = tcpStateName(r.State)
			stColor = tcpStateColor(r.State)
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

func adapterTypeName(t uint32) string {
	switch t {
	case IF_TYPE_ETHERNET_CSMACD:
		return "ethernet"
	case IF_TYPE_IEEE80211:
		return "wifi"
	case IF_TYPE_SOFTWARE_LOOPBACK:
		return "loopback"
	case IF_TYPE_TUNNEL:
		return "tunnel"
	}
	return fmt.Sprintf("iftype-%d", t)
}

func cmdAdapters(args []string) int {
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

	adapters, err := queryAdapters()
	if err != nil {
		fmt.Fprintf(os.Stderr, "netctl: %v\n", err)
		return 5
	}
	if upOnly {
		var filtered []AdapterInfo
		for _, a := range adapters {
			if a.OperStatus == IfOperStatusUp {
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
				"type":        adapterTypeName(a.IfType),
				"up":          a.OperStatus == IfOperStatusUp,
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
		if w := dispWidth(adapterTypeName(a.IfType)); w > typeW {
			typeW = w
		}
		st := "down"
		if a.OperStatus == IfOperStatusUp {
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
		if a.OperStatus == IfOperStatusUp {
			st = "up"
			stColor = clrGreen
		}
		ipv4 := strings.Join(a.IPv4s, ",")
		dns := strings.Join(a.DNS, ",")
		line := padRight(strconv.FormatUint(uint64(a.IfIndex), 10), idxW) + "  " +
			padRight(a.Name, nameW) + "  " +
			padRight(adapterTypeName(a.IfType), typeW) + "  " +
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

func cmdDns(args []string) int {
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

	adapters, err := queryAdapters()
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

func cmdHosts(args []string) int {
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
		data, err := os.ReadFile(hostsPath())
		if err != nil {
			fmt.Fprintf(os.Stderr, "netctl: %v\n", err)
			return 5
		}
		lines := strings.Split(string(data), "\n")
		fmt.Println(c(clrBold+clrCyan, hostsPath()))
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
		if !regexp.MustCompile(`^[0-9a-fA-F:.]+$`).MatchString(ip) {
			fmt.Fprintf(os.Stderr, "hosts add: invalid IP %q\n", ip)
			return 2
		}
		hostnames := pos[1:]
		for _, h := range hostnames {
			if !regexp.MustCompile(`^[A-Za-z0-9.\-]+$`).MatchString(h) {
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
		idx := beginWriteOp()
		backupRel, backupGz, err := backupHosts(idx)
		if err != nil {
			fmt.Fprintf(os.Stderr, "netctl: backup failed, aborting: %v\n", err)
			return 5
		}
		if err := applyHostsAdd(ip, hostnames); err != nil {
			fmt.Fprintf(os.Stderr, "netctl: %v\n", err)
			return 5
		}
		saveOpRecord(idx, &opRecord{
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
		idx := beginWriteOp()
		backupRel, backupGz, err := backupHosts(idx)
		if err != nil {
			fmt.Fprintf(os.Stderr, "netctl: backup failed, aborting: %v\n", err)
			return 5
		}
		if err := applyHostsRemove(hostnames); err != nil {
			fmt.Fprintf(os.Stderr, "netctl: %v\n", err)
			return 5
		}
		saveOpRecord(idx, &opRecord{
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
		return hostsManualRestore()
	}
	fmt.Fprintf(os.Stderr, "hosts: unknown subcommand %q (show|add|remove|restore)\n", sub)
	return 2
}

func hostsManualRestore() int {
	lines, err := readLogLines()
	if err != nil {
		fmt.Fprintf(os.Stderr, "netctl: %v\n", err)
		return 4
	}
	for i := len(lines) - 1; i >= 0; i-- {
		if !manifestExists(i) {
			continue
		}
		rec, err := loadOpRecord(i)
		if err != nil {
			continue
		}
		if rec.Op != "hosts-add" && rec.Op != "hosts-remove" {
			continue
		}
		if err := restoreHosts(rec.BackupFile, rec.BackupGzipped); err != nil {
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

func printProxy(st ProxyState) {
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

func cmdProxy(args []string) int {
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
		printProxy(readProxyState())
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
		old := readProxyState()
		if !force {
			fmt.Fprintf(os.Stderr, "old: enable=%v server=%q bypass=%q\n", old.Enable, old.Server, old.Override)
			if !confirm(fmt.Sprintf("set proxy to %q?", server)) {
				return 1
			}
		}
		idx := beginWriteOp()
		newState := ProxyState{Enable: true, Server: server, Override: bypass, Exists: true}
		if err := writeProxyState(newState); err != nil {
			fmt.Fprintf(os.Stderr, "netctl: set proxy: %v\n", err)
			return 5
		}
		saveOpRecord(idx, &opRecord{
			Op:       "proxy-set",
			TS:       time.Now().Format("2006-01-02 15:04:05"),
			Cmd:      buildCmdLine(os.Args),
			OldProxy: &proxySnap{Enable: old.Enable, Server: old.Server, Override: old.Override, Exists: old.Exists},
			NewProxy: &proxySnap{Enable: true, Server: server, Override: bypass, Exists: true},
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
		old := readProxyState()
		if !force {
			fmt.Fprintf(os.Stderr, "old: enable=%v server=%q bypass=%q\n", old.Enable, old.Server, old.Override)
			if !confirm("disable system proxy?") {
				return 1
			}
		}
		idx := beginWriteOp()
		newState := ProxyState{Enable: false}
		if err := writeProxyState(newState); err != nil {
			fmt.Fprintf(os.Stderr, "netctl: unset proxy: %v\n", err)
			return 5
		}
		saveOpRecord(idx, &opRecord{
			Op:       "proxy-unset",
			TS:       time.Now().Format("2006-01-02 15:04:05"),
			Cmd:      buildCmdLine(os.Args),
			OldProxy: &proxySnap{Enable: old.Enable, Server: old.Server, Override: old.Override, Exists: old.Exists},
			NewProxy: &proxySnap{Enable: false},
		})
		fmt.Printf("%s proxy disabled\n", c(clrYellow, "unset"))
		return 0

	case "restore":
		return proxyManualRestore()
	}
	fmt.Fprintf(os.Stderr, "proxy: unknown subcommand %q (show|set|unset|restore)\n", sub)
	return 2
}

func proxyManualRestore() int {
	lines, err := readLogLines()
	if err != nil {
		fmt.Fprintf(os.Stderr, "netctl: %v\n", err)
		return 4
	}
	for i := len(lines) - 1; i >= 0; i-- {
		if !manifestExists(i) {
			continue
		}
		rec, err := loadOpRecord(i)
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
			k, err := regOpenKey(HKCU, proxyKeyPath, KEY_WRITE)
			if err == nil {
				_ = regDeleteValue(k, "ProxyEnable")
				_ = regDeleteValue(k, "ProxyServer")
				_ = regDeleteValue(k, "ProxyOverride")
				regCloseKey(k)
			}
			fmt.Fprintf(os.Stderr, "restored proxy from op #%d (removed)\n", i)
			return 0
		}
		st := ProxyState{
			Enable:   rec.OldProxy.Enable,
			Server:   rec.OldProxy.Server,
			Override: rec.OldProxy.Override,
			Exists:   rec.OldProxy.Exists,
		}
		if err := writeProxyState(st); err != nil {
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
	case "hosts-add", "hosts-remove":
		if rec.BackupFile == "" {
			return fmt.Errorf("no hosts backup recorded")
		}
		return restoreHosts(rec.BackupFile, rec.BackupGzipped)

	case "proxy-set", "proxy-unset":
		if rec.OldProxy == nil {
			return fmt.Errorf("no old proxy recorded")
		}
		if !rec.OldProxy.Exists {
			k, err := regOpenKey(HKCU, proxyKeyPath, KEY_WRITE)
			if err != nil {
				return nil
			}
			defer regCloseKey(k)
			_ = regDeleteValue(k, "ProxyEnable")
			_ = regDeleteValue(k, "ProxyServer")
			_ = regDeleteValue(k, "ProxyOverride")
			return nil
		}
		st := ProxyState{
			Enable:   rec.OldProxy.Enable,
			Server:   rec.OldProxy.Server,
			Override: rec.OldProxy.Override,
			Exists:   rec.OldProxy.Exists,
		}
		return writeProxyState(st)
	}
	return fmt.Errorf("unknown op %q", rec.Op)
}

// ============================================================================
// Help
// ============================================================================

func printHelp() {
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
  -o, --out <path>     Redirect stdout to a file.
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
		if err := setupOutput(outPath); err != nil {
			fmt.Fprintf(os.Stderr, "netctl: %v\n", err)
			bugs.Flush()
			os.Exit(2)
		}
	}

	if has(args, "--version") {
		fmt.Println("netctl v1.0.0")
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
			fmt.Fprintln(os.Stderr, "netctl: missing command, use -h for help")
			code = 2
			break
		}
		cmd := args[cmdIdx]
		rest := append([]string{}, args[:cmdIdx]...)
		rest = append(rest, args[cmdIdx+1:]...)

		switch cmd {
		case "conn", "connections":
			code = cmdConn(rest)
		case "dns":
			code = cmdDns(rest)
		case "adapters", "if":
			code = cmdAdapters(rest)
		case "hosts":
			code = cmdHosts(rest)
		case "proxy":
			code = cmdProxy(rest)
		default:
			fmt.Fprintf(os.Stderr, "netctl: unknown command %q\n", cmd)
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