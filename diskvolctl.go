//go:build windows && amd64

package main

// diskvolctl — Disk and volume read-only viewer.
// Single-file, standard-library-only build:
//
//   go build -trimpath -ldflags "-s -w" -o diskvolctl.exe diskvolctl.go
//
// Log: ./diskvolctl_backup/diskvolctl.log  [cmd] [ts] [exit code]

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
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

	pGetStdHandle   = kernel32.NewProc("GetStdHandle")
	pGetConsoleMode = kernel32.NewProc("GetConsoleMode")

	pCreateFileW                      = kernel32.NewProc("CreateFileW")
	pDeviceIoControl                  = kernel32.NewProc("DeviceIoControl")
	pCloseHandle                      = kernel32.NewProc("CloseHandle")
	pGetDriveTypeW                    = kernel32.NewProc("GetDriveTypeW")
	pGetVolumeInformationW            = kernel32.NewProc("GetVolumeInformationW")
	pGetDiskFreeSpaceExW              = kernel32.NewProc("GetDiskFreeSpaceExW")
	pFindFirstVolumeW                 = kernel32.NewProc("FindFirstVolumeW")
	pFindNextVolumeW                  = kernel32.NewProc("FindNextVolumeW")
	pFindVolumeClose                  = kernel32.NewProc("FindVolumeClose")
	pGetVolumePathNamesForVolumeNameW = kernel32.NewProc("GetVolumePathNamesForVolumeNameW")
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
		fmt.Fprintln(os.Stderr, "[diskvolctl] -b/--bugs enabled: no errors or warnings captured this run.")
		return
	}
	fmt.Fprintf(os.Stderr, "\n--- diskvolctl bugs report (%d entries) ---\n", len(b.entries))
	for _, e := range b.entries {
		fmt.Fprintf(os.Stderr, "[%s] %s %s\n", e.At.Format("15:04:05.000"), e.Level, e.Msg)
	}
	fmt.Fprintln(os.Stderr, "--- end of bugs report ---")
}

// ============================================================================
// Windows structures
// ============================================================================

type STORAGE_PROPERTY_QUERY struct {
	PropertyId uint32
	QueryType  uint32
	Additional [1]byte
}

type STORAGE_DEVICE_DESCRIPTOR struct {
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

type DEVICE_TRIM_DESCRIPTOR struct {
	Version     uint32
	Size        uint32
	TrimEnabled byte
}

type DISK_GEOMETRY struct {
	Cylinders         int64
	MediaType         uint32
	TracksPerCylinder uint32
	SectorsPerTrack   uint32
	BytesPerSector    uint32
}

type DISK_GEOMETRY_EX struct {
	Geometry DISK_GEOMETRY
	DiskSize int64
	Data     [1]byte
}

type PARTITION_INFORMATION_EX struct {
	PartitionStyle   uint32
	StartingOffset   int64
	PartitionLength  int64
	PartitionNumber  uint32
	RewritePartition byte
	_                [3]byte
	Union            [144]byte
}

// ============================================================================
// Data model
// ============================================================================

type PartitionInfo struct {
	Number uint32 `json:"number"`
	Offset int64  `json:"offset"`
	Length int64  `json:"length"`
	Style  string `json:"style"`
}

type DiskInfo struct {
	Index      uint32          `json:"index"`
	Size       int64           `json:"size"`
	Vendor     string          `json:"vendor,omitempty"`
	Product    string          `json:"product,omitempty"`
	Revision   string          `json:"revision,omitempty"`
	Serial     string          `json:"serial,omitempty"`
	BusType    string          `json:"busType"`
	Removable  bool            `json:"removable"`
	Trim       bool            `json:"trim"`
	Partitions []PartitionInfo `json:"partitions"`
	Error      string          `json:"error,omitempty"`
}

type VolumeInfo struct {
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
	GENERIC_READ     = 0x80000000
	FILE_SHARE_READ  = 0x00000001
	FILE_SHARE_WRITE = 0x00000002
	OPEN_EXISTING    = 3

	IOCTL_STORAGE_QUERY_PROPERTY = 0x2D1400
	IOCTL_DISK_GET_DRIVE_LAYOUT_EX = 0x70050
	IOCTL_DISK_GET_DRIVE_GEOMETRY_EX = 0x700A0

	StorageDeviceProperty     = 0
	StorageDeviceTrimProperty = 8

	PropertyStandardQuery = 0

	BusTypeUnknown           = 0
	BusTypeScsi              = 1
	BusTypeAtapi             = 2
	BusTypeAta               = 3
	BusType1394              = 4
	BusTypeSsa               = 5
	BusTypeFibre             = 6
	BusTypeUsb               = 7
	BusTypeRAID              = 8
	BusTypeiScsi             = 9
	BusTypeSas               = 10
	BusTypeSata              = 11
	BusTypeSd                = 12
	BusTypeMmc               = 13
	BusTypeVirtual           = 14
	BusTypeFileBackedVirtual = 15
	BusTypeSpaces            = 16
	BusTypeNvme              = 17
	BusTypeSCM               = 18
	BusTypeUfs               = 19
)

func win32UTF16Ptr(s string) *uint16 {
	p, _ := syscall.UTF16PtrFromString(s)
	return p
}

func openDevice(path string) (syscall.Handle, error) {
	p := win32UTF16Ptr(path)
	h, _, err := pCreateFileW.Call(
		uintptr(unsafe.Pointer(p)),
		uintptr(GENERIC_READ),
		uintptr(FILE_SHARE_READ|FILE_SHARE_WRITE),
		0,
		uintptr(OPEN_EXISTING),
		0,
		0,
	)
	if syscall.Handle(h) == syscall.InvalidHandle {
		return 0, err
	}
	return syscall.Handle(h), nil
}

func deviceIoControl(h syscall.Handle, code uint32, inBuf []byte, outBuf []byte) (uint32, error) {
	var inPtr, outPtr uintptr
	if len(inBuf) > 0 {
		inPtr = uintptr(unsafe.Pointer(&inBuf[0]))
	}
	if len(outBuf) > 0 {
		outPtr = uintptr(unsafe.Pointer(&outBuf[0]))
	}
	var returned uint32
	r, _, err := pDeviceIoControl.Call(
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

// storageQueryBytes serializes a STORAGE_PROPERTY_QUERY into a byte slice
// without unsafe fixed-size array tricks.
func storageQueryBytes(q *STORAGE_PROPERTY_QUERY) []byte {
	size := int(unsafe.Sizeof(*q))
	return unsafe.Slice((*byte)(unsafe.Pointer(q)), size)
}

func busTypeName(t uint32) string {
	switch t {
	case BusTypeUnknown:
		return "unknown"
	case BusTypeScsi:
		return "SCSI"
	case BusTypeAtapi:
		return "ATAPI"
	case BusTypeAta:
		return "ATA"
	case BusType1394:
		return "1394"
	case BusTypeSsa:
		return "SSA"
	case BusTypeFibre:
		return "Fibre"
	case BusTypeUsb:
		return "USB"
	case BusTypeRAID:
		return "RAID"
	case BusTypeiScsi:
		return "iSCSI"
	case BusTypeSas:
		return "SAS"
	case BusTypeSata:
		return "SATA"
	case BusTypeSd:
		return "SD"
	case BusTypeMmc:
		return "MMC"
	case BusTypeVirtual:
		return "Virtual"
	case BusTypeFileBackedVirtual:
		return "FileBackedVirtual"
	case BusTypeSpaces:
		return "StorageSpaces"
	case BusTypeNvme:
		return "NVMe"
	case BusTypeSCM:
		return "SCM"
	case BusTypeUfs:
		return "UFS"
	}
	return fmt.Sprintf("bus-%d", t)
}

func driveTypeName(t uint32) string {
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

func queryDiskInfo(index uint32) DiskInfo {
	di := DiskInfo{Index: index}

	path := fmt.Sprintf(`\\.\PhysicalDrive%d`, index)
	h, err := openDevice(path)
	if err != nil {
		di.Error = err.Error()
		return di
	}
	defer pCloseHandle.Call(uintptr(h))

	// --- Device descriptor ---
	query := STORAGE_PROPERTY_QUERY{
		PropertyId: StorageDeviceProperty,
		QueryType:  PropertyStandardQuery,
	}
	buf := make([]byte, 1024)
	n, err := deviceIoControl(h, IOCTL_STORAGE_QUERY_PROPERTY,
		storageQueryBytes(&query), buf)
	if err == nil && n > 0 {
		desc := (*STORAGE_DEVICE_DESCRIPTOR)(unsafe.Pointer(&buf[0]))
		di.Vendor = cStringAt(buf, desc.VendorIdOffset)
		di.Product = cStringAt(buf, desc.ProductIdOffset)
		di.Revision = cStringAt(buf, desc.ProductRevisionOffset)
		di.Serial = cStringAt(buf, desc.SerialNumberOffset)
		di.BusType = busTypeName(desc.BusType)
		di.Removable = desc.RemovableMedia != 0
	}

	// --- TRIM descriptor ---
	query.PropertyId = StorageDeviceTrimProperty
	buf2 := make([]byte, 32)
	n, err = deviceIoControl(h, IOCTL_STORAGE_QUERY_PROPERTY,
		storageQueryBytes(&query), buf2)
	if err == nil && n >= uint32(unsafe.Sizeof(DEVICE_TRIM_DESCRIPTOR{})) {
		trim := (*DEVICE_TRIM_DESCRIPTOR)(unsafe.Pointer(&buf2[0]))
		di.Trim = trim.TrimEnabled != 0
	}

	// --- Geometry (EX: includes DiskSize) ---
	geomBuf := make([]byte, 256)
	n, err = deviceIoControl(h, IOCTL_DISK_GET_DRIVE_GEOMETRY_EX, nil, geomBuf)
	if err == nil && n >= uint32(unsafe.Sizeof(DISK_GEOMETRY_EX{})) {
		geom := (*DISK_GEOMETRY_EX)(unsafe.Pointer(&geomBuf[0]))
		di.Size = geom.DiskSize
	}

	// --- Drive layout ---
	layoutBuf := make([]byte, 1024*1024)
	n, err = deviceIoControl(h, IOCTL_DISK_GET_DRIVE_LAYOUT_EX, nil, layoutBuf)
	if err == nil && n >= 8 {
		style := *(*uint32)(unsafe.Pointer(&layoutBuf[0]))
		count := *(*uint32)(unsafe.Pointer(&layoutBuf[4]))
		styleName := "MBR"
		if style == 1 {
			styleName = "GPT"
		}
		off := 48
		entrySize := int(unsafe.Sizeof(PARTITION_INFORMATION_EX{}))
		for i := uint32(0); i < count && off+entrySize <= len(layoutBuf); i++ {
			part := (*PARTITION_INFORMATION_EX)(unsafe.Pointer(&layoutBuf[off]))
			if part.PartitionLength > 0 {
				di.Partitions = append(di.Partitions, PartitionInfo{
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

func cStringAt(buf []byte, offset uint32) string {
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

func listVolumes() []VolumeInfo {
	var out []VolumeInfo

	buf := make([]uint16, 512)
	h, _, err := pFindFirstVolumeW.Call(uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)))
	if syscall.Handle(h) == syscall.InvalidHandle {
		bugs.Add("WARN", "FindFirstVolume: %v", err)
		return out
	}
	defer pFindVolumeClose.Call(h)

	for {
		volID := syscall.UTF16ToString(buf)
		volID = strings.TrimSuffix(volID, `\`)

		vi := VolumeInfo{VolumeID: volID}
		queryVolumeInfo(&vi)
		out = append(out, vi)

		buf = make([]uint16, 512)
		r, _, _ := pFindNextVolumeW.Call(h, uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)))
		if r == 0 {
			break
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].DriveLetters < out[j].DriveLetters })
	return out
}

func queryVolumeInfo(vi *VolumeInfo) {
	volName := vi.VolumeID + `\`

	// Drive letters
	pathBuf := make([]uint16, 1024)
	var pathLen uint32
	pGetVolumePathNamesForVolumeNameW.Call(
		uintptr(unsafe.Pointer(win32UTF16Ptr(volName))),
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
	r, _, _ := pGetVolumeInformationW.Call(
		uintptr(unsafe.Pointer(win32UTF16Ptr(root))),
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
		r, _, _ = pGetDiskFreeSpaceExW.Call(
			uintptr(unsafe.Pointer(win32UTF16Ptr(letters[0]+`\`))),
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
		dt, _, _ := pGetDriveTypeW.Call(uintptr(unsafe.Pointer(win32UTF16Ptr(letters[0]+`\`))))
		vi.DriveType = driveTypeName(uint32(dt))
	}
}

// ============================================================================
// Output formatting
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

func printDisks(disks []DiskInfo) {
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

func printVolumes(vols []VolumeInfo) {
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

func padRight(s string, width int) string {
	w := dispWidth(s)
	if w >= width {
		return s
	}
	return s + strings.Repeat(" ", width-w)
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

// ============================================================================
// Log
// ============================================================================

const (
	backupDirName = "diskvolctl_backup"
	logFileName   = "diskvolctl.log"
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
	for i := len(lines) - 1; i >= 0; i-- {
		n := len(lines) - i
		fmt.Printf("[%d] %s\n", n, lines[i])
	}
	fmt.Fprintf(os.Stderr, "\n%d entrie(s). Log: %s\n", len(lines), logPath())
	return 0
}

func cmdRollback() int {
	fmt.Fprintln(os.Stderr, "diskvolctl is read-only: there are no operations to roll back")
	fmt.Fprintln(os.Stderr, "  diskvolctl only reads disk and volume metadata.")
	fmt.Fprintln(os.Stderr, "  Its history is for audit only; use --history to view it.")
	return 0
}

// ============================================================================
// Help
// ============================================================================

func printHelp() {
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

HISTORY
  Every invocation (except -h/--help/--version/--history/--rollback/--dry-run)
  appends one line to ./diskvolctl_backup/diskvolctl.log:
    [command line] [timestamp] [exit code]
  --history prints it, numbered from newest (1) to oldest.

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
		finalExit(0, false)
	}
	if len(args) == 0 {
		// default action: list everything
	} else if has(args, "-h", "--help") {
		printHelp()
		finalExit(0, false)
	} else if has(args, "--history") {
		finalExit(cmdHistory(), false)
	} else if has(args, "--rollback") {
		finalExit(cmdRollback(), false)
	} else if has(args, "disks") || has(args, "volumes") || has(args, "--json") {
		// valid: handled below
	} else {
		fmt.Fprintf(os.Stderr, "diskvolctl: unexpected argument %q (use -h for help)\n", args[0])
		finalExit(2, true)
	}

	if outPath != "" {
		if err := setupOutput(outPath); err != nil {
			fmt.Fprintf(os.Stderr, "diskvolctl: %v\n", err)
			bugs.Flush()
			os.Exit(2)
		}
	}

	if dryRun {
		fmt.Println("[dry-run] would enumerate physical disks and volumes")
		finalExit(0, false)
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

	var disks []DiskInfo
	var vols []VolumeInfo

	if showDisks {
		for i := uint32(0); i < 32; i++ {
			di := queryDiskInfo(i)
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
		vols = listVolumes()
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
			printDisks(disks)
		}
		if showVolumes && len(vols) > 0 {
			printVolumes(vols)
		}
	}

	finalExit(0, true)
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