//go:build windows && amd64

package main

// openerctl — File type identification and read-only previewer with simple
// decryption attempts. Single-file, standard-library-only build:
//
//   go build -trimpath -ldflags "-s -w" -o openerctl.exe openerctl.go
//
// Log: ./openerctl_backup/openerctl.log  [cmd] [ts] [exit code]

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"crypto/md5"
	"crypto/rc4"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math"
	"os"
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
		fmt.Fprintln(os.Stderr, "[openerctl] -b/--bugs enabled: no errors or warnings captured this run.")
		return
	}
	fmt.Fprintf(os.Stderr, "\n--- openerctl bugs report (%d entries) ---\n", len(b.entries))
	for _, e := range b.entries {
		fmt.Fprintf(os.Stderr, "[%s] %s %s\n", e.At.Format("15:04:05.000"), e.Level, e.Msg)
	}
	fmt.Fprintln(os.Stderr, "--- end of bugs report ---")
}

// ============================================================================
// Magic signatures
// ============================================================================

type MagicSig struct {
	Offset   int
	Bytes    []byte
	Ext      string
	Desc     string
	Category string
}

var magicSigs = []MagicSig{
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

type FileType struct {
	Ext          string
	Description  string
	Category     string
	ByMagic      bool
	ByExtension  bool
	Encrypted    bool
	Text         bool
	EntropyValue float64
	Size         int64
	PE           *PEInfo
}

func detectByMagic(data []byte) *MagicSig {
	for _, sig := range magicSigs {
		end := sig.Offset + len(sig.Bytes)
		if end > len(data) {
			continue
		}
		if bytes.Equal(data[sig.Offset:end], sig.Bytes) {
			s := sig
			return &s
		}
	}
	// TAR has "ustar" at offset 257
	if len(data) > 265 {
		if bytes.Equal(data[257:262], []byte("ustar")) {
			return &MagicSig{Ext: "TAR", Desc: "tar archive", Category: "archive"}
		}
	}
	// ISO 9660 has "CD001" at offset 32769 (sector 16 + 1)
	if len(data) > 32774 {
		if bytes.Equal(data[32769:32774], []byte("CD001")) {
			return &MagicSig{Ext: "ISO", Desc: "ISO 9660 image", Category: "archive"}
		}
	}
	return nil
}

var extMap = map[string]FileType{
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

func detectFile(path string, data []byte) *FileType {
	ft := &FileType{Size: int64(len(data))}
	ext := strings.ToLower(strings.TrimPrefix(filepath.Ext(path), "."))
	if t, ok := extMap[ext]; ok {
		ft.Ext = t.Ext
		ft.Description = t.Description
		ft.Category = t.Category
		ft.ByExtension = true
	}
	if sig := detectByMagic(data); sig != nil {
		// Magic wins over extension for the Ext/Description fields, but we
		// remember that the extension also matched.
		ft.Ext = sig.Ext
		ft.Description = sig.Desc
		ft.Category = sig.Category
		ft.ByMagic = true
	}
	ft.EntropyValue = entropyOf(data)
	if ft.Category == "" {
		if looksText(data) {
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
		ft.PE = parsePE(data)
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

func entropyOf(data []byte) float64 {
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

func printableRatio(data []byte) float64 {
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

func looksText(data []byte) bool {
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
	ratio := printableRatio(sample)
	if ratio < 0.90 {
		return false
	}
	// Either valid UTF-8 or pure ASCII
	if utf8.Valid(sample) {
		return true
	}
	return ratio > 0.95
}

// ============================================================================
// PE parsing
// ============================================================================

type PESection struct {
	Name            string
	VirtualSize     uint32
	VirtualAddr     uint32
	RawSize         uint32
	RawPtr          uint32
	Characteristics uint32
}

type PEInfo struct {
	Valid            bool
	Machine          uint16
	NumberOfSections uint16
	Timestamp        uint32
	Characteristics  uint16
	OptionalMagic    uint16
	EntryPoint       uint32
	ImageBase        uint64
	Subsystem        uint16
	Sections         []PESection
}

func parsePE(data []byte) *PEInfo {
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
	pe := &PEInfo{Valid: true}
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
		pe.Sections = append(pe.Sections, PESection{
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

func peMachineName(m uint16) string {
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

func peSubsystemName(s uint16) string {
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

func imageDimensions(data []byte, ext string) (int, int, bool) {
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
			if i+3 >= len(data) {
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

func previewText(data []byte, maxLines int) {
	lines := bytes.Split(data, []byte("\n"))
	if len(lines) > maxLines {
		lines = lines[:maxLines]
	}
	for i, line := range lines {
		line = bytes.TrimSuffix(line, []byte("\r"))
		fmt.Printf("%s %s\n", c(clrGray, fmt.Sprintf("%4d |", i+1)), string(line))
	}
	if len(lines) < len(bytes.Split(data, []byte("\n"))) {
		fmt.Println(c(clrGray, "  ..."))
	}
}

func hexDump(data []byte, startOffset int64, maxBytes int) {
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
// Decryption
// ============================================================================

var weakPasswords = []string{
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

type KeyCandidate struct {
	Bytes []byte
	Desc  string
}

type IVCandidate struct {
	Bytes []byte
	Desc  string
}

type DecryptAttempt struct {
	Algorithm string
	Mode      string
	Padding   string
	Key       []byte
	KeyDesc   string
	IV        []byte
	IVDesc    string
}

type decryptOpts struct {
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

// deriveKey normalizes input to a key of exactly `size` bytes.
// If input already matches, it is used as-is. Otherwise it is hashed with
// SHA-256 and truncated/extended, which is what most "user password -> key"
// pipelines do in practice.
func deriveKey(input []byte, size int) []byte {
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

func parseHexOrText(s string, isHex bool) []byte {
	if isHex {
		clean := strings.ReplaceAll(s, " ", "")
		clean = strings.ReplaceAll(clean, ":", "")
		if b, err := hex.DecodeString(clean); err == nil {
			return b
		}
	}
	return []byte(s)
}

func scanHardcodedKeys(data []byte, limit int) []KeyCandidate {
	var keys []KeyCandidate
	seen := map[string]bool{}
	sample := data
	if len(sample) > 4*1024*1024 {
		sample = sample[:4*1024*1024]
	}

	// Look for base64-ish or long ASCII runs that could be keys.
	// The most useful pattern is a string of printable characters of length
	// exactly 16, 24, or 32.
	re := regexp.MustCompile(`[A-Za-z0-9+/=._!@#$%^&*\-]{16,64}`)
	for _, m := range re.FindAll(sample, limit*4) {
		if len(m) < 16 {
			continue
		}
		for _, size := range []int{32, 24, 16} {
			if len(m) >= size {
				k := m[:size]
				key := strings.ToLower(string(k))
				if seen[key] {
					continue
				}
				seen[key] = true
				keys = append(keys, KeyCandidate{
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

func loadDictFile(path string) []string {
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

func pkcs7Unpad(data []byte, blockSize int) ([]byte, error) {
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

func zeroUnpad(data []byte) []byte {
	i := len(data)
	for i > 0 && data[i-1] == 0 {
		i--
	}
	return data[:i]
}

func decryptAESCBC(ct, key, iv []byte, usePKCS7 bool) ([]byte, error) {
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
		return pkcs7Unpad(plain, aes.BlockSize)
	}
	return zeroUnpad(plain), nil
}

func decryptAESECB(ct, key []byte, usePKCS7 bool) ([]byte, error) {
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
		return pkcs7Unpad(plain, aes.BlockSize)
	}
	return zeroUnpad(plain), nil
}

func decryptAESCTR(ct, key, iv []byte) ([]byte, error) {
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

func decryptDESCBC(ct, key, iv []byte, usePKCS7 bool) ([]byte, error) {
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
		return pkcs7Unpad(plain, des.BlockSize)
	}
	return zeroUnpad(plain), nil
}

func decryptDESECB(ct, key []byte, usePKCS7 bool) ([]byte, error) {
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
		return pkcs7Unpad(plain, des.BlockSize)
	}
	return zeroUnpad(plain), nil
}

func decryptRC4(ct, key []byte) ([]byte, error) {
	c, err := rc4.NewCipher(key)
	if err != nil {
		return nil, err
	}
	plain := make([]byte, len(ct))
	c.XORKeyStream(plain, ct)
	return plain, nil
}

func runAttempt(data []byte, at DecryptAttempt) ([]byte, error) {
	switch at.Algorithm {
	case "aes":
		switch at.Mode {
		case "cbc":
			return decryptAESCBC(data, at.Key, at.IV, at.Padding == "pkcs7")
		case "ecb":
			return decryptAESECB(data, at.Key, at.Padding == "pkcs7")
		case "ctr":
			return decryptAESCTR(data, at.Key, at.IV)
		}
	case "des":
		switch at.Mode {
		case "cbc":
			return decryptDESCBC(data, at.Key, at.IV, at.Padding == "pkcs7")
		case "ecb":
			return decryptDESECB(data, at.Key, at.Padding == "pkcs7")
		}
	case "rc4":
		return decryptRC4(data, at.Key)
	}
	return nil, fmt.Errorf("unsupported %s/%s", at.Algorithm, at.Mode)
}

func looksDecrypted(plain []byte) bool {
	if len(plain) == 0 {
		return false
	}
	// Strong signal: known magic
	if detectByMagic(plain) != nil {
		return true
	}
	// Text check
	if looksText(plain) {
		return true
	}
	// High printable ratio without NULs is also suspicious-ok
	if bytes.IndexByte(plain, 0) < 0 && printableRatio(plain) > 0.80 && utf8.Valid(plain) {
		return true
	}
	return false
}

func collectAttempts(data []byte, opts *decryptOpts) []DecryptAttempt {
	var keys []KeyCandidate
	seen := map[string]bool{}
	addKey := func(b []byte, desc string) {
		k := string(b)
		if seen[k] {
			return
		}
		seen[k] = true
		keys = append(keys, KeyCandidate{Bytes: b, Desc: desc})
	}

	if opts.key != nil {
		addKey(opts.key, opts.keyDesc)
	}
	if opts.password != "" {
		addKey(deriveKey([]byte(opts.password), 32), "password:"+opts.password)
	}
	if !opts.noDict {
		for _, pw := range weakPasswords {
			addKey(deriveKey([]byte(pw), 32), "dict:"+pw)
		}
	}
	if !opts.noDict && opts.dictFile != "" {
		for _, pw := range loadDictFile(opts.dictFile) {
			addKey(deriveKey([]byte(pw), 32), "dict-file:"+pw)
		}
	}
	if !opts.noScan {
		scanned := scanHardcodedKeys(data, 30)
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
				combos = append(combos, algMode{"aes", strings.ToLower(opts.mode)})
			} else {
				combos = append(combos, algMode{"aes", "cbc"}, algMode{"aes", "ecb"})
			}
		case "des":
			if opts.mode != "" {
				combos = append(combos, algMode{"des", strings.ToLower(opts.mode)})
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

	var attempts []DecryptAttempt

	// Build IV candidates
	var ivs []IVCandidate
	if opts.iv != nil {
		ivs = append(ivs, IVCandidate{Bytes: opts.iv, Desc: opts.ivDesc})
	} else {
		ivs = append(ivs, IVCandidate{Bytes: make([]byte, 16), Desc: "zeros(16)"})
		ivs = append(ivs, IVCandidate{Bytes: make([]byte, 8), Desc: "zeros(8)"})
		seq := make([]byte, 16)
		for i := range seq {
			seq[i] = byte(i)
		}
		ivs = append(ivs, IVCandidate{Bytes: seq, Desc: "seq(0..15)"})
	}

	for _, kc := range keys {
		for _, am := range combos {
			switch am.alg {
			case "aes":
				for _, size := range []int{32, 24, 16} {
					k := deriveKey(kc.Bytes, size)
					if am.mode == "cbc" || am.mode == "ctr" {
						for _, iv := range ivs {
							if len(iv.Bytes) != 16 {
								continue
							}
							for _, pad := range []string{"pkcs7", "zero"} {
								attempts = append(attempts, DecryptAttempt{
									Algorithm: "aes", Mode: am.mode, Padding: pad,
									Key: k, KeyDesc: fmt.Sprintf("%s (AES-%d)", kc.Desc, size*8),
									IV: iv.Bytes, IVDesc: iv.Desc,
								})
							}
						}
					} else {
						for _, pad := range []string{"pkcs7", "zero"} {
							attempts = append(attempts, DecryptAttempt{
								Algorithm: "aes", Mode: am.mode, Padding: pad,
								Key: k, KeyDesc: fmt.Sprintf("%s (AES-%d)", kc.Desc, size*8),
							})
						}
					}
				}
			case "des":
				k := deriveKey(kc.Bytes, 8)
				if am.mode == "cbc" {
					for _, iv := range ivs {
						if len(iv.Bytes) != 8 {
							continue
						}
						for _, pad := range []string{"pkcs7", "zero"} {
							attempts = append(attempts, DecryptAttempt{
								Algorithm: "des", Mode: "cbc", Padding: pad,
								Key: k, KeyDesc: kc.Desc + " (DES)",
								IV: iv.Bytes, IVDesc: iv.Desc,
							})
						}
					}
				} else {
					for _, pad := range []string{"pkcs7", "zero"} {
						attempts = append(attempts, DecryptAttempt{
							Algorithm: "des", Mode: "ecb", Padding: pad,
							Key: k, KeyDesc: kc.Desc + " (DES)",
						})
					}
				}
			case "rc4":
				// RC4 accepts 1..256 byte keys; try the derived 32-byte key
				// plus the raw input if it is short enough.
				attempts = append(attempts, DecryptAttempt{
					Algorithm: "rc4", Key: deriveKey(kc.Bytes, 32),
					KeyDesc: kc.Desc + " (RC4)",
				})
				if len(kc.Bytes) >= 5 && len(kc.Bytes) <= 64 {
					attempts = append(attempts, DecryptAttempt{
						Algorithm: "rc4", Key: append([]byte(nil), kc.Bytes...),
						KeyDesc: kc.Desc + " (RC4 raw)",
					})
				}
			}
		}
	}

	if opts.maxTries > 0 && len(attempts) > opts.maxTries {
		attempts = attempts[:opts.maxTries]
	}
	return attempts
}

// ============================================================================
// Argument parsing helpers
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

// ============================================================================
// commands
// ============================================================================

func cmdInfo(path string) int {
	data, err := os.ReadFile(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "openerctl: %v\n", err)
		return 4
	}
	ft := detectFile(path, data)
	printFileInfo(path, ft)
	return 0
}

func printFileInfo(path string, ft *FileType) {
	fmt.Printf("%s %s\n", c(clrCyan, "File:   "), path)
	fmt.Printf("%s %d bytes\n", c(clrCyan, "Size:   "), ft.Size)
	fmt.Printf("%s %s\n", c(clrCyan, "Type:   "), c(clrGreen, ft.Ext+" - "+ft.Description))
	fmt.Printf("%s %s\n", c(clrCyan, "Category:"), ft.Category)
	if ft.ByMagic {
		fmt.Printf("%s yes\n", c(clrCyan, "Magic:  "))
	}
	if ft.ByExtension {
		fmt.Printf("%s yes\n", c(clrCyan, "Ext:    "))
	}
	fmt.Printf("%s %.4f (0=uniform, 8=random)\n", c(clrCyan, "Entropy:"), ft.EntropyValue)
	if ft.Encrypted {
		fmt.Printf("%s %s\n", c(clrRed, "Encrypted:"),
			"likely (high entropy, no known archive/image magic)")
	}
	if ft.PE != nil && ft.PE.Valid {
		printPEInfo(ft.PE)
	}
}

func printPEInfo(pe *PEInfo) {
	fmt.Println(c(clrBold+clrCyan, "\nPE header"))
	fmt.Printf("  Machine:     %s\n", peMachineName(pe.Machine))
	fmt.Printf("  Subsystem:   %s\n", peSubsystemName(pe.Subsystem))
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

func cmdPreview(path string, lines, maxBytes int, showEntropy bool) int {
	data, err := os.ReadFile(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "openerctl: %v\n", err)
		return 4
	}
	ft := detectFile(path, data)
	printFileInfo(path, ft)

	if showEntropy {
		// Already printed above.
	}

	fmt.Println()
	switch ft.Category {
	case "text":
		fmt.Println(c(clrBold+clrCyan, "Text preview"))
		previewText(data, lines)
	case "image":
		if w, h, ok := imageDimensions(data, ft.Ext); ok {
			fmt.Printf("%s %dx%d\n", c(clrCyan, "Dimensions:"), w, h)
		}
		fmt.Println(c(clrBold+clrCyan, "\nHex preview"))
		hexDump(data, 0, maxBytes)
	case "executable":
		if ft.PE != nil && ft.PE.Valid {
			// printPEInfo already done above.
			fmt.Println(c(clrBold+clrCyan, "\nHex preview (first 256 bytes)"))
			hexDump(data, 0, 256)
		} else {
			fmt.Println(c(clrBold+clrCyan, "Hex preview"))
			hexDump(data, 0, maxBytes)
		}
	case "archive":
		fmt.Println(c(clrBold+clrCyan, "\nHex preview (archive members not listed)"))
		hexDump(data, 0, maxBytes)
	default:
		fmt.Println(c(clrBold+clrCyan, "Hex preview"))
		hexDump(data, 0, maxBytes)
	}
	if ft.Encrypted {
		fmt.Println(c(clrYellow, "\nHint: high entropy suggests this file may be encrypted."))
		fmt.Printf("%s openerctl decrypt %s\n", c(clrGray, "      try:"), path)
	}
	return 0
}

func cmdDecrypt(path string, args []string) int {
	opts := &decryptOpts{maxTries: 2000}
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
			b := parseHexOrText(args[i+1], true)
			if b == nil {
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
			b := parseHexOrText(args[i+1], true)
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

	attempts := collectAttempts(analyze, opts)
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
		plain, err := runAttempt(analyze, at)
		tried++
		if err != nil {
			continue
		}
		if !looksDecrypted(plain) {
			continue
		}
		// Success. Decrypt the full buffer with the same parameters.
		fullPlain := plain
		if len(data) > len(analyze) {
			if fp, err := runAttempt(data, at); err == nil {
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
		pft := detectFile(path+".decrypted", fullPlain)
		if pft.ByMagic || pft.Category == "text" {
			fmt.Printf("  Detected plaintext type: %s (%s)\n\n", pft.Ext, pft.Description)
		}

		if pft.Category == "text" {
			previewText(fullPlain, 0x7FFFFFFF)
		} else {
			hexDump(fullPlain, 0, 4096)
		}
		return 0
	}

	fmt.Fprintf(os.Stderr, "openerctl: no decryption candidate produced recognizable plaintext\n")
	fmt.Fprintf(os.Stderr, "  tried %d candidate(s)\n", tried)
	ft := detectFile(path, data)
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
	backupDirName = "openerctl_backup"
	logFileName   = "openerctl.log"
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
	fmt.Fprintln(os.Stderr, "openerctl is read-only: there are no operations to roll back")
	fmt.Fprintln(os.Stderr, "  openerctl only reads files and (optionally) attempts decryption")
	fmt.Fprintln(os.Stderr, "  in memory; it never writes to the source file or the registry.")
	fmt.Fprintln(os.Stderr, "  Its history is for audit only; use --history to view it.")
	return 0
}

// ============================================================================
// Help
// ============================================================================

func printHelp() {
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
  -m, --mode <mode>        cbc | ecb | ctr (default: try cbc+ecb for block ciphers)
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
  The first combination whose output looks like text, a known file format,
  or valid UTF-8 wins. Because the input is never written to disk, this is
  a safe read-only operation.

GLOBAL
  -o, --out <path>     Redirect stdout to a file
  --dry-run            Print the plan (XPath, attempts) without touching the
                       file. Useful with decrypt to preview the candidate list.
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
// main
// ============================================================================

func main() {
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
		default:
			filtered = append(filtered, a)
			i++
		}
	}
	args = filtered

	if outPath != "" {
		if err := setupOutput(outPath); err != nil {
			fmt.Fprintf(os.Stderr, "openerctl: %v\n", err)
			bugs.Flush()
			os.Exit(2)
		}
	}

	if has(args, "--version") {
		fmt.Println("openerctl v1.0.0")
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

	code := dispatch(args)
	finalExit(code, true)
}

func dispatch(args []string) int {
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
		return runDefault(path, extra)
	}

	switch cmd {
	case "info":
		if len(rest) == 0 {
			fmt.Fprintln(os.Stderr, "openerctl: info requires a file")
			return 2
		}
		return cmdInfo(rest[0])
	case "preview":
		return runPreview(rest)
	case "decrypt":
		if len(rest) == 0 {
			fmt.Fprintln(os.Stderr, "openerctl: decrypt requires a file")
			return 2
		}
		return cmdDecrypt(rest[0], rest[1:])
	}
	fmt.Fprintf(os.Stderr, "openerctl: unknown command %q\n", cmd)
	return 2
}

func runDefault(path string, extra []string) int {
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
			i++
		}
	}
	return cmdPreview(path, lines, maxBytes, showEntropy)
}

func runPreview(args []string) int {
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
	return runDefault(path, extra)
}

// ============================================================================
// -o/--out
// ============================================================================

func setupOutput(path string) error {
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

// Suppress "imported and not used" for sort, md5, and strconv helpers we
// keep around but may not reference on every code path.
var (
	_ = sort.Strings
	_ = md5.Sum
	_ = strconv.Itoa
)