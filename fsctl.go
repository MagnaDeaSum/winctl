//go:build windows && amd64

package main

// fsctl — File and text basics for Windows with per-operation backup and
// inverse rollback. Build (single file, no external deps):
//
//   go build -trimpath -ldflags "-s -w" -o fsctl.exe fsctl.go
//
// Log:    ./fsctl_backup/fsctl.log          [cmd] [ts] [code]
// Ops:    ./fsctl_backup/ops/<logIndex>.json
// Files:  ./fsctl_backup/files/<logIndex>/<seq>_<name>[.gz|.tar.gz]

import (
	"archive/tar"
	"bufio"
	"compress/gzip"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
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
	dryRun        = false
	expandEnabled = true
)

func c(code, s string) string {
	if !useColor {
		return s
	}
	return code + s + clrReset
}

// ============================================================================
// TTY detection
// ============================================================================

func stdinIsTTY() bool {
	fi, err := os.Stdin.Stat()
	if err != nil {
		return false
	}
	return fi.Mode()&os.ModeCharDevice != 0
}

func stdoutIsTTY() bool {
	fi, err := os.Stdout.Stat()
	if err != nil {
		return false
	}
	return fi.Mode()&os.ModeCharDevice != 0
}

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
		fmt.Fprintln(os.Stderr, "[fsctl] -b/--bugs enabled: no errors or warnings captured this run.")
		return
	}
	fmt.Fprintf(os.Stderr, "\n--- fsctl bugs report (%d entries) ---\n", len(b.entries))
	for _, e := range b.entries {
		fmt.Fprintf(os.Stderr, "[%s] %s %s\n", e.At.Format("15:04:05.000"), e.Level, e.Msg)
	}
	fmt.Fprintln(os.Stderr, "--- end of bugs report ---")
}

// ============================================================================
// Paths and log
// ============================================================================

const (
	backupDirName = "fsctl_backup"
	logFileName   = "fsctl.log"
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
	s := bufio.NewScanner(f)
	s.Buffer(make([]byte, 64*1024), 4*1024*1024)
	n := 0
	for s.Scan() {
		n++
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
	if _, err := fmt.Fprintf(f, "[%s] [%s] [%d]\n", cmd, ts, code); err != nil {
		bugs.Add("ERR", "write log: %v", err)
	}
}

var logRe = regexp.MustCompile(`^\[(.*)\] \[(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\] \[(-?\d+)\]$`)

func parseLogLine(line string) (cmd string, ts string, code int, ok bool) {
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

func buildCmdLine(argv []string) string {
	if len(argv) == 0 {
		return ""
	}
	exe, err := os.Executable()
	if err != nil || exe == "" {
		exe = argv[0]
	}
	parts := make([]string, 0, len(argv))
	parts = append(parts, escapeArg(exe))
	for _, a := range argv[1:] {
		parts = append(parts, escapeArg(a))
	}
	return strings.Join(parts, " ")
}

func escapeArg(a string) string {
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

type opRecord struct {
	Op   string          `json:"op"`
	TS   string          `json:"ts"`
	Cmd  string          `json:"cmd"`
	Code int             `json:"code"`
	Data json.RawMessage `json:"data"`
}

func mustJSON(v any) json.RawMessage {
	b, err := json.Marshal(v)
	if err != nil {
		return json.RawMessage(`null`)
	}
	return b
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
// Backup files
// ============================================================================

var compressedExt = map[string]bool{
	".gz": true, ".tgz": true, ".zip": true, ".rar": true, ".7z": true, ".bz2": true,
	".xz": true, ".zst": true, ".jpg": true, ".jpeg": true, ".png": true, ".gif": true,
	".webp": true, ".heic": true, ".mp3": true, ".mp4": true, ".avi": true, ".mkv": true,
	".mov": true, ".flac": true, ".m4a": true, ".pdf": true, ".docx": true, ".xlsx": true,
	".pptx": true, ".jar": true, ".apk": true, ".exe": true, ".dll": true, ".bin": true,
	".iso": true, ".cab": true, ".msi": true, ".woff2": true, ".br": true,
}

const smallFileThreshold = 8192

func backupPath(src, idx string, seq int) (rel string, compressed bool, err error) {
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
		if err = tarGz(src, filepath.Join(filesDir(), rel)); err != nil {
			return "", false, err
		}
		return rel, true, nil
	}
	ext := strings.ToLower(filepath.Ext(src))
	if compressedExt[ext] || info.Size() < smallFileThreshold {
		rel = filepath.Join(idx, fmt.Sprintf("%d_%s", seq, base))
		if err = copyFile(src, filepath.Join(filesDir(), rel)); err != nil {
			return "", false, err
		}
		return rel, false, nil
	}
	rel = filepath.Join(idx, fmt.Sprintf("%d_%s.gz", seq, base))
	if err = gzipFile(src, filepath.Join(filesDir(), rel)); err != nil {
		return "", false, err
	}
	return rel, true, nil
}

func copyFile(src, dst string) error {
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

func gzipFile(src, dst string) error {
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

func tarGz(src, dst string) error {
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
		defer f.Close()
		_, err = io.Copy(tw, f)
		return err
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

func gunzipFile(src, dst string) error {
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

func untarGz(src, baseDir string) error {
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
		dst := filepath.Join(baseDir, filepath.FromSlash(hdr.Name))
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

func restoreFile(backupRel string, compressed bool, dst string) error {
	src := filepath.Join(filesDir(), backupRel)
	if strings.HasSuffix(backupRel, ".tar.gz") {
		return untarGz(src, filepath.Dir(dst))
	}
	if compressed || strings.HasSuffix(backupRel, ".gz") {
		return gunzipFile(src, dst)
	}
	return copyFile(src, dst)
}

// ============================================================================
// Filesystem helpers
// ============================================================================

func exists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

func copyDir(src, dst string) error {
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
		return copyFile(path, target)
	})
}

// ============================================================================
// Pattern expansion
// ============================================================================

func expandPatterns(args []string) []string {
	out := make([]string, 0, len(args))
	for _, a := range args {
		out = append(out, expandPattern(a)...)
	}
	return out
}

func expandPattern(s string) []string {
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '{':
			return expandBrace(s, i)
		case '[':
			return expandBracket(s, i)
		case '}', ']':
			return []string{s}
		}
	}
	return []string{s}
}

func expandBrace(s string, start int) []string {
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
	parts := parseBraceBody(body)
	if len(parts) == 0 {
		return []string{s}
	}
	var out []string
	for _, p := range parts {
		out = append(out, expandPattern(prefix+p+suffix)...)
	}
	return out
}

func expandBracket(s string, start int) []string {
	endRel := strings.IndexByte(s[start:], ']')
	if endRel < 0 {
		return []string{s}
	}
	end := start + endRel
	prefix := s[:start]
	body := s[start+1 : end]
	suffix := s[end+1:]

	if strings.Contains(body, "..") || (strings.Contains(body, "-") && len(body) >= 3) {
		parts := expandRangeBody(body)
		if len(parts) > 0 {
			var out []string
			for _, p := range parts {
				out = append(out, expandPattern(prefix+p+suffix)...)
			}
			return out
		}
	}
	if body != "" && !strings.ContainsAny(body, "[]{},.") {
		var out []string
		for _, ch := range body {
			out = append(out, expandPattern(prefix+string(ch)+suffix)...)
		}
		return out
	}
	return []string{s}
}

func parseBraceBody(body string) []string {
	if strings.Contains(body, "..") && !strings.Contains(body, ",") {
		return expandRangeBody(body)
	}
	return splitTopLevelComma(body)
}

func splitTopLevelComma(s string) []string {
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

func expandRangeBody(body string) []string {
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
// Interactive helpers
// ============================================================================

func confirm(prompt string) bool {
	if !stdinIsTTY() {
		fmt.Fprintf(os.Stderr, "%s\n  non-interactive stdin: use -f to skip confirmation\n", prompt)
		return false
	}
	fmt.Fprintf(os.Stderr, "%s [y/N] ", prompt)
	reader := bufio.NewReader(os.Stdin)
	line, _ := reader.ReadString('\n')
	line = strings.ToLower(strings.TrimSpace(line))
	return line == "y" || line == "yes"
}

// ============================================================================
// Manifest payloads
// ============================================================================

type cpData struct {
	Src        string `json:"src"`
	Dst        string `json:"dst"`
	DstExisted bool   `json:"dstExisted"`
	DstBackup  string `json:"dstBackup,omitempty"`
	Compressed bool   `json:"compressed,omitempty"`
	Recursive  bool   `json:"recursive,omitempty"`
}

type mvData struct {
	Src           string `json:"src"`
	Dst           string `json:"dst"`
	DstExisted    bool   `json:"dstExisted"`
	DstBackup     string `json:"dstBackup,omitempty"`
	DstCompressed bool   `json:"dstCompressed,omitempty"`
}

type rmItem struct {
	Path       string `json:"path"`
	Backup     string `json:"backup,omitempty"`
	Compressed bool   `json:"compressed,omitempty"`
	IsDir      bool   `json:"isDir"`
	Existed    bool   `json:"existed"`
}

type rmData struct {
	Items []rmItem `json:"items"`
}

type repItem struct {
	Path       string `json:"path"`
	Backup     string `json:"backup,omitempty"`
	Compressed bool   `json:"compressed,omitempty"`
	Count      int    `json:"count"`
}

type replaceMulti struct {
	Items []repItem `json:"items"`
}

type mkdirItem struct {
	Path    string `json:"path"`
	Existed bool   `json:"existed"`
}

type mkdirData struct {
	Items []mkdirItem `json:"items"`
}

type touchItem struct {
	Path      string `json:"path"`
	Existed   bool   `json:"existed"`
	OrigMtime string `json:"origMtime,omitempty"`
}

type touchData struct {
	Items []touchItem `json:"items"`
}

// ============================================================================
// Rollback dispatch
// ============================================================================

func rollbackRecord(rec *opRecord) error {
	switch rec.Op {
	case "cp":
		return rollbackCp(rec.Data)
	case "mv":
		return rollbackMv(rec.Data)
	case "rm":
		return rollbackRm(rec.Data)
	case "replace":
		return rollbackReplace(rec.Data)
	case "mkdir":
		return rollbackMkdir(rec.Data)
	case "touch":
		return rollbackTouch(rec.Data)
	}
	return fmt.Errorf("unknown op %q", rec.Op)
}

func rollbackCp(data json.RawMessage) error {
	var d cpData
	if err := json.Unmarshal(data, &d); err != nil {
		return err
	}
	if d.DstExisted {
		return restoreFile(d.DstBackup, d.Compressed, d.Dst)
	}
	if exists(d.Dst) {
		return os.RemoveAll(d.Dst)
	}
	return nil
}

func rollbackMv(data json.RawMessage) error {
	var d mvData
	if err := json.Unmarshal(data, &d); err != nil {
		return err
	}
	if exists(d.Dst) {
		if err := os.MkdirAll(filepath.Dir(d.Src), 0755); err != nil {
			return err
		}
		if exists(d.Src) {
			_ = os.RemoveAll(d.Src)
		}
		if err := os.Rename(d.Dst, d.Src); err != nil {
			info, serr := os.Stat(d.Dst)
			if serr != nil {
				return err
			}
			if info.IsDir() {
				if err := copyDir(d.Dst, d.Src); err != nil {
					return err
				}
			} else {
				if err := copyFile(d.Dst, d.Src); err != nil {
					return err
				}
			}
			_ = os.RemoveAll(d.Dst)
		}
	}
	if d.DstExisted {
		return restoreFile(d.DstBackup, d.DstCompressed, d.Dst)
	}
	return nil
}

func rollbackRm(data json.RawMessage) error {
	var d rmData
	if err := json.Unmarshal(data, &d); err != nil {
		return err
	}
	for i := len(d.Items) - 1; i >= 0; i-- {
		it := d.Items[i]
		if !it.Existed || it.Backup == "" {
			continue
		}
		if err := restoreFile(it.Backup, it.Compressed, it.Path); err != nil {
			return fmt.Errorf("restore %s: %w", it.Path, err)
		}
	}
	return nil
}

func rollbackReplace(data json.RawMessage) error {
	var d replaceMulti
	if err := json.Unmarshal(data, &d); err != nil {
		return err
	}
	for i := len(d.Items) - 1; i >= 0; i-- {
		it := d.Items[i]
		if it.Backup == "" {
			continue
		}
		if err := restoreFile(it.Backup, it.Compressed, it.Path); err != nil {
			return fmt.Errorf("restore %s: %w", it.Path, err)
		}
	}
	return nil
}

func rollbackMkdir(data json.RawMessage) error {
	var d mkdirData
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

func rollbackTouch(data json.RawMessage) error {
	var d touchData
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

func removeOpt(args []string, flags ...string) []string {
	out := make([]string, 0, len(args))
	skip := false
	for _, a := range args {
		if skip {
			skip = false
			continue
		}
		isFlag := false
		for _, f := range flags {
			if a == f {
				isFlag = true
				break
			}
		}
		if isFlag {
			skip = true
			continue
		}
		out = append(out, a)
	}
	return out
}

func removeFlag(args []string, flag string) []string {
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

func readFileOrStdin(path string) ([]byte, error) {
	if path == "-" {
		return io.ReadAll(os.Stdin)
	}
	return os.ReadFile(path)
}

func readLines(path string) ([]string, error) {
	data, err := readFileOrStdin(path)
	if err != nil {
		return nil, err
	}
	s := strings.Split(string(data), "\n")
	if len(s) > 0 && s[len(s)-1] == "" {
		s = s[:len(s)-1]
	}
	return s, nil
}

func resolveInputs(files []string, name string) ([]string, bool) {
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

func cmdLs(args []string) int {
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
			printLsEntry(p, info, long, true)
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
			printLsEntry(filepath.Join(p, name), fi, long, false)
		}
	}
	return 0
}

func printLsEntry(path string, info os.FileInfo, long, showPath bool) {
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

func cmdCat(args []string) int {
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
	if files, ok = resolveInputs(files, "cat"); !ok {
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

func cmdCp(args []string) int {
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
	return doCp(rest[0], rest[1], force, recursive)
}

func doCp(src, dst string, force, recursive bool) int {
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
		return doCpDir(src, dst, force)
	}
	if exists(dst) && !force {
		if !confirm(fmt.Sprintf("overwrite %s?", dst)) {
			return 1
		}
	}
	if dryRun {
		fmt.Printf("[dry-run] cp %s %s\n", src, dst)
		return 0
	}
	idx := beginWriteOp()
	dstExisted := exists(dst)
	var backup string
	var compressed bool
	if dstExisted {
		backup, compressed, err = backupPath(dst, fmt.Sprintf("%d", idx), 0)
		if err != nil {
			fmt.Fprintf(os.Stderr, "cp: backup %s: %v\n", dst, err)
			return 5
		}
	}
	data := cpData{Src: src, Dst: dst, DstExisted: dstExisted, DstBackup: backup, Compressed: compressed}
	rec := &opRecord{Op: "cp", TS: time.Now().Format("2006-01-02 15:04:05"), Cmd: buildCmdLine(os.Args), Data: mustJSON(data)}
	if err := copyFile(src, dst); err != nil {
		saveOpRecord(idx, rec)
		fmt.Fprintf(os.Stderr, "cp: %v\n", err)
		return 5
	}
	saveOpRecord(idx, rec)
	fmt.Printf("%s -> %s\n", c(clrCyan, src), c(clrGreen, dst))
	return 0
}

func doCpDir(src, dst string, force bool) int {
	if exists(dst) && !force {
		if !confirm(fmt.Sprintf("overwrite directory %s?", dst)) {
			return 1
		}
	}
	if dryRun {
		fmt.Printf("[dry-run] cp -r %s %s\n", src, dst)
		return 0
	}
	idx := beginWriteOp()
	dstExisted := exists(dst)
	var backup string
	var compressed bool
	var err error
	if dstExisted {
		backup, compressed, err = backupPath(dst, fmt.Sprintf("%d", idx), 0)
		if err != nil {
			fmt.Fprintf(os.Stderr, "cp: backup %s: %v\n", dst, err)
			return 5
		}
	}
	data := cpData{Src: src, Dst: dst, DstExisted: dstExisted, DstBackup: backup, Compressed: compressed, Recursive: true}
	rec := &opRecord{Op: "cp", TS: time.Now().Format("2006-01-02 15:04:05"), Cmd: buildCmdLine(os.Args), Data: mustJSON(data)}
	if err := copyDir(src, dst); err != nil {
		saveOpRecord(idx, rec)
		fmt.Fprintf(os.Stderr, "cp: %v\n", err)
		return 5
	}
	saveOpRecord(idx, rec)
	fmt.Printf("%s -> %s %s\n", c(clrCyan, src), c(clrGreen, dst), c(clrGray, "(recursive)"))
	return 0
}

// ============================================================================
// mv
// ============================================================================

func cmdMv(args []string) int {
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
	return doMv(rest[0], rest[1], force)
}

func doMv(src, dst string, force bool) int {
	sinfo, err := os.Stat(src)
	if err != nil {
		fmt.Fprintf(os.Stderr, "mv: %v\n", err)
		return 4
	}
	if dinfo, derr := os.Stat(dst); derr == nil && dinfo.IsDir() {
		dst = filepath.Join(dst, filepath.Base(src))
	}
	dstExisted := exists(dst)
	if dstExisted && !force {
		if !confirm(fmt.Sprintf("overwrite %s?", dst)) {
			return 1
		}
	}
	if dryRun {
		fmt.Printf("[dry-run] mv %s %s\n", src, dst)
		return 0
	}
	idx := beginWriteOp()
	var backup string
	var compressed bool
	if dstExisted {
		backup, compressed, err = backupPath(dst, fmt.Sprintf("%d", idx), 0)
		if err != nil {
			fmt.Fprintf(os.Stderr, "mv: backup %s: %v\n", dst, err)
			return 5
		}
	}
	data := mvData{Src: src, Dst: dst, DstExisted: dstExisted, DstBackup: backup, DstCompressed: compressed}
	rec := &opRecord{Op: "mv", TS: time.Now().Format("2006-01-02 15:04:05"), Cmd: buildCmdLine(os.Args), Data: mustJSON(data)}
	if dstExisted {
		_ = os.RemoveAll(dst)
	}
	err = os.Rename(src, dst)
	if err != nil {
		if sinfo.IsDir() {
			err = copyDir(src, dst)
		} else {
			err = copyFile(src, dst)
		}
		if err == nil {
			_ = os.RemoveAll(src)
		}
	}
	if err != nil {
		saveOpRecord(idx, rec)
		fmt.Fprintf(os.Stderr, "mv: %v\n", err)
		return 5
	}
	saveOpRecord(idx, rec)
	fmt.Printf("%s -> %s\n", c(clrCyan, src), c(clrGreen, dst))
	return 0
}

// ============================================================================
// rm
// ============================================================================

func cmdRm(args []string) int {
	force, recursive := false, false
	localDry := false
	expand := expandEnabled
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
		paths = expandPatterns(paths)
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
			if !exists(p) {
				fmt.Fprintf(os.Stderr, "rm: %s: no such file\n", p)
				return 4
			}
			if !confirm(fmt.Sprintf("remove %s?", p)) {
				return 1
			}
		}
	}
	idx := beginWriteOp()
	rec := &opRecord{Op: "rm", TS: time.Now().Format("2006-01-02 15:04:05"), Cmd: buildCmdLine(os.Args)}
	var items []rmItem
	exitCode := 0
	for _, p := range paths {
		if !exists(p) {
			continue
		}
		info, err := os.Stat(p)
		if err != nil {
			fmt.Fprintf(os.Stderr, "rm: %v\n", err)
			exitCode = 5
			continue
		}
		if info.IsDir() && !recursive {
			fmt.Fprintf(os.Stderr, "rm: %s is a directory (use -r)\n", p)
			exitCode = 2
			continue
		}
		seq := len(items)
		backup, compressed, err := backupPath(p, fmt.Sprintf("%d", idx), seq)
		if err != nil {
			fmt.Fprintf(os.Stderr, "rm: backup %s: %v\n", p, err)
			exitCode = 5
			continue
		}
		items = append(items, rmItem{Path: p, Backup: backup, Compressed: compressed, IsDir: info.IsDir(), Existed: true})
		var derr error
		if info.IsDir() {
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
		rec.Data = mustJSON(rmData{Items: items})
		saveOpRecord(idx, rec)
	}
	return exitCode
}

// ============================================================================
// mkdir
// ============================================================================

func cmdMkdir(args []string) int {
	parents := false
	expand := expandEnabled
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
		paths = expandPatterns(paths)
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
	idx := beginWriteOp()
	var items []mkdirItem
	exitCode := 0
	for _, p := range paths {
		items = append(items, mkdirItem{Path: p, Existed: exists(p)})
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
	rec := &opRecord{Op: "mkdir", TS: time.Now().Format("2006-01-02 15:04:05"), Cmd: buildCmdLine(os.Args), Data: mustJSON(mkdirData{Items: items})}
	saveOpRecord(idx, rec)
	return exitCode
}

// ============================================================================
// touch
// ============================================================================

func cmdTouch(args []string) int {
	expand := expandEnabled
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
		paths = expandPatterns(paths)
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
	idx := beginWriteOp()
	var items []touchItem
	exitCode := 0
	now := time.Now()
	for _, p := range paths {
		it := touchItem{Path: p}
		if info, err := os.Stat(p); err == nil {
			it.Existed = true
			it.OrigMtime = info.ModTime().Format(time.RFC3339Nano)
			if err := os.Chtimes(p, now, now); err != nil {
				fmt.Fprintf(os.Stderr, "touch: %v\n", err)
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
	rec := &opRecord{Op: "touch", TS: now.Format("2006-01-02 15:04:05"), Cmd: buildCmdLine(os.Args), Data: mustJSON(touchData{Items: items})}
	saveOpRecord(idx, rec)
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

func cmdStat(args []string) int {
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

func cmdFind(args []string) int {
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

func cmdGrep(args []string) int {
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
	if files, ok = resolveInputs(files, "grep"); !ok {
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
		data, err := readFileOrStdin(f)
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

func cmdHead(args []string) int {
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
	if files, ok = resolveInputs(files, "head"); !ok {
		return 2
	}
	for _, f := range files {
		lines, err := readLines(f)
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

func cmdTail(args []string) int {
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
	if files, ok = resolveInputs(files, "tail"); !ok {
		return 2
	}
	for _, f := range files {
		lines, err := readLines(f)
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

func cmdWc(args []string) int {
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
	if files, ok = resolveInputs(files, "wc"); !ok {
		return 2
	}
	if !showL && !showW && !showC {
		showL, showW, showC = true, true, true
	}
	for _, f := range files {
		data, err := readFileOrStdin(f)
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

func cmdReplace(args []string) int {
	if len(args) < 3 {
		fmt.Fprintln(os.Stderr, "usage: fsctl replace <old> <new> <file...>")
		return 2
	}
	oldStr, newStr := args[0], args[1]
	files := args[2:]

	if dryRun {
		exitCode := 0
		for _, f := range files {
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
			fmt.Printf("[dry-run] replace %q -> %q in %s (%d occurrences)\n", oldStr, newStr, f, count)
		}
		return exitCode
	}

	idx := beginWriteOp()
	var items []repItem
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
		backup, compressed, err := backupPath(f, fmt.Sprintf("%d", idx), seq)
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
		items = append(items, repItem{Path: f, Backup: backup, Compressed: compressed, Count: count})
		fmt.Printf("%s: replaced %d\n", c(clrCyan, f), count)
	}

	if len(items) == 0 {
		return exitCode
	}
	rec := &opRecord{
		Op:   "replace",
		TS:   time.Now().Format("2006-01-02 15:04:05"),
		Cmd:  buildCmdLine(os.Args),
		Data: mustJSON(replaceMulti{Items: items}),
	}
	saveOpRecord(idx, rec)
	return exitCode
}

// ============================================================================
// xargs
// ============================================================================

// cmdXargs reads newline-separated (or NUL-separated with -0) items from
// stdin and invokes <command> [args...] with them.
//
// Behavior:
//   - If any of the command args contains "{}", each item replaces "{}" and
//     the command runs once per item (GNU find -exec style).
//   - Otherwise all items are appended to the command and it runs once.
//     Use -n N to run in batches of N items.
//   - Trailing ";" / "\;" / "+" tokens are treated as terminators and dropped,
//     so "xargs rm -rf {} ';'" and "xargs rm -rf {} \;" both work.
func cmdXargs(args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "usage: fsctl ... :: xargs <command> [args...]")
		return 2
	}

	// Parse xargs's own options first.
	maxArgs := 0
	nullSep := false
	template := ""
	var cmdArgs []string
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
	cmdArgs = append(cmdArgs, args[i:]...)

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

	// Read items.
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

	// Determine placeholder mode.
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
		// One invocation per item.
		failCount := 0
		for _, it := range items {
			full := make([]string, len(cmdArgs))
			for j, a := range cmdArgs {
				full[j] = strings.ReplaceAll(a, placeholder, it)
			}
			if code := dispatch(full); code != 0 {
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

	// Append mode (optionally batched).
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
		if code := dispatch(full); code != 0 {
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
		cmd, _, _, ok := parseLogLine(lines[i])
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
	case "cp":
		var d cpData
		_ = json.Unmarshal(rec.Data, &d)
		if d.DstExisted {
			return "-> restore " + d.Dst
		}
		return "-> delete " + d.Dst
	case "mv":
		var d mvData
		_ = json.Unmarshal(rec.Data, &d)
		return "-> move " + d.Dst + " back to " + d.Src
	case "rm":
		var d rmData
		_ = json.Unmarshal(rec.Data, &d)
		var names []string
		for _, it := range d.Items {
			names = append(names, filepath.Base(it.Path))
		}
		return "-> restore " + strings.Join(names, ", ")
	case "replace":
		var d replaceMulti
		_ = json.Unmarshal(rec.Data, &d)
		var names []string
		for _, it := range d.Items {
			if it.Backup != "" {
				names = append(names, filepath.Base(it.Path))
			}
		}
		return "-> restore " + strings.Join(names, ", ")
	case "mkdir":
		var d mkdirData
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

func cmdRollback(args []string) int {
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
		cmd, _, _, ok := parseLogLine(lines[i])
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
		rec, err := loadOpRecord(i)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[rollback] step %d: load manifest %d: %v\n", k+1, i, err)
			failCount++
			continue
		}
		fmt.Fprintf(os.Stderr, "[rollback] step %d: %s %s\n", k+1, rec.Op, summarizeOp(rec))
		if err := rollbackRecord(rec); err != nil {
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

func splitPipeline(args []string) [][]string {
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

func runPipeline(stages [][]string) int {
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

		code := dispatch(stage)

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

func stageHasControlFlag(stage []string) bool {
	return has(stage, "--history", "--rollback", "-h", "--help", "--version")
}

// ============================================================================
// Dispatch
// ============================================================================

func dispatch(args []string) int {
	if has(args, "--history") {
		return cmdHistory()
	}
	if has(args, "--rollback") {
		return cmdRollback(args)
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
		return cmdLs(rest)
	case "cat":
		return cmdCat(rest)
	case "cp":
		return cmdCp(rest)
	case "mv":
		return cmdMv(rest)
	case "rm":
		return cmdRm(rest)
	case "mkdir":
		return cmdMkdir(rest)
	case "touch":
		return cmdTouch(rest)
	case "stat":
		return cmdStat(rest)
	case "find":
		return cmdFind(rest)
	case "grep":
		return cmdGrep(rest)
	case "head":
		return cmdHead(rest)
	case "tail":
		return cmdTail(rest)
	case "wc":
		return cmdWc(rest)
	case "replace":
		return cmdReplace(rest)
	case "xargs":
		return cmdXargs(rest)
	}
	fmt.Fprintf(os.Stderr, "fsctl: unknown command %q\n", cmd)
	return 2
}

// ============================================================================
// Help
// ============================================================================

func printHelp() {
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
  head [-n N] [file...]                First N lines (default 10)
  tail [-n N] [file...]                Last N lines (default 10)
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
  -o, --out <path>       Redirect stdout to a file (read-only commands)
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

func setupOutput(path string) bool {
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
// main
// ============================================================================

func main() {
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
		printHelp()
		os.Exit(0)
	}

	dryRun = has(args, "--dry-run")

	if has(args, "--no-expand") {
		expandEnabled = false
		args = removeFlag(args, "--no-expand")
	}

	if p := getOpt(args, "-o", "--out"); p != "" {
		args = removeOpt(args, "-o", "--out")
		if !setupOutput(p) {
			bugs.Flush()
			os.Exit(2)
		}
	}

	stages := splitPipeline(args)

	var code int
	if len(stages) > 1 {
		bad := false
		for i, s := range stages {
			if stageHasControlFlag(s) {
				fmt.Fprintf(os.Stderr, "fsctl: --history/--rollback/--help/--version not allowed in a pipeline (stage %d)\n", i+1)
				bad = true
			}
		}
		if bad {
			code = 2
		} else {
			code = runPipeline(stages)
		}
	} else {
		code = dispatch(args)
	}

	finalExit(code)
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
		case "-h", "--help", "--version", "--history":
			return false
		}
	}
	return true
}