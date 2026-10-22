//go:build windows && amd64

package main

// evtctl — Windows Event Log query tool (read-only).
// Single-file, standard-library-only build:
//
//   go build -trimpath -ldflags "-s -w" -o evtctl.exe evtctl.go
//
// Log: ./evtctl_backup/evtctl.log  [cmd] [ts] [exit code]

import (
	"encoding/json"
	"encoding/xml"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
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
		fmt.Fprintln(os.Stderr, "[evtctl] -b/--bugs enabled: no errors or warnings captured this run.")
		return
	}
	fmt.Fprintf(os.Stderr, "\n--- evtctl bugs report (%d entries) ---\n", len(b.entries))
	for _, e := range b.entries {
		fmt.Fprintf(os.Stderr, "[%s] %s %s\n", e.At.Format("15:04:05.000"), e.Level, e.Msg)
	}
	fmt.Fprintln(os.Stderr, "--- end of bugs report ---")
}

// ============================================================================
// wevtapi.dll bindings
// ============================================================================

var (
	wevtapi = syscall.NewLazyDLL("wevtapi.dll")

	pEvtQuery         = wevtapi.NewProc("EvtQuery")
	pEvtNext          = wevtapi.NewProc("EvtNext")
	pEvtRender        = wevtapi.NewProc("EvtRender")
	pEvtFormatMessage = wevtapi.NewProc("EvtFormatMessage")
	pEvtClose         = wevtapi.NewProc("EvtClose")
)

const (
	EvtQueryChannelPath         = 0x1
	EvtQueryForwardDirection    = 0x100
	EvtQueryReverseDirection    = 0x200

	EvtRenderEventXml = 1

	EvtFormatMessageEvent = 1

	ERROR_INSUFFICIENT_BUFFER = syscall.Errno(122)
	ERROR_NO_MORE_ITEMS       = syscall.Errno(259)
)

func initAPIs() error {
	for name, proc := range map[string]*syscall.LazyProc{
		"EvtQuery":         pEvtQuery,
		"EvtNext":          pEvtNext,
		"EvtRender":        pEvtRender,
		"EvtFormatMessage": pEvtFormatMessage,
		"EvtClose":         pEvtClose,
	} {
		if err := proc.Find(); err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
	}
	return nil
}

func evtQuery(path, query string, flags uint32) (uintptr, error) {
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
	r, _, callErr := pEvtQuery.Call(0, pathU, queryU, uintptr(flags))
	if r == 0 {
		if callErr != nil {
			return 0, callErr
		}
		return 0, fmt.Errorf("EvtQuery failed")
	}
	return r, nil
}

func evtNextBatch(resultSet uintptr, batch uint32) ([]uintptr, bool, error) {
	if batch == 0 {
		batch = 32
	}
	hbuf := make([]uintptr, batch)
	var returned uint32
	r, _, callErr := pEvtNext.Call(resultSet, uintptr(batch),
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

// evtRenderXML renders an event as XML. EvtRender's BufferSize / BufferUsed
// are in BYTES, so a []uint16 buffer of (bytes/2) elements is correct.
// We retry up to 3 times in case the event grows between the size probe and
// the real call.
func evtRenderXML(evt uintptr) (string, error) {
	var needed, propCount uint32
	pEvtRender.Call(0, evt, uintptr(EvtRenderEventXml),
		0, 0,
		uintptr(unsafe.Pointer(&needed)), uintptr(unsafe.Pointer(&propCount)))
	if needed == 0 {
		return "", fmt.Errorf("EvtRender: zero size")
	}
	for attempt := 0; attempt < 3; attempt++ {
		buf := make([]uint16, needed/2)
		size := uint32(len(buf) * 2)
		used := size
		r, _, callErr := pEvtRender.Call(0, evt, uintptr(EvtRenderEventXml),
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

// evtFormatMessage resolves the human-readable message for an event.
// EvtFormatMessage's BufferSize / BufferUsed are in CHARACTERS (WCHARs), so we
// allocate that many uint16 elements and pass the same count as BufferSize.
// This is the bug that used to truncate messages to roughly half their length.
//
// If the API succeeds but only partially renders the message (for example
// ERROR_EVT_UNRESOLVED_VALUE_INSERT when an argument can't be substituted),
// we still return whatever bytes were filled in, because the message template
// itself is usually useful.
func evtFormatMessage(evt uintptr) string {
	var needed uint32
	pEvtFormatMessage.Call(0, evt, 0, 0, 0,
		uintptr(EvtFormatMessageEvent), 0, 0,
		uintptr(unsafe.Pointer(&needed)))
	if needed == 0 {
		return ""
	}

	for attempt := 0; attempt < 3; attempt++ {
		buf := make([]uint16, needed)
		size := uint32(len(buf))
		used := size
		r, _, _ := pEvtFormatMessage.Call(0, evt, 0, 0, 0,
			uintptr(EvtFormatMessageEvent), uintptr(size),
			uintptr(unsafe.Pointer(&buf[0])),
			uintptr(unsafe.Pointer(&used)))
		if r != 0 {
			if used > uint32(len(buf)) {
				used = uint32(len(buf))
			}
			return syscall.UTF16ToString(buf[:used])
		}
		// The API failed. Two possibilities:
		//   1. The buffer grew between the probe and the call (used > size):
		//      retry with the new size.
		//   2. Partial render (used <= size): return what we got.
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

func evtClose(h uintptr) {
	if h != 0 {
		pEvtClose.Call(h)
	}
}

// ============================================================================
// XML event parsing
// ============================================================================

type xmlEvent struct {
	XMLName   xml.Name     `xml:"Event"`
	System    xmlSystem    `xml:"System"`
	EventData xmlEventData `xml:"EventData"`
}

type xmlSystem struct {
	Provider    xmlProvider    `xml:"Provider"`
	EventID     uint32         `xml:"EventID"`
	Level       uint8          `xml:"Level"`
	TimeCreated xmlTimeCreated `xml:"TimeCreated"`
	Channel     string         `xml:"Channel"`
	Computer    string         `xml:"Computer"`
}

type xmlProvider struct {
	Name string `xml:"Name,attr"`
	Guid string `xml:"Guid,attr"`
}

type xmlTimeCreated struct {
	SystemTime string `xml:"SystemTime,attr"`
}

type xmlEventData struct {
	Data []xmlDataField `xml:"Data"`
}

type xmlDataField struct {
	Name  string `xml:"Name,attr"`
	Value string `xml:",chardata"`
}

// ============================================================================
// Event record
// ============================================================================

type EventDataField struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type EventRecord struct {
	Time     time.Time
	Level    uint8
	EventID  uint32
	Source   string
	Channel  string
	Computer string
	Message  string
	Data     []EventDataField
}

// ============================================================================
// Time parsing
// ============================================================================

func parseEvtTime(s string) time.Time {
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

func parseTimeArg(s string) (time.Time, error) {
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
	if m := regexp.MustCompile(`^(\d+)([smhdw])$`).FindStringSubmatch(s); m != nil {
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

func xpathQuote(s string) string {
	if strings.Contains(s, `'`) && !strings.Contains(s, `"`) {
		return `"` + s + `"`
	}
	if strings.Contains(s, `'`) && strings.Contains(s, `"`) {
		return `'` + strings.ReplaceAll(s, `'`, "") + `'`
	}
	return `'` + s + `'`
}

func levelNumber(s string) (int, bool) {
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

func buildXPath(opts *queryOpts) string {
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
		conds = append(conds, "Provider[@Name="+xpathQuote(opts.provider)+"]")
	}
	if !opts.since.IsZero() {
		ts := opts.since.UTC().Format("2006-01-02T15:04:05.000Z")
		conds = append(conds, fmt.Sprintf("TimeCreated[@SystemTime>=%s]", xpathQuote(ts)))
	}
	if !opts.until.IsZero() {
		ts := opts.until.UTC().Format("2006-01-02T15:04:05.000Z")
		conds = append(conds, fmt.Sprintf("TimeCreated[@SystemTime<=%s]", xpathQuote(ts)))
	}
	if len(conds) == 0 {
		return "*"
	}
	return "*[System[" + strings.Join(conds, " and ") + "]]"
}

// ============================================================================
// Query execution
// ============================================================================

type queryOpts struct {
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

func parseEvent(evt uintptr) (EventRecord, error) {
	xmlStr, err := evtRenderXML(evt)
	if err != nil {
		return EventRecord{}, err
	}
	var ev xmlEvent
	if err := xml.Unmarshal([]byte(xmlStr), &ev); err != nil {
		return EventRecord{}, fmt.Errorf("parse XML: %w", err)
	}
	rec := EventRecord{
		Time:     parseEvtTime(ev.System.TimeCreated.SystemTime),
		Level:    ev.System.Level,
		EventID:  ev.System.EventID,
		Source:   ev.System.Provider.Name,
		Channel:  ev.System.Channel,
		Computer: ev.System.Computer,
		Message:  evtFormatMessage(evt),
	}
	for _, d := range ev.EventData.Data {
		rec.Data = append(rec.Data, EventDataField{Name: d.Name, Value: d.Value})
	}
	return rec, nil
}

func queryChannel(channel, xpath string, maxTotal uint32, newestFirst bool, collected *[]EventRecord) error {
	flags := uint32(EvtQueryChannelPath)
	if newestFirst {
		flags |= EvtQueryReverseDirection
	} else {
		flags |= EvtQueryForwardDirection
	}

	resultSet, err := evtQuery(channel, xpath, flags)
	if err != nil {
		return fmt.Errorf("%s: %w", channel, err)
	}
	defer evtClose(resultSet)

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
		handles, more, err := evtNextBatch(resultSet, batch)
		if err != nil {
			return fmt.Errorf("%s: %w", channel, err)
		}
		if !more {
			return nil
		}
		for _, h := range handles {
			rec, perr := parseEvent(h)
			evtClose(h)
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

func runQuery(opts *queryOpts) ([]EventRecord, error) {
	xpath := buildXPath(opts)
	if dryRun {
		fmt.Fprintf(os.Stderr, "[dry-run] XPath: %s\n", xpath)
		for _, ch := range opts.channels {
			fmt.Fprintf(os.Stderr, "[dry-run] query channel %q\n", ch)
		}
		return nil, nil
	}

	var collected []EventRecord
	hadSuccess := false
	var lastErr error
	for _, ch := range opts.channels {
		if err := queryChannel(ch, xpath, opts.max, opts.newest, &collected); err != nil {
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

func levelName(l uint8) string {
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

func levelColor(l uint8) string {
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

// effectiveMessage returns the rendered message, or a fallback built from
// EventData when EvtFormatMessage cannot resolve one.
func effectiveMessage(rec *EventRecord) string {
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

// oneLine collapses embedded CR/LF/TAB so that each event stays on a single
// terminal line. Event messages commonly contain newlines for structured
// output, which would otherwise break the table layout.
func oneLine(s string) string {
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

func printEventsText(records []EventRecord) {
	if len(records) == 0 {
		return
	}

	timeW := len("2024-01-01 00:00:00")
	levelW := len("Critical")
	eidW := len("EVENTID")
	srcW := len("SOURCE")
	chW := len("CHANNEL")
	for _, r := range records {
		if w := len(levelName(r.Level)); w > levelW {
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
			c(levelColor(r.Level), padRight(levelName(r.Level), levelW)) + "  " +
			padRight(strconv.FormatUint(uint64(r.EventID), 10), eidW) + "  " +
			padRight(r.Source, srcW) + "  " +
			padRight(r.Channel, chW) + "  " +
			oneLine(effectiveMessage(&r)))
	}
}

type jsonEvent struct {
	Time      string           `json:"time"`
	Level     string           `json:"level"`
	EventID   uint32           `json:"eventId"`
	Source    string           `json:"source"`
	Channel   string           `json:"channel"`
	Computer  string           `json:"computer"`
	Message   string           `json:"message"`
	EventData []EventDataField `json:"eventData,omitempty"`
}

func printEventsJSON(records []EventRecord) {
	out := make([]jsonEvent, len(records))
	for i, r := range records {
		out[i] = jsonEvent{
			Time:      r.Time.UTC().Format(time.RFC3339Nano),
			Level:     levelName(r.Level),
			EventID:   r.EventID,
			Source:    r.Source,
			Channel:   r.Channel,
			Computer:  r.Computer,
			Message:   effectiveMessage(&r),
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
// Paths and log
// ============================================================================

const (
	backupDirName = "evtctl_backup"
	logFileName   = "evtctl.log"
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

// ============================================================================
// --history / --rollback
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

func cmdRollback(_ []string) int {
	fmt.Fprintln(os.Stderr, "evtctl is read-only: there are no operations to roll back")
	fmt.Fprintln(os.Stderr, "  evtctl only reads event logs and exports them.")
	fmt.Fprintln(os.Stderr, "  Its history is for audit only; use --history to view it.")
	return 0
}

// ============================================================================
// Help
// ============================================================================

func printHelp() {
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
                            and security.
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
// Query argument parsing
// ============================================================================

var defaultChannels = []string{"system", "application"}

var channelAliases = map[string]string{
	"system":      "System",
	"application": "Application",
	"security":    "Security",
	"setup":       "Setup",
}

func parseQueryArgs(args []string) (*queryOpts, error) {
	opts := &queryOpts{
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
			t, err := parseTimeArg(args[i+1])
			if err != nil {
				return nil, err
			}
			opts.since = t
			i += 2
		case "--until":
			if i+1 >= len(args) {
				return nil, fmt.Errorf("--until requires a time")
			}
			t, err := parseTimeArg(args[i+1])
			if err != nil {
				return nil, err
			}
			opts.until = t
			i += 2
		case "--last":
			if i+1 >= len(args) {
				return nil, fmt.Errorf("--last requires a duration")
			}
			t, err := parseTimeArg(args[i+1])
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
		opts.channels = defaultChannels
	} else {
		for _, cr := range channelsRaw {
			for _, part := range strings.Split(cr, ",") {
				part = strings.ToLower(strings.TrimSpace(part))
				if part == "" {
					continue
				}
				if part == "all" {
					opts.channels = append(opts.channels, "system", "application", "security")
					continue
				}
				if canonical, ok := channelAliases[part]; ok {
					opts.channels = append(opts.channels, canonical)
					continue
				}
				opts.channels = append(opts.channels, cr)
			}
		}
	}
	if len(opts.channels) == 0 {
		opts.channels = defaultChannels
	}

	for _, lr := range levelsRaw {
		for _, part := range strings.Split(lr, ",") {
			part = strings.ToLower(strings.TrimSpace(part))
			if part == "" {
				continue
			}
			if n, ok := levelNumber(part); ok {
				opts.levels = append(opts.levels, n)
			} else {
				return nil, fmt.Errorf("invalid level %q", part)
			}
		}
	}

	return opts, nil
}

// ============================================================================
// main
// ============================================================================

func main() {
	if err := initAPIs(); err != nil {
		fmt.Fprintf(os.Stderr, "evtctl: %v\n", err)
		os.Exit(5)
	}

	args, outPath, err := consumeGlobalFlags(os.Args[1:])
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

	if has(args, "--version") {
		fmt.Println("evtctl v1.0.0")
		os.Exit(0)
	}
	if len(args) == 0 || has(args, "-h", "--help") {
		printHelp()
		os.Exit(0)
	}
	if has(args, "--history") {
		finalExit(cmdHistory(), false)
	}
	if has(args, "--rollback") {
		finalExit(cmdRollback(nil), false)
	}

	if len(args) > 0 && args[0] == "query" {
		args = args[1:]
	}

	opts, err := parseQueryArgs(args)
	if err != nil {
		fmt.Fprintf(os.Stderr, "evtctl: %v\n", err)
		bugs.Flush()
		os.Exit(2)
	}

	if outPath != "" {
		if err := setupOutput(outPath); err != nil {
			fmt.Fprintf(os.Stderr, "evtctl: %v\n", err)
			bugs.Flush()
			os.Exit(2)
		}
	}

	records, err := runQuery(opts)
	code := 0
	if err != nil {
		code = 5
	}
	if !dryRun {
		if opts.jsonOut {
			printEventsJSON(records)
		} else {
			printEventsText(records)
		}
		if len(records) == 0 && err == nil {
			fmt.Fprintln(os.Stderr, "no events matched")
		} else if len(records) > 0 {
			fmt.Fprintf(os.Stderr, "\n%d event(s)\n", len(records))
		}
	}

	finalExit(code, true)
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