# winctl — Windows Command-Line Operations Toolbox

> **Single file · Pure Go · Zero external dependencies · Integrated operations**
> 2026-10-22 · Wang Xikun

---

## 1. Why Build This

Windows has long lacked a good GNU toolchain. PowerShell is powerful, but in many operations scenarios — batch files, CI scripts, remote SSH sessions — people prefer a set of **command-line, composable, rollback-capable** small tools:

- There are no native Windows equivalents for text-processing basics such as `find` / `grep` / `wc` / `xargs`.
- Registry, service, scheduled-task, and ACL changes are scattered across `reg.exe`, `sc.exe`, `schtasks.exe`, and `icacls.exe`. **No single tool automatically backs up before a change and makes the change rollback-capable afterward.**
- Diagnosing PE dependencies, Authenticode signatures, physical disks/partitions, event logs, network connections, and more often requires installing a pile of third-party software.

So I wrote a suite of tools from scratch in Go, with each submodule as a separate `.exe`; then I **deduplicated and merged them into a single `winctl.exe`** — one program with all capabilities.

---

## 2. Features and Advantages

| Advantage | Description |
|---|---|
| **Pure Go native compilation** | Standard library only; one `go build` command produces a single executable |
| **Zero external dependencies** | No CGO, no VC++ runtime, no DLL installation required |
| **Works on 64-bit Windows** | Runs on any amd64 CPU, compatible from Win7 to Win11 / Server 2025 |
| **Powerful** | 15 submodules cover networking, processes, services, registry, ACLs, disks, event logs, PE, signatures, filesystem, backup, and more |
| **Everything rollback-capable** | Every write operation is **backed up first**; `--rollback` restores in reverse log order |
| **CLI + machine-readable** | Most commands support `--json` for script consumption |
| **Safety design** | Has `--dry-run` (print the plan only) and `-f` (skip confirmation); dangerous operations are refused by default in non-interactive input |
| **Unified conventions** | All modules share `-o/--out`, `--no-color`, `-b/--bugs`, `--dry-run`, `--history`, and `--rollback` |

---

## 3. Modules and Functions at a Glance

A single `winctl <subcommand>` invokes all capabilities. The table below shows the **original small-tool suite before merging** and **each tool's responsibility**:

| Sub-tool (original exe, ~3–4.5 MB each) | Subcommand | Function |
|---|---|---|
| **netctl.exe** | `net` | TCP/UDP connection viewing, adapter information, DNS, hosts editing, system proxy settings (all rollback-capable) |
| **openerctl.exe** | `open` | File type identification (magic + extension + entropy), text/hex/PE preview, **weak-password decryption attempts** (all AES/DES/RC4 combinations) |
| **pectl.exe** | `pe` | PE dependency diagnosis (simulated DLL search path), imports/exports, section table, batch directory scanning |
| **procctl.exe** | `proc` | Process list / real-time TUI monitoring, kill / suspend / resume, priority, **Job Object resource limits** (CPU/memory/IOPS/network/process count), `run` with limits |
| **regctl.exe** | `reg` | Registry reading, `.reg` import/export, JSON export, value type conversion |
| **svcctl.exe** | `svc` | Service list, start/stop/pause/resume, startup type modification, full rollback |
| **sysfixctl.exe** | `sys` | Interactive orchestrator for DISM / SFC / chkdsk system repair (can elevate) |
| **taskctl.exe** | `task` | Scheduled task create/delete/enable/disable/import/export + **startup item management** (Run, RunOnce, Winlogon, Startup folder) |
| **aclctl.exe** | `acl` | View DACL/SDDL, change owner, add/deny ACEs (including inheritance), full rollback |
| **backupctl.exe** | `bkp` | **Unified backup center**: files/directories/registry/services/scheduled tasks packaged in one click, with pre-restore snapshots and archive cleanup |
| **diskvolctl.exe** | `disk` | Physical disk / partition / volume read-only viewing (BusType, TRIM, Serial, partition table) |
| **doctor.exe** | `doc` | Environment self-check: Windows version, CPU, encoding, long-path setting, **writability of all backup directories**, **integrity of all exes** |
| **evtctl.exe** | `evt` | Event log query (WEvtAPI + XPath filtering), supports time/level/Provider/ID, can export JSON |
| **fsctl.exe** | `fs` | **GNU file tool suite**: ls/cat/cp/mv/rm/mkdir/touch/stat/find/grep/head/tail/wc/replace/xargs + pipes + rollback |
| **hashsigctl.exe** | `hash` | MD5/SHA1/SHA256, **Authenticode signature verification** (WinVerifyTrust + signer/issuer extraction) |

The original small tools total **~55 MB**; after merging, a single `winctl.exe` carries all functionality.

---

## 4. Quick Start

```bat
:: List all adapters and DNS
winctl net adapters
winctl net dns

:: See who is using port 8080
winctl net conn --port 8080 --process

:: List the top 10 processes by CPU usage
winctl proc sum 10

:: Real-time monitoring (TUI, arrow keys / Space / K / Z / R)
winctl proc monitor

:: Limit a process to 1 GB of memory
winctl proc limit 1234 --mem 1G

:: Check whether a DLL dependency set is complete
winctl pe info C:\Windows\System32\notepad.exe

:: Determine whether a file is signed
winctl hash sig setup.exe

:: View disks and partitions
winctl disk

:: Query system error logs from the last hour
winctl evt --channel system --level error --since 1h

:: Back up a registry key
winctl bkp backup --reg "HKLM\SOFTWARE\MyApp"

:: Batch-delete temporary files GNU-style (look first, then delete)
winctl fs find . -name "*.tmp"
winctl fs find . -name "*.tmp" ::: xargs rm -rf
```

Rollback:

```bat
winctl fs --history
winctl fs --rollback 3
```

---

## 5. Implementation Principles and Design

### 1. Why Go

- **One command produces a single file**: `go build -trimpath -ldflags "-s -w" -o winctl.exe winctl.go` produces no DLL and no PDB — ready to use immediately.
- **Static linking without CGO**: No MSVC, no CRT, and no runtime libraries need to be installed on the user's machine; double-click it on any 64-bit Windows.
- **The standard library covers many needs**: `crypto/{aes,des,rc4,sha256,md5}`, `compress/{gzip,zlib}`, `archive/tar`, `debug/pe`, `encoding/{xml,json,asn1}` — all ready out of the box.
- **`syscall` + `LazyDLL` directly call Win32 APIs**: Registry (advapi32), services (advapi32), event logs (wevtapi), disks (kernel32), signature verification (wintrust), networking (iphlpapi), and more can all be bound in pure Go. `NewProc` is lazy-loaded, so missing exports will not crash startup.
- **goroutine + `sync` naturally suit concurrency**: Process information collection (worker pool), DISM output dual-pumping (pumping stdout/stderr simultaneously), and the TUI refresh loop — Go's concurrency model makes these concise.
- **Strong typing + `unsafe.Pointer`**: Define a C struct as a Go `struct` and reinterpret it directly in memory with `unsafe.Pointer`; this is standard practice for Windows API programming. When field order matches C, `unsafe.Sizeof` is `sizeof`.

### 2. Struct Mapping and Memory Layout

The code contains many occurrences of `unsafe.Pointer(&buf[0])` followed by a cast to `(*SomeStruct)`, for example:

```go
row := (*net_MIB_TCPROW_OWNER_PID)(unsafe.Pointer(&buf[off]))
```

There are several **pitfalls that must be handled correctly or bugs will occur**; all have been fixed in the code:

- **`PARTITION_INFORMATION_EX`**: Windows returns 144 bytes per partition, but early code defined it as 176 bytes (`Union [144]byte` would cause stride misalignment). It has been changed to `Union [112]byte`.
- **`JOBOBJECT_EXTENDED_LIMIT_INFORMATION`**: Because it contains pointers, Go's `unsafe.Sizeof` result under amd64 does not exactly match the C layout, so it is **manually serialized by offset** into `[]byte` (each field's offset is commented in `proc_buildExtendedLimitBuffer`).
- **`WINTRUST_DATA`**: Windows 10/11 validates `cbStruct`. If a `PSignatureSettings` field is missing, the entire function returns `E_INVALIDARG`. The code has been corrected to the complete amd64 layout.
- **`EVT_RENDER` is bytes, `EVT_FORMAT_MESSAGE` is WCHAR**: The "buffer size" units of the two APIs differ, so each is implemented separately.

### 3. Core Design of the Rollback Mechanism

This is the most important convention in the entire toolset. Every write operation follows this flow:

1. `beginWriteOp()` — calculate the current log line number = operation index
2. Back up the affected objects — files → gzip/tar.gz; registry → `.reg`; services → JSON
3. Execute the modification
4. Write `ops/<idx>.json` — record everything needed for the inverse operation
5. Append a log line — `[full command line] [timestamp] [exit code]`

Rollback reads the log in reverse order. `--rollback N` means "undo the most recent N rollback-capable operations." Each operation type has a clear inverse operation:

| Operation | Inverse operation |
|---|---|
| `hosts add` | Restore the entire hosts file from backup |
| `proxy set` | Restore the old ProxyEnable/Server/Override; delete them if they did not originally exist |
| `svc start` | stop |
| `svc start-type auto` | Restore the original auto/manual/disabled |
| `task create` (overwriting an existing task) | Re-create from the backed-up XML |
| `task create` (new task) | delete |
| `acl set-owner` | Restore SDDL from the `.sddl` backup |
| `fs cp` (target is a new file) | Delete the target; if the target existed before, restore it from backup |
| `fs mv` | Move dst back to src and restore any overwritten dst |
| `fs rm` | Extract from `.tar.gz` / `.gz` / the original file |
| `fs replace` | Restore content from backup |
| `bkp backup` | Delete the generated backup directory |
| `bkp clean` | Move the archive directory back to `backup<timestamp>/` |

Why choose "one JSON per operation + one backup file" instead of a database?

- **Transparent**: The user can `cat ops/42.json` and see exactly what this operation changed, without the tool.
- **Safe**: Even if `winctl.exe` is deleted, it can be restored manually according to the manifest.
- **Zero dependencies**: No SQLite, no background service.

### 4. TUI Implementation

The real-time monitoring TUI of `proc monitor` **does not use any TUI framework**; it directly:

- Uses `ReadConsoleInputW` to get raw keyboard/mouse events (`KEY_EVENT_RECORD` / `MOUSE_EVENT_RECORD`), determines arrow keys via `VirtualKeyCode`, and gets printable characters via `UnicodeChar`;
- Enables the alternate screen buffer with `\x1b[?1049h` and restores it on exit, leaving no dirty screen;
- Each frame moves the cursor home with `\x1b[H` and clears each line ending with `\x1b[K` to avoid flicker;
- Uses an `FPS` cap + `time.NewTicker` to control refresh rate and avoid sampling slowing down the machine.

For sampling, it uses a `worker pool` to concurrently open each process's handle and obtain memory/thread/GDI/handle/IO counts; `--parallel` is adjustable.

### 5. Elevation (UAC)

When `proc run --admin` and `sysfixctl` need administrator privileges, they do not use the `runas` command line (which would mess up arguments). Instead:

- Use `ShellExecuteExW` + `lpVerb="runas"` to restart itself;
- Append an `--elevated` marker to avoid infinite elevation;
- The parent process waits with `WaitForSingleObject` until the child exits, then returns the child's exit code unchanged.

### 6. Encoding Handling

Windows has multiple code pages. Output from child processes (DISM/SFC/schtasks) may be OEM CP, ANSI CP, UTF-16LE, or UTF-8. The handling strategy has three layers:

- **`sys` (DISM/SFC)**: `GetOEMCP` → `MultiByteToWideChar` → UTF-8.
- **`task` (schtasks)**: First detect the UTF-16LE BOM, then determine BOM-less UTF-16LE by the ratio of NULs at odd positions (**this is a key fix** — the old heuristic was too weak; a four-byte CJK string is all non-zero and was misclassified as ANSI), and finally fall back to the ANSI CP.
- **`reg`**: `.reg` files are always read and written as UTF-16LE + BOM, exactly the format `reg.exe` recognizes.

### 7. Read-Only Modules

The six modules `pe`, `open`, `disk`, `doc`, `evt`, and `hash` are **read-only by design**:

- They do not modify any files, registry, services, or disks;
- Their only write operation is appending an audit log line to their own `*_backup/*.log`;
- Therefore `--rollback` is a no-op for these modules (and explicitly says so).

This is a "least privilege" safety design: when you need to inspect a suspicious file, use `winctl hash` / `winctl pe`, and you **know for sure** it will not trigger virus scanning or side effects.

---

## 6. Compilation

```bash
:: Single file (Windows amd64)
go build -trimpath -ldflags "-s -w" -o winctl.exe winctl.go
```

- `-trimpath`: Removes source path information, making the artifact cleaner and avoiding leaking the developer's directory.
- `-ldflags "-s -w"`: Strips the symbol table and DWARF debug information, reducing size by about another 30%.
- CGO is not required; `CGO_ENABLED=0` is in effect by default.

To build a single sub-tool separately (reverting to the pre-merge state):

```bash
:: Extract the corresponding section from winctl.go separately, for example:
go build -trimpath -ldflags "-s -w" -o fsctl.exe fsctl.go
```

---

## 7. Unified Global Conventions

Almost all subcommands share the following behavior (**this is the most important consistency contract of the toolset**):

| Convention | Description |
|---|---|
| `-o/--out <path>` | Redirect stdout to a file (also accepts `--out=path` / `-o=path`); color is automatically disabled when redirected |
| `--dry-run` | Only print "what would be done"; change nothing, write no backups, write no logs |
| `--no-color` | Disable ANSI color; also respects the `NO_COLOR` environment variable |
| `-b/--bugs` | Print errors/warnings collected during this run on exit |
| `-h/--help` / `--version` | Show help / version |
| `--history` | List rollback-capable operations in reverse order (`[1]` is the latest) |
| `--rollback [-n N]` | Undo the most recent N operations |
| Exit codes | `0` success, `1` partial failure, `2` argument error, `3` permission denied, `4` not found, `5` API/IO error |

**Unified log file format** (all modules write the same thing):

```
[<full command line>] [<YYYY-MM-DD HH:MM:SS>] [<exit code>]
```

This is the index basis for `--history` and `--rollback` — **line number = operation number**.

---

## 8. Files and Directory Layout

```
<exe directory>/
├── winctl.exe                        ← the only file you need
├── netctl_backup/
│   ├── netctl.log
│   ├── ops/<idx>.json
│   └── files/<idx>_hosts[.gz]
├── fsctl_backup/
│   ├── fsctl.log
│   ├── ops/<idx>.json
│   └── files/<idx>/<seq>_<name>[.gz|.tar.gz]
├── svcctl_backup/
├── taskctl_backup/
├── regctl_backup/
├── aclctl_backup/
├── backupctl_backup/
├── doctor_backup/
├── evtctl_backup/
├── hashsigctl_backup/
├── diskvolctl_backup/
├── procctl_backup/
├── pectl_backup/
├── openerctl_backup/
├── sysfixctl_backup/
├── backup<YYYYMMDD_HHMMSS>/         ← backupctl backup output
└── backup_archived/                 ← backupctl clean archive
```

> Everything is placed in the **same directory as the executable**. It is a portable program: copy it and move it, leaving no system residue.

---

## 9. Design Tradeoffs

- **Not a Windows service**: It stays "present only when you invoke it", occupying no background resources and leaving no resident process.
- **No GUI**: Command line + pipes + JSON are the native language of the scripting world; a GUI would actually limit composability.
- **No COFF/Go plugin module splitting**: Go's plugin mechanism has many restrictions on Windows and conflicts with `-ldflags -s`; merging into a single `main` package is the most reliable approach, at the cost of a slightly larger binary.
- **Write tools must be rollback-capable**: This is a hard constraint. Any new write operation must first have a clear "what is the inverse operation?" before implementation; otherwise it is not accepted.
- **Read-only tools do not provide `--rollback`**: Rather than giving a fake "rollback", it is better to tell the user clearly that "there are no side effects here."

---

## 10. Author and Date

- **Author**: Wang Xikun
- **Date**: October 22, 2026
- **Acknowledgments**: The Go community

---

*"If GNU is missing, we build our own; if rollback is missing, we make it rollback-capable by design."*