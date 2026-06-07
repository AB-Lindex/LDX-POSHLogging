# GitHub Copilot Instructions — LDXLogging

## Module overview

**LDXLogging** is a PowerShell logging module (`LDXLogging.psm1`) developed for AB Lindex.
It provides a single, consistent way for scripts to write structured log entries to any
combination of screen, file, and syslog, with optional email alerting and automatic housekeeping.

---

## Exported public API

| Function | Purpose |
|---|---|
| `Write-Log` | Write a formatted log entry to one or more destinations. Primary entry point. |
| `New-LogFileParameters` | Create a configuration object that controls `Write-Log` behavior. Call once per script. |
| `New-LogFileCurrentRunName` | Return a per-run log file path (`<name>_yyyyMMdd-HHmmss.log`). |
| `Get-CurrentDailyLogfile` | Return the full path of today's daily log file for the calling script. |
| `New-DailyLogFileComputername` | Return a daily log file *name* (no path) keyed to the computer name. |
| `Invoke-LogFileHouseKeeping` | Delete old log files by age, count, or total folder size. |
| `Send-AzEmail` | Send email via Azure Communication Services SMTP relay. |

Internal helpers (`Write-LogEntry2025`, `Write-Tee`, `Write-SyslogEntry`, `Send-Email`,
`Set-LogEntryFormat`, `New-DailyLogfileName`, `New-CustomDailyLogfileName`,
`Get-LogFilesFolder`) are **not exported** and should not be called directly.

---

## Key design decisions

- **`Write-Log` requires a script context.** It reads `$MyInvocation.ScriptName` to derive
  the script base name and default log folder. It cannot be called interactively from a
  PowerShell console.

- **Configuration object pattern.** `New-LogFileParameters` produces an `LdxLogParameters`
  instance that bundles all optional settings. Pass it once via `-LogFileParameters` rather
  than repeating individual switches on every `Write-Log` call.

- **`-ScreenOnly` mode.** When `New-LogFileParameters -ScreenOnly` is used, `Write-Log`
  writes only to the console. No log file, syslog, or alert email is produced. The `-Tee`
  switch is redundant in this mode — screen output is always on.

- **Default behavior (no parameters).** When `-LogFileParameters` is omitted, `Write-Log`
  writes to screen *and* a daily log file — no extra setup needed.

- **Log file locations.**
  - Default: `<ScriptFolder>\logfiles\<ScriptBaseName>_yyyyMMdd.log`
  - Custom folder: set `-LogPath` in `New-LogFileParameters`
  - Fixed file: set `-LogFile` in `New-LogFileParameters` or pass `-LogFile` directly to `Write-Log`

- **File writing uses `Write-LogEntry2025`** (stream-based, `FileShare.Read`) so that
  `Get-Content` can read the file while it is being written. `Write-LogEntryLogFile` (the
  older `Add-Content` approach) is retained but no longer used.

- **Syslog** is RFC 3164 UDP on port 514. Facility must be in range 16–23 (local0–local7).
  Severity maps to standard RFC 5424 levels.

- **Email alerting** fires only on `Severity = 'Critical'` via the internal `Send-Email`
  helper (plain SMTP). For Azure Communication Services, use the exported `Send-AzEmail`.

- **Housekeeping** runs at the end of every `Write-Log` call when `-HouseKeeping` is set.
  Only one strategy is active at a time: `DaysToKeep`, `RunsToKeep`, or `MegaBytesToKeep`.

---

## Log entry format

```
yyyy-MM-dd HH:mm:ss <Severity>: <Message>
```

Example: `2025-06-07 14:23:01 Critical: Disk space below threshold`

---

## Severity levels

Accepted values (case-insensitive): `Emergency`, `Alert`, `Critical`, `Error`,
`Warning`, `Notice`, `Info`, `Debug`. Default: `Info`.

---

## Common usage patterns

### Minimal — screen + daily log file
```powershell
Write-Log "Service started"
```

### Full setup — all destinations, housekeeping, alert email
```powershell
$LogParams = New-LogFileParameters -Tee -DailyLogFile -HouseKeeping -DaysToKeep 90 `
                -Syslog -SyslogServer "syslog.example.com" -SyslogFacility 20 `
                -AlertEmail "ops@example.com" -SMTPServer "smtp.example.com" -ReplyTo "noreply@example.com"

Write-Log "Starting job"           -LogFileParameters $LogParams
Write-Log "Unexpected failure" -Severity Critical -LogFileParameters $LogParams  # triggers email
```

### Per-run log file (new file on each execution)
```powershell
$LogParams = New-LogFileParameters -Tee
$LogFile   = New-LogFileCurrentRunName

Write-Log "Processing started"  -LogFileParameters $LogParams -LogFile $LogFile
Write-Log "Processing finished" -LogFileParameters $LogParams -LogFile $LogFile
```

### Keep only the 10 most recent files
```powershell
$LogParams = New-LogFileParameters -Tee -DailyLogFile -HouseKeeping -RunsToKeep 10
```

### Console output only (no log file)
```powershell
$LogParams = New-LogFileParameters -ScreenOnly
Write-Log "Dry-run mode active" -LogFileParameters $LogParams
```

### Custom log folder
```powershell
$LogParams = New-LogFileParameters -Tee -DailyLogFile -LogPath "C:\Logs\MyApp"
```

### Retrieve today's log file path
```powershell
$LogFile = Get-CurrentDailyLogfile
```

### Send email via Azure Communication Services
```powershell
$cred = Import-Clixml "C:\Secure\smtp-cred.xml"
Send-AzEmail -From "noreply@example.com" -To @("ops@example.com") `
             -Subject "Alert" -Body "Something failed" -Credentials $cred
```

---

## Module manifest (`LDXLogging.psd1`)

- **ModuleVersion**: update when adding exported functions or breaking changes.
- **FunctionsToExport**: must be kept in sync with the public API listed above.
  Do not add internal helpers to this list.
- **GUID**: `1690488f-9000-46f9-874f-8fe2ddaaab61` — do not change.

---

## Conventions for contributors

- All public functions must have a `Get-Help`-compatible comment block with at minimum
  `.SYNOPSIS`, `.DESCRIPTION`, and at least one `.EXAMPLE`.
- Internal functions do not require help blocks but should have clear parameter names.
- Use `[System.IO.File]::Open` with `FileShare.Read` for any new file-write helpers
  (follow the `Write-LogEntry2025` pattern).
- Do not hardcode organisation-specific addresses (email, server names) in the module;
  these belong in the calling script's `New-LogFileParameters` call.
- Severity validation uses `[ValidateSet]` on `Write-Log`. Keep the set aligned with
  RFC 5424 levels and the `$LogLevel` array in `Write-SyslogEntry`.
