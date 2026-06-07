function Write-Log {
<#
.SYNOPSIS
    Writes a formatted log entry to screen, log file, and/or syslog.

.DESCRIPTION
    Write-Log is the central logging function of the LDXLogging module. It formats each entry
    with a timestamp and severity level, then dispatches it to any combination of:
      - Screen output (Tee)
      - A daily log file  (<ScriptName>_yyyyMMdd.log)
      - A per-run log file (a new file for each script execution)
      - A syslog server   (UDP, RFC 3164)
      - An alert email    (triggered on Severity 'Critical')

    Log files are written to a 'logfiles' subfolder relative to the calling script unless
    a custom path is provided in LogFileParameters.

    IMPORTANT: Write-Log must be called from within a script, not from the interactive console.
    It relies on $MyInvocation.ScriptName to determine the script name and default log path.

    Use New-LogFileParameters once at the start of your script to configure logging behavior,
    then pass the resulting object to each Write-Log call via -LogFileParameters.
    When -LogFileParameters is omitted, output goes to both screen and a daily log file.

.PARAMETER LogEntry
    The message text to log.

.PARAMETER LogFile
    Full path to the log file. Overrides any path derived from LogFileParameters.
    Use New-LogFileCurrentRunName to generate a per-run file name automatically.

.PARAMETER Severity
    Log level for the entry. Accepted values (RFC 5424 aligned):
      Emergency, Alert, Critical, Error, Warning, Notice, Info, Debug
    Defaults to 'Info'.

.PARAMETER LogFileParameters
    A configuration object created by New-LogFileParameters. Controls all logging destinations
    and housekeeping behavior.

.EXAMPLE
    # Minimal usage – screen output and a daily log file.
    Write-Log "Service started successfully"

.EXAMPLE
    # Screen + daily log file + syslog + 90-day housekeeping + alert email on Critical.
    $LogParams = New-LogFileParameters -Tee -DailyLogFile -HouseKeeping -DaysToKeep 90 `
                    -Syslog -SyslogServer "syslog.example.com" -SyslogFacility 20 `
                    -AlertEmail "ops@example.com" -SMTPServer "smtp.example.com" -ReplyTo "noreply@example.com"

    Write-Log "Disk space below threshold" -Severity Critical -LogFileParameters $LogParams

.EXAMPLE
    # Per-run log file: a new, uniquely named file is created every time the script executes.
    $LogParams = New-LogFileParameters -Tee
    $LogFile   = New-LogFileCurrentRunName

    Write-Log "Processing started"  -LogFileParameters $LogParams -LogFile $LogFile
    Write-Log "Processing finished" -LogFileParameters $LogParams -LogFile $LogFile

.NOTES
    Log entry format: yyyy-MM-dd HH:mm:ss <Severity>: <Message>
    Syslog messages are sent over UDP port 514 (RFC 3164).
#>

    Param(
        [Parameter(Mandatory = $false,
        ValueFromPipeline = $true)]
        [string]
        $LogEntry,
        [Parameter(Mandatory = $false)]
        [string]
        $LogFile,
        [Parameter(Mandatory = $false)]
        [string]
        [ValidateSet("Emergency","Alert","Critical","Error","Warning","Notice","Info","Debug")]
        $Severity = "info",
        [Parameter(Mandatory = $false)]
        [object]
        $LogFileParameters
    )

    [bool]$LogTodo = $false
    [bool]$HouseKeepingTodo = $false
    $ScriptName = $MyInvocation.ScriptName
    if ($LogEntry) { 
         if (!$ScriptName -and !($logfileParameters.screenOnly)) {
            Write-Output "This command has to run from a script, not from the command line"
        } else {
            $LogTodo = $true
            $LogEntryFormatted = (Set-LogEntryFormat -LogEntry $LogEntry -Severity $Severity)
            if ($LogFileParameters.LogFile) {
                $LogFile = $LogFileParameters.LogFile
            }
 
            if (!$LogFileParameters.ScreenOnly) {
                if (!$LogFile) {
                    $BaseName=(Get-Item $ScriptName).BaseName
                    if ($LogFileParameters.DailyLogFile -or !$LogFileParameters) {
                        if (!$LogFileParameters.LogPath) {
                            $WorkingDir = (Split-Path -Parent $ScriptName)
                            $Logfile = (New-DailyLogfileName -WorkingDir $WorkingDir -BaseName $BaseName)
                        } else {
                            $Logfile = (New-CustomDailyLogfileName -LogPath $LogFileParameters.LogPath -BaseName $BaseName)
                        }
                    }
                }

                if ($Logfile) {
                    Write-LogEntry2025 -LogEntry $LogEntryFormatted -LogFile $Logfile
                }
            }

            if ($LogFileParameters.Tee -or !$LogFileParameters -or $LogFileParameters.ScreenOnly) {
                Write-Tee -LogEntry $LogEntryFormatted
            }

            if ($LogFileParameters.Syslog -and $LogFileParameters.SyslogServer) {
                Write-SyslogEntry -LogEntry $LogEntry -SyslogFacility $LogFileParameters.SyslogFacility -Severity $Severity -SyslogServer $LogFileParameters.SyslogServer
            }

            if ($LogFileParameters.AlertEmail -and $Severity -eq 'Critical') {
                $Subject = $MyInvocation.Scriptname + " encountered an error"
                Send-Email -Subject $Subject -Body $LogEntryFormatted -EmailReceiver $LogFileParameters.AlertEmail -SMTPServer $LogFileParameters.SMTPServer -ReplyTo $LogFileParameters.ReplyTo
            }
        }
    } 

    if ($LogFileParameters.HouseKeeping) {
        $HouseKeepingTodo = $true
        Invoke-LogFileHouseKeeping -DaysToKeep $LogFileParameters.DaysToKeep -RunsToKeep $LogFileParameters.RunsToKeep -LogFilesFolder (Split-Path $LogFile -Parent)
    }
    if (!$LogTodo -and !$HouseKeepingTodo) {
        write-output "Nothing to log, use get-help write-log for parameters."
    }
}

function New-LogFileParameters {
<#
.SYNOPSIS
    Creates a logging configuration object used by Write-Log.

.DESCRIPTION
    New-LogFileParameters returns an LdxLogParameters object that encapsulates all logging
    settings for your script. Create this object once at the start of the script and pass it
    to every Write-Log call via the -LogFileParameters parameter.

    When no parameters are specified the object reflects the Write-Log defaults:
    screen output and a daily log file. Use this function when you need to change
    or extend that behavior.

.PARAMETER Tee
    Echo log entries to the console in addition to the log file.

.PARAMETER DailyLogFile
    Write entries to a daily log file named <ScriptBaseName>_yyyyMMdd.log placed in the
    'logfiles' subfolder of the calling script, or in -LogPath if specified.

.PARAMETER HouseKeeping
    Enable automatic deletion of old log files after each Write-Log call.
    Pair with -DaysToKeep, -RunsToKeep, or -MegaBytesToKeep.

.PARAMETER DaysToKeep
    Remove log files older than this many days. Requires -HouseKeeping.

.PARAMETER RunsToKeep
    Keep only the N most recent log files, deleting older ones. Requires -HouseKeeping.

.PARAMETER MegaBytesToKeep
    Delete the oldest log files until the total folder size is at or below this limit (MB).
    Requires -HouseKeeping.

.PARAMETER Syslog
    Forward log entries to a syslog server. Requires -SyslogServer.

.PARAMETER SyslogServer
    Hostname or IP address of the syslog server (UDP port 514).

.PARAMETER SyslogFacility
    RFC 3164 syslog facility code. Valid range: 16-23 (local0-local7).

.PARAMETER AlertEmail
    Email address to notify when a log entry with Severity 'Critical' is written.
    Requires -SMTPServer.

.PARAMETER SMTPServer
    SMTP relay host used for alert emails.

.PARAMETER ReplyTo
    Reply-To address on alert emails.

.PARAMETER LogPath
    Custom directory for daily log files, overriding the default 'logfiles' subfolder.
    The directory is created automatically if it does not exist.

.PARAMETER LogFile
    Fixed log file path. All Write-Log calls using this parameter object write to this
    single file, regardless of date or script name.

.PARAMETER ScreenOnly
    When set, log entries are written to the console only — no log file, syslog, or email
    alert is produced. Intended for interactive or diagnostic use where persistent logging
    is not required.

.EXAMPLE
    # Screen + daily log file + syslog + 90-day housekeeping + Critical alert email.
    $LogParams = New-LogFileParameters -Tee -DailyLogFile -HouseKeeping -DaysToKeep 90 `
                    -Syslog -SyslogServer "syslog.example.com" -SyslogFacility 20 `
                    -AlertEmail "ops@example.com" -SMTPServer "smtp.example.com" -ReplyTo "noreply@example.com"

.EXAMPLE
    # Screen + daily log file. Keep only the 20 most recent files.
    $LogParams = New-LogFileParameters -Tee -DailyLogFile -HouseKeeping -RunsToKeep 20

.EXAMPLE
    # Screen + daily log file written to a custom folder. Keep only the 20 most recent files.
    $LogParams = New-LogFileParameters -Tee -DailyLogFile -HouseKeeping -RunsToKeep 20 -LogPath "C:\Logs\MyApp"

.EXAMPLE
    # Default behavior (screen + daily log file in the script's own logfiles subfolder).
    $LogParams = New-LogFileParameters

.EXAMPLE
    # Console output only — no log file written.
    $LogParams = New-LogFileParameters -ScreenOnly
    Write-Log "Dry-run mode active" -LogFileParameters $LogParams
#>

    param(
        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true)]
        [switch]
        $Tee,
        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true)]
        [switch]
        $DailyLogFile,
        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true)]
        [switch]
        $HouseKeeping,
        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true)]
        [int]
        $DaysToKeep,
        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true)]
        [int]
        $RunsToKeep,
        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true)]
        [int]
        $MegaBytesToKeep,
        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true)]
        [switch]
        $Syslog,
        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true)]
        [ValidateRange(16,23)]
        [int]
        $SyslogFacility,
        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true)]
        [string]
        $AlertEmail,
        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true)]
        [string]
        $SMTPServer,
        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true)]
        [string]
        $ReplyTo,
        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true)]
        [string]
        $SyslogServer,
        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true)]
        [string]
        $LogPath,
        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true)]
        [string]
        $LogFile,
        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true)]
        [switch]
        $ScreenOnly
    )
    class LdxLogParameters {
        [bool]$Tee
        [bool]$DailyLogFile
        [bool]$HouseKeeping
        [int]$DaysToKeep
        [int]$RunsToKeep
        [int]$MegaBytesToKeep
        [bool]$Syslog
        [int]$SyslogFacility
        [string]$AlertEmail
        [string]$SMTPServer
        [string]$ReplyTo
        [string]$SyslogServer
        [string]$LogPath
        [string]$LogFile
        [bool]$ScreenOnly
    }
    $Parameters = New-Object LdxLogParameters
    $Parameters.Tee = $Tee
    $Parameters.DailyLogFile = $DailyLogFile
    $Parameters.HouseKeeping = $HouseKeeping
    $Parameters.DaysToKeep = $DaysToKeep
    $Parameters.RunsToKeep = $RunsToKeep
    $Parameters.MegaBytesToKeep = $MegaBytesToKeep
    $Parameters.Syslog = $Syslog
    $Parameters.SyslogFacility = $SyslogFacility
    $Parameters.AlertEmail = $AlertEmail
    $Parameters.SMTPServer = $SMTPServer
    $Parameters.ReplyTo = $ReplyTo
    $Parameters.SyslogServer = $SyslogServer
    $Parameters.LogPath = $LogPath
    $Parameters.LogFile = $LogFile
    $Parameters.ScreenOnly = $ScreenOnly

    Return $Parameters
}

Function New-LogFileCurrentRunName {
<#
.SYNOPSIS
    Returns a unique log file path for the current script execution.

.DESCRIPTION
    Generates a log file path in the form:
        <ScriptFolder>\logfiles\<ScriptBaseName>_yyyyMMdd-HHmmss.log

    The timestamp (to the nearest second) ensures a distinct file for every run.
    Pass the result to Write-Log via -LogFile to capture each execution in its own file.

    Must be called from within a script; it relies on $MyInvocation.ScriptName
    to determine the script name and folder.

.EXAMPLE
    # Action.ps1 in C:\Scripts, called at 14:20:31 on 2020-03-31:
    #   Result: C:\Scripts\logfiles\Action_20200331-142031.log

    $LogParams = New-LogFileParameters -Tee
    $LogFile   = New-LogFileCurrentRunName

    Write-Log "Processing started"  -LogFileParameters $LogParams -LogFile $LogFile
    Write-Log "Processing finished" -LogFileParameters $LogParams -LogFile $LogFile
#>
    $ScriptName = $MyInvocation.ScriptName
    $WorkingDir=(Split-Path -Parent $ScriptName)
    $BaseName=(Get-Item $ScriptName).BaseName
    $LogfileName = $BaseName + "_" + (get-date -Format "yyyyMMdd-HHmmss") + ".log"
    return (Join-Path -Path (Get-LogFilesFolder $WorkingDir) -ChildPath $LogfileName)
}
function Get-CurrentDailyLogfile {
<#
.SYNOPSIS
    Returns the full path of today's log file for the currently running script.

.DESCRIPTION
    Derives the current daily log file path using the calling script's name and folder:
        <ScriptFolder>\logfiles\<ScriptBaseName>_yyyyMMdd.log

    Use this to retrieve the active log file path after logging has started — for example,
    to attach it to a notification email or archive it when processing completes.

    Must be called from within a script; it relies on $MyInvocation.ScriptName.

.EXAMPLE
    # Retrieve today's log and attach it to a summary email.
    $LogFile = Get-CurrentDailyLogfile
    Send-AzEmail -From "noreply@example.com" -To @("ops@example.com") `
                 -Subject "Daily log" -Body (Get-Content $LogFile -Raw) -Credentials $cred
#>
    $ScriptName = $MyInvocation.ScriptName
    $WorkingDir = (Split-Path -Parent $ScriptName)
    $BaseName=(Get-Item $ScriptName).BaseName

    return New-DailyLogfileName -WorkingDir $WorkingDir -BaseName $BaseName    
}
Function New-DailyLogfileName {
    Param(
        [Parameter(Mandatory = $true)]
        [string]
        $WorkingDir,
        [Parameter(Mandatory = $true)]
        [string]
        $BaseName
    )
    $LogfileName = $BaseName + "_" + (get-date -Format "yyyyMMdd") + ".log"

    return (Join-Path -Path (Get-LogFilesFolder $WorkingDir) -ChildPath $LogfileName)
}
Function New-DailyLogFileComputername {
    <#
    .SYNOPSIS
        Returns a daily log file name based on the computer name.

    .DESCRIPTION
        Generates a log file name in the form:
            <COMPUTERNAME>_yyyyMMdd.log

        Useful when multiple scripts on the same host should share a single daily log file
        identified by the machine name rather than the script name.

        Unlike New-LogFileCurrentRunName, this function returns a file name only (no path).
        Combine it with a log folder path as required.

    .EXAMPLE
        # On a server named SRV01, called on 2025-06-07:
        #   Result: SRV01_20250607.log

        $LogFile = Join-Path "C:\Logs" (New-DailyLogFileComputername)
        Write-Log "Scheduled task completed" -LogFile $LogFile
    #>
        $LogfileName = $ENV:COMPUTERNAME + "_" + (get-date -Format "yyyyMMdd") + ".log"
        return $LogfileName
    }
function  New-CustomDailyLogfileName  {
    param (
        [Parameter(Mandatory = $true)]
        [string]
        $LogPath,
        [Parameter(Mandatory = $true)]
        [string]
        $BaseName
    )
    $LogfileName = $BaseName + "_" + (get-date -Format "yyyyMMdd") + ".log"
    if (!(Test-Path -Path $LogPath)) {
        New-Item -Path $LogPath -ItemType Directory -Force
    }
    return (Join-Path -Path $LogPath -ChildPath $LogfileName)
}
Function Get-LogFilesFolder {
    Param(
        [Parameter(Mandatory = $true)]
        [string]
        $WorkingDir
    )
    $LogFilesFolder=(Join-Path -Path $WorkingDir -ChildPath "logfiles")
    if (!(test-path -path $LogFilesFolder)) {
        New-Item -ItemType Directory -Path $LogFilesFolder | Out-Null
    }
    return $LogFilesFolder
}

function Write-SyslogEntry {
    Param(
        [Parameter(Mandatory = $true)]
        [string]
        $LogEntry,
        [Parameter(Mandatory = $true)]
        [int]
        [ValidateRange(16,23)]
        $SyslogFacility,
        [Parameter(Mandatory = $false)]
        [string]
        $Severity="Info",
        [Parameter(Mandatory = $true)]
        [string]
        $SyslogServer
    )
    [string[]]$LogLevel = "emergency", "alert", "critical", "error", "warning", "notice", "info", "debug"
    [int]$SeverityLevel = [array]::IndexOf($LogLevel,$Severity.ToLower())
    if ($SeverityLevel -eq -1) { $SeverityLevel = 6 }
    [int]$Facility = $SyslogFacility * 8
    $SyslogCode = $Facility + $SeverityLevel

    [string]$SyslogMsg = ("<" + $SyslogCode + ">"),":" + $LogEntry
    [byte[]]$RawMsg=[System.Text.Encoding]::ASCII.GetBytes($SyslogMsg)

    $UDPCLient = New-Object System.Net.Sockets.UdpClient
    $UDPCLient.Connect($SyslogServer, '514')
    $UDPCLient.Send($RawMsg, $rawmsg.Length) | Out-Null
    $UDPCLient.Close()
    $UDPCLient.Dispose()
}

function Write-LogEntryLogFile-Notinuse {
    Param(
        [Parameter(Mandatory = $true)]
        [string]
        $LogEntry,
        [Parameter(Mandatory = $true)]
        [string]
        $LogFile
    )
    Add-Content -Value $LogEntry -Path $LogFile -Force
}

function Write-LogEntry2025 {
    Param(
        [Parameter(Mandatory = $true)]
        [string]$LogEntry,
        [Parameter(Mandatory = $true)]
        [string]$LogFile
    )
    
    $stream = $null
    $writer = $null
    
    try {
        # Open with shared read access so Get-Content can read while writing
        $stream = [System.IO.File]::Open(
            $LogFile,
            [System.IO.FileMode]::Append,
            [System.IO.FileAccess]::Write,
            [System.IO.FileShare]::Read
        )
        
        $writer = New-Object System.IO.StreamWriter($stream)
        $writer.WriteLine($LogEntry)
        $writer.Flush()  # ← Force data to disk immediately
    }
    finally {
        if ($writer) { $writer.Close() }
        if ($stream) { $stream.Close() }
    }
}

function Send-Email {
    Param(
        [Parameter(Mandatory = $true)]
        [string]
        $Subject,
        [Parameter(Mandatory = $true)]
        [string]
        $Body,
        [Parameter(Mandatory = $true)]
        [string]
        $EmailReceiver,
        [Parameter(Mandatory = $true)]
        [string]
        $SMTPServer,
        [Parameter(Mandatory = $true)]
        [string]
        $ReplyTo
    )

    $msg = new-object Net.Mail.MailMessage
    $smtp = new-object Net.Mail.SmtpClient($smtpServer)

    $msg.From = "$ENV:computername@lindex.com"
    $msg.ReplyTo = $ReplyTo
    $msg.To.Add($EmailReceiver)
    $msg.subject = $Subject
    $msg.body = $Body
    $smtp.Send($msg)
}

function Write-Tee {
    Param(
        [Parameter(Mandatory = $true)]
        [string]
        $LogEntry
    )
    Write-Output $LogEntry
}

function Set-LogEntryFormat {
    Param(
        [Parameter(Mandatory = $true)]
        [string]
        $LogEntry,
        [Parameter(Mandatory = $false)]
        [string]
        $Severity
    )
    if ($Severity) { $SeverityEntry = $Severity + ": " }
    return (get-date -Format "yyyy-MM-dd HH:mm:ss") + " " + $SeverityEntry + $LogEntry
}

Function Invoke-LogFileHouseKeeping {
<#
.SYNOPSIS
    Removes old log files from a folder based on age, count, or total size.

.DESCRIPTION
    Cleans up a log folder using one of three strategies:

      -DaysToKeep      Delete files last-written more than N days ago.
      -RunsToKeep      Keep only the N most recently modified files; delete the rest.
      -MegaBytesToKeep Delete the oldest files until the folder is at or below the size limit.

    Only one strategy is applied per call. When invoked automatically via Write-Log and
    New-LogFileParameters, housekeeping runs after every log entry.

    Use -List to preview which files would be removed without actually deleting them.

.PARAMETER LogFilesFolder
    Full path to the folder containing log files to evaluate.

.PARAMETER Recurse
    Include files in subfolders when evaluating and deleting.

.PARAMETER DaysToKeep
    Delete log files whose last-write time is older than this many days.

.PARAMETER RunsToKeep
    Retain only the N most recently modified files. Older files are deleted.

.PARAMETER MegaBytesToKeep
    Delete the oldest files until the total folder size is at or below this value (MB).

.PARAMETER List
    Preview mode. Lists the files that would be removed without deleting them.

.EXAMPLE
    # Delete log files older than 30 days.
    Invoke-LogFileHouseKeeping -LogFilesFolder "C:\Scripts\logfiles" -DaysToKeep 30

.EXAMPLE
    # Keep only the 10 most recent log files.
    Invoke-LogFileHouseKeeping -LogFilesFolder "C:\Scripts\logfiles" -RunsToKeep 10

.EXAMPLE
    # Preview which files would be removed to bring the folder under 50 MB.
    Invoke-LogFileHouseKeeping -LogFilesFolder "C:\Scripts\logfiles" -MegaBytesToKeep 50 -List
#>
    Param(
        [Parameter(Mandatory = $true)]
        [string]
        $LogFilesFolder,
        [Parameter(Mandatory = $false)]
        [switch]
        $Recurse,
        [Parameter(Mandatory = $false)]
        [int]
        $DaysToKeep,
        [Parameter(Mandatory = $false)]
        [int]
        $RunsToKeep,
        [Parameter(Mandatory = $false)]
        [int]
        $MegaBytesToKeep,
        [Parameter(Mandatory = $false)]
        [switch]
        $List
    )
    if ($DaysToKeep) {
        $files = Get-ChildItem -Path $LogFilesFolder -File -Recurse:$Recurse | Where-Object {$_.lastwritetime -le (get-date).AddDays(-$DaysToKeep)} 
        if ($List) {
            $files
        } else {
            $files | remove-item -Force
        }
    }

    if ($RunsToKeep) {
        $files = (Get-ChildItem -Path $LogFilesFolder -Recurse:$Recurse | Sort-Object LastWriteTime | Select-Object -first ((Get-ChildItem -Path $LogFilesFolder | Measure-Object).count -$RunsToKeep))
        if ($List) {
            $files
        } else {
            $files | remove-item -Force
        }
    }

    if ($MegaBytesToKeep) {
        $ActualMegaBytesToKeep = $MegaBytesToKeep * 1024 * 1024
        $files = Get-ChildItem -Path $LogFilesFolder -Recurse:$false | Sort-Object LastWriteTime
        $sum = (($files | Measure-Object -Sum Length).Sum)
        $n=0
        while (($sum -gt $ActualMegaBytesToKeep) -or ($n -gt $files.count)) {
            $sum = $sum - $files[$n].Length
            if ($List) {
                $files[$n]
            } else {
                $files[$n] | remove-item -Force
            }
            $n++
        }
    }
}

function Send-AzEmail {
<#
.SYNOPSIS
    Sends an email via an Azure Communication Services SMTP relay.

.DESCRIPTION
    A wrapper around System.Net.Mail.SmtpClient pre-configured for Azure Communication
    Services (smtp.azurecomm.net, port 587, TLS enabled). Supply credentials as a
    PSCredential object. The sender address must be a verified sender domain registered
    in your Azure Communication Services resource.

.PARAMETER SMTPHost
    SMTP relay hostname. Defaults to 'smtp.azurecomm.net'.

.PARAMETER SMTPPort
    SMTP port. Defaults to 587.

.PARAMETER EnableSsl
    Use TLS for the SMTP connection. Defaults to $true.

.PARAMETER From
    Sender email address. Must match a verified sender domain in Azure Communication Services.

.PARAMETER To
    Array of recipient email addresses.

.PARAMETER Subject
    Email subject line.

.PARAMETER Body
    Email body text (plain text or HTML depending on -IsBodyHTML).

.PARAMETER IsBodyHTML
    Set to $true to send the body as HTML. Defaults to $false.

.PARAMETER Credentials
    PSCredential object containing the Azure Communication Services SMTP username and password.

.EXAMPLE
    $cred = Get-Credential
    Send-AzEmail -From "noreply@example.com" -To @("ops@example.com") `
                 -Subject "Alert" -Body "Disk space low" -Credentials $cred

.EXAMPLE
    # Send an HTML email using stored credentials.
    $cred = Import-Clixml "C:\Secure\smtp-cred.xml"
    Send-AzEmail -From "noreply@example.com" -To @("team@example.com","mgr@example.com") `
                 -Subject "Report ready" -Body "<h1>Done</h1>" -IsBodyHTML $true -Credentials $cred
#>
    Param(
        [Parameter(Mandatory = $false)]
        [string]
        $SMTPHost = 'smtp.azurecomm.net',
        [Parameter(Mandatory = $false)]
        [int]
        $SMTPPort = 587,
        [Parameter(Mandatory = $false)]
        [bool]
        $EnableSsl = $true,
        [Parameter(Mandatory = $true)]
        [string]
        $From,
        [Parameter(Mandatory = $true)]
        [array]
        $To,
        [Parameter(Mandatory = $true)]
        [string]
        $Subject,
        [Parameter(Mandatory = $true)]
        [string]
        $Body,
        [Parameter(Mandatory = $false)]
        [bool]
        $IsBodyHTML = $false,
        [parameter(Mandatory = $true)]
        [pscredential]
        $Credentials
    )
    
    $smtp = new-object Net.Mail.SmtpClient
    $smtp.Credentials = $Credentials
    $smtp.EnableSsl = $EnableSsl
    $smtp.host = $SMTPHost
    $smtp.Port = $SMTPPort

    $msg = new-object Net.Mail.MailMessage
    $msg.Subject = $Subject
    $msg.Body = $Body
    $msg.From = $From
    $msg.replyTo = $From
    $msg.IsBodyHtml = $IsBodyHTML
    foreach($Receiver in $To) {
        $msg.To.add($Receiver)
    }

    $smtp.send($msg)
}
