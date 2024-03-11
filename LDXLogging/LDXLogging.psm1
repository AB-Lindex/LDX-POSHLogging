function Write-Log {
<#
.Synopsis
Leif Almberg AB Lindex 4/11/2022
Lindex Powershell Module for Logging standardization

.Description
Write-Log writes log entries to screen, logfile and syslog depending on the setup.
The logfiles are located in the subfolder 'logfiles' of the script that is being processed, or a custom path.
Please note that you cannot test the function Write-Log at the prompt, since a script, and its path, 
are mandatory for Write-Log to extract in order to log correctly.

Since a plethora of parameters are available, and perhaps needed (depending on your setup and demands), they are collected in a class that you create using the method New-LogFileParameters
See examples for details.

.Example
Scenario: Log output to screen (Tee) and daily logfile. No parameters are needed, this is default.
please note that no housekeeping will take place.

Write-Log -LogEntry "Entry 01"
or
Write-Log "entry 01"

.Example
Scenario: Log output to screen, daily logfile and syslog.
Housekeeping, keep the last 90 days. 
Send email to opsgenie@lindex.com if an error (Severity 'Critical') is logged in the script.

$LogParams = New-LogFileParameters -Tee -DailyLogFile -HouseKeeping -DaysToKeep 90 -Syslog -SyslogFacility 20 -AlertEmail opsgenie@lindex.com
Write-Log -LogEntry "Entry 01" -Severity Critical -LogFileParameters $LogParams

Please see help for New-LogFileParameters for detailed Syslog help.

.Example
Scenario: Log output to screen and to a new logfile for each time the script is processed.
No housekeeping.
No email if an error (Severity 'Critical') is logged in the script.

N.B. This can also be used to log to a logfile of your own choice, since the logfile name is one of the input parameters.

The LogFile created in the example will be stored in the subfolder 'logfiles' with the name of the script concatenated
with date and time to the nearest second, in order to create a new logfile for each run.
See 'New-LogFileCurrentRunName' for details of Logfile name creation.

Note that only 'Tee' is a parameter in this case since the other command-line arguments
are handled with 'Write-Log' parameters.

$LogParams = New-LogFileParameters -Tee
$LogFile = New-LogFileCurrentRunName

Write-Log -LogEntry "Entry 01" -LogFileParameters $LogParams -LogFile $LogFile
#>

    Param(
        [Parameter(Mandatory=$false,
        ValueFromPipeline=$true)]
        [string]
        $LogEntry,
        [Parameter(Mandatory=$false)]
        [string]
        $LogFile,
        [Parameter(Mandatory=$false)]
        [string]
        [ValidateSet("Emergency","Alert","Critical","Error","Warning","Notice","Info","Debug")]
        $Severity = "info",
        [Parameter(Mandatory=$false)]
        [object]
        $LogFileParameters
    )

    [bool]$LogTodo = $false
    [bool]$HouseKeepingTodo = $false

    if ($LogEntry) { 
         if ( -not ($MyInvocation.ScriptName)) {
            Write-Output "This command has to run from a script, not from the command line"
        } else {
            $LogTodo = $true
            $LogEntryFormat = (Set-LogEntryFormat $LogEntry $Severity)
            $BaseName=(Get-Item $MyInvocation.ScriptName).BaseName
            if ($LogFileParameters.LogFile) {
                $LogFile = $LogFileParameters.LogFile
            }
 
            if (-not $LogFile) {
                if ($LogFileParameters.DailyLogFile -or -not ($LogFileParameters)) {
                    if ( -not ($LogFileParameters.LogPath)) {
                        $WorkingDir=(Split-Path -Parent $MyInvocation.ScriptName)
                        $Logfile = (New-DailyLogfileName $WorkingDir $BaseName)
                    } else {
                        $Logfile = (New-CustomDailyLogfileName $LogFileParameters.LogPath $BaseName)
                    }
                    
                }
            }

            if ($Logfile) {
                Write-LogEntryLogFile $LogEntryFormat $Logfile
            }

            if ($LogFileParameters.Tee -or -not ($LogFileParameters)) {
                Write-Tee $LogEntryFormat
            }

            if ($LogFileParameters.Syslog -and $LogFileParameters.SyslogServer) {
                Write-SyslogEntry $LogEntry $LogFileParameters.SyslogFacility $Severity $LogFileParameters.SyslogServer
            }

            if ($LogFileParameters.AlertEmail -and $Severity -eq 'Critical') {
                $Subject=$MyInvocation.Scriptname + " encountered an error"
                Send-Email $Subject $LogEntryFormat $LogFileParameters.AlertEmail $LogFileParameters.SMTPServer $LogFileParameters.ReplyTo
            }
        }
    } 

    if ($LogFileParameters.HouseKeeping) {
        $HouseKeepingTodo = $true
        Invoke-LogFileHouseKeeping $LogFileParameters.DaysToKeep $LogFileParameters.RunsToKeep
    }
    if (!($LogTodo) -and !($HouseKeepingTodo)) {
        write-output "Nothing to log, use get-help write-log for parameters."
    }
}

function New-LogFileParameters {
<#
.Synopsis
Leif Almberg AB Lindex 4/11/2022
Lindex Powershell Module for Logging standardization

.Description

New-LogFileParameters setups a class of variables that are mandatory or 
voluntary input to the Write-Log method.
These parameters are only to be setup once, in the beginning of the script, 
and are command-line parameters for each call to Write-Log.
See 'Write-Log' for utilization of this class.

.Example
Scenario: Log Output to screen, daily logfile and syslog.
Housekeeping, keep the last 90 days. 
Send email to opsgenie@lindex.com if an error (Severity 'Critical') is logged in the script.

$LogParams = New-LogFileParameters -Tee -DailyLogFile -HouseKeeping -DaysToKeep 90 -Syslog -SyslogFacility 20 -AlertEmail opsgenie@lindex.com

.Example
Scenario: Do not log output to screen
Log to a new logfile for each time the script is processed.
No housekeeping.
No email if an error (Severity 'Critical') is logged in the script.

$LogParams = New-LogFileParameters

.Example
Scenario: Log Output to screen, daily logfile and no syslog.
Housekeeping, keep the last 20 logfiles, regardless of timestamps.

$LogParams = New-LogFileParameters -Tee -DailyLogFile -HouseKeeping -RunsToKeep 20

.Example
Scenario: Log Output to screen, daily logfile and no syslog. Log to a custom folder. 
Housekeeping, keep the last 20 logfiles.

$LogParams = New-LogFileParameters -Tee -DailyLogFile -HouseKeeping -RunsToKeep 20

#>

    param(
        [Parameter(Mandatory=$false)]
        [switch]
        $Tee,
        [Parameter(Mandatory=$false)]
        [switch]
        $DailyLogFile,
        [Parameter(Mandatory=$false)]
        [switch]
        $HouseKeeping,
        [Parameter(Mandatory=$false)]
        [int]
        $DaysToKeep,
        [Parameter(Mandatory=$false)]
        [int]
        $RunsToKeep,
        [Parameter(Mandatory=$false)]
        [int]
        $MegaBytesToKeep,
        [Parameter(Mandatory=$false)]
        [switch]
        $Syslog,
        [Parameter(Mandatory=$false)]
        [int]
        [ValidateRange(16,23)]
        $SyslogFacility,
        [Parameter(Mandatory=$false)]
        [string]
        $AlertEmail,
        [Parameter(Mandatory=$false)]
        [string]
        $SMTPServer,
        [Parameter(Mandatory=$false)]
        [string]
        $ReplyTo,
        [Parameter(Mandatory=$false)]
        [string]
        $SyslogServer,
        [Parameter(Mandatory=$false)]
        [string]
        $LogPath,
        [Parameter(Mandatory=$false)]
        [string]
        $LogFile
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
    }
    $Parameters = New-Object LdxLogParameters
    $Parameters.Tee=$Tee
    $Parameters.DailyLogFile=$DailyLogFile
    $Parameters.HouseKeeping=$HouseKeeping
    $Parameters.DaysToKeep=$DaysToKeep
    $Parameters.RunsToKeep=$RunsToKeep
    $Parameters.MegaBytesToKeep=$MegaBytesToKeep
    $Parameters.Syslog=$Syslog
    $Parameters.SyslogFacility=$SyslogFacility
    $Parameters.AlertEmail=$AlertEmail
    $Parameters.SMTPServer = $SMTPServer
    $Parameters.ReplyTo = $ReplyTo
    $Parameters.SyslogServer = $SyslogServer
    $Parameters.LogPath = $LogPath
    $Parameters.LogFile = $LogFile

    Return $Parameters
}

Function New-LogFileCurrentRunName {
<#
.Synopsis
Leif Almberg AB Lindex 4/11/2022
Lindex Powershell Module for Logging standardization

.Description

New-LogFileCurrentRunName returns a logfile name based on:
The script name
The script folder
Current time down to a second

The output can be used as a command-line argument to 'Write-Log' 
if you want to have a new logfile created each time you run a script.

.Example
Scenario: You have a script name called 'Action.ps1' in the folder 'C:\Script'
The time is 14:20:31 and the date is March 31, 2020
The output of 'New-LogFileCurrentRunName' will be:
C:\Script\logfiles\Action_20200331-142031.log

#>

    $WorkingDir=(Split-Path -Parent $MyInvocation.ScriptName)
    $BaseName=(Get-Item $MyInvocation.ScriptName).BaseName
    $LogfileName = $BaseName + "_" + (get-date -Format "yyyyMMdd-HHmmss") + ".log"

    return (Join-Path -Path (Get-LogFileDirectory $WorkingDir) -ChildPath $LogfileName)
}

Function New-DailyLogfileName {
    Param(
        [Parameter(Mandatory=$true)]
        [string]
        $WorkingDir,
        [Parameter(Mandatory=$true)]
        [string]
        $BaseName
    )
    $LogfileName = $BaseName + "_" + (get-date -Format "yyyyMMdd") + ".log"

    return (Join-Path -Path (Get-LogFileDirectory $WorkingDir) -ChildPath $LogfileName)
}
Function New-DailyLogFileComputername {
    <#
    .Synopsis
    Leif Almberg AB Lindex 4/11/2022
    Lindex Powershell Module for Logging standardization
    
    .Description
    
    New-DailyLogFileComputername returns a logfile name based on:
    The Computername
    Current date
    
    The output can be used as a command-line argument to 'Write-Log' 
    if you want to have a customized new logfile name.
    
    .Example
    
    #>
    
        $LogfileName = $ENV:COMPUTERNAME + "_" + (get-date -Format "yyyyMMdd") + ".log"
    
        return $LogfileName
    }
    
    Function New-DailyLogfileName {
        Param(
            [Parameter(Mandatory=$true)]
            [string]
            $WorkingDir,
            [Parameter(Mandatory=$true)]
            [string]
            $BaseName
        )
        $LogfileName = $BaseName + "_" + (get-date -Format "yyyyMMdd") + ".log"
    
        return (Join-Path -Path (Get-LogFileDirectory $WorkingDir) -ChildPath $LogfileName)
    }
    
function  New-CustomDailyLogfileName  {
    param (
        [Parameter(Mandatory=$true)]
        [string]
        $LogPath,
        [Parameter(Mandatory=$true)]
        [string]
        $BaseName
    )
    $LogfileName = $BaseName + "_" + (get-date -Format "yyyyMMdd") + ".log"
    if (!(Test-Path -Path $LogPath)) {
        New-Item -Path $LogPath -ItemType Directory -Force
    }
    return (Join-Path -Path $LogPath -ChildPath $LogfileName)
}
Function Get-LogFileDirectory {
    Param(
        [Parameter(Mandatory=$true)]
        [string]
        $WorkingDir
    )
    $LogFileDirectory=(Join-Path -Path $WorkingDir -ChildPath "logfiles")
    if (!(test-path -path $LogFileDirectory)) {
        New-Item -ItemType Directory -Path $LogFileDirectory | Out-Null
    }

    return $LogFileDirectory
}

function Write-SyslogEntry {
    Param(
        [Parameter(Mandatory=$true)]
        [string]
        $LogEntry,
        [Parameter(Mandatory=$true)]
        [int]
        [ValidateRange(16,23)]
        $SyslogFacility,
        [Parameter(Mandatory=$false)]
        [string]
        $Severity="Info",
        [Parameter(Mandatory=$true)]
        [string]
        $SyslogServer
    )
    $LogLevel = "emergency", "alert", "critical", "error", "warning", "notice", "info", "debug"
    [int]$SeverityLevel = [array]::IndexOf($LogLevel,$Severity.ToLower())
    if ($SeverityLevel -eq -1) { $SeverityLevel = 6 }
    [int]$Facility = $SyslogFacility * 8
    $SyslogCode = $Facility + $SeverityLevel

    [string[]]$SyslogMsg = ("<" + $SyslogCode + ">"),":" + $LogEntry
    [byte[]]$RawMsg=[System.Text.Encoding]::ASCII.GetBytes($SyslogMsg)

    $UDPCLient = New-Object System.Net.Sockets.UdpClient
    $UDPCLient.Connect($SyslogServer, '514')
    $UDPCLient.Send($RawMsg, $rawmsg.Length) | Out-Null

}

function Write-LogEntryLogFile {
    Param(
        [Parameter(Mandatory=$true)]
        [string]
        $LogEntry,
        [Parameter(Mandatory=$true)]
        [string]
        $LogFile
    )

    $LogEntry | Out-File -FilePath $LogFile -Append -Force
}

function Send-Email {
    Param(
        [Parameter(Mandatory=$true)]
        [string]
        $Subject,
        [Parameter(Mandatory=$true)]
        [string]
        $Body,
        [Parameter(Mandatory=$true)]
        [string]
        $EmailReceiver,
        [Parameter(Mandatory=$true)]
        [string]
        $SMTPServer,
        [Parameter(Mandatory=$true)]
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
        [Parameter(Mandatory=$true)]
        [string]
        $LogEntry
    )

    Write-Output $LogEntry
}

function Set-LogEntryFormat {
    Param(
        [Parameter(Mandatory=$true)]
        [string]
        $LogEntry,
        [Parameter(Mandatory=$false)]
        [string]
        $Severity
    )
    if ($Severity) { $SeverityEntry = $Severity + ": " }
    return (get-date -Format "yyyy-MM-dd HH:mm:ss") + " " + $SeverityEntry + $LogEntry
}

Function Invoke-LogFileHouseKeeping {
    Param(
        [Parameter(Mandatory=$false)]
        [string]
        $LogFilesFolder,
        [Parameter(Mandatory=$false)]
        [switch]
        $Recurse,
        [Parameter(Mandatory=$false)]
        [int]
        $DaysToKeep,
        [Parameter(Mandatory=$false)]
        [int]
        $RunsToKeep,
        [Parameter(Mandatory=$false)]
        [int]
        $MegaBytesToKeep,
        [Parameter(Mandatory=$false)]
        [switch]
        $List
        
    )

    if (-not ($LogFilesFolder)) {
        if ( -not ($MyInvocation.ScriptName)) {
            Write-Output "Without LogFilesFolder as an argument, this command has to run from a script, not from the command line"
        } else {
            $WorkingDir=(Split-Path -Parent $MyInvocation.ScriptName)
            $LogFileDirectory=(Get-LogFileDirectory $WorkingDir)
        }
    } else {
        $LogFileDirectory = $LogFilesFolder
    }
    if ($LogFileDirectory) {
        if ($DaysToKeep) {
            foreach ($file in Get-ChildItem -Path $LogFileDirectory -File -Recurse:$Recurse) { 
                if ($file.lastwritetime -le (get-date).AddDays(-$DaysToKeep)) {
                    if ($List) {
                        $file
                    } else {
                        remove-item -path (Join-Path -Path $file.Directory -ChildPath $file) -Force 
                    }
                } 
            }
        }

        if ($RunsToKeep) {
            $files = (Get-ChildItem -Path $LogFileDirectory -Recurse:$Recurse | Sort-Object LastWriteTime | Select-Object -first ((Get-ChildItem -Path $LogFileDirectory | Measure-Object).count -$RunsToKeep))
            if ($List) {
                $files
            } else {
                $files | remove-item -Force
            }
        }

        if ($MegaBytesToKeep) {
            $ActualMegaBytesToKeep = $MegaBytesToKeep * 1024 * 1024
            $files = Get-ChildItem -Path $LogFileDirectory -Recurse:$false | Sort-Object LastWriteTime
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
    } else {
        Write-Output "No LogFilesFolder as argument and not running from a script, nothing to do."
    }
}
