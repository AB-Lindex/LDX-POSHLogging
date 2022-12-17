$LogParams = New-LogFileParameters -tee -DailyLogFile -HouseKeeping -DaysToKeep 90 -syslog -SyslogFacility 20 -SyslogServer selxnms01.lindex.local -smtpserver smtp.lindex.local -AlertEmail leif.almberg@lindex.com -ReplyTo pki@lindex.com


write-log -LogEntry "Entry 01" -LogFileParameters $LogParams


