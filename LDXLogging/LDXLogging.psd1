@{

RootModule = 'LDXLogging.psm1'

ModuleVersion = '0.99.106'

GUID = '1690488f-9000-46f9-874f-8fe2ddaaab61'

Author = 'Leif Almberg, Niklas Goude'

CompanyName = 'AB Lindex'

Copyright = '2020 Free to use.'

Description = 'AB Lindex Log Module'

NestedModules = 'LDXLogging.psm1'

FunctionsToExport = 'Write-Log','New-LogFileParameters','New-LogFileCurrentRunName','Invoke-LogFileHouseKeeping','New-DailyLogFileComputername','Send-AzEmail'

CmdletsToExport = @()

VariablesToExport = '*'

AliasesToExport = @()

}

