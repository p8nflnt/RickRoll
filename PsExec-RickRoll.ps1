<#
.SYNOPSIS
    Install Ps-Exec, accept EULA, ensure elevated shell, use PsExec to execute script
    on all systems in ComputerList

.NOTES
    Name: PsExec-RickRoll
    Author: Payton Flint
    Version: 1.0
    DateCreated: 2023-Aug

.LINK
    https://github.com/p8nflnt/RickRoll/blob/main/PsExec-RickRoll.ps1
#>

# Clear variables for repeatability
Get-Variable -Exclude PWD,*Preference | Remove-Variable -EA 0

# Identify location of script
$ScriptPath = Split-Path ($MyInvocation.MyCommand.Path) -Parent
# Specify script for invocation via PsExec
$FilePath = Join-Path $ScriptPath "Invoke-Astley.ps1"
# Specify list of computer names
$ComputerList = "ComputerList.txt"
# Get content from computer list
$ComputerList = Get-Content (Join-Path $ScriptPath $ComputerList)

# Check for PsExec, if not present, install
Function Install-PsExec {
    param (
        [bool]$AcceptEULA
    )
    $PsExec = Get-Command psexec -ErrorAction SilentlyContinue
    If($PsExec){
        # Accept EULA if specified
        If ($AcceptEULA -eq $True) {
            psexec.exe -accepteula | Out-Null
        }
    } Else {
        # courtesy of Adam Bertram @ https://adamtheautomator.com/psexec/
        Invoke-WebRequest -Uri 'https://download.sysinternals.com/files/PSTools.zip' -OutFile 'pstools.zip'
        Expand-Archive -Path 'pstools.zip' -DestinationPath "$env:TEMP\pstools"
        Move-Item -Path "$env:TEMP\pstools\psexec.exe" .
        Remove-Item -Path "$env:TEMP\pstools" -Recurse
        # Accept EULA if specified
        If ($AcceptEULA -eq $True) {
            psexec.exe -accepteula | Out-Null
        }
    }
} # End Function Install-PsExec

# Identify if shell is elevated
function Test-ElevatedShell
		{
			$user = [Security.Principal.WindowsIdentity]::GetCurrent()
			(New-Object Security.Principal.WindowsPrincipal $user).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
		}
$admin = Test-ElevatedShell

If($admin) {
    # Execute Install-PSExec function
    Install-PsExec -AcceptEULA $True

    # Invoke script w/ PsExec for computers in list
    psexec -nobanner -h -i \\$ComputerList Powershell.exe -ExecutionPolicy Bypass -File "$FilePath" 2> $null
} Else {
    "Insufficient privilege level- please exeucte script with elevated privileges."
}
