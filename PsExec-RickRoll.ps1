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

# check for PsExec, if not present, install
Function Install-PsExec {
    param (
        [bool]$AcceptEULA
    )
    Function RegEdit {
        param(
        $regPath,
        $regName,
        $regValue,
        [bool]$silent
        )
        $regFull = Join-Path $regPath $regName
            Try {
                    $CurrentKeyValue = (Get-ItemProperty -Path $regPath -Name $regName -ErrorAction SilentlyContinue).$regName
                    If (Test-Path $regPath) {
                        If ($CurrentKeyValue -eq $regValue) {
                            If (!($silent)) {
                                Write-Host -ForegroundColor Green 'Registry key' $regFull 'value is set to the desired value of' $regValue'.'
                            }
                            $script:regTest = $True  
                        } Else {
                            If (!($silent)) {
                                Write-Host -ForegroundColor Red 'Registry key' $regFull 'value is not' $regValue'.'
                                Write-Host -ForegroundColor Cyan 'Setting registry key' $regFull 'value to' $regValue'.'
                            }
                            New-ItemProperty -Path $regPath -Name $regName -Value $regValue -PropertyType DWORD -Force | Out-Null
                            $CurrentKeyValue = (Get-ItemProperty -Path $regPath -Name $regName -ErrorAction SilentlyContinue).$regName
                            If ($CurrentKeyValue -eq $regValue) {
                                If (!($silent)) {
                                    Write-Host -ForegroundColor Green 'Registry key' $regFull 'value is set to the desired value of' $regValue'.'
                                }
                                $script:regTest = $True  
                            } Else {
                                If (!($silent)) {
                                    Write-Host -ForegroundColor Red 'Registry key' $regFull 'value could not be set to' $regValue '.'
                                }
                            }
                        }
                    } Else {
                        If (!($silent)) {
                            Write-Host -ForegroundColor Red 'Registry key' $regFull 'path does not exist.'
                            Write-Host -ForegroundColor Cyan 'Creating registry key' $regFull'.'
                        }
                        New-Item -Path $regPath -Force | Out-Null
                        If (!($silent)) {
                            Write-Host -ForegroundColor Cyan 'Setting registry key' $regFull 'value to' $regValue'.'
                        }
                        New-ItemProperty -Path $regPath -Name $regName -Value $regValue -PropertyType DWORD -Force | Out-Null
                        $CurrentKeyValue = (Get-ItemProperty -Path $regPath -Name $regName -ErrorAction SilentlyContinue).$regName
                        If ($CurrentKeyValue -eq $regValue) {
                            If (!($silent)) {
                                Write-Host -ForegroundColor Green 'Registry key' $regFull 'value is set to the desired value of' $regValue'.'
                            }
                            $script:regTest = $True  
                        } Else {
                            If (!($silent)) {
                                Write-Host -ForegroundColor Red 'Registry key' $regFull 'value could not be set to' $regValue '.'
                            }
                        }
                    }
            } Catch {
                If (!($silent)) {
                    Write-Host -ForegroundColor Red 'Registry key' $regFull 'value could not be set to' $regValue '.'
                }
            }
    } # End RegEdit Function

    $PsExec = Get-Command psexec -ErrorAction SilentlyContinue
    If($PsExec){
        # Accept EULA if specified
        If ($AcceptEULA -eq $True) {
            RegEdit -regPath "HKCU:\SOFTWARE\Sysinternals\PsExec" -regName "EulaAccepted" -regValue "1" -silent $true
        }
    } Else {
        # courtesy of Adam Bertram @ https://adamtheautomator.com/psexec/
        Invoke-WebRequest -Uri 'https://download.sysinternals.com/files/PSTools.zip' -OutFile 'pstools.zip'
        Expand-Archive -Path 'pstools.zip' -DestinationPath "$env:TEMP\pstools"
        Move-Item -Path "$env:TEMP\pstools\psexec.exe" .
        Remove-Item -Path "$env:TEMP\pstools" -Recurse
        # Accept EULA if specified
        If ($AcceptEULA -eq $True) {
            RegEdit -regPath "HKCU:\SOFTWARE\Sysinternals\PsExec" -regName "EulaAccepted" -regValue "1" -silent $true
        }
    }
} # end function Install-PsExec

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
