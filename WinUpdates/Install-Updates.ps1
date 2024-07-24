[CmdletBinding(DefaultParameterSetName="First")]
param (
    [Parameter(Mandatory = $true, HelpMessage = "Enter server hostname with updates")]
    [ValidateNotNullOrEmpty()]
    [string]$ManagementServer,

    [Parameter(Mandatory = $true, HelpMessage = "Enter path to updates on management server")]
    [ValidateNotNullOrEmpty()]
    [string]$UpdateSourcePath,

    [Parameter(Mandatory = $true, HelpMessage = "Enter destination for update files")]
    [ValidateNotNullOrEmpty()]
    [string]$UpdateDestinationPath,

    [Parameter(Mandatory = $false, HelpMessage = "Do not copy files from server")]
    [bool]$NoCopy = $false,

    [Parameter(Mandatory = $false)]
    [bool]$Restart = $false,

    [Parameter(Mandatory = $false)]
    [int]$RestartSeconds = 60
)


# check if Powershell instance runs in elevated mode
if ( -not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
  ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Output "Run an elevated instance of powershell (as Administrator)."
    return 2
}

Write-Output $Env:COMPUTERNAME

if (-not $UpdateSourcePath.EndsWith('\')) {
    $UpdateSourcePath = $UpdateSourcePath + '\'
}

if (-not $UpdateDestinationPath.EndsWith('\')) {
    $UpdateDestinationPath = $UpdateDestinationPath + '\'
}

if (-not (Test-Path $UpdateDestinationPath)) {
    New-Item $UpdateDestinationPath -ItemType Directory -ErrorAction Stop
}


if ($NoCopy -eq $false) {
    Write-Output "Copying files ..."
    
    # Robocopy.exe "\\$($ManagementServer)\$($UpdateSourcePath)" $UpdateDestinationPath "*.*" /PURGE /R:2 /W:60 #/NJH /NP /NFL /NDL
    
    Copy-Item -Path "\\$($ManagementServer)\$($UpdateSourcePath)*" -Destination $UpdateDestinationPath
    
    if (-not (Get-ChildItem $UpdateDestinationPath)) {
        Write-Output "No files were copied."
        return 3
    }
}

$Good = 0   # successful updates
$Bad = 0    # unsuccessful updates
$AlreadyInstalled = 0


# msu Updates
$updates = Get-ChildItem -Path $UpdateDestinationPath -Filter *.msu
foreach ($update in $updates) {
    # Extract KB version of update
    $Kb = $update.Name.Split("-") | Where-Object { $_ -match "^kb[0-9]+$" }

    if ($null -eq $Kb -or $Kb.GetType() -ne [string]) {
        Write-Output "Error: $update is not a standard name for KB update!`n"
        $Bad += 1
        continue
    }

    # Check if update is installed
    if ( -not (Get-HotFix -Id $Kb -ErrorAction SilentlyContinue)) {
        Write-Output "Installing $Kb($update) ..."

        Start-Process -FilePath "wusa.exe" -ArgumentList `
            "$UpdateDestinationPath$update /quiet /norestart" -Wait -Verb runAs
        
        Write-Output "$($update): Process exited."

        if (Get-HotFix -Id $Kb -ErrorAction SilentlyContinue) {
            Write-Output "$Kb installed succesfully.`n"
            $Good += 1

            # remove file after successful installation
            Remove-Item $UpdateDestinationPath$update -Force -ErrorAction SilentlyContinue
        }
        else {
            Write-Output "$Kb was NOT installed!`n"
            $Bad += 1
        }
    }
    else {
        Write-Output "$Kb is already installed on this server.`n"
        $AlreadyInstalled += 1
        
        # remove file if update already installed
        Remove-Item $UpdateDestinationPath$update -Force -ErrorAction SilentlyContinue
    }
}

# Malicious software removal tool
# https://support.microsoft.com/en-us/topic/deploy-windows-malicious-software-removal-tool-in-an-enterprise-environment-kb891716-a10cc756-2b3b-32e3-9ee3-2c1298ea3538
$updates = Get-ChildItem -Path $UpdateDestinationPath -Filter *.exe
foreach ($update in $updates) {
    if ($null -ne $update) {
        $Kb = $update.Name.Split("-") | Where-Object { $_ -match "^KB[0-9]+$" }
    
        if ($null -eq $Kb -or $Kb.GetType() -ne [string]) {
            Write-Output "Error: $update is not a standard name for KB update!`n"
            $Bad += 1
        }
        else {
            Write-Output "Running MSRT $Kb($update) ..."

            Start-Process -FilePath $UpdateDestinationPath$update -ArgumentList "/q" -Wait -Verb runAs
            
            $logContentMrt = Get-Content -Path "$($env:windir)\debug\mrt.log" -Tail 8
            Write-Output $logContentMrt

            $msrtExitCode = [int]$logContentMrt[$logContentMrt.Length - 1].ToString().Substring(13).Split()[0]
    
            if ($msrtExitCode -eq 0) {
                $Good += 1

                # remove file after successful installation
                Remove-Item $UpdateDestinationPath$update -Force -ErrorAction SilentlyContinue
            }
            else {
                Write-Output ("Explanation of exit codes: https://support.microsoft.com/en-us/topic" +
                    "/deploy-windows-malicious-software-removal-tool-in-an-enterprise-environment" +
                    "-kb891716-a10cc756-2b3b-32e3-9ee3-2c1298ea3538`n")
                $Bad += 1
            }
        }
    }
}


# Exchange Update
if ($Env:COMPUTERNAME -match "^(EX).*") {
    $update = Get-ChildItem -Path $UpdateDestinationPath -Filter Exchange*.msp

    if ($null -ne $update) {
        $Kb = $update.Name.Split("-") | Where-Object { $_ -match "^KB[0-9]+$" }

        if ($null -eq $Kb -or $Kb.GetType() -ne [string]) {
            Write-Output "Error: $update is not a standard name for KB update!`n"
            $Bad += 1
        }
        else {
            if (-not (Get-HotFix -Id $Kb -ErrorAction SilentlyContinue)) {
                Write-Output "Installing exchange update $Kb($update) ..."

                Start-Process -FilePath msiexec.exe -ArgumentList `
                    "/update $UpdateDestinationPath$update /quiet" -Wait -Verb runAs
                
                Write-Output "$($update): Process exited."
        
                if (Get-HotFix -Id $Kb -ErrorAction SilentlyContinue) {
                    Write-Output "$Kb installed succesfully`n."
                    $Good += 1

                    # remove file after successful installation
                    Remove-Item $UpdateDestinationPath$update -Force -ErrorAction SilentlyContinue
                }
                else {
                    Write-Output "$Kb was NOT installed!`n"
                    $Bad += 1
                }
            }
            else {
                Write-Output "$Kb is already installed on this server.`n"
                $AlreadyInstalled += 1

                # remove file if update already installed
                Remove-Item $UpdateDestinationPath$update -Force -ErrorAction SilentlyContinue
            }
        }
    }
}


Write-Output ("`n$($env:COMPUTERNAME): $Good update(s) installed, $Bad update(s) did not install." `
+ " $AlreadyInstalled update(s) were already installed.`n")

# InstalledOn can sometimes be NULL for new installed updates
get-hotfix | Where-Object {$_.InstalledOn -gt (Get-Date).AddDays(-3) -or $null -eq $_.InstalledOn}

if ($Restart) {
    shutdown.exe /r /t $RestartSeconds
}

return 0