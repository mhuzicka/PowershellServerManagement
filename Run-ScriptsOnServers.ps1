<#
    .SYNOPSIS
    Runs given Powershell script on all machines.

    .DESCRIPTION
    Runs the script specified as a parameter on all computers with hostname in hostnames.txt or
    other file if given as a parameter.
    
    First, the given hostnames are resolved and the script returns hosts it was able to resolve.
    The user is then prompted to enter username and password for the user. If domain is not given
    with the username, a domain of local host is used.

    Remote scripts run asynchronously on every machine. This script waits for all started jobs to
    finish. Remote scripts shall return numeric values only. After the jobs finish, these return
    values are displayed on standard output. Use RETURN, not EXIT! If the job didn't run, -1 is
    returned and if it couldn't parse the return value to [int], -2 is returned.

    The script can also return whole output a remote job generates into a file if the destination
    path is provided in -OutputDirectory.

    If timeout paramater is given, the execution of remote scripts will not stop (this has to be
    implemented in executed scripts), but this script will stop waiting for return values and
    terminate. If script is terminated before a child script could copy and start the process, it
    won't run on remote machine. You can run Get-Job to view running jobs.

    .PARAMETER Script
    Path to a Powershell script you wish to execute. It should return a numeric value using "return
    <VALUE>" indicating a success or failure.

    .PARAMETER ScriptArgs
    Positional arguments for the given script.

    .PARAMETER HostList
    Path to a list of hosts on wich you wish to run the script.

    .PARAMETER OutputDirectory
    Path to a directory in which outputs of remote jobs will be written to.

    .PARAMETER Timeout
    A time value in minutes, after which the script won't wait for return values and terminate
    itself. If 0, then wait indefinitely.

    .PARAMETER DoNotWait
    Do not wait for remote jobs to complete. Takes precedence over timeout if True.

    .INPUTS
    A path to the script can be given via pipeline.

    .OUTPUTS
    0 if ran normally, an integer >0 if error.

    .NOTES
    In case of termination of script by user (i.e. pressing ctrl+c), remote jobs continue to run
    until the job is completed/failed or interactive Powershell session is terminated. 

    hostnames.txt file structure:
        server1
        server2
        server3
        ...
    
    Use Write-Output cmdline if you want output to be logged to a log file and Write-Host if you
    want to log to console.

    .EXAMPLE
    PS> .\Run-ScriptsOnServers C:\temp\Install-Updates.ps1

    .EXAMPLE
    PS> .\Run-ScriptsOnServers .\Install-Updates.ps1 -ScriptArgs "mng01","C:\temp","C:\winupdate\",$false,$true,50

    .EXAMPLE
    PS> C:\Scripts\Run-ScriptsOnServers -Script C:\temp\Install-Updates.ps1 -OutputDirectory .\ -Verbose

    .EXAMPLE
    PS> .\Run-ScriptsOnServers .\Install-Updates.ps1 -HostList .\servers.txt -Timeout 10

    .EXAMPLE
    PS> .\Run-ScriptsOnServers .\Install-Updates.ps1 -DoNotWait $True
#>

[CmdletBinding(DefaultParameterSetName="First")]
param (
    [Parameter(Mandatory = $True, ValueFromPipeline = $True,
        HelpMessage = "Enter path to the script you wish to run")]
    [ValidateNotNullOrEmpty()]
    [string]$Script,

    [Parameter(Mandatory = $False)]
    [ValidateNotNull()]
    [System.Object[]]$ScriptArgs = @(),

    [Parameter(Mandatory = $False)]
    [ValidateNotNullOrEmpty()]
    [string]$HostList = "$PSScriptRoot\hostnames.txt",

    [Parameter(Mandatory = $False)]
    [ValidateNotNull()]
    [string]$OutputDirectory,

    [Parameter(Mandatory = $False)]
    [int]$Timeout = 0,

    [Parameter(Mandatory = $False)]
    [bool]$DoNotWait = $False
)

Set-Variable JobNamePrefix -Option Constant -Value "ScriptJob_" -Visibility Private


class ServerInstance {
    [System.Net.IPAddress]  $InetAddress
    [string]                $HostName
    [string]                $ScriptPath
    [System.Object[]]       $ScriptArgs
    [System.Management.Automation.Job] $Job
    [bool]                  $JobDone
    [string]                $JobStatus
    [int]                   $JobReturnValue # -1 = no job ran, -2 = server-side error, 3 = to file
    [System.IO.FileInfo]    $OutputFile

    ServerInstance([string]$HostName, [string]$ScriptPath, [System.Object[]]$ScriptArgs, [string]$OutputDir) {
        try {
            if ($HostName.Length -eq 0) {
                throw [System.FormatException]::new()
            }

            $Resolved = ([System.Net.Dns]::GetHostAddresses($HostName) | 
                Where-Object {$_.AddressFamily -eq "InterNetwork"})[0]

            if ($null -eq $Resolved) {
                throw [System.FormatException]::new()
            }

            $this.InetAddress = $Resolved.Address
        }
        catch {
            Write-Verbose "Hostname $HostName could not be resolved to a valid IPv4 address."
            throw [System.FormatException]::new("Cannot parse this name.")
        }

        if ( -not [bool](Test-WSMan -ComputerName $HostName -ErrorAction SilentlyContinue) ) {
            Write-Host -ForegroundColor Red ("Powershell remoting is not enabled for $HostName. " `
            + "Enable Powershell remoting for this machine and run the script again.")
            
            throw [System.InvalidOperationException]::new("Could not connect.")
        }

        $this.ScriptPath = $ScriptPath
        $this.ScriptArgs = $ScriptArgs
        $this.HostName = $HostName
        $this.JobDone = $False
        $this.JobReturnValue = -1

        if ($OutputDir.Length -gt 0) {
            # Windows doesn't allow ":" in paths...
            $OutFileName = "$(Get-Date -Format "yyyy-MM-ddTHH-mm-ss")_$($this.HostName).log"
            
            try {
                $this.OutputFile = New-Item -Path $OutputDir -Name $OutFileName -ItemType File
                Write-Verbose "Created File $($this.OutputFile.ToString())"
            }
            catch {
                Write-Warning "Couldn't create output file for $($this.HostName)."
            }
        }
        else {
            $this.OutputFile = $null
        }
    }

    [void] ResetJobDone() {
        $this.JobDone = $False
        $this.JobReturnValue = -1
        $this.JobStatus = $null
    }

    [System.Management.Automation.Job] RunScript([System.Management.Automation.PSCredential]$Credentials) {
        $JobName = "$($script:JobNamePrefix)$($this.HostName)"
        Write-Verbose "Creating job for $($this.HostName) as $JobName."
        $this.Job = [System.Management.Automation.Job](
            Invoke-Command -ComputerName $this.HostName -Credential $Credentials -FilePath `
            $this.ScriptPath -ArgumentList $this.ScriptArgs -AsJob -JobName $JobName
        )

        $this.JobStatus = "Started"
        return $this.job
    }

    [string[]] getJobOutput() {
        $JobOutput = @()
        Receive-Job -Id $this.Job.Id -OutVariable +JobOutput -ErrorVariable +JobOutput `
        -WarningVariable +JobOutput -InformationVariable +JobOutput
        return $JobOutput
    }

    [void] UpdateJobStatus() {
        if ($null -ne $this.Job) {
            if ($this.Job.State -ne "Running") {
                $this.JobDone = $True

                try {
                    $this.JobStatus = $this.Job.JobStateInfo

                    $JobOutput = $this.getJobOutput()

                    if ($null -ne $this.OutputFile) {
                        $JobOutput | Out-File -FilePath $this.OutputFile.ToString()
                    }

                    $this.JobReturnValue = $JobOutput[$JobOutput.Count - 1]
                }
                catch {
                    $this.JobReturnValue = -2 # error receiving job status
                }
            }
            else {
                $this.JobStatus = $this.Job.JobStateInfo
            }
        }
    }
}


# Test output directory if defined
if ($OutputDirectory.Length -gt 0 -and -not (Test-Path -Path $OutputDirectory -PathType Container)) {
    throw [System.IO.IOException]::new("Directory $OutputDirectory doesn't exist.")
}

# check if Powershell instance runs in elevated mode
if ( -not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
  ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host -ForegroundColor Red "Run an elevated instance of powershell (as Administrator)."
    exit 3
}

if ( -not (Test-Path $Script -PathType Leaf) -or -not ([IO.Path]::GetExtension($Script) -eq '.ps1')) {
    Write-Host -ForegroundColor Red "Enter a valid path to a Powershell script."
    exit 4
}

Write-Verbose "Get-Content of $HostList"
$AddressList = Get-Content -Path $HostList -Delimiter "`n" -ErrorAction Stop

if ($AddressList.Length -eq 0) {
    Write-Host -ForegroundColor Yellow "No address defined. Nothing to do."
    exit 0
}

$Domain = (Get-CimInstance Win32_ComputerSystem).Domain
Write-Verbose "Domain is $Domain"

$ServerList = @()
$ValidCount = 0
$InvalidCount = 0
foreach ($ServerAddress in $AddressList) {
    try {
        $ServerList += [ServerInstance]::new($($ServerAddress.Trim()), $Script, $ScriptArgs, `
            $OutputDirectory)
        $ValidCount += 1
    }
    catch {
        $InvalidCount += 1
    }
}

Write-Host "There were $ValidCount servers found."
$ServerList | Select-Object HostName,InetAddress | Format-Table

if ($InvalidCount -gt 0) {
    Write-Host -ForegroundColor Red "$InvalidCount addresses could not be resolved!"
}
else {
    Write-Host -ForegroundColor DarkGreen "All given addresses resolved."
}

$Question = "Continue?"
$Choices  = '&Y', '&N'
$Decision = $Host.UI.PromptForChoice("", $question, $choices, 1)

if ($decision -ne 0) {
    Write-Host "Cancelled."
    exit 2
}

$Username = Read-Host "Enter Username"
$Password = Read-Host -AsSecureString "Enter Password"

# Accept "domain\user" as well as "user" (append domain automatically)
if ($Username -match ".+\\.+") {
    $FullName = $Username
}
else {
    $FullName = $Domain + "\" + $Username
}
$Credentials = [System.Management.Automation.PSCredential]::new($FullName, $Password)

Write-Verbose "Scripts will run using $($Credentials.UserName) username."

# User can cleanup running processes before running new
if (Get-Job | Where-Object {$_.Name -match "$JobNamePrefix.+" -and $_.State -eq "Running"}) {
    Write-Host -ForegroundColor Yellow "There are running remote jobs likely started by this script."
    $Question = "Do you wish to terminate them?"
    $Choices  = '&Y', '&N'
    $Decision = $Host.UI.PromptForChoice("", $question, $choices, 1)

    if ($decision -eq 0) {
        Write-Verbose "Running jobs started by this script will be forced to stop."
        Get-Job | Where-Object {$_.Name -match "$JobNamePrefix.+"} | Remove-Job -Force
    }
}

$JobList = @()
foreach ($Server in $ServerList) {
    $JobList += $Server.RunScript($Credentials)
}

$JobsStartTime = Get-Date
Write-Host "Jobs started at $JobsStartTime"
$JobsMaxTime = $JobsStartTime.AddMinutes($Timeout)

if ($DoNotWait -eq $True) {
    Write-Host -ForegroundColor Yellow ("DoNotWait - Jobs will be running in the background" `
    + " until interactive session is not closed. Use Get-Job to get information about remote " `
    + "jobs.")

    if ($OutputDirectory.Length -gt 0) {
        Write-Warning ("Output directory for logs was defined with DoNotWait attribute. Output " `
        + "will not be logged automatically. Use Get-Job | Receive-Job to receive logs.")
    }
}
else {
    while ($True) {
        Wait-Job -id $JobList.Id -Timeout 60 # Check every minute if timeout was reached
    
        Write-Verbose "Running: $(($JobList | Where-Object {$_.State -eq "Running"} | Measure-Object).Count)"
    
        if ($Timeout -ne 0 -and $JobsMaxTime -le (Get-Date) ) {
            Write-Host -ForegroundColor Yellow "Timeout was reached while waiting for jobs to finish."
            break
        }
        elseif (($JobList | Where-Object {$_.State -eq "Running"} | Measure-Object).Count -eq 0) {
            Write-Host -ForegroundColor DarkGreen "All jobs ran. Check job return values."
            break
        }
    }
}

foreach ($Server in $ServerList) {
    $Server.UpdateJobStatus()
}

$ServerList | Select-Object HostName,JobReturnValue,JobDone,JobStatus |
    Sort-Object -Descending -Property JobReturnValue | Format-Table

# Cleanup because jobs are inherited by an interactive shell
$JobList | Where-Object {$_.State -ne "Running"} | Remove-Job
exit 0
