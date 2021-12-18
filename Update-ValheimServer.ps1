#requires -version 5 -RunAsAdministrator

# Update-ValheimServer
# Installs or updates the Valheim dedicated server

<#
Sample command:

.\Update-ValheimServer.ps1 -Anonymous -Force -Verbose
#>

[Cmdletbinding()]
param ( 
        # Use an anonymous logon with Steam. Useful for automation of dedicated server updates that doen't require a Steam username.
        [switch]$Anonymous,
        
        # Do not start dedicated server task(s) after the update is complete.
        [switch]$NoStart,

        # Prompts user for password and stores it as a secure string.
        [switch]$pass2SecStr,

        # Steam username. Not needed to update Valheim dedicated server. Use -Anonymous.
        $steamUser = "Use Anonymous for Valheim Dedicated Server"

        # Steam password as a secure string.
        [string]$secPass,

        # Supresses prompts.
        [switch]$Force
    )


##### CONSTANTS #####

# path to the root Valheim folder
$gamePath = "D:\ValheimServer"

# the process name of the dedicated server, minus .exe
$gameProcessName = "valheim_server"


[array]$worlds = @( ([pscustomobject] @{
                        Name = "Valheim server"
                        savePath = "D:\ValheimServer\save"
                        port = 2458
                        protocol = "UDP"
                        }),

                    ([pscustomobject] @{
                        Name = "Valheim Server H&H"
                        savePath = "D:\ValheimServer\saveHH"
                        port = 2456
                        protocol = "UDP"}),

                    ([pscustomobject] @{
                        Name = "Valheim Server Max"
                        savePath = "D:\ValheimServer\saveMax"
                        port = 2460
                        protocol = "UDP"})
                  )

# the directory where steamcmd.exe is located
$steamCmdPath = "C:\SteamCMD"

# steamcmd download URL
$steamCMDURI = 'https://steamcdn-a.akamaihd.net/client/installer/steamcmd.zip'


# the steam ID of the dedicated server
$steamGameID = '896660' # Valheim Dedicated Server



##### NO EDITING BELOW HERE UNLESS YOU KNOW WHAT YOU ARE DOING #####

##### FUNCTIONS #####
#region


function Get-WebFile
{
    param ( 
        [string]$URI,
        [string]$savePath,
        [string]$fileName
    )

    Write-Verbose "Get-WebFile - Begin."
    Write-Verbose "Get-WebFile - Attempting to download: $dlUrl"

    # make sure we don't try to use an insecure SSL/TLS protocol when downloading files
    Write-Debug "Get-WebFile - Disabling deprecated SSL/TLS versions."
    $secureProtocols = @() 
    $insecureProtocols = @( [System.Net.SecurityProtocolType]::SystemDefault, 
                            [System.Net.SecurityProtocolType]::Ssl3, 
                            [System.Net.SecurityProtocolType]::Tls, 
                            [System.Net.SecurityProtocolType]::Tls11) 
    foreach ($protocol in [System.Enum]::GetValues([System.Net.SecurityProtocolType])) 
    { 
        if ($insecureProtocols -notcontains $protocol) 
        { 
            $secureProtocols += $protocol 
        } 
    } 
    Write-Debug "Get-WebFile - Disabling $($insecureProtocols -join ', ')."
    [System.Net.ServicePointManager]::SecurityProtocol = $secureProtocols

    try 
    {
        Write-Verbose "Get-WebFile - Downloading to: $savePath\$fileName"
        Invoke-WebRequest -Uri $URI -OutFile "$savePath\$fileName" -MaximumRedirection 5 -EA Stop
    } 
    catch 
    {
        Write-Error "Could not download $URI`: $($Error[0].ToString())"
        return $null
    }

    #Add-Log "Downloaded successfully to: $output"
    Write-Verbose "Get-WebFile - Successfully downloaded."
    Write-Verbose "Get-WebFile - End."
    return "$savePath\$fileName"
}


function ConvertFrom-SecureToPlain 
{
    
    param( [Parameter(Mandatory=$true)][System.Security.SecureString] $SecurePassword)
    
    # Create a "password pointer"
    $PasswordPointer = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecurePassword)
    
    # Get the plain text version of the password
    $PlainTextPassword = [Runtime.InteropServices.Marshal]::PtrToStringAuto($PasswordPointer)
    
    # Free the pointer
    [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($PasswordPointer)
    
    #Write-Verbose "Secret is: $PlainTextPassword"

    # Return the plain text password
    return $PlainTextPassword
    
}


# UpToDateCheck isn't working for Valheim Dedicated Server.
function Start-UpToDateCheck
{
    param (
        [uint32]$appID,
        [uint32]$version
        )

    $method = 'GET'
    $URI = 'https://api.steampowered.com/ISteamApps/UpToDateCheck/v1/?appid='+$appID+'&version='+$version

    $body = [PSCustomObject]@{
        appid = $appID
        version = $version
    } | ConvertTo-Json

    $result = Invoke-WebRequest -Uri $URI -Method $method -Body $body
}


#endregion

##### VALIDATION #####
#region
Write-Verbose "Validating paths."
## make sure the Valheim path is valid
if (-NOT (Test-Path "$gamePath" -IsValid)) {

    Write-Error "ERROR: The Valheim server path is invalid: $gamePath"
    exit
}

## make sure the steamcmd path is valid and contains the steamcmd.exe file
if (-NOT (Test-Path "$steamCmdPath" -IsValid)) {

    Write-Error "ERROR: The SteamCMD path is invalid: $gamePath"
    exit
}

#endregion


##### MAIN #####

# Steam password. for security purposes this is prompted
if ($Anonymous.IsPresent)
{
    # setup anonymouse access
    Write-Verbose "Anonymous Steam login used."
    $steamArgs = @"
+login anonymous +force_install_dir $gamePath +app_update $steamGameID validate +exit
"@
}
else 
{
    $steamPassword = $( # prompt for password and convert to secure string text when $pass2SecStr is true
        if ($pass2SecStr) {
            $pass = Read-Host "Steam password" -AsSecureString
            $secStrPass = ConvertTo-SecureString $pass -AsPlainText -Force
            return $($secStrPass | ConvertFrom-SecureString)
            #$($secStrPass | ConvertFrom-SecureString)
            exit
        } elseif ($noConfirm) {
            # use the secPass parameter when noConfirm is set, and convert that to a secure string
        
            try {
                $secStrPass = ConvertTo-SecureString $secPass -ErrorAction Stop
            } catch {
                Write-Verbose "Plain text password passed. This is not recommended."
            } 

            # convert plain text pass to secure string if try{} failed
            if (!$secStrPass) {
                $secStrPass = ConvertTo-SecureString $secPass -AsPlainText -Force
            }

            # return the secure string
            $secStrPass

        } else {
            Read-Host "Steam password" -AsSecureString
        }
    ) 

    $steamArgs = @"
+login $steamUser $(ConvertFrom-SecureToPlain $steamPassword) +force_install_dir $gamePath +app_update $steamGameID validate +exit
"@
}


# warning prompt.
# controlled by Force parameter switch

if (!$Force.IsPresent) {
    $title = "Stop Valheim server"
    $message = "The Valheim server is about to be stopped. Please make sure all users `"Save and quit`" before continuing. Would you like to continue?"

    $yes = New-Object System.Management.Automation.Host.ChoiceDescription "&Yes", `
        "Stop the Valheim server"

    $no = New-Object System.Management.Automation.Host.ChoiceDescription "&No", `
        "Exit the update script."

    $options = [System.Management.Automation.Host.ChoiceDescription[]]($yes, $no)

    $result = $host.ui.PromptForChoice($title, $message, $options, 1) 

    if ($result -eq 1) {
        Write-Verbose "Update terminated by user."
        Start-Sleep 3
        exit
    }
}

Write-Verbose "Stopping Valheim server task(s)."
# stop the Valheim server task
foreach ($task in $worlds.Name)
{
    try
    {
        Stop-ScheduledTask -TaskName "$task" -EA Stop
    }
    catch {}
}

# make super sure all the Valheim processes are closed
# wait one minute for graceful close then kill the process
Write-Verbose "Waiting for the server process to end."
$startTime = Get-Date
do
{
    Start-Sleep -Milliseconds 250
    $running = Get-Process $gameProcessName -EA SilentlyContinue
} until (-NOT $running -or (Get-Date) -gt $startTime.AddMinutes(3))

if ($running)
{
    Write-Verbose "Forcing the process to stop."
    $null = Get-Process $gameProcessName -EA SilentlyContinue | Stop-Process -Force
}


# download and extract steamcmd if it does not exist
$stmCmdFnd = Get-Item "$steamCmdPath\steamcmd.exe" -EA SilentlyContinue
if (-NOT $stmCmdFnd)
{
    Write-Verbose "SteamCMD not found. Attempting to download and install."
    # make the directory, just in case
    try
    {
        $null = mkdir "$steamCmdPath" -Force -EA Stop
    }
    catch
    {
        return (Write-Error "Failed to create the game path ($gamePath): $_" -EA Stop)
    }

    # download steamcmd.zip
    $stmCmdZip = Get-WebFile -URI $steamCMDURI -savePath "$steamCmdPath" -fileName "steamcmd.zip"

    # extract
    Write-Verbose "Extracting SteamCMD."
    Expand-Archive "$stmCmdZip" -DestinationPath "$steamCmdPath" -Force

    # run steamcmd once to complete the setup
    $steamCmd = "$steamCmdPath\steamcmd.exe"

    $worked = Get-Item "$steamCmd" -EA SilentlyContinue
    if ($worked)
    {
        Write-Verbose "Running SteamCMD with +exit only to complete setup."
        Start-Process $steamCmd -ArgumentList "+exit" -Wait -WindowStyle Normal
    }
    else 
    {
        return (Write-Error "Failed to download SteamCMD." -EA Stop)
    }

    Write-Verbose "SteamCMD has been installed."
}


## run the app update once to 
Write-Verbose "Checking for updates to Valheim. This may take a while."
$steamCmd = "$steamCmdPath\steamcmd.exe"

# run the app updater
Start-Process $steamCmd -ArgumentList $steamArgs -WorkingDirectory "$steamCmdPath" -Wait



foreach ($world in $worlds)
{
    # start the server task
    $isTaskFnd = Get-ScheduledTask -TaskName $($world.Name) -EA SilentlyContinue

    if (-NOT $isTaskFnd)
    {
        $gameProcessArgs = '-nographics -batchmode -name "My Valheim Server" -port '+$($world.Port)+' -world "Dedicated" -password "KoolKatsRule!" -savedir '+$($world.savePath)+'\save -public 0'

        Write-Verbose "The scheduled task is not found. Creating it."
        # create the task
        $A = New-ScheduledTaskAction -Execute "cmd" -Argument "/c $gameProcessName`.exe $gameProcessArgs" -WorkingDirectory "$gamePath"
        $T = New-ScheduledTaskTrigger -AtStartup
        $P = New-ScheduledTaskPrincipal -UserId "LOCALSERVICE" -LogonType ServiceAccount
        $S = New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Days 365) -Compatibility Win8
        $D = New-ScheduledTask -Action $A -Principal $P -Trigger $T -Settings $S
        $null = Register-ScheduledTask -TaskName "$($world.Name)" -InputObject $D

        # create a firewall rule to allow the traffic to the server
        Write-Verbose "Allowing network traffic to the server process."
        $null = New-NetFirewallRule -Name "$($world.Name)" -DisplayName "Allows traffic to the $gameProcessName dedicated server" -Enabled True -Program "$gamePath\$gameProcessName`.exe" -Action Allow -Direction Inbound

        # give LOCALSERVICE admin rights to gamePath
        Write-Verbose "Fixing ACL's so LocalService has FullControl to the server files."
        $acl = Get-ACL "$gamePath"

        if ($acl.Access.IdentityReference.Value -notcontains 'NT AUTHORITY\LocalService')
        {
            $identity = "NT AUTHORITY\LocalService"
            $fileSystemRights = "FullControl"
            $type = "Allow"
            # Create new rule
            $fileSystemAccessRuleArgumentList = $identity, $fileSystemRights, ([System.Security.AccessControl.InheritanceFlags]::ContainerInherit, [System.Security.AccessControl.InheritanceFlags]::ObjectInherit), [System.Security.AccessControl.PropagationFlags]::None, $type
            $fileSystemAccessRule = New-Object -TypeName System.Security.AccessControl.FileSystemAccessRule -ArgumentList $fileSystemAccessRuleArgumentList
            # Apply new rule
            try
            {
                $acl.SetAccessRule($fileSystemAccessRule)
                Set-Acl -Path "$gamePath" -AclObject $acl -EA Stop
            }
            catch
            {
                Write-Warning "Failed to grant LocalService permissions to $gamePath. This may cause problems executing the dedicated server."
            }
        }
    }

    if (-NOT $NoStart.IsPresent)
    {
        Write-Verbose "Starting the $gameTaskName task."
        $null = Start-ScheduledTask -TaskName $($world.Name)

        # look for Valheim_server.exe process before continuing
        Write-Verbose "Waiting for the Valheim_server process."
        do {
            Start-Sleep -m 250
            $process = Get-Process $gameProcessName -EA SilentlyContinue
        } until ($process)


        Write-Verbose "Waiting for a listener on the Valheim game port: $($world.port)"
        Write-Verbose "This may take a very long time on first run."
        do {
            Start-Sleep -m 250
            if ($($world.protocol) -eq "TCP")
            {
                $listening = Get-NetTCPConnection -State Listen -LocalPort $($world.port) -EA SilentlyContinue
            }
            elseif ($($world.protocol) -eq "UDP") 
            {
                $listening = Get-NetUDPEndpoint -LocalPort $($world.port) -EA SilentlyContinue
            }
        } until ($listening)
    }
}



Write-Verbose "$gameTaskName is now ready. Have fun exploring!"