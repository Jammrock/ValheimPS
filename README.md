# ValheimPS
PowerShell scripts to install and update a Valheim dedicated server in Windows.

# Instructions

1. Open PowerShell as administrator.
2. Create a location for the script and navigate to that directory.

```powershell
mkdir C:\temp
CD C:\temp
```

3. Download the script.

```powershell
curl https://raw.githubusercontent.com/Jammrock/ValheimPS/main/Update-ValheimServer.ps1 -OutFile .\Update-ValheimServer.ps1
```

4. \[Optional\] Make changes to the script. The top part of the script contains where things are installed, and various bits of info used to install and run the server.
5. Execute the script with these parameters. A Steam account is not needed to install the dedicated server.

```powershell
.\Update-ValheimServer.ps1 -Anonymous -Force -Verbose
```

If script execution is blocked you will need to [change the script execution policy](https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.security/set-executionpolicy?view=powershell-7.1).

5. All set!

## Things the script does

- Installs SteamCMD.
- Uses SteamCMD to install the Valheim Dedicated Server.
- Creates a Scheduled Task that runs the server on startup.
  - The task runs as LocalService.
  - File and folder permissions to the Valheim install directory are granted to LocalService.
- Adds an allow rule in Windows Firewall for valheim_server.exe.
- Starts the server using these arguments:

```
-nographics -batchmode -name "My Valheim Server" -port '+$gameListenPort+' -world "Dedicated" -password "mySecret" -savedir '+$gamePath+'\save -public 0
```

- The server arguments can be adjusted using the `<$gameProcessArgs>` variable.


## Things the script does not do

- Automatically run on a schedule to update the server files to a new version. This is something I'll address in the future. For now, run the same command to update the server files as needed.
- Open any permimeter firewall ports for cloud services like Azure, AWS, etc.
- Make you good at Valheim.
