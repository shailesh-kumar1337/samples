function endpoint-script 
{
    <# Getting Current logged in user#>
    $currentusername = $env:alexr
    $hostnameofsystem = hostname
    <#Creating file path variable for savaing <Username>.txt file on Desktop#> 
    $outputfilepath = "C:\Users\" + $currentusername + "\Documents\" + $hostnameofsystem + ".txt"
    New-Item -Path $outputfilepath -ItemType File -Force

	$text = "OS version"
    Out-File -FilePath $outputfilepath -InputObject $text -Append
	[environment]::OSVersion.Version | Out-File -FilePath $outputfilepath -Append

	$text = "++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
    Out-File -FilePath $outputfilepath -InputObject $text -Append
	
    $currentdomain = $env:USERDNSDOMAIN
    $text = "Hostname: " + $currentusername
    Out-File -FilePath $outputfilepath -InputObject $text
    $text = "Domain: " + $currentdomain
    Out-File -FilePath $outputfilepath -InputObject $text -Append

	$text = "++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
    Out-File -FilePath $outputfilepath -InputObject $text -Append
	
    $text = "Local User List:"
    Out-File -FilePath $outputfilepath -InputObject $text -Append
    Get-LocalUser | Format-Table -Property Name, Enabled, PasswordChangeableDate | Out-File -FilePath $outputfilepath -Append

	$text = "++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
    Out-File -FilePath $outputfilepath -InputObject $text -Append
	
    $text = "Local Group List:"
    Out-File -FilePath $outputfilepath -InputObject $text -Append
    Get-LocalGroup | Select-Object Name | Out-File -FilePath $outputfilepath -Append 

	$text = "++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
    Out-File -FilePath $outputfilepath -InputObject $text -Append
	     
    $text = "Users List member of Administrators group:"
    Out-File -FilePath $outputfilepath -InputObject $text -Append
    Get-LocalGroupMember -Group Administrators | Format-Table -Property Name, SID, ObjectClass | Out-File -FilePath $outputfilepath -Append

	$text = "++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
    Out-File -FilePath $outputfilepath -InputObject $text -Append
	
    $text = "Users List member of Remote Desktop Users group:"
    Out-File -FilePath $outputfilepath -InputObject $text -Append
    Get-LocalGroupMember -Group "Remote Desktop Users" | Format-Table -Property Name, SID, ObjectClass | Out-File -FilePath $outputfilepath -Append

	$text = "++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
    Out-File -FilePath $outputfilepath -InputObject $text -Append
	
    $text = "List the hotfix and updates installed on the local machine:"
    Out-File -FilePath $outputfilepath -InputObject $text -Append
    Get-HotFix | Format-Table -Property HotFixID, InstalledBy, InstalledOn | Out-File -FilePath $outputfilepath -Append

	$text = "++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
    Out-File -FilePath $outputfilepath -InputObject $text -Append
	
    $text = "List Windows Firewall Profiles Status"
    Out-File -FilePath $outputfilepath -InputObject $text -Append
    Get-NetFirewallProfile | Format-Table Name,Enabled | Out-File -FilePath $outputfilepath -Append

	$text = "++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
    Out-File -FilePath $outputfilepath -InputObject $text -Append
	
    $text = "List of Process currently running excluding svchost:"
    Out-File -FilePath $outputfilepath -InputObject $text -Append
    Get-Process |  where Name -ne "svchost" | Format-Table -Property Name, Id, Path, Company, ProductVersion |  Out-File -FilePath $outputfilepath -Append

	$text = "++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
    Out-File -FilePath $outputfilepath -InputObject $text -Append
	
    $text = "List of Services"
    Out-File -FilePath $outputfilepath -InputObject $text -Append
    Get-Service | Out-File -FilePath $outputfilepath -Append

	$text = "++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
    Out-File -FilePath $outputfilepath -InputObject $text -Append
	
    
    $text = "List of Ports"
    Out-File -FilePath $outputfilepath -InputObject $text -Append
    netstat -abno | select-string -pattern "TCP" | Out-File -FilePath $outputfilepath -Append

	$text = "++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
    Out-File -FilePath $outputfilepath -InputObject $text -Append
	
    $text = "List of Startup Application"
    Out-File -FilePath $outputfilepath -InputObject $text -Append
    Get-CimInstance Win32_StartupCommand | Select-Object Name, User | Format-Table | Out-File -FilePath $outputfilepath -Append

	$text = "++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
    Out-File -FilePath $outputfilepath -InputObject $text -Append
	
    $text = "Proxy Enabled or Disabled: 0 Disabled, 1 Enabled"
    Out-File -FilePath $outputfilepath -InputObject $text -Append
    (get-itemproperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings').ProxyEnable | Out-File -FilePath $outputfilepath -Append

	$text = "++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
    Out-File -FilePath $outputfilepath -InputObject $text -Append
	
	$text = "Proxy Settings"
    Out-File -FilePath $outputfilepath -InputObject $text -Append
	netsh winhttp show proxy | Out-File -FilePath $outputfilepath -Append

	$text = "++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
    Out-File -FilePath $outputfilepath -InputObject $text -Append
	    
    $text = "WSUS Server URL"
    Out-File -FilePath $outputfilepath -InputObject $text -Append
    (Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate').WUStatusServer | Out-File -FilePath $outputfilepath -Append

	$text = "++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
    Out-File -FilePath $outputfilepath -InputObject $text -Append
	
    $text = "List of Softwares installed:"
    Out-File -FilePath $outputfilepath -InputObject $text -Append
    <#For 32-bit reg value software#>
    Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | Select-Object DisplayName, DisplayVersion, Publisher | Out-File -FilePath $outputfilepath -Append
    <#For 64-bit reg value software#>
    Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* | Select-Object DisplayName, DisplayVersion, Publisher | Out-File -FilePath $outputfilepath -Append

	$text = "++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
    Out-File -FilePath $outputfilepath -InputObject $text -Append
	
    $text = "List of drives encrypted with bit-locker"
    Out-File -FilePath $outputfilepath -InputObject $text -Append
    Get-BitLockerVolume | Out-File -FilePath $outputfilepath -Append

	$text = "++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
    Out-File -FilePath $outputfilepath -InputObject $text -Append
	
    $text = "Type of File System: NTFS or FAT32"
    Out-File -FilePath $outputfilepath -InputObject $text -Append
    Get-Volume |Format-Table -Property DriveLetter, FileSYstemType, HealthStatus | Out-File -FilePath $outputfilepath -Append

	$text = "++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
    Out-File -FilePath $outputfilepath -InputObject $text -Append
	

    $text = "USB Allowed or not (3 means enabled, 4 means disabled)"
    Out-File -FilePath $outputfilepath -InputObject $text -Append
    Get-ItemProperty  "HKLM:\SYSTEM\CurrentControlSet\services\USBSTOR" | Select-Object Start | Out-File -FilePath $outputfilepath -Append

	$text = "++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
    Out-File -FilePath $outputfilepath -InputObject $text -Append
	
    $text = "Files on the Desktop"
    Out-File -FilePath $outputfilepath -InputObject $text -Append
    $DesktopPath = "C:\Users\" + $currenthostname +"\OneDrive - EY\Desktop"
    $DesktopPath.Count | Out-File -FilePath $outputfilepath -Append

	$text = "++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
    Out-File -FilePath $outputfilepath -InputObject $text -Append
	
    
    $text = "Password Policy:"
    Out-File -FilePath $outputfilepath -InputObject $text -Append
    net accounts | Out-File -FilePath $outputfilepath -Append

	$text = "++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
    Out-File -FilePath $outputfilepath -InputObject $text -Append
	
    $text = "Current Logged In User Privilege:"
    Out-File -FilePath $outputfilepath -InputObject $text -Append
    whoami /priv | Out-File -FilePath $outputfilepath -Append

	$text = "++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
    Out-File -FilePath $outputfilepath -InputObject $text -Append
	
    $text = "Execution Policy"
    Out-File -FilePath $outputfilepath -InputObject $text -Append
    Get-ExecutionPolicy -List | Out-File -FilePath $outputfilepath -Append

	$text = "++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
    Out-File -FilePath $outputfilepath -InputObject $text -Append
	
    $text = "Password Protect the screen saver (0 Disabled, 1 Enabled)"
    Out-File -FilePath $outputfilepath -InputObject $text -Append
    Get-ItemProperty "HKCU:\Software\Policies\Microsoft\Windows\Control Panel\Desktop" | Select-Object ScreenSaverIsSecure | Out-File -FilePath $outputfilepath -Append 

	$text = "++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
    Out-File -FilePath $outputfilepath -InputObject $text -Append
	
    $text = "Google Chrome Version"
    Out-File -FilePath $outputfilepath -InputObject $text -Append
    (Get-Item (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\chrome.exe').'(Default)').VersionInfo | Out-File -FilePath $outputfilepath -Append

	$text = "++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
    Out-File -FilePath $outputfilepath -InputObject $text -Append
	
    $text = "Mozilla Firefox Version"
    Out-File -FilePath $outputfilepath -InputObject $text -Append
    (Get-Item (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\firefox.exe').'(Default)').VersionInfo | Out-File -FilePath $outputfilepath -Append

	$text = "++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
    Out-File -FilePath $outputfilepath -InputObject $text -Append
	
    $text = "Internet Explore Version"
    Out-File -FilePath $outputfilepath -InputObject $text -Append
    (Get-Item (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\IEXPLORE.EXE').'(Default)').VersionInfo | Out-File -FilePath $outputfilepath -Append

	$text = "++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
    Out-File -FilePath $outputfilepath -InputObject $text -Append
	

    $text = "Getting Antivirus Status:"
    Out-File -FilePath $outputfilepath -InputObject $text -Append
    Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntivirusProduct | Format-Table -Property displayName, productState, timestamp | Out-File -FilePath $outputfilepath -Append

	$text = "++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
    Out-File -FilePath $outputfilepath -InputObject $text -Append
	
    $text = "Trying to stop Antivirus process if running:(If ouput is recorded then the antivirus did not stop)"
    Out-File -FilePath $outputfilepath -InputObject $text -Append
    $antiviruspatharray = ((Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntivirusProduct | Select-Object -Index 0).pathToSignedReportingExe).Split("\")
    Stop-Process -Name (($exename = $antiviruspatharray[-1]).split("."))[0] | Out-File -FilePath $outputfilepath -Append
    Get-Process | findstr (($exename = $antiviruspatharray[-1]).split("."))[0]

	$text = "++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
    Out-File -FilePath $outputfilepath -InputObject $text -Append
	    
	
    <#Changing output filepath here for new file. I new file media path will be written#>
    $outputfilepath = "C:\Users\" + $currentusername + "\Documents\MediaFiles.txt"
    New-Item -Path $outputfilepath -ItemType File -Force

	
	(Get-Volume).DriveLetter | ForEach-Object {
    $pathas = $_ + ":\"
    Get-ChildItem -Path $pathas -File *.mp4 -Recurse | Format-Table -Property Name, Directory | Out-File -FilePath $outputfilepath -Append
    Get-ChildItem -Path $pathas -File *.mp3 -Recurse | Format-Table -Property Name, Directory | Out-File -FilePath $outputfilepath -Append
    Get-ChildItem -Path $pathas -File *.avi -Recurse | Format-Table -Property Name, Directory | Out-File -FilePath $outputfilepath -Append
    Get-ChildItem -Path $pathas -File *.flv -Recurse | Format-Table -Property Name, Directory | Out-File -FilePath $outputfilepath -Append
    Get-ChildItem -Path $pathas -File *.mov -Recurse | Format-Table -Property Name, Directory | Out-File -FilePath $outputfilepath -Append
    Get-ChildItem -Path $pathas -File *.wmv -Recurse | Format-Table -Property Name, Directory | Out-File -FilePath $outputfilepath -Append
    Get-ChildItem -Path $pathas -File *.webm -Recurse | Format-Table -Property Name, Directory | Out-File -FilePath $outputfilepath -Append
    }
}
