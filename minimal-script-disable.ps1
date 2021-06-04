$ISVM = (Get-WmiObject -Class Win32_ComputerSystem).Model | Select-String -Pattern "KVM|Virtual" -Quiet

echo "Disabling V1..."
Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force

echo "Disabling NetBIOS..."
$key = "HKLM:SYSTEM\CurrentControlSet\services\NetBT\Parameters\Interfaces"
Get-ChildItem $key |
foreach { 
  Write-Host("Modify $key\$($_.pschildname)")
  $NetbiosOptions_Value = (Get-ItemProperty "$key\$($_.pschildname)").NetbiosOptions
  Write-Host("NetbiosOptions updated value is $NetbiosOptions_Value")
}

echo "DEP enabled for Windows Essentials Services only..."
cmd.exe /C "bcdedit.exe /set {current} nx OptIn"

echo "Disabling unnecessary network services..."
Disable-NetAdapterBinding -Name "Ethernet" -ComponentID ms_lldp 2> $null
Disable-NetAdapterBinding -Name "Ethernet" -ComponentID ms_lltdio
Disable-NetAdapterBinding -Name "Ethernet" -ComponentID ms_implat
Disable-NetAdapterBinding -Name "Ethernet" -ComponentID ms_rspndr
Disable-NetAdapterBinding -Name "Ethernet" -ComponentID ms_tcpip6
Disable-NetAdapterBinding -Name "Ethernet" -ComponentID ms_server
Disable-NetAdapterBinding -Name "Ethernet" -ComponentID ms_msclient

echo "Activating automatic updates..."
reg add "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\WindowsUpdate\AU" /v NoAutoUpdate /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\WindowsUpdate\AU" /v AUOptions /t REG_DWORD /d 4 /f

echo "Disabling Firewall rules..."
Netsh advfirewall firewall set rule group="Windows Remote Management" new enable=no
Netsh advfirewall firewall set rule group="Windows Management Instrumentation (WMI)" new enable=no

echo "Activating ICMP input..."
Netsh advfirewall firewall set rule name="File and Printer Sharing (Echo Request - ICMPv4-In)" new enable=yes

echo "Activating RDP..."
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f
Netsh advfirewall firewall set rule group="remote desktop" new enable=yes

echo "Updating server time with NTP..."
tzutil /s "Central Standard Time"
net start w32time
netsh advfirewall firewall delete rule name="Allow OUT NTP"
netsh advfirewall firewall add rule name="Allow OUT NTP" dir=out remoteport="123" protocol=udp  action=allow
w32tm /resync

echo "Disabling Auto-start Server Manager..."
Get-ScheduledTask -TaskName ServerManager | Disable-ScheduledTask -Verbose

echo "Disabling the expiration of the Administrator user..."
WMIC USERACCOUNT SET PasswordExpires=FALSE

if ($ISVM) {
	echo "VM detected, disabling Antivirus..."
	Set-MpPreference -DisableRealtimeMonitoring $true
}

echo "Changing RDP port to 20389..."
netsh advfirewall firewall delete rule name="RDP Alternate Port"
netsh advfirewall firewall add rule name="RDP Alternative Port" dir=in localport="20389" protocol=tcp  action=allow
Set-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Control\Terminal*Server\WinStations\RDP-TCP\ -Name PortNumber -Value 20389

echo "Final cleaning..."
Remove-Item (Get-PSReadlineOption).HistorySavePath
Remove-Item -Path $MyInvocation.MyCommand.Source

echo "Ready!"
