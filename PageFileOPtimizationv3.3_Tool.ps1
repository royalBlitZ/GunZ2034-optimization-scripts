# Script PowerShell to Change PAGEFILE size and location for Windows Server 2012R2
# OPtimization for App Server - XenApp Servers and RDSH Servers
# by Javier Sanchez Alcazar (CTXDOM.COM)
# Citrix CTP (2009-2017) and Microsoft MVP Reconnect
# Release 3.3 / Modifications in this release, include full Network configuration
# BUG modified in RDHS registry key
#--------------------------------------
# Reference Values Definition
#--------------------------------------
# Binary = REG_BINARY
# DWord = REG_DWORD
# ExpandString = REG_EXPAND_SZ
# MultiString = REG_MULTI_SZ
# None = –
# QWord	= REG_QWORD
# String = REG_SZ
# Unknown  = –
# -------------------------------------

# Import modules
Import-Module Dism
Import-Module PSDesiredStateConfiguration
Import-Module WindowsErrorReporting
Import-Module ScheduledTasks
Import-Module CimCmdlets
Import-Module RemoteDesktop
Import-Module ServerManager


#----------------------------------------------------------------------------------------------------------------
# Variable definition
#---------------------------------------------------------------------------------------------------------------- 
# TMP and TEMP Path location
# 	   Configuration:
#      --------------  
#           The mode is save the TMP and TEMP files to especified centralized storage folder with user name
#            Sample to use:  
#                  Value for TMP folder: \\<Storage_Folder>\%USERNAME%\Temporal\TMP 
#                  Value for TEMP folder: \\<Storage_Folder>\%USERNAME%\Temporal\TEMP
#---------------------------------------------------------------------------------------------------------------
$temp_path = "%USERPROFILE%\AppData\Local\Temp"
$tmp_path = "%USERPROFILE%\AppData\Local\Tmp"
#
# Page File Location
# Specified the correct path to create or reconfigure a pagefile.sys file with correct parameters.
$pagepath = "C:\pagefile.sys"
#
# Menu Show Delay 
# The value is possible accelerate, a full accelerate y 0, and normal rate is 400, default implemented 100.
$menu_delay = 100
#
# Encoding User Preferences Mask
$string_desktop =  0x90,0x12,0x01,0x80,0x10,0x00,0x00,0x00
#
# Read the Network configuration for apply changes
$nic = Get-WmiObject Win32_NetworkAdapterConfiguration -filter "ipenabled = 'true'"
#
#----------------------------------------------------------------------------------------------------------------
# End variable definition
#----------------------------------------------------------------------------------------------------------------

Write-Host "-------------------------------------------------------------"
Write-Host "Server Optimization Tool (C)CTXDOM.COM 2016 - Release 3.3  "
Write-Host "-------------------------------------------------------------"
Write-Host "This Script modifies all Server Configurations, for optimize the performance and mofidy registry keys and other server parameters"
Write-Host "Page File, CleanPageFile,UAC, CrashDump, Hibernate,Memory Management,Auto Layout,System Hand Error,TimeOut,MaxToken Size,ActiveDesktop, CIFS,NFS,Print Error,Task Schedule, TMP and TEMP Folders,Menu Show,Windows Error and Desktop Optimization"
Write-Host "Please, read the Script code, for change the correct values for a TMP / TEMP and Pagile location and Network Configuration".
Write-Host ""

Pause

#----------------------------------------------------
# Networkconfiguration and adapter configuration
# Recomended use a Dialog Box for this configration
# Parameters for read and asign information:
#----------------------------------------------------
# Get-NetAdapter           
# Disable-NetAdapter     
# Enable-NetAdapter      
# Rename-NetAdapter    
# Restart-NetAdapter
# Set-NetAdapter
# New-NetIPAddress
# Remove-NetIPAddress
# Set-DNSClientServerAddress
#----------------------------------------------------
$confirmation = Read-Host "Are you configure Network parameters ? (y/n):"
if ($confirmation -eq 'y' ) {
			$ip_address = Read-Host("Server IP address :")
			$subnetMask = Read-Host("Subnet mask :")
			$gateway = Read-Host("Gateway :")
			$dns = Read-Host("DNS :")
			$domainname = Read-Host ("Domain name :")
			$nic.EnableStatic($ip_address,$subnetmask)
			$nic.SetGateways($gateway,1)
			$nic.SetDNSServerSearchOrder($dns)
			$nic.SetDnsDomain($domainname)
		Write-Host "Network configuration is Modified"
	}

# Configure NetBios over TCP parameter independent to Networkconfiguration
$netbios = Read-Host ("Nebios (0-Enabled 1-NB over TCP, 2 TCP) :")
$nic.SetTcpipNetbios($netbios)

# Server RAM calculator 
$Memoriatotal = Get-CimInstance Win32_PhysicalMemory | Measure-Object -Property capacity -Sum | Foreach {"{0:N2}" -f ([math]::round(($_.Sum / 1MB), 2))}
# Enable All Privileges for Registry changes.
Get-WmiObject -Class Win32_ComputerSystem -EnableAllPrivileges
Write-Host "Total Server Memory : " $MemoriaTotal

# Assign the correct values and change values to num
$valor=1.5
$MemoriaTotalN = [int]$MemoriaTotal
$Memoriatotalvalor=($MemoriaTotalN*$valor)
Write-Host "Total Memory to Asign to PageFile: " $MemoriaTotalvalor
Write-Host ""

# Asign Memory to Page File and Modify the Registre Values. / Remember->Restart is necessary to apply changes
# Modify the Registry Key for this modification and New calculated values.
set-itemproperty "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\" -name "PagingFiles" -type multistring -value "$pagepath $MemoriaTotalvalor $MemoriaTotalvalor" 
Write-Host "PageFile is changed in this Server"
Write-Host ""

# Modify the ClearPageFile ShutDown to No in Server Configuration
set-itemproperty "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\" -name "ClearPageFileShutdown" -type dword -value "00000000" 
Write-Host "ClearPageFile Shutdown Changed"

# Dissable UAC in Server configuration
set-itemproperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\policies\system\" -name "EnableLUA" -type dword -value "00000000"
Write-Host "UAC is Disabled"

# Dissable CrashDumpConfiguration in Server Configuration
set-itemproperty "HKLM:\SYSTEM\CurrentControlSet\Control\CrashControl\" -name "LogEvent" -type dword -value "00000000"
set-itemproperty "HKLM:\SYSTEM\CurrentControlSet\Control\CrashControl\" -name "AutoReboot" -type dword -value "00000000"
set-itemproperty "HKLM:\SYSTEM\CurrentControlSet\Control\CrashControl\" -name "CrashDumpEnabled" -type dword -value "00000000"
Write-Host "Crash Dump Configuration is Disabled [Disabled: Event Log, Auto Reboot and Crash Dump File"

# Dissable Hibernate in Server Configuration
set-itemproperty "HKLM:\SYSTEM\CurrentControlSet\Control\Power\" -name "HibernateEnabled" -type dword -value "00000000"
Write-Host "Hibernate is Disabled"

# Modify the Paging Executive in Server Configuration
set-itemproperty "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\" -name "DisablePagingExecutive" -type dword -value "00000001" 
Write-Host "Paging Executive is Dissable"

# Dissable Task Offload in Server Configuration
set-itemproperty "HKLM:\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\" -name "DisableTaskOffload" -type dword -value "00000001" 
Write-Host "Dissable Task Offload"

# Enable Auto Layout in Server Configuration
set-itemproperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\OptimalLayout\" -name "EnableAutoLayout" -type string -value "C:\\Windows\\Prefetch\\Layout.ini" 
set-itemproperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\OptimalLayout\" -name "EnableAutoLayout" -type dword -value "00000000" 
Write-Host "AutoLayout is Enabled"

# Hide System HandError Messages in Server Configuration
set-itemproperty "HKLM:\SYSTEM\CurrentControlSet\Control\Windows\" -name "ErrorMode" -type dword -value "00000002" 
Write-Host "Hand Error Messages is Disabled"

# Increased Services Timeot in Server Configuration
set-itemproperty "HKLM:\SYSTEM\CurrentControlSet\Control\" -name "WaitToKillServiceTimeout" -type string -value "20000" 
set-itemproperty "HKLM:\SYSTEM\CurrentControlSet\Control\" -name "ServicesPipeTimeout" -type string -value "30000" 
Write-Host "Services Timeout Increased"

# MaxTokenSize_Kerberos in Server Configuration
set-itemproperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\Kerberos\Parameters\" -name "ErrorMode" -type dword -value "00065535" 
Write-Host "Max Token Size Modified"

# Hide System HandError Messages in Server Configuration / Error Reporting
set-itemproperty "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Policies\Explorer\" -name "ForceActiveDesktopOn" -type dword -value "00000000" 
set-itemproperty "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Policies\Explorer\" -name "NoActiveDesktopChanges" -type dword -value "00000001" 
set-itemproperty "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Policies\Explorer\" -name "ForceActiveDesktop" -type dword -value "00000001"
set-itemproperty "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Policies\Explorer\" -name "NoRwmorwEwcursiveEvents" -type dword -value "00000001" 
Write-Host "ActiveDesktop & CIFS Disabled"

# NFS Dissable Last Access Time Stamp in Server Configuration
set-itemproperty "HKLM:\SYSTEM\CurrentControlSet\Control\FileSystem\" -name "NfsDisableAccessUpdate" -type dword -value "00000001" 
Write-Host "NFS DIssable Last Access Time Stamp is Applied"

# Enable Print Error Event Only in Server Configuration
set-itemproperty "HKLM:\SYSTEM\CurrentControlSet\Control\Print\Providers\" -name "EventLog" -type dword -value "00000001" 
Write-Host "Only Enable Print Error Event is Applied"

# Dissable a Scheduled Tasks Google
Get-ScheduledTask -taskname google* | Disable-ScheduledTask
Write-Host "Google Schedule Task is Disabled"

# Dissable a Scheduled Tasks Adobe
Get-ScheduledTask -taskname Adobe* | Disable-ScheduledTask
Write-Host "Adobe Flash Player Updater Schedule Task is Disabled"

# Modify the TEMP and TMP environment
Write-Host "TEMP and TMP Configuration [Standard: %USERPROFILE%\AppData\Local\Temp]"
$env:TEMP
$env:TMP
Write-Debug "Modified with especified parameters configuration"
set-itemproperty -Path Registry::HKEY_USERS\.DEFAULT\Environment\ -name "TEMP" -Type ExpandString -value $temp_path
Write-Host "TEMP parameter modified"
set-itemproperty -Path Registry::HKEY_USERS\.DEFAULT\Environment\ -name "TMP" -Type ExpandString -value $tmp_path
Write-Host "TMP parameter modified"

# Menu Show Delay accelerated
set-itemproperty -Path Registry::"HKCU\Control Panel\Desktop\" -name "MenuShowDelay" -Type String -value $menu_delay
set-itemproperty -Path Registry::"HKEY_USERS\.DEFAULT\Control Panel\Desktop\" -name "MenuShowDelay" -Type String -value $menu_delay
Write-Host "Menu is accelerated"

# Diable Windows Error Reporting
Disable-WindowsErrorReporting
Write-Host "Windows Error Reporting is Disabled"

#-----------------------------------------------------------------------------------------------------------------------------
# Desktop Server Optimization - Thisparameters is possible applied to Windows Desktop
#-----------------------------------------------------------------------------------------------------------------------------
set-itemproperty -Path Registry::"HKEY_USERS\.DEFAULT\Control Panel\Desktop\" -name "DragFullWindows" -Type String -value "0"
Write-Host "Drag Full Windows is Disabled"
set-itemproperty -Path Registry::"HKEY_USERS\.DEFAULT\Control Panel\Desktop\" -name "FontSmoothing" -Type String -value "0"
Write-Host "Font Smoothing is Disabled"
# Encoding User Preferences Mask
set-itemproperty -Path Registry::"HKEY_USERS\.DEFAULT\Control Panel\Desktop\" -name "UserPreferencesMask" -Type Binary -value $string_desktop
Write-Host "User Preferences Mask Modified"
# Minimum Animated Windows Metrics Modified
set-itemproperty -Path Registry::"HKEY_USERS\.DEFAULT\Control Panel\Desktop\WindowMetrics\" -name "MinAnimate" -Type String -value "0"
Write-Host "Minimum Animated Windows Metrics Modified"

#-------------------------------------------------------------------------------------------
# Don't check Windows Update
# Values:
# 1 = Disables AU (Same as disabling it through the standard controls)
# 2 = Notify Download and Install (Requires Administrator Privileges)
# 3 = Notify Install (Requires Administrator Privileges)
# 4 = Automatically, no notification (Uses ScheduledInstallTime and ScheduledInstallDay)
#-------------------------------------------------------------------------------------------
set-itemproperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\" -name "AUOptions" -Type dword -value "00000001"
Write-Host "Don't check Windows Update is applied"

# Remote Desktop Session Host configuration 
#                   Delete Temporal folders on exit/Yes 
#                   Use temporary folders per session/Yes 
#                  
# 
# Get-WindowsFeature display the features installed on this server.
# 
$ServiceName = "Remote-Desktop-Services"
$Servicio = Get-WindowsFeature -Name $ServiceName
if ($Servicio.InstallState -ne "Installed"){
				Write-Host  "No RDSH services installed on this server, no changed to apply" 
}
if ($Servicio.InstallState -eq "Installed"){ 
				Write-Host "RDSH services installed on this server .. Apply the specified modificacions"
				# Configuration parameters to apply only to this RDSH Server.
				# Delete Temporal folders on exit
				# 
				set-itemproperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\" -name "DeleteTempDirsOnExit" -Type dword -value "00000000"
				Write-Host ".....RDSH: Delete Temporal folders on exit modified"
				set-itemproperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\" -name "PerSessionTempDir" -Type dword -value "00000000"
				Write-Host ".....RDSH: Do nout use temporary folder per session modified"
}


# ---------------------------------------------------------------------------------
# Standby no modified by the moment, pending to decission to implement.
# Disable convention name8 
# 0 enabled
# 1 disabled
# Value : NtfsDisable8dot3NameCreation
# HKLM\System\CurrentControlSet\Control\FileSystem\NtfsDisable8dot 3NameCreation
# ---------------------------------------------------------------------------------

#-----------------------------------------------------------------------------------------------------------
# Restart Server for aply all configurations
#-----------------------------------------------------------------------------------------------------------
Write-Host ""
Write-Host "Please, Restart your Server, all changes applied".
Restart-Computer -Confirm

#-----------------------------------------------------------------------------------------------------------
# End of Code/PowerShell
#-----------------------------------------------------------------------------------------------------------
