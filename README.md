# GunZ2034-optimization-scripts
Set-NetTCPSetting : Only the custom templates InternetCustom and DatacenterCustom can be modified under Windows 8 and older Windows 10 versions.

Even though theoretically only the "Custom" templates can be modified, many of the commands below (both netsh and PowerShell TCP cmdlets) are global and modify all templates simultaneously.

#By default, the "Internet" template/profile is applied to TCP connections. To find the currently used template type either:

using PowerShell cmdlets (run as Administrator):
Get-NetTransportFilter

or, using netsh:
netsh int tcp show supplemental

#To view the current template settings, use:

    Get-NetTCPSetting -SettingName "Internet"  (or your current template name)
#make sure that you do not uses the service before disabling it.
Dism.exe /Online /Disable-Feature /NoRestart /featurename:Client-ProjFS
Dism.exe /Online /Disable-Feature /NoRestart /featurename:DirectPlay
Dism.exe /Online /Disable-Feature /NoRestart /featurename:HypervisorPlatform
Dism.exe /Online /Disable-Feature /NoRestart /featurename:IIS-ApplicationDevelopment
Dism.exe /Online /Disable-Feature /NoRestart /featurename:IIS-ApplicationInit
Dism.exe /Online /Disable-Feature /NoRestart /featurename:IIS-ASP
Dism.exe /Online /Disable-Feature /NoRestart /featurename:IIS-ASPNET
Dism.exe /Online /Disable-Feature /NoRestart /featurename:IIS-ASPNET45
Dism.exe /Online /Disable-Feature /NoRestart /featurename:IIS-BasicAuthentication
Dism.exe /Online /Disable-Feature /NoRestart /featurename:IIS-CGI
Dism.exe /Online /Disable-Feature /NoRestart /featurename:IIS-CommonHttpFeatures
Dism.exe /Online /Disable-Feature /NoRestart /featurename:IIS-CustomLogging
Dism.exe /Online /Disable-Feature /NoRestart /featurename:IIS-DefaultDocument
Dism.exe /Online /Disable-Feature /NoRestart /featurename:IIS-DirectoryBrowsing
Dism.exe /Online /Disable-Feature /NoRestart /featurename:IIS-FTPExtensibility
Dism.exe /Online /Disable-Feature /NoRestart /featurename:IIS-FTPServer
Dism.exe /Online /Disable-Feature /NoRestart /featurename:IIS-FTPSvc
Dism.exe /Online /Disable-Feature /NoRestart /featurename:IIS-HealthAndDiagnostics
Dism.exe /Online /Disable-Feature /NoRestart /featurename:IIS-HostableWebCore
Dism.exe /Online /Disable-Feature /NoRestart /featurename:IIS-HttpCompressionDynamic
Dism.exe /Online /Disable-Feature /NoRestart /featurename:IIS-HttpCompressionStatic
Dism.exe /Online /Disable-Feature /NoRestart /featurename:IIS-HttpErrors
Dism.exe /Online /Disable-Feature /NoRestart /featurename:IIS-HttpLogging
Dism.exe /Online /Disable-Feature /NoRestart /featurename:IIS-HttpRedirect
Dism.exe /Online /Disable-Feature /NoRestart /featurename:IIS-HttpTracing
Dism.exe /Online /Disable-Feature /NoRestart /featurename:IIS-IIS6ManagementCompatibility
Dism.exe /Online /Disable-Feature /NoRestart /featurename:IIS-IPSecurity
Dism.exe /Online /Disable-Feature /NoRestart /featurename:IIS-ISAPIExtensions
Dism.exe /Online /Disable-Feature /NoRestart /featurename:IIS-ISAPIFilter
Dism.exe /Online /Disable-Feature /NoRestart /featurename:IIS-LegacyScripts
Dism.exe /Online /Disable-Feature /NoRestart /featurename:IIS-LegacySnapIn
Dism.exe /Online /Disable-Feature /NoRestart /featurename:IIS-LoggingLibraries
Dism.exe /Online /Disable-Feature /NoRestart /featurename:IIS-ManagementConsole
Dism.exe /Online /Disable-Feature /NoRestart /featurename:IIS-ManagementScriptingTools
Dism.exe /Online /Disable-Feature /NoRestart /featurename:IIS-ManagementService
Dism.exe /Online /Disable-Feature /NoRestart /featurename:IIS-Metabase
Dism.exe /Online /Disable-Feature /NoRestart /featurename:IIS-NetFxExtensibility
Dism.exe /Online /Disable-Feature /NoRestart /featurename:IIS-NetFxExtensibility45
Dism.exe /Online /Disable-Feature /NoRestart /featurename:IIS-Performance
Dism.exe /Online /Disable-Feature /NoRestart /featurename:IIS-RequestFiltering
Dism.exe /Online /Disable-Feature /NoRestart /featurename:IIS-RequestMonitor
Dism.exe /Online /Disable-Feature /NoRestart /featurename:IIS-Security
Dism.exe /Online /Disable-Feature /NoRestart /featurename:IIS-ServerSideIncludes
Dism.exe /Online /Disable-Feature /NoRestart /featurename:IIS-StaticContent
Dism.exe /Online /Disable-Feature /NoRestart /featurename:IIS-URLAuthorization
Dism.exe /Online /Disable-Feature /NoRestart /featurename:IIS-WebDAV
Dism.exe /Online /Disable-Feature /NoRestart /featurename:IIS-WebServer
Dism.exe /Online /Disable-Feature /NoRestart /featurename:IIS-WebServerManagementTools
Dism.exe /Online /Disable-Feature /NoRestart /featurename:IIS-WebServerRole
Dism.exe /Online /Disable-Feature /NoRestart /featurename:IIS-WebSockets
Dism.exe /Online /Disable-Feature /NoRestart /featurename:IIS-WMICompatibility
Dism.exe /Online /Disable-Feature /NoRestart /featurename:Internet-Explorer-Optional-amd64
Dism.exe /Online /Disable-Feature /NoRestart /featurename:LegacyComponents
Dism.exe /Online /Disable-Feature /NoRestart /featurename:MediaPlayback
Dism.exe /Online /Disable-Feature /NoRestart /featurename:MicrosoftWindowsPowerShellV2
Dism.exe /Online /Disable-Feature /NoRestart /featurename:MicrosoftWindowsPowerShellV2Root
Dism.exe /Online /Disable-Feature /NoRestart /featurename:Microsoft-Windows-Subsystem-Linux
Dism.exe /Online /Disable-Feature /NoRestart /featurename:MSMQ-Container
Dism.exe /Online /Disable-Feature /NoRestart /featurename:MSMQ-DCOMProxy
Dism.exe /Online /Disable-Feature /NoRestart /featurename:MSMQ-HTTP
Dism.exe /Online /Disable-Feature /NoRestart /featurename:MSMQ-Multicast
Dism.exe /Online /Disable-Feature /NoRestart /featurename:MSMQ-Server
Dism.exe /Online /Disable-Feature /NoRestart /featurename:MSMQ-Triggers
Dism.exe /Online /Disable-Feature /NoRestart /featurename:NetFx4Extended-ASPNET45
Dism.exe /Online /Disable-Feature /NoRestart /featurename:Printing-Foundation-LPDPrintService 
Dism.exe /Online /Disable-Feature /NoRestart /featurename:Printing-Foundation-LPRPortMonitor
Dism.exe /Online /Disable-Feature /NoRestart /featurename:Printing-XPSServices-Features
rem Dism.exe /Online /Disable-Feature /NoRestart /featurename:RasRip
Dism.exe /Online /Disable-Feature /NoRestart /featurename:SimpleTCP
Dism.exe /Online /Disable-Feature /NoRestart /featurename:SMB1Protocol
Dism.exe /Online /Disable-Feature /NoRestart /featurename:SMB1Protocol-Client
Dism.exe /Online /Disable-Feature /NoRestart /featurename:SMB1Protocol-Deprecation
Dism.exe /Online /Disable-Feature /NoRestart /featurename:SMB1Protocol-Server
Dism.exe /Online /Disable-Feature /NoRestart /featurename:SNMP
Dism.exe /Online /Disable-Feature /NoRestart /featurename:TelnetClient
Dism.exe /Online /Disable-Feature /NoRestart /featurename:TFTP
Dism.exe /Online /Disable-Feature /NoRestart /featurename:TIFFIFilter
Dism.exe /Online /Disable-Feature /NoRestart /featurename:VirtualMachinePlatform
Dism.exe /Online /Disable-Feature /NoRestart /featurename:WAS-ConfigurationAPI
Dism.exe /Online /Disable-Feature /NoRestart /featurename:WAS-NetFxEnvironment
Dism.exe /Online /Disable-Feature /NoRestart /featurename:WAS-ProcessModel
Dism.exe /Online /Disable-Feature /NoRestart /featurename:WAS-WindowsActivationService
Dism.exe /Online /Disable-Feature /NoRestart /featurename:WCF-HTTP-Activation
Dism.exe /Online /Disable-Feature /NoRestart /featurename:WCF-HTTP-Activation45
Dism.exe /Online /Disable-Feature /NoRestart /featurename:WCF-MSMQ-Activation45
Dism.exe /Online /Disable-Feature /NoRestart /featurename:WCF-NonHTTP-Activation
Dism.exe /Online /Disable-Feature /NoRestart /featurename:WCF-Pipe-Activation45
Dism.exe /Online /Disable-Feature /NoRestart /featurename:WCF-Services45
Dism.exe /Online /Disable-Feature /NoRestart /featurename:WCF-TCP-Activation45
Dism.exe /Online /Disable-Feature /NoRestart /featurename:WCF-TCP-PortSharing45
Dism.exe /Online /Disable-Feature /NoRestart /featurename:Windows-Identity-Foundation
Dism.exe /Online /Disable-Feature /NoRestart /featurename:WindowsMediaPlayer
rem Dism.exe /Online /Disable-Feature /NoRestart /featurename:WMISnmpProvider
Dism.exe /Online /Disable-Feature /NoRestart /featurename:WorkFolders-Client
Dism.exe /Online /Enable-Feature /NoRestart /featurename:FaxServicesClientPackage
Dism.exe /Online /Enable-Feature /NoRestart /featurename:Microsoft-Windows-NetFx3-OC-Package
Dism.exe /Online /Enable-Feature /NoRestart /featurename:Microsoft-Windows-NetFx3-WCF-OC-Package
Dism.exe /Online /Enable-Feature /NoRestart /featurename:Microsoft-Windows-NetFx4-US-OC-Package
Dism.exe /Online /Enable-Feature /NoRestart /featurename:Microsoft-Windows-NetFx4-WCF-US-OC-Package
Dism.exe /Online /Enable-Feature /NoRestart /featurename:MSRDC-Infrastructure
Dism.exe /Online /Enable-Feature /NoRestart /featurename:NetFx3
Dism.exe /Online /Enable-Feature /NoRestart /featurename:NetFx4-AdvSrvs
Dism.exe /Online /Enable-Feature /NoRestart /featurename:Printing-Foundation-Features
Dism.exe /Online /Enable-Feature /NoRestart /featurename:Printing-Foundation-InternetPrinting-Client 
Dism.exe /Online /Enable-Feature /NoRestart /featurename:Printing-PrintToPDFServices-Features
Dism.exe /Online /Enable-Feature /NoRestart /featurename:SearchEngine-Client-Package
Dism.exe /Online /Enable-Feature /NoRestart /featurename:Windows-Defender-Default-Definitions

netsh advfirewall firewall set rule group="Connect" new enable=no
netsh advfirewall firewall set rule group="Contact Support" new enable=no
netsh advfirewall firewall set rule group="Cortana" new enable=no
netsh advfirewall firewall set rule group="DiagTrack" new enable=no
netsh advfirewall firewall set rule group="Feedback Hub" new enable=no
netsh advfirewall firewall set rule group="Microsoft Photos" new enable=no
netsh advfirewall firewall set rule group="OneNote" new enable=no
netsh advfirewall firewall set rule group="Remote Assistance" new enable=no
netsh advfirewall firewall set rule group="Windows Spotlight" new enable=no netsh advfirewall set allprofile state on
 netsh advfirewall firewall add rule name=deny445 dir=in action=block protocol=TCP localport=445
#netsh advfirewall firewall add rule name="Block Domain and Private Networking" dir=out action=block profile=domain,private enable=yes | Out-Null
#netsh advfirewall firewall add rule name="Block Windows Update" dir=out action=block program="%SystemRoot%\system32\svchost.exe" protocol=TCP remoteport=80,443 profile=any enable=yes | Out-Null
#netsh advfirewall firewall add rule name="Core Networking - DNS" dir=out action=allow program="%SystemRoot%\system32\svchost.exe" protocol=UDP remoteport=53 profile=public enable=yes | Out-Null
#netsh advfirewall firewall add rule name="Core Networking - DHCP" dir=out action=allow program="%SystemRoot%\system32\svchost.exe" protocol=UDP localport=68 remoteport=67 profile=public enable=yes | Out-Null
			netsh advfirewall firewall add rule name="Block Domain and Private Networking" dir=in action=block profile=domain,private enable=yes | Out-Null		}
# Enable Firewall Profiles & Disable Local Firewall Rules
Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True -AllowLocalFirewallRules False
	
New-ItemProperty -Force -Path "HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters" -Name "EnableLMHOSTS" -PropertyType DWord -Value 0 | Out-Null

# Disable NetBIOS
Disable-NetAdapterBinding -Name "*" -ComponentID "ms_pacer" | Out-Null

# Disable SMB Server

Disable-NetAdapterBinding -Name "*" -ComponentID "ms_server" | Out-Null

# Disable Ipv6

Disable-NetAdapterBinding -Name "*" -ComponentID "ms_tcpip6" | Out-Null
New-ItemProperty -Force -Path "HKLM:\SYSTEM\CurrentControlSet\Services\TCPIP6\Parameters" -Name "DisabledComponents" -PropertyType DWord -Value "0xFFFFFFFF" | Out-Null

# Disable LLDP
write "`n Disabling LLDP `n"

Disable-NetAdapterBinding -Name "*" -ComponentID "ms_lldp" | Out-Null

# Disable LLTD


Disable-NetAdapterBinding -Name "*" -ComponentID "ms_lltdio" | Out-Null
Disable-NetAdapterBinding -Name "*" -ComponentID "ms_rspndr" | Out-Null

# Disable SMBv1
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" SMB1 -Value 0

# Cred Exposure and Credential Hardening
Set-ItemProperty HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System -Name LocalAccountTokenFilterPolicy -Value 0
Set-ItemProperty HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System -Name FilterAdministratorToken -Value 1
Set-ItemProperty HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System -Name EnableLUA -Value 1

# Cleartext Password Protection
Set-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest -Name UseLogonCredential -Value 0
Set-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Control\Lsa -Name TokenLeakDetectDelaySecs -Value 30
powershell "Disable-MMAgent -MemoryCompression"

# Disable MS Net Client
	write "`n Disabling MS Net Client `n"

# Block SMB
netsh advfirewall firewall set rule group=”File and Printer Sharing” new enable=no

Notes:
PowerShell cmdlets are not case-sensitive. Even though some settings below modify all templates, it may still be necessary to sometimes change the default template used for TCP connections from Internet to Custom/InternetCustom. The following command supposedly changes the default (does not work as documented by MS under Windows 8/8.1):
Disable Nagle's Algorithm
(TCP Optimizer "Advanced Settings" tab)
This tweak works with all versions of Windows from Windows XP to Windows 8.1/10/2012 server. This is the same as listed in our general tweaking articles per OS.

Nagle's algorithm is designed to allow several small packets to be combined together into a single, larger packet for more efficient transmissions. While this improves throughput efficiency and reduces TCP/IP header overhead, it also briefly delays transmission of small packets. Disabling "nagling" can help reduce latency/ping in some games. Keep in mind that disabling Nagle's algorithm may also have some negative effect on file transfers. Nagle's algorithm is enabled in Windows by default. To implement this tweak and disable Nagle's algorithm, modify the following registry keys.

HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{NIC-id}
There will be multiple NIC interfaces listed there, for example: {1660430C-B14A-4AC2-8F83-B653E83E8297}. Find the correct one with your IP address listed. Under this {NIC-id} key, create a new DWORD value:
"TcpAckFrequency"=1 (DWORD value, not present by default interpreted as 2, 1=disable nagling, specifies number of outstanding ACKs before ignoring delayed ACK timer). For gaming performance, recommended is 1 (disable). For pure throughput and data streaming, you can experiment with small values over 2. Wifi performance may see a slight improvement with disabled TcpAckFrequency as well.

In the same location, add a new DWORD value:
TCPNoDelay=1 (DWORD, not present by default, 0 to enable Nagle's algorithm, 1 to disable)

To configure the ACK interval timeout (only has effect if nagling is enabled), find the following key:
TcpDelAckTicks=0  (DWORD value, not present by default interpreted as 2, 0=disable nagling, 1-6=100-600 ms). Note you can also set this to 1 to reduce the nagle effect from the default of 200ms without disabling it.

For Server Operating Systems that have Microsoft Message Queuing (MSMQ) installed, or if you have the MSMQ registry hive present, also add TCPNoDelay to:
HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\MSMQ\Parameters
TCPNoDelay=1 (DWORD, not present by default, 0 to enable Nagle's algorithm, 1 to disable)

Note: Reportedly, disabling Nagle's algorithm can reduce the latency in many MMOs like Diablo III and WoW (World of Warcraft) by almost half! Yes, it works with Windows 7 and Windows 8.



Network Throttling Index Gaming Tweak
(TCP Optimizer "Advanced Settings" tab)
Works with all current versions of Windows from Vista to 8.1/10/2012 Server.

Windows implements a network throttling mechanism to restrict the processing of non-multimedia network traffic to 10 packets per millisecond (a bit over 100 Mbits/second). The idea behind such throttling is that processing of network packets can be a resource-intensive task, and it may need to be throttled to give prioritized CPU access to multimedia programs. In some cases, such as Gigabit networks and some online games, for example, it is beneficial to turn off such throttling all together for achieving maximum throughput.

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile]
"NetworkThrottlingIndex"=dword:ffffffff (DWORD, default: 10, recommended: 10 for media sharing, ffffffff for gaming and max throughput, valid range: 1 through 70 decimal or ffffffff to completely disable throttling)

It is only recommended to change this setting in saturated Gigabit LAN environments, where you do not want to give priority to multimedia playback. Reportedly, disabling throttling by using ffffffff can also help reduce ping spikes in some online games. Games that may be affected by this throttling: Source Engine games (TF2, Left 4 Dead, CS:S), HoN, CoD, Overlord series.



System Responsiveness Gaming Tweak
(TCP Optimizer "Advanced Settings" tab)
Exists in all versions of Windows from Vista to 8.1/10/2012 Server.

Multimedia applications use the "Multimedia Class Scheduler" service (MMCSS) to ensure prioritized access to CPU resources, without denying CPU resources to lower-priority background applications. This reserves 20% of CPU by default for background processes, your multimedia streaming and some games can only utilize up to 80% of the CPU. This setting, in combination with the "NetworkThrottlingIndex" can help some games and video streaming. We recommend reducing the reserved CPU for background processes from the default of 20%.

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile]
"SystemResponsiveness"=dword:00000000  (default: 20, recommended: decimal 10 for general applications, 0 for pure gaming/streaming)

Note: In Server operating systems (Windows 2008/2012 Server), SystemResponsiveness is set to 100 by default, denoting that background services should take priority over any multimedia applications.



Turn off LargeSystemCache
(TCP Optimizer "Advanced Settings" tab)
For local network large file transfers, this registry settings allows for better throughput and eliminates some file sharing event log errors (Event ID 2017 error). However, reportedly it has issues with some ATI Video card drivers and certain applications performance. Therefore we recommend turning it off (set to zero) for gaming.

HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management
LargeSystemCache=0 (DWORD, default value: 0, recommended value: 1 for LAN throughput, 0 for gaming)
A value of zero establishes a cache of ~8 MB, a value of 1 allows the cache to expand up to the amount of physical memory minus 4 MB, as necessary.



Disable Game Bar and Game Mode under Windows 10 Creators update
Windows 10 Creators' update introduced a "Game Bar" to to help Xbox integration and gaming in general, however, they can reportedly cause stuttering during gaming, especially with Windows 10 builds prior to v1709.

Congestion Control Provider
The TCP Congestion Control Algorithm controls how well, and how fast your connection recovers from network congestion, packet loss, and increase in latency. Microsoft changed the default "congestion provider" from CTCP to CUBIC with the Windows Creators update.

Possible settings are: none, CTCP, CUBIC, DCTCP, New-Reno
Recommended: CTCP for gaming and latency sensitive apps, CUBIC for pure throughput

To see the current setting, in PowerShell use: Get-NetTCPSetting | Select SettingName, CongestionProvider  (in later Windows 10 builds, the default used template "SettingName" is "Internet". For more info se our Windows 10 Tweaks article)

Note: If using CTCP and with lossy connections (good possibility of congestion/packet loss), you may also want to enable ECN.

 

ECN Capability
(Editable with the TCP Optimizer)
ECN (Explicit Congestion Notification, RFC 3168) is a mechanism that provides routers with an alternate method of communicating network congestion. It is aimed to decrease retransmissions. In essence, ECN assumes that the cause of any packet loss is router congestion. It allows routers experiencing congestion to mark packets and allow clients to automatically lower their transfer rate to prevent further packet loss. Traditionally, TCP/IP networks signal congestion by dropping packets. When ECN is successfully negotiated, an ECN-aware router may set a bit in the IP header (in the DiffServ field) instead of dropping a packet in order to signal congestion. The receiver echoes the congestion indication to the sender, which must react as though a packet drop were detected. ECN is disabled by default in modern Windows TCP/IP implementations, as it is possible that it may cause problems with some outdated routers that drop packets with the ECN bit set, rather than ignoring the bit.

Possible settings are: enabled, disabled, default (restores the state to the system default).
Default state: disabled
Recommendation: "enabled" for gaming only with routers that support it, after testing. It's effects are more noticeable in the presence of congestion/packet loss. Disable for pure throughput with no packet loss.

ECN works well for short-lived, interactive connections like gaming and HTTP requests with routers that support it, in the presence of congestion/packet loss. It can be disabled if tuning for pure bulk throughput with large TCP Window, no regular congestion/packet loss, or with outdated routers that do not support ECN.

To change using netsh:

netsh int tcp set global ecncapability=enabled
(alternative syntax:  netsh int tcp set global ecn=enabled)

To change using PowerShell cmdlets in Windows 8.1/2012 Server R2 :

Set-NetTCPSetting -SettingName InternetCustom -EcnCapability Disabled
(for Windows 8/2012, the name of the template in the above command is "Custom" instead of "InternetCustom")

Notes:
ECN is only effective in combination with AQM (Active Queue Management) router policy. It has more noticeable effect on performance with interactive connections, online games, and HTTP requests, in the presence of router congestion/packet loss. Its effect on bulk throughput with large TCP Window are less clear. Currently, we only recommend enabling this setting in the presence of packet loss, with ECN-capable routers. Its effects should be tested. We also recommend using ECN if you are enabling the CoDel scheduling algorithm to combat bufferbloat and reduce latency.
Use caution when enabling ECN, as it may also have negative impact on throughput with some residential US ISPs. Some EA multiplayer games that require a profile logon do not support ECN yet (you will not be able to logon). Note that if supported, ECN can reduce latency in some games with ECN-capable routers in the presence of packet loss (dropped packets).

In the same Registry hive as the above two tweaks, you can also change the priority of Games, compared to other types of traffic. These tweaks only affect games that communicate with e Multimedia Class Scheduler Service (MMCSS). Below is a list of the settings and default/recommended values:

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games]
"Affinity"=dword:00000000  (DWORD, default: 0, recommended: 0. Both 0x00 and 0xFFFFFFFF indicate that processor affinity is not used)
"Background Only"="False"   (REG_SZ, default: "False", recommended: "False", possible values are True or False). Indicates whether this is a background task.
"Clock Rate"=dword:00002710  (DWORD, default: 2710, recommended: 2710). The maximum guaranteed clock rate the system uses if a thread joins disk task, in 100-nanosecond intervals.
"GPU Priority"=dword:00000008  (DWORD, default: 2, recommended: 8. range: 0-31). The GPU priority. Not used in Windows XP and 2003.
"Priority"=dword:00000002   (DWORD, default: 2, recommended: leave alone if using "Scheduling Category" below, set to 6 otherwise for gaming, possible values are 1-8). The task priority, ranging from 1(low) to 8(high). Note  for tasks with Scheduling Category of "High", this value is always treated as 2.
"Scheduling Category"="High"   (REG_SZ, default: "Medium", recommended: "High". possible values: Low, Medium, High)
"SFIO Priority"="High"  (REG_SZ, default: "Normal", recommended: "High") The scheduled I/O priority, possible values are Idle, Low, Normal, or High.

Disable Receive Segment Coalescing State (RSC)
(Editable with the TCP Optimizer) This is applicable to Windows 8/10/2012 Server, not available for earlier Windows versions.

Receive Segment Coalescing (RSC) allows the NIC to coalesce multiple TCP/IP packets that arrive within a single interrupt into a single larger packet (up to 64KB) so that the network stack has to process fewer headers, resulting in 10% to 30% reduction in I/O overhead depending on the workload, thereby improving throughput. Receive Segment Coalescing (RCS) is able to collect packets that are received during the same interrupt cycle and put them together so that they can be more efficiently delivered to the network stack. While this reduces CPU utilization and improves thorughput, it can also have a negative impact on latency. That is why we recommend you disable it where latency is more important than throughput.

Possible states: enabled, disabled, default. Default state: disabled
Recommended: disabled for pure gaming latency, enabled for better throughput.
To enable using netsh:

netsh int tcp set global rsc=disabled

To change using PowerShell cmdlets:

Disable-NetAdapterRsc -Name *  (use to disable RSC for all adapters)
Enable-NetAdapterRsc -Name *  (use to enables RSC for all adapters that support it)
Get-NetAdapterRsc -Name *       (use to view adapters that support RSC)

Notes: Only supported by some network adapters. May need "Checksum Offload" enabled as well to work.





Disable Large Send Offload (LSO)
(Editable with the TCP Optimizer) Windows 8/10/2012 Server, not available in earlier Windows versions

Large Send Offload lets the network adapter hardware to complete data segmentation, rather than the OS. Theoretically, this feature may improve transmission performance, and reduce CPU load. The problem with this setting is buggy implementation on many levels, including Network Adapter Drivers. Intel and Broadcom drivers are known to have this enabled by default, and may have many issues with it. In addition, in general any additional processing by the network adapter can introduce some latency which is exactly what we are trying to avoid when tweaking for gaming performance. We recommend disabling LSO at both the Network Adapter properties, and at the OS level with the setting below.

Default: adapter-dependent
Recommended: disable (both in network adapter properties and in the TCP/IP stack at the OS level)

Disable-NetAdapterLso -Name *    (disable LSO for all visible network adapters)
Enable-NetAdapterLso -Name *    (to enable LSO for both IPv4 and IPv6 on all network adapters, not recommended)
Get-NetAdapterLso -Name *  (get a list of network adapters that support LSO)

Notes: Default state is network adapter dependent. Needs Checksum Offload to be enabled to work.



Receive-Side Scaling State (RSS)
(Editable with the TCP Optimizer)
It is sometimes useful to disable RSS if you need to reduce CPU load. This is useful on systems with older/slower CPUs where games tax the processor up to 100% at times. This could be checked with "Task Monitor". Disabling RSS will only have an effect if your network adapter is capable/using RSS, and the CPU is being used up to 100%. Otherwise, you can leave it enabled.

To disable:

netsh int tcp set global rss=disabled





Advanced Concepts
Disable Coalescing: Some network adapters support advanced settings, such as DMA Coalescing, DCA Coalescing, Receive Segment Coalescing (RSC). In general, any type of packet or memory coalescing can reduce CPU utilization (also power consumption) and increases throughput, as it allows the network adapter to combine multiple packets, however, coalescing can also have negative impact on latency, especially with more aggressive settings. That is why it should be either disabled, or used very conservatively for gaming.  Any type of network adapter packet/memory coalescing allows the NIC to collect packets before it interacts with other hardware. This may increase network latency. For gaming, disable "DMA coalescing" and "Receive Side Coalescing State (RSC)", where applicable.

NetDMA: This setting needs to be supported by the NIC, BIOS, and CPU (Intel I/O Acceleration Technology - I/OAT). It allows the network adapter direct memory access (DMA), theoretically reducing CPU usage. It is ok to enable for OSes that support it (according to Microsoft it is no longer supported in Windows 8/10). Note that NetDMA is not compatible with TCP Chimney Offload (Chimney offload should be disabled for gaming anyway).

TCP Offloading: TCP Offloads can improve throughput in general, however, they've been plagued by driver issues in the past, and, they also put more strain on the network adapter. For pure gaming, disable any TCP Offloads, such as "Large Send Offload (LSO)", for example. For pure gaming and lowest possible latency, the only safe offload that should be left to the network adapter is "Checksum Offload".

Disable Interrupt Moderation: If your Network Adapter supports this setting, it should be disabled for the lowest possible latency (at the expense of a bit higher CPU utilization).

For some of those settings specific to your OS, see our tweaking articles. To disable at the network adapter, see our Network Adapter Optimization article.

Use adequate Send/Receive buffers: low send/receive buffers values conserve a bit of memory, however they can result in dropped packets and decreased performance if exhausted, so they shouldn't be set to values less than 256 in general. Higher-end NICS/systems can increase the values a bit to 512, or up to 1024.


Router Settings
Most broadband users have some type of NAT router that sits between them and the internet. There are some settings that may help your router better prioritize gaming traffic and improve gaming experience.

Enable upstream QoS in your router. It may be useful to enable upstream QoS at the router, if available, to prioritize the different types of traffic. Upstream QoS is important, because typically residential connections have much lower upstream cap, and when upstream bandwidth is all utilized, it can introduce some delay in the downstream traffic as well. Note this is only recommended for newer routers, where the router has ample computing power to handle the QoS overhead.

Enable WMM if using Wi-Fi. If you must use Wi-Fi, enable WMM, and try to avoid USB Wi-Fi adapters.

Use Open Source Firmware. Many NAT router models support open source firmware, such as dd-wrt, Tomato, etc. If your router's default firmware does not support advanced functionality that you may need (QoS, WMM, VLANs, etc.), you may be able to flash dd-wrt instead. It is not uncommon for open source firmware to make your connection more stable and reduce router overhead/delay.

Enable CTF (Cut Through Forwarding) - CTF is Broadcom proprietary NAT acceleration. It is a software module that allows routers based on their hardware/firmware to achieve near-gigabit performance and lower CPU utilization through various methods, including bypassing parts of the Linux stack. It is a great feature to use, however there is a catch - it is only available when not using certain other incompatible features that need the Linux functionality (like QoS). You'd have to pick which feature you prefer by testing. In our experience CTF performs better, as the lower CPU/memory utilization and minimal processing trumps QoS in both throughput and latency.

TCP/UDP Timeouts - tweaking the TCP/UDP timeouts can have a noticeable impact on your connection by freeing up resources for active connections. Some of the more advanced router firmwares (Tomato, ASUS Merlin, dd-wrt) have a number of tweakable timeout settings that we've already covered in our Wireless Network Speed Tweaks article linked below.

Note: If using dd-wrt, or on Wi-Fi, check our wireless network speed tweaks, some of the advanced router settings are applicable to wired connections as well.



General Online Gaming Recommendations
Use brand-name, wired Ethernet cards when possible - avoid Wi-Fi, especially with USB client adapters.
When tweaking TCP/IP (using our general tweaking articles), enable CTCP, enable DCA, and try disabling most "TCP Offloading" settings, with the exception of "Checksum Offload" in both the OS and the Network Adapter Properties.
Disable "Flow Control" and "Interrupt Moderation" in your Network adapter properties
Disable TCP/IPv6 in Network adapter properties if not using IPv6
Reduce the number of background processes, enable QoS at your router and give priority to your traffic.
Test your latency to game servers using "tracert" in Command Prompt (or PowerShell).
Disable search indexing on your SSD/hard drive (right-click on drive in Explorer -> choose "Properties" -> untick "Allow files on this drive to have contents indexed..." and wait a few minutes, ignore errors for system-protected files)
Close unnecessary programs running on your network, you can close the processes in task manager (ctrl+shift+escape). P2P applications such as utorrent and skype open many sockets purely for passive listening and eat up a lot of your available bandwidth. Programs that check for software updates, eg google updates, adobe update, etc. can cause ping spikes.


Intel Recommended Network Adapter Settings


Optimized for quick response and low latency (Gaming):

Minimize or disable Interrupt Moderation Rate
Disable Offload TCP Segmentation
Increase Transmit Descriptors
Increase Receive Descriptors
Increase RSS Queues
Optimized for throughput:

Enable Jumbo Frames
Increase Transmit Descriptors
Increase Receive Descriptors
For low CPU utilization:

Maximize Interrupt Moderation Rate
Keep Receive Descriptors at default
Avoid setting large Receive Descriptors
Decrease RSS Queues
Decrease the Max number of RSS CPUs in Hyper-V environments

set-NetTCPConnection -AutomaticUseCustom true
(acceptable parameters are [true|false], doesn't seem to work in Windows 8.1 ?)

Other Useful TCP/IP connection related PowerShell cmdlets:
Get-NetOffloadGlobalSetting   (view current TCP Offload settings)
Get-Help Get-NetTCPSetting -detailed  (help on NetTCPSetting)
Get-NetTCPConnection   (see active connections)
(Get-NetTransportFilter | Where DestinationPrefix -eq '*' | Get-NetTCPSetting)  -- view current template settings
(Get-NetTransportFilter | Where DestinationPrefix -eq '*' | Get-NetTCPSetting).CongestionProvider  -- view only "CongestionProvider" setting in currently used template




#Disable 57-bits 5-level paging, also known as "Linear Address 57". Only 100% effective on 10th gen Intel. 256 TB of virtual memory per-disk is way much more than enough anyway.
bcdedit /set linearaddress57 OptOut

bcdedit /set increaseuserva 268435328



Avoid the use of uncontiguous portions of low-memory from the OS. Boosts memory performance and improves microstuttering at least 80% of the cases. Also fixes the command buffer stutter after disabling 5-level paging on 10th gen Intel. Causes system freeze on unstable memory sticks.
bcdedit /set firstmegabytepolicy UseAll

bcdedit /set avoidlowmemory 0x8000000

bcdedit /set nolowmem Yes



Disable some of the kernel memory mitigations. Causes boot crash/loops if Intel SGX is enforced and not set to "Application Controlled" or "Off" in your Firmware. Gamers don't use SGX under any possible circumstance.
bcdedit /set allowedinmemorysettings 0x0

bcdedit /set isolatedcontext No



Disable DMA memory protection and cores isolation ("virtualization-based protection").
bcdedit /set vsmlaunchtype Off

bcdedit /set vm No

HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\FVE

DisableExternalDMAUnderLock -> 0

HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard

EnableVirtualizationBasedSecurity -> 0

HVCIMATRequired -> 0



Disable Process and Kernel Mitigations.
powershell "ForEach($v in (Get-Command -Name \"Set-ProcessMitigation\").Parameters[\"Disable\"].Attributes.ValidValues){Set-ProcessMitigation -System -Disable $v.ToString() -ErrorAction SilentlyContinue}"

powershell "Remove-Item -Path \"HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\*\" -Recurse -ErrorAction SilentlyContinue"

HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\kernel

DisableExceptionChainValidation -> 1

KernelSEHOPEnabled -> 0

HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management

EnableCfg -> 0



Use realtime priority for csrss.exe.
HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\csrss.exe\PerfOptions

CpuPriorityClass -> 4

IoPriority -> 3



Disable RAM compression.
powershell "Disable-MMAgent -MemoryCompression"



Enable Kernel-Managed Memory and disable Meltdown/Spectre patches.
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management

FeatureSettings -> 1

FeatureSettingsOverride -> 3

FeatureSettingsOverrideMask -> 3



Disallow drivers to get paged into virtual memory.
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management

DisablePagingExecutive -> 1



Use big system memory caching to improve microstuttering.
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management

LargeSystemCache -> 1



Use big pagefile to improve microstuttering (reboot or system might become unstable and BSoD).
wmic computersystem where name="%computername%" set AutomaticManagedPagefile=False

wmic pagefileset where name="C:\\pagefile.sys" set InitialSize=32768,MaximumSize=32768



Disable additional NTFS/ReFS mitigations.
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager

ProtectionMode -> 0



Enable X2Apic and enable Memory Mapping for PCI-E devices.
(for best results, further more enable MSI mode for all devices using MSI utility or manually)

bcdedit /set x2apicpolicy Enable

bcdedit /set configaccesspolicy Default

bcdedit /set MSI Default

bcdedit /set usephysicaldestination No

bcdedit /set usefirmwarepcisettings No



Disable synthetic TSC tick and use accurate RTC instead (not to be confused with useplatformclock). Enable HPET in BIOS for best results. Only for untweaked systems (TSC recommended instead on tweaked systems).
bcdedit /deletevalue useplatformclock

bcdedit /deletevalue disabledynamictick

bcdedit /set useplatformtick Yes

bcdedit /set tscsyncpolicy Enhanced



Set a reliable 1 ms (minimum) timestamp. Only for untweaked systems (disabling it with 0 is recommended on tweaked systems).
HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Reliability

TimeStampInterval -> 1



Force contiguous memory allocation in the DirectX Graphics Kernel.
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers

DpiMapIommuContiguous -> 1



Force contiguous memory allocation in the NVIDIA driver.
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000

PreferSystemMemoryContiguous -> 1

(0000 may vary depending on the GPU number)



Enforce Security-Only Telemetry (disable other kinds of Telemetry).
HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DataCollection

AllowTelemetry -> 0



Disable Application Telemetry.
HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\AppCompat

AITEnable -> 0



Disable Windows Error Reporting.
HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting

Disabled -> 1



Enable Experimental Autotuning and NEWRENO congestion provider.
netsh int tcp set global autotuning=experimental

netsh int tcp set supp internet congestionprovider=newreno

HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\QoS

Tcp Autotuning Level -> Experimental

Application DSCP Marking Request -> Allowed



Enable WH send and WH receive.
powershell "Get-NetAdapter -IncludeHidden | Set-NetIPInterface -WeakHostSend Enabled -WeakHostReceive Enabled -ErrorAction SilentlyContinue"



Enable UDP offloading.
netsh int udp set global uro=enabled



Enable Teredo and 6to4 (Win 2004 Xbox LIVE fix).
netsh int teredo set state natawareclient

netsh int 6to4 set state state=enabled



Disable local firewall (you're behind a NAT / router dude).
netsh advfirewall set allprofiles state off

There seems to be a bug with Windows Firewall and IPsec when disabling the local firewall. This causes IPsec to ignore all the advanced tunneling settings that have been set in the source program / connector, and this causes IPSec servers to refuse the connection in some cases. To revert:

netsh advfirewall set allprofiles state on



Enable Winsock Send Autotuning (dynamic send-buffer)
netsh winsock set autotuning on



Decrease mouse and keyboard buffer sizes.
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\mouclass\Parameters

MouseDataQueueSize -> 16 decimal

HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\kbdclass\Parameters

KeyboardDataQueueSize -> 16 decimal



Tell Windows to stop tolerating high DPC/ISR latencies.
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power

ExitLatency -> 1

ExitLatencyCheckEnabled -> 1

Latency -> 1

LatencyToleranceDefault -> 1

LatencyToleranceFSVP -> 1

LatencyTolerancePerfOverride -> 1

LatencyToleranceScreenOffIR -> 1

LatencyToleranceVSyncEnabled -> 1

RtlCapabilityCheckLatency -> 1

HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power

DefaultD3TransitionLatencyActivelyUsed -> 1

DefaultD3TransitionLatencyIdleLongTime -> 1

DefaultD3TransitionLatencyIdleMonitorOff -> 1

DefaultD3TransitionLatencyIdleNoContext -> 1

DefaultD3TransitionLatencyIdleShortTime -> 1

DefaultD3TransitionLatencyIdleVeryLongTime -> 1

DefaultLatencyToleranceIdle0 -> 1

DefaultLatencyToleranceIdle0MonitorOff -> 1

DefaultLatencyToleranceIdle1 -> 1

DefaultLatencyToleranceIdle1MonitorOff -> 1

DefaultLatencyToleranceMemory -> 1

DefaultLatencyToleranceNoContext -> 1

DefaultLatencyToleranceNoContextMonitorOff -> 1

DefaultLatencyToleranceOther -> 1

DefaultLatencyToleranceTimerPeriod -> 1

DefaultMemoryRefreshLatencyToleranceActivelyUsed -> 1

DefaultMemoryRefreshLatencyToleranceMonitorOff -> 1

DefaultMemoryRefreshLatencyToleranceNoContext -> 1

Latency -> 1

MaxIAverageGraphicsLatencyInOneBucket -> 1

MiracastPerfTrackGraphicsLatency -> 1

MonitorLatencyTolerance -> 1

MonitorRefreshLatencyTolerance -> 1

TransitionLatency -> 1

HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000

(NVIDIA GPU)
D3PCLatency -> 1

F1TransitionLatency -> 1

LOWLATENCY -> 1

Node3DLowLatency -> 1

PciLatencyTimerControl -> 32 decimal

RMDeepL1EntryLatencyUsec -> 1

RmGspcMaxFtuS -> 1

RmGspcMinFtuS -> 1

RmGspcPerioduS -> 1

RMLpwrEiIdleThresholdUs -> 1

RMLpwrGrIdleThresholdUs -> 1

RMLpwrGrRgIdleThresholdUs -> 1

RMLpwrMsIdleThresholdUs -> 1

VRDirectFlipDPCDelayUs -> 1

VRDirectFlipTimingMarginUs -> 1

VRDirectJITFlipMsHybridFlipDelayUs -> 1

vrrCursorMarginUs -> 1

vrrDeflickerMarginUs -> 1

vrrDeflickerMaxUs -> 1

(AMD GPU)
LTRSnoopL1Latency -> 1

LTRSnoopL0Latency -> 1

LTRNoSnoopL1Latency -> 1

LTRMaxNoSnoopLatency -> 1

KMD_RpmComputeLatency -> 1

DalUrgentLatencyNs -> 1

memClockSwitchLatency -> 1

PP_RTPMComputeF1Latency -> 1

PP_DGBMMMaxTransitionLatencyUvd -> 1

PP_DGBPMMaxTransitionLatencyGfx -> 1

DalNBLatencyForUnderFlow -> 1

DalDramClockChangeLatencyNs -> 1

BGM_LTRSnoopL1Latency -> 1

BGM_LTRSnoopL0Latency -> 1

BGM_LTRNoSnoopL1Latency -> 1

BGM_LTRNoSnoopL0Latency -> 1

BGM_LTRMaxSnoopLatencyValue -> 1

BGM_LTRMaxNoSnoopLatencyValue -> 1



LOGGING OPTIONALS
Enable detailed startup/shutdown messages.
HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System

VerboseStatus -> 1



ANTIVIRUS OPTIONALS
Disable Windows Defender Antivirus
bcdedit /set disableelamdrivers Yes

HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender

DisableAntiSpyware -> 1

DisableRoutinelyTakingAction -> 1

ServiceKeepAlive -> 0

HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection

DisableBehaviorMonitoring -> 1

DisableIOAVProtection -> 1

DisableOnAccessProtection -> 1

DisableRealtimeMonitoring -> 1

HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Reporting

DisableEnhancedNotifications -> 1
