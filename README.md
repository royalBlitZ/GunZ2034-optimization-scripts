# iGunZ-optimization-scripts





Disable 57-bits 5-level paging, also known as "Linear Address 57". Only 100% effective on 10th gen Intel. 256 TB of virtual memory per-disk is way much more than enough anyway.
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
