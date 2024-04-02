# AV_EDR_EPP_Notes

This project aims to document some of the AV/EDR (and perhaps more) encounters I've had in my red teaming career. I'll be noting observations and countermeasures I've observed or devised. Hopefully, this can be helpful to other red team operators (or maybe even malware developers, haha).

------

Within this project, I plan to document some basic information such as:

- Windows API Hook List
- Process information, registry information, driver services
- Detection blind spots
- Registered callback information

If you have any better suggestions, you can submit them to me through issues, and I will work on this in my spare time.

------

SentinelOne

Test environment: Windows Server 2019, SentinelOne 23.2.3.358 (now updated to 23.3.3.264)

Windows API Hook List (Inline) (may not be complete)

```
[*] Dll Name:   ntdll.dll
        [*] LdrLoadDll HAS been hooked!
        [*] RtlAddVectoredExceptionHandler HAS been hooked!
        [*] NtCreateThreadEx HAS been hooked!
        [*] NtCreateUserProcess HAS been hooked!
        [*] NtDuplicateObject HAS been hooked!
        [*] NtFreeVirtualMemory HAS been hooked!
        [*] NtGetTickCount HAS been hooked!
        [*] NtLoadDriver HAS been hooked!
        [*] NtMapUserPhysicalPages HAS been hooked!
        [*] NtMapViewOfSection HAS been hooked!
        [*] NtOpenProcess HAS been hooked!
        [*] NtQuerySystemInformation HAS been hooked!
        [*] NtQuerySystemInformationEx HAS been hooked!
        [*] NtQuerySystemTime HAS been hooked!
        [*] NtQueueApcThread HAS been hooked!
        [*] NtQueueApcThreadEx HAS been hooked!
        [*] NtReadVirtualMemory HAS been hooked!
        [*] NtResumeThread HAS been hooked!
        [*] NtSetContextThread HAS been hooked!
        [*] NtSetInformationProcess HAS been hooked!
        [*] NtSetInformationThread HAS been hooked!
        [*] NtTerminateProcess HAS been hooked!
        [*] NtUnmapViewOfSection HAS been hooked!
        [*] NtWriteVirtualMemory HAS been hooked!
        [*] NtdllDefWindowProc_A HAS been hooked!
        [*] NtdllDefWindowProc_W HAS been hooked!
        [*] NtdllDialogWndProc_A HAS been hooked!
        [*] NtdllDialogWndProc_W HAS been hooked!
        [*] ZwCreateThreadEx HAS been hooked!
        [*] ZwCreateUserProcess HAS been hooked!
        [*] ZwDuplicateObject HAS been hooked!
        [*] ZwFreeVirtualMemory HAS been hooked!
        [*] ZwLoadDriver HAS been hooked!
        [*] ZwMapUserPhysicalPages HAS been hooked!
        [*] ZwMapViewOfSection HAS been hooked!
        [*] ZwOpenProcess HAS been hooked!
        [*] ZwQuerySystemInformation HAS been hooked!
        [*] ZwQuerySystemInformationEx HAS been hooked!
        [*] ZwQuerySystemTime HAS been hooked!
        [*] ZwQueueApcThread HAS been hooked!
        [*] ZwQueueApcThreadEx HAS been hooked!
        [*] ZwReadVirtualMemory HAS been hooked!
        [*] ZwResumeThread HAS been hooked!
        [*] ZwSetContextThread HAS been hooked!
        [*] ZwSetInformationProcess HAS been hooked!
        [*] ZwSetInformationThread HAS been hooked!
        [*] ZwTerminateProcess HAS been hooked!
        [*] ZwUnmapViewOfSection HAS been hooked!
        [*] ZwWriteVirtualMemory HAS been hooked!
        [*] KiUserApcDispatcher HAS been hooked!

[*] Dll Name:   kernel32.dll
        [*] Wow64SetThreadContext HAS been hooked!


[*] Dll Name:   KernelBase.dll    
        [*] CreateFileW HAS been hooked!            
        [*] CloseHandle HAS been hooked!            
        [*] WriteFile HAS been hooked!            
        [*] CreateProcessInternalW HAS been hooked!           
        [*] WriteConsoleW HAS been hooked!            
        [*] CopyFileExW HAS been hooked!            
        [*] PrivCopyFileExW HAS been hooked!            
        [*] LoadLibraryA HAS been hooked!            
        [*] CopyFile2 HAS been hooked!            
        [*] UnhandledExceptionFilter HAS been hooked!


[*] Dll Name:   advapi32.dll 
        [*] LsaLookupSids HAS been hooked!


[*] Dll Name:   combase.dll 
        [*] CoGetInstanceFromIStorage HAS been hooked!

[*] Dll Name:   crypt32.dll     
        [*] CryptUnprotectData HAS been hooked!


[*] Dll Name:   ole32.dll     
        [*] CoGetObject HAS been hooked!

 [*] Dll Name:   samcli.dll    
        [*] NetUserModalsGet HAS been hooked!
        [*] NetUserGetLocalGroups HAS been hooked!            
        [*] NetLocalGroupGetMembers HAS been hooked!            
        [*] NetUserGetInfo HAS been hooked!            
        [*] NetUserEnum HAS been hooked!           
        [*] NetGroupGetUsers HAS been hooked!           
        [*] NetUserAdd HAS been hooked!            
        [*] NetUserGetGroups HAS been hooked!            
        [*] NetUserSetInfo HAS been hooked!


 [*] Dll Name:   samlib.dll    
        [*] SamGetMembersInAlias HAS been hooked!            
        [*] SamOpenAlias HAS been hooked!           
        [*] SamGetAliasMembership HAS been hooked!           
        [*] SamLookupNamesInDomain HAS been hooked!           
        [*] SamQueryInformationUser HAS been hooked!            
        [*] SamConnect HAS been hooked!            
        [*] SamOpenDomain HAS been hooked!            
        [*] SamCloseHandle HAS been hooked!            
        [*] SamQueryInformationAlias HAS been hooked!


[*] Dll Name:   sechost.dll             
        [*] LsaLookupSids HAS been hooked!            
        [*] LsaOpenPolicy HAS been hooked!


[*] Dll Name:   shell32.dll             
        [*] Shell_NotifyIconW HAS been hooked!


[*] Dll Name:   srvcli.dll             
        [*] NetShareEnum HAS been hooked!            
        [*] NetServerGetInfo HAS been hooked!            
        [*] NetSessionEnum HAS been hooked!


[*] Dll Name:   sspicli.dll             
        [*] LsaCallAuthenticationPackage HAS been hooked!            
        [*] LsaFreeReturnBuffer HAS been hooked!            
        [*] InitializeSecurityContextW HAS been hooked!


[*] Dll Name:   user32.dll             
        [*] CreateWindowExW HAS been hooked!            
        [*] SetWindowLongPtrW HAS been hooked!            
        [*] SetWindowLongW HAS been hooked!            
        [*] PeekMessageW HAS been hooked!            
        [*] PeekMessageA HAS been hooked!            
        [*] SystemParametersInfoW HAS been hooked!            
        [*] GetKeyState HAS been hooked!            
        [*] SystemParametersInfoA HAS been hooked!            
        [*] GetMessageW HAS been hooked!            
        [*] GetAsyncKeyState HAS been hooked!            
        [*] GetMessageA HAS been hooked!            
        [*] SetWindowsHookExW HAS been hooked!            
        [*] SetWindowLongA HAS been hooked!            
        [*] CreateWindowExA HAS been hooked!            
        [*] ExitWindowsEx HAS been hooked!            
        [*] SetWindowLongPtrA HAS been hooked!            
        [*] SetWindowsHookExA HAS been hooked!


[*] Dll Name:   win32u.dll             
        [*] NtUserSetProp HAS been hooked!            
        [*] NtUserShowWindow HAS been hooked!            
        [*] NtUserGetKeyboardState HAS been hooked!            
        [*] NtUserAttachThreadInput HAS been hooked!            
        [*] NtUserRegisterRawInputDevices HAS been hooked!

Total: 114 hooks
```

Windows API Hook List (EAT) (may not be complete)

```
KERNEL32.DLL!ord 1629
KERNEL32.DLL!ord 1630
KERNEL32.DLL!ord 1631
KERNEL32.DLL!ord 1632
KERNEL32.DLL!ord_1633
KERNEL32.DLL!ord 1634
KERNEL32.DLL!ord 1635
KERNEL32.DLL!ord 1636
KERNEL32.DLL!ord 1637
KERNEL32.DLL!ord_1638
KERNEL32.DLL!ord 1639
KERNEL32.DLL!ord 1640
KERNEL32.DLL!ord 1641
KERNEL32.DLL!ord_1642
KERNEL32.DLL!ord 1643
KERNEL32.DLL!ord 1644
KERNEL32.DLL!ord 1645
KERNEL32.DLL!ord_1646
```

process information

```
SentinelUI.exe
SentinelAgent.exe
SentinelStaticEngineScanner.exe
SentinelStaticEngine.exe
SentinelServiceHost.exe
```

Registry/Service Information

```
HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
HKEY_CLASSES_ROOT\Drive\shell\SentinelOneScan
Server: LogProcessorService
Server: SentinelAgent
Server: SentinelHelprService
Server: SentinelStaticEngine
```

driver information

```
SentinelDeviceControl SentinelDeviceControl.sys
SentinelELAM SentinelELAM.sys
SentinelMonitor SentinelMonitor.sys
```

Scheduled Tasks

```
\Sentinel\AutoRepair_23.3.3.264 (23.3.3.264 is version)
Todo "C:\Program Files\SentinelOne\Sentinel Agent 23.3.3.264\uninstall.exe"
Arg /os_upgrade /q /p {xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx}
```

<img width="1075" alt="SentinelOne" src="https://github.com/kyxiaxiang/AV_EDR_EPP_Notes/assets/102843981/06979933-6f7e-4051-a526-59d7b848f5e5">


------
#CrowdStrike

Only Check ntdll Hook~

CrowdStrike Version 7.11.*

Windows API Hook List (Inline) (may not be complete)

```
[*] Dll Name:   ntdll.dll
        [*] NtAllocateVirtualMemory HAS been hooked!
        [*] NtAllocateVirtualMemoryEx HAS been hooked!
        [*] NtCreateMutant HAS been hooked!
        [*] NtDeviceIoControlFile HAS been hooked!
        [*] NtGetContextThread HAS been hooked!
        [*] NtGetTickCount HAS been hooked!
        [*] NtMapViewOfSection HAS been hooked!
        [*] NtMapViewOfSectionEx HAS been hooked!
        [*] NtProtectVirtualMemory HAS been hooked!
        [*] NtQueryInformationThread HAS been hooked!
        [*] NtQuerySystemTime HAS been hooked!
        [*] NtQueueApcThread HAS been hooked!
        [*] NtQueueApcThreadEx HAS been hooked!
        [*] NtQueueApcThreadEx2 HAS been hooked!
        [*] NtReadVirtualMemory HAS been hooked!
        [*] NtResumeThread HAS been hooked!
        [*] NtSetContextThread HAS been hooked!
        [*] NtSetInformationProcess HAS been hooked!
        [*] NtSetInformationThread HAS been hooked!
        [*] NtSuspendThread HAS been hooked!
        [*] NtUnmapViewOfSection HAS been hooked!
        [*] NtUnmapViewOfSectionEx HAS been hooked!
        [*] NtWriteVirtualMemory HAS been hooked!
        [*] NtdllDefWindowProc_A HAS been hooked!
        [*] NtdllDefWindowProc_W HAS been hooked!
        [*] NtdllDialogWndProc_A HAS been hooked!
        [*] NtdllDialogWndProc_W HAS been hooked!
        [*] ZwAllocateVirtualMemory HAS been hooked!
        [*] ZwAllocateVirtualMemoryEx HAS been hooked!
        [*] ZwCreateMutant HAS been hooked!
        [*] ZwDeviceIoControlFile HAS been hooked!
        [*] ZwGetContextThread HAS been hooked!
        [*] ZwMapViewOfSection HAS been hooked!
        [*] ZwMapViewOfSectionEx HAS been hooked!
        [*] ZwProtectVirtualMemory HAS been hooked!
        [*] ZwQueryInformationThread HAS been hooked!
        [*] ZwQuerySystemTime HAS been hooked!
        [*] ZwQueueApcThread HAS been hooked!
        [*] ZwQueueApcThreadEx HAS been hooked!
        [*] ZwQueueApcThreadEx2 HAS been hooked!
        [*] ZwReadVirtualMemory HAS been hooked!
        [*] ZwResumeThread HAS been hooked!
        [*] ZwSetContextThread HAS been hooked!
        [*] ZwSetInformationProcess HAS been hooked!
        [*] ZwSetInformationThread HAS been hooked!
        [*] ZwSuspendThread HAS been hooked!
        [*] ZwUnmapViewOfSection HAS been hooked!
        [*] ZwUnmapViewOfSectionEx HAS been hooked!
        [*] ZwWriteVirtualMemory HAS been hooked!
        
Total: 49 hooks
```

process information

```
CsSystemTray_*(version).exe
CSFalconService.exe
CSFalconContainer.exe
```

driver information

```
CSDeviceControl.sys
CSFirmwareAnalysis.sys
```
Bypass CrowdStrike && run Mimikatz (just for fun *^_^*)

![image](https://github.com/kyxiaxiang/AV_EDR_EPP_Notes/assets/102843981/360c4a5a-857e-4a5b-9f20-c1812c583363)
