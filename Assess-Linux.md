
# Summary

When the IR team is alerted to suspicious activity on a Windows server, the steps in this document should be performed to make an initial assessment as to whether or not that system has been compromised.


# Assets Summary

Collect information for both fully managed, less managed and unmanaged instances.


# Gather Background/Contextual Information

Contact the owner of the system to determine: 

1. What is the system normally used for (e.g. deployment, customer demos, web hosting, third-party application hosting, etc.)?
2. Has the owner done anything unusual around the time of the incident?
3. Can the owner share available access credentials?
4. Taking a point-in-time snapshot PRIOR to doing any changes is recommended. A snapshot preserves the state of the machine for deep forensic analysis if it’s indeed compromised.


# Examine Local and Centralized Logs

1. The Security audit log is an essential log. Administrators can review this data locally using Event Viewer(_eventvwr.msc_) under Microsoft Windows Log => Security.

2. [Sysmon](https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon) (from Sysinternal) captures rich details on the server.

3. PowerShell can be used to exploit a system with little noise, enabling and collecting PowerShell execution logs is important to gain visibility and detect growing threats in this area.

4. [Windows Management Instrumentation](https://docs.microsoft.com/en-us/windows/desktop/wmisdk/wmi-start-page)(WMI) may used by attackers to carry out objectives, such as system reconnaissance, remote code execution, persistence, lateral movement, covert data storage, and VM detection. 

5. [Windows Scheduler Task](https://docs.microsoft.com/en-us/windows/win32/taskschd/task-scheduler-start-page) may use task scheduling to execute programs at system startup or on a scheduled basis for persistence, to conduct remote Execution as part of Lateral Movement, to gain SYSTEM privileges, or to run a process under the context of a specified account. 

6. Consider [deploying OSquery](https://osquery.readthedocs.io/en/stable/installation/install-windows/) wherever possible, it’s a powerful tool to collect info and investigate remotely. \

If any anomalies are found, record them and try to correlate these findings where possible.
This information could help investigators gain additional context about the alerting message.


# Currently Logged-On Users

Enumerate users who are currently logged on to the system using Microsoft Windows built-in CLI  to display information on local and remote user sessions:

`C:\>query user`

Alternatively, the Microsoft internal CLI tool [LogonSessions](https://docs.microsoft.com/en-us/sysinternals/downloads/logonsessions) lists not only the currently active sessions, but other useful information is included, such as processes running in each session:

`C:\>logonsessions -p`

Run `lusrmgr.msc` to check all user accounts on a local machine:



*   Execute a `Select Users` statement to look for any new, suspicious accounts that are not supposed to be on the machine and active Guest accounts. \
Alternatively, use Osquery (if available) to execute this query:  \
`SELECT uid,username,shell,directory FROM users WHERE type = ‘local’;`
*   Select Groups, then Administrators, look for accounts that should not have Administrator privileges. \
Alternatively, use Osquery query:  \
`SELECT users.uid,users.username,users.shell FROM user_groups INNER JOIN users ON user_groups.uid = users.uid WHERE user_groups.gid = 544;`

When only terminal access is available, consider the following command line tools:



*   `net user` – displays all user accounts on a local machine. 
*   `net localgroup administrators` – display all local administrator user accounts.

If any IPs are present in the logs, but cannot be explained, the system should be considered compromised.


# Previously Logged-On Users

The Microsoft Windows Security event log keeps records of which users have logged in:

Event ID 4624 Logon Event



*   Logon event type: Local account vs. Domain account can be distinguished by examining the “Account Domain” field.
    *   In an AD managed domain, consider a local account login as a suspicious event. Conversely, in a non-AD managed domain, consider a domain account login as a suspicious event and investigate further.
    *   In an RDP dominant management environment, first filter RDP logon by Logon Type field=10 for Terminal Services, Remote Desktop or Remote Assistance related logon & logoff events.

Event ID 4634, 4647 Logoff Event or 4608 System boot Event



*   Correlate with 4624 Logon event by Logon-ID field, can identify the beginning and ending of a logon session.
*   Search for many failed logon events followed by successful 4624 logon event.

Event ID 4672 Special privileges assigned to new logon



*   Any "super user" account logons

Also, check other remote access methods available, such as VNC, SSH, or FTP, and perform the same analysis on the access logs for those services. Check [Look for Various Ways of Remote Execution](#Look-for-Various-Ways-of-Remote-Execution), [Remote Desktop Access](#Remote-Desktop-Access), and [Network Share Access](#Network-Share-Access) sections for possible signs of remote access & execution. 

Note: below is a screenshot taken from Microsoft Windows built-in Event Viewer application, it can be used to view, filter, export logs stored on the local system.

If any user sessions are present in the logs, but cannot be explained, the system should be considered compromised.


# Review OS Command History

Examine execution history across all accounts on the system by searching Security audit logs related to process events:



*   4688 A new process has been created \
Filter out LogonID=0x3e7 for events triggered by the Microsoft Windows OS itself. \
Use “LogonID” to correlate backwards to the logon event (4624) \
Use “Creator Process ID” to look for parent process in a preceding 4688 event
*   4689 A process has exited

Search *Windows Prefetch* folder `C:\Windows\Prefetch`, because it records programs that have been run on a system, even after the program has since been deleted.

When *Prefetch* is disabled, the *ShimCache* becomes a more valuable artifact. The *ShimCache* SYSTEM registry hive stores information about all executed binaries that have been executed in the system since it was rebooted, and it tracks:
*   File Full Path
*   File Size
*   $Standard_Information (SI) Last Modified time
*   *Shimcache* Last Updated time
*   Process Execution Flag

Data can be extracted using [ShimCacheParser.py](https://github.com/mandiant/ShimCacheParser ).

The *Amcache.hve* file is also an important artifact to record the traces of anti-forensic programs, portable programs, and external storage devices. It tracks:



*   Execution path
*   First executed time
*   Deleted time
*   First installation

The *Amcache.hve* content can be analyzed using Amcache plugin [RegRipper](https://github.com/keydet89/RegRipper2.8).

After program execution information is collected, look for suspicious executables in the following categories:



*   Mislocated folder \
`C:\Windows\tasks.exe` (instead of `C:\Windows\System32`)
*   Typosquatting  \
`C:\Windows\System32\taskse.exe` (instead of `tasks.exe`)
*   Executables located in:
    *   *%Temp%* folder
    *   Download folder
    *   Public folders
    *   Folder with random characters
    *   Registry location with random characters
*   Uncommon association with the parent process, such as:
    *   `svchost.exe` as parent process of interactive applications (Malware infection)
    *   Firefox launches an executable (Malicious plug-in or vulnerability in browser)
    *   Office executable(e.g. `Excel.exe, Word.exe`) launches an executable such as `cmd.exe`, `powershell.exe `(Malicious Office micro)
    *   `mshta.exe` launches Javascript or VBscript from registry location (HTA abuse behavior)
    *   `svchost.exe` launches Script Event Consumer WMI “`scrcons.exe`” (WMI backdoor)
    *   `powershell.exe` launches `regsvr32.exe` to load data from remote 
*   Executables with names associated with well-known attacker tools, such as  “empire” or “mimikatz”
*   Check command lines for suspicious arguments, for example:
    *   “Process Command Line” field has “`powershell.exe`” in it, scan for encoded payload.
    *   `powershell.exe` with the “DownloadString” call
    *   `regsvr32.exe` is called to register and run COM data from remote location (Squiblydoo)
    *   `cmd.exe /Q /c` follow with `powershell.exe`, `wmic.exe`
    *   `wmic.exe` and .XSL file from local or remote location.
*   Programs that may indicate an attempt to hide info, such as *Eraser* and *CCleaner*
*   New System services creation and starting:
    *   Commands: `sc create` , `sc start`
    *   Registry location: HKLM/SYSTEM/CurrentControlSet/Services
    *   Security event log IDs: 7045(create), 7000, 7009, 7035, 7036
*   Check to see if trusted processes make suspicious connection as a result of malware injection:
*   Trusted executables such as `wmic, regsvr32, powershell` etc. connect to suspicious IPs. E.g. `msiexec.exe` connects to a Cryptomining IP.
*   WMI ActiveScriptEventConsumer `scrcons.exe` runs malicious scripts.

If process name seems suspicious, Google the executable name and its common location.

To confirm a suspicious executable, [VirtusTotal](https://www.virustotal.com/gui/home/upload) can be helpful to scan the binary in a sandbox and identify by the hash of executable for known good/bad binaries.

When a suspicious binary or process is identified, further assess the damage by examining Security events between ID 4688 and ID 4689 in chronological order.

If any unusual commands or processes or binaries are found which cannot be explained by the real owner of the system which executed them, the system should be considered compromised.


# Resource Utilization

Examine CPU, network, memory, and other resource utilization on the system:



*   Resource Monitor offers a quick way to review processes performance in relationship to CPU, memory, network and disk.
*   [Process Explorer](https://docs.microsoft.com/en-us/sysinternals/downloads/process-explorer) provides enriched process info as well as resource utilization data.

Consider techniques described in [Examine Running Processes](#Examine-Running-Processes) to examine processes associated with high resource utilization.

If malware is present in the system, or suspicious behavior cannot be explained by the owner of the system, the system should be considered compromised.

# Examine Running Processes

There are several ways to fetch running processes on a live system:



1. Use `wmic process list full` to list running process with much more context information
2. Use `tasklist.exe` or [Get-Process](https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.management/get-process?view=powershell-6), if powershell is installed. These two output similar information, for example:
    1. `tasklist /svc` shows which services are running inside of each process.
    2. `tasklist /m` shows every DLL currently loaded into all running processes.
3. Download and run [Process Explorer](https://docs.microsoft.com/en-us/sysinternals/downloads/process-explorer)
4. A quick way to bring up *Task Manager* by typing `taskmgr.exe` directly in a terminal window, switch to “Processes” tab and toggle “Show processes from all users”, or press  the “Ctrl+Shift+Esc” keyboard combination.
5. Run Osquery when available, following query displays all processes sorted by time spent in Userspace, Kernel and Private memory:

    `SELECT pid,name,user_time,system_time,resident_size FROM processes ORDER BY user_time ORDER BY system_time ORDER BY resident_size;`


If the OS is in inactive state, look at the Security audit logs and search for Event ID 4688 (A new process has been created) without Event ID 4689(process exit event) in backward chronological order.

Search for malicious processes, they often disguised using well-known system process name. 

Check standard Microsoft Windows processes, such as `CSRSS.EXE, WININIT.EXE, SERVICES.EXE, LSASS.EXE, EXPLORER.EXE`, validate processes’ location, account, identity, number of occurance and parent/child process relationship according to [this document](https://www.andreafortuna.org/2017/06/15/standard-windows-processes-a-brief-reference/).

Be cautious when tracing and analyzing inter-process behavior, malicious actors may disguise process launching via Task Scheduler, WMI, DLL injection, Registry Run keys, in which circumstances a new process won’t reveal as a child process, for example: Process A(run as user X) calls `wmic.exe`, which launches `svchost.exe` to launch Process B (run as user Y) on the same or remote host.

Look for suspicious processes, DLLs further using steps described in [Review the command history](#Review-the-command-history).

To summary, correlating process events would generally require:
*   Process tree
*   Network activity behind the process
*   User behind the process
*   File activity behind the process
*   DLL loads
*   Module hashes
*   Registry access activity behind the process
*   Inter-process activity

If suspicious binaries are identified as malicious and cannot be explained by the owner of the system, the system should be considered compromised.


# Examine Listening Network Services

Enumerate network services listening on the system using [TCPView](https://docs.microsoft.com/en-us/sysinternals/downloads/tcpview) or running `netstat -anob` command line tool, either will list network connections made by local software and current network communication state with other hosts.

The output from `netstat` also includes open ports and associated processes, look for any ports and processes that are unusual, one unusual example is `explorer.exe` listening for incoming connections. 

Review Security Event logs related to Windows Firewall rule change event in the following events, look for non-compliant and unexpected rules added.

Also, review Windows Firewall specific event logs, and identify suspicious network connections in relationship with the process/program in the following events:



*   5156 The Windows Filtering Platform has allowed a connection \
Examine the process making the outbound connection to destination IP:port and determine if this connection makes sense or is suspicious.
*   5157 The Windows Filtering Platform has blocked a connection \
Examine the process accepting the inbound connection over the source port makes sense or is suspicious.

Look for interesting access patterns such as:



*   Unrecognized internal connections with other internal instances.
*   Actions blocked at first but followed by allowed for the same outbound connection.
*   Look up blacklist feeds (e.g. [Talos IP reputation](https://www.talosintelligence.com/reputation_center)) to determine whether IPs are questionable.
*   Any new IP accessed for the first time before/after the incident.
*   Large volume of outbound traffic over DNS, HTTP, HTTPS, FTP, SFTP etc.
*   Large volume of internal network connections over a short period of time.

Run OSquery, if possible:



*   Query listening ports for suspicious listening process/ports:

`SELECT DISTINCT processes.name, processes.path, listening_ports.port FROM listening_ports JOIN processes USING (pid) WHERE listening_ports.family = 2 AND listening_ports.address <> ‘127.0.0.1’;`



*   List all the network connection associated with process ID: \
`select distinct pid, family, protocol, local_address, local_port, remote_port, path from process_open_sockets;`
*   Search processes making connections by suspicious IP: \
`select p.pid, p.parent, p.cmdline, p.path, s.remote_address, s.remote_port from process_open_sockets as s INNER JOIN processes AS p ON p.pid=s.pid WHERE s.remote_address='<ip_addr>' ;` \


If unexpected processes listening for network connections are found and cannot be explained by the owner of the system, the system should be considered compromised.


# Looking for Persistence

Run `schtasks` or Task Scheduler (GUI) version to check current scheduled tasks to see if any unauthorized jobs have been added, as well as unplanned and unrecognized tasks were executed in the past, in which these events are recorded in scheduled task log file: `C:\Windows\Tasks\SCHEDLGU.TXT`

Alternatively, run Osquery, if available:  \
`SELECT hidden,name,action FROM scheduled_tasks WHERE enabled = 1;`

Attackers may abuse Background Intelligent Transfer Service (BITS) to download, execute, and even clean up after running malicious code.

Use [bits_parser](https://github.com/ANSSI-FR/bits_parser) CLI to extract BITS job from QMGR queue or disk image to CSV file, and scan `src_fn` field for suspicious downloading URL. For example:

`bits_parser -o result.csv C:\ProgramData\Microsoft\Network\Downloader\qmgr0.dat`

Search various folders, pay special attention to executables or scripts with the following file extensions: `.bat, .cmd, .com, .lnk, .pif, .scr, .vb, .vbe, .vbs, .wsh, .ps, .exe`

Apply extra caution to those files with multiple extensions e.g. `image.jpg.exe`. Multiple extensions may disguise a standard image icon to look like a harmless image, are very likely indicators of malware.

Use Google to search for a process name and determine its function or if it is malicious:



*   `C:\windows\temp`
*   Recycle Bin
*   Recent items
*   `C:\Users\<user-name>\AppData\Roaming\Microsoft\Windows\Recent`
*   Shared folders: use `net` command to list all sharing folders: `net view \\127.0.0.1`

A PowerShell profile is a script that runs as a logon script when PowerShell starts. 

Locations that profile.ps1 can be stored should be monitored for new profiles or changes since these can be used for malicious persistence:



*   AllUsersAllHosts - `%windir%\System32\WindowsPowerShell\v1.0\profile.ps1`
*   AllUsersAllHosts (WoW64) - `%windir%\SysWOW64\WindowsPowerShell\v1.0\profile.ps1` 
*   AllUsersCurrentHost - `%windir%\System32\WindowsPowerShell\v1.0\Microsoft.PowerShell_profile.ps1` 
*   AllUsersCurrentHost (ISE) - `%windir%\System32\WindowsPowerShell\v1.0\Microsoft.PowerShellISE_profile.ps1`
*   AllUsersCurrentHost (WoW64) – `%windir%\SysWOW64\WindowsPowerShell\v1.0\Microsoft.PowerShell_profile.ps1`
*   AllUsersCurrentHost (ISE - WoW64) - `%windir%\SysWOW64\WindowsPowerShell\v1.0\Microsoft.PowerShellISE_profile.ps1`
*   CurrentUserAllHosts - `%homedrive%%homepath%\[My]Documents\profile.ps1` 
*   CurrentUserCurrentHost - `%homedrive%%homepath%\[My]Documents\Microsoft.PowerShell_profile.ps1` 
*   CurrentUserCurrentHost (ISE) - `%homedrive%%homepath%\[My]Documents\Microsoft.PowerShellISE_profile.ps1`

Search Registry audit events around the time of incident for possible fileless malware using Registry as storage, particularly in following events:



*   4656 A handle to an object was requested
*   4657 A registry value was modified
*   4659 A handle to an object was requested with intent to delete
*   4663 An attempt was made to access an object
*   4670 Permissions on an object were changed

Scan for new keys with large encoded binaries created and fetched from the Registry audit events. Pay attention to the binary name and location in which had accessed and modified those registry keys.

Many Registry keys are used by Microsoft Windows to load and run Exe/DLL/shell executables when various events occur. To search for malware using Registry keys to persist, [here](https://www.dropbox.com/s/rlzvhaaqrq9xyns/autoruns.txt?dl=0) is a comprehensive list of key locations. Consider using [Autoruns](https://docs.microsoft.com/en-us/sysinternals/downloads/autoruns) whenever possible to examine these registry locations for:



*   Browser Helper Objects(IE BHO) being installed
*   Winlogon script being installed
*   Startup program in Run/RunOnce Keys
*   Legacy Windows Load
*   AppInit_DLLs
*   AppCombat Shims

If malicious software is found via these techniques, the system should be considered compromised. 


# Look for Malware infection

Investigators should examine if malware files are present on the system using:



*   [ClamAV](https://www.clamav.net/downloads#otherversions) to scan the system, or 
*   Calculate hash of binaries and check with VirusTotal using [virustotal-search.py](https://github.com/DidierStevens/DidierStevensSuite/blob/master/virustotal-search.py)

    If the system is live, consider installing [Process Explorer](https://isc.sans.edu/forums/diary/Process+Explorer+and+VirusTotal/19931/) which comes with built-in VirtusTotal to check hash on selected processes.


If malware is discovered using any of these techniques, the system should be considered compromised.


# Look for Network and File Access and Changes

Search Security log event ID 4663 (An attempt was made to access an object) and 4656 (A handle to an object was requested) for attempts at reading sensitive information in:



*   Processes memory, for example: \
Scraping credentials in `lsass.exe`, reveals in “Object Name” field.
*   Access to domain user hash file `ntds.dit`, reveals in “Object Name” field.
*   Registry location for example: \
Access SAM, Security and System hives to extract local password hashes.

Search Security log event ID 4719 (System audit policy was changed) to identify unauthorized auditing policy change either via Local Security Policy, Group Policy in Active Directory or the `auditpol.exe` command.

Attackers may change execution policy to a less restrictive setting, such as "bypass". Search in registry key for unauthorized change: `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PowerShell\1\ShellIds\Microsoft.PowerShell\ExecutionPolicy`.

If any unexpected changes are found and cannot be explained by the owner of the system, the system should be considered compromised.


# Look for Various Ways of Remote Execution

Search for indicators of processes being executed remotely in following ways:



*   PsExecSvc Remote Execution
    *   Search System Event ID 7045 (A new service was installed in the system) when PsExec service `PSEXECSVC` is installed
    *   Search registry `HKLM\System\CurrentControlSet\Services\PSEXESVC` for new service creation.
    *   Search in *ShimCache* and *AmCache* for first time execution: `psexesvc.exe`
    *   Search Prefetch folder which records malicious binary and PsExec binary: `C:\Windows\Prefetch\evil.exe-{hash}.pf C:\Windows\Prefetch\psexesvc.exe-{hash}.pf`
    *   Search `psexesvc.exe` as well as malicious executables (e.g. `evil.exe`) that are pushed by PsExec, placed in ADMIN$ folder by default.
    *   Search Security Event ID 5140 (A network share object was accessed) \
Check ‘Share Name’ field for windows shares `ADMIN$` were used by PsExec
    *   Search Security Event ID 4648 (A logon was attempted using explicit credentials) for logon specifying alternate credentials in:
        *   Connecting User Name
        *   Process Name 
    *   Search Security Event ID 4624(An account was successfully logged on)
        *   Filter by “Logon Type”=3 or 2 if “-u” Alternate Credentials are used.
        *   Extract caller info stored in “Source IP/Logon User Name” field 
    *   Search Security Event ID 4672 for a user with administrative privileges
*   Remote Scheduler Tasks Creation
    *   Search Security Event ID:
        *   4698 – Scheduled task created
        *   4702 – Scheduled task updated
        *   4699 – Scheduled task deleted
        *   4700/4701 – Scheduled task enabled/disabled
    *   Search Windows-Task Scheduler Log Event ID:
        *    106 – Scheduled task created
        *    140 – Scheduled task updated
        *    141 – Scheduled task deleted
        *    200/201 – Scheduled task executed/completed
    *   Search registry `HKLM\Software\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks` (flat list by GUID)`HKLM\Software\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree` (tree view by task name) for new installed tasks
    *   Search in *ShimCache* and *AmCache* for first time malicious file execution.
    *   Search for Job files created in folder `C:\Windows\Tasks`
    *   Search for XML task files created in folder `C:\Windows\System32\Tasks`
        *   Extract Author tag under "RegistrationInfo" can identify: Source system name and Creator username
    *   Search Prefetch folder which records malicious task binary execution: `C:\Windows\Prefetch\evil.exe-{hash}.pf`
    *   Search Security Event ID 4624(An account was successfully logged on)
        *   Filter by “Logon Type”=3
        *   Extract caller info stored in “Source IP/Logon User Name” field 
    *   Search Security Event ID 4672 (Special privileges assigned to new logon) for a user logon with administrative privileges
*   Remote Services Installation
    *   Search System Event ID:
        *   7034 – Service crashed unexpectedly 
        *   7035 – Service sent a Start/Stop control 
        *   7036 – Service started or stopped 
        *   7040 – Start type changed (Boot | On Request | Disabled) 
        *   7045 – A service was installed on the system
    *   Search registry `HKLM\System\CurrentControlSet\Services` for new service creation.
    *   Search Prefetch folder which records malicious service binary execution: `C:\Windows\Prefetch\evil.exe-{hash}.pf`
    *   Search in *ShimCache* and *AmCache* for first time malicious service executable (unless service is implemented as a service DLL).
    *   Search Security Event ID 4697 (A service was installed in the system) for a new server installed.
    *   Search Security Event ID 4624 (An account was successfully logged on)
        *   Filter by “Logon Type”=3
        *   Extract caller info stored in “Source IP/Logon User Name” field 
*   WMI/WMIC Remote Execution
    *   WMI Activity Event ID 5857 \
Search for time of `wmiprvse.exe` execution and path to provider DLLs, note attackers sometimes install malicious WMI provider DLLs
    *   WMI Activity Event ID 5860 (Registration of Temporary) and 5861 (Registration of Permanent) \
Typically used for persistence, but can indicate remote execution.
    *   Search in *ShimCache* and *AmCache* for first time execution: \
`scrcons.exe`, `mofcomp.exe`, `wmiprvse.exe`, and malicious executable.
    *   Search Prefetch folder which records WMI remote execution: \
`C:\Windows\Prefetch\scrcons.exe-{hash}.pf  \
C:\Windows\Prefetch\mofcomp.exe-{hash}.pf  \
C:\Windows\Prefetch\wmiprvse.exe-{hash}.pf  \
C:\Windows\Prefetch\evil.exe-{hash}.pf `\
Note: The command the attacker ran, is usually next prefetch file entry above the `WMIPRVSE.EXE` process in list of files sorted in chronological order.
    *   Search unauthorized changes in WMI Repository in `C:\Windows\ System32\wbem\Repository` using [WMI Query](https://docs.microsoft.com/en-us/windows/desktop/wmisdk/querying-wmi).
    *   Search Security Event ID 4624(An account was successfully logged on)
        *   Filter by “Logon Type”=3
        *   Extract caller info stored in “Source IP/Logon User Name” field 
    *   Search Security Event ID 4672 (Special privileges assigned to new logon) for a user logon with administrative privileges
*   PowerShell Remote Execution
    *   Search PowerShell Event ID 400, 403 "ServerRemoteHost" indicates start/end of Remoting Powershell session
    *   Search PowerShell Event ID 4103, 4104 Script Block logging Logs scripts
    *   Search Prefetch folder which records malicious binary file and WinRM Remote Powershell session: `C:\Windows\Prefetch\evil.exe-{hash}.pf C:\Windows\Prefetch\wsmprovhost.exe-{hash}.pf`
    *   Search in *ShimCache* and *AmCache* for first time execution: \
`wsmprovhost.exe` and malicious executable.
    *   Search Security Event ID 4624, filter by “Logon Type”=3, caller info stored in “Source IP/Logon User Name” field 
    *   Search Security Event ID 4672 for a user with administrative privileges
    *   In the event of suspicious PowerShell execution, further search PowerShell cmdlets calls below(not a complete list):

        `Mimikatz, powercat, powersploit, PowershellEmpire, Payload, GetProcAddress, Get-WMIObject, Get-GPPPassword, Get-Keystrokes, Get-TimedScreenshot, Invoke-Command, Invoke-Expression, iex, Invoke-Shellcode, Invoke--Shellcode, Invoke-ShellcodeMSIL, Out-Word, Out-Excel, Out-Java, `etc. 


If any remote execution are found and cannot be explained by the owner of the system, the system should be considered compromised.


# Look for Remote Desktop Access



*   Search Windows-Remote-Desktop-Services-Rdp-CoreTS-Operational Event ID:
    *    131 – Connection Attempts
        *   Extract IP in “Source IP” field
        *   Search for successful brute-force attack when many failed attempts follow by a successful connection.
    *    98 – Successful Connections
*   Search Windows-Terminal-Services-LocalSession-Manager-Operational Event ID:
    *   Event ID 21, 22, 25
        *   Extract caller info in “Source IP/Logon User Name” field
    *   Event ID 41
        *   Extract username info in “Logon User Name” field
*   Search Security Event ID 4624 (An account was successfully logged on)
    *   Filter by “Logon Type”=10
    *   Extract caller info stored in “Source IP/Logon User Name” field 
*   Search Security Event ID 4778/4779 (A session was reconnected/disconnected to a Window Station)
    *   Extract caller info stored in “IP Address of Source/Source System Name”, “Logon User Name” fields
*   Search in *ShimCache* and *AmCache* for first time execution: \
`rdpclip.exe`, `tstheme.exe`.
*   Search Prefetch folder which records RDP executables: \
`C:\Windows\Prefetch\rdpclip.exe-{hash}.pf  \
C:\Windows\Prefetch\tstheme.exe-{hash}.pf`

If any unexpected remote sessions are found and cannot be explained by the owner of the system, the system should be considered compromised.


# Search for New & Recently-Modified Files

Search for new executables, DLLs, scripts,  especially unsigned binaries in:



*   Temporary or cache folders
*   User profiles (AppData, Roaming, Local, etc) 
*   `C:\ProgramData` or All Users profile
*   `C:\RECYCLE`
*   `C:\Windows & C:\Windows\System32`
*   Random and encoded file names in non-internet temp folder
*   Files in wrong folders (i.e. `C:\Windows\svchost.exe`)

Consider tools such as [AnalyzeMFT](https://github.com/dkovar/analyzeMFT)(Python) and [Windows Journal Parser](https://tzworks.net/prototype_page.php?proto_id=5)(Win32), which would acquire changes in NTFS easily and help streamline the analysis process.

If new or modified files are identified as malicious and cannot be explained by the owner of the system, the system should be considered compromised.

 

Check for Modifications to Name Resolution



1. Review `c:\Windows\System32\drivers\etc\hosts` if unrecognized DNS resolution entries added or changed
2. Run `nslookup google.com` to display DNS server in use. 
3. Run `ipconfig /displaydns` to display DNS cache on Microsoft Windows, and scan DNS records for suspicious low TTLs(10m or lower), which may indicate connections to the fast-flux botnets.

If the system is resolving DNS names using unexpected name servers, the system should be considered compromised.


# How to Handle a Compromised System

Recommended dump tool: [Dumpit](https://my.comae.io/) (free to download after registration) for Microsoft Windows.

*   First, Copy `Dumpit.exe` to the newly created volume
*   Run `Dumpit.exe` as administrator or in an admin privileged terminal.
