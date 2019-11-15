
# Summary

When IR team is alerted to suspicious activity on a Linux server, the steps in this document should be performed to make an initial assessment as to whether or not that system has been compromised.

# Gather Background/Contextual Information

Contact the owner of the system to determine: 

1. What is the system normally used for (e.g. deployment, customer demos, web hosting, third-party application hosting, etc.)?

2. Has the owner done anything unusual around the time of the incident?

3. Can the owner share available access credentials?

# Currently Logged-On Users

Enumerate users who are currently logged on to the system, e.g. via the `w` shell command.

If any unexpected client IPs are found in the output, not associated with any organization users, perform a `whois` lookup to determine which organization and location that IP is associated with.

If any IPs are present in the logs, but cannot be explained, the system should be considered compromised. 

# Previously Logged-On Users

Linux servers keep a record of which users have logged in, the client IP which was used for that session, the date/time of the session, and the length of the session. This information is typically stored in `/var/log/wtmp` and users can access it with the `last` command.

If unexpected IP addresses are found, see the previous section for instructions on verification steps to perform for each IP address.

If the `last` command only returns the current login of the investigator, this could indicate that the attackers have altered `/var/log/wtmp`. In that case, investigators should also check the modification times on all users’ home directories and their `.bash_histor` files for suspicious shell execution by each user(see [Review OS Command History](#Review-OS-Command-History) below).

If there are other remote access methods available, such as VNC, RDP, or FTP, perform the same analysis on the access logs for those services.

If any user sessions are present in the logs, but cannot be explained, the system should be considered compromised.

# Review OS Command History

Examine shell history files for each user account on the system (`.bash_history`, `.history`, etc.). 

Indications that `.bash_history` has been altered or evaded is a noteworthy indicator of compromise.

Look for any unusual commands, but in particular:

* `wget` and `curl` used to download unexpected files, as these are often used to download malicious binaries.

* Commands used against files that contain OS or application user information, such as `/etc/passwd`, `/etc/shadow`, `/etc/gshadow`, `/etc/group` or `/etc/secret-volume` files:

    * *Search utilities such as `grep` or `find`

    * *File viewing utilities such as `cat`, `less`, `head`, `more`, or `strings`

    * *Commonly used text editors such as `vim`, `vi`, `gedit`, `emacs`, `nano`, etc.

* Renaming of binary files.

* Explicit execution of shell binaries (`/bin/sh`, `/bin/bash`, `/bin/rbash`, `/bin/dash`, etc.).

* Uncommon commands such as `whoami`, `w`, `useradd`, `passwd`, `id`, `last`, `exec`, `history`,`chsh`, `mail`, `pico`, `uname`. Also pay attention to commonly used commands that are used in an interesting way, e.g: wget+chmod/chown+run shell

* Common attacker-used tools such as `nmap`, `masscan`, `ettercap` to collect info and move laterally. For more tools, see the [Kali tool](https://tools.kali.org/tools-listing) list

* Commands used to avoid bash history logging, such as:
`unset HISTFILE set +o history export history=0`

If any unusual commands are found which cannot be explained by the real owner of the system which executed them, the system should be considered compromised.

# Resource Utilization

Examine CPU, network, memory, and other resource utilization on the system.

High CPU usage is suspicious because it can indicate attackers are launching brute-force attacks against other assets or crypto-mining. This conspicuous resource consumption generally makes it pretty easy to spot them. Simply running `top` and looking at the processes consuming the most CPU time can often reveal these attacks.

If you do not recognize the `top` process, then either Google the name or investigate what it is doing with `losf` or `strace`.

To use these tools, first copy the PID from `top` and run:

`strace -p PID`

This command will display all the system calls the process is making. It displays a lot of information, but looking through it will give you a good idea of what is going on.

`lsof  -p PID`

This program will list the open files that the process has. Again, this will give you a good idea what it’s doing by showing you what files it is accessing. If attackers have patched `lsof` it may make sense to check `/proc`. Examining the links in `/proc/[PID]/fd` will also reveal what files are currently open and what sockets, if any, are open.

The command `iftop` functions like `top` to show a ranked list of processes that are sending and receiving network data along with their source and destination. A process like a DoS attack or spam bot will generally appear at the top of the list.

If malware presented in the system, or suspicious behavior cannot be explained by the owner of the system, the system should be considered compromised.

# Examine Running Processes

Run the command `ps auxwwf` to list as much process information as possible. Look for any processes that you don’t recognize or which seem like tools an attacker would use.

Use `pstree` to display processes in a hierarchical tree, identify suspicious parent-child process relationship, for example: Web server process launches a shell.

If a suspect system process is observed, investigators can find the binary associated with that process by executing `ls -al /proc/[PID]/exe`. If the file no longer exists (i.e. it has been deleted), but is still running, it can sometimes be recovered with `cat /proc/[PID]/exe > /tmp/newfile`. 

If suspicious binaries are identified as malicious, and cannot be explained by the owner of the system, the system should be considered compromised.

# Examine Listening Network Services

Enumerate network services which are listening on the system, using `lsof -i` or `netstat -plunt`.

The output from `lsof -i` also includes network connections made by local software communicating with other hosts via network connections. 

When notice less known processes are communicating, or well-known processes are communicating with suspicious IP via uncommon ports or protocols, investigators should examine these processes and the hosts with which they are communicating.

If any unexpected network services are found, and cannot be explained by the owner of the system, the system should be considered compromised.

# Look for Persistence and Backdoors

Any remote console service or network enabled daemon is a likely target for a back door. Examine the various timestamps for these files to determine if they have been modified more recently than expected. For example, all three timestamps can be examined for `/usr/bin/sshd` with these commands:

* `ls -al /usr/bin/sshd`

* `ls -cal /usr/bin/sshd`

* `ls -mal /usr/bin/sshd`

These same commands can be used to examine the contents of entire directories. Anomalous timestamps can indicate that an attacker has modified a binary.

Investigators should examine cron jobs with the `crontab -e` command, and search for unexpected or malicious commands executed via this mechanism.

Investigators should examine start-up scripts with the `ls -als -t /etc/init.d/` command (on some Linux distribution, start-up scripts are found in `/etc/rc.d`), and search for unexpected or malicious commands executed via this mechanism.

Investigators should examine kernel modules with the command `lsmod`. This output should be more or less the same as `cat /proc/modules`, although it is formatted in a more readable way. Any discrepancies between these lists could indicate that an attacker has tried to hide a  backdoor or rootkit.

Investigators should also search for binaries with the SUID bit set. A simple command to find these binaries is `find / -perm +5000 -uid root`. Under normal situations, this command will reveal some binaries that must be run as `root` in order to function. However, attackers might configure some executables with this bit for future privilege escalation. Any file that shows up on that list, which does not show up on a comparable trusted Linux host may be a backdoor.

The following commands perform the comparison to the baseline volume:

`find / -uid 0 -perm -4000 -print > suid_evidence`

`find /linux_base/ -uid 0 -perm -4000 -print > suid_base `

`cut suid_base -d"/" -f4- > suid_base_relative `

`cut suid_base -d"/" -f4- > suid_evidence_relative `

`diff suid_base_relative suid_evidence_relative`

Investigators should look for unusual accounts and multiple accounts with a user id (UID) set to zero. Also, note any new groups or services that have created an account as well.

Using `diff` to find new entries from baseline file:

`diff /etc/passwd <baseline_path>/etc/passwd`
`diff /etc/group <baseline_path>/etc/group`
`diff /etc/gshadow <baseline_path>/etc/gshadow`
`diff /etc/shadow <baseline_path>/etc/shadow`

If malicious software is found via these techniques, the system should be considered compromised.

# Look for Malware Infection

Investigators should examine if malware files presented on the system.

* Scan with [ClamAV](https://www.clamav.net/downloads#otherversions), or

* Calculate hash of binaries and check with VirusTotal using [virustotal-search.py](https://github.com/DidierStevens/DidierStevensSuite/blob/master/virustotal-search.py)

File names can be a gold mine for threat hunters regarding clues to attacker activity. The `/tmp` directory is frequently used to store uploaded files:

`ls -als /tmp`

Internet search the suspicious filename if any, and determine the nature of the file.

When suspicious files are identified, quick indication regarding the nature of the file and can identify potential indicators of compromise.

The output of the `strings` command may include file names, IP addresses, configuration details, menu options, and help screens, for example:

`strings mymalwarefile` # Extract Strings (ASCII)

Consider also searching for Unicode strings:

`strings -eS mymalwarefile` # Extract strings (UTF-8)

For [little-endian](https://en.wikipedia.org/wiki/Endianness) processor architectures (x86 and most other common CPUs):

`strings -el mymalwarefile` # Extract strings (UTF-16)

`strings -eL mymalwarefile` # Extract strings (UTF-32)

For [big-endian](https://en.wikipedia.org/wiki/Endianness) processor architectures (SPARC, etc.):

`strings -eb mymalwarefile` # Extract strings (UTF-16)

`strings -eB mymalwarefile` # Extract strings (UTF-32)

`grep -aoE "\b([0-9]{1,3}\.){3}[0-9]{1,3}\b"` mymalwarefile # Extract IPs

If malware is discovered using any of these techniques, the system should be considered compromised.

# Search for Network Sniffers and Keyloggers

Attackers will often run network "sniffers" to intercept data or other programs to spy on user activity. This software will often create real-time log files, network traffic or other activity. Creating an empty “dummy” file followed by a successful authentication or other network traffic can reveal a sniffer:

1. Issue this command: `touch /tmp/newer`

2. Log into the server or perform any activity which you fear might be logged

3. Issue this command: `find / -newer /tmp/newer -type f > /tmp/filelog`

The file `/tmp/filelog` will contain a list of files created or updated since the beginning of this exercise. If the attacker is logging activity to a local file, that file should be included on that list along with several others.

The command `ifconfig -a` can sometimes also reveal a sniffer. If the string "PROMISC" appears with any clause describing a network interface, that indicates that the interface is processing traffic not destined for it. If the “PROMISC” flag is not visible after a sniffer like `tcpdump` is engaged, this may indicate that the attacker has modified `ifconfig` or the kernel itself.

If sniffers or keyloggers are present on the system, and cannot be explained by the owner of the system, the system should be considered compromised.

# Search for New and Recently-Modified Files

List all the files created or changed around the time of the incident. For example, to list all files modified in the last day:

`find / -mtime -1`

For the last week:

`find / -mtime -7`

Use `-ctime` instead of `-mtime` to check the file creation timestamp.

Look for unusual file names and permissive permissions such as world-readable or world-writeable. For example:

`find / -type f -perm -o=a`

`find / -type f -perm -o=w`

Pay close attention to following files, if any of these being modified or created suspiciously recently:

Cron:

* `/etc/crontab`

* `/etc/cron.hourly, daily, weekly, monthly`

* `/etc/cron.d`

* `/var/spool/cron/USERNAME`

* `Anacron`

Credentials:

* `/etc/passwd`

* `/etc/shadow`

* `/etc/gshadow`

* `/etc/group`

* `/etc/secret-volume`

Shell configuration:

* `/etc/profile`

* `~/.bash_profile`

* `~/.bash_login`

* `~/.profile`

* `/home/USERNAME/.bashrc`

* `/etc/bash.bashrc`

* `/etc/profile.d/`

* BASH_ENV environment variable

Network configuration:

* `/etc/netns`

* `/etc/network/interfaces`

* `/etc/NetworkManager/NetworkManager.conf`

* `/etc/sysconfig/iptables-config`

Certificate authority:

* Using CLI below to search for unrecognized certificate installed on the system:

`awk -v cmd='openssl x509 -noout -subject' '`

`    /BEGIN/{close(cmd)};{print | cmd}' < /etc/ssl/certs/ca-certificates.crt`

If integrated with other authentication systems, check `/etc/pam.d` for malicious plug-in modules.

If new or modified files are identified as malicious, and cannot be explained by the owner of the system, the system should be considered compromised.

# Examine Service Logs

If the system hosts a web application with a WAF(Web Application Firewall) enabled, check if the WAF had reported the result of a successful attack.

Though a thorough approach of investigating common web attack patterns is beyond the scope of this article, a brief search of access logs for indicators of compromise should be done, for example:

* Large volume of requests for the same Url (mostly Web script) by the same source. Pay attention to the change in request and response. This may indicate attackers trying different ways to successfully exploit vulnerabilities.

* Many failed authentication attempts followed by successful authentication.

* Many failed status codes such as 4xx and 5xx errors followed by successful authentication

* Large volume of data returned in the response body (average normal response is less than 500KB, unless downloading a resource, for instance .zip file)

* Newly-created server-side files in web-accessible locations, such as PHP, Perl, Bash, Python, Javascript, Java classes, etc.

* Shell processes that were created by the web server account

* … ...

If the system hosts a database, check database logs from around the time of the incident, look for:

* Unseen SQL queries and stored-procedure executions from the past

* SQL execution errors

* Long-standing queries

* Unplanned backup operations

* Large volume of reading against where sensitive table are stored, e.g. user auth, PII.

If log files are missing from the period of the incident, or are smaller than expected, that activity should be considered suspicious.

Oftentimes, it can be hard to make sense of volume of log data by hand, leveraging scripting language (such as Python, Go) are highly recommended for ad-hoc investigations.

If evidence of successful intrusion or data exfiltration is identified, the system should be considered compromised.

# Check for Modifications to Name Resolution

Run `nslookup` and verify that the default nameserver is neither IaaS provided:

* AWS 169.254.169.253

* Azure 168.63.129.16

* GCP 169.254.169.254

* nor well-known DNS IP such as 8.8.8.8, 8.8.4.4, 1.1.1.1, 1.0.0.1

Examine the contents of `/etc/hosts` and `/etc/resolv.conf` to determine if the entries match those on trusted systems.

Examine `/etc/hosts` and `/etc/resolv.conf` file for any changes.

If the system is resolving DNS names using unexpected name servers, the system should be considered compromised.

**Note**:

Run` arp -a` and verify IP and Mac address entries are correct according to the network configuration. If the IP of Gateway or DNS or Domain Controller or server resolves to an unexpected MAC address, the system may be attacked by Arp spoofing from the host or other systems in the network.

# How to Handle a Compromised System

First, review:

* Document a Playbook document to cover:

    * General information for all team members

    * Information for responders and security staff

    * Handling process

According to [Microsoft 5-Step Incident Response Lifecycle model](http://aka.ms/SecurityResponsepaper), this section discusses actions in step 2, the assessing stage, which is always taken if a system is determined to be "compromised". This section focuses on gathering digital evidence by incident responders:

1. Contact the owner of the instance to get SSH `root` access. If not possible to obtain shell or RDP access for the host or the container, skip #2.

2. Capture volatile data before system suspension:
Dump Linux memory to capture important information about processes, open files, network state and other areas.

    1. For AWS, consider using 2-in-1 tool [aws_ir](https://aws-ir.readthedocs.io/en/latest/quickstart.html#instance-compromise) to automate step#2(memory dump) & 4(snapshot): `aws_ir instance-compromise --target <instance-id> --user <username> --ssh-key <ssh-key.pem> --bucket <bucket-name>`
If it’s desired to dump memory using other custom processes and tools, [create](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ebs-creating-volume.html) a new Volume in the same Availability Zone as the problem VM, and [attach](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ebs-attaching-volume.html) and [mount](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ebs-using-volumes.html) that volume to the target EC2 instance. Once attached, this will be the drive that volatile data will be dumped.

    1. For Azure, create a new VM in the same cloud service as the problem VM, delete VM but keep the attached disk, attach the disk to the problem VM. See [here](https://blogs.msdn.microsoft.com/mast/2014/11/20/recover-azure-vm-by-attaching-os-disk-to-another-azure-vm/) for detailed steps. 
[install](https://margaritashotgun.readthedocs.io/en/latest/installing.html ) [Margarita Shotgun](https://margaritashotgun.readthedocs.io/en/latest/quickstart.html#capture-a-single-machine) and run the command to save memory dump to new VHD: `margaritashotgun --server <vm_ip> --username <username> --key <ssh-key.pem> --module lime-3.13.0-74-generic.ko --filename <vhd_path_file_name>`

    1. For GCP, follow these [instructions](https://blogs.msdn.microsoft.com/mast/2014/11/20/recover-azure-vm-by-attaching-os-disk-to-another-azure-vm/) to create and attach new persistent disk to the problem VM. 
[install](https://margaritashotgun.readthedocs.io/en/latest/installing.html ) [Margarita Shotgun](https://margaritashotgun.readthedocs.io/en/latest/quickstart.html#capture-a-single-machine) and run the command: `margaritashotgun --server <vm_ip> --username <username> --key <ssh-key.pem> --module lime-3.13.0-74-generic.ko --filename <vhd_path_file_name>`

3. Block network access of compromised instances or VMs.

4. Create a point-in-time snapshot for deep forensic analysis of data on the hard drive, record Zone or Region, Instance identification, Snapshot identification and VolumeId(AWS) about the snapshot.

    1. For AWS, if `aws_ir` was not used in step#2, follow these [instructions](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ebs-creating-snapshot.html) to create EBS snapshot.

    1. For Azure, follow these [instructions](https://docs.microsoft.com/en-us/azure/virtual-machines/windows/snapshot-copy-managed-disk) to create full, read-only copy of a virtual hard drive (VHD).

    1. For GCP, follow these [instructions](https://cloud.google.com/compute/docs/disks/create-snapshots) to create persistent disk snapshots.

5. Gather evidence by collecting all logs available:

    1. System logs (e.g. go-audit log, osquery log, entire /var/log/ folder which includes all [common logs](https://www.unixmen.com/common-linux-log-files-name-and-usage/).).

    1. Application logs (e.g. Web server access log, SQL audit log)

    1. Authentication logs (e.g. AppGate/VPN, AD logs, RADIUS logs etc.)

    1. Logs from Security controls, examples are:
AntiVirus,  IDS/IPS, DLP, [WAF](https://aws.amazon.com/waf/) (AWS), [GuardDuty](https://aws.amazon.com/guardduty/) (AWS), [Macie](https://aws.amazon.com/macie/) (AWS), [Azure AD ](https://azure.microsoft.com/en-ca/services/active-directory/)(Azure), [Operations Management Suite](https://azure.microsoft.com/en-ca/resources/videos/operations-management-suite-oms-overview/) (Azure), [Security Center](https://azure.microsoft.com/en-ca/services/security-center/) (Azure), [Cloud DLP](https://cloud.google.com/dlp/) (GCP), [Cloud Security Scanner](https://cloud.google.com/security-scanner/) (GCP) etc.

    1. Administration log, examples are:
[CloudTrail](https://aws.amazon.com/cloudtrail/) (AWS), [Activity Log](https://docs.microsoft.com/en-us/azure/azure-monitor/platform/activity-logs-overview) (Azure), [Cloud Audit log](https://cloud.google.com/logging/docs/audit/) (GCP)

    1. Resource change and violation history, examples are:
Config (AWS), Policy (Azure)

    1. Network traffic, examples are:
VPC flow log (AWS & GCP), Route53 log (AWS), Stackdriver Logging (GCP), ELB access logs (AWS), Network security group flow logs (Azure)

6. Investigate evidence by analyzing, correlating data to determine (digital forensics is beyond the scope of this document, the following is only to highlight the process.):

    1. *how, when, where* the incident occurred

        1. How the bad actors attacked the system, search for:

            1. Indicator of compromise

            2. Indicator of persistence

            3. What activities took place by the malware

        1. Perform timeline analysis, reconstruct the sequence of events

        1. Assess damage by analyzing data collected in aforementioned, to identify:

            1. If keys are present on compromised system

            1. Devices being compromised

            1. Link to other possible compromised systems

            1. Data being stolen and sensitivity of the data

            1. The weakness of system

            1. Root cause of the intrusion

    1. *who and why* the incident occurred

        1. Although hard, but possible to attribute to APT groups with:

            1. Reverse malware

            1. Indicators of compromise (IOC) and 

            1. Tactics, techniques, and procedures (TTPs) found during the investigation process.

    1. Consider [SIFT Workstation](https://digital-forensics.sans.org/blog/category/sift-workstation) to perform forensic analysis.

