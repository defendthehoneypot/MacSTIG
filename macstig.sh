#!/bin/bash
<<COMMENT1
Remote access services, such as those providing remote access to network devices and information systems, increase risk and expose those systems to possible cyber attacks, so all remote access should be closely monitored and audited. Only authorized users should be permitted to remotely access DoD non-public information systems. An attacker might attempt to log in as an authorized user, through stolen credentials, unpatched exploits of the remote access service, or brute force attempts to guess a valid username and password. If a user is attempting to log in to a system from an unusual location or at an unusual time, or if there are many failed attempts, there is a possibility that the system is the target of a cyber attack. Auditing logon events mitigates this risk by recording all logon attempts, successful and unsuccessful, to the system.
COMMENT1
/usr/bin/sudo /usr/bin/sed -i.bak '/^flags/ s/$/,lo/' /etc/security/audit_control; /usr/bin/sudo /usr/sbin/audit -s

<<COMMENT2
The operating system must, for networked systems, compare internal information system clocks at least every 24 hours with a server which is synchronized to one of the redundant United States Naval Observatory (USNO) time servers or a time server designated for the appropriate DoD network (NIPRNet/SIPRNet), and/or the Global Positioning System (GPS).
COMMENT2
/usr/bin/sudo /bin/launchctl load -w /System/Library/LaunchDaemons/org.ntp.ntpd.plist 

<<COMMENT3
The operating system must implement DoD-approved encryption to protect the confidentiality of remote access sessions.
COMMENT3
/usr/bin/sudo /bin/launchctl disable system/com.apple.rexecd

<<COMMENT4
The rshd service must be disabled.
COMMENT4
/usr/bin/sudo /bin/launchctl disable system/com.apple.rshd

<<COMMENT5
The operating system must enforce requirements for remote connections to the information system.
COMMENT5
/usr/bin/sudo /bin/launchctl disable system/com.apple.screensharing

<<COMMENT6
Wi-Fi support software must be disabled.
Not implemented
COMMENT6
#/usr/bin/sudo /usr/sbin/networksetup -setnetworkserviceenabled "Wi-Fi" off

<<COMMENT7
Infrared [IR] support must be disabled.
COMMENT7
/usr/bin/sudo /usr/bin/defaults write /Library/Preferences/com.apple.driver.AppleIRController DeviceEnabled -bool FALSE

<<COMMENT8
The operating system must provide an immediate real-time alert to the SA and ISSO, at a minimum, of all audit failure events requiring real-time alerts.
COMMENT8
/usr/bin/sudo /usr/bin/sed -i.bak 's/logger -p/logger -s -p/' /etc/security/audit_warn; /usr/bin/sudo /usr/sbin/audit -s

<<COMMENT9
The operating system must provide an immediate warning to the SA and ISSO (at a minimum) when allocated audit record storage volume reaches 75% of repository maximum audit record storage capacity.
COMMENT9
/usr/bin/sudo /usr/bin/sed -i.bak 's/.*minfree.*/minfree:25/' /etc/security/audit_control; /usr/bin/sudo /usr/sbin/audit -s

<<COMMENT10
The operating system must allocate audit record storage capacity to store at least one weeks worth of audit records, when audit records are not immediately sent to a central audit record storage facility.
COMMENT10
/usr/bin/sudo /usr/bin/sed -i.bak 's/.*expire-after.*/expire-after:7d/' /etc/security/audit_control; /usr/bin/sudo /usr/sbin/audit -s 

<<COMMENT11
The operating system must generate audit records for all account creations, modifications, disabling, and termination events, for privileged activities or other system-level access, all kernel module load, unload, and restart actions, all program initiations, and organizationally defined events for all non-local maintenance and diagnostic sessions.
COMMENT11
/usr/bin/sudo /usr/bin/sed -i.bak '/^flags/ s/$/,ad/' /etc/security/audit_control; /usr/bin/sudo /usr/sbin/audit -s 

<<COMMENT12
SMB File Sharing must be disabled unless required.
COMMENT12
/usr/bin/sudo /bin/launchctl disable system/com.apple.smbd

<<COMMENT13
Apple File (AFP) Sharing must be disabled.
COMMENT13
/usr/bin/sudo /bin/launchctl disable system/com.apple.AppleFileServer

<<COMMENT14
The NFS daemon must be disabled unless required.
COMMENT14
/usr/bin/sudo /bin/launchctl disable system/com.apple.nfsd 

<<COMMENT15
The NFS lock daemon must be disabled unless required.
COMMENT15
/usr/bin/sudo /bin/launchctl disable system/com.apple.lockd

<<COMMENT16
The NFS stat daemon must be disabled unless required.
COMMENT16
/usr/bin/sudo /bin/launchctl disable system/com.apple.statd.notify

<<COMMENT17
The SSH banner must contain the Standard Mandatory DoD Notice and Consent Banner.
COMMENT17
/usr/bin/sudo cp ./banner /etc/banner

<<COMMENT18
The operating system must initiate session audits at system startup.
COMMENT18
/usr/bin/sudo /bin/launchctl load -w /System/Library/LaunchDaemons/com.apple.auditd.plist

<<COMMENT19
The operating system must generate audit records for DoD defined events such as: successful/unsuccessful logon attempts, successful/unsuccessful direct access attempts, starting and ending time for user access, and concurrent logons to the same account from different sources.
COMMENT19
/usr/bin/sudo /usr/bin/sed -i.bak '/^flags/ s/$/,aa/' /etc/security/audit_control; /usr/bin/sudo /usr/sbin/audit -s

<<COMMENT20
Any connection to the operating system must display the Standard Mandatory DoD Notice and Consent Banner before granting access to the system.
COMMENT20
/usr/bin/sudo cp ./PolicyBanner.rtf /Library/Security/PolicyBanner.rtf
/usr/bin/sudo chmod o+x /Library/Security/PolicyBanner.rtf

<<COMMENT21
The operating system must display the Standard Mandatory DoD Notice and Consent Banner before granting access to the system via SSH.
COMMENT21
/usr/bin/sudo /usr/bin/sed -i.bak 's|#Banner none|Banner /etc/banner|' /etc/ssh/sshd_config

<<COMMENT22
The Security assessment policy subsystem must be enabled.
COMMENT22
/usr/bin/sudo /usr/sbin/spctl --master-enable

<<COMMENT23
Sending diagnostic and usage data to Apple must be disabled.
COMMENT23
/usr/bin/defaults read "/Library/Application Support/CrashReporter/DiagnosticMessagesHistory.plist" AutoSubmit 
/usr/bin/sudo /usr/bin/defaults write "/Library/Application Support/CrashReporter/DiagnosticMessagesHistory.plist" AutoSubmit -bool false 
/usr/bin/sudo /bin/chmod 644 /Library/Application\ Support/CrashReporter/DiagnosticMessagesHistory.plist 
/usr/bin/sudo /usr/bin/chgrp admin /Library/Application\ Support/CrashReporter/DiagnosticMessagesHistory.plist

<<COMMENT24
Find My Mac must be disabled.
COMMENT24
/usr/bin/sudo /bin/launchctl disable system/com.apple.findmymacd

<<COMMENT25
Find My Mac messenger must be disabled.
COMMENT25
/usr/bin/sudo /bin/launchctl disable system/com.apple.findmymacmessenger

<<COMMENT26
Location Services must be disabled.
COMMENT26
/usr/bin/sudo /usr/bin/defaults write /private/var/db/locationd/Library/Preferences/ByHost/com.apple.locationd.`/usr/sbin/system_profiler SPHardwareDataType | /usr/bin/grep "Hardware UUID" | /usr/bin/cut -c22-57` LocationServicesEnabled -bool false

<<COMMENT27
Bonjour multicast advertising must be disabled on the system.
COMMENT27
/usr/bin/sudo /usr/bin/defaults write /Library/Preferences/com.apple.mDNSResponder.plist NoMulticastAdvertisements -bool true 

<<COMMENT28
The UUCP service must be disabled.
COMMENT28
/usr/bin/sudo /bin/launchctl disable system/com.apple.uucp

<<COMMENT29
The operating system must require individuals to be authenticated with an individual authenticator prior to using a group authenticator.
COMMENT29
/usr/bin/sudo /usr/bin/sed -i.bak 's/^[\#]*PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config

<<COMMENT30
The operating system must implement replay-resistant authentication mechanisms for network access to privileged and non-privileged accounts.
COMMENT30
/usr/bin/sudo /usr/bin/sed -i.bak 's/.*Protocol.*/Protocol 2/' /etc/ssh/sshd_config

<<COMMENT31
The operating system must implement cryptography to protect the integrity and confidentiality of data during transmission of remote access sessions, non-local maintenance sessions, and diagnostic communications. 
COMMENT31
/usr/bin/sudo /bin/launchctl disable system/com.apple.telnetd 

<<COMMENT32
The SSH daemon ClientAliveInterval option must be set correctly.
COMMENT32
/usr/bin/sudo /usr/bin/sed -i.bak 's/.*ClientAliveInterval.*/ClientAliveInterval 600/' /etc/ssh/sshd_config

<<COMMENT33
The SSH daemon ClientAliveCountMax option must be set correctly.
COMMENT33
/usr/bin/sudo /usr/bin/sed -i.bak 's/.*ClientAliveCountMax.*/ClientAliveCountMax 0/' /etc/ssh/sshd_config

<<COMMENT34
The operating system must audit the enforcement actions used to restrict access associated with changes to the system.
COMMENT34
/usr/bin/sudo /usr/bin/sed -i.bak '/^flags/ s/$/,fm,-fr,-fw/' /etc/security/audit_control; /usr/bin/sudo /usr/sbin/audit -s

<<COMMENT35
The operating system must generate audit records when successful/unsuccessful attempts to access/modify privileges occur.
COMMENT35
/usr/bin/sudo sed -i.bak '/^flags/ s/$/,lo/' /etc/security/audit_control; /usr/bin/sudo /usr/sbin/audit -s 

<<COMMENT36
The SSH daemon LoginGraceTime must be set correctly.
COMMENT36
/usr/bin/sudo /usr/bin/sed -i.bak 's/.*LoginGraceTime.*/LoginGraceTime 30/' /etc/ssh/sshd_config

<<COMMENT37
The operating system must implement cryptographic mechanisms to protect the confidentiality and integrity of all information at rest.
COMMENT37
/usr/bin/sudo /usr/bin/fdesetup enable 

<<COMMENT38
The usbmuxd daemon must be disabled.
COMMENT38
/usr/bin/sudo /bin/launchctl disable system/com.apple.usbmuxd 

<<COMMENT39
The OS X firewall must have logging enabled.
COMMENT39
/usr/bin/sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setloggingmode on

<<COMMENT40
Bluetooth devices must not be allowed to wake the computer.
COMMENT40
/usr/bin/defaults write /Users/`whoami`/Library/Preferences/ByHost/com.apple.Bluetooth.`/usr/sbin/system_profiler SPHardwareDataType | /usr/bin/grep "Hardware UUID" | /usr/bin/cut -c22-57`.plist RemoteWakeEnabled 0

<<COMMENT41
Bluetooth Sharing must be disabled.
COMMENT41
/usr/bin/defaults write /Users/`whoami`/Library/Preferences/ByHost/com.apple.Bluetooth.`/usr/sbin/system_profiler SPHardwareDataType | /usr/bin/grep "Hardware UUID" | /usr/bin/cut -c22-57`.plist PrefKeyServicesEnabled 0

<<COMMENT42
Remote Apple Events must be disabled.
COMMENT42
/usr/bin/sudo /bin/launchctl disable system/com.apple.AEServer

<<COMMENT43
All public directories must be owned by root or an application account.
COMMENT43
/usr/bin/sudo find / -type d -perm +o+w -not -uid 0 -exec chown root {} \;

<<COMMENT44
The finger service must be disabled.
COMMENT44
/usr/bin/sudo /bin/launchctl disable system/com.apple.fingerd

<<COMMENT45
The sticky bit must be set on all public directories.
COMMENT45
/usr/bin/sudo /usr/bin/find / -type d \( -perm -0002 -a ! -perm -1000 \) -exec chmod +t {} \;

<<COMMENT46
The system must not accept source-routed IPv4 packets.
COMMENT46
/usr/bin/sudo echo "net.inet.ip.accept_sourceroute=0" >> /etc/sysctl.conf

<<COMMENT47
The system must ignore IPv4 ICMP redirect messages.
COMMENT47
/usr/bin/sudo echo "net.inet.icmp.drop_redirect=1" >> /etc/sysctl.conf

<<COMMENT48
IP forwarding for IPv4 must not be enabled.
COMMENT48
/usr/bin/sudo echo "net.inet.ip.forwarding=0" >> /etc/sysctl.conf

<<COMMENT49
IP forwarding for IPv6 must not be enabled.
COMMENT49
/usr/bin/sudo echo "net.inet6.ip6.forwarding=0" >> /etc/sysctl.conf

<<COMMENT50
Web Sharing must be disabled.
COMMENT50
/usr/bin/sudo /bin/launchctl disable system/org.apache.httpd 

<<COMMENT51
Internet Sharing must be disabled.
COMMENT51
/usr/bin/sudo /bin/launchctl disable system/com.apple.NetworkSharing 

<<COMMENT52
The system must not send IPv4 ICMP redirects by default.
COMMENT52
/usr/bin/sudo echo "net.inet.ip.redirect=0" >> /etc/sysctl.conf

<<COMMENT53
The system must not send IPv6 ICMP redirects by default.
COMMENT53
/usr/bin/sudo echo "net.inet6.ip6.redirect=0" >> /etc/sysctl.conf

<<COMMENT54
The system must prevent local applications from generating source-routed packets.
COMMENT54
/usr/bin/sudo echo "net.inet.ip.sourceroute=0" >> /etc/sysctl.conf

<<COMMENT55
The system must not process Internet Control Message Protocol [ICMP] timestamp requests.
COMMENT55
/usr/bin/sudo echo "net.inet.icmp.timestamp=0" >> /etc/sysctl.conf

<<COMMENT56
The operating system must generate audit records when successful/unsuccessful attempts to access/modify/delete objects, access/modify categories of information (e.g., classification levels), and delete privileges occur.
COMMENT56
/usr/bin/sudo /usr/bin/sed -i.bak '/^flags/ s/$/,fm/' /etc/security/audit_control; /usr/bin/sudo /usr/sbin/audit -s 
