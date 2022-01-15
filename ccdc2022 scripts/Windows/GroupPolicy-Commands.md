# Ensure 'Interactive logon: Do not display last user name' is set to 'Enabled'
`Set-GPRegistryValue -Name "" -Key "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System" -ValueName "DontDisplayLastUserName" -Type REG_DWORD -Value 1`

# Ensure 'Interactive logon: Smart card removal behavior' is set to 'Lock Workstation' or higher
`Set-GPRegistryValue -Name "" -Key "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" -ValueName "ScRemoveOption" -Type REG_SZ -Value 1`

# Ensure 'Microsoft network client: Digitally sign communications (always)' is set to 'Enabled'
`Set-GPRegistryValue -Name "" -Key "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\LanmanWorkstation\Parameters" -ValueName "RequireSecuritySignature" -Type REG_DWORD -Value 1`

# Ensure 'Network access: Do not allow storage of passwords and credentials for network authentication' is set to 'Enabled'
`Set-GPRegistryValue -Name "" -Key "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa" -ValueName "DisableDomainCreds" -Type REG_DWORD -Value 1`

# Ensure 'Network security: Minimum session security for NTLM SSP based (including secure RPC) clients' is set to 'Require NTLMv2 session security, Require 128-bit encryption'
`Set-GPRegistryValue -Name "" -Key "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa\MSV1_0" -ValueName "NTLMMinClientSec" -Type REG_DWORD -Value 537395200`


# Disable Null Sessions in Windows
Guide to disable null sessions via Group Policy: 
https://social.technet.microsoft.com/Forums/windowsserver/en-US/e56374b4-6132-4aae-ab6b-349e5d355575/disable-null-sessions-on-domain-controllers-and-member-servers?forum=winserverGP

`Set-GPRegistryValue -Name "" -Key "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA" -ValueName "RestrictAnonymous" -Type REG_DWORD -Value 1`

# Ensure 'Accounts: Limit local account use of blank passwords to console logon only' is set to 'Enabled'
`Set-GPRegistryValue -Name "" -Key "HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Control\\Lsa" -ValueName "LimitBlankPasswordUse" -Type  -Value 1`

# Ensure 'Audit: Shut down system immediately if unable to log security audits' is set to 'Disabled'
`Set-GPRegistryValue -Name "" -Key "HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Control\\Lsa" -ValueName "CrashOnAuditFail" -Type  -Value 0`

# Ensure 'Devices: Prevent users from installing printer drivers' is set to 'Enabled'
`Set-GPRegistryValue -Name "" -Key "HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Control\\Print\\Providers\\LanMan Print Services\\Servers" -ValueName "AddPrinterDrivers" -Type  -Value 1`

# Ensure 'Domain member: Digitally encrypt or sign secure channel data (always)' is set to 'Enabled'
`Set-GPRegistryValue -Name "" -Key "HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services\\Netlogon\\Parameters" -ValueName "RequireSignOrSeal" -Type  -Value 1`

# Ensure 'Domain member: Digitally encrypt secure channel data (when possible)' is set to 'Enabled'
`Set-GPRegistryValue -Name "" -Key "HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services\\Netlogon\\Parameters" -ValueName "SealSecureChannel" -Type  -Value 1`

# Ensure 'Domain member: Digitally sign secure channel data (when possible)' is set to 'Enabled'
`Set-GPRegistryValue -Name "" -Key "HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services\\Netlogon\\Parameters" -ValueName "SignSecureChannel" -Type  -Value 1`

# Ensure 'Domain member: Disable machine account password changes' is set to 'Disabled'
`Set-GPRegistryValue -Name "" -Key "HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services\\Netlogon\\Parameters" -ValueName "DisablePasswordChange" -Type  -Value 0`

# Ensure 'Domain member: Require strong (Windows 2000 or later) session key' is set to 'Enabled'
`Set-GPRegistryValue -Name "" -Key "HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services\\Netlogon\\Parameters" -ValueName "RequireStrongKey" -Type  -Value 1`

# Ensure 'Interactive logon: Do not require CTRL+ALT+DEL' is set to 'Disabled'
`Set-GPRegistryValue -Name "" -Key "HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System" -ValueName "DisableCAD" -Type  -Value 0`

# Ensure 'Interactive logon: Prompt user to change password before expiration' is set to 'between 5 and 14 days'
`Set-GPRegistryValue -Name "" -Key "HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon" -ValueName "PasswordExpiryWarning" -Type  -Value 14 <- check if this number is right :)`

# Ensure 'Microsoft network client: Digitally sign communications (if server agrees)' is set to 'Enabled'
`Set-GPRegistryValue -Name "" -Key "HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services\\LanmanWorkstation\\Parameters" -ValueName "EnableSecuritySignature" -Type  -Value 1`

# Ensure 'Microsoft network client: Send unencrypted password to third-party SMB servers' is set to 'Disabled' <- LMAO WHY BRO WHY?
`Set-GPRegistryValue -Name "" -Key "HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services\\LanmanWorkstation\\Parameters" -ValueName "EnablePlainTextPassword" -Type  -Value 0`

# Ensure 'Microsoft network server: Amount of idle time required before suspending session' is set to '15 or fewer minute(s), but not 0'
`Set-GPRegistryValue -Name "" -Key "HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services\\LanManServer\\Parameters" -ValueName "AutoDisconnect" -Type  -Value 0`

# Ensure 'Microsoft network server: Digitally sign communications (always)' is set to 'Enabled'
`Set-GPRegistryValue -Name "" -Key "HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services\\LanManServer\\Parameters" -ValueName "RequireSecuritySignature" -Type  -Value 1`

# Ensure 'Microsoft network server: Digitally sign communications (if client agrees)' is set to 'Enabled'
`Set-GPRegistryValue -Name "" -Key "HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services\\LanManServer\\Parameters" -ValueName "RequireSecuritySignature" -Type  -Value 1`

# Ensure 'Network access: Do not allow anonymous enumeration of SAM accounts' is set to 'Enabled'
`Set-GPRegistryValue -Name "" -Key "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Lsa" -ValueName "RestrictAnonymousSAM" -Type  -Value 1`

# Ensure 'Network access: Let Everyone permissions apply to anonymous users' is set to 'Disabled'
`Set-GPRegistryValue -Name "" -Key "HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Control\\Lsa" -ValueName "EveryoneIncludesAnonymous" -Type  -Value 0`

# Ensure 'Network access: Restrict anonymous access to Named Pipes and Shares' is set to 'Enabled'
`Set-GPRegistryValue -Name "" -Key "HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services\\LanManServer\\Parameters" -ValueName "RestrictNullSessAccess" -Type  -Value 1`

# Ensure 'Network access: Sharing and security model for local accounts' is set to 'Classic - local users authenticate as themselves'
`Set-GPRegistryValue -Name "" -Key "HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Control\\Lsa" -ValueName "ForceGuest" -Type  -Value 0`

# Ensure 'Network security: Do not store LAN Manager hash value on next password change' is set to 'Enabled'
`Set-GPRegistryValue -Name "" -Key "HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Control\\Lsa" -ValueName "NoLMHash" -Type  -Value 1`

# Ensure 'Network security: LDAP client signing requirements' is set to 'Negotiate signing' or higher
`Set-GPRegistryValue -Name "" -Key "HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services\\LDAP" -ValueName "LDAPClientIntegrity" -Type  -Value 1`

# Ensure 'System objects: Require case insensitivity for non-Windows subsystems' is set to 'Enabled'
`Set-GPRegistryValue -Name "" -Key "HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Control\\Session Manager\\Kernel" -ValueName "ObCaseInsensitive" -Type  -Value 1`

# Ensure 'System objects: Strengthen default permissions of internal system objects (e.g. Symbolic Links)' is set to 'Enabled'
`Set-GPRegistryValue -Name "" -Key "HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Control\\Session Manager" -ValueName "ProtectionMode" -Type  -Value 1`

# Ensure DCOM is enabled
`Set-GPRegistryValue -Name "" -Key "HKEY_LOCAL_MACHINE\\Software\\Microsoft\\OLE" -ValueName "EnableDCOM" -Type  -Value Y`

# Ensure Automatic Logon is disabled
Not sure if what I did here was right
`Set-GPRegistryValue -Name "" -Key "HKLM\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon" -ValueName "DefaultPassword" -Type  -Value Y
Set-GPRegistryValue -Name "" -Key "HKLM\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon" -ValueName "AutoAdminLogon" -Type  -Value 0`

# Ensure Winpcap packet filter driver is not present
If this returns true then Winpcap is present. This could be a sign of wireshark or other network sniffing tools.
`Test-Path -Path "%WINDIR%\\Sysnative\\drivers\\npf.sys" -PathType Leaf
Test-Path -Path "%WINDIR%\\System32\\drivers\\npf.sys"  -PathType Leaf`

# Ensure 'Devices: Allowed to format and eject removable media' is set to 'Administrators'
`Set-GPRegistryValue -Name "" -Key "HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon" -ValueName "AllocateDASD" -Type  -Value 0`

# Ensure 'Network access: Shares that can be accessed anonymously' is set to 'None'
`Set-GPRegistryValue -Name "" -Key "HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services\\LanManServer\\Parameters" -ValueName "NullSessionShares" -Type REG_MULTI_SZ -Value \\. <- might be wrong`

# Ensure 'Network security: LAN Manager authentication level' is set to 'Send NTLMv2 response only. Refuse LM & NTLM'
`Set-GPRegistryValue -Name "" -Key "HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Control\\Lsa" -ValueName "LmCompatibilityLevel" -Type  -Value 5`

# Ensure 'Windows Firewall: Private: Firewall state' is set to 'On'
`Set-GPRegistryValue -Name "" -Key "HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\WindowsFirewall\\PrivateProfile" -ValueName "EnableFirewall" -Type  -Value 1`

# Ensure 'Windows Firewall: Public: Firewall state' is set to 'On'
`Set-GPRegistryValue -Name "" -Key "HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\WindowsFirewall\\PublicProfile" -ValueName "EnableFirewall" -Type  -Value 1`

# Ensure Registry tools set is enabled
`Set-GPRegistryValue -Name "" -Key "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System" -ValueName "DisableRegistryTools" -Type  -Value 0`

# Ensure LM authentication is not allowed (disable weak passwords)
Didnt know what to do with this one because registry key was very similar to a previous one

# Ensure Firewall/Anti Virus notifications are enabled
`Set-GPRegistryValue -Name "" -Key "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Security Center" -ValueName "FirewallDisableNotify" -Type  -Value 0
Set-GPRegistryValue -Name "" -Key "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Security Center" -ValueName "antivirusoverride" -Type  -Value 0
Set-GPRegistryValue -Name "" -Key "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Security Center" -ValueName "firewalldisablenotify" -Type  -Value 0
Set-GPRegistryValue -Name "" -Key "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Security Center" -ValueName "firewalldisableoverride" -Type  -Value 0`

# Ensure Microsoft Firewall is enabled
`Set-GPRegistryValue -Name "" -Key "HKEY_LOCAL_MACHINE\\software\\policies\\microsoft\\windowsfirewall\\domainprofile" -ValueName "enablefirewall" -Type  -Value 1`

# Ensure Turn off Windows Error reporting is enabled
`Set-GPRegistryValue -Name "" -Key "HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\PCHealth\\ErrorReporting" -ValueName "DoReport" -Type  -Value 0
Set-GPRegistryValue -Name "" -Key "HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\Windows Error Reporting" -ValueName "Disabled" -Type  -Value 1`

# Ensure 'MSS: (AutoAdminLogon) Enable Automatic Logon (not recommended)' is set to 'Disabled'
`Set-GPRegistryValue -Name "" -Key "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon" -ValueName "AutoAdminLogon" -Type  -Value 0`

# Ensure 'MSS: (DisableIPSourceRouting IPv6) IP source routing protection level (protects against packet spoofing)' is set to 'Enabled: Highest protection, source routing is completely disabled'
`Set-GPRegistryValue -Name "" -Key "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\Tcpip6\\Parameters" -ValueName "DisableIPSourceRouting" -Type  -Value 2`

# Ensure 'MSS: (DisableIPSourceRouting) IP source routing protection level (protects against packet spoofing)' is set to 'Enabled: Highest protection, source routing is completely disabled'
`Set-GPRegistryValue -Name "" -Key "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters" -ValueName "DisableIPSourceRouting" -Type  -Value 2`

# Ensure 'MSS: (SafeDllSearchMode) Enable Safe DLL search mode (recommended)' is set to 'Enabled'
`Set-GPRegistryValue -Name "" -Key "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Session Manager" -ValueName "SafeDllSearchMode" -Type  -Value 1`

# Ensure 'MSS: (ScreenSaverGracePeriod) The time in seconds before the screen saver grace period expires (0 recommended)' is set to 'Enabled: 5 or fewer seconds'
`Set-GPRegistryValue -Name "" -Key "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon" -ValueName "ScreenSaverGracePeriod" -Type  -Value 0`

# Ensure 'MSS: (WarningLevel) Percentage threshold for the security event log at which the system will generate a warning' is set to 'Enabled: 90% or less'
SOC Team can change this if they dont wanna look through too many logs. 
`Set-GPRegistryValue -Name "" -Key "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\Eventlog\\Security" -ValueName "WarningLevel" -Type  -Value 90`

# Ensure 'Configure registry policy processing: Do not apply during periodic background processing' is set to 'Enabled: FALSE'
`Set-GPRegistryValue -Name "" -Key "HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\Group Policy\\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}" -ValueName "NoBackgroundPolicy" -Type  -Value 0`

# Ensure 'Turn off downloading of print drivers over HTTP' is set to 'Enabled'
`Set-GPRegistryValue -Name "" -Key "HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Printers" -ValueName "DisableWebPnPDownload" -Type  -Value 1`

# Ensure 'Turn off Internet download for Web publishing and online ordering wizards' is set to 'Enabled'
`Set-GPRegistryValue -Name "" -Key "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer" -ValueName "NoWebServices" -Type  -Value 1`

# Ensure 'Turn off printing over HTTP' is set to 'Enabled'
`Set-GPRegistryValue -Name "" -Key "HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Printers" -ValueName "DisableHTTPPrinting" -Type  -Value 1`

# Ensure 'Configure Offer Remote Assistance' is set to 'Disabled'
`Set-GPRegistryValue -Name "" -Key "HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services" -ValueName "fAllowUnsolicited" -Type  -Value 0`

# Ensure 'Configure Solicited Remote Assistance' is set to 'Disabled'
`Set-GPRegistryValue -Name "" -Key "HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services" -ValueName "fAllowToGetHelp" -Type  -Value 0`

# Ensure 'Turn off Autoplay' is set to 'Enabled: All drives'
`Set-GPRegistryValue -Name "" -Key "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer" -ValueName "NoDriveTypeAutoRun" -Type  -Value 255`

# Ensure 'Do not allow passwords to be saved' is set to 'Enabled'
`Set-GPRegistryValue -Name "" -Key "HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services" -ValueName "DisablePasswordSaving" -Type  -Value 1`

# Ensure 'Do not allow drive redirection' is set to 'Enabled'
`Set-GPRegistryValue -Name "" -Key "HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services" -ValueName "fDisableCdm" -Type  -Value 1`

# Ensure 'Always prompt for password upon connection' is set to 'Enabled'
`Set-GPRegistryValue -Name "" -Key "HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services" -ValueName "fPromptForPassword" -Type  -Value 1`

# Ensure 'Set client connection encryption level' is set to 'Enabled: High Level'
`Set-GPRegistryValue -Name "" -Key "HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services" -ValueName "MinEncryptionLevel" -Type  -Value 3`

# Ensure 'Always install with elevated privileges' is set to 'Disabled'
`Set-GPRegistryValue -Name "" -Key "HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer" -ValueName "AlwaysInstallElevated" -Type  -Value 0`

# Ensure 'Configure Automatic Updates' is set to 'Enabled'
`Set-GPRegistryValue -Name "" -Key "HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate\\AU" -ValueName "NoAutoUpdate" -Type  -Value 0`

# Ensure 'No auto-restart with logged on users for scheduled automatic updates installations' is set to 'Disabled'
`Set-GPRegistryValue -Name "" -Key "HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate\\AU" -ValueName "NoAutoRebootWithLoggedOnUsers" -Type  -Value 0`

# Ensure 'MSS: (TcpMaxDataRetransmissions IPv6) How many times unacknowledged data is retransmitted' is set to 'Enabled: 3'
`Set-GPRegistryValue -Name "" -Key "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\TCPIP6\\Parameters" -ValueName "TcpMaxDataRetransmissions" -Type  -Value 3`

# Ensure 'MSS: (TcpMaxDataRetransmissions) How many times unacknowledged data is retransmitted' is set to 'Enabled: 3'
`Set-GPRegistryValue -Name "" -Key "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters" -ValueName "TcpMaxDataRetransmissions" -Type  -Value 3`

# Ensure 'Turn off Search Companion content file updates' is set to 'Enabled'
`Set-GPRegistryValue -Name "" -Key "HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\SearchCompanion" -ValueName "DisableContentFileUpdates" -Type  -Value 1`

# Ensure 'Turn off the "Publish to Web" task for files and folders' is set to 'Enabled'
`Set-GPRegistryValue -Name "" -Key "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer" -ValueName "NoPublishingWizard" -Type  -Value 1`

# Ensure 'Turn off the Windows Messenger Customer Experience Improvement Program' is set to 'Enabled'
`Set-GPRegistryValue -Name "" -Key "HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Messenger\\Client" -ValueName "CEIP" -Type  -Value 2`

# Ensure 'Turn off Windows Error Reporting' is set to 'Enabled'
`Set-GPRegistryValue -Name "" -Key "HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\Windows Error Reporting" -ValueName "Disabled" -Type  -Value 1`

# Ensure 'Enable RPC Endpoint Mapper Client Authentication' is set to 'Enabled'
`Set-GPRegistryValue -Name "" -Key "HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Rpc" -ValueName "EnableAuthEpResolution" -Type  -Value 1`

# Ensure 'Restrict Unauthenticated RPC clients' is set to 'Enabled: Authenticated'
`Set-GPRegistryValue -Name "" -Key "HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Rpc" -ValueName "RestrictRemoteClients" -Type  -Value 1`

You've been pepe'd LMAO, type "poggers" in chat 50 times so peepo comes to ur house
⣿⠿⣛⣯⣭⣭⣭⣭⣭⣭⣥⣶⣶⣶⣶⣶⣮⣭⣭⣭⣭⣭⡛⢻⣿⣿⣿⣿⣿⣿⣿
⡇⣾⣿⣿⣿⣿⣿⠿⢛⣯⣭⣭⣷⣶⣶⣶⣶⣶⣶⣶⣶⣬⣭⢸⣿⣿⣿⣿⣿⣿⣿
⢰⣶⣶⣶⣶⣶⢰⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⢸⣿⣿⣿⣿⣿⣿⣿
⡏⣿⣿⣿⣿⣿⢸⣿⣿⣿⣿⡿⢋⣩⠭⠭⡙⢋⣭⠶⠒⠒⢍⡘⠻⣿⣿⣿⣿⣿⣿
⡇⣿⣿⣿⣿⣿⢸⣿⣿⡿⣋⣴⣯⡴⠚⠉⡡⠤⢄⣉⣅⡤⠄⢀⢺⡌⣻⣿⣿⣿⣿
⡇⣿⣿⣿⣿⣿⢸⣿⡏⡆⣿⣿⣉⣐⢴⣿⠈⠈⢀⠟⡿⠷⠄⢠⢎⢰⣿⣿⣿⣿⣿
⡇⣿⣿⣿⣿⣿⢸⣿⢸⣿⣿⣿⡫⣽⣒⣤⠬⠬⠤⠭⠭⢭⣓⣒⡏⣾⣿⣿⣿⣿⣿
⡇⣿⣿⣿⣿⣿⢸⡿⢸⣿⣿⣿⣿⣷⣾⣾⣭⣭⣭⣭⣭⣵⣵⡴⡇⠉⠹⣿⣿⣿⣿
⡇⣿⣿⣿⣿⣿⢸⠠⠄⠉⠉⠛⠛⠛⠛⠛⠊⠉⠉⠉⠉⠁⠄⠄⠄⠠⢤⡸⣿⣿⣿
⢇⡻⠿⣿⣿⣿⠘⣠⣤⣤⣀⡚⠿⢦⣄⡀⠤⠤⠤⣤⣤⣤⣤⣤⣤⣄⣘⠳⣭⢻⣿
⣎⢿⣿⣶⣬⣭⣀⠛⢿⣿⣿⣿⣷⣶⣬⣙⡳⠟⢗⣈⠻⠛⠛⠛⠛⢿⣿⣿⣦⢸⣿
⣿⣆⢿⣿⣿⣿⣽⣛⣲⠤⠤⢤⣤⣤⣤⣀⡙⣿⣿⣿⠇⣤⣤⣤⡶⢰⣿⣿⠃⣼⣿
⣿⣿⣆⢿⣿⣿⣿⣿⣿⣿⣿⣿⣶⣶⣶⣶⡖⣸⣿⡟⣠⣶⣶⡖⣠⣿⡿⣡⣾⣿⣿
⣿⣿⣿⢸⣿⣿⣿⣿⣿⣿⣿⣽⣛⣛⡻⣿⠇⣿⣿⠃⣿⣟⡭⠁⣿⣯⣄⢻⣿⣿⣿
⣿⣿⣿⢸⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡇⣿⣷⣭⣙⠗⣸⣿⡇⣾⣮⣙⡛⣸⣿⣿⣿
puh puh POG 

# Links
https://4sysops.com/archives/administering-group-policy-with-powershell/
