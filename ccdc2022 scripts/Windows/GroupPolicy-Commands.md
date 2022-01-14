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

# Links
https://4sysops.com/archives/administering-group-policy-with-powershell/
