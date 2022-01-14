# important
import-moduleActiveDirectory

# Setting Group Policy Register Values
Set-GPRegistryValue -Name "" -Key "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System" -ValueName "DontDisplayLastUserName" -Type REG_DWORD -Value 1

Set-GPRegistryValue -Name "" -Key "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" -ValueName "ScRemoveOption" -Type REG_SZ -Value 1

Set-GPRegistryValue -Name "" -Key "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\LanmanWorkstation\Parameters" -ValueName "RequireSecuritySignature" -Type REG_DWORD -Value 1

Set-GPRegistryValue -Name "" -Key "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa" -ValueName "DisableDomainCreds" -Type REG_DWORD -Value 1

# Links
https://4sysops.com/archives/administering-group-policy-with-powershell/
