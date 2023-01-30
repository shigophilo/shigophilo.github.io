---
title: "LINUX基础"
date: 2020-03-25 11:56:23 +0800
category: LINUX
tags: [linux]
excerpt: linux基础命令
---
# 基础命令

## 服务管理

### systemctl   redhat7
  `systemctl start foo.service`	启动服务
  `systemctl restart foo.service`	重启服务
  `systemctl stop foo.service`	停止服务
  `systemctl reload foo.service`	不重启服务下重新加载配置文件
  `systemctl status foo.service`	查看服务状态
  `systemctl enable foo.service`	设置服务开机自动启
  `systemctl disable foo.service`	设置服务开机不启动
  `systemctl is-ebabled foo.service`	查看服务是否开机自启
  `systemctl list-unit-files --type=service`	查看各个界别下的服务的启动与禁用情况

## 常用命令
### man
```shell
man [数字] 命令|配置文件		获取命令,配置文件的帮助信息
```
### whatis
```shell
whatis 命令	查看命令帮助信息中的NAME字段
````
### help
```shell
help 命令		获取shell内置命令的帮助信息,which等命令找不到路径的命令都是shell内置命令(bash)
```
### apropos
```shell
apropos 配置文件信息	查看配置文件信息中的name字段
```
### echo
  `echo 字符`	输出字符
  `echo $变量`	输出变量
### date
  `date`	查看系统当前时间
  `date "+%Y-%m-%d %H:%M:%S"`	按照年月日小时分钟秒格式
  `date -s "20190101 8:30:00"`	设置当前日期为2019年1月1日8:30分

### reboot
  `reboot`	重启
### shutdown
```shell
shutdown [选项] 时间	关闭
-c	取消前一个关机命令
-h	关机 now.马上关机	20:20定时关机	
-r	重启
```
### halt 
```shell

```
### init 
> 系统运行级别	/etc/inittab
```shell
0	关机
1	单用户
2	不完全多用户,不含NFS服务
3	完全多用户
4	未分配
5	图形界面
6	重启
```
### runlevel
`runlevel`	查询系统的运行级别

### logout
`logout`	退出登陆

### poweroff
  `poweroff`	关机
### ps
  ```
  -a	显示所有进程,包括其他用户的进行
  -u	用户以及其它详细信息
  -x	显示没有控制终端的进程
  ```
### top

`top`	动态监视进程活动与系统负载等信息,类似windows任务管理器

### pidof
`pidof [参数] [服务名]`	查询服务进程的PID值
|参数|解释|
|----|----|
|-s|仅返回一个进程号|
|-c|仅显示具有相同“root”目录的进程|
|-x|显示由脚本开启的进程|
|-o|指定不显示的进程ID|

### kill & killall

`kill [参数] [进程ID]`	终止某个pid的服务进程
`kiliall [参数] [服务名称]`	终止某个指定名称的服务所对应的全部进程,类似windows任务管理器的结束进程树

### alias
`alias rm='rm -i'`	定义一个命令的别名
### write
```shell
write 用户名		给在线用户发信
Ctrl+D	保存并发送
```
### wall
```shell
wall [发送信息]		给所有在线用户发送广播信息
```
### ping
```shell
ping [选项] ip地址
-c num	指定ping的次数
```
### mail
```shell
mail [用户名]		直接mail是收信,mail 用户名是给用户发信
Ctrl+D 保存发送
h	返回邮件列表
d num	删除邮件
q	退出
```
## 系统状态检测命令
### ifconfig
```shell
ifconfig [网络设备] [参数]		获取网卡配置与网络状态等信息
ifconfig 网卡名 IP地址		给网卡设置IP地址,临时生效,重启失效
ifconfig 网卡名:1 IP地址		增加虚拟网卡,绑定多个IP
```
### uname
`uname [-a]`	查看系统名称,系统内核,主机名,内核发型版本,节点名,系统时间,硬件名称,硬件平台,处理器类型,操作系统名称等

### uptime
`uptime`	查看系统的负载信息

### free

`free [-h]`	显示系统内存的使用量

### who
`who [参数]`	查看当前登陆主机的用户终端信息
格式:登陆的用户名	登陆终端(tty本地,pts远程终端)	登陆时间	登陆的主机地址

### w
`w [参数] [用户名]`		显示目前登入系统的用户信息

### last
`last [参数]`	查看所有系统的登陆记录

### lastlog

```shell
lastlog [选项] [用户]		显示所有系统用户的最后登陆信息
-u uid		查看指定用户的最后登陆信息
```
### setup
```shell
setup	配置网络
```
### netstat
```shell
netstat [选项]	显示网络相关信息
-t	tcp协议
-u	udp协议
-l	监听
-r	路由
-n	显示ip地址和端口号
netstat -an	查看本机所有的网络连接
netstat -tlun	查看本机监听的端口
netstat -rn	查看本机路由表
```
### traceroute
`traceroute ip|域名`	显示数据包到主机间的路径,windows中的tracert

### history

`history [参数]`	显示历史执行过的命令 -c 删除历史命令记录

### sosreport
`sosreport`	收集系统配置和架构信息并输出诊断文档
## 工作目录切换
### pwd
`pwd`	显示用户当前所处的工作目录
### cd
```
cd [目录名称]	切换工作路径
cd -	切换上一个目录
cd ~	切换到家目录
cd ~username	切换到username的家目录
```
### ls
文件类型(d目录,l软链接,-文件) 权限(ugo) 引用计数(链接) 所有者 所属组 文件大小(字节) 文件最后修改时间
```
ls [选项] [文件]	显示目录文件信息
ls -a	all,查看全部文件,包括隐藏文件
ls -d	查看目录属性
ls -l	long,查看详细信息
ls -h	显示容易阅读的文件大小
ls -i	查看文件的i节点
```
## 文本文件编辑命令
### cat
```
cat [参数] [文件名]	查看内容较少的纯文本文件
cat -n	显示行号
```
### tac
`tac 文件`	倒着显示文本,cat的倒着写
### more
`more [选项] 文件`	查看内容较多的纯文本文件
|快捷键|功能|
|----|----|
|Q\|q|退出|
|enter|换行|
|空格\f|翻页|
### less
`less 文件名`	分页显示文件内容

|快捷键|功能|
|----|----|
|enter|换行|
|空格\f|翻页|
|向上箭头|向上换行|
|/关键词|搜索关键词|
|n|下一个搜索的关键词|
|pageup|向上翻页|
### head
```
head [选项] [文件]		查看纯文本文档的前N行
head -n 20 [文件名]	查看前20行
```
### tail
```
tail [选项] [文件]		查看纯文本文件的后N行
tail -n 20 文件名		查看后20行
tail -f 文件名		持续刷新文件内容
```
### tr
```
tr [原始字符] [目标字符]	替换文本文件中的字符
cat 1.txt | tr a m		将1.txt中的a替换成m,实际文件中并没有改变,只在输出时改变
```
### wc
```
wc [参数] 文本		统计指定文本的行数
wc -l		只显示行数
wc -w		只显示单词数
wc -c		只显示字节数
```
### stat
`stat 文件名`	查看文件的具体存储信息和时间等信息
|状态|解释|
|----|----|
|Access|文件最后一次的访问时间|
|Modify|文件内容最后一次修改的时间|
|Change|文件属性信息的最后一次修改时间|
### cut
```
cut [参数] 文本	按列提取文本字符
-d	分隔符
-f	取的列数
cut -d: -f1 /etc/passwd	提取passwd文件中的第一列(用户名)信息
```
### diff
```
diff [参数] 文件...	比较多个文本文件的差异
--brief	比较两个文件是否相同
	diff --brief 1.txt 2.txt
-c	详细比较多个文件的差异之处
	diff -c 1.txt 2.txt
```
### ln
> 硬链接相当于 cp -p + 同步更新
> 通过i节点判断软硬链接,软链接在ls -l时会有箭头指向->
> 硬链接不能针对目录创建,不能跨分区创建
```shell
ln [参数] 源文件 目标文件
-s	创建软链接
```
### sed
> 利用脚本处理文本文件
`sed [选项] 'command' 文件`
|选项|作用||command|作用|
|----|----|----|----|----|
|-e|可以指定多个命令||a|新增|
|-f|指定命令文件||c|替换|
|-n|取消默认控制台输出,与p一起使用可以打印指定内容||d|删除|
|-i|输出到源文件,静默执行(修改源文件的意思)||i|插入|
||||p|打印,要和-n参数一起使用|
||||s|替换(匹配局部替换)|
>若不指定行号，则每一行都操作。
>$代表最后一行，双引号内的$代表使用变量。
|新增|a|
|----|----|
|sed '2a testcontent' test.txt|在第2行后面新增一行内容|
|sed '1,3a testcontent' text.txt|在原文的第1-3行后面各新增一行内容|
|替换|c|
|----|----|
|sed '2c testcontent' test.txt|将第2行内容正行替换|
|sed '1,3c testcontent' text.txt|将第1-3行内容替换成一行指定内容|
|删除|d|
|----|----|
|sed '2d' test.txt|删除第2行|
|sed '1,3d' text.txt|删除第1-3行|
|插入|i|
|----|----|
|sed '2i testcontent' test.txt|在第2行前面新增一行内容|
|sed '1,3a testcontent' text.txt|在原文的第1-3行后面各新增一行内容|
|打印|p|
|----|----|
|sed '2p' test.txt|重复打印第2行|
|sed '1,3p' text.txt|重复打印第1-3行|
|sed -n '2p' test.txt|只打印第 2 行|
|sed -n '1,3p' test.txt|只打印第 1~3 行|
|sed -n '/user/p' test.txt|打印匹配到user的行，类似grep|
|sed -n '/user/!p' test.txt|! 反选，打印没有匹配到user的行|
|sed -n 's/old/new/gp' test.txt|只打印匹配替换的行|
|替换| s|
|----|----|
|sed 's/old/new/' test.txt|匹配每一行的第一个old替换为new|
|sed 's/old/new/gi' test.txt|匹配所有old替换为new，g 代表一行多个，i 代表匹配忽略大小写|
|sed '3,9s/old/new/gi' test.txt|匹配第 3~9 行所有old替换为new|
|参数| -e|
|----|----|
|sed -e 's/系统/00/g' -e '2d' test.txt|执行多个指令|
|参数 |-f|
|----|----|
|sed -f ab.log test.txt|多个命令写进ab.log文件里，一行一条命令，效果同-e|
### touch
```
touch [选项] [文件...]	创建空白文件或设置文件时间
touch -a	修改文件读取时间(atime)
touch -m	修改文件修改时间(mtime)
touch -d "2019-09-01" 文件名	同时修改atime和mtime
```
## 文件目录管理
### mkdir
```
mkdir [选项] 目录名	创建空白目录
mkdir -p a/b/c	递归创建目录
```
### rmdir
`rmdir 目录名`		删除空目录
### cp
```
cp [选项] 源文件1,2,3 目标文件	复制文件或目录
cp -p	保留原始文件的属性
cp -d	若对象为链接文件,保留链接文件的属性
cp -r	递归复制(用于目录)
cp -i	如果目标文件存在,则询问是否覆盖
cp -a	相当于-pdr
```
### mv
`mv [选项] [源文件] [目标路径|目标文件名]	剪切文件或者文件重命名`
### rm
```
rm [选项] 文件	删除文件或目录
rm -f 文件	强制删除,不显示确认信息
rm -r 目录名	删除目录和目录里的文件
```
### dd
```
dd [参数]	按照指定大小和个数的数据块来复制文件或者转换文件
if	输入的文件名
of	保存的文件名
bs	设置每个块的大小
count	设置要复制块的个数
dd if=/ect/passwd of=newpass count 1 bs=560m	从passwd文件中取出一个560m的数据块,保存成newpass
dd if=/dev/cdrom of=redhat7.0.iso	将光驱设备中的光盘制作成iso格式的镜像文件
```
### file
`file [文件|目录]`	查看文件类型
## 打包压缩与搜索
### gzip
> 只能压缩文件,不能压缩目录
> 不保留源文件
> 默认后缀 .gz
```shell
gzip 文件名	压缩
-d 解压缩		解压缩
gunzip 压缩包	解压缩
```
### tar
> 压缩文件名 file.tar.gz 一般都是先tar然后gzip压缩,tar命令配合-z使用
```shell
tar [选项] [压缩后的文件名(配合-f使用)] [文件]		对文件压缩或解压
-c	创建压缩文件
-x	解压
-t	查看压缩包中文件
-z	用Gzip压缩或解压
-f	指定文件名(压缩或解压时都可以使用)
-j	用bzip2压缩或解压
-v	显示压缩和解压过程
-f	目标文件名
-P	保留原始权限和属性
-p	使用绝对路径来压缩
-C	指定解压到目录
tar -czvf 文件名.gz 打包目录	将目录使用Gzip方式打包
tar -xzvf 压缩包 -C 解压目录	将压缩包解压到指定目录
```
### zip
```shell
zip [选项] [压缩后的文件名] [文件或目录]	压缩文件或目录
-r	压缩目录
```
### unzip
```shell
unzip [压缩文件]	解压zip文件
```
### bzip2
```shell
bzip2 [选项] [文件]		压缩文件
-k	压缩后保留源文件
```
### grep
```shell
grep [选项] [文件]	在文本中执行关键词搜索并显示匹配的结果
-b	将可执行文件(binary)当作文本文件来搜索
-c	仅显示找到的行数
-i	忽略大小写
-n	显示行号
-v	反向选择--仅列出没有关键词的行
grep 1111 1.txt	在1.txt中搜索1111
```
### find
```shell
find [查找路径] 寻找条件 操作	按照指定条件查找文件
-name	匹配名称
-iname	不区分大小写
-perm	匹配权限(mode为完全匹配,-mode为包含即可)
-user	匹配所有者
-group	匹配所有组
-mtine -n +n	匹配修改内容的时间(-n是n天以内,+n是n天以前)
-atime -n +n	匹配访问文件的时间
-ctime -n +n	匹配修改文件权限的时间
-nouser	匹配无所有者的文件
-nogroup	匹配无所有组的文件
-newer f1 f2	匹配比文件f1新但是比f2旧的文件
-a	两个条件同时满足 find / -size+1600 -a -size -2000
-o	两个条件满足一个即可
--type b/d/v/p/l/f	匹配文件类型(块设备/目录/字符设备/管道/链接文件/文本文件)
-inum	根据i节点查找
-size	匹配文件大仙(+50k是查找超过50k的文件,-50k是查找小于50k的文件,50是等于50k)
-prune	忽略某个目录
-exec …… {} \;	后面跟用于进一步处理搜索结果的命令 find / -name inittab -exec ls {} \;
-ok …… {} \;	询问是否执行,后面跟用于进一步处理搜索结果的命令 find / -name inittab -ok ls {} \;
find /etc -name "host*"	搜索etc目录下所有以host开头的文件
find / -perm -4000	搜索整个系统中权限中包括SUID权限的所有文件
find / -user mrhonest -exec cp -a {} /root/findfile/ \;	在整个文件系统中找出所有归属于mrhonest用户的文件并复制到root/findfile目录,({}表示find命令搜索出的每一个文件)
```
### locate
````shell
locate 文件名		搜索文件,基于资料库查找文件,/tmp等临时文件目录的文件不会更新到资料库中
-i	不区分大小写
updatedb	更新资料库,此命令直接使用,updatedb不是参数
````
### which
```shell
which 命令		搜索命令所在目录及别名信息
```
### whereis
```shell
whereis 命令		搜索命令所在目录及帮助信息位置
```
# 管道符,重定向,环境变量
## 输入输出重定向
> 标准输入重定向(STDIN,文件描述符为0):默认从键盘输入,也可以从其它文件或者命令中输入
> 标准输出重定向(STDOUT,文件描述符为1):默认输出到屏幕
> 错误输出重定向(STDERR,文件描述符为2):默认输出到屏幕
>
> -  输入重定向
```
命令 < 文件	将文件作为命令的标准输入
命令 << 分界符	从标准输入中读入,知道遇见分界符才停止
命令 < 文件1 > 文件2	将文件1作为命令的标准输入并将标准输出到文件2
wc -w < 1.txt	把1.txt中的内容交给wc统计
```
- 输出重定向
```
命令 > 文件	将标准输出重定向到一个文件中(清空原有的文件数据)
命令 2> 文件	将错误输出重定向到一个文件中(清空原有文件的数据)
命令 >> 文件	将标准输出重定向到一个文件中(追加到原有的内容后面)
命令 2>> 文件	将错误输出重定向到一个文件中(追加到原有的内容后面)
命令 >> 文件 2>&1	将标准输出与错误输出共同写入到文件中(追加到原来的内容后面)
命令 &>> 文件	同上,将标准输出与错误输出共同写入到文件中(追加到原来的内容后面)
```
## 管道命令符
+ |	将前一个命令原本要输出到屏幕的标准正常数据当作最后一个命令的标准输入
```
grep "/sbin/nologin" /etc/passwd | wc -l	统计被限制登陆用户的数量
ls -l /etc | more	用翻页的形式查看/etc下的文件列表信息
echo "111111" | passwd --stdin root	一条命令修改root用户密码
```
## 命令行的通配符
```
*	匹配多个字符
	?	匹配单个字符
	[0-9]	匹配0-9之间的单个数字字符
	[abc]	匹配a,b,c单个字符
	[a-z]	匹配a-z的单个字符
```
## 常用转义字符
```
\	反斜杠:后面的变量变为单纯的字符串
''	单引号:转义其中所有的变量为单纯的字符串
""	双引号:保留其中的变量属性,不进行转义处理
``	反引号:把其中的命令执行后返回给结果
```

```
mrhonest = 5	定义变量
echo "$mrhonest"	输出变量
echo '$mirhonest'	输出$mrhonest
```
## 重要的环境变量
```
HOME	用户的主目录
SHELL	用户在使用的shell解释器名称
HISTSIZE	输出的历史命令记录条数
HISTFILESIZE	保存的历史命令记录条数
MAIL	邮件保存路径
LANG	系统语言,语系名称
PANDOM	生成一个随机数字
PS1	Bash解释权的提示符
PATH	定义解释器搜索用户执行的命令路径
EDITOR	用户默认的文本编辑器
```

```
WORKDIR=/HOME/WORK	创建变量
export WORKDIR	提升为全局变量
```
# VIM与Shell命令脚本
## vim文本编辑器
+ 命令模式
```
i	输入模式,光标当前位置
a	输入模式,光标后以为
o	输入模式,光标下面插入一个空行
ESC	退出写入模式
```
+ 输入模式
```
dd	删除(剪切)光标所在的整行
5dd	删除(剪切)光标开始的5行
yy	复制光标所在的整行
5yy	复制光标处开始的5行
n	显示搜索命令定位到的下一个字符串
N	显示搜索命令定位到的上一个字符串
u	撤销上一步的操作
p	将之前删除(dd)或复制(yy)过的数据粘贴到光标后面
```
+ 末行模式
```
:w	保存
:q	退出
:q!	强制退出(放弃对文档的修改内容)
:wq!	强制保存退出
:set nu	显示行号
:set nonu	不显示行号
:命令	执行该命令
:整数	跳转到该行
:s/one/two	将光标所在行的第一个one替换成two
:s/one/two/g	将光标所在行的所有one替换成two
:%s/one/two/g	将全文中的所有one替换成two
?字符串	在文本中从下至上搜索该字符串
/字符串	在文本中从上到下搜索该字符串
```
## 配置Yum软件仓库
## 编写Shell脚本
+ 运行

	`bash shell.sh`	执行sh脚本
+ 接收用户的参数
```
$0	当前shell脚本程序的名称
$#	参数的总数
$*	所有位置的参数值
%?	显示上一次命令的执行返回值
$N	第N个参数的值
```
+ 判断用户的参数

	测试语句格式 **[ 条件表达式 ]**	条件表达式两边均有一个空格	
> 文件测试语句
```
-d	测试文件是否为目录类型
-e	测试文件是否存在
-f	判断是否为一般文件
-r	测试当前用户是否具有权限读取
-w	测试当前用户是否具有权限写入
-x	测试当前用户是否具有权限执行
```
> 逻辑测试语句
```
&&	与
||	或
!	非
```
> 整数值比较语句
** 0 = true ** ** 非0的数字 = false **
```
-eq	是否等于
-ne	是否不等于
-gt	是否大于
-lt	是否小于
-le	是否等于或小于
-ge	是否大于或等于
```
> 字符串比较语句
```
=	比较字符串内容是否相同
!=	比较字符串内容是否不同
-z	判断字符串内容是否为空
```
### 流程控制语句
+ if条件测试语句
​```shell

	if	[ 表达式 ]
then

	如果表达式成立,执行
fi
```
​```shell
if	[ 表达式 ]
then
	如果表达式成立,执行
esle
	表达式不成立时,执行
fi
```
```shell
if	[ 表达式 ]
then
	如果表达式成立,执行
elif [ 表达式 ]
	表达式成立时,执行
else
	以上两个表达式均不成立时,执行
fi
```
+ for条件循环语句
```shell
for 变量名 in 取值列表
do
	命令序列
done
```
+ while条件循环语句
```shell
while 条件测试操作
do
	命令序列
done
```
+ case条件测试语句
```shell
case 变量值 in
模式1
	命令序列1
;;
模式2
	命令序列2
;;
	……
*)
esac
```
## 计划任务服务程序
+ 一次性计划任务:今晚23:30开启网站服务
```shell
at 23:30	设定任务时间
at>systemctl restart httpd	设定任务详情
at>Ctrl+D结束编写
at -l	查看任务
atrm 任务序号	删除任务
```
`echo "systemctl reatart httpd" | at 23:30`	一条命令建立任务
+ 周期性计划任务:每周一03:25分把/home/wwwroot目录打包备份为bacaup.tar.gz
```shell
crontab -e	创建,编辑周期任务
crontab -l	查看任务
crontab -u	编辑他人的计划任务
```
>分,时,日,月,星期,命令	任务格式
>8,9,12	设置月份,表示8月,9月,12月
>12-15	设置日期,表示12日到15日
>*/2	执行任务的间隔时间,每隔2分钟执行一次
>计划任务中的"分"字段必须有数值,不能空或者是*号,"日"和"星期"字段不能同时使用
```shell
usage:  crontab [-u user] file
        crontab [-u user] [ -e | -l | -r ]
                (default operation is replace, per 1003.2)
        -e      (edit user's crontab)
        -l      (list user's crontab)
        -r      (delete user's crontab)
        -i      (prompt before deleting user's crontab)
        -s      (selinux context)
```
`*/2 * * * * echo `date` >> $HOME>test.txt`	每隔2分钟输出时间到文件
# 用户身份与文件权限
## 用户身份与能力 
>管理员UID为0
>系统用户UID为1-999
>普通用户UID从1000开始
>用户组号码:GID
### useradd
```shell
useradd [选项] 用户名	创建新用户
-d	指定用户的家目录(默认为/home/username)
-e	账号到期时间,格式为:YYYY-MM-DD
-u	指定用户的默认UID
-g	指定一个初始的已存在的用户基本组
-G	指定一个或多个扩展用户组
-s	指定该用户默认的shell解释器
```
### groupadd

	`groupadd [选项] 组名	创建用户组`
### usermod

```shell
usermod [选项] 用户名	修改用户属性
-c	填写用户账户的备注信息
-d -m	-d和-m连用,可重新指定用户的家目录并自动吧旧的数据转移过去
-e	账户到期时间,格式为:YYYY-MM-DD
-g	变更所属用户组
-G	变更扩展用户组
-L	锁定该用户禁止其登陆系统
-U	解锁用户,允许登陆系统
-s	变更默认终端
-u	修改用户的UID
```
### passwd

```shell
passwd [选项] [用户名]	修改用户密码,过期时间,认证信息等 
-l	锁定用户,禁止登陆
-u	解锁用户,允许登陆
--stdin	允许通过标准输入修改用户密码,如 echo "newpassword" | passwd --stdin username
-d	用户可用空密码登陆系统
-e	强制用户在下次登录时修改密码
-S 显示用的密码是否呗锁定,以及密码所采用的加密算法名称
```
### userdel

```shell
userdel [选项] 用户名	删除用户
-f	强制删除用户
-r	同时删除用户及家目录
```
## 文件权限与归属
|代表符号|权限|对文件的含义|对目录的含义|
|----|----|----|----|
|r|读|可以查看文件内容|可以列出目录中的内容|
|w|写|可以修改文件内容|可以在目录中创建,删除文件|
|x|执行|可以执行文件|可以进入目录|
>-	:	普通文件
>	d	:	目录文件
>	l	:	链接文件
>	b	:	块设备文件
>	c	:	字符设备文件
>	p	:	管道文件
+ 权限分配 **文件所有者	文件所属组	其他用户**
>>r:4	读
>>w:2	写
>>x:1	执行
+ SUID
> SUID是一种对二进制程序进行设置的特殊权限,可以让二进制程序的执行者临时拥有属主的权限(仅对拥有执行权限的二进制程序有效)
+ SGID
> 让执行者临时拥有属组的权限(对拥有执行权限的二进制程序进行设置)
> 在某个目录中创建的文件自动继承该目录的用户组(只可以对目录进行设置)
+ SBIT
> 设置SBIT(粘滞位|保护位),可确保用户只能删除自己的文件
`chmod -R o+t 文件|文件夹`	设置SBIT特殊权限
### chmod
> -R	递归
```shell
chmod [参数] 权限 文件或目录名	设置文件或目录权限
chmod -R o+t 文件|文件夹	设置SBIT特殊权限
chmod [{ugoa}{+-=}{rwx}] 文件或目录
chmod u+w,g-w,o=rwx 文件或文件名
chmod mode=777 文件或目录
```
### chown
> -R	递归
> 只有管理员才可以执行
```shell
chown [参数] 所有者:所属组 文件或目录名	设置文件或目录的所有者和所属组
chown username 文件或目录	将目录的所有者改为username
```
### chgrp
```shell
chgrp [参数] 用户组 文件或目录	更改文件或目录的所属组
-R 递归
```
### umask
**默认新建的文件(非目录)没有x执行权限**
```shell
umask [参数] [缺省权限值]	显示,设置文件的缺省权限
-S	以rwx形式显示
## 文件的隐藏属性
+ chattr
​```shell
chattr [+|-][参数] 文件	设置文件的隐藏权限
i	无法对文件进行修改,若对美剧设置了该参数,则仅能修改其中的子文件内容,不能新建或删除文件
a	仅允许补充(追加)内容,无法覆盖/删除内容(Append Omy)
S	文件内容在变更后立即同步到硬盘(sync)
s	彻底从硬盘中删除,不可恢复(用0填充原文件所在硬盘区域)
A	不再修改这个文件或目录的最后访问时间(atime)
b	不再修改文件或目录的存取时间
D	检查压缩文件中的错误
d	使用dump命令备份时忽略本文件/目录
c	默认将文件或目录进行压缩
u	当删除该文件后依然保留其在硬盘中的数据,方便日后恢复
t	让文件系统支持尾部合并(tail-merging)
X	可以直接访问压缩文件中的内容
```
+ lsattr

	`lsattr [参数] 文件`	显示文件的隐藏权限
## 文件访问控制列表
+ setfacl

	setfacl [参数] 文件名称		管理文件的ACL(访问控制权限)规则
	-R	递归设置,针对目录
	-m	针对普通文件
	-b	删除ACL规则
	setcacl -Rm u:mrhonest:rwx /root	设置mrhonest对root目录的rwx权限
	dr-wrwx---**+**	+表示该文件已经设置了ACL
```
+ getfacl
`getfacl 文件名称`	显示文件上设置的ACL信息
## su和sudo
+ su
`su [-] 用户名`	切换用户身份,-代表把环境表里信息也变更为新用户的相应信息
+ sudo
​```shell
sudo [参数] 命令名称	给普通用户提供额外的权限来完成原本root管理员才能完成的任务
-h	列出帮助信息
-l	列出当前用户可执行的命令
-u用户名或UID值	以指定的用户身份执行命令
-k	情况密码的有效时间,下次执行sudo时需要再次进行密码认证
-b	在后台执行指定的命令
-p	更改询问密码的提示语
```
+ visudo
# 存储结构与磁盘划分
## 常见的目录名称以及相应内容
+ FHS
+ 绝对路径		以根目录开始
+ 相对路径		以当前路径开始
> /boot	开机所需文件--内核,开机菜单以及所需配置文件等
> /dev	以文件形式存放任何设备与接口
> /etc	配置文件,系统内所有采用默认安装方式的服务的配置文件全部保存在这个目录中,如用户账户密码,服务启动脚本,常用服务的配置文件等
> /home	用户家目录
> /bin	存放单用户模式下还可以操作的命令,所有用户均可以执行
> /sbin	保存和系统环境设置相关的命令,只有超级用户可以使用,部分命令普通用户允许查看
> /usr/bin	存放系统命令的目录,所有用户都可以执行,这些命令和系统启动无关,但是在单用户模式下不能执行
> /usr/sbin	存放根文件系统不必要的系统管理命令,例如多数服务程序
> /lib	开机过程中需要的命令,系统调用的函数库保存位置
> /media	用于挂在设备文件的目录,建议挂载软盘,光盘
> /opt	放置第三方的软件,不建议使用,建议安装到/usr/local中
> /root	系统管理员的家目录
> /srv		一些网络服务的数据文件目录,一些系统服务启动后,在这个目录保存所需的数据
> /tmp	任何人均可使用的"共享"临时目录
> /proc	虚拟文件系统,列入系统内核,进程,外部设备及网络状态等
> /usr/local	用户自行安装的软件
> /usr/sbin	linux系统开机时不会使用到的软件/命令/脚本
> /usr/share	帮助与说明文件,也可以放置共享文件
> /var	动态数据保存目录,主要存放动态变化的文件,如日志等
> /lost+found	当文件系统发生错误时,将一些丢失的文件片段存在在这里,这个目录只在每个分区中出现
> /mnt	挂载目录,建议挂载U盘,移动硬盘等
> /misc	挂载目录,建议挂载NFS服务的共享目录
> /proc	虚拟文件系统,存在内存中,存在硬件信息
> /sys	虚拟文件系统,存放内核相关信息
> /usr	系统软件资源目录,类似c:/windows文件夹
## 物理设备的命名规则
> IDE设备			/dev/hd[a-d]
> SCSI/STAT/U盘	/dev/sd/[a-p]
> 软驱			/dev/fd[0-1]
> 打印机			/dev/lp[0-15]
> 光驱			/dev/cdrom
> 鼠标			/dev/mouse
> 磁带机			/dev/st0或/dev/ht0
+ 主分区或扩展分区的编号从1开始到4结束
+ 逻辑分区从编号5开始
## 文件系统与数据资料
> Ext3	是一款日志文件系统,能够在系统异常宕机时避免文件系统资料丢失,并能自动修复数据的不一致与错误
> Ext4	Ext3的改进版本,支持的存数容量高达1EB,能够有无限多的子目录,Ext4文件系统能够批量分配block块,提高了读写效率
> XFS	是一种高性能的日志文件系统,最大支持存储容量18EB
>
+ super block	硬盘地图
## 挂载硬件设备
+ mount
```shell
mount 文件系统 挂载目录		挂载文件系统
-a	挂载所有在/etc/fstab中定义的文件系统
-t	指定文件系统的类型
mount /dev/sdb2 /backup	把设备/dev/sdb2挂载到/backup目录
```
+ etc/fstab

	** 设备文件	挂载目录	格式类型	权限选项	是否备份	是否自检**
> 设备文件	一般为设备的路径+设备名称,也可以写唯一的识别码(UUID)
> 挂载目录	指定要挂载到的目录,需挂载前创建好
> 格式类型	指定文件系统的格式,如Ext3,Ext4,XFS,SWAP,iso9600(光盘设备)等
> 权限选项	若设备为defaults,则默认权限问:rw,suid,dev,exec,auto,mouser,async
> 是否备份	若为1则开机后使用dump进行磁盘备份,为0则不备份
> 是否自检	若为1则开机后自动进行紫盘自检,为0则不自检
+ umount

	`umount [挂载点/设备文件]`	撤销已挂载设备文件,如`umount /dev/sdb2`
## 添加硬盘设备
+ fdisk
```shell
fdisk [磁盘名称]	管理磁盘分区
m		查看全部可用的参数
n		添加新的分区
d		删除某个分区信息
l		列出所有可用的分区类型
t		该表某个分区的类型
p		查看分区信息
w		保存并退出
q		不保存直接退出
```
+ mkfs.*

	`mkfs.* 磁盘名称`	按照*的文件系统格式格式化磁盘
+ du
```shell
du [选项] [文件]	查看文件数据占用量
du -sh /*			查看系统根目录下所有文件占用多大的硬盘空间
```
## 添加交换分区
```shell
mkswap 目录名		格式化交换分区
swapon 目录名		将SWAP分区挂载到系统中
```
## 磁盘容量配额
+ quota
> 软限制	当达到软限制时会提示用户,但仍允许用户在限定的额度内继续使用
> 硬限制	当达到硬限制时会提示用户,并强制终止用户的操作
+ xfs_quota
```shell
xfs_quota [参数] 配额 文件系统
-c	以参数的形式设置要执行的命令
-x	专家模式
xfs_quota -x -c 'limit bsoft=3m bhard=6m isoft=2 ihard=6 tom' /boot	设置用户tom对/boot目录容量的配额:软限制3MB,硬限制6MB,创建文件数量的软限制3个,硬限制6个
```
+ edquota
```shell
edquota [参数] [用户]	编辑用户的quota配额限制
-u	针对用户设置
-g	针对用户组设置
```
## 软链接 硬链接
> 硬链接(hard link)	"指向源文件inode的指针",不能跨分区对目录文件进行链接
> 软链接(符号链接[symbolic link])	仅包含链接文件的路径名,可跨文件系统进行链接+ in
> ```shell	
> in [选项] 目标 链接文件		创建链接文件
> -s		创建软链接"符号链接",不带-s参数默认创建硬链接
> -f		强制创建文件或目录链接
> -i		覆盖前询问
> -v		显示创建链接的过程
> ```
# 使用RAID与LVM磁盘阵列技术
## RAIL(独立冗余磁盘列阵)
### RAID 0
**RAIL 0技术能够有效的提升硬盘数据的吞吐速度,但不具备数据备份和错误修复能力**
### RAID 1
**将数据同时写入到多块硬盘设备上(镜像或备份),当其中某一块应硬盘发生故障后,一般立即自动以热交换的方式来恢复数据的正常使用**
### RAID 5
**把硬盘设备的数据奇偶校验信息保存到其它硬盘设备中**
### RAID 10
**RAID 1 + RAID 0的"组合体",该技术至少需要4块硬盘**
### 部署磁盘列阵
+ mdadm
```shell
mdadm [模式] <RAID设备名称> [选项] [成员设备名称]	管理linux系统中的软件RAID硬盘列阵
-a	检测设备名称
-n	指定设备数量
-l	指定RAID级别
-C	创建
-v	显示过程
-f	模拟设备损坏
-r	移除设备
-Q	查看摘要信息
-D	查看详细信息
-S	停止RAID磁盘列阵
```
```shell
mdadm -Cv /dev/md0 -a yes -n 4 -l 10 /dev/sdb /dev/sdc /dev/sdd /dev/sde	-C代表创建一个RAID阵列卡,-v显示创建过程,后面跟上设备名/dev/md0 ,-a yes代表自动创建设备文件,-n4 代表使用4块硬盘来部署这个RAID磁盘列阵,-l 10代表使用RAID 10方案,最后加上4块硬盘设备的名称
mkfs.ext4 /dev/md0	将制作好的RAID磁盘列阵格式化为ext4格式
mkdir /RAID	建立目录,创建挂载点
mount /dev/md0 /RAID	将硬盘设备进行挂载
mdadm -D /dev/md0	查看磁盘列阵的相信信息
echo "dev/md0 /RAID ext defaults 0 0" >> /etc/fatab	将挂载信息写入配置文件
```
### 损坏磁盘列阵及修复
```mdadm /dev/md0 -f /dev/sdb```	在磁盘阵列中移除/dev/sdb磁盘
### 磁盘列阵+备份盘
```
mdam -Cv /dev/md0 -n 3 -l 5 -x 1 /dev/sdb /dev/sdc /dev/sdd /dev/sde	创建RAID 5磁盘列阵+备份盘 ,-n 3代表创建这个列阵所需的硬盘数,-l 5代表列阵的级别,-x 1代表有一块备份盘
mlfs.ext4 /dev/md0	格式化
```
## LVM(逻辑卷管理器)
### 部署逻辑卷
**常用LVM部署命令**
|功能/命令|物理卷管理|卷组管理|逻辑卷管理|
|----|----|----|----|
|扫描|pvscan|vgscan|lvscan|
|建立|pvcreate|vgcreate|lvcreate|
|显示|pvdisplay|vgdisplay|lvdisplay|
|删除|pvremove|vgremove|lvremove|
|扩展| |vgextend|lvextend|
|缩小||vgreduce|lvreduce|
```shell
pvcreate /dev/sdb /dev/sdc	让新添加的凉快硬盘设备支持LVM技术
vgcreate storage /dev/sdb /dev/sdc	把两块硬盘设备加入到storage卷组中
lvcreate -n -vo -l 37 storage	切割出一个约为150MB的逻辑卷设备 -l 37等于-L 150M
msfs.ext4 /dev/storage/vo	把生成好的逻辑卷格式化
mount /dev/storage/vo 目录名	挂载
```
### 扩容逻辑卷
**扩容前记得卸载设备和挂载点的关联**
```shell
umount	目录名		卸载挂载
lvextend -L 290M /dev/storage/vo	将vo扩展至290MB
e2fsck -f /dev/storage/vo	检查硬盘完整性
resize2fs /dev/storage/vo	重置硬盘容量
mount -a	重新挂载即可
```
### 缩小逻辑卷
```shell
umount 目录名	卸载挂载
e2fsck -f /dev/storage/vo	检查硬盘完整性
resize2fs /dev/storage/vo 128M	把逻辑卷vo的容量减小到128MB
mount -a	挂载
```
### 逻辑卷快照
> 快照的容量必须等于逻辑卷的容量
> 快照仅一次有效,一旦执行怀远操作后则会立即自动删除
```shell
vgdisplay	查看卷组的信息
lvcreate -L 120M -s -n SNAP /dev/storage/vo	-s参数生产快照,-L指定大小
umount 目录名	先卸载挂载,此部是为了验证是否能恢复
lvconvert --merge /dev/storage/SNAP	恢复vo的快照
monut -a	重新挂载
```
### 删除逻辑卷
```shell
umonut 目录名	卸载挂载
vim /etc/fstab	编辑fatab文件,删除配置文件中永久生效的设备参数(挂载的设备)
lvremove /dev/storage/vo	删除逻辑卷设备,需要输入y来确认操作
vgremove storage	删除卷组,此处只写卷组名称即可,不需要设备的绝对路径
pvremove /dev/sdb /dev/sdc	删除物理卷设备
```
# iptables与firewalld防火墙
### iptables
### 策略与规则链
> 在进行路由选择前处理数据包(PRERPUTING)
> 处理流入的数据包(INPUT)
> 处理流出的数据包(OUTPUT)
> 处理转发的数据包(FORWARD)
> 在进行路由选择后处理数据包(POSTROUTING)
+ ACCEPT	允许流量通过
+ REJECT	拒绝流量通过,在拒绝流量后在回复一条"您的信息收到,但是被扔掉",发送方会看到端口不可达的响应
+ LOG	记录日志信息
+ DROP	拒绝流量通过(将流量直接丢弃,并不响应它),发送方显示响应超时,默认规则链的拒绝动作只能是这个
### iptables中的基本命令参数
```
-P	设置默认策略
-F	清空规则链
-L	查看规则链
-A	在规则链的末尾加入新规则
-I num	在规则链的头部加入新规则
-D num	删除某一条规则
-s	匹配来源地址IP/MASK,加叹号"!"表示除这个IP外
-d	匹配目标地址
-i 网卡名称	匹配从这块网卡流入的数据
-o 网卡名称	匹配从这块网卡流出的数据
-p	匹配协议,如TCP,UDP,ICMP
--dport num	匹配目标端口号
--sport num	匹配来源端口号
```
```shell
iptables -L		查看防洪墙规则链
iptables -F		清空已有的防火墙规则链
iptables -P INPUT DROP	把INPUT规则链的默认策略设置为拒绝
iptables -I INPUT -s 192.168.10.0/24 -p tcp --dport 22 -j ACCEPT	将INPUT规则链设置为只允许指定网段的主机访问本机的22端口,在INPUT默认规则上添加
iptables -I INPUT -p tcp --dport 12345 -j REJECT	禁止所有人通过tcp协议访问本机12345端口	
iptables -I INPUT -p udp --dport 12345 -j REJECT	禁止所有人通过udp协议访问本机12345端口 
iptables -A INPUT -p tcp --dport 1000:102 -j REJECT	向INPUT规则链中添加拒绝所有主机访问本机1000-1024端口的策略
service iptables save	防火墙规则永久生效(重启后也不失效)
```
## firewalld
**firewalld中常用的区域名称及策略规则**
|区域|默认策略规则|
|--|--|
|trusted|允许所有的数据包|
|home|拒绝流入的流量,除非与流出的流量相关,而如果流量与ssh,mdns,ipp-client,amba-client与dhcpv6-client服务相关,则允许流量|
|internal|等同于home区域|
|work|拒绝流入的流量,除非与流出的流量相关,而如果流量与ssh,ipp-client,dhcpv6-client服务相关,则允许流量|
|public|拒绝流入的流量,除非与流出的流量相关,而如果流量与ssh,dhcpv6-client服务相关,则允许流量|
|external|拒绝流入的流量,除非与流出的流量相关,而如果流量与ssh服务相关,则允许流量|
|dmz|拒绝流入的流量,除非与流出的流量相关,而如果流量与ssh服务相关,则允许流量|
|block|拒绝流入的流量,除非与流出的流量相关|
|drop|拒绝流入的流量,除非与流出的流量相关|
### 终端管理工具
**firewalld-cmd命令中使用的参数以及作用**
|参数|作用|
|-|-|
|--get-default-zone|查询默认的区域名称|
|--get-default-zone=<区域名称>|设置默认的区域,使其永久生效|
|--get-zones|显示可用的区域|
|--ger-services|显示预先定义的服务|
|--get-active-zones|显示当前正在使用的区域与网卡名称|
|--add-source=|将源自此IP或子网的流量导向指定区域|
|--add-interface=<网卡名称>|将源自该忘啦的所有流量都导向某个指定区域|
|--remove-source=|不再将源自此IP或子网的流量导向某个指定区域|
|--change-interface=<网卡名称>|将某个网卡与区域进行关联|
|--list-all|显示当前区域的网卡配置参数,资源,端口以及服务等信息|
|--list-all-zones|显示所有区域的网卡怕配置参数,资源,端口以及服务等信息|
|--add-service=<服务名>|设置默认区域允许该服务的流量|
|--add-port=<端口号/协议>|设置默认区域允许该端口的流量|
|--remove-service=<服务名>|设置默认区域不再允许该服务的流量|
|--remove-port=<端口号/协议>|设置默认区域不再允许该端口的流量|
|--reload|让"永久生效"的配置规则立即生效,并覆盖当前的配置规则|
|--panic-on|开启应急状况模式|
|--panic-off|关闭应急状况模式|
```shell
firewalld-cmd --get-default-zone	查看firewalld服务当前所使用的区域
firewalld-cmd --get-zone-of-interface=eno16777728	查看eno16777728网卡在firewalld服务中的区域
firewalld-cmd --permanent --zone=external --change-interface=eno16777728	把friewalld服务中的eno16777728网卡的默认区域修改成external,并在系统重启后剩下
```
### 图形管理工具
iptables不错
## 服务的访问控制列表
+ TCPWrappers
# 使用ssh服务管理远程主机
## 配置网络服务
### 配置网络参数
+ nmtui
### 创建网络会话
+ nmcli
### 绑定两块网卡
## 远程控制服务
### 配置sshd服务
> 基于口令的验证
> 基于密钥的验证
**sshd服务配置文件中包含的参数以及作用/etc/ssh/sshd_config**
|参数|作用|
|-----|-----|
|port 22|默认的sshd服务端口|
|listenAddress 0.0.0.0|设置sshd服务器监听的ip地址|
|protocol 2|ssh协议的版本号|
|HostKey /etc/ssh/ssh_host_key|ssh协议版本为1时,DES私钥存放的位置|
|HostKey /etc/ssh/ssh_host_res_key|ssh协议版本为2时,RSA私钥存放的位置|
|HostKey /etc/ssh/ssh_host_dsa_key|ssh协议版本为2时,DEA私钥存放的位置|
|PermitRootLogin yes|是否允许root管理员直接登陆|
|StrictModes yes|当远程用户的私钥改变时直接拒绝连接|
|MaxAuthTries 6|嘴打密码尝试次数|
|MaxSessions 10|最大终端数|
|PasswordAuthentication yes|是否允许密码验证|
|PermitEmptyPasswords no|是否允许空密码登陆|
`ssh [参数] ip地址`	ssh连接
### 安全密钥验证
```shell
ssh-keygen	在客户端生成"密钥树"
ssh-copy-id 服务器ip	把客户端主机中生产的公钥文件传送至远程主机
```
### 远程传输命令
+ scp
`scp [参数] 本地文件 远程账户@远程IP地址:远程目录`
|参数|作用|
|---|---|
|-v|显示详细的连接进度|
|-p|指定远程主机的sshd端口|
|-r|用于传输文件夹|
|-6|使用IPV6协议|
```shell
scp /root/q.txt 192.168.1.1:/home	将本地q.txt传到192.168.1.1的home目录,使用远程的root账号
scp 192.168.1.1:/etc/passwd /root	将远程的passwd文件下载到本机root目录下
```
## 不间断会话服务
+ screen
|参数|作用|
|--|--|
|-S|新建会话|
|-d|将会话"离线"|
|-r|恢复指定会话|
|-x|恢复所有会话|
|-ls|查看所有会话|
|-wipe|删除无法使用的会话|
|exit|退出会话|
# Apache服务部署静态网站
## 配置服务文件参数
|配置文件的名称|存放位置|
|----|----|
|服务目录|/etc/httpd|
|主配置文件|/etc/httpd/conf/httpd.conf|
|网站数据目录|/var/www/httml|
|访问日志|/var/log/httpd/access_log|
|错误日志|/var/log/httpd/error_log|
> 注释行信息
> 全局配置
> 区域配置
|参数|用途|
|----|----|
|ServerRoot|服务目录|
|ServerAdmin|管理员邮箱|
|User|运行服务的用户|
|Group|运行服务的用户组|
|ServerName|网站服务器的域名|
|DocumentRoot|网站数据目录|
|Directory|网站数据目录的权限|
|Listen|监听的ip地址与端口|
|DirectoryIndex|默认的索引页页面|
|ErrorLog|错误的日志文件|
|Customlog|访问日志文件|
|Timeout|网页超市时间,默认为300秒|
## 个人用户主页功能
```shell
htpasswd -c /etc/httpd/passwd mrhonest	生成范文mrhonest个人主页所需要的密码
配置401认证	见书228页
```
## 虚拟主机功能
`vim /etc/httpd/conf/httpd.conf`	编辑配置文件,添加虚拟主机,格式如下:
```
<VirtualHost 192.168.1.1:80>
DocumentRoot /home/wwwrorr/www1
ServerName www.mrhonest.com
<Directory /home/wwwroot/www1>
AllowOVerride None
Require all granted
</VirtualHost>
```
## 基于主机域名
## 基于端口号
## Apache的访问控制
# 使用vsftpd服务传输文件
## 文件传输协议
> 主动模式:ftp服务主动向客户端发起连接请求
> 被动模式:ftp服务器等待客户端发起连接请求(ftp的默认工作模式)
**vsftpd服务程序常用的参数以及作用**
|参数|作用|
|----|----|
|listen=[YSE\|NO]|是否以独立运行的方式监听服务|
|listen_address=IP|设置要监听的IP地址|
|listen_port=21|设置ftp服务的监听端口|
|download_enable=[YES\|NO|是否允许下载文件|
|userlist_enable=[YES\|NO]  userlist_deny=[YES\|NO]|设置用户列表为"允许"还是"禁止"操作|
|max_clients=0|最大客户端连接数,0为不限制|
|max_per_ip=0|同一IP地址的最大连接数,0为不限制|
|anonymous_enable=[YES\|NO]|是否允许匿名用户上传文件|
|anon_upload_enable=[YES\|NO]|是否允许匿名用户上传文件|
|anon_umask=022|匿名用户上传文件的umask值|
|anon_root=/var/ftp|匿名用户的ftp根目录|
|anon_mkdir_write_enable=[YES\|NO]|是否允许匿名用户创建目录|
|anon_other_write_enable=[YES\|NO]|是否开放匿名用户的其它写入权限(包括重命名,删除等操作权限)|
|anon_max_rate=0|匿名用户的最大传输速率(字节/秒),0为不限制|
|local_enable=[YES\|NO]|是否允许本地用户登陆|
|local_umask=022|本地用户上传文件的umask值|
|locao_root=/var/ftp|本地用户的ftp目录|
|chroot_local_user=[YES\|NO]|是否将用户权限禁锢在ftp目录,以确保安全|
|local_max_rate=0|本地用户最大的传输速率(字节/秒),0为不限制|
## vsftpd服务
> 匿名开放模式
> 本地用户模式
> 虚拟用户模式
### 匿名开放模式
> 默认目录就/var/ftp目录
245页
### 本地用户模式
> /etc/vsftpd/user_list	和 /etc/vsftpd/ftpusers 里存放着禁止登陆的用户名
> 默认目录是用户家目录
249页
### 虚拟用户模式
> 虚拟用户数据文件需要创建 奇数行为用户名,偶数行为密码
252页
```shell
vim /etc/vsftpd/user.txt
db_load -T -t hash -f user.txt user.db	将用户文件内容hash加密
useradd -d 虚拟用户ftp目录 -s /sbin.nologin 虚拟用户名	创建一个禁止登陆的用户,指定其家目录(ftp目录)
```
## 简单文件传输协议
+ tftp
> UDP协议 无需认证
`tftp ip`	建立tftp连接
|命令|作用|
|----|---|
|?|帮助信息|
|put|上传文件|
|get|下载文件|
|verbose|显示详细的处理信息|
|status|显示当前的状态信息|
|binary|使用二进制进行传输|
|ascii|使用ASCII码进行传输|
|timeout|设置重传的超时时间|
|quit|退出|
256页
# 使用samba或NFS实现文件共享
## Samba文件共享服务
 > 不同操作系统之间文件共享
**Samba服务程序中的参数以及作用**
|[global]|参数|作用|
|----|----|----|
||workgroup=MYGROUP|工作组名称|
||server string = Samba Server Version %v|服务器介绍信息,参数%v为显示SMB版本号|
||log file=/var/log/samba/log.%m|定义日志文件的存放位置与名称,参数%m为来访的主机名|
||max log size=50|定义日志文件的最大容量为50KB|
||security=user|安全验证的方式,总共分4种, :<br> share:来访主机无需验证口令<br>user:需验证来访主机提供的口令后才可以访问<br>server:使用独立的远程主机验证来访主机提供的口令(集中管理账户)<br>domain:使用域控制器进行身份验证|
||passdb backed=tdbsan|定义用户后台的类型,共3种:<br>smbpasswd:使用smbpasswd命令为系统用户设置samba服务程序的密码<br>tdbsam:穿件数据库文件并使用pdbedit命令建立samba服务程序的密码<br>ldapsam:基于LDAP服务进行账户验证|
||load printers=yes|设置在samba服务启动时是否共享打印机设备|
||cups options=raw|打印机的选项|
|[homes]||共享参数|
||comment=Home Directories|描述信息|
||browseable=no|指定共享信息是否在"网上邻居"中可见|
||writable=yse|定义是否可以执行写入操作,与"read only"相反|
|[printers]||打印机共享参数|
### 配置共享资源
**用于设置Samba服务程序的参数以及作用:/etc/samba/smb.conf**
|参数|作用|
|--|--|
|[database]|共享名称为database|
|comment = Do not arbitrarily modify the database file|警告用户不要随意修改数据库|
|path = /home/database|共享目录为/home/database|
|public = no|关闭"所有人可见"|
|writable = yes|允许写入操作|
```shell
pdbedit [选项] 账户		管理SMB服务程序的账户信息数据库
-a 用户名		建立Samba账户
-x 用户名		删除samba账户
-L		列出账户列表
-Lv		列出账户详细信息的列表
pdbedit -a -u mrhonest		为系统账号mrhonest创建smb账号
mkdir /home/database	创建用于共享资源的文件目录
chown -Rf mrhonest:mrhonest /home/database	设置共享资源的文件目录的所有者和所有组
264页
```
### windows访问文件共享服务
`\\ip`	连接文件共享服务器
### linux访问文件共享服务
268页
```shell
yum install cifs-utils	安装cifs-utils
vim auth.smb	编辑配置文件
username=mrhonest	目标用户名
password=222222		目标密码
domain=MUGROUP		目标所在组
chmod 600 auth.smb	由于密码明文,将文件设置只有root可以读写
mkdir /localdatabae 本机建立用于挂载目标的目录
vim /etc/fstab		编辑配置文件
//目标ip/databse /localdatabase cifs credenttials=root/auth.smb 0 0	写入自动挂载信息
```
## NFS(网络文件系统)
> linux之间文件共享
`yum install nfs-utils`		安装NFS服务
**NFS配置文件参数:/etc/exports,格式"共享目录的路径  允许放的NFS客户端(默认权限参数)"**
|参数|作用|
|----|----|
|ro|只读|
|rw|读写|
|root_squash|当NFS客户端以root管理员访问时,映射为NFS服务的的匿名用户|
|no_root_squash|当NFS客户端以root管理员访问时,映射为NFS服务器的root管理员|
|all_squash|无论NFS客户端使用什么账户访问,均映射为NFS服务器的匿名文虎|
|sync|同时将数据写入到内存与硬盘中,保证不丢失数据|
|async|优先将数据保存到内存,然后在写入硬盘,这样效率更高,但可能会丢失数据|
```
vim /etc/exports
/nfsfile 192.168.1.*(rw,sync,root_squash)	//IP地址与权限之间没有空格
systemctl restart rpcbind	//nfs需要RPC服务,用于将NFS服务器的ip地址和端口等信息发送给客户端
systemctl enable rpcbind	将rpc(远程过程调用)服务加入开机自启
systemctl start nfs-server	启动nfs服务
systemctl enable nsf-server	加入开机自启
```
**客户端showmount命令可用的参数和作用**
|参数|作用|
|----|----|
|-e|显示NFS服务器的共享列表|
|-a|显示本机挂载的文件资源情况|
|-v|显示版本号|
|-t|指定挂载的文件系统类型|
```shell
showmount -e 192.168.10.10	显示目标ip的共享列表
mkdir /nfsfile		建立用于挂载目标共享文件的目录
mount -t nfs 192.168.10.10:/nfsfile /nfsfile	将目标ip的共享目录nfsfile挂载到本地nfsfile目录
## autofs自动挂载服务
挂载配置文件:/etc/auto.master格式:	"挂载目录	子配置文件" 详见273页
​```shell
yum install autofs 
vim /etc/auto.master	编辑配置文件
/media /etc/iso.misc	编辑内容
vim /etc/iso/misc		编辑子配置文件
iso -fstype=iso9660,ro,nosuid,nodev :/dev/cdrom		编辑内容
systemctl enable sutofs		加入开机自启
```
# 使用BIND提供域名解析服务
## DNS域名解析服务
279页
> 主服务器
> 从服务器
> 缓存服务器
## 安装bind服务程序
**bind服务配置文件**
|文件|文件名|作用|
|----|----|---|
|主配置文件|/etc/named.conf|定义bind服务程序的运行|
|区域配置文件|/etc/named.rfc1912.zones|保存域名和IP地址对应关系的所在位置|
|数据配置文件目录|/var/named|保存域名和IP地址真是对应关系的数据配置文件|
`yum install bind-chroot`	安装bind和chroot扩展包
### 正向解析实验
281页
### 反向解析实验
283页
## 部署从服务器
285页
## 安全的加密传输
286页
## 部署缓存服务器
290页
## 分离解析技术
293页
# 使用DHCP动态管理主机地址
## 动态主机配置协议
299页
# 软件包管理


### 软件包分类
> 源码包 	脚本安装包
> 二进制包	RPM包,系统默认包
### rpm包管理
#### 命名规则
+ 包名	操作已经安装的软件时,使用包名,是搜索/var/lib/rpm中的数据库
+ 包全名	操作的是没有安装的软件包时,要注意安装路径
httpd-2.2.15-15.el6.centos.1.i686.rpm
|名称|含义|
|----|----|
|httpd|软件包名|
|2.2.15|软件版本|
|15|软件发布次数|
|el6.centos|适合的linux平台|
|i686|适合的硬件平台|
|noarch|全部硬件平台|
|rpm|rmp包扩展名|
+ rpm包依赖性
> 树形依赖	a->b->c
> 环形依赖	a->c->c->a
> 模块依赖	模块依赖查询网站www.rpmfind.net
#### rpm命令管理
#### rpm
+ 安装
```shell
rpm [参数] 包全名	rpm软件安装
rpm -ivh 包全名
-i	install,安装
-v	verbose,显示详细信息
-h	hash,显示进度
-U	upgrade,升级
-e	erase,卸载
--nodeps	不检测依赖性
```
+ 升级
```shell
rpm [参数] 包全名	rpm软件升级
rpm -ivh 包全名
-v	verbose,显示详细信息
-h	hash,显示进度
-U	upgrade,升级
```
+ 卸载
```shell
rpm [参数] 包名		rpm软件卸载
-e	erase,卸载
--nodeps	不检测依赖性
```
+ 查询
```shell
rpm [参数] [包名]		查询软件是否安装
-q	query,查询[包名]是否已经安装
-a	all,查询所有已经安装的rpm包,此参数不需要指定包名
rpm -qa | grep httpd	查询跟httpd(apache)有关的所有包
-i	information,查询软件详细信息,-qi
-l	list,列表,查询安装位置, -ql
-p [包全名]	-qp,package,查询未安装包信息,此命令后接[包全名],此命令是查询软件仓库中存在的rpm安装包,但是未安装的
-qlp [包全名]	查询未安装的软件默认的安装路径
-f [系统文件名]	file,查询某个文件输入哪个rpm包,-qf,查询的文件名是需要通过rpm安装的
-R	requires,查询软件包的依赖性,-qR
```
+ rpm包校验
```shell
rpm [参数] 已安装的包名		查询软件是否安装
-V	verify,校验指定的rpm包中的文件
```
|标志|意思|
|----|----|
|S|文件大小是否改变|
|M|文件的类型或文件的权限是否改变|
|5|文件的MD5值是否改变(可以理解成文件内容是否改变)|
|D|设备的中,从代码是否改变|
|L|文件的路径是否改变|
|U|文件的属主(所有者)是否改变|
|G|文件的数组是否改变|
|T|文件的修改时间是否改变|
|c|配置文件,config file|
|d|普通文档,documentation|
|g|"鬼"文件,ghost file,很少见,该文件不应该被这个rpm包包含|
|l|授权文件,license file|
|r|描述文件,read me|
+ rpm包中的文件提取
> rpm2cpio	将rpm包转换为cpio格式的命令
> cpio	是一个标准工具,用于创建软件档案文件和从档案中提取文件
```shell
rpm2cpio 包全名 | cpio -idv .文件绝对路径	.代表保存在当前路径下  文件绝对路径是文件在rpm包中的路径,-d会在当前目录下按照文件绝对路径的样子新建目录
```
```shell
cpio 选项 < [文件|设备]
-i	copy-in模式,还原
-d	还原时自动新建目录
-v	显示还原过程
```
#### yum
+ IP地址配置和网络yum源
	`setup`		配置网络
|参数|作用|
|----|----|
|[base]|容器名称,一定要放在[]中|
|name|容器说明,可以随便写|
|mirrorlist|容器站点,可以注释掉|
|baseurl|yum源服务器的地址|
|enabled|此容器是否生效,默认=1,=1生效,=0不生效|
|gpgcheck|如果是1是指rpm的数字证书生效,为0不生效|
|gpgkey|数字证书的公钥文件保存位置|
+ yum命令
```shell
yum list		查询所有可用的软件包列表
yum search 关键字	搜索服务器上所有和关键字相关的包
yum [参数] 包名
install		安装
update		升级,不加包名的话会升级linux上的所有软件包,包括linux内核
remove		卸载,尽量不要用yum卸载,会自动卸载相关的支持库,曹成系统异常
-y		自动回答yes
grouplist	列出所有可用的软件组列表
groupinstall 软件组名	安装指定软件组,组名可以用grouplist查询出来
groupremove 软件组名	卸载指定软件组
```
+ 光盘yum源
```shell
mount /dev/cdrom /mnt/cdrom		挂载光盘
//让网络yum源失效
cd /etc/yum.repos.d/
mv CentOS-Base.repo CentOS-Base.repo.bak
mv CentOS-Debuginfo.repo CentOS-Debuginfo.repo.bak
mv CentOS-Vault.repo CentOS-Vault.repo.bak
vim CentOS-Media.repo
//地址修改为自己的光盘挂载地址
baseurl=file:///mnt/cdrom
enabled=1	把enabled改为1,让这个yum源生效
```
+ 源码包管理
> 区别:安装前,概念上的区别 安装后,安装位置不同
+ 源码包安装
> /usr/local/sec	源代码保存位置
> /usr/local		软件安装位置
> 卸载软件方法	直接删除软件安装目录即可
./configure 软件配置与检查
> 定义需要的功能选项
> 检测系统环境是否符合安装要求
> 把定义号的功能选项和检测系统环境的信息都写入Makefile文件,用于后续的编辑
```shell
yum -y install gcc	安装C语言编译器
./configure --prefix/usr/local/apache2	指定安装路径
make		编译
make clean		make如果报错,可使用此命令情况make命令编译产生的临时文件
make install		编译安装
```
+ 脚本安装方法
# 用户和用户组管理
|文件位置|作用|
|----|----|
|/etc/passwd|用户信息文件|
|/etc/shadow|影子文件|
|/etc/group|组信息文件|
|/etc/gshadow|组密码文件|
|/home/用户名|普通用户家目录|
|/var/spool/mail/用户名|用户邮箱|
|/etc/skel/|用户模版文件|
+ passwd
用户名:密码标识:UID:GID:用户说明:家目录:shell
+ shadow
> 密码sha512加密,!!或*为无密码,禁止登陆
> 密码修改日期以1970年1月1日开始,按天递增
用户名:用户密码:密码最后一次修改日期:要修改密码的时间间隔:密码有效期:密码到期的警告时间:密码到期的宽限时间:账号的失效时间:保留字段
+ group
组名:组密码标志:GID:组中附加用户
+ gshadow
组名:组密码:组管理员用户名:组中附加用户
## useradd 添加用户
**useradd [选项] 用户名**
|选项|作用|
|----|----|
|-u UID|指定UID|
|-g 组名|指定GID|
|-d 家目录|指定家目录|
|-c 用户说明|指定用户明说|
|-G 组名|指定用户的附加组,用逗号分隔多个组|
|-s shell|指定用户的登陆shell,默认是/bin/bash|
## passwd 修改密码
**passwd [选项] [用户名]**
|选项|用户名|
|----|----|
|-S|查询用户密码的密码状态,仅限root使用|
|-l|暂时锁定用户,root使用|
|-u|解锁用户,root使用|
|--stdin|可以通过管道符输出的数据作为用户的密码|
## usermod 修改用户信息
**usermod [选项] 用户名**

|选项|作用|
|----|----|
|-u UID|修改UID|
|-d 家目录|修改家目录|
|-c 用户说明|修改用户明说|
|-G 组名|修改用户的附加组,用逗号分隔多个组|
|-L|暂时锁定用户,root使用|
|-U|解锁用户,root使用|
## chage 修改用户密码状态
**chage [选项] 用户名**
|选项|作用|
|----|----|
|-l|列出用户的详细密码状态|
|-d 日期|修改密码最后一次更改日期|
|-m 天数|两次密码修改间隔|
|-M 天数|密码有效期|
|-W|密码过期前经考天数|
|-I|密码过期后宽限天数|
|-E 日期|账号失效时间|
## userdel 删除用户
**userdel [选项] 用户名**
|选项|作用|
|----|----|
|-r|删除用户同时删除用户家目录|
## su 用户切换命令
**su [选项] 用户名**
`su -root -c "useradd user1"`
|选项|作用|
|----|----|
|-|连带用户的环境变量一起切换|
|-c 命令|仅执行一次命令,而不切换用户身份|
## id 查看用户的id
**id [用户名]**
## env 查看环境变量
`env`

## groupadd 添加组
**groupadd [选项] 组名**
|选项|作用|
|----|----|
|-g GID|指定组ID|
## groupmod 修改组
**groupmod [选项] 组名**

|选项|作用|
|----|----|
|-g GID|修改组ID|
|-n 新组名|修改组名|
## groupdel 删除用户组
**groupdel 组名**
> 有初始用户的组无法删除,有附加用户的组不影响删除
## gpasswd 把用户添加入组或者从组中删除
**gpasswd 选项 组名**
|选项|作用|
|----|----|
|-a 用户名|把用户加入附加组|
|-d 用户名|把用户从附加组中删除|
# 权限管理
## ACL权限
```shell
dumpe2fs [参数] 分区	查询指定分区详细文件系统信息
-h	仅显示超级块中的信息,而不显示磁盘块组的相信信息
dumpe2fs -h /dev/sda3	查看分区是否支持acl权限
看default mount options : acl
mount -o remount,acl	重新挂载根分区,并挂载加入acl权限(临时)
```
+ 查看ACL权限
	`getfacl 文件名`		查看acl权限
+ 设定ACL权限
**mask是用来指定最大有效权限的**
```shell
setfacl 选项 文件名
setfacl -m u:用户:权限 文件名|目录	给用户设定acl权限
setfacl -m g:组名:rwx 文件名|目录	给组设定acl权限
setfacl -m m:rwx 文件名|目录		设定文件的最大acl权限
setfacl	-x m|g:用户名|组名 文件|目录	删除指定用户|组的acl权限
setfacl -b 文件名|目录		删除文件的所有acl权限
setfacl	-m m|g:用户名|组名:权限 -R 目录		递归给指定用户|组设置acl权限
setfacl -m d:u|g:用户名|组名:权限 [-R] 目录		设置父目录的默认ACL权限
```
|参数|作用|
|----|----|
|-m|设定acl权限|
|-x|删除指定的acl权限|
|-b|删除所有acl权限|
|-d|设定默认的acl权限|
|-k|删除默认acl权限|
|-R|递归设定acl权限|
|u:|给用户设定acl权限|
|g:|给组设定权限|
|m:|设定最大权限|
|d:|如果给父目录设定了ACL权限,那么父目录中所有以后新建的子文件都会继承父目录的acl权限|
## 文件特殊权限
### SetUID
> 只有可执行的二进制程序还能设定SUID全选
> 命令执行者要对该程序拥有执行(x)权限
> 命令执行者在执行该程序时获得该程序文件属主的身份(在执行程序的过程中灵魂附体为文件的属主)
> SetUID权限只在该程序执行过程中有效,也就是说身份改变只在程序执行过程中有效
> 查看文件权限时,用户的权限处有"s","S"表示设置失败
+ 设定SetUID
```shell
chmod 4755 文件名	4:用户  2:组   1:其他人
chmod u+s 文件名
```
+ 取消
```shell
chmod 755 文件名
chmod u-s 文件名
```
### SetGID
> 针对二进制文件时,功能与SetUID相似
> 针对目录时:普通用户必须对此目录拥有r和x权限才能进入此目录
> 普通用户在此目录中的有效组会变成此目录的属组
> 若普通用户对此目录拥有w全限时,新建的文件的默认属组是这个创建这个目录的属组
> 查看文件权限时,组的权限处有"s","S"表示设置失败
```shell
chmod 2755 文件名	4:用户  2:组   1:其他人
chmod g+s 文件名
chmod 755 文件名		取消SetGID
chmod g-s 文件名		取消SetGID
```
### Sticky BIT
> 粘着位权限目前只对目录有效
> 普通用户对该目录拥有w和x权限,即普通用户可以在此目录拥有写入权限
> 如果没有粘着位,因为普通用户拥有w权限,所以可以删除此目录下的所有文件,包括其他用户建立的文件,一旦赋予粘着位,除了root可以删除所有文件,普通用户就算拥有w权限,也只能删除自己建立的文件,不能删除其他用户建立的文件
> 查看文件权限时,其他人的权限处"x"权限换成"t"
```shell
chmod 1775 目录名	设置粘着位权限
chmod o+t 目录名	设置粘着位权限
chmod 775 目录名	取消粘着位权限
chmod o-t 目录名	取消粘着位权限
```
### chattr
文件系统属性权限
+ 设置
```shell
chattr [+|-|=] [选项] 文件|目录
+	增加权限
-	删除权限
=	等于某权限
```
|选项|作用|
|----|----|
|i|如果对文件设置i属性,那么不允许对文件进行删除,改名,也不能添加和修改数据 <br> 如果对目录设置i属性,那么只能修改目录下文件的数据,但不允许建立和删除文件|
|a|如果对文件设置a属性,那么只能在文件中增加数据,但不能删除也不能修改数据 <br> 如果对目录设置a属性,那么只允许在目录中建立和修改文件,但是不允许删除|
+ 查看
```shell
lsattr 选项 文件|目录		查看文件系统属性
-a			显示所有文件和目录
-d			若目标是目录,仅列出目录本身的属性,而不是子文件的
```
### sudo  权限
> root把本来只能超级用户执行的命令赋予普通用户执行
> sudo的操作对象是系统命令
```shell
sudo -l		查看有哪些权限
visudo		实际修改的是/etc/sudoers文件
用户名	被管理主机的地址=(可使用的身份)	授权命令(绝对路径)
root	ALL=(ALL)					ALL
组名	被管理主机的地址=(可使用的身份)	授权命令(绝对路径)
# %wheel	ALL=(ALL)					ALL
```
# 文件系统管理
> 主分区最多自能有四个
> 扩展分区最多只能有一个,也算作主分区的一种,不能存储数据和格式化
> 逻辑分区:IDE接口最多59个逻辑分区,scsi接口最多有11个逻辑分区
## 常用命令
### df
`df [选项] [挂载点]`		查看分区(文件)系统的占用情况信息
> df命令是从文件系统考虑的,不光要考虑文件占用的空间,还要统计被命令程序序占用的空间(最常见的就是文件已经删除,但是程序并没有释放空间),所以比du命令显示的占用量大,此命令显示的结果比du命令的准确
|参数|作用|
|----|----|
|-a|显示所有的文件系统,包括特俗文件系统,如:/proc,/sysfs|
|-h|使用习惯单位显示容量,如kb,MB,GB等|
|-T|显示文件系统类型|
|-m|以MB单位显示容量|
|-k|以KB单位显示容量,默认就是以KB单位显示|
### du
`du [选项] [目录名|文件名]`		显示目录占用大小
> du命令是面向文件的,只会计算文件或目录占用的空间,所以比df命令显示的占用量小
|参数|作用|
|----|----|
|-a|显示每个子文件的磁盘占用量,默认只统计子目录的磁盘占用量|
|-h|使用习惯单位显示容量,如kb,MB,GB等|
|-s|统计总占用量,而不列出子目录和子文件的占用量|
### fsck
`fsck [选项] 分区设备文件名`		文件系统修复命令
|参数|作用|
|----|----|
|-a|不用显示用户提示,自动修复文件系统|
|-y|自动修复,和-a作用一致,不过有些文件系统只支持-y|
### dumpe2fs
`dumpe2fs 分区设备文件名`		显示磁盘状态命令
### mount
+ 查看
|参数|作用|
|----|----|
|-a|根据/etc/fstab的内容自动挂载|
|-l|查询系统中已挂载的设备,-l会显示卷标名称|
+ 挂载
`mount [-t 文件系统] [-L 卷标名] [-o 特殊选项] 设备文件名 挂载点`
|参数|作用|
|----|----|
|-t 文件系统|加入文件系统类型来自定挂载的类型,可以以ext3.ext4,iso9660等文件系统|
|-L 卷标名|挂载指定卷标的分区,而不是安装设备文件名挂载|
|-o 特殊选项|可以指定挂载的额外选项|
**-t参数需指定格式,如挂载光盘,U盘等需使用**
**-o参数内容**
![1570426181553](RedHat.assets/1570426181553.png)

+ 卸载
	`umount 设备文件名或挂载点`		卸载挂载
### 支持NTFS文件系统
+ NTFS-3G
	`mount -t ntfs-3g 分区设备文件名 挂载点`	使用ntfs-3g挂载ntfs文件系统的设备
### fdisk
+ 分区
	`fdisk 硬盘设备`	分区
![1570450179706](RedHat.assets/1570450179706.png)
+ 格式化
	`mkfs -t ext4 /dev/sdb1`	格式化/dev/sdb1分区
### partprobe
> 重新读取分区表信息
### 自动挂载
`vim /etc/fstab`
`dumpe2fs -h /dev/sdb1`		查看设备的UUID
![1570451126431](RedHat.assets/1570451126431.png)
#### /etc/fstab文件修复
`mount -o remount,rw /`
开机可输入root密码,修改/etc/fstab文件属性,然后再修改此文件
### 分配swap分区
#### free
`free [-m]`	查看内存与swap分区使用状况
> cached(缓存):是指把读取出来的数据保存在内存当中,当再次读取时,不用读取硬盘而直接从内存当中读取,加快了数据的读取过程
> buffer(缓冲):是指在写入数据时,先把分散的写入操作保存到内存当中,当达到一定程度再集中写入硬盘,减少了磁盘碎片和硬盘的反复寻道,加速了数据的写入过程
+ 新建swap分区
	`fdisk /dev/sdb`	给sdb新分个分区,别忘记把分区ID改为82(t键修改)
+ swap格式化
	`mkswap /dev/sdb6`	格式化swap分区
+ 加入swap分区
`swapon /dev/sdb6`
	`vim /etc/fstab`	加入开机自动挂载
+ 取消swap分区
`swapoff /dev/sdb6`
# 服务管理
## 服务的分类
+ RPM包默认的安装服务
独立的服务
基于xinetd服务
+ 源码包安装的服务
自启动是指让服务在系统开机或重启之后,随着系统的启动而自动启动
## 查询已安装的服务
### RPM包安装的服务
+ 启动脚本位置
|位置|作用|
|----|----|
|/etc/init.d/|独立服务的启动脚本位置|
|/etc/xinetd.d/|基于xinnetd服务的启动脚本|
|/etc/xinnetd.conf|xinnetd配置文件|
|/etc/sysconfig/|rpm安装包的初始化环境配置文件位置|
|/etc/|配置文件位置|
|/var/lib|服务产生的数据放在这里|
|/var/log|日志|
### 源码包安装的服务
> 查看服务安装位置,一般/usr/local/下
## 服务启动
### RPM包安装的启动
+ 手工启动
```shell
/etc/init.d/独立服务名 start|stop|status|restart
service 独立服务名 start|stop|status|restart
```
+  服务自启动
> chkconfig
```shell
chkconfig --list	查看服务自启动状态,可以看到所有RPM包安装的服务
chkconfig --level 2345 httpd on		设置httpd在init2345为自启动
chkconfig --add 服务名		将服务加入chkconfig序列
chkconfig --del 服务器		将服务从chkconfig序列中移除
chkconfig httpd off		设置httpd在开机不自启动,默认级别就是2345
```
> 修改配置文件/etc/rc/d/re.local(//etc/rc.local),此文件时在开机时在输入用户名和密码登陆之前,系统读取此文件内的内容,只要将要执行的命令写入此文件即可实现开机自启动
```shell
/etc/init.d/独立服务名 start|stop|status|restart
service 独立服务名 start|stop|status|restart
```
> ntsysv
`ntsysv`	在需要自启动的项目前加入*即可
### 基于xinetd服务管理 
+ 手工启动
> xinetd 超级守护进程,启动方式,修改对应的服务配置文件,然后重启xinnetd服务
`vim /etc/xinetd.d/服务配置文件` 如vim /etc/xinetd.d/telnet
+ 自启动
> 启动和自启动相连,也就是说基于xinetd的服务只要启动了就会自启动
`chkconfig telnet on`		命令方式
`ntsysv`		配置方式
### 源码包安装软件自启动
> 修改配置文件/etc/rc/d/re.local(//etc/rc.local),此文件时在开机时在输入用户名和密码登陆之前,系统读取此文件内的内容,只要将要执行的命令写入此文件即可实现开机自启动
> 制作一个软件启动脚本的软链接,放在/etc/init.d/目录下,即可使用:/etc/init.d/独立服务名 start|stop|status|restart或者:service 独立服务名 start|stop|status|restart 启动
+ 让源码包的apache服务能呗chkconfig和ntsysv管理命令自启动
```shell
vim /etc/init.d/apache		编辑启动脚本
# chkconfig 运行级别 启动顺序 关闭顺序
如:(下面两行的内容,包括#)
# chkconfig 2345 86 76
# description:source package apache 
然后将apache的服务加入到chkconfig的序列
chkconfig --add apache
```
>运行级别是/etc/rc.d/下的文件以rc[数字].d开始的,对应的是init[数字]
>启动顺序与关闭顺序是每个rc[数字].d文件中文件开始的编号,不能重复,如:S99local代表第99个启动
## 总结
![1570517681643](RedHat.assets/1570517681643.png)
# 系统管理
## 进程
### ps
```shell
ps aux		查看系统进程,使用BSD操作格式
ps -le		查看系统进程,使用linux标准格式
```
|参数|作用|
|----|----|
|a|显示前台进程|
|x|显示后台进程|
|u|显示进程使用的用户|
|-l|显示更加详细的信息|
|-e|显示所有进程|
**显示说明**
|显示|说明|
|----|----|
|USER|该进程由哪个用户产生|
|PID|进程的ID号|
|%CPU|进程占用CPU的百分比|
|%MEM|进程占用物理内容百分比|
|VSZ|进程占用虚拟内存的大小(kb)|
|RSS|进程占用实际物理内存的大小(kb)|
|TTY|进程在哪个终端中运行,?是内核直接调用<br>tty1-tty6:本地控制台终端(字符界面)<br>tty7:本地图形界面终端<br>pts/0-255:虚拟终端(远程登陆)|
|STAT|进程状态,常见的有,R:运行,S:睡眠,T:停止,s:包含子进程,+:位于后台|
|START|进程的启动时间|
|TIME|进程占用CPU的运算时间|
|COMMAND|产生进程的命令名|
### pstree
`pstree [选项]`	查看进程树
|选项|作用|
|----|----|
|-p|显示进程PID|
|-u|显示进程的所属用户|
### top
> 查看系统健康状态
`top`
|参数(显示页面配合shift键使用)|作用|
|----|----|
|-d 秒数|指定top命令每隔几秒更新,默认3秒|
|?\|h|显示交互模式的帮助|
|P|以CPU使用率排序|
|M|以内存使用率排序|
|N|以PID排序|
|q|退出top命令|
#### top命令显示结果解析
**第一行:任务队列信息**
|内容|说明|
|----|----|
|12:26:46|系统当前时间|
|up 1 day,13:32|系统运行时间|
|2 users|当前登陆了两个用户|
|load average:0.00,0.00,0.00|系统在1分钟,5分钟,15分钟的平均负载<br>一般认为小于1时负载较小,大于1时系统属于超出负荷<br>(按照CPU核数计算,如4核计算机,显示4为超负载)|
**第二行:进程信息**
|内容|说明|
|----|----|
|Task:95 total|系统中的进程总数|
|1 running|正在运行的进程数|
|94 sleeping|睡眠的进程数|
|0 stopped|正在停止的进程|
|0 zombie|僵尸进程,如果不是0,需手工检查僵尸进程|
**第三行:CPU信息**
|内容|说明|
|----|----|
|Cpu(s):0.1%us|用户模式占用的CPU百分比|
|0.1%sy|系统模式占用的CPU百分比|
|0.0%ni|改变过优先级的用户进程占用的cpu百分比|
|99.7%id|空闲CPU的CPU百分比|
|0.1%wa|等待输入/输出的进程的占用CPU百分比|
|0.0%hi|硬中断请求服务占用的CPU百分比|
|0.1%si|软中断请求服务占用的CPU百分比|
|0.0%st|st(steal time)虚拟时间百分比,就是当有虚拟机时,虚拟CPU等待实际CPU的时间百分比|
**第四行:物理内存信息**
|内容|说明|
|----|----|
|MEM|物理内存的总量(kb)|
|used|已使用的物理内存数量|
|free|空闲的物理内存数量|
|buffers|作为缓冲区的内存数量|
**第五行:交换分区(swap)信息**
|内容|说明|
|----|----|
|swap|交换分区的总大小(kb)|
|used|已使用的交换分区大小|
|free|空闲的交换分区大小|
|cached|作为缓冲区的交换分区大小|
### 终止进程
#### kill
`kill -l`	查看可用的进程信号
`kill [-信号代码] PID`	终止进程,默认15	
![1570525055748](RedHat.assets/1570525055748.png)

#### killall
`killall [选项] [信号] 进程名`		按照进程名杀死进程
|选项|作用|
|----|----|
|-i|交互式,询问是否杀死某个进程|
|-I|忽略进程名的大小写|
#### pkill
`pkill [信号] [选项] 进程名`	按照进程名终止进程
|选项|作用|
|----|----|
|-t 终端号|按照终端号踢出用户|
## 工作管理
### 放入后台
#### &
> 放入后台后,程序继续运行
`命令 &`		在命令后加"&"
#### Ctrl+z
> 放入后台后,程序暂停运行
```shell
top
Ctrl+z
```
### 查看后台工作
#### jobs
`jobs [-l]`		查看所有后台工作,-l:显示工作的PID
> 工作号,按照顺序排列
> "+"号代表最近一个放入后台的工作,也就是工作恢复时,默认恢复的工作
> "-"号代表倒数第二个放入后台的工作
### 恢复后台工作
#### fg
`fg %工作号`	"%"可以省略(直接输入工作号),省略的话就按照+-号的顺序恢复,注:是工作号,不是PID
#### bg
`bg %工作号`	把后台暂停的工作恢复到后台执行,注:后台恢复执行的命令,是不能和前台有交互的,否则不能恢复到后台执行
## 系统资源
### vmstat
`vmstat [刷新延时 刷新次数]`	监控系统资源,如:vmstat 1 3(每1秒钟监听1次系统资源,共3次)
### dmesg
`dmesg`	开机时内核检测信息,如dmesg | grep CPU
### free
`free [选项]`		查看内存使用状态
|选项|作用|
|----|----|
|-b|以字节为单位显示|
|-k|以KB为单位显示,默认项|
|-m|以MB为单位显示|
|-g|以GB为单位显示|
### 查看cpu信息
`cat /proc/cpuinfo`
### uptime
`uptime`	显示系统的启动时间和平均负载,也就是`top`命令的第一行,`w`命令也可以看到这个数据
### uname
`uname [选项]`	查看系统与内核相关信息
|选项|作用|
|----|----|
|-a|查看系统所有相关信息|
|-r|查看内核版本|
|-s|查看内核名称|
### 判断当前系统的位数
`file /bin/ls`
### 查看当前linux系统的发行版本
`lsb_release -a`
### 列出进程打开或者使用的文件信息
`lsof [选项]`		列出进程调用或者打开的文件的信息
|选项|作用|
|----|----|
|-c 字符串|只列出以字符串开头的进程打开的文件|
|-u 用户名|只列出某个用户的进程打开的文件|
|-p pid|列出某个PID进程打开的文件|
## 系统定时任务
### crond服务管理与访问控制
```shell
service crond restart	重启服务,默认是启动状态
chkconfig crond on		加入开机自启,默认都是自启
```
`crond [选项]`
|选项|作用|
|----|----|
|-e|编辑crontab定时任务|
|-l|查询crontab任务|
|-r|删除当前用户所有的crontab任务|
**分钟(0-59) 小时(0-23) 天(1-31) 月(1-12) 星期(0-7,0和7都是星期天) 命令**
|符号|作用|
|----|----|
|*|代表任何时间,比如第一个"*"就代表一小时中的每分钟都执行一次|
|,|代表不连续的时间,比如"0 8,12,16 * * * 命令"代表每天的8点12点16点都执行一次|
|-|代表连续的时间访问比如"0 5 * * 1-6 命令"代表每周一到周六的5点执行|
|*/n|代表每隔多久执行一次,比如"*/10 * * * * 命令"代表每隔10分钟就执行一次|
# 日志管理
## rsyslogd
![1570543947209](RedHat.assets/1570543947209.png)
![1570544325571](RedHat.assets/1570544325571.png)
### lastb
`lastb`		登陆错误日志,文件位于/var/log/btmp,二进制文件
### lastlog
`lastlog`	记录系统中所有用户最后一次登陆时间的日志,文件位于/var/log/lastlog,二进制文件

### last
`last`	永久记录所有用户的登陆,注销信息,同时记录系统的启动,重启,关机时间,文件位于/var/log/wtmp,二进制文件
## RPM安装软件日志
![1570544724091](RedHat.assets/1570544724091.png)
## 日志文件格式
> 事件产生的时间'
> 发生事件的服务器的主机名
> 产生事件的服务名或程序名
> 事件的具体信息
### /etc/rsyslog.conf配置文件
+ 格式
```shell
服务名称[连接符号]日志等级	日志记录位置
authpriv.*	/var/log/secure
```
+ 连接符
> "."代表只要比后门的等级高的(包含该等级)日志都记录下来,比如:"cron.info"代表cron服务产生的日志,只要日志等级大于等于info级别就记录
> ".="代表只记录所需等级的日志,其它等级的都不记录.比如:"*.=emerg"代表任何服务产生的日志,只要等级是emerg就记录,用的较少
> ".!"代表不等于,也就是除了该等级的日志外,其它等级的日志都记录
+ 日志等级
|等级名称|说明|
|----|----|
|*|所有等级|
|debug|一般的调试信息说明|
|info|基本的通知信息|
|notice|普通信息,但是有一定的重要性|
|warning|警告信息,但是还不会影响到服务或系统的运行|
|err|错误信息,一般达到err等级的信息已经可以影响到服务或系统的运行了|
|crit|临界状况信息,比err等级还严重|
|alert|警告状态信息,比crit还严重|
|emerg|疼痛等级信息,系统已经无法使用了|
+ 日志记录位置
|日志位置|说明|
|----|----|
|/var/log/secure|绝对路径|
|/dev/lp0|系统设备文件|
|@192.168.1.1:514|转发给远程主机|
|root|用户名(需用户在线)"*"代表任何人|
|~|忽略或丢弃|
![1570572911822](RedHat.assets/1570572911822.png)
![1570583064039](RedHat.assets/1570583064039.png)
## 日志轮替
+ 日志文件的命名规则
> 如果配置文件中拥有"dateext"参数,那么日志会用日期来作为日志文件的后缀,如:secure-20191010
> 如果配置文件中没有"dateext"参数,那么日志就需要改名了
### logrotate
`logroteta [选项] 配置文件名`		如果此命令没有选项,则会按照配置文件中的条件进行日志轮替
|参数|说明|
|----|----|
|-v|显示日志轮替过程|
|-f|强制进行日志轮替|
### 配置文件 /etc/lorptate.conf
```shell
vim /etc/lorptate.conf		//把源码包安装的apache日志进行轮替
/usr/local/apache2/logs/access_log {	//apache的默认日志文件地址
	daily								//每天轮替
	create								//创建新文件	
	rotate 30							//日志保留30天
}
```
|参数|说明|
|----|----|
|daily|日志的轮替周期是每天|
|weekly|每周轮替|
|monthly|每月轮替|
|rotate 数字|保留的日志文件的个数,0指没有备份|
|compress|日志轮替时,就得日志进行压缩|
|create mode oener group|建立新日志,同时指定新日志的权限与所有者和所属组,如:create 0600 root utmp|
|mail address|当体质轮替时,输出内容通过邮件发送到指定的邮件地址,如 mail mrhonest@qq.com|
|missingok|如果日志不存在,则忽略该日志的警告信息|
|notifempty|如果日志为空文件,则不进行日志轮替|
|minsize 大小|日志轮替的最小值,也就是日志要达到这个最小值才能轮替,否则就算时间达到也不轮替|
|size 大小|日志只有大于指定大小才进行轮替,而不是按照时间轮替,如:size 100k|
|dateext|使用日期作为日志轮替的文件后缀|
# 启动管理
## 运行级别
|运行级别|含义|
|----|----|
|0|关机|
|1|单用户模式,可以想象为windows的安全模式,主要用于系统痛修复|
|2|不完全的命令行模式,不包含NFS服务|
|3|完全的命令行模式,就是标准的字符界面|
|4|系统保留|
|5|图形模式|
|6|重启动|
### runlevel
`runlevel`	查看运行级别
### init
`init 运行级别`	改变运行级别命令

### 系统默认运行级别
`vim /etc/inittab`	修改配置文件,设置系统默认的运行级别
## 启动过程
![1570588219042](RedHat.assets/1570588219042.png)
## 启动引导程序grub
+ /boot/grub/grub.conf
![1570590009381](RedHat.assets/1570590009381.png)
### grub加密
+ grub-md5-crypt
	`grub-md5-crypt`	生成加密密码串
> 修改/boot/grub下的grub.conf,在timeout下加入"password --md5 加密的密码串"
## 字符界面的分辨率调整 
## 系统修复
### 单用户模式
+ 修改root密码
+ 修改运行级别
> 内核启动选项界面选择"e"
> 启动选项后面加"1",单用户启动,回车
> 回到启动选项界面,按"b",进入单用户启动
> 直接修改root密码, passwd root
### 光盘修复模式
+ 重要系统文件丢失,导致系统无法启动
```shell
chroot /mnt/sysimage	//改变主目录,然后就可以执行任意命令了
cd /root				//以下步骤为修复系统文件的方式
rmp -qf /etc/inittab	//查询下/etc/inittab属于哪个包
mkdir /mnt/cdrom		//建立挂载点
mount /dev/sr0 /mnt/cdrom	//挂载光盘
rpm2cpio /mnt/cdrom/Packages/inittab的rpm包名 | cpio -idv ./etc/inittab	//提取inittab文件到当前目录
cp /etc/inittab /etc/inittab	//复制文件到指定位置
```
# 备份和恢复
> 完全备份:备份文件或目录时只能用完全备份
> 增量备份:备份分区时可以使用增量备份
> 差异备份
## dump
`dump [选项] 备份之后的文件名 源文件或目录`		备份
```shell
dump -0uj -f /root/boot.bak.bz2 /boot	//先执行一次完全备份,并压缩和更新备份时间
cat /etc/dumpdates		//查看备份时间文件
cp install.log /boot/	//复制日志文件到/boot分区
dump -1uj -f /root/book.bak1.bz2 /boot/		//增量备份/boot分区,并压缩
dump -W		//查询分区的备份时间和备份级别
```
|选项|含义|
|----|----|
|-level|0-9,10个备份几笔|
|-f 文件名|指定备份之后的文件名|
|-u|备份成功之后,把备份时间记录在/etc/dumpdates文件|
|-v|显示备份过程中更多的输出信息|
|-j|调用bzlib库备份压缩文件.其实就是把备份文件压缩为.bz2格式|
|-W|显示允许被dump的分区的备份等级和备份时间|
## restore
`restore [模式选项] [选项]`	恢复
> 模式选项不能混用
|类别|选项|含义|
|----|----|----|
|模式选项|-C|比较备份数据和实际数据的变化|
|模式选项|-i|进入交互模式,手工选择需要恢复的文件|
|模式选项|-t|查看模式,用于查看备份文件中拥有哪些数据|
|模式选项|-r|还原模式,用于数据还远|
|选项|-f|指定备份文件的文件名g|