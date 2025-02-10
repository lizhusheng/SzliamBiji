[[log4j-RCE漏洞-笔记.pdf]]

# Log4j RCE 漏洞原理笔记

## Log4j 介绍与漏洞影响

### 什么是 Log4j
- Apache 的开源日志组件
- 记录日志的作用：
  1. 对程序的运行进行调试跟踪
  2. 对业务操作进行记录，方便追溯

### 用法
1. pom 引入依赖
2. 获得 logger 实例
3. 使用 `logger.info()`, `debug()`, `error()`, `warn()` 等方法记录日志

### 为什么要用 Log4j
- 日志级别管理（如生产环境只打印 info 日志，不打印 debug 日志）
- 不同 package 的打印格式不同
- 多输出渠道（控制台、文件、数据库）
- 日志文件管理（文件大小、定时自动清理）
- 易于集成（Spring、Spring Boot）

### Log4j 漏洞时间线
4. 11 月 24 日，阿里云安全团队陈兆军报告 Log4j RCE 漏洞
5. 12 月 4 日开始有在野攻击
6. 12 月 10 日凌晨漏洞细节被公开
7. 各 SRC 陆续关闭 Log4j 漏洞提交通道
8. 各安全厂商纷纷通报，发布临时解决办法
9. Apache 陆续发布 rc1 补丁、rc2 补丁、2.15 正式版

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
1. 先去公布资源（`bind` 方法）
2. 然后别人可以用名字查找资源（`lookup` 方法）

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
- 不在命名/目录服务本地的一个资源，叫做命名引用
- 让 JNDI 去请求一个不存在的资源
- 当 JNDI 客户端在本地 `classpath` 找不到这个类，就去指定的远程地址请求，下载这个类到本地执行

### 示例
- `Exploit` 定义静态方法块

### 流程
3. `NamingManager` 341 行
4. `getObjectFactoryFrom...`

### RMI 资源也可以这样利用，原理一样

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
- `LDAPRefServer.java`
- Maven 依赖：`unboundid-ldapsdk`
- 配置远程代码的 HTTP URL
- 启动服务，绑定指定端口

### 3. LDAP 客户端（Log4j）
- Maven 依赖：2.14.1 版本
- Apache Log4j 2.x <= 2.14.1
- 打印日志即可，客户端即下载恶意代码并执行

## 漏洞影响范围
- Log4j 2.x <= 2.14.1
- JDK 小于 8u191、7u201、6u211

## 漏洞排查
- pom 版本检查
- 日志中是否存在 `jndi:ldap://`、`jndi:rmi`、`dnslog.cn`、`ceye.io` 等
- 是否存在 `JndiLookup`、`ldapURLContext`、`getObjectFactoryFromReference` 调用

### 工具
- [log4j-local-check.sh](https://static.threatbook.cn/tools/log4j-local-check.sh)
- [allScanner.zip](https://sca.seczone.cn/allScanner.zip)

## 漏洞修复

### 思路
5. 禁止用户请求参数出现攻击关键字
6. 禁止 `lookup` 下载远程文件（命名引用）
7. 禁止 Log4j 的应用连接外网
8. 禁止 Log4j 使用 `lookup`
9. 从 Log4j jar 包中删除 `lookup`（2.10 以下）

### 升级到 2.17.1
- 默认不再支持二次跳转（命名引用）的方式获取对象
- 只有在 `log4j2.allowedLdapClasses` 列表中指定的 class 才能获取
- 只有远程地址是本地地址或者在 `log4j2.allowedLdapHosts` 列表中指定的地址才能获取

### 其他方案
- 升级 JDK
  - JDK 6u45、7u21 之后：`java.rmi.server.useCodebaseOnly` 默认值为 `true`，禁用自动加载远程类文件
  - JDK 6u141、7u131、8u121 之后：`com.sun.jndi.rmi.object.trustURLCodebase` 默认为 `false`，禁止 RMI 和 CORBA 协议使用远程 codebase
  - JDK 6u211、7u201、8u191 之后：`com.sun.jndi.ldap.object.trustURLCodebase` 默认为 `false`，禁止 LDAP 协议使用远程 codebase

### 修改 Log4j 配置
10. 设置参数：`log4j2.formatMsgNoLookups=True`
11. 修改 JVM 参数：`-Dlog4j2.formatMsgNoLookups=true`
12. 系统环境变量：`FORMAT_MESSAGES_PATTERN_DISABLE_LOOKUPS` 设置为 `true`
13. 禁止 Log4j2 所在服务器外连

## Log4j RCE 原理分析
- Log4j 支持 JNDI `lookup` 功能
- `StrSubstitutor` 的 `resolveVariable()` 方法
- `NamingManager` 的 `newInstance` 方法

### 任意命令执行
- 前端注入点：只要是参数被 Log4j 记录的地方都可以
- 现成利用工具：`log4j_POC.jar`
