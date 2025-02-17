
---

### **1. 文件与目录操作**
#### **`ls`** - 列出目录内容
```bash
ls -l /home   # 详细列表（权限、大小、时间）
ls -a         # 显示隐藏文件（以`.`开头的文件）
```

#### **`cd`** - 切换目录
```bash
cd /var/log   # 进入 `/var/log` 目录
cd ..         # 返回上一级目录
```

#### **`cp`** - 复制文件/目录
```bash
cp file.txt /backup/      # 复制文件
cp -r dir1/ dir_backup/   # 递归复制目录
```

#### **`mv`** - 移动或重命名文件
```bash
mv old.txt new.txt        # 重命名文件
mv file.txt /target_dir/  # 移动文件到目标目录
```

#### **`rm`** - 删除文件/目录
```bash
rm file.txt              # 删除文件
rm -r dir/               # 递归删除目录（谨慎使用！）
```

#### **`mkdir`** - 创建目录
```bash
mkdir project_files      # 创建空目录
mkdir -p parent/child    # 创建多级目录
```

#### **`find`** - 查找文件
```bash
find /home -name "*.log"   # 按名称查找文件
find . -type f -size +10M  # 查找大于10MB的文件
```

---

### **2. 文本处理**
#### **`cat`** - 查看文件内容
```bash
cat config.yml          # 显示文件内容
cat file1.txt file2.txt > merged.txt  # 合并文件
```

#### **`grep`** - 文本搜索
```bash
grep "error" app.log     # 查找包含 "error" 的行
grep -i "warning" *.log  # 忽略大小写搜索
```

#### **`sed`** - 流编辑器（替换文本）
```bash
sed 's/foo/bar/g' file.txt      # 替换所有 "foo" 为 "bar"
sed -i.bak 's/old/new/' file    # 直接修改文件（备份原文件）
```

#### **`awk`** - 文本分析工具
```bash
awk '{print $1}' data.txt      # 打印第一列
awk -F',' '{sum += $3} END {print sum}' data.csv  # 对第三列求和
```

#### **`tail` / `head`** - 查看文件尾部/头部
```bash
tail -n 100 app.log       # 查看最后100行
tail -f app.log           # 实时跟踪日志更新
head -n 5 data.csv        # 查看前5行
```

---

### **3. 系统信息与管理**
#### **`ps`** - 查看进程状态
```bash
ps aux | grep nginx      # 查看nginx相关进程
ps -ef                   # 显示所有进程的完整信息
```

#### **`top` / `htop`** - 实时监控系统资源
```bash
top                      # 动态查看CPU、内存占用
htop                     # 更友好的交互式监控工具（需安装）
```

#### **`df` / `du`** - 磁盘空间检查
```bash
df -h                   # 查看磁盘使用情况（人类可读格式）
du -sh /var/log/        # 统计目录总大小
```

#### **`free`** - 查看内存使用
```bash
free -h                # 显示内存和Swap使用情况（GB/MB单位）
```

#### **`uname`** - 查看系统信息
```bash
uname -a               # 显示内核版本和系统架构
```

---

### **4. 网络相关**
#### **`ping`** - 测试网络连通性
```bash
ping google.com        # 检查与Google的连通性
```

#### **`curl` / `wget`** - 下载或测试HTTP请求
```bash
curl -I http://example.com    # 查看HTTP响应头
wget http://example.com/file.zip  # 下载文件
```

#### **`netstat` / `ss`** - 查看网络连接
```bash
netstat -tuln         # 查看所有监听端口
ss -ltn               # 更快速的替代命令（推荐）
```

#### **`ssh`** - 远程登录
```bash
ssh user@192.168.1.100    # 登录远程服务器
```

#### **`scp`** - 安全复制文件
```bash
scp file.txt user@remote:/path/   # 复制文件到远程服务器
```

---

### **5. 权限管理**
#### **`chmod`** - 修改文件权限
```bash
chmod 755 script.sh     # 设置权限为 rwxr-xr-x
chmod +x script.sh      # 添加可执行权限
```

#### **`chown`** - 修改文件所有者
```bash
chown user:group file.txt   # 修改所有者和所属组
```

#### **`sudo`** - 以管理员权限执行命令
```bash
sudo apt update         # 以root权限更新软件包
```

---

### **6. 软件包管理**
#### **APT (Debian/Ubuntu)**
```bash
sudo apt update              # 更新软件包列表
sudo apt install nginx       # 安装软件
sudo apt remove nginx        # 卸载软件
```

#### **YUM/DNF (CentOS/RHEL)**
```bash
sudo dnf install httpd       # 安装软件（CentOS 8+）
sudo yum remove httpd        # 卸载软件（旧版CentOS）
```

---

### **7. 进程管理**
#### **`kill`** - 终止进程
```bash
kill 1234           # 终止PID为1234的进程
kill -9 1234        # 强制终止进程
```

#### **`systemctl`** - 管理系统服务
```bash
systemctl start nginx    # 启动服务
systemctl status nginx   # 查看服务状态
```

---

### **8. 压缩与解压**
#### **`tar`** - 打包与解包
```bash
tar -czvf archive.tar.gz dir/   # 压缩目录为gzip格式
tar -xzvf archive.tar.gz        # 解压gzip文件
```

#### **`zip` / `unzip`** - ZIP压缩
```bash
zip -r backup.zip dir/     # 压缩目录为ZIP
unzip backup.zip           # 解压ZIP文件
```

---

### **9. 其他实用命令**
#### **`history`** - 查看命令历史
```bash
history | grep "ssh"   # 查找过去执行过的ssh相关命令
```

#### **`alias`** - 创建命令别名
```bash
alias ll='ls -alF'     # 输入 `ll` 等同于 `ls -alF`
```

#### **`crontab`** - 定时任务管理
```bash
crontab -e            # 编辑当前用户的定时任务
```

---

### **总结**
掌握这些命令能覆盖大部分日常运维、开发和管理需求。建议结合以下技巧提升效率：
1. **手册查询**：使用 `man <命令>`（如 `man grep`）查看详细用法。
2. **自动补全**：按 `Tab` 键补全命令或文件名。
3. **命令历史**：按 `Ctrl+R` 搜索历史命令。

如果需要更深入的学习，可以参考：[Linux Command Line Basics](https://ubuntu.com/tutorials/command-line-for-beginners) 或 [The Linux Documentation Project](https://tldp.org/)。