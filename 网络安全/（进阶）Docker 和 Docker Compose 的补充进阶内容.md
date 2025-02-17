
### **一、Docker Compose 进阶技巧**

---

#### **1. 多环境配置**
通过 `-f` 指定不同环境的配置文件（如开发、测试、生产）：
```bash
docker-compose -f docker-compose.yml -f docker-compose.prod.yml up
```
- **用途**：分离环境配置（如端口、资源限制、密钥）。

---

#### **2. 动态扩展服务实例**
对服务进行横向扩展（例如启动3个 `web` 实例）：
```bash
docker-compose up -d --scale web=3
```
- **要求**：服务需支持无状态设计，且依赖负载均衡。

---

#### **3. 依赖检查与配置验证**
```bash
docker-compose config  # 验证docker-compose.yml语法
docker-compose images  # 查看服务使用的镜像信息
```

---

### **二、Docker 高级操作**

---

#### **1. 容器调试与故障排查**
| 命令 | 说明 |
|------|------|
| `docker diff <容器>` | 查看容器内文件系统的改动（对比镜像） |
| `docker cp <容器>:<路径> <主机路径>` | 从容器复制文件到主机 |
| `docker commit <容器> <新镜像名>` | 将容器当前状态保存为新镜像（慎用，应优先用Dockerfile） |

---

#### **2. 资源限制与监控**
限制容器资源（CPU、内存）：
```bash
docker run -d --name myapp --cpus 1.5 --memory 512m nginx
```
查看容器资源使用详情：
```bash
docker stats <容器>  # 实时监控
docker inspect <容器> | grep -i "memory\|cpu"  # 查看配置
```

---

#### **3. 容器网络深度管理**
创建自定义网络并指定IP段：
```bash
docker network create --subnet=172.20.0.0/24 mynet
docker run --network=mnet --ip=172.20.0.100 -d nginx
```
查看容器网络命名空间（需安装 `iproute2`）：
```bash
docker inspect <容器> | grep SandboxKey  # 获取网络命名空间路径
nsenter --net=<命名空间路径> ip addr  # 进入容器的网络命名空间
```

---

### **三、镜像构建优化**

---

#### **1. 多阶段构建（减少镜像体积）**
```dockerfile
# 第一阶段：构建环境
FROM golang:1.18 AS builder
WORKDIR /app
COPY . .
RUN go build -o myapp .

# 第二阶段：运行环境
FROM alpine:latest
COPY --from=builder /app/myapp /usr/local/bin/
CMD ["myapp"]
```

#### **2. 利用构建缓存**
- 将不频繁变动的操作（如安装依赖）放在 Dockerfile 的前面。
- 使用 `.dockerignore` 排除无关文件，加速构建。

---

### **四、安全与权限管理**

---

#### **1. 非 root 用户运行容器**
在 Dockerfile 中指定非特权用户：
```dockerfile
RUN groupadd -r appuser && useradd -r -g appuser appuser
USER appuser
```

#### **2. 限制容器权限**
禁用危险权限：
```bash
docker run -d --cap-drop=ALL --cap-add=NET_BIND_SERVICE nginx
```
- **常用权限**：`NET_ADMIN`（网络管理）、`SYS_PTRACE`（调试）。

---

### **五、Docker 底层原理简析**

---

#### **1. 核心组件**
- **Docker Daemon**：后台服务，管理容器生命周期。
- **Containerd**：容器运行时，负责底层操作（如创建容器）。
- **Runc**：实际执行容器进程的工具。

#### **2. 容器与虚拟机的区别**
- **容器**：共享宿主机内核，轻量级进程隔离。
- **虚拟机**：独立内核，硬件级虚拟化，资源消耗大。

---

### **六、常用命令速查表**

| 场景 | 命令 |
|------|------|
| **批量清理** | `docker system prune -a --volumes -f` |
| **查看容器IP** | `docker inspect -f '{{.NetworkSettings.IPAddress}}' <容器>` |
| **导出/导入镜像** | `docker save -o image.tar <镜像>` / `docker load -i image.tar` |
| **查看容器启动命令** | `docker inspect <容器> | grep -A 1 Args` |

---

### **七、常见问题解决方案**

---

#### **1. 端口冲突**
- **错误**：`Bind for 0.0.0.0:80 failed: port is already allocated`
- **解决**：  
  - 停止占用端口的容器：`docker stop <冲突容器>`  
  - 修改 `docker-compose.yml` 中的端口映射（如 `"8080:80"`）。

#### **2. 容器启动后立即退出**
- **排查**：  
  - 查看日志：`docker logs <容器>`  
  - 检查容器内进程是否前台运行（如未指定 `CMD` 或 `ENTRYPOINT`）。

---

### **总结**
掌握这些进阶内容后，你可以更高效地管理容器化应用，应对复杂场景。建议结合以下资源深化学习：  
- [Docker 官方文档](https://docs.docker.com/)  
- [《Docker Deep Dive》](https://www.amazon.com/Docker-Deep-Dive-Nigel-Poulton/dp/1527280304)（书籍）  
- [Play with Docker](https://labs.play-with-docker.com/)（在线实验环境）