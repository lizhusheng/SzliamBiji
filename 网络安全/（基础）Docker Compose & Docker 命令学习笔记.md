
#### **一、Docker Compose 常用命令**

---

##### **1. 启动与关闭**
| 命令 | 说明 | 示例 |
|------|------|------|
| `docker-compose up -d` | 启动容器（后台运行） | `docker-compose up -d` |
| `docker-compose down` | 停止并删除容器（保留卷、网络、镜像） | `docker-compose down` |
| `docker-compose down --volumes` | 停止并删除容器及相关卷 | `docker-compose down -v` |
| `docker-compose down --rmi all` | 停止并删除容器、卷及所有相关镜像 | `docker-compose down --rmi all` |
| `docker-compose stop` | 停止容器（不删除） | `docker-compose stop` |
| `docker-compose start` | 启动已停止的容器 | `docker-compose start` |
| `docker-compose restart` | 重启容器 | `docker-compose restart` |

---

##### **2. 容器管理**
| 命令 | 说明 | 示例 |
|------|------|------|
| `docker-compose ps` | 查看由 Compose 管理的容器状态 | `docker-compose ps` |
| `docker-compose logs` | 查看容器日志 | `docker-compose logs -f`（实时跟踪） |
| `docker-compose exec` | 进入运行中的容器 | `docker-compose exec app bash` |

---

##### **3. 镜像与配置**
| 命令 | 说明 | 示例 |
|------|------|------|
| `docker-compose build` | 根据 `Dockerfile` 重新构建镜像 | `docker-compose build` |
| `docker-compose pull` | 拉取服务所需的镜像 | `docker-compose pull` |

---

#### **二、Docker 容器生命周期管理**

---

##### **1. 运行与停止**
| 命令 | 说明 | 示例 |
|------|------|------|
| `docker run` | 启动一个新容器 | `docker run -d --name nginx nginx:latest` |
| `docker stop` | 停止一个运行中的容器 | `docker stop nginx` |
| `docker start` | 启动一个已停止的容器 | `docker start nginx` |
| `docker restart` | 重启容器 | `docker restart nginx` |

---

##### **2. 删除与清理**
| 命令 | 说明 | 示例 |
|------|------|------|
| `docker rm` | 删除已停止的容器 | `docker rm nginx` |
| `docker rm -f` | 强制删除运行中的容器 | `docker rm -f nginx` |
| `docker container prune` | 删除所有已停止的容器 | `docker container prune` |

---

#### **三、Docker 镜像管理**

---

##### **1. 查看与拉取**
| 命令 | 说明 | 示例 |
|------|------|------|
| `docker images` | 列出本地镜像 | `docker images` |
| `docker pull` | 从仓库拉取镜像 | `docker pull ubuntu:22.04` |
| `docker search` | 搜索 Docker Hub 中的镜像 | `docker search mysql` |

---

##### **2. 删除与清理**
| 命令 | 说明 | 示例 |
|------|------|------|
| `docker rmi` | 删除镜像 | `docker rmi ubuntu:22.04` |
| `docker image prune` | 删除未被容器引用的镜像 | `docker image prune -a`（删除所有未使用的镜像） |

---

#### **四、Docker 网络与卷管理**

---

##### **1. 网络操作**
| 命令 | 说明 | 示例 |
|------|------|------|
| `docker network ls` | 列出所有网络 | `docker network ls` |
| `docker network create` | 创建自定义网络 | `docker network create mynet` |
| `docker network inspect` | 查看网络详细信息 | `docker network inspect mynet` |

---

##### **2. 卷操作**
| 命令 | 说明 | 示例 |
|------|------|------|
| `docker volume ls` | 列出所有卷 | `docker volume ls` |
| `docker volume rm` | 删除卷 | `docker volume rm myvol` |
| `docker volume prune` | 删除未使用的卷 | `docker volume prune` |

---

#### **五、系统清理与维护**

---

##### **1. 一键清理**
| 命令 | 说明 | 示例 |
|------|------|------|
| `docker system prune` | 清理所有未使用的资源（容器、镜像、网络、构建缓存） | `docker system prune -a --volumes`（包含卷） |

---

#### **六、其他实用命令**

---

##### **1. 调试与监控**
| 命令 | 说明 | 示例 |
|------|------|------|
| `docker logs` | 查看容器日志 | `docker logs -f nginx`（实时跟踪） |
| `docker exec` | 进入运行中的容器 | `docker exec -it nginx bash` |
| `docker stats` | 实时监控容器资源使用 | `docker stats` |

---

##### **2. 信息查看**
| 命令 | 说明 | 示例 |
|------|------|------|
| `docker ps` | 查看运行中的容器 | `docker ps -a`（包含已停止的容器） |
| `docker inspect` | 查看容器/镜像的详细信息 | `docker inspect nginx` |

---

#### **注意事项**
1. **数据持久化**：使用 `-v` 挂载卷避免数据丢失，例如：
   ```bash
   docker run -v /host/path:/container/path nginx
   ```
2. **危险操作**：`docker rm -f` 和 `docker system prune` 会直接删除资源，需谨慎使用。
3. **版本差异**：新版本 Docker 使用 `docker compose`（无连字符），旧版使用 `docker-compose`。

---

#### **常用组合命令**
- **批量停止所有容器**：
  ```bash
  docker stop $(docker ps -aq)
  ```
- **批量删除所有镜像**：
  ```bash
  docker rmi -f $(docker images -aq)
  ```