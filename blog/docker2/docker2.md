docker 2: 特性
===

Docker的本质是通过**分层共享**机制实现资源原子化。

### 分层结构

假设现在有一个在 docker 中部署 `tomcat` 项目的交付包, 其内容结构如下:

```ini
myapp-docker/
├── docker-compose.yml     # 容器编排核心
├── dockerfile             # 构建脚本
├── .env                   # 环境变量配置
├── volumes/               # 挂载目录
│   └── tomcat-webapps/    # 绑定Tomcat工程目录
└── services/              # 依赖服务配置
    ├── redis/             # Redis配置
    └── nginx/             # Nginx配置
```

#### 只读层

可能的例子: `dockerfile` 将分层实现部署;

```dockerfile
# Dockerfile
FROM tomcat:9-jdk11         # 层1：基础层, 只读, 操作系统+Tomcat
COPY app.war /webapps/      # 层2：应用层, 只读, WAR包
VOLUME /webapps             # 层3: 元数据,（调试接口）
EXPOSE 8080                 # 层4：元数据, 端口配置
ENTRYPOINT ["catalina.sh", "run"] # 层4：入口点（元数据层）
```

只读层的文件存放在 `/var/lib/docker/overlay2` 目录下, 而可写层的数据在容器的独立目录中。只读层的内容是**不可修改**的, 在容器重启后保持不变, 而可写层的内容是**实时读写**的, 默认情况下容器重启后会丢失。

#### 哈希

示例 `dockerfile`:

```dockerfile
# 层 1: 基础层 (FROM)
FROM ubuntu:22.04

# 层 2: 修改配置文件 + 安装软件 (RUN)
RUN echo "ServerName localhost" >> /etc/apache2/apache2.conf \
    && apt-get update \
    && apt-get install -y apache2

# 层 3: 添加应用代码 (COPY)
COPY index.html /var/www/html/
```

-   层 1:  基础只读层
    -   `ubuntu:22.04` 镜像本身也是由多个层构成（例如 `base-files`, `apt`, `bash` 等包各自的层）。为了简化，我们把这些基础层合并视为 **`Layer1-base`**。
    -   哈希计算 (H1): Docker 引擎会对构成 `ubuntu:22.04` 镜像最终状态的所有文件（`/bin`, `/etc`, `/usr`, `/var` 等）进行快照，打包成一个 `tar` 文件，计算其 `SHA256` 哈希值，得到 `H1`。这个 `H1` 就是 `ubuntu:22.04` 镜像最顶层（即最终状态层）的唯一标识。**`Layer1-base`** 的 ID = `sha256:H1`。
-   层 2:  新的只读层
    -   Docker 启动一个*临时容器*，基于 **`Layer1-base`** 。
    -   在临时容器中执行各条终端指令, 如安装 apache2 服务;
    -   .**捕获差异**: 执行完毕后, Docker 引擎会比较当前容器的文件系统和启动时 (**`Layer1-base`**) 的差异, 然后捕获: 获取所有修改和新增的文件, 并记录删除的文件。
    -   Docker 将这个**差异集合**打包成一个新的 tar 文件，计算其 SHA256 哈希值，得到 `H2`。**`Layer2-run`** 的 ID = `sha256:H2`。
    >   注意：`H2` 的计算依赖于 `RUN` 命令产生的 *所有* 文件变化，不是只算修改的部分。
-   层 3:  `COPY index.html`
    -   Docker 基于 **`Layer1-base`** + **`Layer2-run`** (`H1` + `H2`) 的状态启动另一个临时容器（或*复用*）。
    -   将宿主机上的 `index.html` 文件复制到容器内的 `/var/www/html/` 目录下。这是一个**新增文件操作**。
    -   **捕获差异**： Docker 捕获到新增文件 `/var/www/html/index.html`。
    -   哈希计算 (`H3`): Docker 将这个只包含新增文件 `/var/www/html/index.htm`l 及其完整内容 (`<h1>Hello Docker Layers!</h1>`) 的集合打包成一个新的 tar 文件，计算其 SHA256 哈希值，得到 `H3`。**`Layer3-copy`** 的 ID = `sha256:H3`。
   
>   镜像本身的 ID 通常是其**最顶层** (**`Layer3-copy`**) 的哈希 `H3` 或其**配置清单** (Manifest) 的哈希。

构建结果：镜像 **`my-app:latest`**, 由 3 个只读层组成（按顺序堆叠）：

1. **`Layer1-base`**: `sha256:H1` (Ubuntu 22.04 的最终层)
2. **`Layer2-run`**: `sha256:H2` (修改配置 + 安装 Apache2)
3. **`Layer3-copy`**: `sha256:H3` (添加 `index.html`)

#### 可写层

运行容器和共享的概念发生在 `docker run` 时。

Docker 引擎的执行步骤:

- 找到镜像 `my-app:latest` 对应的层列表 (`H1`, `H2`, `H3`)。
- 检查本地存储（通常在 `/var/lib/docker/overlay2/`）是否已有这些层(对照哈希)。
- 为容器创建一个**新的、空的、可写层** (Container Writable Layer)。
- 使用联合文件系统 (如 OverlayFS) 将这 4 层挂载起来：
    -   `lowerdir` = `Layer1-base:H1,Layer2-run:H2,Layer3-copy:H3` (只读)
    -   `upperdir` = `Container Writable Layer` (可写)
    -   `merged`= 容器内看到的统一视图。

### 共享

#### 基于分层结构的共享

在多个容器运行时, 有相同哈希的只读层会共享存储空间。举个例子:

-   场景 I : 容器 A 和容器 B 都直接基于 `my-app:latest` 运行:
    -   层共享情况:
        -   `Layer1-base` (`H1`): **共享** (*磁盘上一份*，Page Cache *共享只读文件*)
        -   `Layer2-run` (`H2`): **共享**
        -   `Layer3-copy` (`H3`): **共享**
    -   哈希比较过程: 两个容器指定了同一个镜像: `my-app:latest`, docker 引擎只需要检查 `H1`, `H2`, `H3` 均已知且存在, 就可以直接复用。
    >   操作系统层面上, 运行时，内核通过 Page Cache 共享相同只读文件的内存页。

-   场景 II : 容器 C 基于 `ubuntu:22.04` 运行
    -   仅共享 FROM 层 `H1`;
    -   层共享情况:
        -   `Layer1-base` (`H1`): 共享 (和 `my-app` 容器共用同一份 `Ubuntu 22.04` 基础层)
        -   `Layer2-run`, `Layer3-copy` (`H2`, `H3`): 不共享 (容器 C 没有这个两个层)
    -   哈希比较过程: 
        -   当运行 `docker run ubuntu:22.04` 时，引擎解析出 `ubuntu:22.04` 镜像的最顶层哈希是 `H1`。
        -   引擎检查本地存储：`H1` 已存在！ (因为之前构建 `my-app` 时拉取过)。
        -   引擎直接复用本地已有的 `Layer1-base (H1)` 的磁盘数据。无需重新下载或存储。
        -   容器 C 有自己的可写层，在 `H1` 之上。

>  **考虑情景**:  容器 X 和容器 Y 有相同的 `Layer1`, 不同的 `Layer2`。 而在构建 `Layer3` 时的文件操作指令完全相同, 那么 `Layer3:X` 和 `Layer3:Y` 会共享吗?实际上, 即使指令完全一致, 由于父层存在差异, 导致即使执行了相同的变更操作，由于变更操作所作用的**底层文件状态不同**，最终导致子层的内容 (tar 包) 几乎必然不同，因此它们的哈希值 (`Layer3:X` 和 `Layer3:Y`) 也几乎必然不同，无法共享。可以说, 共享只会在极其特殊且刻意控制的情况下发生。

#### 内存共享 (Page Cache)

当容器进程读取文件系统中的文件（无论是来自底层的只读镜像层还是自己的可写层）时，内核会将文件内容缓存到内存（Page Cache）中以加速后续访问。

如果多个容器访问同一个底层**只读镜像层**中的**同一个文件**（例如 `/usr/lib/libc.so`），并且这些容器运行在**同一个主机上**，那么内核只会将这个文件在物理内存中加载一份，并通过 Page Cache 共享给所有访问它的容器进程。这极大地减少了内存消耗。

### 其他重要特性

1. 进程级隔离

    利用 Linux 内核的 `pid`, `net`, `ipc`, `mnt`, `uts`, `user`, 实现独立进程树(容器内 PID = 1),独立网络栈, 主机名隔离, 独立挂载点。

2. 一次构建，处处运行

    镜像包含应用及其完整依赖链（libc、环境变量、配置文件）。运行时通过 Docker Engine 抽象底层差异。

3. 网络模型
   
    可以近似理解为 Docker 设置了一个内网, 宿主机充当 **网关** + **交换机** 的作用

### 数据持久化: Volume

Volume 是由 Docker 管理的**独立于容器和镜像之外**的存储区域。

生命周期:

- Volume 的创建/销毁与容器解耦（`docker volume create/rm`）。
- 容器删除时，Volume 默认保留（除非使用 `docker rm -v`）。

#### 挂载

联合文件系统绕过：Volume 通过 `bind mount` 直接挂载到容器路径，完全绕过联合文件系统（**OverlayFS**）。

> 对 Volume 的读写操作不触发 `Copy-on-Write`，直接操作宿主机磁盘。

首次挂载时如果容器内目标文件夹不为空, 将被宿主机覆盖。
