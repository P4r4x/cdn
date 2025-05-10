Linux 提权专项
===

提权, 也就是**提升权限**(Privilege Escalation), 最终获得 root 权限。渗透测试中, 提权操作是无法避免的非常重要的过程。

### 常用手段

提权一定是对系统某种保护措施的利用, 逃逸或破坏。

一般来常用到的手段有这些:

-   低权限可修改高权限用户执行的脚本, 这本质上是 UGO 上的问题;
-   低权限运维人员也会输入/存储高权限凭据;
-   超越权限体系, 在其上层 (如内存) 捕获 / 修改凭据等信息和内核利用。

### 升级 shell 交互性

在拿到任何一个用户 (即使是低权限用户) 的 shell 时, 首先应该让其交互性尽可能完整。

1. 利用 python 来提升交互性:

```bash
python -c 'import pty;pty.spawn("/bin/bash")'
```

1. 禁用终端的输入预处理 (可以激活方向键):

```bash
stty raw -echo
```

3. 指定终端类型, 支持颜色输出和全屏程序

```bash
export TERM=xterm-256color
```

### 枚举

枚举（Enumeration） 是渗透测试的关键环节，其核心目标是**系统性收集目标系统的信息**，通过分析这些信息寻找可利用的脆弱点。

#### 手工枚举

尽管枚举已经有很多自动化工具, 手工枚举依然非常重要, 因为自动化工具（如 LinPEAS）易被 HIDS/EDR 检测，手工枚举可通过分段操作**规避告警**。

最常用的枚举命令:

1. 基本信息

```bash
# 当前登录名
whoami 
# 查看给定用户所在组等信息, 留空为当前用户
id [username] 
# 最近登录信息
last

# 直接显示系统版本号
uname -a
# 通过进程信息显示系统信息
cat /proc/version
cat /etc/issue
# 主机名
hostname
hostnamectl

# ip 地址
ip addr
ip a
ifconfig
# 查看路由表信息
ip route
# 查看网络邻居(内网)
ip neigh
# 查看 ARP 缓存(内网横向渗透)
arp -a
```

2. 关键信息

```bash
# 列出当前用户可以用 root 权限执行的文件清单, 这条非常关键
sudo -l
# 列出 capabilities 权限体系下, 根目录所有信息:
getcap -r / 2>/dev/null
# 列出当前目录文件详细信息
ls -liah

# 查看历史记录
history

# 查看所有用户信息: 
# root:x:0:0: root: /root:/bin/bash
# 名称:密码(x):属组:属组:描述:家目录: bash 环境
# 一般来说没有家目录的用户都是功能账户, 利用价值不会太大;
cat /etc/passwd


```
