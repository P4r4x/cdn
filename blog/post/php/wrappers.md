PHP 特性 - 伪协议
===

总结一下 CTF 等场景中常见的伪协议的利用条件, 手段, 常用方法;

## php 伪协议

### 伪协议的通用特性

php 内置的伪协议是 *stream wrappers*, 它既不是网络协议, 也不是外部命令调用; 

本质上来说, 它是直接使用这些系统调用来实现的:

```
fopen()
fread()
fwrite()
fclose()
opendir()
readdir()
stat()
unlink()
rename()
```

### file:// 协议

通常用来**读取本地文件**,

```php
file_get_contents("file:///etc/passwd");
include "file:///var/www/html/config.php";
```

#### 启用配置

`file://` 协议即使在双 off 的情况下也能启用;

- `allow_url_fopen` ：`off/on`
- `allow_url_include`：`off/on`

#### php 源码

```php
php_stream_open_wrapper_ex()
    -> file_stream_wrapper   // 针对 file:// 的 wrapper
       -> file_stream_opener
           -> _php_stream_fopen()
               -> fopen()   // C 标准库
```

> 这里的 `fopen()` 是 C 标准库函数，不是 PHP 用户函数。

`file://` 伪协议在 PHP 源码层面靠调用 C 的 `fopen()` 实现，在更底层靠 Linux 的 `open()` 系统调用。要禁用 `fopen()` 可以禁用 `file://` 协议, 不过通常来说不会这么做, 因为这一操作会影响大量其他函数的使用。

### php:// 协议

#### 启用配置

- `allow_url_fopen` ：`off/on`
- `allow_url_include`：
  - `php://input`, `php://stdin`, `php://memory`, `php://temp` 需要打开这个配置

#### php://filter 协议

`php://filter` 允许给任意流添加处理器 (filter), 一个常见的用法:

```
php://filter/read=convert.base64-encode/resource=index.php
```

协议有三个部分:
- `php://filter`: 协议头;
- `read=` 读模式, 对应的还有 `write=` 写模式; 其后为解释器;
- `resource=` 读写操作的目标;

这个协议有**读 (read)** 和**写 (write)** 两个模式, 一般用读比较多, read 模式下, 通俗的理解就是**读取, 并加工**

##### php 源码

```php
php_stream_open_wrapper_ex("php://filter/...")
    -> php_stream_filter_create()
         -> 查找所需 filter（base64、zlib等）
         -> 将 filter 链插入到 stream 上

    -> 调用底层资源的 wrapper (最终还是 file_stream_wrapper)
```

##### 常用手法

一般在渗透的时候用 `php://filter` 结合 `include()` 等函数来读取特定文件, 例如源码; 

##### 常用过滤器

只归纳了一些常用的, 来源: [PHP 手册](https://www.php.net/manual/zh/filters.php)

|过滤器|作用|
|----|----|
|`convert.base64-encode`; <br>`convert.base64-decode`|base64 编码 / 解码 |
|`string.rot13`|rot13 变换, 对字母做向前/后顺位 13 位的变换|
|`string.toupper`; <br> `string.tolower`|大小写变换|
|`convert.quoted-printable-encode`; <br> `convert.quoted-printable-decode`|quoted-printable 字符串与 8-bit 字符串编码 / 解码|
|`zlib.deflate`; <br> `zlib.inflate`|gzip 压缩/解压, 注意这里的压缩和解压都只对**文件流本身**做读写 (raw), 不涉及正常 gzip 文件的文件头 (header)|
|`bzip2.compress`; <br> `bzip2.decompress`|和上面同理, 不过是创建的 `bz2` 格式文件; |
|`mcrypt.*`; <br> `mdecrypt.*`|libmcrypt 对称加 / 解密算法|
|`zip://`||


`php://filter` 并不是文件访问协议，它只是对已有流进行加工。底层文件仍然由 `file://` 的 *fopen → open* 系统调用完成。filter 本身不依赖 `popen` 或任何命令执行链。

#### php://input 协议

`php://input` 是一个只读**原始请求体 (raw body)** 流, 可以访问请求的原始数据的只读流, 在 POST 请求中访问 POST 的 data 部分。

##### 协议特性

需要注意:

1. 在 enctype="multipart/form-data" 的时候`php://input` 是无效的。

2. 开启后, POST 内容不会解析为 `$_POST`

3. `php://input` 本质是一个**虚拟流**, 不对应任何真实文件。

##### php 源码

```php
php_stream_open_wrapper_ex("php://input")
    → php_stream_url_wrap_php
        → php_stream_php_stream_opener
            → case INPUT:
                return php_stream_memory_open(...)
```

> 注意, `php://input` 并不会调用 `file wrapper`, 因为它是虚拟流; 

PHP 在解析 HTTP 请求时就将 request body 存入一个 buffer, 打开 `php://input` 时，PHP 只是在这个 buffer 上建立一个 stream 视图。

换句话说, `php://input` 指向的是 php **内部的一块缓冲区**。

因此, 在访问 `php://input` 时, **不执行任何系统调用, 只在内存中移动指针**。

##### 常见利用

一个典型利用:

```
http://127.0.0.1/include.php?file=php://input
```

然后把代码执行内容放进 POST 正文就行了。

#### php://temp 协议

`php://temp` 是一个 *内存 + 临时文件* 的**混合流**。

在默认 2MB 的数据阈值内, 保存在内存中; 超过阈值后写入一个临时文件; 长话短说, 是**可自动溢写到磁盘的虚拟文件**。

##### php 源码

```php
php_stream_open_wrapper_ex("php://temp")
    → php_stream_url_wrap_php
        → php_stream_php_stream_opener()
            → case TEMP:
                return php_stream_temp_create(int max_memory) -> 核心

# 核心函数是 php_stream_temp_create(int max_memory)
case require_memory <= max_memory:
    Zend
        -> emalloc/realloc
# 不触发文件系统

#----

case require_memory > max_memory:
    tmpfile() # C 库 , tmpfile() 在 /tmp 创建匿名临时文件
        -> open() # 系统调用

# 将已有的内存数据 flush 到临时文件
# 后续写入全部写入该临时文件

```

> 阈值 `max_memory` 默认是 2MB;

1. 在不写入临时文件时 (`<= max_memory`) 只发生 `emalloc()` / `erealloc()` / `memcpy()`, 都是用户态内存管理, 不涉及系统调用;

2. 超出阈值时, 触发系统调用: `tmpfile()`, 临时文件根据 `sys_get_temp_dir()` 的配置存放, 这里默认是 `/tmp`:
    - `open("/tmp/...")`: 创建匿名临时文件
    - `unlink("/tmp/...")`: 立即删除目录项，但文件仍保持打开状态 (匿名)

##### 可能的利用

通过写超量文件触发落盘, 然后通过路径泄露或者报错, 找到临时文件名, 触发代码进行 RCE;

### zip / bzip2 / zlib:// 协议

用于**读取** `zip` / `bzip2` /` gzip + zlib`  文件内部的内容; 和 filter 协议中的过滤器的区别是, 这三个协议是只读不写的, 并且作用于完整的压缩文件而不仅是一段压缩流;

#### 常用手法

可以访问压缩文件中的子文件, 并且**不限制后缀名**, 例如:

```
http://127.0.0.1/include.php?file=zip:///tmp/phpinfo.jpg%23phpinfo.txt
```

> 压缩 phpinfo.txt 为 phpinfo.zip, 并上传;

### data:// 协议

使用 `data://` 数据流封装器, 以在 url 中传递相应格式的数据。通常可以用来执行代码。

#### 启用配置

- `allow_url_fopen`:on
- `allow_url_include` :on


#### php 层面

它属于 data 流包装器, `php_stream_wrapper` 注册。 主要用在 RCE bypass;

或者在不能读写文件时, 绕过 `open_basedir` 的限制, 通过 `data://`, `include` 解析它。

#### 常用手法

形如:

```
data://text/plain;base64,
data://text/plain;<?=phpinfo();?>
```

### 其它

主要是 `phar://` 协议, 会解析 phar 归档文件 (和 jar 差不多), 利用点在于特定的反序列化。

