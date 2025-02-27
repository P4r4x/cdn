---
title: Reverse Note 1
date:
updated:
type:
comments:
description: 
keywords: Reverse
top_img: https://cdn.jsdelivr.net/gh/p4r4x/cdn/img/gallery/4.png
mathjax:
katex:
aside:
aplayer: 
highlight_shrink:
random:
limit:
  type:
  value:
---
##  Hexo: 部署

### 1 安装 Hexo 命令行

先安装[宝塔面板](https://www.bt.cn/new/index.html), 然后按提示安装相关组件和 node.js 版本管理器, 方便不同环境进行版本隔离。

打开 node.js 版本管理器, 安装 `node LTS v20.18.3`, 并选为命令行版本, 然后选中模块, 安装 `hexo-cli`, `hexo`。

![1.png](https://cdn.jsdelivr.net/gh/p4r4x/cdn/post/hexo_build/1.png)

安装完成后输入 `hexo -v` 来验证安装。

### 2 用 Hexo 建站

选定目录 ( Linux 默认为 `/www/wwwroot`) 并进行网站初始化。

```bash
hexo init blog
cd blog
npm install
```

启动项目, 可以直接在命令行输入 `hexo s` 来启动, 也可以在宝塔面板中选择添加 node 项目, 然后选中项目文件夹。注意启动项设置为 `hexo server`。

![3.png](https://cdn.jsdelivr.net/gh/p4r4x/cdn/post/hexo_build/3.png)

hexo 项目的默认端口为 4000, 注意在服务器安全组合防火墙放行对应端口。配置完毕后即可访问网站。

![4.png](https://cdn.jsdelivr.net/gh/p4r4x/cdn/post/hexo_build/4.png)

### 3 配置 Git

首先安装 Git:

```bash
yum install git
```

然后配置用户名和邮箱, 安装完成后输入 `git config -l` 来验证。

```bash
git config --global user.name "你的用户名"
git config --global user.email "你的邮箱"
```

由于众所周知的原因, 用 http 的方式访问 Github 非常容易超时, 推荐使用 SSH 连接, 首先生成SSH密钥对:

```bash
ssh-keygen -t rsa -C "你的邮箱"
```

用宝塔面板打开`root/.ssh`, 复制 `id_rsa.pub` 全部内容, 在 Github 中找到 SSH 设置, 新建密钥对, 并粘贴。

测试 SSH 连接:

```
ssh -T git@github.com
```

![2.png](https://cdn.jsdelivr.net/gh/p4r4x/cdn/post/hexo_build/2.png)

### 4 连接到 Github 远程仓库

在 Github 中新建一个远程仓库并命名, 然后在项目根目录下执行:

```bash
git init
git add .
git commit -m "first commit"
git branch -M master
git remote add origin git@github.com:你的用户名/仓库名.git
git push -u origin master
```

之后的每次仓库更新需要执行:

```bash
git add .
git commit -m "更新内容"
git push
```
### 5 安装主题

在网站根目录下使用 npm 安装网站主题和两个渲染器:

```bash
npm install hexo-theme-butterfly 
npm install hexo-renderer-pug hexo-renderer-stylus --save
```
打开 `_config.yml` , 修改 `theme: butterfly` 

之后, 把主题文件夹中的 `_config.yml` 复制到 Hexo 根目录里，同时重新命名为 `_config.butterfly.yml` 。以后只需要在 `_config.butterfly.yml` 进行配置即可生效。Hexo会自动合併主题中的 `_config.yml` 和 `_config.butterfly.yml` 里的配置，如果存在同名配置，会使用 `_config.butterfly.yml` 的配置，其优先度较高。

配置完毕后再次访问网站, 显示如下则应用成功。

![5.png](https://cdn.jsdelivr.net/gh/p4r4x/cdn/post/hexo_build/5.png)

### 6 开发

Hexo 支持直接对 Markdown 做渲染, 非常方便 :smile: 。

>   Markdown 是一种轻量级标记语言, 非常适合随手写笔记或者发布博客。[了解Markdown语法](https://www.runoob.com/markdown/md-tutorial.html)

>   参考链接: [Hexo博客搭建基础教程(二)](https://www.fomal.cc/posts/4aa2d85f.html)

![小豆泥](https://cdn.jsdelivr.net/gh/p4r4x/cdn/xiaoniuni.gif)
