---
title:  
date:
updated:
type:
comments:
description:
keywords:
top_img:
mathjax:
katex:
aside:
aplayer:
highlight_shrink:
---
## 手撕Next.js

### 1.部署环境

#### 1.1 安装宝塔面板

在[宝塔官网](https://www.bt.cn/new/download.html)安装Linux宝塔面板:

```bash
url=https://download.bt.cn/install/install_panel.sh;if [ -f /usr/bin/curl ];then curl -sSO $url;else wget -O install_panel.sh $url;fi;bash install_panel.sh ed8484bec
```
部署完毕后打开宝塔面板软件商店, 安装node.js版本管理器

#### 1.2 安装next.js和相关依赖

直接使用脚手架快速安装部署 `next.js` 到网站:

```bash
npx create-next-app@latest
```

然后**添加 `node.js` 项目并启动**, 或在命令行输入
```bash
npm run dev
```

在宝塔面板中开启域名映射, 然后在SSL中申请免费的 `Let's encrypt` 证书并部署到网站

![图片]()

完成后访问网站:

![图片]()

#### 1.3 推送到 Github

在 Github 创建一个远程仓库, 并[建立连接](https://blog.csdn.net/qq_42815188/article/details/128735530), 然后将代码推送到 Github:

```bash
git init
git add .
git commit -m "Initial commit"
git remote add origin git@github.com:P4r4x/blog.git
git push -u origin master
```

#### 1.4 

安装 `remark` , `remark-html` ,支持直接对md文档做渲染
```bash
npm install remark remark-html
```


