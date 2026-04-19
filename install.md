# Gemini 聊天记录本地备份工具

将你的 Gemini 全部聊天记录抓取到本地，生成可离线搜索的静态网站。数据完全存在自己电脑上，不经过任何第三方服务。

## 安装（告诉你的 AI 助手）

> 帮我安装这个 Gemini 备份工具：https://raw.githubusercontent.com/shuai1iu/gemini-backup/main/gemini_api_capture.py
>
> 把脚本下载到 ~/bin/gemini_api_capture.py，并安装依赖 requests websockets pycryptodome。

## 使用

安装完成后，告诉你的 AI 助手：

> 帮我备份 Gemini 聊天记录

它会：
1. 检查 Chrome 是否以调试模式运行
2. 引导你启动（如未启动）
3. 自动抓取全部对话
4. 生成本地网站，直接在浏览器打开

## 平台要求

- macOS（使用 Keychain 解密 Chrome Cookie）
- Chrome 浏览器，已登录 Gemini
- Python 3.9+

## 工作原理

通过 Chrome DevTools Protocol 连接已登录的 Chrome，借用浏览器现有 Cookie 调用 Gemini 内部 API，完整获取每条对话所有轮次（无截断）。不需要任何额外账号或 API Key。

## 输出

```
~/Documents/gemini_local_site/
├── index.html          ← 搜索主页，双击打开
├── data/_all.json      ← 结构化数据，可编程处理
└── conversations/      ← 每条对话独立 HTML 页面
```
