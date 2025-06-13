# 微信公众号 AI 助手

这是一个基于 Flask 的微信公众号后端应用，集成了 Gemini AI 模型，可以处理文本、图片、语音消息，并提供 AI 生成的回复。

## 功能特性

- **文本消息处理**:接收用户文本消息，调用 Gemini AI 生成回复。
- **图片消息处理**:接收用户图片，调用 Gemini AI 进行图片识别和内容理解，用户可通过特定指令查询识别结果。
- **语音消息处理**:接收用户语音（需在微信后台开启语音识别），将识别后的文本交由 Gemini AI 处理。
- **智能回复**:利用 Gemini AI 的强大能力，提供智能、连贯的对话体验。
- **异步处理**:对于耗时的 AI 操作（如图片识别），采用异步处理，避免微信请求超时。
- **结果缓存**:使用 Redis 缓存 AI 处理结果和用户重复的文本请求，提高响应速度并减少 API 调用。
- **超长回复转图片**:当 AI 回复文本过长时，自动转换为图片发送，突破微信文本长度限制。
- **配置灵活**:通过环境变量配置各项参数，如 API 密钥、服务器端口、AI 模型参数等。
- **详细日志**:记录详细的 JSON 格式日志，方便问题排查和监控。
- **URL 安全检查**:对用户发送的图片链接进行基本的安全检查，防止 SSRF 攻击。
- **依赖管理**:提供 `requirements.txt` 文件，方便快速部署。

## 项目结构

```
wechat/
├── app.py                   # Flask 应用主文件，处理微信消息路由和核心逻辑
├── config.py                # 应用配置，包括日志、环境变量、AI和Redis初始化
├── constants.py             # 存放应用中使用的常量字符串
├── utils.py                 # 通用工具函数模块
├── wechat_handler.py        # 封装微信相关操作，如签名验证、消息解析/构建、素材管理
├── ai_handler.py            # 封装 AI 模型交互逻辑
├── redis_handler.py         # 封装 Redis 缓存操作
├── requirements.txt         # Python 依赖包列表
├── SourceHanSansSC-Regular.otf # (可选) 思源黑体字体文件，用于文本转图片
├── .env.example             # (可选) 环境变量示例文件
└── README.md                # 项目说明文件
```

## 环境准备与部署

1.  **Python 环境**: 确保已安装 Python 3.8 或更高版本。
2.  **依赖安装**: 在项目根目录下执行 `pip install -r requirements.txt`。
3.  **环境变量配置**:
    *   复制 `.env.example` (如果提供) 为 `.env` 文件，或者直接设置以下环境变量：
        *   `WECHAT_TOKEN`: 微信公众号后台设置的 Token。
        *   `GEMINI_API_KEY`: Google Gemini AI 的 API Key。
        *   `WECHAT_APPID`: 微信公众号的 AppID。
        *   `WECHAT_APPSECRET`: 微信公众号的 AppSecret。
        *   `REDIS_HOST`: Redis 服务器地址 (默认为 `localhost`)。
        *   `REDIS_PORT`: Redis 服务器端口 (默认为 `6379`)。
        *   `REDIS_PASSWORD`: (可选) Redis 密码。
        *   `REDIS_DB`: (可选) Redis 数据库编号 (默认为 `0`)。
        *   `FONT_PATH`: (可选) 用于文本转图片的字体文件路径 (如 `./SourceHanSansSC-Regular.otf`)。如果未提供或文件不存在，会尝试使用 Pillow 默认字体，中文显示可能不佳。
        *   `PORT`: (可选) 应用运行的端口 (默认为 `80`)。
        *   其他 AI 模型参数和超时时间等也可通过环境变量配置，详见 `config.py`。
4.  **字体文件**: (可选但推荐) 下载[思源黑体](https://github.com/adobe-fonts/source-han-sans/tree/release/OTF/SimplifiedChinese) (例如 `SourceHanSansSC-Regular.otf`) 并放置在项目根目录，或通过 `FONT_PATH` 环境变量指定其路径。这用于将超长文本回复转换为图片时获得更好的中文显示效果。
5.  **Redis 服务**: 确保 Redis 服务正在运行并且网络可达。

## 运行

在项目根目录下执行：

```bash
python app.py
```

应用默认会使用 Waitress WSGI 服务器（如果已安装）在 `0.0.0.0` 的 `80` 端口（或 `PORT` 环境变量指定的端口）启动。如果 Waitress 未安装，则会回退到 Flask 内置的开发服务器（不推荐用于生产环境）。

## 微信公众号配置

1.  登录微信公众平台。
2.  进入 “开发” -> “基本配置”。
3.  **服务器配置**:
    *   **URL**: 填写你部署应用的公网访问地址，例如 `http://yourdomain.com/` 或 `http://your_public_ip:port/`。
    *   **Token**: 填写与环境变量 `WECHAT_TOKEN` 一致的值。
    *   **EncodingAESKey**: 可以选择明文模式或安全模式。如果选择安全模式，需要生成并填写 EncodingAESKey，并在代码中相应处理加解密（当前代码示例为明文模式）。
    *   **消息加解密方式**: 根据选择是明文模式还是安全模式。
4.  点击 “提交” 并 “启用” 服务器配置。
5.  (可选) 在 “开发” -> “接口权限” 中，根据需要开启 “语音识别”权限，以便应用能接收到微信后台自动转换的语音识别文本。

## 注意事项

*   **安全性**: 请务必妥善保管您的 API 密钥和微信敏感配置信息，不要硬编码到代码中或提交到公共代码仓库。
*   **错误处理**: 应用包含基本的错误处理和日志记录，但生产环境建议配置更完善的监控和告警机制。
*   **异步任务**: 图片处理是异步的。在某些无状态的部署环境（如某些 Serverless 平台），后台线程可能在主请求结束后被终止。对于这类环境，建议将异步任务（如 `process_image_async`）改造为使用消息队列（如 Celery + RabbitMQ/Redis）等更可靠的异步方案。
*   **微信 API 调用限制**: 注意微信对 Access Token 获取、媒体文件上传/下载等接口的调用频率限制，避免超出配额。

## 未来可扩展方向

*   集成更丰富的 AI 功能，如多轮对话、情感分析等。
*   支持更多微信消息类型和事件。
*   实现更完善的用户管理和个性化设置。
*   优化性能和资源使用。
*   添加单元测试和集成测试。

<img width="805" alt="image" src="https://github.com/user-attachments/assets/b77857a6-f0a3-457e-8900-bd5141e045a9" />


