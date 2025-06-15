# 微信公众号 AI 助手

这是一个基于 Flask 框架和 Google Gemini AI 模型构建的微信公众号 AI 助手，旨在为用户提供智能文本问答和图片识别服务。当 AI 回复内容过长时，系统能自动将文本转换为图片并发送给用户，以规避微信文本消息的字数限制。项目集成了多种生产环境优化，包括日志、缓存、SSRF 防护、敏感词过滤和健康检查等，确保了服务的高可用性和安全性。

## 目录

* [功能特性](#功能特性)
* [技术栈](#技术栈)
* [部署](#部署)
    * [环境准备](#环境准备)
    * [安装依赖](#安装依赖)
    * [配置](#配置)
    * [运行](#运行)
* [使用指南](#使用指南)
    * [文本问答](#文本问答)
    * [图片识别](#图片识别)
    * [语音识别](#语音识别)
* [安全性和合规性](#安全性和合规性)
* [可观测性](#可观测性)
* [未来优化方向](#未来优化方向)
* [许可证](#许可证)

## 功能特性

* **微信消息处理**: 支持接收和回复文本、图片、语音和事件（关注/取消关注）消息。
* **智能文本问答**: 通过 Google Gemini AI 模型为用户提供智能对话服务。
* **图片识别与分析**: 用户发送图片后，AI 模型会进行识别和详细描述。
* **长文本转图片**: 当 AI 回复内容超过微信文本消息字数限制时，自动将回复文本渲染成图片发送，提升用户体验。
* **Redis 缓存**:
    * 缓存图片识别结果，用户可以通过特定命令查询。
    * 缓存文本问答结果，提高重复查询的响应速度并减少 AI API 调用。
* **SSRF 防护**: 对外部图片 URL 进行严格的安全校验，防止服务器端请求伪造攻击。
* **敏感词过滤**: 对用户输入内容和 AI 生成的回复内容进行敏感词检测，确保内容合规性。
* **Access Token 自动刷新**: 自动管理微信 Access Token 的获取和缓存，确保与微信接口的通信顺畅。
* **健壮的错误处理**: 针对各种异常情况（AI 服务不可用、网络问题、无效输入等）提供友好的错误提示。
* **日志系统**: 使用结构化 JSON 日志和按时间轮转的日志文件，便于日志收集和分析。
* **可观测性指标**: 暴露 Prometheus 兼容的 `/metrics` 端点，提供请求量、AI 调用状态、缓存命中率等关键指标。
* **Redis 健康检查**: 后台线程周期性检查 Redis 连接，并在断开时尝试自动重连，增强服务可用性。
* **请求会话复用**: 使用 `requests.Session` 复用 HTTP 连接，提高网络请求效率。
* **字体支持**: 支持加载自定义字体，确保中文在图片中正常显示。

## 技术栈

* **后端框架**: Flask
* **AI 模型**: Google Gemini API (`google-generativeai` 库)
* **数据库/缓存**: Redis
* **图片处理**: Pillow (PIL Fork)
* **HTTP 请求**: Requests
* **XML 解析**: `defusedxml.ElementTree` (用于安全解析 XML)
* **日志**: `logging`, `python-json-logger`, `logging.handlers.TimedRotatingFileHandler`
* **并发**: `concurrent.futures.ThreadPoolExecutor`
* **网络工具**: `ipaddress`, `urllib.parse`, `socket`

## 部署

### 环境准备

1.  **Python 环境**: 推荐使用 Python 3.8+。
2.  **Redis 服务**: 确保你的服务器上运行着 Redis 服务，并可供应用访问。
3.  **敏感词文件**: 创建一个名为 `sensitive_words.txt` 的文本文件，每行一个敏感词。如果不需要敏感词过滤，可以不创建此文件或保持为空。
    ```
    # 示例 sensitive_words.txt
    敏感词1
    敏感词2
    违禁内容
    ```
4.  **字体文件**: 下载一个支持中文的 TrueType 字体文件（例如：思源黑体 `SourceHanSansSC-Regular.otf`），并将其放在项目根目录或指定路径。

### 安装依赖

```bash
pip install Flask google-generativeai Pillow requests redis defusedxml python-json-logger gunicorn
```

### 配置

本项目通过环境变量进行配置。请根据实际情况设置以下环境变量：

| 环境变量                     | 说明                                                         | 示例值/默认值                       |
| :--------------------------- | :----------------------------------------------------------- | :---------------------------------- |
| `WECHAT_TOKEN`               | 微信公众号后台填写的 Token                                   | `your_wechat_token`                 |
| `WECHAT_APPID`               | 微信公众号的 AppID                                           | `wx1234567890abcdef`                |
| `WECHAT_APPSECRET`           | 微信公众号的 AppSecret                                       | `your_app_secret`                   |
| `GEMINI_API_KEY`             | Google Gemini API 密钥                                       | `AIzaSyB-xxxxxxxxxxxxxx`            |
| `GEMINI_MODEL_NAME`          | Gemini 模型名称                                              | `gemini-2.0-flash`                  |
| `GEMINI_TEMPERATURE`         | 模型生成温度 (0.0-1.0)                                       | `0.7`                               |
| `GEMINI_TOP_P`               | 模型 Top P 参数 (0.0-1.0)                                    | `0.9`                               |
| `GEMINI_TOP_K`               | 模型 Top K 参数                                              | `40`                                |
| `GEMINI_MAX_OUTPUT_TOKENS`   | 模型最大输出 Token 数                                        | `8192`                              |
| `REDIS_HOST`                 | Redis 服务器地址                                             | `localhost`                         |
| `REDIS_PORT`                 | Redis 端口                                                   | `6379`                              |
| `REDIS_DB`                   | Redis 数据库索引                                             | `0`                                 |
| `REDIS_PASSWORD`             | Redis 密码 (如果存在)                                        | `your_redis_password` (可选)        |
| `MAX_WORKER_THREADS`         | 异步处理图片的线程池大小                                     | `5`                                 |
| `FONT_PATH`                  | 中文字体文件路径 (例如: `./SourceHanSansSC-Regular.otf`)      | `./SourceHanSansSC-Regular.otf`     |
| `SENSITIVE_WORDS_FILE`       | 敏感词文件路径                                               | `./sensitive_words.txt`             |
| `LOG_DIR`                    | 日志文件存放目录                                             | `./logs`                            |

**推荐使用 `.env` 文件进行管理**：
创建一个 `.env` 文件在项目根目录，内容如下：

```dotenv
WECHAT_TOKEN=your_wechat_token
WECHAT_APPID=wx1234567890abcdef
WECHAT_APPSECRET=your_app_secret
GEMINI_API_KEY=AIzaSyB-xxxxxxxxxxxxxx
GEMINI_MODEL_NAME=gemini-2.0-flash
GEMINI_TEMPERATURE=0.7
GEMINI_TOP_P=0.9
GEMINI_TOP_K=40
GEMINI_MAX_OUTPUT_TOKENS=8192

REDIS_HOST=localhost
REDIS_PORT=6379
REDIS_DB=0
# REDIS_PASSWORD=your_redis_password # 如果有密码，请取消注释并填写

MAX_WORKER_THREADS=5
FONT_PATH=./SourceHanSansSC-Regular.otf
SENSITIVE_WORDS_FILE=./sensitive_words.txt
LOG_DIR=./logs
```
部署时，可以通过 `source .env` 命令加载环境变量，或者在 Docker Compose/Kubernetes 配置中直接设置。

### 运行

#### 直接运行

```bash
python app.py
```

服务将监听在 `0.0.0.0:80`。

#### 使用 Gunicorn (推荐用于生产环境)

```bash
gunicorn -w 4 -b 0.0.0.0:80 app:app
```
其中 `-w 4` 表示启动 4 个 worker 进程。

#### Docker 部署 (推荐)

1.  **创建 Dockerfile** (如果项目根目录没有)
    ```dockerfile
    # Dockerfile
    FROM python:3.9-slim-buster

    WORKDIR /app

    COPY requirements.txt .
    RUN pip install --no-cache-dir -r requirements.txt

    COPY . .

    # 如果字体和敏感词文件不在项目根目录，请修改下方路径
    # 确保这些文件在容器中可访问，这里假设它们位于 /app 目录下
    # 可以通过 VOLUME 或 COPY 命令挂载/复制
    # COPY SourceHanSansSC-Regular.otf /app/SourceHanSansSC-Regular.otf
    # COPY sensitive_words.txt /app/sensitive_words.txt

    EXPOSE 80

    CMD ["gunicorn", "-w", "4", "-b", "0.0.0.0:80", "app:app"]
    ```

2.  **创建 requirements.txt**
    ```
    Flask
    google-generativeai
    Pillow
    requests
    redis
    defusedxml
    python-json-logger
    gunicorn
    ipaddress
    ```

3.  **构建 Docker 镜像**
    ```bash
    docker build -t wechat-gemini-bot .
    ```

4.  **运行 Docker 容器**
    ```bash
    docker run -d \
      -p 80:80 \
      --name wechat-gemini-bot \
      -e WECHAT_TOKEN="your_wechat_token" \
      -e WECHAT_APPID="wx1234567890abcdef" \
      -e GEMINI_API_KEY="AIzaSyB-xxxxxxxxxxxxxx" \
      -e REDIS_HOST="your_redis_host" \
      -e REDIS_PORT="6379" \
      -e REDIS_PASSWORD="your_redis_password" \
      -e FONT_PATH="/app/SourceHanSansSC-Regular.otf" \
      -e SENSITIVE_WORDS_FILE="/app/sensitive_words.txt" \
      -v /path/to/your/logs:/app/logs \ # 挂载日志目录，便于查看和持久化
      wechat-gemini-bot
    ```
    请替换所有 `your_...` 占位符为你的实际值。同时，请确保 `/path/to/your/logs` 是你希望日志文件存储在宿主机上的路径。

## 使用指南

将你的微信公众号服务器配置指向部署的服务器地址（例如：`http://your_domain.com/` 或 `http://your_ip_address/`），并填写你在环境变量中设置的 `WECHAT_TOKEN`。

### 文本问答

直接向公众号发送文本消息，AI 会进行回复。

### 图片识别

发送图片给公众号，AI 会对图片内容进行识别和描述。由于图片识别需要时间，系统会先回复“图片已收到，AI正在努力识别中...”，约 10-20 秒后，你需要发送 **`查询图片结果`** 来获取 AI 的识别结果。

### 语音识别

发送语音消息给公众号，系统会尝试识别语音内容，并将识别出的文本发送给 AI 进行回复。

## 安全性和合规性

* **SSRF 防护**: `is_safe_url` 函数用于严格校验外部 URL，包括 IP 地址的私有性检查和 DNS 解析结果验证，防止恶意请求访问内部资源。

* **敏感词过滤**: `sensitive_words.txt` 文件提供了一个敏感词过滤机制，对用户输入和 AI 生成的回复进行双重检查，确保内容符合法规要求。如果检测到敏感词，将返回预设的合规性提示。

* **XML 解析安全**: 使用 `defusedxml.ElementTree` 库来防止 XML 外部实体注入等攻击。

* **环境依赖校验**: 启动时会检查必要的环境变量是否配置，确保服务安全运行。

## 可观测性

### 日志

日志采用 JSON 格式输出到文件 (`./logs/wechat_gemini.log`) 和控制台，并按天轮转。日志中包含 `request_id` 和 `user_id` 等上下文信息，方便追踪特定请求和用户的行为。

### 指标暴露

项目在 `/metrics` 路径下暴露了兼容 Prometheus 的纯文本格式指标，可以通过 Prometheus 等监控系统进行抓取和可视化。

**访问地址**: `http://your_domain.com/metrics` 或 `http://your_ip_address/metrics`

暴露的指标包括：

* `requests_total`: 按消息类型统计的总请求数。

* `ai_calls_total`: AI API 调用的成功、失败和被阻断次数。

* `ai_response_time_seconds`: AI 响应时间的总和与计数（用于计算平均响应时间）。

* `image_download_bytes_total`: 下载图片的总字节数。

* `image_download_failed_total`: 图片下载失败的总次数。

* `image_process_failed_total`: 图片处理失败的总次数。

* `wechat_media_upload_total`: 微信媒体上传的成功与失败次数。

* `redis_cache_total`: Redis 缓存的命中和未命中次数。

* `sensitive_content_blocked_total`: 因敏感内容被阻断的消息总数。

* `api_errors_total`: 内部 API 错误总数。

## 未来优化方向

尽管当前代码已经包含了许多生产级别的优化，但仍有一些可以探索的未来改进方向：

* **异步回复队列**: 对于耗时较长的操作（如图片识别），可以先回复用户“处理中”，然后将最终结果通过微信客服消息接口异步推送，进一步提升用户体验（需要微信客服消息权限）。

* **更专业的敏感词过滤**: 引入更复杂的敏感词匹配算法（如 Aho-Corasick），或集成第三方内容审核 API，以应对更高级的敏感内容识别需求。

* **AI 多模态回复**: 探索 Gemini 的其他输出能力，例如生成图片、代码、视频等，丰富 AI 助手的回复形式。

* **更完善的错误码体系**: 为内部错误定义更细粒度的错误码，便于自动化监控和报警。

* **负载均衡和横向扩展**: 在高并发场景下，考虑使用 Kubernetes 或其他容器编排工具进行服务的负载均衡和弹性伸缩。

* **持久化存储**: 如果需要存储用户的长期对话历史或更多数据，可以考虑集成关系型数据库（如 PostgreSQL）或 NoSQL 数据库。

* **配置中心**: 将环境变量配置迁移到专业的配置中心（如 Apollo, Nacos），支持动态配置更新。

## 许可证

本项目采用 [MIT 许可证](LICENSE)。
