import hashlib
import time
import requests
from flask import Flask, request, make_response
from defusedxml.ElementTree import fromstring
from xml.sax.saxutils import escape
import logging
import google.generativeai as genai
import os
from PIL import Image, ImageDraw, ImageFont
import io
import traceback
import re
from datetime import datetime
import textwrap # 引入 textwrap 模块
import threading
import redis
import ipaddress
from urllib.parse import urlparse, urljoin
import socket
from typing import Union # 导入 Union

app = Flask(__name__)

# ==================== 常量定义 ====================
# 用户命令
QUERY_IMAGE_RESULT_COMMAND = "查询图片结果"

# 回复消息常量
INITIAL_IMAGE_PROCESSING_MESSAGE = "图片已收到，AI正在努力识别中，请耐心等待10-20秒后发送“查询图片结果”来获取。[抱拳]"
UNSUPPORTED_MESSAGE_TYPE_REPLY = "暂不支持该类型的消息，请发送文本或图片。"
SERVER_INTERNAL_ERROR_REPLY = "服务器内部错误，请稍后重试。"
AI_SERVICE_UNAVAILABLE_REPLY = "AI 服务暂时不可用，请稍后再试。"
IMAGE_DOWNLOAD_FAILED_REPLY = "抱歉，图片下载失败，请检查网络或图片链接是否有效，然后重试。"
IMAGE_PROCESSING_FAILED_REPLY = "抱歉，图片处理失败，请重试。"
IMAGE_QUERY_NO_RESULT_REPLY = "AI正在努力识别中，或您目前没有待查询的图片识别结果，或者结果已过期。请先发送一张图片让我识别。[抱拳]"
IMAGE_QUERY_PARSE_ERROR_REPLY = "抱歉，无法解析存储的图片识别结果，请重试或重新发送图片。"
AI_REPLY_TOO_LONG_IMAGE_FAIL_PREFIX = "AI回复超长，转图片失败。以下为截断内容：\n"
AI_REPLY_EXCEPTION_REPLY = "AI回复异常，请稍后重试。"
ACCESS_TOKEN_FETCH_FAILED_REPLY = "抱歉，无法获取微信服务凭证，请联系管理员。"
UNSAFE_URL_REPLY = "抱歉，检测到图片链接可能存在安全风险，已拒绝处理。"
AI_BLOCK_REASON_PREFIX = "抱歉，AI 认为您提问的内容或图片可能存在问题，已被安全策略阻断（原因："
AI_BLOCK_REASON_SUFFIX = "）。请尝试换一种方式提问或更换图片。"
NO_REDIS_CONNECTION_REPLY = "抱歉，目前无法连接到结果存储服务，请稍后再试。"

# Redis 键前缀和过期时间
REDIS_USER_AI_RESULT_PREFIX = "wechat_ai_result:"
REDIS_TEXT_CACHE_PREFIX = "wechat_text_cache:"
AI_RESULT_EXPIRATION_SECONDS = 5 * 60  # 图片识别结果缓存时间
TEXT_CACHE_EXPIRATION_SECONDS = 5 * 60  # 文本回复缓存时间

# AI 模型配置参数 (可从环境变量配置)
GEMINI_GENERATION_CONFIG = genai.types.GenerationConfig(
    temperature=float(os.environ.get('GEMINI_TEMPERATURE', 0.7)),
    top_p=float(os.environ.get('GEMINI_TOP_P', 0.9)),
    top_k=int(os.environ.get('GEMINI_TOP_K', 40)),
    max_output_tokens=int(os.environ.get('GEMINI_MAX_OUTPUT_TOKENS', 8192))
)

# 图片下载限制 (软限制，字节)
MAX_IMAGE_DOWNLOAD_SIZE = 5 * 1024 * 1024  # 5MB

# 微信图片上传限制 (字节)
WECHAT_MAX_IMAGE_UPLOAD_SIZE = 2 * 1024 * 1024  # 2MB

# 微信文本消息限制 (字节)
WECHAT_TEXT_MAX_BYTES = 2000 # 微信文本消息限制 2048 字节，这里取安全线 2000

# API 请求超时时间
GEMINI_IMAGE_TIMEOUT = int(os.environ.get('GEMINI_IMAGE_TIMEOUT', 30)) # Gemini 图片识别超时
GEMINI_TEXT_TIMEOUT = int(os.environ.get('GEMINI_TEXT_TIMEOUT', 20))   # Gemini 文本回复超时
WECHAT_ACCESS_TOKEN_TIMEOUT = int(os.environ.get('WECHAT_ACCESS_TOKEN_TIMEOUT', 5)) # 获取微信 AccessToken 超时
WECHAT_MEDIA_UPLOAD_TIMEOUT = int(os.environ.get('WECHAT_MEDIA_UPLOAD_TIMEOUT', 10)) # 微信媒体上传超时
IMAGE_DOWNLOAD_TIMEOUT = int(os.environ.get('IMAGE_DOWNLOAD_TIMEOUT', 10)) # 图片下载超时

# ==================== 初始化配置 ====================
def setup_logging():
    """配置详细的日志记录系统"""
    log_format = '%(asctime)s - %(levelname)s - %(filename)s:%(lineno)d - %(message)s'
    log_datefmt = '%Y-%m-%d %H:%M:%S'

    # 使用 __name__ 获取当前模块的 logger
    logger = logging.getLogger(__name__)
    logger.setLevel(logging.DEBUG)

    # 避免重复添加 handlers
    if not logger.handlers:
        # 控制台输出
        console_handler = logging.StreamHandler()
        console_handler.setLevel(logging.INFO)  # 生产环境建议 INFO 或 WARNING
        console_formatter = logging.Formatter(log_format, datefmt=log_datefmt)
        console_handler.setFormatter(console_formatter)
        logger.addHandler(console_handler)

        # 文件输出（每天轮换）
        file_handler = logging.FileHandler(
            filename=f'wechat_gemini_{datetime.now().strftime("%Y%m%d")}.log',
            encoding='utf-8',
            mode='a'
        )
        file_handler.setLevel(logging.DEBUG)
        file_formatter = logging.Formatter(log_format, datefmt=log_datefmt)
        file_handler.setFormatter(file_formatter)
        logger.addHandler(file_handler)

    return logger

logger = setup_logging()

# 环境变量校验
REQUIRED_ENV_VARS = {
    'WECHAT_TOKEN': '微信Token',
    'GEMINI_API_KEY': 'Gemini API密钥',
    'WECHAT_APPID': '微信APPID',
    'WECHAT_APPSECRET': '微信APPSECRET',
    'REDIS_HOST': 'Redis主机地址',
    'REDIS_PORT': 'Redis端口',
}

missing_vars = [name for name in REQUIRED_ENV_VARS if not os.environ.get(name)]
if missing_vars:
    error_msg = f"缺少必要环境变量: {', '.join([f'{v} ({REQUIRED_ENV_VARS[v]})' for v in missing_vars])}"
    logger.critical(error_msg)
    raise EnvironmentError(error_msg)

# 初始化配置
WECHAT_TOKEN = os.environ['WECHAT_TOKEN']
GEMINI_API_KEY = os.environ['GEMINI_API_KEY']
APPID = os.environ['WECHAT_APPID']
APPSECRET = os.environ['WECHAT_APPSECRET']

# FONT_PATH: 优先从环境变量获取，如果不存在则使用默认值
FONT_PATH = os.environ.get('FONT_PATH', './SourceHanSansSC-Regular.otf')

if not os.path.exists(FONT_PATH):
    logger.critical(f"字体文件不存在: {FONT_PATH}，请确保已下载并放置在应用根目录或设置正确的路径。")
    # 如果字体文件不存在，尝试使用 Pillow 的默认字体，这可能会导致中文显示问题，但至少能运行
    try:
        ImageFont.load_default()
        logger.warning("字体文件未找到，将使用 Pillow 默认字体，中文显示可能不正常。")
        FONT_PATH = None # 设置为 None 表示使用默认字体
    except Exception as e:
        logger.critical(f"加载默认字体也失败: {e}")
        raise FileNotFoundError(f"字体文件不存在: {FONT_PATH} 且无法加载默认字体。")


try:
    genai.configure(api_key=GEMINI_API_KEY)
    gemini_model = genai.GenerativeModel('gemini-2.0-flash')
    logger.info("Gemini AI 模型 (gemini-2.0-flash) 初始化成功。")
except Exception as e:
    logger.critical(f"Gemini 初始化失败: {str(e)}\n{traceback.format_exc()}")
    raise RuntimeError("Gemini AI 模型初始化失败，请检查API密钥和网络连接。")

# ==================== Redis 配置和连接 ====================
REDIS_HOST = os.environ.get('REDIS_HOST', 'localhost')
REDIS_PORT = int(os.environ.get('REDIS_PORT', 6379))
REDIS_DB = int(os.environ.get('REDIS_DB', 0))
REDIS_PASSWORD = os.environ.get('REDIS_PASSWORD')
REDIS_MAX_CONNECTIONS = int(os.environ.get('REDIS_MAX_CONNECTIONS', 20))
REDIS_CONNECT_TIMEOUT = int(os.environ.get('REDIS_CONNECT_TIMEOUT', 5))
REDIS_SOCKET_TIMEOUT = int(os.environ.get('REDIS_SOCKET_TIMEOUT', 5))
REDIS_HEALTH_CHECK_INTERVAL = int(os.environ.get('REDIS_HEALTH_CHECK_INTERVAL', 30))

try:
    REDIS_CONNECTION_POOL = redis.ConnectionPool(
        host=REDIS_HOST,
        port=REDIS_PORT,
        db=REDIS_DB,
        password=REDIS_PASSWORD,
        max_connections=REDIS_MAX_CONNECTIONS,
        socket_connect_timeout=REDIS_CONNECT_TIMEOUT,
        socket_timeout=REDIS_SOCKET_TIMEOUT,
        decode_responses=True,
        health_check_interval=REDIS_HEALTH_CHECK_INTERVAL,
        retry_on_timeout=True
    )
    redis_client = redis.Redis(connection_pool=REDIS_CONNECTION_POOL)
    redis_client.ping()
    logger.info(f"成功连接到 Redis 服务器: {REDIS_HOST}:{REDIS_PORT} (DB: {REDIS_DB}, 连接池大小: {REDIS_CONNECTION_POOL.max_connections})")
except redis.exceptions.ConnectionError as e:
    logger.critical(f"无法连接到 Redis 服务器: {e}")
    raise RuntimeError(f"无法连接到 Redis 服务器: {e}")
except Exception as e:
    logger.critical(f"Redis 初始化失败: {e}")
    raise RuntimeError(f"Redis 初始化失败: {e}")

# @app.teardown_request
# def check_redis_connections(exc):
#     """
#     在请求结束时检查Redis连接（仅为调试和监控，非必要）。
#     由于使用了连接池，这里通常不需要显式地ping。
#     """
#     try:
#         redis_client.ping()
#         logger.debug("Redis 连接在请求结束时仍可用。")
#     except Exception as e:
#         logger.warning(f"检查 Redis 连接时发生错误: {e}")


# ==================== 核心功能 - Access Token ====================
access_token_cache = {"token": None, "expires_at": 0}
token_lock = threading.Lock()

def get_access_token() -> Union[str, None]: # 修改此处
    """
    获取微信 access_token，使用缓存并支持自动刷新。
    """
    now = int(time.time())
    with token_lock:
        # 提前一分钟刷新，避免临期失效
        if access_token_cache["token"] and access_token_cache["expires_at"] > now + 60:
            logger.debug("使用缓存的access_token。")
            return access_token_cache["token"]

    logger.info("正在获取新的access_token...")
    start_time = time.time()
    try:
        url = f"https://api.weixin.qq.com/cgi-bin/token?grant_type=client_credential&appid={APPID}&secret={APPSECRET}"
        resp = requests.get(url, timeout=WECHAT_ACCESS_TOKEN_TIMEOUT)
        resp.raise_for_status() # 检查 HTTP 状态码
        data = resp.json()

        if 'access_token' in data:
            with token_lock:
                access_token_cache["token"] = data['access_token']
                expires_in = data.get('expires_in', 7200) # 默认 7200 秒
                access_token_cache["expires_at"] = now + expires_in
            duration = time.time() - start_time
            logger.info(f"获取access_token成功，耗时: {duration:.2f}秒，有效期: {expires_in}秒，下次刷新时间: {datetime.fromtimestamp(access_token_cache['expires_at']-60)}")
            return data['access_token']

        logger.error(f"获取access_token失败，微信API返回错误: {data}")
    except requests.exceptions.Timeout:
        logger.error(f"获取access_token超时，URL: {url}")
    except requests.exceptions.RequestException as e:
        logger.error(f"获取access_token网络请求失败: {e}")
    except Exception as e:
        logger.error(f"获取access_token时发生异常: {e}\n{traceback.format_exc()}")
    return None

def verify_wechat_config() -> bool:
    """
    验证微信配置是否正确。
    """
    logger.info("开始验证微信配置...")
    if not all([WECHAT_TOKEN, APPID, APPSECRET]):
        logger.critical("微信基础配置（WECHAT_TOKEN, APPID, WECHAT_APPSECRET）不完整。")
        return False
    token = get_access_token()
    if not token:
        logger.critical("无法获取access_token，请检查WECHAT_APPID和WECHAT_APPSECRET是否正确。")
        return False
    logger.info("微信配置验证通过。")
    return True

# 服务启动前进行微信配置验证
if not verify_wechat_config():
    raise RuntimeError("微信配置验证失败，服务无法启动。请检查环境变量和网络。")

# ==================== SSRF 防范辅助函数 (增强版) ====================

def is_private_ip(ip_str: str) -> bool:
    """
    检查一个 IP 地址是否属于私有网络范围、回环地址、链路本地地址、多播地址或保留地址。
    这些地址通常不应该通过外部 URL 访问。
    """
    try:
        ip = ipaddress.ip_address(ip_str)
        # 检查是否是私有 IP (RFC1918)、回环 IP、链路本地 IP、多播 IP、保留 IP
        # ipaddress 库的这些属性已经覆盖了大部分不安全的IP范围
        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_reserved:
            return True
        # 额外检查一些可能不在上述属性中的特殊保留地址，如 0.0.0.0/8
        if ipaddress.ip_network('0.0.0.0/8').overlaps(ipaddress.ip_network(ip)):
            return True
        return False
    except ValueError:
        # 如果 ip_str 不是一个有效的 IP 地址格式，则认为不是私有 IP (或无法判断)
        logger.debug(f"IP地址格式无效，跳过私有IP检查: {ip_str}")
        return False

def is_safe_url(url: str, dns_timeout: int = 2) -> bool:
    """
    增强版检查 URL 是否安全，以防范 SSRF 攻击，包括 DNS 解析结果检查。

    参数:
    url (str): 要检查的 URL。
    dns_timeout (int): DNS 解析的超时时间（秒）。

    检查项：
    1. 协议必须是 HTTP 或 HTTPS。
    2. 主机名必须存在。
    3. 端口必须是标准端口（80, 443）或未指定。
    4. 对主机名进行 DNS 解析，确保所有解析到的 IP 地址不属于私有网络或特殊用途IP。
    """
    if not url:
        logger.warning("URL为空，拒绝处理。")
        return False

    try:
        parsed_url = urlparse(url)

        # 1. 协议检查
        if parsed_url.scheme not in ('http', 'https'):
            logger.warning(f"不安全的URL协议: {parsed_url.scheme} for URL: {url[:100]}...")
            return False

        # 2. 主机名检查
        if not parsed_url.hostname:
            logger.warning(f"URL缺少主机名: {url[:100]}...")
            return False

        # 3. 端口检查 (可选，但推荐)
        # 如果端口指定了，必须是 80 或 443
        if parsed_url.port is not None and parsed_url.port not in (80, 443):
            logger.warning(f"非标准或不安全的URL端口: {parsed_url.port} for URL: {url[:100]}...")
            return False

        # 4. IP 地址检查 (核心 SSRF 防范)
        original_timeout = socket.getdefaulttimeout()
        socket.setdefaulttimeout(dns_timeout)

        resolved_ips = set()
        try:
            # 尝试直接解析主机名，如果它是 IP 地址，直接检查
            if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", parsed_url.hostname) or \
               ':' in parsed_url.hostname: # 简单的IPv6判断，更精确的正则会更复杂
                if is_private_ip(parsed_url.hostname):
                    logger.warning(f"URL主机是私有IP地址: {parsed_url.hostname} for URL: {url[:100]}...")
                    return False
                resolved_ips.add(parsed_url.hostname)
            else:
                # 对于域名，进行 DNS 解析
                addr_info = socket.getaddrinfo(
                    parsed_url.hostname,
                    parsed_url.port if parsed_url.port else parsed_url.scheme,
                    socket.AF_UNSPEC, # 接受 IPv4 和 IPv6
                    socket.SOCK_STREAM
                )

                for info in addr_info:
                    ip_address = info[4][0]
                    if ip_address not in resolved_ips:
                        resolved_ips.add(ip_address)
                        if is_private_ip(ip_address):
                            logger.warning(f"URL主机名 '{parsed_url.hostname}' 解析到私有IP地址: {ip_address} for URL: {url[:100]}...")
                            return False

        except socket.timeout:
            logger.warning(f"DNS解析超时 for hostname: {parsed_url.hostname}, URL: {url[:100]}...")
            return False
        except socket.gaierror as e:
            logger.warning(f"DNS解析失败 for hostname: {parsed_url.hostname}, Error: {e} for URL: {url[:100]}...")
            return False
        finally:
            socket.setdefaulttimeout(original_timeout) # 恢复默认的 socket 超时设置

        if not resolved_ips:
            logger.warning(f"URL主机名 '{parsed_url.hostname}' 无法解析到任何IP地址 for URL: {url[:100]}...")
            return False

        return True
    except Exception as e:
        logger.error(f"URL安全检查过程中发生异常: {e}\n{traceback.format_exc()} for URL: {url[:100]}...")
        return False


# ==================== 消息处理接口 ====================
@app.route('/', methods=['POST'])
def handle_message():
    from_user = ""
    to_user = ""
    try:
        logger.info("收到用户消息 POST 请求。")
        xml_data = request.data
        logger.debug(f"原始XML数据: {xml_data.decode('utf-8', errors='ignore')[:500]}...")
        xml = fromstring(xml_data)
        msg_type = xml.find('MsgType').text
        from_user = xml.find('FromUserName').text
        to_user = xml.find('ToUserName').text

        logger.info(f"消息类型: {msg_type}, 来自用户: {from_user}, 发送给: {to_user}")

        if msg_type == 'text':
            content_element = xml.find('Content')
            if content_element is None or not content_element.text:
                logger.error(f"文本消息中缺少 Content 字段或为空 for user: {from_user}")
                return build_reply(from_user, to_user, "抱歉，收到的文本消息内容为空。")
            content = content_element.text
            logger.info(f"接收到文本消息: {content[:100]}...")

            if content.strip() == QUERY_IMAGE_RESULT_COMMAND:
                return query_image_result(from_user, to_user)

            ai_response_content = process_text_message(content)
            return build_reply(from_user, to_user, ai_response_content)

        elif msg_type == 'image':
            pic_url_element = xml.find('PicUrl')
            if pic_url_element is None or not pic_url_element.text:
                logger.error(f"图片消息中缺少 PicUrl 字段或为空 for user: {from_user}")
                return build_reply(from_user, to_user, "抱歉，收到的图片消息格式不完整。")
            pic_url = pic_url_element.text

            # SSRF 防范增强：对 PicUrl 进行安全检查
            if not is_safe_url(pic_url):
                logger.warning(f"检测到不安全的图片URL，拒绝处理: {pic_url[:100]}... for user: {from_user}")
                # 记录错误信息到 Redis，以便用户查询时给出具体原因
                redis_client.set(f"{REDIS_USER_AI_RESULT_PREFIX}{from_user}",
                                  f"{int(time.time())}|ERROR:{UNSAFE_URL_REPLY}",
                                  ex=AI_RESULT_EXPIRATION_SECONDS)
                return build_reply(from_user, to_user, UNSAFE_URL_REPLY)

            logger.info(f"接收到图片消息, URL 头部: {pic_url[:50]}... for user: {from_user}")

            reply_xml_str = f"""<xml>
                <ToUserName><![CDATA[{from_user}]]></ToUserName>
                <FromUserName><![CDATA[{to_user}]]></FromUserName>
                <CreateTime>{int(time.time())}</CreateTime>
                <MsgType><![CDATA[text]]></MsgType>
                <Content><![CDATA[{INITIAL_IMAGE_PROCESSING_MESSAGE}]]></Content>
            </xml>"""

            # 使用线程处理图片，避免阻塞主进程
            threading.Thread(target=async_process_image, args=(pic_url, from_user, to_user)).start()

            return make_response(reply_xml_str, 200, {'Content-Type': 'application/xml'})

        else:
            logger.warning(f"接收到不支持的消息类型: {msg_type} for user: {from_user}")
            return build_reply(from_user, to_user, UNSUPPORTED_MESSAGE_TYPE_REPLY)

    except Exception as e:
        logger.error(f"处理微信消息时发生异常: {e}\n{traceback.format_exc()}")
        safe_from_user = from_user if from_user else 'unknown_user'
        safe_to_user = to_user if to_user else 'unknown_app'
        error_xml_str = f"""<xml>
            <ToUserName><![CDATA[{safe_from_user}]]></ToUserName>
            <FromUserName><![CDATA[{safe_to_user}]]></FromUserName>
            <CreateTime>{int(time.time())}</CreateTime>
            <MsgType><![CDATA[text]]></MsgType>
            <Content><![CDATA[{SERVER_INTERNAL_ERROR_REPLY}]]></Content>
        </xml>"""
        return make_response(error_xml_str, 500, {'Content-Type': 'application/xml'})

# ==================== 后台图片处理及辅助函数 ====================
def async_process_image(pic_url: str, from_user: str, to_user: str):
    """
    异步处理图片消息：下载、识别、存储结果。
    """
    try:
        logger.info(f"后台线程开始处理图片 (URL 头部): {pic_url[:50]}... for user: {from_user}")
        start_overall_time = time.time()
        start_download_time = time.time()
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/100.0.4896.127 Safari/537.36'}
        image_data = None

        try:
            # SSRF 防护增强：禁用自动重定向，手动检查 Location 头
            image_resp = requests.get(pic_url, timeout=IMAGE_DOWNLOAD_TIMEOUT, headers=headers, stream=True, allow_redirects=False)
            image_resp.raise_for_status()

            # 检查并处理重定向
            if image_resp.status_code in (301, 302, 303, 307, 308):
                redirect_url = image_resp.headers.get('Location')
                if redirect_url:
                    # 将相对路径转换为绝对路径
                    redirect_url = urljoin(pic_url, redirect_url)
                    if not is_safe_url(redirect_url): # 对重定向后的URL进行SSRF检查
                        logger.warning(f"检测到不安全的图片URL重定向，拒绝处理: {pic_url[:50]}... -> {redirect_url[:50]}... for user: {from_user}")
                        redis_client.set(f"{REDIS_USER_AI_RESULT_PREFIX}{from_user}", f"{int(time.time())}|ERROR:{UNSAFE_URL_REPLY}", ex=AI_RESULT_EXPIRATION_SECONDS)
                        image_resp.close()
                        return
                    logger.info(f"图片URL重定向到安全地址: {pic_url[:50]}... -> {redirect_url[:50]}... for user: {from_user}")
                    # 重新请求重定向后的URL
                    image_resp.close() # 关闭之前的连接
                    image_resp = requests.get(redirect_url, timeout=IMAGE_DOWNLOAD_TIMEOUT, headers=headers, stream=True)
                    image_resp.raise_for_status()
                else:
                    logger.warning(f"图片URL发生重定向但未找到Location头: {pic_url[:50]}... for user: {from_user}")
                    redis_client.set(f"{REDIS_USER_AI_RESULT_PREFIX}{from_user}", f"{int(time.time())}|ERROR:{IMAGE_DOWNLOAD_FAILED_REPLY} (重定向失败)", ex=AI_RESULT_EXPIRATION_SECONDS)
                    image_resp.close()
                    return

            # 读取内容并限制大小
            downloaded_size = 0
            image_bytes_buffer = io.BytesIO()
            for chunk in image_resp.iter_content(chunk_size=8192):
                if chunk:
                    downloaded_size += len(chunk)
                    if downloaded_size > MAX_IMAGE_DOWNLOAD_SIZE:
                        logger.warning(f"图片文件过大 ({downloaded_size/1024/1024:.2f}MB)，超过 {MAX_IMAGE_DOWNLOAD_SIZE/1024/1024:.2f}MB 限制，中断下载 for user: {from_user}")
                        redis_client.set(f"{REDIS_USER_AI_RESULT_PREFIX}{from_user}", f"{int(time.time())}|ERROR:{IMAGE_DOWNLOAD_FAILED_REPLY} (文件过大)", ex=AI_RESULT_EXPIRATION_SECONDS)
                        image_resp.close()
                        return
                    image_bytes_buffer.write(chunk)
            image_data = image_bytes_buffer.getvalue()
            image_resp.close() # 确保关闭连接

            if not image_data:
                 raise ValueError("下载的图片数据为空。")

            logger.info(f"后台图片下载完成，耗时: {time.time()-start_download_time:.2f}秒，大小: {len(image_data)/1024:.2f}KB")
        except requests.exceptions.Timeout:
            logger.error(f"后台图片下载超时 for user {from_user} (URL 头部: {pic_url[:50]}...): 请求超时")
            redis_client.set(f"{REDIS_USER_AI_RESULT_PREFIX}{from_user}", f"{int(time.time())}|ERROR:{IMAGE_DOWNLOAD_FAILED_REPLY} (下载超时)", ex=AI_RESULT_EXPIRATION_SECONDS)
            return
        except requests.exceptions.RequestException as e:
            logger.error(f"后台图片下载失败 for user {from_user} (URL 头部: {pic_url[:50]}...): {e}\n{traceback.format_exc()}")
            redis_client.set(f"{REDIS_USER_AI_RESULT_PREFIX}{from_user}", f"{int(time.time())}|ERROR:{IMAGE_DOWNLOAD_FAILED_REPLY}", ex=AI_RESULT_EXPIRATION_SECONDS)
            return
        except ValueError as e:
            logger.error(f"图片下载或处理初始阶段失败 for user {from_user}: {e}\n{traceback.format_exc()}")
            redis_client.set(f"{REDIS_USER_AI_RESULT_PREFIX}{from_user}", f"{int(time.time())}|ERROR:{IMAGE_DOWNLOAD_FAILED_REPLY}", ex=AI_RESULT_EXPIRATION_SECONDS)
            return

        try:
            img = Image.open(io.BytesIO(image_data))
            if img.mode != 'RGB':
                img = img.convert('RGB')
        except Exception as e:
            logger.error(f"无法打开或转换图片数据 for user {from_user}: {e}\n{traceback.format_exc()}")
            redis_client.set(f"{REDIS_USER_AI_RESULT_PREFIX}{from_user}", f"{int(time.time())}|ERROR:{IMAGE_PROCESSING_FAILED_REPLY} (图片格式或损坏)", ex=AI_RESULT_EXPIRATION_SECONDS)
            return

        prompt = "请用中文详细描述这张图片的内容，并尽可能分析它的含义。请直接给出描述，不要说“这张图片显示了...”之类的引导语。"
        logger.info(f"后台调用 Gemini 处理图片 for user: {from_user}...")
        ai_response_content = generate_with_retry(prompt, img, is_image_context=True)

        logger.info(f"后台AI处理图片完成 for user: {from_user}，总耗时: {time.time()-start_overall_time:.2f}秒。回复内容长度: {len(ai_response_content.encode('utf-8'))}字节")

        redis_key = f"{REDIS_USER_AI_RESULT_PREFIX}{from_user}"
        value = f"{int(time.time())}|{ai_response_content}"

        try:
            redis_client.set(redis_key, value, ex=AI_RESULT_EXPIRATION_SECONDS)
            logger.info(f"AI图片结果已为用户 {from_user} 存储到 Redis (key: {redis_key})，有效期 {AI_RESULT_EXPIRATION_SECONDS} 秒。")
        except redis.exceptions.ConnectionError as e:
            logger.error(f"无法将 AI 图片结果存储到 Redis (连接错误): {e}")
        except Exception as e:
            logger.error(f"存储 AI 图片结果到 Redis 时发生未知错误: {e}\n{traceback.format_exc()}")

    except Exception as e:
        logger.error(f"后台图片处理线程发生未捕获异常 for user {from_user}: {e}\n{traceback.format_exc()}")
        redis_client.set(f"{REDIS_USER_AI_RESULT_PREFIX}{from_user}", f"{int(time.time())}|ERROR:{IMAGE_PROCESSING_FAILED_REPLY}", ex=AI_RESULT_EXPIRATION_SECONDS)


def query_image_result(from_user: str, to_user: str) -> requests.Response:
    """
    查询用户存储的图片识别结果。
    """
    redis_key = f"{REDIS_USER_AI_RESULT_PREFIX}{from_user}"
    stored_value = None
    try:
        stored_value = redis_client.get(redis_key)
    except redis.exceptions.ConnectionError as e:
        logger.error(f"无法从 Redis 获取 AI 图片结果 (连接错误): {redis_key}, 错误: {e}")
        return build_reply(from_user, to_user, NO_REDIS_CONNECTION_REPLY)
    except Exception as e:
        logger.error(f"从 Redis 获取 AI 图片结果时发生未知错误: {redis_key}, 错误: {e}\n{traceback.format_exc()}")
        return build_reply(from_user, to_user, SERVER_INTERNAL_ERROR_REPLY)

    content_to_reply = IMAGE_QUERY_NO_RESULT_REPLY
    if stored_value:
        try:
            timestamp_str, content = stored_value.split('|', 1)
            timestamp = int(timestamp_str)

            if content.startswith("ERROR:"):
                error_message = content[6:]
                content_to_reply = f"抱歉，您的图片处理失败了（{time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(timestamp))}）。\n原因：{error_message} 请尝试重新发送图片。"
                logger.warning(f"为用户 {from_user} 返回存储在 Redis 中的图片处理失败信息: {error_message}")
            else:
                content_to_reply = f"这是您最近一次图片识别的结果（{time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(timestamp))}）:\n\n{content}"
                logger.info(f"为用户 {from_user} 返回存储在 Redis 中的图片识别结果。")
            # 清除已查询的结果，避免重复查询或查询到旧结果
            try:
                redis_client.delete(redis_key)
                logger.debug(f"已清除用户 {from_user} 的 Redis 图片结果缓存 (key: {redis_key})。")
            except Exception as e:
                logger.warning(f"清除 Redis 图片结果缓存失败 for user {from_user}: {e}")

        except ValueError:
            content_to_reply = IMAGE_QUERY_PARSE_ERROR_REPLY
            logger.error(f"解析 Redis 存储值失败 for user {from_user}, key: {redis_key}, value: {stored_value}")
    else:
        logger.info(f"用户 {from_user} 查询图片结果，Redis 中无可用结果 (key: {redis_key})。")

    return build_reply(from_user, to_user, content_to_reply)

def process_text_message(content: str) -> str:
    """
    处理文本消息，调用 AI 并缓存结果。
    """
    logger.info(f"调用 Gemini 处理文本: {content[:50]}...")
    normalized_content = content.strip().lower()
    # 使用 MD5 作为缓存键，长度适中，对于缓存键来说足够安全
    cache_key = f"{REDIS_TEXT_CACHE_PREFIX}{hashlib.md5(normalized_content.encode('utf-8')).hexdigest()}"

    try:
        cached_answer = redis_client.get(cache_key)
        if cached_answer:
            logger.info(f"从 Redis 缓存中获取文本答案 (key: {cache_key[:10]}...): {cached_answer[:50]}...")
            return cached_answer
    except redis.exceptions.ConnectionError as e:
        logger.warning(f"无法从 Redis 获取文本缓存 (连接错误): {cache_key}, 错误: {e}")
        # 不中断流程，尝试直接调用 AI
    except Exception as e:
        logger.warning(f"获取文本缓存时发生未知错误: {cache_key}, 错误: {e}\n{traceback.format_exc()}")
        # 不中断流程，尝试直接调用 AI

    try:
        ai_response_content = generate_with_retry(content, is_image_context=False)
        if ai_response_content:
            try:
                redis_client.set(cache_key, ai_response_content, ex=TEXT_CACHE_EXPIRATION_SECONDS)
                logger.info(f"AI文本答案已存入 Redis 缓存 (key: {cache_key[:10]}...)，有效期 {TEXT_CACHE_EXPIRATION_SECONDS} 秒。")
            except redis.exceptions.ConnectionError as e:
                logger.warning(f"无法将 AI 文本答案存储到 Redis (连接错误): {cache_key}, 错误: {e}")
            except Exception as e:
                logger.warning(f"存储 AI 文本答案到 Redis 时发生未知错误: {cache_key}, 错误: {e}\n{traceback.format_exc()}")
        return ai_response_content
    except Exception as e:
        logger.error(f"处理文本消息时 AI 调用失败: {e}\n{traceback.format_exc()}")
        return AI_SERVICE_UNAVAILABLE_REPLY

def generate_with_retry(prompt: str, image=None, max_retries: int = 3, is_image_context: bool = False) -> str:
    """
    调用 Gemini AI 模型生成内容，支持重试和指数退避。
    """
    retry_count = 0
    ai_api_request_timeout = GEMINI_IMAGE_TIMEOUT if is_image_context else GEMINI_TEXT_TIMEOUT
    logger.debug(f"AI请求超时设置为: {ai_api_request_timeout}秒 (is_image_context={is_image_context})")

    start_overall_ai_time = time.time()
    while retry_count < max_retries:
        try:
            start_single_attempt_time = time.time()
            contents = [prompt]
            if image:
                contents.insert(0, image) # 图片作为第一个元素

            response = gemini_model.generate_content(
                contents,
                generation_config=GEMINI_GENERATION_CONFIG,
                request_options={"timeout": ai_api_request_timeout}
            )
            # 检查 AI 返回的 BlockReason，提供更详细的错误信息
            if response.prompt_feedback and response.prompt_feedback.block_reason:
                block_reason = response.prompt_feedback.block_reason.name
                logger.warning(f"AI 提示被阻断，原因: {block_reason}")
                return f"{AI_BLOCK_REASON_PREFIX}{block_reason}{AI_BLOCK_REASON_SUFFIX}"

            if not response or not response.text:
                raise ValueError("AI returned an empty or invalid response.")

            current_ai_duration = time.time() - start_overall_ai_time
            logger.info(f"AI 生成成功，耗时: {current_ai_duration:.2f}秒 (单次尝试: {time.time()-start_single_attempt_time:.2f}秒)")
            return response.text.strip()
        except Exception as e:
            retry_count += 1
            wait_time = min(2 ** retry_count, 10) # 指数退避，最大10秒
            logger.warning(f"AI 生成失败 (尝试 {retry_count}/{max_retries}), 等待 {wait_time:.2f} 秒: {e}\n{traceback.format_exc()}")
            time.sleep(wait_time)
    logger.error("AI 生成失败，已达到最大重试次数。")
    return AI_SERVICE_UNAVAILABLE_REPLY

def build_reply(from_user: str, to_user: str, content: str) -> requests.Response:
    """
    构建微信回复 XML，支持文本超长时转换为图片回复。
    """
    try:
        cleaned_content = clean_content(content)
        content_bytes = len(cleaned_content.encode('utf-8'))
        reply_xml_str = None

        if content_bytes > WECHAT_TEXT_MAX_BYTES:
            logger.info(f"内容过长({content_bytes}字节 > {WECHAT_TEXT_MAX_BYTES}字节)，尝试转换为图片并回复。")
            img_data = text_to_image(cleaned_content)
            if img_data:
                if len(img_data) > WECHAT_MAX_IMAGE_UPLOAD_SIZE:
                    logger.warning(f"生成的图片大小 ({len(img_data)/1024:.2f}KB) 超过微信上传限制 ({WECHAT_MAX_IMAGE_UPLOAD_SIZE/1024:.2f}KB)。将回退为截断文本。")
                    truncated_content = clean_content(cleaned_content, max_bytes=WECHAT_TEXT_MAX_BYTES)
                    reply_xml_str = f"""<xml>
                        <ToUserName><![CDATA[{from_user}]]></ToUserName>
                        <FromUserName><![CDATA[{to_user}]]></FromUserName>
                        <CreateTime>{int(time.time())}</CreateTime>
                        <MsgType><![CDATA[text]]></MsgType>
                        <Content><![CDATA[{escape(AI_REPLY_TOO_LONG_IMAGE_FAIL_PREFIX + truncated_content)}]]></Content>
                    </xml>"""
                else:
                    media_id = upload_image_to_wechat(img_data)
                    if media_id:
                        logger.info(f"图片已成功上传至微信，MediaId: {media_id[:10]}... 使用图片回复。")
                        reply_xml_str = f"""<xml>
                            <ToUserName><![CDATA[{from_user}]]></ToUserName>
                            <FromUserName><![CDATA[{to_user}]]></FromUserName>
                            <CreateTime>{int(time.time())}</CreateTime>
                            <MsgType><![CDATA[image]]></MsgType>
                            <Image><MediaId><![CDATA[{media_id}]]></MediaId></Image>
                        </xml>"""
                    else:
                        logger.warning("图片上传至微信失败，回退到文本回复并截断。")
                        truncated_content = clean_content(cleaned_content, max_bytes=WECHAT_TEXT_MAX_BYTES)
                        reply_xml_str = f"""<xml>
                            <ToUserName><![CDATA[{from_user}]]></ToUserName>
                            <FromUserName><![CDATA[{to_user}]]></FromUserName>
                            <CreateTime>{int(time.time())}</CreateTime>
                            <MsgType><![CDATA[text]]></MsgType>
                            <Content><![CDATA[{escape(AI_REPLY_TOO_LONG_IMAGE_FAIL_PREFIX + truncated_content)}]]></Content>
                        </xml>"""
            else:
                logger.warning("文本转换为图片失败，回退到文本回复并截断。")
                truncated_content = clean_content(cleaned_content, max_bytes=WECHAT_TEXT_MAX_BYTES)
                reply_xml_str = f"""<xml>
                    <ToUserName><![CDATA[{from_user}]]></ToUserName>
                    <FromUserName><![CDATA[{to_user}]]></FromUserName>
                    <CreateTime>{int(time.time())}</CreateTime>
                    <MsgType><![CDATA[text]]></MsgType>
                    <Content><![CDATA[{escape(AI_REPLY_TOO_LONG_IMAGE_FAIL_PREFIX + truncated_content)}]]></Content>
                </xml>"""
        else:
            logger.info(f"内容在文本限制内({content_bytes}字节)，使用文本回复。")
            reply_xml_str = f"""<xml>
                <ToUserName><![CDATA[{from_user}]]></ToUserName>
                <FromUserName><![CDATA[{to_user}]]></FromUserName>
                <CreateTime>{int(time.time())}</CreateTime>
                <MsgType><![CDATA[text]]></MsgType>
                <Content><![CDATA[{escape(cleaned_content)}]]></Content>
            </xml>"""
        return make_response(reply_xml_str, 200, {'Content-Type': 'application/xml'})

    except Exception as e:
        logger.error(f"构建回复时发生异常: {e}\n{traceback.format_exc()}")
        safe_from_user = from_user if from_user else 'unknown_user'
        safe_to_user = to_user if to_user else 'unknown_app'
        error_xml_str = f"""<xml>
            <ToUserName><![CDATA[{safe_from_user}]]></ToUserName>
            <FromUserName><![CDATA[{safe_to_user}]]></FromUserName>
            <CreateTime>{int(time.time())}</CreateTime>
            <MsgType><![CDATA[text]]></MsgType>
            <Content><![CDATA[{AI_REPLY_EXCEPTION_REPLY}]]></Content>
        </xml>"""
        return make_response(error_xml_str, 500, {'Content-Type': 'application/xml'})

def clean_content(content: str, max_bytes: Union[int, None] = None) -> str: # 修改此处
    """
    清理文本内容，移除Markdown标记、多余空格和连续空行，并可选地按字节截断。
    """
    if not content:
        return ""
    
    # 移除常见的Markdown标记，但保留换行
    content = re.sub(r'(\*\*|__|\*|_|`|~~|#+\s*)', '', content)
    # 移除链接的Markdown格式，只保留文本
    content = re.sub(r'\[(.*?)\]\(.*?\)', r'\1', content)

    processed_lines = []
    for paragraph in content.split('\n'):
        # 移除行首尾空格，但保留完全空行
        if not paragraph.strip():
            processed_lines.append('')
        else:
            processed_lines.append(paragraph.strip())

    content = '\n'.join(processed_lines)
    # 确保没有连续的多个空行，只保留最多两个空行
    content = re.sub(r'\n{3,}', '\n\n', content)
    content = content.strip()

    if max_bytes is not None:
        encoded = content.encode('utf-8')
        if len(encoded) > max_bytes:
            logger.warning(f"内容因字节限制被截断: 原始 {len(encoded)} 字节，截断至 {max_bytes} 字节。")
            # 采用更安全的截断方式，避免截断多字节字符
            truncated_content = encoded[:max_bytes].decode('utf-8', 'ignore')
            # 确保截断后不会有不完整的字符或乱码
            while len(truncated_content.encode('utf-8')) > max_bytes:
                truncated_content = truncated_content[:-1]
            return truncated_content
    return content

def text_to_image(text: str, max_width: int = 600, font_size: int = 24, line_spacing_factor: float = 0.5) -> Union[bytes, None]: # 修改此处
    """
    将文本转换为图片。
    参数:
    text (str): 要转换的文本。
    max_width (int): 图片最大宽度。
    font_size (int): 字体大小。
    line_spacing_factor (float): 行间距与字体大小的比例。
    """
    try:
        start_time_img_gen = time.time()
        padding = 30
        line_spacing = int(font_size * line_spacing_factor)
        
        font = None
        if FONT_PATH:
            font = ImageFont.truetype(FONT_PATH, font_size)
        else:
            font = ImageFont.load_default() # Fallback to default if FONT_PATH is None

        wrapped_lines = []
        max_line_content_width = max_width - 2 * padding

        for paragraph in text.split('\n'):
            if not paragraph.strip():
                wrapped_lines.append('') # 保留空行
                continue

            current_line = []
            current_line_width = 0
            for char in paragraph:
                char_width = font.getlength(char) if FONT_PATH else font.getbbox(char)[2] # getlength更精确，getbbox兼容默认字体
                if current_line_width + char_width <= max_line_content_width:
                    current_line.append(char)
                    current_line_width += char_width
                else:
                    if current_line:
                        wrapped_lines.append("".join(current_line))
                    current_line = [char]
                    current_line_width = char_width
            if current_line:
                wrapped_lines.append("".join(current_line))


        if not wrapped_lines:
            wrapped_lines = [""]

        # 计算图片高度
        line_height = font_size + line_spacing
        img_height = 2 * padding + len(wrapped_lines) * line_height

        # 确保图片高度不会过大，防止生成超大图
        MAX_IMG_HEIGHT = 4000
        if img_height > MAX_IMG_HEIGHT:
            logger.warning(f"图片高度超过限制 {MAX_IMG_HEIGHT}px，原始高度 {img_height}px，将截断内容。")
            # 重新计算能容纳的行数
            # 预留两行给提示信息，再减去上下padding和提示行的line_height
            displayable_lines = int((MAX_IMG_HEIGHT - 2 * padding - 2 * line_height) / line_height)
            if displayable_lines < 0: # 极端情况，如果连提示信息都放不下
                displayable_lines = 0
            
            wrapped_lines = wrapped_lines[:displayable_lines]
            img_height = 2 * padding + len(wrapped_lines) * line_height # 重新计算高度

            # 添加提示信息
            if img_height + 2 * line_height <= MAX_IMG_HEIGHT: # 确保有足够空间添加提示
                wrapped_lines.append("...") # 添加省略号表示内容被截断
                wrapped_lines.append("(内容过长，已截断)")
                img_height += 2 * line_height # 为提示信息增加高度
            else:
                # 实在放不下了，就只保留原始内容，不加提示了
                pass


        img = Image.new("RGB", (max_width, img_height), (255, 255, 255))
        draw = ImageDraw.Draw(img)

        y = padding
        for line in wrapped_lines:
            draw.text((padding, y), line, font=font, fill=(0, 0, 0))
            y += line_height

        watermark = "AI生成内容"
        watermark_font = None
        if FONT_PATH:
            watermark_font = ImageFont.truetype(FONT_PATH, int(font_size * 0.8))
        else:
            watermark_font = ImageFont.load_default() # Fallback

        # getbbox 返回 (left, top, right, bottom)
        watermark_bbox = draw.textbbox((0, 0), watermark, font=watermark_font)
        watermark_width = watermark_bbox[2] - watermark_bbox[0]
        watermark_height = watermark_bbox[3] - watermark_bbox[1]

        draw.text(
            (max_width - watermark_width - 15, img_height - watermark_height - 10),
            watermark,
            font=watermark_font,
            fill=(200, 200, 200)
        )

        output = io.BytesIO()
        img.save(output, format='PNG', optimize=True, quality=85) # 适当降低质量
        logger.info(f"文本转图片耗时: {time.time()-start_time_img_gen:.2f}秒，图片大小: {len(output.getvalue())/1024:.2f}KB")
        return output.getvalue()
    except Exception as e:
        logger.error(f"文本转换为图片失败: {e}\n{traceback.format_exc()}")
        return None

def upload_image_to_wechat(image_bytes: bytes) -> Union[str, None]: # 修改此处
    """
    将图片上传到微信服务器，获取 media_id。
    """
    access_token = get_access_token()
    if not access_token:
        logger.error("上传图片失败: 无法获取有效的access_token。")
        return None
    if not image_bytes:
        logger.error("上传图片失败: 图片数据为空。")
        return None
    
    # 再次检查图片大小，确保不超过微信上传限制
    if len(image_bytes) > WECHAT_MAX_IMAGE_UPLOAD_SIZE:
        logger.error(f"上传图片失败: 图片大小 ({len(image_bytes)/1024:.2f}KB) 超过微信上传限制 ({WECHAT_MAX_IMAGE_UPLOAD_SIZE/1024:.2f}KB)。")
        return None

    try:
        url = f"https://api.weixin.qq.com/cgi-bin/media/upload?access_token={access_token}&type=image"
        files = {'media': ('ai_reply.png', image_bytes, 'image/png')}
        logger.info(f"正在上传图片到微信服务器 (大小: {len(image_bytes)/1024:.2f}KB)...")
        start_time_img_upload = time.time()
        resp = requests.post(url, files=files, timeout=WECHAT_MEDIA_UPLOAD_TIMEOUT)
        resp.raise_for_status()
        data = resp.json()
        logger.info(f"图片上传到微信耗时: {time.time()-start_time_img_upload:.2f}秒")
        if 'media_id' in data:
            logger.info(f"图片上传成功，MediaId: {data['media_id'][:10]}...")
            return data['media_id']
        logger.error(f"图片上传至微信失败，微信API返回错误: {data}")
    except requests.exceptions.Timeout:
        logger.error(f"图片上传到微信超时，URL: {url}")
    except requests.exceptions.RequestException as e:
        logger.error(f"图片上传网络请求失败: {e}\n{traceback.format_exc()}")
    except Exception as e:
        logger.error(f"图片上传过程中发生异常: {e}\n{traceback.format_exc()}")
    return None

@app.before_request
def log_request():
    """在每个请求前记录请求信息，便于调试。"""
    logger.debug(f"收到请求: {request.method} {request.url}")
    if request.args:
        logger.debug(f"查询参数: {request.args}")
    if request.method == 'POST' and request.data:
        try:
            body_preview = request.data.decode('utf-8', errors='ignore')[:500]
            logger.debug(f"请求体: {body_preview}...")
        except Exception:
            logger.debug(f"请求体（无法解码）：{request.data[:500]}...")
