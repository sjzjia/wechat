import hashlib
import time
import requests
from flask import Flask, request, make_response
from defusedxml.ElementTree import fromstring, ParseError
from xml.sax.saxutils import escape
import logging
import google.generativeai as genai
import os
from PIL import Image, ImageDraw, ImageFont
import io
import traceback
import re
from datetime import datetime
import textwrap
import threading
import redis
import ipaddress
from urllib.parse import urlparse, urljoin
import socket
from typing import Union, Dict, Any, Set
import json
from pythonjsonlogger import jsonlogger
from concurrent.futures import ThreadPoolExecutor
from logging.handlers import TimedRotatingFileHandler
import uuid

app = Flask(__name__)

# ==================== 可观测性指标存储 ====================
# 简单模拟Metrics存储，方便 /metrics 端点暴露
metrics: Dict[str, Any] = {
    'requests_total': {},  # 按消息类型统计请求总数
    'ai_calls_total': {'success': 0, 'failure': 0, 'blocked': 0}, # AI调用总数
    'ai_response_time_seconds': {'sum': 0.0, 'count': 0}, # AI响应时间
    'image_download_bytes_total': 0, # 图片下载字节数
    'image_download_failed_total': 0, # 图片下载失败次数
    'image_process_failed_total': 0, # 图片处理失败次数
    'wechat_media_upload_total': {'success': 0, 'failure': 0}, # 微信媒体上传次数
    'redis_cache_hits_total': 0, # Redis缓存命中次数
    'redis_cache_misses_total': 0, # Redis缓存未命中次数
    'sensitive_content_blocked_total': 0, # 敏感内容阻断次数
    'api_errors_total': 0 # API内部错误总数
}

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
VOICE_MESSAGE_EMPTY_RESULT_REPLY = "抱歉，语音识别结果为空，请确保语音清晰。"
VOICE_MESSAGE_PROCESSING_FAILED_REPLY = "抱歉，语音识别失败，请稍后重试或尝试发送文本消息。"
WELCOME_MESSAGE_REPLY = "欢迎关注！我是AI助手，您可以向我提问或发送图片让我识别。"
INVALID_TEXT_MESSAGE_REPLY = "抱歉，收到的文本消息内容为空。"
INVALID_IMAGE_MESSAGE_REPLY = "抱歉，收到的图片消息格式不完整。"
SENSITIVE_CONTENT_BLOCKED_REPLY = "抱歉，您发送的内容或AI生成的内容可能包含敏感信息，已被系统阻断。请修改后重试。"


# Redis 键前缀和过期时间
REDIS_USER_AI_RESULT_PREFIX = "wechat_ai_result:"
REDIS_TEXT_CACHE_PREFIX = "wechat_text_cache:"
AI_RESULT_EXPIRATION_SECONDS = 5 * 60  # 图片识别结果缓存时间
TEXT_CACHE_EXPIRATION_SECONDS = 5 * 60  # 文本回复缓存时间

# AI 模型配置参数 (可从环境变量配置)
GEMINI_MODEL_NAME = os.environ.get('GEMINI_MODEL_NAME', 'gemini-2.0-flash') # 新增：AI模型名称
GEMINI_TEMPERATURE = float(os.environ.get('GEMINI_TEMPERATURE', 0.7))
GEMINI_TOP_P = float(os.environ.get('GEMINI_TOP_P', 0.9))
GEMINI_TOP_K = int(os.environ.get('GEMINI_TOP_K', 40))
GEMINI_MAX_OUTPUT_TOKENS = int(os.environ.get('GEMINI_MAX_OUTPUT_TOKENS', 8192))
GEMINI_GENERATION_CONFIG = genai.types.GenerationConfig(
    temperature=GEMINI_TEMPERATURE,
    top_p=GEMINI_TOP_P,
    top_k=GEMINI_TOP_K,
    max_output_tokens=GEMINI_MAX_OUTPUT_TOKENS
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
WECHAT_VOICE_DOWNLOAD_TIMEOUT = int(os.environ.get('WECHAT_VOICE_DOWNLOAD_TIMEOUT', 10)) # 微信语音下载超时
IMAGE_DOWNLOAD_TIMEOUT = int(os.environ.get('IMAGE_DOWNLOAD_TIMEOUT', 10)) # 图片下载超时
DNS_RESOLVE_TIMEOUT = 2 # DNS 解析超时时间

# 文本转图片限制
MAX_IMG_WIDTH = 600 # 生成图片的最大宽度
MAX_IMG_HEIGHT = 4000 # 生成图片的最大高度，防止生成超大图片
FONT_SIZE = 24
LINE_SPACING_FACTOR = 0.5 # 行间距与字体大小的比例
IMAGE_PADDING = 30 # 图片内边距
LOG_DIR = os.environ.get('LOG_DIR', './logs') # 日志文件存放目录

# 合规性：敏感词文件路径
SENSITIVE_WORDS_FILE = os.environ.get('SENSITIVE_WORDS_FILE', './sensitive_words.txt')
sensitive_words: Set[str] = set()

# ==================== 初始化配置 ====================
def setup_logging():
    """配置详细的日志记录系统，输出为 JSON 格式"""
    # 增加 request_id 和 user_id 到日志格式中
    log_format = '%(asctime)s %(levelname)s %(filename)s:%(lineno)d %(request_id)s %(user_id)s %(message)s'

    logger = logging.getLogger(__name__)
    logger.setLevel(logging.DEBUG)

    if not os.path.exists(LOG_DIR):
        os.makedirs(LOG_DIR)

    if not logger.handlers:
        console_handler = logging.StreamHandler()
        console_handler.setLevel(logging.INFO)
        formatter = jsonlogger.JsonFormatter(log_format,
                                             rename_fields={'levelname': 'level', 'asctime': 'timestamp', 'filename': 'file', 'lineno': 'line'},
                                             json_ensure_ascii=False)
        console_handler.setFormatter(formatter)
        logger.addHandler(console_handler)

        file_handler = TimedRotatingFileHandler(
            filename=os.path.join(LOG_DIR, 'wechat_gemini.log'),
            when='midnight',
            interval=1,
            backupCount=7,
            encoding='utf-8',
            delay=True
        )
        file_handler.setLevel(logging.DEBUG)
        file_handler.setFormatter(formatter)
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
    logger.critical(error_msg, extra={'request_id': 'N/A', 'user_id': 'N/A'})
    raise EnvironmentError(error_msg)

# 初始化配置
WECHAT_TOKEN = os.environ['WECHAT_TOKEN']
GEMINI_API_KEY = os.environ['GEMINI_API_KEY']
APPID = os.environ['WECHAT_APPID']
APPSECRET = os.environ['WECHAT_APPSECRET']

FONT_PATH = os.environ.get('FONT_PATH', './SourceHanSansSC-Regular.otf')

# 字体加载逻辑优化
try:
    if FONT_PATH and os.path.exists(FONT_PATH):
        font_global = ImageFont.truetype(FONT_PATH, FONT_SIZE)
        logger.info(f"成功加载字体文件: {FONT_PATH}", extra={'request_id': 'N/A', 'user_id': 'N/A'})
    else:
        font_global = ImageFont.load_default()
        logger.warning(f"字体文件不存在或未指定: {FONT_PATH}，将使用 Pillow 默认字体，中文显示可能不正常。", extra={'request_id': 'N/A', 'user_id': 'N/A'})
        FONT_PATH = None # 标记为使用默认字体
except Exception as e:
    logger.critical(f"加载字体失败: {e}\n{traceback.format_exc()}", extra={'request_id': 'N/A', 'user_id': 'N/A'})
    try:
        font_global = ImageFont.load_default()
        logger.warning("加载指定字体失败，已回退到 Pillow 默认字体，中文显示可能不正常。", extra={'request_id': 'N/A', 'user_id': 'N/A'})
        FONT_PATH = None
    except Exception as default_font_e:
        logger.critical(f"加载默认字体也失败: {default_font_e}", extra={'request_id': 'N/A', 'user_id': 'N/A'})
        raise RuntimeError(f"无法加载任何可用字体: {e}, {default_font_e}")

# 加载敏感词
def load_sensitive_words():
    """从文件中加载敏感词。"""
    global sensitive_words
    if not os.path.exists(SENSITIVE_WORDS_FILE):
        logger.warning(f"敏感词文件 '{SENSITIVE_WORDS_FILE}' 不存在，将不启用敏感词过滤。", extra={'request_id': 'N/A', 'user_id': 'N/A'})
        return

    try:
        with open(SENSITIVE_WORDS_FILE, 'r', encoding='utf-8') as f:
            for line in f:
                word = line.strip()
                if word:
                    sensitive_words.add(word.lower()) # 转换为小写以便进行不区分大小写的匹配
        logger.info(f"成功加载 {len(sensitive_words)} 个敏感词。", extra={'request_id': 'N/A', 'user_id': 'N/A'})
    except Exception as e:
        logger.error(f"加载敏感词文件失败: {e}\n{traceback.format_exc()}", extra={'request_id': 'N/A', 'user_id': 'N/A'})

load_sensitive_words()


try:
    genai.configure(api_key=GEMINI_API_KEY)
    gemini_model = genai.GenerativeModel(GEMINI_MODEL_NAME) # 使用环境变量配置的模型名称
    logger.info(f"Gemini AI 模型 ({GEMINI_MODEL_NAME}) 初始化成功。", extra={'request_id': 'N/A', 'user_id': 'N/A'})
except Exception as e:
    logger.critical(f"Gemini 初始化失败: {str(e)}\n{traceback.format_exc()}", extra={'request_id': 'N/A', 'user_id': 'N/A'})
    raise RuntimeError("Gemini AI 模型初始化失败，请检查API密钥和网络连接。")

# ==================== Redis 配置和连接 ====================
REDIS_HOST = os.environ.get('REDIS_HOST', 'localhost')
REDIS_PORT = int(os.environ.get('REDIS_PORT', 6379))
REDIS_DB = int(os.environ.get('REDIS_DB', 0))
REDIS_PASSWORD = os.environ.get('REDIS_PASSWORD')
REDIS_MAX_CONNECTIONS = int(os.environ.get('REDIS_MAX_CONNECTIONS', 20))
REDIS_CONNECT_TIMEOUT = int(os.environ.get('REDIS_CONNECT_TIMEOUT', 5))
REDIS_SOCKET_TIMEOUT = int(os.environ.get('REDIS_SOCKET_TIMEOUT', 5))
REDIS_HEALTH_CHECK_INTERVAL = int(os.environ.get('REDIS_HEALTH_CHECK_INTERVAL', 30)) # 秒

# Redis 连接池和客户端，在启动时初始化一次
REDIS_CONNECTION_POOL = None
redis_client = None
redis_health_thread = None
redis_connection_lock = threading.Lock() # 用于保护Redis连接池和客户端的初始化

def init_redis_client(request_id: str = 'N/A', user_id: str = 'N/A') -> bool:
    global REDIS_CONNECTION_POOL, redis_client
    with redis_connection_lock:
        if redis_client:
            try:
                redis_client.ping()
                logger.debug("Redis客户端已存在且连接正常，无需重新初始化。", extra={'request_id': request_id, 'user_id': user_id})
                return True
            except redis.exceptions.ConnectionError:
                logger.warning("现有Redis连接已失效，尝试重新初始化。", extra={'request_id': request_id, 'user_id': user_id})
            except Exception as e:
                logger.warning(f"检查现有Redis连接时发生异常: {e}，尝试重新初始化。", extra={'request_id': request_id, 'user_id': user_id})

        logger.info(f"尝试连接到 Redis 服务器: {REDIS_HOST}:{REDIS_PORT}...", extra={'request_id': request_id, 'user_id': user_id})
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
            redis_client.ping() # 尝试ping，确认连接可用
            logger.info(f"成功连接到 Redis 服务器: {REDIS_HOST}:{REDIS_PORT} (DB: {REDIS_DB}, 连接池大小: {REDIS_CONNECTION_POOL.max_connections})", extra={'request_id': request_id, 'user_id': user_id})
            return True
        except redis.exceptions.ConnectionError as e:
            logger.critical(f"无法连接到 Redis 服务器: {e}", extra={'request_id': request_id, 'user_id': user_id})
            return False
        except Exception as e:
            logger.critical(f"Redis 初始化失败: {e}", extra={'request_id': request_id, 'user_id': user_id})
            return False

def redis_health_check_task():
    """后台 Redis 健康检查任务，如果连接断开则尝试重连。"""
    while True:
        try:
            if redis_client:
                redis_client.ping()
                logger.debug("Redis 健康检查：连接正常。", extra={'request_id': 'N/A', 'user_id': 'N/A'})
            else:
                logger.warning("Redis客户端未初始化或已断开，尝试重新初始化。", extra={'request_id': 'N/A', 'user_id': 'N/A'})
                if not init_redis_client():
                    logger.error("Redis重连失败，将在下次检查时重试。", extra={'request_id': 'N/A', 'user_id': 'N/A'})
        except redis.exceptions.ConnectionError as e:
            logger.error(f"Redis 健康检查失败，连接断开: {e}。尝试重新初始化连接。", extra={'request_id': 'N/A', 'user_id': 'N/A'})
            if not init_redis_client():
                logger.error("Redis重连失败，将在下次检查时重试。", extra={'request_id': 'N/A', 'user_id': 'N/A'})
        except Exception as e:
            logger.error(f"Redis 健康检查过程中发生未知异常: {e}\n{traceback.format_exc()}", extra={'request_id': 'N/A', 'user_id': 'N/A'})
        time.sleep(REDIS_HEALTH_CHECK_INTERVAL)

if not init_redis_client():
    raise RuntimeError("初始 Redis 连接失败，服务无法启动。")

redis_health_thread = threading.Thread(target=redis_health_check_task, daemon=True)
redis_health_thread.start()
logger.info("Redis 健康检查线程已启动。", extra={'request_id': 'N/A', 'user_id': 'N/A'})


# ==================== 线程池配置 ====================
MAX_WORKER_THREADS = int(os.environ.get('MAX_WORKER_THREADS', 5))
executor = ThreadPoolExecutor(max_workers=MAX_WORKER_THREADS)
logger.info(f"初始化 ThreadPoolExecutor，最大工作线程数: {MAX_WORKER_THREADS}", extra={'request_id': 'N/A', 'user_id': 'N/A'})

# ==================== Requests 会话复用 ====================
wechat_api_session = requests.Session()
image_download_session = requests.Session()
logger.info("requests 会话已创建，用于复用连接。", extra={'request_id': 'N/A', 'user_id': 'N/A'})


# ==================== 核心功能 - Access Token ====================
access_token_cache = {"token": None, "expires_at": 0}
token_lock = threading.Lock()

def get_access_token(request_id: str = 'N/A', user_id: str = 'N/A') -> Union[str, None]:
    """
    获取微信 access_token，使用缓存并支持自动刷新。
    """
    now = int(time.time())
    with token_lock:
        if access_token_cache["token"] and access_token_cache["expires_at"] > now + 60:
            logger.debug("使用缓存的access_token。", extra={'request_id': request_id, 'user_id': user_id})
            return access_token_cache["token"]

    logger.info("正在获取新的access_token...", extra={'request_id': request_id, 'user_id': user_id})
    start_time = time.time()
    try:
        url = f"https://api.weixin.qq.com/cgi-bin/token?grant_type=client_credential&appid={APPID}&secret={APPSECRET}"
        resp = wechat_api_session.get(url, timeout=WECHAT_ACCESS_TOKEN_TIMEOUT)
        resp.raise_for_status()
        data = resp.json()

        if 'access_token' in data:
            with token_lock:
                access_token_cache["token"] = data['access_token']
                expires_in = data.get('expires_in', 7200)
                access_token_cache["expires_at"] = now + expires_in
            duration = time.time() - start_time
            logger.info(f"获取access_token成功，耗时: {duration:.2f}秒，有效期: {expires_in}秒，下次刷新时间: {datetime.fromtimestamp(access_token_cache['expires_at']-60)}", extra={'request_id': request_id, 'user_id': user_id})
            return data['access_token']

        logger.error(f"获取access_token失败，微信API返回错误: {data}", extra={'request_id': request_id, 'user_id': user_id})
    except requests.exceptions.Timeout:
        logger.error(f"获取access_token超时，URL: {url}", extra={'request_id': request_id, 'user_id': user_id})
    except requests.exceptions.RequestException as e:
        logger.error(f"获取access_token网络请求失败: {e}", extra={'request_id': request_id, 'user_id': user_id})
    except Exception as e:
        logger.error(f"获取access_token时发生异常: {e}\n{traceback.format_exc()}", extra={'request_id': request_id, 'user_id': user_id})
    return None

def verify_wechat_config() -> bool:
    """
    验证微信配置是否正确。
    """
    logger.info("开始验证微信配置...", extra={'request_id': 'N/A', 'user_id': 'N/A'})
    if not all([WECHAT_TOKEN, APPID, APPSECRET]):
        logger.critical("微信基础配置（WECHAT_TOKEN, APPID, WECHAT_APPSECRET）不完整。", extra={'request_id': 'N/A', 'user_id': 'N/A'})
        return False
    token = get_access_token()
    if not token:
        logger.critical("无法获取access_token，请检查WECHAT_APPID和WECHAT_APPSECRET是否正确。", extra={'request_id': 'N/A', 'user_id': 'N/A'})
        return False
    logger.info("微信配置验证通过。", extra={'request_id': 'N/A', 'user_id': 'N/A'})
    return True

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
        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_reserved:
            return True
        if ipaddress.ip_network('0.0.0.0/8').overlaps(ipaddress.ip_network(ip)):
            return True
        return False
    except ValueError:
        logger.debug(f"IP地址格式无效，跳过私有IP检查: {ip_str}", extra={'request_id': 'N/A', 'user_id': 'N/A'})
        return False

def is_safe_url(url: str, request_id: str = 'N/A', user_id: str = 'N/A', dns_timeout: int = DNS_RESOLVE_TIMEOUT) -> bool:
    """
    增强版检查 URL 是否安全，以防范 SSRF 攻击，包括 DNS 解析结果检查。
    """
    if not url:
        logger.warning("URL为空，拒绝处理。", extra={'request_id': request_id, 'user_id': user_id})
        return False

    try:
        parsed_url = urlparse(url)

        if parsed_url.scheme not in ('http', 'https'):
            logger.warning(f"不安全的URL协议: {parsed_url.scheme} for URL: {url[:100]}...", extra={'request_id': request_id, 'user_id': user_id})
            return False

        if not parsed_url.hostname:
            logger.warning(f"URL缺少主机名: {url[:100]}...", extra={'request_id': request_id, 'user_id': user_id})
            return False

        if parsed_url.port is not None and parsed_url.port not in (80, 443):
            logger.warning(f"非标准或不安全的URL端口: {parsed_url.port} for URL: {url[:100]}...", extra={'request_id': request_id, 'user_id': user_id})
            return False

        original_timeout = socket.getdefaulttimeout()
        socket.setdefaulttimeout(dns_timeout)

        resolved_ips = set()
        try:
            if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", parsed_url.hostname) or \
               re.match(r"^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$", parsed_url.hostname):
                if is_private_ip(parsed_url.hostname):
                    logger.warning(f"URL主机是私有IP地址: {parsed_url.hostname} for URL: {url[:100]}...", extra={'request_id': request_id, 'user_id': user_id})
                    return False
                resolved_ips.add(parsed_url.hostname)
            else:
                addr_info = socket.getaddrinfo(
                    parsed_url.hostname,
                    parsed_url.port if parsed_url.port else parsed_url.scheme,
                    socket.AF_UNSPEC,
                    socket.SOCK_STREAM
                )

                for info in addr_info:
                    ip_address = info[4][0]
                    if ip_address not in resolved_ips:
                        resolved_ips.add(ip_address)
                        if is_private_ip(ip_address):
                            logger.warning(f"URL主机名 '{parsed_url.hostname}' 解析到私有IP地址: {ip_address} for URL: {url[:100]}...", extra={'request_id': request_id, 'user_id': user_id})
                            return False

        except socket.timeout:
            logger.warning(f"DNS解析超时 for hostname: {parsed_url.hostname}, URL: {url[:100]}...", extra={'request_id': request_id, 'user_id': user_id})
            return False
        except socket.gaierror as e:
            logger.warning(f"DNS解析失败 for hostname: {parsed_url.hostname}, Error: {e} for URL: {url[:100]}...", extra={'request_id': request_id, 'user_id': user_id})
            return False
        finally:
            socket.setdefaulttimeout(original_timeout)

        if not resolved_ips:
            logger.warning(f"URL主机名 '{parsed_url.hostname}' 无法解析到任何IP地址 for URL: {url[:100]}...", extra={'request_id': request_id, 'user_id': user_id})
            return False

        return True
    except Exception as e:
        logger.error(f"URL安全检查过程中发生异常: {e}\n{traceback.format_exc()} for URL: {url[:100]}...", extra={'request_id': request_id, 'user_id': user_id})
        return False

# ==================== 合规性：敏感词检测 ====================
def contains_sensitive_words(text: str, request_id: str = 'N/A', user_id: str = 'N/A') -> bool:
    """
    检查文本是否包含敏感词。
    """
    if not sensitive_words:
        return False # 如果没有加载敏感词，则跳过检查

    text_lower = text.lower()
    for word in sensitive_words:
        if word in text_lower:
            logger.warning(f"检测到敏感词: '{word}' 在文本中 for user: {user_id}", extra={'request_id': request_id, 'user_id': user_id})
            metrics['sensitive_content_blocked_total'] += 1
            return True
    return False

# ==================== 消息处理接口 ====================
@app.route('/', methods=['POST'])
def handle_message():
    from_user = "N/A"
    to_user = "N/A"
    request_id = str(uuid.uuid4()) # 为每个请求生成唯一ID

    # 为当前请求设置 logger extra
    log_extra = {'request_id': request_id, 'user_id': from_user}
    
    try:
        logger.info("收到用户消息 POST 请求。", extra=log_extra)
        xml_data = request.data
        logger.debug(f"原始XML数据: {xml_data.decode('utf-8', errors='ignore')[:500]}...", extra=log_extra)
        
        try:
            xml = fromstring(xml_data)
        except ParseError as e:
            logger.error(f"XML解析失败: {e}. 原始数据: {xml_data.decode('utf-8', errors='ignore')[:500]}...", extra=log_extra)
            metrics['api_errors_total'] += 1
            return make_response("Invalid XML Format", 400)
        
        msg_type_element = xml.find('MsgType')
        if msg_type_element is None or not msg_type_element.text:
            logger.error("XML消息中缺少 MsgType 字段或为空。", extra=log_extra)
            metrics['api_errors_total'] += 1
            return make_response("Invalid XML: Missing MsgType", 400)
        msg_type = msg_type_element.text

        from_user_element = xml.find('FromUserName')
        if from_user_element is None or not from_user_element.text:
            logger.error("XML消息中缺少 FromUserName 字段或为空。", extra=log_extra)
            metrics['api_errors_total'] += 1
            return make_response("Invalid XML: Missing FromUserName", 400)
        from_user = from_user_element.text
        log_extra['user_id'] = from_user # 更新logger extra中的user_id

        to_user_element = xml.find('ToUserName')
        if to_user_element is None or not to_user_element.text:
            logger.error("XML消息中缺少 ToUserName 字段或为空。", extra=log_extra)
            metrics['api_errors_total'] += 1
            return make_response("Invalid XML: Missing ToUserName", 400)
        to_user = to_user_element.text

        logger.info(f"消息类型: {msg_type}, 来自用户: {from_user}, 发送给: {to_user}", extra=log_extra)
        metrics['requests_total'].setdefault(msg_type, 0)
        metrics['requests_total'][msg_type] += 1

        if msg_type == 'text':
            return handle_text_message(xml, from_user, to_user, request_id)
        elif msg_type == 'image':
            return handle_image_message(xml, from_user, to_user, request_id)
        elif msg_type == 'voice':
            return handle_voice_message(xml, from_user, to_user, request_id)
        elif msg_type == 'event':
            return handle_event_message(xml, from_user, to_user, request_id)
        else:
            logger.warning(f"接收到不支持的消息类型: {msg_type}", extra=log_extra)
            return build_reply(from_user, to_user, UNSUPPORTED_MESSAGE_TYPE_REPLY, request_id)

    except Exception as e:
        logger.error(f"处理微信消息时发生异常: {e}\n{traceback.format_exc()}", extra=log_extra)
        metrics['api_errors_total'] += 1
        safe_from_user = from_user if from_user else 'unknown_user'
        safe_to_user = to_user if to_user else 'unknown_app'
        error_content = SERVER_INTERNAL_ERROR_REPLY.replace(']]>', ']]]]><![CDATA[>')
        error_xml_str = f"""<xml>
            <ToUserName><![CDATA[{safe_from_user}]]></ToUserName>
            <FromUserName><![CDATA[{safe_to_user}]]></FromUserName>
            <CreateTime>{int(time.time())}</CreateTime>
            <MsgType><![CDATA[text]]></MsgType>
            <Content><![CDATA[{error_content}]]></Content>
        </xml>"""
        return make_response(error_xml_str, 500, {'Content-Type': 'application/xml'})

def handle_text_message(xml, from_user, to_user, request_id: str):
    log_extra = {'request_id': request_id, 'user_id': from_user}
    content_element = xml.find('Content')
    if content_element is None or not content_element.text:
        logger.error("文本消息中缺少 Content 字段或为空。", extra=log_extra)
        return build_reply(from_user, to_user, INVALID_TEXT_MESSAGE_REPLY, request_id)
    content = content_element.text
    logger.info(f"接收到文本消息: {content[:100]}...", extra=log_extra)

    # 合规性：用户输入内容敏感词过滤
    if contains_sensitive_words(content, request_id, from_user):
        logger.warning("用户文本消息包含敏感词，已阻断。", extra=log_extra)
        return build_reply(from_user, to_user, SENSITIVE_CONTENT_BLOCKED_REPLY, request_id)

    if content.strip() == QUERY_IMAGE_RESULT_COMMAND:
        return query_image_result(from_user, to_user, request_id)

    ai_response_content = process_text_message(content, request_id, from_user)
    return build_reply(from_user, to_user, ai_response_content, request_id)

def handle_image_message(xml, from_user, to_user, request_id: str):
    log_extra = {'request_id': request_id, 'user_id': from_user}
    pic_url_element = xml.find('PicUrl')
    if pic_url_element is None or not pic_url_element.text:
        logger.error("图片消息中缺少 PicUrl 字段或为空。", extra=log_extra)
        return build_reply(from_user, to_user, INVALID_IMAGE_MESSAGE_REPLY, request_id)
    pic_url = pic_url_element.text

    if not is_safe_url(pic_url, request_id, from_user):
        logger.warning(f"检测到不安全的图片URL，拒绝处理: {pic_url[:100]}...", extra=log_extra)
        try:
            if redis_client and init_redis_client(request_id, from_user):
                redis_client.set(f"{REDIS_USER_AI_RESULT_PREFIX}{from_user}",
                                f"{int(time.time())}|ERROR:{UNSAFE_URL_REPLY}",
                                ex=AI_RESULT_EXPIRATION_SECONDS)
            else:
                logger.error("Redis客户端不可用，无法记录图片安全检查失败信息。", extra=log_extra)
        except Exception as redis_e:
            logger.error(f"设置Redis图片安全检查失败信息时出错: {redis_e}", extra=log_extra)
        metrics['image_download_failed_total'] += 1
        return build_reply(from_user, to_user, UNSAFE_URL_REPLY, request_id)

    logger.info(f"接收到图片消息, URL 头部: {pic_url[:50]}...", extra=log_extra)

    reply_xml_str = f"""<xml>
        <ToUserName><![CDATA[{from_user}]]></ToUserName>
        <FromUserName><![CDATA[{to_user}]]></FromUserName>
        <CreateTime>{int(time.time())}</CreateTime>
        <MsgType><![CDATA[text]]></MsgType>
        <Content><![CDATA[{INITIAL_IMAGE_PROCESSING_MESSAGE}]]></Content>
    </xml>"""

    # 提交任务时传递 request_id
    executor.submit(async_process_image, pic_url, from_user, to_user, request_id)
    logger.info("图片处理任务已提交到线程池。", extra=log_extra)

    return make_response(reply_xml_str, 200, {'Content-Type': 'application/xml'})

def handle_voice_message(xml, from_user, to_user, request_id: str):
    log_extra = {'request_id': request_id, 'user_id': from_user}
    recognition_element = xml.find('Recognition')

    recognition_content = ""
    if recognition_element is not None and recognition_element.text:
        recognition_content = recognition_element.text.strip()
        logger.info(f"接收到语音消息 (已识别内容): {recognition_content[:100]}...", extra=log_extra)
    else:
        logger.warning("接收到语音消息但未包含 Recognition 字段或内容为空。", extra=log_extra)
        return build_reply(from_user, to_user, VOICE_MESSAGE_EMPTY_RESULT_REPLY, request_id)

    # 合规性：语音识别结果敏感词过滤
    if contains_sensitive_words(recognition_content, request_id, from_user):
        logger.warning("用户语音识别结果包含敏感词，已阻断。", extra=log_extra)
        return build_reply(from_user, to_user, SENSITIVE_CONTENT_BLOCKED_REPLY, request_id)

    if recognition_content:
        ai_response_content = process_text_message(recognition_content, request_id, from_user)
        return build_reply(from_user, to_user, ai_response_content, request_id)
    else:
        logger.warning("语音识别结果为空，无法处理。", extra=log_extra)
        return build_reply(from_user, to_user, VOICE_MESSAGE_EMPTY_RESULT_REPLY, request_id)

def handle_event_message(xml, from_user, to_user, request_id: str):
    log_extra = {'request_id': request_id, 'user_id': from_user}
    event_element = xml.find('Event')
    if event_element is None or not event_element.text:
        logger.error("事件消息中缺少 Event 字段或为空。", extra=log_extra)
        logger.warning("接收到不支持的事件消息类型 (Event字段缺失)。", extra=log_extra)
        return build_reply(from_user, to_user, UNSUPPORTED_MESSAGE_TYPE_REPLY, request_id)

    event_type = event_element.text
    logger.info(f"接收到事件消息: {event_type}", extra=log_extra)
    metrics['requests_total'].setdefault(f'event_{event_type}', 0)
    metrics['requests_total'][f'event_{event_type}'] += 1


    if event_type == 'subscribe':
        logger.info(f"用户 {from_user} 关注了公众号。", extra=log_extra)
        return build_reply(from_user, to_user, WELCOME_MESSAGE_REPLY, request_id)
    elif event_type == 'unsubscribe':
        logger.info(f"用户 {from_user} 取消关注了公众号。", extra=log_extra)
        return make_response("", 200)
    else:
        logger.warning(f"接收到未处理的事件类型: {event_type}", extra=log_extra)
        return build_reply(from_user, to_user, UNSUPPORTED_MESSAGE_TYPE_REPLY, request_id)


# ==================== 后台图片处理及辅助函数 ====================
def async_process_image(pic_url: str, from_user: str, to_user: str, request_id: str):
    """
    异步处理图片消息：下载、识别、存储结果。
    """
    log_extra = {'request_id': request_id, 'user_id': from_user}
    if not redis_client or not init_redis_client(request_id, from_user):
        logger.error("Redis客户端不可用，无法处理图片识别请求。", extra=log_extra)
        try:
            redis_client.set(f"{REDIS_USER_AI_RESULT_PREFIX}{from_user}", f"{int(time.time())}|ERROR:{NO_REDIS_CONNECTION_REPLY}", ex=AI_RESULT_EXPIRATION_SECONDS)
        except Exception as redis_e:
            logger.error(f"设置Redis图片处理失败信息时出错 (Redis连接断开): {redis_e}", extra=log_extra)
        metrics['image_process_failed_total'] += 1
        return

    try:
        logger.info(f"后台线程开始处理图片 (URL 头部): {pic_url[:50]}...", extra=log_extra)
        start_overall_time = time.time()
        start_download_time = time.time()
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/100.0.4896.127 Safari/537.36'}
        image_data = None

        try:
            image_resp = image_download_session.get(pic_url, timeout=IMAGE_DOWNLOAD_TIMEOUT, headers=headers, stream=True, allow_redirects=False)
            image_resp.raise_for_status()

            if image_resp.status_code in (301, 302, 303, 307, 308):
                redirect_url = image_resp.headers.get('Location')
                if redirect_url:
                    full_redirect_url = urljoin(pic_url, redirect_url)
                    if not is_safe_url(full_redirect_url, request_id, from_user):
                        logger.warning(f"检测到不安全的图片URL重定向，拒绝处理: {pic_url[:50]}... -> {full_redirect_url[:50]}...", extra=log_extra)
                        redis_client.set(f"{REDIS_USER_AI_RESULT_PREFIX}{from_user}", f"{int(time.time())}|ERROR:{UNSAFE_URL_REPLY}", ex=AI_RESULT_EXPIRATION_SECONDS)
                        metrics['image_download_failed_total'] += 1
                        image_resp.close()
                        return
                    logger.info(f"图片URL重定向到安全地址: {pic_url[:50]}... -> {full_redirect_url[:50]}...", extra=log_extra)
                    image_resp.close()
                    image_resp = image_download_session.get(full_redirect_url, timeout=IMAGE_DOWNLOAD_TIMEOUT, headers=headers, stream=True)
                    image_resp.raise_for_status()
                else:
                    logger.warning(f"图片URL发生重定向但未找到Location头: {pic_url[:50]}...", extra=log_extra)
                    redis_client.set(f"{REDIS_USER_AI_RESULT_PREFIX}{from_user}", f"{int(time.time())}|ERROR:{IMAGE_DOWNLOAD_FAILED_REPLY} (重定向失败)", ex=AI_RESULT_EXPIRATION_SECONDS)
                    metrics['image_download_failed_total'] += 1
                    image_resp.close()
                    return

            downloaded_size = 0
            image_bytes_buffer = io.BytesIO()
            for chunk in image_resp.iter_content(chunk_size=8192):
                if chunk:
                    downloaded_size += len(chunk)
                    if downloaded_size > MAX_IMAGE_DOWNLOAD_SIZE:
                        logger.warning(f"图片文件过大 ({downloaded_size/1024/1024:.2f}MB)，超过 {MAX_IMAGE_DOWNLOAD_SIZE/1024/1024:.2f}MB 限制，中断下载。", extra=log_extra)
                        redis_client.set(f"{REDIS_USER_AI_RESULT_PREFIX}{from_user}", f"{int(time.time())}|ERROR:{IMAGE_DOWNLOAD_FAILED_REPLY} (文件过大)", ex=AI_RESULT_EXPIRATION_SECONDS)
                        metrics['image_download_failed_total'] += 1
                        image_resp.close()
                        return
                    image_bytes_buffer.write(chunk)
            image_data = image_bytes_buffer.getvalue()
            image_resp.close()
            metrics['image_download_bytes_total'] += len(image_data) # 记录下载字节数

            if not image_data:
                 raise ValueError("下载的图片数据为空。")

            logger.info(f"后台图片下载完成，耗时: {time.time()-start_download_time:.2f}秒，大小: {len(image_data)/1024:.2f}KB。", extra=log_extra)
        except requests.exceptions.Timeout:
            logger.error(f"后台图片下载超时 (URL 头部: {pic_url[:50]}...): 请求超时", extra=log_extra)
            redis_client.set(f"{REDIS_USER_AI_RESULT_PREFIX}{from_user}", f"{int(time.time())}|ERROR:{IMAGE_DOWNLOAD_FAILED_REPLY} (下载超时)", ex=AI_RESULT_EXPIRATION_SECONDS)
            metrics['image_download_failed_total'] += 1
            return
        except requests.exceptions.RequestException as e:
            logger.error(f"后台图片下载失败 (URL 头部: {pic_url[:50]}...): {e}\n{traceback.format_exc()}", extra=log_extra)
            redis_client.set(f"{REDIS_USER_AI_RESULT_PREFIX}{from_user}", f"{int(time.time())}|ERROR:{IMAGE_DOWNLOAD_FAILED_REPLY}", ex=AI_RESULT_EXPIRATION_SECONDS)
            metrics['image_download_failed_total'] += 1
            return
        except ValueError as e:
            logger.error(f"图片下载或处理初始阶段失败: {e}\n{traceback.format_exc()}", extra=log_extra)
            redis_client.set(f"{REDIS_USER_AI_RESULT_PREFIX}{from_user}", f"{int(time.time())}|ERROR:{IMAGE_DOWNLOAD_FAILED_REPLY}", ex=AI_RESULT_EXPIRATION_SECONDS)
            metrics['image_download_failed_total'] += 1
            return

        try:
            img = Image.open(io.BytesIO(image_data))
            if img.mode != 'RGB':
                img = img.convert('RGB')
        except Exception as e:
            logger.error(f"无法打开或转换图片数据: {e}\n{traceback.format_exc()}", extra=log_extra)
            redis_client.set(f"{REDIS_USER_AI_RESULT_PREFIX}{from_user}", f"{int(time.time())}|ERROR:{IMAGE_PROCESSING_FAILED_REPLY} (图片格式或损坏)", ex=AI_RESULT_EXPIRATION_SECONDS)
            metrics['image_process_failed_total'] += 1
            return

        prompt = "请用中文详细描述这张图片的内容，并尽可能分析它的含义。请直接给出描述，不要说“这张图片显示了...”之类的引导语。"
        logger.info("后台调用 Gemini 处理图片...", extra=log_extra)
        ai_response_content = generate_with_retry(prompt, request_id, from_user, img, is_image_context=True)

        # 合规性：AI回复敏感词过滤
        if contains_sensitive_words(ai_response_content, request_id, from_user):
            logger.warning("AI图片识别结果包含敏感词，已阻断。", extra=log_extra)
            ai_response_content = SENSITIVE_CONTENT_BLOCKED_REPLY

        logger.info(f"后台AI处理图片完成，总耗时: {time.time()-start_overall_time:.2f}秒。回复内容长度: {len(ai_response_content.encode('utf-8'))}字节", extra=log_extra)

        redis_key = f"{REDIS_USER_AI_RESULT_PREFIX}{from_user}"
        value = f"{int(time.time())}|{ai_response_content.replace('|', '&#124;')}"

        try:
            redis_client.set(redis_key, value, ex=AI_RESULT_EXPIRATION_SECONDS)
            logger.info(f"AI图片结果已为用户 {from_user} 存储到 Redis (key: {redis_key})，有效期 {AI_RESULT_EXPIRATION_SECONDS} 秒。", extra=log_extra)
        except redis.exceptions.ConnectionError as e:
            logger.error(f"无法将 AI 图片结果存储到 Redis (连接错误): {e}。用户将无法查询到结果。", extra=log_extra)
        except Exception as e:
            logger.error(f"存储 AI 图片结果到 Redis 时发生未知错误: {e}\n{traceback.format_exc()}。用户将无法查询到结果。", extra=log_extra)

    except Exception as e:
        logger.error(f"后台图片处理线程发生未捕获异常: {e}\n{traceback.format_exc()}", extra=log_extra)
        try:
            if redis_client and init_redis_client(request_id, from_user):
                redis_client.set(f"{REDIS_USER_AI_RESULT_PREFIX}{from_user}", f"{int(time.time())}|ERROR:{IMAGE_PROCESSING_FAILED_REPLY}", ex=AI_RESULT_EXPIRATION_SECONDS)
            else:
                logger.error("Redis客户端不可用，无法记录未捕获异常到Redis。", extra=log_extra)
        except Exception as redis_e:
            logger.error(f"记录未捕获异常到Redis时出错: {redis_e}", extra=log_extra)
        metrics['image_process_failed_total'] += 1


def query_image_result(from_user: str, to_user: str, request_id: str) -> requests.Response:
    """
    查询用户存储的图片识别结果。
    """
    log_extra = {'request_id': request_id, 'user_id': from_user}
    if not redis_client or not init_redis_client(request_id, from_user):
        logger.error("Redis客户端不可用，无法查询图片识别结果。", extra=log_extra)
        return build_reply(from_user, to_user, NO_REDIS_CONNECTION_REPLY, request_id)

    redis_key = f"{REDIS_USER_AI_RESULT_PREFIX}{from_user}"
    stored_value = None
    try:
        stored_value = redis_client.get(redis_key)
        if stored_value:
            metrics['redis_cache_hits_total'] += 1
        else:
            metrics['redis_cache_misses_total'] += 1
    except redis.exceptions.ConnectionError as e:
        logger.error(f"无法从 Redis 获取 AI 图片结果 (连接错误): {redis_key}, 错误: {e}", extra=log_extra)
        return build_reply(from_user, to_user, NO_REDIS_CONNECTION_REPLY, request_id)
    except Exception as e:
        logger.error(f"从 Redis 获取 AI 图片结果时发生未知错误: {redis_key}, 错误: {e}\n{traceback.format_exc()}", extra=log_extra)
        return build_reply(from_user, to_user, SERVER_INTERNAL_ERROR_REPLY, request_id)

    content_to_reply = IMAGE_QUERY_NO_RESULT_REPLY
    if stored_value:
        try:
            timestamp_str, content = stored_value.split('|', 1)
            timestamp = int(timestamp_str)
            content = content.replace('&#124;', '|') # 恢复管道符

            if content.startswith("ERROR:"):
                error_message = content[6:]
                content_to_reply = f"抱歉，您的图片处理失败了（{time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(timestamp))}）。\n原因：{error_message} 请尝试重新发送图片。"
                logger.warning(f"为用户 {from_user} 返回存储在 Redis 中的图片处理失败信息: {error_message}", extra=log_extra)
            else:
                content_to_reply = f"这是您最近一次图片识别的结果（{time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(timestamp))}）:\n\n{content}"
                logger.info(f"为用户 {from_user} 返回存储在 Redis 中的图片识别结果。", extra=log_extra)
            try:
                redis_client.delete(redis_key)
                logger.debug(f"已清除用户 {from_user} 的 Redis 图片结果缓存 (key: {redis_key})。", extra=log_extra)
            except Exception as e:
                logger.warning(f"清除 Redis 图片结果缓存失败: {e}", extra=log_extra)

        except ValueError:
            content_to_reply = IMAGE_QUERY_PARSE_ERROR_REPLY
            logger.error(f"解析 Redis 存储值失败 for user {from_user}, key: {redis_key}, value: {stored_value}", extra=log_extra)
    else:
        logger.info(f"用户 {from_user} 查询图片结果，Redis 中无可用结果 (key: {redis_key})。", extra=log_extra)

    return build_reply(from_user, to_user, content_to_reply, request_id)

def process_text_message(content: str, request_id: str, from_user: str) -> str:
    """
    处理文本消息，调用 AI 并缓存结果。
    """
    log_extra = {'request_id': request_id, 'user_id': from_user}
    logger.info(f"调用 Gemini 处理文本: {content[:50]}...", extra=log_extra)
    normalized_content = content.strip().lower()
    cache_key = f"{REDIS_TEXT_CACHE_PREFIX}{hashlib.md5(normalized_content.encode('utf-8')).hexdigest()}"

    if redis_client and init_redis_client(request_id, from_user):
        try:
            cached_answer = redis_client.get(cache_key)
            if cached_answer:
                logger.info(f"从 Redis 缓存中获取文本答案 (key: {cache_key[:10]}...): {cached_answer[:50]}...", extra=log_extra)
                metrics['redis_cache_hits_total'] += 1
                return cached_answer
            else:
                metrics['redis_cache_misses_total'] += 1
        except redis.exceptions.ConnectionError as e:
            logger.warning(f"无法从 Redis 获取文本缓存 (连接错误): {cache_key}, 错误: {e}。将尝试重新生成。", extra=log_extra)
        except Exception as e:
            logger.warning(f"获取文本缓存时发生未知错误: {cache_key}, 错误: {e}\n{traceback.format_exc()}。将尝试重新生成。", extra=log_extra)
    else:
        logger.warning("Redis客户端不可用，跳过文本缓存查询。", extra=log_extra)

    try:
        ai_response_content = generate_with_retry(content, request_id, from_user, is_image_context=False)
        
        # 合规性：AI回复敏感词过滤
        if contains_sensitive_words(ai_response_content, request_id, from_user):
            logger.warning("AI文本回复包含敏感词，已阻断。", extra=log_extra)
            return SENSITIVE_CONTENT_BLOCKED_REPLY

        if ai_response_content:
            if redis_client and init_redis_client(request_id, from_user):
                try:
                    redis_client.set(cache_key, ai_response_content, ex=TEXT_CACHE_EXPIRATION_SECONDS)
                    logger.info(f"AI文本答案已存入 Redis 缓存 (key: {cache_key[:10]}...)，有效期 {TEXT_CACHE_EXPIRATION_SECONDS} 秒。", extra=log_extra)
                except redis.exceptions.ConnectionError as e:
                    logger.warning(f"无法将 AI 文本答案存储到 Redis (连接错误): {cache_key}, 错误: {e}", extra=log_extra)
                except Exception as e:
                    logger.warning(f"存储 AI 文本答案到 Redis 时发生未知错误: {cache_key}, 错误: {e}\n{traceback.format_exc()}", extra=log_extra)
            else:
                logger.warning("Redis客户端不可用，跳过文本缓存存储。", extra=log_extra)
        return ai_response_content
    except Exception as e:
        logger.error(f"处理文本消息时 AI 调用失败: {e}\n{traceback.format_exc()}", extra=log_extra)
        metrics['ai_calls_total']['failure'] += 1
        return AI_SERVICE_UNAVAILABLE_REPLY

def generate_with_retry(prompt: str, request_id: str, user_id: str, image=None, max_retries: int = 3, is_image_context: bool = False) -> str:
    """
    调用 Gemini AI 模型生成内容，支持重试和指数退避。
    """
    log_extra = {'request_id': request_id, 'user_id': user_id}
    retry_count = 0
    ai_api_request_timeout = GEMINI_IMAGE_TIMEOUT if is_image_context else GEMINI_TEXT_TIMEOUT
    logger.debug(f"AI请求超时设置为: {ai_api_request_timeout}秒 (is_image_context={is_image_context})", extra=log_extra)

    start_overall_ai_time = time.time()
    while retry_count < max_retries:
        try:
            start_single_attempt_time = time.time()
            contents = [prompt]
            if image:
                contents.insert(0, image)

            response = gemini_model.generate_content(
                contents,
                generation_config=GEMINI_GENERATION_CONFIG,
                request_options={"timeout": ai_api_request_timeout}
            )
            
            if response.prompt_feedback and response.prompt_feedback.block_reason:
                block_reason = response.prompt_feedback.block_reason.name
                logger.warning(f"AI 提示被阻断，原因: {block_reason}", extra=log_extra)
                metrics['ai_calls_total']['blocked'] += 1
                return f"{AI_BLOCK_REASON_PREFIX}{block_reason}{AI_BLOCK_REASON_SUFFIX}"

            if not response or not response.text:
                raise ValueError("AI returned an empty or invalid response.")

            current_ai_duration = time.time() - start_overall_ai_time
            metrics['ai_response_time_seconds']['sum'] += current_ai_duration
            metrics['ai_response_time_seconds']['count'] += 1
            metrics['ai_calls_total']['success'] += 1
            logger.info(f"AI 生成成功，耗时: {current_ai_duration:.2f}秒 (单次尝试: {time.time()-start_single_attempt_time:.2f}秒)", extra=log_extra)
            return response.text.strip()
        except Exception as e:
            retry_count += 1
            wait_time = min(2 ** retry_count, 10)
            logger.warning(f"AI 生成失败 (尝试 {retry_count}/{max_retries}), 等待 {wait_time:.2f} 秒: {e}\n{traceback.format_exc()}", extra=log_extra)
            time.sleep(wait_time)
    logger.error("AI 生成失败，已达到最大重试次数。", extra=log_extra)
    metrics['ai_calls_total']['failure'] += 1
    return AI_SERVICE_UNAVAILABLE_REPLY

def build_reply(from_user: str, to_user: str, content: str, request_id: str) -> requests.Response:
    """
    构建微信回复 XML，支持文本超长时转换为图片回复。
    """
    log_extra = {'request_id': request_id, 'user_id': from_user}
    try:
        # 合规性：最终回复内容敏感词过滤
        if contains_sensitive_words(content, request_id, from_user):
            logger.warning("AI生成内容或最终回复内容包含敏感词，已阻断。", extra=log_extra)
            content = SENSITIVE_CONTENT_BLOCKED_REPLY

        cleaned_content = clean_content(content)
        content_bytes = len(cleaned_content.encode('utf-8'))
        reply_xml_str = None

        if content_bytes > WECHAT_TEXT_MAX_BYTES:
            logger.info(f"内容过长({content_bytes}字节 > {WECHAT_TEXT_MAX_BYTES}字节)，尝试转换为图片并回复。", extra=log_extra)
            img_data = text_to_image(cleaned_content, max_width=MAX_IMG_WIDTH, font_size=FONT_SIZE, line_spacing_factor=LINE_SPACING_FACTOR, request_id=request_id, user_id=from_user)
            if img_data:
                if len(img_data) > WECHAT_MAX_IMAGE_UPLOAD_SIZE:
                    logger.warning(f"生成的图片大小 ({len(img_data)/1024:.2f}KB) 超过微信上传限制 ({WECHAT_MAX_IMAGE_UPLOAD_SIZE/1024:.2f}KB)。将回退为截断文本。", extra=log_extra)
                    truncated_content = clean_content(cleaned_content, max_bytes=WECHAT_TEXT_MAX_BYTES - len(AI_REPLY_TOO_LONG_IMAGE_FAIL_PREFIX.encode('utf-8')))
                    safe_truncated_content = escape_cdata(AI_REPLY_TOO_LONG_IMAGE_FAIL_PREFIX + truncated_content)
                    reply_xml_str = f"""<xml>
                        <ToUserName><![CDATA[{from_user}]]></ToUserName>
                        <FromUserName><![CDATA[{to_user}]]></FromUserName>
                        <CreateTime>{int(time.time())}</CreateTime>
                        <MsgType><![CDATA[text]]></MsgType>
                        <Content><![CDATA[{safe_truncated_content}]]></Content>
                    </xml>"""
                else:
                    media_id = upload_image_to_wechat(img_data, request_id, from_user)
                    if media_id:
                        logger.info(f"图片已成功上传至微信，MediaId: {media_id[:10]}... 使用图片回复。", extra=log_extra)
                        metrics['wechat_media_upload_total']['success'] += 1
                        reply_xml_str = f"""<xml>
                            <ToUserName><![CDATA[{from_user}]]></ToUserName>
                            <FromUserName><![CDATA[{to_user}]]></FromUserName>
                            <CreateTime>{int(time.time())}</CreateTime>
                            <MsgType><![CDATA[image]]></MsgType>
                            <Image><MediaId><![CDATA[{media_id}]]></MediaId></Image>
                        </xml>"""
                    else:
                        logger.warning("图片上传至微信失败，回退到文本回复并截断。", extra=log_extra)
                        metrics['wechat_media_upload_total']['failure'] += 1
                        truncated_content = clean_content(cleaned_content, max_bytes=WECHAT_TEXT_MAX_BYTES - len(AI_REPLY_TOO_LONG_IMAGE_FAIL_PREFIX.encode('utf-8')))
                        safe_truncated_content = escape_cdata(AI_REPLY_TOO_LONG_IMAGE_FAIL_PREFIX + truncated_content)
                        reply_xml_str = f"""<xml>
                            <ToUserName><![CDATA[{from_user}]]></ToUserName>
                            <FromUserName><![CDATA[{to_user}]]></FromUserName>
                            <CreateTime>{int(time.time())}</CreateTime>
                            <MsgType><![CDATA[text]]></MsgType>
                            <Content><![CDATA[{safe_truncated_content}]]></Content>
                        </xml>"""
            else:
                logger.warning("文本转换为图片失败，回退到文本回复并截断。", extra=log_extra)
                truncated_content = clean_content(cleaned_content, max_bytes=WECHAT_TEXT_MAX_BYTES - len(AI_REPLY_TOO_LONG_IMAGE_FAIL_PREFIX.encode('utf-8')))
                safe_truncated_content = escape_cdata(AI_REPLY_TOO_LONG_IMAGE_FAIL_PREFIX + truncated_content)
                reply_xml_str = f"""<xml>
                    <ToUserName><![CDATA[{from_user}]]></ToUserName>
                    <FromUserName><![CDATA[{to_user}]]></FromUserName>
                    <CreateTime>{int(time.time())}</CreateTime>
                    <MsgType><![CDATA[text]]></MsgType>
                    <Content><![CDATA[{safe_truncated_content}]]></Content>
                </xml>"""
        else:
            logger.info(f"内容在文本限制内({content_bytes}字节)，使用文本回复。", extra=log_extra)
            safe_cleaned_content = escape_cdata(cleaned_content)
            reply_xml_str = f"""<xml>
                <ToUserName><![CDATA[{from_user}]]></ToUserName>
                <FromUserName><![CDATA[{to_user}]]></FromUserName>
                <CreateTime>{int(time.time())}</CreateTime>
                <MsgType><![CDATA[text]]></MsgType>
                <Content><![CDATA[{safe_cleaned_content}]]></Content>
            </xml>"""
        return make_response(reply_xml_str, 200, {'Content-Type': 'application/xml'})

    except Exception as e:
        logger.error(f"构建回复时发生异常: {e}\n{traceback.format_exc()}", extra=log_extra)
        metrics['api_errors_total'] += 1
        safe_from_user = from_user if from_user else 'unknown_user'
        safe_to_user = to_user if to_user else 'unknown_app'
        safe_error_reply = escape_cdata(AI_REPLY_EXCEPTION_REPLY)
        error_xml_str = f"""<xml>
            <ToUserName><![CDATA[{safe_from_user}]]></ToUserName>
            <FromUserName><![CDATA[{safe_to_user}]]></FromUserName>
            <CreateTime>{int(time.time())}</CreateTime>
            <MsgType><![CDATA[text]]></MsgType>
            <Content><![CDATA[{safe_error_reply}]]></Content>
        </xml>"""
        return make_response(error_xml_str, 500, {'Content-Type': 'application/xml'})

def escape_cdata(text: str) -> str:
    """
    确保字符串在 CDATA 块中安全，替换 `]]>` 为 `]]]]><![CDATA[>`。
    """
    return text.replace(']]>', ']]]]><![CDATA[>')

def clean_content(content: str, max_bytes: Union[int, None] = None) -> str:
    """
    清理文本内容，移除Markdown标记、多余空格和连续空行，并可选地按字节截断。
    """
    if not content:
        return ""
    
    content = re.sub(r'```.*?```', '', content, flags=re.DOTALL) # 移除代码块
    content = re.sub(r'\|.*?\|', '', content) # 移除表格线及内容
    content = re.sub(r'(\*\*|__|\*|_|`|~~|#+\s*)', '', content) # 移除粗体、斜体、代码、删除线、标题
    content = re.sub(r'\[([^\]]+?)\]\(.*?\)', r'\1', content) # 移除链接，保留文本
    content = re.sub(r'!\[.*?\]\(.*?\)', '', content) # 移除图片
    content = re.sub(r'^[>\s*]\s*', '', content, flags=re.MULTILINE) # 移除引用和列表标记
    content = re.sub(r'^[*-]\s*', '', content, flags=re.MULTILINE) # 移除列表标记

    processed_lines = []
    avg_char_width = (font_global.getbbox('A')[2] - font_global.getbbox('A')[0] + (font_global.getbbox('中')[2] - font_global.getbbox('中')[0])) / 2
    if avg_char_width == 0: avg_char_width = FONT_SIZE * 0.7
    estimated_chars_per_line = int((MAX_IMG_WIDTH - 2 * IMAGE_PADDING) / avg_char_width)
    if estimated_chars_per_line < 10:
        estimated_chars_per_line = 10

    for paragraph in content.split('\n'):
        if not paragraph.strip():
            processed_lines.append('')
            continue
        wrapped = textwrap.wrap(paragraph, width=estimated_chars_per_line)
        for line in wrapped:
            processed_lines.append(line.strip())

    content = '\n'.join(processed_lines)
    content = re.sub(r'\n{3,}', '\n\n', content)
    content = content.strip()

    if max_bytes is not None:
        encoded_content = content.encode('utf-8')
        if len(encoded_content) > max_bytes:
            logger.warning(f"内容因字节限制被截断: 原始 {len(encoded_content)} 字节，截断至 {max_bytes} 字节。", extra={'request_id': 'N/A', 'user_id': 'N/A'})
            truncated_bytes = encoded_content[:max_bytes]
            while not truncated_bytes.decode('utf-8', 'ignore').encode('utf-8') == truncated_bytes:
                truncated_bytes = truncated_bytes[:-1]
            return truncated_bytes.decode('utf-8', 'ignore')
    return content

def text_to_image(text: str, max_width: int = MAX_IMG_WIDTH, font_size: int = FONT_SIZE, line_spacing_factor: float = LINE_SPACING_FACTOR, request_id: str = 'N/A', user_id: str = 'N/A') -> Union[bytes, None]:
    """
    将文本转换为图片。
    """
    log_extra = {'request_id': request_id, 'user_id': user_id}
    try:
        start_time_img_gen = time.time()
        padding = IMAGE_PADDING
        line_spacing = int(font_size * line_spacing_factor)
        
        font = font_global

        lines = []
        max_line_width_pixels = max_width - 2 * padding

        avg_char_width = (font.getbbox('A')[2] - font.getbbox('A')[0] + (font.getbbox('中')[2] - font.getbbox('中')[0])) / 2
        if avg_char_width == 0: avg_char_width = font_size * 0.7
        estimated_chars_per_line = int(max_line_width_pixels / avg_char_width)
        if estimated_chars_per_line < 10: estimated_chars_per_line = 10

        wrapped_lines = []
        for paragraph in text.split('\n'):
            if not paragraph.strip():
                wrapped_lines.append('')
                continue
            wrapped_paragraph = textwrap.wrap(paragraph, width=estimated_chars_per_line)
            wrapped_lines.extend(wrapped_paragraph)

        if not wrapped_lines:
            wrapped_lines = [""]

        if FONT_PATH:
            text_height_bbox = font.getbbox("Ay")
            line_height_base = text_height_bbox[3] - text_height_bbox[1]
            if line_height_base <= 0:
                line_height_base = font_size
        else:
            line_height_base = font_size

        line_height = line_height_base + line_spacing
        if line_height <= 0:
            line_height = font_size + line_spacing

        img_height = 2 * padding + len(wrapped_lines) * line_height

        if img_height > MAX_IMG_HEIGHT:
            logger.warning(f"图片高度超过限制 {MAX_IMG_HEIGHT}px，原始高度 {img_height}px，将截断内容。", extra=log_extra)
            displayable_lines = int((MAX_IMG_HEIGHT - 2 * padding - (font_size + line_spacing) * 2) / line_height)
            
            if displayable_lines < 0:
                displayable_lines = 0
            
            wrapped_lines = wrapped_lines[:displayable_lines]
            
            if len(wrapped_lines) < len(text.split('\n')) or (len(wrapped_lines) == 0 and len(text.strip()) > 0): 
                wrapped_lines.append("...")
                wrapped_lines.append("(内容过长，已截断)")
            
            img_height = 2 * padding + len(wrapped_lines) * line_height


        img = Image.new("RGB", (max_width, img_height), (255, 255, 255))
        draw = ImageDraw.Draw(img)

        y = padding
        for line in wrapped_lines:
            draw.text((padding, y), line, font=font, fill=(0, 0, 0))
            y += line_height

        watermark = "AI生成内容"
        watermark_font = None
        if FONT_PATH:
            watermark_font = ImageFont.truetype(FONT_PATH, int(FONT_SIZE * 0.8))
        else:
            watermark_font = ImageFont.load_default()

        watermark_bbox = draw.textbbox((0, 0), watermark, font=watermark_font)
        watermark_width = watermark_bbox[2] - watermark_bbox[0]
        watermark_height = watermark_bbox[3] - watermark_bbox[1]

        if img.height >= (watermark_height + 10):
            draw.text(
                (max_width - watermark_width - 15, img_height - watermark_height - 10),
                watermark,
                font=watermark_font,
                fill=(200, 200, 200)
            )

        output = io.BytesIO()
        img.save(output, format='PNG', optimize=True, quality=85)
        logger.info(f"文本转图片耗时: {time.time()-start_time_img_gen:.2f}秒，图片大小: {len(output.getvalue())/1024:.2f}KB。", extra=log_extra)
        return output.getvalue()
    except Exception as e:
        logger.error(f"文本转换为图片失败: {e}\n{traceback.format_exc()}", extra=log_extra)
        return None

def upload_image_to_wechat(image_bytes: bytes, request_id: str = 'N/A', user_id: str = 'N/A') -> Union[str, None]:
    """
    将图片上传到微信服务器，获取 media_id。
    """
    log_extra = {'request_id': request_id, 'user_id': user_id}
    access_token = get_access_token(request_id, user_id)
    if not access_token:
        logger.error("上传图片失败: 无法获取有效的access_token。", extra=log_extra)
        return None
    if not image_bytes:
        logger.error("上传图片失败: 图片数据为空。", extra=log_extra)
        return None
    
    if len(image_bytes) > WECHAT_MAX_IMAGE_UPLOAD_SIZE:
        logger.error(f"上传图片失败: 图片大小 ({len(image_bytes)/1024:.2f}KB) 超过微信上传限制 ({WECHAT_MAX_IMAGE_UPLOAD_SIZE/1024:.2f}KB)。", extra=log_extra)
        return None

    try:
        url = f"https://api.weixin.qq.com/cgi-bin/media/upload?access_token={access_token}&type=image"
        files = {'media': ('ai_reply.png', image_bytes, 'image/png')}
        logger.info(f"正在上传图片到微信服务器 (大小: {len(image_bytes)/1024:.2f}KB)...", extra=log_extra)
        start_time_img_upload = time.time()
        resp = wechat_api_session.post(url, files=files, timeout=WECHAT_MEDIA_UPLOAD_TIMEOUT)
        resp.raise_for_status()
        data = resp.json()
        logger.info(f"图片上传到微信耗时: {time.time()-start_time_img_upload:.2f}秒", extra=log_extra)
        if 'media_id' in data:
            logger.info(f"图片上传成功，MediaId: {data['media_id'][:10]}...", extra=log_extra)
            return data['media_id']
        logger.error(f"图片上传至微信失败，微信API返回错误: {data}", extra=log_extra)
    except requests.exceptions.Timeout:
        logger.error(f"图片上传到微信超时，URL: {url}", extra=log_extra)
    except requests.exceptions.RequestException as e:
        logger.error(f"图片上传网络请求失败: {e}\n{traceback.format_exc()}", extra=log_extra)
    except Exception as e:
        logger.error(f"图片上传过程中发生异常: {e}\n{traceback.format_exc()}", extra=log_extra)
    return None

@app.before_request
def log_request_and_set_context():
    """在每个请求前记录请求信息，并为日志设置 request_id 和 user_id 上下文。"""
    request_id = str(uuid.uuid4())
    # 尝试从请求中获取 FromUserName，如果获取不到，则使用 'N/A'
    from_user = "N/A"
    try:
        if request.method == 'POST' and request.data:
            xml_data = request.data
            try:
                xml = fromstring(xml_data)
                user_element = xml.find('FromUserName')
                if user_element is not None and user_element.text:
                    from_user = user_element.text
            except ParseError:
                pass # XML解析失败，from_user 保持 N/A

    except Exception as e:
        logger.warning(f"无法从请求中解析 FromUserName for context: {e}", extra={'request_id': request_id, 'user_id': from_user})

    # 将 request_id 和 user_id 附加到 logger 的 extra 字典中
    # 这会影响当前线程（或协程）中的所有日志
    # 注意：在生产WSGI服务器中，需要确保请求上下文和线程的正确管理
    # Flask 2.0+ 提供了 flask.g 来存储请求期间的数据，但 logger.extra 更加直接
    # 更严谨的 LoggerAdapter 方案可以参考：https://docs.python.org/3/howto/logging-cookbook.html#using-loggeradapters-to-add-contextual-information
    
    # 这里直接修改logger的filter，将request_id和user_id注入到LogRecord中
    class ContextFilter(logging.Filter):
        def filter(self, record):
            record.request_id = request_id
            record.user_id = from_user
            return True
    
    # 确保只添加一次这个filter
    if not any(isinstance(f, ContextFilter) for f in logger.filters):
        logger.addFilter(ContextFilter())

    logger.debug(f"收到请求: {request.method} {request.url}", extra={'request_id': request_id, 'user_id': from_user})
    if request.args:
        logger.debug(f"查询参数: {request.args}", extra={'request_id': request_id, 'user_id': from_user})
    if request.method == 'POST' and request.data:
        try:
            body_preview = request.data.decode('utf-8', errors='ignore')[:500]
            logger.debug(f"请求体: {body_preview}...", extra={'request_id': request_id, 'user_id': from_user})
        except Exception:
            logger.debug(f"请求体（无法解码）：{request.data[:500]}...", extra={'request_id': request_id, 'user_id': from_user})

@app.route('/metrics', methods=['GET'])
def get_metrics():
    """
    暴露Prometheus格式的指标。
    """
    output = []
    output.append('# HELP requests_total Total number of requests by message type.')
    output.append('# TYPE requests_total counter')
    for msg_type, count in metrics['requests_total'].items():
        output.append(f'requests_total{{message_type="{msg_type}"}} {count}')
    
    output.append('\n# HELP ai_calls_total Total number of AI calls.')
    output.append('# TYPE ai_calls_total counter')
    output.append(f'ai_calls_total{{status="success"}} {metrics["ai_calls_total"]["success"]}')
    output.append(f'ai_calls_total{{status="failure"}} {metrics["ai_calls_total"]["failure"]}')
    output.append(f'ai_calls_total{{status="blocked"}} {metrics["ai_calls_total"]["blocked"]}')

    output.append('\n# HELP ai_response_time_seconds Duration of AI responses in seconds.')
    output.append('# TYPE ai_response_time_seconds summary')
    if metrics['ai_response_time_seconds']['count'] > 0:
        output.append(f'ai_response_time_seconds_sum {metrics["ai_response_time_seconds"]["sum"]}')
        output.append(f'ai_response_time_seconds_count {metrics["ai_response_time_seconds"]["count"]}')
    else:
        output.append('ai_response_time_seconds_sum 0')
        output.append('ai_response_time_seconds_count 0')

    output.append('\n# HELP image_download_bytes_total Total bytes downloaded for images.')
    output.append('# TYPE image_download_bytes_total counter')
    output.append(f'image_download_bytes_total {metrics["image_download_bytes_total"]}')

    output.append('\n# HELP image_download_failed_total Total number of failed image downloads.')
    output.append('# TYPE image_download_failed_total counter')
    output.append(f'image_download_failed_total {metrics["image_download_failed_total"]}')

    output.append('\n# HELP image_process_failed_total Total number of failed image processing attempts.')
    output.append('# TYPE image_process_failed_total counter')
    output.append(f'image_process_failed_total {metrics["image_process_failed_total"]}')

    output.append('\n# HELP wechat_media_upload_total Total number of media uploads to WeChat.')
    output.append('# TYPE wechat_media_upload_total counter')
    output.append(f'wechat_media_upload_total{{status="success"}} {metrics["wechat_media_upload_total"]["success"]}')
    output.append(f'wechat_media_upload_total{{status="failure"}} {metrics["wechat_media_upload_total"]["failure"]}')

    output.append('\n# HELP redis_cache_total Total Redis cache operations.')
    output.append('# TYPE redis_cache_total counter')
    output.append(f'redis_cache_total{{status="hit"}} {metrics["redis_cache_hits_total"]}')
    output.append(f'redis_cache_total{{status="miss"}} {metrics["redis_cache_misses_total"]}')

    output.append('\n# HELP sensitive_content_blocked_total Total number of messages blocked due to sensitive content.')
    output.append('# TYPE sensitive_content_blocked_total counter')
    output.append(f'sensitive_content_blocked_total {metrics["sensitive_content_blocked_total"]}')

    output.append('\n# HELP api_errors_total Total internal API errors.')
    output.append('# TYPE api_errors_total counter')
    output.append(f'api_errors_total {metrics["api_errors_total"]}')

    response = make_response('\n'.join(output), 200)
    response.headers['Content-Type'] = 'text/plain; version=0.0.4; charset=utf-8'
    return response


# Flask 应用入口
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=80, debug=False)
