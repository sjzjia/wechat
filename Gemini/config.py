# -*- coding: utf-8 -*-
"""
存放应用的配置信息和初始化逻辑
"""
import os
import logging
import traceback
from datetime import datetime

import google.generativeai as genai
import redis
from PIL import ImageFont
from pythonjsonlogger import jsonlogger

# ==================== 日志配置 ====================
def setup_logging():
    """配置详细的日志记录系统，输出为 JSON 格式"""
    log_format = '%(asctime)s %(levelname)s %(filename)s:%(lineno)d %(message)s'
    logger = logging.getLogger(__name__) # 使用 __name__ 获取当前模块的 logger
    # 检查 logger 是否已经有 handlers，防止重复添加
    if not logger.handlers:
        logger.setLevel(logging.DEBUG)
        # 控制台输出 handler
        console_handler = logging.StreamHandler()
        console_handler.setLevel(logging.INFO)
        formatter = jsonlogger.JsonFormatter(log_format,
                                             rename_fields={'levelname': 'level', 'asctime': 'timestamp', 'filename': 'file', 'lineno': 'line'},
                                             json_ensure_ascii=False)
        console_handler.setFormatter(formatter)
        logger.addHandler(console_handler)

        # 文件输出 handler
        file_handler = logging.FileHandler(
            filename=f'wechat_gemini_{datetime.now().strftime("%Y%m%d")}.log',
            encoding='utf-8',
            mode='a'
        )
        file_handler.setLevel(logging.DEBUG)
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)
    return logger

logger = setup_logging()

# ==================== 环境变量校验 ====================
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
    error_msg = f"缺少必要环境变量: {', '.join([f'{REQUIRED_ENV_VARS[v]} ({v})' for v in missing_vars])}"
    logger.critical(error_msg)
    raise EnvironmentError(error_msg)

# ==================== 应用配置 (从环境变量读取) ====================
WECHAT_TOKEN = os.environ['WECHAT_TOKEN']
GEMINI_API_KEY = os.environ['GEMINI_API_KEY']
APPID = os.environ['WECHAT_APPID']
APPSECRET = os.environ['WECHAT_APPSECRET']

# AI 模型配置参数
GEMINI_TEMPERATURE = float(os.environ.get('GEMINI_TEMPERATURE', 0.7))
GEMINI_TOP_P = float(os.environ.get('GEMINI_TOP_P', 0.9))
GEMINI_TOP_K = int(os.environ.get('GEMINI_TOP_K', 40))
GEMINI_MAX_OUTPUT_TOKENS = int(os.environ.get('GEMINI_MAX_OUTPUT_TOKENS', 8192))

# 图片下载限制 (软限制，字节)
MAX_IMAGE_DOWNLOAD_SIZE = int(os.environ.get('MAX_IMAGE_DOWNLOAD_SIZE', 5 * 1024 * 1024))  # 5MB

# 微信图片上传限制 (字节)
WECHAT_MAX_IMAGE_UPLOAD_SIZE = int(os.environ.get('WECHAT_MAX_IMAGE_UPLOAD_SIZE', 2 * 1024 * 1024))  # 2MB

# 微信文本消息限制 (字节)
WECHAT_TEXT_MAX_BYTES = int(os.environ.get('WECHAT_TEXT_MAX_BYTES', 2000))

# API 请求超时时间
GEMINI_IMAGE_TIMEOUT = int(os.environ.get('GEMINI_IMAGE_TIMEOUT', 30))
GEMINI_TEXT_TIMEOUT = int(os.environ.get('GEMINI_TEXT_TIMEOUT', 20))
WECHAT_ACCESS_TOKEN_TIMEOUT = int(os.environ.get('WECHAT_ACCESS_TOKEN_TIMEOUT', 5))
WECHAT_MEDIA_UPLOAD_TIMEOUT = int(os.environ.get('WECHAT_MEDIA_UPLOAD_TIMEOUT', 10))
WECHAT_VOICE_DOWNLOAD_TIMEOUT = int(os.environ.get('WECHAT_VOICE_DOWNLOAD_TIMEOUT', 10))
IMAGE_DOWNLOAD_TIMEOUT = int(os.environ.get('IMAGE_DOWNLOAD_TIMEOUT', 10))
DNS_RESOLVE_TIMEOUT = int(os.environ.get('DNS_RESOLVE_TIMEOUT', 2))

# 文本转图片限制
MAX_IMG_WIDTH = int(os.environ.get('MAX_IMG_WIDTH', 600))
MAX_IMG_HEIGHT = int(os.environ.get('MAX_IMG_HEIGHT', 4000))
FONT_SIZE = int(os.environ.get('FONT_SIZE', 24))
LINE_SPACING_FACTOR = float(os.environ.get('LINE_SPACING_FACTOR', 0.5))
IMAGE_PADDING = int(os.environ.get('IMAGE_PADDING', 30))

FONT_PATH = os.environ.get('FONT_PATH', './SourceHanSansSC-Regular.otf')
if not os.path.exists(FONT_PATH):
    logger.warning(f"字体文件不存在: {FONT_PATH}，将尝试使用Pillow默认字体。中文显示可能不正常。")
    try:
        ImageFont.load_default()
        FONT_PATH = None # 标记为使用默认字体
        logger.info("已成功加载Pillow默认字体。")
    except Exception as e:
        logger.critical(f"加载Pillow默认字体失败: {e}。请确保Pillow已正确安装或提供有效的字体文件路径。")
        # 根据实际需求，这里可以选择抛出异常或者允许程序继续运行（但中文可能乱码）
        # raise FileNotFoundError(f"字体文件 {FONT_PATH} 不存在且无法加载默认字体。")
        FONT_PATH = None # 即使加载失败，也尝试继续，但记录严重错误

# ==================== Gemini AI 初始化 ====================
GEMINI_GENERATION_CONFIG = genai.types.GenerationConfig(
    temperature=GEMINI_TEMPERATURE,
    top_p=GEMINI_TOP_P,
    top_k=GEMINI_TOP_K,
    max_output_tokens=GEMINI_MAX_OUTPUT_TOKENS
)

try:
    genai.configure(api_key=GEMINI_API_KEY)
    gemini_model = genai.GenerativeModel('gemini-2.0-flash') # 或者 'gemini-pro', 'gemini-pro-vision'
    logger.info(f"Gemini AI 模型 ({gemini_model.model_name}) 初始化成功。")
except Exception as e:
    logger.critical(f"Gemini 初始化失败: {str(e)}\n{traceback.format_exc()}")
    # 在生产环境中，如果AI模型是核心功能，应该抛出异常终止应用启动
    raise RuntimeError("Gemini AI 模型初始化失败，请检查API密钥和网络连接。")

# ==================== Redis 配置和连接 ====================
REDIS_HOST = os.environ.get('REDIS_HOST', 'localhost')
REDIS_PORT = int(os.environ.get('REDIS_PORT', 6379))
REDIS_DB = int(os.environ.get('REDIS_DB', 0))
REDIS_PASSWORD = os.environ.get('REDIS_PASSWORD') # 如果没有密码，环境变量可以不设置，这里会是 None
REDIS_MAX_CONNECTIONS = int(os.environ.get('REDIS_MAX_CONNECTIONS', 20))
REDIS_CONNECT_TIMEOUT = int(os.environ.get('REDIS_CONNECT_TIMEOUT', 5))
REDIS_SOCKET_TIMEOUT = int(os.environ.get('REDIS_SOCKET_TIMEOUT', 5))
REDIS_HEALTH_CHECK_INTERVAL = int(os.environ.get('REDIS_HEALTH_CHECK_INTERVAL', 30))

redis_client = None
try:
    REDIS_CONNECTION_POOL = redis.ConnectionPool(
        host=REDIS_HOST,
        port=REDIS_PORT,
        db=REDIS_DB,
        password=REDIS_PASSWORD,
        max_connections=REDIS_MAX_CONNECTIONS,
        socket_connect_timeout=REDIS_CONNECT_TIMEOUT,
        socket_timeout=REDIS_SOCKET_TIMEOUT,
        decode_responses=True, # 自动解码 bytes 为 str
        health_check_interval=REDIS_HEALTH_CHECK_INTERVAL,
        retry_on_timeout=True # 连接超时时重试
    )
    redis_client = redis.Redis(connection_pool=REDIS_CONNECTION_POOL)
    redis_client.ping() # 测试连接
    logger.info(f"成功连接到 Redis 服务器: {REDIS_HOST}:{REDIS_PORT} (DB: {REDIS_DB}, 连接池大小: {REDIS_CONNECTION_POOL.max_connections})")
except redis.exceptions.ConnectionError as e:
    logger.critical(f"无法连接到 Redis 服务器 ({REDIS_HOST}:{REDIS_PORT}): {e}")
    # 根据应用需求，这里可以选择抛出异常或允许应用在没有 Redis 的情况下运行（功能受限）
    # raise RuntimeError(f"无法连接到 Redis 服务器: {e}")
    redis_client = None # 明确标记 Redis 不可用
    logger.warning("Redis 连接失败，应用将在没有 Redis 缓存的情况下运行，部分功能可能受限或不可用。")

# 可以在这里添加更多配置项的加载和校验
logger.info("应用配置加载完成。")
