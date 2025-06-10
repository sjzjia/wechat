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
import textwrap
import threading
import redis # 引入 redis 库

app = Flask(__name__)

# ==================== 初始化配置 ====================
def setup_logging():
    """配置详细的日志记录系统"""
    log_format = '%(asctime)s - %(levelname)s - %(filename)s:%(lineno)d - %(message)s'
    log_datefmt = '%Y-%m-%d %H:%M:%S'
    
    logger = logging.getLogger()
    logger.setLevel(logging.DEBUG) 
    
    # 控制台输出
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.INFO)
    console_formatter = logging.Formatter(log_format, datefmt=log_datefmt)
    console_handler.setFormatter(console_formatter)
    
    # 文件输出（每天轮换）
    file_handler = logging.FileHandler(
        filename=f'wechat_gemini_{datetime.now().strftime("%Y%m%d")}.log',
        encoding='utf-8',
        mode='a'
    )
    file_handler.setLevel(logging.DEBUG)
    file_formatter = logging.Formatter(log_format, datefmt=log_datefmt)
    file_handler.setFormatter(file_formatter)
    
    logger.addHandler(console_handler)
    logger.addHandler(file_handler)
    
    return logger

logger = setup_logging()

# 环境变量校验
REQUIRED_ENV_VARS = {
    'WECHAT_TOKEN': '微信Token',
    'GEMINI_API_KEY': 'Gemini API密钥',
    'WECHAT_APPID': '微信APPID',
    'WECHAT_APPSECRET': '微信APPSECRET',
    'REDIS_HOST': 'Redis主机地址', # 新增 Redis 配置
    'REDIS_PORT': 'Redis端口'     # 新增 Redis 配置
}

missing_vars = [name for name in REQUIRED_ENV_VARS if not os.environ.get(name)]
if missing_vars:
    error_msg = f"缺少必要环境变量: {', '.join(missing_vars)}"
    logger.critical(error_msg)
    raise EnvironmentError(error_msg)

# 初始化配置
WECHAT_TOKEN = os.environ['WECHAT_TOKEN']
GEMINI_API_KEY = os.environ['GEMINI_API_KEY']
APPID = os.environ['WECHAT_APPID']
APPSECRET = os.environ['WECHAT_APPSECRET']
FONT_PATH = "SourceHanSansSC-Regular.otf" 

if not os.path.exists(FONT_PATH):
    logger.critical(f"字体文件不存在: {FONT_PATH}，请确保已下载并放置在应用根目录。")
    raise FileNotFoundError(f"字体文件不存在: {FONT_PATH}")

try:
    genai.configure(api_key=GEMINI_API_KEY)
    gemini_model = genai.GenerativeModel('gemini-2.0-flash')
    logger.info("Gemini AI 模型初始化成功")
except Exception as e:
    logger.critical(f"Gemini 初始化失败: {str(e)}")
    raise RuntimeError("Gemini AI 模型初始化失败，请检查API密钥和网络连接。")

# ==================== Redis 配置和连接 ====================
REDIS_HOST = os.environ.get('REDIS_HOST', 'localhost')
REDIS_PORT = int(os.environ.get('REDIS_PORT', 6379))
REDIS_DB = int(os.environ.get('REDIS_DB', 0))
REDIS_PASSWORD = os.environ.get('REDIS_PASSWORD') # 如果有密码

try:
    redis_client = redis.StrictRedis(
        host=REDIS_HOST,
        port=REDIS_PORT,
        db=REDIS_DB,
        password=REDIS_PASSWORD,
        decode_responses=True, # 自动解码 Redis 返回的字节为字符串
        socket_connect_timeout=5 # 连接超时
    )
    # 尝试连接 Redis
    redis_client.ping()
    logger.info(f"成功连接到 Redis 服务器: {REDIS_HOST}:{REDIS_PORT}")
except redis.exceptions.ConnectionError as e:
    logger.critical(f"无法连接到 Redis 服务器: {e}")
    raise RuntimeError(f"无法连接到 Redis 服务器: {e}")
except Exception as e:
    logger.critical(f"Redis 初始化失败: {e}")
    raise RuntimeError(f"Redis 初始化失败: {e}")

# Redis 键的前缀，用于区分不同类型的数据
REDIS_KEY_PREFIX = "wechat_ai_result:"
# AI 结果在 Redis 中的过期时间（秒），例如 24 小时
AI_RESULT_EXPIRATION_SECONDS = 24 * 3600 

# ==================== 核心功能 ====================
access_token_cache = {"token": None, "expires_at": 0}

def get_access_token():
    """
    获取微信access_token，带缓存和重试机制。
    access_token 有效期为2小时，我们提前1分钟刷新。
    """
    now = int(time.time())
    if access_token_cache["token"] and access_token_cache["expires_at"] > now + 60:
        logger.debug("使用缓存的access_token")
        return access_token_cache["token"]
    
    logger.info("正在获取新的access_token...")
    try:
        url = f"https://api.weixin.qq.com/cgi-bin/token?grant_type=client_credential&appid={APPID}&secret={APPSECRET}"
        resp = requests.get(url, timeout=5)
        resp.raise_for_status()
        data = resp.json()
        
        if 'access_token' in data:
            access_token_cache["token"] = data['access_token']
            expires_in = data.get('expires_in', 7200)
            access_token_cache["expires_at"] = now + expires_in
            logger.info(f"获取access_token成功，有效期: {expires_in}秒，下次刷新时间: {datetime.fromtimestamp(access_token_cache['expires_at']-60)}")
            return data['access_token']
        
        logger.error(f"获取access_token失败，微信API返回错误: {data}")
    except requests.exceptions.RequestException as e:
        logger.error(f"获取access_token网络请求失败: {e}")
    except Exception as e:
        logger.error(f"获取access_token时发生异常: {e}")
    return None

def verify_wechat_config():
    """验证微信基础配置和API连通性"""
    logger.info("开始验证微信配置...")
    
    if not all([WECHAT_TOKEN, APPID, APPSECRET]):
        logger.error("微信基础配置（WECHAT_TOKEN, APPID, APPSECRET）不完整。")
        return False
    
    token = get_access_token()
    if not token:
        logger.error("无法获取access_token，请检查WECHAT_APPID和WECHAT_APPSECRET是否正确。")
        return False
    
    logger.info("微信配置验证通过。")
    return True

if not verify_wechat_config():
    raise RuntimeError("微信配置验证失败，服务无法启动。请检查环境变量和网络。")

# ==================== 微信验证接口 ====================
@app.route('/', methods=['GET'])
def wechat_verify():
    """
    微信服务器URL验证接口。
    此接口用于微信后台配置URL时进行验证。
    """
    try:
        logger.info("收到微信服务器验证请求。")
        
        signature = request.args.get('signature', '').strip()
        timestamp = request.args.get('timestamp', '').strip()
        nonce = request.args.get('nonce', '').strip()
        echostr = request.args.get('echostr', '').strip()

        logger.debug(f"验证参数 - signature: {signature}, timestamp: {timestamp}, nonce: {nonce}, echostr: {echostr}")

        if not all([signature, timestamp, nonce, echostr]):
            missing_params = [p for p, val in {'signature': signature, 'timestamp': timestamp, 'nonce': nonce, 'echostr': echostr}.items() if not val]
            logger.error(f"验证请求参数缺失: {', '.join(missing_params)}")
            return make_response("Invalid parameters.", 400)

        if check_signature(signature, timestamp, nonce):
            logger.info("微信服务器验证成功。")
            return echostr
        else:
            logger.warning("微信服务器签名验证失败。")
            return make_response("Signature verification failed.", 403)

    except Exception as e:
        logger.error(f"微信服务器验证接口发生异常: {e}\n{traceback.format_exc()}")
        return make_response("Server internal error during verification.", 500)

def check_signature(signature, timestamp, nonce):
    """
    增强的微信服务器签名验证。
    """
    try:
        if not all([signature, timestamp, nonce]):
            logger.warning("签名验证失败: 传入参数不完整。")
            return False

        try:
            timestamp_int = int(timestamp)
            time_diff = abs(int(time.time()) - timestamp_int)
            if time_diff > 300:
                logger.warning(f"签名验证失败: 时间戳过期 (当前时间戳差异: {time_diff}秒)。")
                return False
        except ValueError:
            logger.warning(f"签名验证失败: 时间戳格式无效 '{timestamp}'。")
            return False

        tmp_list = sorted([WECHAT_TOKEN, timestamp, nonce])
        tmp_str = ''.join(tmp_list).encode('utf-8')
        calculated_signature = hashlib.sha1(tmp_str).hexdigest()
        
        if calculated_signature == signature:
            logger.debug("签名验证成功。")
            return True
            
        logger.warning(f"签名验证失败: 计算签名 '{calculated_signature[:10]}...' 与接收签名 '{signature[:10]}...' 不匹配。")
        return False
    except Exception as e:
        logger.error(f"签名验证过程中发生异常: {e}\n{traceback.format_exc()}")
        return False

# ==================== 消息处理接口 ====================
@app.route('/', methods=['POST'])
def handle_message():
    """处理用户发送的微信消息"""
    from_user = ""
    to_user = ""
    try:
        logger.info("收到用户消息 POST 请求。")
        
        xml_data = request.data
        logger.debug(f"原始XML数据: {xml_data.decode('utf-8')[:500]}...")
        
        xml = fromstring(xml_data)
        msg_type = xml.find('MsgType').text
        from_user = xml.find('FromUserName').text
        to_user = xml.find('ToUserName').text
        
        logger.info(f"消息类型: {msg_type}, 来自用户: {from_user}, 发送给: {to_user}")

        if msg_type == 'text':
            content = xml.find('Content').text
            logger.info(f"接收到文本消息: {content[:100]}...")
            
            # 处理用户查询图片结果的文本消息
            if content.strip() == "查询图片结果":
                return query_image_result(from_user, to_user)
            
            # 如果不是查询指令，则作为普通文本消息处理
            ai_response_content = process_text_message(content)
            return build_reply(from_user, to_user, ai_response_content)
        
        elif msg_type == 'image':
            pic_url = xml.find('PicUrl').text
            logger.info(f"接收到图片消息, URL: {pic_url[:100]}...")
            
            # 立即返回一个“处理中”的文本消息给微信
            reply_xml_str = f"""<xml>
                <ToUserName><![CDATA[{from_user}]]></ToUserName>
                <FromUserName><![CDATA[{to_user}]]></FromUserName>
                <CreateTime>{int(time.time())}</CreateTime>
                <MsgType><![CDATA[text]]></MsgType>
                <Content><![CDATA[图片已收到，AI正在努力识别中，请耐心等待10-20秒后发送“查询图片结果”来获取。]]></Content>
            </xml>"""
            
            # 在一个新线程中异步调用图片处理逻辑
            # 注意：这里需要将 from_user 传递给异步函数，以便存储结果
            threading.Thread(target=async_process_image, args=(pic_url, from_user, to_user)).start()
            
            # 立即返回响应，避免微信超时
            return make_response(reply_xml_str, 200, {'Content-Type': 'application/xml'})
            
        else:
            logger.warning(f"接收到不支持的消息类型: {msg_type}")
            ai_response_content = "暂不支持该类型的消息，请发送文本或图片。"
            return build_reply(from_user, to_user, ai_response_content)

    except Exception as e:
        logger.error(f"处理微信消息时发生异常: {e}\n{traceback.format_exc()}")
        safe_from_user = from_user if 'from_user' in locals() and from_user else 'unknown_user'
        safe_to_user = to_user if 'to_user' in locals() and to_user else 'unknown_app'
        
        error_xml_str = f"""<xml>
            <ToUserName><![CDATA[{safe_from_user}]]></ToUserName>
            <FromUserName><![CDATA[{safe_to_user}]]></FromUserName>
            <CreateTime>{int(time.time())}</CreateTime>
            <MsgType><![CDATA[text]]></MsgType>
            <Content><![CDATA[服务器内部错误，请稍后重试。]]></Content>
        </xml>"""
        return make_response(error_xml_str, 500, {'Content-Type': 'application/xml'})

def async_process_image(pic_url, from_user, to_user):
    """
    在后台线程中异步处理图片消息。
    处理完成后将结果存储到 Redis，但不发送给用户。
    """
    try:
        logger.info(f"后台线程开始处理图片: {pic_url} for user: {from_user}")
        
        start_overall_time = time.time()
        
        # 1. 下载图片
        start_download_time = time.time()
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/100.0.4896.127 Safari/537.36'}
        image_resp = requests.get(pic_url, timeout=5, headers=headers)
        image_resp.raise_for_status()
        image_data = image_resp.content
        logger.info(f"后台图片下载完成，耗时: {time.time()-start_download_time:.2f}秒，大小: {len(image_data)/1024:.2f}KB")

        # 2. 图像预处理
        img = Image.open(io.BytesIO(image_data))
        if img.mode != 'RGB':
            img = img.convert('RGB')

        # 3. 调用 Gemini
        prompt = "请用中文详细描述这张图片的内容，并尽可能分析它的含义。"
        logger.info("后台调用 Gemini 处理图片...")
        ai_response_content = generate_with_retry(prompt, img, is_image_context=True)
        
        logger.info(f"后台AI处理图片完成，总耗时: {time.time()-start_overall_time:.2f}秒。回复内容长度: {len(ai_response_content.encode('utf-8'))}字节")

        # ====== 新增：将AI结果存储到 Redis ======
        redis_key = f"{REDIS_KEY_PREFIX}{from_user}"
        # 将结果存储为字符串，包含时间戳和内容
        # 如果需要存储多条，可以使用 Redis 的 List 或 Hash
        # 这里为了简化，只存储最新的结果
        value = f"{int(time.time())}|{ai_response_content}"
        redis_client.set(redis_key, value, ex=AI_RESULT_EXPIRATION_SECONDS)
        logger.info(f"AI结果已为用户 {from_user} 存储到 Redis (key: {redis_key})，有效期 {AI_RESULT_EXPIRATION_SECONDS} 秒。")
        # ==========================================
        
    except Exception as e:
        logger.error(f"后台图片处理线程发生异常: {e}\n{traceback.format_exc()}")


def query_image_result(from_user, to_user):
    """
    处理用户查询图片结果的请求，从 Redis 中获取结果。
    """
    redis_key = f"{REDIS_KEY_PREFIX}{from_user}"
    stored_value = redis_client.get(redis_key) # 获取存储的值

    if stored_value:
        # 解析存储的值
        try:
            timestamp_str, content = stored_value.split('|', 1)
            timestamp = int(timestamp_str)
            content_to_reply = f"这是您最近一次图片识别的结果（{time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(timestamp))}）:\n\n{content}"
            logger.info(f"为用户 {from_user} 返回存储在 Redis 中的图片识别结果。")
        except ValueError: # 解析失败
            content_to_reply = "抱歉，无法解析存储的图片识别结果，请重试。"
            logger.error(f"解析 Redis 存储值失败 for user {from_user}: {stored_value}")
    else:
        content_to_reply = "AI正在努力识别中,请耐心等待。"
        logger.info(f"用户 {from_user} 查询图片结果，Redis 中无可用结果。")
    
    # 使用 build_reply 函数来统一处理文本或图片回复
    return build_reply(from_user, to_user, content_to_reply)

def process_text_message(content):
    """通过 Gemini 处理文本消息并返回 AI 生成的文本"""
    logger.info("调用 Gemini 处理文本...")
    try:
        # 文本消息不涉及图片下载和转换，通常速度快，可以同步处理
        return generate_with_retry(content, is_image_context=False)
    except Exception as e:
        logger.error(f"处理文本消息时 AI 调用失败: {e}")
        return "AI处理文本失败，请稍后再试。"

def generate_with_retry(prompt, image=None, max_retries=3, is_image_context=False):
    """
    带重试机制的 AI 内容生成。
    对于图片上下文，会尽可能在API层面设置短超时。
    """
    retry_count = 0
    
    # AI 模型的请求超时时间。这是对 Gemini API 调用本身的网络超时。
    # 对于图片上下文，由于我们现在是异步处理，可以给 Gemini 更多时间来响应，
    # 比如 15-20 秒，因为主线程已经返回了。
    ai_api_request_timeout = 20 if is_image_context else 30 
    logger.debug(f"AI请求超时设置为: {ai_api_request_timeout}秒 (is_image_context={is_image_context})")


    generation_config = genai.types.GenerationConfig(
        temperature=0.7,
        top_p=0.9,
        top_k=40,
        max_output_tokens=1024 
    )
    
    start_overall_ai_time = time.time()
    
    while retry_count < max_retries:
        try:
            start_single_attempt_time = time.time()
            
            if image:
                response = gemini_model.generate_content(
                    [prompt, image],
                    generation_config=generation_config,
                    request_options={"timeout": ai_api_request_timeout}
                )
            else:
                response = gemini_model.generate_content(
                    prompt,
                    generation_config=generation_config,
                    request_options={"timeout": ai_api_request_timeout}
                )
            
            if response and response.text:
                current_ai_duration = time.time() - start_overall_ai_time
                logger.info(f"AI 生成成功，耗时: {current_ai_duration:.2f}秒 (单次尝试: {time.time()-start_single_attempt_time:.2f}秒)")
                return response.text.strip()
            
            logger.warning(f"AI 返回了空内容或无效响应 (尝试 {retry_count+1}/{max_retries})。")
            
        except Exception as e:
            retry_count += 1
            wait_time = min(2 ** retry_count, 10)
            logger.warning(f"AI 生成失败 (尝试 {retry_count}/{max_retries}), 等待 {wait_time:.2f} 秒: {e}")
            time.sleep(wait_time)
            
    logger.error("AI 生成失败，已达到最大重试次数。")
    return "AI 服务暂时不可用，请稍后再试。"

def build_reply(from_user, to_user, content):
    """
    根据内容长度构建微信回复。
    - 大于 2000 字节转图片回复。
    - 小于等于 2000 字节文本回复，不截断。
    - 图片转换或上传失败时，回退到截断的文本回复。
    """
    try:
        cleaned_content = clean_content(content, max_bytes=None)
        content_bytes = len(cleaned_content.encode('utf-8'))
        reply_xml_str = None

        if content_bytes > 2000:
            logger.info(f"内容过长({content_bytes}字节)，尝试转换为图片并回复。")
            img_data = text_to_image(cleaned_content)

            if img_data:
                media_id = upload_image_to_wechat(img_data)
                
                if media_id:
                    logger.info("图片已成功上传至微信，使用图片回复。")
                    reply_xml_str = f"""<xml>
                        <ToUserName><![CDATA[{from_user}]]></ToUserName>
                        <FromUserName><![CDATA[{to_user}]]></FromUserName>
                        <CreateTime>{int(time.time())}</CreateTime>
                        <MsgType><![CDATA[image]]></MsgType>
                        <Image><MediaId><![CDATA[{media_id}]]></MediaId></Image>
                    </xml>"""
                else:
                    logger.warning("图片上传至微信失败，回退到文本回复并截断。")
                    truncated_content = clean_content(cleaned_content, max_bytes=2000)
                    reply_xml_str = f"""<xml>
                        <ToUserName><![CDATA[{from_user}]]></ToUserName>
                        <FromUserName><![CDATA[{to_user}]]></FromUserName>
                        <CreateTime>{int(time.time())}</CreateTime>
                        <MsgType><![CDATA[text]]></MsgType>
                        <Content><![CDATA[AI回复超长，转图片失败。以下为截断内容：\n{escape(truncated_content)}]]></Content>
                    </xml>"""
            else:
                logger.warning("文本转换为图片失败，回退到文本回复并截断。")
                truncated_content = clean_content(cleaned_content, max_bytes=2000)
                reply_xml_str = f"""<xml>
                    <ToUserName><![CDATA[{from_user}]]></ToUserName>
                    <FromUserName><![CDATA[{to_user}]]></FromUserName>
                    <CreateTime>{int(time.time())}</CreateTime>
                    <MsgType><![CDATA[text]]></MsgType>
                    <Content><![CDATA[AI回复超长，转图片失败。以下为截断内容：\n{escape(truncated_content)}]]></Content>
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
        safe_from_user = from_user if 'from_user' in locals() and from_user else 'unknown_user'
        safe_to_user = to_user if 'to_user' in locals() and to_user else 'unknown_app'
        error_xml_str = f"""<xml>
            <ToUserName><![CDATA[{safe_from_user}]]></ToUserName>
            <FromUserName><![CDATA[{safe_to_user}]]></FromUserName>
            <CreateTime>{int(time.time())}</CreateTime>
            <MsgType><![CDATA[text]]></MsgType>
            <Content><![CDATA[AI回复异常，请稍后重试。]]></Content>
        </xml>"""
        return make_response(error_xml_str, 500, {'Content-Type': 'application/xml'})

# ==================== 实用工具函数 ====================
def clean_content(content, max_bytes=None):
    """
    清理文本内容：移除 Markdown 格式、合并多余空行、去除首尾空白。
    如果提供了 max_bytes，则会根据字节数进行截断。
    """
    if not content:
        return ""
    
    content = re.sub(r'(\*\*|__|\*|_|`|~~|#+\s*|\[.*?\]\(.*?\))', '', content)

    processed_lines = []
    for line in content.split('\n'):
        stripped_line = line.strip()
        if not stripped_line:
            processed_lines.append('')
        else:
            processed_lines.append(stripped_line)

    content = '\n'.join(processed_lines)
    content = re.sub(r'\n{2,}', '\n\n', content)
    content = content.strip()

    if max_bytes is not None:
        encoded = content.encode('utf-8')
        if len(encoded) > max_bytes:
            logger.warning(f"内容因字节限制被截断: 原始 {len(encoded)} 字节，截断至 {max_bytes} 字节。")
            return encoded[:max_bytes].decode('utf-8', errors='ignore')
    return content

def text_to_image(text, max_width=600, font_size=24):
    """
    将长文本转换为图片。
    自动处理文本换行和添加水印。
    """
    try:
        start_time_img_gen = time.time()
        padding = 30
        line_spacing = 10
        font = ImageFont.truetype(FONT_PATH, font_size)
        
        avg_char_width = font.getlength('中') 
        chars_per_line = int((max_width - 2 * padding) / avg_char_width)

        wrapped_lines = []
        for paragraph in text.split('\n'):
            if not paragraph.strip():
                wrapped_lines.append('')
            else:
                wrapped_lines.extend(textwrap.wrap(paragraph, width=chars_per_line, break_long_words=False, replace_whitespace=False))
        
        if not wrapped_lines:
            wrapped_lines = [""]

        line_height = font_size + line_spacing
        img_height = 2 * padding + len(wrapped_lines) * line_height
        
        img = Image.new("RGB", (max_width, img_height), (255, 255, 255))
        draw = ImageDraw.Draw(img)
        
        y = padding
        for line in wrapped_lines:
            draw.text((padding, y), line, font=font, fill=(0, 0, 0))
            y += line_height
        
        watermark = "AI生成内容"
        watermark_font = ImageFont.truetype(FONT_PATH, int(font_size * 0.8))
        watermark_width = watermark_font.getlength(watermark)
        draw.text(
            (max_width - watermark_width - 15, img_height - int(font_size * 0.8) - 10),
            watermark,
            font=watermark_font,
            fill=(200, 200, 200)
        )
        
        output = io.BytesIO()
        img.save(output, format='PNG', optimize=True, quality=90)
        logger.info(f"文本转图片耗时: {time.time()-start_time_img_gen:.2f}秒")
        return output.getvalue()
    except Exception as e:
        logger.error(f"文本转换为图片失败: {e}\n{traceback.format_exc()}")
        return None

def upload_image_to_wechat(image_bytes):
    """
    将生成的图片上传到微信服务器，获取 media_id。
    media_id 默认有效期为3天。
    """
    access_token = get_access_token()
    if not access_token:
        logger.error("上传图片失败: 无法获取有效的access_token。")
        return None
    
    try:
        url = f"https://api.weixin.qq.com/cgi-bin/media/upload?access_token={access_token}&type=image"
        files = {'media': ('ai_reply.png', image_bytes, 'image/png')}
        
        logger.info("正在上传图片到微信服务器...")
        start_time_img_upload = time.time()
        resp = requests.post(url, files=files, timeout=10)
        resp.raise_for_status()
        data = resp.json()
        logger.info(f"图片上传到微信耗时: {time.time()-start_time_img_upload:.2f}秒")
        
        if 'media_id' in data:
            logger.info(f"图片上传成功，MediaId: {data['media_id'][:10]}...")
            return data['media_id']
        
        logger.error(f"图片上传至微信失败，微信API返回错误: {data}")
    except requests.exceptions.RequestException as e:
        logger.error(f"图片上传网络请求失败: {e}")
    except Exception as e:
        logger.error(f"图片上传过程中发生异常: {e}")
    return None

# ==================== 请求/响应日志和启动 ====================
@app.before_request
def log_request():
    """在每个请求处理前记录请求信息"""
    logger.debug(f"收到请求: {request.method} {request.url}")
    if request.args:
        logger.debug(f"查询参数: {request.args}")
    if request.method == 'POST' and request.data:
        try:
            body_preview = request.data.decode('utf-8', errors='ignore')[:200]
            logger.debug(f"请求体: {body_preview}...")
        except Exception:
            logger.debug(f"请求体（无法解码）：{request.data[:200]}...")
