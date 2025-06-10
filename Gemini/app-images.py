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
    'WECHAT_APPSECRET': '微信APPSECRET'
}

missing_vars = [name for name in REQUIRED_ENV_VARS if not os.environ.get(name)]
if missing_vars:
    error_msg = f"缺少必要环境变量: {', '.join(missing_vars)}"
    logger.critical(error_msg)
    # 在生产环境中，强烈建议在启动时抛出异常，防止程序在配置不全时运行
    raise EnvironmentError(error_msg)

# 初始化配置
WECHAT_TOKEN = os.environ['WECHAT_TOKEN']
GEMINI_API_KEY = os.environ['GEMINI_API_KEY']
APPID = os.environ['WECHAT_APPID']
APPSECRET = os.environ['WECHAT_APPSECRET']
FONT_PATH = "SourceHanSansSC-Regular.otf" # 确保此字体文件存在于你的应用目录下

# 检查字体文件是否存在
if not os.path.exists(FONT_PATH):
    logger.critical(f"字体文件不存在: {FONT_PATH}，请确保已下载并放置在应用根目录。")
    raise FileNotFoundError(f"字体文件不存在: {FONT_PATH}")

# 初始化 Gemini 模型（全局唯一实例）
try:
    genai.configure(api_key=GEMINI_API_KEY)
    gemini_model = genai.GenerativeModel('gemini-2.0-flash')
    logger.info("Gemini AI 模型初始化成功")
except Exception as e:
    logger.critical(f"Gemini 初始化失败: {str(e)}")
    raise RuntimeError("Gemini AI 模型初始化失败，请检查API密钥和网络连接。")

# ==================== 核心功能 ====================
access_token_cache = {"token": None, "expires_at": 0}

def get_access_token():
    """
    获取微信access_token，带缓存和重试机制。
    access_token 有效期为2小时，我们提前1分钟刷新。
    """
    now = int(time.time())
    # 提前60秒刷新 access_token
    if access_token_cache["token"] and access_token_cache["expires_at"] > now + 60:
        logger.debug("使用缓存的access_token")
        return access_token_cache["token"]
    
    logger.info("正在获取新的access_token...")
    try:
        url = f"https://api.weixin.qq.com/cgi-bin/token?grant_type=client_credential&appid={APPID}&secret={APPSECRET}"
        resp = requests.get(url, timeout=5)
        resp.raise_for_status() # 检查HTTP响应状态码
        data = resp.json()
        
        if 'access_token' in data:
            access_token_cache["token"] = data['access_token']
            expires_in = data.get('expires_in', 7200) # 默认 7200 秒
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
    
    # 尝试获取一次 access_token 来验证 API 连通性
    token = get_access_token()
    if not token:
        logger.error("无法获取access_token，请检查WECHAT_APPID和WECHAT_APPSECRET是否正确。")
        return False
    
    logger.info("微信配置验证通过。")
    return True

# 应用启动时立即验证所有关键配置
if not verify_wechat_config():
    raise RuntimeError("微信配置验证失败，服务无法启动。请检查环境变量和网络。")

# ==================== 微信验证接口 ====================
def check_signature(signature, timestamp, nonce):
    """
    增强的微信服务器签名验证。
    - 检查参数完整性。
    - 检查时间戳是否在合理范围内（防止重放攻击）。
    - 计算并验证签名。
    """
    try:
        if not all([signature, timestamp, nonce]):
            logger.warning("签名验证失败: 传入参数不完整。")
            return False

        # 检查时间戳有效性 (5分钟内)
        try:
            timestamp_int = int(timestamp)
            time_diff = abs(int(time.time()) - timestamp_int)
            if time_diff > 300: # 5分钟 = 300秒
                logger.warning(f"签名验证失败: 时间戳过期 (当前时间戳差异: {time_diff}秒)。")
                return False
        except ValueError:
            logger.warning(f"签名验证失败: 时间戳格式无效 '{timestamp}'。")
            return False

        # 按字典序排序 token, timestamp, nonce 并拼接
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

@app.route('/', methods=['GET'])
def wechat_verify():
    """
    微信服务器URL验证接口。
    此接口用于微信后台配置URL时进行验证。
    """
    try:
        logger.info("收到微信服务器验证请求。")
        
        # 使用更稳健的方式获取参数，以防大小写或编码问题
        signature = request.args.get('signature', '').strip()
        timestamp = request.args.get('timestamp', '').strip()
        nonce = request.args.get('nonce', '').strip()
        echostr = request.args.get('echostr', '').strip()

        # 详细日志记录所有收到的参数
        logger.debug(f"验证参数 - signature: {signature}, timestamp: {timestamp}, nonce: {nonce}, echostr: {echostr}")

        # 验证所有必需参数是否存在
        if not all([signature, timestamp, nonce, echostr]):
            missing_params = [p for p, val in {'signature': signature, 'timestamp': timestamp, 'nonce': nonce, 'echostr': echostr}.items() if not val]
            logger.error(f"验证请求参数缺失: {', '.join(missing_params)}")
            return make_response("Invalid parameters.", 400) # 返回 400 Bad Request

        # 执行签名验证
        if check_signature(signature, timestamp, nonce):
            logger.info("微信服务器验证成功。")
            return echostr # 返回 echostr
        else:
            logger.warning("微信服务器签名验证失败。")
            return make_response("Signature verification failed.", 403) # 返回 403 Forbidden

    except Exception as e:
        logger.error(f"微信服务器验证接口发生异常: {e}\n{traceback.format_exc()}")
        return make_response("Server internal error during verification.", 500)

# ==================== 消息处理接口 ====================
@app.route('/', methods=['POST'])
def handle_message():
    """处理用户发送的微信消息"""
    from_user = "" # 确保在 try 块外部初始化，以便在 except 块中可以访问
    to_user = ""
    try:
        logger.info("收到用户消息 POST 请求。")
        
        xml_data = request.data
        logger.debug(f"原始XML数据: {xml_data.decode('utf-8')[:500]}...") # 限制日志长度
        
        xml = fromstring(xml_data) # 解析 XML
        msg_type = xml.find('MsgType').text
        from_user = xml.find('FromUserName').text
        to_user = xml.find('ToUserName').text
        
        logger.info(f"消息类型: {msg_type}, 来自用户: {from_user}, 发送给: {to_user}")

        ai_response_content = "" # 存储 AI 生成的回复内容（纯文本）

        if msg_type == 'text':
            content = xml.find('Content').text
            logger.info(f"接收到文本消息: {content[:100]}...") # 限制日志长度
            ai_response_content = process_text_message(content)
        elif msg_type == 'image':
            pic_url = xml.find('PicUrl').text
            # media_id = xml.find('MediaId').text # media_id 在当前逻辑中未使用，如果需要上传到其他地方再考虑
            logger.info(f"接收到图片消息, URL: {pic_url[:100]}...") # 限制日志长度
            ai_response_content = process_image_message(pic_url)
        # elif msg_type == 'voice':
        #     logger.warning("暂不支持语音消息处理。")
        #     ai_response_content = "暂不支持语音消息，请发送文本或图片。"
        else:
            logger.warning(f"接收到不支持的消息类型: {msg_type}")
            ai_response_content = "暂不支持该类型的消息，请发送文本或图片。"

        # 构建最终的微信回复（可能为文本或图片）
        return build_reply(from_user, to_user, ai_response_content)

    except Exception as e:
        logger.error(f"处理微信消息时发生异常: {e}\n{traceback.format_exc()}")
        # 确保 from_user 和 to_user 在异常时也能安全访问，以便构建错误回复
        safe_from_user = from_user if 'from_user' in locals() and from_user else 'unknown_user'
        safe_to_user = to_user if 'to_user' in locals() and to_user else 'unknown_app'
        
        # 返回一个通用的错误文本回复
        error_xml_str = f"""<xml>
            <ToUserName><![CDATA[{safe_from_user}]]></ToUserName>
            <FromUserName><![CDATA[{safe_to_user}]]></FromUserName>
            <CreateTime>{int(time.time())}</CreateTime>
            <MsgType><![CDATA[text]]></MsgType>
            <Content><![CDATA[服务器内部错误，请稍后重试。]]></Content>
        </xml>"""
        return make_response(error_xml_str, 500, {'Content-Type': 'application/xml'})

def process_text_message(content):
    """通过 Gemini 处理文本消息并返回 AI 生成的文本"""
    logger.info("调用 Gemini 处理文本...")
    try:
        return generate_with_retry(content)
    except Exception as e:
        logger.error(f"处理文本消息时 AI 调用失败: {e}")
        return "AI处理文本失败，请稍后再试。"

def process_image_message(pic_url):
    """下载图片并通过 Gemini 处理图片消息并返回 AI 生成的文本"""
    try:
        logger.info("开始下载图片...")
        start_time = time.time()
        # 增加 headers 模拟浏览器请求，避免部分网站拒绝
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/100.0.4896.127 Safari/537.36'}
        image_resp = requests.get(pic_url, timeout=15, headers=headers)
        image_resp.raise_for_status() # 检查HTTP响应状态码
        image_data = image_resp.content
        logger.info(f"图片下载完成，耗时: {time.time()-start_time:.2f}秒，大小: {len(image_data)/1024:.2f}KB")

        # 验证并加载图片
        # 使用 Image.open(io.BytesIO(image_data)) 而不是 img.verify() 后再重新打开，更简洁
        img = Image.open(io.BytesIO(image_data))
        # 确保图片是 RGB 模式，以防某些 Gemini 模型不兼容其他模式
        if img.mode != 'RGB':
            img = img.convert('RGB')

        prompt = "请用中文详细描述这张图片的内容，并尽可能分析它的含义。"
        logger.info("调用 Gemini 处理图片...")
        return generate_with_retry(prompt, img)
    except requests.exceptions.RequestException as e:
        logger.error(f"下载图片网络请求失败: {e}")
        return "下载图片失败，请检查图片链接或稍后重试。"
    except Exception as e:
        logger.error(f"处理图片消息时发生异常: {e}")
        return "图片处理失败，请换一张图片试试。"

def generate_with_retry(prompt, image=None, max_retries=3):
    """
    带重试机制的 AI 内容生成。
    使用指数退避策略处理暂时的 API 错误。
    """
    retry_count = 0
    
    generation_config = genai.types.GenerationConfig(
        temperature=0.7,      # 随机性：0.0 (确定性) 到 1.0 (创造性)
        top_p=0.9,            # 核心采样：考虑累积概率为 top_p 的 tokens
        top_k=40,             # Top-K 采样：考虑概率最高的 top_k 个 tokens
        max_output_tokens=2048 # 最大输出 token 数量
    )
    
    while retry_count < max_retries:
        try:
            start_time = time.time()
            
            if image:
                response = gemini_model.generate_content( # 使用全局 model 实例
                    [prompt, image],
                    generation_config=generation_config,
                    request_options={"timeout": 30} # 增加 AI 请求超时时间
                )
            else:
                response = gemini_model.generate_content( # 使用全局 model 实例
                    prompt,
                    generation_config=generation_config,
                    request_options={"timeout": 30}
                )
            
            # 检查 AI 返回的内容是否有效
            if response and response.text:
                logger.info(f"AI 生成成功，耗时: {time.time()-start_time:.2f}秒")
                return response.text.strip()
            
            logger.warning(f"AI 返回了空内容或无效响应 (尝试 {retry_count+1}/{max_retries})。")
            # 如果没有有效内容，不认为是成功，可以尝试重试
            
        except Exception as e:
            retry_count += 1
            wait_time = min(2 ** retry_count, 10) # 指数退避，最大等待10秒
            logger.warning(f"AI 生成失败 (尝试 {retry_count}/{max_retries}): {e}")
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
        # 1. 首先清理内容（去除 Markdown 格式、多余空行），此处不进行字节截断
        cleaned_content = clean_content(content, max_bytes=None)
        
        # 2. 检查清理后内容的字节长度
        content_bytes = len(cleaned_content.encode('utf-8'))
        reply_xml_str = None # 用于存储最终生成的 XML 字符串

        if content_bytes > 2000:
            logger.info(f"内容过长({content_bytes}字节)，尝试转换为图片并回复。")
            img_data = text_to_image(cleaned_content) # 使用完整的清理内容生成图片

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
                    # 图片上传失败的回退：发送截断的文本 + 警告
                    logger.warning("图片上传至微信失败，回退到文本回复并截断。")
                    truncated_content = clean_content(cleaned_content, max_bytes=2000) # 为回退文本截断
                    reply_xml_str = f"""<xml>
                        <ToUserName><![CDATA[{from_user}]]></ToUserName>
                        <FromUserName><![CDATA[{to_user}]]></FromUserName>
                        <CreateTime>{int(time.time())}</CreateTime>
                        <MsgType><![CDATA[text]]></MsgType>
                        <Content><![CDATA[AI回复超长，转图片失败。以下为截断内容：\n{escape(truncated_content)}]]></Content>
                    </xml>"""
            else:
                # 文本转图片本身失败的回退：发送截断的文本 + 警告
                logger.warning("文本转换为图片失败，回退到文本回复并截断。")
                truncated_content = clean_content(cleaned_content, max_bytes=2000) # 为回退文本截断
                reply_xml_str = f"""<xml>
                    <ToUserName><![CDATA[{from_user}]]></ToUserName>
                    <FromUserName><![CDATA[{to_user}]]></FromUserName>
                    <CreateTime>{int(time.time())}</CreateTime>
                    <MsgType><![CDATA[text]]></MsgType>
                    <Content><![CDATA[AI回复超长，转图片失败。以下为截断内容：\n{escape(truncated_content)}]]></Content>
                </xml>"""
        else:
            # 如果内容在文本限制内，则直接发送清理后的文本，不截断
            logger.info(f"内容在文本限制内({content_bytes}字节)，使用文本回复。")
            reply_xml_str = f"""<xml>
                <ToUserName><![CDATA[{from_user}]]></ToUserName>
                <FromUserName><![CDATA[{to_user}]]></FromUserName>
                <CreateTime>{int(time.time())}</CreateTime>
                <MsgType><![CDATA[text]]></MsgType>
                <Content><![CDATA[{escape(cleaned_content)}]]></Content>
            </xml>"""
        
        # 始终返回 Flask 的 make_response 对象，确保 Content-Type 正确
        return make_response(reply_xml_str, 200, {'Content-Type': 'application/xml'})
    
    except Exception as e:
        logger.error(f"构建回复时发生异常: {e}\n{traceback.format_exc()}")
        # 即使构建回复失败，也尝试返回一个通用错误文本
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
    
    # 移除常用的 Markdown 标记
    content = re.sub(r'(\*\*|__|\*|_|`|~~|\n{2,})', '\n', content) # 将多个换行符也替换为单个
    content = re.sub(r'#+\s*', '', content) # 移除 Markdown 标题
    content = re.sub(r'\[(.*?)\]\((.*?)\)', r'\1', content) # 移除 Markdown 链接

    # 合并多余的空行并去除首尾空白
    content = re.sub(r'\n{2,}', '\n\n', content).strip()

    # 字节数检查和截断 (仅当 max_bytes 提供时才执行)
    if max_bytes is not None:
        encoded = content.encode('utf-8')
        if len(encoded) > max_bytes:
            logger.warning(f"内容因字节限制被截断: 原始 {len(encoded)} 字节，截断至 {max_bytes} 字节。")
            # 确保在字节截断后，仍能解码为有效 UTF-8 字符串
            return encoded[:max_bytes].decode('utf-8', errors='ignore')
    return content

def text_to_image(text, max_width=600, font_size=24):
    """
    将长文本转换为图片。
    自动处理文本换行和添加水印。
    """
    try:
        padding = 30
        line_spacing = 10 # 行间距
        font = ImageFont.truetype(FONT_PATH, font_size)
        
        # 预估每行可容纳的字符数，用于 textwrap.wrap
        # 这是一个粗略的估计，中文字符通常宽度一致，英文字符和标点可能不同
        avg_char_width = font.getlength('中') 
        chars_per_line = int((max_width - 2 * padding) / avg_char_width)

        # 使用 textwrap 自动换行
        wrapped_lines = []
        for paragraph in text.split('\n'):
            if not paragraph.strip(): # 处理空行
                wrapped_lines.append('')
            else:
                # 针对每个段落进行换行
                wrapped_lines.extend(textwrap.wrap(paragraph, width=chars_per_line, break_long_words=False, replace_whitespace=False))
        
        if not wrapped_lines: # 如果内容为空，返回空图片
            wrapped_lines = [""]

        # 计算图片高度
        line_height = font_size + line_spacing
        img_height = 2 * padding + len(wrapped_lines) * line_height
        
        # 创建图片，白色背景
        img = Image.new("RGB", (max_width, img_height), (255, 255, 255))
        draw = ImageDraw.Draw(img)
        
        # 绘制文本
        y = padding
        for line in wrapped_lines:
            draw.text((padding, y), line, font=font, fill=(0, 0, 0))
            y += line_height
        
        # 添加水印（右下角，灰色）
        watermark = "AI生成内容"
        watermark_font = ImageFont.truetype(FONT_PATH, int(font_size * 0.8)) # 水印字体可以小一点
        watermark_width = watermark_font.getlength(watermark)
        draw.text(
            (max_width - watermark_width - 15, img_height - int(font_size * 0.8) - 10),
            watermark,
            font=watermark_font,
            fill=(200, 200, 200) # 更浅的灰色
        )
        
        # 将图片保存到 BytesIO 对象，以 PNG 格式返回字节流
        output = io.BytesIO()
        img.save(output, format='PNG', optimize=True, quality=90)
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
        # files 参数的格式：{'字段名': ('文件名', 文件内容字节流, '文件MIME类型')}
        files = {'media': ('ai_reply.png', image_bytes, 'image/png')}
        
        logger.info("正在上传图片到微信服务器...")
        resp = requests.post(url, files=files, timeout=20) # 增加上传超时时间
        resp.raise_for_status() # 检查 HTTP 响应状态码
        data = resp.json()
        
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
    # 对于 POST 请求，记录请求体的前 200 个字符
    if request.method == 'POST' and request.data:
        try:
            # 尝试解码并限制长度，避免日志过大
            body_preview = request.data.decode('utf-8', errors='ignore')[:200]
            logger.debug(f"请求体: {body_preview}...")
        except Exception:
            logger.debug(f"请求体（无法解码）：{request.data[:200]}...")
