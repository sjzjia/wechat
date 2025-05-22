# -*- coding: utf-8 -*-
import os
import hashlib
import time
import requests
from xml.etree import ElementTree as ET
from flask import Flask, request, make_response
import logging
from dotenv import load_dotenv
import re

# 加载环境变量
load_dotenv()

app = Flask(__name__)

# 日志配置
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('wechat_bot.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class Config:
    # 从环境变量读取配置
    WECHAT_TOKEN = os.getenv("WECHAT_TOKEN", "")
    DEEPSEEK_API_KEY = os.getenv("DEEPSEEK_API_KEY", "")
    DEEPSEEK_API_URL = "https://api.deepseek.com/v1/chat/completions"
    MAX_MESSAGE_LENGTH = 2000  # 微信文本消息限制
    MODEL_NAME = "deepseek-chat"
    MAX_TOKENS = 2000
    TIMEOUT = 30  # API超时时间(秒)

def check_signature(signature, timestamp, nonce):
    """验证微信服务器签名"""
    if not all([signature, timestamp, nonce]):
        return False
        
    tmp_list = sorted([Config.WECHAT_TOKEN, timestamp, nonce])
    tmp_str = hashlib.sha1("".join(tmp_list).encode('utf-8')).hexdigest()
    logger.debug(f"Signature check: {tmp_str == signature}")
    return tmp_str == signature

def safe_truncate(content, max_length=Config.MAX_MESSAGE_LENGTH):
    """安全截断文本，保证UTF-8编码不超长"""
    content = content.strip()
    encoded = content.encode('utf-8')
    if len(encoded) <= max_length:
        return content
    
    # 回溯找到最后一个完整字符
    truncated = encoded[:max_length]
    try:
        return truncated.decode('utf-8')
    except UnicodeDecodeError:
        return truncated[:-1].decode('utf-8', 'ignore')

def smart_split(content, max_length=Config.MAX_MESSAGE_LENGTH):
    """
    智能分割长文本，优先按段落分割
    返回格式：["【1/3】第一部分", "【2/3】第二部分"...]
    """
    if len(content.encode('utf-8')) <= max_length:
        return [content]
    
    # 计算有效长度（减去分页标记长度）
    marker_len = len("【XX/XX】".encode('utf-8'))
    effective_len = max_length - marker_len
    
    # 分割策略：优先按段落，其次按句子
    parts = []
    current = ""
    
    # 先按双换行分段落
    paragraphs = [p.strip() for p in content.split('\n\n') if p.strip()]
    
    for para in paragraphs:
        para_bytes = para.encode('utf-8')
        
        # 段落可直接放入
        if len(current.encode('utf-8')) + len(para_bytes) < effective_len:
            current += f"\n\n{para}" if current else para
            continue
            
        # 当前段落过长需要分割
        if current:
            parts.append(current)
            current = ""
            
        # 按句子分割长段落
        sentences = re.split(r'(?<=[。！？.?!])', para)
        for sent in sentences:
            if not sent.strip():
                continue
                
            sent_bytes = sent.encode('utf-8')
            if len(current.encode('utf-8')) + len(sent_bytes) < effective_len:
                current += sent
            else:
                if current:
                    parts.append(current)
                current = sent[:effective_len]  # 极端情况：单句超长
    
    if current:
        parts.append(current)
    
    # 添加分页标记
    total = len(parts)
    if total > 1:
        return [f"【{i+1}/{total}】{p}" for i, p in enumerate(parts)]
    return parts

def call_deepseek_api(prompt, retries=2):
    """调用DeepSeek API（带重试机制）"""
    headers = {
        "Authorization": f"Bearer {Config.DEEPSEEK_API_KEY}",
        "Content-Type": "application/json"
    }
    payload = {
        "model": Config.MODEL_NAME,
        "messages": [{"role": "user", "content": prompt}],
        "max_tokens": Config.MAX_TOKENS,
        "temperature": 0.7
    }
    
    for attempt in range(retries):
        try:
            resp = requests.post(
                Config.DEEPSEEK_API_URL,
                json=payload,
                headers=headers,
                timeout=Config.TIMEOUT
            )
            resp.raise_for_status()
            data = resp.json()
            
            if not data.get("choices"):
                raise ValueError("Invalid API response format")
                
            return data
            
        except (requests.RequestException, ValueError) as e:
            if attempt == retries - 1:
                logger.error(f"API调用失败: {str(e)}")
                raise
            time.sleep(1)

def create_reply(from_user, to_user, content):
    """生成微信回复XML"""
    return f"""<xml>
<ToUserName><![CDATA[{from_user}]]></ToUserName>
<FromUserName><![CDATA[{to_user}]]></FromUserName>
<CreateTime>{int(time.time())}</CreateTime>
<MsgType><![CDATA[text]]></MsgType>
<Content><![CDATA[{content}]]></Content>
</xml>"""

@app.route('/', methods=['GET', 'POST'])
def wechat_handler():
    """微信消息处理入口"""
    if request.method == 'GET':
        # 验证服务器
        sig = request.args.get('signature', '')
        timestamp = request.args.get('timestamp', '')
        nonce = request.args.get('nonce', '')
        echostr = request.args.get('echostr', '')
        
        if check_signature(sig, timestamp, nonce):
            return echostr
        return "Invalid signature", 403
    
    # 处理POST消息
    try:
        xml = ET.fromstring(request.data)
        msg_type = xml.find('MsgType').text
        from_user = xml.find('FromUserName').text
        to_user = xml.find('ToUserName').text
        
        # 只处理文本消息
        if msg_type != 'text':
            return create_reply(from_user, to_user, "暂仅支持文本消息")
            
        content = xml.find('Content').text
        if not content.strip():
            return create_reply(from_user, to_user, "消息内容为空")
        
        # 调用AI接口
        try:
            response = call_deepseek_api(content)
            ai_reply = response['choices'][0]['message']['content']
            
            # 清理回复内容
            ai_reply = re.sub(r'\s+', ' ', ai_reply).strip()
            reply_part = safe_truncate(ai_reply)
            
            return create_reply(from_user, to_user, reply_part)
            
        except Exception as api_error:
            logger.error(f"AI处理失败: {str(api_error)}")
            return create_reply(from_user, to_user, "AI服务暂时不可用，请稍后再试")
            
    except Exception as e:
        logger.error(f"消息处理异常: {str(e)}")
        return create_reply(from_user, to_user, "服务器处理消息时出错")

if __name__ == '__main__':
    # 检查关键配置
    if not all([Config.WECHAT_TOKEN, Config.DEEPSEEK_API_KEY]):
        raise ValueError("缺少必要的环境变量配置")
    
    # 启动服务（生产环境应使用WSGI服务器）
    app.run(
        host='0.0.0.0',
        port=80,
        debug=os.getenv('FLASK_DEBUG', 'false').lower() == 'true'
    )
