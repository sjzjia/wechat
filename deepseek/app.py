from flask import Flask, request, make_response
import hashlib
import time
import requests
from xml.etree import ElementTree as ET
import threading
import logging

app = Flask(__name__)

# 在 app 初始化后添加日志配置
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# 在文件开头添加配置类
class Config:
    WECHAT_TOKEN = "YOU_WECHAT_TOKEN"
    DEEPSEEK_API_KEY = "YOU_DEEPSEEK_API_KEY"
    DEEPSEEK_API_URL = "https://api.deepseek.com/v1/chat/completions"
    MAX_MESSAGE_LENGTH = 2000
    MODEL_NAME = "deepseek-chat"
    MAX_TOKENS = 5000
    APPID = "YOU_WECHAT_APPID"
    APPSECRET = "YOU_WECHAT_APPSECRET"

# 验证微信服务器
def check_signature(signature, timestamp, nonce):
    """
    验证微信服务器的签名。
    """
    tmp_list = sorted([Config.WECHAT_TOKEN, timestamp, nonce])
    tmp_str = ''.join(tmp_list).encode('utf-8')
    tmp_str = hashlib.sha1(tmp_str).hexdigest()
    logger.info(f"Signature Validation: expected {tmp_str}, received {signature}")
    return tmp_str == signature

# 截取消息内容
def truncate_message(content, max_length=None):
    """
    截取消息内容，确保不超过最大字节长度。
    """
    max_length = max_length or Config.MAX_MESSAGE_LENGTH
    content_bytes = content.encode('utf-8')
    if len(content_bytes) > max_length:
        content = content_bytes[:max_length].decode('utf-8', 'ignore')
    return content

# 将内容分成多个部分
def split_message(content, max_length=None):
    """
    将内容分成多个部分，每部分不超过 max_length 字节。
    优化分割逻辑，确保每部分内容的完整性。
    """
    max_length = max_length or Config.MAX_MESSAGE_LENGTH
    
    # 计算预留给标记的长度
    marker_length = len("【XX/XX】\n".encode('utf-8'))
    effective_length = max_length - marker_length
    
    # 按段落分割内容
    parts = []
    current_part = ''
    
    # 按句号分割内容
    sentences = content.split('。')
    
    for sentence in sentences:
        if sentence:
            sentence += '。'  # 添加句号
            if len((current_part + sentence).encode('utf-8')) > effective_length:
                # 如果当前部分不为空，保存它
                if current_part:
                    parts.append(current_part.strip())
                current_part = sentence  # 开始新的部分
            else:
                current_part += sentence  # 添加到当前部分
    
    # 添加最后一部分
    if current_part:
        parts.append(current_part.strip())
    
    # 添加序号标记并清理
    total_parts = len(parts)
    for i in range(total_parts):
        marker = f"【{i+1}/{total_parts}】\n" if total_parts > 1 else ""
        parts[i] = marker + parts[i].strip()
    
    return parts

# 处理用户消息
def handle_message(xml_data):
    """
    处理用户发送的消息，并调用 DeepSeek API 获取回复。
    优化消息处理逻辑。
    """
    try:
        xml = ET.fromstring(xml_data)
        msg_type = xml.find('MsgType').text
        from_user = xml.find('FromUserName').text
        to_user = xml.find('ToUserName').text
        content = xml.find('Content').text if msg_type == 'text' else ''

        try:
            api_response = call_deepseek_api(content)
            reply_content = api_response.get('choices')[0].get('message', {}).get('content', '')
            logger.info("API 返回的原始内容：%s", repr(reply_content))
            
            # 清理内容
            reply_content = reply_content.replace("\r\n", " ").replace("\n", " ")
            logger.info("清理后的内容：%s", repr(reply_content))
            
            # 分割消息
            parts = split_message(reply_content)
            if not parts:
                return create_reply_xml(from_user, to_user, "抱歉，生成的回复内容为空。")
                
            # 返回第一部分的 XML
            return create_reply_xml(from_user, to_user, parts[0])
            
        except Exception as e:
            logger.error("调用 API 失败: %s", str(e))
            return create_reply_xml(from_user, to_user, "抱歉，我暂时无法处理你的请求。")

    except Exception as e:
        logger.error("处理消息时发生错误: %s", str(e), exc_info=True)
        return create_reply_xml(from_user, to_user, "抱歉，处理消息时发生了错误。")

# 微信服务器验证和消息处理
@app.route('/', methods=['GET', 'POST'])
def wechat():
    """
    处理微信服务器的验证和消息推送。
    """
    if request.method == 'GET':
        # 验证服务器地址有效性
        signature = request.args.get('signature', '')
        timestamp = request.args.get('timestamp', '')
        nonce = request.args.get('nonce', '')
        echostr = request.args.get('echostr', '')
        if check_signature(signature, timestamp, nonce):
            return echostr
        else:
            return '验证失败'
    elif request.method == 'POST':
        # 处理用户消息
        xml_data = request.data
        logger.info("Received XML Data: %s", xml_data)
        
        # 获取回复消息
        reply_xml = handle_message(xml_data)
        
        # 设置响应
        response = make_response(reply_xml)
        response.content_type = 'application/xml'
        return response

def call_deepseek_api(content):
    """
    封装 DeepSeek API 调用
    """
    headers = {
        "Authorization": f"Bearer {Config.DEEPSEEK_API_KEY}",
        "Content-Type": "application/json"
    }
    data = {
        "model": Config.MODEL_NAME,
        "messages": [
            {"role": "user", "content": content}
        ],
        "max_tokens": Config.MAX_TOKENS
    }
    
    response = requests.post(
        Config.DEEPSEEK_API_URL, 
        json=data, 
        headers=headers,
        timeout=30  # 添加超时设置
    )
    response.raise_for_status()  # 抛出非200状态码的异常
    return response.json()

def create_reply_xml(from_user, to_user, content):
    """
    创建回复XML的工具函数
    """
    return f"""
    <xml>
        <ToUserName><![CDATA[{from_user}]]></ToUserName>
        <FromUserName><![CDATA[{to_user}]]></FromUserName>
        <CreateTime>{int(time.time())}</CreateTime>
        <MsgType><![CDATA[text]]></MsgType>
        <Content><![CDATA[{content}]]></Content>
    </xml>
    """

# 启动 Flask 应用（HTTP）
if __name__ == '__main__':
    # 启动 HTTP 服务器
    app.run(host='0.0.0.0', port=80)
