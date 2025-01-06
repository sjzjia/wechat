import hashlib
import time
import requests
from flask import Flask, request, make_response
from xml.etree import ElementTree as ET
import logging

app = Flask(__name__)

# 开启 Flask 的日志显示
app.logger.setLevel(logging.DEBUG)  # 设置日志级别为 DEBUG
handler = logging.StreamHandler()  # 控制台输出日志
handler.setLevel(logging.DEBUG)
formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
handler.setFormatter(formatter)
app.logger.addHandler(handler)

# 微信公众号配置
WECHAT_TOKEN = "jiazhangshaowei123"  # 与公众号后台配置的 Token 一致
DEEPSEEK_API_KEY = "sk-698fdd0c711344fa80e2ec0b02d229f0"  # DeepSeek 的 API 密钥
DEEPSEEK_API_URL = "https://api.deepseek.com/v1/chat/completions"  # DeepSeek 的 API 地址

# 验证微信服务器
def check_signature(signature, timestamp, nonce):
    """
    验证微信服务器的签名。
    """
    tmp_list = sorted([WECHAT_TOKEN, timestamp, nonce])
    tmp_str = ''.join(tmp_list).encode('utf-8')
    tmp_str = hashlib.sha1(tmp_str).hexdigest()
    app.logger.debug(f"check_signature: {signature} == {tmp_str}")
    return tmp_str == signature

# 将内容分成多个部分
def split_message(content, max_length=2000):
    """
    将内容分成多个部分，每部分不超过 max_length 字节。
    """
    content_bytes = content.encode('utf-8')
    parts = []
    
    while len(content_bytes) > max_length:
        part = content_bytes[:max_length].decode('utf-8', 'ignore')
        parts.append(part)
        content_bytes = content_bytes[max_length:]
    
    if content_bytes:
        parts.append(content_bytes.decode('utf-8', 'ignore'))
    
    return parts

# 处理用户消息
def handle_message(xml_data):
    """
    处理用户发送的消息，并调用 DeepSeek API 获取回复。
    """
    try:
        # 解析 XML 数据
        xml = ET.fromstring(xml_data)
        msg_type = xml.find('MsgType').text
        from_user = xml.find('FromUserName').text
        to_user = xml.find('ToUserName').text
        content = xml.find('Content').text if msg_type == 'text' else ''

        # 打印接收到的消息内容
        app.logger.debug(f"Received message from {from_user}: {content}")

        # 调用 DeepSeek API
        headers = {
            "Authorization": f"Bearer {DEEPSEEK_API_KEY}",
            "Content-Type": "application/json"
        }
        data = {
            "model": "deepseek-chat",
            "messages": [
                {"role": "user", "content": content}
            ],
            "max_tokens": 5000
        }
        app.logger.debug(f"Calling DeepSeek API with data: {data}")
        response = requests.post(DEEPSEEK_API_URL, json=data, headers=headers)
        
        if response.status_code == 200:
            reply_content = response.json().get('choices')[0].get('message', {}).get('content', '')
            app.logger.debug(f"DeepSeek API response: {reply_content}")
            reply_content = reply_content.replace("\r\n", " ").replace("\n", " ")  # 清理换行符
        else:
            reply_content = "抱歉，我暂时无法处理你的请求。"
    except requests.exceptions.RequestException as e:
        app.logger.error(f"Request error: {e}")
        reply_content = "抱歉，服务器请求失败。"
    except Exception as e:
        app.logger.error(f"Error while handling message: {e}")
        reply_content = "抱歉，处理消息时发生了错误。"

    # 将回复内容分成多个部分
    reply_parts = split_message(reply_content)

    return reply_parts, from_user, to_user

# 发送回复
def send_reply(reply_xml_list):
    """
    同步发送所有回复消息
    """
    for reply_xml in reply_xml_list:
        app.logger.debug(f"Sending reply: {reply_xml}")
        response = make_response(reply_xml)
        response.content_type = 'application/xml'  # 确保是 XML 格式
        app.logger.debug(f"Response content_type: {response.content_type}")
        app.logger.debug(f"Sent message: {reply_xml}")
        return response  # 返回第一个消息时直接响应

# 微信服务器验证和消息处理
@app.route('/wechat', methods=['GET', 'POST'])
def wechat():
    """
    处理微信服务器的验证和消息推送。
    """
    start_time = time.time()  # 记录请求开始时间
    if request.method == 'GET':
        # 验证服务器地址有效性
        signature = request.args.get('signature', '')
        timestamp = request.args.get('timestamp', '')
        nonce = request.args.get('nonce', '')
        echostr = request.args.get('echostr', '')
        app.logger.debug(f"GET request: signature={signature}, timestamp={timestamp}, nonce={nonce}, echostr={echostr}")
        if check_signature(signature, timestamp, nonce):
            return echostr
        else:
            return '验证失败'
    elif request.method == 'POST':
        # 处理用户消息
        xml_data = request.data
        app.logger.debug(f"POST request data: {xml_data}")
        reply_parts, from_user, to_user = handle_message(xml_data)

        # 构造回复 XML
        reply_xml_list = []
        for part in reply_parts:
            reply_xml = f"""
            <xml>
                <ToUserName><![CDATA[{from_user}]]></ToUserName>
                <FromUserName><![CDATA[{to_user}]]></FromUserName>
                <CreateTime>{int(time.time())}</CreateTime>
                <MsgType><![CDATA[text]]></MsgType>
                <Content><![CDATA[{part}]]></Content>
            </xml>
            """
            reply_xml_list.append(reply_xml)

        # 同步发送所有回复
        return send_reply(reply_xml_list)  # 发送所有的回复

# 启动 Flask 应用（HTTP）
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=80)
