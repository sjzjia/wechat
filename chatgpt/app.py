import hashlib
import time
import requests
from flask import Flask, request, make_response
from xml.etree import ElementTree as ET
import threading
import logging
import openai

app = Flask(__name__)

# 开启 Flask 的日志显示
app.logger.setLevel(logging.DEBUG)  # 设置日志级别为 DEBUG
handler = logging.StreamHandler()  # 控制台输出日志
handler.setLevel(logging.DEBUG)
formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
handler.setFormatter(formatter)
app.logger.addHandler(handler)

# 微信公众号配置
WECHAT_TOKEN = "YOU_WECHAT_TOKEN"  # 与公众号后台配置的 Token 一致
OPENAI_API_KEY = "OPENAI_API_KEY"  # 替换为您的 OpenAI API 密钥
openai.api_key = "OPENAI_API_KEY"  # 设置 OpenAI API 密钥

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

# 截取消息内容
def truncate_message(content, max_length=2000):
    """
    截取消息内容，确保不超过最大字节长度。
    """
    content_bytes = content.encode('utf-8')
    if len(content_bytes) > max_length:
        content = content_bytes[:max_length].decode('utf-8', 'ignore')
    return content

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
    处理用户发送的消息，并调用 OpenAI API 获取回复。
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

        # 调用 OpenAI API
        response = openai.chat.completions.create(
            model="gpt-3.5-turbo",  # 改为 gpt-3.5-turbo 模型，或者根据你的访问权限修改为 gpt-4
            messages=[
                {"role": "system", "content": "You are a helpful assistant."},
                {"role": "user", "content": content}
            ],
            max_tokens=500,  # 限制回复的最大 token 数
            temperature=0.7,  # 控制输出的随机性
        )
        
        # 获取模型的回复
        reply_content = response['choices'][0]['message']['content'].strip()  # 提取模型回复文本
        app.logger.debug(f"OpenAI API response: {reply_content}")

    except openai.OpenAIError as e:  # 捕获 OpenAI API 错误
        app.logger.error(f"OpenAI API error: {e}")
        reply_content = "抱歉，服务器请求失败。"
    except Exception as e:
        app.logger.error(f"Error while handling message: {e}")
        reply_content = "抱歉，处理消息时发生了错误。"

    # 将回复内容分成多个部分
    reply_parts = split_message(reply_content)

    # 构造多条回复消息
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

    return reply_xml_list

# 发送微信回复消息
def send_reply(reply_xml):
    """
    发送微信回复消息。
    """
    app.logger.debug(f"Sending reply: {reply_xml}")
    return make_response(reply_xml)

# 异步发送剩余回复
def send_async_reply(reply_xml_list):
    """
    异步发送剩余回复消息。
    """
    for reply_xml in reply_xml_list[1:]:
        time.sleep(1)  # 模拟延迟
        # 在异步线程中显式创建应用上下文
        with app.app_context():
            send_reply(reply_xml)  # 需要确保这个方法能处理发送操作

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
        app.logger.debug(f"GET request: signature={signature}, timestamp={timestamp}, nonce={nonce}, echostr={echostr}")
        if check_signature(signature, timestamp, nonce):
            return echostr
        else:
            return '验证失败'
    elif request.method == 'POST':
        # 处理用户消息
        xml_data = request.data
        app.logger.debug(f"POST request data: {xml_data}")
        reply_xml_list = handle_message(xml_data)

        # 返回第一条回复
        response = send_reply(reply_xml_list[0])
        response.content_type = 'application/xml'

        # 异步发送剩余回复
        if len(reply_xml_list) > 1:
            threading.Thread(target=send_async_reply, args=(reply_xml_list,)).start()

        app.logger.debug("Reply sent successfully.")
        return response

# 启动 Flask 应用（HTTP）
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=80)
