from flask import Flask, request, make_response
import hashlib
import time
import requests
from xml.etree import ElementTree as ET
import threading

app = Flask(__name__)

# 微信公众号配置
WECHAT_TOKEN = "YOU_WECHAT_TOKEN"  # 与公众号后台配置的 Token 一致
DEEPSEEK_API_KEY = "YOU_DEEPSEEK_API_KEY"  # DeepSeek 的 API 密钥
DEEPSEEK_API_URL = "https://api.deepseek.com/v1/chat/completions"  # DeepSeek 的 API 地址

# 验证微信服务器
def check_signature(signature, timestamp, nonce):
    """
    验证微信服务器的签名。
    """
    tmp_list = sorted([WECHAT_TOKEN, timestamp, nonce])
    tmp_str = ''.join(tmp_list).encode('utf-8')
    tmp_str = hashlib.sha1(tmp_str).hexdigest()
    print(f"Signature Validation: expected {tmp_str}, received {signature}")
    return tmp_str == signature

# 截取消息内容
def truncate_message(content, max_length=2000):
    """
    截取消息内容，确保不超过最大字节长度。
    """
    content_bytes = content.encode('utf-8')
    if len(content_bytes) > max_length:
        # 截取前 max_length 个字节，并确保不会截断 UTF-8 字符
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
        # 保证分割后部分的完整性
        part = content_bytes[:max_length].decode('utf-8', 'ignore')
        parts.append(part)
        content_bytes = content_bytes[max_length:]
    
    if content_bytes:
        parts.append(content_bytes.decode('utf-8', 'ignore'))
    
    # 确保返回的每个部分都不破坏 XML 格式
    for i in range(len(parts)):
        parts[i] = parts[i].replace("\r\n", " ").replace("\n", " ").strip()
    
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
        response = requests.post(DEEPSEEK_API_URL, json=data, headers=headers)
        print("DeepSeek API Response Status Code:", response.status_code)
        print("DeepSeek API Raw Response:", response.text)

        # 检查 API 响应
        if response.status_code == 200:
            reply_content = response.json().get('choices')[0].get('message', {}).get('content', '')
            print("API 返回的原始内容：", repr(reply_content))
            # 彻底清理转义字符
            reply_content = reply_content.replace("\r\n", " ").replace("\n", " ")  # 将换行符替换为空格
            print("清理后的内容：", repr(reply_content))
        else:
            reply_content = "抱歉，我暂时无法处理你的请求。"
    except requests.exceptions.RequestException as e:
        print("API Request Failed:", e)
        reply_content = "抱歉，服务器请求失败。"
    except ValueError as e:
        print("JSON Decode Error:", e)
        reply_content = "抱歉，服务器返回了无效的响应。"
    except Exception as e:
        print("Error handling message:", e)
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
        print(f"Prepared reply XML part: {repr(reply_xml)}")
        reply_xml_list.append(reply_xml)

    return reply_xml_list

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
        print("Received XML Data:", xml_data)
        reply_xml_list = handle_message(xml_data)

        # 返回第一条回复
        response = make_response(reply_xml_list[0])
        response.content_type = 'application/xml'

        # 不使用异步发送，直接返回所有回复
        for reply_xml in reply_xml_list[1:]:
            # 模拟发送（实际发送需要调用微信 API）
            print("Sending async reply:", reply_xml)
            time.sleep(1)  # 模拟延迟

        return response

# 启动 Flask 应用（HTTP）
if __name__ == '__main__':
    # 启动 HTTP 服务器
    app.run(host='0.0.0.0', port=80)
