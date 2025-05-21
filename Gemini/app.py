import hashlib
import time
import requests
from flask import Flask, request, make_response
from xml.etree import ElementTree as ET
import logging
import google.generativeai as genai
import os
from PIL import Image
import io
import traceback

app = Flask(__name__)

# 配置日志记录
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# 微信公众号配置
WECHAT_TOKEN = os.environ.get("WECHAT_TOKEN")
GEMINI_API_KEY = os.environ.get("GEMINI_API_KEY")
genai.configure(api_key=GEMINI_API_KEY)

# 微信签名验证
def check_signature(signature, timestamp, nonce):
    tmp_list = sorted([WECHAT_TOKEN, timestamp, nonce])
    tmp_str = ''.join(tmp_list).encode('utf-8')
    tmp_str = hashlib.sha1(tmp_str).hexdigest()
    logger.debug(f"check_signature: {signature} == {tmp_str}")
    return tmp_str == signature

# 截取消息内容
def truncate_message(content, max_length=2000):
    content_bytes = content.encode('utf-8')
    if len(content_bytes) > max_length:
        content = content_bytes[:max_length].decode('utf-8', 'ignore')
    return content

# 将内容分成多个部分 (这个函数现在不直接使用，但保留以备将来可能需要)
def split_message(content, max_length=2000):
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
    try:
        xml = ET.fromstring(xml_data)
        msg_type = xml.find('MsgType').text
        from_user = xml.find('FromUserName').text
        to_user = xml.find('ToUserName').text
        content = xml.find('Content').text if msg_type == 'text' else ''
        pic_url = xml.find('PicUrl').text if msg_type == 'image' else ''

        logger.debug(f"Received message from {from_user}: {content}, pic_url: {pic_url}")

        model = genai.GenerativeModel('gemini-2.0-flash')
        if msg_type == 'text':
            response = model.generate_content(content)
        elif msg_type == 'image':
            try:
                image_data = requests.get(pic_url, timeout=10).content #Added timeout
                image = Image.open(io.BytesIO(image_data))
                chinese_prompt = "请用中文回复。"
                response = model.generate_content([chinese_prompt, image])
            except requests.exceptions.RequestException as e:
                logger.error(f"Error downloading image: {e}, pic_url: {pic_url}, traceback: {traceback.format_exc()}")
                error_reply_xml = f"""
                    <xml>
                        <ToUserName><![CDATA[{from_user}]]></ToUserName>
                        <FromUserName><![CDATA[{to_user}]]></FromUserName>
                        <CreateTime>{int(time.time())}</CreateTime>
                        <MsgType><![CDATA[text]]></MsgType>
                        <Content><![CDATA[图片下载失败]]></Content>
                    </xml>
                    """
                return error_reply_xml
            except Exception as e:
                logger.error(f"Error processing image: {e}, pic_url: {pic_url}, traceback: {traceback.format_exc()}")
                error_reply_xml = f"""
                    <xml>
                        <ToUserName><![CDATA[{from_user}]]></ToUserName>
                        <FromUserName><![CDATA[{to_user}]]></FromUserName>
                        <CreateTime>{int(time.time())}</CreateTime>
                        <MsgType><![CDATA[text]]></MsgType>
                        <Content><![CDATA[图片处理失败]]></Content>
                    </xml>
                    """
                return error_reply_xml

        if response and response.text:
            reply_content = response.text.strip()
            reply_content = truncate_message(reply_content, 2048) # 确保内容长度不超过限制
            logger.debug(f"Gemini API response: {reply_content}")
            reply_xml = f"""
                <xml>
                    <ToUserName><![CDATA[{from_user}]]></ToUserName>
                    <FromUserName><![CDATA[{to_user}]]></FromUserName>
                    <CreateTime>{int(time.time())}</CreateTime>
                    <MsgType><![CDATA[text]]></MsgType>
                    <Content><![CDATA[{reply_content}]]></Content>
                </xml>
                """
            return reply_xml
        else:
            logger.warning("Gemini API 返回空值或无效数据")
            error_reply_xml = f"""
                <xml>
                    <ToUserName><![CDATA[{from_user}]]></ToUserName>
                    <FromUserName><![CDATA[{to_user}]]></FromUserName>
                    <CreateTime>{int(time.time())}</CreateTime>
                    <MsgType><![CDATA[text]]></MsgType>
                    <Content><![CDATA[Gemini API 返回空值或无效数据]]></Content>
                </xml>
                """
            return error_reply_xml

    except ET.ParseError as e:
        logger.error(f"XML parsing error: {e}, xml_data: {xml_data}, traceback: {traceback.format_exc()}")
        error_reply_xml = f"""
            <xml>
                <ToUserName><![CDATA[{from_user}]]></ToUserName>
                <FromUserName><![CDATA[{to_user}]]></FromUserName>
                <CreateTime>{int(time.time())}</CreateTime>
                <MsgType><![CDATA[text]]></MsgType>
                <Content><![CDATA[XML 解析错误]]></Content>
            </xml>
            """
        return error_reply_xml
    except Exception as e:
        logger.error(f"Error while handling message: {e}, xml_data: {xml_data}, traceback: {traceback.format_exc()}")
        error_reply_xml = f"""
            <xml>
                <ToUserName><![CDATA[{from_user}]]></ToUserName>
                <FromUserName><![CDATA[{to_user}]]></FromUserName>
                <CreateTime>{int(time.time())}</CreateTime>
                <MsgType><![CDATA[text]]></MsgType>
                <Content><![CDATA[抱歉，处理消息时发生了错误。]]></Content>
            </xml>
            """
        return error_reply_xml

# 发送微信回复消息
def send_reply(reply_xml):
    logger.debug(f"Sending reply: {reply_xml}")
    response = make_response(reply_xml)
    response.content_type = 'application/xml'
    return response


# 微信服务器验证和消息处理
@app.route('/', methods=['GET', 'POST'])
def wechat():
    if request.method == 'GET':
        signature = request.args.get('signature', '')
        timestamp = request.args.get('timestamp', '')
        nonce = request.args.get('nonce', '')
        echostr = request.args.get('echostr', '')
        logger.debug(f"GET request: signature={signature}, timestamp={timestamp}, nonce={nonce}, echostr={echostr}")
        if check_signature(signature, timestamp, nonce):
            return echostr
        else:
            return '验证失败'
    elif request.method == 'POST':
        xml_data = request.data
        logger.debug(f"POST request data: {xml_data}")
        reply_xml = handle_message(xml_data) # 直接获取单个 XML 字符串

        if reply_xml:
            logger.debug(f"Reply to send: {reply_xml}")
            response = send_reply(reply_xml)
            logger.debug("Reply sent successfully.")
            return response
        else:
            logger.warning("No reply generated.")
            return "没有生成回复。", 200

# 启动 Flask 应用（HTTP）
if __name__ == '__main__':
    try:
        app.run(host='0.0.0.0', port=80)
    finally:
        pass # No need to shutdown the executor and queue.
