import hashlib
import time
import requests
from flask import Flask, request, make_response
from xml.etree import ElementTree as ET
import threading
import logging
import google.generativeai as genai
import os
from PIL import Image
import io
import queue
import concurrent.futures
import traceback

app = Flask(__name__)

# 配置日志记录
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# 微信公众号配置
WECHAT_TOKEN = os.environ.get("WECHAT_TOKEN")
GEMINI_API_KEY = os.environ.get("GEMINI_API_KEY")
genai.configure(api_key=GEMINI_API_KEY)

# 异步回复队列
reply_queue = queue.Queue(maxsize=100)  # 设置队列最大长度

# 异步发送回复的线程池
executor = concurrent.futures.ThreadPoolExecutor(max_workers=5)

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

# 将内容分成多个部分
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
                return ["<xml><Content><![CDATA[图片下载失败]]></Content></xml>"]
            except Exception as e:
                logger.error(f"Error processing image: {e}, pic_url: {pic_url}, traceback: {traceback.format_exc()}")
                return ["<xml><Content><![CDATA[图片处理失败]]></Content></xml>"]

        if response and response.text:
            reply_content = response.text.strip()
            logger.debug(f"Gemini API response: {reply_content}")
            reply_parts = split_message(reply_content)

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
        else:
            logger.warning("Gemini API 返回空值或无效数据")
            return ["<xml><Content><![CDATA[Gemini API 返回空值或无效数据]]></Content></xml>"]

    except ET.ParseError as e:
        logger.error(f"XML parsing error: {e}, xml_data: {xml_data}, traceback: {traceback.format_exc()}")
        return ["<xml><Content><![CDATA[XML 解析错误]]></Content></xml>"]
    except Exception as e:
        logger.error(f"Error while handling message: {e}, xml_data: {xml_data}, traceback: {traceback.format_exc()}")
        return ["<xml><Content><![CDATA[抱歉，处理消息时发生了错误。]]></Content></xml>"]

# 发送微信回复消息
def send_reply(reply_xml):
    logger.debug(f"Sending reply: {reply_xml}")
    response = make_response(reply_xml)
    response.content_type = 'application/xml'
    return response

# 异步发送剩余回复
def send_async_reply_worker():
    while True:
        try:
            reply_xml = reply_queue.get(timeout=10) #Add timeout to prevent thread hang.
            if reply_xml is None:
                break
            try:
                with app.app_context():
                    response = send_reply(reply_xml)
                    logger.debug(f"Async reply sent: {reply_xml}")
            except Exception as e:
                logger.error(f"Error sending async reply: {e}, reply_xml: {reply_xml}, traceback: {traceback.format_exc()}")
            reply_queue.task_done()
        except queue.Empty:
            logger.debug("Async reply queue is empty.")

# 启动异步回复线程
executor.submit(send_async_reply_worker)

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
        reply_xml_list = handle_message(xml_data)

        if reply_xml_list:
            response = send_reply(reply_xml_list[0])

            if len(reply_xml_list) > 1:
                for reply_xml in reply_xml_list[1:]:
                    reply_queue.put(reply_xml)

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
        reply_queue.put(None)
        executor.shutdown()
