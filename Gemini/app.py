import hashlib
import time
import requests
from flask import Flask, request, make_response
from xml.etree import ElementTree as ET
from xml.sax.saxutils import escape
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
            if content.strip().lower() in ['help', '帮助', '菜单']:
                reply_content = "欢迎使用 AI 智能助手！您可以发送文字让我回复，也可以发送图片让我分析内容。"
            else:
                response = model.generate_content(content)
                reply_content = response.text.strip() if response and response.text else "AI 没有返回任何内容。"

        elif msg_type == 'image':
            try:
                image_data = requests.get(pic_url, timeout=10).content
                image = Image.open(io.BytesIO(image_data))
                image.verify()  # 验证图片格式
                image = Image.open(io.BytesIO(image_data))  # 重新打开用于模型输入

                prompt = "请用中文详细描述这张图片的内容，并尽可能分析它的含义。"
                response = model.generate_content([prompt, image])
                reply_content = response.text.strip() if response and response.text else "AI 没有返回任何内容。"

            except requests.exceptions.RequestException as e:
                logger.error(f"Error downloading image: {e}, pic_url: {pic_url}, traceback: {traceback.format_exc()}")
                reply_content = "图片下载失败，请稍后再试。"
            except Exception as e:
                logger.error(f"Error processing image: {e}, pic_url: {pic_url}, traceback: {traceback.format_exc()}")
                reply_content = "图片格式不支持或处理失败，请换一张图片试试。"

        else:
            reply_content = "暂不支持该类型的消息，请发送文字或图片。"

        # 安全处理和截断
        reply_content = truncate_message(reply_content, 2048)
        reply_content = escape(reply_content)

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

    except ET.ParseError as e:
        logger.error(f"XML parsing error: {e}, xml_data: {xml_data}, traceback: {traceback.format_exc()}")
        return make_error_xml("XML 解析错误", from_user, to_user)
    except Exception as e:
        logger.error(f"Error while handling message: {e}, xml_data: {xml_data}, traceback: {traceback.format_exc()}")
        return make_error_xml("抱歉，处理消息时发生了错误。", from_user, to_user)

def make_error_xml(content, from_user, to_user):
    safe_content = escape(content)
    return f"""
        <xml>
            <ToUserName><![CDATA[{from_user}]]></ToUserName>
            <FromUserName><![CDATA[{to_user}]]></FromUserName>
            <CreateTime>{int(time.time())}</CreateTime>
            <MsgType><![CDATA[text]]></MsgType>
            <Content><![CDATA[{safe_content}]]></Content>
        </xml>
        """

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
        params = request.args.to_dict()
        signature = params.get('signature', '')
        timestamp = params.get('timestamp', '')
        nonce = params.get('nonce', '')
        echostr = params.get('echostr', '')
        logger.debug(f"GET request: signature={signature}, timestamp={timestamp}, nonce={nonce}, echostr={echostr}")
        if check_signature(signature, timestamp, nonce):
            return echostr
        else:
            return '验证失败'

    elif request.method == 'POST':
        if request.content_type != 'text/xml':
            logger.warning(f"Unexpected content type: {request.content_type}")
            return "不支持的 Content-Type", 400

        xml_data = request.data
        logger.debug(f"POST request data: {xml_data}")
        reply_xml = handle_message(xml_data)
        return send_reply(reply_xml)

# 启动 Flask 应用（HTTP）
# if __name__ == '__main__':
#    app.run(host='0.0.0.0', port=80)
