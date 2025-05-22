import os
import logging
from flask import Flask, request, Response
import hashlib
import requests
import time
from xml.etree import ElementTree as ET
from xml.dom import minidom
from xml.sax.saxutils import escape
import re

# 配置日志
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

app = Flask(__name__)

# 从环境变量获取配置
WECHAT_TOKEN = os.environ.get('WECHAT_TOKEN')
SPARK_API_KEY = os.environ.get('SPARK_API_KEY')
SPARK_API_URL = 'https://spark-api-open.xf-yun.com/v1/chat/completions'

# 常量定义
MSG_TYPE_TEXT = 'text'
CONTENT_TYPE_XML = 'application/xml'
XML_ROOT = 'xml'
TO_USER = 'ToUserName'
FROM_USER = 'FromUserName'
CREATE_TIME = 'CreateTime'
MSG_TYPE = 'MsgType'
CONTENT = 'Content'
MAX_MESSAGE_LENGTH = 2000  # 微信文本消息限制

def check_signature(signature, timestamp, nonce):
    """验证微信服务器发送请求的签名"""
    if not all([signature, timestamp, nonce, WECHAT_TOKEN]):
        return False
    tmp_list = sorted([WECHAT_TOKEN, timestamp, nonce])
    tmp_str = hashlib.sha1(''.join(tmp_list).encode('utf-8')).hexdigest()
    return tmp_str == signature

def call_spark_api(user_message):
    """调用讯飞 Spark API 获取回复"""
    if not SPARK_API_KEY:
        logging.error("讯飞 Spark API Key 未配置")
        return '抱歉，服务器配置错误。'

    headers = {
        'Authorization': f'Bearer {SPARK_API_KEY}',
        'Content-Type': 'application/json'
    }
    data = {
        'model': '4.0Ultra',
        'messages': [{'role': 'user', 'content': user_message}],
        'stream': False
    }
    try:
        logging.info(f"请求 Spark API - URL: {SPARK_API_URL}, Headers: {headers}, Data: {data}")
        response = requests.post(SPARK_API_URL, headers=headers, json=data, timeout=10)
        response.raise_for_status()  # 抛出 HTTPError 以处理非 200 的状态码
        result = response.json()
        logging.info(f"Spark API 响应: {result}")
        return result['choices'][0]['message']['content']
    except requests.exceptions.RequestException as e:
        logging.error(f"调用 Spark API 出错: {e}")
        return '抱歉，我暂时无法处理你的请求。'
    except (KeyError, IndexError, ValueError) as e:
        logging.error(f"解析 Spark API 响应出错: {e}, 原始响应: {response.text if 'response' in locals() else 'N/A'}")
        return '抱歉，服务器内部错误。'

def generate_reply_xml_direct(to_user, from_user, content):
    """直接生成回复消息的 XML 字符串"""
    return f"""<xml>
<ToUserName><![CDATA[{to_user}]]></ToUserName>
<FromUserName><![CDATA[{from_user}]]></FromUserName>
<CreateTime>{int(time.time())}</CreateTime>
<MsgType><![CDATA[text]]></MsgType>
<Content><![CDATA[{escape(content)}]]></Content>
</xml>"""

def smart_split_for_wechat(content, max_length=MAX_MESSAGE_LENGTH):
    """
    智能分割长文本以适应微信限制，优先按段落分割。
    返回一个文本片段列表。
    """
    if len(content.encode('utf-8')) <= max_length:
        return [content]

    parts = []
    current_part = ""
    paragraphs = content.split('\n\n')

    for para in paragraphs:
        if not para.strip():
            continue

        para_bytes = para.encode('utf-8')

        if not current_part:
            if para_bytes <= max_length:
                current_part = para
            else:
                # 极端情况：单个段落也超长，按句子分割
                sentences = re.split(r'(?<=[。！？.?!])', para)
                for sent in sentences:
                    sent = sent.strip()
                    if not sent:
                        continue
                    sent_bytes = sent.encode('utf-8')
                    if len(current_part.encode('utf-8')) + len(sent_bytes) + 1 < max_length:
                        current_part += (("\n" if current_part else "") + sent)
                    else:
                        if current_part:
                            parts.append(current_part)
                        current_part = sent
                if current_part:
                    parts.append(current_part)
                    current_part = ""
        elif len(current_part.encode('utf-8')) + len(para_bytes) + 2 < max_length:
            current_part += "\n\n" + para
        else:
            parts.append(current_part)
            current_part = para

    if current_part:
        parts.append(current_part)

    return parts

@app.route('/xf', methods=['GET', 'POST'])
def wechat():
    if request.method == 'GET':
        signature = request.args.get('signature', '')
        timestamp = request.args.get('timestamp', '')
        nonce = request.args.get('nonce', '')
        echostr = request.args.get('echostr', '')

        if check_signature(signature, timestamp, nonce):
            return echostr
        else:
            logging.warning("微信服务器签名验证失败")
            return '验证失败'
    else:
        xml_data = request.data
        logging.info(f"接收到的 XML 数据: {xml_data.decode('utf-8')}")
        try:
            xml_tree = ET.fromstring(xml_data)
            msg_type = xml_tree.find(MSG_TYPE).text
            from_user = xml_tree.find(FROM_USER).text
            to_user = xml_tree.find(TO_USER).text

            if msg_type == MSG_TYPE_TEXT:
                user_message = xml_tree.find(CONTENT).text
                if not user_message.strip():
                    reply_content = "消息内容为空"
                    reply_xml = generate_reply_xml_direct(from_user, to_user, reply_content)
                    return Response(reply_xml, content_type=CONTENT_TYPE_XML)

                try:
                    reply_content = call_spark_api(user_message)
                    # 清理回复内容 (可以根据需要添加)
                    reply_content = re.sub(r'\s+', ' ', reply_content).strip()
                    reply_parts = smart_split_for_wechat(reply_content) # 使用分割函数

                    if reply_parts:
                        reply_xml = generate_reply_xml_direct(from_user, to_user, reply_parts[0])
                        logging.info(f"发送的回复 XML: {reply_xml}")
                        return Response(reply_xml, content_type=CONTENT_TYPE_XML)
                    else:
                        return 'success' # 返回空消息的成功响应

                except Exception as api_error:
                    logger.error(f"Spark API 处理失败: {str(api_error)}")
                    reply_content = "AI服务暂时不可用，请稍后再试"
                    reply_xml = generate_reply_xml_direct(from_user, to_user, reply_content)
                    return Response(reply_xml, content_type=CONTENT_TYPE_XML)

            else:
                reply_content = "暂仅支持文本消息"
                reply_xml = generate_reply_xml_direct(from_user, to_user, reply_content)
                return Response(reply_xml, content_type=CONTENT_TYPE_XML)

        except ET.ParseError as e:
            logger.error(f"解析 XML 数据出错: {e}, 原始数据: {xml_data.decode('utf-8')}")
            return 'success'  # 返回 success 避免微信服务器重试
        except Exception as e:
            logger.error(f"处理微信消息时发生未知错误: {e}")
            return 'success'  # 返回 success 避免微信服务器重试

if __name__ == '__main__':
    # 建议使用更专业的 WSGI 服务器（如 Gunicorn 或 uWSGI）在生产环境运行
    app.run(host='0.0.0.0', port=80, debug=True) # debug 模式仅用于开发
