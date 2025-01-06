from flask import Flask, request, Response
import hashlib
import requests
import time
from xml.etree import ElementTree as ET
from xml.dom import minidom
from xml.sax.saxutils import escape  # 用于转义特殊字符

app = Flask(__name__)

# 微信公众号配置
WECHAT_TOKEN = 'YOU_WECHAT_TOKEN'  # 替换为你在微信公众平台设置的 Token

# 讯飞 Spark API 配置
SPARK_API_URL = 'https://spark-api-open.xf-yun.com/v1/chat/completions'
SPARK_API_KEY = 'YOU_SPARK_API_KEY'  # 替换为你的 API Key

@app.route('/', methods=['GET', 'POST'])
def wechat():
    if request.method == 'GET':
        # 验证服务器地址
        signature = request.args.get('signature', '')
        timestamp = request.args.get('timestamp', '')
        nonce = request.args.get('nonce', '')
        echostr = request.args.get('echostr', '')

        # 验证签名
        if check_signature(signature, timestamp, nonce):
            return echostr
        else:
            return '验证失败'
    else:
        # 处理微信服务器发送的消息
        xml_data = request.data
        print(f"接收到的 XML 数据: {xml_data.decode('utf-8')}")

        # 解析 XML 数据
        try:
            xml_tree = ET.fromstring(xml_data)
            msg_type = xml_tree.find('MsgType').text
            user_message = xml_tree.find('Content').text if msg_type == 'text' else ''

            # 调用讯飞 Spark API 生成回复
            reply_content = call_spark_api(user_message)

            # 返回回复消息
            return Response(generate_reply_xml(xml_tree, reply_content), content_type='application/xml')
        except Exception as e:
            print(f"解析 XML 或处理消息时出错: {e}")
            return 'success'  # 返回 success 避免微信服务器重试

def check_signature(signature, timestamp, nonce):
    # 将 Token、timestamp、nonce 按字典序排序并拼接
    tmp_list = [WECHAT_TOKEN, timestamp, nonce]
    tmp_list.sort()
    tmp_str = ''.join(tmp_list)

    # 进行 sha1 加密
    tmp_str = hashlib.sha1(tmp_str.encode('utf-8')).hexdigest()

    # 与 signature 对比
    return tmp_str == signature

def call_spark_api(user_message):
    # 调用讯飞 Spark API
    headers = {
        'Authorization': f'Bearer {SPARK_API_KEY}',
        'Content-Type': 'application/json'
    }
    data = {
        'model': '4.0Ultra',
        'messages': [
            {
                'role': 'user',
                'content': user_message
            }
        ],
        'stream': False
    }
    try:
        print(f"请求 URL: {SPARK_API_URL}")
        print(f"请求头部: {headers}")
        print(f"请求参数: {data}")

        response = requests.post(SPARK_API_URL, headers=headers, json=data, timeout=10)
        
        print(f"API 响应状态码: {response.status_code}")
        print(f"API 响应内容: {response.text}")

        if response.status_code == 200:
            result = response.json()
            return result['choices'][0]['message']['content']
        else:
            # 处理 API 错误
            error_message = f"API 调用失败，状态码: {response.status_code}"
            if response.text:
                error_message += f"，错误信息: {response.text}"
            print(error_message)
            return '抱歉，我暂时无法处理你的请求。'
    except requests.exceptions.RequestException as e:
        print(f"调用讯飞 Spark API 时出错: {e}")
        return '抱歉，我暂时无法处理你的请求。'

def generate_reply_xml(xml_tree, reply_content):
    # 生成回复消息的 XML
    to_user = xml_tree.find('FromUserName').text
    from_user = xml_tree.find('ToUserName').text

    # 转义回复内容中的特殊字符
    escaped_content = escape(reply_content)

    xml = ET.Element('xml')
    ET.SubElement(xml, 'ToUserName').text = to_user
    ET.SubElement(xml, 'FromUserName').text = from_user
    ET.SubElement(xml, 'CreateTime').text = str(int(time.time()))
    ET.SubElement(xml, 'MsgType').text = 'text'
    ET.SubElement(xml, 'Content').text = escaped_content

    # 格式化 XML
    rough_string = ET.tostring(xml, 'utf-8')
    parsed = minidom.parseString(rough_string)
    return parsed.toxml()

if __name__ == '__main__':
    # 使用 HTTP 运行 Flask 应用
    app.run(host='0.0.0.0', port=80)
