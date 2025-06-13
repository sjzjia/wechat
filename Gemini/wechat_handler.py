# -*- coding: utf-8 -*-
"""
处理与微信公众号交互的逻辑
"""
import hashlib
import time
import requests
from flask import request, make_response
from defusedxml.ElementTree import fromstring # 使用 defusedxml 防止 XML 炸弹
import json

from config import logger, WECHAT_TOKEN, APPID, APPSECRET, WECHAT_ACCESS_TOKEN_TIMEOUT, WECHAT_MEDIA_UPLOAD_TIMEOUT, WECHAT_VOICE_DOWNLOAD_TIMEOUT
from utils import sanitize_xml_text, truncate_text_by_bytes
from constants import ACCESS_TOKEN_FETCH_FAILED_REPLY, WECHAT_TEXT_MAX_BYTES

# ==================== 微信签名验证 ====================
def check_signature(signature, timestamp, nonce):
    """验证微信服务器的签名。"""
    token = WECHAT_TOKEN
    tmp_arr = sorted([token, timestamp, nonce])
    tmp_str = "".join(tmp_arr)
    sha1_tmp_str = hashlib.sha1(tmp_str.encode('utf-8')).hexdigest()
    return sha1_tmp_str == signature

# ==================== 消息解析与构建 ====================
def parse_message(xml_data):
    """解析微信发送的 XML 消息。"""
    try:
        msg = {}
        root = fromstring(xml_data)
        for child in root:
            msg[child.tag] = child.text
        logger.debug(f"成功解析微信消息: {msg}")
        return msg
    except Exception as e:
        logger.error(f"解析微信 XML 消息失败: {e}", exc_info=True)
        return None

def build_text_response(to_user, from_user, content):
    """构建文本回复消息的 XML。"""
    # 对 content 进行 XML 转义，防止注入，并按字节截断
    safe_content = sanitize_xml_text(content)
    truncated_content = truncate_text_by_bytes(safe_content, WECHAT_TEXT_MAX_BYTES)
    if len(safe_content.encode('utf-8')) > WECHAT_TEXT_MAX_BYTES:
        logger.warning(f"回复文本超长，已截断。原始长度: {len(safe_content.encode('utf-8'))} bytes, 截断后: {len(truncated_content.encode('utf-8'))} bytes")

    return f"""<xml>
<ToUserName><![CDATA[{to_user}]]></ToUserName>
<FromUserName><![CDATA[{from_user}]]></FromUserName>
<CreateTime>{int(time.time())}</CreateTime>
<MsgType><![CDATA[text]]></MsgType>
<Content><![CDATA[{truncated_content}]]></Content>
</xml>"""

def build_image_response(to_user, from_user, media_id):
    """构建图片回复消息的 XML。"""
    return f"""<xml>
<ToUserName><![CDATA[{to_user}]]></ToUserName>
<FromUserName><![CDATA[{from_user}]]></FromUserName>
<CreateTime>{int(time.time())}</CreateTime>
<MsgType><![CDATA[image]]></MsgType>
<Image>
  <MediaId><![CDATA[{media_id}]]></MediaId>
</Image>
</xml>"""

# ==================== 微信 API 交互 ====================
_access_token_cache = {
    "token": None,
    "expires_at": 0
}

def get_access_token():
    """获取微信 Access Token，带缓存机制。"""
    now = time.time()
    if _access_token_cache["token"] and _access_token_cache["expires_at"] > now:
        logger.info("从缓存获取 Access Token")
        return _access_token_cache["token"]

    url = f"https://api.weixin.qq.com/cgi-bin/token?grant_type=client_credential&appid={APPID}&secret={APPSECRET}"
    try:
        response = requests.get(url, timeout=WECHAT_ACCESS_TOKEN_TIMEOUT)
        response.raise_for_status() # 如果请求失败则抛出 HTTPError
        data = response.json()
        if "access_token" in data:
            _access_token_cache["token"] = data["access_token"]
            # 提前 5 分钟过期，防止边界情况
            _access_token_cache["expires_at"] = now + data.get("expires_in", 7200) - 300
            logger.info(f"成功获取新的 Access Token，有效期至: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(_access_token_cache['expires_at']))}")
            return data["access_token"]
        else:
            logger.error(f"获取 Access Token 失败: {data.get('errmsg', '未知错误')}")
            return None
    except requests.exceptions.RequestException as e:
        logger.error(f"请求 Access Token 时发生网络错误: {e}", exc_info=True)
        return None
    except json.JSONDecodeError as e:
        logger.error(f"解析 Access Token 响应 JSON 失败: {e}", exc_info=True)
        return None

def upload_media_to_wechat(media_type: str, media_bytes: bytes, filename: str = "media") -> str:
    """上传临时素材到微信服务器。"""
    access_token = get_access_token()
    if not access_token:
        logger.error("无法上传媒体文件，因为 Access Token 获取失败。")
        return ACCESS_TOKEN_FETCH_FAILED_REPLY # 返回错误提示，而不是 None

    upload_url = f"https://api.weixin.qq.com/cgi-bin/media/upload?access_token={access_token}&type={media_type}"
    files = {'media': (filename, media_bytes)}

    try:
        response = requests.post(upload_url, files=files, timeout=WECHAT_MEDIA_UPLOAD_TIMEOUT)
        response.raise_for_status()
        result = response.json()
        if "media_id" in result:
            logger.info(f"媒体文件上传成功，Media ID: {result['media_id']}")
            return result["media_id"]
        else:
            logger.error(f"上传媒体文件到微信失败: {result.get('errmsg', '未知错误')}")
            return f"上传媒体文件失败: {result.get('errmsg', '请稍后重试')}"
    except requests.exceptions.RequestException as e:
        logger.error(f"上传媒体文件到微信时发生网络错误: {e}", exc_info=True)
        return "上传媒体文件网络错误，请稍后重试。"
    except json.JSONDecodeError as e:
        logger.error(f"解析微信媒体上传响应 JSON 失败: {e}", exc_info=True)
        return "解析微信媒体上传响应失败，请稍后重试。"

def download_wechat_media(media_id: str) -> bytes:
    """从微信服务器下载媒体文件（如图文消息内的图片、语音）。"""
    access_token = get_access_token()
    if not access_token:
        logger.error("无法下载媒体文件，因为 Access Token 获取失败。")
        return None

    download_url = f"https://api.weixin.qq.com/cgi-bin/media/get?access_token={access_token}&media_id={media_id}"

    try:
        response = requests.get(download_url, timeout=WECHAT_VOICE_DOWNLOAD_TIMEOUT, stream=True)
        response.raise_for_status()

        # 检查响应头，判断是否为错误信息 (JSON)
        content_type = response.headers.get('Content-Type', '')
        if 'application/json' in content_type or 'text/plain' in content_type:
            try:
                error_data = response.json()
                logger.error(f"下载微信媒体文件失败 (Media ID: {media_id}): {error_data.get('errmsg', '未知错误')}")
                return None
            except json.JSONDecodeError:
                # 如果不是合法的 JSON，可能是其他文本错误
                logger.error(f"下载微信媒体文件时收到非预期的文本响应 (Media ID: {media_id}): {response.text[:200]}")
                return None

        # 否则认为是媒体文件内容
        media_content = response.content
        logger.info(f"成功下载微信媒体文件 (Media ID: {media_id}), 大小: {len(media_content)} bytes")
        return media_content

    except requests.exceptions.RequestException as e:
        logger.error(f"下载微信媒体文件时发生网络错误 (Media ID: {media_id}): {e}", exc_info=True)
        return None
