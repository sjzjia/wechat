# -*- coding: utf-8 -*-
"""
存放应用中使用的工具函数
"""
import io
import re
import socket
import textwrap
from typing import Union
from urllib.parse import urlparse, urljoin

from PIL import Image, ImageDraw, ImageFont

from config import logger, FONT_PATH, MAX_IMG_WIDTH, MAX_IMG_HEIGHT, FONT_SIZE, LINE_SPACING_FACTOR, IMAGE_PADDING, DNS_RESOLVE_TIMEOUT

# ==================== 文本处理与图片生成 ====================
def text_to_image_bytes(text: str, font_path: Union[str, None] = FONT_PATH, max_width: int = MAX_IMG_WIDTH,
                        max_height: int = MAX_IMG_HEIGHT, font_size: int = FONT_SIZE,
                        line_spacing_factor: float = LINE_SPACING_FACTOR, padding: int = IMAGE_PADDING) -> Union[bytes, None]:
    """将长文本转换为图片，并返回图片的字节流。"""
    try:
        # 尝试加载字体
        try:
            if font_path:
                font = ImageFont.truetype(font_path, font_size)
            else:
                font = ImageFont.load_default() # 使用Pillow默认字体
        except IOError:
            logger.error(f"无法加载字体: {font_path}，将使用默认字体。")
            font = ImageFont.load_default()

        # 文本自动换行
        wrapped_lines = []
        avg_char_width = font.getlength("A") # 获取单个字符的大致宽度
        chars_per_line = max(1, int((max_width - 2 * padding) / avg_char_width)) # 每行大致字符数

        for para in text.split('\n'): # 处理段落换行
            if not para.strip(): # 空行直接添加
                wrapped_lines.append("")
                continue
            # 使用 textwrap 进行更精确的换行
            para_wrapped = textwrap.wrap(para, width=chars_per_line, replace_whitespace=False, drop_whitespace=False)
            wrapped_lines.extend(para_wrapped)

        # 计算图片尺寸
        line_height = font.getbbox("Tg")[3] - font.getbbox("Tg")[1] # 获取字体高度 ('Tg' 通常包含上下突出部分)
        spacing = int(line_height * line_spacing_factor) # 行间距
        img_height = padding * 2 + len(wrapped_lines) * line_height + (len(wrapped_lines) - 1) * spacing
        img_height = min(img_height, max_height) # 限制最大高度

        img_width = max_width

        # 创建图片
        image = Image.new('RGB', (img_width, img_height), color='white')
        draw = ImageDraw.Draw(image)

        # 绘制文本
        y_text = padding
        for line in wrapped_lines:
            # 检查是否超出图片高度
            if y_text + line_height > max_height - padding:
                logger.warning("文本内容超出图片最大高度，部分内容可能被截断。")
                # 可以在这里添加省略号等标记
                draw.text((padding, y_text), "... (内容过长，已截断)", font=font, fill='black')
                break
            draw.text((padding, y_text), line, font=font, fill='black')
            y_text += line_height + spacing

        # 将图片保存到内存中
        img_byte_arr = io.BytesIO()
        image.save(img_byte_arr, format='PNG')
        img_byte_arr = img_byte_arr.getvalue()
        logger.info(f"文本成功转换为图片，图片大小: {len(img_byte_arr)} bytes")
        return img_byte_arr

    except Exception as e:
        logger.error(f"文本转图片失败: {e}", exc_info=True)
        return None

# ==================== 网络与安全 ====================
def is_safe_url(url: str, allowed_schemes=('http', 'https'), timeout: int = DNS_RESOLVE_TIMEOUT) -> bool:
    """检查 URL 是否安全，包括协议、是否为私有/保留IP、能否正常解析。"""
    try:
        parsed_url = urlparse(url)
        if parsed_url.scheme not in allowed_schemes:
            logger.warning(f"检测到不安全的 URL 协议: {parsed_url.scheme} (URL: {url})")
            return False

        hostname = parsed_url.hostname
        if not hostname:
            logger.warning(f"URL 中缺少主机名: {url}")
            return False

        # 尝试解析 IP 地址
        try:
            # 设置 DNS 解析超时
            socket.setdefaulttimeout(timeout)
            ip_address = socket.gethostbyname(hostname)
        except socket.gaierror as e: # getaddrinfo error
            logger.warning(f"无法解析主机名 {hostname} (URL: {url}): {e}")
            return False
        except socket.timeout:
            logger.warning(f"DNS 解析超时: {hostname} (URL: {url})")
            return False
        finally:
            socket.setdefaulttimeout(None) # 恢复默认超时设置

        # 检查是否为私有或保留IP地址 (更全面的检查)
        # 注意：这里需要 ipaddress 模块，已在 app.py 中导入
        # 如果 utils.py 单独使用，需要在此处导入 from ipaddress import ip_address as ip_addr_obj, IPv4Address, IPv6Address
        from ipaddress import ip_address as ip_addr_obj, IPv4Address, IPv6Address # 放在函数内部，避免循环导入

        try:
            ip_obj = ip_addr_obj(ip_address)
            if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local or \
               ip_obj.is_multicast or ip_obj.is_reserved or ip_obj.is_unspecified:
                logger.warning(f"检测到 URL 指向私有或保留 IP 地址: {ip_address} (URL: {url})")
                return False
        except ValueError:
            logger.warning(f"无效的 IP 地址格式: {ip_address} (URL: {url})")
            return False # 无法解析为有效的 IP 对象

        # 简单的 SSRF 防护：检查常见的元数据地址 (可以根据需要扩展)
        # AWS EC2 metadata
        if hostname == '169.254.169.254' or ip_address == '169.254.169.254':
            logger.warning(f"检测到尝试访问 AWS EC2 元数据服务: {url}")
            return False
        # Google Cloud metadata
        if hostname == 'metadata.google.internal' or ip_address == '169.254.169.254': # GCE metadata IP is also 169.254.169.254
            logger.warning(f"检测到尝试访问 Google Cloud 元数据服务: {url}")
            return False

        logger.info(f"URL 安全检查通过: {url} (解析到 IP: {ip_address})")
        return True

    except Exception as e:
        logger.error(f"URL 安全检查时发生意外错误 (URL: {url}): {e}", exc_info=True)
        return False # 默认为不安全

def sanitize_xml_text(text: str) -> str:
    """对文本进行XML转义，防止注入。"""
    # 移除可能导致XML解析问题的控制字符 (除了合法的空白符 \t, \n, \r)
    # XML 1.0 spec: #x9 | #xA | #xD | [#x20-#xD7FF] | [#xE000-#xFFFD] | [#x10000-#x10FFFF]
    text = re.sub(r'[\x00-\x08\x0B\x0C\x0E-\x1F]', '', text)
    from xml.sax.saxutils import escape # 放在函数内部，避免循环导入
    return escape(text)


def truncate_text_by_bytes(text: str, max_bytes: int, encoding: str = 'utf-8') -> str:
    """按字节数截断文本，确保不会在多字节字符中间截断。"""
    if not text:
        return ""
    encoded_text = text.encode(encoding)
    if len(encoded_text) <= max_bytes:
        return text

    # 截断到最大字节数
    truncated_bytes = encoded_text[:max_bytes]

    # 尝试解码，如果失败则逐步减少字节直到成功
    while True:
        try:
            decoded_text = truncated_bytes.decode(encoding)
            logger.info(f"文本已按字节截断，原始长度 {len(encoded_text)} bytes, 截断后 {len(truncated_bytes)} bytes.")
            return decoded_text
        except UnicodeDecodeError:
            if not truncated_bytes:
                logger.warning("无法按字节截断文本，即使是空字节串也无法解码。")
                return "" # 或者抛出错误
            truncated_bytes = truncated_bytes[:-1] # 移除最后一个字节
