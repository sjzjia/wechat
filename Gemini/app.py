# -*- coding: utf-8 -*- 
from typing import Union, Dict, Any, Optional
import hashlib
import time
import requests # 保留，因为 ai_handler 和 wechat_handler 内部可能使用
from flask import Flask, request, make_response
import traceback
import threading # 保留，如果后续有异步处理需求
import io # 保留，utils 和 ai_handler 中使用

# 导入自定义模块
from config import logger, WECHAT_TOKEN, WECHAT_MAX_IMAGE_UPLOAD_SIZE, FONT_PATH, MAX_IMG_WIDTH, MAX_IMG_HEIGHT, FONT_SIZE, LINE_SPACING_FACTOR, IMAGE_PADDING
import constants as C # 使用别名，方便引用常量
import utils
import wechat_handler as wx
import ai_handler as ai
import redis_handler as cache

app = Flask(__name__)

# ==================== 微信消息处理核心逻辑 ====================
@app.route('/', methods=['GET', 'POST'])
def wechat_interface():
    """微信公众号消息接口"""
    if request.method == 'GET':
        # 微信接入认证
        signature = request.args.get('signature', '')
        timestamp = request.args.get('timestamp', '')
        nonce = request.args.get('nonce', '')
        echostr = request.args.get('echostr', '')
        if wx.check_signature(signature, timestamp, nonce):
            logger.info("微信接入认证成功")
            return make_response(echostr)
        else:
            logger.error("微信接入认证失败")
            return make_response("认证失败", 403)
    else:
        # 处理 POST 请求，即用户发送的消息
        xml_data = request.data
        if not xml_data:
            logger.warning("收到空的 POST 请求")
            return make_response("Empty request", 400)

        msg = wx.parse_message(xml_data)
        if not msg:
            logger.error("解析微信消息失败")
            # 根据微信开发文档，即使解析失败，也应回复空字符串或success
            return make_response("success") # 或者返回一个通用错误XML

        msg_type = msg.get('MsgType', '')
        from_user = msg.get('FromUserName', '')
        to_user = msg.get('ToUserName', '')
        content = msg.get('Content', '').strip() if msg_type == 'text' else ''
        user_id = from_user # 使用 FromUserName 作为用户唯一标识

        logger.info(f"收到用户 [{user_id}] 的 [{msg_type}] 消息。内容/MediaId: {content or msg.get('MediaId') or msg.get('PicUrl')}")

        response_xml = handle_message_logic(user_id, msg_type, msg, from_user, to_user, content)

        logger.info(f"准备回复用户 [{user_id}] XML: {response_xml[:500]}...") # 日志截断，避免过长
        response = make_response(response_xml)
        response.content_type = 'application/xml'
        return response

def handle_message_logic(user_id, msg_type, msg, from_user, to_user, content: str = ''):
    """根据消息类型处理具体逻辑并返回响应 XML。"""
    reply_content = ""
    media_id_for_reply = None

    try:
        if msg_type == 'text':
            # 检查是否为查询图片结果的命令
            if content == C.QUERY_IMAGE_RESULT_COMMAND:
                ai_result = cache.get_ai_result(user_id)
                if ai_result and "text" in ai_result:
                    reply_content = ai_result["text"]
                    # 成功查询后，可以选择删除该结果，避免重复查询
                    cache.delete_ai_result(user_id)
                elif ai_result and "error" in ai_result:
                    reply_content = ai_result["error"]
                else:
                    reply_content = C.IMAGE_QUERY_NO_RESULT_REPLY
            else:
                # 检查是否有缓存的文本回复
                request_hash = hashlib.md5(content.encode('utf-8')).hexdigest()
                cached_reply = cache.get_cached_text_reply(user_id, request_hash)
                if cached_reply:
                    reply_content = cached_reply
                    logger.info(f"命中用户 [{user_id}] 的文本请求缓存。")
                else:
                    # 调用 AI 生成文本回复
                    reply_content = ai.generate_text_from_text(content, user_id=user_id)
                    if not reply_content.startswith(C.AI_BLOCK_REASON_PREFIX): # 仅缓存成功的AI回复
                        cache.cache_text_reply(user_id, request_hash, reply_content)

        elif msg_type == 'image':
            pic_url = msg.get('PicUrl')
            media_id = msg.get('MediaId') # 图片消息会同时有 PicUrl 和 MediaId
            if pic_url:
                # 异步处理图片识别，先回复提示信息
                # 使用 threading 创建一个新线程来处理耗时的 AI 调用
                # 注意：在某些部署环境（如无状态的 serverless function）中，后台线程可能在主请求结束后被终止
                # 对于这类环境，需要使用消息队列等更可靠的异步处理机制
                thread = threading.Thread(target=process_image_async, args=(user_id, pic_url, media_id))
                thread.start()
                reply_content = C.INITIAL_IMAGE_PROCESSING_MESSAGE
            else:
                reply_content = C.IMAGE_DOWNLOAD_FAILED_REPLY + " (缺少图片链接)"

        elif msg_type == 'voice':
            media_id = msg.get('MediaId')
            recognition = msg.get('Recognition', '') # 语音识别结果（如果微信开启了）

            if recognition: # 如果微信已经提供了识别结果
                logger.info(f"用户 [{user_id}] 语音消息，微信识别结果: {recognition}")
                reply_content = ai.generate_text_from_text(f"处理以下语音转文本的结果：{recognition}", user_id=user_id)
            elif media_id:
                # 下载语音文件并进行处理 (此处假设有语音转文本服务，或直接将 media_id 交给 AI 处理，如果 AI 支持)
                # 这里简化为提示用户我们收到了语音，实际应用中需要集成语音转文字服务
                # voice_bytes = wx.download_wechat_media(media_id)
                # if voice_bytes:
                #     # text_from_voice = call_voice_to_text_service(voice_bytes)
                #     # reply_content = ai.generate_text_from_text(text_from_voice)
                #     reply_content = "语音消息已收到，正在处理中...（功能待实现）"
                # else:
                #     reply_content = C.VOICE_MESSAGE_PROCESSING_FAILED_REPLY
                logger.warning(f"用户 [{user_id}] 发送了语音消息，但未开启微信语音识别，且后端未实现语音处理。Media ID: {media_id}")
                reply_content = "您的语音已收到。如需AI回复，请开启微信后台的语音识别功能，或稍后尝试发送文本。"
            else:
                reply_content = C.VOICE_MESSAGE_PROCESSING_FAILED_REPLY + " (缺少 MediaID)"

        elif msg_type == 'event':
            event = msg.get('Event', '')
            if event == 'subscribe':
                reply_content = C.WELCOME_MESSAGE_REPLY
            elif event == 'unsubscribe':
                logger.info(f"用户 [{user_id}] 取消关注")
                return "success" # 取消关注不需要回复XML
            # 可以处理其他事件，如点击菜单等
            else:
                logger.info(f"收到未处理的事件类型: {event} from user [{user_id}] ")
                # reply_content = "收到了一个事件，但我不知道怎么处理它。"
                return "success" # 对于未明确处理的事件，回复 success 让微信不再重试

        else:
            reply_content = C.UNSUPPORTED_MESSAGE_TYPE_REPLY
            logger.warning(f"收到不支持的消息类型: {msg_type} from user [{user_id}]")

    except Exception as e:
        logger.error(f"处理用户 [{user_id}] 消息时发生严重错误: {e}\n{traceback.format_exc()}")
        reply_content = C.SERVER_INTERNAL_ERROR_REPLY

    # 统一回复构建
    if media_id_for_reply:
        return wx.build_image_response(from_user, to_user, media_id_for_reply)
    else:
        # 检查回复内容是否过长，如果过长且是文本，尝试转为图片
        if len(reply_content.encode('utf-8')) > C.WECHAT_TEXT_MAX_BYTES:
            logger.info(f"回复用户 [{user_id}] 的文本内容过长 ({len(reply_content.encode('utf-8'))} bytes)，尝试转为图片。")
            image_bytes = utils.text_to_image_bytes(reply_content)
            if image_bytes:
                # 检查图片大小是否超过微信限制
                if len(image_bytes) > WECHAT_MAX_IMAGE_UPLOAD_SIZE:
                    logger.warning(f"生成的回复图片大小 ({len(image_bytes)} bytes) 超过微信限制 ({WECHAT_MAX_IMAGE_UPLOAD_SIZE} bytes)。将发送截断的文本。")
                    # 可以选择发送部分文本，或者一个提示图片超大的文本
                    # 此处简单发送前缀+截断文本
                    final_reply_content = C.AI_REPLY_TOO_LONG_IMAGE_FAIL_PREFIX + utils.truncate_text_by_bytes(reply_content, C.WECHAT_TEXT_MAX_BYTES - len(C.AI_REPLY_TOO_LONG_IMAGE_FAIL_PREFIX.encode('utf-8')))
                    return wx.build_text_response(from_user, to_user, final_reply_content)

                uploaded_media_id = wx.upload_media_to_wechat('image', image_bytes, filename=f"reply_{user_id}.png")
                if uploaded_media_id and not uploaded_media_id.startswith("上传媒体文件失败") and not uploaded_media_id.startswith(C.ACCESS_TOKEN_FETCH_FAILED_REPLY):
                    logger.info(f"成功将超长文本转为图片并上传，Media ID: {uploaded_media_id}，回复给用户 [{user_id}]。")
                    return wx.build_image_response(from_user, to_user, uploaded_media_id)
                else:
                    logger.error(f"超长文本转图片后上传微信失败: {uploaded_media_id}。将回复截断的文本给用户 [{user_id}]。")
                    # 上传失败，回复截断的文本
                    final_reply_content = C.AI_REPLY_TOO_LONG_IMAGE_FAIL_PREFIX + utils.truncate_text_by_bytes(reply_content, C.WECHAT_TEXT_MAX_BYTES - len(C.AI_REPLY_TOO_LONG_IMAGE_FAIL_PREFIX.encode('utf-8')))
                    return wx.build_text_response(from_user, to_user, final_reply_content)
            else:
                logger.error(f"超长文本转图片失败。将回复截断的文本给用户 [{user_id}]。")
                # 转图片也失败，回复截断的文本
                final_reply_content = C.AI_REPLY_TOO_LONG_IMAGE_FAIL_PREFIX + utils.truncate_text_by_bytes(reply_content, C.WECHAT_TEXT_MAX_BYTES - len(C.AI_REPLY_TOO_LONG_IMAGE_FAIL_PREFIX.encode('utf-8')))
                return wx.build_text_response(from_user, to_user, final_reply_content)

        return wx.build_text_response(from_user, to_user, reply_content if reply_content else "我现在有点忙，稍后再试吧～")

def process_image_async(user_id: str, pic_url: str, media_id: str):
    """异步处理图片识别的函数，在单独的线程中运行。"""
    with app.app_context(): # 确保在 Flask 应用上下文中执行，以便访问 logger 等
        logger.info(f"开始异步处理用户 [{user_id}] 的图片，URL: {pic_url}, Media ID: {media_id}")
        # 优先使用 PicUrl，如果 Gemini 处理 URL 有问题，可以考虑下载 MediaId 对应的图片
        # ai_text_result = ai.generate_text_from_image_url(pic_url, user_id=user_id)

        # 尝试从微信服务器下载图片（可能更稳定，但会消耗token调用次数）
        image_bytes = wx.download_wechat_media(media_id)
        if image_bytes:
            logger.info(f"成功从微信下载用户 [{user_id}] 的图片 (Media ID: {media_id}), 大小: {len(image_bytes)} bytes, 准备提交给 AI。")
            ai_text_result = ai.generate_text_from_image_bytes(image_bytes, prompt="请用中文详细描述这张图片的内容，并尽可能分析它的含义。请直接给出描述，不要说“这张图片显示了...”之类的引导语。请务必使用中文回复", user_id=user_id)
        else:
            logger.warning(f"从微信下载用户 [{user_id}] 的图片 (Media ID: {media_id}) 失败，尝试使用 PicUrl。")
            ai_text_result = ai.generate_text_from_image_url(pic_url, prompt="请用中文详细描述这张图片的内容，并尽可能分析它的含义。请直接给出描述，不要说“这张图片显示了...”之类的引导语。请务必使用中文回复", user_id=user_id)

        if ai_text_result:
            # 将结果存储到 Redis，供用户后续查询
            storage_success = cache.store_ai_result(user_id, {"text": ai_text_result, "source_pic_url": pic_url, "source_media_id": media_id})
            if storage_success is True: # store_ai_result 成功时返回 True
                logger.info(f"用户 [{user_id}] 的图片识别结果已成功存入 Redis。")
            elif isinstance(storage_success, str): # 返回错误消息字符串
                 logger.error(f"用户 [{user_id}] 的图片识别结果存入 Redis 失败: {storage_success}")
            else: # 返回 False
                 logger.error(f"用户 [{user_id}] 的图片识别结果存入 Redis 失败 (未知原因)。")
        else:
            # AI 处理失败，也可以考虑存储一个错误标记
            cache.store_ai_result(user_id, {"error": C.IMAGE_PROCESSING_FAILED_REPLY, "source_pic_url": pic_url, "source_media_id": media_id})
            logger.error(f"用户 [{user_id}] 的图片 AI 处理失败。")


# ==================== 核心功能 - Access Token ====================
# Access token management is now handled in wechat_handler.py

# ==================== SSRF 防范辅助函数 (增强版) ====================
# SSRF protection functions (is_private_ip, is_safe_url) are now in utils.py

# Redundant handle_message function and its route have been removed.
# All GET (authentication) and POST (message handling) requests to '/' are now handled by wechat_interface.





def query_image_result(from_user: str, to_user: str) -> requests.Response:
    """
    查询用户存储的图片识别结果。
    """
    redis_key = f"{REDIS_USER_AI_RESULT_PREFIX}{from_user}"
    stored_value = None
    try:
        stored_value = redis_client.get(redis_key)
    except redis.exceptions.ConnectionError as e:
        logger.error(f"无法从 Redis 获取 AI 图片结果 (连接错误): {redis_key}, 错误: {e}")
        return build_reply(from_user, to_user, NO_REDIS_CONNECTION_REPLY)
    except Exception as e:
        logger.error(f"从 Redis 获取 AI 图片结果时发生未知错误: {redis_key}, 错误: {e}\n{traceback.format_exc()}")
        return build_reply(from_user, to_user, SERVER_INTERNAL_ERROR_REPLY)

    content_to_reply = IMAGE_QUERY_NO_RESULT_REPLY
    if stored_value:
        try:
            timestamp_str, content = stored_value.split('|', 1)
            timestamp = int(timestamp_str)

            if content.startswith("ERROR:"):
                error_message = content[6:]
                content_to_reply = f"抱歉，您的图片处理失败了（{time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(timestamp))}）。\n原因：{error_message} 请尝试重新发送图片。"
                logger.warning(f"为用户 {from_user} 返回存储在 Redis 中的图片处理失败信息: {error_message}")
            else:
                content_to_reply = f"这是您最近一次图片识别的结果（{time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(timestamp))}）:\n\n{content}"
                logger.info(f"为用户 {from_user} 返回存储在 Redis 中的图片识别结果。")
            try:
                redis_client.delete(redis_key)
                logger.debug(f"已清除用户 {from_user} 的 Redis 图片结果缓存 (key: {redis_key})。")
            except Exception as e:
                logger.warning(f"清除 Redis 图片结果缓存失败 for user {from_user}: {e}")

        except ValueError:
            content_to_reply = IMAGE_QUERY_PARSE_ERROR_REPLY
            logger.error(f"解析 Redis 存储值失败 for user {from_user}, key: {redis_key}, value: {stored_value}")
    else:
        logger.info(f"用户 {from_user} 查询图片结果，Redis 中无可用结果 (key: {redis_key})。")

    return build_reply(from_user, to_user, content_to_reply)

def process_text_message(content: str) -> str:
    """
    处理文本消息，调用 AI 并缓存结果。
    """
    logger.info(f"调用 Gemini 处理文本: {content[:50]}...")
    normalized_content = content.strip().lower()
    cache_key = f"{REDIS_TEXT_CACHE_PREFIX}{hashlib.md5(normalized_content.encode('utf-8')).hexdigest()}"

    try:
        cached_answer = redis_client.get(cache_key)
        if cached_answer:
            logger.info(f"从 Redis 缓存中获取文本答案 (key: {cache_key[:10]}...): {cached_answer[:50]}...")
            return cached_answer
    except redis.exceptions.ConnectionError as e:
        logger.warning(f"无法从 Redis 获取文本缓存 (连接错误): {cache_key}, 错误: {e}")
    except Exception as e:
        logger.warning(f"获取文本缓存时发生未知错误: {cache_key}, 错误: {e}\n{traceback.format_exc()}")

    try:
        ai_response_content = generate_with_retry(content, is_image_context=False)
        if ai_response_content:
            try:
                redis_client.set(cache_key, ai_response_content, ex=TEXT_CACHE_EXPIRATION_SECONDS)
                logger.info(f"AI文本答案已存入 Redis 缓存 (key: {cache_key[:10]}...)，有效期 {TEXT_CACHE_EXPIRATION_SECONDS} 秒。")
            except redis.exceptions.ConnectionError as e:
                logger.warning(f"无法将 AI 文本答案存储到 Redis (连接错误): {cache_key}, 错误: {e}")
            except Exception as e:
                logger.warning(f"存储 AI 文本答案到 Redis 时发生未知错误: {cache_key}, 错误: {e}\n{traceback.format_exc()}")
        return ai_response_content
    except Exception as e:
        logger.error(f"处理文本消息时 AI 调用失败: {e}\n{traceback.format_exc()}")
        return AI_SERVICE_UNAVAILABLE_REPLY

def generate_with_retry(prompt: str, image=None, max_retries: int = 3, is_image_context: bool = False) -> str:
    """
    调用 Gemini AI 模型生成内容，支持重试和指数退避。
    """
    retry_count = 0
    ai_api_request_timeout = GEMINI_IMAGE_TIMEOUT if is_image_context else GEMINI_TEXT_TIMEOUT
    logger.debug(f"AI请求超时设置为: {ai_api_request_timeout}秒 (is_image_context={is_image_context})")

    start_overall_ai_time = time.time()
    while retry_count < max_retries:
        try:
            start_single_attempt_time = time.time()
            contents = [prompt]
            if image:
                contents.insert(0, image)

            response = gemini_model.generate_content(
                contents,
                generation_config=GEMINI_GENERATION_CONFIG,
                request_options={"timeout": ai_api_request_timeout}
            )
            
            if response.prompt_feedback and response.prompt_feedback.block_reason:
                block_reason = response.prompt_feedback.block_reason.name
                logger.warning(f"AI 提示被阻断，原因: {block_reason}")
                return f"{AI_BLOCK_REASON_PREFIX}{block_reason}{AI_BLOCK_REASON_SUFFIX}"

            if not response or not response.text:
                raise ValueError("AI returned an empty or invalid response.")

            current_ai_duration = time.time() - start_overall_ai_time
            logger.info(f"AI 生成成功，耗时: {current_ai_duration:.2f}秒 (单次尝试: {time.time()-start_single_attempt_time:.2f}秒)")
            return response.text.strip()
        except Exception as e:
            retry_count += 1
            wait_time = min(2 ** retry_count, 10)
            logger.warning(f"AI 生成失败 (尝试 {retry_count}/{max_retries}), 等待 {wait_time:.2f} 秒: {e}\n{traceback.format_exc()}")
            time.sleep(wait_time)
    logger.error("AI 生成失败，已达到最大重试次数。")
    return AI_SERVICE_UNAVAILABLE_REPLY

def build_reply(from_user: str, to_user: str, content: str) -> requests.Response:
    """
    构建微信回复 XML，支持文本超长时转换为图片回复。
    """
    try:
        cleaned_content = clean_content(content)
        content_bytes = len(cleaned_content.encode('utf-8'))
        reply_xml_str = None

        if content_bytes > WECHAT_TEXT_MAX_BYTES:
            logger.info(f"内容过长({content_bytes}字节 > {WECHAT_TEXT_MAX_BYTES}字节)，尝试转换为图片并回复。")
            img_data = text_to_image(cleaned_content, max_width=MAX_IMG_WIDTH, font_size=FONT_SIZE, line_spacing_factor=LINE_SPACING_FACTOR)
            if img_data:
                if len(img_data) > WECHAT_MAX_IMAGE_UPLOAD_SIZE:
                    logger.warning(f"生成的图片大小 ({len(img_data)/1024:.2f}KB) 超过微信上传限制 ({WECHAT_MAX_IMAGE_UPLOAD_SIZE/1024:.2f}KB)。将回退为截断文本。")
                    truncated_content = clean_content(cleaned_content, max_bytes=WECHAT_TEXT_MAX_BYTES - len(AI_REPLY_TOO_LONG_IMAGE_FAIL_PREFIX.encode('utf-8'))) # 为前缀预留空间
                    reply_xml_str = f"""<xml>
                        <ToUserName><![CDATA[{from_user}]]></ToUserName>
                        <FromUserName><![CDATA[{to_user}]]></FromUserName>
                        <CreateTime>{int(time.time())}</CreateTime>
                        <MsgType><![CDATA[text]]></MsgType>
                        <Content><![CDATA[{escape(AI_REPLY_TOO_LONG_IMAGE_FAIL_PREFIX + truncated_content)}]]></Content>
                    </xml>"""
                else:
                    media_id = upload_image_to_wechat(img_data)
                    if media_id:
                        logger.info(f"图片已成功上传至微信，MediaId: {media_id[:10]}... 使用图片回复。")
                        reply_xml_str = f"""<xml>
                            <ToUserName><![CDATA[{from_user}]]></ToUserName>
                            <FromUserName><![CDATA[{to_user}]]></FromUserName>
                            <CreateTime>{int(time.time())}</CreateTime>
                            <MsgType><![CDATA[image]]></MsgType>
                            <Image><MediaId><![CDATA[{media_id}]]></MediaId></Image>
                        </xml>"""
                    else:
                        logger.warning("图片上传至微信失败，回退到文本回复并截断。")
                        truncated_content = clean_content(cleaned_content, max_bytes=WECHAT_TEXT_MAX_BYTES - len(AI_REPLY_TOO_LONG_IMAGE_FAIL_PREFIX.encode('utf-8')))
                        reply_xml_str = f"""<xml>
                            <ToUserName><![CDATA[{from_user}]]></ToUserName>
                            <FromUserName><![CDATA[{to_user}]]></FromUserName>
                            <CreateTime>{int(time.time())}</CreateTime>
                            <MsgType><![CDATA[text]]></MsgType>
                            <Content><![CDATA[{escape(AI_REPLY_TOO_LONG_IMAGE_FAIL_PREFIX + truncated_content)}]]></Content>
                        </xml>"""
            else:
                logger.warning("文本转换为图片失败，回退到文本回复并截断。")
                truncated_content = clean_content(cleaned_content, max_bytes=WECHAT_TEXT_MAX_BYTES - len(AI_REPLY_TOO_LONG_IMAGE_FAIL_PREFIX.encode('utf-8')))
                reply_xml_str = f"""<xml>
                    <ToUserName><![CDATA[{from_user}]]></ToUserName>
                    <FromUserName><![CDATA[{to_user}]]></FromUserName>
                    <CreateTime>{int(time.time())}</CreateTime>
                    <MsgType><![CDATA[text]]></MsgType>
                    <Content><![CDATA[{escape(AI_REPLY_TOO_LONG_IMAGE_FAIL_PREFIX + truncated_content)}]]></Content>
                </xml>"""
        else:
            logger.info(f"内容在文本限制内({content_bytes}字节)，使用文本回复。")
            reply_xml_str = f"""<xml>
                <ToUserName><![CDATA[{from_user}]]></ToUserName>
                <FromUserName><![CDATA[{to_user}]]></FromUserName>
                <CreateTime>{int(time.time())}</CreateTime>
                <MsgType><![CDATA[text]]></MsgType>
                <Content><![CDATA[{escape(cleaned_content)}]]></Content>
            </xml>"""
        return make_response(reply_xml_str, 200, {'Content-Type': 'application/xml'})

    except Exception as e:
        logger.error(f"构建回复时发生异常: {e}\n{traceback.format_exc()}")
        safe_from_user = from_user if from_user else 'unknown_user'
        safe_to_user = to_user if to_user else 'unknown_app'
        error_xml_str = f"""<xml>
            <ToUserName><![CDATA[{safe_from_user}]]></ToUserName>
            <FromUserName><![CDATA[{safe_to_user}]]></FromUserName>
            <CreateTime>{int(time.time())}</CreateTime>
            <MsgType><![CDATA[text]]></MsgType>
            <Content><![CDATA[{AI_REPLY_EXCEPTION_REPLY}]]></Content>
        </xml>"""
        return make_response(error_xml_str, 500, {'Content-Type': 'application/xml'})

def clean_content(content: str, max_bytes: Union[int, None] = None) -> str:
    """
    清理文本内容，移除Markdown标记、多余空格和连续空行，并可选地按字节截断。
    """
    if not content:
        return ""
    
    # 移除所有Markdown标记，包括但不限于粗体、斜体、删除线、下划线、代码块、引用、列表、链接、图片
    # 尽可能保留换行，除非是代码块或多行引用等
    content = re.sub(r'```.*?```', '', content, flags=re.DOTALL) # 移除代码块
    content = re.sub(r'\|.*?\|', '', content) # 移除表格行
    content = re.sub(r'(\*\*|__|\*|_|`|~~|#+\s*)', '', content) # 粗体、斜体、删除线、下划线、标题
    content = re.sub(r'\[([^\]]+?)\]\(.*?\)', r'\1', content) # 链接只保留文本
    content = re.sub(r'!\[.*?\]\(.*?\)', '', content) # 移除图片链接
    content = re.sub(r'^>\s*', '', content, flags=re.MULTILINE) # 移除引用标记
    content = re.sub(r'^[*-]\s*', '', content, flags=re.MULTILINE) # 移除列表标记

    processed_lines = []
    for paragraph in content.split('\n'):
        if not paragraph.strip():
            processed_lines.append('')
            continue

        # 使用 textwrap 智能断行
        wrapped = textwrap.wrap(paragraph, width=MAX_IMG_WIDTH // (FONT_SIZE // 2)) # 大致估算字符宽度
        for line in wrapped:
            processed_lines.append(line.strip())

    content = '\n'.join(processed_lines)
    # 确保没有连续的多个空行，只保留最多两个空行
    content = re.sub(r'\n{3,}', '\n\n', content)
    content = content.strip()

    if max_bytes is not None:
        encoded_content = content.encode('utf-8')
        if len(encoded_content) > max_bytes:
            logger.warning(f"内容因字节限制被截断: 原始 {len(encoded_content)} 字节，截断至 {max_bytes} 字节。")
            truncated_bytes = encoded_content[:max_bytes]
            # 找到最后一个完整的UTF-8字符的边界
            while not truncated_bytes.decode('utf-8', 'ignore').encode('utf-8') == truncated_bytes:
                truncated_bytes = truncated_bytes[:-1]
            return truncated_bytes.decode('utf-8', 'ignore')
    return content

def text_to_image(text: str, max_width: int = MAX_IMG_WIDTH, font_size: int = FONT_SIZE, line_spacing_factor: float = LINE_SPACING_FACTOR) -> Union[bytes, None]:
    """
    将文本转换为图片。
    """
    try:
        start_time_img_gen = time.time()
        padding = IMAGE_PADDING
        line_spacing = int(font_size * line_spacing_factor)
        
        font = None
        if FONT_PATH:
            font = ImageFont.truetype(FONT_PATH, font_size)
        else:
            font = ImageFont.load_default()

        wrapped_lines = []
        max_line_content_width = max_width - 2 * padding

        for paragraph in text.split('\n'):
            if not paragraph.strip():
                wrapped_lines.append('')
                continue

            current_line_chars = []
            current_line_width = 0
            for char in paragraph:
                # 使用 getbbox 来获取字符的精确宽度，即使是默认字体也能工作
                # getbbox returns (left, top, right, bottom)
                char_bbox = font.getbbox(char)
                char_width = char_bbox[2] - char_bbox[0] # width is right - left

                if current_line_width + char_width <= max_line_content_width:
                    current_line_chars.append(char)
                    current_line_width += char_width
                else:
                    if current_line_chars:
                        wrapped_lines.append("".join(current_line_chars))
                    current_line_chars = [char]
                    current_line_width = char_width
            if current_line_chars:
                wrapped_lines.append("".join(current_line_chars))

        if not wrapped_lines:
            wrapped_lines = [""] # 确保即使文本为空也有一行

        line_height = font_size + line_spacing
        img_height = 2 * padding + len(wrapped_lines) * line_height

        if img_height > MAX_IMG_HEIGHT:
            logger.warning(f"图片高度超过限制 {MAX_IMG_HEIGHT}px，原始高度 {img_height}px，将截断内容。")
            displayable_lines = int((MAX_IMG_HEIGHT - 2 * padding) / line_height) - 2
            
            if displayable_lines < 0:
                displayable_lines = 0
            
            wrapped_lines = wrapped_lines[:displayable_lines]
            
            if len(wrapped_lines) > 0 or displayable_lines == 0: # 即使完全截断也加提示
                wrapped_lines.append("...")
                wrapped_lines.append("(内容过长，已截断)")
            
            img_height = 2 * padding + len(wrapped_lines) * line_height

        img = Image.new("RGB", (max_width, img_height), (255, 255, 255))
        draw = ImageDraw.Draw(img)

        y = padding
        for line in wrapped_lines:
            draw.text((padding, y), line, font=font, fill=(0, 0, 0))
            y += line_height

        watermark = "AI生成内容"
        watermark_font = None
        if FONT_PATH:
            watermark_font = ImageFont.truetype(FONT_PATH, int(font_size * 0.8))
        else:
            watermark_font = ImageFont.load_default()

        # 确保图片有足够的空间绘制水印
        if img.height >= (watermark_font.getbbox(watermark)[3] - watermark_font.getbbox(watermark)[1] + 20):
            watermark_bbox = draw.textbbox((0, 0), watermark, font=watermark_font)
            watermark_width = watermark_bbox[2] - watermark_bbox[0]
            watermark_height = watermark_bbox[3] - watermark_bbox[1]

            draw.text(
                (max_width - watermark_width - 15, img_height - watermark_height - 10),
                watermark,
                font=watermark_font,
                fill=(200, 200, 200)
            )

        output = io.BytesIO()
        img.save(output, format='PNG', optimize=True, quality=85)
        logger.info(f"文本转图片耗时: {time.time()-start_time_img_gen:.2f}秒，图片大小: {len(output.getvalue())/1024:.2f}KB。")
        return output.getvalue()
    except Exception as e:
        logger.error(f"文本转换为图片失败: {e}\n{traceback.format_exc()}")
        return None

def upload_image_to_wechat(image_bytes: bytes) -> Union[str, None]:
    """
    将图片上传到微信服务器，获取 media_id。
    """
    access_token = get_access_token()
    if not access_token:
        logger.error("上传图片失败: 无法获取有效的access_token。")
        return None
    if not image_bytes:
        logger.error("上传图片失败: 图片数据为空。")
        return None
    
    if len(image_bytes) > WECHAT_MAX_IMAGE_UPLOAD_SIZE:
        logger.error(f"上传图片失败: 图片大小 ({len(image_bytes)/1024:.2f}KB) 超过微信上传限制 ({WECHAT_MAX_IMAGE_UPLOAD_SIZE/1024:.2f}KB)。")
        return None

    try:
        url = f"https://api.weixin.qq.com/cgi-bin/media/upload?access_token={access_token}&type=image"
        files = {'media': ('ai_reply.png', image_bytes, 'image/png')}
        logger.info(f"正在上传图片到微信服务器 (大小: {len(image_bytes)/1024:.2f}KB)...")
        start_time_img_upload = time.time()
        resp = requests.post(url, files=files, timeout=WECHAT_MEDIA_UPLOAD_TIMEOUT)
        resp.raise_for_status()
        data = resp.json()
        logger.info(f"图片上传到微信耗时: {time.time()-start_time_img_upload:.2f}秒")
        if 'media_id' in data:
            logger.info(f"图片上传成功，MediaId: {data['media_id'][:10]}...")
            return data['media_id']
        logger.error(f"图片上传至微信失败，微信API返回错误: {data}")
    except requests.exceptions.Timeout:
        logger.error(f"图片上传到微信超时，URL: {url}")
    except requests.exceptions.RequestException as e:
        logger.error(f"图片上传网络请求失败: {e}\n{traceback.format_exc()}")
    except Exception as e:
        logger.error(f"图片上传过程中发生异常: {e}\n{traceback.format_exc()}")
    return None

@app.before_request
def log_request():
    """在每个请求前记录请求信息，便于调试。"""
    logger.debug(f"收到请求: {request.method} {request.url}")
    if request.args:
        logger.debug(f"查询参数: {request.args}")
    if request.method == 'POST' and request.data:
        try:
            body_preview = request.data.decode('utf-8', errors='ignore')[:500]
            logger.debug(f"请求体: {body_preview}...")
        except Exception:
            logger.debug(f"请求体（无法解码）：{request.data[:500]}...")
