# -*- coding: utf-8 -*-
import os
"""
存放应用中使用的常量
"""

# ==================== 用户命令 ====================
QUERY_IMAGE_RESULT_COMMAND = "查询图片结果"

# ==================== 回复消息常量 ====================
INITIAL_IMAGE_PROCESSING_MESSAGE = "图片已收到，AI正在努力识别中，请耐心等待10-20秒后发送“查询图片结果”来获取。[抱拳]"
UNSUPPORTED_MESSAGE_TYPE_REPLY = "暂不支持该类型的消息，请发送文本或图片。"
SERVER_INTERNAL_ERROR_REPLY = "服务器内部错误，请稍后重试。"
AI_SERVICE_UNAVAILABLE_REPLY = "AI 服务暂时不可用，请稍后再试。"
IMAGE_DOWNLOAD_FAILED_REPLY = "抱歉，图片下载失败，请检查网络或图片链接是否有效，然后重试。"
IMAGE_PROCESSING_FAILED_REPLY = "抱歉，图片处理失败，请重试。"
IMAGE_QUERY_NO_RESULT_REPLY = "AI正在努力识别中，或您目前没有待查询的图片识别结果，或者结果已过期。请先发送一张图片让我识别。[抱拳]"
IMAGE_QUERY_PARSE_ERROR_REPLY = "抱歉，无法解析存储的图片识别结果，请重试或重新发送图片。"
AI_REPLY_TOO_LONG_IMAGE_FAIL_PREFIX = "AI回复超长，转图片失败。以下为截断内容：\n"
AI_REPLY_EXCEPTION_REPLY = "AI回复异常，请稍后重试。"
ACCESS_TOKEN_FETCH_FAILED_REPLY = "抱歉，无法获取微信服务凭证，请联系管理员。"
UNSAFE_URL_REPLY = "抱歉，检测到图片链接可能存在安全风险，已拒绝处理。"
AI_BLOCK_REASON_PREFIX = "抱歉，AI 认为您提问的内容或图片可能存在问题，已被安全策略阻断（原因："
AI_BLOCK_REASON_SUFFIX = "）。请尝试换一种方式提问或更换图片。"
NO_REDIS_CONNECTION_REPLY = "抱歉，目前无法连接到结果存储服务，请稍后再试。"
VOICE_MESSAGE_EMPTY_RESULT_REPLY = "抱歉，语音识别结果为空，请确保语音清晰。"
VOICE_MESSAGE_PROCESSING_FAILED_REPLY = "抱歉，语音识别失败，请稍后重试或尝试发送文本消息。"
WELCOME_MESSAGE_REPLY = "欢迎关注！我是AI助手，您可以向我提问或发送图片让我识别。"
TEXT_SAFETY_REPLY = "抱歉，您的消息可能包含了不安全的内容，无法处理。"

# ==================== Redis 键前缀和过期时间 ====================
REDIS_USER_AI_RESULT_PREFIX = "wechat_ai_result:"
REDIS_TEXT_CACHE_PREFIX = "wechat_text_cache:"
AI_RESULT_EXPIRATION_SECONDS = 5 * 60  # 图片识别结果缓存时间
TEXT_CACHE_EXPIRATION_SECONDS = 5 * 60  # 文本回复缓存时间

# 微信文本消息限制 (字节)
WECHAT_TEXT_MAX_BYTES = 2000 # 微信文本消息限制 2048 字节，这里取安全线 2000
