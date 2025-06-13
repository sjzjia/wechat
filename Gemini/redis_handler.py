# -*- coding: utf-8 -*-
"""
处理与 Redis 缓存的交互逻辑
"""
import json
import traceback

from config import logger, redis_client
from constants import (
    REDIS_USER_AI_RESULT_PREFIX,
    REDIS_TEXT_CACHE_PREFIX,
    AI_RESULT_EXPIRATION_SECONDS,
    TEXT_CACHE_EXPIRATION_SECONDS,
    NO_REDIS_CONNECTION_REPLY,
    IMAGE_QUERY_PARSE_ERROR_REPLY
)

# ==================== Redis 操作封装 ====================
def _is_redis_available():
    """检查 Redis 客户端是否可用。"""
    if redis_client is None:
        logger.warning("Redis 客户端未初始化，操作无法执行。")
        return False
    try:
        redis_client.ping() # 轻量级检查连接
        return True
    except Exception as e: #捕捉所有可能的 redis 连接异常
        logger.error(f"Redis 连接检查失败: {e}", exc_info=True)
        return False

def store_ai_result(user_id: str, result_data: dict):
    """将 AI 处理结果（通常是图片识别后待查询的文本）存储到 Redis。"""
    if not _is_redis_available():
        return NO_REDIS_CONNECTION_REPLY # 或者 False，让调用者处理
    try:
        key = f"{REDIS_USER_AI_RESULT_PREFIX}{user_id}"
        # 存储 JSON 字符串
        redis_client.setex(key, AI_RESULT_EXPIRATION_SECONDS, json.dumps(result_data))
        logger.info(f"用户 [{user_id}] 的 AI 结果已存储到 Redis，键: {key}，有效期: {AI_RESULT_EXPIRATION_SECONDS}s")
        return True
    except Exception as e:
        logger.error(f"存储用户 [{user_id}] AI 结果到 Redis 失败: {e}\n{traceback.format_exc()}")
        return False # 或特定的错误消息

def get_ai_result(user_id: str) -> dict:
    """从 Redis 获取指定用户的 AI 处理结果。"""
    if not _is_redis_available():
        return {"error": NO_REDIS_CONNECTION_REPLY}
    try:
        key = f"{REDIS_USER_AI_RESULT_PREFIX}{user_id}"
        result_json = redis_client.get(key)
        if result_json:
            logger.info(f"从 Redis 获取到用户 [{user_id}] 的 AI 结果，键: {key}")
            try:
                return json.loads(result_json)
            except json.JSONDecodeError as je:
                logger.error(f"解析存储在 Redis 中的用户 [{user_id}] AI 结果 JSON 失败: {je}", exc_info=True)
                # 可以选择删除损坏的数据
                # redis_client.delete(key)
                return {"error": IMAGE_QUERY_PARSE_ERROR_REPLY}
        else:
            logger.info(f"Redis 中未找到用户 [{user_id}] 的 AI 结果，键: {key}")
            return None
    except Exception as e:
        logger.error(f"从 Redis 获取用户 [{user_id}] AI 结果失败: {e}\n{traceback.format_exc()}")
        return {"error": "获取缓存结果时发生内部错误。"}

def delete_ai_result(user_id: str):
    """从 Redis 删除指定用户的 AI 处理结果。"""
    if not _is_redis_available():
        return False
    try:
        key = f"{REDIS_USER_AI_RESULT_PREFIX}{user_id}"
        deleted_count = redis_client.delete(key)
        if deleted_count > 0:
            logger.info(f"已从 Redis 删除用户 [{user_id}] 的 AI 结果，键: {key}")
        else:
            logger.info(f"尝试删除用户 [{user_id}] 的 AI 结果，但键 {key} 不存在于 Redis。")
        return True
    except Exception as e:
        logger.error(f"从 Redis 删除用户 [{user_id}] AI 结果失败: {e}\n{traceback.format_exc()}")
        return False

def cache_text_reply(user_id: str, request_hash: str, reply_content: str):
    """缓存文本消息的回复内容，防止重复处理相同请求。"""
    if not _is_redis_available():
        return
    try:
        # 使用用户ID和请求内容的哈希作为键，确保唯一性
        key = f"{REDIS_TEXT_CACHE_PREFIX}{user_id}:{request_hash}"
        redis_client.setex(key, TEXT_CACHE_EXPIRATION_SECONDS, reply_content)
        logger.info(f"用户 [{user_id}] 的文本回复已缓存，键: {key}，有效期: {TEXT_CACHE_EXPIRATION_SECONDS}s")
    except Exception as e:
        logger.error(f"缓存用户 [{user_id}] 文本回复到 Redis 失败: {e}\n{traceback.format_exc()}")

def get_cached_text_reply(user_id: str, request_hash: str) -> str:
    """获取缓存的文本消息回复内容。"""
    if not _is_redis_available():
        return None
    try:
        key = f"{REDIS_TEXT_CACHE_PREFIX}{user_id}:{request_hash}"
        cached_reply = redis_client.get(key)
        if cached_reply:
            logger.info(f"从 Redis 获取到用户 [{user_id}] 的缓存文本回复，键: {key}")
            # 每次获取到缓存后，可以选择性地刷新其过期时间（如果希望频繁访问的内容保持更久）
            # redis_client.expire(key, TEXT_CACHE_EXPIRATION_SECONDS)
            return cached_reply
        else:
            logger.info(f"Redis 中未找到用户 [{user_id}] 的缓存文本回复，键: {key}")
            return None
    except Exception as e:
        logger.error(f"从 Redis 获取用户 [{user_id}] 缓存文本回复失败: {e}\n{traceback.format_exc()}")
        return None

# 可以在此添加更多针对特定场景的 Redis 操作函数
