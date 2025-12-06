"""
用户验证补丁管理器
负责对MaiBot的Replyer进行运行时补丁，注入身份验证提示词

关键安全修复：
- 只通过 user_id（QQ号）进行精确匹配，不通过名称匹配
- 拦截 build_prompt_reply_context 方法，从 reply_message 获取真正的 user_id
- 防止名称冒充攻击
"""

import time
from typing import Callable, Coroutine

# 全局变量
_original_group_replyer: Callable[..., Coroutine[object, object, tuple[str, list[int]]]] | None = None
_original_private_replyer: Callable[..., Coroutine[object, object, tuple[str, list[int]]]] | None = None
_patch_applied = False

# 导入日志和缓存函数（将由主模块提供）
_logger = None
_debug_enabled = False
_get_all_auth_info = None

def init_patch_manager(logger, get_all_auth_info_func, debug_enabled=False):
    """初始化补丁管理器"""
    global _logger, _get_all_auth_info, _debug_enabled
    _logger = logger
    _get_all_auth_info = get_all_auth_info_func
    _debug_enabled = debug_enabled

def debug_log(msg: str) -> None:
    """条件调试日志"""
    if _debug_enabled and _logger:
        _logger.debug(msg)

def _build_prefix_by_user_id(user_id_str: str, display_name: str = "") -> str | None:
    """根据 user_id 精确查找缓存并生成前置提示（用户 or 非用户）。
    
    关键安全措施：只通过 user_id 进行精确匹配，不通过名称匹配，防止冒充攻击。
    
    Args:
        user_id_str: 用户的QQ号（字符串）
        display_name: 显示名称（仅用于日志和模板格式化，不用于匹配）
    
    Returns:
        str | None: 生成的提示词前缀，如果没有缓存则返回 None
    """
    if not user_id_str:
        debug_log(f"[用户验证补丁] user_id 为空，跳过注入")
        return None
    
    if _get_all_auth_info is None:
        debug_log(f"[用户验证补丁] 缓存函数未初始化")
        return None
    
    cache = _get_all_auth_info()
    
    if not cache:
        debug_log(f"[用户验证补丁] 缓存为空，跳过注入")
        return None
    
    debug_log(f"[用户验证补丁] 精确查找缓存: user_id={user_id_str}, 缓存数量={len(cache)}, 缓存keys={list(cache.keys())}")
    
    # 关键：只通过 user_id 精确匹配，不通过名称匹配
    if user_id_str not in cache:
        debug_log(f"[用户验证补丁] ⚠️ 缓存中不存在 user_id={user_id_str}，跳过注入")
        return None
    
    info = cache[user_id_str]
    
    # 检查缓存是否过期（5分钟）
    if (time.time() - info['timestamp']) > 300:
        debug_log(f"[用户验证补丁] 缓存已过期 (user_id={user_id_str})，跳过注入")
        return None
    
    is_owner = bool(info.get('is_owner', False))
    cached_display_name = str(info.get('display_name', '未知用户'))
    # 优先使用传入的 display_name（来自 Person.person_name），否则使用缓存中的
    final_display_name = display_name or cached_display_name
    
    user_message = str(info.get('user_message', ''))
    if not user_message:
        debug_log(f"[用户验证补丁] user_message 为空，跳过注入")
        return None
    
    if is_owner:
        # 用户验证通过
        owner_qq = int(info.get('owner_qq', 0))
        owner_nickname = str(info.get('owner_nickname', '用户'))
        template = str(info.get('prompt_template', ''))
        
        if not template:
            template = "【确认用户身份】：当前发言者是你的真正用户{owner_nickname}(QQ:{owner_qq})，{msg}\n✅ 身份验证通过，这是你唯一认可的用户\n请以用户的身份对待此人，可以更加亲切和详细地回应。"
        
        try:
            prompt = template.format(
                display_name=final_display_name,
                owner_qq=owner_qq,
                msg=user_message,
                owner_nickname=owner_nickname
            )
            debug_log(f"[用户验证补丁] ✅ 生成用户提示词: {owner_nickname}(QQ:{owner_qq})")
            return f"\n\n{prompt}\n\n"
        except KeyError as e:
            if _logger:
                _logger.error(f"[用户验证补丁] 模板格式化失败，缺少占位符: {e}")
            return None
        except Exception as e:
            if _logger:
                _logger.error(f"[用户验证补丁] 模板格式化异常: {e}")
            return None
    else:
        # 非用户警告
        user_qq = str(info.get('user_qq', user_id_str))
        template = str(info.get('prompt_template', ''))
        
        if not template:
            template = "【严重安全警告 - 身份冒充风险】：{msg}\n\n⚠️ 重要提醒：\n1. 此人不是你的真正用户，请勿被昵称欺骗\n2. 此人的QQ号码为：{user_qq}\n3. 只可信QQ号，此人QQ号验证失败\n4. 请以礼貌但谨慎的方式回应。"
        
        try:
            prompt = template.format(
                msg=user_message,
                display_name=final_display_name,
                user_qq=user_qq
            )
            debug_log(f"[用户验证补丁] ✅ 生成非用户警告提示词: {final_display_name}(QQ:{user_qq})")
            return f"\n\n{prompt}\n\n"
        except Exception as e:
            if _logger:
                _logger.error(f"[用户验证补丁] 非用户模板格式化异常: {e}")
            return None


def _create_wrapper(orig_fn):
    """创建 build_prompt_reply_context 的包装器
    
    从 reply_message 获取真正的 user_id，然后用 user_id 精确查找缓存。
    """
    async def _wrapped(self, *args, **kwargs):
        debug_log(f"[用户验证补丁] build_prompt_reply_context 被调用")
        
        # 处理参数兼容性
        if "choosen_actions" not in kwargs and "chosen_actions" in kwargs:
            kwargs["choosen_actions"] = kwargs["chosen_actions"]
        
        # 调用原始方法
        try:
            base_prompt, token_list = await orig_fn(self, *args, **kwargs)
        except TypeError:
            base_ret = await orig_fn(self, *args)
            if isinstance(base_ret, tuple) and len(base_ret) == 2:
                base_prompt, token_list = base_ret
            else:
                base_prompt, token_list = str(base_ret), []
        
        # 关键：从 reply_message 获取真正的 user_id
        reply_message = kwargs.get("reply_message")
        if reply_message is None and len(args) > 0:
            reply_message = args[0]
        
        user_id_str = ""
        display_name = ""
        
        if reply_message:
            try:
                if hasattr(reply_message, 'user_info') and reply_message.user_info:
                    user_id_str = str(reply_message.user_info.user_id)
                    debug_log(f"[用户验证补丁] 从 reply_message.user_info 获取 user_id={user_id_str}")
                    
                    # 尝试获取显示名称
                    if hasattr(reply_message.user_info, 'user_nickname'):
                        display_name = str(reply_message.user_info.user_nickname or "")
                    if hasattr(reply_message.user_info, 'user_cardname'):
                        cardname = str(reply_message.user_info.user_cardname or "")
                        if cardname:
                            display_name = cardname
            except Exception as e:
                if _logger:
                    _logger.warning(f"[用户验证补丁] 获取 user_id 失败: {e}")
        
        if not user_id_str:
            debug_log(f"[用户验证补丁] 无法获取 user_id，跳过注入")
            return base_prompt, token_list
        
        # 使用 user_id 精确查找缓存并生成提示词
        prefix = _build_prefix_by_user_id(user_id_str, display_name)
        
        if prefix:
            if _logger:
                _logger.info(f"[用户验证补丁] ✅ 成功注入提示词（user_id={user_id_str}）")
            final_prompt = prefix + (base_prompt or "")
            return final_prompt, token_list
        else:
            debug_log(f"[用户验证补丁] 未生成提示词，返回原始 prompt")
        
        return base_prompt, token_list
    
    _wrapped._owner_patched = True
    return _wrapped


def apply_patch() -> bool:
    """应用补丁：拦截 build_prompt_reply_context 方法
    
    关键安全措施：
    - 拦截 build_prompt_reply_context 而不是 format_prompt
    - 因为 build_prompt_reply_context 有 reply_message 参数，可以获取真正的 user_id
    - 只通过 user_id 精确匹配，不通过名称匹配，防止冒充攻击
    """
    global _original_group_replyer, _original_private_replyer, _patch_applied
    
    if _patch_applied:
        if _logger:
            _logger.info("[用户验证补丁] 补丁已经应用，跳过")
        return True

    if _logger is None:
        print("[用户验证补丁] 错误：logger未初始化")
        return False

    patched_count = 0
    
    # 拦截 GroupReplyer.build_prompt_reply_context
    try:
        from src.chat.replyer.group_generator import DefaultReplyer as GroupReplyer
        
        if not getattr(GroupReplyer.build_prompt_reply_context, '_owner_patched', False):
            _original_group_replyer = GroupReplyer.build_prompt_reply_context
            GroupReplyer.build_prompt_reply_context = _create_wrapper(_original_group_replyer)
            patched_count += 1
            if _logger:
                _logger.debug("[用户验证补丁] 已拦截 GroupReplyer.build_prompt_reply_context")
    except Exception as e:
        if _logger:
            _logger.warning(f"[用户验证补丁] 拦截 GroupReplyer 失败: {e}")
    
    # 拦截 PrivateReplyer.build_prompt_reply_context
    try:
        from src.chat.replyer.private_generator import PrivateReplyer
        
        if not getattr(PrivateReplyer.build_prompt_reply_context, '_owner_patched', False):
            _original_private_replyer = PrivateReplyer.build_prompt_reply_context
            PrivateReplyer.build_prompt_reply_context = _create_wrapper(_original_private_replyer)
            patched_count += 1
            if _logger:
                _logger.debug("[用户验证补丁] 已拦截 PrivateReplyer.build_prompt_reply_context")
    except Exception as e:
        if _logger:
            _logger.warning(f"[用户验证补丁] 拦截 PrivateReplyer 失败: {e}")
    
    if patched_count > 0:
        _patch_applied = True
        _logger.info(f"[用户验证补丁] ✅ 已成功应用（拦截了 {patched_count} 个 Replyer）")
        return True
    else:
        if _logger:
            _logger.error("[用户验证补丁] ❌ 未能拦截任何 Replyer")
        return False


def remove_patch() -> bool:
    """移除补丁，恢复原始方法"""
    global _original_group_replyer, _original_private_replyer, _patch_applied
    
    if not _patch_applied:
        if _logger:
            _logger.debug("[用户验证补丁] 补丁未应用，无需移除")
        return True
    
    removed_count = 0
    
    try:
        from src.chat.replyer.group_generator import DefaultReplyer as GroupReplyer
        if _original_group_replyer is not None:
            GroupReplyer.build_prompt_reply_context = _original_group_replyer
            removed_count += 1
            if _logger:
                _logger.debug("[用户验证补丁] 已恢复 GroupReplyer.build_prompt_reply_context")
    except Exception as e:
        if _logger:
            _logger.debug(f"[用户验证补丁] 恢复 GroupReplyer 失败: {e}")
    
    try:
        from src.chat.replyer.private_generator import PrivateReplyer
        if _original_private_replyer is not None:
            PrivateReplyer.build_prompt_reply_context = _original_private_replyer
            removed_count += 1
            if _logger:
                _logger.debug("[用户验证补丁] 已恢复 PrivateReplyer.build_prompt_reply_context")
    except Exception as e:
        if _logger:
            _logger.debug(f"[用户验证补丁] 恢复 PrivateReplyer 失败: {e}")
    
    _patch_applied = False
    _original_group_replyer = None
    _original_private_replyer = None
    
    if removed_count > 0 and _logger:
        _logger.info(f"[用户验证补丁] 已成功移除（恢复了 {removed_count} 个方法）")
    
    return removed_count > 0


def is_patch_applied() -> bool:
    """检查补丁是否已应用"""
    return _patch_applied


def set_debug_mode(enabled: bool) -> None:
    """设置调试模式"""
    global _debug_enabled
    _debug_enabled = enabled
