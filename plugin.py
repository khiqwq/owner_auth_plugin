"""Owner authentication plugin for MaiBot SDK v2.

The old implementation patched MaiBot internals to inject identity prompts.
This version uses official hooks:

- ``chat.receive.after_process`` caches the latest sender identity.
- ``maisaka.replyer.before_request`` appends the matching identity prompt.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any

from maibot_sdk import Command, HookHandler, MaiBotPlugin
from maibot_sdk.types import ErrorPolicy, HookMode, HookOrder

from .config import OwnerAuthPluginConfig, PLUGIN_VERSION, UserConfig


@dataclass(slots=True)
class AuthInfo:
    user_id: str
    message_id: str
    session_id: str
    display_name: str
    user_message: str
    is_owner: bool
    owner_qq: int
    owner_nickname: str
    prompt_template: str
    timestamp: float
    is_private: bool


@dataclass(slots=True)
class InjectionInfo:
    user_id: str
    session_id: str
    reply_message_id: str
    is_owner: bool
    timestamp: float
    prompt_chars: int


class OwnerAuthPlugin(MaiBotPlugin):
    """Verify senders by QQ number and inject identity hints into replyer prompts."""

    config_model = OwnerAuthPluginConfig

    def __init__(self) -> None:
        super().__init__()
        self._auth_by_message_id: dict[str, AuthInfo] = {}
        self._latest_by_session_id: dict[str, AuthInfo] = {}
        self._last_injection_by_session_id: dict[str, InjectionInfo] = {}

    async def on_load(self) -> None:
        self._auth_by_message_id.clear()
        self._latest_by_session_id.clear()
        self._last_injection_by_session_id.clear()
        configured_users = self._configured_users()
        self.ctx.logger.info(
            "主人身份验证插件 v%s 已按 MaiBot 1.0 Hook 架构加载，启用=%s，授权用户数=%s",
            PLUGIN_VERSION,
            self.config.plugin.enabled and self.config.owner_auth.enable_auth,
            len(configured_users),
        )

    async def on_unload(self) -> None:
        self._auth_by_message_id.clear()
        self._latest_by_session_id.clear()
        self._last_injection_by_session_id.clear()
        self.ctx.logger.info("主人身份验证插件已卸载，身份缓存已清理")

    async def on_config_update(self, scope: str, config_data: dict[str, Any], version: str) -> None:
        del config_data
        self._purge_expired()
        self.ctx.logger.info("主人身份验证插件配置已更新: scope=%s version=%s", scope, version)

    def normalize_plugin_config(self, config_data: dict[str, Any] | None) -> tuple[dict[str, Any], bool]:
        raw_config = dict(config_data or {})
        self._migrate_legacy_user_sections(raw_config)
        return super().normalize_plugin_config(raw_config)

    @staticmethod
    def _migrate_legacy_user_sections(config_data: dict[str, Any]) -> None:
        plugin_section = config_data.setdefault("plugin", {})
        if isinstance(plugin_section, dict):
            plugin_section["version"] = PLUGIN_VERSION
            plugin_section["config_version"] = PLUGIN_VERSION

        owner_auth = config_data.setdefault("owner_auth", {})
        if not isinstance(owner_auth, dict) or "users" in owner_auth:
            return

        configured_count = owner_auth.pop("User", 0)
        try:
            configured_count = max(int(configured_count), 1)
        except (TypeError, ValueError):
            configured_count = 1

        users: list[dict[str, Any]] = []
        max_legacy_index = max(configured_count, 10)
        for index in range(1, max_legacy_index + 1):
            section = config_data.get(f"user{index}")
            if not isinstance(section, dict):
                continue
            owner_qq = section.get("owner_qq", 0)
            try:
                owner_qq_int = int(owner_qq or 0)
            except (TypeError, ValueError):
                owner_qq_int = 0
            if owner_qq_int <= 0 and index > configured_count:
                continue
            users.append(
                {
                    "nickname": str(section.get("nickname") or "用户"),
                    "owner_qq": owner_qq_int,
                    "prompt_template": str(section.get("prompt_template") or ""),
                }
            )

        if users:
            owner_auth["users"] = users

    def _purge_expired(self) -> None:
        ttl = max(int(self.config.owner_auth.cache_ttl_seconds), 10)
        now = time.time()
        expired_message_ids = [
            message_id
            for message_id, info in self._auth_by_message_id.items()
            if now - info.timestamp > ttl
        ]
        for message_id in expired_message_ids:
            self._auth_by_message_id.pop(message_id, None)

        expired_sessions = [
            session_id
            for session_id, info in self._latest_by_session_id.items()
            if now - info.timestamp > ttl
        ]
        for session_id in expired_sessions:
            self._latest_by_session_id.pop(session_id, None)

        expired_injections = [
            session_id
            for session_id, info in self._last_injection_by_session_id.items()
            if now - info.timestamp > ttl
        ]
        for session_id in expired_injections:
            self._last_injection_by_session_id.pop(session_id, None)

    def _configured_users(self) -> dict[int, UserConfig]:
        users: dict[int, UserConfig] = {}
        for user_config in self.config.owner_auth.users:
            owner_qq = int(getattr(user_config, "owner_qq", 0) or 0)
            if owner_qq > 0:
                users[owner_qq] = user_config
        return users

    @staticmethod
    def _mask_user_id(user_id: str | int) -> str:
        raw = str(user_id or "").strip()
        if len(raw) <= 4:
            return raw or "未知"
        return f"{raw[:2]}***{raw[-2:]}"

    @staticmethod
    def _message_text(message: dict[str, Any]) -> str:
        processed = message.get("processed_plain_text")
        if isinstance(processed, str) and processed.strip():
            return processed.strip()

        raw_message = message.get("raw_message")
        if isinstance(raw_message, dict):
            raw_text = raw_message.get("plain_text") or raw_message.get("text")
            if isinstance(raw_text, str):
                return raw_text.strip()
        return ""

    @staticmethod
    def _message_user_info(message: dict[str, Any]) -> tuple[str, str, str]:
        message_info = message.get("message_info")
        if not isinstance(message_info, dict):
            return "", "", ""

        user_info = message_info.get("user_info")
        if not isinstance(user_info, dict):
            return "", "", ""

        user_id = str(user_info.get("user_id") or "").strip()
        nickname = str(user_info.get("user_nickname") or "").strip()
        cardname = str(user_info.get("user_cardname") or "").strip()
        return user_id, nickname, cardname

    @staticmethod
    def _is_private_message(message: dict[str, Any]) -> bool:
        message_info = message.get("message_info")
        if not isinstance(message_info, dict):
            return False
        group_info = message_info.get("group_info")
        return not isinstance(group_info, dict) or not str(group_info.get("group_id") or "").strip()

    def _build_auth_info(self, message: dict[str, Any]) -> AuthInfo | None:
        user_id, nickname, cardname = self._message_user_info(message)
        if not user_id:
            return None

        configured_users = self._configured_users()
        if not configured_users:
            return None

        message_id = str(message.get("message_id") or "").strip()
        session_id = str(message.get("session_id") or "").strip()
        user_message = self._message_text(message)
        display_name = cardname or nickname or user_id

        try:
            numeric_user_id = int(user_id)
        except (TypeError, ValueError):
            numeric_user_id = -1

        matched_user = configured_users.get(numeric_user_id)
        is_owner = matched_user is not None
        if matched_user is not None:
            owner_qq = int(matched_user.owner_qq)
            owner_nickname = str(matched_user.nickname or "用户")
            prompt_template = str(matched_user.prompt_template or "")
        else:
            owner_qq = 0
            owner_nickname = ""
            prompt_template = str(self.config.owner_auth.non_owner_prompt_template or "")

        return AuthInfo(
            user_id=user_id,
            message_id=message_id,
            session_id=session_id,
            display_name=display_name,
            user_message=user_message,
            is_owner=is_owner,
            owner_qq=owner_qq,
            owner_nickname=owner_nickname,
            prompt_template=prompt_template,
            timestamp=time.time(),
            is_private=self._is_private_message(message),
        )

    def _store_auth_info(self, info: AuthInfo) -> None:
        if info.message_id:
            self._auth_by_message_id[info.message_id] = info
        if info.session_id:
            self._latest_by_session_id[info.session_id] = info

    def _lookup_auth_info(self, session_id: str, reply_message_id: str) -> AuthInfo | None:
        self._purge_expired()
        if reply_message_id:
            info = self._auth_by_message_id.get(reply_message_id)
            if info is not None:
                return info
        if session_id:
            return self._latest_by_session_id.get(session_id)
        return None

    def _render_prompt(self, info: AuthInfo) -> str:
        if info.is_owner:
            template = info.prompt_template or (
                "【确认用户身份】：当前发言者是你的真正用户{display_name}(QQ:{owner_qq})，{msg}\n"
                "身份验证通过，请以用户的身份对待此人。"
            )
            values = {
                "display_name": info.display_name,
                "owner_qq": info.owner_qq,
                "msg": info.user_message,
                "owner_nickname": info.owner_nickname,
                "user": info.display_name,
            }
        else:
            template = info.prompt_template or self.config.owner_auth.non_owner_prompt_template
            values = {
                "msg": info.user_message,
                "display_name": info.display_name,
                "user_qq": info.user_id,
                "user": info.display_name,
            }

        try:
            return str(template).replace("{{", "{").replace("}}", "}").format(**values).strip()
        except Exception as exc:
            self.ctx.logger.warning("身份提示词模板格式化失败，将使用兜底提示: %s", exc)
            if info.is_owner:
                return f"【确认用户身份】：当前发言者是你的真正用户{info.display_name}(QQ:{info.owner_qq})。"
            return f"【身份验证失败】：当前发言者不是已配置用户，QQ号为 {info.user_id}，名称为 {info.display_name}。"

    @HookHandler(
        "chat.receive.after_process",
        name="owner_auth_cache_message",
        description="缓存最新消息的 QQ 身份验证结果",
        mode=HookMode.BLOCKING,
        order=HookOrder.EARLY,
        timeout_ms=3000,
        error_policy=ErrorPolicy.SKIP,
    )
    async def cache_message_auth(self, message: dict[str, Any] | None = None, **kwargs: Any) -> dict[str, Any] | None:
        del kwargs
        if message is None or not self.config.plugin.enabled or not self.config.owner_auth.enable_auth:
            return None

        info = self._build_auth_info(message)
        if info is None:
            return None

        self._store_auth_info(info)
        if self.config.owner_auth.log_auth_result:
            if info.is_owner:
                self.ctx.logger.info("用户验证成功: %s(%s)", info.owner_nickname or info.display_name, info.user_id)
            else:
                self.ctx.logger.info("用户验证失败: %s(%s) 不是已配置用户", info.display_name, info.user_id)

        if self.config.debug.enable_debug or self.config.debug.show_detailed_info:
            self.ctx.logger.debug(
                "身份缓存: session=%s message=%s private=%s owner=%s text=%r",
                info.session_id,
                info.message_id,
                info.is_private,
                info.is_owner,
                info.user_message[:120],
            )
        return {"action": "continue", "modified_kwargs": {"message": message}}

    @HookHandler(
        "maisaka.replyer.before_request",
        name="owner_auth_inject_replyer_prompt",
        description="在 replyer 请求前注入 QQ 身份验证提示词",
        mode=HookMode.BLOCKING,
        order=HookOrder.EARLY,
        timeout_ms=3000,
        error_policy=ErrorPolicy.SKIP,
    )
    async def inject_replyer_prompt(self, **kwargs: Any) -> dict[str, Any] | None:
        if not self.config.plugin.enabled or not self.config.owner_auth.enable_auth:
            return None

        session_id = str(kwargs.get("session_id") or "").strip()
        reply_message_id = str(kwargs.get("reply_message_id") or "").strip()
        info = self._lookup_auth_info(session_id, reply_message_id)
        if info is None:
            return None

        if info.is_private and not self.config.owner_auth.enable_private_inject:
            return None

        prompt = self._render_prompt(info)
        if not prompt:
            return None

        original_extra_prompt = str(kwargs.get("extra_prompt") or "").strip()
        if original_extra_prompt:
            kwargs["extra_prompt"] = f"{original_extra_prompt}\n\n{prompt}"
        else:
            kwargs["extra_prompt"] = prompt

        if session_id:
            self._last_injection_by_session_id[session_id] = InjectionInfo(
                user_id=info.user_id,
                session_id=session_id,
                reply_message_id=reply_message_id,
                is_owner=info.is_owner,
                timestamp=time.time(),
                prompt_chars=len(prompt),
            )

        if self.config.debug.enable_debug:
            self.ctx.logger.debug(
                "已注入身份提示词: session=%s reply_message=%s user=%s owner=%s",
                session_id,
                reply_message_id,
                info.user_id,
                info.is_owner,
            )
        if self.config.owner_auth.log_auth_result:
            self.ctx.logger.info(
                "身份提示词已注入 replyer: user=%s owner=%s session=%s reply_message=%s",
                self._mask_user_id(info.user_id),
                info.is_owner,
                session_id or "未知",
                reply_message_id or "最近消息",
            )
        return {"action": "continue", "modified_kwargs": kwargs}

    @Command(
        "owner_auth_status",
        description="查看主人身份验证插件状态",
        pattern=r"^/(?:身份验证状态|主人验证状态|owner_auth_status)\s*$",
        intercept_message_level=1,
    )
    async def handle_status(
        self,
        stream_id: str = "",
        user_id: str = "",
        **kwargs: Any,
    ) -> tuple[bool, str, bool]:
        del kwargs
        self._purge_expired()

        configured_users = self._configured_users()
        current_user_id = str(user_id or "").strip()
        try:
            current_user_num = int(current_user_id)
        except (TypeError, ValueError):
            current_user_num = -1

        matched_user = configured_users.get(current_user_num)
        normalized_stream_id = str(stream_id or "").strip()
        latest_info = self._latest_by_session_id.get(normalized_stream_id)
        latest_injection = self._last_injection_by_session_id.get(normalized_stream_id)

        lines = [
            "主人身份验证插件状态",
            f"- 插件启用: {self.config.plugin.enabled}",
            f"- 身份验证启用: {self.config.owner_auth.enable_auth}",
            f"- 私聊注入: {self.config.owner_auth.enable_private_inject}",
            f"- 授权用户数: {len(configured_users)}",
            f"- 当前用户: {self._mask_user_id(current_user_id)}",
            f"- 当前用户命中: {bool(matched_user)}",
            f"- 当前会话缓存: {'有' if latest_info else '无'}",
            f"- 当前会话最近注入: {'有' if latest_injection else '无'}",
            f"- 消息缓存数: {len(self._auth_by_message_id)}",
        ]
        if matched_user is not None:
            lines.append(f"- 命中昵称: {matched_user.nickname}")
        if latest_info is not None:
            age = max(0, int(time.time() - latest_info.timestamp))
            lines.append(
                f"- 最近缓存: user={self._mask_user_id(latest_info.user_id)} owner={latest_info.is_owner} age={age}s"
            )
        if latest_injection is not None:
            injection_age = max(0, int(time.time() - latest_injection.timestamp))
            lines.append(
                f"- 最近注入: user={self._mask_user_id(latest_injection.user_id)} "
                f"owner={latest_injection.is_owner} age={injection_age}s chars={latest_injection.prompt_chars}"
            )
        return True, "\n".join(lines), True


def create_plugin() -> OwnerAuthPlugin:
    return OwnerAuthPlugin()
