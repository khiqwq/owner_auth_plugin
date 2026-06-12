"""用户身份验证插件（MaiBot 1.0 / maibot_sdk 2.x 重写版）

在麦麦生成回复之前，按 QQ 号精确判断当前被回复的发言者是否为配置的用户（主人），
并把对应的身份提示词注入到这一次回复的 prompt 中。

设计：固定槽位 + 「用户数量控制」数字（配置模型见 config.py）。该数字 = 生成并显示的用户槽位
个数（填 N 就生成 N 个），每个槽位各自独立 QQ / 昵称 / 限制群聊群号 / 多行模板 / 启用开关。
把数字调小并保存后，超出的槽位配置会在插件重载时被清空（关「启用此用户」开关则只是临时停用）。

实现要点：
- 用官方 Hook：``chat.receive.after_process``（缓存最近真人发言者）、``maisaka.replyer.before_request``
  （回复阶段经 extra_prompt 注入）、``maisaka.planner.before_request``（可选，行动规划阶段注入）。
- 发言者 QQ 在注入时两级定位：``reply_message_id`` 精确取回 → 本插件缓存（收到消息时存下的那条触发消息）；
  刻意不再用"会话最近消息"兜底——那在群聊里会把身份误判成别的发言者。
- 身份判定只依据平台已验证的 QQ 号；提示词模板支持 {nickname}/{qq}/{display_name}/{msg} 等占位符，
  单遍替换不二次展开，发言者显示名与消息文本均做注入清洗。
- 会话发言者缓存带 TTL（cache_ttl_seconds），超时清理，避免长期运行内存累积。
- 「日志显示等级」可调（INFO/DEBUG/WARNING）；覆写 normalize_plugin_config 兼容旧版配置迁移。
- 全程无平台相关代码，兼容 Linux 部署的麦麦。

配置布局：「插件」页（通用设置，含用户数量控制、日志等级、缓存有效期）、「用户」页（用户1~N，各自
独立 QQ/昵称/限制群聊群号/多行模板）、「非用户」页。每个用户可填「限制群聊群号」：填了则该用户只在
该群被认作用户，留空则所有聊天流（含私聊）都生效；同一 QQ 群专属优先于全局。
作者：风花叶（重构）
许可：GPL-3.0-or-later
"""

from __future__ import annotations

import re
import time
import tomllib
from pathlib import Path
from typing import Any, ClassVar

from maibot_sdk import Command, HookHandler, MaiBotPlugin, PluginConfigBase
from maibot_sdk.types import ErrorPolicy, HookMode, HookOrder

from .config import (
    DEFAULT_NON_OWNER_TEMPLATE as _DEFAULT_NON_OWNER_TEMPLATE,
    DEFAULT_USER_TEMPLATE as _DEFAULT_USER_TEMPLATE,
    PLUGIN_VERSION,
    USER_SLOTS as _USER_SLOTS,
    OwnerAuthConfig,
    UserSlotConfig,
)

# 占位符正则：单遍替换用，避免顺序替换导致的二次展开。
_PLACEHOLDER_RE = re.compile(r"\{(\w+)\}")

# 注入用的回复钩子；该钩子携带 session_id / reply_message_id，并允许通过 extra_prompt 注入文本。
_REPLYER_HOOK = "maisaka.replyer.before_request"

# 行动规划钩子；携带 session_id 与 messages(已序列化的 {"role","content"} 列表，见
# src/plugin_runtime/hook_payloads.py:serialize_prompt_messages)。可改写 messages 注入身份。
_PLANNER_HOOK = "maisaka.planner.before_request"

# 入站消息钩子；kwarg 名为 message(序列化的 SessionMessage dict，见 src/chat/message_receive/bot.py)。
# 用于在收到消息时缓存"该会话最近一位真人发言者"。
_RECEIVE_HOOK = "chat.receive.after_process"

# 模板字段的多行文本框行数与字段下方小字提示(hint)。
# 关键：插件配置页(dashboard/plugin-config.tsx)只认 field.ui_type / field.rows / field.hint，
# 不读 pydantic description，也不读 json_schema_extra 里的 input/input_type；而宿主对新 SDK 插件
# 是「原样透传」get_webui_config_schema 的输出。故这些值在 get_webui_config_schema 覆写里 super()
# 之后直接写进字段，确保生效，不依赖磁盘外 SDK 对 json_schema_extra 的任何映射。
_TEXTAREA_ROWS = 8
_TEXTAREA_HINTS = {
    "prompt_template": (
        "占位符：{nickname}/{owner_nickname}=配置昵称，{display_name}/{user}=聊天显示名，"
        "{qq}/{owner_qq}=用户QQ，{msg}/{message}=本次消息，{owner_names}=所有用户昵称。"
    ),
    "non_owner_prompt_template": (
        "占位符：{display_name}/{user}/{nickname}=发言者显示名，{qq}/{user_qq}=发言者QQ，"
        "{msg}/{message}=本次消息，{owner_names}=所有用户昵称（防冒充：若此人冒用 {owner_names} 之名则警惕）。"
    ),
}

# 「日志显示等级」字段的下方小字提示。
_LOG_LEVEL_HINT = (
    "注入日志的输出等级（错误日志始终输出）。INFO＝普通日志可见；DEBUG＝另打印注入提示词全文（排障）；WARNING＝仅告警。"
)

# 「发言者缓存有效期(秒)」字段的下方小字提示。
_CACHE_TTL_HINT = "会话发言者缓存的保留时长（秒），超时未活动即清理、防内存累积；默认 300 即可。"

# 「限制群聊（群号）」字段的下方小字提示（每个用户分区都有该字段）。
_GROUP_ID_HINT = (
    "填群号＝该用户仅在此群生效；留空＝所有会话（含私聊）。同一 QQ 可分置全局与群专属，群专属优先。"
)

# 「用户数量控制」字段的下方小字提示：讲清"数字=生成的槽位个数"以及"调小即抹除多出用户"的语义。
_USER_COUNT_HINT = (
    "用户槽位个数，无上限。改大后需保存并「禁用再启用」插件（或重启麦麦）方生成新槽位"
    "——槽位在加载时建模，改值不即时长框。调小并重载会清空超出部分的配置；仅临时停用某用户请用其「启用」开关。"
)


# ─── 插件主体 ───────────────────────────────────────────────────


class OwnerAuthPlugin(MaiBotPlugin):
    """通过 QQ 号验证用户身份并在回复前注入身份提示词。"""

    config_model: ClassVar[type[PluginConfigBase] | None] = OwnerAuthConfig

    async def on_load(self) -> None:
        self._bot_qq_account: str | None = None  # 机器人自身 QQ 缓存（懒加载，用于排除自身消息）
        # 收到消息时按 session_id 缓存"最近一位真人发言者"（每会话一条，随活跃会话数有界，并按 TTL 清理）。
        # 存的是精简后的 message dict，便于复用 _extract_identity 统一解析。
        self._recent_by_session: dict[str, dict[str, Any]] = {}
        # 最近一次注入记录（仅保留全局最新一条 + 累计计数，供状态命令查看；天然有界）。
        self._last_injection: dict[str, Any] | None = None
        self._injection_count: int = 0
        self.ctx.logger.info(
            f"[用户身份验证] 插件 v{PLUGIN_VERSION} 已加载（钩子注入模式，已生成 {_USER_SLOTS} 个用户槽位）"
        )

    async def on_unload(self) -> None:
        self._recent_by_session.clear()
        self._last_injection = None
        self.ctx.logger.info("[用户身份验证] 插件已卸载")

    async def on_config_update(self, scope: str, config_data: dict, version: str) -> None:
        # 配置实时读取，无需缓存；此处仅作日志并顺手清一次过期缓存。scope=="self" 为本插件配置热重载。
        if scope == "self":
            if hasattr(self, "_recent_by_session"):  # 防御：极早热重载时 on_load 可能尚未初始化字段
                self._purge_recent_cache()
            self.ctx.logger.info("[用户身份验证] 配置已更新")

    # ─── 旧版配置迁移 + 数量约束 ─────────────────────────────

    def normalize_plugin_config(
        self, config_data: dict[str, Any] | None
    ) -> tuple[dict[str, Any], bool]:
        """把旧版（单用户 [user] / 列表版 [users] / 0.x owner_auth）迁移到固定槽位结构，
        并按 user_count 清空超出的槽位（实现"调小数字即抹除多出用户"）。

        宿主在加载时会调用本方法(已核实 runner_main.py:665-675：先 hasattr 再调用)，并用返回的
        dict 覆盖配置；返回 (配置, 是否有变更)。从磁盘读原始 config.toml 判定旧字段，避免依赖宿主
        版本预处理是否保留旧字段；不抛异常（最坏只是不迁移）。
        """

        data = dict(config_data or {})
        try:
            disk = self._read_disk_config()
            changed = self._migrate_legacy(data, disk if isinstance(disk, dict) else {})
            if changed:
                self.ctx.logger.info("[用户身份验证] 检测到旧版配置，已迁移到固定槽位结构")
            # 无论是否迁移，都按 user_count 清空超出的槽位。
            if self._enforce_user_count(data):
                changed = True
            return data, changed
        except Exception as exc:  # noqa: BLE001 - 迁移失败不影响加载，记日志后按现有配置走
            self.ctx.logger.warning(f"[用户身份验证] 旧版配置迁移失败，按现有配置加载: {exc}")
            return data, False

    @staticmethod
    def _read_disk_config() -> dict[str, Any] | None:
        """读磁盘 config.toml 原始内容；不存在或解析异常时返回 None。"""

        path = Path(__file__).resolve().parent / "config.toml"
        if not path.exists():
            return None
        with path.open("rb") as handle:
            data = tomllib.load(handle)
        return data if isinstance(data, dict) else None

    def _migrate_legacy(self, data: dict[str, Any], disk: dict[str, Any]) -> bool:
        """把磁盘旧配置(disk)的可迁移字段写入 data(目标新配置)。返回是否有改动。

        覆盖三类旧结构 → 固定槽位 [userN]：
        - 单用户版 [user]（user_prompt→user1.prompt_template）。
        - 列表版 [users].entries（共用 user_prompt → 每个迁入槽位的 prompt_template）。
        - 0.x owner_auth.*（开关/非用户模板/User→user_count）与 [userN].owner_qq。
        并清除新模型未知的旧节键 [user]/[users]。幂等：迁移并写回后磁盘即为 [userN] 结构、不再触发。
        """

        changed = False

        # A) 单用户结构 [user] → user1
        single = disk.get("user")
        if isinstance(single, dict) and self._norm_qq(single.get("qq")):
            target = data.setdefault("user1", {})
            # [user] 是权威旧数据 → 覆盖模型默认值。注意：config_data 里 user1 已被模型默认值预填
            # （nickname="用户"、模板=通用），故不能用 "not target.get(key)" 判空，否则 nickname/模板
            # 会被默认值挡住、迁移不过来（曾因此只迁到了 qq）。
            ev = bool(single.get("enabled", True))
            if target.get("enabled") != ev:
                target["enabled"] = ev
                changed = True
            for key, value in (
                ("qq", self._norm_qq(single.get("qq"))),
                ("nickname", single.get("nickname")),
                ("group_id", self._norm_group(single.get("group_id", ""))),
                ("prompt_template", single.get("user_prompt")),
            ):
                if value and target.get(key) != value:
                    target[key] = value
                    changed = True

        # B) 列表版 [users].entries → user1..（共用 user_prompt 写入每个迁入槽位）
        users = disk.get("users")
        if isinstance(users, dict):
            shared = users.get("user_prompt")
            idx = 1
            for entry in users.get("entries") or []:
                if not (isinstance(entry, dict) and self._norm_qq(entry.get("qq"))):
                    continue
                if idx > _USER_SLOTS:
                    break
                target = data.setdefault(f"user{idx}", {})
                vals = {
                    "qq": self._norm_qq(entry.get("qq")),
                    "nickname": entry.get("nickname"),
                    "group_id": self._norm_group(entry.get("group_id", "")),
                    "prompt_template": shared,
                }
                for key, value in vals.items():
                    # entries 是权威旧数据 → 覆盖模型默认值（同 A：user{idx} 已被默认值预填）。
                    if value and target.get(key) != value:
                        target[key] = value
                        changed = True
                idx += 1

        # C) 0.x owner_auth.* 开关/非用户模板/User → 新字段
        owner_auth = disk.get("owner_auth")
        if isinstance(owner_auth, dict):
            plugin_sec = data.setdefault("plugin", {})
            if "User" in owner_auth:
                try:
                    value = max(1, min(_USER_SLOTS, int(owner_auth["User"])))
                    if plugin_sec.get("user_count") != value:
                        plugin_sec["user_count"] = value
                        changed = True
                except (TypeError, ValueError) as exc:
                    self.ctx.logger.warning(
                        f"[用户身份验证] 旧版 owner_auth.User 值无法解析为数字、跳过 user_count 迁移: {exc}"
                    )
            for old_key, new_key in (
                ("enable_auth", "enabled"),
                ("enable_private_inject", "enable_private_inject"),
                ("log_auth_result", "log_result"),
            ):
                if old_key in owner_auth:
                    value = bool(owner_auth[old_key])
                    if plugin_sec.get(new_key) != value:
                        plugin_sec[new_key] = value
                        changed = True
            tpl = owner_auth.get("non_owner_prompt_template")
            if tpl:
                non_owner_sec = data.setdefault("non_owner", {})
                if non_owner_sec.get("non_owner_prompt_template") != tpl:
                    non_owner_sec["non_owner_prompt_template"] = tpl
                    changed = True

        # D) 旧固定槽位 [userN].owner_qq(int, 0.x) → qq
        for i in range(1, _USER_SLOTS + 1):
            old = disk.get(f"user{i}")
            if not isinstance(old, dict) or "owner_qq" not in old:
                continue
            qq = self._norm_qq(old.get("owner_qq"))
            target = data.setdefault(f"user{i}", {})
            if qq and not self._norm_qq(target.get("qq")):
                target["qq"] = qq
                changed = True

        # E) 清除新模型未知的旧节键
        if data.pop("user", None) is not None:
            changed = True
        if data.pop("users", None) is not None:
            changed = True

        # F) 清除超出当前已生成槽位数(_USER_SLOTS)的 [userN] 表：USER_SLOTS 随 user_count 自动增长，
        #    把 user_count 调小后下次导入 USER_SLOTS 会缩小，之前更大规模留下的 [userN] 表对现模型已无
        #    对应字段，必须移除、以免成为未知字段导致配置校验失败。
        for key in [k for k in list(data.keys()) if isinstance(k, str) and re.fullmatch(r"user\d+", k)]:
            if int(key[4:]) > _USER_SLOTS and data.pop(key, None) is not None:
                changed = True

        return changed

    def _enforce_user_count(self, data: dict[str, Any]) -> bool:
        """把超出 user_count 的槽位里"已配置(带 QQ)的用户"清空为默认，返回是否有改动。

        实现"把数字调小并保存后，多出来的用户配置直接抹除"的语义。只清空带 QQ 的槽位（真正配置过
        的用户），未配置(无 QQ)的空槽位不动，避免每次加载都判定为有改动而反复改写磁盘。
        """

        plugin_sec = data.get("plugin")
        raw = plugin_sec.get("user_count", 1) if isinstance(plugin_sec, dict) else 1
        try:
            count = max(1, min(_USER_SLOTS, int(raw)))
        except (TypeError, ValueError) as exc:
            # data 来自磁盘原始配置（未经 pydantic 校验），user_count 可能是垃圾值；按 1 处理并记日志。
            self.ctx.logger.warning(f"[用户身份验证] 迁移期 user_count 非整数、按 1 处理、不清空任何槽位: {exc}")
            count = 1
        changed = False
        for i in range(count + 1, _USER_SLOTS + 1):
            slot = data.get(f"user{i}")
            if isinstance(slot, dict) and self._norm_qq(slot.get("qq")):
                data[f"user{i}"] = {}  # 置空 → 模型用默认值填充，等于抹除该用户配置
                changed = True
        return changed

    # ─── 配置读取辅助 ───────────────────────────────────────

    def _active_user_count(self) -> int:
        """运行时生效的用户数量（读 self.config，运行时可靠），钳制在 1.._USER_SLOTS。"""

        raw = getattr(getattr(self.config, "plugin", None), "user_count", 1)
        try:
            count = int(raw)
        except (TypeError, ValueError) as exc:
            # 正常路径 user_count 已被 pydantic 校验为 int、走不到这里；仅防御异常配置，记 debug。
            self.ctx.logger.debug(f"[用户身份验证] user_count 非整数、回退为 1: {exc}")
            count = 1
        return max(1, min(_USER_SLOTS, count))

    def _cache_ttl(self) -> int:
        """会话缓存有效期（秒），读 self.config，钳制在 10..3600。"""

        raw = getattr(getattr(self.config, "plugin", None), "cache_ttl_seconds", 300)
        try:
            return max(10, min(3600, int(raw)))
        except (TypeError, ValueError) as exc:
            self.ctx.logger.debug(f"[用户身份验证] cache_ttl_seconds 非整数、回退为 300: {exc}")
            return 300

    def _read_config_user_count(self) -> int | None:
        """从磁盘 config.toml 读取 user_count，专供 WebUI schema 构建用。

        构建配置 schema 时 self.config 可能尚未就绪甚至访问即抛异常，磁盘上的值才是用户已保存
        的真值。读不到返回 None。
        """

        try:
            path = Path(__file__).resolve().parent / "config.toml"
            if not path.exists():
                return None
            with path.open("rb") as handle:
                data = tomllib.load(handle)
            plugin_section = data.get("plugin") if isinstance(data, dict) else None
            raw = (plugin_section or {}).get("user_count", 1)
            return max(1, min(_USER_SLOTS, int(raw)))
        except Exception as exc:  # noqa: BLE001 - 读不到就回退，绝不让配置页 500
            self.ctx.logger.debug(f"[用户身份验证] schema 构建期读取磁盘 user_count 失败、回退默认: {exc}")
            return None

    def _user_slots(self) -> list[UserSlotConfig]:
        """仅返回生效数量内的用户槽位（user1..user_count）。"""

        slots: list[UserSlotConfig] = []
        for i in range(1, self._active_user_count() + 1):
            slot = getattr(self.config, f"user{i}", None)
            if slot is not None:
                slots.append(slot)
        return slots

    def _has_configured_user(self) -> bool:
        """是否至少配置了一个启用且带有效 QQ 的用户。未配置时插件整体静默。"""

        for slot in self._user_slots():
            if getattr(slot, "enabled", False) and self._norm_qq(getattr(slot, "qq", "")):
                return True
        return False

    def _configured_owner_names(self) -> str:
        """所有"已启用且配置了有效 QQ"的用户昵称，去重后用「、」连接（供 {owner_names} 占位符用）。

        值来自配置（你自己填的昵称，可信），主要给非用户模板写"若此人冒用了 {owner_names} 的名字…"
        这类防冒充提示用。无已配置用户时返回空串。
        """

        names: list[str] = []
        seen: set[str] = set()
        for slot in self._user_slots():
            if not (getattr(slot, "enabled", False) and self._norm_qq(getattr(slot, "qq", ""))):
                continue
            nick = str(getattr(slot, "nickname", "") or "").strip()
            if nick and nick not in seen:
                seen.add(nick)
                names.append(nick)
        return "、".join(names)

    def _match_user(self, speaker_qq: str, current_group_id: str = "") -> UserSlotConfig | None:
        """按 QQ + 当前群号匹配用户槽位，群专属优先于全局（同 QQ 多槽位时的冲突处理）。

        - 槽位填了「限制群聊群号」→ 仅当当前正处在该群时才匹配（私聊或别的群一律不匹配）。
        - 槽位群号留空 → 全局，所有聊天流（含私聊）都匹配。
        - 群号优先：同一 QQ 若既有命中当前群的群专属槽位、又有全局槽位，取群专属（更精确者优先）。
        - 同一优先级内出现多个重复槽位时取第一个，并记一条 warning 提示配置重复（避免静默歧义）。
        """

        target = self._norm_qq(speaker_qq)
        if not target:
            return None
        current_group = self._norm_group(current_group_id)
        specific: list[UserSlotConfig] = []  # 群号 == 当前群 的槽位（群专属命中）
        globals_: list[UserSlotConfig] = []  # 群号留空（全局）的槽位
        for slot in self._user_slots():
            if not getattr(slot, "enabled", False):
                continue
            if self._norm_qq(getattr(slot, "qq", "")) != target:
                continue
            slot_group = self._norm_group(getattr(slot, "group_id", ""))
            if slot_group:
                if current_group and slot_group == current_group:
                    specific.append(slot)
                # 群专属但不是当前群 → 在此处不生效，跳过
            else:
                globals_.append(slot)
        chosen = specific if specific else globals_
        if not chosen:
            return None
        if len(chosen) > 1:
            self.ctx.logger.warning(
                f"[用户身份验证] QQ {self._mask_qq(target)} 命中多个"
                f"{'群专属' if specific else '全局'}用户槽位（{len(chosen)} 个，"
                f"当前群={current_group or '无/私聊'}）；已取第一个、忽略其余，请检查是否重复配置同一用户"
            )
        return chosen[0]

    @staticmethod
    def _norm_qq(raw: Any) -> str:
        """提取纯数字 QQ；空/全 0/非数字一律返回空串（拒绝 qq=0 误匹配 user_id=0）。"""

        digits = "".join(ch for ch in str(raw or "") if ch.isdigit())
        return digits if digits and digits.strip("0") else ""

    @classmethod
    def _norm_group(cls, raw: Any) -> str:
        """归一化群号：与 QQ 同为纯数字 ID（全 0/非数字→空串，代表无群限制或非群聊）。"""

        return cls._norm_qq(raw)

    @classmethod
    def _mask_qq(cls, raw: Any) -> str:
        """日志/状态展示用的脱敏 QQ：保留首尾各 2 位，中间打码。"""

        digits = cls._norm_qq(raw)
        if not digits:
            return "未知"
        if len(digits) <= 4:
            return digits[0] + "***"
        return f"{digits[:2]}****{digits[-2:]}"

    @staticmethod
    def _sanitize_display(name: Any) -> str:
        """清洗发言者显示名：去花括号/换行/制表/控制字符、压缩空白并截断。

        防止攻击者用群名片/昵称做二阶提示词注入（注入进 extra_prompt）或日志注入。
        """

        text = re.sub(r"[{}\r\n\t]", " ", str(name or ""))
        text = re.sub(r"[\x00-\x1f\x7f]", "", text)
        text = re.sub(r"\s+", " ", text).strip()
        return text[:40]

    @staticmethod
    def _message_text(message: dict[str, Any]) -> str:
        """取发言者本次消息文本（供 {msg}/{message} 占位符用）并做注入清洗，截断；空则返回空串。

        与 _sanitize_display 同口径：去花括号、把换行/制表/控制字符压成空格、合并空白；这样即便用户把
        {msg} 写进模板，攻击者也无法用多行结构化文本伪造指令块来突破模板框定（二阶提示词注入防护）。
        （单遍 _safe_format 本就不会二次展开占位符，这里是额外收紧注入面。）
        """

        text = message.get("processed_plain_text")
        if not isinstance(text, str):
            return ""
        cleaned = re.sub(r"[{}\r\n\t]", " ", text)  # 与 _sanitize_display 同一首遍：花括号/换行/制表→空格
        cleaned = re.sub(r"[\x00-\x1f\x7f]", "", cleaned)
        cleaned = re.sub(r"\s+", " ", cleaned).strip()
        return cleaned[:300]

    @staticmethod
    def _safe_format(template: str, mapping: dict[str, Any]) -> str:
        """单遍替换已知占位符（不会二次展开），未知占位符原样保留，绝不抛异常。"""

        def _repl(match: "re.Match[str]") -> str:
            key = match.group(1)
            return str(mapping[key]) if key in mapping else match.group(0)

        return _PLACEHOLDER_RE.sub(_repl, template or "").strip()

    async def _get_bot_qq(self) -> str:
        """读取并缓存机器人自身 QQ（bot.qq_account），用于排除机器人自己的消息。"""

        cached = getattr(self, "_bot_qq_account", None)
        if cached is not None:
            return cached
        value = ""
        try:
            raw = await self.ctx.config.get("bot.qq_account", "")
            if isinstance(raw, dict):  # 防御：包装层若未解包 envelope
                raw = raw.get("value", "")
            value = self._norm_qq(raw)
        except Exception as exc:  # noqa: BLE001 - 读不到就退化为不排除，绝不影响回复
            self.ctx.logger.warning(f"[用户身份验证] 读取 bot.qq_account 失败、本次不排除机器人自身: {exc}")
        self._bot_qq_account = value
        return value

    # ─── 缓存清理（TTL）─────────────────────────────────────

    def _purge_recent_cache(self) -> None:
        """清理超过 TTL 未活动的会话发言者缓存，避免长期运行内存累积。"""

        ttl = self._cache_ttl()
        now = time.time()
        stale = [
            sid
            for sid, cached in self._recent_by_session.items()
            if isinstance(cached, dict) and now - float(cached.get("_cached_at") or 0) > ttl
        ]
        for sid in stale:
            self._recent_by_session.pop(sid, None)

    # ─── 消息解析 ───────────────────────────────────────────

    async def _resolve_speaker_message(
        self, session_id: str, reply_message_id: str
    ) -> tuple[dict[str, Any] | None, str, str]:
        """定位"机器人正在回复的发言者"消息，返回 (消息, 来源, 诊断)。两级定位：

        1) 精确：用 reply_message_id 按消息号【全局】查（不按 chat_id 限定，避免 stream/session
           维度不一致导致查不到）。
        2) 会话缓存：收到消息时缓存的"本会话最近一位真人发言者"（来自 _RECEIVE_HOOK，不走在线查询，
           即使该消息号不在可查消息库里也能命中；这是实际最常命中的一档）。
        两者都拿不到则返回 (None, "none", 诊断)——刻意不再用"会话最近消息(get_recent)"兜底，因为它在
        群聊里会把身份误判成"最近发的另一个人"；诊断串记录每步结果，便于在日志里定位原因。
        """

        diag: list[str] = []
        if reply_message_id:
            try:
                res = await self.ctx.message.get_by_id(message_id=reply_message_id)
                msg = res.get("message") if isinstance(res, dict) else None
                if isinstance(msg, dict):
                    return msg, "reply_id", ""
                diag.append(f"by_id={'未找到' if isinstance(res, dict) else type(res).__name__}")
            except Exception as exc:  # noqa: BLE001 - 取不到就走下一档，绝不影响回复
                diag.append(f"by_id异常={exc}")

        if session_id:
            cached = self._recent_by_session.get(session_id)
            if isinstance(cached, dict):
                return cached, "cache", ""
            diag.append("cache未命中")

        return None, "none", "; ".join(diag)

    @classmethod
    def _extract_identity(cls, message: dict[str, Any]) -> tuple[str, str, bool, str]:
        """从消息体提取 (发言者QQ, 已清洗显示名, 是否私聊, 当前群号)。

        当前群号：群聊取 group_info.group_id（纯数字，全 0/缺失视为空串）；私聊恒为空串。
        """

        info = message.get("message_info") or {}
        user_info = info.get("user_info") or {}
        group_info = info.get("group_info")

        speaker_qq = str(user_info.get("user_id") or "").strip()
        display_name = cls._sanitize_display(
            user_info.get("user_cardname") or user_info.get("user_nickname") or ""
        )
        is_private = group_info is None
        group_id = cls._norm_group(group_info.get("group_id")) if isinstance(group_info, dict) else ""
        return speaker_qq, display_name, is_private, group_id

    # ─── 提示词构建 ─────────────────────────────────────────

    def _render_user_prompt(
        self, slot: UserSlotConfig, speaker_qq: str, display_name: str, user_message: str = ""
    ) -> str:
        configured_nickname = str(getattr(slot, "nickname", "") or "用户")
        template = str(getattr(slot, "prompt_template", "") or "") or _DEFAULT_USER_TEMPLATE
        mapping = {
            "nickname": configured_nickname,
            "owner_nickname": configured_nickname,
            "display_name": display_name or configured_nickname,
            "user": display_name or configured_nickname,
            "qq": speaker_qq,
            "owner_qq": speaker_qq,
            "user_qq": speaker_qq,
            "msg": user_message,
            "message": user_message,
            "owner_names": self._configured_owner_names(),
        }
        return self._safe_format(template, mapping)

    def _render_non_owner_prompt(
        self, speaker_qq: str, display_name: str, user_message: str = ""
    ) -> str:
        template = (
            str(getattr(self.config.non_owner, "non_owner_prompt_template", "") or "")
            or _DEFAULT_NON_OWNER_TEMPLATE
        )
        shown = display_name or "未知用户"
        mapping = {
            "nickname": shown,
            "owner_nickname": shown,
            "display_name": shown,
            "user": shown,
            "qq": speaker_qq,
            "owner_qq": speaker_qq,
            "user_qq": speaker_qq,
            "msg": user_message,
            "message": user_message,
            "owner_names": self._configured_owner_names(),
        }
        return self._safe_format(template, mapping)

    def _build_identity_prompt(
        self, speaker_qq: str, display_name: str, current_group_id: str = "", user_message: str = ""
    ) -> tuple[str, str] | None:
        """按 QQ 命中与否构建身份提示词，返回 (提示词, 角色) 或 None(应跳过)。"""

        slot = self._match_user(speaker_qq, current_group_id)
        if slot is not None:
            prompt = self._render_user_prompt(slot, speaker_qq, display_name, user_message)
            role = "用户"
        else:
            if not bool(getattr(self.config.non_owner, "enable_non_owner_inject", False)):
                return None
            prompt = self._render_non_owner_prompt(speaker_qq, display_name, user_message)
            role = "非用户"
        if not prompt:
            return None
        return prompt, role

    def _record_injection(
        self, stage: str, role: str, speaker_qq: str, display_name: str, is_private: bool, source: str
    ) -> None:
        """记录最近一次注入（供状态命令查看）。"""

        self._injection_count += 1
        self._last_injection = {
            "stage": stage,
            "role": role,
            "speaker_qq": speaker_qq,
            "display_name": display_name,
            "is_private": is_private,
            "source": source,
        }

    def _log_inject(self, message: str, prompt: str = "") -> None:
        """按配置的「日志显示等级」输出一条注入活动日志；「插件记录注入日志」关闭时不输出。

        等级仅作用于这类常规注入活动日志；异常/错误日志在各自调用点固定用 error/warning，不受此控制。
        log_level=DEBUG 时额外把本次注入的提示词全文一并打出，便于排查"到底注入了什么"。
        """

        if not bool(getattr(self.config.plugin, "log_result", True)):
            return
        level = str(getattr(self.config.plugin, "log_level", "INFO") or "INFO").upper()
        emit = {
            "DEBUG": self.ctx.logger.debug,
            "INFO": self.ctx.logger.info,
            "WARNING": self.ctx.logger.warning,
        }.get(level, self.ctx.logger.info)
        if level == "DEBUG" and prompt:
            emit(f"{message}\n──注入内容全文──\n{prompt}")
        else:
            emit(message)

    # ─── 缓存钩子：收到消息时记录最近发言者 ──────────────────

    @HookHandler(
        _RECEIVE_HOOK,
        name="owner_auth_cache_speaker",
        description="收到消息时缓存该会话最近一位真人发言者，供回复/规划阶段定位身份",
        mode=HookMode.BLOCKING,
        order=HookOrder.EARLY,
        error_policy=ErrorPolicy.SKIP,  # 钩子调用失败（含宿主编码消息 OOM）一律跳过，不拖垮入站处理
    )
    async def cache_recent_speaker(
        self, message: dict[str, Any] | None = None, **kwargs: Any
    ) -> None:
        # 只读观察：不改写消息、不中止链路（返回 None 直接放行）；异常一律吞掉但记 debug，绝不影响入站。
        try:
            if not isinstance(message, dict):
                return None
            info = message.get("message_info") or {}
            user_info = info.get("user_info") or {}
            speaker_qq = self._norm_qq(user_info.get("user_id"))
            if not speaker_qq:
                return None  # 拿不到发言者 QQ（系统/通知类消息）→ 不缓存
            bot_qq = await self._get_bot_qq()
            if bot_qq and speaker_qq == bot_qq:
                return None  # 机器人自己的消息不作为"发言者"
            session_id = str(message.get("session_id") or "").strip()
            if not session_id:
                return None
            # 存精简后的 message dict，便于 _resolve_speaker_message → _extract_identity 统一解析；
            # 额外存 processed_plain_text 供 {msg} 占位符、_cached_at 供 TTL 清理。
            self._recent_by_session[session_id] = {
                "message_info": {
                    "user_info": {
                        "user_id": user_info.get("user_id"),
                        "user_nickname": user_info.get("user_nickname"),
                        "user_cardname": user_info.get("user_cardname"),
                    },
                    "group_info": info.get("group_info"),
                },
                "message_id": message.get("message_id"),
                "timestamp": message.get("timestamp"),
                "processed_plain_text": message.get("processed_plain_text"),
                "_cached_at": time.time(),
            }
            self._purge_recent_cache()
        except Exception as exc:  # noqa: BLE001 - 缓存失败不影响入站处理
            self.ctx.logger.debug(f"[用户身份验证] 缓存发言者失败（已忽略）: {exc}")
        return None

    # ─── 注入钩子：回复阶段 ─────────────────────────────────

    @HookHandler(
        _REPLYER_HOOK,
        name="owner_auth_inject",
        description="按 QQ 号验证用户身份并在回复前注入身份提示词",
        mode=HookMode.BLOCKING,
        order=HookOrder.NORMAL,
        error_policy=ErrorPolicy.SKIP,  # 注入钩子失败一律跳过，绝不影响麦麦正常回复
    )
    async def inject_user_identity(self, **kwargs: Any) -> dict[str, Any] | None:
        try:
            if not bool(getattr(self.config.plugin, "enabled", True)):
                return None

            # 未配置任何用户 → 插件视为惰性，绝不注入（避免新装时对所有人注入警告）。
            if not self._has_configured_user():
                return None

            general_cfg = self.config.plugin
            log_on = bool(getattr(general_cfg, "log_result", True))

            reply_message_id = str(kwargs.get("reply_message_id") or "").strip()
            session_id = str(kwargs.get("session_id") or "").strip()

            message, source, diag = await self._resolve_speaker_message(
                session_id, reply_message_id
            )
            if not message:
                if log_on:
                    self.ctx.logger.info(
                        f"[用户身份验证] 未能定位发言者，跳过注入"
                        f"（reply_id={reply_message_id or '空'}, session={session_id or '空'}, "
                        f"详情={diag or '无'}）"
                    )
                return None

            speaker_qq, display_name, is_private, current_group_id = self._extract_identity(message)
            if not speaker_qq:
                if log_on:
                    self.ctx.logger.info(f"[用户身份验证] 定位到消息但无 QQ，跳过（来源={source}）")
                return None

            if is_private and not bool(getattr(general_cfg, "enable_private_inject", True)):
                return None

            user_message = self._message_text(message)
            built = self._build_identity_prompt(speaker_qq, display_name, current_group_id, user_message)
            if built is None:
                return None
            prompt, role = built

            # extra_prompt 由宿主拼进回复 prompt；保留已有内容再追加，避免覆盖其他插件。
            existing = str(kwargs.get("extra_prompt") or "").strip()
            kwargs["extra_prompt"] = f"{existing}\n\n{prompt}".strip() if existing else prompt

            self._record_injection("replyer", role, speaker_qq, display_name, is_private, source)
            # 按「日志显示等级」输出（默认 INFO，普通日志即可见）；_log_inject 内部判 log_result 开关，
            # DEBUG 等级会额外把 prompt 全文打出。
            self._log_inject(
                f"[用户身份验证] 已为{role}注入身份提示词："
                f"QQ={self._mask_qq(speaker_qq)}, 名称={display_name or '未知'}, "
                f"私聊={is_private}, 来源={source}",
                prompt,
            )

            # modified_kwargs 是整体替换：必须返回完整 kwargs（已原地改 extra_prompt）。
            return {"action": "continue", "modified_kwargs": kwargs}
        except Exception as exc:  # noqa: BLE001 - 注入失败绝不能影响正常回复
            self.ctx.logger.error(f"[用户身份验证] 注入过程出错，已跳过: {exc}", exc_info=True)
            return None

    # ─── 注入钩子：行动规划阶段（可选，默认关）────────────────

    @HookHandler(
        _PLANNER_HOOK,
        name="owner_auth_inject_planner",
        description="（可选）在行动规划请求前注入身份提示词，让规划阶段也认用户",
        mode=HookMode.BLOCKING,
        order=HookOrder.NORMAL,
        error_policy=ErrorPolicy.SKIP,  # 注入钩子失败一律跳过，绝不影响规划
    )
    async def inject_planner_identity(self, **kwargs: Any) -> dict[str, Any] | None:
        try:
            general_cfg = self.config.plugin
            if not bool(getattr(general_cfg, "enabled", True)):
                return None
            if not bool(getattr(general_cfg, "enable_planner_inject", False)):
                return None  # 默认关，需在「插件」页显式开启
            if not self._has_configured_user():
                return None

            messages = kwargs.get("messages")
            if not isinstance(messages, list) or not messages:
                return None

            session_id = str(kwargs.get("session_id") or "").strip()
            # planner 钩子无 reply_message_id，只按会话定位"最近发言者"。
            message, source, diag = await self._resolve_speaker_message(session_id, "")
            if not message:
                if bool(getattr(general_cfg, "log_result", True)):
                    self.ctx.logger.info(
                        f"[用户身份验证] planner 未能定位发言者，跳过注入"
                        f"（session={session_id or '空'}, 详情={diag or '无'}）"
                    )
                return None

            speaker_qq, display_name, is_private, current_group_id = self._extract_identity(message)
            if not speaker_qq:
                return None
            if is_private and not bool(getattr(general_cfg, "enable_private_inject", True)):
                return None

            user_message = self._message_text(message)
            built = self._build_identity_prompt(speaker_qq, display_name, current_group_id, user_message)
            if built is None:
                return None
            prompt, role = built

            self._inject_into_messages(messages, prompt)
            self._record_injection("planner", role, speaker_qq, display_name, is_private, source)
            self._log_inject(
                f"[用户身份验证] 已为{role}注入行动规划提示词："
                f"QQ={self._mask_qq(speaker_qq)}, 来源={source}",
                prompt,
            )

            # messages 已原地改；modified_kwargs 整体替换，返回完整 kwargs。
            return {"action": "continue", "modified_kwargs": kwargs}
        except Exception as exc:  # noqa: BLE001 - 注入失败绝不能影响规划
            self.ctx.logger.error(f"[用户身份验证] planner 注入出错，已跳过: {exc}", exc_info=True)
            return None

    @staticmethod
    def _inject_into_messages(messages: list[Any], prompt: str) -> None:
        """把 prompt 注入 messages：优先并入首条 system 消息的 content；没有就在最前插一条 system。

        messages 是宿主序列化的 {"role","content",...} 列表（hook_payloads.serialize_prompt_messages），
        回传后会被 deserialize_prompt_messages 还原；并入已有 system 的 content(保持结构不变)最稳。
        """

        for msg in messages:
            if isinstance(msg, dict) and msg.get("role") == "system":
                content = msg.get("content")
                if isinstance(content, str):
                    msg["content"] = f"{content}\n\n{prompt}".strip()
                    return
        messages.insert(0, {"role": "system", "content": prompt})

    # ─── 状态查询命令 ───────────────────────────────────────

    @Command(
        "owner_auth_status",
        description="查看用户身份验证插件运行状态",
        pattern=r"^/(?:owner_auth_status|身份验证状态|主人验证状态)\s*$",
    )
    async def cmd_status(
        self, stream_id: str = "", user_id: str = "", group_id: str = "", **kwargs: Any
    ) -> tuple[bool, str, int]:
        try:
            general = self.config.plugin
            active = self._active_user_count()
            configured = sum(
                1
                for slot in self._user_slots()
                if getattr(slot, "enabled", False) and self._norm_qq(getattr(slot, "qq", ""))
            )
            bot_qq = await self._get_bot_qq()
            me = self._norm_qq(user_id)
            hit = self._match_user(me, group_id) if me else None

            lines = [
                "📋 用户身份验证 · 状态",
                f"- 插件启用：{bool(getattr(general, 'enabled', True))}",
                f"- 生效用户槽位：{active}（已配置 QQ：{configured} 个）",
                f"- 私聊注入：{bool(getattr(general, 'enable_private_inject', True))}",
                f"- 非用户注入：{bool(getattr(self.config.non_owner, 'enable_non_owner_inject', False))}",
                f"- 行动规划(planner)注入：{bool(getattr(general, 'enable_planner_inject', False))}",
                f"- 机器人 QQ 已识别：{'是' if bot_qq else '否'}",
                f"- 会话缓存数：{len(self._recent_by_session)}",
                f"- 累计注入次数：{self._injection_count}",
                f"- 你的 QQ：{self._mask_qq(user_id)} → "
                + (f"命中「{getattr(hit, 'nickname', '用户')}」" if hit is not None else "未命中（非用户）"),
            ]
            if self._last_injection:
                li = self._last_injection
                lines.append(
                    f"- 最近一次注入：{li['stage']}/{li['role']} "
                    f"QQ={self._mask_qq(li['speaker_qq'])} 来源={li['source']}"
                )
            text = "\n".join(lines)
            await self.ctx.send.text(text, stream_id)
            # weight=1：拦截原始命令消息，避免麦麦再把 /owner_auth_status 当普通消息处理。
            return True, "owner_auth status sent", 1
        except Exception as exc:  # noqa: BLE001
            self.ctx.logger.warning(f"[用户身份验证] 状态命令处理失败: {exc}")
            return False, f"status command failed: {exc}", 1

    # ─── WebUI：拆分为「插件」「用户」「非用户」三个标签页 ──────

    @staticmethod
    def _force_textarea_fields(sections: dict[str, Any]) -> None:
        """把模板字段直接改成多行 textarea 并补字段下方小字 hint。

        页面只认 field.ui_type / field.rows / field.hint，宿主又原样透传本方法返回的 schema，
        因此直接写这三个键即可，不依赖磁盘外 SDK 对 json_schema_extra 的映射。
        """

        for section in sections.values():
            if not isinstance(section, dict):
                continue
            raw_fields = section.get("fields")
            if isinstance(raw_fields, dict):
                field_items: list[tuple[Any, Any]] = list(raw_fields.items())
            elif isinstance(raw_fields, list):
                field_items = [(None, f) for f in raw_fields]
            else:
                continue
            for fname, fschema in field_items:
                if not isinstance(fschema, dict):
                    continue
                name = fname if fname in _TEXTAREA_HINTS else fschema.get("name")
                if name in _TEXTAREA_HINTS:
                    fschema["ui_type"] = "textarea"
                    fschema["rows"] = _TEXTAREA_ROWS
                    fschema["hint"] = _TEXTAREA_HINTS[name]

    @classmethod
    def _set_field_hint(cls, section: dict[str, Any], field_name: str, hint: str) -> None:
        """给指定 section 下某字段写入 hint（页面字段下方小字）；字段不存在则静默跳过。"""

        cls._set_field_props(section, field_name, {"hint": hint})

    @staticmethod
    def _set_field_props(section: dict[str, Any], field_name: str, props: dict[str, Any]) -> None:
        """给指定 section 下某字段写入若干键（如 hint / min / max）；字段不存在则静默跳过。

        页面数字控件读 field.min / field.max（dashboard/plugin-config.tsx:247-248），而 SDK 不会把
        json_schema_extra 的 min/max 映射成这两个键，故在此显式写入。
        """

        raw_fields = section.get("fields")
        field: Any = None
        if isinstance(raw_fields, dict):
            field = raw_fields.get(field_name)
        elif isinstance(raw_fields, list):
            for candidate in raw_fields:
                if isinstance(candidate, dict) and candidate.get("name") == field_name:
                    field = candidate
                    break
        if isinstance(field, dict):
            field.update(props)

    def get_webui_config_schema(self, **kwargs: Any) -> dict[str, Any]:
        try:
            schema = super().get_webui_config_schema(**kwargs)
        except Exception as exc:  # noqa: BLE001 - 配置页绝不能 500；记一条日志便于诊断（硬规则#2）
            logger = getattr(getattr(self, "ctx", None), "logger", None)
            if logger is not None:
                logger.warning(f"[用户身份验证] 构建配置页 schema 失败，已回退空 schema: {exc}")
            return {}
        if not (isinstance(schema, dict) and isinstance(schema.get("sections"), dict)):
            return schema

        sections = schema["sections"]

        # 把模板字段强制改成多行 textarea 并补上字段下方小字 hint（页面只认这三个键）。
        self._force_textarea_fields(sections)

        # 优先读磁盘 config.toml 的 user_count（schema 构建时 self.config 可能未就绪/抛异常）；
        # 读不到才退化到 self.config，再不行兜底为 1。
        active = self._read_config_user_count()
        if active is None:
            try:
                active = self._active_user_count()
            except Exception as exc:  # noqa: BLE001
                self.ctx.logger.debug(f"[用户身份验证] schema 构建期取 user_count 失败、回退为 1: {exc}")
                active = 1

        # 给「插件」页的数字/下拉字段补 min/max 与 hint。
        if isinstance(sections.get("plugin"), dict):
            self._set_field_hint(sections["plugin"], "user_count", _USER_COUNT_HINT)
            # 显式写 min（无硬上限，不设 max；超出当前已生成槽位的数值会在重载后自动补足）。
            self._set_field_props(sections["plugin"], "user_count", {"min": 1})
            self._set_field_hint(sections["plugin"], "log_level", _LOG_LEVEL_HINT)
            self._set_field_hint(sections["plugin"], "cache_ttl_seconds", _CACHE_TTL_HINT)
            self._set_field_props(sections["plugin"], "cache_ttl_seconds", {"min": 10, "max": 3600})
        # 给每个生效用户的「限制群聊群号」补提示。
        for i in range(1, active + 1):
            user_sec = sections.get(f"user{i}")
            if isinstance(user_sec, dict):
                user_sec["collapsed"] = True  # 用户分区默认折叠，人多时配置页不糊成一屏
                self._set_field_hint(user_sec, "group_id", _GROUP_ID_HINT)

        # 「插件」页：通用设置（含总开关与用户数量控制）。
        plugin_tab_sections = [s for s in ("plugin",) if s in sections]
        # 「用户」页：仅前 N 个用户分区（多余的用户分区不引用 → 在页面中隐藏）。
        users_tab_sections = [f"user{i}" for i in range(1, active + 1) if f"user{i}" in sections]
        # 「非用户」页。
        non_owner_tab_sections = [s for s in ("non_owner",) if s in sections]

        tabs: list[dict[str, Any]] = []
        if plugin_tab_sections:
            tabs.append(
                {"id": "basic", "title": "插件", "icon": "settings", "order": 1, "sections": plugin_tab_sections}
            )
        if users_tab_sections:
            tabs.append(
                {"id": "users", "title": "用户", "icon": "users", "order": 2, "sections": users_tab_sections}
            )
        if non_owner_tab_sections:
            tabs.append(
                {"id": "non_owner", "title": "非用户", "icon": "shield", "order": 3, "sections": non_owner_tab_sections}
            )
        if tabs:
            # Dashboard 按数组顺序渲染标签页、忽略 order 字段，故显式按 order 排序使顺序可控。
            tabs.sort(key=lambda t: t["order"])
            schema["layout"] = {"type": "tabs", "tabs": tabs}
        return schema


def create_plugin() -> OwnerAuthPlugin:
    return OwnerAuthPlugin()
