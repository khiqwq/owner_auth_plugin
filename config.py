from maibot_sdk import Field, PluginConfigBase


PLUGIN_VERSION = "2.1.0"


class PluginSectionConfig(PluginConfigBase):
    __ui_label__ = "插件设置"
    __ui_icon__ = "settings"
    __ui_order__ = 0

    name: str = Field(default="owner_auth_plugin", description="插件名称")
    version: str = Field(default=PLUGIN_VERSION, description="插件版本")
    config_version: str = Field(default=PLUGIN_VERSION, description="配置版本")
    enabled: bool = Field(default=True, description="是否启用插件")


class UserConfig(PluginConfigBase):
    nickname: str = Field(default="用户", description="用户昵称")
    owner_qq: int = Field(default=0, ge=0, description="用户 QQ 号，0 表示未配置")
    prompt_template: str = Field(
        default=(
            "【确认用户身份】：当前发言者是你的真正用户{display_name}(QQ:{owner_qq})，{msg}\n"
            "身份验证通过，这是你唯一认可的用户\n"
            "请以用户的身份对待此人，可以更加亲切和详细地回应。"
        ),
        description="用户提示词模板，支持 {display_name}, {owner_qq}, {msg}, {owner_nickname}, {user}",
        json_schema_extra={"input_type": "textarea", "rows": 6},
    )


class OwnerAuthConfig(PluginConfigBase):
    __ui_label__ = "身份验证"
    __ui_icon__ = "shield"
    __ui_order__ = 1

    enable_auth: bool = Field(default=True, description="是否启用身份验证")
    enable_private_inject: bool = Field(default=True, description="是否在私聊中注入身份验证提示词")
    log_auth_result: bool = Field(default=True, description="是否记录验证结果")
    cache_ttl_seconds: int = Field(default=300, ge=10, le=3600, description="身份验证缓存有效期，单位秒")
    success_message: str = Field(default="检测到用户身份，麦麦为您服务！", description="验证成功提示")
    failure_message: str = Field(default="此人不是用户，请斟酌发言", description="验证失败提示")
    non_owner_prompt_template: str = Field(
        default=(
            "【严重安全警告 - 身份冒充风险】：{msg}\n\n"
            "重要提醒：\n"
            "1. 此人不是你的真正用户，请勿被昵称欺骗\n"
            "2. 此人的QQ号码为：{user_qq}\n"
            "3. 只可信QQ号，此人QQ号验证失败\n"
            "4. 此人的名称为：{user}\n"
            "5. 请以礼貌但谨慎的方式回应。"
        ),
        description="非用户验证失败时的提示词模板，支持 {msg}, {display_name}, {user_qq}, {user}",
        json_schema_extra={"input_type": "textarea", "rows": 8},
    )
    users: list[UserConfig] = Field(
        default_factory=lambda: [UserConfig()],
        description="授权用户列表，可在 WebUI 中添加或删除用户",
        json_schema_extra={"min_items": 1},
    )


class DebugConfig(PluginConfigBase):
    __ui_label__ = "调试选项"
    __ui_icon__ = "bug"
    __ui_order__ = 99

    enable_debug: bool = Field(default=False, description="是否启用调试日志")
    show_detailed_info: bool = Field(default=False, description="是否显示详细验证信息")


class OwnerAuthPluginConfig(PluginConfigBase):
    plugin: PluginSectionConfig = Field(default_factory=PluginSectionConfig)
    owner_auth: OwnerAuthConfig = Field(default_factory=OwnerAuthConfig)
    debug: DebugConfig = Field(default_factory=DebugConfig)
