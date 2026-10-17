"""Nextcloud Talk platform plugin, version 0.2.1."""
from .settings import environment_settings, get_scoped_secret, setting


def check_requirements():
    # SDK check_fn is a dependency probe, not an env-only credential gate:
    # credentials may legitimately come from this profile's config.extra.
    from importlib.util import find_spec
    return find_spec("aiohttp") is not None


def validate_config(config):
    extra = getattr(config, "extra", {}) or {}
    return bool(setting(extra, "base_url") and setting(extra, "bot_secret"))


def _env_enablement():
    values = environment_settings()
    if not (values["base_url"] and values["bot_secret"]):
        return None
    seed = {key: value for key, value in values.items() if value != ""}
    home = get_scoped_secret("NC_TALK_HOME_ROOM", "", external_fallback=True)
    if home:
        seed["home_channel"] = {"chat_id": home, "name": "Nextcloud Talk Home"}
    return seed


def register(ctx):
    from .adapter import NextcloudTalkAdapter
    ctx.register_platform(
        name="nextcloud_talk", label="Nextcloud Talk",
        adapter_factory=NextcloudTalkAdapter, check_fn=check_requirements,
        validate_config=validate_config, env_enablement_fn=_env_enablement,
        required_env=["NC_TALK_BASE_URL", "NC_TALK_BOT_SECRET"],
        install_hint="Install aiohttp in the Hermes Python environment",
        cron_deliver_env_var="NC_TALK_HOME_ROOM", max_message_length=32000,
        platform_hint="You are chatting via Nextcloud Talk. Markdown is supported. Prefer concise responses.",
        emoji="☁️",
    )
