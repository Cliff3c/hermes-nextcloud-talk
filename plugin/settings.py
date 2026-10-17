"""Profile-aware settings; environment retains precedence over config.extra."""
from gateway.platforms._shared import extra_or_secret, get_scoped_secret

ENV_KEYS = {
    "base_url": "NC_TALK_BASE_URL",
    "bot_secret": "NC_TALK_BOT_SECRET",
    "api_user": "NC_TALK_API_USER",
    "api_password": "NC_TALK_API_PASSWORD",
    "webhook_host": "NC_TALK_WEBHOOK_HOST",
    "webhook_port": "NC_TALK_WEBHOOK_PORT",
    "webhook_path": "NC_TALK_WEBHOOK_PATH",
    "ignore_bots": "NC_TALK_IGNORE_BOTS",
}


def setting(extra, key, default=""):
    return extra_or_secret(extra, key, ENV_KEYS.get(key, ""), default)


def boolean(value):
    if isinstance(value, bool):
        return value
    if isinstance(value, str) and value.lower() in {"true", "1", "yes", "on"}:
        return True
    if isinstance(value, str) and value.lower() in {"false", "0", "no", "off"}:
        return False
    raise ValueError("ignore_bots must be a boolean")


def environment_settings():
    # SDK startup fallback permits externally managed profile credentials.
    return {key: get_scoped_secret(env, "", external_fallback=True)
            for key, env in ENV_KEYS.items()}
