"""Nextcloud Talk text bot transport, with bounded authenticated admission.

Inbound HMAC covers random + raw body. Outbound HMAC covers random + text.
Dedupe acknowledges gateway admission, NOT completion of the agent's reply.
"""
from __future__ import annotations

import asyncio
from collections import OrderedDict
import hashlib
import hmac
import json
import logging
import re
import secrets
import time
from urllib.parse import quote, urlsplit
from weakref import WeakValueDictionary

from aiohttp import BasicAuth, ClientError, ClientSession, ClientTimeout, TCPConnector, web
try:
    from aiohttp import encode_basic_auth
except ImportError:  # aiohttp 3.9-era compatibility
    def encode_basic_auth(login, password):
        return BasicAuth(login, password).encode()
from gateway.config import Platform, PlatformConfig
from gateway.platforms.base import BasePlatformAdapter, MessageEvent, MessageType, SendResult

from .settings import boolean, setting

logger = logging.getLogger(__name__)
# The SDK lock permits same-PID reentry; also prevent duplicate multiplex adapters.
_OWNERS = WeakValueDictionary()


class _TTLCache:
    """Insertion-ordered TTL cache: bounded entries, amortized O(1) expiration."""
    def __init__(self, limit, ttl):
        self.limit, self.ttl = limit, ttl
        self.entries = OrderedDict()

    def get(self, key):
        now = time.monotonic()
        while self.entries:
            _, (_, expires) = next(iter(self.entries.items()))
            if expires > now:
                break
            self.entries.popitem(last=False)
        item = self.entries.get(key)
        return item[0] if item else None

    def put(self, key, value=True):
        self.get(key)
        self.entries.pop(key, None)
        self.entries[key] = (value, time.monotonic() + self.ttl)
        while len(self.entries) > self.limit:
            self.entries.popitem(last=False)


def _positive_id(value):
    if isinstance(value, bool) or not isinstance(value, (str, int)):
        raise ValueError("Invalid message id")
    text = str(value)
    if not re.fullmatch(r"[0-9]{1,32}", text) or int(text) <= 0:
        raise ValueError("Invalid message id")
    return text


def _room_token(value):
    if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,255}", value):
        raise ValueError("Invalid room token")
    return value


def _ocs_data(payload):
    """Accept OCS v1/v2 success codes, never HTTP success alone.
    Handles both JSON and XML responses; tolerates empty data (NC 32+).
    """
    if not isinstance(payload, dict) or not isinstance(payload.get("ocs"), dict):
        raise ValueError("Invalid OCS envelope")
    ocs = payload["ocs"]
    meta = ocs.get("meta")
    if not isinstance(meta, dict):
        raise ValueError("Missing OCS metadata")
    code = meta.get("statuscode")
    if type(code) not in (int, str) or str(code) not in {"100", "200", "201"} or meta.get("status") != "ok":
        raise ValueError("OCS did not acknowledge success")
    # NC 32+ returns empty <data/> with no message ID — treat as success with no ID
    if "data" not in ocs:
        raise ValueError("Missing OCS data")
    data = ocs.get("data")
    if data is None or data == []:
        return {}
    if not isinstance(data, dict):
        raise ValueError("Invalid OCS data")
    return data


class NextcloudTalkAdapter(BasePlatformAdapter):
    REPLAY_TTL = 300
    EVENT_TTL = 3600
    CACHE_LIMIT = 4096
    MAX_INFLIGHT = 128
    MAX_BODY_BYTES = 1024 * 1024
    ROOM_CACHE_TTL = 900
    ROOM_CACHE_LIMIT = 1024
    LOOKUP_BACKOFF = 30
    LOOKUP_BACKOFF_MAX = 300

    def __init__(self, config: PlatformConfig):
        super().__init__(config, Platform("nextcloud_talk"))
        extra = config.extra or {}
        self._base_url = str(setting(extra, "base_url")).strip().rstrip("/")
        self._secret = str(setting(extra, "bot_secret")).encode()
        self._api_user = str(setting(extra, "api_user")).strip()
        self._api_pass = str(setting(extra, "api_password")).strip()
        self._host = str(setting(extra, "webhook_host", "0.0.0.0"))
        self._port = int(setting(extra, "webhook_port", 8788))
        self._path = str(setting(extra, "webhook_path", "/nextcloud-talk-webhook"))
        self._ignore_bots = boolean(setting(extra, "ignore_bots", True))
        self._seen_nonces = _TTLCache(self.CACHE_LIMIT, self.REPLAY_TTL)
        self._seen_events = _TTLCache(self.CACHE_LIMIT, self.EVENT_TTL)
        self._pending_nonces = set()
        self._pending_events = set()
        self._room_type_cache = _TTLCache(self.ROOM_CACHE_LIMIT, self.ROOM_CACHE_TTL)
        self._lookup_lock = asyncio.Lock()
        self._lookup_retry_at = 0.0
        self._lookup_failures = 0
        self._http_timeout = ClientTimeout(total=20, connect=5, sock_connect=5, sock_read=15)
        self._lookup_timeout = ClientTimeout(total=5, connect=2, sock_connect=2, sock_read=3)
        self._session = None
        self._runner = None
        self._site = None
        self._owned_identity = None
        self._lifecycle_lock = asyncio.Lock()

    def _make_random(self):
        return secrets.token_hex(32)

    def _sign_outbound(self, random_value, text):
        return hmac.new(self._secret, (random_value + text).encode(), hashlib.sha256).hexdigest()

    def _verify_inbound(self, random_header, raw_body, signature):
        # Random is opaque, NOT hex-only. NC uses a random alphabet, while its
        # verifier requires >=32 bytes. Permit bounded visible ASCII, including
        # base64 punctuation; do not infer entropy from formatting.
        if (not isinstance(random_header, str)
                or not re.fullmatch(r"[\x21-\x7e]{32,256}", random_header)
                or not isinstance(signature, str)
                or not re.fullmatch(r"[a-fA-F0-9]{64}", signature)
                or not self._secret):
            return False
        expected = hmac.new(self._secret, random_header.encode("ascii") + raw_body, hashlib.sha256).hexdigest()
        return hmac.compare_digest(expected, signature.lower())

    @staticmethod
    def _parse_message(raw_body):
        payload = json.loads(raw_body)
        if not isinstance(payload, dict) or not isinstance(payload.get("type"), str):
            raise ValueError("Invalid event")
        if payload["type"] != "Create":
            return None
        actor, target, obj = (payload.get(k) for k in ("actor", "target", "object"))
        if not all(isinstance(v, dict) for v in (actor, target, obj)):
            raise ValueError("Invalid message shape")
        if not isinstance(obj.get("type", "Note"), str):
            raise ValueError("Invalid object type")
        if obj.get("type", "Note") != "Note":
            return None
        actor_id = actor.get("id")
        if not isinstance(actor_id, str) or not 1 <= len(actor_id) <= 512 or any(ord(c) < 32 for c in actor_id):
            raise ValueError("Invalid actor")
        actor_name = actor.get("name", actor_id)
        actor_type = actor.get("type", "Person")
        if not isinstance(actor_name, str) or not isinstance(actor_type, str):
            raise ValueError("Invalid actor metadata")
        room = _room_token(target.get("id"))
        message_id = _positive_id(obj.get("id"))
        raw_content = obj.get("content")
        if not isinstance(raw_content, str):
            raise ValueError("Invalid message content")
        content = json.loads(raw_content)
        if not isinstance(content, dict) or not isinstance(content.get("message"), str):
            raise ValueError("Invalid nested content")
        text = content["message"].strip()
        if not text:
            return None
        is_bot = actor_id.startswith("bots/") or actor_type in {"Application", "Service"}
        # Preserve guests/bots namespaces; only remove the leading users/ prefix.
        user_id = actor_id.removeprefix("users/")
        if not user_id:
            raise ValueError("Empty user identity")
        return room, message_id, text, user_id, actor_name, is_bot, actor_id, actor_type

    async def _handle_webhook(self, request):
        # Reject duplicate security headers instead of selecting an arbitrary one.
        for header in ("X-Nextcloud-Talk-Random", "X-Nextcloud-Talk-Signature"):
            if len(request.headers.getall(header, [])) != 1:
                return web.Response(status=401)
        nonce = request.headers["X-Nextcloud-Talk-Random"]
        signature = request.headers["X-Nextcloud-Talk-Signature"]
        raw_body = await request.read()  # aiohttp's application size limit applies.
        if not self._verify_inbound(nonce, raw_body, signature):
            return web.Response(status=401)
        try:
            message = self._parse_message(raw_body)
        except (ValueError, TypeError, UnicodeError, RecursionError):
            return web.Response(status=400)
        # No replay-state reads/mutations until after authentication/schema checks.
        if self._seen_nonces.get(nonce):
            return web.Response(status=200)
        if message is None:
            self._seen_nonces.put(nonce)
            return web.Response(status=200)
        room, mid, text, uid, name, is_bot, actor_id, actor_type = message
        key = (room, mid)  # caches belong to exactly one adapter/bot identity
        if self._seen_events.get(key) or (is_bot and self._ignore_bots):
            self._seen_nonces.put(nonce)
            self._seen_events.put(key)
            return web.Response(status=200)
        # Reserving is synchronous: concurrent delivery cannot pass while the
        # first request awaits metadata/admission. A pending request is NOT acked.
        if (nonce in self._pending_nonces or key in self._pending_events
                or len(self._pending_events) >= self.MAX_INFLIGHT):
            return web.Response(status=503, headers={"Retry-After": "1"})
        self._pending_nonces.add(nonce)
        self._pending_events.add(key)
        event = None
        try:
            room_type = await self._get_room_type(room)
            source = self.build_source(chat_id=room, chat_name=room,
                                       chat_type="dm" if room_type == 1 else "group",
                                       user_id=uid, user_name=name, is_bot=is_bot)
            event = MessageEvent(text=text, message_type=MessageType.TEXT,
                                 source=source, message_id=mid,
                                 metadata={"nextcloud_actor_id": actor_id,
                                           "nextcloud_actor_type": actor_type})
            await self.handle_message(event)
            # Modern SDK: explicit False is failed admission. Older handlers
            # lack the receipt (None): successful return retains legacy meaning.
            if getattr(event, "_gateway_accepted", None) is False:
                return web.Response(status=503, headers={"Retry-After": "1"})
            self._seen_nonces.put(nonce)
            self._seen_events.put(key)
            return web.Response(status=200)
        except asyncio.CancelledError:
            if event is not None and getattr(event, "_gateway_accepted", None) is True:
                self._seen_nonces.put(nonce)
                self._seen_events.put(key)
            raise
        except Exception:
            # Do not log payloads, URLs, signatures or exception strings.
            if event is not None and getattr(event, "_gateway_accepted", None) is True:
                self._seen_nonces.put(nonce)
                self._seen_events.put(key)
                return web.Response(status=200)
            logger.warning("[nextcloud-talk] Gateway admission failed")
            return web.Response(status=503, headers={"Retry-After": "1"})
        finally:
            self._pending_nonces.discard(nonce)
            self._pending_events.discard(key)

    async def _dispatch_inline_reply(self, event, **kwargs):
        # Current SDK's busy /new, /stop, /approve and clarify bypass paths
        # dispatch successfully but leave the admission receipt False. Keep ALL
        # command logic in the SDK and fill only that missing receipt.
        await super()._dispatch_inline_reply(event, **kwargs)
        event._gateway_accepted = True

    async def _read_json(self, response):
        data = bytearray()
        async for chunk in response.content.iter_chunked(65536):
            data.extend(chunk)
            if len(data) > self.MAX_BODY_BYTES:
                raise ValueError("OCS response too large")
        content_type = response.headers.get("Content-Type", "").lower()
        if "xml" in content_type:
            # NC 32 can return XML despite Accept: application/json. Reject
            # DTDs at the parser (also covers UTF-16), never expand entities.
            import xml.etree.ElementTree as ET

            class NoDTD(ET.TreeBuilder):
                def doctype(self, name, pubid, system):
                    raise ValueError("OCS XML DTDs are forbidden")

            try:
                root = ET.fromstring(data, parser=ET.XMLParser(target=NoDTD()))
            except ET.ParseError as exc:
                raise ValueError("Malformed OCS XML") from exc
            if root.tag != "ocs" or len(root.findall("meta")) != 1 or len(root.findall("data")) != 1:
                raise ValueError("Invalid OCS XML envelope")

            def fields(element):
                result = {}
                if element.text and element.text.strip():
                    raise ValueError("Invalid OCS XML data")
                for child in element:
                    if child.tag in result:
                        raise ValueError("Duplicate OCS XML field")
                    if child.tag in {"status", "statuscode", "id", "type"} and len(child):
                        raise ValueError("Invalid OCS XML scalar")
                    result[child.tag] = child.text
                return result

            meta = fields(root.find("meta"))
            ocs_data = fields(root.find("data"))
            # XML scalars are strings, unlike JSON room metadata.
            if "type" in ocs_data:
                if ocs_data["type"] not in {"1", "2", "3", "4", "5", "6"}:
                    raise ValueError("Invalid XML room type")
                ocs_data["type"] = int(ocs_data["type"])
            return {"ocs": {"meta": meta, "data": ocs_data}}
        return json.loads(data)

    async def _get_room_type(self, room):
        room = _room_token(room)
        cached = self._room_type_cache.get(room)
        if cached is not None:
            return cached
        if not (self._api_user and self._api_pass and self._session and not self._session.closed):
            return 2
        # Serialize lookups so bursts do not defeat global credential-failure
        # backoff; a second room must not immediately repeat a 401/timeout.
        async with self._lookup_lock:
            cached = self._room_type_cache.get(room)
            if cached is not None:
                return cached
            if time.monotonic() < self._lookup_retry_at:
                return 2
            try:
                url = f"{self._base_url}/ocs/v2.php/apps/spreed/api/v4/room/{quote(room, safe='')}"
                async with self._session.get(url,
                        headers={"OCS-APIRequest": "true", "Accept": "application/json",
                                 "Authorization": encode_basic_auth(self._api_user, self._api_pass)},
                        timeout=self._lookup_timeout, allow_redirects=False) as response:
                    if response.status != 200:
                        raise ValueError("Room lookup refused")
                    room_type = _ocs_data(await self._read_json(response)).get("type")
                    if type(room_type) is not int or room_type not in {1, 2, 3, 4, 5, 6}:
                        raise ValueError("Invalid room type")
                self._room_type_cache.put(room, room_type)
                self._lookup_failures = 0
                self._lookup_retry_at = 0.0
                return room_type
            except (ClientError, asyncio.TimeoutError, ValueError, UnicodeError, RecursionError):
                self._lookup_failures = min(self._lookup_failures + 1, 5)
                delay = min(self.LOOKUP_BACKOFF * 2 ** (self._lookup_failures - 1), self.LOOKUP_BACKOFF_MAX)
                self._lookup_retry_at = time.monotonic() + delay
                logger.warning("[nextcloud-talk] Room metadata unavailable; using group with backoff")
                return 2

    async def connect(self, *, is_reconnect: bool = False, **kwargs):
        async with self._lifecycle_lock:
            if self._running:
                return True
            try:
                parsed = urlsplit(self._base_url)
                valid = (parsed.scheme in {"http", "https"} and bool(parsed.hostname)
                         and (parsed.port is None or 1 <= parsed.port <= 65535))
            except ValueError:
                valid = False
            if (not valid
                    or parsed.username or parsed.password or parsed.query or parsed.fragment
                    or not self._secret or not self._path.startswith("/")
                    or not 0 <= self._port <= 65535):
                logger.error("[nextcloud-talk] Invalid or missing connection settings")
                return False
            identity = hashlib.sha256(self._base_url.encode() + b"\0" + self._secret).hexdigest()
            if identity in _OWNERS and _OWNERS[identity] is not self:
                logger.error("[nextcloud-talk] Bot identity already owned in this process")
                return False
            try:
                if not self._acquire_platform_lock("nextcloud_talk_bot", identity, "Nextcloud Talk bot identity"):
                    return False
                self._owned_identity = identity
                _OWNERS[identity] = self
                connector = TCPConnector(limit=32, limit_per_host=16)
                try:
                    self._session = ClientSession(timeout=self._http_timeout, trust_env=False,
                                                  connector=connector)
                except BaseException:
                    await connector.close()
                    raise
                app = web.Application(client_max_size=self.MAX_BODY_BYTES)
                app.router.add_post(self._path, self._handle_webhook)
                self._runner = web.AppRunner(app, access_log=None, shutdown_timeout=10)
                await self._runner.setup()
                # Deliberately no SO_REUSEPORT: another owner must fail loudly.
                self._site = web.TCPSite(self._runner, self._host, self._port)
                await self._site.start()
                self._mark_connected()
                return True
            except asyncio.CancelledError:
                await self._cleanup()
                raise
            except Exception:
                logger.error("[nextcloud-talk] Connect failed; cleaning up resources")
                await self._cleanup()
                return False

    async def _cleanup(self):
        runner, session = self._runner, self._session
        self._runner = self._site = self._session = None
        try:
            if runner:
                await runner.cleanup()
        finally:
            try:
                if session:
                    await session.close()
            finally:
                if self._owned_identity:
                    _OWNERS.pop(self._owned_identity, None)
                    self._release_platform_lock()
                    self._owned_identity = None
                self._mark_disconnected()

    async def disconnect(self):
        async with self._lifecycle_lock:
            await self._cleanup()

    def _send_retry_is_final(self, result):
        # The base SDK otherwise retries based on error text OR sends a plain
        # fallback even with retryable=False. OCS has no idempotency key here.
        return True

    @staticmethod
    def _failure(error, state="unknown", status=None):
        return SendResult(success=False, error=error, retryable=False,
                          raw_response={"delivery_state": state, "http_status": status})

    async def send(self, chat_id, content, reply_to=None, metadata=None):
        if not self._session or self._session.closed:
            return self._failure("Nextcloud Talk adapter is disconnected", "not_sent")
        try:
            room = _room_token(chat_id)
            if not isinstance(content, str) or not content.strip() or len(content) > 32000:
                raise ValueError("Invalid message text")
            body = {"message": content}
            if reply_to is not None:
                body["replyTo"] = _positive_id(reply_to)
            nonce = self._make_random()
            signature = self._sign_outbound(nonce, content)
        except (ValueError, UnicodeError):
            return self._failure("Invalid Nextcloud Talk outbound message", "not_sent")
        headers = {"Content-Type": "application/json", "Accept": "application/json",
                   "OCS-APIRequest": "true", "X-Nextcloud-Talk-Bot-Random": nonce,
                   "X-Nextcloud-Talk-Bot-Signature": signature}
        url = f"{self._base_url}/ocs/v2.php/apps/spreed/api/v1/bot/{quote(room, safe='')}/message"
        try:
            async with self._session.post(url, json=body, headers=headers, allow_redirects=False) as response:
                if response.status not in {200, 201}:
                    state = "rejected" if 400 <= response.status < 500 else "unknown"
                    return self._failure(f"Nextcloud Talk HTTP {response.status}", state, response.status)
                try:
                    payload = await self._read_json(response)
                    ocs_d = _ocs_data(payload)
                    # An explicit empty acknowledgement has no ID. Never invent
                    # one, nor accept malformed nonempty data as an empty ack.
                    message_id = _positive_id(ocs_d.get("id")) if ocs_d else None
                except (ValueError, UnicodeError, RecursionError):
                    return self._failure("Nextcloud Talk delivery unconfirmed: invalid OCS acknowledgement",
                                         status=response.status)
                return SendResult(success=True, message_id=message_id,
                                  raw_response={"delivery_state": "confirmed", "http_status": response.status})
        except asyncio.TimeoutError:
            return self._failure("Nextcloud Talk delivery unconfirmed: request timed out")
        except ClientError:
            return self._failure("Nextcloud Talk delivery unconfirmed: transport error")

    async def get_chat_info(self, chat_id):
        room_type = await self._get_room_type(chat_id)
        return {"name": chat_id, "type": "dm" if room_type == 1 else "group"}
