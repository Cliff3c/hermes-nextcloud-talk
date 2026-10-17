"""Standalone offline regressions using the installed Hermes SDK and aiohttp.

Run with the Hermes venv Python. No Hermes full-suite/conftest, production
credentials, production plugin imports, real Nextcloud or model calls.
"""
from __future__ import annotations
import asyncio
import hashlib
import hmac
import importlib.util
import inspect
import io
import json
import os
from pathlib import Path
import socket
import sys
import tempfile
import unittest
from unittest.mock import AsyncMock, patch

# Isolation is installed BEFORE importing Hermes (which can read configuration).
ROOT = Path(__file__).resolve().parents[1]
SDK_PATH = os.environ.get("HERMES_SOURCE")
if SDK_PATH:
    sys.path.insert(0, str(Path(SDK_PATH).expanduser().resolve()))
SANDBOX = tempfile.TemporaryDirectory(prefix="isolated-", dir=ROOT / "tests")
os.environ.clear()
os.environ.update({"HOME": SANDBOX.name, "HERMES_HOME": SANDBOX.name,
                   "HERMES_GATEWAY_LOCK_DIR": str(Path(SANDBOX.name) / "locks"),
                   "PYTHONDONTWRITEBYTECODE": "1", "PATH": "/usr/bin:/bin"})
sys.dont_write_bytecode = True


# Fail closed if a regression ever attempts non-loopback networking.
_original_connect = socket.socket.connect
_original_connect_ex = socket.socket.connect_ex
_original_getaddrinfo = socket.getaddrinfo
_original_bind = socket.socket.bind

def local_bind(sock, address):
    if sock.family in (socket.AF_INET, socket.AF_INET6) and address[0] not in {"127.0.0.1", "::1"}:
        raise AssertionError("Offline tests forbid non-loopback listeners")
    return _original_bind(sock, address)

def local_connect(sock, address):
    if sock.family in (socket.AF_INET, socket.AF_INET6) and address[0] not in {"127.0.0.1", "::1"}:
        raise AssertionError("Offline tests forbid non-loopback connections")
    return _original_connect(sock, address)

def local_connect_ex(sock, address):
    if sock.family in (socket.AF_INET, socket.AF_INET6) and address[0] not in {"127.0.0.1", "::1"}:
        raise AssertionError("Offline tests forbid non-loopback connections")
    return _original_connect_ex(sock, address)

def local_resolve(host, *args, **kwargs):
    if host not in {"127.0.0.1", "::1", "localhost", None}:
        raise AssertionError("Offline tests forbid non-loopback DNS")
    return _original_getaddrinfo(host, *args, **kwargs)

socket.socket.connect = local_connect
socket.socket.connect_ex = local_connect_ex
socket.getaddrinfo = local_resolve
socket.socket.bind = local_bind

from aiohttp import ClientSession, ClientTimeout, web
from aiohttp.test_utils import TestServer
from multidict import CIMultiDict
from gateway.config import PlatformConfig
from gateway.platforms.base import BasePlatformAdapter, MessageType
from agent import secret_scope

spec = importlib.util.spec_from_file_location("nc_hardening", ROOT / "plugin" / "__init__.py",
                                            submodule_search_locations=[str(ROOT / "plugin")])
plugin = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = plugin
spec.loader.exec_module(plugin)
from nc_hardening import adapter as mod
from hermes_cli.plugins import PluginContext, PluginManager
from hermes_cli.plugins_manifest import parse_manifest_file
from gateway.platform_registry import platform_registry

# Match gateway startup: register the custom platform BEFORE constructing it.
manifest = parse_manifest_file(ROOT / "plugin" / "plugin.yaml", ROOT / "plugin", "user", "")
assert manifest is not None
manager = PluginManager()
plugin.register(PluginContext(manifest, manager))
assert platform_registry.is_registered("nextcloud_talk")

SECRET = "offline-fixture-not-a-production-secret"
NONCE = "n" * 64


def payload(actor="users/human", mid="123", room="test-room", text="hello", actor_type="Person"):
    return {"type": "Create", "actor": {"id": actor, "name": "Test Person", "type": actor_type},
            "target": {"id": room},
            "object": {"type": "Note", "id": mid, "name": "message",
                       "content": json.dumps({"message": text, "parameters": {}})}}


class Request:
    def __init__(self, value=None, nonce=NONCE, *, raw=None, signature=None):
        self.body = raw if raw is not None else json.dumps(value).encode()
        sig = hmac.new(SECRET.encode(), nonce.encode() + self.body, hashlib.sha256).hexdigest()
        self.headers = CIMultiDict({"X-Nextcloud-Talk-Random": nonce,
                                   "X-Nextcloud-Talk-Signature": signature or sig})

    async def read(self):
        return self.body


def ocs(data=None, *, code=200, status="ok"):
    return {"ocs": {"meta": {"status": status, "statuscode": code},
                    "data": {"id": 456} if data is None else data}}


class OfflineTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.adapters = []
        self.servers = []
        self.received = []
        self.response_status = 201
        self.response_body = ocs()
        self.response_raw = None
        self.response_delay = 0
        self.response_headers = {}
        self.lookups = 0
        self.lookup_status = 200
        self.lookup_body = ocs({"type": 1})
        self.lookup_delay = 0
        self.lookup_raw = None

    async def asyncTearDown(self):
        for adapter in self.adapters:
            for task in list(adapter._background_tasks):
                task.cancel()
            if adapter._background_tasks:
                await asyncio.gather(*adapter._background_tasks, return_exceptions=True)
            await adapter.disconnect()
        for server in self.servers:
            await server.close()

    def make(self, **extra):
        values = {"base_url": "http://127.0.0.1:1", "bot_secret": SECRET,
                  "webhook_host": "127.0.0.1", "webhook_port": 0}
        values.update(extra)
        adapter = mod.NextcloudTalkAdapter(PlatformConfig(extra=values))
        self.adapters.append(adapter)
        return adapter

    def admit(self, adapter, accepted=True):
        async def handoff(event):
            event._gateway_accepted = accepted
        adapter.handle_message = AsyncMock(side_effect=handoff)
        return adapter.handle_message

    async def post(self, adapter, value=None, **kwargs):
        return await adapter._handle_webhook(Request(payload() if value is None else value, **kwargs))

    async def server(self):
        async def send(request):
            body = await request.json()
            nonce = request.headers["X-Nextcloud-Talk-Bot-Random"]
            expected = hmac.new(SECRET.encode(), (nonce + body["message"]).encode(), hashlib.sha256).hexdigest()
            self.assertEqual(request.headers["X-Nextcloud-Talk-Bot-Signature"], expected)
            self.assertEqual(request.headers["Accept"], "application/json")
            self.assertEqual(request.headers["OCS-APIRequest"], "true")
            self.assertNotIn("Authorization", request.headers)
            self.received.append((request.path, body))
            if self.response_delay:
                await asyncio.sleep(self.response_delay)
            if self.response_raw is not None:
                return web.Response(status=self.response_status, body=self.response_raw,
                                    headers=self.response_headers)
            return web.json_response(self.response_body, status=self.response_status,
                                     headers=self.response_headers)

        async def room(request):
            self.lookups += 1
            self.assertTrue(request.headers.get("Authorization", "").startswith("Basic "))
            if self.lookup_delay:
                await asyncio.sleep(self.lookup_delay)
            if self.lookup_raw is not None:
                return web.Response(body=self.lookup_raw, status=self.lookup_status,
                                    content_type="application/xml")
            return web.json_response(self.lookup_body, status=self.lookup_status)

        app = web.Application()
        app.router.add_post("/ocs/v2.php/apps/spreed/api/v1/bot/{room}/message", send)
        app.router.add_get("/ocs/v2.php/apps/spreed/api/v4/room/{room}", room)
        server = TestServer(app, host="127.0.0.1")
        await server.start_server()
        self.servers.append(server)
        return str(server.make_url("/")).rstrip("/")

    async def connected(self, **extra):
        url = await self.server()
        adapter = self.make(base_url=url, **extra)
        self.assertTrue(await adapter.connect())
        return adapter

    async def test_signature_before_cache_and_bad_signature_replay(self):
        adapter = self.make()
        handoff = self.admit(adapter)
        self.assertEqual((await self.post(adapter, signature="0" * 64)).status, 401)
        self.assertEqual(len(adapter._seen_nonces.entries), 0)
        self.assertEqual(len(adapter._seen_events.entries), 0)
        self.assertEqual((await self.post(adapter)).status, 200)
        self.assertEqual(handoff.await_count, 1)
        self.assertEqual((await self.post(adapter, signature="0" * 64)).status, 401)

    async def test_random_is_not_assumed_hex_or_fixed_64(self):
        adapter = self.make()
        handoff = self.admit(adapter)
        for index, nonce in enumerate(["Z+/=\\_-" * 9, "G" * 32, "Q" * 256]):
            req = Request(payload(mid=str(index + 1)), nonce)
            req.headers["X-Nextcloud-Talk-Signature"] = req.headers["X-Nextcloud-Talk-Signature"].upper()
            self.assertEqual((await adapter._handle_webhook(req)).status, 200)
        self.assertEqual(handoff.await_count, 3)

    async def test_malformed_headers_are_controlled(self):
        adapter = self.make()
        for nonce in ["", "x" * 31, "x" * 257, "é" * 64, "x" * 63 + "\n", "x" * 63 + " "]:
            with self.subTest(nonce_length=len(nonce)):
                self.assertEqual((await self.post(adapter, nonce=nonce)).status, 401)
        for sig in ["g" * 64, "é" * 64, "x", "0" * 65]:
            self.assertEqual((await self.post(adapter, signature=sig)).status, 401)
        for header in ("X-Nextcloud-Talk-Random", "X-Nextcloud-Talk-Signature"):
            req = Request(payload())
            req.headers.add(header, req.headers[header])
            self.assertEqual((await adapter._handle_webhook(req)).status, 401)
            del req.headers[header]
            self.assertEqual((await adapter._handle_webhook(req)).status, 401)
        self.assertFalse(adapter._seen_nonces.entries)

    async def test_malformed_json_and_nested_shapes(self):
        adapter = self.make()
        handoff = self.admit(adapter)
        malformed = [[], None, "text", 12, {}, {"type": []}]
        for key in ("actor", "object", "target"):
            for bad in (None, [], "text", 3):
                p = payload()
                p[key] = bad
                malformed.append(p)
        for field, bad_values in (("id", [None, [], 1]), ("name", [None, {}]), ("type", [[]])):
            for bad in bad_values:
                p = payload()
                p["actor"][field] = bad
                malformed.append(p)
        for bad in (None, {}, [], 3, "not json", "[]", "null", '{"message": 5}', '{"message": null}'):
            p = payload()
            p["object"]["content"] = bad
            malformed.append(p)
        for bad in (None, True, 0, -1, [], "unknown", ""):
            p = payload()
            p["object"]["id"] = bad
            malformed.append(p)
        for bad in (None, [], "../room", "", "room?query"):
            p = payload()
            p["target"]["id"] = bad
            malformed.append(p)
        for p in malformed:
            with self.subTest(shape=type(p).__name__):
                self.assertEqual((await adapter._handle_webhook(Request(p))).status, 400)
        for raw in (b"{", b"\xff", b'{"type":'):
            self.assertEqual((await self.post(adapter, raw=raw)).status, 400)
        self.assertFalse(adapter._seen_nonces.entries)
        handoff.assert_not_awaited()
        self.assertEqual((await self.post(adapter)).status, 200)

    async def test_ignored_event_types_and_empty_text(self):
        adapter = self.make()
        handoff = self.admit(adapter)
        for value in ({"type": "Join"}, {"type": "Leave"}, {"type": "Like"}, payload(text="  ")):
            self.assertEqual((await self.post(adapter, value)).status, 200)
        handoff.assert_not_awaited()

    async def test_duplicate_nonce_and_room_message_dedupe(self):
        adapter = self.make()
        handoff = self.admit(adapter)
        for nonce in (NONCE, NONCE, "b" * 64):
            self.assertEqual((await self.post(adapter, nonce=nonce)).status, 200)
        self.assertEqual(handoff.await_count, 1)
        self.assertEqual((await self.post(adapter, payload(room="other-room"), nonce="c" * 64)).status, 200)
        self.assertEqual((await self.post(adapter, payload(mid="124"), nonce="d" * 64)).status, 200)
        self.assertEqual(handoff.await_count, 3)

    async def test_cache_count_bound_and_expiration(self):
        cache = mod._TTLCache(2, 10)
        with patch.object(mod.time, "monotonic", return_value=100):
            for key in ("a", "b", "c"):
                cache.put(key)
            self.assertEqual(list(cache.entries), ["b", "c"])
            self.assertIsNone(cache.get("a"))
        with patch.object(mod.time, "monotonic", return_value=111):
            self.assertIsNone(cache.get("b"))
            self.assertFalse(cache.entries)
        adapter = self.make()
        adapter._seen_nonces = mod._TTLCache(2, 300)
        adapter._seen_events = mod._TTLCache(2, 3600)
        self.admit(adapter)
        for i in range(8):
            await self.post(adapter, payload(mid=str(i + 1)), nonce=str(i) * 64)
        self.assertEqual(len(adapter._seen_nonces.entries), 2)
        self.assertEqual(len(adapter._seen_events.entries), 2)

    async def test_bot_ignored_by_default_human_reports_work(self):
        adapter = self.make()
        handoff = self.admit(adapter)
        for index, (actor, kind) in enumerate((("bots/reporter", "Person"), ("users/service", "Application"),
                                              ("users/automation", "Service"))):
            self.assertEqual((await self.post(adapter, payload(actor, mid=str(index + 1), actor_type=kind),
                                             nonce=str(index) * 64)).status, 200)
        handoff.assert_not_awaited()
        await self.post(adapter, payload(text="Daily report from a human"), nonce="h" * 64)
        event = handoff.await_args.args[0]
        self.assertFalse(event.source.is_bot)
        self.assertEqual(event.source.user_id, "human")
        self.assertEqual(event.source.chat_type, "group")
        self.assertTrue(event.allow_gateway_control)

    async def test_bot_opt_in_metadata_and_guest_identity(self):
        adapter = self.make(ignore_bots=False)
        handoff = self.admit(adapter)
        await self.post(adapter, payload("bots/reporter"))
        event = handoff.await_args.args[0]
        self.assertTrue(event.source.is_bot)
        self.assertEqual(event.source.user_id, "bots/reporter")
        self.assertEqual(event.metadata["nextcloud_actor_id"], "bots/reporter")
        await self.post(adapter, payload("guests/users/guest", mid="124"), nonce="g" * 64)
        event = handoff.await_args.args[0]
        self.assertFalse(event.source.is_bot)
        self.assertEqual(event.source.user_id, "guests/users/guest")

    async def test_admission_false_allows_same_nonce_retry(self):
        adapter = self.make()
        handoff = self.admit(adapter, False)
        self.assertEqual((await self.post(adapter)).status, 503)
        self.assertFalse(adapter._seen_events.entries)
        self.assertFalse(adapter._seen_nonces.entries)
        self.assertFalse(adapter._pending_events)
        self.admit(adapter)
        self.assertEqual((await self.post(adapter)).status, 200)
        self.assertEqual(handoff.await_count, 1)

    async def test_admission_exception_allows_new_nonce_retry(self):
        adapter = self.make()
        adapter.handle_message = AsyncMock(side_effect=RuntimeError("fixture"))
        self.assertEqual((await self.post(adapter)).status, 503)
        handoff = self.admit(adapter)
        self.assertEqual((await self.post(adapter, nonce="r" * 64)).status, 200)
        self.assertEqual(handoff.await_count, 1)

    async def test_legacy_none_receipt_and_none_return_are_distinct(self):
        adapter = self.make()
        handoff = self.admit(adapter, None)
        self.assertEqual((await self.post(adapter)).status, 200)
        self.assertEqual((await self.post(adapter, nonce="l" * 64)).status, 200)
        self.assertEqual(handoff.await_count, 1)
        other = self.make()
        other.handle_message = AsyncMock(return_value=None)  # modern event still False
        self.assertEqual((await self.post(other)).status, 503)

    async def test_real_sdk_no_handler_is_retryable(self):
        adapter = self.make()
        self.assertEqual((await self.post(adapter)).status, 503)
        self.assertFalse(adapter._seen_events.entries)

    async def test_real_sdk_command_path_and_busy_bypass_receipt(self):
        adapter = self.make()
        adapter._message_handler = AsyncMock(return_value=None)
        captured = []
        def start(event, key):
            captured.append(event)
            return True
        with patch.object(adapter, "_start_session_processing", side_effect=start):
            self.assertEqual((await self.post(adapter, payload(text="/help"))).status, 200)
        self.assertTrue(captured[0].is_command())
        self.assertEqual(captured[0].get_command(), "help")
        key = adapter._event_session_key(captured[0])
        # Keep a real active guard owned by a task so SDK self-healing does not
        # clear it. /approve must use the inline path, NOT model processing.
        guard_task = asyncio.create_task(asyncio.Event().wait())
        adapter._active_sessions[key] = asyncio.Event()
        adapter._session_tasks[key] = guard_task
        try:
            self.assertEqual((await self.post(adapter, payload(mid="124", text="/approve"), nonce="a" * 64)).status, 200)
            self.assertEqual((await self.post(adapter, payload(mid="124", text="/approve"), nonce="b" * 64)).status, 200)
            adapter._message_handler.assert_awaited_once()
            self.assertEqual(adapter._message_handler.await_args.args[0].get_command(), "approve")
        finally:
            guard_task.cancel()
            await asyncio.gather(guard_task, return_exceptions=True)
            adapter._session_tasks.clear()
            adapter._active_sessions.clear()

    async def test_concurrent_duplicate_not_acked_before_admission(self):
        adapter = self.make()
        entered, release = asyncio.Event(), asyncio.Event()
        async def delayed(event):
            entered.set()
            await release.wait()
            event._gateway_accepted = False
        adapter.handle_message = AsyncMock(side_effect=delayed)
        first = asyncio.create_task(self.post(adapter))
        await entered.wait()
        self.assertEqual((await self.post(adapter)).status, 503)
        self.assertEqual((await self.post(adapter, nonce="q" * 64)).status, 503)
        self.assertEqual(adapter.handle_message.await_count, 1)
        release.set()
        self.assertEqual((await first).status, 503)
        self.admit(adapter)
        self.assertEqual((await self.post(adapter)).status, 200)

    async def test_inflight_bound_and_cancellation_release(self):
        adapter = self.make()
        adapter.MAX_INFLIGHT = 1
        entered = asyncio.Event()
        async def wait_forever(event):
            entered.set()
            await asyncio.Event().wait()
        adapter.handle_message = AsyncMock(side_effect=wait_forever)
        first = asyncio.create_task(self.post(adapter))
        await entered.wait()
        self.assertEqual((await self.post(adapter, payload(mid="124"), nonce="q" * 64)).status, 503)
        first.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await first
        self.assertFalse(adapter._pending_events)
        self.assertFalse(adapter._pending_nonces)
        self.admit(adapter)
        self.assertEqual((await self.post(adapter)).status, 200)

    async def test_exception_after_receipt_does_not_redeliver(self):
        adapter = self.make()
        async def accepted_then_error(event):
            event._gateway_accepted = True
            raise RuntimeError("post-admission fixture")
        adapter.handle_message = AsyncMock(side_effect=accepted_then_error)
        self.assertEqual((await self.post(adapter)).status, 200)
        self.assertEqual((await self.post(adapter, nonce="z" * 64)).status, 200)
        self.assertEqual(adapter.handle_message.await_count, 1)

    async def test_real_http_webhook_and_body_limit(self):
        adapter = await self.connected()
        handoff = self.admit(adapter)
        port = adapter._site._server.sockets[0].getsockname()[1]
        url = f"http://127.0.0.1:{port}{adapter._path}"
        req = Request(payload())
        async with ClientSession(timeout=ClientTimeout(total=3)) as client:
            async with client.post(url, data=req.body, headers=req.headers) as response:
                self.assertEqual(response.status, 200)
            async with client.post(url, data=b"x", headers={}) as response:
                self.assertEqual(response.status, 401)
            async with client.post(url, data=io.BytesIO(b"x" * (adapter.MAX_BODY_BYTES + 1)), headers=req.headers) as response:
                self.assertEqual(response.status, 413)
        self.assertEqual(handoff.await_count, 1)

    async def test_outbound_valid_ocs_signing_and_reply(self):
        adapter = await self.connected()
        session = adapter._session
        for code in (100, 200, 201, "200"):
            self.response_body = ocs({"id": "789"}, code=code)
            result = await adapter.send("test-room", "hello ü\nworld", reply_to="123")
            self.assertTrue(result.success)
            self.assertEqual(result.message_id, "789")
            self.assertEqual(result.raw_response["delivery_state"], "confirmed")
        self.assertIs(adapter._session, session)
        self.assertEqual(self.received[0][1], {"message": "hello ü\nworld", "replyTo": "123"})

    async def test_outbound_http_errors_no_sdk_retry_or_body_leak(self):
        adapter = await self.connected()
        self.response_raw = b"server private body must not escape"
        for status in (400, 401, 403, 404, 413, 429, 500, 502):
            with self.subTest(status=status):
                before = len(self.received)
                self.response_status = status
                result = await adapter._send_with_retry("test-room", "hello", base_delay=0)
                self.assertFalse(result.success)
                self.assertIsNone(result.message_id)
                self.assertFalse(result.retryable)
                self.assertNotIn("private", result.error)
                self.assertEqual(len(self.received), before + 1)
                self.assertEqual(result.raw_response["delivery_state"], "rejected" if status < 500 else "unknown")

    async def test_outbound_malformed_success_and_ocs_errors_no_retry(self):
        adapter = await self.connected()
        bodies = [None, [], {}, {"ocs": []}, {"ocs": {"data": {"id": 1}}},
                  ocs(code=997, status="error"), ocs(code=200, status="failure"),
                  ocs(code=True), ocs({"unexpected": "value"}),
                  {"ocs": {"meta": {"status": "ok", "statuscode": 200}}}]
        for bad_id in (None, True, {}, [], 0, -1, 1.5, "unknown", ""):
            bodies.append(ocs({"id": bad_id}))
        for body in bodies:
            before = len(self.received)
            self.response_body = body
            result = await adapter._send_with_retry("test-room", "hello", base_delay=0)
            self.assertFalse(result.success)
            self.assertIsNone(result.message_id)
            self.assertEqual(result.raw_response["delivery_state"], "unknown")
            self.assertEqual(len(self.received), before + 1)
        for raw in (b"not JSON", b"\xff", b"x" * (adapter.MAX_BODY_BYTES + 1)):
            self.response_raw = raw
            result = await adapter._send_with_retry("test-room", "hello", base_delay=0)
            self.assertFalse(result.success)

    async def test_reconnect_keyword_contract_and_resource_lifecycle(self):
        parameter = inspect.signature(mod.NextcloudTalkAdapter.connect).parameters["is_reconnect"]
        self.assertEqual(parameter.kind, inspect.Parameter.KEYWORD_ONLY)
        self.assertIs(parameter.default, False)
        adapter = self.make()
        self.assertTrue(await adapter.connect(is_reconnect=False))
        session, site = adapter._session, adapter._site
        self.assertTrue(await adapter.connect(is_reconnect=True))
        self.assertIs(adapter._session, session)
        self.assertIs(adapter._site, site)
        await adapter.disconnect()
        self.assertTrue(session.closed)
        self.assertTrue(await adapter.connect(is_reconnect=True))
        self.assertIsNot(adapter._session, session)
        self.assertTrue(adapter._running)

    async def test_nc32_xml_success_with_and_without_message_id(self):
        adapter = await self.connected()
        for media_type in ("application/xml; charset=utf-8", "text/xml", "Application/XML"):
            for data, expected_id in (("<data><id>789</id></data>", "789"), ("<data/>", None)):
                with self.subTest(media_type=media_type, data=data):
                    self.response_headers = {"Content-Type": media_type}
                    self.response_raw = ("<?xml version='1.0'?><ocs><meta><status>ok</status>"
                                         "<statuscode>200</statuscode></meta>" + data + "</ocs>").encode()
                    before = len(self.received)
                    result = await adapter._send_with_retry("test-room", "hello", base_delay=0)
                    self.assertTrue(result.success)
                    self.assertEqual(result.message_id, expected_id)
                    self.assertEqual(result.raw_response["delivery_state"], "confirmed")
                    self.assertEqual(len(self.received), before + 1)

    async def test_empty_json_ocs_ack_has_no_synthetic_id(self):
        adapter = await self.connected()
        for empty in ({}, [], None):
            self.response_body = ocs()
            self.response_body["ocs"]["data"] = empty
            result = await adapter.send("test-room", "hello")
            self.assertTrue(result.success)
            self.assertIsNone(result.message_id)

    async def test_xml_errors_malformed_and_entities_never_retry(self):
        adapter = await self.connected()
        self.response_headers = {"Content-Type": "application/xml"}
        good_meta = "<meta><status>ok</status><statuscode>200</statuscode></meta>"
        cases = [b"<ocs>", b"not xml", b"\xff", b"<ocs><data/></ocs>",
                 b"<ocs><meta><status>error</status><statuscode>997</statuscode></meta><data/></ocs>"]
        cases += [(f"<ocs>{good_meta}{data}</ocs>").encode() for data in
                  ("", "<data><id/></data>", "<data><id>0</id></data>",
                   "<data><id>unknown</id></data>", "<data><id><nested>1</nested></id></data>",
                   "<data><id>1</id><id>2</id></data>", "<data/><data/>")]
        cases += [(f"<wrong>{good_meta}<data><id>1</id></data></wrong>").encode(),
                  (f"<ocs>{good_meta}{good_meta}<data/></ocs>").encode()]
        dtd = ("<!DOCTYPE ocs [<!ENTITY fixture '789'>]>"
               f"<ocs>{good_meta}<data><id>&fixture;</id></data></ocs>")
        cases += [dtd.encode(), dtd.encode("utf-16"), b"x" * (adapter.MAX_BODY_BYTES + 1)]
        for raw in cases:
            with self.subTest(size=len(raw)):
                self.response_raw = raw
                before = len(self.received)
                result = await adapter._send_with_retry("test-room", "hello", base_delay=0)
                self.assertFalse(result.success)
                self.assertIsNone(result.message_id)
                self.assertFalse(result.retryable)
                self.assertEqual(len(self.received), before + 1)

    async def test_xml_room_metadata_and_malformed_backoff(self):
        adapter = await self.connected(api_user="offline-user", api_password="offline-password")
        self.lookup_raw = (b"<ocs><meta><status>ok</status><statuscode>200</statuscode></meta>"
                           b"<data><type>1</type></data></ocs>")
        self.assertEqual(await adapter._get_room_type("room-one"), 1)
        self.lookup_raw = b"<ocs>"
        self.assertEqual(await adapter._get_room_type("room-two"), 2)
        self.assertEqual(await adapter._get_room_type("room-three"), 2)
        self.assertEqual(self.lookups, 2)

    async def test_outbound_redirect_not_followed(self):
        adapter = await self.connected()
        self.response_status = 307
        self.response_headers = {"Location": "/redirect-target"}
        result = await adapter._send_with_retry("test-room", "hello", base_delay=0)
        self.assertFalse(result.success)
        self.assertEqual(result.raw_response["http_status"], 307)
        self.assertEqual(len(self.received), 1)

    async def test_outbound_timeout_is_unknown_no_blind_retry(self):
        adapter = self.make(base_url=await self.server())
        adapter._http_timeout = ClientTimeout(total=0.03, connect=0.02, sock_read=0.02)
        self.assertTrue(await adapter.connect())
        self.response_delay = 0.08
        result = await adapter._send_with_retry("test-room", "hello", base_delay=0)
        self.assertFalse(result.success)
        self.assertFalse(result.retryable)
        self.assertEqual(result.raw_response["delivery_state"], "unknown")
        self.assertEqual(len(self.received), 1)

    async def test_outbound_connection_failure_and_disconnected_send(self):
        url = await self.server()
        await self.servers[-1].close()
        adapter = self.make(base_url=url)
        result = await adapter.send("test-room", "hello")
        self.assertEqual(result.raw_response["delivery_state"], "not_sent")
        self.assertTrue(await adapter.connect())
        # Refused connection to the just-closed fake server, never a production
        # endpoint. Transport errors conservatively remain unconfirmed.
        result = await adapter._send_with_retry("test-room", "hello", base_delay=0)
        self.assertFalse(result.success)
        self.assertEqual(result.raw_response["delivery_state"], "unknown")

    async def test_invalid_outbound_input_never_posts(self):
        adapter = await self.connected()
        for room, text, reply in (("../bad", "hello", None), ("test-room", "", None),
                                  ("test-room", "x" * 32001, None), ("test-room", [], None),
                                  ("test-room", "hello", True)):
            result = await adapter.send(room, text, reply_to=reply)
            self.assertEqual(result.raw_response["delivery_state"], "not_sent")
        self.assertFalse(self.received)

    async def test_room_metadata_success_cache_and_dm(self):
        adapter = await self.connected(api_user="offline-user", api_password="offline-password")
        handoff = self.admit(adapter)
        await self.post(adapter)
        self.assertEqual(handoff.await_args.args[0].source.chat_type, "dm")
        self.assertEqual((await adapter.get_chat_info("test-room"))["type"], "dm")
        self.assertEqual(self.lookups, 1)
        value, _ = adapter._room_type_cache.entries["test-room"]
        adapter._room_type_cache.entries["test-room"] = (value, 0)
        await adapter.get_chat_info("test-room")
        self.assertEqual(self.lookups, 2)

    async def test_room_lookup_failure_global_backoff_recovery(self):
        adapter = await self.connected(api_user="offline-user", api_password="offline-password")
        self.lookup_status = 401
        self.assertEqual(await adapter._get_room_type("room-one"), 2)
        self.assertEqual(await adapter._get_room_type("room-two"), 2)
        self.assertEqual(self.lookups, 1)
        self.assertEqual(adapter._lookup_failures, 1)
        adapter._lookup_retry_at = 0
        self.assertEqual(await adapter._get_room_type("room-one"), 2)
        self.assertEqual(adapter._lookup_failures, 2)
        self.lookup_status = 200
        adapter._lookup_retry_at = 0
        self.assertEqual(await adapter._get_room_type("room-one"), 1)
        self.assertEqual(adapter._lookup_failures, 0)
        self.assertEqual(self.lookups, 3)

    async def test_room_lookup_malformed_and_timeout_backoff(self):
        adapter = await self.connected(api_user="offline-user", api_password="offline-password")
        self.lookup_body = ocs({"type": True})
        self.assertEqual(await adapter._get_room_type("room-one"), 2)
        self.lookup_body = ocs({"type": 1})
        adapter._lookup_retry_at = 0
        adapter._lookup_timeout = ClientTimeout(total=0.03, sock_read=0.02)
        self.lookup_delay = 0.08
        self.assertEqual(await adapter._get_room_type("room-one"), 2)
        self.assertEqual(await adapter._get_room_type("room-two"), 2)
        self.assertEqual(self.lookups, 2)

    async def test_room_lookup_optional_and_singleflight(self):
        adapter = await self.connected()
        self.assertEqual(await adapter._get_room_type("room-one"), 2)
        self.assertEqual(self.lookups, 0)
        adapter._api_user, adapter._api_pass = "offline-user", "offline-password"
        self.lookup_delay = 0.02
        self.assertEqual(await asyncio.gather(*(adapter._get_room_type("room-one") for _ in range(5))), [1] * 5)
        self.assertEqual(self.lookups, 1)

    async def test_session_lifecycle_timeouts_and_reconnect(self):
        adapter = self.make()
        self.assertIsNone(adapter._session)
        self.assertTrue(await adapter.connect())
        session, runner = adapter._session, adapter._runner
        self.assertEqual(session.timeout.total, 20)
        self.assertEqual(session.timeout.connect, 5)
        self.assertEqual(session.timeout.sock_read, 15)
        self.assertTrue(await adapter.connect())
        self.assertIs(adapter._session, session)
        self.assertIs(adapter._runner, runner)
        await adapter.disconnect()
        self.assertTrue(session.closed)
        self.assertIsNone(adapter._session)
        self.assertIsNone(adapter._runner)
        self.assertIsNone(adapter._site)
        self.assertFalse(adapter._running)
        await adapter.disconnect()
        self.assertTrue(await adapter.connect())
        self.assertIsNot(adapter._session, session)

    async def test_identity_lock_same_process_and_no_reuse_port(self):
        one = self.make()
        self.assertTrue(await one.connect())
        duplicate = self.make()
        self.assertFalse(await duplicate.connect())
        self.assertIsNone(duplicate._session)
        # Different identity, same listener port: must fail bind, not load-share.
        port = one._site._server.sockets[0].getsockname()[1]
        two = self.make(bot_secret="different-offline-fixture", webhook_port=port)
        self.assertFalse(await two.connect())
        self.assertIsNone(two._session)
        self.assertIsNone(two._runner)
        self.assertIsNone(two._owned_identity)
        await one.disconnect()
        self.assertTrue(await duplicate.connect())

    async def test_connect_failure_cleanup_and_cancellation(self):
        adapter = self.make()
        sessions = []
        real_session = mod.ClientSession
        def capture_session(*args, **kwargs):
            session = real_session(*args, **kwargs)
            sessions.append(session)
            return session
        with patch.object(mod, "ClientSession", side_effect=capture_session), \
             patch.object(mod.web.TCPSite, "start", side_effect=RuntimeError("fixture")):
            self.assertFalse(await adapter.connect())
        self.assertTrue(sessions[-1].closed)
        self.assertIsNone(adapter._runner)
        self.assertIsNone(adapter._owned_identity)
        with patch.object(mod, "ClientSession", side_effect=capture_session), \
             patch.object(mod.web.TCPSite, "start", side_effect=asyncio.CancelledError):
            with self.assertRaises(asyncio.CancelledError):
                await adapter.connect()
        self.assertTrue(sessions[-1].closed)
        self.assertIsNone(adapter._owned_identity)
        self.assertTrue(await adapter.connect())

    async def test_connect_lock_denial_creates_no_session(self):
        adapter = self.make()
        with patch.object(adapter, "_acquire_platform_lock", return_value=False), \
             patch.object(mod, "ClientSession") as factory:
            self.assertFalse(await adapter.connect())
            factory.assert_not_called()
        self.assertIsNone(adapter._owned_identity)

    async def test_disconnect_runner_error_still_closes_session(self):
        adapter = self.make()
        self.assertTrue(await adapter.connect())
        session = adapter._session
        real_cleanup = adapter._runner.cleanup
        async def cleanup_error():
            await real_cleanup()
            raise RuntimeError("fixture")
        with patch.object(mod.web.AppRunner, "cleanup", side_effect=cleanup_error):
            with self.assertRaises(RuntimeError):
                await adapter.disconnect()
        self.assertTrue(session.closed)
        self.assertIsNone(adapter._owned_identity)
        self.assertFalse(adapter._running)

    async def test_scoped_secrets_env_precedence_and_unrelated_secret_ignored(self):
        with patch.dict(os.environ, {"NC_TALK_BOT_SECRET": "process-fixture",
                                     "NC_TALK_BASE_URL": "http://127.0.0.1:2",
                                     "NC_TALK_BOT_SECRET_OTHER_PROFILE": SECRET,
                                     "NC_TALK_IGNORE_BOTS": "false"}):
            adapter = self.make()
            self.assertEqual(adapter._secret, b"process-fixture")
            self.assertFalse(adapter._ignore_bots)
            self.assertFalse(adapter._verify_inbound(NONCE, Request(payload()).body,
                                                     Request(payload()).headers["X-Nextcloud-Talk-Signature"]))
            with patch.object(secret_scope, "_MULTIPLEX_ACTIVE", True):
                token = secret_scope.set_secret_scope({"NC_TALK_BOT_SECRET": "scoped-fixture",
                                                       "NC_TALK_BASE_URL": "http://127.0.0.1:3"})
                try:
                    scoped = self.make()
                    self.assertEqual(scoped._secret, b"scoped-fixture")
                    self.assertEqual(scoped._base_url, "http://127.0.0.1:3")
                    self.assertTrue(scoped._ignore_bots)  # no process-env bleed
                    self.assertTrue(plugin.check_requirements())
                    self.assertEqual(plugin._env_enablement()["bot_secret"], "scoped-fixture")
                finally:
                    secret_scope.reset_secret_scope(token)
                token = secret_scope.set_secret_scope({})
                try:
                    self.assertTrue(plugin.check_requirements())  # dependencies, not credentials
                    self.assertFalse(plugin.validate_config(PlatformConfig(extra={})))
                    self.assertIsNone(plugin._env_enablement())
                    self.assertEqual(self.make()._secret, SECRET.encode())  # own YAML
                finally:
                    secret_scope.reset_secret_scope(token)

    async def test_config_only_real_sdk_factory(self):
        self.assertTrue(plugin.check_requirements())
        self.assertIsNone(plugin._env_enablement())
        config = PlatformConfig(extra={"base_url": "http://127.0.0.1:1", "bot_secret": SECRET,
                                       "webhook_host": "127.0.0.1", "webhook_port": 0})
        adapter = platform_registry.create_adapter("nextcloud_talk", config)
        self.assertIsInstance(adapter, mod.NextcloudTalkAdapter)
        self.adapters.append(adapter)
        self.assertTrue(await adapter.connect())
        self.assertIsNone(platform_registry.create_adapter("nextcloud_talk", PlatformConfig(extra={})))

    async def test_bad_url_connect_is_controlled(self):
        for url in ("http://[broken", "http://127.0.0.1:bad", "ftp://127.0.0.1", "", "http://user:password@127.0.0.1"):
            adapter = self.make(base_url=url)
            self.assertFalse(await adapter.connect())
            self.assertIsNone(adapter._session)
            self.assertIsNone(adapter._owned_identity)

    async def test_client_session_constructor_failure_cleans_connector(self):
        adapter = self.make()
        connectors = []
        real_connector = mod.TCPConnector
        def capture_connector(*args, **kwargs):
            connector = real_connector(*args, **kwargs)
            connectors.append(connector)
            return connector
        with patch.object(mod, "TCPConnector", side_effect=capture_connector), \
             patch.object(mod, "ClientSession", side_effect=RuntimeError("fixture")):
            self.assertFalse(await adapter.connect())
        self.assertTrue(connectors[0].closed)
        self.assertIsNone(adapter._owned_identity)

    async def test_registration_seeding_and_boolean_validation(self):
        class Context:
            def register_platform(inner, **kwargs):
                inner.values = kwargs
        ctx = Context()
        plugin.register(ctx)
        self.assertIs(ctx.values["adapter_factory"], mod.NextcloudTalkAdapter)
        self.assertEqual(ctx.values["name"], "nextcloud_talk")
        with patch.dict(os.environ, {"NC_TALK_BASE_URL": "http://127.0.0.1:3",
                                     "NC_TALK_BOT_SECRET": SECRET,
                                     "NC_TALK_WEBHOOK_PORT": "12345", "NC_TALK_HOME_ROOM": "home-room",
                                     "NC_TALK_IGNORE_BOTS": "false"}):
            seed = plugin._env_enablement()
            self.assertEqual(seed["webhook_port"], "12345")
            self.assertEqual(seed["home_channel"]["chat_id"], "home-room")
            self.assertEqual(seed["ignore_bots"], "false")
            self.assertTrue(plugin.validate_config(PlatformConfig(extra={})))
        for value in ("false", "0", False):
            self.assertFalse(self.make(ignore_bots=value)._ignore_bots)
        for value in ("true", "1", True):
            self.assertTrue(self.make(ignore_bots=value)._ignore_bots)
        with self.assertRaises(ValueError):
            self.make(ignore_bots="maybe")


if __name__ == "__main__":
    try:
        unittest.main(verbosity=2)
    finally:
        SANDBOX.cleanup()
