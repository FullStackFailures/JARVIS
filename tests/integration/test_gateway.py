"""Model gateway tests.

Labels: FAKE_REASONER = scripted in-process Reasoner (test double, exercises gateway logic only);
STUB_HTTP = a real local HTTP server speaking the Ollama / OpenAI wire formats, exercising the
real adapters and urllib transport. Neither proves behaviour against a real model.
"""

import json
import socket
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer

from jarvis.config.schema import OllamaConfig, RemoteConfig
from jarvis.core.models import HealthReport, ModelCapabilities, ModelError, ModelErrorClass, ModelRequest, ModelResponse
from jarvis.models.base import Reasoner
from jarvis.models.gateway import ModelGateway
from jarvis.models.ollama import OllamaReasoner
from jarvis.models.remote import OpenAICompatReasoner
from tests.harness import tags

SCHEMA = {"type": "object", "properties": {"x": {"type": "integer"}}, "required": ["x"], "additionalProperties": False}


class Fake(Reasoner):
    def __init__(self, bid, replies, local=True, healthy=True, schema=True):
        self.backend_id, self.local, self.replies, self.healthy, self.schema = bid, local, list(replies), healthy, schema
        self.calls = 0

    def capabilities(self):
        return ModelCapabilities(backend_id=self.backend_id, model="fake", supports_json_schema=self.schema,
                                 supports_open_planning=True, local=self.local)

    def health(self, deep=False):
        return HealthReport(backend_id=self.backend_id, server_reachable=self.healthy,
                            model_present=self.healthy, detail="" if self.healthy else "down")

    def complete(self, request):
        self.calls += 1
        r = self.replies.pop(0) if self.replies else "{}"
        if isinstance(r, ModelError):
            return ModelResponse(request_id=request.request_id, backend_id=self.backend_id, ok=False, error=r)
        return ModelResponse(request_id=request.request_id, backend_id=self.backend_id, ok=True, content=r)


def req(**kw):
    return ModelRequest(messages=[{"role": "user", "content": "go"}], **kw)


@tags("FAKE_REASONER")
class GatewayLogic(unittest.TestCase):
    def gw(self, backends, **kw):
        return ModelGateway(backends, sleep=lambda s: None, jitter=False, **kw)

    def test_fallback_when_primary_unhealthy(self):
        a, b = Fake("a", [], healthy=False), Fake("b", ['{"x":1}'])
        r = self.gw({"a": a, "b": b}, default="a", fallback_order=["b"]).route(req(response_schema=SCHEMA))
        self.assertTrue(r.ok)
        self.assertEqual(r.backend_id, "b")
        self.assertEqual(a.calls, 0)
        self.assertTrue(r.fallbacks_tried)

    def test_all_backends_down_returns_error_never_raises(self):
        r = self.gw({"a": Fake("a", [], healthy=False)}, default="a").route(req())
        self.assertFalse(r.ok)
        self.assertEqual(r.error.cls, ModelErrorClass.NO_BACKEND)

    def test_schema_repair_retry_once_then_success(self):
        a = Fake("a", ["not json", '{"x": 2}'])
        r = self.gw({"a": a}, default="a").route(req(response_schema=SCHEMA))
        self.assertTrue(r.ok)
        self.assertEqual(r.parsed, {"x": 2})
        self.assertEqual(a.calls, 2)

    def test_schema_still_invalid_after_repair_fails(self):
        a = Fake("a", ["nope", '{"x": "str"}', '{"x": "str"}'])
        r = self.gw({"a": a}, default="a").route(req(response_schema=SCHEMA))
        self.assertFalse(r.ok)
        self.assertLessEqual(a.calls, 2)

    def test_privacy_local_only_blocks_external(self):
        ext = Fake("remote", ['{"x":1}'], local=False)
        r = self.gw({"remote": ext}, default="remote").route(req(response_schema=SCHEMA))
        self.assertFalse(r.ok)
        self.assertEqual(ext.calls, 0)
        r2 = self.gw({"remote": Fake("remote", ['{"x":1}'], local=False)}, default="remote").route(
            req(response_schema=SCHEMA, privacy_class="may_leave_machine"))
        self.assertTrue(r2.ok)

    def test_non_retryable_error_not_retried(self):
        err = ModelError(cls=ModelErrorClass.AUTH, message="bad key", retryable=False)
        a = Fake("a", [err, '{"x":1}'])
        r = self.gw({"a": a}, default="a").route(req(response_schema=SCHEMA))
        self.assertFalse(r.ok)
        self.assertEqual(a.calls, 1)

    def test_retryable_error_is_retried(self):
        err = ModelError(cls=ModelErrorClass.TIMEOUT, message="slow", retryable=True)
        a = Fake("a", [err, '{"x":1}'])
        r = self.gw({"a": a}, default="a").route(req(response_schema=SCHEMA))
        self.assertTrue(r.ok)
        self.assertEqual(a.calls, 2)

    def test_native_backend_refuses_open_planning(self):
        from jarvis.brain.native_lite import NativeLiteReasoner
        r = self.gw({"native": NativeLiteReasoner()}, default="native").route(req(), require_open_planning=True)
        self.assertFalse(r.ok)


class _Handler(BaseHTTPRequestHandler):
    models = ["qwen2.5:7b"]
    chat_reply = '{"x": 5}'
    last_auth = None
    last_body = None

    def log_message(self, *a):
        pass

    def _send(self, code, obj):
        raw = json.dumps(obj).encode()
        self.send_response(code); self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw))); self.end_headers(); self.wfile.write(raw)

    def do_GET(self):
        type(self).last_auth = self.headers.get("Authorization")
        if self.path == "/api/tags":
            self._send(200, {"models": [{"name": m} for m in self.models]})
        elif self.path == "/v1/models":
            self._send(200 if self.last_auth == "Bearer sk-test" else 401,
                       {"data": [{"id": "gpt-x"}]} if self.last_auth == "Bearer sk-test" else {"error": "no"})
        else:
            self._send(404, {})

    def do_POST(self):
        n = int(self.headers.get("Content-Length", 0))
        type(self).last_body = json.loads(self.rfile.read(n) or b"{}")
        if self.path == "/api/chat":
            self._send(200, {"message": {"content": self.chat_reply}, "done": True, "eval_count": 3})
        elif self.path == "/v1/chat/completions":
            self._send(200, {"choices": [{"message": {"content": self.chat_reply}, "finish_reason": "stop"}],
                             "usage": {"prompt_tokens": 1, "completion_tokens": 2}})
        else:
            self._send(404, {})


@tags("STUB_HTTP")
class AdaptersAgainstStubServer(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.srv = HTTPServer(("127.0.0.1", 0), _Handler)
        cls.port = cls.srv.server_address[1]
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()
        cls.base = f"http://127.0.0.1:{cls.port}"

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown(); cls.srv.server_close()

    def test_ollama_three_level_health_and_generation(self):
        ok = OllamaReasoner(OllamaConfig(enabled=True, base_url=self.base, model="qwen2.5:7b"))
        h = ok.health(deep=True)
        self.assertTrue(h.server_reachable and h.model_present and h.generation_ok)
        missing = OllamaReasoner(OllamaConfig(enabled=True, base_url=self.base, model="llama3:70b")).health()
        self.assertTrue(missing.server_reachable)
        self.assertFalse(missing.model_present)
        self.assertNotEqual(missing.level, "AVAILABLE")

    def test_ollama_complete_sends_schema_and_returns_parsed_through_gateway(self):
        o = OllamaReasoner(OllamaConfig(enabled=True, base_url=self.base, model="qwen2.5:7b"))
        _Handler.chat_reply = '{"x": 5}'
        r = ModelGateway({"ollama": o}, default="ollama", sleep=lambda s: None).route(req(response_schema=SCHEMA))
        self.assertTrue(r.ok, r.error)
        self.assertEqual(r.parsed, {"x": 5})
        self.assertEqual(_Handler.last_body["format"], SCHEMA)

    def test_ollama_server_down(self):
        s = socket.socket(); s.bind(("127.0.0.1", 0)); port = s.getsockname()[1]; s.close()
        o = OllamaReasoner(OllamaConfig(enabled=True, base_url=f"http://127.0.0.1:{port}", model="m", health_timeout_s=1))
        h = o.health()
        self.assertFalse(h.server_reachable)
        self.assertEqual(h.level, "UNREACHABLE")
        gw = ModelGateway({"ollama": o}, default="ollama", sleep=lambda s: None)
        r = gw.route(req())
        self.assertFalse(r.ok)  # reported, not raised

    def test_remote_requires_key_and_sends_bearer(self):
        cfg = RemoteConfig(enabled=True, base_url=self.base + "/v1", model="gpt-x", allow_task_content=True)
        nokey = OpenAICompatReasoner(cfg, api_key=lambda: None)
        self.assertFalse(nokey.health().configured)
        good = OpenAICompatReasoner(cfg, api_key=lambda: "sk-test")
        h = good.health(deep=True)
        self.assertTrue(h.server_reachable and h.generation_ok, h)
        bad = OpenAICompatReasoner(cfg, api_key=lambda: "sk-wrong")
        self.assertNotEqual(bad.health().level, "AVAILABLE")

    def test_remote_blocked_for_local_only_requests(self):
        cfg = RemoteConfig(enabled=True, base_url=self.base + "/v1", model="gpt-x")
        gw = ModelGateway({"remote": OpenAICompatReasoner(cfg, api_key=lambda: "sk-test")}, default="remote",
                          sleep=lambda s: None)
        self.assertFalse(gw.route(req()).ok)
        self.assertTrue(gw.route(req(privacy_class="may_leave_machine")).ok)


if __name__ == "__main__":
    unittest.main()
