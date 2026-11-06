"""Offline Gmail adapter regression tests; never authorize a real account."""
import asyncio
import builtins
import importlib
import json
from pathlib import Path
import sys
import threading
import tempfile
from types import ModuleType, SimpleNamespace
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from exceptions import NetworkError


def load_client():
    try:
        return importlib.import_module("gmail_client").GmailClient
    except ImportError as exc:
        raise AssertionError("Gmail must import offline without Google libraries") from exc


def config(**overrides):
    values = dict(ACK_POLICY="none", TARGET_SENDER="", TARGET_SUBJECT="",
                  GMAIL_REQUEST_TIMEOUT_SECONDS=3, GMAIL_MAX_ATTEMPTS=3,
                  GMAIL_MAX_PAGES=20, GMAIL_RETRY_BASE_SECONDS=0,
                  TOKEN_FILE=Path("unused-token.json"),
                  CREDENTIALS_FILE=Path("unused-credentials.json"))
    values.update(overrides)
    return SimpleNamespace(**values)


class APIError(Exception):
    def __init__(self, status):
        self.resp = SimpleNamespace(status=status)


class FakeService:
    """Only the actual Google discovery request boundary is replaced."""
    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = []
        self.executions = []
        self.active = 0
        self.maximum_active = 0

    def users(self):
        return self

    def messages(self):
        return self

    def attachments(self):
        return self

    def _request(self, operation, kwargs):
        self.calls.append((operation, kwargs))
        owner = self

        class Request:
            def execute(self, **execute_kwargs):
                owner.executions.append((threading.get_ident(), execute_kwargs))
                owner.active += 1
                owner.maximum_active = max(owner.maximum_active, owner.active)
                try:
                    response = owner.responses.pop(0)
                    if callable(response):
                        return response()
                    if isinstance(response, BaseException):
                        raise response
                    return response
                finally:
                    owner.active -= 1
        return Request()

    def list(self, **kwargs):
        return self._request("list", kwargs)

    def get(self, **kwargs):
        return self._request("get", kwargs)

    def modify(self, **kwargs):
        return self._request("modify", kwargs)


class GmailAdapterTests(unittest.IsolatedAsyncioTestCase):
    def test_import_and_constructor_are_offline(self):
        real_import = builtins.__import__

        def guarded(name, *args, **kwargs):
            if name.startswith(("google", "httplib2")):
                self.fail("Constructor/import attempted a Google dependency")
            return real_import(name, *args, **kwargs)

        with patch("builtins.__import__", side_effect=guarded):
            module = importlib.import_module("gmail_client")
            client = module.GmailClient(config())
        self.assertIsNone(client.service)
        self.assertFalse(hasattr(client, "trash_email"))

    async def test_every_page_is_read_beyond_first_fifty(self):
        first = [{"id": f"m{i}", "threadId": f"t{i}"} for i in range(50)]
        service = FakeService([{"messages": first, "nextPageToken": "second"},
                               {"messages": [{"id": "m50", "threadId": "t50"}]}])
        client = load_client()(config(), service=service)
        result = await client.get_unread_emails()
        self.assertEqual(len(result), 51)
        self.assertEqual(result[-1]["id"], "m50")
        self.assertEqual(service.calls[1][1]["pageToken"], "second")
        self.assertTrue(all(t != threading.get_ident() for t, _ in service.executions))

    async def test_configured_query_restriction_is_not_broadened(self):
        service = FakeService([{}])
        client = load_client()(config(GMAIL_QUERY="label:Print subject:invoice", TARGET_SENDER="sender@example.invalid"), service=service)
        await client.get_unread_emails()
        self.assertEqual(service.calls[0][1]["q"],
                         'is:unread -in:trash -in:spam (label:Print subject:invoice) from:"sender@example.invalid"')

    def test_optional_default_paths_do_not_initialize_or_read_credentials(self):
        client = load_client()(config(TOKEN_FILE=None, CREDENTIALS_FILE=None))
        self.assertIsNone(client.service)

    async def test_page_budget_continues_next_poll_without_starvation(self):
        service = FakeService([{"messages": [{"id": "a"}], "nextPageToken": "p2"},
                               {"messages": [{"id": "b"}]}])
        client = load_client()(config(GMAIL_MAX_PAGES=1), service=service)
        self.assertEqual(await client.get_unread_emails(), [{"id": "a"}])
        self.assertEqual(await client.get_unread_emails(), [{"id": "b"}])
        self.assertEqual(service.calls[1][1]["pageToken"], "p2")

    async def test_expired_pagination_cursor_resets_for_next_poll(self):
        service = FakeService([{"messages": [{"id": "a"}], "nextPageToken": "expired"},
                               APIError(400), {"messages": [{"id": "a"}]}])
        client = load_client()(config(GMAIL_MAX_PAGES=1), service=service)
        await client.get_unread_emails()
        with self.assertRaises(NetworkError):
            await client.get_unread_emails()
        await client.get_unread_emails()
        self.assertNotIn("pageToken", service.calls[-1][1])

    async def test_repeated_pagination_token_is_rejected(self):
        service = FakeService([{"nextPageToken": "same"}, {"nextPageToken": "same"}])
        client = load_client()(config(), service=service)
        with self.assertRaises(NetworkError):
            await client.get_unread_emails()
        self.assertEqual(len(service.executions), 2)

    async def test_transient_http_failure_has_capped_retries(self):
        service = FakeService([APIError(429), APIError(503), APIError(500), {"id": "no"}])
        client = load_client()(config(), service=service)
        with self.assertRaises(NetworkError):
            await client.get_email("message")
        self.assertEqual(len(service.executions), 3)
        self.assertEqual(len(service.responses), 1)
        self.assertTrue(all(kwargs == {"num_retries": 0} for _, kwargs in service.executions))

    async def test_permission_error_is_not_retried(self):
        service = FakeService([APIError(403), {"id": "unexpected"}])
        client = load_client()(config(), service=service)
        with self.assertRaises(NetworkError):
            await client.get_email("message")
        self.assertEqual(len(service.executions), 1)

    async def test_transient_error_then_success_and_attachment_adapter(self):
        service = FakeService([APIError(503), {"id": "message", "payload": {}},
                               {"data": "JVBERi0=", "size": 5}])
        client = load_client()(config(), service=service)
        self.assertEqual((await client.get_email("message"))["id"], "message")
        self.assertEqual(await client.get_attachment("message", "attachment"),
                         {"data": "JVBERi0=", "size": 5})
        self.assertEqual(service.calls[-1], ("get", {"userId": "me", "messageId": "message", "id": "attachment"}))

    async def test_mark_read_requires_explicit_policy_and_only_removes_unread(self):
        service = FakeService([{}])
        client = load_client()(config(), service=service)
        with self.assertRaises(NetworkError):
            await client.mark_read("message")
        self.assertEqual(service.calls, [])
        allowed = load_client()(config(ACK_POLICY="mark-read"), service=service)
        await allowed.mark_read("message")
        self.assertEqual(service.calls, [("modify", {"userId": "me", "id": "message", "body": {"removeLabelIds": ["UNREAD"]}})])

    async def test_blocking_transport_is_serialized_even_after_cancellation(self):
        entered = threading.Event()
        release = threading.Event()

        def slow_response():
            entered.set()
            release.wait(2)
            return {"id": "first"}

        service = FakeService([slow_response, {"id": "second"}])
        client = load_client()(config(), service=service)
        task = asyncio.create_task(client.get_email("first"))
        await asyncio.to_thread(entered.wait, 1)
        task.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await task
        second = asyncio.create_task(client.get_email("second"))
        await asyncio.sleep(0.02)
        self.assertEqual(service.maximum_active, 1)
        release.set()
        self.assertEqual((await second)["id"], "second")
        self.assertEqual(service.maximum_active, 1)


class GoogleDependencyFixture:
    """Model Google construction only; every transport is inert."""
    def __init__(self):
        self.records = {}
        self.service = FakeService([])
        self.credentials = SimpleNamespace(valid=True, expired=False, refresh_token=None)
        names = ("httplib2", "google_auth_httplib2", "google", "google.oauth2",
                 "google.oauth2.credentials", "googleapiclient", "googleapiclient.discovery")
        self.modules = {name: ModuleType(name) for name in names}
        for name in ("google", "google.oauth2", "googleapiclient"):
            self.modules[name].__path__ = []

        def http(**kwargs):
            self.records["http"] = kwargs
            return "inert-http"

        def authorized(credentials, **kwargs):
            self.records["authorized"] = kwargs
            return "inert-authorized-http"

        def build(*args, **kwargs):
            self.records["build"] = (args, kwargs)
            return self.service

        self.modules["httplib2"].Http = http
        self.modules["google_auth_httplib2"].AuthorizedHttp = authorized
        self.modules["google_auth_httplib2"].Request = lambda http: http
        self.modules["google.oauth2.credentials"].Credentials = SimpleNamespace(
            from_authorized_user_file=lambda *args: self.credentials)
        self.modules["googleapiclient.discovery"].build = build


class GmailAuthenticationTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.token = Path(self.temp.name) / "private-token.json"

    def tearDown(self):
        self.temp.cleanup()

    async def test_token_setup_has_bounded_transport_and_no_hidden_auth_retry(self):
        self.token.write_text(json.dumps({"scopes": ["https://www.googleapis.com/auth/gmail.readonly"]}))
        fixture = GoogleDependencyFixture()
        with patch.dict(sys.modules, fixture.modules):
            client = load_client()(config(TOKEN_FILE=self.token))
            await client.initialize()
        self.assertIs(client.service, fixture.service)
        self.assertEqual(fixture.records["http"], {"timeout": 3})
        self.assertEqual(fixture.records["authorized"].get("max_refresh_attempts"), 0)
        self.assertEqual(fixture.records["build"], (("gmail", "v1"), {"http": "inert-authorized-http", "cache_discovery": False}))

    async def test_wrong_scope_and_corrupt_tokens_are_preserved_without_auth(self):
        for content in ('{"scopes":["https://www.googleapis.com/auth/gmail.modify"]}',
                        "NOT-JSON-PRIVATE-TOKEN"):
            with self.subTest(content=content):
                self.token.write_text(content)
                fixture = GoogleDependencyFixture()
                with patch.dict(sys.modules, fixture.modules):
                    client = load_client()(config(TOKEN_FILE=self.token))
                    with self.assertRaises(NetworkError) as caught:
                        await client.initialize()
                self.assertEqual(self.token.read_text(), content)
                self.assertNotIn(content, str(caught.exception))
                self.assertNotIn("build", fixture.records)

    async def test_missing_token_never_starts_implicit_authentication(self):
        fixture = GoogleDependencyFixture()
        with patch.dict(sys.modules, fixture.modules):
            client = load_client()(config(TOKEN_FILE=self.token))
            with self.assertRaises(NetworkError) as caught:
                await client.initialize()
        self.assertIn("explicit", str(caught.exception))
        self.assertFalse(self.token.exists())

    def test_token_atomic_replace_failure_preserves_predecessor(self):
        self.token.write_text("PREDECESSOR")
        client = load_client()(config(TOKEN_FILE=self.token))
        credentials = SimpleNamespace(to_json=lambda: "SUCCESSOR")
        with patch("gmail_client.os.replace", side_effect=OSError("inert simulated write fault")):
            with self.assertRaises(NetworkError):
                client._save_credentials(credentials)
        self.assertEqual(self.token.read_text(), "PREDECESSOR")
        self.assertEqual(list(self.token.parent.iterdir()), [self.token])
        client._save_credentials(credentials)
        self.assertEqual(self.token.read_text(), "SUCCESSOR")


if __name__ == "__main__":
    unittest.main()
