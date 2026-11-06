"""Gmail transport with explicit authentication and bounded, serialized reads.

Importing this module and constructing a client perform no I/O. Injected
services support offline tests; the real Google transport is created only by
``initialize``. Raw API errors and token contents are never logged here.
"""
import asyncio
import json
import os
from pathlib import Path
import tempfile
import threading

from exceptions import NetworkError


class GmailClient:
    READ_SCOPE = "https://www.googleapis.com/auth/gmail.readonly"
    MODIFY_SCOPE = "https://www.googleapis.com/auth/gmail.modify"

    def __init__(self, config, service=None):
        self.config = config
        self.service = service
        self.scopes = [self.MODIFY_SCOPE if getattr(config, "ACK_POLICY", "none") == "mark-read" else self.READ_SCOPE]
        self.token_file = Path(getattr(config, "TOKEN_FILE", None) or "token.json")
        self.credentials_file = Path(getattr(config, "CREDENTIALS_FILE", None) or "credentials.json")
        self.request_timeout = self._bounded_number("GMAIL_REQUEST_TIMEOUT_SECONDS", 30, 0.1, 300)
        self.max_attempts = int(self._bounded_number("GMAIL_MAX_ATTEMPTS", 3, 1, 5, integer=True))
        self.max_pages = int(self._bounded_number("GMAIL_MAX_PAGES", 20, 1, 1000, integer=True))
        self.retry_base = self._bounded_number("GMAIL_RETRY_BASE_SECONDS", 1, 0, 10)
        # A cancelled to_thread await does not stop its thread. This lock lives
        # inside the worker and therefore survives cancellation of its caller.
        self._transport_lock = threading.Lock()
        self._page_token = None
        self._page_query = None

    def _bounded_number(self, name, default, minimum, maximum, integer=False):
        value = getattr(self.config, name, default)
        if isinstance(value, bool) or not isinstance(value, (float, int)):
            raise ValueError(f"Invalid {name}")
        if not minimum <= value <= maximum or (integer and int(value) != value):
            raise ValueError(f"Invalid {name}")
        return value

    async def initialize(self, authenticate=False):
        """Load/refresh a saved token; browser consent requires explicit opt-in.

        Corrupt, overprivileged and failed-refresh token files are preserved.
        ``authenticate=True`` is the only path that can open a consent browser.
        """
        if self.service is not None:
            return True
        if not isinstance(authenticate, bool):
            raise ValueError("authenticate must be boolean")
        self.service = await asyncio.to_thread(self._build_service, authenticate)
        return True

    def _build_service(self, authenticate):
        try:
            import httplib2
            import google_auth_httplib2
            from google.oauth2.credentials import Credentials
            from google_auth_httplib2 import Request
            from googleapiclient.discovery import build
        except ImportError:
            raise NetworkError("Google transport dependencies are not installed") from None

        with self._transport_lock:
            creds = None
            if self.token_file.exists():
                try:
                    creds = Credentials.from_authorized_user_file(str(self.token_file), self.scopes)
                    saved = json.loads(self.token_file.read_text(encoding="utf-8"))
                    saved_scopes = saved.get("scopes", [])
                    if isinstance(saved_scopes, str):
                        saved_scopes = saved_scopes.split()
                    if not isinstance(saved_scopes, list):
                        raise ValueError("Invalid saved scope declaration")
                    gmail_scopes = {s for s in saved_scopes if isinstance(s, str) and "googleapis.com/auth/gmail" in s}
                    if gmail_scopes != set(self.scopes):
                        raise ValueError("Saved Gmail scopes do not match policy")
                except Exception:
                    if not authenticate:
                        raise NetworkError("Saved token could not be loaded for this policy; file preserved") from None
                    creds = None

            transport = httplib2.Http(timeout=self.request_timeout)
            if creds is not None and not creds.valid:
                if creds.expired and creds.refresh_token:
                    try:
                        creds.refresh(Request(transport))
                        self._save_credentials(creds)
                    except Exception:
                        if not authenticate:
                            raise NetworkError("Saved token refresh failed; file preserved") from None
                        creds = None
                else:
                    creds = None

            if creds is None:
                if not authenticate:
                    raise NetworkError("Authentication required; run the explicit authentication command")
                try:
                    from google_auth_oauthlib.flow import InstalledAppFlow
                    flow = InstalledAppFlow.from_client_secrets_file(str(self.credentials_file), self.scopes)
                    creds = flow.run_local_server(port=0, timeout_seconds=180, open_browser=True,
                                                  authorization_prompt_message="Complete Gmail consent in your browser.",
                                                  success_message="Gmail authorization complete. You may close this window.")
                    if not creds or not creds.valid:
                        raise ValueError("No valid authorization result")
                    self._save_credentials(creds)
                except Exception:
                    raise NetworkError("Explicit Gmail authentication failed; existing token preserved") from None

            try:
                authorized = google_auth_httplib2.AuthorizedHttp(creds, http=transport, max_refresh_attempts=0)
                return build("gmail", "v1", http=authorized, cache_discovery=False)
            except Exception:
                raise NetworkError("Gmail service initialization failed") from None

    def _save_credentials(self, credentials):
        """Atomically replace a token only after a valid refresh/consent result."""
        content = credentials.to_json()
        self.token_file.parent.mkdir(parents=True, exist_ok=True)
        temporary = None
        try:
            with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=self.token_file.parent,
                                             prefix=".gmail-token-", suffix=".tmp", delete=False) as handle:
                temporary = Path(handle.name)
                handle.write(content)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary, self.token_file)
        except Exception:
            raise NetworkError("Token could not be saved atomically; previous file preserved") from None
        finally:
            if temporary is not None and temporary.exists():
                temporary.unlink(missing_ok=True)

    def _execute_once(self, factory):
        with self._transport_lock:
            request = factory(self.service)
            # Disable Google's independent retry loop; our classified budget
            # is the only application-level request retry budget.
            return request.execute(num_retries=0)

    async def _execute(self, factory, *, retry=True):
        if self.service is None:
            raise NetworkError("Gmail service has not been explicitly initialized")
        attempts = self.max_attempts if retry else 1
        for attempt in range(attempts):
            try:
                result = await asyncio.to_thread(self._execute_once, factory)
                if not isinstance(result, dict):
                    raise NetworkError("Gmail returned an invalid response")
                return result
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                status = getattr(getattr(exc, "resp", None), "status", None)
                transient = isinstance(status, int) and (status == 429 or 500 <= status <= 599)
                if not transient or attempt + 1 >= attempts:
                    detail = f"HTTP {status}" if isinstance(status, int) else "transport or response failure"
                    failure = NetworkError(f"Gmail request failed ({detail})")
                    failure.status = status
                    raise failure from None
                await asyncio.sleep(min(self.retry_base * (2 ** attempt), 30))
        raise NetworkError("Gmail request budget exhausted")

    @staticmethod
    def _identifier(value):
        if not isinstance(value, str) or not value or len(value) > 4096 or any(ord(c) < 32 for c in value):
            raise ValueError("Invalid Gmail identifier")
        return value

    @staticmethod
    def _query_value(value):
        if not isinstance(value, str) or any(ord(c) < 32 for c in value):
            raise ValueError("Invalid Gmail search filter")
        return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'

    def _query(self):
        query = ["is:unread", "-in:trash", "-in:spam"]
        restriction = getattr(self.config, "GMAIL_QUERY", None)
        if restriction is not None:
            if (not isinstance(restriction, str) or not restriction.strip() or len(restriction) > 1024
                    or any(ord(c) < 32 or ord(c) == 127 for c in restriction)):
                raise ValueError("Invalid configured Gmail query")
            query.append("(" + restriction + ")")
        sender = getattr(self.config, "TARGET_SENDER", "")
        subject = getattr(self.config, "TARGET_SUBJECT", "")
        if sender:
            query.append("from:" + self._query_value(sender))
        if subject:
            query.append("subject:" + self._query_value(subject))
        return " ".join(query)

    async def get_unread_emails(self):
        """Read all pages within a budget, resuming the next poll fairly.

        Pagination is a best-effort mailbox view rather than a snapshot.
        Durable deduplication belongs to the caller. A budget-limited poll
        resumes its continuation token, wrapping after the last page.
        """
        query = self._query()
        token = self._page_token if self._page_query == query else None
        tokens_seen = {token} if token else set()
        messages = []
        ids_seen = set()
        for _ in range(self.max_pages):
            kwargs = {"userId": "me", "q": query, "maxResults": 500}
            if token:
                kwargs["pageToken"] = token
            try:
                page = await self._execute(lambda service, kw=kwargs: service.users().messages().list(**kw))
            except NetworkError as exc:
                if token and getattr(exc, "status", None) == 400:
                    # Gmail pagination tokens can expire as the mailbox changes.
                    # Reset for the next bounded poll; do not loop on one token.
                    self._page_query, self._page_token = None, None
                raise
            entries = page.get("messages", [])
            if not isinstance(entries, list):
                raise NetworkError("Gmail returned invalid message entries")
            for item in entries:
                if not isinstance(item, dict) or not isinstance(item.get("id"), str) or not item["id"]:
                    raise NetworkError("Gmail returned an invalid message identity")
                if item["id"] not in ids_seen:
                    ids_seen.add(item["id"])
                    messages.append(item)
            token = page.get("nextPageToken")
            if not token:
                token = None
                break
            if not isinstance(token, str) or len(token) > 4096 or token in tokens_seen:
                raise NetworkError("Gmail returned invalid pagination")
            tokens_seen.add(token)
        self._page_query, self._page_token = query, token
        return messages

    async def get_email(self, message_id):
        self._identifier(message_id)
        return await self._execute(lambda service: service.users().messages().get(userId="me", id=message_id, format="full"))

    async def get_attachment(self, message_id, attachment_id):
        self._identifier(message_id)
        self._identifier(attachment_id)
        return await self._execute(lambda service: service.users().messages().attachments().get(
            userId="me", messageId=message_id, id=attachment_id))

    async def mark_read(self, message_id):
        if getattr(self.config, "ACK_POLICY", "none") != "mark-read":
            raise NetworkError("Mark-read acknowledgment is disabled by policy")
        self._identifier(message_id)
        return await self._execute(lambda service: service.users().messages().modify(
            userId="me", id=message_id, body={"removeLabelIds": ["UNREAD"]}), retry=False)
