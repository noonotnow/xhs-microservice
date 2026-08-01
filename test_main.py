import asyncio
import json
import os
import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest.mock import patch

import httpx
from fastapi import HTTPException
from fastapi.testclient import TestClient

sys.modules.setdefault("xhshow", types.SimpleNamespace(Xhshow=object))

import main


MP4_BYTES = b"\x00\x00\x00\x18ftypmp42" + b"\x00" * 32
MEDIA_URL = "https://images.xhs.justlikekatie.com/videos/assets/post.mp4"


class QRLoginRouteTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.qr_file_patch = patch.object(
            main,
            "QR_STATE_FILE",
            os.path.join(self.temp_dir.name, "qr_state.json"),
        )
        self.qr_file_patch.start()
        self.client = TestClient(main.app)
        self.headers = {"X-Api-Key": main.API_KEY}

    def tearDown(self):
        self.qr_file_patch.stop()
        self.temp_dir.cleanup()

    def test_qr_generation_requires_api_key(self):
        Path(main.QR_STATE_FILE).write_text('{"stale": true}')
        response = self.client.get("/login/qr")
        self.assertEqual(response.status_code, 403)
        self.assertTrue(os.path.exists(main.QR_STATE_FILE))

    def test_qr_generation_is_disabled_and_clears_stale_state(self):
        Path(main.QR_STATE_FILE).write_text('{"stale": true}')
        response = self.client.get("/login/qr", headers=self.headers)

        self.assertEqual(response.status_code, 503)
        self.assertEqual(
            response.json()["detail"],
            main.CREATOR_QR_UNAVAILABLE_DETAIL,
        )
        self.assertEqual(
            response.json()["detail"]["code"],
            "CREATOR_QR_UNAVAILABLE",
        )
        self.assertIn(
            "https://creator.rednote.com/login",
            response.json()["detail"]["message"],
        )
        self.assertNotIn("xymerchant", response.text)
        self.assertFalse(os.path.exists(main.QR_STATE_FILE))
        self.assertIn("no-store", response.headers["cache-control"])

    def test_qr_status_is_disabled_and_clears_stale_state(self):
        Path(main.QR_STATE_FILE).write_text('{"stale": true}')
        response = self.client.get("/login/status", headers=self.headers)

        self.assertEqual(response.status_code, 503)
        self.assertEqual(
            response.json()["detail"]["code"],
            "CREATOR_QR_UNAVAILABLE",
        )
        self.assertFalse(os.path.exists(main.QR_STATE_FILE))
        self.assertIn("no-store", response.headers["cache-control"])

class CreatorQRProtocolTests(unittest.TestCase):
    def test_health_reports_deployed_revision(self):
        with patch.object(main, "APP_REVISION", "commit-sha"):
            response = TestClient(main.app).get("/health")

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["revision"], "commit-sha")

    def test_global_error_response_does_not_leak_traceback(self):
        request = types.SimpleNamespace(
            method="GET",
            url=types.SimpleNamespace(path="/login/qr"),
        )
        response = asyncio.run(
            main.global_exception_handler(
                request,
                RuntimeError("secret response payload"),
            )
        )

        self.assertEqual(response.status_code, 500)
        self.assertEqual(
            json.loads(response.body),
            {"error": "Internal server error"},
        )


class CookieLoginRouteTests(unittest.TestCase):
    def setUp(self):
        self.client = TestClient(main.app)
        self.headers = {"X-Api-Key": main.API_KEY}
        self.original_client = main.client

    def tearDown(self):
        main.client = self.original_client

    def test_accepts_only_creator_valid_cookie_and_preserves_equals_in_value(self):
        candidate = object()
        with (
            patch.object(
                main,
                "_new_creator_client",
                return_value=candidate,
            ),
            patch.object(
                main,
                "_validate_creator_session",
                return_value=main.CreatorSessionValidation(valid=True),
            ),
            patch.object(main, "_save_and_swap_client") as save_and_swap,
        ):
            response = self.client.post(
                "/login/cookie",
                headers=self.headers,
                json={
                    "cookie": (
                        "a1=fresh-a1; web_session=session-with-padding==; "
                        "webId=browser-id"
                    )
                },
            )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["valid"], True)
        save_and_swap.assert_called_once_with(
            "a1=fresh-a1; web_session=session-with-padding==; webId=browser-id",
            candidate,
        )

    def test_rejects_devtools_table_export_without_echoing_input(self):
        response = self.client.post(
            "/login/cookie",
            headers=self.headers,
            json={
                "cookie": (
                    "web_session\tsecret-value\t.rednote.com\t/\tSession"
                )
            },
        )

        self.assertEqual(response.status_code, 400)
        self.assertEqual(
            response.json()["detail"],
            (
                "Expected a Cookie request-header value in "
                "'name=value; name=value' format. DevTools cookie table "
                "exports are not accepted."
            ),
        )
        self.assertNotIn("secret-value", response.text)

    def test_rejects_header_without_required_session_cookies(self):
        response = self.client.post(
            "/login/cookie",
            headers=self.headers,
            json={"cookie": "webId=browser-id; xsecappid=ugc"},
        )

        self.assertEqual(response.status_code, 400)
        self.assertIn("a1 and web_session", response.json()["detail"])

    def test_cookie_login_requires_api_key_before_parsing(self):
        response = self.client.post(
            "/login/cookie",
            json={"cookie": "not a valid cookie header"},
        )

        self.assertEqual(response.status_code, 403)

    def test_creator_redirect_does_not_persist_or_replace_working_client(self):
        working_client = object()
        candidate = object()
        main.client = working_client
        validation = main.CreatorSessionValidation(
            valid=False,
            error_code="creator_session_invalid",
            relogin_required=True,
            reason="redirect",
            upstream_status=302,
        )
        with (
            patch.object(
                main,
                "_new_creator_client",
                return_value=candidate,
            ),
            patch.object(
                main,
                "_validate_creator_session",
                return_value=validation,
            ),
            patch.object(main, "_save_and_swap_client") as save_and_swap,
        ):
            response = self.client.post(
                "/login/cookie",
                headers=self.headers,
                json={"cookie": "a1=new-secret; web_session=new-session"},
            )

        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.json()["valid"], False)
        self.assertEqual(response.json()["relogin_required"], True)
        self.assertEqual(
            response.json()["error"]["code"],
            "creator_session_invalid",
        )
        self.assertEqual(response.json()["error"]["reason"], "redirect")
        self.assertEqual(response.json()["error"]["upstream_status"], 302)
        save_and_swap.assert_not_called()
        self.assertIs(main.client, working_client)
        self.assertNotIn("new-secret", response.text)
        self.assertNotIn("new-session", response.text)

    def test_validation_unavailable_does_not_persist_or_replace_working_client(self):
        working_client = object()
        candidate = object()
        main.client = working_client
        validation = main.CreatorSessionValidation(
            valid=False,
            error_code="creator_session_validation_unavailable",
        )
        with (
            patch.object(
                main,
                "_new_creator_client",
                return_value=candidate,
            ),
            patch.object(
                main,
                "_validate_creator_session",
                return_value=validation,
            ),
            patch.object(main, "_save_and_swap_client") as save_and_swap,
        ):
            response = self.client.post(
                "/login/cookie",
                headers=self.headers,
                json={"cookie": "a1=new-secret; web_session=new-session"},
            )

        self.assertEqual(response.status_code, 502)
        self.assertEqual(
            response.json()["error"]["code"],
            "creator_session_validation_unavailable",
        )
        save_and_swap.assert_not_called()
        self.assertIs(main.client, working_client)
        self.assertNotIn("new-secret", response.text)
        self.assertNotIn("new-session", response.text)

    def test_failed_validation_preserves_cookie_file_and_active_client_atomically(self):
        working_client = object()
        candidate = object()
        main.client = working_client
        failures = (
            (
                main.CreatorSessionValidation(
                    valid=False,
                    error_code="creator_session_invalid",
                    relogin_required=True,
                    reason="http_401",
                    upstream_status=401,
                ),
                401,
            ),
            (
                main.CreatorSessionValidation(
                    valid=False,
                    error_code="creator_session_validation_unavailable",
                    upstream_status=503,
                ),
                502,
            ),
        )
        with tempfile.TemporaryDirectory() as data_dir:
            cookie_file = os.path.join(data_dir, "cookie.json")
            with (
                patch.object(main, "DATA_DIR", data_dir),
                patch.object(main, "COOKIE_FILE", cookie_file),
            ):
                main.save_cookie("a1=working-secret; web_session=working-session")
                for validation, expected_status in failures:
                    with (
                        self.subTest(expected_status=expected_status),
                        patch.object(
                            main,
                            "_new_creator_client",
                            return_value=candidate,
                        ),
                        patch.object(
                            main,
                            "_validate_creator_session",
                            return_value=validation,
                        ),
                        patch.object(main, "_save_and_swap_client") as save_and_swap,
                    ):
                        response = self.client.post(
                            "/login/cookie",
                            headers=self.headers,
                            json={
                                "cookie": (
                                    "a1=replacement-secret; "
                                    "web_session=replacement-session"
                                )
                            },
                        )

                    self.assertEqual(response.status_code, expected_status)
                    self.assertEqual(
                        main.load_cookie(),
                        "a1=working-secret; web_session=working-session",
                    )
                    self.assertIs(main.client, working_client)
                    save_and_swap.assert_not_called()
                    self.assertNotIn("replacement-secret", response.text)
                    self.assertNotIn("replacement-session", response.text)

    def test_session_failure_does_not_return_upstream_payload(self):
        upstream_error = "cookie=must-not-escape"
        response_payload = {
            "success": False,
            "code": -1,
            "result": -100,
            "msg": upstream_error,
        }
        upstream_response = types.SimpleNamespace(
            is_redirect=False,
            is_permanent_redirect=False,
            status_code=200,
            json=lambda: response_payload,
        )
        with (
            patch.object(
                main,
                "get_client",
                return_value=types.SimpleNamespace(
                    cookie="a1=current; web_session=current"
                ),
            ),
            patch.object(
                main,
                "_request_creator_validation",
                return_value=upstream_response,
            ),
        ):
            response = self.client.get(
                "/session/status",
                headers=self.headers,
            )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["valid"], False)
        self.assertEqual(response.json()["relogin_required"], True)
        self.assertEqual(
            response.json()["error"]["code"],
            "creator_session_invalid",
        )
        self.assertEqual(
            response.json()["error"]["reason"],
            "api_session_expired",
        )
        self.assertEqual(response.json()["error"]["upstream_status"], 200)
        self.assertEqual(response.json()["error"]["upstream_code"], -100)
        self.assertNotIn(upstream_error, response.text)

    def test_cookie_login_and_status_share_creator_validation_contract(self):
        candidate = types.SimpleNamespace(
            cookie="a1=fresh; web_session=fresh"
        )
        validation = main.CreatorSessionValidation(valid=True)
        with (
            patch.object(
                main,
                "_new_creator_client",
                return_value=candidate,
            ),
            patch.object(
                main,
                "_validate_creator_session",
                return_value=validation,
            ),
            patch.object(main, "get_client", return_value=candidate),
            patch.object(main, "_save_and_swap_client") as save_and_swap,
        ):
            login_response = self.client.post(
                "/login/cookie",
                headers=self.headers,
                json={"cookie": "a1=fresh; web_session=fresh"},
            )
            status_response = self.client.get(
                "/session/status",
                headers=self.headers,
            )

        save_and_swap.assert_called_once()
        for key in (
            "valid",
            "session_type",
            "validation",
            "relogin_required",
        ):
            self.assertEqual(
                login_response.json()[key],
                status_response.json()[key],
            )

    def test_saved_cookie_file_is_private_and_old_file_is_tightened(self):
        with tempfile.TemporaryDirectory() as data_dir:
            cookie_file = os.path.join(data_dir, "cookie.json")
            with (
                patch.object(main, "DATA_DIR", data_dir),
                patch.object(main, "COOKIE_FILE", cookie_file),
            ):
                main.save_cookie("a1=fresh; web_session=fresh")
                self.assertEqual(os.stat(cookie_file).st_mode & 0o777, 0o600)

                os.chmod(cookie_file, 0o644)
                self.assertEqual(
                    main.load_cookie(),
                    "a1=fresh; web_session=fresh",
                )
                self.assertEqual(os.stat(cookie_file).st_mode & 0o777, 0o600)


class CreatorSessionValidationTests(unittest.TestCase):
    @staticmethod
    def _response(status_code, payload=None, headers=None):
        response = main.requests.Response()
        response.status_code = status_code
        response.headers.update(headers or {})
        if payload is not None:
            response.headers["Content-Type"] = "application/json"
            response._content = json.dumps(payload).encode()
        else:
            response._content = b""
        return response

    def test_uses_exact_cookie_header_signing_and_browser_request_without_mutation(self):
        class RecordingAdapter(main.requests.adapters.BaseAdapter):
            def __init__(self):
                self.requests = []

            def send(self, request, **kwargs):
                self.requests.append((request, kwargs))
                response = CreatorSessionValidationTests._response(
                    200,
                    {
                        "success": True,
                        "data": {
                            "uploadTempPermits": [
                                {"fileIds": ["file-id"], "token": "token"}
                            ]
                        },
                    },
                    {"Set-Cookie": "server_cookie=must-not-mutate; Path=/"},
                )
                response.request = request
                return response

            def close(self):
                pass

        cookie_header = (
            "a1=signing-cookie; web_session=authenticated-session; "
            "webId=submitted-browser; path_scoped=submitted-value"
        )
        candidate = main._new_creator_client(cookie_header)
        candidate.session.cookies.clear()
        for name, value in main._parse_cookie_header(cookie_header).items():
            candidate.session.cookies.set(
                name,
                value,
                domain=".rednote.com",
                path="/login",
            )
        candidate.session.cookies.set(
            "jar-only",
            "must-not-be-sent",
            domain=".rednote.com",
            path="/",
        )
        original_headers = dict(candidate.session.headers)
        original_cookies = [
            (cookie.name, cookie.value, cookie.domain, cookie.path)
            for cookie in candidate.session.cookies
        ]
        adapter = RecordingAdapter()
        candidate.session.mount("https://", adapter)
        with patch.object(
            main,
            "creator_sign",
            return_value={
                "x-s": "signed",
                "x-t": "time",
                "x-s-common": "common",
            },
        ) as creator_sign:
            validation = main._validate_creator_session(
                candidate,
                cookie_header,
            )

        self.assertEqual(validation, main.CreatorSessionValidation(valid=True))
        creator_sign.assert_called_once_with(
            main.REDNOTE_CREATOR_VALIDATION_URI,
            None,
            a1="signing-cookie",
        )
        request, request_kwargs = adapter.requests[0]
        self.assertEqual(
            request.url,
            f"{main.REDNOTE_CREATOR_HOST}{main.REDNOTE_CREATOR_VALIDATION_URI}",
        )
        self.assertEqual(request.method, "GET")
        self.assertEqual(request.headers["Cookie"], cookie_header)
        self.assertNotIn("jar-only", request.headers["Cookie"])
        self.assertEqual(request.headers["Origin"], main.REDNOTE_CREATOR_HOST)
        self.assertEqual(
            request.headers["Referer"],
            f"{main.REDNOTE_CREATOR_HOST}/publish/publish",
        )
        self.assertIn("Mozilla/5.0", request.headers["User-Agent"])
        self.assertEqual(
            request.headers["Accept"],
            "application/json, text/plain, */*",
        )
        self.assertEqual(request.headers["x-s"], "signed")
        self.assertEqual(request.headers["x-t"], "time")
        self.assertEqual(request.headers["x-s-common"], "common")
        self.assertEqual(request.headers["Sec-Fetch-Dest"], "empty")
        self.assertEqual(request.headers["Sec-Fetch-Mode"], "cors")
        self.assertEqual(request.headers["Sec-Fetch-Site"], "same-origin")
        self.assertEqual(request_kwargs["timeout"], candidate.timeout)
        self.assertEqual(dict(candidate.session.headers), original_headers)
        self.assertEqual(
            [
                (cookie.name, cookie.value, cookie.domain, cookie.path)
                for cookie in candidate.session.cookies
            ],
            original_cookies,
        )

    def test_submitted_cookie_values_are_not_replaced_by_supplemental_defaults(self):
        candidate = main._new_creator_client(
            "a1=submitted-a1; web_session=submitted-session; "
            "webId=submitted-web-id; xsecappid=submitted-app"
        )

        self.assertEqual(candidate.cookie_dict["webId"], "submitted-web-id")
        self.assertEqual(candidate.cookie_dict["xsecappid"], "submitted-app")
        self.assertEqual(
            [cookie.name for cookie in candidate.session.cookies].count("webId"),
            1,
        )
        self.assertEqual(
            [cookie.name for cookie in candidate.session.cookies].count(
                "xsecappid"
            ),
            1,
        )

    def test_redirect_and_http_auth_failures_have_sanitized_reasons(self):
        cases = (
            (
                types.SimpleNamespace(
                    is_redirect=True,
                    is_permanent_redirect=False,
                    status_code=302,
                    headers={"Location": "https://secret.example/login"},
                ),
                "redirect",
                302,
            ),
            (
                types.SimpleNamespace(
                    is_redirect=False,
                    is_permanent_redirect=False,
                    status_code=401,
                ),
                "http_401",
                401,
            ),
            (
                types.SimpleNamespace(
                    is_redirect=False,
                    is_permanent_redirect=False,
                    status_code=403,
                ),
                "http_403",
                403,
            ),
        )
        for response, reason, status in cases:
            with (
                self.subTest(reason=reason),
                patch.object(
                    main,
                    "_request_creator_validation",
                    return_value=response,
                ),
                self.assertLogs(main.logger, level="INFO") as captured,
            ):
                validation = main._validate_creator_session(
                    object(),
                    "a1=secret-a1; web_session=secret-session",
                )

            self.assertEqual(
                validation,
                main.CreatorSessionValidation(
                    valid=False,
                    error_code="creator_session_invalid",
                    relogin_required=True,
                    reason=reason,
                    upstream_status=status,
                ),
            )
            payload = main._session_status_payload(validation)
            self.assertEqual(payload["error"]["reason"], reason)
            self.assertEqual(payload["error"]["upstream_status"], status)
            self.assertNotIn("secret.example", json.dumps(payload))
            log_text = " ".join(captured.output)
            self.assertNotIn("secret.example", log_text)
            self.assertNotIn("Location", log_text)
            self.assertNotIn("secret-a1", log_text)
            self.assertNotIn("secret-session", log_text)

    def test_api_session_expiry_exposes_only_safe_numeric_diagnostics(self):
        response = types.SimpleNamespace(
            is_redirect=False,
            is_permanent_redirect=False,
            status_code=200,
            json=lambda: {
                "success": True,
                "code": -100,
                "data": {
                    "uploadTempPermits": [
                        {"fileIds": ["file-id"], "token": "token"}
                    ]
                },
                "msg": "raw-upstream-secret",
                "headers": {"Cookie": "a1=raw-secret"},
            },
        )
        with (
            patch.object(
                main,
                "_request_creator_validation",
                return_value=response,
            ),
            self.assertLogs(main.logger, level="INFO") as captured,
        ):
            validation = main._validate_creator_session(
                object(),
                "a1=submitted-secret; web_session=submitted-session",
            )

        self.assertEqual(
            validation,
            main.CreatorSessionValidation(
                valid=False,
                error_code="creator_session_invalid",
                relogin_required=True,
                reason="api_session_expired",
                upstream_status=200,
                upstream_code=-100,
            ),
        )
        payload_text = json.dumps(main._session_status_payload(validation))
        log_text = " ".join(captured.output)
        for secret in (
            "raw-upstream-secret",
            "raw-secret",
            "submitted-secret",
            "submitted-session",
            "a1",
            "web_session",
            "Cookie",
        ):
            self.assertNotIn(secret, payload_text)
            self.assertNotIn(secret, log_text)

    def test_response_contract_drops_unrecognized_or_non_numeric_diagnostics(self):
        payload = main._session_status_payload(
            main.CreatorSessionValidation(
                valid=False,
                error_code="creator_session_invalid",
                relogin_required=True,
                reason="raw-upstream-secret",
                upstream_status="401",
                upstream_code={"secret": "value"},
            )
        )

        self.assertEqual(
            payload["error"],
            {
                "code": "creator_session_invalid",
                "message": (
                    "Creator session is not authenticated; "
                    "re-login is required."
                ),
            },
        )
        self.assertNotIn("raw-upstream-secret", json.dumps(payload))

    def test_server_and_unexpected_responses_are_unavailable_not_invalid(self):
        responses = (
            types.SimpleNamespace(
                is_redirect=False,
                is_permanent_redirect=False,
                status_code=503,
            ),
            types.SimpleNamespace(
                is_redirect=False,
                is_permanent_redirect=False,
                status_code=200,
                json=lambda: {
                    "success": False,
                    "code": -1,
                    "msg": "raw-secret",
                },
            ),
            types.SimpleNamespace(
                is_redirect=False,
                is_permanent_redirect=False,
                status_code=200,
                json=lambda: {"success": True, "data": {"name": "creator"}},
            ),
            types.SimpleNamespace(
                is_redirect=False,
                is_permanent_redirect=False,
                status_code=200,
                json=lambda: {
                    "success": True,
                    "data": {"uploadTempPermits": [{}]},
                },
            ),
            types.SimpleNamespace(
                is_redirect=False,
                is_permanent_redirect=False,
                status_code=200,
                json=lambda: {
                    "success": True,
                    "data": {
                        "uploadTempPermits": [
                            {"fileIds": [""], "token": ""}
                        ]
                    },
                },
            ),
            types.SimpleNamespace(
                is_redirect=False,
                is_permanent_redirect=False,
                status_code=200,
                json=lambda: {
                    "success": True,
                    "data": {
                        "uploadTempPermits": [
                            {"fileIds": ["   "], "token": "\t"}
                        ]
                    },
                },
            ),
            types.SimpleNamespace(
                is_redirect=False,
                is_permanent_redirect=False,
                status_code=200,
                json=lambda: {
                    "success": True,
                    "code": -1,
                    "data": {
                        "uploadTempPermits": [
                            {"fileIds": ["file-id"], "token": "token"}
                        ]
                    },
                },
            ),
            self._response(
                200,
                headers={
                    "Location": "https://raw-secret.example",
                    "X-Raw-Secret": "raw-secret",
                },
            ),
        )
        for response in responses:
            with (
                self.subTest(status_code=response.status_code),
                patch.object(
                    main,
                    "_request_creator_validation",
                    return_value=response,
                ),
                self.assertLogs(main.logger, level="WARNING") as captured,
            ):
                validation = main._validate_creator_session(
                    object(),
                    "a1=secret-a1; web_session=secret-session",
                )

            self.assertFalse(validation.valid)
            self.assertEqual(
                validation.error_code,
                "creator_session_validation_unavailable",
            )
            self.assertFalse(validation.relogin_required)
            self.assertIsNone(validation.reason)
            self.assertEqual(
                validation.upstream_status,
                response.status_code,
            )
            payload_text = json.dumps(main._session_status_payload(validation))
            self.assertNotIn("raw-secret", payload_text)
            self.assertNotIn("secret-a1", payload_text)
            self.assertNotIn("secret-session", payload_text)
            log_text = " ".join(captured.output)
            self.assertNotIn("raw-secret", log_text)
            self.assertNotIn("secret-a1", log_text)
            self.assertNotIn("secret-session", log_text)
            self.assertNotIn("Location", log_text)

    def test_transport_failure_is_validation_unavailable(self):
        with (
            patch.object(
                main,
                "_request_creator_validation",
                side_effect=main.requests.ConnectionError(
                    "upstream-secret"
                ),
            ),
            self.assertLogs(main.logger, level="WARNING") as captured,
        ):
            validation = main._validate_creator_session(
                object(),
                "a1=submitted-secret; web_session=submitted-session",
            )

        self.assertEqual(
            validation,
            main.CreatorSessionValidation(
                valid=False,
                error_code="creator_session_validation_unavailable",
            ),
        )
        log_text = " ".join(captured.output)
        self.assertNotIn("upstream-secret", log_text)
        self.assertNotIn("submitted-secret", log_text)
        self.assertNotIn("submitted-session", log_text)


class RemoteVideoDownloadTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.upload_dir_patch = patch.object(main, "UPLOAD_DIR", self.temp_dir.name)
        self.upload_dir_patch.start()

    def tearDown(self):
        self.upload_dir_patch.stop()
        self.temp_dir.cleanup()

    def _client(self, handler):
        return httpx.AsyncClient(transport=httpx.MockTransport(handler))

    async def test_stages_trusted_mp4(self):
        def handler(request):
            self.assertEqual(str(request.url), MEDIA_URL)
            return httpx.Response(
                200,
                headers={"Content-Type": "video/mp4"},
                content=MP4_BYTES,
            )

        async with self._client(handler) as client:
            filepath = await main._stage_remote_media_video(MEDIA_URL, client)

        self.assertEqual(Path(filepath).read_bytes(), MP4_BYTES)

    async def test_rejects_untrusted_host_before_request(self):
        async with self._client(
            lambda request: self.fail("request should not run")
        ) as client:
            with self.assertRaises(HTTPException) as raised:
                await main._stage_remote_media_video(
                    "https://example.com/videos/assets/post.mp4",
                    client,
                )
        self.assertEqual(raised.exception.status_code, 400)

    def test_rejects_invalid_port(self):
        with self.assertRaises(HTTPException) as raised:
            main._validate_media_video_url(
                "https://images.xhs.justlikekatie.com:invalid/videos/assets/post.mp4"
            )
        self.assertEqual(raised.exception.status_code, 400)

    def test_rejects_dot_segment_path(self):
        with self.assertRaises(HTTPException) as raised:
            main._validate_media_video_url(
                "https://images.xhs.justlikekatie.com/videos/assets/../private.mp4"
            )
        self.assertEqual(raised.exception.status_code, 400)

    async def test_rejects_redirect(self):
        async with self._client(
            lambda request: httpx.Response(
                302,
                headers={"Location": "https://example.com/post.mp4"},
            )
        ) as client:
            with self.assertRaises(HTTPException) as raised:
                await main._stage_remote_media_video(MEDIA_URL, client)
        self.assertEqual(raised.exception.status_code, 502)
        self.assertEqual(os.listdir(self.temp_dir.name), [])

    async def test_rejects_non_mp4_body(self):
        async with self._client(
            lambda request: httpx.Response(
                200,
                headers={"Content-Type": "video/mp4"},
                content=b"not an mp4 file",
            )
        ) as client:
            with self.assertRaises(HTTPException) as raised:
                await main._stage_remote_media_video(MEDIA_URL, client)
        self.assertEqual(raised.exception.status_code, 415)
        self.assertEqual(os.listdir(self.temp_dir.name), [])

    async def test_rejects_oversized_body_and_removes_partial_file(self):
        async with self._client(
            lambda request: httpx.Response(
                200,
                headers={"Content-Type": "video/mp4"},
                content=MP4_BYTES,
            )
        ) as client:
            with (
                patch.object(main, "MAX_REMOTE_VIDEO_BYTES", 16),
                self.assertRaises(HTTPException) as raised,
            ):
                await main._stage_remote_media_video(MEDIA_URL, client)
        self.assertEqual(raised.exception.status_code, 413)
        self.assertEqual(os.listdir(self.temp_dir.name), [])

    async def test_enforces_total_download_deadline(self):
        class SlowStream(httpx.AsyncByteStream):
            async def __aiter__(self):
                await asyncio.sleep(0.05)
                yield MP4_BYTES

        async with self._client(
            lambda request: httpx.Response(
                200,
                headers={"Content-Type": "video/mp4"},
                stream=SlowStream(),
            )
        ) as client:
            with (
                patch.object(main, "REMOTE_VIDEO_DOWNLOAD_TIMEOUT_SECONDS", 0.01),
                self.assertRaises(HTTPException) as raised,
            ):
                await main._stage_remote_media_video(MEDIA_URL, client)
        self.assertEqual(raised.exception.status_code, 504)
        self.assertEqual(os.listdir(self.temp_dir.name), [])

    async def test_cancellation_removes_partial_file(self):
        class SlowStream(httpx.AsyncByteStream):
            async def __aiter__(self):
                yield MP4_BYTES
                await asyncio.sleep(10)

        async with self._client(
            lambda request: httpx.Response(
                200,
                headers={"Content-Type": "video/mp4"},
                stream=SlowStream(),
            )
        ) as client:
            task = asyncio.create_task(
                main._stage_remote_media_video(MEDIA_URL, client)
            )
            await asyncio.sleep(0)
            task.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await task

        self.assertEqual(os.listdir(self.temp_dir.name), [])


class RemoteVideoEndpointTests(unittest.IsolatedAsyncioTestCase):
    async def test_requires_permanent_api_key_before_staging(self):
        request = main.RemoteVideoPublishRequest(
            video_url=MEDIA_URL,
            title="Ready post",
            caption="Prepared caption",
        )
        with (
            patch.object(main, "_stage_remote_media_video") as stage,
            self.assertRaises(HTTPException) as raised,
        ):
            await main.publish_video_url(request, x_api_key=None)

        self.assertEqual(raised.exception.status_code, 403)
        stage.assert_not_called()

    async def test_returns_stable_success_and_removes_staged_file(self):
        with tempfile.NamedTemporaryFile(suffix=".mp4", delete=False) as staged:
            staged.write(MP4_BYTES)
            staged_path = staged.name

        request = main.RemoteVideoPublishRequest(
            video_url=MEDIA_URL,
            title="Ready post",
            caption="Prepared caption",
            tags=["travel"],
        )
        with (
            patch.object(main, "_stage_remote_media_video", return_value=staged_path),
            patch.object(main, "_get_video_metadata", return_value={}),
            patch.object(
                main,
                "publish_video",
                return_value={"status": "success", "note_id": "note-123"},
            ),
        ):
            result = await main.publish_video_url(request, x_api_key=main.API_KEY)

        self.assertEqual(
            result,
            {
                "status": "success",
                "note_id": "note-123",
                "share_url": "https://www.xiaohongshu.com/explore/note-123",
            },
        )
        self.assertFalse(os.path.exists(staged_path))

    async def test_rejects_publish_without_note_id(self):
        with tempfile.NamedTemporaryFile(suffix=".mp4", delete=False) as staged:
            staged_path = staged.name

        request = main.RemoteVideoPublishRequest(
            video_url=MEDIA_URL,
            title="Ready post",
            caption="Prepared caption",
        )
        with (
            patch.object(main, "_stage_remote_media_video", return_value=staged_path),
            patch.object(main, "_get_video_metadata", return_value={}),
            patch.object(main, "publish_video", return_value={"status": "success"}),
            self.assertRaises(HTTPException) as raised,
        ):
            await main.publish_video_url(request, x_api_key=main.API_KEY)

        self.assertEqual(raised.exception.status_code, 502)
        self.assertFalse(os.path.exists(staged_path))

    async def test_rejects_unreadable_video_and_removes_staged_file(self):
        with tempfile.NamedTemporaryFile(suffix=".mp4", delete=False) as staged:
            staged_path = staged.name

        request = main.RemoteVideoPublishRequest(
            video_url=MEDIA_URL,
            title="Ready post",
            caption="Prepared caption",
        )
        with (
            patch.object(main, "_stage_remote_media_video", return_value=staged_path),
            patch.object(
                main,
                "_get_video_metadata",
                side_effect=ValueError("invalid"),
            ),
            patch.object(main, "publish_video") as publish,
            self.assertRaises(HTTPException) as raised,
        ):
            await main.publish_video_url(request, x_api_key=main.API_KEY)

        self.assertEqual(raised.exception.status_code, 415)
        self.assertFalse(os.path.exists(staged_path))
        publish.assert_not_called()


if __name__ == "__main__":
    unittest.main()
