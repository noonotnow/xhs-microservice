import asyncio
import io
import json
import os
import sys
import tempfile
import threading
import types
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch

import httpx
from fastapi import HTTPException
from fastapi.testclient import TestClient

sys.modules.setdefault("xhshow", types.SimpleNamespace(Xhshow=object))

import main


MP4_BYTES = b"\x00\x00\x00\x18ftypmp42" + b"\x00" * 32
MEDIA_URL = "https://images.xhs.justlikekatie.com/videos/assets/post.mp4"
NOTE_ID = "64b000000000000001234567"
SHARE_URL = f"https://www.xiaohongshu.com/explore/{NOTE_ID}"


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


class DebugPermitProbeSecurityTests(unittest.TestCase):
    def test_publish_steps_never_calls_or_echoes_permit_probes(self):
        permit_token = "synthetic-permit-token-canary"
        permit_file_id = "synthetic-permit-file-id-canary"
        raw_payload = "synthetic-raw-payload-canary"
        upstream_header = "synthetic-upstream-header-canary"
        cookie_value = "synthetic-cookie-canary"

        class FakeClient:
            cookie_dict = {"a1": cookie_value}

            def __init__(self):
                self.get_calls = []

            def get_self_info(self):
                return {}

            def get(self, uri, *args, **kwargs):
                self.get_calls.append(uri)
                if "permit" in uri:
                    payload = {
                        "uploadTempPermits": [
                            {
                                "token": permit_token,
                                "fileIds": [permit_file_id],
                            }
                        ],
                        "raw": raw_payload,
                        "headers": {"X-Synthetic": upstream_header},
                        "cookie": cookie_value,
                    }
                    print(payload)
                    return payload
                return {}

            def get_suggest_topic(self, keyword):
                return []

        fake_client = FakeClient()
        stdout = io.StringIO()
        with (
            patch.object(main, "get_client", return_value=fake_client),
            patch(
                "sign_service.sign",
                return_value={
                    "x-s": "synthetic-signature",
                    "x-s-common": "synthetic-common",
                },
            ),
            patch.object(main.logger, "info") as log_info,
            patch.object(main.logger, "warning") as log_warning,
            patch.object(main.logger, "error") as log_error,
            redirect_stdout(stdout),
        ):
            response = TestClient(main.app).get(
                "/debug/publish-steps",
                headers={"X-Api-Key": main.API_KEY},
            )

        self.assertEqual(response.status_code, 200)
        self.assertNotIn("2_upload_permit", response.json())
        self.assertNotIn("2b_creator_upload_permit", response.json())
        self.assertFalse(
            any("permit" in uri for uri in fake_client.get_calls)
        )
        log_info.assert_not_called()
        log_warning.assert_not_called()
        log_error.assert_not_called()
        output = " ".join((response.text, stdout.getvalue()))
        for canary in (
            permit_token,
            permit_file_id,
            raw_payload,
            upstream_header,
            cookie_value,
        ):
            self.assertNotIn(canary, output)


class CookieLoginRouteTests(unittest.TestCase):
    def setUp(self):
        self.client = TestClient(main.app)
        self.headers = {"X-Api-Key": main.API_KEY}
        self.original_active_client_state = main._active_client_state

    def tearDown(self):
        main._active_client_state = self.original_active_client_state

    def assert_cookie_parse_failure(
        self,
        submitted_cookie,
        expected_code,
        canaries=(),
        request_kwargs=None,
    ):
        working_client = object()
        working_cookie = "a1=working-secret; web_session=working-session"
        main._active_client_state = main.ActiveClientState(
            working_client,
            working_cookie,
        )
        stdout = io.StringIO()
        if request_kwargs is None:
            request_kwargs = {"json": {"cookie": submitted_cookie}}
        request_kwargs = dict(request_kwargs)
        request_headers = {
            **self.headers,
            **request_kwargs.pop("headers", {}),
        }
        with (
            patch.object(main, "_new_creator_client") as new_client,
            patch.object(main, "creator_sign") as creator_sign,
            patch.object(main, "_validate_creator_session") as validate,
            patch.object(main, "_save_and_swap_client") as save_and_swap,
            patch.object(main, "save_cookie") as save_cookie,
            patch.object(main.logger, "info") as log_info,
            patch.object(main.logger, "warning") as log_warning,
            patch.object(main.logger, "error") as log_error,
            redirect_stdout(stdout),
        ):
            response = self.client.post(
                "/login/cookie",
                headers=request_headers,
                **request_kwargs,
            )

        self.assertEqual(response.status_code, 400)
        self.assertEqual(
            response.json(),
            {
                "detail": {
                    "code": expected_code,
                    "message": main.COOKIE_HEADER_ERROR_MESSAGES[expected_code],
                }
            },
        )
        new_client.assert_not_called()
        creator_sign.assert_not_called()
        validate.assert_not_called()
        save_and_swap.assert_not_called()
        save_cookie.assert_not_called()
        log_info.assert_not_called()
        log_warning.assert_not_called()
        log_error.assert_not_called()
        self.assertEqual(
            main.get_client_snapshot(),
            (working_client, working_cookie),
        )
        output = " ".join((response.text, stdout.getvalue()))
        for canary in canaries:
            self.assertNotIn(canary, output)
        return response

    def test_accepts_only_creator_valid_cookie_and_preserves_equals_in_value(self):
        candidate = object()
        submitted_cookie = (
            "creator_antibot=host-scoped-synthetic; "
            "a1=fresh-a1; domain_state=domain-scoped-synthetic; "
            "web_session=session-with-padding==; webId=browser-id"
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
                return_value=main.CreatorSessionValidation(valid=True),
            ) as validate,
            patch.object(main, "_save_and_swap_client") as save_and_swap,
        ):
            response = self.client.post(
                "/login/cookie",
                headers=self.headers,
                json={"cookie": submitted_cookie},
            )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["valid"], True)
        validate.assert_called_once_with(candidate, submitted_cookie)
        save_and_swap.assert_called_once_with(submitted_cookie, candidate)
        for cookie_value in (
            "host-scoped-synthetic",
            "domain-scoped-synthetic",
            "fresh-a1",
            "session-with-padding==",
        ):
            self.assertNotIn(cookie_value, response.text)

    def test_accepts_optional_cookie_label_outer_spaces_and_trailing_newline(self):
        normalized = "a1=synthetic; web_session=synthetic"
        submissions = (
            (normalized, normalized),
            (f"  cOoKiE:  {normalized}  \r\n  ", normalized),
            (f"COOKIE: {normalized}\n", normalized),
            (
                "a1=latin-1-\u00e9; web_session=synthetic",
                "a1=latin-1-\u00e9; web_session=synthetic",
            ),
        )
        for submitted, expected in submissions:
            candidate = object()
            with (
                self.subTest(submitted=submitted),
                patch.object(
                    main,
                    "_new_creator_client",
                    return_value=candidate,
                ) as new_client,
                patch.object(
                    main,
                    "_validate_creator_session",
                    return_value=main.CreatorSessionValidation(valid=True),
                ) as validate,
                patch.object(main, "_save_and_swap_client") as save_and_swap,
            ):
                response = self.client.post(
                    "/login/cookie",
                    headers=self.headers,
                    json={"cookie": submitted},
                )

            self.assertEqual(response.status_code, 200)
            new_client.assert_called_once_with(expected)
            validate.assert_called_once_with(candidate, expected)
            save_and_swap.assert_called_once_with(expected, candidate)

    def test_nested_creator_permit_response_returns_only_sanitized_status(self):
        candidate = object()
        permit_token = "synthetic-placeholder-token"
        permit_file_id = "synthetic-placeholder-file-id"
        upstream_response = types.SimpleNamespace(
            is_redirect=False,
            is_permanent_redirect=False,
            status_code=200,
            json=lambda: {
                "success": True,
                "code": 0,
                "data": {
                    "result": {"success": True},
                    "uploadTempPermits": [
                        {
                            "token": permit_token,
                            "fileIds": [permit_file_id],
                        }
                    ],
                },
            },
        )
        with (
            patch.object(
                main,
                "_new_creator_client",
                return_value=candidate,
            ),
            patch.object(
                main,
                "_request_creator_validation",
                return_value=upstream_response,
            ),
            patch.object(main, "_save_and_swap_client") as save_and_swap,
            patch.object(main.logger, "info") as log_info,
            patch.object(main.logger, "warning") as log_warning,
        ):
            response = self.client.post(
                "/login/cookie",
                headers=self.headers,
                json={"cookie": "a1=synthetic; web_session=synthetic"},
            )

        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.json()["valid"])
        self.assertEqual(
            response.json()["validation"]["source"],
            "cookie_login_candidate",
        )
        save_and_swap.assert_called_once_with(
            "a1=synthetic; web_session=synthetic",
            candidate,
        )
        log_info.assert_not_called()
        log_warning.assert_not_called()
        for permit_value in (permit_token, permit_file_id):
            self.assertNotIn(permit_value, response.text)

    def test_rejects_malformed_cookie_headers_with_stable_sanitized_codes(self):
        cases = (
            (
                "devtools table export",
                "web_session\ttable-canary\t.rednote.com\t/\tSession",
                "cookie_header_control_character",
                ("table-canary",),
            ),
            (
                "duplicate names",
                (
                    "a1=first-canary; creator_antibot=synthetic; "
                    "a1=second-canary; web_session=synthetic"
                ),
                "cookie_header_duplicate_name",
                ("first-canary", "second-canary"),
            ),
            (
                "embedded CRLF second header",
                (
                    "a1=crlf-canary; web_session=synthetic\r\n"
                    "X-Injected: injection-canary"
                ),
                "cookie_header_control_character",
                ("crlf-canary", "injection-canary"),
            ),
            (
                "embedded newline",
                "a1=newline-canary\nweb_session=synthetic",
                "cookie_header_control_character",
                ("newline-canary",),
            ),
            (
                "multiple trailing newlines",
                "a1=newlines-canary; web_session=synthetic\n\n",
                "cookie_header_control_character",
                ("newlines-canary",),
            ),
            (
                "embedded tab",
                "a1=tab-canary;\tweb_session=synthetic",
                "cookie_header_control_character",
                ("tab-canary",),
            ),
            (
                "embedded null",
                "a1=null-canary;\x00web_session=synthetic",
                "cookie_header_control_character",
                ("null-canary",),
            ),
            (
                "invalid name",
                "invalid name=name-canary; a1=synthetic; web_session=synthetic",
                "cookie_header_invalid_name",
                ("name-canary",),
            ),
            (
                "non-Latin-1 value",
                "a1=unicode-canary-\U0001f512; web_session=synthetic",
                "cookie_header_invalid_value",
                ("unicode-canary", "\U0001f512"),
            ),
            (
                "missing equals",
                "pair-canary; a1=synthetic; web_session=synthetic",
                "cookie_header_missing_equals",
                ("pair-canary",),
            ),
            (
                "too large",
                (
                    "a1=size-canary; web_session="
                    + "x" * main.MAX_COOKIE_HEADER_BYTES
                ),
                "cookie_header_too_large",
                ("size-canary",),
            ),
            (
                "empty string",
                "",
                "cookie_header_empty",
                (),
            ),
            (
                "outer spaces",
                "   ",
                "cookie_header_empty",
                (),
            ),
            (
                "empty labeled header",
                " Cookie: \r\n ",
                "cookie_header_empty",
                (),
            ),
        )
        for name, submitted, code, canaries in cases:
            with self.subTest(name=name):
                self.assert_cookie_parse_failure(
                    submitted,
                    code,
                    canaries,
                )

    def test_rejects_missing_required_session_fields_with_distinct_safe_code(self):
        response = self.assert_cookie_parse_failure(
            "webId=browser-canary; xsecappid=ugc",
            "cookie_required_session_fields",
            ("browser-canary",),
        )

        self.assertNotIn("a1", response.text)
        self.assertNotIn("web_session", response.text)

    def test_sanitizes_invalid_cookie_request_shapes_without_reflection(self):
        cases = (
            (
                "missing field",
                {"json": {"other": "missing-canary"}},
                ("missing-canary",),
            ),
            (
                "object field",
                {"json": {"cookie": {"raw": "object-canary"}}},
                ("object-canary",),
            ),
            (
                "array field",
                {"json": {"cookie": ["array-canary"]}},
                ("array-canary",),
            ),
            (
                "numeric field",
                {"json": {"cookie": 12345}},
                (),
            ),
            (
                "malformed JSON",
                {
                    "content": '{"cookie":"malformed-canary"',
                    "headers": {"Content-Type": "application/json"},
                },
                ("malformed-canary",),
            ),
        )
        for name, request_kwargs, canaries in cases:
            with self.subTest(name=name):
                self.assert_cookie_parse_failure(
                    None,
                    "cookie_header_invalid_type",
                    canaries,
                    request_kwargs=request_kwargs,
                )

    def test_unrelated_request_validation_keeps_default_422_contract(self):
        response = self.client.post(
            "/publish",
            headers=self.headers,
            json={"title": {"synthetic": "value"}},
        )

        self.assertEqual(response.status_code, 422)
        self.assertIsInstance(response.json()["detail"], list)

    def test_rejects_duplicate_cookie_names_without_selecting_a_value(self):
        working_client = object()
        working_cookie = "a1=working-secret; web_session=working-session"
        main._active_client_state = main.ActiveClientState(
            working_client,
            working_cookie,
        )
        with tempfile.TemporaryDirectory() as data_dir:
            cookie_file = os.path.join(data_dir, "cookie.json")
            with (
                patch.object(main, "DATA_DIR", data_dir),
                patch.object(main, "COOKIE_FILE", cookie_file),
            ):
                main.save_cookie(working_cookie)
                with (
                    patch.object(main, "_new_creator_client") as new_client,
                    patch.object(main, "_validate_creator_session") as validate,
                    patch.object(main, "_save_and_swap_client") as save_and_swap,
                ):
                    response = self.client.post(
                        "/login/cookie",
                        headers=self.headers,
                        json={
                            "cookie": (
                                "a1=first-synthetic; "
                                "creator_antibot=synthetic; "
                                "a1=second-synthetic; "
                                "web_session=synthetic"
                            )
                        },
                    )
                persisted_cookie = main.load_cookie()

        self.assertEqual(response.status_code, 400)
        new_client.assert_not_called()
        validate.assert_not_called()
        save_and_swap.assert_not_called()
        self.assertEqual(persisted_cookie, working_cookie)
        self.assertEqual(
            main.get_client_snapshot(),
            (working_client, working_cookie),
        )
        self.assertNotIn("first-synthetic", response.text)
        self.assertNotIn("second-synthetic", response.text)

    def test_cookie_login_requires_api_key_before_parsing(self):
        response = self.client.post(
            "/login/cookie",
            json={"cookie": "not a valid cookie header"},
        )

        self.assertEqual(response.status_code, 403)

    def test_creator_redirect_does_not_persist_or_replace_working_client(self):
        working_client = object()
        candidate = object()
        main._active_client_state = main.ActiveClientState(
            working_client,
            "a1=working-secret; web_session=working-session",
        )
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
        self.assertIs(main._active_client_state.client, working_client)
        self.assertNotIn("new-secret", response.text)
        self.assertNotIn("new-session", response.text)

    def test_validation_unavailable_does_not_persist_or_replace_working_client(self):
        working_client = object()
        candidate = object()
        main._active_client_state = main.ActiveClientState(
            working_client,
            "a1=working-secret; web_session=working-session",
        )
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
        self.assertIs(main._active_client_state.client, working_client)
        self.assertNotIn("new-secret", response.text)
        self.assertNotIn("new-session", response.text)

    def test_conflicting_candidate_response_preserves_prior_session_atomically(self):
        working_client = object()
        candidate = object()
        main._active_client_state = main.ActiveClientState(
            working_client,
            "a1=working-secret; web_session=working-session",
        )
        upstream_marker = "synthetic-upstream-marker"
        response_payload = {
            "success": True,
            "code": 0,
            "data": {
                "result": {"success": False},
                "uploadTempPermits": [
                    {
                        "fileIds": ["synthetic-placeholder-file-id"],
                        "token": upstream_marker,
                    }
                ],
            },
        }
        upstream_response = types.SimpleNamespace(
            is_redirect=False,
            is_permanent_redirect=False,
            status_code=200,
            json=lambda: response_payload,
        )
        with tempfile.TemporaryDirectory() as data_dir:
            cookie_file = os.path.join(data_dir, "cookie.json")
            with (
                patch.object(main, "DATA_DIR", data_dir),
                patch.object(main, "COOKIE_FILE", cookie_file),
                patch.object(
                    main,
                    "_new_creator_client",
                    return_value=candidate,
                ),
                patch.object(
                    main,
                    "_request_creator_validation",
                    return_value=upstream_response,
                ),
                patch.object(main, "_save_and_swap_client") as save_and_swap,
                self.assertLogs(main.logger, level="WARNING") as captured,
            ):
                main.save_cookie(
                    "a1=prior-synthetic; web_session=prior-synthetic"
                )
                response = self.client.post(
                    "/login/cookie",
                    headers=self.headers,
                    json={
                        "cookie": (
                            "a1=candidate-synthetic; "
                            "web_session=candidate-synthetic"
                        )
                    },
                )

            self.assertEqual(response.status_code, 502)
            self.assertEqual(
                response.json()["validation"]["source"],
                "cookie_login_candidate",
            )
            self.assertEqual(
                json.loads(Path(cookie_file).read_text())["cookie"],
                "a1=prior-synthetic; web_session=prior-synthetic",
            )
            self.assertIs(main._active_client_state.client, working_client)
            save_and_swap.assert_not_called()
            response_text = response.text
            log_text = " ".join(captured.output)
            for marker in (
                upstream_marker,
                "synthetic-placeholder-file-id",
                "candidate-synthetic",
                "prior-synthetic",
            ):
                self.assertNotIn(marker, response_text)
                self.assertNotIn(marker, log_text)

    def test_failed_validation_preserves_cookie_file_and_active_client_atomically(self):
        working_client = object()
        candidate = object()
        main._active_client_state = main.ActiveClientState(
            working_client,
            "a1=working-secret; web_session=working-session",
        )
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
                    self.assertIs(
                        main._active_client_state.client,
                        working_client,
                    )
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
                "get_client_snapshot",
                return_value=(
                    object(),
                    "a1=current; web_session=current",
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
            cookie="webBuild=default; a1=jar-order; web_session=jar-order"
        )
        canonical_cookie = "a1=fresh; web_session=fresh"
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
            ) as validate,
            patch.object(
                main,
                "get_client_snapshot",
                return_value=(candidate, canonical_cookie),
            ),
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
            "relogin_required",
        ):
            self.assertEqual(
                login_response.json()[key],
                status_response.json()[key],
            )
        login_metadata = login_response.json()["validation"]
        status_metadata = status_response.json()["validation"]
        for key in ("method", "host", "path"):
            self.assertEqual(login_metadata[key], status_metadata[key])
        self.assertEqual(
            login_metadata["source"],
            "cookie_login_candidate",
        )
        self.assertEqual(status_metadata["source"], "active_session")
        self.assertEqual(
            validate.call_args_list,
            [
                unittest.mock.call(candidate, "a1=fresh; web_session=fresh"),
                unittest.mock.call(candidate, canonical_cookie),
            ],
        )
        self.assertNotIn(canonical_cookie, status_response.text)
        self.assertNotIn(candidate.cookie, status_response.text)

    def test_lazy_startup_loads_one_paired_client_and_canonical_cookie(self):
        canonical_cookie = (
            "creator_state=host-scoped; a1=startup-a1; "
            "web_session=startup-session"
        )
        startup_client = object()
        with tempfile.TemporaryDirectory() as data_dir:
            cookie_file = os.path.join(data_dir, "cookie.json")
            with (
                patch.object(main, "DATA_DIR", data_dir),
                patch.object(main, "COOKIE_FILE", cookie_file),
            ):
                main.save_cookie(canonical_cookie)
                main._active_client_state = None
                with (
                    patch.object(
                        main,
                        "load_cookie",
                        wraps=main.load_cookie,
                    ) as load_cookie,
                    patch.object(
                        main,
                        "_new_creator_client",
                        return_value=startup_client,
                    ) as new_client,
                ):
                    first_snapshot = main.get_client_snapshot()
                    second_snapshot = main.get_client_snapshot()
                    publishing_client = main.get_client()

        self.assertEqual(
            first_snapshot,
            (startup_client, canonical_cookie),
        )
        self.assertEqual(second_snapshot, first_snapshot)
        self.assertIs(publishing_client, startup_client)
        load_cookie.assert_called_once_with()
        new_client.assert_called_once_with(canonical_cookie)

    def test_empty_startup_session_is_paired_and_requires_relogin(self):
        startup_client = object()
        main._active_client_state = None
        with tempfile.TemporaryDirectory() as data_dir:
            with (
                patch.object(main, "DATA_DIR", data_dir),
                patch.object(
                    main,
                    "COOKIE_FILE",
                    os.path.join(data_dir, "cookie.json"),
                ),
                patch.object(
                    main,
                    "_new_creator_client",
                    return_value=startup_client,
                ) as new_client,
                patch.object(main, "_validate_creator_session") as validate,
            ):
                response = self.client.get(
                    "/session/status",
                    headers=self.headers,
                )
                snapshot = main.get_client_snapshot()

        self.assertEqual(response.status_code, 200)
        self.assertFalse(response.json()["valid"])
        self.assertTrue(response.json()["relogin_required"])
        self.assertEqual(
            response.json()["validation"]["source"],
            "active_session",
        )
        self.assertEqual(snapshot, (startup_client, ""))
        new_client.assert_called_once_with(None)
        validate.assert_not_called()

    def test_persistence_failure_preserves_old_pair_and_cookie_file(self):
        old_client = object()
        candidate = object()
        old_cookie = "a1=old-secret; web_session=old-session"
        candidate_cookie = "a1=candidate-secret; web_session=candidate-session"
        main._active_client_state = main.ActiveClientState(
            old_client,
            old_cookie,
        )
        with tempfile.TemporaryDirectory() as data_dir:
            cookie_file = os.path.join(data_dir, "cookie.json")
            with (
                patch.object(main, "DATA_DIR", data_dir),
                patch.object(main, "COOKIE_FILE", cookie_file),
            ):
                main.save_cookie(old_cookie)
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
                    patch.object(
                        main,
                        "save_cookie",
                        side_effect=OSError("candidate-secret"),
                    ),
                    patch.object(main.logger, "error") as log_error,
                ):
                    response = self.client.post(
                        "/login/cookie",
                        headers=self.headers,
                        json={"cookie": candidate_cookie},
                    )

                persisted_cookie = json.loads(
                    Path(cookie_file).read_text()
                )["cookie"]

        self.assertEqual(response.status_code, 500)
        self.assertEqual(
            response.json()["detail"],
            "Unable to persist Creator session.",
        )
        self.assertEqual(persisted_cookie, old_cookie)
        self.assertEqual(
            main.get_client_snapshot(),
            (old_client, old_cookie),
        )
        log_error.assert_called_once_with("Unable to persist Creator session")
        output = f"{response.text} {log_error.call_args!r}"
        self.assertNotIn("candidate-secret", output)
        self.assertNotIn("candidate-session", output)
        self.assertNotIn("old-secret", output)
        self.assertNotIn("old-session", output)

    def test_swap_and_snapshot_never_return_a_torn_pair(self):
        old_client = object()
        new_client = object()
        old_cookie = "a1=old; web_session=old"
        new_cookie = "a1=new; web_session=new"
        main._active_client_state = main.ActiveClientState(
            old_client,
            old_cookie,
        )
        persist_barrier = threading.Barrier(2)
        release_persist = threading.Event()
        snapshot_started = threading.Event()
        snapshot_finished = threading.Event()
        snapshots = []
        failures = []

        def blocking_save(cookie):
            try:
                self.assertEqual(cookie, new_cookie)
                self.assertEqual(
                    main._active_client_state,
                    main.ActiveClientState(old_client, old_cookie),
                )
                persist_barrier.wait(timeout=1)
                release_persist.wait(timeout=1)
            except BaseException as exc:
                failures.append(exc)
                release_persist.set()

        def swap():
            try:
                main._save_and_swap_client(new_cookie, new_client)
            except BaseException as exc:
                failures.append(exc)

        def snapshot():
            try:
                snapshot_started.set()
                snapshots.append(main.get_client_snapshot())
            except BaseException as exc:
                failures.append(exc)
            finally:
                snapshot_finished.set()

        with patch.object(main, "save_cookie", side_effect=blocking_save):
            swap_thread = threading.Thread(target=swap)
            swap_thread.start()
            persist_barrier.wait(timeout=1)
            snapshot_thread = threading.Thread(target=snapshot)
            snapshot_thread.start()
            self.assertTrue(snapshot_started.wait(timeout=1))
            self.assertFalse(snapshot_finished.wait(timeout=0.1))
            release_persist.set()
            swap_thread.join(timeout=1)
            snapshot_thread.join(timeout=1)

        self.assertFalse(swap_thread.is_alive())
        self.assertFalse(snapshot_thread.is_alive())
        self.assertEqual(failures, [])
        self.assertEqual(snapshots, [(new_client, new_cookie)])

    def test_status_releases_lock_before_network_validation(self):
        old_client = object()
        new_client = object()
        old_cookie = "a1=old; web_session=old"
        new_cookie = "a1=new; web_session=new"
        main._active_client_state = main.ActiveClientState(
            old_client,
            old_cookie,
        )
        validation_started = threading.Event()
        release_validation = threading.Event()
        swap_finished = threading.Event()
        observed = []
        failures = []

        def blocking_validation(active_client, canonical_cookie):
            observed.append((active_client, canonical_cookie))
            validation_started.set()
            release_validation.wait(timeout=1)
            return main.CreatorSessionValidation(valid=True)

        def status():
            try:
                main.session_status(main.API_KEY)
            except BaseException as exc:
                failures.append(exc)

        def swap():
            try:
                main._save_and_swap_client(new_cookie, new_client)
            except BaseException as exc:
                failures.append(exc)
            finally:
                swap_finished.set()

        with (
            patch.object(
                main,
                "_validate_creator_session",
                side_effect=blocking_validation,
            ),
            patch.object(main, "save_cookie"),
        ):
            status_thread = threading.Thread(target=status)
            status_thread.start()
            self.assertTrue(validation_started.wait(timeout=1))
            swap_thread = threading.Thread(target=swap)
            swap_thread.start()
            self.assertTrue(swap_finished.wait(timeout=1))
            release_validation.set()
            status_thread.join(timeout=1)
            swap_thread.join(timeout=1)

        self.assertFalse(status_thread.is_alive())
        self.assertFalse(swap_thread.is_alive())
        self.assertEqual(failures, [])
        self.assertEqual(observed, [(old_client, old_cookie)])
        self.assertEqual(
            main.get_client_snapshot(),
            (new_client, new_cookie),
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
                        "code": 0,
                        "data": {
                            "result": {"success": True},
                            "uploadTempPermits": [
                                {
                                    "fileIds": [
                                        "synthetic-placeholder-file-id"
                                    ],
                                    "token": "synthetic-placeholder-token",
                                }
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
            "creator_antibot=host-scoped-synthetic; "
            "a1=signing-cookie; domain_state=domain-scoped-synthetic; "
            "web_session=authenticated-session; "
            "webId=submitted-browser; path_scoped=submitted-value"
        )
        self.assertEqual(
            main._cookie_header_string(main._parse_cookie_header(cookie_header)),
            cookie_header,
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
        with (
            patch.object(
                main,
                "creator_sign",
                return_value={
                    "x-s": "signed",
                    "x-t": "time",
                    "x-s-common": "common",
                },
            ) as creator_sign,
            patch.object(main.logger, "info") as log_info,
            patch.object(main.logger, "warning") as log_warning,
        ):
            validation = main._validate_creator_session(
                candidate,
                cookie_header,
            )

        self.assertEqual(validation, main.CreatorSessionValidation(valid=True))
        expected_path = "/api/media/v1/upload/creator/permit"
        expected_uri = (
            f"{expected_path}"
            "?biz_name=spectrum&scene=image&file_count=1&version=1&source=web"
        )
        self.assertEqual(main.REDNOTE_CREATOR_VALIDATION_PATH, expected_path)
        self.assertEqual(main.REDNOTE_CREATOR_VALIDATION_URI, expected_uri)
        creator_sign.assert_called_once_with(
            expected_uri,
            None,
            a1="signing-cookie",
        )
        request, request_kwargs = adapter.requests[0]
        self.assertEqual(
            request.url,
            f"https://creator.rednote.com{expected_uri}",
        )
        self.assertEqual(request.method, "GET")
        self.assertEqual(request.headers["Cookie"], cookie_header)
        self.assertNotIn("jar-only", request.headers["Cookie"])
        log_info.assert_not_called()
        log_warning.assert_not_called()
        for cookie_value in (
            "host-scoped-synthetic",
            "domain-scoped-synthetic",
            "signing-cookie",
            "authenticated-session",
        ):
            self.assertNotIn(cookie_value, repr(validation))
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

    def test_accepts_observed_nested_permit_success_shape(self):
        response = self._response(
            200,
            {
                "success": True,
                "code": 0,
                "data": {
                    "result": {"success": True},
                    "uploadTempPermits": [
                        {
                            "token": "synthetic-placeholder-token",
                            "fileIds": ["synthetic-placeholder-file-id"],
                        }
                    ],
                },
            },
        )
        with patch.object(
            main,
            "_request_creator_validation",
            return_value=response,
        ):
            validation = main._validate_creator_session(
                object(),
                "a1=synthetic; web_session=synthetic",
            )

        self.assertEqual(validation, main.CreatorSessionValidation(valid=True))

    def test_accepts_nested_success_contract_without_top_level_signals(self):
        response = self._response(
            200,
            {
                "data": {
                    "result": {"success": True},
                    "uploadTempPermits": [
                        {
                            "token": "synthetic-placeholder-token",
                            "fileIds": ["synthetic-placeholder-file-id"],
                        }
                    ],
                },
            },
        )
        with patch.object(
            main,
            "_request_creator_validation",
            return_value=response,
        ):
            validation = main._validate_creator_session(
                object(),
                "a1=synthetic; web_session=synthetic",
            )

        self.assertEqual(validation, main.CreatorSessionValidation(valid=True))

    def test_accepts_top_level_success_contract_without_nested_result(self):
        response = self._response(
            200,
            {
                "success": True,
                "code": 0,
                "data": {
                    "uploadTempPermits": [
                        {
                            "token": "synthetic-placeholder-token",
                            "fileIds": ["synthetic-placeholder-file-id"],
                        }
                    ],
                },
            },
        )
        with patch.object(
            main,
            "_request_creator_validation",
            return_value=response,
        ):
            validation = main._validate_creator_session(
                object(),
                "a1=synthetic; web_session=synthetic",
            )

        self.assertEqual(validation, main.CreatorSessionValidation(valid=True))

    def test_rejects_conflicting_partial_and_malformed_success_signals(self):
        permit_data = {
            "uploadTempPermits": [
                {
                    "token": "synthetic-placeholder-token",
                    "fileIds": ["synthetic-placeholder-file-id"],
                }
            ],
        }
        payloads = (
            {
                "success": True,
                "code": 0,
                "data": {**permit_data, "result": {"success": False}},
            },
            {
                "success": False,
                "code": 0,
                "data": {**permit_data, "result": {"success": True}},
            },
            {
                "success": True,
                "code": 1,
                "data": {**permit_data, "result": {"success": True}},
            },
            {"success": True, "data": permit_data},
            {"code": 0, "data": permit_data},
            {
                "success": True,
                "code": 0,
                "data": {**permit_data, "result": {"success": "true"}},
            },
            {
                "success": True,
                "code": 0,
                "result": {"success": True},
                "data": permit_data,
            },
        )
        for payload in payloads:
            with (
                self.subTest(payload=payload),
                patch.object(
                    main,
                    "_request_creator_validation",
                    return_value=self._response(200, payload),
                ),
            ):
                validation = main._validate_creator_session(
                    object(),
                    "a1=synthetic; web_session=synthetic",
                )

            self.assertFalse(validation.valid)
            self.assertEqual(
                validation.error_code,
                "creator_session_validation_unavailable",
            )
            self.assertFalse(validation.relogin_required)

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
            payload = main._session_status_payload(validation, "active_session")
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
        payload_text = json.dumps(
            main._session_status_payload(validation, "active_session")
        )
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
            ),
            "active_session",
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
            payload_text = json.dumps(
                main._session_status_payload(validation, "active_session")
            )
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


class PublishSchedulingContractTests(unittest.TestCase):
    def setUp(self):
        self.client = TestClient(main.app)
        self.headers = {"X-Api-Key": main.API_KEY}

    def test_rejects_every_non_null_post_time_before_publish_work(self):
        for post_time in ("2026-08-07 10:00:00", "", "not-a-time"):
            with (
                self.subTest(post_time=post_time),
                patch.object(main, "get_client") as get_client,
                patch.object(main.os.path, "exists") as path_exists,
            ):
                response = self.client.post(
                    "/publish",
                    headers=self.headers,
                    json={
                        "title": "Scheduled post",
                        "desc": "Must not publish",
                        "files": ["/tmp/image.jpg"],
                        "post_time": post_time,
                    },
                )

            self.assertEqual(response.status_code, 422)
            self.assertEqual(
                response.json()["detail"]["code"],
                "scheduling_not_supported",
            )
            get_client.assert_not_called()
            path_exists.assert_not_called()

    def test_legacy_publish_failure_does_not_expose_raw_error_or_traceback(self):
        canary = "synthetic-upstream-secret"
        request = main.PublishRequest(
            title="Immediate post",
            desc="Publish now",
            files=[],
        )
        with patch.object(main, "get_client", side_effect=RuntimeError(canary)):
            result = main.publish_note(request, x_api_key=main.API_KEY)

        self.assertEqual(
            result,
            {"status": "error", "detail": "XHS image publish failed"},
        )
        self.assertNotIn(canary, json.dumps(result))
        self.assertNotIn("traceback", result)


class ReceiptNormalizationTests(unittest.TestCase):
    def test_extracts_only_exact_canonical_share_urls(self):
        self.assertEqual(
            main.extract_note_id_from_share_url(SHARE_URL),
            NOTE_ID,
        )
        self.assertEqual(
            main.extract_note_id_from_share_url(
                f"https://www.rednote.com/explore/{NOTE_ID}"
            ),
            NOTE_ID,
        )

        invalid_urls = (
            f"http://www.xiaohongshu.com/explore/{NOTE_ID}",
            f"https://xiaohongshu.com/explore/{NOTE_ID}",
            f"https://evil.www.xiaohongshu.com/explore/{NOTE_ID}",
            f"https://www.xiaohongshu.com/explore/{NOTE_ID}/",
            f"https://www.xiaohongshu.com/explore/{NOTE_ID}?xsec_token=secret",
            f"https://www.xiaohongshu.com/explore/{NOTE_ID}#fragment",
            f"https://www.xiaohongshu.com:443/explore/{NOTE_ID}",
            f"https://user@www.xiaohongshu.com/explore/{NOTE_ID}",
            f"https://www.xiaohongshu.com/discovery/{NOTE_ID}",
            "https://xhslink.com/short-link",
        )
        for share_url in invalid_urls:
            with self.subTest(share_url=share_url), self.assertRaises(ValueError):
                main.extract_note_id_from_share_url(share_url)

    def test_normalizers_return_fixed_sanitized_shapes(self):
        note = {
            "note_id": NOTE_ID,
            "type": "video",
            "time": 1_690_000_000_000,
            "last_update_time": "1690003600000",
            "user": {
                "user_id": "author-123",
                "nickname": "must-not-leak",
            },
            "image_list": [{"url": "secret-1"}, {"url": "secret-2"}],
            "video": {"media": {"stream": "secret-video"}},
            "interact_info": {
                "liked_count": "1.2万",
                "collected_count": "345",
                "comment_count": 67,
                "share_count": "8K",
                "raw_secret": "must-not-leak",
            },
            "desc": "must-not-leak",
        }

        self.assertEqual(
            main.normalize_receipt(NOTE_ID, note),
            {
                "note_id": NOTE_ID,
                "share_url": SHARE_URL,
                "published_at": "2023-07-22T04:26:40Z",
                "updated_at": "2023-07-22T05:26:40Z",
                "author_id": "author-123",
                "note_type": "video",
            },
        )
        self.assertEqual(
            main.normalize_receipt_assets(note),
            {"image_count": 2, "video_present": True},
        )
        self.assertEqual(
            main.normalize_receipt_metrics(note, "2026-08-06T22:32:22Z"),
            {
                "liked": 12000,
                "collected": 345,
                "commented": 67,
                "shared": 8000,
                "observed_at": "2026-08-06T22:32:22Z",
            },
        )


class ReceiptValidationEndpointTests(unittest.TestCase):
    def setUp(self):
        self.client = TestClient(main.app)
        self.headers = {"X-Api-Key": main.API_KEY}
        self.note = {
            "note_id": NOTE_ID,
            "type": "normal",
            "time": 1_690_000_000_000,
            "last_update_time": 1_690_003_600_000,
            "user": {"user_id": "author-123", "nickname": "private-name"},
            "image_list": [{}, {}],
            "interact_info": {
                "liked_count": "10",
                "collected_count": "20",
                "comment_count": "30",
                "share_count": "40",
            },
            "title": "must-not-leak",
            "desc": "must-not-leak",
        }

    def test_requires_permanent_api_key_before_lookup(self):
        with patch.object(main, "get_client") as get_client:
            response = self.client.post(
                "/receipt/validate",
                json={"note_id": NOTE_ID},
            )

        self.assertEqual(response.status_code, 403)
        get_client.assert_not_called()

    def test_requires_matching_valid_identifier_before_lookup(self):
        cases = (
            ({}, "receipt_identifier_required"),
            (
                {
                    "note_id": NOTE_ID,
                    "share_url": (
                        "https://www.xiaohongshu.com/explore/"
                        "64b000000000000001234568"
                    ),
                },
                "receipt_identifier_mismatch",
            ),
            (
                {"share_url": f"https://example.com/explore/{NOTE_ID}"},
                "receipt_identifier_invalid",
            ),
        )
        for payload, expected_code in cases:
            with (
                self.subTest(payload=payload),
                patch.object(main, "get_client") as get_client,
            ):
                response = self.client.post(
                    "/receipt/validate",
                    headers=self.headers,
                    json=payload,
                )

            self.assertEqual(response.status_code, 422)
            self.assertEqual(response.json()["detail"]["code"], expected_code)
            get_client.assert_not_called()

    def test_returns_normalized_receipt_without_any_mutation_surface(self):
        class ReadOnlyClient:
            def __init__(self, note):
                self.note = note
                self.lookups = []

            def get_note_by_id(self, note_id):
                self.lookups.append(note_id)
                return self.note

        read_only_client = ReadOnlyClient(self.note)
        mutation_names = (
            "_stage_remote_media_video",
            "_get_video_metadata",
            "_get_image_dimensions",
            "_validate_media_video_url",
            "publish_note",
            "publish_video",
            "publish_video_url",
            "save_cookie",
            "_save_and_swap_client",
        )
        mutation_patches = [
            patch.object(main, name)
            for name in mutation_names
        ]
        mutation_mocks = [patcher.start() for patcher in mutation_patches]
        self.addCleanup(
            lambda: [patcher.stop() for patcher in reversed(mutation_patches)]
        )
        with (
            patch.object(main, "get_client", return_value=read_only_client),
            patch.object(main.time, "time", return_value=1_700_000_000),
            patch.object(main.os, "makedirs") as makedirs,
            patch("builtins.open") as open_file,
            patch.object(Path, "write_text") as write_text,
            patch.object(Path, "write_bytes") as write_bytes,
            patch.object(Path, "unlink") as unlink,
        ):
            response = self.client.post(
                "/receipt/validate",
                headers=self.headers,
                json={"share_url": SHARE_URL},
            )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.json(),
            {
                "status": "validated",
                "receipt": {
                    "note_id": NOTE_ID,
                    "share_url": SHARE_URL,
                    "published_at": "2023-07-22T04:26:40Z",
                    "updated_at": "2023-07-22T05:26:40Z",
                    "author_id": "author-123",
                    "note_type": "normal",
                },
                "assets": {"image_count": 2, "video_present": False},
                "metrics": {
                    "liked": 10,
                    "collected": 20,
                    "commented": 30,
                    "shared": 40,
                    "observed_at": "2023-11-14T22:13:20Z",
                },
            },
        )
        self.assertEqual(read_only_client.lookups, [NOTE_ID])
        for mutation_mock in mutation_mocks:
            mutation_mock.assert_not_called()
        makedirs.assert_not_called()
        open_file.assert_not_called()
        write_text.assert_not_called()
        write_bytes.assert_not_called()
        unlink.assert_not_called()

    def test_maps_upstream_failures_to_sanitized_stable_codes(self):
        cases = (
            (
                main.DataFetchError(
                    {"code": -510001, "msg": "private-secret"}
                ),
                404,
                "receipt_not_found",
            ),
            (IndexError("missing-secret"), 404, "receipt_not_found"),
            (
                main.DataFetchError(
                    {"code": -100, "msg": "session-secret"}
                ),
                401,
                "creator_session_invalid",
            ),
            (
                main.requests.RequestException(
                    "redirect-secret",
                    response=types.SimpleNamespace(status_code=302),
                ),
                401,
                "creator_session_invalid",
            ),
            (
                main.requests.ConnectionError("transport-secret"),
                502,
                "receipt_lookup_unavailable",
            ),
        )
        for error, expected_status, expected_code in cases:
            fake_client = types.SimpleNamespace(
                get_note_by_id=lambda note_id, error=error: (_ for _ in ()).throw(
                    error
                )
            )
            with (
                self.subTest(expected_code=expected_code),
                patch.object(main, "get_client", return_value=fake_client),
            ):
                response = self.client.post(
                    "/receipt/validate",
                    headers=self.headers,
                    json={"note_id": NOTE_ID},
                )

            self.assertEqual(response.status_code, expected_status)
            self.assertEqual(response.json()["detail"]["code"], expected_code)
            for canary in (
                "private-secret",
                "missing-secret",
                "session-secret",
                "redirect-secret",
                "transport-secret",
            ):
                self.assertNotIn(canary, response.text)


if __name__ == "__main__":
    unittest.main()
