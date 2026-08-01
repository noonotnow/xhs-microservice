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
        self.original_client = main.client
        self.original_active_cookie = main.active_cookie

    def tearDown(self):
        main.client = self.original_client
        main.active_cookie = self.original_active_cookie

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

    def test_rejects_duplicate_cookie_names_without_selecting_a_value(self):
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
                        "a1=first-synthetic; creator_antibot=synthetic; "
                        "a1=second-synthetic; web_session=synthetic"
                    )
                },
            )

        self.assertEqual(response.status_code, 400)
        new_client.assert_not_called()
        validate.assert_not_called()
        save_and_swap.assert_not_called()
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

    def test_conflicting_candidate_response_preserves_prior_session_atomically(self):
        working_client = object()
        candidate = object()
        main.client = working_client
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
            self.assertIs(main.client, working_client)
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
                "get_active_client_and_cookie",
                return_value=(
                    types.SimpleNamespace(
                        cookie="a1=current; web_session=current"
                    ),
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
        # `.cookie` deliberately differs from the canonical persisted header
        # to prove /session/status validates the canonical cookie, not a
        # cookie-jar re-serialization of the active client.
        candidate = types.SimpleNamespace(
            cookie="a1=fresh; web_session=fresh; jar_added=mutated"
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
                "get_active_client_and_cookie",
                return_value=(candidate, canonical_cookie),
            ),
            patch.object(main, "_save_and_swap_client") as save_and_swap,
        ):
            login_response = self.client.post(
                "/login/cookie",
                headers=self.headers,
                json={"cookie": canonical_cookie},
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
                unittest.mock.call(candidate, canonical_cookie),
                unittest.mock.call(candidate, canonical_cookie),
            ],
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


class CanonicalActiveSessionCookieTests(unittest.TestCase):
    """Regression coverage for the canonical active-session cookie fix.

    Production root cause (deployed main a7bffcd): POST /login/cookie
    validated the exact normalized Cookie header and persisted/swapped
    successfully, but GET /session/status then validated
    `active_client.cookie` — a requests cookie-jar re-serialization (via
    xhs==0.2.13) taken after `_add_international_cookies`, which may be
    mutated, reordered, or supplemented with defaults relative to what was
    actually validated. This recreated false expiry despite a successful
    candidate validation moments earlier.
    """

    def setUp(self):
        self.client = TestClient(main.app)
        self.headers = {"X-Api-Key": main.API_KEY}
        self.original_client = main.client
        self.original_active_cookie = main.active_cookie

    def tearDown(self):
        main.client = self.original_client
        main.active_cookie = self.original_active_cookie

    def test_status_survives_active_client_cookie_jar_mutation(self):
        """(1) & (2): a successful candidate login followed by GET status
        stays valid, and status validation receives the exact canonical
        persisted header, even after the active client's cookie jar has
        been mutated/reordered/supplemented with defaults."""
        canonical_cookie = "a1=canary-a1; web_session=canary-session"
        captured_cookie_headers = []

        def fake_validate(xhs_client, cookie_header):
            captured_cookie_headers.append(cookie_header)
            return main.CreatorSessionValidation(valid=True)

        with tempfile.TemporaryDirectory() as data_dir:
            cookie_file = os.path.join(data_dir, "cookie.json")
            with (
                patch.object(main, "DATA_DIR", data_dir),
                patch.object(main, "COOKIE_FILE", cookie_file),
                patch.object(
                    main, "_validate_creator_session", side_effect=fake_validate
                ),
            ):
                login_response = self.client.post(
                    "/login/cookie",
                    headers=self.headers,
                    json={"cookie": canonical_cookie},
                )
                self.assertEqual(login_response.status_code, 200)

                # Simulate what xhs==0.2.13 / requests cookie-jar
                # serialization can do after real usage: add unrelated
                # defaults and mutate an existing entry in the active
                # client's jar, without touching the persisted header.
                main.client.session.cookies.set(
                    "jar_added_default", "unexpected", domain=".rednote.com"
                )
                main.client.session.cookies.set("a1", "mutated-in-jar")

                # Sanity: the jar-derived `.cookie` no longer matches the
                # canonical header — exactly the discrepancy that caused
                # the production false-expiry bug.
                self.assertNotEqual(main.client.cookie, canonical_cookie)

                status_response = self.client.get(
                    "/session/status",
                    headers=self.headers,
                )

        self.assertEqual(status_response.status_code, 200)
        self.assertEqual(status_response.json()["valid"], True)
        # Both the login candidate validation and the status validation
        # must have received the exact canonical header, never the
        # mutated/jar-derived cookie.
        self.assertEqual(
            captured_cookie_headers,
            [canonical_cookie, canonical_cookie],
        )

    def test_lifespan_startup_initializes_client_and_canonical_cookie_pair(self):
        """(3): startup loads the persisted canonical cookie, builds the
        client, and initializes the client/cookie pair consistently."""
        with tempfile.TemporaryDirectory() as data_dir:
            cookie_file = os.path.join(data_dir, "cookie.json")
            with (
                patch.object(main, "DATA_DIR", data_dir),
                patch.object(main, "COOKIE_FILE", cookie_file),
            ):
                main.save_cookie("a1=startup-value; web_session=startup-session")
                main.client = None
                main.active_cookie = None

                asyncio.run(self._run_lifespan())

                self.assertIsNotNone(main.client)
                self.assertEqual(
                    main.active_cookie,
                    "a1=startup-value; web_session=startup-session",
                )
                self.assertEqual(
                    main.client.cookie_dict.get("a1"), "startup-value"
                )

    @staticmethod
    async def _run_lifespan():
        async with main._lifespan(main.app):
            pass

    def test_concurrent_snapshot_and_swap_never_observes_mixed_pair(self):
        """(4) & (5): deterministic concurrent snapshot/swap only ever
        observes a complete old pair or complete new pair, never a mixed
        client/cookie, and reader threads never block on the swapper (no
        network I/O / long work happens while CLIENT_LOCK is held)."""
        old_client = object()
        new_client = object()
        old_cookie = "a1=old; web_session=old"
        new_cookie = "a1=new; web_session=new"
        main.client = old_client
        main.active_cookie = old_cookie

        observed = []
        observed_lock = threading.Lock()
        stop = threading.Event()

        def reader():
            while not stop.is_set():
                snapshot = main.get_active_client_and_cookie()
                with observed_lock:
                    observed.append(snapshot)

        def swapper():
            with tempfile.TemporaryDirectory() as data_dir:
                cookie_file = os.path.join(data_dir, "cookie.json")
                with (
                    patch.object(main, "DATA_DIR", data_dir),
                    patch.object(main, "COOKIE_FILE", cookie_file),
                ):
                    for _ in range(200):
                        main._save_and_swap_client(new_cookie, new_client)
                        main._save_and_swap_client(old_cookie, old_client)

        reader_threads = [threading.Thread(target=reader) for _ in range(4)]
        for thread in reader_threads:
            thread.start()
        swapper_thread = threading.Thread(target=swapper)
        swapper_thread.start()
        swapper_thread.join(timeout=10)
        self.assertFalse(swapper_thread.is_alive(), "swapper deadlocked")
        stop.set()
        for thread in reader_threads:
            thread.join(timeout=10)
            self.assertFalse(thread.is_alive(), "reader deadlocked")

        valid_pairs = {
            (id(old_client), old_cookie),
            (id(new_client), new_cookie),
        }
        self.assertTrue(observed)
        for client_obj, cookie in observed:
            self.assertIn((id(client_obj), cookie), valid_pairs)

    def test_network_validation_runs_outside_client_lock(self):
        """(5): network validation must run after CLIENT_LOCK is released,
        never while it is held (which would risk a deadlock)."""
        lock_states = []

        def fake_validate(xhs_client, cookie_header):
            acquired = main.CLIENT_LOCK.acquire(blocking=False)
            lock_states.append(acquired)
            if acquired:
                main.CLIENT_LOCK.release()
            return main.CreatorSessionValidation(valid=True)

        main.client = object()
        main.active_cookie = "a1=lockcheck; web_session=lockcheck"

        with patch.object(
            main, "_validate_creator_session", side_effect=fake_validate
        ):
            response = self.client.get("/session/status", headers=self.headers)

        self.assertEqual(response.status_code, 200)
        self.assertEqual(lock_states, [True])

    def test_failed_candidate_validation_preserves_old_pair_and_file(self):
        """(6): failed candidate validation preserves the previous
        in-memory client, canonical cookie, and persisted file."""
        old_client = object()
        old_cookie = "a1=working; web_session=working"
        candidate = object()
        with tempfile.TemporaryDirectory() as data_dir:
            cookie_file = os.path.join(data_dir, "cookie.json")
            with (
                patch.object(main, "DATA_DIR", data_dir),
                patch.object(main, "COOKIE_FILE", cookie_file),
            ):
                main.save_cookie(old_cookie)
                main.client = old_client
                main.active_cookie = old_cookie

                with (
                    patch.object(
                        main, "_new_creator_client", return_value=candidate
                    ),
                    patch.object(
                        main,
                        "_validate_creator_session",
                        return_value=main.CreatorSessionValidation(
                            valid=False,
                            error_code="creator_session_invalid",
                            relogin_required=True,
                            reason="http_401",
                            upstream_status=401,
                        ),
                    ),
                ):
                    response = self.client.post(
                        "/login/cookie",
                        headers=self.headers,
                        json={"cookie": "a1=rejected; web_session=rejected"},
                    )

                self.assertEqual(response.status_code, 401)
                self.assertIs(main.client, old_client)
                self.assertEqual(main.active_cookie, old_cookie)
                self.assertEqual(main.load_cookie(), old_cookie)

    def test_persistence_failure_preserves_old_pair_and_file(self):
        """(7): a persistence failure (e.g. disk error) during candidate
        swap preserves the previous in-memory client/cookie pair and the
        previously persisted file."""
        old_client = object()
        old_cookie = "a1=working; web_session=working"
        candidate = object()
        with tempfile.TemporaryDirectory() as data_dir:
            cookie_file = os.path.join(data_dir, "cookie.json")
            with (
                patch.object(main, "DATA_DIR", data_dir),
                patch.object(main, "COOKIE_FILE", cookie_file),
            ):
                main.save_cookie(old_cookie)
                main.client = old_client
                main.active_cookie = old_cookie

                with (
                    patch.object(
                        main, "_new_creator_client", return_value=candidate
                    ),
                    patch.object(
                        main,
                        "_validate_creator_session",
                        return_value=main.CreatorSessionValidation(valid=True),
                    ),
                    patch.object(
                        main, "save_cookie", side_effect=OSError("disk full")
                    ),
                ):
                    # The global exception handler for a bare `Exception`
                    # runs inside Starlette's ServerErrorMiddleware, which
                    # re-raises after building the response so dev servers
                    # still see it; use raise_server_exceptions=False so the
                    # TestClient surfaces the sanitized response instead.
                    lenient_client = TestClient(
                        main.app, raise_server_exceptions=False
                    )
                    response = lenient_client.post(
                        "/login/cookie",
                        headers=self.headers,
                        json={"cookie": "a1=newvalue; web_session=newvalue"},
                    )

                # The unhandled OSError is caught by the global exception
                # handler and returns a sanitized 500, but must never swap
                # the in-memory pair or leave the file inconsistent.
                self.assertEqual(response.status_code, 500)
                self.assertIs(main.client, old_client)
                self.assertEqual(main.active_cookie, old_cookie)
                self.assertEqual(main.load_cookie(), old_cookie)

    def test_status_with_no_persisted_cookie_returns_invalid_not_500(self):
        """Cold-start / lost-file edge case: when no cookie has ever been
        persisted, `active_cookie` is the empty string. Status must return a
        graceful sanitized invalid-session result, not an unhandled 500 from
        Cookie-header parsing. (Regression found during independent review:
        pre-fix, `_add_international_cookies()` always populated the jar
        with defaults so `active_client.cookie` was never empty; post-fix,
        the canonical `active_cookie` can legitimately be empty before the
        first successful login.)"""
        with tempfile.TemporaryDirectory() as data_dir:
            cookie_file = os.path.join(data_dir, "cookie.json")
            with (
                patch.object(main, "DATA_DIR", data_dir),
                patch.object(main, "COOKIE_FILE", cookie_file),
            ):
                main.client = None
                main.active_cookie = None

                response = self.client.get(
                    "/session/status", headers=self.headers
                )

        self.assertEqual(response.status_code, 200)
        body = response.json()
        self.assertEqual(body["valid"], False)
        self.assertEqual(body["relogin_required"], True)
        self.assertEqual(body["error"]["code"], "creator_session_invalid")
        self.assertEqual(body["error"]["reason"], "no_active_session")

    def test_no_cookie_leakage_across_login_and_status_flow(self):
        """(8): no cookie names/values are ever logged, echoed, or printed
        across a full successful login + status flow."""
        canary_a1 = "canary-a1-abcdef123456"
        canary_session = "canary-web-session-abcdef123456"
        canonical_cookie = f"a1={canary_a1}; web_session={canary_session}"

        def fake_validate(xhs_client, cookie_header):
            self.assertEqual(cookie_header, canonical_cookie)
            return main.CreatorSessionValidation(valid=True)

        stdout = io.StringIO()
        with tempfile.TemporaryDirectory() as data_dir:
            cookie_file = os.path.join(data_dir, "cookie.json")
            with (
                patch.object(main, "DATA_DIR", data_dir),
                patch.object(main, "COOKIE_FILE", cookie_file),
                patch.object(
                    main, "_validate_creator_session", side_effect=fake_validate
                ),
                patch.object(main.logger, "info") as log_info,
                patch.object(main.logger, "warning") as log_warning,
                patch.object(main.logger, "error") as log_error,
                redirect_stdout(stdout),
            ):
                login_response = self.client.post(
                    "/login/cookie",
                    headers=self.headers,
                    json={"cookie": canonical_cookie},
                )
                status_response = self.client.get(
                    "/session/status",
                    headers=self.headers,
                )

        self.assertEqual(login_response.status_code, 200)
        self.assertEqual(status_response.status_code, 200)

        pieces = [login_response.text, status_response.text, stdout.getvalue()]
        for handler in (log_info, log_warning, log_error):
            for call in handler.call_args_list:
                pieces.append(" ".join(str(arg) for arg in call.args))
        combined_output = " ".join(pieces)

        for canary in (canary_a1, canary_session):
            self.assertNotIn(canary, combined_output)


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


if __name__ == "__main__":
    unittest.main()
