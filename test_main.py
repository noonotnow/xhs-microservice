import asyncio
import json
import os
import sys
import tempfile
import time
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


class FakeLoginClient:
    def __init__(self, cookie="temporary-login-cookie"):
        self.cookie = cookie


class QRLoginRouteTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.data_dir_patch = patch.object(main, "DATA_DIR", self.temp_dir.name)
        self.qr_file_patch = patch.object(
            main,
            "QR_STATE_FILE",
            os.path.join(self.temp_dir.name, "qr_state.json"),
        )
        self.qr_rejected_file_patch = patch.object(
            main,
            "QR_REJECTED_STATE_FILE",
            os.path.join(self.temp_dir.name, "qr_rejected.json"),
        )
        self.data_dir_patch.start()
        self.qr_file_patch.start()
        self.qr_rejected_file_patch.start()
        main.login_client = None
        main.RECENT_REJECTED_QR_IDS.clear()
        self.client = TestClient(main.app)
        self.headers = {"X-Api-Key": main.API_KEY}

    def tearDown(self):
        main.login_client = None
        main.RECENT_REJECTED_QR_IDS.clear()
        self.qr_rejected_file_patch.stop()
        self.qr_file_patch.stop()
        self.data_dir_patch.stop()
        self.temp_dir.cleanup()

    def test_qr_generation_requires_api_key(self):
        with patch.object(main, "get_login_client") as get_login_client:
            response = self.client.get("/login/qr")

        self.assertEqual(response.status_code, 403)
        self.assertIn("no-store", response.headers["cache-control"])
        get_login_client.assert_not_called()

    def test_qr_generation_replaces_stale_state_with_resumable_state(self):
        Path(main.QR_STATE_FILE).write_text('{"stale": true}')
        fake_client = FakeLoginClient()

        with patch.object(
            main,
            "get_login_client",
            return_value=fake_client,
        ) as get_login_client, patch.object(
            main,
            "_create_creator_qr",
            return_value={
                "qr_id": "qr-id",
                "code": "123456",
                "url": "xhsdiscover://login",
            },
        ):
            response = self.client.get("/login/qr", headers=self.headers)

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["url"], "xhsdiscover://login")
        self.assertIn("expires_at", response.json())
        self.assertNotIn("login_cookie", response.json())
        get_login_client.assert_called_once_with()
        state = json.loads(Path(main.QR_STATE_FILE).read_text())
        self.assertEqual(state["flow"], "creator")
        self.assertEqual(state["login_cookie"], fake_client.cookie)
        self.assertGreater(state["expires_at"], int(time.time()))
        self.assertIn("no-store", response.headers["cache-control"])

    def test_qr_generation_retries_reused_qr_id(self):
        main._save_qr_state({
            "flow": "creator",
            "qr_id": "old-id",
            "code": "123456",
            "login_cookie": "old-cookie",
            "expires_at": int(time.time()) + 60,
        })
        first_client = FakeLoginClient("first-cookie")
        second_client = FakeLoginClient("second-cookie")

        with (
            patch.object(
                main,
                "get_login_client",
                side_effect=[first_client, second_client],
            ) as get_login_client,
            patch.object(
                main,
                "_create_creator_qr",
                side_effect=[
                    {
                        "qr_id": "old-id",
                        "code": "123456",
                        "url": "xhsdiscover://old",
                    },
                    {
                        "qr_id": "new-id",
                        "code": "654321",
                        "url": "xhsdiscover://new",
                    },
                ],
            ),
        ):
            response = self.client.get("/login/qr", headers=self.headers)

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["qr_id"], "new-id")
        self.assertEqual(response.json()["url"], "xhsdiscover://new")
        self.assertEqual(get_login_client.call_count, 2)
        state = json.loads(Path(main.QR_STATE_FILE).read_text())
        self.assertEqual(state["qr_id"], "new-id")
        self.assertEqual(state["login_cookie"], "second-cookie")

    def test_qr_generation_retries_immediately_expired_upstream_qr(self):
        first_client = FakeLoginClient("first-cookie")
        second_client = FakeLoginClient("second-cookie")
        now = 2_000_000_000
        upstream_expiry_ms = (now + 120) * 1000

        with (
            patch.object(main.time, "time", return_value=now),
            patch.object(
                main,
                "get_login_client",
                side_effect=[first_client, second_client],
            ),
            patch.object(
                main,
                "_create_creator_qr",
                side_effect=[
                    {
                        "qr_id": "expired-id",
                        "code": "123456",
                        "url": "xhsdiscover://expired",
                        "expires_at": now - 1,
                    },
                    {
                        "qr_id": "fresh-id",
                        "code": "654321",
                        "url": "xhsdiscover://fresh",
                        "expires_at": upstream_expiry_ms,
                    },
                ],
            ),
        ):
            response = self.client.get("/login/qr", headers=self.headers)

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["qr_id"], "fresh-id")
        self.assertEqual(
            response.json()["expires_at"],
            now + 120 - main.QR_EXPIRY_SAFETY_SECONDS,
        )

    def test_qr_generation_fails_when_upstream_only_returns_stale_qrs(self):
        now = 2_000_000_000
        with (
            patch.object(main.time, "time", return_value=now),
            patch.object(main, "get_login_client", return_value=FakeLoginClient()),
            patch.object(
                main,
                "_create_creator_qr",
                side_effect=[
                    {
                        "qr_id": "expired-id",
                        "code": "123456",
                        "url": "xhsdiscover://expired",
                        "expires_at": now - 1,
                    },
                    {
                        "qr_id": "expired-id",
                        "code": "123456",
                        "url": "xhsdiscover://same-id-without-expiry",
                    },
                ],
            ),
        ):
            response = self.client.get("/login/qr", headers=self.headers)

        self.assertEqual(response.status_code, 502)
        self.assertEqual(
            response.json(),
            {"detail": "Could not generate XHS QR code"},
        )
        self.assertFalse(os.path.exists(main.QR_STATE_FILE))
        self.assertIn("no-store", response.headers["cache-control"])

    def test_qr_generation_rejects_expired_id_on_later_start(self):
        now = 2_000_000_000
        with (
            patch.object(main.time, "time", return_value=now),
            patch.object(main, "get_login_client", return_value=FakeLoginClient()),
            patch.object(
                main,
                "_create_creator_qr",
                side_effect=[
                    {
                        "qr_id": "expired-id",
                        "code": "123456",
                        "url": "xhsdiscover://expired",
                        "expires_at": now - 1,
                    },
                    {
                        "qr_id": "expired-id",
                        "code": "123456",
                        "url": "xhsdiscover://same-id",
                    },
                    {
                        "qr_id": "expired-id",
                        "code": "123456",
                        "url": "xhsdiscover://same-id-again",
                    },
                    {
                        "qr_id": "fresh-id",
                        "code": "654321",
                        "url": "xhsdiscover://fresh",
                    },
                ],
            ),
        ):
            first_response = self.client.get(
                "/login/qr",
                headers=self.headers,
            )
            second_response = self.client.get(
                "/login/qr",
                headers=self.headers,
            )

        self.assertEqual(first_response.status_code, 502)
        self.assertEqual(second_response.status_code, 200)
        self.assertEqual(second_response.json()["qr_id"], "fresh-id")

    def test_rejected_qr_id_remains_blocked_after_process_restart(self):
        now = 2_000_000_000
        main._remember_rejected_qr_id("expired-id", now)
        main.RECENT_REJECTED_QR_IDS.clear()

        with (
            patch.object(main.time, "time", return_value=now),
            patch.object(main, "get_login_client", return_value=FakeLoginClient()),
            patch.object(
                main,
                "_create_creator_qr",
                side_effect=[
                    {
                        "qr_id": "expired-id",
                        "code": "123456",
                        "url": "xhsdiscover://stale",
                    },
                    {
                        "qr_id": "fresh-id",
                        "code": "654321",
                        "url": "xhsdiscover://fresh",
                    },
                ],
            ),
        ):
            response = self.client.get("/login/qr", headers=self.headers)

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["qr_id"], "fresh-id")

    def test_qr_generation_failure_clears_stale_state(self):
        Path(main.QR_STATE_FILE).write_text('{"stale": true}')
        with (
            patch.object(
                main,
                "get_login_client",
                return_value=FakeLoginClient(),
            ),
            patch.object(
                main,
                "_create_creator_qr",
                side_effect=main.XhsLoginProtocolError(-1),
            ),
        ):
            response = self.client.get("/login/qr", headers=self.headers)

        self.assertEqual(response.status_code, 502)
        self.assertEqual(
            response.json(),
            {"detail": "XHS QR login is currently unavailable"},
        )
        self.assertFalse(os.path.exists(main.QR_STATE_FILE))

    def test_qr_generation_rejects_merchant_qianfan_target(self):
        merchant_url = (
            "https://oia.xiaohongshu.com/thor/home/main"
            "?deepLink=xymerchant%3A%2F%2Flogin"
        )
        with (
            patch.object(
                main,
                "get_login_client",
                return_value=FakeLoginClient(),
            ),
            patch.object(
                main,
                "_create_creator_qr",
                return_value={
                    "qr_id": "merchant-id",
                    "code": "123456",
                    "url": merchant_url,
                },
            ),
        ):
            response = self.client.get("/login/qr", headers=self.headers)

        self.assertEqual(response.status_code, 502)
        self.assertEqual(
            response.json(),
            {"detail": "Could not generate XHS QR code"},
        )
        self.assertNotIn("xymerchant", response.text)
        self.assertFalse(os.path.exists(main.QR_STATE_FILE))

    def test_expired_qr_state_is_removed(self):
        main._save_qr_state({
            "flow": "creator",
            "qr_id": "old-id",
            "code": "123456",
            "login_cookie": "temporary",
            "expires_at": int(time.time()) - 1,
        })

        response = self.client.get("/login/status", headers=self.headers)

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["expired"], True)
        self.assertFalse(os.path.exists(main.QR_STATE_FILE))
        self.assertIn("no-store", response.headers["cache-control"])

    def test_polling_resumes_from_persisted_login_cookie(self):
        main._save_qr_state({
            "flow": "creator",
            "qr_id": "qr-id",
            "code": "123456",
            "login_cookie": "persisted-temporary-cookie",
            "expires_at": int(time.time()) + 60,
        })
        resumed_client = FakeLoginClient(cookie="updated-temporary-cookie")

        with patch.object(
            main,
            "get_login_client",
            return_value=resumed_client,
        ) as get_login_client, patch.object(
            main,
            "_check_creator_qr",
            return_value={"code_status": 1},
        ) as check_creator_qr:
            response = self.client.get("/login/status", headers=self.headers)

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["code_status"], 1)
        get_login_client.assert_called_once_with("persisted-temporary-cookie")
        check_creator_qr.assert_called_once_with(
            resumed_client,
            "qr-id",
            "123456",
        )
        state = json.loads(Path(main.QR_STATE_FILE).read_text())
        self.assertEqual(
            state["login_cookie"],
            "updated-temporary-cookie",
        )

    def test_creator_initial_status_remains_pending(self):
        main._save_qr_state({
            "flow": "creator",
            "qr_id": "qr-id",
            "code": "123456",
            "login_cookie": "temporary",
            "expires_at": int(time.time()) + 60,
        })
        main.login_client = FakeLoginClient()

        with patch.object(
            main,
            "_check_creator_qr",
            return_value={"code_status": 0},
        ):
            response = self.client.get("/login/status", headers=self.headers)

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["code_status"], 0)
        self.assertEqual(response.json()["expired"], False)
        self.assertTrue(os.path.exists(main.QR_STATE_FILE))

    def test_success_saves_session_and_clears_qr_state(self):
        main._save_qr_state({
            "flow": "creator",
            "qr_id": "qr-id",
            "code": "123456",
            "login_cookie": "temporary",
            "expires_at": int(time.time()) + 60,
        })
        authenticated_client = FakeLoginClient(cookie="authenticated-cookie")
        main.login_client = authenticated_client

        with (
            patch.object(
                main,
                "_check_creator_qr",
                return_value={"code_status": 2, "login_info": {}},
            ),
            patch.object(main, "save_cookie") as save_cookie,
            patch.object(main, "refresh_client") as refresh_client,
        ):
            response = self.client.get("/login/status", headers=self.headers)

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["code_status"], 2)
        save_cookie.assert_called_once_with("authenticated-cookie")
        refresh_client.assert_called_once_with()
        self.assertFalse(os.path.exists(main.QR_STATE_FILE))
        self.assertIsNone(main.login_client)

    def test_legacy_qr_state_is_rejected_and_removed(self):
        Path(main.QR_STATE_FILE).write_text(json.dumps({
            "qr_id": "legacy-id",
            "code": "legacy-code",
        }))

        response = self.client.get("/login/status", headers=self.headers)

        self.assertEqual(response.status_code, 400)
        self.assertFalse(os.path.exists(main.QR_STATE_FILE))


class CreatorQRProtocolTests(unittest.TestCase):
    def test_new_login_client_replaces_pinned_static_identity(self):
        fake_client = types.SimpleNamespace(
            session=types.SimpleNamespace(
                cookies=types.SimpleNamespace(
                    clear=unittest.mock.Mock(),
                    update=unittest.mock.Mock(),
                )
            )
        )
        with (
            patch.object(main, "XhsClient", return_value=fake_client),
            patch.object(
                main,
                "get_a1_and_web_id",
                return_value=("fresh-a1", "fresh-web-id"),
            ),
        ):
            result = main.get_login_client()

        self.assertIs(result, fake_client)
        fake_client.session.cookies.clear.assert_called_once_with()
        fake_client.session.cookies.update.assert_called_once_with({
            "a1": "fresh-a1",
            "webId": "fresh-web-id",
        })

    def test_resumed_login_client_restores_only_persisted_cookies(self):
        fake_client = types.SimpleNamespace()
        cookie = "a1=fresh-a1; webId=fresh-id; acw_tc=padded=="
        with patch.object(
            main,
            "_new_xhs_client",
            return_value=fake_client,
        ) as new_xhs_client:
            result = main.get_login_client(cookie)

        self.assertIs(result, fake_client)
        new_xhs_client.assert_called_once_with(cookie)

    def test_health_reports_deployed_revision(self):
        with patch.object(main, "APP_REVISION", "commit-sha"):
            response = TestClient(main.app).get("/health")

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["revision"], "commit-sha")

    def test_creator_qr_uses_first_party_rednote_endpoint(self):
        class Response:
            status_code = 200

            def json(self):
                return {
                    "success": True,
                    "data": {
                        "qr_id": "creator-qr-id",
                        "code": "123456",
                        "url": "xhsdiscover://creator-login",
                    },
                }

        class Session:
            def __init__(self):
                self.request_args = None

            def request(self, *args, **kwargs):
                self.request_args = (args, kwargs)
                return Response()

        client = types.SimpleNamespace(
            cookie_dict={},
            session=Session(),
            timeout=10,
            proxies=None,
        )
        with patch.object(
            main,
            "sign",
            return_value={"x-s": "signed", "x-t": "time"},
        ) as sign:
            result = main._create_creator_qr(client)

        self.assertEqual(result["qr_id"], "creator-qr-id")
        args, kwargs = client.session.request_args
        self.assertEqual(args[0], "POST")
        self.assertEqual(
            args[1],
            "https://webapi.rednote.com/api/sns/web/v1/login/qrcode/create",
        )
        self.assertEqual(json.loads(kwargs["data"]), {})
        sign.assert_called_once_with(
            "/api/sns/web/v1/login/qrcode/create",
            {},
            a1="",
            web_session="",
        )

    def test_creator_qr_status_uses_first_party_rednote_endpoint(self):
        class Response:
            status_code = 200

            def json(self):
                return {
                    "success": True,
                    "data": {"code_status": 0},
                }

        session = types.SimpleNamespace(
            request=unittest.mock.Mock(return_value=Response())
        )
        client = types.SimpleNamespace(
            cookie_dict={},
            session=session,
            timeout=10,
            proxies=None,
        )
        with patch.object(main, "sign", return_value={}):
            result = main._check_creator_qr(
                client,
                "qr-id",
                "123456",
            )

        self.assertEqual(result["code_status"], 0)
        args, kwargs = session.request.call_args
        self.assertEqual(args[0], "GET")
        self.assertEqual(
            args[1],
            (
                "https://webapi.rednote.com/api/sns/web/v1/login/"
                "qrcode/status?qr_id=qr-id&code=123456"
            ),
        )

    def test_merchant_and_qianfan_qr_urls_are_rejected(self):
        self.assertFalse(main._is_supported_creator_qr_url(
            "https://oia.xiaohongshu.com/thor/home/main"
            "?deepLink=xymerchant%253A%252F%252Flogin"
        ))
        self.assertFalse(main._is_supported_creator_qr_url(
            "xhsdiscover://qianfan/login"
        ))
        self.assertFalse(main._is_supported_creator_qr_url(
            "xhsdiscover://%25252571ianfan/login"
        ))
        self.assertTrue(main._is_supported_creator_qr_url(
            "xhsdiscover://creator/login"
        ))

    def test_creator_qr_failure_exposes_only_numeric_code(self):
        class Response:
            status_code = 200

            def json(self):
                return {
                    "code": -1,
                    "success": False,
                    "ticket": "must-not-escape",
                }

        client = types.SimpleNamespace(
            cookie_dict={},
            session=types.SimpleNamespace(
                request=lambda *args, **kwargs: Response()
            ),
            timeout=10,
            proxies=None,
        )
        with (
            patch.object(main, "sign", return_value={}),
            self.assertRaises(main.XhsLoginProtocolError) as raised,
        ):
            main._create_creator_qr(client)

        self.assertEqual(raised.exception.code, -1)
        self.assertNotIn("must-not-escape", str(raised.exception))

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

    def test_accepts_rednote_cookie_header_and_preserves_token_padding(self):
        with (
            patch.object(main, "save_cookie") as save_cookie,
            patch.object(main, "refresh_client") as refresh_client,
        ):
            response = self.client.post(
                "/login/cookie",
                headers=self.headers,
                json={
                    "cookie": (
                        "a1=fresh-a1; web_session=session-with-padding==; "
                        "id_token=padded-token==; webId=browser-id"
                    )
                },
            )

        self.assertEqual(response.status_code, 200)
        save_cookie.assert_called_once_with(
            "a1=fresh-a1; web_session=session-with-padding==; "
            "id_token=padded-token==; webId=browser-id"
        )
        refresh_client.assert_called_once_with()

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
            json={"cookie": "id_token=token; webId=browser-id"},
        )

        self.assertEqual(response.status_code, 400)
        self.assertIn("a1 and web_session", response.json()["detail"])

    def test_cookie_login_requires_api_key_before_parsing(self):
        response = self.client.post(
            "/login/cookie",
            json={"cookie": "not a valid cookie header"},
        )

        self.assertEqual(response.status_code, 403)

    def test_session_failure_does_not_return_upstream_payload(self):
        upstream_error = "cookie=must-not-escape"
        with patch.object(
            main,
            "get_client",
            return_value=types.SimpleNamespace(
                get_self_info=lambda: (_ for _ in ()).throw(
                    RuntimeError(upstream_error)
                )
            ),
        ):
            response = self.client.get(
                "/session/status",
                headers=self.headers,
            )

        self.assertEqual(
            response.json(),
            {"valid": False, "error": "Session validation failed"},
        )
        self.assertNotIn(upstream_error, response.text)

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
