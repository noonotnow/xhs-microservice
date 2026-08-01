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

    def test_accepts_cookie_header_and_preserves_equals_in_value(self):
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
                        "webId=browser-id"
                    )
                },
            )

        self.assertEqual(response.status_code, 200)
        save_cookie.assert_called_once_with(
            "a1=fresh-a1; web_session=session-with-padding==; webId=browser-id"
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
