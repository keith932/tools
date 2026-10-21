"""Offline checks; never contacts Falcon or installs a sensor."""
import contextlib
import io
from pathlib import Path
import unittest
from unittest.mock import patch


SCRIPT = Path(__file__).resolve().parents[1] / "falcon-host-install.sh"
HELPER = SCRIPT.read_text().split("<<'FALCON_HOST_GROUP_CODE'\n", 1)[1].split(
    "\nFALCON_HOST_GROUP_CODE\n", 1
)[0]
GROUP_ID = "f21f4746723b4e4994c26d8b566fcab2"
AID = "ab" * 16


class SubmissionTests(unittest.TestCase):
    def setUp(self):
        self.code = {"__name__": "offline_test"}
        exec(compile(HELPER, str(SCRIPT), "exec"), self.code)

    def test_install_submits_once_without_polling_or_claiming_membership(self):
        calls = []

        def api(base, route, token=None, body=None, form=None):
            calls.append((route, body))
            if route == "/oauth2/token":
                return {"access_token": "fake-token"}
            if route.startswith("/devices/entities/host-groups/v1?"):
                return {"resources": [{"id": GROUP_ID, "name": "misc1", "group_type": "static"}]}
            if route == "/devices/entities/host-group-actions/v1?action_name=add-hosts":
                return {"resources": []}
            self.fail("Unexpected membership poll: " + route)

        self.code["api"] = api
        request = "\0".join(["enroll", "fake-id", "fake-secret", "us-1", GROUP_ID, AID, ""])
        output = io.StringIO()
        with patch("sys.stdin", io.BytesIO(request.encode())), contextlib.redirect_stdout(output), patch(
            "time.sleep", side_effect=AssertionError("must not wait for membership")
        ):
            self.code["main"]()
        self.assertIn("GROUP=SUBMITTED misc1", output.getvalue())
        self.assertNotIn("VERIFIED", output.getvalue())
        actions = [body for route, body in calls if "action_name=add-hosts" in route]
        self.assertEqual(actions, [{
            "ids": [GROUP_ID],
            "action_parameters": [{"name": "filter", "value": "(device_id:['{}'])".format(AID)}],
        }])

    def test_rejected_requests_and_connection_errors_still_fail(self):
        errors = [self.code["APIError"](status, "/test") for status in (400, 401, 403, 404)]
        errors.append(RuntimeError("connection failed"))
        for error in errors:
            with self.subTest(error=str(error)):
                def api(*args, **kwargs):
                    raise error
                self.code["api"] = api
                with self.assertRaises(type(error)):
                    self.code["enroll"]("unused", "fake-token", GROUP_ID, AID)

    def test_conflict_warns_without_claiming_submission_or_membership(self):
        calls = []

        def api(base, route, token=None, body=None, form=None):
            calls.append(route)
            if route == "/oauth2/token":
                return {"access_token": "fake-token"}
            if route.startswith("/devices/entities/host-groups/v1?"):
                return {"resources": [{"id": GROUP_ID, "name": "misc1", "group_type": "static"}]}
            if route == "/devices/entities/host-group-actions/v1?action_name=add-hosts":
                raise self.code["APIError"](409, route)
            self.fail("Unexpected membership poll: " + route)

        self.code["api"] = api
        request = "\0".join(["enroll", "fake-id", "fake-secret", "us-1", GROUP_ID, AID, ""])
        output = io.StringIO()
        with patch("sys.stdin", io.BytesIO(request.encode())), contextlib.redirect_stdout(output), patch(
            "time.sleep", side_effect=AssertionError("must not wait or retry conflicts")
        ):
            self.code["main"]()
        self.assertIn("GROUP=WARNING_HTTP_409 misc1", output.getvalue())
        for false_status in ("GROUP=SUBMITTED", "GROUP=VERIFIED", "GROUP=FAILED"):
            self.assertNotIn(false_status, output.getvalue())
        self.assertEqual(sum("action_name=add-hosts" in route for route in calls), 1)

    def test_invalid_aid_cannot_submit(self):
        def api(*args, **kwargs):
            self.fail("invalid AID must not reach API")
        self.code["api"] = api
        for aid in ("", "bad", "0" * 32):
            with self.assertRaises(RuntimeError):
                self.code["enroll"]("unused", "fake-token", GROUP_ID, aid)

    def test_explicit_read_only_check_still_rejects_unconfirmed_membership(self):
        def api(base, route, token=None, body=None, form=None):
            self.assertIsNone(body)
            self.assertNotIn("host-group-actions", route)
            return {"resources": []}
        self.code["api"] = api
        with contextlib.redirect_stdout(io.StringIO()), self.assertRaises(RuntimeError):
            self.code["diagnose"]("unused", "fake-token", GROUP_ID, AID)


if __name__ == "__main__":
    unittest.main()
