"""The disposable setup reports only fixed causes and retries only the same pinned pull."""
import os
import subprocess
import unittest
from unittest.mock import patch

from recover import Failure, Project, pull_release


class AcquisitionTests(unittest.TestCase):
    def setUp(self):
        self.project = Project("imageproof123456789abc", "source")

    def test_permanent_pull_errors_are_closed_and_never_retried(self):
        cases = ((b"no space left on device", "pull_disk_full"),
                 (b"Cannot connect to the Docker daemon", "pull_daemon_unavailable"),
                 (b"toomanyrequests: Too Many Requests", "pull_rate_limited"),
                 (b"unauthorized: access denied", "pull_denied"),
                 (b"manifest unknown", "pull_manifest_unavailable"),
                 (b"unexpected private detail", "pull_other"))
        for message, expected in cases:
            result = subprocess.CompletedProcess([], 1, b"", message + b" " + os.urandom(16).hex().encode())
            with self.subTest(expected=expected), patch("recover.subprocess.run", return_value=result) as run:
                with self.assertRaises(Failure) as caught:
                    pull_release(self.project)
                self.assertEqual(str(caught.exception), expected)
                self.assertEqual(run.call_count, 1)

    def test_transient_retry_is_identical_and_within_original_budget(self):
        transient = subprocess.CompletedProcess([], 1, b"", b"503 Service Unavailable")
        success = subprocess.CompletedProcess([], 0, b"", b"")
        for second in (success, transient):
            with self.subTest(second=second.returncode), patch("recover.time.sleep") as pause, \
                    patch("recover.time.monotonic", side_effect=[0, 1, 2, 6]), \
                    patch("recover.subprocess.run", side_effect=[transient, second]) as run:
                if second.returncode:
                    with self.assertRaisesRegex(Failure, "^pull_registry_transient$"):
                        pull_release(self.project)
                else:
                    pull_release(self.project)
                pause.assert_called_once_with(3)
                first, retry = run.call_args_list
                self.assertEqual(first.args, retry.args)
                self.assertEqual(first.args[0][-5:], ["pull", "--quiet", "server", "redis", "database"])
                self.assertEqual([first.kwargs["timeout"], retry.kwargs["timeout"]], [419, 414])

    def test_deadline_and_command_timeout_do_not_retry(self):
        transient = subprocess.CompletedProcess([], 1, b"", b"connection reset by peer")
        with patch("recover.time.monotonic", side_effect=[0, 1, 417]), \
                patch("recover.subprocess.run", return_value=transient) as run:
            with self.assertRaisesRegex(Failure, "^pull_registry_transient$"):
                pull_release(self.project)
            self.assertEqual(run.call_count, 1)
        with patch("recover.subprocess.run", side_effect=subprocess.TimeoutExpired("private", 420)) as run:
            with self.assertRaisesRegex(Failure, "^pull_timeout$"):
                pull_release(self.project)
            self.assertEqual(run.call_count, 1)
