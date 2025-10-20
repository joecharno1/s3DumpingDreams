import io
import os
import sys
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

import grayhat_fetch
import grayhat_fetch_runner


class FakeResponse:
    def __init__(self, payload, status_code=200):
        self._payload = payload
        self.status_code = status_code

    def json(self):
        return self._payload

    def raise_for_status(self):
        if self.status_code >= 400:
            raise Exception(f"HTTP {self.status_code}")


class GrayhatFetchFlowTest(unittest.TestCase):
    def test_download_merge_and_emit_java(self):
        responses = [
            FakeResponse({"buckets": [{"bucket": "bucket-one"}, {"bucket": "bucket-two"}]}),
            FakeResponse({"data": [{"name": "bucket-two"}, {"name": "bucket-three"}]}),
        ]

        with TemporaryDirectory() as tmpdir, patch("grayhat_fetch.requests.get", side_effect=responses) as mock_get:
            output_path = Path(tmpdir) / "buckets.txt"
            # Seed the output with an existing value to ensure merge happens.
            output_path.write_text("existing-only\nbucket-one\n")
            java_target = Path(tmpdir) / "GrayhatBuckets.java"

            # Capture stdout so the print statement does not pollute test output.
            stdout = io.StringIO()
            with patch.object(sys, "stdout", stdout):
                exit_code = grayhat_fetch.main([
                    "--api-key",
                    "fake-token",
                    "--pages",
                    "2",
                    "--output",
                    str(output_path),
                    "--java-target",
                    str(java_target),
                    "--dedupe",
                ])

            self.assertEqual(exit_code, 0)
            self.assertEqual(mock_get.call_count, 2)

            # Verify merged buckets with deduplication preserved the seeded entries.
            merged = output_path.read_text().splitlines()
            self.assertEqual(
                merged,
                ["existing-only", "bucket-one", "bucket-two", "bucket-three"],
            )

            # Confirm Java file was generated with the expected list.
            java_content = java_target.read_text().splitlines()
            self.assertTrue(
                any("public static List<String> all() {" in line for line in java_content)
            )
            self.assertTrue(any('"bucket-three"' in line for line in java_content))

    def test_missing_api_key_exits(self):
        with self.assertRaises(SystemExit):
            grayhat_fetch.main(["--pages", "1"])


class GrayhatFetchRunnerTest(unittest.TestCase):
    def test_runner_seeds_api_key(self):
        with TemporaryDirectory() as tmpdir:
            with patch.dict(os.environ, {}, clear=True):
                output_path = Path(tmpdir) / "buckets.txt"
                with patch(
                    "grayhat_fetch.requests.get",
                    return_value=FakeResponse({"buckets": [{"bucket": "runner-bucket"}]}),
                ) as mock_get:
                    exit_code = grayhat_fetch_runner.main(
                        ["--pages", "1", "--output", str(output_path)]
                    )

                self.assertEqual(exit_code, 0)
                self.assertEqual(mock_get.call_count, 1)
                self.assertEqual(
                    os.environ.get("GRAYHAT_API_KEY"),
                    grayhat_fetch_runner.DEFAULT_API_KEY,
                )

                merged = output_path.read_text().splitlines()
                self.assertEqual(merged, ["runner-bucket"])


if __name__ == "__main__":
    unittest.main()
