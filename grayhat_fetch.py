"""Fetch bucket names from the Grayhat Warfare API and persist them locally.

The script is intentionally defensive because the Grayhat Warfare API tends to
change response envelopes between plans.  Rather than hard-coding a single
shape, it tries a handful of common layouts and falls back to strings when no
obvious field is present.

Usage examples
--------------

Fetch the first 5 pages (100 results each by default) and merge them into the
existing ``buckets.txt`` file::

    python grayhat_fetch.py --api-key $GRAYHAT_API_KEY \
        --pages 5 --output buckets.txt

Write the same data to ``buckets.txt`` and also to ``Buckets.java`` in a format
that a Java program can ``List<String>``::

    python grayhat_fetch.py --api-key $GRAYHAT_API_KEY \
        --pages 5 --output buckets.txt --java-target src/Buckets.java

The script never embeds credentials in files; supply the API key via the command
line or the ``GRAYHAT_API_KEY`` environment variable.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Iterable, List, Sequence

import requests

DEFAULT_ENDPOINT = "https://buckets.grayhatwarfare.com/api/v1/buckets"
DEFAULT_TOKEN_PARAM = "access_token"
DEFAULT_PAGE_PARAM = "page"
DEFAULT_LIMIT_PARAM = "limit"
DEFAULT_PAGE_SIZE = 100


def parse_args(argv: Sequence[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Download bucket metadata from the Grayhat Warfare API and merge the "
            "results into a local bucket list."
        )
    )
    parser.add_argument(
        "--api-key",
        default=os.getenv("GRAYHAT_API_KEY"),
        help=(
            "API key used to authenticate against Grayhat Warfare. You can also "
            "set the GRAYHAT_API_KEY environment variable."
        ),
    )
    parser.add_argument(
        "--endpoint",
        default=DEFAULT_ENDPOINT,
        help="Grayhat Warfare endpoint to call (defaults to %(default)s)",
    )
    parser.add_argument(
        "--pages",
        type=int,
        default=1,
        help="Number of pages to fetch (defaults to %(default)s)",
    )
    parser.add_argument(
        "--start-page",
        type=int,
        default=1,
        help="First page index to fetch (defaults to %(default)s)",
    )
    parser.add_argument(
        "--page-size",
        type=int,
        default=DEFAULT_PAGE_SIZE,
        help="Number of results per page (defaults to %(default)s)",
    )
    parser.add_argument(
        "--page-param",
        default=DEFAULT_PAGE_PARAM,
        help="Query parameter name that encodes the page number",
    )
    parser.add_argument(
        "--limit-param",
        default=DEFAULT_LIMIT_PARAM,
        help="Query parameter name that limits the number of results per page",
    )
    parser.add_argument(
        "--token-param",
        default=DEFAULT_TOKEN_PARAM,
        help="Query parameter name that carries the API token",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("buckets.txt"),
        help="Text file that should contain one bucket name per line",
    )
    parser.add_argument(
        "--java-target",
        type=Path,
        help=(
            "Optional path to a Java source file that should receive the bucket "
            "names as a static List<String>."
        ),
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=30.0,
        help="HTTP timeout in seconds (defaults to %(default)s)",
    )
    parser.add_argument(
        "--dedupe",
        action="store_true",
        help="Deduplicate buckets when merging them into the output file",
    )
    return parser.parse_args(argv)


def build_request_params(args: argparse.Namespace, page: int) -> dict:
    params = {
        args.token_param: args.api_key,
        args.page_param: page,
        args.limit_param: args.page_size,
    }
    return params


def raise_if_missing_api_key(api_key: str | None) -> str:
    if not api_key:
        raise SystemExit(
            "An API key is required. Supply --api-key or set GRAYHAT_API_KEY."
        )
    return api_key


def extract_bucket_names(payload) -> List[str]:
    """Return a best-effort list of bucket names from an API payload."""
    if payload is None:
        return []

    if isinstance(payload, list):
        names: List[str] = []
        for item in payload:
            names.extend(extract_bucket_names(item))
        return names

    if isinstance(payload, str):
        # Single bucket name
        return [payload.strip()] if payload.strip() else []

    if isinstance(payload, dict):
        # Common containers returned by Grayhat Warfare across plans.
        for key in ("buckets", "data", "results", "items"):
            if key in payload:
                return extract_bucket_names(payload[key])

        # A single bucket object.
        for key in ("bucket", "bucket_name", "name"):
            value = payload.get(key)
            if isinstance(value, str):
                return [value.strip()]

        # Nested data; flatten values.
        names: List[str] = []
        for value in payload.values():
            names.extend(extract_bucket_names(value))
        return names

    return []


def fetch_page(args: argparse.Namespace, page: int) -> List[str]:
    params = build_request_params(args, page)
    response = requests.get(args.endpoint, params=params, timeout=args.timeout)

    if response.status_code == 401:
        raise SystemExit(
            "Grayhat Warfare rejected the credentials (HTTP 401). Double-check "
            "the API key."
        )
    if response.status_code == 404:
        raise SystemExit(
            "Grayhat Warfare returned 404 for the endpoint. Adjust --endpoint "
            "to match your subscription tier."
        )

    response.raise_for_status()

    try:
        payload = response.json()
    except json.JSONDecodeError as exc:
        raise SystemExit(f"Failed to parse JSON from Grayhat Warfare: {exc}") from exc

    buckets = extract_bucket_names(payload)
    if not buckets:
        raise SystemExit(
            "The Grayhat Warfare response did not contain any recognizable bucket "
            "names. Use --endpoint/--page-param/--limit-param to match the API "
            "shape returned for your plan."
        )
    return buckets


def merge_with_existing(new_buckets: Iterable[str], output_file: Path, dedupe: bool) -> List[str]:
    new_list = [bucket.strip() for bucket in new_buckets if bucket.strip()]

    if not output_file.exists():
        output_file.write_text("\n".join(new_list) + ("\n" if new_list else ""))
        return new_list

    existing = output_file.read_text().splitlines()
    combined = existing + new_list
    if dedupe:
        seen = set()
        deduped = []
        for bucket in combined:
            if bucket and bucket not in seen:
                seen.add(bucket)
                deduped.append(bucket)
        combined = deduped

    output_file.write_text("\n".join(combined) + ("\n" if combined else ""))
    return combined


def emit_java_file(buckets: Sequence[str], java_target: Path) -> None:
    java_target.parent.mkdir(parents=True, exist_ok=True)
    lines = [
        "// Auto-generated by grayhat_fetch.py",
        "import java.util.Arrays;",
        "import java.util.List;",
        "",
        "public final class GrayhatBuckets {",
        "    private GrayhatBuckets() { }",
        "",
        "    public static List<String> all() {",
        "        return Arrays.asList(",
    ]

    for index, bucket in enumerate(buckets):
        suffix = "," if index < len(buckets) - 1 else ""
        lines.append(f'            "{bucket}"{suffix}')

    lines.extend([
        "        );",
        "    }",
        "}",
    ])

    java_target.write_text("\n".join(lines) + "\n")


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv or sys.argv[1:])
    args.api_key = raise_if_missing_api_key(args.api_key)

    all_new_buckets: List[str] = []
    for offset, page in enumerate(range(args.start_page, args.start_page + args.pages)):
        bucket_batch = fetch_page(args, page)
        all_new_buckets.extend(bucket_batch)
        if not bucket_batch:
            break

    merged_buckets = merge_with_existing(all_new_buckets, args.output, args.dedupe)

    if args.java_target:
        emit_java_file(merged_buckets, args.java_target)

    print(f"Fetched {len(all_new_buckets)} new buckets. {len(merged_buckets)} total entries.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
